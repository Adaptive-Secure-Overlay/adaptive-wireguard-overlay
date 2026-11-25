"""Endpoint authentication for the active r3 MCC path, before selection.

Only the public NodeDaemon mixes this adapter in.  Relay envelopes are routing
data, never proof of an endpoint identity.  The final IKE sink accepts a local,
single-use thread proof bound to a VerifiedMessage and the exact payload/meta.
There is no network ``verified`` flag and no password-derived seal fallback.
"""
from __future__ import annotations

import hashlib
import base64
import binascii
import ipaddress
import os
import random
import secrets
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519

import config
from crypto_util import aesgcm_decrypt, aesgcm_encrypt, xpub_bytes, xpub_from_bytes
from mcc_e2e import EndpointSecurity, MccSecurityError, VerifiedMessage, canonical_json, strict_json_loads
from protocol import jdump, T_MCC_START, T_MCC_OFFER, T_PRIV_BACK, T_MCC_OPAQUE_FWD
from runtime_contract import require_runtime

MAX_ACTIVE = 256
MAX_REQUESTS = 128
MAX_PLAINTEXT = 65507
MAX_IKE = 8192  # bounded signed record plus nested seals fits one link envelope
MAX_ATTEMPTS = 3
MAX_WIRE_CIPHERTEXT = MAX_PLAINTEXT
MAX_BASE64_CIPHERTEXT = 4 * ((MAX_WIRE_CIPHERTEXT + 2) // 3)
MCC_NEIGHBOR_WIRE_BUDGET = 65507 - 256


@dataclass
class _LocalDeliveryProof:
    verified: VerifiedMessage
    payload: bytes
    meta: bytes
    used: bool = False


class MccAuthenticatedMixin:
    def __init__(self, name):
        # Refuse missing/invalid node-local keys and replay state BEFORE binding
        # an overlay socket.  No intermediary needs another node's private key.
        require_runtime()
        security = EndpointSecurity.from_environment(name, required_nodes=config.ACTIVE_USERS)
        self._init_mcc_auth(security)
        super().__init__(name)

    def _init_mcc_auth(self, security, policy=None):
        self.mcc_security = security
        self._mcc_policy = dict(policy or self._auth_policy_from_environment())
        self._mcc_local = threading.local()
        self._mcc_verify_slots = threading.BoundedSemaphore(2)
        self._mcc_auth_pending = {}
        self._mcc_auth_sessions = {}  # (verified initiator, context), never raw context
        self._mcc_auth_timers = {}
        self._mcc_auth_quiet = {}
        self._mcc_auth_attempts = {}
        self._mcc_auth_deadlines = {}
        self._mcc_auth_x1_choices = {}
        self._mcc_auth_a_routes = {}  # (recipient, initiator SPI), local only

    @staticmethod
    def _auth_policy_from_environment():
        def integer(name, default, low, high):
            try:
                value = int(os.environ.get(name, str(default)))
            except ValueError as exc:
                raise MccSecurityError('invalid_selection_config') from exc
            if not low <= value <= high:
                raise MccSecurityError('invalid_selection_config')
            return value

        def millis(name, default, low, high):
            try:
                value = float(os.environ.get(name, str(default)))
                number = int(value * 1000)
            except (ValueError, OverflowError) as exc:
                raise MccSecurityError('invalid_selection_config') from exc
            if not low <= number <= high:
                raise MccSecurityError('invalid_selection_config')
            return number

        window = millis('IKE_MCC_ACCEPT_WINDOW_S', config.IKE_MCC_ACCEPT_WINDOW_S, 0, 120000)
        mode = os.environ.get('IKE_MCC_ACCEPT_MODE', '').strip().lower()
        wait_all = os.environ.get('IKE_MCC_WAIT_ALL_COPIES', '0').lower() in ('1', 'true', 'yes', 'on')
        adaptive = os.environ.get('IKE_MCC_ADAPTIVE_ACCEPT', '0').lower() in ('1', 'true', 'yes', 'on')
        if wait_all and adaptive:
            raise MccSecurityError('conflicting_selection_config')
        flag_mode = 'wait-all' if wait_all else 'adaptive' if adaptive else ''
        if mode and flag_mode and mode != flag_mode:
            raise MccSecurityError('conflicting_selection_config')
        mode = mode or flag_mode or ('window' if window else 'first')
        if mode not in ('first', 'window', 'adaptive', 'wait-all') or (mode == 'window' and not window):
            raise MccSecurityError('unsupported_selection_mode')
        return {'mode': mode, 'window_ms': window,
                'deadline_ms': millis('IKE_MCC_ROUTE_TIMEOUT_S', config.IKE_MCC_ROUTE_TIMEOUT_S, 100, 120000),
                'min_copies': integer('IKE_MCC_ACCEPT_MIN_COPIES', 3, 1, 64),
                'quiet_ms': millis('IKE_MCC_ACCEPT_QUIET_S', 0.150, 0, 120000)}

    def _auth_reject(self, code='invalid_record'):
        # No endpoint names, ciphertext, keys or attacker-controlled exception text.
        self.logger.warning('[MCC/AUTH] rejected code=%s' % code)

    @staticmethod
    def _auth_read(plain):
        return strict_json_loads(plain, max_bytes=MAX_PLAINTEXT)

    def _seal_key_for_user(self, user):
        raise MccSecurityError('password_seals_disabled')

    def _seal_for_user(self, user, conn_id, obj):
        return self._auth_pack_seal(self.mcc_security.seal_to(user, obj, conn_id, purpose='hop'))

    def _open_seal_for_me(self, conn_id, sealed):
        return self.mcc_security.open_for_me(self._auth_expand_seal(sealed), conn_id, purpose='hop')

    @staticmethod
    def _auth_hex(value, length):
        if type(value) is not str or len(value) != length * 2:
            raise MccSecurityError('invalid_wire_encoding')
        raw = bytes.fromhex(value)
        if raw.hex() != value:
            raise MccSecurityError('invalid_wire_encoding')
        return raw

    @staticmethod
    def _auth_encode_ct(raw):
        if not 16 <= len(raw) <= MAX_WIRE_CIPHERTEXT:
            raise MccSecurityError('wire_ciphertext_size')
        return base64.b64encode(raw).decode('ascii')

    @staticmethod
    def _auth_decode_ct(value):
        # Reject size/type before allocation or decoder invocation. Re-encoding
        # rejects nonzero padding bits and every alternate representation.
        if (type(value) is not str or not 24 <= len(value) <= MAX_BASE64_CIPHERTEXT or len(value) % 4):
            raise MccSecurityError('invalid_wire_encoding')
        try:
            raw = base64.b64decode(value.encode('ascii'), validate=True)
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise MccSecurityError('invalid_wire_encoding') from exc
        if (not 16 <= len(raw) <= MAX_WIRE_CIPHERTEXT or
                base64.b64encode(raw).decode('ascii') != value):
            raise MccSecurityError('invalid_wire_encoding')
        return raw

    @classmethod
    def _auth_pack_seal(cls, seal):
        if type(seal) is not dict or set(seal) != {'v', 'epk', 'nonce', 'ct'} or type(seal['v']) is not int or seal['v'] != 1:
            raise MccSecurityError('invalid_core_seal')
        cls._auth_hex(seal['epk'], 32)
        cls._auth_hex(seal['nonce'], 12)
        if type(seal['ct']) is not str or len(seal['ct']) > MAX_WIRE_CIPHERTEXT * 2:
            raise MccSecurityError('wire_ciphertext_size')
        raw = bytes.fromhex(seal['ct'])
        if raw.hex() != seal['ct']:
            raise MccSecurityError('invalid_core_seal')
        return dict(seal, v=2, ct=cls._auth_encode_ct(raw))

    @classmethod
    def _auth_expand_seal(cls, seal):
        if type(seal) is not dict or set(seal) != {'v', 'epk', 'nonce', 'ct'} or type(seal['v']) is not int or seal['v'] != 2:
            raise MccSecurityError('invalid_wire_seal')
        cls._auth_hex(seal['epk'], 32)
        cls._auth_hex(seal['nonce'], 12)
        return dict(seal, v=1, ct=cls._auth_decode_ct(seal['ct']).hex())

    def _auth_open_endpoint(self, seal, context):
        return self.mcc_security.open_for_me(self._auth_expand_seal(seal), context, purpose='endpoint')

    def _opaque_start_batches(self, message):
        # Preserve the global transport cap. Account for the EXISTING neighbor
        # AEAD envelope, including hex expansion, tag, sid and actual identities.
        peer = message['x1']
        with self.lock:
            session = self.sessions.get(peer)
        if not session:
            raise MccSecurityError('no_first_hop_session')
        base = dict(message)
        branches = base.pop('branches')

        def fits(current):
            raw = jdump(dict(base, branches=current))
            envelope = {'t': T_MCC_START, 'sid': session.sid, 'from': self.name, 'to': peer,
                        'nonce': '0' * 24, 'ct': '0' * (2 * (len(raw) + 16)),
                        'meta': {'mode': 'mcc-ike'}}
            return len(jdump(envelope)) <= MCC_NEIGHBOR_WIRE_BUDGET

        batches, current = [], []
        for branch in branches:
            trial = current + [branch]
            if fits(trial):
                current = trial
                continue
            if not current or not fits([branch]):
                raise MccSecurityError('one_capsule_exceeds_link_budget')
            batches.append(dict(base, branches=current))
            current = [branch]
        if current:
            batches.append(dict(base, branches=current))
        return batches

    def _opaque_select_x2(self, req, context, fanout):
        key = (req, context)
        with self.lock:
            previous = self._mcc_auth_x1_choices.get(key)
        if previous:
            return list(previous['selected'])
        self._auth_prune()
        with self.lock:
            if len(self._mcc_auth_x1_choices) >= MAX_ACTIVE:
                raise MccSecurityError('relay_capacity')
        candidates = [p for p in config.ACTIVE_USERS if p != self.name]
        chosen = self._ordered_route_candidates(candidates, 'IKE_DEBUG_FORCE_X2', 'X2')[:fanout]
        with self.lock:
            state = self._mcc_auth_x1_choices.setdefault(key, {'selected': chosen, 'expires': time.time() + 120})
        return list(state['selected'])

    def _auth_prune(self):
        now = time.time()
        with self.lock:
            for key, state in list(self._mcc_auth_x1_choices.items()):
                if state['expires'] < now:
                    self._mcc_auth_x1_choices.pop(key, None)
            for key, state in list(self._mcc_auth_sessions.items()):
                if state['expires'] + 5 < now:
                    self._mcc_auth_sessions.pop(key, None)
            for key, route in list(self._mcc_auth_a_routes.items()):
                if now - route.created_at > 120:
                    self._mcc_auth_a_routes.pop(key, None)
            for key, state in list(self._mcc_auth_pending.items()):
                if state['expires'] + 5 < now:
                    self._mcc_auth_pending.pop(key, None)
                    self.mcc_b_selected.pop(key, None)
                    self.mcc_b_delivered.pop(key, None)
                    self._mcc_auth_attempts.pop(key, None)
                    self._mcc_auth_deadlines.pop(key, None)
                    for table in (self._mcc_auth_timers, self._mcc_auth_quiet):
                        timer = table.pop(key, None)
                        if timer:
                            timer.cancel()
            for table in (self.priv_x1_state, self.priv_x2_state, self.priv_b_state):
                for key, state in list(table.items()):
                    if now - state.get('created_at', now) > 120:
                        table.pop(key, None)

    @staticmethod
    def _auth_message_id(header):
        return '%d:%d' % (header[18], int.from_bytes(header[20:24], 'big'))

    def _auth_body(self, payload, src_ip, src_port, dst_ip, dst_port, udp_port, a_pub,
                   conn, budget, selection=None):
        if not isinstance(payload, bytes) or not 28 <= len(payload) <= MAX_IKE:
            raise MccSecurityError('ike_size_limit')
        return {'ike_payload': payload.hex(), 'ike_length': len(payload),
                'ike_src_ip': src_ip, 'ike_src_port': src_port,
                'ike_dst_ip': dst_ip, 'ike_dst_port': dst_port, 'udp_port': udp_port,
                'a_to_b_ke': a_pub, 'transport_conn': conn,
                'budget': list(budget), 'selection': dict(selection or self._mcc_policy),
                'request_digest': hashlib.sha256(payload).hexdigest()}

    def send_ike_datagram(self, dst_user, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port,
                          payload, udp_port):
        if not config.IKE_MCC_ENABLED:
            raise MccSecurityError('authenticated_profile_requires_mcc')
        if dst_user not in config.USERS:
            raise MccSecurityError('invalid_destination')
        # REDIRECT exposes loopback/unknown destination at capture. Preserve
        # canonical endpoint metadata (as the original adapter already does for
        # UDP ports), rather than signing the transient local capture address.
        if ike_src_ip == '0.0.0.0' or str(ike_src_ip).startswith('127.'):
            ike_src_ip = config.USERS[self.name]['ip']
        if ike_dst_ip == '0.0.0.0' or str(ike_dst_ip).startswith('127.'):
            ike_dst_ip = config.USERS[dst_user]['ip']
        ike_src_port, ike_dst_port = self._canonical_ike_ports(ike_src_port, ike_dst_port, udp_port)
        header = self._opaque_ike_header(payload, udp_port)
        if header[19] & 0x20:
            message_id = self._auth_message_id(header)
            with self.lock:
                matches = [state for (sender, context), state in self._mcc_auth_sessions.items()
                           if sender == dst_user and state['initiator_spi'] == header[:8]
                           and message_id in state['requests'] and time.time() <= state['expires'] + 5]
            if not matches or len({s['requests'][message_id] for s in matches}) != 1:
                raise MccSecurityError('unbound_local_response')
            # Repeated identical IKE requests in a newer local context may share
            # the SPI; use the newest matching request, never another payload.
            route = max(matches, key=lambda state: state['created_at'])['route']
            return self._send_priv_ike_back(route, payload, ike_src_ip, ike_src_port,
                                            ike_dst_ip, ike_dst_port, udp_port)
        with self.lock:
            key = (dst_user, header[:8])
            route = self._mcc_auth_a_routes.get(key)
            if route and time.time() - route.created_at > 120:
                self._mcc_auth_a_routes.pop(key, None)
                route = None
        if route:
            with self.lock:
                state = self.priv_ab_state.get(route.ab_context)
            request_key = (header[:8], header[18], header[20:24])
            if state and request_key == state['first_request']:
                if state['auth_requests'].get(self._auth_message_id(header)) != hashlib.sha256(payload).hexdigest():
                    raise MccSecurityError('conflicting_initial_retransmission')
                for peer, message in state.get('auth_initial_messages', []):
                    self.link_send(peer, T_MCC_START, jdump(message), meta={'mode': 'mcc-ike'})
                return
            return self._opaque_send_forward(route, payload, ike_src_ip, ike_src_port,
                                              ike_dst_ip, ike_dst_port, udp_port)
        return self._send_mcc_inline_ike_start(dst_user, payload, ike_src_ip, ike_src_port,
                                                ike_dst_ip, ike_dst_port, udp_port)

    def _send_mcc_inline_ike_start(self, dst, payload, src_ip, src_port, dst_ip, dst_port, udp_port):
        if dst not in config.USERS or dst == self.name:
            raise MccSecurityError('invalid_destination')
        header = self._opaque_ike_header(payload, udp_port)
        if header[19] & 0x20:
            raise MccSecurityError('initial_requires_request')
        # Bound size/config before local pending-state creation.
        if len(payload) > MAX_IKE:
            raise MccSecurityError('ike_size_limit')
        candidates = [u for u in config.ACTIVE_USERS if u != self.name]
        ordered = self._ordered_route_candidates(candidates, 'IKE_DEBUG_FORCE_X1', 'X1')
        x1_count = min(max(1, config.IKE_MCC_X1_FANOUT), len(ordered))
        x2_count = min(max(1, config.IKE_MCC_X2_FANOUT), len(config.ACTIVE_USERS) - 1)
        ike_count = max(1, config.IKE_MCC_IKE_FANOUT)
        expected = x1_count * x2_count * ike_count
        if not 1 <= expected <= 64:
            raise MccSecurityError('copy_budget_limit')
        digest, context, replayed = self._opaque_prepare_initial(dst, payload, udp_port)
        if replayed:
            return
        try:
            self._auth_build_initial(dst, payload, src_ip, src_port, dst_ip, dst_port, udp_port,
                                     header, ordered, x1_count, x2_count, ike_count, expected, digest, context)
        except Exception:
            # Roll back only this newly created local context. Never leave a
            # failed serialization as a replayable pending start.
            with self.lock:
                pending = self.mcc_opaque_pending.get(digest)
                if pending and pending['context'] == context:
                    self.mcc_opaque_pending.pop(digest, None)
                self.priv_ab_state.pop(context, None)
            raise

    def _auth_build_initial(self, dst, payload, src_ip, src_port, dst_ip, dst_port, udp_port,
                            header, ordered, x1_count, x2_count, ike_count, expected, digest, context):
        a_pub = self._ensure_priv_ab_pub(context, dst)
        msg_id = self._auth_message_id(header)
        with self.lock:
            self.priv_ab_state[context]['auth_requests'] = {msg_id: hashlib.sha256(payload).hexdigest()}
        sent = 0
        for x1_slot, x1 in enumerate(ordered[:x1_count]):
            branches = []
            for x2 in (u for u in config.ACTIVE_USERS if u != x1):
                for x2_slot in range(x2_count):
                    for ike_index in range(ike_count):
                        copy_id = ((x1_slot * x2_count) + x2_slot) * ike_count + ike_index
                        conn = secrets.token_hex(16)
                        body = self._auth_body(payload, src_ip, src_port, dst_ip, dst_port,
                                               udp_port, a_pub, conn, (x1_count, x2_count, ike_count))
                        record = self.mcc_security.signed_message(dst, context, body, copy_id, expected,
                                                                 kind='initial', message_id=msg_id)
                        sealed_b = self._auth_pack_seal(self.mcc_security.seal_to(dst, record, context, purpose='endpoint'))
                        inner = {'auth_mcc': 1, 'mcc_session_id': context, 'conn_id': conn,
                                 'branch_id': secrets.token_hex(16), 'dst': dst, 'x1': x1, 'x2': x2,
                                 'opaque_mcc': 1, 'ab_context': context, 'mcc_carry_ike': True,
                                 'sealed_b': sealed_b}
                        branches.append({'conn_id': conn, 'branch_id': inner['branch_id'], 'x2': x2,
                                         'x2_slot': x2_slot, 'ike_copy': ike_index,
                                         'capsule': self._seal_for_user(x2, conn, inner)})
            if not self.ensure_session(x1, reason='authenticated MCC first hop'):
                continue
            with self.lock:
                self.priv_ab_state[context]['first_hops'].add(x1)
            message = {'auth_mcc': 1, 'mcc_session_id': context, 'req': self.name, 'x1': x1,
                       'x1_index': x1_slot, 'x1_fanout': x1_count, 'x2_fanout': x2_count,
                       'ike_fanout': ike_count, 'total_possible': expected, 'mcc_carry_ike': True,
                       'opaque_mcc': 1, 'ike_len': len(payload), 'branches': branches,
                       'expires_at': int(time.time()) + max(1, self._mcc_policy['deadline_ms'] // 1000)}
            for batch in self._opaque_start_batches(message):
                with self.lock:
                    self.mcc_opaque_pending[digest]['messages'].append((x1, batch))
                self.link_send(x1, T_MCC_START, jdump(batch), meta={'mode': 'mcc-ike'})
            sent += 1
        if not sent:
            raise MccSecurityError('no_first_hop')
        with self.lock:
            self.priv_ab_state[context]['auth_initial_messages'] = list(self.mcc_opaque_pending[digest]['messages'])

    def handle_MCC_START(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            if (msg.get('auth_mcc') != 1 or msg.get('opaque_mcc') != 1 or
                    msg.get('mcc_carry_ike') is not True or type(msg.get('x2_fanout')) is not int or
                    not 1 <= msg['x2_fanout'] <= 64 or type(msg.get('branches')) is not list or
                    len(msg['branches']) > 576):
                raise MccSecurityError('legacy_or_invalid_start')
            for branch in msg['branches']:
                if type(branch) is not dict or type(branch.get('x2_slot')) is not int or not 0 <= branch['x2_slot'] < msg['x2_fanout']:
                    raise MccSecurityError('invalid_copy_slot')
            self._auth_prune()
            with self.lock:
                if len(self.priv_x1_state) + len(msg['branches']) > MAX_ACTIVE * 4:
                    raise MccSecurityError('relay_capacity')
            super().handle_MCC_START(peer, plain)
        except (MccSecurityError, ValueError, KeyError, TypeError, InvalidTag):
            self._auth_reject('invalid_start')

    def handle_MCC_X2(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            if msg.get('auth_mcc') != 1 or msg.get('opaque_mcc') != 1:
                raise MccSecurityError('legacy_x2')
            conn = msg['conn_id']
            inner = self._open_seal_for_me(conn, msg['capsule'])
            if (inner.get('auth_mcc') != 1 or inner.get('conn_id') != conn or inner.get('x1') != peer or
                    inner.get('x2') != self.name or inner.get('dst') not in config.USERS or
                    inner.get('ab_context') != inner.get('mcc_session_id') or not inner.get('sealed_b')):
                raise MccSecurityError('invalid_x2_scope')
            with self.lock:
                old = self.priv_x2_state.get(conn)
                if old and (old['x1'] != peer or old['dst'] != inner['dst']):
                    raise MccSecurityError('conflicting_relay_branch')
                if old and old.get('queued_mcc_offers'):
                    return
                if not old:
                    if len(self.priv_x2_state) >= MAX_ACTIVE * 4:
                        raise MccSecurityError('relay_capacity')
                    self.priv_x2_state[conn] = {'x1': peer, 'dst': inner['dst'], 'created_at': time.time(),
                        'inline': True, 'mcc': True, 'mcc_carry_ike': True, 'opaque_mcc': 1,
                        'mcc_session_id': inner['mcc_session_id'], 'branch_id': inner['branch_id']}
            self._queue_mcc_x2_ike_offer(conn, inner, msg.get('total_possible', 0))
        except (MccSecurityError, ValueError, KeyError, TypeError, InvalidTag):
            self._auth_reject('invalid_x2')

    def _queue_mcc_x2_ike_offer(self, conn_id, inner, total_possible):
        # Relays may change this wrapper; B always opens and verifies sealed_b.
        offer = {key: inner[key] for key in ('auth_mcc', 'mcc_session_id', 'conn_id', 'branch_id',
                 'dst', 'opaque_mcc', 'ab_context', 'sealed_b')}
        offer.update(x2=self.name, total_possible=total_possible, inline=True, mcc_carry_ike=True)
        with self.lock:
            state = self.priv_x2_state[conn_id]
            seal = state.get('x1b_seal')
            if not seal:
                state.setdefault('queued_mcc_offers', []).append(offer)
                need_key = not state.get('bkey_requested')
                state['bkey_requested'] = True
            else:
                need_key = False
        if not seal:
            if need_key:
                # Uses the original routing-compatibility locator exchange.
                threading.Thread(target=self._request_priv_bkey, args=(conn_id, inner['dst']),
                                 daemon=True, name='mcc-auth-locator').start()
            return
        offer['x1b_seal'] = seal
        self._send_mcc_offer_to_dst(inner['dst'], offer, conn_id)

    def _prepare_priv_bkey_response(self, conn_id, x2_peer):
        if (not isinstance(conn_id, str) or len(conn_id) != 32 or
                any(c not in '0123456789abcdef' for c in conn_id) or x2_peer not in config.USERS):
            raise MccSecurityError('invalid_locator_request')
        now = time.time()
        with self.lock:
            for old_conn, state in list(self.priv_b_state.items()):
                if now - state.get('created_at', now) > 120:
                    self.priv_b_state.pop(old_conn, None)
            previous = self.priv_b_state.get(conn_id)
            if previous:
                if previous['x2'] != x2_peer:
                    raise MccSecurityError('conflicting_locator_request')
                return {'conn_id': conn_id, 'bke': xpub_bytes(previous['priv'].public_key()).hex()}
            if len(self.priv_b_state) >= MAX_ACTIVE * 4:
                raise MccSecurityError('locator_capacity')
        return super()._prepare_priv_bkey_response(conn_id, x2_peer)

    def handle_PRIV_BKEY_REQ(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            if set(msg) != {'conn_id'}:
                raise MccSecurityError('invalid_locator_schema')
            # The old routine calls the bounded, idempotent preparation above.
            super().handle_PRIV_BKEY_REQ(peer, plain)
        except (MccSecurityError, ValueError, KeyError, TypeError):
            self._auth_reject('invalid_locator_request')

    def handle_PRIV_BKEY_RESP(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            if set(msg) != {'conn_id', 'bke'} or not isinstance(msg['bke'], str) or len(msg['bke']) != 64:
                raise MccSecurityError('invalid_locator_response')
            with self.lock:
                x1 = self.priv_x1_state.get(msg['conn_id'])
                x2 = self.priv_x2_state.get(msg['conn_id'])
            if (x1 and peer != x1['x2']) or (not x1 and (not x2 or peer != x2['dst'])):
                raise MccSecurityError('wrong_locator_boundary')
            super().handle_PRIV_BKEY_RESP(peer, plain)
        except (MccSecurityError, ValueError, KeyError, TypeError):
            self._auth_reject('invalid_locator_response')

    def handle_PRIV_X1B_SEAL(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            with self.lock:
                state = self.priv_x2_state.get(msg.get('conn_id'))
            if not state or state['x1'] != peer:
                raise MccSecurityError('wrong_locator_seal_boundary')
            super().handle_PRIV_X1B_SEAL(peer, plain)
        except (MccSecurityError, ValueError, KeyError, TypeError):
            self._auth_reject('invalid_locator_seal')

    def _auth_validate_request(self, verified, *, initial):
        body = verified.body_dict()
        fields = {'ike_payload', 'ike_length', 'ike_src_ip', 'ike_src_port', 'ike_dst_ip',
                  'ike_dst_port', 'udp_port', 'a_to_b_ke', 'transport_conn', 'budget',
                  'selection', 'request_digest'}
        if set(body) != fields or canonical_json(body['selection']) != canonical_json(self._mcc_policy):
            raise MccSecurityError('invalid_protected_body')
        payload = self._auth_validate_ike(verified, body, response=False)
        if (body['ike_src_ip'] != config.USERS[verified.sender]['ip'] or
                body['ike_dst_ip'] != config.USERS[self.name]['ip'] or
                body['request_digest'] != hashlib.sha256(payload).hexdigest()):
            raise MccSecurityError('invalid_request_binding')
        budget = body['budget']
        if (type(budget) is not list or len(budget) != 3 or
                any(type(n) is not int or not 1 <= n <= 64 for n in budget) or
                budget[0] * budget[1] * budget[2] != verified.expected_copies or
                (not initial and (budget != [1, 1, 1] or verified.expected_copies != 1))):
            raise MccSecurityError('invalid_copy_budget')
        if not isinstance(body['transport_conn'], str) or len(body['transport_conn']) != 32:
            raise MccSecurityError('invalid_transport_binding')
        public = bytes.fromhex(body['a_to_b_ke'])
        if len(public) != 32 or public.hex() != body['a_to_b_ke']:
            raise MccSecurityError('invalid_endpoint_key')
        xpub_from_bytes(public)
        return body, payload

    def _auth_validate_ike(self, verified, body, *, response):
        if type(body.get('ike_length')) is not int or not 28 <= body['ike_length'] <= MAX_IKE:
            raise MccSecurityError('ike_size_limit')
        payload = bytes.fromhex(body['ike_payload'])
        if payload.hex() != body['ike_payload'] or len(payload) != body['ike_length']:
            raise MccSecurityError('ike_length_mismatch')
        for field in ('ike_src_port', 'ike_dst_port', 'udp_port'):
            if type(body.get(field)) is not int or body[field] not in (500, 4500):
                raise MccSecurityError('invalid_ike_port')
        if body['ike_src_port'] != body['udp_port'] or body['ike_dst_port'] != body['udp_port']:
            raise MccSecurityError('inconsistent_ike_ports')
        for field in ('ike_src_ip', 'ike_dst_ip'):
            if str(ipaddress.IPv4Address(body[field])) != body[field]:
                raise MccSecurityError('invalid_ike_address')
        header = self._opaque_ike_header(payload, body['udp_port'])
        if bool(header[19] & 0x20) != response or self._auth_message_id(header) != verified.message_id:
            raise MccSecurityError('invalid_ike_message_binding')
        return payload

    def handle_MCC_OFFER(self, peer, plain):
        if not self._mcc_verify_slots.acquire(blocking=False):
            self._auth_reject('verification_capacity')
            return
        try:
            msg = self._auth_read(plain)
            if msg.get('auth_mcc') != 1 or msg.get('opaque_mcc') != 1:
                raise MccSecurityError('legacy_offer')
            context = msg['mcc_session_id']
            record = self._auth_open_endpoint(msg['sealed_b'], context)
            verified = self.mcc_security.verify_signed(record, context, kind='initial')
            body, payload = self._auth_validate_request(verified, initial=True)
            if msg.get('conn_id') != body['transport_conn'] or msg.get('dst') != self.name or peer not in config.USERS:
                raise MccSecurityError('invalid_offer_scope')
            # Reject contradictory wrappers, while taking every authoritative
            # value from the signature. branch_id and outer count have no vote.
            for key in ('ike_payload', 'a_to_b_ke', 'ike_dst_ip', 'ike_dst_port', 'udp_port'):
                if key in msg and msg[key] != body[key]:
                    raise MccSecurityError('contradictory_wrapper')
            if msg.get('ab_context') != verified.context:
                raise MccSecurityError('invalid_endpoint_context')
            # All crypto and semantics precede dedup, candidate counters, timers,
            # route selection and endpoint state allocation.
            self._auth_prune()
            with self.lock:
                if verified.message_key not in self._mcc_auth_pending and len(self._mcc_auth_pending) >= MAX_ACTIVE:
                    raise MccSecurityError('endpoint_capacity')
                if (verified.message_key not in self._mcc_auth_pending and
                        sum(s['sender'] == verified.sender for s in self._mcc_auth_pending.values()) >= MAX_ACTIVE // 4):
                    raise MccSecurityError('sender_capacity')
            status = self.mcc_security.admit(verified)
            if status != 'new':
                if status == 'delivered':
                    self._auth_replay_response(verified, body)
                return
            offer = {'verified': verified, 'peer': peer, 'body': body, 'payload': payload}
            self._auth_enqueue(offer)
        except (MccSecurityError, ValueError, KeyError, TypeError, InvalidTag) as exc:
            self._auth_reject(getattr(exc, 'code', 'invalid_offer'))
        finally:
            self._mcc_verify_slots.release()

    def _auth_timer(self, key, delay, *, quiet=False):
        timer = threading.Timer(max(0.001, delay), self._select_MCC_offer, args=(key,))
        timer.daemon = True
        table = self._mcc_auth_quiet if quiet else self._mcc_auth_timers
        previous = table.get(key)
        if previous:
            previous.cancel()
        table[key] = timer
        timer.start()

    def _auth_enqueue(self, offer):
        verified = offer['verified']
        key = verified.message_key
        select = False
        with self.lock:
            state = self._mcc_auth_pending.setdefault(key, {'offers': [], 'expires': verified.expires,
                'expected': verified.expected_copies, 'fingerprint': verified.fingerprint, 'sender': verified.sender})
            if self.mcc_b_selected.get(key) or state.get('closed'):
                return
            state['offers'].append(offer)
            policy = offer['body']['selection']
            mode = policy['mode']
            if key not in self._mcc_auth_deadlines:
                wait_ms = policy['window_ms'] if mode == 'window' else policy['deadline_ms']
                self._mcc_auth_deadlines[key] = time.monotonic() + wait_ms / 1000
                if mode != 'first':
                    self._auth_timer(key, wait_ms / 1000)
            elif mode != 'first' and key not in self._mcc_auth_timers:
                remaining = self._mcc_auth_deadlines[key] - time.monotonic()
                if remaining <= 0:
                    # A known local refusal may leave no immediate reserve.
                    # A later verified ticket still gets the bounded retry;
                    # it cannot create a fresh or moving deadline.
                    select = True
                else:
                    self._auth_timer(key, remaining)
            if mode == 'first' or (mode == 'wait-all' and len(state['offers']) >= state['expected']):
                select = True
            elif mode == 'adaptive' and len(state['offers']) >= policy['min_copies']:
                if not policy['quiet_ms']:
                    select = True
                else:
                    # Only a NEW admitted signed ticket can reset quiet time.
                    remaining = self._mcc_auth_deadlines[key] - time.monotonic()
                    self._auth_timer(key, min(remaining, policy['quiet_ms'] / 1000), quiet=True)
        if select:
            self._select_MCC_offer(key)

    def _select_MCC_offer(self, message_key, *unused):
        with self.lock:
            for table in (self._mcc_auth_timers, self._mcc_auth_quiet):
                timer = table.pop(message_key, None)
                if timer:
                    timer.cancel()
            state = self._mcc_auth_pending.get(message_key)
            if not state or not state['offers'] or self.mcc_b_selected.get(message_key):
                return
            offers = state['offers']
            mode = offers[0]['body']['selection']['mode']
            selected = offers.pop(0 if mode == 'first' else random.randrange(len(offers)))
        self._accept_MCC_offer(message_key, selected)

    def _accept_MCC_offer(self, message_key, offer):
        verified = offer.get('verified')
        if not isinstance(verified, VerifiedMessage) or verified.message_key != message_key:
            self._auth_reject('unverified_selection')
            return
        with self.lock:
            if self.mcc_b_selected.get(message_key):
                return
            attempts = self._mcc_auth_attempts.get(message_key, 0)
            if attempts >= MAX_ATTEMPTS:
                self._mcc_auth_pending[message_key]['closed'] = True
                self._auth_reject('delivery_attempt_limit')
                return
            self._mcc_auth_attempts[message_key] = attempts + 1
        result = self._deliver_selected_mcc_ike_to_local(offer['peer'], offer)
        if result is False:
            # Only a known failure BEFORE injection permits another candidate.
            with self.lock:
                self.mcc_b_selected.pop(message_key, None)
                more = bool(self._mcc_auth_pending[message_key]['offers'])
            if more:
                self._select_MCC_offer(message_key)

    def _deliver_selected_mcc_ike_to_local(self, peer, offer):
        verified = offer.get('verified')
        if not isinstance(verified, VerifiedMessage):
            self._auth_reject('unverified_delivery')
            return False
        body, payload = self._auth_validate_request(verified, initial=True)
        from node_daemon import OverlayRoute
        route = OverlayRoute(conn_id=body['transport_conn'], src=verified.sender, dst=self.name,
            x1='', x2=peer, created_at=time.time(), privacy=True, ab_pub=body['a_to_b_ke'], inline=True,
            mcc_session_id=verified.context, mcc_branch_id=str(verified.copy_id),
            mcc_fanout=verified.expected_copies, ab_context=verified.context)
        pair = (verified.sender, verified.context)
        with self.lock:
            old = self._mcc_auth_sessions.get(pair)
            if old and old['conn'] != route.conn_id:
                raise MccSecurityError('conflicting_selected_route')
            if not old:
                if len(self._mcc_auth_sessions) >= MAX_ACTIVE:
                    raise MccSecurityError('endpoint_capacity')
                private = x25519.X25519PrivateKey.generate()
                shared = private.exchange(xpub_from_bytes(bytes.fromhex(route.ab_pub)))
                self._mcc_auth_sessions[pair] = {'conn': route.conn_id, 'peer': peer,
                    'src': verified.sender, 'a_pub': route.ab_pub, 'created_at': time.time(),
                    'expires': verified.expires, 'bke': xpub_bytes(private.public_key()).hex(),
                    'key': self._ab_key(shared, verified.context),
                    'forward_key': self._opaque_forward_key(shared, verified.context),
                    'route': route,
                    'requests': {verified.message_id: body['request_digest']},
                    'responses': {}, 'selected_copy': verified.copy_id,
                    'initiator_spi': self._opaque_ike_header(payload, body['udp_port'])[:8]}
        meta = self._auth_meta(verified, body, route, direction='fwd')
        result = self._auth_inject(verified, payload, meta)
        with self.lock:
            if result is False:
                self._mcc_auth_sessions.pop(pair, None)
            else:
                self.mcc_b_selected[verified.message_key] = route.conn_id
                if result is True:
                    self.mcc_b_delivered[verified.message_key] = route.conn_id
        return result

    @staticmethod
    def _auth_meta(verified, body, route, direction):
        meta = {key: body[key] for key in ('ike_src_ip', 'ike_src_port', 'ike_dst_ip', 'ike_dst_port', 'udp_port')}
        meta.update(kind='ike', privacy=True, inline=True, conn_id=route.conn_id, src=route.src,
                    dst=route.dst, x1=route.x1, x2=route.x2, dir=direction, idx=3,
                    phase='REAL_IKE_MCC_AUTH', ab_pub=route.ab_pub, ab_context=verified.context,
                    opaque_token=route.opaque_token, mcc_session_id=verified.context,
                    mcc_fanout=verified.expected_copies, mcc_branch_id='')
        return meta

    def _auth_inject(self, verified, payload, meta):
        body = verified.body_dict()
        if (body.get('ike_payload') != payload.hex() or body.get('ike_length') != len(payload) or
                any(meta.get(key) != body.get(key) for key in
                    ('ike_src_ip', 'ike_src_port', 'ike_dst_ip', 'ike_dst_port', 'udp_port')) or
                verified.receiver != self.name or
                (verified.direction == 'forward' and (meta.get('src') != verified.sender or meta.get('dst') != self.name)) or
                (verified.direction == 'reverse' and (meta.get('src') != self.name or meta.get('dst') != verified.sender))):
            self._auth_reject('delivery_proof_binding')
            return False
        proof = _LocalDeliveryProof(verified, bytes(payload), canonical_json(meta))
        previous = getattr(self._mcc_local, 'proof', None)
        self._mcc_local.proof = proof
        try:
            return self.deliver_ike_to_local_strongswan(payload, meta)
        finally:
            self._mcc_local.proof = previous

    def deliver_ike_to_local_strongswan(self, payload, meta):
        proof = getattr(self._mcc_local, 'proof', None)
        if (not isinstance(proof, _LocalDeliveryProof) or proof.used or
                not isinstance(proof.verified, VerifiedMessage) or proof.payload != payload or
                proof.meta != canonical_json(meta)):
            self._auth_reject('missing_local_delivery_proof')
            return False
        proof.used = True
        verified = proof.verified
        if not self.ike_proxy:
            return False
        try:
            if not self.mcc_security.claim_delivery(verified):
                return None
        except MccSecurityError as exc:
            # No injection was attempted, and no caller-owned claim exists.
            self._auth_reject(exc.code)
            return False
        from node_daemon import OverlayRoute
        route = OverlayRoute(conn_id=meta['conn_id'], src=meta['src'], dst=meta['dst'],
            x1=meta['x1'], x2=meta['x2'], created_at=time.time(), privacy=True,
            ab_pub=meta.get('ab_pub', ''), inline=True, mcc_session_id=verified.context,
            mcc_fanout=verified.expected_copies, ab_context=verified.context,
            opaque_token=meta.get('opaque_token', ''))
        with self.ike_route_lock:
            route_key = self._route_key(route.src, route.dst)
            previous = self.ike_routes.get(route_key)
            if previous and previous.ab_context == route.ab_context:
                route.created_at = previous.created_at
            self.ike_routes[route_key] = route
        try:
            outcome = self.ike_proxy.inject_to_charon(payload, meta)
        except Exception:
            # The adapter may have sent before raising. Keep the durable claim.
            self._auth_reject('injection_outcome_unknown')
            return None
        value = getattr(outcome, 'value', outcome)
        if outcome is True or value == 'sent':
            try:
                self.mcc_security.delivered(verified)
            except MccSecurityError:
                self._auth_reject('post_injection_ledger_failure')
                return None
            return True
        if outcome is False or value == 'rejected':
            try:
                self.mcc_security.failed_delivery(verified)
            except MccSecurityError:
                self._auth_reject('delivery_claim_release_failed')
                return None
            with self.ike_route_lock:
                if self.ike_routes.get(route_key) is route:
                    if previous:
                        self.ike_routes[route_key] = previous
                    else:
                        self.ike_routes.pop(route_key, None)
            return False
        self._auth_reject('injection_outcome_unknown')
        return None

    def _opaque_seal_back(self, route, payload, src_ip, src_port, dst_ip, dst_port, udp_port):
        with self.lock:
            state = self._mcc_auth_sessions.get((route.src, route.ab_context))
        header = self._opaque_ike_header(payload, udp_port)
        msg_id = self._auth_message_id(header)
        if (not state or state['conn'] != route.conn_id or not header[19] & 0x20 or
                header[:8] != state['initiator_spi'] or msg_id not in state['requests']):
            raise MccSecurityError('unbound_local_response')
        body = {'ike_payload': payload.hex(), 'ike_length': len(payload),
                'ike_src_ip': src_ip, 'ike_src_port': src_port, 'ike_dst_ip': dst_ip,
                'ike_dst_port': dst_port, 'udp_port': udp_port,
                'bke': state['bke'], 'a_to_b_ke': state['a_pub'],
                'request_digest': state['requests'][msg_id]}
        record = self.mcc_security.signed_message(route.src, route.ab_context, body, 0, 1,
            direction='reverse', kind='response', message_id=msg_id)
        nonce, ct = aesgcm_encrypt(state['key'], jdump(record), aad=f'priv-b-a:{route.ab_context}'.encode())
        with self.lock:
            state['responses'][msg_id] = (bytes(payload), src_ip, src_port, dst_ip, dst_port, udp_port)
        return {'mode': 'x25519', 'auth_mcc': 1, 'v': 2, 'conn_id': route.ab_context,
                'bke': state['bke'], 'nonce': nonce.hex(), 'ct': self._auth_encode_ct(ct)}

    def _auth_replay_response(self, verified, body):
        with self.lock:
            state = self._mcc_auth_sessions.get((verified.sender, verified.context))
            if not state or state['requests'].get(verified.message_id) != body['request_digest']:
                return
            if verified.kind == 'initial' and (state['conn'] != body['transport_conn'] or
                                                state['selected_copy'] != verified.copy_id):
                return
            cached = state['responses'].get(verified.message_id)
        if cached:
            # Replay the existing real response only; never inject this request
            # into charon twice and never add a route-confirmation round.
            self._send_priv_ike_back(state['route'], *cached)

    def _open_back_for_a(self, context, seal):
        if (set(seal) != {'mode', 'auth_mcc', 'v', 'conn_id', 'bke', 'nonce', 'ct'} or
                type(seal['v']) is not int or seal['v'] != 2 or
                seal.get('mode') != 'x25519' or seal.get('auth_mcc') != 1 or seal.get('conn_id') != context):
            raise MccSecurityError('invalid_reverse_capsule')
        encoded = {}
        for key, length in (('bke', 32), ('nonce', 12)):
            encoded[key] = self._auth_hex(seal[key], length)
        encoded['ct'] = self._auth_decode_ct(seal['ct'])
        with self.lock:
            state = self.priv_ab_state.get(context)
        if not state:
            raise MccSecurityError('no_pending_request')
        shared = state['priv'].exchange(xpub_from_bytes(encoded['bke']))
        raw = aesgcm_decrypt(self._ab_key(shared, context), encoded['nonce'], encoded['ct'],
                             aad=f'priv-b-a:{context}'.encode())
        # Do not let the old permissive jload erase duplicated fields before
        # the strict signature parser sees the decrypted response.
        return strict_json_loads(raw, max_bytes=MAX_PLAINTEXT)

    def _opaque_handle_back(self, peer, msg):
        if msg.get('leg') != 'x1-a':
            # Existing relay code only forwards opaque bytes and creates a
            # local route handle. It cannot authenticate or select endpoints.
            return super()._opaque_handle_back(peer, msg)
        if set(msg) != {'opaque_mcc', 'leg', 'conn_id', 'route_token', 'sealed_a'} or msg.get('opaque_mcc') != 1:
            raise MccSecurityError('invalid_response_schema')
        seal = msg['sealed_a']
        context = msg['conn_id']
        token = msg['route_token']
        if (seal.get('auth_mcc') != 1 or seal.get('conn_id') != context or
                not isinstance(token, str) or len(token) != 64 or any(c not in '0123456789abcdef' for c in token)):
            raise MccSecurityError('invalid_response_scope')
        with self.lock:
            state = self.priv_ab_state.get(context)
        if not state or not state.get('opaque_mcc') or peer not in state['first_hops']:
            raise MccSecurityError('no_pending_request')
        # Decryption does NOT authenticate bke; the signed inner B record does.
        record = self._open_back_for_a(context, seal)
        verified = self.mcc_security.verify_signed(record, context, expected_sender=state['dst'],
                                                   direction='reverse', kind='response')
        body = verified.body_dict()
        if set(body) != {'ike_payload', 'ike_length', 'ike_src_ip', 'ike_src_port', 'ike_dst_ip',
                         'ike_dst_port', 'udp_port', 'bke', 'a_to_b_ke', 'request_digest'}:
            raise MccSecurityError('invalid_response_body')
        if verified.expected_copies != 1 or verified.copy_id != 0:
            raise MccSecurityError('invalid_response_copy_budget')
        payload = self._auth_validate_ike(verified, body, response=True)
        header = self._opaque_ike_header(payload, body['udp_port'])
        if (body['bke'] != seal['bke'] or body['a_to_b_ke'] != state['pub'] or
                body['ike_src_ip'] != config.USERS[state['dst']]['ip'] or
                body['ike_dst_ip'] != config.USERS[self.name]['ip'] or
                state.get('auth_requests', {}).get(verified.message_id) != body['request_digest'] or
                header[:8] != state['initiator_spi']):
            raise MccSecurityError('response_request_binding')
        with self.lock:
            existing = self._mcc_auth_a_routes.get((state['dst'], header[:8]))
        if existing and (existing.ab_context != context or existing.x1 != peer or existing.opaque_token != token):
            raise MccSecurityError('late_response_route_change')
        if not existing and (header[:8], header[18], header[20:24]) != state['first_request']:
            raise MccSecurityError('unrelated_initial_response')
        if self.mcc_security.admit(verified) != 'new':
            return
        shared = state['priv'].exchange(xpub_from_bytes(bytes.fromhex(body['bke'])))
        from node_daemon import OverlayRoute
        route = OverlayRoute(conn_id=context, src=self.name, dst=state['dst'], x1=peer, x2='',
            created_at=time.time(), privacy=True, inline=True, ab_context=context, opaque_token=token)
        meta = self._auth_meta(verified, body, route, direction='back')
        # All signature/request/copy/route checks and durable admission above
        # have passed. Publish this authenticated route before UDP injection:
        # real charon may emit IKE_AUTH on another capture thread immediately,
        # while the sink is still recording its delivery result. Publishing
        # after injection accidentally started a second MCC context for AUTH.
        route_key = (state['dst'], header[:8])
        with self.lock:
            previous = self._mcc_auth_a_routes.get(route_key)
            if previous and (previous.ab_context != context or previous.x1 != peer or previous.opaque_token != token):
                raise MccSecurityError('late_response_route_change')
            previous_key = state.get('forward_key')
            state['forward_key'] = self._opaque_forward_key(shared, context)
            self._mcc_auth_a_routes[route_key] = route
        result = self._auth_inject(verified, payload, meta)
        if result is False:
            # Only a confirmed pre-send refusal can undo publication. Unknown
            # outcomes retain route/key, just like the durable in-flight claim.
            with self.lock:
                if self._mcc_auth_a_routes.get(route_key) is route:
                    if previous is None:
                        self._mcc_auth_a_routes.pop(route_key, None)
                    else:
                        self._mcc_auth_a_routes[route_key] = previous
                    if previous_key is None:
                        state.pop('forward_key', None)
                    else:
                        state['forward_key'] = previous_key

    def _opaque_send_forward(self, route, payload, src_ip, src_port, dst_ip, dst_port, udp_port):
        with self.lock:
            state = self.priv_ab_state.get(route.ab_context)
        if not state or not state.get('forward_key'):
            raise MccSecurityError('no_authenticated_continuation_key')
        header = self._opaque_ike_header(payload, udp_port)
        if header[19] & 0x20:
            raise MccSecurityError('continuation_requires_request')
        msg_id = self._auth_message_id(header)
        body = self._auth_body(payload, src_ip, src_port, dst_ip, dst_port, udp_port,
                               state['pub'], route.conn_id, (1, 1, 1))
        with self.lock:
            if msg_id not in state['auth_requests'] and len(state['auth_requests']) >= MAX_REQUESTS:
                raise MccSecurityError('request_capacity')
        record = self.mcc_security.signed_message(route.dst, route.ab_context, body, 0, 1,
                                                  kind='continuation', message_id=msg_id)
        with self.lock:
            state['auth_requests'][msg_id] = body['request_digest']
        nonce, ct = aesgcm_encrypt(state['forward_key'], jdump(record), aad=f'mcc-a-b-fwd:{route.ab_context}'.encode())
        outgoing = {'opaque_mcc': 1, 'leg': 'a-x1', 'conn_id': route.ab_context,
                    'route_token': route.opaque_token,
                    'sealed_fwd': {'v': 2, 'context': route.ab_context, 'nonce': nonce.hex(), 'ct': self._auth_encode_ct(ct),
                                   'key_tag': self._auth_forward_tag(state['forward_key'])}}
        self._opaque_send(route.x1, T_MCC_OPAQUE_FWD, outgoing)

    @staticmethod
    def _auth_forward_tag(key):
        # A short secret-derived lookup tag exposes no sender identity. It also
        # prevents a valid intermediary's SAME raw context/conn from making B's
        # lookup ambiguous for the separate authenticated A exchange.
        return hashlib.sha256(b'mcc-auth-forward-lookup-v1:' + key).hexdigest()[:32]

    def handle_MCC_OPAQUE_FWD(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            if msg.get('leg') != 'x2-b':
                return super().handle_MCC_OPAQUE_FWD(peer, plain)
            if msg.get('opaque_mcc') != 1 or set(msg) != {'opaque_mcc', 'leg', 'conn_id', 'sealed_fwd'}:
                raise MccSecurityError('invalid_continuation_schema')
            seal = msg['sealed_fwd']
            if (type(seal) is not dict or set(seal) != {'v', 'context', 'nonce', 'ct', 'key_tag'} or
                    type(seal['v']) is not int or seal['v'] != 2):
                raise MccSecurityError('invalid_forward_wire_seal')
            context = seal['context']
            with self.lock:
                candidates = [state for (sender, ctx), state in self._mcc_auth_sessions.items()
                              if ctx == context and state['conn'] == msg['conn_id'] and state['peer'] == peer
                              and self._auth_forward_tag(state['forward_key']) == seal.get('key_tag')]
            if len(candidates) != 1:
                raise MccSecurityError('no_selected_continuation_route')
            state = candidates[0]
            raw = aesgcm_decrypt(state['forward_key'], self._auth_hex(seal['nonce'], 12), self._auth_decode_ct(seal['ct']),
                                aad=f'mcc-a-b-fwd:{context}'.encode())
            verified = self.mcc_security.verify_signed(raw, context, expected_sender=state['src'], kind='continuation')
            body, payload = self._auth_validate_request(verified, initial=False)
            if body['a_to_b_ke'] != state['a_pub'] or body['transport_conn'] != context:
                raise MccSecurityError('changed_continuation_key')
            route = state['route']
            if (route.conn_id != state['conn'] or route.ab_context != context or
                    time.time() - route.created_at > 120):
                raise MccSecurityError('expired_continuation_route')
            if len(state['requests']) >= MAX_REQUESTS and verified.message_id not in state['requests']:
                raise MccSecurityError('request_capacity')
            status = self.mcc_security.admit(verified)
            if status != 'new':
                if status == 'delivered':
                    self._auth_replay_response(verified, body)
                return
            state['requests'][verified.message_id] = body['request_digest']
            self._auth_inject(verified, payload, self._auth_meta(verified, body, route, direction='fwd'))
        except (MccSecurityError, ValueError, KeyError, TypeError, InvalidTag) as exc:
            self._auth_reject(getattr(exc, 'code', 'invalid_continuation'))

    # Protected profile has one endpoint ingress. These sibling legacy formats
    # cannot select a route, mutate success state or reach the common IKE sink.
    def handle_PROXY(self, peer, plain, meta):
        self._auth_reject('legacy_proxy_disabled')

    def handle_PRIV_DELIVER(self, peer, plain):
        self._auth_reject('legacy_deliver_disabled')

    def handle_PRIV_FWD(self, peer, plain):
        self._auth_reject('legacy_forward_disabled')

    def handle_PRIV_INLINE_START(self, peer, plain):
        self._auth_reject('legacy_inline_disabled')

    def handle_PRIV_INLINE_X2(self, peer, plain):
        self._auth_reject('legacy_inline_disabled')

    def handle_MCC_ACCEPT(self, peer, plain):
        self._auth_reject('legacy_accept_disabled')

    def handle_I1(self, peer, plain):
        self._auth_reject('legacy_route_setup_disabled')

    def handle_I2(self, peer, plain):
        self._auth_reject('legacy_route_setup_disabled')

    def handle_OKX2(self, peer, plain):
        self._auth_reject('legacy_route_setup_disabled')

    def on_local_connect(self, packet, src):
        self._auth_reject('legacy_demo_connect_disabled')

    def on_error(self, packet, peer):
        self._auth_reject('unauthenticated_error_ignored')

    def handle_PRIV_BACK(self, peer, plain):
        try:
            msg = self._auth_read(plain)
            if msg.get('opaque_mcc') != 1:
                raise MccSecurityError('legacy_reverse_disabled')
            self._opaque_handle_back(peer, msg)
        except (MccSecurityError, ValueError, KeyError, TypeError, InvalidTag) as exc:
            self._auth_reject(getattr(exc, 'code', 'invalid_response'))
