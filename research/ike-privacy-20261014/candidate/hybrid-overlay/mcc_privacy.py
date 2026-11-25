"""MCC real-IKE continuation without revealing the selected X2 to initiator A.

Reuse the existing X25519/HKDF/AES-GCM primitives and hop management sessions.
Initial capsules cover the candidate directory; only X1 chooses its X2 fanout.
The encrypted real response, not a route ACCEPT, completes the initiator route.
This separates logical roles, not the memory of co-located physical processes.
"""
import hashlib
import secrets
import time

from cryptography.hazmat.primitives.asymmetric import x25519

from config import USERS, ACTIVE_USERS, IKE_ROUTE_CACHE_TTL_S, IKE_MCC_ROUTE_TIMEOUT_S
from crypto_util import aesgcm_encrypt, aesgcm_decrypt, hkdf_sha256, xpub_bytes, xpub_from_bytes
from protocol import jdump, jload, T_PRIV_BACK, T_MCC_OPAQUE_FWD


class MccOpaqueMixin:
    def _init_opaque_mcc(self):
        self.mcc_opaque_handles = {}
        self.mcc_opaque_b_keys = {}
        self.mcc_opaque_pending = {}
        self.mcc_opaque_x1_selection = {}

    @staticmethod
    def _opaque_forward_key(shared, context):
        return hkdf_sha256(shared, salt=context.encode(),
                           info=b'mcc-a-b-forward-v1', length=32)

    @staticmethod
    def _opaque_ike_header(payload, udp_port):
        if udp_port not in (500, 4500):
            raise ValueError('Invalid IKE UDP service')
        offset = 4 if udp_port == 4500 else 0
        if offset and payload[:4] != b'\x00' * 4:
            raise ValueError('Missing Non-ESP marker')
        header = payload[offset:]
        if len(header) < 28 or header[17] >> 4 != 2:
            raise ValueError('Invalid IKEv2 header')
        if int.from_bytes(header[24:28], 'big') != len(header):
            raise ValueError('Invalid IKE length')
        return header

    def _opaque_prune(self):
        now = time.time()
        with self.lock:
            for token, state in list(self.mcc_opaque_handles.items()):
                if now - state['created_at'] > IKE_ROUTE_CACHE_TTL_S:
                    self.mcc_opaque_handles.pop(token, None)
            for context, state in list(self.priv_ab_state.items()):
                if state.get('opaque_mcc') and now - state['created_at'] > IKE_ROUTE_CACHE_TTL_S:
                    self.priv_ab_state.pop(context, None)
            for context, state in list(self.mcc_opaque_x1_selection.items()):
                if now - state['created_at'] > IKE_ROUTE_CACHE_TTL_S:
                    self.mcc_opaque_x1_selection.pop(context, None)
            for context, state in list(self.mcc_opaque_b_keys.items()):
                if now - state['created_at'] > IKE_ROUTE_CACHE_TTL_S:
                    self.mcc_opaque_b_keys.pop(context, None)
                    self.mcc_b_selected.pop(context, None)
                    self.mcc_b_delivered.pop(context, None)
            for digest, state in list(self.mcc_opaque_pending.items()):
                if now - state['created_at'] > IKE_MCC_ROUTE_TIMEOUT_S:
                    self.mcc_opaque_pending.pop(digest, None)
                    context = state['context']
                    ab = self.priv_ab_state.get(context)
                    if ab and not ab.get('forward_key'):
                        self.priv_ab_state.pop(context, None)
            for table in (self.priv_x1_state, self.priv_x2_state):
                for conn, state in list(table.items()):
                    if state.get('opaque_mcc') and now - state['created_at'] > IKE_ROUTE_CACHE_TTL_S:
                        table.pop(conn, None)
                        self.priv_b_state.pop(conn, None)

    def _opaque_drop_context(self, context):
        if not context:
            return
        with self.lock:
            self.mcc_opaque_b_keys.pop(context, None)
            self.priv_ab_state.pop(context, None)
            self.mcc_opaque_x1_selection.pop(context, None)
            for token, state in list(self.mcc_opaque_handles.items()):
                if state['context'] == context:
                    self.mcc_opaque_handles.pop(token, None)
            for digest, state in list(self.mcc_opaque_pending.items()):
                if state['context'] == context:
                    self.mcc_opaque_pending.pop(digest, None)

    def _opaque_prepare_initial(self, dst, payload, udp_port):
        self._opaque_prune()
        header = self._opaque_ike_header(payload, udp_port)
        if header[19] & 0x20:
            raise ValueError('A new MCC route requires a real IKE request')
        digest = hashlib.sha256(dst.encode() + bytes([udp_port // 256, udp_port % 256]) + payload).hexdigest()
        with self.lock:
            previous = self.mcc_opaque_pending.get(digest)
        if previous:
            for peer, message in previous['messages']:
                self.link_send(peer, 'MCC_START', jdump(message), meta={'mode': 'mcc-ike'})
            return digest, previous['context'], True
        context = secrets.token_hex(16)
        self._ensure_priv_ab_pub(context, dst)
        with self.lock:
            self.priv_ab_state[context].update(
                opaque_mcc=True, initiator_spi=header[:8], udp_port=udp_port,
                first_request=(header[:8], header[18], header[20:24]),
                requests={(header[:8], header[18], header[20:24])},
                first_hops=set(), created_at=time.time())
            self.mcc_opaque_pending[digest] = {
                'context': context, 'created_at': time.time(), 'messages': []}
        return digest, context, False

    def _opaque_select_x2(self, req, context, fanout):
        self._opaque_prune()
        with self.lock:
            existing = self.mcc_opaque_x1_selection.get(context)
        if existing:
            if existing['req'] != req:
                raise ValueError('Conflicting MCC requester')
            return list(existing['selected'])
        # Selection is independent of capsule batching and remains fixed across
        # retransmissions. A cannot infer it from capsule order or an early batch.
        candidates = [p for p in ACTIVE_USERS if p != self.name]
        selected = self._ordered_route_candidates(candidates, 'IKE_DEBUG_FORCE_X2', 'X2')[:max(1, min(fanout, len(candidates)))]
        with self.lock:
            existing = self.mcc_opaque_x1_selection.setdefault(context, {
                'req': req, 'selected': selected, 'created_at': time.time()})
            if existing['req'] != req:
                raise ValueError('Conflicting MCC requester')
        return list(existing['selected'])

    @staticmethod
    def _opaque_start_batches(message):
        # The link envelope hex-encodes its AEAD ciphertext, approximately
        # doubling plaintext bytes. Stay below the IPv4 UDP payload limit.
        base = dict(message)
        branches = base.pop('branches')
        batches, current = [], []
        for branch in branches:
            trial = dict(base, branches=current + [branch])
            if len(jdump(trial)) > 28000:
                if not current:
                    raise ValueError('One MCC capsule exceeds the UDP budget')
                batches.append(dict(base, branches=current))
                current = [branch]
                if len(jdump(dict(base, branches=current))) > 28000:
                    raise ValueError('One MCC capsule exceeds the UDP budget')
            else:
                current.append(branch)
        if current:
            batches.append(dict(base, branches=current))
        return batches

    def _opaque_seal_back(self, route, payload, src_ip, src_port, dst_ip, dst_port, udp_port):
        context = route.ab_context
        with self.lock:
            key_state = self.mcc_opaque_b_keys.get(context)
            if not key_state:
                private = x25519.X25519PrivateKey.generate()
                shared = private.exchange(xpub_from_bytes(bytes.fromhex(route.ab_pub)))
                key_state = {
                    'key': self._ab_key(shared, context),
                    'forward_key': self._opaque_forward_key(shared, context),
                    'bke': xpub_bytes(private.public_key()).hex(),
                    'src': route.src, 'conn_id': route.conn_id,
                    'created_at': time.time()}
                self.mcc_opaque_b_keys[context] = key_state
            if key_state['conn_id'] != route.conn_id or key_state['src'] != route.src:
                raise ValueError('MCC endpoint context changed branch')
        body = {'src': route.src, 'dst': route.dst, 'ike_payload': payload.hex(),
                'ike_src_ip': src_ip, 'ike_src_port': src_port,
                'ike_dst_ip': dst_ip, 'ike_dst_port': dst_port, 'udp_port': udp_port}
        nonce, ct = aesgcm_encrypt(key_state['key'], jdump(body),
                                   aad=f'priv-b-a:{context}'.encode())
        with self.lock:
            key_state['last_response'] = (bytes(payload), src_ip, src_port, dst_ip, dst_port, udp_port)
        return {'mode': 'x25519', 'conn_id': context, 'bke': key_state['bke'],
                'nonce': nonce.hex(), 'ct': ct.hex()}

    def _opaque_replay_response(self, context, conn):
        with self.lock:
            state = self.mcc_opaque_b_keys.get(context)
            cached = state.get('last_response') if state else None
        if not state or state['conn_id'] != conn or not cached:
            return
        # Retry the real cached response, not a second route confirmation or
        # a second injection of every fanout copy into charon.
        route = self._get_cached_route(state['src'], self.name)
        if route and route.conn_id == conn and route.ab_context == context:
            self._send_priv_ike_back(route, *cached)

    def _opaque_send(self, peer, message_type, message):
        if peer == self.name:
            # Only B==X2 is an adjacent repeated role; consume, never send to self.
            if message_type == T_MCC_OPAQUE_FWD:
                self.handle_MCC_OPAQUE_FWD(self.name, jdump(message))
            elif message_type == T_PRIV_BACK:
                self.handle_PRIV_BACK(self.name, jdump(message))
            else:
                raise ValueError('Unsupported local logical hop')
            return
        if not self.ensure_session(peer, reason='opaque MCC adjacent hop'):
            raise ValueError('Opaque MCC adjacent session unavailable')
        self.link_send(peer, message_type, jdump(message), meta={'mode': 'mcc-opaque'})

    def _opaque_handle_back(self, peer, msg):
        self._opaque_prune()
        if msg.get('opaque_mcc') != 1:
            raise ValueError('Unsupported MCC privacy version')
        conn = msg.get('conn_id', '')
        sealed = msg.get('sealed_a', {})
        context = sealed.get('conn_id', '')
        leg = msg.get('leg')
        with self.lock:
            x2 = self.priv_x2_state.get(conn)
            x1 = self.priv_x1_state.get(conn)
        if leg == 'b-x2':
            if not x2 or not x2.get('opaque_mcc') or peer != x2.get('dst'):
                raise ValueError('Wrong reverse X2 boundary')
            if context != x2.get('mcc_session_id'):
                raise ValueError('Reverse endpoint context mismatch')
            outgoing = {'opaque_mcc': 1, 'leg': 'x2-x1',
                        'conn_id': conn, 'sealed_a': sealed}
            self._opaque_send(x2['x1'], T_PRIV_BACK, outgoing)
            return
        if leg == 'x2-x1':
            if not x1 or not x1.get('opaque_mcc') or peer != x1.get('x2'):
                raise ValueError('Wrong reverse X1 boundary')
            if context != x1.get('mcc_session_id'):
                raise ValueError('Reverse endpoint context mismatch')
            with self.lock:
                token = x1.get('opaque_token')
                if not token:
                    token = secrets.token_hex(32)
                    x1['opaque_token'] = token
                    self.mcc_opaque_handles[token] = {
                        'context': context, 'conn_id': conn, 'req': x1['req'],
                        'x2': x1['x2'], 'created_at': x1['created_at']}
            outgoing = {'opaque_mcc': 1, 'leg': 'x1-a', 'conn_id': context,
                        'route_token': token, 'sealed_a': sealed}
            self._opaque_send(x1['req'], T_PRIV_BACK, outgoing)
            return
        if leg != 'x1-a' or set(msg) != {'opaque_mcc', 'leg', 'conn_id', 'route_token', 'sealed_a'}:
            raise ValueError('Invalid final MCC response schema')
        token = msg['route_token']
        if not isinstance(token, str) or len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
            raise ValueError('Invalid opaque handle')
        if conn != context or sealed.get('mode') != 'x25519':
            raise ValueError('Invalid final endpoint context')
        with self.lock:
            state = self.priv_ab_state.get(context)
        if not state or not state.get('opaque_mcc') or peer not in state['first_hops']:
            raise ValueError('No pending MCC request from this first hop')
        if time.time() - state['created_at'] > IKE_ROUTE_CACHE_TTL_S:
            raise ValueError('Expired MCC endpoint context')
        existing = self._get_cached_route(self.name, state['dst'])
        if existing and existing.opaque_token and (
                existing.ab_context != context or existing.x1 != peer or existing.opaque_token != token):
            raise ValueError('Late response cannot replace the selected route')
        opened = self._open_back_for_a(context, sealed)
        if opened.get('src') != self.name or opened.get('dst') != state['dst']:
            raise ValueError('Reverse endpoint binding mismatch')
        payload = bytes.fromhex(opened['ike_payload'])
        header = self._opaque_ike_header(payload, opened['udp_port'])
        request_key = (header[:8], header[18], header[20:24])
        if request_key not in state['requests'] or not header[19] & 0x20:
            raise ValueError('Unrelated IKE response')
        if not existing and request_key != state['first_request']:
            raise ValueError('Only the pending real IKE response completes a new route')
        shared = state['priv'].exchange(xpub_from_bytes(bytes.fromhex(sealed['bke'])))
        with self.lock:
            state['forward_key'] = self._opaque_forward_key(shared, context)
        meta = dict(opened)
        meta.pop('ike_payload', None)
        meta.update(kind='ike', privacy=True, inline=True, conn_id=context,
                    src=self.name, dst=state['dst'], x1=peer, x2='',
                    ab_context=context, opaque_token=token, dir='back', idx=3,
                    phase='REAL_IKE_MCC_OPAQUE')
        self.deliver_ike_to_local_strongswan(payload, meta)

    def _opaque_send_forward(self, route, payload, src_ip, src_port, dst_ip, dst_port, udp_port):
        self._opaque_prune()
        with self.lock:
            state = self.priv_ab_state.get(route.ab_context)
        if not state or not state.get('forward_key'):
            raise ValueError('No ready A-B continuation key')
        header = self._opaque_ike_header(payload, udp_port)
        if header[19] & 0x20:
            raise ValueError('A continuation must contain an IKE request')
        with self.lock:
            request_key = (header[:8], header[18], header[20:24])
            if len(state['requests']) >= 1024 and request_key not in state['requests']:
                raise ValueError('MCC request correlation budget exhausted')
            state['requests'].add(request_key)
        body = {'src': self.name, 'dst': route.dst, 'ike_payload': payload.hex(),
                'ike_src_ip': src_ip, 'ike_src_port': src_port,
                'ike_dst_ip': dst_ip, 'ike_dst_port': dst_port, 'udp_port': udp_port}
        nonce, ct = aesgcm_encrypt(state['forward_key'], jdump(body),
                                   aad=f'mcc-a-b-fwd:{route.ab_context}'.encode())
        outgoing = {'opaque_mcc': 1, 'leg': 'a-x1', 'conn_id': route.ab_context,
                    'route_token': route.opaque_token,
                    'sealed_fwd': {'context': route.ab_context, 'nonce': nonce.hex(), 'ct': ct.hex()}}
        self._opaque_send(route.x1, T_MCC_OPAQUE_FWD, outgoing)

    def handle_MCC_OPAQUE_FWD(self, peer, plain):
        try:
            self._opaque_prune()
            msg = jload(plain)
            if msg.get('opaque_mcc') != 1:
                raise ValueError('Unsupported MCC privacy version')
            conn = msg.get('conn_id', '')
            seal = msg.get('sealed_fwd', {})
            context = seal.get('context', '')
            if msg.get('leg') == 'a-x1':
                if set(msg) != {'opaque_mcc', 'leg', 'conn_id', 'route_token', 'sealed_fwd'}:
                    raise ValueError('Invalid initiator continuation schema')
                with self.lock:
                    handle = self.mcc_opaque_handles.get(msg.get('route_token'))
                if not handle or handle['req'] != peer or handle['context'] != conn or context != conn:
                    raise ValueError('Unknown or foreign continuation handle')
                outgoing = {'opaque_mcc': 1, 'leg': 'x1-x2',
                            'conn_id': handle['conn_id'], 'sealed_fwd': seal}
                self._opaque_send(handle['x2'], T_MCC_OPAQUE_FWD, outgoing)
                return
            if msg.get('leg') == 'x1-x2':
                with self.lock:
                    state = self.priv_x2_state.get(conn)
                if not state or not state.get('opaque_mcc') or state['x1'] != peer or state['mcc_session_id'] != context:
                    raise ValueError('Wrong continuation X2 boundary')
                outgoing = {'opaque_mcc': 1, 'leg': 'x2-b', 'conn_id': conn, 'sealed_fwd': seal}
                self._opaque_send(state['dst'], T_MCC_OPAQUE_FWD, outgoing)
                return
            if msg.get('leg') != 'x2-b':
                raise ValueError('Invalid continuation stage')
            with self.lock:
                state = self.mcc_opaque_b_keys.get(context)
            if not state or state['conn_id'] != conn:
                raise ValueError('No selected recipient context')
            route = self._get_cached_route(state['src'], self.name)
            if not route or route.conn_id != conn or route.x2 != peer or route.ab_context != context:
                raise ValueError('Wrong recipient continuation boundary')
            opened = jload(aesgcm_decrypt(state['forward_key'], bytes.fromhex(seal['nonce']),
                                         bytes.fromhex(seal['ct']), aad=f'mcc-a-b-fwd:{context}'.encode()))
            if opened.get('src') != state['src'] or opened.get('dst') != self.name:
                raise ValueError('Forward endpoint binding mismatch')
            payload = bytes.fromhex(opened['ike_payload'])
            header = self._opaque_ike_header(payload, opened['udp_port'])
            if header[19] & 0x20:
                raise ValueError('A forward record must contain an IKE request')
            meta = dict(opened)
            meta.pop('ike_payload', None)
            meta.update(kind='ike', privacy=True, inline=True, conn_id=conn,
                        x1='', x2=peer, ab_pub=route.ab_pub, ab_context=context,
                        dir='fwd', idx=3, phase='REAL_IKE_MCC_OPAQUE')
            self.deliver_ike_to_local_strongswan(payload, meta)
        except Exception:
            # Do not include peer names, ciphertext, keys or branch IDs in a rejection.
            self.logger.warning('[MCC/OPAQUE] rejected continuation')
