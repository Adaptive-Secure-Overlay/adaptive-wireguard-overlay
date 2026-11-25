"""Local active-route security invariants, NOT live IKE/ESP acceptance."""
import copy
import hashlib
import json
from pathlib import Path
import random
import sys
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness_mcc_auth import Harness, M, AUTH, CORE, TRUST, ADAPTER, ike


class IntegrationTests(unittest.TestCase):
    def make(self, **kwargs):
        harness = Harness(**kwargs)
        self.addCleanup(harness.close)
        return harness

    def finish(self, h):
        h.pump()
        h.advance(2)

    def test_nine_valid_in_all_modes_then_ike_auth(self):
        for mode in ('first', 'window', 'adaptive', 'wait-all'):
            for port in (500, 4500):
                with self.subTest(mode=mode, port=port):
                    h = self.make(mode=mode, port=port)
                    with patch('socket.socket', side_effect=AssertionError('No live socket')):
                        h.start(); self.finish(h)
                        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])
                        h.auth(); h.pump()
                    self.assertEqual([n for n, _, _ in h.injections], ['B', 'A', 'B', 'A'])
                    self.assertEqual(len(h.offers()), 9)
                    self.assertEqual(h.selected_count(), 1)
                    self.assertFalse(any(e[2]['t'] == 'MCC_ACCEPT' for e in h.wire))
                    route = h.nodes['A']._get_cached_route('A', 'B')
                    self.assertEqual(route.x2, '')
                    self.assertTrue(route.opaque_token)
                    internal = {e[3]['conn_id'] for e in h.wire if e[2]['t'] == 'MCC_X2'}
                    self.assertNotIn(route.conn_id, internal)
                    h.close()

    def test_one_and_three_equal_substitutions_first_and_last_all_modes(self):
        for mode in ('first', 'window', 'adaptive', 'wait-all'):
            for bad in (1, 3):
                for bad_first in (False, True):
                    with self.subTest(mode=mode, bad=bad, first=bad_first):
                        h = self.make(mode=mode)
                        counts = {'offer': 0}

                        def intercept(src, dst, env, plain):
                            if env['t'] != 'MCC_OFFER':
                                return False
                            index = counts['offer']; counts['offer'] += 1
                            is_bad = index < bad if bad_first else index >= 9 - bad
                            if is_bad:
                                forged = copy.deepcopy(plain)
                                forged['ike_payload'] = ike(tail=b'identical-substitution').hex()
                                # A compromised actual X2 re-encrypts its own neighbor link.
                                nonce, ct = M.aesgcm_encrypt(h.nodes[src].sessions[dst].key, M.jdump(forged),
                                    aad=f"{env['t']}:{src}->{dst}:{env['sid']}".encode())
                                rewritten = dict(env, nonce=nonce.hex(), ct=ct.hex())
                                h.nodes[dst].on_secure_msg(rewritten, src)
                                return True
                            return False

                        h.start(); h.pump(intercept); h.advance(2)
                        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])
                        self.assertEqual(h.injections[0][1], ike())
                        self.assertEqual(h.selected_count(), 1)
                        self.assertTrue(any('contradictory_wrapper' in s for s in h.nodes['B'].logger.lines))
                        h.close()

    def test_all_nine_bad_no_endpoint_state_or_timer(self):
        for mode in ('first', 'window', 'adaptive', 'wait-all'):
            h = self.make(mode=mode)

            def intercept(src, dst, env, plain):
                if env['t'] == 'MCC_OFFER':
                    plain['a_to_b_ke'] = '00' * 32
                    # Injection after successful neighbor decryption exercises
                    # the same handler without relying on outer AEAD rejection.
                    h.nodes['B'].handle_MCC_OFFER(src, M.jdump(plain))
                    return True
                return False

            h.start(); h.pump(intercept); h.advance(20)
            self.assertEqual(h.injections, [])
            node = h.nodes['B']
            self.assertEqual(node.mcc_b_selected, {})
            self.assertEqual(node._mcc_auth_pending, {})
            self.assertEqual(node._mcc_auth_timers, {})
            self.assertEqual(node._mcc_auth_sessions, {})
            h.close()

    def test_fresh_recipient_capsule_with_forged_A_signature(self):
        h = self.make(auto_reply=False)
        attacker = h.attacker()
        self.assertFalse(hasattr(attacker, '_materials'))
        caught = []

        def intercept(src, dst, env, plain):
            if env['t'] != 'MCC_OFFER':
                return False
            if caught:
                return True
            caught.append(True)
            context = plain['mcc_session_id']
            body = h.nodes['Y']._auth_body(ike(tail=b'evil'), M.USERS['A']['ip'], 500,
                M.USERS['B']['ip'], 500, 500, attacker.registry.nodes['Y']['encryption'], plain['conn_id'], (1, 1, 9))
            record = attacker.security.signed_message('B', context, body, 0, 9, message_id='34:0')
            record['signed']['sender'] = 'A'
            record['signed']['key_id'] = attacker.registry.nodes['A']['key_id']
            record['signature'] = '00' * 64
            forged = dict(plain, ike_payload=body['ike_payload'],
                sealed_b=h.nodes['Y']._auth_pack_seal(attacker.security.seal_to('B', record, context, purpose='endpoint')))
            h.nodes['B'].handle_MCC_OFFER('Y', M.jdump(forged))
            self.assertEqual(h.nodes['B']._mcc_auth_pending, {})
            self.assertEqual(h.nodes['B'].mcc_b_selected, {})
            # The forged first capsule did not suppress the legitimate ticket.
            h.nodes['B'].handle_MCC_OFFER('Y', M.jdump(plain))
            return True

        h.start(); h.pump(intercept)
        self.assertEqual([n for n, _, _ in h.injections], ['B'])
        self.assertEqual(h.injections[0][1], ike())

    def test_unknown_revoked_and_untrusted_sender(self):
        for case in ('unknown', 'revoked', 'untrusted'):
            h = self.make(auto_reply=False)
            entries = {n: dict(e) for n, e in h.registry.nodes.items()}
            if case == 'unknown':
                entries.pop('A')
            elif case == 'revoked':
                entries['A']['revoked'] = True
            else:
                entries['A']['verification'] = entries['Y']['verification']
                entries['A']['key_id'] = entries['Y']['key_id']
            # A sends with its own original keys; only B's trusted view changes.
            h.nodes['B'].mcc_security.registry = TRUST.VerifiedRegistry(2, 'test-root', entries, 'changed')
            h.start(); self.finish(h)
            self.assertEqual(h.injections, [])
            self.assertEqual(h.nodes['B']._mcc_auth_pending, {})
            h.close()

    def test_repeated_outer_ids_do_not_inflate_unique_tickets(self):
        h = self.make(mode='wait-all', auto_reply=False)
        original = []

        def intercept(src, dst, env, plain):
            if env['t'] != 'MCC_OFFER':
                return False
            if not original:
                original.append(copy.deepcopy(plain))
                h.nodes['B'].handle_MCC_OFFER(src, M.jdump(plain))
                for i in range(12):
                    changed = dict(plain, branch_id='outer-%d' % i, total_possible=1)
                    h.nodes['B'].handle_MCC_OFFER(src, M.jdump(changed))
                for i in range(12):
                    changed = dict(plain, conn_id='%032x' % i)
                    h.nodes['B'].handle_MCC_OFFER(src, M.jdump(changed))
            return True

        h.start(); h.pump(intercept)
        self.assertEqual(h.candidate_count(), 1)
        self.assertEqual(h.injections, [])
        h.advance(2)
        self.assertEqual([n for n, _, _ in h.injections], ['B'])
        for _ in range(3):
            h.emit('Y', 'B', 'MCC_OFFER', original[0])
        h.pump()
        self.assertEqual(len(h.injections), 1)

    def test_replay_after_restart_uses_durable_claim(self):
        h = self.make(auto_reply=False)
        h.start(); h.pump()
        original = h.offers()[0][3]
        self.assertEqual(len(h.injections), 1)
        h.nodes['B'] = h.new_node('B')
        h.emit('Y', 'B', 'MCC_OFFER', original); h.pump()
        self.assertEqual(len(h.injections), 1)
        self.assertEqual(h.nodes['B'].mcc_b_selected, {})

    def test_legacy_sibling_ingress_and_json_verified_flag_are_closed(self):
        h = self.make(auto_reply=False)
        node = h.nodes['B']
        meta = {'kind': 'ike', 'src': 'A', 'dst': 'B', 'x1': 'X', 'x2': 'Y',
                'conn_id': 'a' * 32, 'idx': 3, 'dir': 'fwd', 'verified': True,
                'ike_src_ip': M.USERS['A']['ip'], 'ike_src_port': 500,
                'ike_dst_ip': M.USERS['B']['ip'], 'ike_dst_port': 500, 'udp_port': 500}
        self.assertFalse(node.deliver_ike_to_local_strongswan(ike(), meta))
        node.handle_PROXY('Y', ike(), meta)
        node.handle_PRIV_DELIVER('Y', M.jdump(dict(meta, ike_payload=ike().hex())))
        node.handle_MCC_ACCEPT('Y', M.jdump(dict(meta, mcc_session_id='a' * 32)))
        node.on_error({'code': 'FAKE', 'meta': {'conn_id': 'a' * 32}}, 'Y')
        self.assertEqual(h.injections, [])
        self.assertEqual(node.ike_routes, {})
        h.start(); self.finish(h)
        self.assertEqual(len(h.injections), 1)

    def test_reverse_fake_bke_rejected_before_route_or_forward_key(self):
        h = self.make()
        seen = []

        def intercept(src, dst, env, plain):
            if env['t'] == 'PRIV_BACK' and plain.get('leg') == 'x1-a' and not seen:
                seen.append(copy.deepcopy(plain))
                bad = copy.deepcopy(plain)
                bad['sealed_a']['bke'] = h.attacker().registry.nodes['Y']['encryption']
                h.nodes['A'].handle_PRIV_BACK(src, M.jdump(bad))
                context = plain['conn_id']
                self.assertNotIn('forward_key', h.nodes['A'].priv_ab_state[context])
                self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
            return False

        h.start(); h.pump(intercept)
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])
        h.emit('X', 'A', 'PRIV_BACK', seen[0]); h.pump()
        self.assertEqual(len(h.injections), 2)

    def test_signed_response_still_requires_exact_request_digest(self):
        h = self.make()
        seen = []

        def intercept(src, dst, env, plain):
            if env['t'] != 'PRIV_BACK' or plain.get('leg') != 'x1-a' or seen:
                return False
            seen.append(True)
            context = plain['conn_id']
            state = h.nodes['A'].priv_ab_state[context]
            correct = state['auth_requests']['34:0']
            state['auth_requests']['34:0'] = '00' * 32
            h.nodes['A'].handle_PRIV_BACK(src, M.jdump(plain))
            self.assertNotIn('forward_key', state)
            self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
            state['auth_requests']['34:0'] = correct
            return False

        h.start(); h.pump(intercept)
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])

    def test_twenty_seven_planned_slots_forward_exactly_twenty_seven(self):
        h = self.make(mode='wait-all', fanout=(3, 3, 3), auto_reply=False)
        h.start(); h.pump()
        self.assertEqual(len(h.offers()), 27)
        self.assertEqual([n for n, _, _ in h.injections], ['B'])
        signed = []
        for src, dst, env, offer in h.offers():
            record = h.nodes['B']._auth_open_endpoint(offer['sealed_b'], offer['mcc_session_id'])
            signed.append(record['signed'])
        self.assertEqual({r['copy_id'] for r in signed}, set(range(27)))
        self.assertEqual({r['expected_copies'] for r in signed}, {27})
        self.assertTrue(all(r['body']['budget'] == [3, 3, 3] for r in signed))

    def test_hop_confidentiality_has_no_endpoint_A_identity_at_X2(self):
        h = self.make(auto_reply=False)
        h.start(); h.pump()
        for src, dst, env, plain in h.wire:
            if env['t'] == 'MCC_START':
                self.assertNotIn('dst', plain)
                for branch in plain['branches']:
                    self.assertEqual(set(branch['capsule']), {'v', 'epk', 'nonce', 'ct'})
            elif env['t'] == 'MCC_X2':
                inner = h.nodes[dst]._open_seal_for_me(plain['conn_id'], plain['capsule'])
                self.assertNotIn('src', inner)
                self.assertNotIn('sender', inner)
                self.assertNotIn('signature', inner)
                self.assertNotIn('key_id', inner)
                self.assertNotIn('a_to_b_ke', inner)
                self.assertNotIn('ike_payload', inner)
                self.assertEqual(set(inner['sealed_b']), {'v', 'epk', 'nonce', 'ct'})
                with self.assertRaises(CORE.MccSecurityError):
                    h.nodes[dst]._auth_open_endpoint(inner['sealed_b'], inner['mcc_session_id'])

    def test_verified_local_refusal_can_use_reserve_unknown_send_cannot(self):
        for outcome in (False, None):
            h = self.make(mode='wait-all', auto_reply=False)
            original = h.nodes['B'].ike_proxy.inject_to_charon
            calls = []

            def inject(payload, meta):
                calls.append(1)
                if len(calls) == 1:
                    return outcome
                return original(payload, meta)

            h.nodes['B'].ike_proxy.inject_to_charon = inject
            h.start(); h.pump()
            self.assertEqual(len(calls), 2 if outcome is False else 1)
            self.assertEqual(len(h.injections), 1 if outcome is False else 0)
            h.advance(10)
            self.assertEqual(len(calls), 2 if outcome is False else 1)
            h.close()

    def test_invalid_duplicates_do_not_reset_adaptive_or_waitall_deadline(self):
        for mode in ('adaptive', 'wait-all'):
            h = self.make(mode=mode, auto_reply=False, quiet_ms=150, deadline_ms=1000)
            seen = []

            def intercept(src, dst, env, plain):
                if env['t'] == 'MCC_OFFER':
                    if len(seen) < 3:
                        seen.append(copy.deepcopy(plain))
                        return False
                    return True
                return False

            h.start(); h.pump(intercept)
            node = h.nodes['B']
            deadlines = dict(node._mcc_auth_deadlines)
            timers = dict(node._mcc_auth_quiet)
            for i in range(5):
                node.handle_MCC_OFFER('Y', M.jdump(seen[0]))
                bad = dict(seen[0], ike_payload='00')
                node.handle_MCC_OFFER('Y', M.jdump(bad))
            self.assertEqual(deadlines, node._mcc_auth_deadlines)
            self.assertEqual(timers, node._mcc_auth_quiet)
            h.advance(0.2)
            self.assertEqual(len(h.injections), 1 if mode == 'adaptive' else 0)
            h.advance(1)
            self.assertEqual(len(h.injections), 1)
            h.close()

    def test_unknown_mode_fail_closed_before_socket_bind(self):
        with patch.dict('os.environ', {'IKE_MCC_ACCEPT_MODE': 'unexpected'}):
            with self.assertRaises(CORE.MccSecurityError):
                AUTH.MccAuthenticatedMixin._auth_policy_from_environment()
        with patch.object(CORE.EndpointSecurity, 'from_environment', side_effect=CORE.MccSecurityError('missing_endpoint_configuration')):
            with patch('socket.socket', side_effect=AssertionError('Must not bind')):
                with self.assertRaises(CORE.MccSecurityError):
                    M.NodeDaemon('A')

    def test_adapter_reject4500_and_unknown_send_are_explicit(self):
        daemon = types.SimpleNamespace(name='B', logger=types.SimpleNamespace(warning=lambda *a: None,
            info=lambda *a: None, error=lambda *a: None), user_by_ip=lambda ip: 'A')
        proxy = ADAPTER.IkeProxy(daemon)
        meta = {'ike_src_ip': M.USERS['A']['ip'], 'ike_src_port': 4500, 'udp_port': 4500}
        with patch('socket.socket', side_effect=AssertionError('Refused before socket')):
            self.assertEqual(proxy.inject_to_charon(b'non-esp', meta), ADAPTER.IkeInjectionOutcome.REJECTED)
        sock = types.SimpleNamespace(setsockopt=lambda *a: None, close=lambda: None,
                                     sendto=lambda *a: (_ for _ in ()).throw(OSError('uncertain send')))
        with patch.object(ADAPTER.socket, 'socket', return_value=sock):
            self.assertEqual(proxy.inject_to_charon(ike(port=4500), meta), ADAPTER.IkeInjectionOutcome.UNKNOWN)

    def test_all_repeated_logical_roles_keep_init_auth_path(self):
        for x1 in ('B', 'X', 'Y'):
            for x2 in (n for n in ('A', 'B', 'X', 'Y') if n != x1):
                for port in (500, 4500):
                    with self.subTest(x1=x1, x2=x2, port=port):
                        h = self.make(fanout=(1, 1, 1), x1=x1, x2=x2, port=port)
                        h.start(); h.pump(); h.auth(); h.pump()
                        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A', 'B', 'A'])
                        h.close()

    def test_valid_intermediary_signature_same_context_and_conn_cannot_poison_A(self):
        h = self.make()
        attacker = h.attacker()
        done = []

        def intercept(src, dst, env, plain):
            if env['t'] != 'MCC_OFFER' or done:
                return False
            done.append(True)
            # The attacker is a legitimate participant and signs AS ITSELF,
            # while reusing the observed A context AND transport identifier.
            context = plain['mcc_session_id']
            body = h.nodes['Y']._auth_body(ike(), M.USERS['Y']['ip'], 500, M.USERS['B']['ip'],
                500, 500, attacker.registry.nodes['Y']['encryption'], plain['conn_id'], (1, 1, 1))
            record = attacker.security.signed_message('B', context, body, 0, 1, message_id='34:0')
            forged = dict(plain, a_to_b_ke=body['a_to_b_ke'],
                sealed_b=h.nodes['Y']._auth_pack_seal(attacker.security.seal_to('B', record, context, purpose='endpoint')))
            # This own-identity request may be accepted, but must stay separate.
            h.auto_reply = False
            h.nodes['B'].handle_MCC_OFFER('Y', M.jdump(forged))
            h.auto_reply = True
            self.assertEqual(h.injections[0][2]['src'], 'Y')
            return False

        h.start(); h.pump(intercept); h.auth(); h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'B', 'A', 'B', 'A'])
        self.assertEqual([meta['src'] for n, _, meta in h.injections if n == 'B'], ['Y', 'A', 'A'])
        self.assertEqual(len(h.nodes['B']._mcc_auth_sessions), 2)

    def test_fresh_reverse_AEAD_from_intermediary_is_not_signature_B(self):
        from cryptography.hazmat.primitives.asymmetric import x25519
        h = self.make()
        attacker = h.attacker()
        done = []

        def intercept(src, dst, env, plain):
            if env['t'] != 'PRIV_BACK' or plain.get('leg') != 'x1-a' or done:
                return False
            done.append(True)
            context = plain['conn_id']
            # Give the attacker the PUBLIC ephemeral key as conservative extra
            # knowledge. The compact wire itself no longer exposes it to X2.
            a_pub = h.nodes['A'].priv_ab_state[context]['pub']
            private = x25519.X25519PrivateKey.generate()
            bke = private.public_key().public_bytes_raw().hex()
            shared = private.exchange(M.xpub_from_bytes(bytes.fromhex(a_pub)))
            response = ike(response=True)
            body = {'ike_payload': response.hex(), 'ike_length': len(response),
                'ike_src_ip': M.USERS['B']['ip'], 'ike_src_port': 500,
                'ike_dst_ip': M.USERS['A']['ip'], 'ike_dst_port': 500, 'udp_port': 500,
                'bke': bke, 'a_to_b_ke': a_pub, 'request_digest': hashlib.sha256(ike()).hexdigest()}
            record = attacker.security.signed_message('A', context, body, 0, 1,
                direction='reverse', kind='response', message_id='34:0')
            record['signed']['sender'] = 'B'
            record['signed']['key_id'] = attacker.registry.nodes['B']['key_id']
            record['signature'] = '00' * 64
            duplicated = (b'{"signed":' + M.jdump(record['signed']) + b',"signed":' +
                M.jdump(record['signed']) + b',"signature":"' + b'0' * 128 + b'"}')
            dup_nonce, dup_ct = M.aesgcm_encrypt(h.nodes['Y']._ab_key(shared, context), duplicated,
                                                aad=f'priv-b-a:{context}'.encode())
            duplicate_response = dict(plain, sealed_a={'mode': 'x25519', 'auth_mcc': 1, 'v': 2, 'conn_id': context,
                'bke': bke, 'nonce': dup_nonce.hex(), 'ct': h.nodes['Y']._auth_encode_ct(dup_ct)})
            h.nodes['A'].handle_PRIV_BACK(src, M.jdump(duplicate_response))
            self.assertTrue(any('duplicate_json_key' in line for line in h.nodes['A'].logger.lines))
            nonce, ct = M.aesgcm_encrypt(h.nodes['Y']._ab_key(shared, context), M.jdump(record),
                                        aad=f'priv-b-a:{context}'.encode())
            forged = dict(plain, sealed_a={'mode': 'x25519', 'auth_mcc': 1, 'v': 2, 'conn_id': context,
                'bke': bke, 'nonce': nonce.hex(), 'ct': h.nodes['Y']._auth_encode_ct(ct)})
            h.nodes['A'].handle_PRIV_BACK(src, M.jdump(forged))
            self.assertNotIn('forward_key', h.nodes['A'].priv_ab_state[context])
            self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
            self.assertTrue(any('bad_signature' in line for line in h.nodes['A'].logger.lines))
            return False

        h.start(); h.pump(intercept)
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])

    def test_uncertain_inflight_claim_survives_restart_without_retry(self):
        h = self.make(auto_reply=False)
        calls = []

        def inject(payload, meta):
            calls.append(1)
            raise OSError('could have sent before exception')

        h.nodes['B'].ike_proxy.inject_to_charon = inject
        h.start(); h.pump()
        self.assertEqual(len(calls), 1)
        captured = h.offers()[0][3]
        h.nodes['B'] = h.new_node('B')
        h.emit('Y', 'B', 'MCC_OFFER', captured); h.pump()
        self.assertEqual(h.injections, [])
        self.assertEqual(len(calls), 1)

    def test_random_choice_invariants_with_fixed_seed_series(self):
        for seed in range(6):
            h = self.make(mode='window', auto_reply=False)
            random.seed(seed)
            seen = []

            def intercept(src, dst, env, plain):
                if env['t'] == 'MCC_OFFER':
                    seen.append(plain)
                    if len(seen) <= 3:
                        plain['ike_payload'] = ike(tail=b'bad').hex()
                        h.nodes['B'].handle_MCC_OFFER(src, M.jdump(plain))
                        return True
                return False

            h.start(); h.pump(intercept); h.advance(2)
            self.assertEqual(len(h.injections), 1)
            self.assertEqual(h.injections[0][1], ike())
            self.assertIn(h.injections[0][2]['conn_id'], {p['conn_id'] for p in seen[3:]})
            h.close()

    def test_parallel_same_peer_different_spis_keep_request_and_response_contexts(self):
        h = self.make(fanout=(1, 1, 1))
        spis = (b'INITSP01', b'INITSP02')
        for spi in spis:
            h.start(payload=ike(spi=spi))
        h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'B', 'A', 'A'])
        for spi in spis:
            h.nodes['A'].send_ike_datagram('B', M.USERS['A']['ip'], 500, M.USERS['B']['ip'], 500,
                ike(exchange=35, message_id=1, spi=spi), 500)
        h.pump()
        self.assertEqual(len(h.injections), 8)
        for spi in spis:
            selected = [payload for name, payload, meta in h.injections if name == 'B' and payload[:8] == spi]
            self.assertEqual(len(selected), 2)
        self.assertEqual(len(h.nodes['A']._mcc_auth_a_routes), 2)
        self.assertEqual(len(h.nodes['B']._mcc_auth_sessions), 2)

    def test_redirect_addresses_are_canonical_before_signature(self):
        h = self.make(fanout=(1, 1, 1))
        h.nodes['A'].send_ike_datagram('B', '127.0.0.1', 17231, '0.0.0.0', 15000, ike(), 500)
        h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])
        self.assertEqual(h.injections[0][2]['ike_src_ip'], M.USERS['A']['ip'])
        self.assertEqual(h.injections[0][2]['ike_dst_ip'], M.USERS['B']['ip'])
        self.assertEqual(h.injections[0][2]['ike_src_port'], 500)
        self.assertEqual(h.injections[0][2]['ike_dst_port'], 500)

    def test_verification_capacity_and_expired_memory_cleanup_preserve_replay_fence(self):
        h = self.make(auto_reply=False)
        originals = []

        def intercept(src, dst, env, plain):
            if env['t'] == 'MCC_OFFER' and not originals:
                originals.append(copy.deepcopy(plain))
                node = h.nodes['B']
                self.assertTrue(node._mcc_verify_slots.acquire(False))
                self.assertTrue(node._mcc_verify_slots.acquire(False))
                node.handle_MCC_OFFER(src, M.jdump(plain))
                self.assertEqual(node._mcc_auth_pending, {})
                node._mcc_verify_slots.release(); node._mcc_verify_slots.release()
            return False

        h.start(); h.pump(intercept)
        self.assertEqual(len(h.injections), 1)
        node = h.nodes['B']
        with patch.object(AUTH.time, 'time', return_value=time.time() + 130):
            node._auth_prune()
        self.assertEqual(node._mcc_auth_pending, {})
        self.assertEqual(node._mcc_auth_sessions, {})
        self.assertEqual(node.mcc_b_selected, {})
        # Even artificial early removal of volatile state cannot reopen a
        # still-valid packet: the independent durable ledger stays closed.
        node.handle_MCC_OFFER('Y', M.jdump(originals[0]))
        self.assertEqual(len(h.injections), 1)

    def test_duplicate_locator_request_does_not_replace_key_or_grow_state(self):
        h = self.make(auto_reply=False)
        node = h.nodes['B']
        first = node._prepare_priv_bkey_response('1' * 32, 'Y')
        for _ in range(10):
            self.assertEqual(node._prepare_priv_bkey_response('1' * 32, 'Y'), first)
        self.assertEqual(len(node.priv_b_state), 1)
        with patch.object(AUTH, 'MAX_ACTIVE', 1):
            for i in range(2, 5):
                node._prepare_priv_bkey_response('%032x' % i, 'Y')
            with self.assertRaises(CORE.MccSecurityError):
                node._prepare_priv_bkey_response('5' * 32, 'Y')
        self.assertEqual(len(node.priv_b_state), 4)

    def test_verified_ticket_after_window_refusal_retries_without_new_deadline(self):
        h = self.make(mode='window', auto_reply=False)
        saved = []

        def intercept(src, dst, env, plain):
            if env['t'] == 'MCC_OFFER':
                saved.append(copy.deepcopy(plain))
                return len(saved) > 1
            return False

        original = h.nodes['B'].ike_proxy.inject_to_charon
        h.nodes['B'].ike_proxy.inject_to_charon = lambda *a: False
        h.start(); h.pump(intercept); h.advance(0.2)
        self.assertEqual(h.injections, [])
        deadline = dict(h.nodes['B']._mcc_auth_deadlines)
        h.nodes['B'].ike_proxy.inject_to_charon = original
        h.emit('Y', 'B', 'MCC_OFFER', saved[1]); h.pump()
        self.assertEqual(len(h.injections), 1)
        self.assertEqual(h.nodes['B']._mcc_auth_deadlines, deadline)

    def test_lost_real_response_is_replayed_without_second_IKE_injection(self):
        h = self.make()

        def drop_response(src, dst, env, plain):
            return env['t'] == 'PRIV_BACK' and plain.get('leg') == 'x1-a'

        h.start(); h.pump(drop_response)
        self.assertEqual([n for n, _, _ in h.injections], ['B'])
        self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
        h.start(); h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])
        h.auth(); h.pump(drop_response)
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A', 'B'])
        h.auth(); h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A', 'B', 'A'])

    def test_initial_retransmission_after_ready_route_keeps_initial_ticket(self):
        h = self.make()
        h.start(); h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])
        # Even after the original short pending cache has gone, a local IKE
        # INIT retransmit must not become a new continuation-delivery key.
        h.nodes['A'].mcc_opaque_pending.clear()
        h.start(); h.pump()
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A'])

    def test_reentrant_nat_port_switch_uses_authenticated_route_before_injection_returns(self):
        h = self.make()
        original = h.nodes['A'].ike_proxy.inject_to_charon
        emitted = []

        def charon_emits_auth_immediately(payload, meta):
            result = original(payload, meta)
            offset = 4 if meta['udp_port'] == 4500 else 0
            if payload[offset + 18] == 34 and not emitted:
                emitted.append(True)
                # Real charon emits IKE_AUTH on UDP/4500 as soon as the INIT
                # response is injected, before the caller's fsync/return.
                h.port = 4500
                h.auth()
            return result

        h.nodes['A'].ike_proxy.inject_to_charon = charon_emits_auth_immediately
        h.start(); h.pump()
        self.assertEqual([name for name, _, _ in h.injections], ['B', 'A', 'B', 'A'])
        self.assertEqual(len(h.nodes['A'].priv_ab_state), 1)
        self.assertEqual(len(h.nodes['B']._mcc_auth_sessions), 1)

    def test_confirmed_reverse_injection_refusal_rolls_back_published_route(self):
        h = self.make()
        h.nodes['A'].ike_proxy.inject_to_charon = lambda *_: False
        h.start(); h.pump()
        self.assertEqual([name for name, _, _ in h.injections], ['B'])
        self.assertEqual(h.nodes['A']._mcc_auth_a_routes, {})
        self.assertTrue(all('forward_key' not in state for state in h.nodes['A'].priv_ab_state.values()))

    def test_real_link_fragmentation_payload_limits_init_auth_both_directions(self):
        for size in (4096, 6144, 8192):
            for port in (500, 4500):
                with self.subTest(size=size, port=port):
                    h = self.make(fanout=(1, 1, 1), real_link=True, echo_reply_payload=True, port=port)
                    initial = ike(port=port, tail=b'x' * (size - 28 - (4 if port == 4500 else 0)))
                    auth = ike(exchange=35, message_id=1, port=port,
                               tail=b'y' * (size - 28 - (4 if port == 4500 else 0)))
                    with patch('socket.socket', side_effect=AssertionError('No live socket')):
                        h.start(initial); h.pump()
                        h.nodes['A'].send_ike_datagram('B', M.USERS['A']['ip'], port,
                            M.USERS['B']['ip'], port, auth, port)
                        h.pump()
                    self.assertEqual([n for n, _, _ in h.injections], ['B', 'A', 'B', 'A'])
                    self.assertEqual(h.injections[0][1], initial)
                    self.assertEqual(h.injections[2][1], auth)
                    self.assertEqual([len(payload) for _, payload, _ in h.injections], [size] * 4)
                    self.assertTrue(h.raw_frames)
                    self.assertLessEqual(max(length for _, _, length in h.raw_frames), 1200)
                    self.assertLessEqual(max(h.assembled_sizes), 65507)
                    self.assertTrue(all(not node.link_frag_buf for node in h.nodes.values()))
                    h.close()

    def test_payload8193_rejected_before_pending_or_wire(self):
        h = self.make(real_link=True)
        with self.assertRaises(CORE.MccSecurityError):
            h.start(ike(tail=b'x' * (8193 - 28)))
        self.assertEqual(h.wire, [])
        self.assertEqual(h.raw_frames, [])
        self.assertEqual(h.nodes['A'].mcc_opaque_pending, {})
        self.assertEqual(h.nodes['A'].priv_ab_state, {})

    def test_v2_wire_seal_parser_is_strict_and_bounded_before_decode(self):
        h = self.make(auto_reply=False)
        node = h.nodes['A']
        seal = node._seal_for_user('Y', '1' * 32, {'value': 'test'})
        self.assertEqual(h.nodes['Y']._open_seal_for_me('1' * 32, seal), {'value': 'test'})
        bad_values = [dict(seal, v=True), dict(seal, v='2'), dict(seal, v=1),
                      dict(seal, extra=1), {k: v for k, v in seal.items() if k != 'nonce'},
                      dict(seal, ct=seal['ct'] + '\n'), dict(seal, ct='%' * 24),
                      dict(seal, ct='AAAAAAAAAAAAAAAAAAAAAB==')]
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises((CORE.MccSecurityError, ValueError)):
                    node._auth_expand_seal(bad)
        with patch.object(AUTH.base64, 'b64decode', side_effect=AssertionError('Must check size first')):
            with self.assertRaises(CORE.MccSecurityError):
                node._auth_expand_seal(dict(seal, ct='A' * (AUTH.MAX_BASE64_CIPHERTEXT + 4)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
