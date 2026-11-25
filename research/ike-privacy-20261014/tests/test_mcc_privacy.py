"""Offline wire simulation: actual daemon methods and AEAD, no sockets/VM/charon.

Run with existing bundled Python; --source selects the immutable baseline for
the pre-fix reproduction or the independent candidate for acceptance.
"""
import ast
import copy
import hashlib
import importlib
import itertools
import json
import os
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('MCC_TEST_SOURCE', ROOT / 'candidate/hybrid-overlay'))
NAMES = ['A', 'B', 'X', 'Y']


def load_code():
    for name in ('node_daemon', 'mcc_privacy', 'crypto_util', 'protocol', 'config', 'logging_util', 'ike_proxy'):
        sys.modules.pop(name, None)
    config = types.ModuleType('config')
    tree = ast.parse((SOURCE / 'node_daemon.py').read_text(encoding='utf-8-sig'))
    fields = next(n.names for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == 'config')
    for field in fields:
        setattr(config, field.name, 0)
    config.USERS = {name: {'ip': f'192.0.2.{i+1}', 'port': 9000, 'password': 'synthetic-test-only-' + name}
                    for i, name in enumerate(NAMES)}
    config.ACTIVE_USERS = NAMES
    config.IKE_MCC_ENABLED = True
    config.IKE_PRIVACY_OVERLAY = True
    config.IKE_PRIVACY_INLINE = True
    config.IKE_MCC_X1_FANOUT = 1
    config.IKE_MCC_X2_FANOUT = 1
    config.IKE_MCC_IKE_FANOUT = 1
    config.IKE_MCC_ROUTE_TIMEOUT_S = 10
    config.IKE_ROUTE_CACHE_TTL_S = 120
    config.IKE_INLINE_ROUTE_TIMEOUT_S = 10
    config.RETRIES = 1
    sys.modules['config'] = config
    logger = types.ModuleType('logging_util')
    logger.setup_logger = lambda name: None
    sys.modules['logging_util'] = logger
    adapter = types.ModuleType('ike_proxy')
    adapter.IkeProxy = None
    sys.modules['ike_proxy'] = adapter
    sys.path.insert(0, str(SOURCE))
    try:
        return importlib.import_module('node_daemon')
    finally:
        sys.path.pop(0)


M = load_code()


def ike(exchange=34, response=False, port=500, spi=b'INITSP01', message_id=0):
    header = spi + (b'RESPSP01' if response or exchange != 34 else b'\0' * 8)
    header += bytes([0, 0x20, exchange, 0x20 if response else 0x08])
    header += message_id.to_bytes(4, 'big') + (28).to_bytes(4, 'big')
    return (b'\0' * 4 if port == 4500 else b'') + header


class Log:
    def __init__(self):
        self.lines = []

    def __getattr__(self, name):
        return lambda text, *args: self.lines.append(str(text))


class Harness:
    def __init__(self, x1='X', x2='Y', port=500, auto_reply=True, mcc=True):
        self.x1, self.x2, self.port = x1, x2, port
        self.queue, self.wire, self.injections = [], [], []
        self.auto_reply = auto_reply
        self.nodes = {}
        M.IKE_MCC_ENABLED = mcc
        harness = self

        class DeferredThread:
            def __init__(self, target, args=(), kwargs=None, **unused):
                self.target, self.args, self.kwargs = target, args, kwargs or {}

            def start(self):
                harness.queue.append(('call', self.target, self.args, self.kwargs))

        self.thread_context = patch.object(M, 'threading', types.SimpleNamespace(
            Thread=DeferredThread, Lock=threading.RLock, Event=threading.Event, Timer=threading.Timer))
        self.thread_context.start()
        for name in NAMES:
            node = M.NodeDaemon.__new__(M.NodeDaemon)  # Never bind a daemon socket.
            node.name = name
            node.lock = threading.RLock()
            node.ike_route_lock = threading.RLock()
            node.logger = Log()
            for field in ('sessions', 'priv_x1_state', 'priv_x2_state', 'priv_b_state',
                          'priv_ab_state', 'priv_x2_pub', 'mcc_accept_ev', 'mcc_accept_data',
                          'mcc_b_selected', 'mcc_b_delivered', 'mcc_b_pending', 'mcc_b_timers',
                          'ike_routes', 'route_cooldowns', 'route_failure_counts', 'conns',
                          'okx2_ev', 'okx2_data', 'okx2_x2name', 'ensure_inflight'):
                setattr(node, field, {})
            if hasattr(node, '_init_opaque_mcc'):
                node._init_opaque_mcc()
            for peer in NAMES:
                if peer == name:
                    continue
                label = '-'.join(sorted((name, peer)))
                node.sessions[peer] = M.MgmtSession(peer, label, hashlib.sha256(label.encode()).digest())
            node.ensure_session = types.MethodType(lambda n, peer, **kw: peer != n.name, node)

            def ordered(n, candidates, env_name, role):
                forced = harness.x1 if role == 'X1' else harness.x2
                return ([forced] if forced in candidates else []) + [p for p in candidates if p != forced]

            node._ordered_route_candidates = types.MethodType(ordered, node)
            node._choose_route_candidate = types.MethodType(
                lambda n, candidates, env_name, role: ordered(n, candidates, env_name, role)[0], node)

            def send(n, peer, data):
                assert peer != n.name, 'Forbidden network self-send'
                message = json.loads(data)
                plain = self.nodes[peer].link_decrypt(message)
                self.wire.append((n.name, peer, copy.deepcopy(message), json.loads(plain)))
                self.queue.append(('wire', n.name, peer, message))

            node.send_peer = types.MethodType(send, node)

            def inject(payload, meta, name=name):
                self.injections.append((name, payload, copy.deepcopy(meta)))
                offset = 4 if meta['udp_port'] == 4500 else 0
                if self.auto_reply and name == 'B' and not payload[offset+19] & 0x20:
                    reply = ike(payload[offset+18], True, meta['udp_port'], payload[offset:offset+8],
                                int.from_bytes(payload[offset+20:offset+24], 'big'))
                    self.nodes['B'].send_ike_datagram('A', M.USERS['B']['ip'], meta['udp_port'],
                        M.USERS['A']['ip'], meta['udp_port'], reply, meta['udp_port'])

            node.ike_proxy = types.SimpleNamespace(inject_to_charon=inject)
            self.nodes[name] = node

    def close(self):
        self.thread_context.stop()

    def start(self):
        self.nodes['A'].send_ike_datagram('B', M.USERS['A']['ip'], self.port,
            M.USERS['B']['ip'], self.port, ike(port=self.port), self.port)

    def auth(self):
        self.nodes['A'].send_ike_datagram('B', M.USERS['A']['ip'], self.port,
            M.USERS['B']['ip'], self.port, ike(35, port=self.port, message_id=1), self.port)

    def pump(self, drop=None):
        count = 0
        while self.queue:
            event = self.queue.pop(0)
            count += 1
            assert count < 2000, 'Unbounded offline event queue'
            if event[0] == 'call':
                _, target, args, kwargs = event
                target(*args, **kwargs)
            else:
                _, src, dst, message = event
                plain = json.loads(self.nodes[dst].link_decrypt(message))
                if drop and drop(src, dst, message, plain):
                    continue
                self.nodes[dst].on_secure_msg(message, src)

    def emit(self, src, dst, message_type, body):
        self.nodes[src].link_send(dst, message_type, M.jdump(body), meta={'mode': 'test'})

    def final_replies(self):
        return [r for r in self.wire if r[1] == 'A' and r[3].get('leg') == 'x1-a']


class PrivacyTests(unittest.TestCase):
    def make(self, **kwargs):
        h = Harness(**kwargs)
        self.addCleanup(h.close)
        return h

    def assert_complete(self, h):
        self.assertEqual([n for n, _, _ in h.injections], ['B', 'A', 'B', 'A'])
        self.assertFalse(any(r[2]['t'] == 'MCC_ACCEPT' for r in h.wire))
        route = h.nodes['A']._get_cached_route('A', 'B')
        self.assertIsNotNone(route)
        self.assertEqual(route.x2, '')
        self.assertEqual(route.mcc_branch_id, '')
        self.assertTrue(route.opaque_token)
        self.assertFalse(h.nodes['A']._is_inline_pending(route))
        for _, _, outer, inner in h.final_replies():
            self.assertEqual(set(inner), {'opaque_mcc', 'leg', 'conn_id', 'route_token', 'sealed_a'})
            self.assertEqual(outer['meta'], {'mode': 'mcc-opaque'})
            self.assertEqual(inner['conn_id'], route.ab_context)
            self.assertEqual(inner['sealed_a']['conn_id'], route.ab_context)
            self.assertNotIn('x2', inner)
        internal = {r[3]['conn_id'] for r in h.wire if r[2]['t'] == 'MCC_X2'}
        self.assertNotIn(route.conn_id, internal)
        for _, _, meta in [r for r in h.injections if r[0] == 'A']:
            self.assertEqual(meta['x2'], '')
            self.assertNotIn(meta['conn_id'], internal)

    def test_all_legal_role_assignments_and_both_ports(self):
        for x1 in ['B', 'X', 'Y']:
            for x2 in [p for p in NAMES if p != x1]:
                for port in (500, 4500):
                    with self.subTest(x1=x1, x2=x2, port=port):
                        h = self.make(x1=x1, x2=x2, port=port)
                        with patch('socket.socket', side_effect=AssertionError('No network in tests')):
                            h.start(); h.pump()
                            before = sum(r[2]['t'] == 'MCC_START' for r in h.wire)
                            h.auth(); h.pump()
                        self.assert_complete(h)
                        self.assertEqual(sum(r[2]['t'] == 'MCC_START' for r in h.wire), before)
                        h.close()

    def test_endpoint_role_overlap_has_full_reverse_path(self):
        h = self.make(x1='B', x2='A')
        h.start(); h.pump()
        legs = [(s, d, p['leg']) for s, d, o, p in h.wire if o['t'] == 'PRIV_BACK']
        self.assertEqual(legs, [('B', 'A', 'b-x2'), ('A', 'B', 'x2-x1'), ('B', 'A', 'x1-a')])

    def test_no_ready_route_before_real_response(self):
        h = self.make(auto_reply=False)
        h.start(); h.pump()
        self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
        self.assertFalse(any(r[2]['t'] == 'MCC_ACCEPT' for r in h.wire))

    def test_initial_retransmission_reuses_context_and_capsules(self):
        h = self.make()
        h.start()
        original = copy.deepcopy([r[3] for r in h.wire if r[2]['t'] == 'MCC_START'])
        h.start()
        repeated = [r[3] for r in h.wire if r[2]['t'] == 'MCC_START']
        self.assertEqual(repeated, original * 2)
        h.pump()
        self.assertEqual(sum(n == 'B' for n, _, _ in h.injections), 1)

    def test_a_prepares_all_candidates_x1_selects_actual_fanout(self):
        h = self.make(x2='Y')
        h.start(); h.pump()
        start = next(r[3] for r in h.wire if r[2]['t'] == 'MCC_START')
        self.assertEqual({b['x2'] for b in start['branches']}, set(NAMES) - {h.x1})
        forwarded = [r for r in h.wire if r[2]['t'] == 'MCC_X2']
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0][1], 'Y')

    def test_final_schema_rejects_added_x2(self):
        h = self.make()
        h.start(); h.pump(drop=lambda s,d,o,p: d == 'A' and p.get('leg') == 'x1-a')
        reply = copy.deepcopy(h.final_replies()[0][3]); reply['x2'] = 'Y'
        h.emit('X', 'A', 'PRIV_BACK', reply); h.pump()
        self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))

    def test_bad_context_ciphertext_or_stage_cannot_complete_route(self):
        for kind in ('context', 'ciphertext', 'stage', 'handle', 'legacy'):
            with self.subTest(kind=kind):
                h = self.make()
                h.start(); h.pump(drop=lambda s,d,o,p: d == 'A' and p.get('leg') == 'x1-a')
                reply = copy.deepcopy(h.final_replies()[0][3])
                if kind == 'context': reply['conn_id'] = 'foreign'
                if kind == 'ciphertext':
                    reply['sealed_a']['ct'] = f"{int(reply['sealed_a']['ct'][:2],16)^1:02x}" + reply['sealed_a']['ct'][2:]
                if kind == 'stage': reply['leg'] = 'b-x2'
                if kind == 'handle': reply['route_token'] = 'invalid'
                if kind == 'legacy': reply.pop('opaque_mcc')
                h.emit('X', 'A', 'PRIV_BACK', reply); h.pump()
                self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
                h.close()

    def test_wrong_ike_spi_or_exchange_cannot_complete_route(self):
        for payload in (ike(response=True, spi=b'OTHERSP1'), ike(35, response=True, message_id=1)):
            h = self.make(auto_reply=False)
            h.start(); h.pump()
            h.nodes['B'].send_ike_datagram('A', M.USERS['B']['ip'], 500, M.USERS['A']['ip'], 500, payload, 500)
            h.pump()
            self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
            h.close()

    def test_wrong_first_hop_or_foreign_forward_handle(self):
        h = self.make()
        h.start(); h.pump()
        route = h.nodes['A']._get_cached_route('A', 'B')
        reply = copy.deepcopy(h.final_replies()[0][3])
        count = len(h.injections)
        h.emit('Y', 'A', 'PRIV_BACK', reply); h.pump()
        self.assertEqual(len(h.injections), count)
        h.auth()
        request = copy.deepcopy(next(r[3] for r in h.wire if r[2]['t'] == 'MCC_OPAQUE_FWD'))
        h.queue.clear()
        request['route_token'] = '0' * 64
        h.emit('A', 'X', 'MCC_OPAQUE_FWD', request); h.pump()
        self.assertEqual(len(h.injections), count)
        self.assertEqual(h.nodes['A']._get_cached_route('A', 'B').opaque_token, route.opaque_token)

    def test_duplicate_real_response_keeps_handle_and_forward_key(self):
        h = self.make()
        h.start(); h.pump()
        first = h.nodes['A']._get_cached_route('A', 'B').opaque_token
        h.nodes['B'].send_ike_datagram('A', M.USERS['B']['ip'], 500, M.USERS['A']['ip'], 500, ike(response=True), 500)
        h.pump()
        self.assertEqual(first, h.nodes['A']._get_cached_route('A', 'B').opaque_token)
        h.auth(); h.pump()
        self.assertEqual([n for n,_,_ in h.injections], ['B','A','A','B','A'])

    def test_lost_initial_response_recovered_by_real_response_replay(self):
        h = self.make(x1='B', x2='A')
        h.start(); h.pump(drop=lambda s,d,o,p: p.get('leg') == 'x1-a')
        self.assertIsNone(h.nodes['A']._get_cached_route('A','B'))
        h.start(); h.pump()
        self.assertEqual([n for n,_,_ in h.injections], ['B','A'])
        h.auth(); h.pump()
        self.assert_complete(h)

    def test_repeat_keeps_original_x2_despite_new_random_order(self):
        h = self.make()
        h.start(); h.pump(drop=lambda s,d,o,p: p.get('leg') == 'x1-a')
        h.x2 = 'B'
        h.start(); h.pump()
        self.assertEqual([n for n,_,_ in h.injections], ['B','A'])
        selected = {r[1] for r in h.wire if r[2]['t'] == 'MCC_X2'}
        self.assertEqual(selected, {'Y'})

    def test_windowed_selection_can_replay_lost_response(self):
        h = self.make()
        class ManualTimer:
            def __init__(self, *args, **kwargs): pass
            def start(self): pass
            def cancel(self): pass
        with patch.object(M,'IKE_MCC_ACCEPT_WINDOW_S',1), patch.object(M.threading,'Timer',ManualTimer):
            h.start(); h.pump()
            b = h.nodes['B']
            context = next(iter(b.mcc_b_pending))
            b._select_MCC_offer(context)
            h.pump(drop=lambda s,d,o,p: p.get('leg') == 'x1-a')
            self.assertIsNone(h.nodes['A']._get_cached_route('A','B'))
            h.start(); h.pump()
            self.assertEqual([n for n,_,_ in h.injections], ['B','A'])

    def test_same_transport_accepts_new_ike_spi_after_ready(self):
        h = self.make()
        h.start(); h.pump(); h.auth(); h.pump()
        h.nodes['A'].send_ike_datagram('B',M.USERS['A']['ip'],500,M.USERS['B']['ip'],500,
                                      ike(spi=b'NEXTSP01'),500)
        h.pump()
        self.assertEqual([n for n,_,_ in h.injections], ['B','A','B','A','B','A'])

    def test_auth_can_rebuild_transport_after_ttl(self):
        h = self.make()
        h.start(); h.pump()
        old = h.nodes['A']._get_cached_route('A','B')
        old.created_at -= 121
        h.auth(); h.pump()
        self.assertEqual([n for n,_,_ in h.injections], ['B','A','B','A'])
        self.assertNotEqual(h.nodes['A']._get_cached_route('A','B').ab_context,old.ab_context)

    def test_all_candidate_capsules_fit_udp_even_with_twelve_members(self):
        h = self.make()
        members = NAMES + ['P'+str(i) for i in range(8)]
        extra = {n:{'ip':f'192.0.2.{i+10}','port':9000,'password':'synthetic-'+n} for i,n in enumerate(members[4:])}
        privacy_module = sys.modules['mcc_privacy']
        payload = bytearray(ike() + b'x'*484)
        payload[24:28] = len(payload).to_bytes(4,'big')
        with patch.object(M,'ACTIVE_USERS',members), patch.object(privacy_module,'ACTIVE_USERS',members), patch.dict(M.USERS,extra), patch.object(M,'IKE_MCC_IKE_FANOUT',8):
            h.nodes['A'].send_ike_datagram('B',M.USERS['A']['ip'],500,M.USERS['B']['ip'],500,bytes(payload),500)
        start_frames = [r for r in h.wire if r[2]['t']=='MCC_START']
        self.assertGreater(len(start_frames),1)
        self.assertTrue(all(len(M.jdump(r[2])) < 60000 for r in start_frames))
        self.assertEqual(sum(len(r[3]['branches']) for r in start_frames),11*8)

    def test_full_two_by_two_by_two_fanout_delivers_one_selected_copy(self):
        h = self.make()
        with patch.object(M, 'IKE_MCC_X1_FANOUT', 2), patch.object(M, 'IKE_MCC_X2_FANOUT', 2), patch.object(M, 'IKE_MCC_IKE_FANOUT', 2):
            h.start(); h.pump()
            self.assertEqual(sum(r[2]['t'] == 'MCC_X2' for r in h.wire), 8)
            self.assertEqual([n for n,_,_ in h.injections], ['B','A'])
            h.auth(); h.pump()
            self.assert_complete(h)

    def test_late_alternate_token_cannot_replace_selected_route(self):
        h = self.make()
        h.start(); h.pump()
        route = h.nodes['A']._get_cached_route('A','B')
        token = route.opaque_token
        reply = copy.deepcopy(h.final_replies()[0][3]); reply['route_token'] = 'f' * 64
        count = len(h.injections)
        h.emit('X','A','PRIV_BACK',reply); h.pump()
        self.assertEqual(len(h.injections),count)
        self.assertEqual(h.nodes['A']._get_cached_route('A','B').opaque_token,token)

    def test_expired_continuation_handle_rejected(self):
        h = self.make()
        h.start(); h.pump(); h.auth()
        request = copy.deepcopy(next(r[3] for r in h.wire if r[2]['t'] == 'MCC_OPAQUE_FWD'))
        h.queue.clear()
        for state in h.nodes['X'].mcc_opaque_handles.values(): state['created_at'] -= 121
        count = len(h.injections)
        h.emit('A','X','MCC_OPAQUE_FWD',request); h.pump()
        self.assertEqual(len(h.injections),count)

    def test_real_ike_accept_ignored_but_prebuild_accept_retained(self):
        h = self.make()
        message = {'mcc_session_id':'s','conn_id':'c','x1':'X','x2':'Y',
                   'dst':'B','selected_by':'B','mcc_carry_ike':True}
        h.nodes['A'].handle_MCC_ACCEPT('X', M.jdump(message))
        self.assertIsNone(h.nodes['A']._get_cached_route('A', 'B'))
        event = threading.Event()
        h.nodes['A'].mcc_accept_ev['s'] = event
        message.pop('mcc_carry_ike')
        h.nodes['A'].handle_MCC_ACCEPT('X', M.jdump(message))
        self.assertTrue(event.is_set())

    def test_non_mcc_inline_still_works(self):
        h = self.make(mcc=False)
        h.start(); h.pump(); h.auth(); h.pump()
        self.assertEqual([n for n,_,_ in h.injections], ['B','A','B','A'])
        self.assertTrue(h.nodes['A']._get_cached_route('A','B').x2)

    def test_ttl_and_error_remove_endpoint_key(self):
        h = self.make()
        h.start(); h.pump()
        route = h.nodes['A']._get_cached_route('A','B')
        route.created_at -= 121
        self.assertIsNone(h.nodes['A']._get_cached_route('A','B'))
        self.assertNotIn(route.ab_context, h.nodes['A'].priv_ab_state)
        for state in h.nodes['X'].mcc_opaque_handles.values(): state['created_at'] -= 121
        h.nodes['X']._opaque_prune()
        self.assertFalse(h.nodes['X'].mcc_opaque_handles)

    def test_failed_selected_delivery_can_retry(self):
        h = self.make(auto_reply=False)
        b = h.nodes['B']
        msg = {'mcc_session_id':'s','conn_id':'c','branch_id':'z',
               'mcc_carry_ike':True,'ike_payload':'00','opaque_mcc':1}
        b._accept_MCC_offer('s', {'peer':'Y','conn_id':'c','branch_id':'z','msg':msg})
        self.assertNotIn('s', b.mcc_b_delivered)

    def test_adapter_exception_rolls_back_then_real_request_can_retry(self):
        h = self.make()
        adapter = h.nodes['B'].ike_proxy
        def fail(*args): raise RuntimeError('synthetic adapter failure')
        with patch.object(adapter,'inject_to_charon',fail):
            h.start(); h.pump()
        self.assertFalse(h.nodes['B'].mcc_b_delivered)
        self.assertIsNone(h.nodes['B']._get_cached_route('A','B'))
        h.start(); h.pump(); h.auth(); h.pump()
        self.assert_complete(h)

    def test_legacy_demo_and_management_functions_are_unchanged(self):
        old_tree = ast.parse((ROOT/'baseline/hybrid-overlay/node_daemon.py').read_text(encoding='utf-8-sig'))
        new_tree = ast.parse((SOURCE/'node_daemon.py').read_text(encoding='utf-8-sig'))
        def methods(tree):
            cls = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='NodeDaemon')
            return {n.name:ast.dump(n,include_attributes=False) for n in cls.body if isinstance(n,ast.FunctionDef)}
        old,new = methods(old_tree),methods(new_tree)
        for name in ('on_mgmt_init','on_mgmt_auth','ensure_session','handle_I1','handle_I2',
                     'handle_OKX2','handle_PROXY','forward_proxy','on_local_connect','run_connection'):
            with self.subTest(method=name):
                self.assertEqual(old[name],new[name])


if __name__ == '__main__':
    if '--reproduce' in sys.argv:
        h = Harness()
        try:
            h.start(); h.pump(); h.auth(); h.pump()
            route = h.nodes['A']._get_cached_route('A','B')
            result = {'baseline_sha256':hashlib.sha256((SOURCE/'node_daemon.py').read_bytes()).hexdigest(),
                      'extra_accept_messages':sum(r[2]['t']=='MCC_ACCEPT' for r in h.wire),
                      'selected_x2_cached_at_A':route.x2,
                      'legitimate_init_auth_injections':len(h.injections),
                      'network_sockets_opened':False}
            assert result['extra_accept_messages'] == 3 and result['selected_x2_cached_at_A']=='Y'
            assert result['legitimate_init_auth_injections']==4
            print(json.dumps(result))
        finally:
            h.close()
    else:
        unittest.main(verbosity=2)
