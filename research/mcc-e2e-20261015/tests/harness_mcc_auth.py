"""Offline active-daemon wire harness. No sockets, VM, charon or real ESP.

Nodes use their own endpoint private keys, a public VerifiedRegistry and actual
NodeDaemon link AEAD methods. An attacker view contains only its own daemon.
Persistent fixture state is confined to the caller-selected temporary root.
"""
import ast
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'candidate'
NAMES = ['A', 'B', 'X', 'Y']


def load_code():
    for name in ('node_daemon', 'mcc_privacy', 'mcc_auth', 'mcc_e2e', 'trust_registry',
                 'crypto_util', 'protocol', 'config', 'logging_util', 'ike_proxy', 'link_transport'):
        sys.modules.pop(name, None)
    cfg = types.ModuleType('config')
    tree = ast.parse((SOURCE / 'node_daemon.py').read_text(encoding='utf-8-sig'))
    fields = next(n.names for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == 'config')
    for field in fields:
        setattr(cfg, field.name, 0)
    cfg.USERS = {name: {'ip': '192.0.2.%d' % (index + 1), 'port': 9000,
                        'password': 'unusable-public-lab-password'} for index, name in enumerate(NAMES)}
    cfg.ACTIVE_USERS = list(NAMES)
    cfg.IKE_MCC_ENABLED = True
    cfg.IKE_PRIVACY_OVERLAY = True
    cfg.IKE_PRIVACY_INLINE = True
    cfg.IKE_MCC_ROUTE_TIMEOUT_S = 10
    cfg.IKE_ROUTE_CACHE_TTL_S = 120
    cfg.IKE_INLINE_ROUTE_TIMEOUT_S = 10
    cfg.RETRIES = 1
    # Allow importing the real adapter for separate outcome-contract tests.
    cfg.IKE_CAPTURE_BIND = '127.0.0.1'
    cfg.IKE_CAPTURE_PORTS = {500: 15000, 4500: 15001}
    cfg.IKE_CAPTURE_USER_PORTS = {}
    cfg.IKE_CHARON_HOST = '127.0.0.1'
    cfg.IKE_CHARON_PORTS = {500: 500, 4500: 4500}
    cfg.IKE_PROXY_DEFAULT_DST_USER = ''
    cfg.IKE_SOCKET_MARK = 1
    cfg.IKE_TRANSPARENT_INJECT_REQUIRED = True
    sys.modules['config'] = cfg
    logging = types.ModuleType('logging_util')
    logging.setup_logger = lambda name: Log()
    sys.modules['logging_util'] = logging
    sys.path.insert(0, str(SOURCE))
    try:
        module = importlib.import_module('node_daemon')
        auth = importlib.import_module('mcc_auth')
        core = importlib.import_module('mcc_e2e')
        trust = importlib.import_module('trust_registry')
        adapter = importlib.import_module('ike_proxy')
    finally:
        sys.path.pop(0)
    return module, auth, core, trust, adapter


class Log:
    def __init__(self):
        self.lines = []

    def __getattr__(self, unused):
        return lambda text, *args: self.lines.append(str(text))


M, AUTH, CORE, TRUST, ADAPTER = load_code()


def ike(exchange=34, response=False, port=500, spi=b'INITSP01', message_id=0, tail=b''):
    header = spi + (b'RESPSP01' if response or exchange != 34 else b'\0' * 8)
    header += bytes([0, 0x20, exchange, 0x20 if response else 0x08])
    header += message_id.to_bytes(4, 'big') + (28 + len(tail)).to_bytes(4, 'big')
    return (b'\0' * 4 if port == 4500 else b'') + header + tail


class Harness:
    def __init__(self, mode='first', fanout=(1, 1, 9), x1='X', x2='Y', port=500, auto_reply=True,
                 quiet_ms=150, deadline_ms=1000, real_link=False, echo_reply_payload=False):
        self.queue, self.wire, self.injections, self.local_offers = [], [], [], []
        self.nodes = {}
        self.x1, self.x2, self.port = x1, x2, port
        self.auto_reply = auto_reply
        self.real_link, self.echo_reply_payload = real_link, echo_reply_payload
        self.raw_frames, self.assembled_sizes = [], []
        self.now = time.monotonic()
        self.timers = []
        temp_root = os.environ.get('MCC_TEST_TMP_DIR') or os.environ.get('TEMP')
        self.temp = tempfile.TemporaryDirectory(prefix='mcc-auth-wire-', dir=temp_root)
        self.policy = {'mode': mode, 'window_ms': 100 if mode == 'window' else 0,
                       'deadline_ms': deadline_ms, 'min_copies': 3, 'quiet_ms': quiet_ms}
        import config as cfg
        cfg.IKE_MCC_X1_FANOUT, cfg.IKE_MCC_X2_FANOUT, cfg.IKE_MCC_IKE_FANOUT = fanout
        cfg.IKE_MCC_ENABLED = M.IKE_MCC_ENABLED = True
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        materials = {name: (ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()) for name in NAMES}
        publics = {name: {'encryption': keys[1].public_key().public_bytes_raw().hex(),
                         'verification': keys[0].public_key().public_bytes_raw().hex(),
                         'key_id': hashlib.sha256(keys[0].public_key().public_bytes_raw()).hexdigest(),
                         'revoked': False} for name, keys in materials.items()}
        self.registry = TRUST.VerifiedRegistry(1, 'test-root', publics, 'fixture-only')
        self._materials = materials  # fixture owner, NEVER included in attacker view
        harness = self

        class DeferredThread:
            def __init__(self, target, args=(), kwargs=None, **unused):
                self.target, self.args, self.kwargs = target, args, kwargs or {}

            def start(self):
                harness.queue.append(('call', self.target, self.args, self.kwargs))

        class DeferredTimer:
            def __init__(self, interval, target, args=(), kwargs=None):
                self.interval, self.target, self.args, self.kwargs = interval, target, args, kwargs or {}
                self.cancelled = False
                self.daemon = True

            def start(self):
                self.due = harness.now + self.interval
                harness.timers.append(self)

            def cancel(self):
                self.cancelled = True

        self.patches = [
            patch.object(M, 'threading', types.SimpleNamespace(Thread=DeferredThread, Lock=threading.RLock,
                          Event=threading.Event, Timer=DeferredTimer)),
            patch.object(AUTH, 'threading', types.SimpleNamespace(Thread=DeferredThread, Lock=threading.RLock,
                          Event=threading.Event, Timer=DeferredTimer, local=threading.local,
                          BoundedSemaphore=threading.BoundedSemaphore)),
            patch.object(AUTH, 'time', types.SimpleNamespace(time=time.time, monotonic=lambda: harness.now)),
        ]
        for item in self.patches:
            item.start()
        for name in NAMES:
            self.nodes[name] = self.new_node(name)

    def new_node(self, name):
        node = M.NodeDaemon.__new__(M.NodeDaemon)  # no __init__, no socket bind
        node.name = name
        node.lock = threading.RLock()
        node.ike_route_lock = threading.RLock()
        node.logger = Log()
        for field in ('sessions', 'priv_x1_state', 'priv_x2_state', 'priv_b_state', 'priv_ab_state',
                      'priv_x2_pub', 'mcc_accept_ev', 'mcc_accept_data', 'mcc_b_selected',
                      'mcc_b_delivered', 'mcc_b_pending', 'mcc_b_timers', 'ike_routes',
                      'route_cooldowns', 'route_failure_counts', 'conns', 'okx2_ev',
                      'okx2_data', 'okx2_x2name', 'ensure_inflight'):
            setattr(node, field, {})
        node._init_opaque_mcc()
        node._init_link_transport()
        signing, encryption = self._materials[name]
        security = CORE.EndpointSecurity(name, self.registry, signing, encryption,
                                         Path(self.temp.name) / (name + '.sqlite'))
        node._init_mcc_auth(security, self.policy)
        for peer in NAMES:
            if peer != name:
                label = '-'.join(sorted((name, peer)))
                node.sessions[peer] = M.MgmtSession(peer, label, hashlib.sha256(label.encode()).digest())
        node.ensure_session = types.MethodType(lambda n, peer, **unused: peer != n.name, node)
        harness = self

        def ordered(n, candidates, unused_env, role):
            forced = harness.x1 if role == 'X1' else harness.x2
            return ([forced] if forced in candidates else []) + [p for p in candidates if p != forced]

        node._ordered_route_candidates = types.MethodType(ordered, node)

        def send(n, peer, data):
            assert peer != n.name, 'No network self-send'
            message = json.loads(data)
            plain = self.nodes[peer].link_decrypt(message)
            self.wire.append((n.name, peer, copy.deepcopy(message), json.loads(plain)))
            self.queue.append(('wire', n.name, peer, message))

        def raw_send(n, peer, data):
            self.raw_frames.append((n.name, peer, len(data)))
            packet = json.loads(data)
            if packet.get('t') == 'LINK_FRAG':
                assembled = self.nodes[peer]._handle_link_frag(packet, n.name)
                if assembled is None:
                    return
                data = assembled
            self.assembled_sizes.append(len(data))
            send(n, peer, data)

        if self.real_link:
            node._send_peer_raw = types.MethodType(raw_send, node)
            node.send_peer = types.MethodType(M.LinkTransportMixin.send_peer, node)
        else:
            node.send_peer = types.MethodType(send, node)

        def inject(payload, meta):
            self.injections.append((name, bytes(payload), copy.deepcopy(meta)))
            off = 4 if meta['udp_port'] == 4500 else 0
            if self.auto_reply and name == 'B' and not payload[off + 19] & 0x20:
                reply = ike(payload[off + 18], True, meta['udp_port'], payload[off:off + 8],
                            int.from_bytes(payload[off + 20:off + 24], 'big'),
                            tail=payload[off + 28:] if self.echo_reply_payload else b'')
                self.queue.append(('call', self.nodes['B'].send_ike_datagram,
                    ('A', M.USERS['B']['ip'], meta['udp_port'], M.USERS['A']['ip'], meta['udp_port'], reply, meta['udp_port']), {}))
            return True

        node.ike_proxy = types.SimpleNamespace(inject_to_charon=inject)
        original_offer = node.handle_MCC_OFFER

        def local_offer(n, peer, plain):
            if peer == n.name:
                self.local_offers.append((n.name, n.name, {'t': 'MCC_OFFER'}, json.loads(plain)))
            return original_offer(peer, plain)

        node.handle_MCC_OFFER = types.MethodType(local_offer, node)
        return node

    def close(self):
        for timer in self.timers:
            timer.cancel()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def attacker(self, name='Y'):
        # Attacker owns its daemon/private keys and neighbor sessions only.
        # It has no reference to fixture materials, A/B daemons or their keys.
        node = self.nodes[name]
        return types.SimpleNamespace(name=name, security=node.mcc_security, sessions=node.sessions,
                                     registry=self.registry)

    def start(self, payload=None):
        self.nodes['A'].send_ike_datagram('B', M.USERS['A']['ip'], self.port,
            M.USERS['B']['ip'], self.port, payload or ike(port=self.port), self.port)

    def auth(self):
        self.nodes['A'].send_ike_datagram('B', M.USERS['A']['ip'], self.port,
            M.USERS['B']['ip'], self.port, ike(35, port=self.port, message_id=1), self.port)

    def pump(self, intercept=None):
        count = 0
        while self.queue:
            count += 1
            assert count <= 6000, 'Bounded offline event queue'
            event = self.queue.pop(0)
            if event[0] == 'call':
                _, fn, args, kwargs = event
                fn(*args, **kwargs)
                continue
            _, src, dst, envelope = event
            plain = json.loads(self.nodes[dst].link_decrypt(envelope))
            if intercept and intercept(src, dst, envelope, plain):
                continue
            self.nodes[dst].on_secure_msg(envelope, src)

    def advance(self, seconds):
        self.now += seconds
        for _ in range(10):
            due = [t for t in self.timers if not t.cancelled and t.due <= self.now]
            if not due:
                return
            for timer in due:
                timer.cancelled = True
                timer.target(*timer.args, **timer.kwargs)
            self.pump()
        raise AssertionError('Unbounded timer work')

    def emit(self, src, dst, typ, body, meta=None):
        self.nodes[src].link_send(dst, typ, M.jdump(body), meta=meta or {'mode': 'test'})

    def offers(self):
        return [entry for entry in self.wire if entry[2]['t'] == 'MCC_OFFER'] + self.local_offers

    def selected_count(self):
        return len(self.nodes['B'].mcc_b_selected)

    def candidate_count(self):
        return sum(len(s['offers']) for s in self.nodes['B']._mcc_auth_pending.values())
