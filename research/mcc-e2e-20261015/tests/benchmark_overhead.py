"""Bounded offline microbenchmark; not a connection/strongSwan timing test.

Run with Python -I -B, MCC_TEST_TMP_DIR pointing to disposable output storage.
Prints JSON only; does not retain keys, install packages, or use the network.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_registry_v2 import RegistryFixture
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'candidate'))
import cryptography
import mcc_e2e as core


def distribution(values):
    ordered = sorted(values)
    return {'n': len(values), 'median_ms': statistics.median(values),
            'p95_ms': ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]}


def measure(function, count=200):
    for _ in range(5):
        function()
    elapsed, cpu = [], []
    batch_cpu_start = time.process_time()
    for _ in range(count):
        start, cpu_start = time.perf_counter(), time.process_time()
        function()
        cpu.append(1000 * (time.process_time() - cpu_start))
        elapsed.append(1000 * (time.perf_counter() - start))
    return {'wall': distribution(elapsed), 'process_cpu': distribution(cpu),
            'batch_process_cpu_ms': 1000 * (time.process_time() - batch_cpu_start),
            'cpu_note': 'Windows process CPU quantization may yield zero per operation; not zero CPU cost'}


def main():
    with tempfile.TemporaryDirectory(prefix='mcc-benchmark-', dir=os.environ.get('MCC_TEST_TMP_DIR')) as directory:
        fixture = RegistryFixture(directory)
        registry = fixture.verified()
        nodes = {name: core.EndpointSecurity(name, registry, fixture.signing[name], fixture.encryption[name],
                  Path(directory) / (name + '.sqlite')) for name in ('A', 'B')}
        a, b = nodes['A'], nodes['B']
        body = {'ike_payload': 'ab' * 1024, 'ike_length': 1024, 'a_ke': '12' * 32,
                'selection': 'first', 'transport_conn': 'example-conn'}
        record = a.signed_message('B', 'benchmark', body, 0, 9)
        capsule = a.seal_to('B', record, 'benchmark', purpose='endpoint')
        unsigned_capsule = a.seal_to('B', body, 'benchmark', purpose='endpoint')
        unsigned_bytes, record_bytes = core.canonical_json(body), core.canonical_json(record)
        signed_bytes = core.canonical_json(record['signed'])
        signature = bytes.fromhex(record['signature'])
        results = {
            'schema': 'candidate-mcc-offline-overhead/v1', 'python': platform.python_version(),
            'cryptography': cryptography.__version__, 'network': False, 'charon': False,
            'scope': 'single-node module microbenchmark, synthetic 1024-byte IKE field; not connection latency',
            'sizes_bytes': {'example_body_json': len(unsigned_bytes), 'signed_record_json': len(record_bytes),
                'unsigned_endpoint_capsule_json': len(core.canonical_json(unsigned_capsule)),
                'signed_endpoint_capsule_json': len(core.canonical_json(capsule)),
                'signature_raw': len(signature)},
            'ed25519_sign': measure(lambda: fixture.signing['A'].sign(signed_bytes)),
            'ed25519_verify': measure(lambda: fixture.signing['A'].public_key().verify(signature, signed_bytes)),
            'verify_full_record': measure(lambda: b.verify_signed(record, 'benchmark')),
            'seal_signed_record': measure(lambda: a.seal_to('B', record, 'benchmark', purpose='endpoint')),
            'open_signed_capsule': measure(lambda: b.open_for_me(capsule, 'benchmark', purpose='endpoint')),
        }
        counter = iter(range(40))
        def durable_delivery():
            context = 'durable-' + str(next(counter))
            verified = b.verify_signed(a.signed_message('B', context, body, 0, 9), context)
            assert b.admit(verified) == 'new'
            assert b.claim_delivery(verified)
            b.delivered(verified)
        results['sign_verify_and_three_durable_transactions'] = measure(durable_delivery, count=30)
        tracemalloc.start()
        for _ in range(50):
            b.verify_signed(b.open_for_me(capsule, 'benchmark', purpose='endpoint'), 'benchmark')
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results['python_allocation_bytes_for_50_sequential_open_verify'] = {'current': current, 'peak': peak,
            'includes_native_crypto_allocations': False, 'is_rss_or_system_resource_cap': False}
        results['candidate_sha256'] = {name: hashlib.sha256((Path(__file__).resolve().parents[1] / 'candidate' / name).read_bytes()).hexdigest()
            for name in ('mcc_e2e.py', 'trust_registry.py')}
        print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
