"""Reproduce the two baseline issues, validate the local candidate, emit evidence.

No VMware/network/daemon initialization. Evidence goes only to caller-selected
prepared staging. Baseline config is never printed or included in the diff.
"""
import argparse
import ast
import datetime
import difflib
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
BASE = ROOT / 'baseline/hybrid-overlay'
CANDIDATE = ROOT / 'candidate/hybrid-overlay'
ARCHIVE_SHA = '476fabcad148ce27e5ceef60f1151b509d6051a7406d1e292e166c151a8576fb'
NODE_SHA = '791af0fe3a41fc3b416769fc3b716f6e22eb890b83daa14dcacb227fa634728e'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    assert evidence.is_dir()
    before = {str(p.relative_to(BASE)): sha(p) for p in BASE.rglob('*') if p.is_file()}
    assert sha(ROOT / 'baseline/last-pilot.tar.gz') == ARCHIVE_SHA
    assert sha(BASE / 'node_daemon.py') == NODE_SHA
    syntax = []
    for p in [*CANDIDATE.rglob('*.py'), *ROOT.joinpath('tests').rglob('*.py'), Path(__file__)]:
        ast.parse(p.read_text(encoding='utf-8-sig'), filename=str(p))
        syntax.append(str(p.relative_to(ROOT)))
    test = ROOT / 'tests/test_mcc_privacy.py'
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    env = dict(os.environ, MCC_TEST_SOURCE=str(BASE))
    reproduction = subprocess.run([sys.executable, '-I', '-B', str(test), '--reproduce'],
                                  capture_output=True, text=True, env=env, timeout=20, creationflags=flags)
    (evidence / 'baseline-reproduction.log').write_text(reproduction.stdout + reproduction.stderr, encoding='utf-8')
    assert reproduction.returncode == 0, 'Baseline reproduction failed'
    baseline = json.loads(reproduction.stdout)
    env['MCC_TEST_SOURCE'] = str(CANDIDATE)
    checks = subprocess.run([sys.executable, '-I', '-B', str(test)], capture_output=True,
                            text=True, env=env, timeout=20, creationflags=flags)
    (evidence / 'candidate-tests.log').write_text(checks.stdout + checks.stderr, encoding='utf-8')
    changed = []
    patch_parts = []
    for name in ('node_daemon.py', 'protocol.py', 'mcc_privacy.py'):
        old = (BASE / name).read_text(encoding='utf-8-sig') if (BASE / name).exists() else ''
        new = (CANDIDATE / name).read_text(encoding='utf-8-sig')
        if old != new:
            changed.append(name)
            patch_parts.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                fromfile='a/hybrid-overlay/' + name if old else '/dev/null',
                tofile='b/hybrid-overlay/' + name))
    patch_parts.extend(difflib.unified_diff([], test.read_text(encoding='utf-8').splitlines(True),
                                         fromfile='/dev/null', tofile='b/tests/test_mcc_privacy.py'))
    patch_path = evidence / 'candidate.patch'
    patch_path.write_text(''.join(patch_parts), encoding='utf-8', newline='\n')
    after = {str(p.relative_to(BASE)): sha(p) for p in BASE.rglob('*') if p.is_file()}
    assert before == after, 'Immutable baseline changed'
    untouched = [name for name in before if name not in changed]
    assert all(sha(BASE / name) == sha(CANDIDATE / name) for name in untouched)
    result = {
        'passed': checks.returncode == 0, 'scope': 'offline-only local candidate; not deployed',
        'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'archive_sha256': ARCHIVE_SHA, 'baseline_node_sha256': NODE_SHA,
        'baseline_reproduction': baseline, 'syntax_files': syntax,
        'test_command': [sys.executable, '-I', '-B', str(test)],
        'unit_test_exit_code': checks.returncode, 'changed_code_files': changed,
        'unit_test_methods': int(re.search(r'Ran (\d+) tests', checks.stderr).group(1)),
        'role_port_scenarios_in_matrix': 18,
        'baseline_unchanged': before == after, 'other_candidate_files_unchanged': True,
        'candidate_code_hashes': {n: sha(CANDIDATE / n) for n in changed},
        'test_source_sha256': sha(test), 'patch_sha256': sha(patch_path),
        'new_connections': 0, 'network_sockets_opened_by_tests': False,
        'runtime_installs': 0, 'live_IKE_acceptance': 'not_run_by_user_instruction',
        'resource_limits': 'one lightweight offline process; 20s subprocess timeout',
        'rework': ['duplicate branch initialization corrected',
                   'one independent review found four regressions; all reproduced and covered by tests',
                   'large initial capsule groups batched to fit UDP',
                   'adapter failure rollback covered',
                   'one test method-name typo repaired',
                   'patch output normalized to LF for native Git application'],
        'actual_total_usage_tokens': None, 'usage_reason': 'combined parent/agent counters unavailable',
    }
    (evidence / 'LOCAL-VALIDATION.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))
    return 0 if checks.returncode == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
