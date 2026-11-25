"""Offline package checks. Output must be disposable, outside the source tree.

No deployment, sockets, installs or mutation of baseline/historical results.
"""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--baseline-contract', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = args.output_dir.resolve()
    if output.is_relative_to(root) or not output.is_dir():
        parser.error('Output must be an existing disposable directory outside source')
    outputs = ['validation.json', 'tests.txt', 'overhead.json', 'candidate.diff']
    if any((output / name).exists() for name in outputs):
        parser.error('Refusing to overwrite an earlier evidence run')
    contract = json.loads(args.baseline_contract.read_text(encoding='utf-8-sig'))
    expected = contract['candidate_files']
    baseline = {name: digest(root / 'baseline' / name) for name in expected}
    if baseline != expected:
        raise RuntimeError('Baseline does not match sealed source contract')
    historical_root = args.baseline_contract.parent / 'candidate-code'
    historical = {name: digest(historical_root / name) for name in expected}
    if historical != expected:
        raise RuntimeError('Historical source does not match sealed source contract')
    files = sorted(p for folder in ('candidate', 'tests') for p in (root / folder).rglob('*')
                   if p.is_file() and '__pycache__' not in p.parts)
    before = {str(p.relative_to(root)): digest(p) for p in files}
    parsed = []
    for path in files + [Path(__file__)]:
        if path.suffix == '.py':
            ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
            parsed.append(str(path.relative_to(root)))
    diff = []
    names = sorted({p.relative_to(root / folder) for folder in ('baseline', 'candidate')
                    for p in (root / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts})
    for name in names:
        old, new = root / 'baseline' / name, root / 'candidate' / name
        left = old.read_text(encoding='utf-8-sig').splitlines(keepends=True) if old.exists() else []
        right = new.read_text(encoding='utf-8-sig').splitlines(keepends=True) if new.exists() else []
        diff.extend(difflib.unified_diff(left, right, fromfile='baseline/' + name.as_posix(), tofile='candidate/' + name.as_posix()))
    (output / 'candidate.diff').write_text(''.join(diff), encoding='utf-8')
    env = dict(os.environ, MCC_TEST_TMP_DIR=str(output), TEMP=str(output), TMP=str(output))
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    commands = [
        ('tests.txt', [sys.executable, '-X', 'utf8', '-I', '-B', '-W', 'error::ResourceWarning', '-m', 'unittest',
                       'discover', '-s', str(root / 'tests'), '-p', 'test_*.py', '-v']),
        ('overhead.json', [sys.executable, '-X', 'utf8', '-I', '-B', str(root / 'tests' / 'benchmark_overhead.py')])]
    runs = []
    for name, command in commands:
        start = time.perf_counter()
        result = subprocess.run(command, env=env, cwd=output, capture_output=True, timeout=180,
                                creationflags=flags, check=False)
        (output / name).write_bytes(result.stdout + result.stderr)
        runs.append({'command': command, 'exit_code': result.returncode, 'wall_s': time.perf_counter() - start,
                     'artifact': name, 'sha256': digest(output / name)})
        if result.returncode:
            break
    after = {str(p.relative_to(root)): digest(p) for p in files}
    stable = before == after and all(digest(root / 'baseline' / name) == sha for name, sha in expected.items())
    stable = stable and all(digest(historical_root / name) == sha for name, sha in expected.items())
    summary = {'schema': 'candidate-mcc-local-validation/v1', 'network_used': False,
        'baseline_files_verified': len(expected), 'historical_source_files_verified': len(historical),
        'ast_checked': parsed, 'source_hashes': after, 'sources_unchanged_during_validation': stable,
        'runs': runs, 'passed': stable and len(runs) == 2 and all(r['exit_code'] == 0 for r in runs),
        'live_ike_esp_verified': False, 'native_posix_private_key_permissions_verified': False}
    (output / 'validation.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
