"""Only power the existing isolated copy and read/export its saved checkpoint.

No lab-node launch, network changes, IKE connections, or old-result writes.
All operational evidence is supplied with --evidence in prepared staging.
"""
import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
PILOT = Path(r'C:\Codex\Candidate\Experiments\ike_real_ab_pilot_20261014')
sys.path.insert(0, str(PILOT))
import boot_stage as b

GUEST = '/root/candidate-ike-privacy-20261014'


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('boot', 'probe', 'fetch', 'stop'))
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--guest-script', type=Path)
    args = parser.parse_args()
    root = args.evidence.resolve()
    assert root.is_dir()
    status = root / 'extraction-status.json'
    if args.action == 'boot':
        assert not status.exists(), 'Existing boot: reconcile, do not replay'
        assert json.loads((PILOT / 'CLONE-CHECK.json').read_text())['passed']
        inventory = b.vmrun(['list'])
        assert 'Total running VMs: 0' in inventory
        isolation = b.c.vmx_contract()
        assert isolation['ram_gib'] == 32 and isolation['vcpus'] == 4
        memory = b.memory_gate(48)
        source = {
            'configs': {str(p): b.c.digest(p) for p in b.c.SOURCE.iterdir()
                        if p.is_file() and p.suffix in ('.vmx', '.vmsd', '.vmxf', '.nvram')},
            'disks': [b.c.metadata(p) for p in b.c.SOURCE.glob('*.vmdk')],
        }
        value = {'stage': 'boot_submitting', 'source_before': source,
                 'isolation': isolation, 'memory_before': memory,
                 'connections_started': 0, 'at_utc': b.c.now()}
        save(status, value)
        b.vmrun(['start', b.c.VMX, 'nogui'], timeout=120)
        value.update(stage='isolated_copy_started', memory_after=b.memory_gate(16))
        save(status, value)
        print(json.dumps({k: v for k, v in value.items() if k != 'source_before'}))
        return
    value = json.loads(status.read_text())
    if args.action in ('probe', 'fetch'):
        listing = b.vmrun(['list'])
        assert str(b.c.VMX) in listing and str(b.c.SOURCE_VMX) not in listing
        b.c.vmx_contract()
        tools = b.vmrun(['checkToolsState', b.c.VMX], timeout=15).strip()
        assert tools in ('running', 'installed'), 'Existing GuestOps not ready'
    if args.action == 'probe':
        assert args.guest_script and args.guest_script.is_file()
        assert not (root / 'guest-probe.json').exists(), 'Probe already collected'
        b.vmrun(['runProgramInGuest', b.c.VMX, '/bin/mkdir', '-p', GUEST], guest=True)
        b.vmrun(['copyFileFromHostToGuest', b.c.VMX, args.guest_script,
                 GUEST + '/probe.py'], guest=True)
        b.vmrun(['runProgramInGuest', b.c.VMX, '/usr/bin/python3', GUEST + '/probe.py'],
                guest=True, timeout=60)
        b.vmrun(['copyFileFromGuestToHost', b.c.VMX, GUEST + '/probe.json',
                 root / 'guest-probe.json'], guest=True)
        probe = json.loads((root / 'guest-probe.json').read_text())
        assert not probe['physical_nics'] and not probe['running_qemu']
        value.update(stage='guest_read_only_inventory', guest_tools=tools)
        save(status, value)
        print(json.dumps(probe))
    elif args.action == 'fetch':
        assert args.guest_script and args.guest_script.is_file()
        assert not (root / 'checkpoint.tar.gz').exists(), 'Export already collected'
        b.vmrun(['copyFileFromHostToGuest', b.c.VMX, args.guest_script,
                 GUEST + '/export.py'], guest=True)
        b.vmrun(['runProgramInGuest', b.c.VMX, '/usr/bin/python3', GUEST + '/export.py'],
                guest=True, timeout=90)
        b.vmrun(['copyFileFromGuestToHost', b.c.VMX, GUEST + '/export.json',
                 root / 'export.json'], guest=True)
        receipt = json.loads((root / 'export.json').read_text())
        assert receipt['passed'] and receipt['read_only_source']
        b.vmrun(['copyFileFromGuestToHost', b.c.VMX, GUEST + '/checkpoint.tar.gz',
                 root / 'checkpoint.tar.gz'], guest=True)
        assert b.c.digest(root / 'checkpoint.tar.gz') == receipt['sha256']
        value.update(stage='checkpoint_exported')
        save(status, value)
        print(json.dumps(receipt))
    elif args.action == 'stop':
        assert str(b.c.SOURCE_VMX) not in b.vmrun(['list'])
        b.vmrun(['stop', b.c.VMX, 'soft'], timeout=90)
        assert str(b.c.VMX) not in b.vmrun(['list'])
        for path, digest in value['source_before']['configs'].items():
            assert b.c.digest(Path(path)) == digest
        for record in value['source_before']['disks']:
            assert b.c.metadata(Path(record['path'])) == record
        value.update(stage='copy_stopped_source_unchanged', source_unchanged=True,
                     source_full_disk_hash_not_computed=True, at_utc=b.c.now())
        save(status, value)
        print(json.dumps({'stage': value['stage'], 'connections_started': 0}))


if __name__ == '__main__':
    main()
