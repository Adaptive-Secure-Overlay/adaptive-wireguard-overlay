"""Explicit, offline provisioning: one node's own keys, or public registry signing.

No network, no node deployment, no overwrite, no shared master derivation.
Issuer key is an operator-owned registry key, never a node signing key.
"""
import argparse,base64,hashlib,json,os,re,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,x25519
import trust_registry as registry
from mcc_e2e import strict_json_loads
from runtime_contract import require_runtime

def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def private_bytes(key):
    return key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())

def permissions(path,fixture=False):
    if os.name!='posix':
        if not fixture:raise ValueError('Native node provisioning requires verified POSIX permissions; Windows is test-fixtures only')
        return False
    st=path.stat()
    if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:
        raise ValueError('Private key must belong to the current user with no group/world permissions')
    return True

def create(path,raw,mode=0o600):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
    fd=os.open(path,flags,mode)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def node_entry(name,signing,encryption):
    verify=public_bytes(signing);enc=public_bytes(encryption)
    return {'node':name,'keys':{'encryption':enc.hex(),'verification':verify.hex(),
        'key_id':hashlib.sha256(verify).hexdigest(),'revoked':False}}

def keygen(args):
    assert re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',args.node),'Invalid node name'
    if os.name!='posix' and not args.test_fixtures:raise ValueError('Windows private-key ACL not qualified; explicit --test-fixtures required')
    directory=args.directory.resolve()
    assert not directory.exists(),'Refuse to overwrite an identity directory'
    directory.mkdir(mode=0o700,parents=False)
    signing=ed25519.Ed25519PrivateKey.generate();encryption=x25519.X25519PrivateKey.generate()
    for name,key in (('signing.key',signing),('encryption.key',encryption)):
        create(directory/name,private_bytes(key).hex().encode()+b'\n')
        permissions(directory/name,args.test_fixtures)
    entry=node_entry(args.node,signing,encryption)
    create(directory/'public-entry.json',json.dumps(entry,sort_keys=True,separators=(',',':')).encode()+b'\n',0o644)
    # stdout contains public data only. No private bytes or command-line secret.
    return {'generated':True,'node':args.node,'public_entry':entry,'posix_permissions_verified':os.name=='posix','test_fixtures_only':args.test_fixtures}

def sign_registry(args):
    assert args.version>=1
    entries={}
    for path in args.entries:
        raw=path.read_bytes();assert len(raw)<=8192
        entry=strict_json_loads(raw,max_bytes=8192)
        assert set(entry)=={'node','keys'} and entry['node'] not in entries
        entries[entry['node']]=entry['keys']
    assert 2<=len(entries)<=256
    old_version=None
    if args.from_v1:
        import trust_registry_v1 as old
        value=old.verify_registry_bytes(args.from_v1.read_bytes(),args.trust_root,entries)
        old_version=value.version;assert args.version>old_version,'Migration requires a higher accepted version'
        replacements=[n for n in entries if entries[n]['encryption']!=value.nodes[n]]
        assert not replacements or args.replace_encryption_keys,'Individual replacement encryption keys require explicit --replace-encryption-keys'
    assert not args.issuer_key.is_symlink()
    permissions(args.issuer_key,args.test_fixtures)
    raw=args.issuer_key.read_bytes();assert len(raw)<=65
    value=raw.decode('ascii').rstrip('\n')
    assert len(value)==64 and bytes.fromhex(value).hex()==value
    issuer=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))
    signed={'schema':registry.REGISTRY_SCHEMA,'version':args.version,'nodes':entries}
    sig=issuer.sign(registry._canonical_json(signed))
    envelope={'signed':signed,'signatures':[{'key_id':args.issuer_id,'algorithm':'Ed25519','sig':base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}]}
    data=registry._canonical_json(envelope)
    # Reverify actual output against pinned trust root before creating it.
    verified=registry.verify_registry_bytes(data,args.trust_root,entries)
    create(args.output,data+b'\n',0o644)
    return {'signed':True,'version':verified.version,'nodes':sorted(entries),'migration_from_version':old_version,'output_sha256':hashlib.sha256(data+b'\n').hexdigest(),'test_fixtures_only':args.test_fixtures}

def main():
    require_runtime()
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    k=sub.add_parser('keygen');k.add_argument('--node',required=True);k.add_argument('--directory',type=Path,required=True);k.add_argument('--test-fixtures',action='store_true')
    s=sub.add_parser('sign-registry');s.add_argument('--entries',type=Path,nargs='+',required=True);s.add_argument('--trust-root',type=Path,required=True);s.add_argument('--issuer-key',type=Path,required=True);s.add_argument('--issuer-id',required=True);s.add_argument('--version',type=int,required=True);s.add_argument('--output',type=Path,required=True);s.add_argument('--from-v1',type=Path);s.add_argument('--replace-encryption-keys',action='store_true');s.add_argument('--test-fixtures',action='store_true')
    args=p.parse_args()
    result=keygen(args) if args.action=='keygen' else sign_registry(args)
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
    try:main()
    except Exception as error:
        # Avoid including key material or raw documents in exception text.
        print(json.dumps({'failed':True,'error_type':type(error).__name__}),file=sys.stderr);raise SystemExit(1)
