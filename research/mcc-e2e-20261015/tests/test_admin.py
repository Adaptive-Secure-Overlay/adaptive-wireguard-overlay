import argparse,base64,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'candidate'))
import mcc_e2e_admin as admin
from cryptography.hazmat.primitives.asymmetric import ed25519
class AdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ['MCC_TEST_TMP_DIR']);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def args(self,node):return argparse.Namespace(node=node,directory=self.root/node,test_fixtures=True)
    def test_individual_keys_and_public_only_stdout_data(self):
        r=admin.keygen(self.args('A'));a=self.root/'A'
        self.assertEqual(set(p.name for p in a.iterdir()),{'signing.key','encryption.key','public-entry.json'})
        s=(a/'signing.key').read_text().strip();e=(a/'encryption.key').read_text().strip()
        self.assertEqual(len(bytes.fromhex(s)),32);self.assertNotEqual(s,e)
        self.assertNotIn(s,json.dumps(r));self.assertNotIn(e,json.dumps(r))
        self.assertEqual(r['public_entry']['keys']['key_id'],hashlib.sha256(bytes.fromhex(r['public_entry']['keys']['verification'])).hexdigest())
    def test_refuses_identity_overwrite(self):
        admin.keygen(self.args('A'));before={p.name:p.read_bytes() for p in (self.root/'A').iterdir()}
        with self.assertRaises(AssertionError):admin.keygen(self.args('A'))
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.root/'A').iterdir()})
    def test_windows_not_claimed_as_live_acl_acceptance(self):
        if os.name=='posix':self.skipTest('POSIX permission guard is exercised by core tests')
        args=self.args('A');args.test_fixtures=False
        with self.assertRaises(ValueError):admin.keygen(args)
        self.assertFalse(args.directory.exists())
    def prepare_registry(self):
        for n in ('A','B'):admin.keygen(self.args(n))
        issuer=ed25519.Ed25519PrivateKey.generate();private=self.root/'issuer.key';admin.create(private,admin.private_bytes(issuer).hex().encode())
        b64=lambda data:base64.urlsafe_b64encode(data).rstrip(b'=').decode()
        trust=self.root/'root.json';trust.write_text(json.dumps({'schema':admin.registry.ROOT_SCHEMA,'signers':{'root':{'algorithm':'Ed25519','public_key':b64(admin.public_bytes(issuer))}}}))
        return argparse.Namespace(version=2,entries=[self.root/n/'public-entry.json' for n in ('A','B')],from_v1=None,trust_root=trust,issuer_key=private,issuer_id='root',output=self.root/'registry.json',replace_encryption_keys=False,test_fixtures=True)
    def test_signs_public_entries_and_reverifies_against_root(self):
        args=self.prepare_registry();r=admin.sign_registry(args)
        self.assertTrue(r['signed']);self.assertEqual(r['nodes'],['A','B'])
        value=admin.registry.verify_registry_bytes(args.output.read_bytes(),args.trust_root,('A','B'));self.assertEqual(value.version,2)
    def test_untrusted_issuer_writes_no_registry(self):
        args=self.prepare_registry();args.issuer_id='untrusted'
        with self.assertRaises(admin.registry.TrustRegistryError):admin.sign_registry(args)
        self.assertFalse(args.output.exists())
    def test_duplicate_json_entry_rejected(self):
        args=self.prepare_registry();p=self.root/'bad.json';p.write_text('{"node":"A","node":"B","keys":{}}');args.entries=[p,p]
        with self.assertRaises(Exception):admin.sign_registry(args)
        self.assertFalse(args.output.exists())
    def v1_registry(self,args):
        issuer=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.issuer_key.read_text()))
        entries={json.loads(p.read_text())['node']:json.loads(p.read_text())['keys']['encryption'] for p in args.entries}
        signed={'schema':admin.registry._v1.REGISTRY_SCHEMA,'version':2,'nodes':entries}
        sig=base64.urlsafe_b64encode(issuer.sign(admin.registry._canonical_json(signed))).rstrip(b'=').decode()
        path=self.root/'v1.json';path.write_text(json.dumps({'signed':signed,'signatures':[{'algorithm':'Ed25519','key_id':'root','sig':sig}]}));return path
    def test_versioned_migration_preserves_authenticated_encryption_keys(self):
        args=self.prepare_registry();args.from_v1=self.v1_registry(args);args.version=3
        result=admin.sign_registry(args);self.assertEqual(result['migration_from_version'],2)
        value=admin.registry.verify_registry_bytes(args.output.read_bytes(),args.trust_root,('A','B'));self.assertEqual(value.version,3)
    def test_migration_refuses_implicit_encryption_key_replacement(self):
        args=self.prepare_registry();args.from_v1=self.v1_registry(args);args.version=3
        from cryptography.hazmat.primitives.asymmetric import x25519
        p=args.entries[0];entry=json.loads(p.read_text());entry['keys']['encryption']=admin.public_bytes(x25519.X25519PrivateKey.generate()).hex();p.write_text(json.dumps(entry))
        with self.assertRaises(AssertionError):admin.sign_registry(args)
        self.assertFalse(args.output.exists())
    def test_registry_output_not_overwritten(self):
        args=self.prepare_registry();admin.sign_registry(args);before=args.output.read_bytes()
        with self.assertRaises(FileExistsError):admin.sign_registry(args)
        self.assertEqual(before,args.output.read_bytes())
if __name__=='__main__':unittest.main(verbosity=2)
