#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import base64,copy,json,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import native_install as native
from cp_runtime_publish import archive
HERE=pathlib.Path(__file__).resolve().parent
class SignedNativeRuntime(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(dir='/srv/organisation-workspace/evidence/connectors-office-offline-20261020',prefix='oos-native-package-test-');root=pathlib.Path(cls.temp.name);cls.root=root
  source='1'*40
  for name in native.FILES-{'runtime-provenance.json'}:
   p=HERE.parent.parent/'organisationos-output/a/organisationos-syncthing' if name=='organisationos-syncthing' else HERE.parent.parent/'LICENSE' if name=='LICENSE' else HERE/name
   (root/name).write_bytes(p.read_bytes())
  (root/'runtime-provenance.json').write_bytes(native.canonical({'sourceCommit':source,'engineCommit':'e80f807467f5e127f35e2de45cfd22d4091bcd42','files':{n:native.digest((root/n).read_bytes())for n in native.FILES-{'runtime-provenance.json'}}}))
  cls.raw=archive(root);cls.m={'schema':'oos-document-runtime-release-v1','installationId':'27c0be38-60bd-4dce-bb28-ef0088716a25','instanceId':'27c0be38-60bd-4dce-bb28-ef0088716a25','sequence':1,'operation':'install','activateWorker':False,'artifact':{'sha256':native.digest(cls.raw),'size':len(cls.raw),'version':'0.1.0','sourceCommit':source,'engineCommit':'e80f807467f5e127f35e2de45cfd22d4091bcd42','engineSha256':native.PIN}}
  cls.key=Ed25519PrivateKey.generate();cls.pub=cls.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def envelope(self):
  e={'schema':'oos-signed-v1','purpose':native.PURPOSE,'algorithm':'Ed25519','issuer':native.digest(self.pub),'payload':self.m};e['signature']=base64.b64encode(self.key.sign(native.canonical(e))).decode();return e
 def test_actual_archive_closure(self):self.assertEqual(set(native.unpack(self.raw,self.m['artifact'])),native.FILES)
 def test_reproducible_control_plane_recipe(self):self.assertEqual(self.raw,archive(self.root))
 def test_signature(self):self.assertEqual(native.verify(self.envelope(),self.pub),self.m)
 def test_changed_activation_refused(self):
  e=self.envelope();e=copy.deepcopy(e);e['payload']['activateWorker']=True
  with self.assertRaises(Exception):native.verify(e,self.pub)
 def test_wrong_purpose_refused(self):
  e=self.envelope();e['purpose']='organisation-employee-software-v1'
  with self.assertRaises(Exception):native.verify(e,self.pub)
 def test_cross_instance_refused(self):
  m=copy.deepcopy(self.m);m['instanceId']='b7a1f6b1-c4aa-4de7-95fb-29d509d3398d'
  with self.assertRaises(ValueError):native.validate(m)
 def test_binary_tampering_refused(self):
  with self.assertRaises(ValueError):native.unpack(self.raw[:-1]+bytes([self.raw[-1]^1]),self.m['artifact'])
 def test_no_private_state_in_bundle(self):
  names=set(native.unpack(self.raw,self.m['artifact']));self.assertFalse(names&{'key.pem','cert.pem','config.xml','service.json'});self.assertFalse(self.m['activateWorker'])
if __name__=='__main__':unittest.main()
