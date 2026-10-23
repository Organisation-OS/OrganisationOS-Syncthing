# SPDX-License-Identifier: MPL-2.0
"""Synthetic package preparation checks: no helper process, CP or installation."""
import base64,datetime as dt,hashlib,json,pathlib,tempfile,unittest,zipfile
from build_dev import public_trust,VERSION,ENGINE_SHA
from package_dev import package

sha=lambda b:hashlib.sha256(b).hexdigest()


class FactoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='oos-dev-package-test-');self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.build=self.root/'build';self.build.mkdir()
        now=dt.datetime.now(dt.timezone.utc)
        self.trust=dict(schema='oos-helper-dev-trust-v1',enabled=True,audience='dev',publicKey=base64.b64encode(bytes(32)).decode(),
          installationId='11111111-1111-4111-8111-111111111111',instanceId='22222222-2222-4222-8222-222222222222',
          apiOrigin='https://dev.synthetic.invalid:18443',applicationId='synthetic-helper',minimumSequence=1,
          notBefore=(now-dt.timedelta(hours=1)).isoformat(),expiresAt=(now+dt.timedelta(hours=1)).isoformat())
        trust_raw=json.dumps(self.trust).encode();(self.build/'dev-trust.json').write_bytes(trust_raw)
        exe=b'synthetic bytes, never executed';source=b'synthetic source archive'
        (self.build/'OrganisationOS-Syncthing-Installer.exe').write_bytes(exe);(self.build/'source-installateur.zip').write_bytes(source)
        self.receipt=dict(version=VERSION,engineSha256=ENGINE_SHA,testsExitCode=0,helperSha256=sha(exe),publicTrustSha256=sha(trust_raw),publicTrust=self.trust,sourceArchiveSha256=sha(source),sourceCommit='a'*40)
        (self.build/'build.json').write_text(json.dumps(self.receipt))
        self.config=dict(schema=2,instanceId=self.trust['instanceId'],apiOrigin=self.trust['apiOrigin'],portalOrigin='https://portal.synthetic.invalid',organisationName='Synthetic',serverDeviceKey='-'.join(['AAAAAAA']*8),publicEndpoint='tcp://sync.synthetic.invalid:22223')
        self.configfile=self.root/'organisation.json';self.configfile.write_text(json.dumps(self.config))
        self.legal=self.root/'synthetic-legal.zip'
        with zipfile.ZipFile(self.legal,'w') as z:
            for name in ('LICENSE.txt','AUTHORS.txt','source-moteur.zip','notices/example.txt'):z.writestr(name,b'SYNTHETIC TEST ONLY')
        self.legalsha=sha(self.legal.read_bytes())

    def test_deterministic_dev_package_and_external_envelope(self):
        first=self.root/'one.zip';second=self.root/'two.zip'
        r=package(self.build,self.configfile,self.legal,self.legalsha,first)
        package(self.build,self.configfile,self.legal,self.legalsha,second)
        self.assertEqual(first.read_bytes(),second.read_bytes())
        self.assertNotEqual(r['installationId'],r['instanceId'])
        self.assertEqual('dev',r['provenance']['admissionAudience'])
        with zipfile.ZipFile(first) as z:
            self.assertNotIn('employee-software.json',z.namelist())
            self.assertEqual(VERSION,json.loads(z.read('provenance.json'))['installerVersion'])
        with self.assertRaises(FileExistsError):package(self.build,self.configfile,self.legal,self.legalsha,first)

    def test_changed_build_and_unverified_legal_bundle_refused(self):
        with self.assertRaises(ValueError):package(self.build,self.configfile,self.legal,'0'*64,self.root/'refused.zip')
        (self.build/'OrganisationOS-Syncthing-Installer.exe').write_bytes(b'changed')
        with self.assertRaises(ValueError):package(self.build,self.configfile,self.legal,self.legalsha,self.root/'refused.zip')
        self.assertFalse((self.root/'refused.zip').exists())

    def test_instance_and_legacy_override_refused(self):
        self.config['instanceId']='33333333-3333-4333-8333-333333333333';self.configfile.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError):package(self.build,self.configfile,self.legal,self.legalsha,self.root/'refused.zip')
        for id in ('27c0be38-60bd-4dce-bb28-ef0088716a25','b7a1f6b1-c4aa-4de7-95fb-29d509d3398d'):
            self.trust['instanceId']=id
            with self.assertRaises(ValueError):public_trust(json.dumps(self.trust).encode())


if __name__=='__main__':unittest.main()
