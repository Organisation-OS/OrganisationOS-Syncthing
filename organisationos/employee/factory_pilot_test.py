# SPDX-License-Identifier: MPL-2.0
"""Synthetic package preparation checks: no helper process, CP or installation."""
import base64,datetime as dt,hashlib,json,os,pathlib,tempfile,unittest,zipfile
from build_pilot import public_trust,VERSION,ENGINE_SHA
from package_pilot import package

sha=lambda b:hashlib.sha256(b).hexdigest()


class PilotFactoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='oos-dev-package-test-');self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.build=self.root/'build';self.build.mkdir()
        now=dt.datetime.now(dt.timezone.utc)
        self.trust=dict(schema='oos-helper-pilot-anchor-v1',enabled=True,audience='pilot',publicKey=base64.b64encode(bytes(32)).decode(),
          installationId='11111111-1111-4111-8111-111111111111',instanceId='22222222-2222-4222-8222-222222222222',
          apiOrigin='https://dev.synthetic.invalid:18443',applicationId='synthetic-helper',minimumSequence=1,
          notBefore=(now-dt.timedelta(hours=1)).isoformat(),expiresAt=(now+dt.timedelta(hours=1)).isoformat())
        self.trust.update(portalOrigin='https://portal.synthetic.invalid',publicEndpoint='tcp://sync.synthetic.invalid:22223')
        self.policy=dict(schema='oos-helper-pilot-trust-v1',enabled=True,anchors=[self.trust])
        trust_raw=json.dumps(self.policy).encode();(self.build/'pilot-trust.json').write_bytes(trust_raw)
        exe=b'synthetic bytes, never executed';source=b'synthetic source archive'
        (self.build/'OrganisationOS-Syncthing-Installer.exe').write_bytes(exe);(self.build/'source-installateur.zip').write_bytes(source)
        self.receipt=dict(version=VERSION,engineSha256=ENGINE_SHA,testsExitCode=0,helperSha256=sha(exe),publicTrustSha256=sha(trust_raw),publicTrust=self.policy,sourceArchiveSha256=sha(source),sourceCommit='a'*40)
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
        self.assertEqual('pilot',r['provenance']['admissionAudience'])
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
        original=dict(self.trust)
        for field,value in [('audience','dev'),('portalOrigin','http://evil.invalid'),('instanceId','bad')]:
            self.trust.clear();self.trust.update(original);self.trust[field]=value
            with self.assertRaises(ValueError):public_trust(json.dumps(self.policy).encode())
        self.trust.clear();self.trust.update(original)
        self.policy['anchors'].append(dict(self.trust))
        with self.assertRaises(ValueError):public_trust(json.dumps(self.policy).encode())

    def test_signed_destinations_must_match_compiled_anchor(self):
        for field,value in [('portalOrigin','https://other.invalid'),('publicEndpoint','tcp://other.invalid:22000')]:
            original=self.config[field];self.config[field]=value;self.configfile.write_text(json.dumps(self.config))
            with self.assertRaises(ValueError):package(self.build,self.configfile,self.legal,self.legalsha,self.root/'refused.zip')
            self.config[field]=original

    def test_actual_native_legal_source_bundle(self):
        path=os.environ.get('OOS_TEST_LEGAL_BUNDLE')
        if not path:self.skipTest('requires exact native legal/source bundle')
        legal=pathlib.Path(path);expected='3823696afb72c9e2b0c00a44614f72678545da1df7b423b7f193d2030af5b814'
        self.assertEqual(expected,sha(legal.read_bytes()))
        target=self.root/'native-legal-synthetic-helper.zip'
        result=package(self.build,self.configfile,legal,expected,target)
        with zipfile.ZipFile(target) as z:
            self.assertEqual(143,len(z.infolist()))
            with zipfile.ZipFile(legal) as original:
                for f in original.infolist():
                    if not f.is_dir():self.assertEqual(original.read(f),z.read(f.filename))
        self.assertEqual(expected,result['provenance']['legalBundleSha256'])

    def test_package_entry_limit_retains_every_notice_or_refuses(self):
        for notice_count,allowed in ((247,True),(248,False)):
            legal=self.root/('legal-'+str(notice_count)+'.zip')
            with zipfile.ZipFile(legal,'w') as z:
                for name in ('LICENSE.txt','AUTHORS.txt','source-moteur.zip'):z.writestr(name,b'Synthetic')
                for n in range(notice_count):z.writestr('notices/fixture-'+str(n)+'.txt',b'Synthetic')
            target=self.root/('package-'+str(notice_count)+'.zip')
            if allowed:
                package(self.build,self.configfile,legal,sha(legal.read_bytes()),target)
                with zipfile.ZipFile(target) as z:self.assertEqual(256,len(z.infolist()))
            else:
                with self.assertRaises(ValueError):package(self.build,self.configfile,legal,sha(legal.read_bytes()),target)
                self.assertFalse(target.exists())


if __name__=='__main__':unittest.main()
