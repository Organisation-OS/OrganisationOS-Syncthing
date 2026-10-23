#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build a DEV helper in an isolated export using PUBLIC CP-admitted inputs.
No CP credentials, signing, installation, enrollment or production mutation.
The relay must separately approve the public trust input; syntax is not trust.
"""
import argparse, base64, datetime as dt, hashlib, io, json, os, pathlib, re
import subprocess, tempfile, zipfile

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
VERSION='0.3.6-dev.1'
ENGINE_SHA='14421c4afbe5b48ddd9065410310f6fd667d678ae5943bd9520f28f261d8eb4b'
LEGACY={'27c0be38-60bd-4dce-bb28-ef0088716a25','b7a1f6b1-c4aa-4de7-95fb-29d509d3398d'}
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def public_trust(raw):
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('duplicate public trust field')
            out[k]=v
        return out
    t=json.loads(raw,object_pairs_hook=unique)
    fields={'schema','enabled','audience','publicKey','installationId','instanceId','apiOrigin','applicationId','minimumSequence','notBefore','expiresAt'}
    if len(raw)>4096 or set(t)!=fields:raise ValueError('closed public trust schema required')
    if t['schema']!='oos-helper-dev-trust-v1' or t['enabled'] is not True or t['audience']!='dev':raise ValueError('DEV only')
    if len(base64.b64decode(t['publicKey'],validate=True))!=32:raise ValueError('Ed25519 public key required')
    pattern=r'[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}'
    if any(not re.fullmatch(pattern,t[k]) for k in ('installationId','instanceId')) or t['instanceId'] in LEGACY:raise ValueError('distinct DEV identity required')
    if type(t['minimumSequence']) is not int or t['minimumSequence']<1 or not t['applicationId']:raise ValueError('sequence and application required')
    from urllib.parse import urlsplit
    u=urlsplit(t['apiOrigin'])
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.path or u.query or u.fragment:raise ValueError('HTTPS API origin required')
    start=dt.datetime.fromisoformat(t['notBefore']);end=dt.datetime.fromisoformat(t['expiresAt'])
    if start.tzinfo is None or end.tzinfo is None or not dt.timedelta(0)<end-start<=dt.timedelta(hours=24):raise ValueError('bounded UTC admission required')
    if not start<=dt.datetime.now(dt.timezone.utc)<end:raise ValueError('admission inactive')
    return t


def build(trust_file,engine_file,output,go):
    raw=pathlib.Path(trust_file).read_bytes();trust=public_trust(raw)
    engine=pathlib.Path(engine_file).read_bytes()
    if sha(engine)!=ENGINE_SHA:raise ValueError('qualified engine hash mismatch')
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain','--','organisationos/employee'],cwd=ROOT):raise ValueError('commit helper source before fabrication')
    archive=subprocess.check_output(['git','archive','--format=zip',source,'organisationos/employee'],cwd=ROOT)
    output=pathlib.Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0')
    env.pop('OOS_TEST_ENGINE',None)
    tool=subprocess.check_output([go,'version'],env=env,text=True).strip()
    with tempfile.TemporaryDirectory(prefix='oos-helper-dev-build-') as temp:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:z.extractall(temp) # trusted git archive, no package input
        source_dir=pathlib.Path(temp)/'organisationos/employee'
        assets=source_dir/'assets';assets.mkdir();(assets/'engine.bin').write_bytes(engine)
        (source_dir/'dev-trust.json').write_bytes(raw)
        test=subprocess.run([go,'test','-count=1','-timeout','120s','-json','./...'],cwd=source_dir,env=env,capture_output=True)
        (output/'tests.jsonl').write_bytes(test.stdout);(output/'tests.stderr.txt').write_bytes(test.stderr)
        if test.returncode:raise RuntimeError('qualification tests failed; output retained')
        env.update(GOOS='windows',GOARCH='amd64')
        executable=output/'OrganisationOS-Syncthing-Installer.exe'
        subprocess.run([go,'build','-trimpath','-buildvcs=false','-ldflags=-s -w -H windowsgui -buildid=','-o',str(executable),'.'],cwd=source_dir,env=env,check=True)
    receipt=dict(schema='oos-helper-dev-build-v1',version=VERSION,sourceCommit=source,baseVersion='0.3.4-candidate.1',
      sourceArchiveSha256=sha(archive),publicTrustSha256=sha(raw),publicTrust=trust,engineSha256=ENGINE_SHA,
      helperSha256=sha(executable.read_bytes()),go=tool,testsExitCode=test.returncode,authenticode='UNSIGNED',
      cpSignature='NOT_PERFORMED',windowsInstallation='NOT_RUN')
    (output/'source-installateur.zip').write_bytes(archive)
    (output/'dev-trust.json').write_bytes(raw)
    (output/'build.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--trust',required=True);p.add_argument('--engine',required=True)
    p.add_argument('--output',required=True);p.add_argument('--go',required=True)
    a=p.parse_args();print(json.dumps(build(a.trust,a.engine,a.output,a.go),indent=2))
