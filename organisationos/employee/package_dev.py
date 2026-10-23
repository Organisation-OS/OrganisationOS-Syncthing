#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Prepare the private DEV ZIP/provenance for the EXISTING CP signer.
The caller supplies its verified legal/source bundle and explicit SHA-256.
This does not sign, publish, install or enroll. Legacy package.py is unchanged.
"""
import argparse, hashlib, io, json, pathlib, re, zipfile
from build_dev import VERSION,ENGINE_SHA,public_trust

sha=lambda raw:hashlib.sha256(raw).hexdigest()


def package(build_dir,config_file,legal_file,legal_sha,output):
    directory=pathlib.Path(build_dir)
    build=json.loads((directory/'build.json').read_bytes())
    trust_raw=(directory/'dev-trust.json').read_bytes();trust=public_trust(trust_raw)
    exe=(directory/'OrganisationOS-Syncthing-Installer.exe').read_bytes()
    source=(directory/'source-installateur.zip').read_bytes()
    if build['version']!=VERSION or build['engineSha256']!=ENGINE_SHA or build['testsExitCode']!=0:raise ValueError('qualified DEV build required')
    if sha(exe)!=build['helperSha256'] or sha(trust_raw)!=build['publicTrustSha256'] or build['publicTrust']!=trust or sha(source)!=build['sourceArchiveSha256']:raise ValueError('build inputs changed')
    config=json.loads(pathlib.Path(config_file).read_bytes())
    if set(config)!={'schema','instanceId','apiOrigin','portalOrigin','organisationName','serverDeviceKey','publicEndpoint'}:raise ValueError('schema2 closed configuration required')
    if config['schema']!=2 or config['instanceId']!=trust['instanceId'] or config['apiOrigin']!=trust['apiOrigin']:raise ValueError('configuration differs from admitted native identity')
    if not re.fullmatch(r'[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}',config['serverDeviceKey']):raise ValueError('server identity required')
    from urllib.parse import urlsplit
    portal=urlsplit(config['portalOrigin']);sync=urlsplit(config['publicEndpoint'])
    if portal.scheme!='https' or not portal.hostname or portal.username or portal.password or portal.path or portal.query or portal.fragment:raise ValueError('HTTPS portal required')
    if sync.scheme!='tcp' or not sync.hostname or not sync.port or sync.username or sync.password or sync.path or sync.query or sync.fragment:raise ValueError('TCP endpoint required')
    if not isinstance(config['organisationName'],str) or not config['organisationName'].strip() or len(config['organisationName'].encode())>120 or any(c in config['organisationName'] for c in '\x00\r\n'):raise ValueError('organisation name refused')
    legal=pathlib.Path(legal_file).read_bytes()
    if len(legal)>256*1024*1024 or not re.fullmatch('[a-f0-9]{64}',legal_sha) or sha(legal)!=legal_sha:raise ValueError('verified legal/source bundle required')
    files={}
    with zipfile.ZipFile(io.BytesIO(legal)) as z:
        for f in z.infolist():
            if f.is_dir():continue
            if not (f.filename.startswith('notices/') or f.filename in ('LICENSE.txt','AUTHORS.txt','source-moteur.zip')):continue
            if f.filename in files or '\\' in f.filename or ':' in f.filename or any(p in ('','.','..') for p in f.filename.split('/')) or f.file_size>128*1024*1024 or (f.external_attr>>16)&0o170000==0o120000:raise ValueError('unsafe legal archive')
            files[f.filename]=z.read(f)
    if not all(files.get(p) for p in ('LICENSE.txt','AUTHORS.txt','source-moteur.zip')) or not any(p.startswith('notices/') for p in files):raise ValueError('complete native notices and engine source required')
    files.update({'LICENSE-Go.txt':(pathlib.Path(__file__).parent/'LICENSE-Go.txt').read_bytes(),
        'OrganisationOS-Syncthing-Installer.exe':exe,'source-installateur.zip':source,
        'organisation.json':json.dumps(config,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode(),
        'LIRE-MOI.txt':('OrganisationOS Syncthing '+VERSION+' - DEV uniquement.\r\n'
        'Admission CP separee obligatoire. Ne pas lancer le ZIP comme une installation legacy.\r\n'
        'Invocation native: OrganisationOS-Syncthing-Installer.exe install-dev <ZIP exact> <enveloppe CP externe>.\r\n'
        'Aucun secret ni appareil commun inclus. Reception Windows encore requise.\r\n').encode()})
    provenance=dict(schema='oos-employee-build-provenance-v1',installerVersion=VERSION,installerSourceCommit=build['sourceCommit'],
      installerSha256=sha(exe),engineVersion='v2.1.6-oos.2',engineSourceCommit='e80f807467f5e127f35e2de45cfd22d4091bcd42',
      engineWindowsSha256=ENGINE_SHA,repository='https://github.com/Organisation-OS/OrganisationOS-Syncthing',
      admissionAudience='dev',devTrustSha256=sha(trust_raw),legalBundleSha256=legal_sha,configuration=config,
      windowsAuthenticode='UNSIGNED',windowsReception='NOT_RUN',internetReception='NOT_RUN',
      deviceIdentityBundled=False,enrollmentTokenBundled=False,serverSecretBundled=False,
      companionComponent={'schema':'oos-companion-component-v1','platforms':[{'platform':'windows','architecture':'x64','minimumVersion':'10.0.19045'}],'installer':{'type':'native-helper','scope':'user'}},
      files={name:sha(raw) for name,raw in sorted(files.items())})
    files['provenance.json']=json.dumps(provenance,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,raw in sorted(files.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,10,23,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            z.writestr(info,raw)
    raw=stream.getvalue();out=pathlib.Path(output)
    if len(files)>128 or len(raw)>256*1024*1024:raise ValueError('package bounds exceeded')
    with out.open('xb') as f:f.write(raw)
    result=dict(schema='oos-helper-dev-package-v1',status='PREPARED_FOR_NATIVE_CP_SIGNING',filename=out.name,size=len(raw),sha256=sha(raw),
        installationId=trust['installationId'],instanceId=trust['instanceId'],applicationId=trust['applicationId'],provenance=provenance)
    with out.with_suffix(out.suffix+'.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2,ensure_ascii=False);f.write('\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('build-dir','config','legal-bundle','legal-sha256','output'):p.add_argument('--'+name,required=True)
    a=p.parse_args();print(json.dumps(package(a.build_dir,a.config,a.legal_bundle,a.legal_sha256,a.output),indent=2))
