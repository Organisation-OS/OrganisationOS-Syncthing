#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Create a reproducible private qualification ZIP; no publication or workstation execution."""
from pathlib import Path
import hashlib,io,json,os,struct,subprocess,tarfile,zipfile
R=Path(__file__).resolve().parents[1];E=R/'organisationos-evidence';O=R/'organisationos-output';receipt=json.loads((R/'organisationos/build-receipt-20261020.json').read_bytes())
engine=next(x for x in receipt['binaries'] if x['platform']=='windows-amd64');raw=(O/'a'/engine['filename']).read_bytes();assert hashlib.sha256(raw).hexdigest()==engine['sha256'] and len(raw)==engine['size']
offset=struct.unpack_from('<I',raw,0x3c)[0];assert raw[:2]==b'MZ' and raw[offset:offset+4]==b'PE\x00\x00' and struct.unpack_from('<H',raw,offset+4)[0]==0x8664
head=subprocess.check_output(['git','-c','safe.directory='+str(R),'rev-parse','HEAD'],cwd=R,text=True).strip()
assert not subprocess.check_output(['git','-c','safe.directory='+str(R),'status','--porcelain'],cwd=R).strip()
files={'organisationos-syncthing.exe':raw,'LICENSE.txt':(R/'LICENSE').read_bytes(),'AUTHORS.txt':(R/'AUTHORS').read_bytes()}
for name in ['Installer-Qualification.ps1','LIRE-MOI.txt']:files[name]=(R/'organisationos/windows'/name).read_bytes()
files['source-moteur.zip']=subprocess.check_output(['git','-c','safe.directory='+str(R),'archive','--format=zip','--prefix=organisationos-syncthing-source/',receipt['sourceCommit']],cwd=R)
for p in (R/'gui/default/vendor').rglob('*'):
 if p.is_file() and any(x in p.name.upper() for x in ['LICENSE','COPYING','NOTICE']):files['notices/gui/'+str(p.relative_to(R/'gui/default/vendor'))]=p.read_bytes()
# Public dependency notices from the exact qualified build container; no private configuration copied.
container=os.environ.get('OOS_SYNCTHING_BUILDER_CONTAINER','organisationos-syncthing-build-a-20261020')
process=subprocess.Popen(['docker','cp',container+':/root/go/pkg/mod','-'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
count=0
with tarfile.open(fileobj=process.stdout,mode='r|') as archive:
 for member in archive:
  if not member.isfile() or member.size>1024*1024:continue
  name=Path(member.name);upper=name.name.upper()
  if any(x in upper for x in ['LICENSE','COPYING','NOTICE','AUTHORS']) and 'cache' not in name.parts and '..' not in name.parts:
   files['notices/go/'+str(name)]=archive.extractfile(member).read();count+=1
stderr=process.stderr.read();assert process.wait()==0,stderr.decode();assert count>30
provenance={'schema':'oos-employee-syncthing-provenance-v1','packageVersion':'0.1.0-qualification','engineVersion':receipt['runtimeVersion'],'binary':engine,'repository':receipt['repository'],'engineCommit':receipt['sourceCommit'],'upstreamTag':receipt['upstreamTag'],'upstreamCommit':receipt['upstreamCommit'],'installerCommit':head,'builderImage':receipt['builderImage'],'engineSources':'source-moteur.zip','authenticode':'UNSIGNED','windowsReception':'NOT_RUN','gedConnection':'NOT_CONFIGURED','startup':'MANUAL_ONLY','serviceInstallation':False,'notices':count,'files':{k:hashlib.sha256(v).hexdigest() for k,v in sorted(files.items())}}
files['provenance.json']=(json.dumps(provenance,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
def package():
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for name,body in sorted(files.items()):
   i=zipfile.ZipInfo(name,date_time=(2026,10,6,0,0,0));i.create_system=3;i.external_attr=0o100644<<16;i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,body,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
 return out.getvalue()
first=package();assert first==package();target=O/'OrganisationOS-Syncthing-Qualification-0.1.0-windows-x64.zip';target.write_bytes(first)
r={'status':'CANDIDATE_PACKAGED_NOT_DISTRIBUTED','filename':target.name,'sha256':hashlib.sha256(first).hexdigest(),'size':len(first),'engineCommit':receipt['sourceCommit'],'engineSha256':engine['sha256'],'installerCommit':head,'peArchitecture':'AMD64','doublePackagingIdentical':True,'noticesFiles':count,'windowsReception':'NOT_RUN','gedIntegrationReception':'NOT_RUN'}
(E/'windows-package-receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
