#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Native CP authorization/signature/audit, private publication; no provider credentials."""
import argparse,fcntl,gzip,io,json,os,pathlib,tarfile,tempfile
from native_install import FILES,PURPOSE,canonical,digest,validate,unpack
P=pathlib.Path
def archive(inputs):
 stream=io.BytesIO()
 with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0)as gz:
  with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT)as tar:
   for name in sorted(FILES):
    p=inputs/name
    if not p.is_file()or p.is_symlink():raise ValueError('Exact source input required')
    raw=p.read_bytes();entry=tarfile.TarInfo(name);entry.mode=0o444;entry.size=len(raw);tar.addfile(entry,io.BytesIO(raw))
 return stream.getvalue()
def atomic(path,raw):
 fd,temp=tempfile.mkstemp(prefix='.pending-',dir=path.parent)
 with os.fdopen(fd,'wb')as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(temp,path)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('action',choices=['preflight','publish']);ap.add_argument('--actor',required=True);ap.add_argument('--manifest',required=True);ap.add_argument('--inputs',required=True);a=ap.parse_args()
 if os.geteuid()==0:raise ValueError('Native CP service identity required')
 os.umask(0o077);os.environ.setdefault('DJANGO_SETTINGS_MODULE','controlplane.settings')
 import django;django.setup()
 from django.db import transaction
 from fleet.models import User,Installation,AuditEvent
 from fleet.policy import require_write
 from fleet.services import audit
 from fleet.signatures import signed,verify,issuer,public_bytes
 actor=User.objects.get(pk=a.actor);require_write(actor,'releases');m=validate(json.loads(P(a.manifest).read_bytes()));installation=Installation.objects.get(pk=m['installationId'])
 raw=archive(P(a.inputs));unpack(raw,m['artifact']);payloadSha=digest(canonical(m));root=P('/var/lib/organisasion-os-control-plane/document-runtime');app=root/str(installation.pk);state=app/'current.json'
 def admit():
  prior=json.loads(state.read_bytes())if state.exists()else {'sequence':0}
  if not(m['sequence']==prior['sequence']and prior.get('payloadSha256')==payloadSha or m['sequence']==prior['sequence']+1):raise ValueError('Native release sequence refused')
 admit()
 if a.action=='preflight':print(json.dumps({'status':'PREFLIGHT_PASS','installationId':str(installation.pk),'artifactSha256':digest(raw),'privatePublication':True,'builtByControlPlane':True}));return
 app.mkdir(parents=True,mode=0o700,exist_ok=True)
 for p in [root,app]:
  s=p.lstat()
  if p.is_symlink()or s.st_uid!=os.geteuid()or s.st_mode&0o077:raise ValueError('Private native registry custody refused')
 with (app/'publish.lock').open('a')as lock:
  fcntl.flock(lock,fcntl.LOCK_EX);admit();key=issuer();envelope=signed(m,PURPOSE,key=key);verify(envelope,PURPOSE,public_bytes(key));manifestSha=digest(canonical(envelope))
  obj=app/(digest(raw)+'.tar.gz');release=app/(str(m['sequence'])+'.signed.json')
  for p,b in [(obj,raw),(release,canonical(envelope))]:
   if p.exists():
    if p.is_symlink()or p.read_bytes()!=b:raise ValueError('Immutable publication differs')
   else:atomic(p,b)
  with transaction.atomic():
   event=AuditEvent.objects.filter(action='updates.document-runtime.install',resource='Installation',resource_id=str(installation.pk),after__manifestSha256=manifestSha).first()
   if event is None:event=audit(actor,'updates.document-runtime.install',installation,after={'manifestSha256':manifestSha,'artifactSha256':digest(raw),'engineSha256':m['artifact']['engineSha256'],'sequence':m['sequence'],'workerRequested':m['activateWorker'],'privatePublication':True},provenance='cli')
  receipt={'status':'PUBLISHED_PRIVATE','sequence':m['sequence'],'payloadSha256':payloadSha,'manifestSha256':manifestSha,'artifactSha256':digest(raw),'auditId':str(event.pk),'builtByControlPlane':True,'providerSecretsImported':0}
  atomic(state,canonical(receipt));rp=app/(str(m['sequence'])+'.receipt.json')
  if rp.exists():
   if rp.read_bytes()!=canonical(receipt):raise ValueError('Receipt replay differs')
  else:atomic(rp,canonical(receipt))
  print(json.dumps(receipt))
if __name__=='__main__':main()
