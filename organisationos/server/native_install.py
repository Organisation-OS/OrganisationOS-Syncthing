#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Native CP-signed server delivery. Unique private state is generated only on its host.
No schema changes, employee enrolment, user credentials or UNAS changes occur here.
The worker stays disabled until a separately signed activation follows the native platform prerequisite.
"""
import argparse,base64,fcntl,hashlib,io,json,os,pathlib,pwd,re,stat,subprocess,tarfile,tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
P=pathlib.Path
PURPOSE='organisation-document-runtime-v1'
PIN='9eaf8cad615cfb07f17af7b87f0e3e77e5a99d902c6f971909bcca4bd3102d6b'
INSTANCES={'27c0be38-60bd-4dce-bb28-ef0088716a25':('10.9.5.18','10.9.5.74','syncthing.thecgp.com'),'b7a1f6b1-c4aa-4de7-95fb-29d509d3398d':('10.100.8.50','10.100.8.13','syncthing.villesadp.ca')}
FILES={'organisationos-syncthing','broker.py','prepare-state.py','firewall.py','worker-launcher.py','LICENSE','runtime-provenance.json'}
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(v):return hashlib.sha256(v).hexdigest()
def need(ok):
 if not ok:raise ValueError('Native documentary runtime precondition refused')
def trusted(p,directory=False):
 p=P(p);s=p.lstat();need(p.resolve()==p and s.st_uid==0 and not s.st_mode&0o022 and (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1));return p

def read(p):return json.loads(P(p).read_bytes())
def run(args,**kw):
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,**kw);need(r.returncode==0);return r.stdout

def write(p,raw,mode=0o644,uid=0,gid=0):
 p=P(p);raw=raw if isinstance(raw,bytes) else canonical(raw)+b'\n'
 if p.exists():
  s=p.lstat();need(p.resolve()==p and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==mode and p.read_bytes()==raw);return
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:os.fchown(f.fileno(),uid,gid);os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())

def directory(p,mode=0o755,uid=0,gid=0):
 p=P(p)
 if not p.exists():p.mkdir(mode=mode);os.chown(p,uid,gid)
 s=p.lstat();need(p.resolve()==p and stat.S_ISDIR(s.st_mode) and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==mode)

def validate(m):
 need(set(m)=={'schema','installationId','instanceId','sequence','operation','artifact','activateWorker'})
 need(m['schema']=='oos-document-runtime-release-v1' and m['operation']=='install' and m['instanceId'] in INSTANCES and m['installationId']==m['instanceId'] and type(m['sequence'])is int and m['sequence']>0 and type(m['activateWorker'])is bool)
 a=m['artifact'];need(set(a)=={'sha256','size','version','sourceCommit','engineCommit','engineSha256'})
 need(re.fullmatch('[a-f0-9]{64}',a['sha256']) and type(a['size'])is int and 0<a['size']<67108864 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',a['version']) and re.fullmatch('[a-f0-9]{40}',a['sourceCommit']) and a['engineCommit']=='e80f807467f5e127f35e2de45cfd22d4091bcd42' and a['engineSha256']==PIN)
 return m

def verify(e,public):
 need(set(e)=={'schema','purpose','algorithm','issuer','payload','signature'} and e['schema']=='oos-signed-v1' and e['purpose']==PURPOSE and e['algorithm']=='Ed25519' and e['issuer']==digest(public))
 Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(e['signature'],validate=True),canonical({k:v for k,v in e.items()if k!='signature'}));return validate(e['payload'])

def unpack(raw,a):
 need(len(raw)==a['size'] and digest(raw)==a['sha256']);files={};total=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
  for item in archive:
   need(item.name in FILES and item.name not in files and item.isfile() and item.uid==item.gid==item.mtime==0 and item.mode==0o444 and not item.pax_headers and 0<=item.size<=33554432)
   total+=item.size;need(total<40000000);files[item.name]=archive.extractfile(item).read()
 need(set(files)==FILES and digest(files['organisationos-syncthing'])==PIN)
 provenance=json.loads(files['runtime-provenance.json']);need(provenance['sourceCommit']==a['sourceCommit'] and provenance['engineCommit']==a['engineCommit'] and provenance['files']=={k:digest(v)for k,v in files.items()if k!='runtime-provenance.json'})
 return files

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--supervisor',required=True);ap.add_argument('--envelope',required=True);ap.add_argument('--artifact',required=True);ap.add_argument('--preflight',action='store_true');args=ap.parse_args();need(os.geteuid()==0)
 s=read(trusted(args.supervisor));policy=read(trusted(s['policy']));native=read(trusted(s['config']));identity=read(trusted(P(s['state'])/'identity.json'))
 envelope=read(args.envelope);m=verify(envelope,base64.b64decode(native['public_key'],validate=True));need(m['installationId']==identity['installation_id']);files=unpack(P(args.artifact).read_bytes(),m['artifact']);runtime=policy['runtime'];config=trusted(runtime['config_directory'],True)
 metadata=read(trusted(P('/etc/organisation/integrations/metadata-v2.json')));need(any(o.get('scope',{}).get('instanceId')==m['instanceId'] for o in metadata['owners']));core=pwd.getpwuid(metadata['runtimeUid']);need(core.pw_uid>0 and metadata['portalUid']!=core.pw_uid)
 listen,proxy,hostname=INSTANCES[m['instanceId']];need(run(['/usr/sbin/ip','-j','address','show']).find(('"local":"'+listen+'"').encode())>=0 or any(a.get('local')==listen for i in json.loads(run(['/usr/sbin/ip','-j','address','show'])) for a in i.get('addr_info',[])))
 need(P('/usr/sbin/nft').is_file() and P('/usr/bin/python3').is_file())
 if m['activateWorker']:
  need(runtime.get('adapter') in ['historical-web-v1','generic-v1','generic-web-v1'] or 'unit_prefix'in runtime)
  source=(P(runtime['core_releases'])/P(runtime['core_marker']).read_text().strip()) if runtime.get('adapter')=='historical-web-v1' else P(policy['prefix'])/'active/core'
  need((source/'bin/documents-offline-worker').is_file())
  # The native loader and seven-table prerequisite remain authoritative at each worker invocation.
 if args.preflight:print(json.dumps({'status':'PREFLIGHT_PASS','instanceId':m['instanceId'],'artifactSha256':m['artifact']['sha256'],'workerRequested':m['activateWorker'],'providerSecretsImported':0}));return
 parent=P('/var/lib/organisation-document-runtime');directory(parent,0o700)
 with (parent/'install.lock').open('a') as lock:
  os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX)
  state=read(parent/'current.json') if (parent/'current.json').exists() else {'sequence':0}
  manifestSha=digest(canonical(envelope));need(m['sequence']==state['sequence'] and state.get('manifestSha256')==manifestSha or m['sequence']==state['sequence']+1)
  try:user=pwd.getpwnam('organisationos-syncthing')
  except KeyError:run(['/usr/sbin/useradd','--system','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','--user-group','organisationos-syncthing']);user=pwd.getpwnam('organisationos-syncthing')
  need(user.pw_uid not in [0,core.pw_uid] and user.pw_shell=='/usr/sbin/nologin' and os.getgrouplist(user.pw_name,user.pw_gid)==[user.pw_gid])
  directory('/opt/organisationos-syncthing');directory('/opt/organisationos-syncthing/releases');release=P('/opt/organisationos-syncthing/releases')/m['artifact']['sha256'];directory(release)
  for name,raw in files.items():write(release/name,raw,0o555 if name=='organisationos-syncthing' else 0o444)
  storage=P('/var/lib/organisationos-syncthing');directory(storage,0o700,user.pw_uid,user.pw_gid)
  home=storage/'state';need(not home.is_symlink())
  if home.exists():need(home.stat().st_uid==user.pw_uid and stat.S_IMODE(home.stat().st_mode)==0o700)
  generated=json.loads(run(['/usr/sbin/runuser','-u',user.pw_name,'--','/usr/bin/python3',str(release/'prepare-state.py'),'--binary',str(release/'organisationos-syncthing'),'--home',str(home),'--listen','tcp://'+listen+':22000']))
  projection=storage/'projections';directory(projection,0o700,user.pw_uid,user.pw_gid)
  directory('/etc/organisation/syncthing',0o755)
  descriptor={'schema':1,'instanceId':m['instanceId'],'projectionRoot':str(projection),'engineBinary':str(release/'organisationos-syncthing'),'engineConfig':str(home/'config.xml'),'serverDeviceKey':generated['deviceId'],'publicEndpoint':'tcp://'+hostname+':22000','coreUid':core.pw_uid,'socket':'/run/organisation-syncthing/broker.sock'}
  write('/etc/organisation/syncthing/service.json',descriptor,0o640,0,user.pw_gid);write('/etc/organisation/syncthing/firewall.json',{'listenIp':listen,'proxyIp':proxy},0o644)
  launch={'schema':1,'instanceId':m['instanceId'],'configurationPath':str(config),'adapter':runtime.get('adapter'),'coreMarker':runtime.get('core_marker'),'coreReleases':runtime.get('core_releases'),'corePath':str(P(policy['prefix'])/'active/core'),'moduleBinding':str(config),'moduleRegistry':read(trusted(P('/etc/organisation-module-runtimes')/(digest(str(config).encode())+'.json')))['registry_path']}
  write('/etc/organisation/syncthing/worker.json',launch,0o644)
  common='NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nCapabilityBoundingSet=\nUMask=0077\n'
  units={
  'organisationos-syncthing-firewall.service':'[Unit]\nDescription=OrganisationOS synchronization proxy boundary\nBefore=organisationos-syncthing.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 '+str(release/'firewall.py')+'\n[Install]\nWantedBy=multi-user.target\n',
  'organisationos-syncthing.service':'[Unit]\nDescription=OrganisationOS Syncthing engine\nAfter=network-online.target organisationos-syncthing-firewall.service\nRequires=organisationos-syncthing-firewall.service\n[Service]\nUser='+user.pw_name+'\nGroup='+user.pw_name+'\nExecCondition=+/usr/bin/python3 '+str(release/'worker-launcher.py')+' --check-module\nExecStart='+str(release/'organisationos-syncthing')+' serve --home '+str(home)+' --no-browser --no-restart --no-upgrade --no-port-probing\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=60\nMemoryMax=768M\n'+common+'ReadWritePaths='+str(storage)+'\n[Install]\nWantedBy=multi-user.target\n',
  'organisationos-syncthing-broker.socket':'[Unit]\nDescription=OrganisationOS private GED synchronization broker\n[Socket]\nListenStream=/run/organisation-syncthing/broker.sock\nSocketUser='+core.pw_name+'\nSocketGroup='+core.pw_name+'\nSocketMode=0600\nDirectoryMode=0755\nRemoveOnStop=yes\n[Install]\nWantedBy=sockets.target\n',
  'organisationos-syncthing-broker.service':'[Unit]\nDescription=OrganisationOS restricted local engine adapter\nAfter=organisationos-syncthing.service\nRequires=organisationos-syncthing.service\n[Service]\nUser='+user.pw_name+'\nGroup='+user.pw_name+'\nExecStart=/usr/bin/python3 '+str(release/'broker.py')+' /etc/organisation/syncthing/service.json\nMemoryMax=512M\n'+common+'ReadWritePaths='+str(projection)+'\n',
  'organisationos-offline-worker.service':'[Unit]\nDescription=OrganisationOS authorized offline projections and GED admission\nAfter=organisationos-syncthing.service\n[Service]\nType=oneshot\nUser='+core.pw_name+'\nGroup='+core.pw_name+'\nExecStart=/usr/bin/python3 '+str(release/'worker-launcher.py')+'\nTimeoutStartSec=240\nMemoryMax=768M\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\n',
  'organisationos-offline-worker.timer':'[Unit]\nDescription=OrganisationOS bounded offline reconciliation\n[Timer]\nOnBootSec=90\nOnUnitInactiveSec=60\nAccuracySec=10\nUnit=organisationos-offline-worker.service\n[Install]\nWantedBy=timers.target\n'}
  for name,content in units.items():write(P('/etc/systemd/system')/name,content.encode())
  run(['/usr/bin/systemctl','daemon-reload']);run(['/usr/bin/systemctl','enable','--now','organisationos-syncthing-firewall.service','organisationos-syncthing.service','organisationos-syncthing-broker.socket'])
  if m['activateWorker']:run(['/usr/bin/systemctl','enable','--now','organisationos-offline-worker.timer'])
  receipt={'schema':'oos-document-runtime-installation-v1','status':'INSTALLED','instanceId':m['instanceId'],'sequence':m['sequence'],'manifestSha256':manifestSha,'artifactSha256':m['artifact']['sha256'],'engineSha256':PIN,'serverDeviceKey':generated['deviceId'],'listen':'tcp://'+listen+':22000','publicEndpoint':'tcp://'+hostname+':22000','proxySource':proxy,'administration':'127.0.0.1:8384','workerActivated':m['activateWorker'],'employeeDevicesCreated':0,'existingDataPreserved':True}
  write(parent/(manifestSha+'.receipt.json'),receipt,0o600)
  # Durable sequence replacement is atomic; prior immutable receipts and generated identity are retained.
  fd,temp=tempfile.mkstemp(prefix='.current-',dir=parent)
  with os.fdopen(fd,'wb')as f:os.fchmod(f.fileno(),0o600);f.write(canonical(receipt));f.flush();os.fsync(f.fileno())
  os.replace(temp,parent/'current.json');print(json.dumps(receipt))
if __name__=='__main__':main()
