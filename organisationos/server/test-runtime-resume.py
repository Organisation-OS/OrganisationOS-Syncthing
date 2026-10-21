from pathlib import Path
import urllib.request
import importlib.util,json,tempfile,subprocess,time,xml.etree.ElementTree as ET,hashlib,copy,base64,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
R=Path('/srv/organisation-workspace/worktrees/connectors-office-offline-20261020/syncthing-upstream');S=R/'organisationos/server'
for name,file in [('native','native_install.py'),('prepare','prepare-state.py')]:
 spec=importlib.util.spec_from_file_location(name,S/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);globals()[name]=module
checks=[];binary=R/'organisationos-output/a/organisationos-syncthing'
with tempfile.TemporaryDirectory(prefix='oos-resume-',dir='/srv/organisation-workspace/evidence/connectors-office-offline-20261020')as temp:
 home=Path(temp)/'state';prepare.prepare(binary,home,'tcp://127.0.0.1:33200','127.0.0.1:33838',True)
 with open(Path(temp)/'engine.log','wb')as log:
  p=subprocess.Popen([str(binary),'serve','--home',str(home),'--no-browser','--no-restart','--no-upgrade'],stdout=log,stderr=log)
  try:
   deadline=time.monotonic()+15
   api=ET.parse(home/'config.xml').getroot().findtext('gui/apikey')
   while True:
    try:
     req=urllib.request.Request('http://127.0.0.1:33838/rest/config/options',data=b'{"maxRecvKbps":1}',headers={'X-API-Key':api,'Content-Type':'application/json'},method='PATCH')
     with urllib.request.urlopen(req,timeout=2)as response:assert response.status==200
     break
    except OSError:
     assert time.monotonic()<deadline;time.sleep(.2)
   while ET.parse(home/'config.xml').getroot().findtext('options/minHomeDiskFree')=='42949672960':
    assert time.monotonic()<deadline;time.sleep(.2)
  finally:p.terminate();p.wait(15)
 before={n:hashlib.sha256((home/n).read_bytes()).hexdigest()for n in ['config.xml','cert.pem','key.pem']}
 v=prepare.prepare(binary,home,'tcp://127.0.0.1:33200','127.0.0.1:33838',True);assert v['status']=='UNCHANGED'and before=={n:hashlib.sha256((home/n).read_bytes()).hexdigest()for n in before};checks.append('actual engine scientific reserve accepted without changing identity or configuration')
 for value,unit in [('42949672959','B'),('42949672960','%'),('NaN','B'),('Infinity','B')]:
  tree=ET.parse(home/'config.xml');e=tree.getroot().find('options/minHomeDiskFree');e.text=value;e.set('unit',unit);tree.write(home/'config.xml')
  try:prepare.prepare(binary,home,'tcp://127.0.0.1:33200','127.0.0.1:33838',True)
  except ValueError:checks.append('changed or non-finite reserve refused')
  else:raise AssertionError('unsafe reserve accepted')
key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
# Use the actual CP-staged exact candidate payload as public schema fixture.
m=json.loads(Path('/srv/organisation-workspace/evidence/connectors-office-offline-20261020/syncthing-native-active-folders/thecgp18.json').read_bytes())
def signed(payload):
 e={'schema':'oos-signed-v1','purpose':native.PURPOSE,'algorithm':'Ed25519','issuer':native.digest(pub),'payload':payload};e['signature']=base64.b64encode(key.sign(native.canonical(e))).decode();return e
old=copy.deepcopy(m);old['sequence']=5;new=copy.deepcopy(m);new['sequence']=6;state={'sequence':4,'artifactSha256':'c39eac51f1da66fb283a0017d3e70a3f4308cbb4a7f9dd5b7ef531910301a2f0'}
assert native.admit_sequence(state,new,signed(new),signed(old),pub)[0]['status']=='SUPERSEDED_WITHOUT_INSTALLATION';checks.append('verified adjacent signed supersession retains failed candidate without declaring installation')
for bad in [None,{**signed(old),'signature':base64.b64encode(b'0'*64).decode()},signed({**old,'sequence':4}),signed({**old,'installationId':'b7a1f6b1-c4aa-4de7-95fb-29d509d3398d','instanceId':'b7a1f6b1-c4aa-4de7-95fb-29d509d3398d'})]:
 try:native.admit_sequence(state,new,signed(new),bad,pub)
 except Exception:checks.append('unsigned nonadjacent or cross-instance supersession refused')
 else:raise AssertionError('invalid chain accepted')
print(json.dumps({'status':'PASS','checks':checks,'actualEngine':True,'productionWrites':0}))
