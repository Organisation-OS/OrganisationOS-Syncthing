#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Bounded isolated real-engine tests. No Windows/production service or prior bench reused."""
import base64,hashlib,importlib.util,json,os,pathlib,subprocess,tempfile,time,uuid
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('broker',HERE/'broker.py');broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)
spec=importlib.util.spec_from_file_location('prepare',HERE/'prepare-state.py');prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
BINARY=HERE.parent.parent/'organisationos-output/a/organisationos-syncthing'
checks=[]
def yes(ok,label):
 if not ok:raise AssertionError(label)
 checks.append(label)
def no(fn,label):
 try:fn()
 except Exception:checks.append(label);return
 raise AssertionError(label)
with tempfile.TemporaryDirectory(prefix='oos-native-broker-',dir='/srv/organisation-workspace/evidence/connectors-office-offline-20261020') as temp:
 root=pathlib.Path(temp);projection=root/'projections';projection.mkdir(mode=0o700)
 home=root/'state';other=root/'peer';p=prepare.prepare(BINARY,home,'tcp://127.0.0.1:32200','127.0.0.1:32838',True);p2=prepare.prepare(BINARY,other,'tcp://127.0.0.1:32201','127.0.0.1:32839',True)
 cfg={'instanceId':'11111111-1111-4111-8111-111111111111','projectionRoot':str(projection),'engineBinary':str(BINARY),'engineConfig':str(home/'config.xml'),'serverDeviceKey':p['deviceId'],'publicEndpoint':'tcp://127.0.0.1:32200','coreUid':os.getuid(),'socket':str(root/'broker.sock')}
 engine=broker.Engine(cfg,True)
 with open(root/'engine-private.log','wb') as log:
  process=subprocess.Popen([str(BINARY),'serve','--home',str(home),'--no-browser','--no-restart','--no-upgrade'],stdout=log,stderr=log)
  try:
   for attempt in range(40):
    try:identity=engine.identity();break
    except Exception:
     if process.poll() is not None:raise RuntimeError('Isolated engine stopped; private log retained only in temporary fixture')
     time.sleep(.25)
   else:raise RuntimeError('Isolated engine startup timeout')
   yes(identity['deviceKey']==p['deviceId'],'actual engine certificate identity verified')
   php='require "/srv/organisation-workspace/worktrees/connectors-office-offline-20261020/core/vendor/autoload.php"; echo App\\Documents\\Connectors\\SyncthingDeviceIdentity::certificate(file_get_contents($argv[1]))["deviceKey"];'
   derived=subprocess.check_output(['php','-r',php,str(home/'cert.pem')],text=True)
   yes(derived==identity['deviceKey'],'PHP certificate identity matches actual upstream engine representation')
   def call(op,**args):return engine.dispatch({'instanceId':cfg['instanceId'],'operation':op,'arguments':args})
   no(lambda:engine.dispatch({'instanceId':str(uuid.uuid4()),'operation':'identity','arguments':{}}),'foreign instance refused')
   no(lambda:call('pair',deviceKey=p['deviceId']),'server identity cannot become employee')
   yes(call('pair',deviceKey=p2['deviceId'])['status']=='PAIRED','actual engine peer API pairing')
   yes(call('pair',deviceKey=p2['deviceId'])['status']=='UNCHANGED','pairing replay preserves identity')
   selection=str(uuid.uuid4());document=str(uuid.uuid4());path='Documents/'+document+'/synthetic.txt';data=b'ORGANISATIONOS-NATIVE-PROJECTION\n';sha=hashlib.sha256(data).hexdigest()
   yes(call('put',selection=selection,path=path,bytes=base64.b64encode(data).decode(),sha256=sha)['status']=='CREATED','immutable initial projection staged')
   yes(call('put',selection=selection,path=path,bytes=base64.b64encode(data).decode(),sha256=sha)['status']=='UNCHANGED','projection replay does not rewrite file')
   yes(call('folder',selection=selection,deviceKey=p2['deviceId'],label='Synthetic native reception')['status']=='SHARED','actual engine folder shared to exactly one employee')
   yes(call('folder',selection=selection,deviceKey=p2['deviceId'],label='Synthetic native reception')['status']=='UNCHANGED','folder replay preserves exact pairing')
   folders=engine.api('GET','config/folders');f=next(f for f in folders if f['id']=='oos-'+selection)
   yes(len(f['devices'])==2 and all(not d.get('encryptionPassword') for d in f['devices']),'both identities have no unintended local encryption setting')
   yes(call('read',selection=selection,path=path)['sha256']==sha,'returned projection bytes checked by SHA256')
   no(lambda:call('read',selection=selection,path='Documents/'+document+'/../../outside'),'path traversal refused')
   (projection/selection/'Documents'/document/'link.txt').symlink_to('/etc/hostname')
   no(lambda:call('read',selection=selection,path='Documents/'+document+'/link.txt'),'remote symlink cannot become GED return')
   os.link(projection/selection/path,projection/selection/'Documents'/document/'hard.txt')
   no(lambda:call('read',selection=selection,path='Documents/'+document+'/hard.txt'),'hard-linked return refused')
   os.unlink(projection/selection/'Documents'/document/'hard.txt')
   edited=b'LOCAL-EMPLOYEE-EDIT\n';(projection/selection/path).write_bytes(edited)
   no(lambda:call('put',selection=selection,path=path,bytes=base64.b64encode(data).decode(),sha256=sha),'refresh never overwrites employee edit')
   yes((projection/selection/path).read_bytes()==edited,'employee edit preserved after refused refresh')
   yes(any(i['kind']=='REFUSED' for i in call('inventory',selection=selection)['items']),'unsafe filesystem entries are reported without reading target')
   yes(call('remove',deviceKey=p2['deviceId'])['status']=='REMOVED','actual API revokes pairing and folder membership')
   yes(p2['deviceId'] not in [d['deviceID'] for d in engine.api('GET','config/devices')],'revoked identity absent from actual engine configuration')
   yes(call('removeFolder',selection=selection)['filesPreserved'],'detaching selection retains private recovery files')
   yes((projection/selection/path).read_bytes()==edited,'revocation never claims erasure of acquired copies')
  finally:
   process.terminate()
   try:process.wait(timeout=15)
   except subprocess.TimeoutExpired:process.kill();process.wait()
print(json.dumps({'status':'PASS','checks':checks,'engineSha256':broker.PIN,'actualEngineApi':True,'externalTransportQualified':False,'productionWrites':0},indent=2))
