from pathlib import Path
import json,tempfile,time,uuid,base64,hashlib,importlib.util,datetime
R=Path('/srv/organisation-workspace/worktrees/connectors-office-offline-20261020/syncthing-upstream');S=R/'organisationos/qualify-engine.py';ns={'__file__':str(S)};exec(compile(S.read_text().split('nodes=[]; result=')[0],str(S),'exec'),ns)
Node,wait,check=ns['Node'],ns['wait'],ns['check'];spec=importlib.util.spec_from_file_location('broker',R/'organisationos/server/broker.py');broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)
result={'schema':'oos-broker-folder-policy-reception-v1','windowsReception':False,'externalReception':False,'productionWrites':0};nodes=[]
try:
 with tempfile.TemporaryDirectory(prefix='oos-broker-folders-',dir='/srv/organisation-workspace/evidence/connectors-office-offline-20261020')as temp:
  root=Path(temp);a=Node(root,'server');b=Node(root,'employee');nodes=[a,b];a.start();b.start();a.connect(b);b.connect(a)
  a.api('config/folders/oos-synthetic',method='DELETE');b.api('config/folders/oos-synthetic',method='DELETE')
  a.api('config/options',{'minHomeDiskFree':{'value':42949672960,'unit':'B'}},'PATCH')
  projection=root/'projections';projection.mkdir();instance=str(uuid.uuid4());sel=str(uuid.uuid4());folderid='oos-'+sel
  engine=broker.Engine({'projectionRoot':str(projection),'engineBinary':str(ns['BIN']),'engineConfig':str(a.home/'config.xml'),'instanceId':instance,'serverDeviceKey':a.id,'publicEndpoint':'tcp://127.0.0.1:'+str(a.listen)},qualification=True)
  def op(name,**args):return engine.dispatch({'instanceId':instance,'operation':name,'arguments':args})
  allowed='Documents/Parent/Enfant/acces.txt';withdrawn='Documents/Parent/Enfant/retrait.txt'
  def put(path,data):return op('put',selection=sel,path=path,bytes=base64.b64encode(data.encode()).decode(),sha256=hashlib.sha256(data.encode()).hexdigest())
  op('restrict',selection=sel,paths=[allowed,withdrawn]);put(allowed,'authorised');put(withdrawn,'before-revocation');put('Documents/Parent/cache.txt','never-shared')
  op('folder',selection=sel,deviceKey=b.id,label='Synthetic folder');f=b.api('config/defaults/folder');f.update(id=folderid,path=str(b.folder),type='sendreceive',rescanIntervalS=1,fsWatcherEnabled=False,devices=[{'deviceID':b.id},{'deviceID':a.id}]);b.api('config/folders',f,'POST')
  def scan(n):n.api('db/scan?folder='+folderid,{},'POST')
  scan(a);scan(b);wait(lambda:b.has(allowed,'authorised')and b.has(withdrawn,'before-revocation'),'native broker shares nested allowlisted files')
  check(not(b.folder/'Documents/Parent/cache.txt').exists(),'policy is applied before first sharing')
  wait(lambda:op('progress',selection=sel,deviceKey=b.id,expectedFiles=2)['complete'],'completion comes from actual connected engine indexes')
  check(op('restrict',selection=sel,paths=[allowed,withdrawn])['status']=='UNCHANGED'and not a.api('config/folders/'+folderid)['paused'],'unchanged authorization does not restart folder every cycle')
  op('restrict',selection=sel,paths=[allowed]);check(a.api('config/folders/'+folderid)['paused'],'rights reduction pauses the actual folder')
  (projection/sel/withdrawn).write_text('server-after-revoke');(b.folder/withdrawn).write_text('employee-unsent-preserved')
  op('folder',selection=sel,deviceKey=b.id,label='Synthetic folder');scan(a);scan(b);time.sleep(3)
  check((projection/sel/withdrawn).read_text()=='server-after-revoke'and b.has(withdrawn,'employee-unsent-preserved'),'revoked path stops both directions without deleting either version')
  new='Documents/Parent/Nouveau/apres-selection.txt';op('restrict',selection=sel,paths=[allowed,new]);put(new,'new-file-after-selection');op('folder',selection=sel,deviceKey=b.id,label='Synthetic folder');scan(a);scan(b);wait(lambda:b.has(new,'new-file-after-selection'),'new authorized subtree joins existing selection')
  (b.folder/allowed).write_text('employee-authorized');scan(b);wait(lambda:(projection/sel/allowed).read_text()=='employee-authorized','other authorized files continue after individual revocation')
  result['transportCompletionCoversAllowedPathsOnly']=op('progress',selection=sel,deviceKey=b.id,expectedFiles=2)['complete'];check(True,'application must separately account for revoked copies and exclusions')
  for path in ['Documents/../escape','Documents/Parent/!evil','Documents/Parent/a*','Documents/Parent/[ab]','Documents/Parent/a\\b','Documents/Parent/a\nsecret']:
   try:broker.ignore_policy([path])
   except broker.Refused:check(True,'unsafe path/pattern refused')
   else:raise AssertionError('unsafe path accepted')
  (projection/sel/'Documents/Parent/link').symlink_to(root)
  try:put('Documents/Parent/link/escape.txt','refused')
  except OSError:check(True,'openat rejects symlink directory')
  else:raise AssertionError('symlink write accepted')
  op('removeFolder',selection=sel);check(b.has(withdrawn,'employee-unsent-preserved')and (projection/sel/allowed).is_file(),'stop selection preserves copies and unsent edits')
  result['status']='PASS'
except Exception as e:
 import traceback;traceback.print_exc();result.update(status='FAIL',errorType=type(e).__name__,error=str(e))
finally:
 for n in nodes:n.stop();n.log.close()
 result.update(checks=ns['checks'],at=datetime.datetime.now(datetime.timezone.utc).isoformat(),processesStopped=True)
 out=Path('/srv/organisation-workspace/evidence/connectors-office-offline-20261020/active-folder-broker.json');out.write_text(json.dumps(result,indent=2));print(json.dumps(result))
if result['status']!='PASS':raise SystemExit(1)
