#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import importlib.util,json,multiprocessing,os,pathlib,subprocess,tempfile,time
HERE=pathlib.Path(__file__).resolve().parent
for name,file in [('broker','broker.py'),('prepare','prepare-state.py')]:
 spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);globals()[name]=module
BINARY=HERE.parent.parent/'organisationos-output/a/organisationos-syncthing'
with tempfile.TemporaryDirectory(prefix='oos-worker-',dir='/srv/organisation-workspace/evidence/connectors-office-offline-20261020') as temp:
 root=pathlib.Path(temp);home=root/'state';peer=root/'peer';projection=root/'projections';projection.mkdir(mode=0o700)
 p=prepare.prepare(BINARY,home,'tcp://127.0.0.1:32200','127.0.0.1:32838',True);p2=prepare.prepare(BINARY,peer,'tcp://127.0.0.1:32201','127.0.0.1:32839',True)
 cfg={'instanceId':'457270a4-4995-4467-8512-cfc91f530aaf','projectionRoot':str(projection),'engineBinary':str(BINARY),'engineConfig':str(home/'config.xml'),'serverDeviceKey':p['deviceId'],'publicEndpoint':'tcp://127.0.0.1:32200','coreUid':os.getuid(),'socket':str(root/'broker.sock')}
 engine=broker.Engine(cfg,True)
 with open(root/'engine-private.log','wb') as log:
  process=subprocess.Popen([str(BINARY),'serve','--home',str(home),'--no-browser','--no-restart','--no-upgrade'],stdout=log,stderr=log)
  server=None
  try:
   for attempt in range(40):
    try:engine.identity();break
    except Exception:time.sleep(.25)
   else:raise RuntimeError('Bounded engine startup failed')
   server=multiprocessing.get_context('fork').Process(target=engine.serve);server.start()
   for attempt in range(40):
    if (root/'broker.sock').exists():break
    time.sleep(.1)
   env=dict(os.environ,OOS_OFFLINE_WORKER_TEST_DSN='mysql:unix_socket=/var/tmp/oos-version-admission-20261020/mysql.sock;dbname=qa_offline_worker_20261021',OOS_OFFLINE_TEST_SOCKET=str(root/'broker.sock'),OOS_OFFLINE_TEST_PROJECTIONS=str(projection),OOS_OFFLINE_TEST_PEER=p2['deviceId'])
   result=subprocess.run(['php','/srv/organisation-workspace/worktrees/connectors-office-offline-20261020/core/tests/documents/offline-worker-mariadb.php'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
   if result.returncode:raise RuntimeError(result.stderr.decode()[:4000]+result.stdout.decode()[:2000])
   print(result.stdout.decode(),end='')
  finally:
   if server:server.terminate();server.join(10)
   process.terminate()
   try:process.wait(timeout=15)
   except subprocess.TimeoutExpired:process.kill();process.wait()
