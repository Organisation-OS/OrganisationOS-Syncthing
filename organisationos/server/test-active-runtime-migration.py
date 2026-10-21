from pathlib import Path
import ast,importlib.util,json,tempfile,types,os,xml.etree.ElementTree as ET,subprocess
R=Path('/srv/organisation-workspace/worktrees/connectors-office-offline-20261020/syncthing-upstream/organisationos/server');spec=importlib.util.spec_from_file_location('native',R/'native_install.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
source=ast.parse((R/'native_install.py').read_text());blocks=[n for n in ast.walk(source)if isinstance(n,ast.If)and isinstance(n.test,ast.Name)and n.test.id=='migrating'and any(isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='timerWasActive'for t in x.targets)for x in n.body)];assert len(blocks)==1
code=compile(ast.fix_missing_locations(ast.Module(body=blocks[0].body,type_ignores=[])),'qualified-native-upgrade-block','exec');checks=[]
for failure in ['none','replace','start','drift']:
 with tempfile.TemporaryDirectory(prefix='oos-native-upgrade-')as temporary:
  root=Path(temporary);unitroot=root/'units';unitroot.mkdir();cfgroot=root/'config';cfgroot.mkdir();backups=root/'backups';backups.mkdir(mode=0o700);home=root/'home';home.mkdir()
  (home/'config.xml').write_text('<configuration><device id="synthetic-server"/><device id="synthetic-retained-employee"/></configuration>');(home/'cert.pem').write_text('synthetic certificate');(home/'key.pem').write_text('synthetic private fixture not a real credential')
  old='/opt/organisationos-syncthing/releases/'+'a'*64;new=Path('/opt/organisationos-syncthing/releases')/('b'*64);units={'organisationos-syncthing.service':'[Service]\nExecStart='+str(new)+'/organisationos-syncthing\n','organisationos-offline-worker.service':'[Service]\nExecStart='+str(new)+'/worker-launcher.py\n'}
  before={n:v.replace(str(new),old).encode()for n,v in units.items()}
  for n,b in before.items():(unitroot/n).write_bytes(b);(unitroot/n).chmod(0o644)
  oldcfg={'engineBinary':old+'/organisationos-syncthing','instanceId':'synthetic'};descriptor={**oldcfg,'engineBinary':str(new)+'/organisationos-syncthing'};(cfgroot/'service.json').write_bytes(native.canonical(oldcfg)+b'\n');(backups/'service.json').write_bytes(native.canonical(oldcfg)+b'\n');(backups/'service.json').chmod(0o600)
  if failure=='drift':(unitroot/'organisationos-offline-worker.service').write_text('unreviewed service drift')
  calls=[];triggered=False;replaceCount=0;realReplace=os.replace
  def mapPath(value):
   path=str(value)
   if path=='/etc/systemd/system':return unitroot
   if path=='/etc/organisationos-syncthing/service.json':return cfgroot/'service.json'
   return Path(value)
  def run(args,**kwargs):
   global triggered
   calls.append(args)
   if 'show'in args:return b'0\n'
   if failure=='start'and 'start'in args and 'organisationos-syncthing.service'in args and not triggered:triggered=True;raise ValueError('synthetic startup failure')
   return b''
  def replace(a,b):
   global triggered,replaceCount
   replaceCount+=1
   if failure=='replace'and replaceCount==2 and not triggered:triggered=True;raise OSError('synthetic atomic switch failure')
   return realReplace(a,b)
  identity={n:native.digest((home/n).read_bytes())for n in ['cert.pem','key.pem']};scope={**vars(native),'P':mapPath,'run':run,'subprocess':types.SimpleNamespace(run=lambda *a,**k:types.SimpleNamespace(returncode=0)),'units':units,'release':new,'previousRelease':old,'environment':'','activeUpgrade':True,'backups':backups,'home':home,'peersBefore':['synthetic-retained-employee','synthetic-server'],'identityBefore':identity,'ET':ET,'descriptor':descriptor,'user':types.SimpleNamespace(pw_gid=0)}
  # Native trusted/write helpers retain real filesystem custody validation under UID0.
  savedP=native.P;native.P=mapPath;os.replace=replace
  failed=False
  try:exec(code,scope)
  except (ValueError,OSError):failed=True
  finally:native.P=savedP;os.replace=realReplace
  assert identity=={n:native.digest((home/n).read_bytes())for n in identity}
  if failure=='none':
   assert not failed and all((unitroot/n).read_bytes()==v.encode()for n,v in units.items());assert json.loads((cfgroot/'service.json').read_bytes())==descriptor;checks.append('retained identity and peers survive exact service switch')
  elif failure=='drift':assert failed and not calls;checks.append('unreviewed predecessor drift refused before stopping services')
  else:
   assert failed and triggered and all((unitroot/n).read_bytes()==b for n,b in before.items());assert json.loads((cfgroot/'service.json').read_bytes())==oldcfg;assert any('start'in a and 'organisationos-syncthing.service'in a for a in calls);checks.append(failure+' failure restores exact old units and descriptor')
  if failure!='drift':assert calls[-1]==['/usr/bin/systemctl','start','organisationos-offline-worker.timer'];checks.append('previous worker timer restored')
print(json.dumps({'status':'PASS','checks':checks,'actualFilesystem':True,'systemdOperations':'SIMULATED_FAULT_INJECTION','productionWrites':0}))
