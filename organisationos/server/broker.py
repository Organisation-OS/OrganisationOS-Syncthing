#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Local, peer-credential restricted engine adapter. Never logs requests or credentials.
A projection is isolated from canonical GED storage; every filesystem traversal uses
openat/O_NOFOLLOW. The native GED worker remains the sole version admission authority.
"""
import base64,hashlib,http.client,json,os,pathlib,re,socket,stat,struct,sys,uuid,xml.etree.ElementTree as ET
MAX_FILE=64*1024*1024
MAX_REQUEST=MAX_FILE*4//3+65536
PIN='9eaf8cad615cfb07f17af7b87f0e3e77e5a99d902c6f971909bcca4bd3102d6b'
class Refused(Exception):pass

def uid(value):
 if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise Refused()
 return value

def device(value):
 if not isinstance(value,str) or not re.fullmatch(r'[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}',value):raise Refused()
 return value

def components(path):
 if not isinstance(path,str) or len(path.encode())>200:raise Refused()
 bits=path.split('/')
 if len(bits)!=3 or bits[0]!='Documents' or uid(bits[1])!=bits[1] or not bits[2] or bits[2] in ['.','..'] or any(c in bits[2] for c in '\\:\x00') or bits[2].startswith('.'):raise Refused()
 return bits

class Projections:
 def __init__(self,path):
  self.path=os.path.abspath(path)
  if os.path.realpath(path)!=self.path:raise Refused()
  self.fd=os.open(self.path,os.O_DIRECTORY|os.O_NOFOLLOW)
 def directory(self,parts,create=False):
  fd=os.dup(self.fd)
  try:
   for part in parts:
    if create:
     try:os.mkdir(part,0o700,dir_fd=fd)
     except FileExistsError:pass
    child=os.open(part,os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
   return fd
  except BaseException:os.close(fd);raise
 def ensure(self,selection):
  fd=self.directory([uid(selection)],True)
  try:
   try:os.mkdir('.stfolder',0o700,dir_fd=fd)
   except FileExistsError:pass
   marker=os.open('.stfolder',os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(marker)
  finally:os.close(fd)
  return self.path+'/'+selection
 def put(self,selection,path,encoded,digest):
  parts=components(path);data=base64.b64decode(encoded,validate=True)
  if len(data)>MAX_FILE or hashlib.sha256(data).hexdigest()!=digest:raise Refused()
  if os.statvfs(self.fd).f_bavail*os.statvfs(self.fd).f_frsize < 42949672960 + len(data):raise Refused()
  self.ensure(selection);fd=self.directory([uid(selection),*parts[:-1]],True)
  temp='.oos-'+uuid.uuid4().hex
  try:
   # An existing employee edit, conflict or rename is never overwritten by refresh/replay.
   try:
    old=self.read(selection,path)
    if old['sha256']!=digest:raise Refused()
    return {'status':'UNCHANGED','sha256':digest}
   except FileNotFoundError:pass
   out=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
   with os.fdopen(out,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
   # Atomic no-replace publication, unlike rename(). A concurrent sync creation wins.
   os.link(temp,parts[-1],src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);os.unlink(temp,dir_fd=fd);os.fsync(fd)
   return {'status':'CREATED','sha256':digest}
  finally:
   try:os.unlink(temp,dir_fd=fd)
   except FileNotFoundError:pass
   os.close(fd)
 def read(self,selection,path):
  parts=components(path);fd=self.directory([uid(selection),*parts[:-1]])
  try:
   inp=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
   with os.fdopen(inp,'rb') as stream:
    before=os.fstat(stream.fileno())
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE:raise Refused()
    data=stream.read(MAX_FILE+1);after=os.fstat(stream.fileno());current=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
    if len(data)!=before.st_size or (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns,after.st_size) or (current.st_dev,current.st_ino)!=(before.st_dev,before.st_ino):raise Refused()
    return {'sha256':hashlib.sha256(data).hexdigest(),'bytes':base64.b64encode(data).decode(),'size':len(data)}
  finally:os.close(fd)
 def inventory(self,selection):
  fd=self.directory([uid(selection)]);items=[]
  def walk(directory,prefix,depth):
   for name in sorted(os.listdir(directory)):
    if name=='.stfolder' or name=='.stversions' or name.startswith('.syncthing.') or name.startswith('.oos-'):continue
    if len(items)>=2048:raise Refused()
    path=prefix+name;s=os.stat(name,dir_fd=directory,follow_symlinks=False)
    if stat.S_ISDIR(s.st_mode) and depth<3:
     child=os.open(name,os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
     try:walk(child,path+'/',depth+1)
     finally:os.close(child)
    else:items.append({'path':path,'kind':'FILE' if stat.S_ISREG(s.st_mode) and s.st_nlink==1 else 'REFUSED','size':s.st_size})
  try:walk(fd,'',0);return items
  finally:os.close(fd)

class Engine:
 def __init__(self,config,qualification=False):
  self.config=config;self.projections=Projections(config['projectionRoot'])
  binary=pathlib.Path(config['engineBinary'])
  if hashlib.sha256(binary.read_bytes()).hexdigest()!=PIN:raise Refused()
  r=ET.parse(config['engineConfig']).getroot();g=r.find('gui')
  address=g.findtext('address');m=re.fullmatch(r'127\.0\.0\.1:([0-9]+)',address or '')
  if not m or (not qualification and int(m[1])!=8384) or g.get('tls')=='true':raise Refused()
  self.port=int(m[1]);self.key=g.findtext('apikey')
  if not self.key or len(self.key)>256:raise Refused()
  endpoint=config['publicEndpoint']
  expected={'27c0be38-60bd-4dce-bb28-ef0088716a25':'tcp://syncthing.thecgp.com:22000','b7a1f6b1-c4aa-4de7-95fb-29d509d3398d':'tcp://syncthing.villesadp.ca:22000'}
  if not qualification and expected.get(config['instanceId'])!=endpoint:raise Refused()
  device(config['serverDeviceKey'])
 def api(self,method,path,body=None):
  c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=10)
  try:
   c.request(method,'/rest/'+path,body=None if body is None else json.dumps(body,separators=(',',':')),headers={'X-API-Key':self.key,'Content-Type':'application/json'})
   r=c.getresponse();raw=r.read(4*1024*1024+1)
   if r.status<200 or r.status>=300 or len(raw)>4*1024*1024:raise Refused()
   return json.loads(raw) if raw else None
  finally:c.close()
 def identity(self):
  r=self.api('GET','system/status')
  if r.get('myID')!=self.config['serverDeviceKey']:raise Refused()
  c=self.api('GET','config');options=c.get('options',{})
  if options.get('minHomeDiskFree')!={'value':42949672960,'unit':'B'}:raise Refused()
  if c.get('gui',{}).get('address')!='127.0.0.1:'+str(self.port) or any(options.get(k,True) for k in ['globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled']):raise Refused()
  return {'deviceKey':r['myID'],'publicEndpoint':self.config['publicEndpoint'],'engineVersion':'v2.1.6-oos.2','engineSha256':PIN}
 def dispatch(self,request):
  if not isinstance(request,dict) or request.get('instanceId')!=self.config['instanceId']:raise Refused()
  op=request.get('operation');args=request.get('arguments')
  if set(request)!=set(['instanceId','operation','arguments']) or not isinstance(args,dict):raise Refused()
  expected={'identity':[],'pair':['deviceKey'],'remove':['deviceKey'],'folder':['selection','deviceKey','label'],'removeFolder':['selection'],'put':['selection','path','bytes','sha256'],'read':['selection','path'],'inventory':['selection']}
  if op not in expected or set(args)!=set(expected[op]):raise Refused()
  identity=self.identity()
  if op=='identity':return identity
  if op in ['pair','remove','folder']:
   key=device(args['deviceKey'])
   if key==identity['deviceKey']:raise Refused()
  if op=='pair':
   devices=self.api('GET','config/devices')
   prior=next((d for d in devices if d['deviceID']==key),None)
   if prior:
    if prior.get('introducer') or prior.get('autoAcceptFolders') or prior.get('untrusted'):raise Refused()
    return {'status':'UNCHANGED'}
   entry=self.api('GET','config/defaults/device');entry.update(deviceID=key,name='OrganisationOS employee',addresses=['dynamic'],introducer=False,autoAcceptFolders=False,untrusted=False,paused=False)
   self.api('PUT','config/devices/'+key,entry);return {'status':'PAIRED'}
  if op=='remove':
   c=self.api('GET','config');c['devices']=[d for d in c['devices'] if d['deviceID']!=key]
   for folder in c['folders']:folder['devices']=[d for d in folder['devices'] if d['deviceID']!=key]
   self.api('PUT','config',c)
   # Active transport must disappear before revocation is confirmed.
   if self.api('GET','system/connections').get('connections',{}).get(key,{}).get('connected'):raise Refused()
   return {'status':'REMOVED'}
  if op in ['folder','removeFolder']:
   selection=uid(args['selection']);folderid='oos-'+selection
   c=self.api('GET','config/folders');prior=next((f for f in c if f['id']==folderid),None)
   if op=='removeFolder':
    if prior:self.api('DELETE','config/folders/'+folderid)
    return {'status':'DETACHED','filesPreserved':True}
   label=args['label']
   if not isinstance(label,str) or not 1<=len(label)<=120 or any(ord(c)<32 for c in label):raise Refused()
   if key not in [d['deviceID'] for d in self.api('GET','config/devices')]:raise Refused()
   path=self.projections.ensure(selection)
   if prior:
    if prior.get('minDiskFree')!={'value':42949672960,'unit':'B'} or prior['path']!=path or prior['type']!='sendreceive' or sorted(d['deviceID'] for d in prior['devices'])!=sorted([key,identity['deviceKey']]) or any(d.get('encryptionPassword') for d in prior['devices']):raise Refused()
    return {'status':'UNCHANGED'}
   folder=self.api('GET','config/defaults/folder');folder.update(id=folderid,label=label,path=path,type='sendreceive',devices=[{'deviceID':identity['deviceKey'],'encryptionPassword':''},{'deviceID':key,'encryptionPassword':''}],paused=False,ignorePerms=True,fsWatcherEnabled=True,rescanIntervalS=60,minDiskFree={'value':42949672960,'unit':'B'})
   self.api('PUT','config/folders/'+folderid,folder);return {'status':'SHARED'}
  if op=='put':return self.projections.put(args['selection'],args['path'],args['bytes'],args['sha256'])
  if op=='read':return self.projections.read(args['selection'],args['path'])
  if op=='inventory':return {'items':self.projections.inventory(args['selection'])}

 def serve(self):
  path=self.config['socket'];activated=os.environ.get('LISTEN_PID')==str(os.getpid()) and os.environ.get('LISTEN_FDS')=='1'
  parent=os.stat(os.path.dirname(path))
  if parent.st_uid not in [0,os.getuid()] or parent.st_mode & 0o022:raise Refused()
  if not activated and os.path.lexists(path):raise Refused()
  listener=socket.socket(fileno=3) if activated else socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  with listener:
   if activated:
    if listener.family!=socket.AF_UNIX or listener.getsockname()!=path:raise Refused()
   else:listener.bind(path);os.chmod(path,0o660);listener.listen(8)
   try:
    while True:
     conn,_=listener.accept()
     with conn:
      conn.settimeout(30)
      try:
       _,peer,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
       if peer!=self.config['coreUid']:raise Refused()
       data=bytearray()
       while not data.endswith(b'\n'):
        chunk=conn.recv(min(65536,MAX_REQUEST+1-len(data)))
        if not chunk or len(data)+len(chunk)>MAX_REQUEST:raise Refused()
        data.extend(chunk)
       if b'\n' in data[:-1]:raise Refused()
       result={'ok':True,'result':self.dispatch(json.loads(data))}
      except Exception:result={'ok':False,'error':'LOCAL_ENGINE_OPERATION_REFUSED'}
      try:conn.sendall(json.dumps(result,separators=(',',':')).encode()+b'\n')
      except OSError:pass
   finally:
    if not activated:os.unlink(path)

def main():
 if len(sys.argv)!=2:raise Refused()
 path=pathlib.Path(sys.argv[1]);s=path.stat()
 if path.is_symlink() or path.resolve()!=path or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise Refused()
 config=json.loads(path.read_bytes())
 if config.get('schema')!=1 or config.get('socket')!='/run/organisation-syncthing/broker.sock':raise Refused()
 Engine(config).serve()
if __name__=='__main__':
 try:main()
 except Exception:sys.exit('OrganisationOS local engine unavailable; private details suppressed.')
