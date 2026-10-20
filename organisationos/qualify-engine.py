#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Two actual fork processes, loopback only, synthetic temporary files. No GED/Windows claim."""
import datetime, hashlib, json, os, pathlib, socket, subprocess, tempfile, time, urllib.request, xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=ROOT/'organisationos-output/a/organisationos-syncthing'
REPORT=pathlib.Path(os.environ.get('OOS_ENGINE_REPORT', '/tmp/oos-engine-reception.json'))
checks=[]
def wait(fn, label, seconds=40):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            if fn(): checks.append(label); return
        except (OSError, ValueError, KeyError): pass
        time.sleep(.2)
    raise AssertionError(label)
def port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def check(value,label):
    if not value: raise AssertionError(label)
    checks.append(label)
class Node:
    def __init__(self, root, name):
        self.name=name; self.home=root/name; self.home.mkdir(); self.folder=self.home/'synthetic'; self.folder.mkdir(); self.p=None
        self.gui=port(); self.listen=port(); self.log=open(self.home/'runtime.log','wb')
        self.env={**os.environ,'HOME':str(self.home),'STNOUPGRADE':'1'}
        subprocess.run([str(BIN),'generate','--home',str(self.home),'--no-port-probing'],env=self.env,stdout=self.log,stderr=self.log,check=True)
        xml=ET.parse(self.home/'config.xml'); r=xml.getroot()
        for f in r.findall('folder'): r.remove(f)
        opts=r.find('options')
        for name_ in ['globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled','crashReportingEnabled']:
            check(opts.findtext(name_)=='false',name+':default:'+name_)
        check(opts.findtext('listenAddress')=='tcp://127.0.0.1:22000',name+':default:loopback')
        opts.find('listenAddress').text='tcp://127.0.0.1:'+str(self.listen)
        r.find('gui/address').text='127.0.0.1:'+str(self.gui)
        self.key=r.findtext('gui/apikey'); self.id=r.find('device').get('id')
        xml.write(self.home/'config.xml')
    def api(self,path,body=None,method=None):
        req=urllib.request.Request('http://127.0.0.1:'+str(self.gui)+'/rest/'+path,data=None if body is None else json.dumps(body).encode(),headers={'X-API-Key':self.key,'Content-Type':'application/json'},method=method)
        with urllib.request.urlopen(req,timeout=3) as response:
            data=response.read(); return json.loads(data) if data else None
    def start(self):
        self.p=subprocess.Popen([str(BIN),'serve','--home',str(self.home),'--no-browser','--no-restart','--no-upgrade','--no-port-probing'],env=self.env,stdout=self.log,stderr=self.log)
        wait(lambda:self.api('system/status').get('myID')==self.id,self.name+':start')
    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try:self.p.wait(15)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait();raise
        self.p=None
    def scan(self): self.api('db/scan?folder=oos-synthetic',{},'POST')
    def pause_peer(self,peer,paused): self.api('config/devices/'+peer.id,{'paused':paused},'PATCH')
    def connect(self,peer):
        d=self.api('config/defaults/device'); d.update(deviceID=peer.id,name='synthetic-'+peer.name,addresses=['tcp://127.0.0.1:'+str(peer.listen)],autoAcceptFolders=False)
        self.api('config/devices',d,'POST')
        f=self.api('config/defaults/folder'); f.update(id='oos-synthetic',label='Synthetic qualification only',path=str(self.folder),type='sendreceive',rescanIntervalS=1,fsWatcherEnabled=False,devices=[{'deviceID':self.id},{'deviceID':peer.id}])
        self.api('config/folders',f,'POST')
    def has(self,name,text): return (self.folder/name).is_file() and (self.folder/name).read_text()==text
nodes=[]; result={'schema':'oos-syncthing-engine-reception-v1','binarySha256':hashlib.sha256(BIN.read_bytes()).hexdigest(),'sourceCommit':(ROOT/'organisationos-evidence/source-commit.txt').read_text().strip(),'windowsReception':'NOT_RUN','gedIntegrationReception':'NOT_RUN'}
try:
    with tempfile.TemporaryDirectory(prefix='oos-syncthing-engine-') as directory:
        root=pathlib.Path(directory); os.chmod(root,0o700)
        try:
            a=Node(root,'a'); b=Node(root,'b'); nodes=[a,b]; a.start();b.start()
            check(a.id!=b.id,'distinct-device-identities')
            a.connect(b);b.connect(a)
            wait(lambda:a.api('system/connections')['connections'].get(b.id,{}).get('connected'), 'actual-mutual-TLS-pair')
            (a.folder/'roundtrip.txt').write_text('synthetic-a-v1');a.scan()
            wait(lambda:b.has('roundtrip.txt','synthetic-a-v1'),'transfer-a-to-b')
            (b.folder/'roundtrip.txt').write_text('synthetic-b-v2');b.scan()
            wait(lambda:a.has('roundtrip.txt','synthetic-b-v2'),'transfer-b-to-a')
            b.stop(); (b.folder/'offline.txt').write_text('offline-synthetic'); b.start();b.scan()
            wait(lambda:a.has('offline.txt','offline-synthetic'),'offline-change-reconnect')
            (a.folder/'conflict.txt').write_text('base-synthetic');a.scan()
            wait(lambda:b.has('conflict.txt','base-synthetic'),'conflict-common-base')
            a.pause_peer(b,True);b.pause_peer(a,True);a.stop();b.stop()
            (a.folder/'conflict.txt').write_text('branch-A-synthetic');(b.folder/'conflict.txt').write_text('branch-B-synthetic')
            a.start();b.start();a.scan();b.scan()
            wait(lambda:a.api('db/file?folder=oos-synthetic&file=conflict.txt')['local']['size']==len('branch-A-synthetic'),'offline-A-indexed')
            wait(lambda:b.api('db/file?folder=oos-synthetic&file=conflict.txt')['local']['size']==len('branch-B-synthetic'),'offline-B-indexed')
            a.pause_peer(b,False);b.pause_peer(a,False)
            def conflict_saved():
                for n in nodes:
                    contents={p.read_text() for p in n.folder.glob('conflict*.txt')}
                    if {'branch-A-synthetic','branch-B-synthetic'} <= contents:return True
                return False
            wait(conflict_saved,'concurrent-versions-preserved-as-conflict')
            a.api('config/devices/'+b.id,method='DELETE')
            wait(lambda:not a.api('system/connections')['connections'].get(b.id,{}).get('connected'),'device-revoked-connection-closed')
            (b.folder/'after-revocation.txt').write_text('must-not-transfer');b.scan();time.sleep(4)
            check(not (a.folder/'after-revocation.txt').exists(),'revoked-device-transfer-denied')
            result['status']='PASS'
        finally:
            for n in nodes:n.stop();n.log.close()
except Exception as exc:
    result['status']='FAIL';result['errorType']=type(exc).__name__;result['error']=str(exc)
finally:
    result.update(checks=checks,finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),processesStopped=all(n.p is None for n in nodes))
    REPORT.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if result['status']!='PASS':raise SystemExit(1)
