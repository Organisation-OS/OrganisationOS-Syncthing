#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Prepare local private state once; no service installation, enrollment or publication."""
import argparse,hashlib,ipaddress,json,os,pathlib,re,stat,subprocess,tempfile,xml.etree.ElementTree as ET
PIN='9eaf8cad615cfb07f17af7b87f0e3e77e5a99d902c6f971909bcca4bd3102d6b'
def prepare(binary,home,listen,gui,qualification=False):
 binary=pathlib.Path(binary).resolve(strict=True);home=pathlib.Path(home).absolute()
 if hashlib.sha256(binary.read_bytes()).hexdigest()!=PIN:raise ValueError('Unqualified engine')
 match=re.fullmatch(r'tcp://([0-9.]+):([0-9]+)',listen);g=re.fullmatch(r'127\.0\.0\.1:([0-9]+)',gui)
 if not match or not g:raise ValueError('TCP IPv4 and local GUI required')
 ip=ipaddress.ip_address(match[1]);port=int(match[2]);gp=int(g[1])
 if not (1024<=port<=65535 and 1024<=gp<=65535 and gp!=port):raise ValueError('Invalid distinct ports')
 if qualification:
  if not ip.is_loopback:raise ValueError('Qualification must stay loopback')
 elif not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved or port!=22000 or gp!=8384:raise ValueError('Production private TCP22000 and local GUI8384 required')
 for p in [home,*home.parents]:
  if p.is_symlink():raise ValueError('Symlink custody refused')
 if home.exists():
  st=home.stat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:raise ValueError('Private state custody refused')
  for n in ['config.xml','cert.pem','key.pem']:
   p=home/n
   if not p.is_file() or p.is_symlink() or p.stat().st_nlink!=1 or p.stat().st_uid!=os.getuid():raise ValueError('State incomplete or unsafe')
  tree=ET.parse(home/'config.xml');r=tree.getroot()
  if r.findtext('options/listenAddress')!=listen or r.findtext('gui/address')!=gui:raise ValueError('Existing endpoint differs; migration required')
  for n in ['globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled','crashReportingEnabled']:
   if r.findtext('options/'+n)!='false':raise ValueError('Unexpected network option')
  return {'status':'UNCHANGED','deviceId':r.find('device').get('id'),'identityPreserved':True,'serviceStarted':False}
 if not home.parent.is_dir():raise ValueError('Native installer must provision state parent')
 with tempfile.TemporaryDirectory(prefix='.oos-syncthing-prepare-',dir=home.parent) as temporary:
  stage=pathlib.Path(temporary)/'state';stage.mkdir(mode=0o700)
  p=subprocess.run([str(binary),'generate','--home',str(stage),'--no-port-probing'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
  if p.returncode:raise RuntimeError('Identity generation failed; private output suppressed')
  tree=ET.parse(stage/'config.xml');r=tree.getroot()
  for folder in r.findall('folder'):r.remove(folder)
  r.find('options/listenAddress').text=listen;r.find('gui/address').text=gui
  for n in ['globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled','crashReportingEnabled']:r.find('options/'+n).text='false'
  tree.write(stage/'config.xml');os.chmod(stage/'config.xml',0o600)
  if home.exists():raise ValueError('Concurrent state creation; refused')
  os.rename(stage,home)
  return {'status':'PREPARED_NOT_INSTALLED','deviceId':r.find('device').get('id'),'folders':0,'serviceStarted':False,'gui':gui,'listen':listen}
def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--home',required=True);p.add_argument('--listen',required=True);p.add_argument('--gui',default='127.0.0.1:8384');p.add_argument('--qualification',action='store_true');a=p.parse_args();print(json.dumps(prepare(a.binary,a.home,a.listen,a.gui,a.qualification)))
if __name__=='__main__':main()
