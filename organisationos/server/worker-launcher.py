#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import json,os,pathlib,re,sys
p=pathlib.Path('/etc/organisation/syncthing/worker.json');s=p.lstat()
if p.resolve()!=p or s.st_uid!=0 or s.st_mode&0o022:sys.exit('Native worker binding unavailable')
c=json.loads(p.read_bytes())
if len(sys.argv)==2 and sys.argv[1]=='--check-module':
 registry=pathlib.Path(c['moduleRegistry']);s=registry.lstat()
 if registry.resolve()!=registry or s.st_uid!=0 or s.st_mode&0o022:sys.exit(1)
 value=json.loads(registry.read_bytes());sys.exit(0 if 'documents'in value.get('modules',{})else 1)
if len(sys.argv)!=1:sys.exit('Native worker invocation refused')
if c['adapter']=='historical-web-v1':
 commit=pathlib.Path(c['coreMarker']).read_text().strip()
 if not re.fullmatch('[a-f0-9]{40}',commit):sys.exit('Native Core pointer unavailable')
 core=pathlib.Path(c['coreReleases'])/commit
else:core=pathlib.Path(c['corePath']).resolve(strict=True)
entry=core/'bin/documents-offline-worker'
if not entry.is_file() or entry.is_symlink():sys.exit('Native offline worker not yet installed')
os.environ['ORG_CONFIGURATION_PATH']=c['configurationPath']
os.execv('/usr/bin/php',['php','-d','memory_limit=512M',str(entry)])
