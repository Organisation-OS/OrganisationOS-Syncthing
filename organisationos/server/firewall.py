#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Own-table-only replay check; never flushes or rewrites another firewall table."""
import json,os,pathlib,subprocess,sys
TABLE='organisationos_syncthing'
def main():
 p=pathlib.Path('/etc/organisation/syncthing/firewall.json');s=p.lstat()
 if p.is_symlink() or p.resolve()!=p or s.st_uid!=0 or s.st_mode&0o022:raise ValueError()
 v=json.loads(p.read_bytes());known={'10.9.5.18':'10.9.5.74','10.100.8.50':'10.100.8.13'}
 if set(v)!=set(['listenIp','proxyIp']) or known.get(v['listenIp'])!=v['proxyIp']:raise ValueError()
 expected=[{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':v['listenIp']}},{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':22000}},{'match':{'op':'!=','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':v['proxyIp']}},{'drop':None}]
 r=subprocess.run(['/usr/sbin/nft','-j','list','table','inet',TABLE],capture_output=True)
 if r.returncode==0:
  objects=json.loads(r.stdout)['nftables'];chains=[o['chain'] for o in objects if 'chain'in o];rules=[o['rule'] for o in objects if 'rule'in o]
  if len(chains)!=1 or len(rules)!=1 or any(k in o for o in objects for k in ['set','map','flowtable']) or chains[0].get('name')!='input' or chains[0].get('type')!='filter' or chains[0].get('hook')!='input' or chains[0].get('prio')!=-5 or chains[0].get('policy')!='accept' or rules[0].get('chain')!='input' or rules[0]['expr']!=expected:raise ValueError()
  return
 # Distinguish absent table from denied/unavailable firewall control, without swallowing errors.
 all_tables=subprocess.run(['/usr/sbin/nft','-j','list','tables'],capture_output=True,check=True)
 if any(o.get('table',{}).get('name')==TABLE and o['table'].get('family')=='inet' for o in json.loads(all_tables.stdout)['nftables']):raise ValueError()
 commands={'nftables':[{'add':{'table':{'family':'inet','name':TABLE}}},{'add':{'chain':{'family':'inet','table':TABLE,'name':'input','type':'filter','hook':'input','prio':-5,'policy':'accept'}}},{'add':{'rule':{'family':'inet','table':TABLE,'chain':'input','expr':expected}}}]}
 subprocess.run(['/usr/sbin/nft','-j','-f','-'],input=json.dumps(commands).encode(),capture_output=True,check=True)
if __name__=='__main__':
 try:main()
 except Exception:sys.exit('OrganisationOS synchronization firewall unavailable; existing rules preserved.')
