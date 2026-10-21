#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build private qualification packages; never enroll a device while packaging."""
from pathlib import Path
import zipfile,json,hashlib,subprocess,io
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def package(config,output):
 names={'27c0be38-60bd-4dce-bb28-ef0088716a25':('TheCGP','https://portal.thecgp.com','tcp://syncthing.thecgp.com:22000'),'b7a1f6b1-c4aa-4de7-95fb-29d509d3398d':('Ville','https://portal.villesadp.ca','tcp://syncthing.villesadp.ca:22000')}
 c=json.loads(Path(config).read_bytes());label,origin,endpoint=names[c['instanceId']];assert c['schema']==2 and c['portalOrigin']==origin and c['publicEndpoint']==endpoint and c['organisationName']==label
 assert c['apiOrigin']=={'TheCGP':'https://portal.thecgp.com','Ville':'https://api.villesadp.ca'}[label]
 assert Path(output).name=='OrganisationOS-Syncthing-'+label+'-0.3.1-candidate.1-windows-x64.zip'
 exe=(HERE/'output-0.3.1/OrganisationOS-Syncthing-Installer.exe').read_bytes();assert sha(exe)=='48e6af2d6dbd252ee4fad9a63672e6d85dfebc976e7f2276d9056b17c9c7a908'
 with zipfile.ZipFile(ROOT/'organisationos-output/OrganisationOS-Syncthing-Qualification-0.2.0-windows-x64.zip')as old:
  files={n:old.read(n) for n in old.namelist()if n.startswith('notices/') or n in ['LICENSE.txt','AUTHORS.txt','source-moteur.zip']}
 files['LICENSE-Go.txt']=(HERE/'LICENSE-Go.txt').read_bytes();files['OrganisationOS-Syncthing-Installer.exe']=exe;files['organisation.json']=json.dumps(c,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 files['source-installateur.zip']=subprocess.check_output(['git','archive','--format=zip','afeb1c6067e986cb019e303230a7a89057b39bca','organisationos/employee'],cwd=ROOT)
 files['LIRE-MOI.txt']=('OrganisationOS Syncthing — '+label+' — qualification 0.3.1-candidate.1\r\n\r\nDécompressez ce ZIP, puis ouvrez OrganisationOS-Syncthing-Installer.exe.\r\nLe navigateur ouvre votre organisation. Connectez-vous puis autorisez ce poste. Aucun serveur, port, clé ou identifiant à recopier.\r\nChoisissez ensuite Garder hors ligne dans Documents. Seules les sélections autorisées deviennent locales.\r\nInstallation dans LOCALAPPDATA/OrganisationOS/Syncthing, identité propre par organisation, reprise à la prochaine ouverture de session, raccourci dans le menu Démarrer. Aucun service système, redémarrage ou modification de RustDesk.\r\nLes mises à jour conservent identité, fichiers et conflits. La révocation bloque les futurs échanges, sans effacer les copies déjà reçues.\r\nCette version reste réservée à la qualification. Réception Windows propre et accès extérieur non réalisés. Ne pas l’utiliser pour des documents personnels pendant la réception.\r\nAuthenticode Windows : absent. La signature du manifeste OrganisationOS est distincte.\r\n').encode()
 provenance={'schema':'oos-employee-build-provenance-v1','installerVersion':'0.3.1-candidate.1','installerSourceCommit':'afeb1c6067e986cb019e303230a7a89057b39bca','installerSha256':sha(exe),'engineVersion':'v2.1.6-oos.2','engineSourceCommit':'e80f807467f5e127f35e2de45cfd22d4091bcd42','engineWindowsSha256':'14421c4afbe5b48ddd9065410310f6fd667d678ae5943bd9520f28f261d8eb4b','repository':'https://github.com/Organisation-OS/OrganisationOS-Syncthing','windowsAuthenticode':'UNSIGNED','windowsReception':'NOT_RUN','internetReception':'NOT_RUN','configuration':c,'deviceIdentityBundled':False,'enrollmentTokenBundled':False,'serverSecretBundled':False,'files':{n:sha(v)for n,v in sorted(files.items())}}
 files['provenance.json']=json.dumps(provenance,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 stream=io.BytesIO()
 with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9)as z:
  for name,raw in sorted(files.items()):
   info=zipfile.ZipInfo(name,date_time=(2026,10,21,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;z.writestr(info,raw)
 raw=stream.getvalue();out=Path(output)
 if out.exists():assert out.read_bytes()==raw
 else:out.write_bytes(raw)
 return {'status':'PACKAGED_QUALIFICATION_ONLY','instanceId':c['instanceId'],'filename':out.name,'size':len(raw),'sha256':sha(raw),'commonInstallerSha256':sha(exe),'windowsReception':False,'secretOrCommonEmployeeIdentityBundled':False}
if __name__=='__main__':
 import sys;print(json.dumps(package(*sys.argv[1:])))
