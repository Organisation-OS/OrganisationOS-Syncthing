# OrganisationOS Syncthing

Véritable fork de `syncthing/syncthing`, distinct de l’intégration GED OrganisationOS et du paquet employé. Amont v2.1.6, commit `4461a1ce354d3990660966ad70176e00246adb61`, objet tag `28000330a4f4f24e03018333ab31846774c6a9a1`. Dépôt : https://github.com/Organisation-OS/OrganisationOS-Syncthing ; branche `organisationos/2.1.6-oos.1`.

## Modifications maintenues

- Nouvelles configurations : découverte globale/locale, relais publics, NAT, télémétrie et rapport de crash désactivés ; écoute initiale en boucle locale TCP. La recherche automatique du port GUI conserve cette écoute explicite. Les configurations existantes ne sont pas réécrites.
- Binaire construit avec l’option amont `-no-upgrade` : les mises à jour passent par les publications OrganisationOS qualifiées. Version distribuée `v2.1.6-oos.1` ; prochaine construction `v2.1.6-oos.2`, constructeur OrganisationOS, titre de l’interface distinguant le fork.
- Protocole, clés/certificats d’appareil, contrôles TLS et mécanisme de transport restent ceux de Syncthing. Aucune identité ni clé partagée dans les sources ou paquets. L’installateur génère une identité sur chaque poste.

Ces valeurs par défaut ne constituent pas une ACL documentaire. Le serveur OrganisationOS décide des projections autorisées avant exposition au moteur ; Syncthing ne reçoit aucun accès global au stockage immuable GED. L’intégration GED et l’installateur sont qualifiés séparément. Aucun binaire n’est annoncé distribué avant reçu de publication et téléchargement effectif.

## Construction sur DEV

Depuis un checkout du commit exact indiqué par le manifeste de livraison :

```sh
docker build -f organisationos/Dockerfile -t organisationos-syncthing-builder .
docker run --name organisationos-syncthing-build --cpus=2 --memory=3g --memory-swap=4g --pids-limit=2048 --security-opt=no-new-privileges --mount type=bind,src="$PWD",dst=/work organisationos-syncthing-builder bash organisationos/build.sh
```

Ubuntu est épinglé par digest ; Go 1.27.3 est vérifié par SHA-256 officiel. `go.mod`/`go.sum` épinglent les dépendances et `go mod verify` les contrôle. Les versions des compilateurs Linux/MinGW sont enregistrées. Les commandes construisent Linux amd64 et Windows amd64 avec CGO/SQLite, deux fois après purge du cache Go, puis comparent les octets. Aucun démon de synchronisation n’est démarré par la construction. Le paquet Windows est portable ; le moteur ne possède pas de signature Authenticode tant qu’un reçu distinct ne l’atteste pas.

`organisationos-evidence` contient journal, résultat, dépendances, compilateurs, version et empreintes. Les binaires sont dans `organisationos-output/a`. Le manifeste final doit préciser le commit du fork, l’image de construction, la provenance de chaque binaire et les résultats réels. Une double construction seule ne qualifie pas installation, appairage ou réception Windows.

## Licences et sources correspondantes

La licence MPL-2.0 et les notices Syncthing sont conservées, y compris les notices dans les fichiers modifiés. Les modifications de ces fichiers sont publiées dans ce dépôt sous MPL-2.0. Le paquet redistribue LICENSE, AUTHORS et la référence exacte du code source correspondant ; les licences des dépendances embarquées restent disponibles. MPL-2.0 ne concède pas de droits de marque. « OrganisationOS Syncthing » désigne notre distribution dérivée, sans prétendre à une publication officielle ni à une approbation du projet Syncthing. Aucun logo amont n’est remplacé par une prétendue marque officielle OrganisationOS.

Références vérifiées le 20 octobre 2026 : https://github.com/syncthing/syncthing/releases/tag/v2.1.6 ; https://docs.syncthing.net/dev/building.html ; https://www.mozilla.org/en-US/MPL/2.0/ ; https://syncthing.net/security/ ; https://go.dev/dl/ .

## Reprise des correctifs amont

Consulter les publications et avis de sécurité amont lors de chaque maintenance et incident. Aucune tâche périodique administrative n’est créée. Récupérer le nouveau tag et son commit, vérifier provenance/signatures disponibles, puis créer une branche de reprise depuis le tag. Réappliquer les personnalisations documentées et le garde-fou de configuration locale ci-dessous ; ne pas transporter des patches moteur sans justification. Mettre à jour les références et la chaîne Go/SQLite/compilateurs, conserver notices et sources, reconstruire deux fois et comparer.

Rejouer les tests transport, le démarrage privé, l’appairage à durée limitée, séparation d’instances, droits révoqués, aller-retour, conflits et récupération. Publier un nouveau manifeste signé par application, déployer d’abord sur les essais synthétiques, puis activer le catalogue. Une régression permet de retirer la version sans effacer documents, identités d’appareils, états de conflit ou anciennes preuves ; un retour de version ne doit jamais ouvrir une base SQLite migrée par une version incompatible. Conserver une copie cohérente du répertoire d’état avant mise à jour.

## Qualification du 20 octobre 2026

Le reçu `build-receipt-20261020.json` identifie les binaires construits au commit `3224efdefffef2d57ccaced4e398f49f79e08dc8`. Les six suites ciblées passent et les deux constructions successives sont identiques, sous la même image avec purge du cache Go. `qualify-engine.py` exécute deux vrais moteurs dans des répertoires temporaires et confirme appairage TLS, aller-retour, modification hors ligne, conflit préservé et révocation. Aucun dossier utilisateur réel ni service permanent. Exécuter avec `OOS_ENGINE_REPORT=/chemin/privé/reception.json python3 organisationos/qualify-engine.py`.

Ces reçus ne constituent pas une qualification GED ni Windows. Le binaire Windows est non signé et son champ PE FileVersion optionnel est absent ; le manifeste et `--version` portent sa version exacte. Le ZIP portable de qualification a depuis été distribué au seul compte de réception TheCGP ; son moteur reste exactement celui du commit `3224efde`. Cela ne constitue pas une distribution générale ni une intégration GED reçue.


## Incident d’annonce de partage et garde-fou (21 octobre 2026)

Le binaire Windows réellement distribué est toujours `v2.1.6-oos.1`, source moteur `3224efdefffef2d57ccaced4e398f49f79e08dc8`, SHA-256 `2a07186aab4f0e2b331760a6c4f7d743410548c58b6693e1cd7cb580d084a2d5`. L’empreinte du poste de réception correspond. L’installateur initial est issu de `355147fa1ae3b6c80b20aac32e9739209934ea7b`. Aucun nouveau binaire n’est distribué par ce correctif de sources.

Cause reproduite avec deux moteurs originaux : un `encryptionPassword` non vide sur l’entrée de **son propre appareil** fait filtrer cette identité par `generateClusterConfigRLocked` lorsqu’il annonce le dossier à un autre appareil. Le destinataire refuse ensuite l’annonce dépourvue de l’identité de l’émetteur. Les deux identités peuvent donc être présentes dans la configuration locale tout en étant absentes de l’annonce. Effacer uniquement ce champ local restaure le transfert, sans changement de certificat, de dossier, de fichiers ou de mot de passe d’un destinataire distant.

L’installateur ne renseigne pas ce champ et les configurations fraîchement générées l’ont vide. L’interface amont pouvait conserver puis réenregistrer une valeur déjà présente sur l’entrée locale cachée. **L’origine historique de l’insertion sur ce poste n’est pas établie** ; la reproduction confirme le mécanisme de refus, pas l’auteur ni le parcours initial de saisie. Aucune valeur de chiffrement, clé API ou configuration privée n’est publiée.

Le garde-fou normalise uniquement l’entrée locale dans la préparation native de la configuration et dans l’édition GUI ; les mots de passe des destinataires distants restent intacts. Les quatre types de dossier sont couverts par le test de configuration. `node organisationos/test-folder-sharing.cjs` exerce les véritables méthodes GUI avec des fixtures synthétiques, pour une entrée locale existante ou ajoutée. Les suites `go test -short ./lib/config ./lib/model ./lib/protocol` passent. Le protocole et le refus d’une annonce invalide restent inchangés.

La réparation locale portable est `windows/Reparer-Qualification-IdentiteLocale.ps1 -ExpectedDeviceId IDENTIFIANT_PUBLIC` (lecture seule), puis le même appel avec `-Repair`. Elle vérifie l’identité active et le périmètre Fichiers-synthetiques, conserve une sauvegarde privée locale de config.xml, et modifie uniquement le champ de l’entrée locale par l’API native. Ne jamais transmettre cette sauvegarde. L’opération est idempotente et ne redémarre pas le moteur. Le script n’a pas été ajouté rétroactivement au ZIP publié ; la réception utilise une commande ciblée équivalente.

La prochaine construction porte `v2.1.6-oos.2` pour distinguer ces sources du moteur déjà distribué. Avant publication : nouvelle provenance, doubles constructions, qualifications du chiffrement distant et de l’aller-retour, puis catalogue signé. Ne pas réutiliser le reçu de construction de `oos.1` pour `oos.2`.

La [réception interne Windows du 21 octobre](windows/RECEPTION-20261021.md) consigne installation, appairage, aller-retour, reprise, conflit et révocation effectivement reçus, avec provenance du moteur et limites de portée.
