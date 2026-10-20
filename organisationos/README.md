# OrganisationOS Syncthing

Véritable fork de `syncthing/syncthing`, distinct de l’intégration GED OrganisationOS et du paquet employé. Amont v2.1.6, commit `4461a1ce354d3990660966ad70176e00246adb61`, objet tag `28000330a4f4f24e03018333ab31846774c6a9a1`. Dépôt : https://github.com/Organisation-OS/OrganisationOS-Syncthing ; branche `organisationos/2.1.6-oos.1`.

## Modifications maintenues

- Nouvelles configurations : découverte globale/locale, relais publics, NAT, télémétrie et rapport de crash désactivés ; écoute initiale en boucle locale TCP. La recherche automatique du port GUI conserve cette écoute explicite. Les configurations existantes ne sont pas réécrites.
- Binaire construit avec l’option amont `-no-upgrade` : les mises à jour passent par les publications OrganisationOS qualifiées. Version `v2.1.6-oos.1`, constructeur OrganisationOS, titre de l’interface distinguant le fork.
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

Consulter les publications et avis de sécurité amont lors de chaque maintenance et incident. Aucune tâche périodique administrative n’est créée. Récupérer le nouveau tag et son commit, vérifier provenance/signatures disponibles, puis créer une branche de reprise depuis le tag. Réappliquer les trois modifications limitées ci-dessus ; ne pas transporter des patches moteur sans justification. Mettre à jour les références et la chaîne Go/SQLite/compilateurs, conserver notices et sources, reconstruire deux fois et comparer.

Rejouer les tests transport, le démarrage privé, l’appairage à durée limitée, séparation d’instances, droits révoqués, aller-retour, conflits et récupération. Publier un nouveau manifeste signé par application, déployer d’abord sur les essais synthétiques, puis activer le catalogue. Une régression permet de retirer la version sans effacer documents, identités d’appareils, états de conflit ou anciennes preuves ; un retour de version ne doit jamais ouvrir une base SQLite migrée par une version incompatible. Conserver une copie cohérente du répertoire d’état avant mise à jour.

## Qualification du 20 octobre 2026

Le reçu `build-receipt-20261020.json` identifie les binaires construits au commit `3224efdefffef2d57ccaced4e398f49f79e08dc8`. Les six suites ciblées passent et les deux constructions successives sont identiques, sous la même image avec purge du cache Go. `qualify-engine.py` exécute deux vrais moteurs dans des répertoires temporaires et confirme appairage TLS, aller-retour, modification hors ligne, conflit préservé et révocation. Aucun dossier utilisateur réel ni service permanent. Exécuter avec `OOS_ENGINE_REPORT=/chemin/privé/reception.json python3 organisationos/qualify-engine.py`.

Ces reçus ne constituent pas une qualification GED ni Windows. Le binaire Windows est non signé et son champ PE FileVersion optionnel est absent ; le manifeste et `--version` portent sa version exacte. Aucun de ces binaires n’est encore distribué aux employés. Le paquet employé et l’intégration GED auront leurs propres versions et reçus.
