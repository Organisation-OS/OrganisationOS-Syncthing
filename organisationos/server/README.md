# Composant serveur natif OrganisationOS Syncthing

Le moteur est commun aux instances; le profil réseau reste une entrée native par
instance. `prepare-state.py` exige l'empreinte Linux du build reçu, crée localement
une identité distincte et aucun dossier, conserve les secrets dans l'état privé,
et refuse de réinitialiser un état existant. Le rejeu vérifie le réseau sans
modifier identité, index, fichiers ou conflits. Les paramètres GUI restent sur
127.0.0.1:8384, la synchronisation TCP sur l'IP privée:22000; découverte, relais
publics et NAT automatique désactivés. Aucun mot de passe/API n'est distribué.

Le template systemd est une entrée pour le mécanisme natif, pas un installateur
à lancer en production. Avant activation : fabrication/signature CP, installation
immuable et preuve de retour arrière du binaire, compte dédié, garde des volumes,
intégration du connecteur natif et de son autorité. La clé API locale générée reste
privée; aucun transport générique ne doit publier l'interface administrative.
Le broker local de projection/enrôlement est implémenté et dispose de22contrôles acquis sur le vrai moteur. Les contrôles du worker avec MariaDB et ClamAV restent distincts des réceptions de production.
Le moteur ne reçoit jamais les répertoires GED immuables ni un partage UNAS.

Le filtrage serveur doit limiter TCP22000 à l'adresse source du proxy propre à
l'instance, avec règle additive et conservation du pare-feu existant. Ne pas
installer un drop global sur les autres ports. Aucun UDP ni PROXY protocol.
L'observation de source via un stream TCP ne qualifie pas TLS Syncthing ni Internet.

La sélection « Garder hors ligne », l'enrôlement authentifié à jeton unique,
les projections par utilisateur/appareil et le retour VersionAdmission ne sont
pas remplacés par une configuration manuelle du moteur. Ils sont implémentés et qualifiés sur banc isolé ; la réception de leur parcours
GED en production reste nécessaire avant une distribution employé générale.
Le ZIP employé0.3.1-candidate.1 reste en qualification.
Une révocation bloque l'avenir sans effacer les copies déjà reçues.

## Livraison native des services

`cp_runtime_publish.py` utilise l'identité de service du Control Plane, son
contrôle releases, son signataire Ed25519 et son audit. Le CP construit l'archive
reproductible depuis les entrées reçues ; la publication est privée et liée à
une installation. La finalité `organisation-document-runtime-v1` est distincte
des paquets employés. `native_install.py` vérifie cette signature avec la clé du
superviseur natif et refuse les instances, séquences, binaires ou inventaires
inattendus. Le code installé vient de cette archive ; aucun secret n'y figure.

Une identité serveur est générée une seule fois dans son compte système privé.
Le socket systemd appartient au seul UID Core ; le broker ne rejoint pas le
groupe du coffre. Le pare-feu ne gère que sa propre table et n'accepte le port
TCP 22000 qu'à travers le proxy propre à l'instance. L'administration reste
127.0.0.1:8384. Une première livraison démarre moteur/broker et laisse le worker
arrêté. Son activation requiert ensuite une livraison signée explicite et le
Core/module Documents natifs reçus. Les reçus d'installation, les écoutes et les
essais de réseau sont distincts de la validation des sources.

Le worker entre dans ModuleMaintenance avant toute composition SQL. L'Agent
1.24 draine ce worker avant mise à jour/restauration, garde son intention de
reprise et ne rejoue pas un traitement oneshot déjà terminé. Le retrait Documents
arrête également le transport ; une condition systemd vérifie la présence du
module au démarrage. Les fichiers, identités et conflits sont conservés.

Les mises à jour du paquet de service vers un inventaire différent sont refusées
si elles demanderaient d'écraser une configuration ou une unité existante : leur
migration doit être reçue explicitement. Le rejeu du même paquet et l'activation
ultérieure de son worker ne régénèrent pas l'identité.

Native service configuration resides in `/etc/organisationos-syncthing`.
It must not inherit traversal restrictions of the historical Core vault root
`/etc/organisation`. Release 0.1.1 moves only this service descriptor and its
unit references; it never broadens Core group membership or vault permissions.
The migration accepts only the exact initial signed 0.1.0 release, with its
worker disabled and no employee devices/folders. It verifies and archives exact
previous units, retains engine identity/state and existing firewall rules, then
starts the replacement native units. Replays retain the installed identity.

## Installation reçue au21octobre2026

Le composant0.1.2 et le moteurv2.1.6-oos.2 sont installés sur TheCGP10.9.5.18 et Ville10.100.8.50 ; les workers sont activés par séquence4 signée. TCP22000 écoute sur l’IP privée de chaque instance, limité respectivement aux proxies10.9.5.74 et10.100.8.13. GUI/API moteur sur127.0.0.1:8384 uniquement. Les adresses publiques sont `tcp://syncthing.thecgp.com:22000` et `tcp://syncthing.villesadp.ca:22000`, sans terminaison TLS dans NGINX.

Les identités serveur, sources de proxy et TLS réels ont leurs reçus ; un test depuis DEV ne constitue pas une réception depuis un réseau extérieur employé. Aucun montage UNAS ni accès global au stockage GED n’est accordé au moteur. Les nouvelles installations Windows, projections et retours GED de production sont réservés à une réception séparée.
