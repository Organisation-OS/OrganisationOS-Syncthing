# Composant serveur préparé, non installé

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
Le broker local de projection/enrôlement reste à implémenter et qualifier.
Le moteur ne reçoit jamais les répertoires GED immuables ni un partage UNAS.

Le filtrage serveur doit limiter TCP22000 à l'adresse source du proxy propre à
l'instance, avec règle additive et conservation du pare-feu existant. Ne pas
installer un drop global sur les autres ports. Aucun UDP ni PROXY protocol.
L'observation de source via un stream TCP ne qualifie pas TLS Syncthing ni Internet.

La sélection « Garder hors ligne », l'enrôlement authentifié à jeton unique,
les projections par utilisateur/appareil et le retour VersionAdmission ne sont
pas remplacés par une configuration manuelle du moteur. Ils demeurent nécessaires
avant une distribution employé générale; le ZIP actuel est de qualification.
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
