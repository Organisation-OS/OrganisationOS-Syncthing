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
