# Installateur employé OrganisationOS — candidat 0.3.1

Ce programme Go est l'installateur et l'accompagnateur du moteur, pas un nouveau
moteur Syncthing. Il embarque exactement le Windows amd64 v2.1.6-oos.2 reçu,
SHA256 14421c4afbe5b48ddd9065410310f6fd667d678ae5943bd9520f28f261d8eb4b,
compilé depuis e80f807467f5e127f35e2de45cfd22d4091bcd42. Le moteur est commun,
`organisation.json` porte l'instance, le portail, l'adresse publique et l'identité
serveur réellement reçue. Aucune valeur de serveur ne doit être inventée.

Après extraction du paquet privé, ouvrir OrganisationOS-Syncthing-Installer.exe.
Installation par utilisateur dans LOCALAPPDATA/OrganisationOS/Syncthing ; état,
identité et fichiers séparés par UUID d'organisation. Aucun ancien dossier de
qualification, installation Syncthing extérieure ou RustDesk n'est repris.
Le raccourci du menu Démarrer ouvre la connexion ; HKCU Run assure le lancement
à la prochaine ouverture de session. Aucun service système Windows, règle de
pare-feu entrante ni redémarrage n'est demandé.

Le navigateur ouvre la bonne organisation. L'utilisateur s'authentifie selon le
parcours natif et autorise le poste, puis revient à l'application par son bouton.
Les sélections « Garder hors ligne » deviennent des dossiers locaux automatiquement.
L'écoute de synchronisation et l'administration Windows restent sur la boucle
locale, avec un port attribué à cette installation ; la connexion vers le serveur
est sortante. Aucun identifiant, adresse ou clé API à saisir manuellement.

Les mises à jour ne suppriment ni Etat, ni Fichiers, ni les anciennes releases.
Une configuration divergente ou un état incomplet est refusé sans régénérer une
identité. L'enrôlement réutilise une identité déjà active, et les codes consommés
ne sont pas réutilisables. La révocation conserve explicitement les copies.

Construction : utiliser l'image Go déjà épinglée
sha256:f4723252fe7167ef67cb0bd6a952dce9c78153b3a1d4ae87f523c01f4dd9d0b1,
CGO_ENABLED=0 ; copier le moteur reçu dans assets/engine.bin (ignoré par Git).
`go test ./...`, puis `GOOS=windows GOARCH=amd64 go build -trimpath
-buildvcs=false -ldflags='-s -w -H windowsgui -buildid=' -o Installer.exe .`.
Aucune dépendance Go externe supplémentaire. Les deux compilations comparées
partagent ici le cache ; ce contrôle ne prétend pas être deux builds indépendants.

La signature Authenticode est absente. Le manifeste du catalogue est signé
séparément par le Control Plane. Le paquet doit rester dans l'audience de
qualification jusqu'à réception du profil Windows propre : installation,
protocole local, authentification, autostart, réinstallation et reprise réelle.
Les tests Linux du protocole et la génération d'un PE AMD64 ne remplacent pas
cette réception. Aucun essai sur le poste utilisateur n'a été lancé cette nuit.

La configuration schema2 distingue portalOrigin (connexion navigateur) et apiOrigin
(requêtes signées). Ville utilise son domaine API natif distinct. Une réinstallation
peut compléter la seule origine API d’un ancien profil schema1 dont tous les autres
champs correspondent exactement; identité, enrôlement et fichiers restent intacts.
