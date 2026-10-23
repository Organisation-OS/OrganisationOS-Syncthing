# Installateur employé OrganisationOS — candidat 0.3.3

Évolution additive courante : **0.3.5-dev.1**, basée sur **0.3.4-candidate.1**.
Lire [DEV-ADMISSION.md](DEV-ADMISSION.md) pour l'admission CP DEV séparée et ses
limites. Les paragraphes ci-dessous conservent le parcours legacy reçu.

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
séparément par le Control Plane. Ville est disponible à tous ses usagers authentifiés sur autorisation explicite
du 21 octobre ; TheCGP conserve son audience de qualification. Restent à recevoir : installation,
protocole local, authentification, autostart, réinstallation et reprise réelle.
Les tests Linux du protocole et la génération d'un PE AMD64 ne remplacent pas
cette réception. Aucun essai sur le poste utilisateur n'a été lancé cette nuit.

La configuration schema2 distingue portalOrigin (connexion navigateur) et apiOrigin
(requêtes signées). Ville utilise son domaine API natif distinct. Une réinstallation
peut compléter la seule origine API d’un ancien profil schema1 dont tous les autres
champs correspondent exactement; identité, enrôlement et fichiers restent intacts.

## Diagnostic de la réception Windows du 21 octobre

La 0.3.1 affichait une erreur générique sans conserver son étape ni le statut HTTP.
La 0.3.2 journalise exclusivement des références aléatoires, codes fermés, version,
heure UTC et statuts HTTP dans `%LOCALAPPDATA%\OrganisationOS\Syncthing\diagnostic.json`.
Aucune URI, ligne de commande, identité personnelle, valeur d’erreur brute, code,
verifier, certificat ou jeton n’est journalisé. `--diagnose` vérifie en lecture seule
le certificat local et le refus HTTP401 attendu de l’API sans authentification.
Cette commande ne consomme aucun code, ne change aucune configuration et n’enrôle pas.

La reprise se fait par le raccourci Syncthing existant du menu Démarrer, avec le même
certificat. Le serveur réutilise son enregistrement pour la même identité et le même
utilisateur, sans copie des sessions de qualification. L’installation conserve les
anciennes releases, les fichiers, la configuration et les conflits.

La collecte réelle Windows établit que le retour a le chemin `/`, refusé par la 0.3.2 qui exigeait un chemin vide. La 0.3.3 accepte exclusivement les deux formes vide et `/` non encodé. Les autres chemins, fragments, autorités, échappements invalides et paramètres inconnus ou dupliqués sont refusés avant tout échange. Les vérifications de demande, identité, preuve et portée restent obligatoires. Une demande expirée se reprend avec le même certificat depuis l’application, sans suppression locale. La réception réelle Windows du correctif reste à effectuer.

Le mode `--diagnose` écrit exclusivement `diagnostic-readonly.json`, avec sa propre référence et heure UTC. Un échec d’écriture est annoncé explicitement : aucun ancien reçu ne vaut preuve du nouveau lancement. Les erreurs de connexion gardent `diagnostic.json`.


## Administration locale — candidat 0.3.4

La GUI reste sur 127.0.0.1. Une identité de connexion locale et un mot de passe aléatoire de 256 bits sont créés automatiquement avant le premier lancement ; seul le hachage bcrypt natif est conservé. Le secret passe à `generate --gui-password -` par stdin, jamais par argv. Le helper utilise la clé API propre au profil. Le portail demeure le parcours employé ; aucun secret commun, dialogue technique ou saisie de mot de passe GUI. Une installation existante est protégée via PATCH natif config/gui, avec contrôle préalable de son identité et relecture. Aucun remplacement de config.xml pendant que le moteur tourne. Les identités, dossiers, conflits, clé API et enrôlement sont conservés. Un enrôlement terminé est repris après preuve signée auprès de l’instance, sans nouveau code ni appareil. Si l’ancien helper tourne déjà, il termine sa session avec sa version ; le registre de démarrage vise le nouveau helper pour la prochaine ouverture de session. La protection GUI est appliquée immédiatement par l’installateur. Les comptes locaux capables de lire les fichiers privés du profil restent dans le périmètre de confiance de ce profil. La réception Windows de cette version reste requise.
