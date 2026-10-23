# Helper 0.3.6-dev.1 — candidat issu de 0.3.4-candidate.1

Base exacte : `d670136e2aa8d617c540baec3c8a6a2920ff84de`. Le moteur reste
`v2.1.6-oos.2`, source `e80f807467f5e127f35e2de45cfd22d4091bcd42`, Windows SHA-256
`14421c4afbe5b48ddd9065410310f6fd667d678ae5943bd9520f28f261d8eb4b`.

Cette version ajoute un chemin DEV distinct. `validate()` et `package.py` des deux
instances existantes sont inchangés ; elles ne peuvent jamais entrer dans ce
chemin. Aucun endpoint existant n'est appelé par la qualification synthétique.
Les tests réutilisent les mécanismes natifs de callback, preuves d'appareil et
protection de la GUI. Le mécanisme de notification est substitué uniquement dans
le binaire de tests, afin d'éviter une boîte modale Windows pendant leur exécution.

Le test du moteur réel a révélé qu'arrêter uniquement le processus moniteur
Syncthing sous Windows pouvait laisser son moteur enfant actif. Le helper utilise
désormais le mode natif `STMONITORED=yes` (inner process) du fork épinglé : il
supervise directement le moteur et son arrêt atteint le bon processus. Aucun
contrôle TLS, GUI, identité ou permission n'est désactivé. Le nettoyage du profil
temporaire fait partie de la qualification de cet arrêt.

## Circuit de confiance et fabrication

Le dépôt contient un `dev-trust.json` **désactivé**. L'entrée publique réelle est
fournie séparément par le circuit natif du CP, jamais extraite d'un ZIP reçu ni
acceptée comme argument d'installation. Le fabricant CP l'incorpore à son export
isolé. Elle lie clé publique Ed25519 brute base64, installationId, instanceId,
apiOrigin HTTPS, applicationId, minimumSequence et dates UTC. L'audience est `dev`,
la durée maximale 24 heures. Pour le banc du 23 octobre, expiresAt doit être au plus
la réserve r2 `2026-10-23T22:42:00Z`, sans renouvellement. Installation et instance
ne sont pas supposées identiques. Les identités des deux instances legacy sont
refusées dans cette entrée, même avec une signature valide.

Après réception des sources et des preuves par le relais :

```text
python build_dev.py --trust <ancrage-public-admis.json> --engine <moteur-qualifié.exe> --output <nouveau-dossier> --go <go>
python package_dev.py --build-dir <dossier> --config <schema2-admis.json> --legal-bundle <ZIP-natif-sources-notices> --legal-sha256 <empreinte-qualifiée> --output <nouveau-ZIP-DEV>
```

`build_dev.py` exige des sources committées, exporte la révision exacte, vérifie le
moteur, exécute les tests avec l'ancrage public incorporé, construit le PE et garde
les empreintes des entrées, du source et du résultat. `package_dev.py` conserve
les notices et sources du moteur issues du bundle natif qualifié et produit la
provenance. Il ne signe rien : le circuit CP existant signe ensuite l'enveloppe
`organisation-employee-software-v1`, liée au ZIP final et à la provenance fournie.
`package.provenance.admissionAudience=dev` et `installerVersion=0.3.6-dev.1` sont
obligatoires. Les séquences natives et l'audience de publication CP restent sous
son autorité. Aucune nouvelle clé de signature ni nouvelle offre de production.

L'enveloppe est **externe au ZIP** : l'inclure créerait une dépendance récursive
entre signature et empreinte. Aucun jeton, certificat privé d'appareil, secret
serveur ou clé privée CP n'est inclus. Authenticode reste un contrôle distinct,
absent du candidat actuel.

## Installation et lancement

```text
OrganisationOS-Syncthing-Installer.exe install-dev <ZIP-exact> <enveloppe-CP-externe>
```

Le helper lit les entrées avec des limites de taille, vérifie l'enveloppe Ed25519
et ses identités, la période, la séquence, l'audience, les octets du ZIP, ceux de
son propre exécutable et le moteur. La configuration schema2 signée doit être
identique à celle du ZIP. Aucun chemin du ZIP n'est extrait ; seuls les contenus
attendus sont lus. Noms dupliqués, traversées et entrées symboliques sont refusés.
Ces vérifications précèdent toute écriture dans le profil et tout démarrage.

Le plafond cohérent fabricant/vérificateur est **256 entrées**. Le bundle légal
natif vérifié `3823696afb72c9e2b0c00a44614f72678545da1df7b423b7f193d2030af5b814`
contient 137 fichiers, soit 143 après ajout du helper, de sa configuration et de sa
provenance. Aucun fichier légal n'est supprimé pour satisfaire un plafond. Les
tests couvrent ce bundle exact, 256 accepté et 257 refusé, doublons/traversées/liens
toujours refusés. `OOS_TEST_LEGAL_BUNDLE` indique sa copie protégée au lanceur.

La suite d'installation réutilise le chemin natif : identité unique, moteur par
instance, GUI locale protégée, protocole Windows, autostart utilisateur, preuve
native et navigateur. Une configuration existante différente est conservée et
refusée. Le chemin sans argument reste réservé aux paquets legacy : une config DEV
non signée ne peut pas l'utiliser. L'installation réelle n'est pas un test unitaire.

Les reçus `AdmissionDEV/<sequence>-<envelopeSHA>.json` sont exclusifs, synchronisés
et conservés, maximum 64. Un mutex Windows sérialise les installations DEV du
profil/instance. Le lancement relit et vérifie l'historique signé ainsi que la
configuration. Régression, même séquence avec contenu divergent, corruption,
absence après installation ou expiration ferment l'accès. Le moteur lancé par
ce helper est arrêté à l'expiration de l'admission, même pendant une requête.

Ce stockage utilisateur ne résiste **pas** à la restauration/suppression de son
profil par son propriétaire. Plancher incorporé et expiration restent obligatoires.
Le candidat fixe aussi la version et les octets du helper dans tous les reçus :
une migration ultérieure de helper DEV exige un contrat de migration explicite,
elle ne supprime pas silencieusement les anciens reçus pour repartir à zéro.
Les droits GED, affectations, autorisations et révocations restent ceux du Core.

## Qualification reproductible

Go 1.27.3, `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0` ; moteur qualifié
dans `assets/engine.bin` (ignoré de Git). `go test -count=1 -timeout 120s ./...` et
`python -m unittest -v factory_dev_test.py`. Le test natif GUI est opt-in via
`OOS_TEST_ENGINE=<moteur.exe>` : profil temporaire, génération réelle, API uniquement
loopback et arrêt du processus en fin de test. Il ne fait aucun enrôlement.
Le test de lien symbolique peut être SKIP si Windows refuse sa création ; le
contrôle de reparse reste actif. Les résultats exacts sont livrés avec le candidat.

Il reste à recevoir après fabrication CP : vérification du manifeste final,
installation dans un contexte Windows admis, transport Syncthing du banc
accessible depuis Windows et allocation de son broker/worker, enrôlement, transfert,
refus et révocation réels. Les ports serveur loopback 28384/22223 ne constituent pas
un endpoint de synchronisation accessible. Aucun compte ou service CRM/ERP réutilisé.
L'installation MSI précédemment refusée par l'approbation automatique demeure
exclue : ce candidat n'est pas un moyen de contourner ce refus.

## Navigateur du Compagnon — protocole opt-in 0.3.6

`install-dev-client <ZIP> <enveloppe>` exécute la même admission/installation
native que `install-dev`. `connect-client <instanceId>` prépare le PKCE natif
ou reprend un enrôlement seulement après sa preuve d'appareil courante.
`callback-client <instanceId>` lit l'URI de retour sur stdin (4096 octets maximum)
et limite la recherche de pending à cette instance. Le code de retour n'est
jamais un argument de processus. Le mécanisme natif vérifie état, délai,
identité, code, PKCE, configuration et preuve serveur sans variante de test.

Ces commandes n'ouvrent ni navigateur par défaut ni boîte de notification.
Stdout contient un seul objet JSON `oos-syncthing-client-result-v1`, avec
helperVersion et status. Succès : `PORTAL_NAVIGATION_REQUIRED` et portalUri,
HTTPS vers le Portal de la configuration native, chemin `/documents/offline`
ou `/documents/offline/enroll`. Échec : `FAILED`, stage, code, reference publics.
Le code de sortie vaut0 au succès,1 au refus. L'URL contient éventuellement le
state/challenge publics : flux IPC transitoire, ne pas le journaliser. Aucun
verifier, code de retour, jeton, clé ou session n'est écrit dans cette réponse.

Le parent doit vérifier version/hash du helper, schéma fermé et origine/chemin
de l'URL contre son instance courante avant affichage dans son profil privé.
Il intercepte le protocole callback sans le transmettre au navigateur personnel.
La session utilisateur et toute approbation restent natives Core/Portal ; le
résultat de lancement n'est pas une preuve d'enrôlement ni de transfert.
Les commandes historiques et validate()/package.py legacy restent inchangés.
