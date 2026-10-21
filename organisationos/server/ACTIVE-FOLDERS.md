# Sélections de dossiers actives — 2026-10-21

Le moteur Syncthing commun reste v2.1.6-oos.2 (e80f807467f5e127f35e2de45cfd22d4091bcd42). L’intégration serveur, les droits GED et le paquet Windows 0.3.4 sont des composants distincts. Cette réception serveur ne constitue pas une réception Windows ou extérieure des dossiers.

Le Portal propose une estimation avant confirmation, puis conserve une sélection par dossier et appareil. Le worker réévalue les descendants et les droits individuels à chaque passage. Le nom visible et l’UUID canonique forment un chemin déterministe ; le mapping JSON fait autorité, sans élargissement de l’index SQL existant. Les raccourcis qui répètent le même document sont signalés comme exclus.

La politique Syncthing ferme par défaut le partage : seuls les chemins autorisés et leurs conflits sont exposés. Une diminution des droits suspend le dossier avant remplacement de cette politique. Les nouvelles entrées sont publiées après préparation et une seconde vérification des droits. Arrêter la sélection détache le partage sans effacer les copies, les modifications non transmises ou les conflits. La révocation ne prétend jamais rappeler une copie déjà reçue.

Les originaux historiques restent en lecture. Une modification locale est conservée en conflit, jamais écrite dans l’original. Les autres retours utilisent l’admission GED existante avec base de version, antivirus et idempotence. Un fichier renommé ou non mappé n’est pas admis par inférence de son nom. Une nouvelle version canonique sur une projection existante exige un rapprochement ; elle n’écrase pas automatiquement les modifications locales.

Bornes explicites : 8 192 entrées, profondeur 64, fichier 64 Mio, chemin 600 octets ; préparation et retours limités à 16 fichiers / 128 Mio par passage. Toute limite ou exclusion empêche « À jour ». Le transport à 100 % ne suffit pas : l’index doit couvrir les fichiers attendus, et il ne doit rester aucun retour, conflit, erreur ou exclusion. Un reçu périmé est présenté comme à vérifier.

Qualifications autonomes : MariaDB et worker réel sur données synthétiques ; deux moteurs fork réels avec allowlist, arrivée d’un sous-dossier, révocation individuelle et préservation des copies ; Portal estimations, exclusions, arrêt et péremption. Les tests de reprise d’installation utilisent des fautes injectées et un systemd simulé : ils ne sont pas une réception de déploiement réel.

Le successeur natif du runtime conserve certificats, clés et appareils. La migration qualifiée ici refuse tout partage serveur déjà présent ; cette limite est vérifiée avant mutation et sous verrou. Un runtime déjà peuplé exige une qualification de migration supplémentaire. Les anciennes unités et le descripteur sont restaurés en cas d’échec de remplacement ou de démarrage. La minuterie retrouve son état antérieur.

Livraison : sources DEV, archive construite/signée par Control Plane, adoption native ; aucun correctif direct de fichiers servis. Les versions et reçus d’installation réels doivent être enregistrés séparément après adoption.
