# Réception interne Windows du 21 octobre 2026

Le poste Windows x64 autorisé a installé le ZIP portable depuis le catalogue TheCGP authentifié. L'utilisateur a exécuté localement les étapes ; aucune session de prise de contrôle distante n'a été établie. Les données sont exclusivement synthétiques dans le dossier de qualification sous LOCALAPPDATA. Aucun service, démarrage automatique, redémarrage du poste ou changement RustDesk.

## Provenance réellement exercée

- Amont Syncthing v2.1.6, commit `4461a1ce354d3990660966ad70176e00246adb61`.
- Moteur OrganisationOS v2.1.6-oos.1, source `3224efdefffef2d57ccaced4e398f49f79e08dc8`.
- Windows amd64 SHA-256 `2a07186aab4f0e2b331760a6c4f7d743410548c58b6693e1cd7cb580d084a2d5`, confirmé sur le poste. Exécutable non signé Authenticode ; manifeste du paquet signé séparément par OrganisationOS.
- Linux amd64 SHA-256 `de5ef047806755c5f525eb940537ef469f309cc11b08c93f34748712939888c7`.
- Installateur initial au commit `355147fa1ae3b6c80b20aac32e9739209934ea7b`. ZIP SHA-256 `79dd4c08d84a5036981a155013d3446595f83d871e927a6bcb242b31dcb2a41c`.

Une instrumentation temporaire du seul moteur DEV a confirmé l'annonce incomplète, source `d41008130718b66b156b22af9e25051c190278cd`. Elle a été retirée avant les essais de reprise, conflit et révocation ; le moteur Linux original a repris le même état et certificat. Le binaire Windows n'a jamais été remplacé pendant cette réception. Le garde-fou de sources `caea980890e85095923ba0ec3880ee496839d93c` vise la prochaine version oos.2 ; ces essais ne prouvent pas sa construction binaire.

## Résultats

Installation et identité unique reçues. Appairage TLS reçu après réparation du champ de chiffrement erroné sur l'entrée locale, sans régénération d'identité. Aller-retour reçu avec contenu DEV et empreinte Windows vérifiés sur les deux côtés.

Le client Windows a été arrêté par son API locale ; un fichier a été modifié pendant l'arrêt. DEV est resté déconnecté et a conservé l'ancienne empreinte. Après relance du même client, la nouvelle empreinte est arrivée sur DEV et le témoin créé sur DEV pendant l'arrêt est arrivé sur Windows.

Après synchronisation complète, suspension temporaire du pair côté DEV, deux modifications concurrentes du même fichier ont été créées. La reprise a conservé le contenu Windows dans le fichier principal et le contenu DEV dans un fichier sync-conflict. Les deux empreintes ont été vérifiées sur les deux appareils.

Le pair a ensuite été retiré de la configuration DEV et du dossier. Les connexions suivantes ont réellement été rejetées pour appareil inconnu. Deux nouveaux témoins, créés après retrait de part et d'autre, sont restés absents de leur destinataire. Aucun effacement des copies locales n'est revendiqué.

Le banc temporaire a été fermé après réception : service arrêté, écoute réseau et API fermées, seule règle réseau dédiée retirée. Le nettoyage a été rejoué avec succès ; identités, fichiers et preuves restent conservés. Les reçus détaillés contenant la topologie privée restent sur l'orchestrateur.

## Limites

Cette réception qualifie le moteur portable sur le réseau interne. Elle ne qualifie pas l'accès extérieur, le futur serveur d'instance, l'association personnelle dans le portail, les projections autorisées ni le retour contrôlé vers la GED. Les 28 contrôles Linux antérieurs demeurent des preuves distinctes. Les futurs essais de l'intégration doivent couvrir droits retirés, antivirus, rejeu, suppression locale sans purge canonique et conflit avec une modification Office.
