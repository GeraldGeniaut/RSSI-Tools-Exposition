#!/bin/bash
# =============================================================================
#  recupere-exposition.sh — MÉTHODE « TIRER » (exécuté sur le serveur web annexe)
#
#  Le serveur web vient chercher le rapport sur le serveur de collecte, avec un
#  compte en LECTURE SEULE. Le serveur de collecte n'a alors aucun droit d'écriture
#  sur le serveur web (méthode la plus sûre).
#
#  Planification (cron root), par exemple 20 min après chaque relevé :
#    30 1,7,13,19 * * * /usr/local/sbin/recupere-exposition.sh
#  Voir docs/06-publication-web.md
# =============================================================================
SRC="expo-lecture@collecte.example.internal:/var/lib/exposition/www"   # <-- à adapter
DST="/var/www/site/rssi"                                               # <-- à adapter
KEY="/root/.ssh/id_exposition"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Téléchargement dans un dossier temporaire : jamais de page tronquée publiée
if scp -q -i "$KEY" -o BatchMode=yes -o ConnectTimeout=10 \
       "$SRC/exposition.html" "$SRC/exposition.json" "$TMP/"; then
    install -o root -g www-data -m 640 "$TMP/exposition.html" "$TMP/exposition.json" "$DST/"
    logger -t recupere-exposition "rapport mis à jour"
else
    logger -t recupere-exposition "échec de récupération depuis le serveur de collecte"
    exit 1
fi
