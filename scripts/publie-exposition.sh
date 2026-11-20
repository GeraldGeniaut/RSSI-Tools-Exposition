#!/bin/sh
# =============================================================================
#  publie-exposition.sh — MÉTHODE « POUSSER » (exécuté sur le serveur de collecte)
#
#  Copie le rapport généré par le compte « exposition » vers un serveur web annexe,
#  en réutilisant une liaison SSH existante de root (ou d'un compte d'administration).
#  Le compte « exposition » n'a jamais accès à cette clé.
#
#  Appelé après chaque relevé par :  ExecStartPost=+/usr/local/sbin/publie-exposition.sh
#  Installation : install -o root -g root -m 750 publie-exposition.sh /usr/local/sbin/
#  Voir docs/06-publication-web.md
# =============================================================================
SRC=/var/lib/exposition/www
DST="compte_depot@web.example.internal:/var/www/site/rssi/"     # <-- à adapter
KEY=""                                                         # <-- clé dédiée (optionnel)

OPTS="-q -o BatchMode=yes -o ConnectTimeout=10"
[ -n "$KEY" ] && OPTS="$OPTS -i $KEY"

# shellcheck disable=SC2086
if scp $OPTS "$SRC/exposition.html" "$SRC/exposition.json" "$DST"; then
    logger -t publie-exposition "rapport copié vers $DST"
else
    logger -t publie-exposition "échec de la copie vers $DST"
    exit 1
fi
