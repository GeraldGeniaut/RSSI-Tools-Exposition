# 6. Publication sur un serveur web annexe

Objectif : consulter le rapport HTML depuis un navigateur (équipe sécurité, astreinte), sans dépendre d'un poste.

**Le rapport est sensible** (comptes compromis, ports, vulnérabilités) : HTTPS obligatoire, authentification,
accès restreint au réseau d'administration si possible.

## Choisir la méthode de transfert

| Méthode | Principe | Sécurité | Quand |
|---|---|---|---|
| **A. Tirer** (recommandée) | le serveur web vient lire le rapport sur le serveur de collecte | le serveur de collecte n'a **aucun droit d'écriture** sur le serveur web | cas général |
| **B. Pousser via une liaison existante** | root sur le serveur de collecte copie vers le serveur web avec une clé déjà en place | le compte de service n'a pas accès à la clé ; mais la liaison existante peut donner plus de droits que nécessaire | une liaison SSH existe déjà dans ce sens |
| C. `scp_target` du script | le compte de service copie lui-même | le compte qui traite des données d'Internet détient une clé vers le serveur web | à éviter, ou avec un compte de dépôt très restreint |

Dans tous les cas : **ne jamais donner au compte `exposition` une clé qui ouvre un compte d'administration**.

---

## A. Tirer depuis le serveur web (recommandée)

### Sur le serveur web : une clé dédiée
```bash
ssh-keygen -t ed25519 -N '' -C "serveur-web: recuperation exposition" -f /root/.ssh/id_exposition
cat /root/.ssh/id_exposition.pub
```
Clé dédiée, sans phrase de passe (lancée par cron), révocable seule.

### Sur le serveur de collecte : un compte en lecture seule
```bash
useradd -m -s /bin/sh expo-lecture
install -d -o expo-lecture -g expo-lecture -m 700 /home/expo-lecture/.ssh
echo 'from="IP_DU_SERVEUR_WEB",restrict ssh-ed25519 AAAA… serveur-web: recuperation exposition' \
  > /home/expo-lecture/.ssh/authorized_keys
chown expo-lecture:expo-lecture /home/expo-lecture/.ssh/authorized_keys
chmod 600 /home/expo-lecture/.ssh/authorized_keys
```
- Pas de mot de passe : seule la clé ouvre ce compte.
- `from="…"` : la clé n'est acceptée que depuis le serveur web.
- `restrict` : pas de terminal, pas de redirection de ports, pas d'agent ; juste la copie de fichiers.
- Le rapport est en `644` : ce compte le lit sans aucun droit d'écriture.

### Sur le serveur web : le script et la planification
```bash
install -o root -g root -m 750 scripts/recupere-exposition.sh /usr/local/sbin/
nano /usr/local/sbin/recupere-exposition.sh            # SRC et DST
ssh -i /root/.ssh/id_exposition expo-lecture@collecte.example.internal true   # accepte la clé d'hôte
/usr/local/sbin/recupere-exposition.sh && journalctl -t recupere-exposition -n 2 --no-pager
echo '30 1,7,13,19 * * * root /usr/local/sbin/recupere-exposition.sh' > /etc/cron.d/recupere-exposition
```
Le script télécharge dans un dossier temporaire puis installe (jamais de page tronquée), fichiers en
`640 root:www-data` (lisibles par le serveur web seulement).

---

## B. Pousser via une liaison existante

Si root sur le serveur de collecte se connecte déjà au serveur web (clé existante) :
```bash
install -o root -g root -m 750 scripts/publie-exposition.sh /usr/local/sbin/
nano /usr/local/sbin/publie-exposition.sh              # DST
/usr/local/sbin/publie-exposition.sh && journalctl -t publie-exposition -n 1 --no-pager
```
Puis décommentez dans `exposition.service` **et** `exposition-resume.service` :
```ini
ExecStartPost=+/usr/local/sbin/publie-exposition.sh
```
et `systemctl daemon-reload`. Le préfixe **`+`** exécute cette seule commande avec les droits root : le relevé reste
sans privilège, seule la copie utilise la clé de root.

Sur le serveur web, le dossier de destination doit être modifiable par le compte de dépôt et lisible par le
serveur web :
```bash
chown compte_depot:www-data /var/www/site/rssi
chmod 2750 /var/www/site/rssi       # setgid : les fichiers déposés héritent du groupe www-data
```

---

## Protéger le dossier (Apache)

Préférez la configuration du **VirtualHost HTTPS** à un `.htaccess` : un `.htaccess` est ignoré sans
`AllowOverride` (le dossier resterait ouvert sans message d'erreur) et peut être modifié par quiconque dépose
un fichier.

```bash
htpasswd -c -B /etc/apache2/.htpasswd-rssi admin      # -B = bcrypt ; -c seulement la 1re fois
chown root:www-data /etc/apache2/.htpasswd-rssi
chmod 640 /etc/apache2/.htpasswd-rssi
cp /etc/apache2/sites-enabled/VOTRE-SITE.conf /root/VOTRE-SITE.conf.bak
nano /etc/apache2/sites-enabled/VOTRE-SITE.conf       # coller scripts/apache-espace-rssi.conf dans <VirtualHost *:443>
apache2ctl configtest && systemctl reload apache2
```
- Fichier de mots de passe **hors du site web**.
- Le bloc interdit le listage **et toute exécution de code** dans ce dossier (CGI, Python, PHP, y compris
  PHP-FPM) : un dépôt malveillant n'y serait jamais exécuté.
- `configtest &&` : Apache n'est rechargé que si la syntaxe est correcte.

Vérification :
```bash
curl -sk -o /dev/null -w 'sans mot de passe : %{http_code}\n' https://web.example.internal/rssi/
curl -sk -o /dev/null -w 'avec mot de passe : %{http_code}\n' -u admin https://web.example.internal/rssi/exposition.html
```
Attendu : `401`, puis `200`.

Si le site n'est qu'en HTTP : passez-le en HTTPS avant de publier (l'authentification Basic transmet le mot de
passe simplement encodé).

## Nginx (équivalent)

```nginx
location /rssi/ {
    auth_basic           "Espace RSSI - acces restreint";
    auth_basic_user_file /etc/nginx/.htpasswd-rssi;
    autoindex off;
    location ~ \.(php[0-9]?|phtml|phar|py|pl|cgi|sh)$ { deny all; }
}
```
