# 3. Installation du serveur de collecte

**Prérequis** : une VM Linux (Debian/Ubuntu testés), Python 3.8 ou plus, accès sortant HTTPS vers Internet,
accès à votre relais SMTP interne. Toutes les commandes sont lancées **en root**.

Dans ce document : `collecte.example.internal` = le serveur de collecte, `votre_compte` = votre compte
d'administration personnel.

---

## 3.1 Vérifier Python

```bash
python3 --version
```
Minimum : 3.8 (le script utilise uniquement la bibliothèque standard).

## 3.2 Compte de service

```bash
useradd --system --home-dir /var/lib/exposition --shell /usr/sbin/nologin exposition
id exposition
```
- **Pourquoi un compte dédié ?** Le script traite des données venues d'Internet. S'il était compromis, l'attaquant
  n'aurait que les droits de ce compte, pas ceux de root.
- `--system` : compte système, sans mot de passe ; `nologin` : aucune connexion interactive possible.

## 3.3 Dossiers

```bash
install -d -o exposition -g exposition -m 755 /var/lib/exposition
install -d -o exposition -g exposition -m 755 /var/lib/exposition/www
install -d -o root -g exposition -m 750 /etc/exposition
```

| Dossier | Contenu | Droits | Raison |
|---|---|---|---|
| `/var/lib/exposition` | état interne | `755` | traversable pour atteindre `www` ; l'état lui-même est en `640` |
| `/var/lib/exposition/www` | rapport publié | `755` | lisible par les postes (scp) et un éventuel serveur web |
| `/etc/exposition` | configuration | `750 root:exposition` | le service lit, seul root modifie |

## 3.4 Script et configuration

```bash
install -o root -g root -m 755 src/exposition.py /usr/local/bin/exposition.py
install -o root -g exposition -m 640 config/exposition-serveur.ini.example /etc/exposition/exposition.ini
nano /etc/exposition/exposition.ini
```
Le script appartient à root : le compte de service ne peut pas modifier son propre programme.
La configuration contiendra éventuellement la clé HIBP : elle n'est lisible que par root et le service.

À renseigner au minimum (voir [04-configuration.md](04-configuration.md)) :
- `[general] domain` ;
- `[ransomwarelive] keywords` ;
- `[certfr] keywords` (votre parc) ;
- `[shodan] ips` (vos plages publiques) ;
- `[server] mail_to`, `mail_from`, `smtp_host`.

Laissez `scp_target` **vide** pour l'instant.

## 3.5 Premier relevé (référence)

```bash
sudo -u exposition /usr/local/bin/exposition.py collect --publish
ls -l /var/lib/exposition /var/lib/exposition/www
```
- `sudo -u exposition` : exécution avec le compte de service, comme le fera la planification (valide les droits).
- Durée : de quelques secondes à ~3 minutes selon la taille des plages Shodan.
- **Premier relevé = référence** : le niveau doit être `stable`. L'existant figure dans le rapport HTML.
- Attendu : `exposition-state.json` en `-rw-r-----`, `exposition.html` et `.json` en `-rw-r--r--`.

> Si une source change de configuration plus tard (ajout d'une plage IP, d'un mot-clé), les éléments ajoutés
> apparaîtront comme nouveautés au relevé suivant : c'est attendu. Consultez-les, puis acquittez.

## 3.6 Mail

Voir [07-envoi-mail.md](07-envoi-mail.md), puis test :
```bash
sudo -u exposition /usr/local/bin/exposition.py collect --publish --mail always
```

## 3.7 Planification

```bash
install -m 644 systemd/serveur/exposition.service        /etc/systemd/system/
install -m 644 systemd/serveur/exposition.timer          /etc/systemd/system/
install -m 644 systemd/serveur/exposition-resume.service /etc/systemd/system/
install -m 644 systemd/serveur/exposition-resume.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now exposition.timer exposition-resume.timer
systemctl list-timers --no-pager | grep exposition
```

| Tâche | Quand | Mail |
|---|---|---|
| `exposition.timer` | 01:10, 07:10, 13:10, 19:10 (+ 0-10 min aléatoires) | seulement si nouveauté |
| `exposition-resume.timer` | lundi-vendredi 07:47 | toujours (résumé) |

- Heures décalées des heures rondes et délai aléatoire : on évite de solliciter les API au même instant que tout le monde.
- `Persistent=true` : un relevé manqué (serveur éteint) est rattrapé au démarrage.

Test de la chaîne :
```bash
systemctl start exposition.service
journalctl -u exposition -n 20 --no-pager
```

## 3.8 Publication web (optionnelle)

Voir [06-publication-web.md](06-publication-web.md).

## 3.9 Acquittement depuis un poste (optionnel)

Pour que `exposition.py ack` lancé sur un poste acquitte sur le serveur :
```bash
echo 'votre_compte ALL=(exposition) NOPASSWD: /usr/local/bin/exposition.py ack' > /etc/sudoers.d/exposition-ack
chmod 440 /etc/sudoers.d/exposition-ack
visudo -c
```
- La règle n'autorise **qu'une commande**, et uniquement en tant que `exposition` (pas root).
- `visudo -c` vérifie la syntaxe : une erreur dans sudoers peut bloquer `sudo` entièrement.
- Le compte doit pouvoir se connecter en SSH au serveur (clé), comme pour la lecture du rapport.

## 3.10 Mise à jour du script

```bash
install -o root -g root -m 755 exposition.py /usr/local/bin/exposition.py
sudo -u exposition /usr/local/bin/exposition.py show
```
L'état et la configuration sont conservés.
