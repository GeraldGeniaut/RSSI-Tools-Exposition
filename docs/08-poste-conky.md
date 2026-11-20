# 8. Poste administrateur : Conky et prompt

Affiche l'état d'exposition **en permanence sur le bureau** (Conky) et **dans le prompt** du terminal.
Testé sous Ubuntu (GNOME). Toutes les commandes : avec votre compte, sans `sudo` sauf indication.

## Prérequis

- Python 3.8+ ;
- une **clé SSH** autorisée sur le serveur de collecte pour votre compte (lecture du rapport) ;
- Conky : `sudo apt install -y conky-all`.

## 8.1 Script et configuration

```bash
sudo install -o root -g root -m 755 src/exposition.py /usr/local/bin/exposition.py
mkdir -p ~/.config/crise-alertes
install -m 600 config/exposition-poste.ini.example ~/.config/crise-alertes/exposition.ini
nano ~/.config/crise-alertes/exposition.ini     # domaine, server_host, mots-clés, plages IP
```

## 8.2 Test

```bash
exposition.py client
```
La dernière ligne indique la source :
- **« via serveur »** : vous êtes sur le réseau interne ou en VPN, le rapport du serveur a été récupéré ;
- **« relevé direct »** : le serveur est injoignable, le poste a interrogé lui-même les API
  (jusqu'à quelques minutes si les plages Shodan sont grandes).

Test de la détection réseau :
```bash
python3 -c "import socket; socket.create_connection(('collecte.example.internal',22),timeout=3); print('serveur joignable')"
```

## 8.3 Mise à jour automatique (toutes les 30 min)

```bash
mkdir -p ~/.config/systemd/user
install -m 644 systemd/poste/exposition.service systemd/poste/exposition.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now exposition.timer
systemctl --user list-timers --no-pager | grep exposition
```
- Sur le réseau interne : simple copie de fichier, aucun appel aux API.
- Hors réseau : relevé direct au plus toutes les `direct_interval_h` heures (6 par défaut), sinon réaffichage.

## 8.4 Bloc Conky

```bash
mkdir -p ~/.config/conky
sed "s/UTILISATEUR/$USER/" conky/conky-exposition.conf > ~/.config/conky/conky-exposition.conf
conky -c ~/.config/conky/conky-exposition.conf -d
```
- Conky ne développe pas `~` dans `${catp}` : le chemin complet est écrit par `sed`.
- `text_buffer_size = 16384` est indispensable : sans lui, Conky tronque le bloc à 256 octets.
- Texte blanc avec ombre noire : lisible quel que soit le fond d'écran.
- Position : `alignment`, `gap_x`, `gap_y`.

Si vous avez déjà un Conky, vous pouvez à la place ajouter dans son `conky.text` :
```
${hr 1}
${catp /home/UTILISATEUR/.cache/crise-alertes/exposition.txt}
```
(et vérifier sa valeur de `text_buffer_size`).

Démarrage automatique :
```bash
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/conky-exposition.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Conky exposition
Exec=conky -c $HOME/.config/conky/conky-exposition.conf -d -p 8
X-GNOME-Autostart-enabled=true
EOF
```

## 8.5 Indicateur dans le prompt

```bash
cat conky/prompt-exposition.bash >> ~/.bashrc
source ~/.bashrc
```
- `stable` : rien n'est affiché ;
- `hausse` : `[EXPO:hausse]` en jaune ;
- `CRITIQUE` / `ERREUR` : en rouge.

L'indicateur lit le dernier relevé local (aucun appel réseau à chaque commande) et disparaît après acquittement.

## 8.6 Acquitter depuis le poste

```bash
exposition.py ack
```
Sur le réseau interne : acquitte **sur le serveur** (nécessite la règle sudoers, [03 §3.9](03-installation-serveur.md)),
puis rafraîchit le poste. Hors réseau : acquitte la référence locale du poste uniquement.

## Désinstallation

```bash
systemctl --user disable --now exposition.timer
rm -f ~/.config/systemd/user/exposition.{service,timer} ~/.config/autostart/conky-exposition.desktop
pkill -f conky-exposition.conf
sudo rm -f /usr/local/bin/exposition.py
# retirer le bloc « Indicateur d'exposition » de ~/.bashrc
```
