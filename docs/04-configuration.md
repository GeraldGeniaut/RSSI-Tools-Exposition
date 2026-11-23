# 4. Configuration (référence)

Format INI. Fichier recherché, dans l'ordre : `--config <fichier>`, `/etc/exposition/exposition.ini`,
`~/.config/crise-alertes/exposition.ini`. Les listes acceptent la virgule ou le retour à la ligne (lignes de
continuation indentées).

## [general]

| Clé | Défaut | Description |
|---|---|---|
| `domain` | — (obligatoire) | domaine de l'établissement (`example.org`) |
| `state_dir` | `~/.cache/crise-alertes` | dossier de l'état ; sur le serveur : `/var/lib/exposition` |

## [hudsonrock]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | interroger Hudson Rock |

## [ransomwarelive]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | interroger ransomware.live |
| `keywords` | — (obligatoire si activé) | mots-clés, recherche en **mot entier** |

## [certfr]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | lire les flux CERT-FR |
| `days` | `30` | fenêtre affichée (jours) |
| `keywords` | liste générique intégrée | produits de votre parc (mots entiers, insensible à la casse) |

## [shodan]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | actif seulement si `ips` est renseigné |
| `ips` | — | adresses et plages CIDR publiques (max 1024 adresses par plage) |

## [ct]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | interroge crt.sh pour `%.domaine` et `domaine` (certificats valides uniquement) |

## [sosies]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | génère les variantes du domaine et teste leur enregistrement (NS) et leur MX |
| `ignore` | vide | variantes à ne pas surveiller (domaines vous appartenant) |
| `tlds` | `fr, com, net, org, eu, info, online, site, xyz, co, io, me, app` | extensions testées pour le nom exact |
| `words` | `etudiant, etudiants, connexion, login, securite, portail, mail, support` | mots accolés au nom |
| `extra` | vide | variantes supplémentaires à tester |
| `doh` | `https://cloudflare-dns.com/dns-query` | résolveur DNS-over-HTTPS (réponses JSON) |

## [rbl]

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | interroge les listes noires DNS avec le résolveur du système |
| `ip_lists` | `zen.spamhaus.org, bl.spamcop.net, b.barracudacentral.org` | listes d'adresses IP |
| `domain_lists` | `dbl.spamhaus.org` | listes de domaines |
| `ips` | vide = `[shodan] ips` | adresses IPv4 à vérifier |
| `domains` | `[general] domain` | domaines à vérifier |

## [hibp] (option payante)

| Clé | Défaut | Description |
|---|---|---|
| `api_key` | vide = désactivé | clé d'API Have I Been Pwned — voir [05-option-hibp.md](05-option-hibp.md) |

## [server] (serveur de collecte uniquement)

| Clé | Défaut | Description |
|---|---|---|
| `out_dir` | `state_dir` | dossier du rapport publié |
| `scp_target` | vide | copie directe `compte@hôte:/chemin/` (préférer les méthodes de [06](06-publication-web.md)) |
| `scp_key` | vide | clé SSH pour `scp_target` |
| `mail_to` | vide = pas de mail | destinataires, séparés par des virgules |
| `mail_from` | `exposition@<domain>` | expéditeur |
| `smtp_host` | `localhost` | relais SMTP |
| `smtp_port` | `25` | port |
| `smtp_starttls` | `false` | chiffrement STARTTLS vers le relais |

## [client] (poste uniquement)

| Clé | Défaut | Description |
|---|---|---|
| `server_host` | — | `compte@serveur` ; vide = toujours en relevé direct |
| `remote_json` | `/var/lib/exposition/www/exposition.json` | rapport à récupérer |
| `remote_ack` | `sudo -u exposition /usr/local/bin/exposition.py ack` | commande d'acquittement distante |
| `direct_interval_h` | `6` | intervalle minimal entre deux relevés directs (heures) |

## Fichiers produits

| Fichier | Où | Contenu |
|---|---|---|
| `exposition-state.json` | `state_dir` | état complet : derniers résultats, référence acquittée, éléments déjà envoyés par mail |
| `exposition.json` | `out_dir` (serveur) / `state_dir` (poste) | rapport : niveau, nouveautés, éléments par source |
| `exposition.html` | `out_dir` | rapport lisible (également envoyé par mail) |
| `exposition.txt` | `state_dir` (poste) | bloc au format Conky |
