# Surveillance de l'exposition externe d'un établissement

Outil léger pour savoir, sans abonnement coûteux, **ce qu'Internet sait de votre établissement** :
identifiants volés par des infostealers, revendications de groupes de rançongiciels, alertes CERT-FR
touchant votre parc, ports et vulnérabilités visibles sur vos adresses publiques et, en option,
adresses de votre domaine présentes dans des fuites (Have I Been Pwned).

- **Un seul script Python** (`src/exposition.py`), bibliothèque standard uniquement (Python 3.8+), aucune dépendance.
- **Un serveur de collecte** interroge les sources toutes les 6 h, produit un rapport HTML/JSON, envoie un mail
  à chaque nouveauté et un résumé quotidien.
- **Les postes d'administration** affichent l'état sur le bureau (Conky) et dans le prompt : ils lisent le rapport
  du serveur sur le réseau interne, ou interrogent eux-mêmes les sources en télétravail.
- **Ne signale que les nouveautés** : la situation existante sert de référence ; après traitement, on « acquitte ».

```
                     Internet (API publiques)
   Hudson Rock · ransomware.live · CERT-FR · Shodan InternetDB · [HIBP]
                │                                   │ (hors réseau interne)
                ▼                                   ▼
   ┌──────────────────────────┐   scp (lecture)   ┌──────────────────────────┐
   │ Serveur de collecte      │ ◄──────────────── │ Poste administrateur      │
   │ compte « exposition »    │                   │ exposition.py client      │
   │ collect · html · json    │                   │ → Conky + prompt          │
   └──────────┬──────────┬────┘                   └──────────────────────────┘
              │ mail     │ publication (optionnelle)
              ▼          ▼
     boîte RSSI    serveur web annexe (HTTPS + authentification)
```

## Contenu

| Chemin | Rôle |
|---|---|
| `src/exposition.py` | le script (serveur et poste) |
| `config/*.ini.example` | configurations commentées (serveur, poste) |
| `systemd/serveur/`, `systemd/poste/` | planifications prêtes à l'emploi |
| `scripts/` | publication vers un serveur web (pousser ou tirer), bloc Apache |
| `conky/` | bloc Conky et indicateur de prompt |
| `docs/` | documentation complète |

## Documentation

1. [Architecture et principes](docs/01-architecture.md)
2. [Les sources : ce qu'elles disent et leurs limites](docs/02-sources.md)
3. [Installation du serveur de collecte](docs/03-installation-serveur.md)
4. [Configuration (référence)](docs/04-configuration.md)
5. [Option Have I Been Pwned (payante)](docs/05-option-hibp.md)
6. [Publication sur un serveur web annexe](docs/06-publication-web.md)
7. [Envoi par mail](docs/07-envoi-mail.md)
8. [Poste administrateur : Conky et prompt](docs/08-poste-conky.md)
9. [Exploitation, acquittement, dépannage](docs/09-exploitation.md)

## Démarrage rapide (serveur)

```bash
sudo useradd --system --home-dir /var/lib/exposition --shell /usr/sbin/nologin exposition
sudo install -d -o exposition -g exposition -m 755 /var/lib/exposition /var/lib/exposition/www
sudo install -d -o root -g exposition -m 750 /etc/exposition
sudo install -m 755 src/exposition.py /usr/local/bin/exposition.py
sudo install -o root -g exposition -m 640 config/exposition-serveur.ini.example /etc/exposition/exposition.ini
sudo nano /etc/exposition/exposition.ini           # domaine, mots-clés, plages IP, mail
sudo -u exposition /usr/local/bin/exposition.py collect --publish     # premier relevé = référence
```
Puis suivre [docs/03](docs/03-installation-serveur.md) pour le mail, la planification et la publication.

## Points d'attention

- Le rapport contient des **informations sensibles** (comptes compromis, ports, vulnérabilités) : diffusion restreinte.
- Les sources gratuites ont des **limites de requêtes** : ne pas multiplier les relevés manuels.
- Les CVE de Shodan sont **déduites des versions annoncées** : à confirmer avant d'agir.
- Avant de déployer, informez votre hiérarchie : l'outil ne fait qu'interroger des services publics, mais
  ses résultats engagent des actions (réinitialisations, fermetures de ports).

## Licence

À définir par l'établissement diffuseur (une licence libre de type MIT ou Licence Ouverte facilite la réutilisation
entre établissements).
