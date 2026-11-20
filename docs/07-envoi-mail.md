# 7. Envoi par mail

## Comportement

| Mode (`--mail`) | Envoi | Usage |
|---|---|---|
| `never` (défaut) | jamais | tests |
| `on-change` | s'il existe au moins une nouveauté **pas encore envoyée** | relevé toutes les 6 h |
| `always` | à chaque exécution | résumé quotidien |

- Un même élément n'est envoyé qu'**une fois** en mode `on-change`. Il reste présent dans chaque résumé quotidien
  tant qu'il n'est pas acquitté.
- Objet : `[Exposition example.org] NOUVEAU — CRITIQUE, 3 nouveauté(s)` ou `… Résumé quotidien — …`.
- Corps : rapport HTML complet, plus une version texte pour les clients sans HTML.

## Configuration

```ini
[server]
mail_to       = rssi@example.org, astreinte-secu@example.org
mail_from     = exposition@example.org
smtp_host     = relais-smtp.example.internal
smtp_port     = 25
smtp_starttls = false
```
- `mail_to` vide : aucun mail (un message l'indique).
- Utilisez une **adresse générique** de l'équipe sécurité plutôt qu'une boîte personnelle.
- Pour un canal Teams : la plupart des équipes ont une **adresse e-mail de canal** ; ajoutez-la à `mail_to`.

## Prérequis côté relais

Le script envoie en SMTP **sans authentification** vers un relais interne (cas typique d'un Postfix qui accepte
les applications internes) :
- le relais doit autoriser l'adresse du serveur de collecte (`mynetworks` sous Postfix) ;
- si le relais exige STARTTLS : `smtp_starttls = true` (et `smtp_port` adapté).

Test de joignabilité, sans rien envoyer :
```bash
nc -vz -w 5 relais-smtp.example.internal 25
```

## Test

```bash
sudo -u exposition /usr/local/bin/exposition.py collect --publish --mail always
```

## Délivrabilité

Si le mail arrive en indésirables :
- l'adresse `mail_from` doit appartenir à un domaine dont le **SPF** autorise votre relais ;
- si vos mails sortent par Microsoft 365 ou un autre fournisseur, vérifiez **DKIM/DMARC** pour ce domaine ;
- au besoin, ajoutez une règle de transport ou d'expéditeur approuvé pour `exposition@`.

## Dépannage

| Message | Cause probable |
|---|---|
| `Connection refused` / délai dépassé | relais injoignable, pare-feu, mauvais port |
| `Relay access denied` | le relais n'autorise pas le serveur de collecte |
| `Sender address rejected` | `mail_from` refusé par le relais |
| aucun mail en `on-change` | normal s'il n'y a pas de nouveauté non encore envoyée |
