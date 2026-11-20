# 1. Architecture et principes

## Deux rôles, un seul script

| Rôle | Commande | Où | Fréquence |
|---|---|---|---|
| **Serveur de collecte** | `exposition.py collect --publish --mail …` | une VM Linux interne (compte de service) | toutes les 6 h + résumé quotidien |
| **Poste administrateur** | `exposition.py client` | poste Linux de l'équipe sécurité | toutes les 30 min |

Le même fichier `exposition.py` sert aux deux : la présence d'une section `[server]` ou `[client]` dans la
configuration détermine le comportement.

## Cycle d'un relevé (serveur)

1. **Collecte** : chaque source active est interrogée. Une source en panne n'empêche pas les autres ; son dernier
   résultat valide est conservé et l'erreur est affichée.
2. **Comparaison** : chaque élément trouvé (revendication, avis CERT-FR, port ouvert, CVE…) porte un identifiant
   stable. Il est comparé à la **référence acquittée** ; tout identifiant inconnu est une **nouveauté**.
   Pour Hudson Rock, ce sont les compteurs qui sont comparés (une hausse = nouveauté).
3. **Niveau global** : `stable` (rien de nouveau), `hausse` (nouveauté de gravité moyenne), `CRITIQUE`
   (nouvelle revendication, nouvelle alerte CERT-FR, nouvelle CVE, nouvel employé compromis), `ERREUR`
   (aucune source n'a répondu).
4. **Sorties** : état interne (`exposition-state.json`, illisible des autres comptes), rapport publié
   (`www/exposition.html` et `www/exposition.json`).
5. **Mail** (optionnel) : à chaque nouveauté non encore envoyée, et/ou résumé quotidien.

## La référence et l'acquittement

- **Premier relevé** d'une source = **référence** : l'existant n'alerte pas (il reste visible dans le rapport).
- **Acquitter** (`exposition.py ack`) = « j'ai pris connaissance » : la situation actuelle devient la nouvelle
  référence, le niveau repasse à `stable`.
- Tant qu'on n'acquitte pas, les nouveautés restent affichées dans le rapport, Conky et le résumé quotidien,
  mais **un même élément n'est envoyé qu'une fois** dans les mails « nouveauté ».

Acquitter ne signifie pas « accepté » : simplement « connu ». Tenez le suivi des corrections ailleurs (ticket, registre).

## Le poste : réseau interne ou télétravail

`exposition.py client` choisit sa source tout seul :

1. Il tente une connexion TCP sur le **port 22 du serveur de collecte** (3 s maximum).
   Le nom du serveur n'est résolu que par les DNS internes et son adresse est privée : la connexion ne réussit
   que **sur le réseau interne ou via le VPN**.
2. **Si elle réussit** : copie de `exposition.json` par scp (aucun appel aux API publiques).
3. **Sinon, ou si la copie échoue** : **relevé direct** des API, au plus toutes les `direct_interval_h` heures ;
   entre deux relevés, le dernier résultat est réaffiché.

La dernière ligne du bloc indique toujours l'origine : « via serveur » ou « relevé direct ».

> Limite connue : en relevé direct, le poste tient sa **propre référence**. Au premier relevé direct, l'existant
> devient référence locale : le poste peut afficher `stable` alors que des nouveautés restent non acquittées sur
> le serveur. Le serveur (rapport, mails) fait foi.

## Modèle de sécurité

| Principe | Mise en œuvre |
|---|---|
| Moindre privilège | compte système `exposition`, sans shell ni mot de passe ; jamais root |
| Configuration non modifiable par le service | `/etc/exposition` en `750 root:exposition`, fichier en `640` |
| Programme non modifiable par le service | `/usr/local/bin/exposition.py` appartient à root |
| État confidentiel | `exposition-state.json` en `640` ; seul le rapport publié est lisible (`644`) |
| Données externes non fiables | tout contenu issu des API est échappé dans le HTML (pas d'injection de script) |
| Publication sans élévation | la copie vers un serveur web est faite par root (`ExecStartPost=+…`) ou tirée par le serveur web ; le compte de service n'a aucune clé vers d'autres machines |
| Pas de secret sur les postes | la clé HIBP ne reste que sur le serveur ; les postes lisent le JSON publié |
