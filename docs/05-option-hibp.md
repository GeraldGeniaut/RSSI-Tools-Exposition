# 5. Option Have I Been Pwned (payante)

## Ce que ça apporte

Have I Been Pwned (HIBP) recense les **adresses e-mail présentes dans des fuites de données** publiques ou
revendues. La recherche par domaine liste **toutes les adresses de votre domaine** touchées, avec le nom des fuites.
C'est complémentaire de Hudson Rock (infostealers) : HIBP couvre surtout les fuites de bases de données de sites
tiers (un agent qui a utilisé son adresse professionnelle sur un site piraté), ainsi que des compilations de logs.

## Ce qui est gratuit, ce qui ne l'est pas

| Fonction | Accès |
|---|---|
| Vérifier la propriété du domaine, tableau de bord | gratuit (compte HIBP) |
| **Notifications** par mail à chaque nouvelle fuite touchant le domaine | gratuit, à activer |
| **Rapport gratuit** d'exposition du domaine (volume, fuites récentes) | gratuit |
| Détail par adresse au-delà d'un petit nombre d'adresses, export | **abonnement** |
| **API** (`breacheddomain`), utilisée par cet outil | **abonnement + clé d'API** |

Les offres et seuils évoluent : consultez la page des abonnements de HIBP au moment de souscrire.
**Même sans abonnement**, faites les étapes 1 et 2 ci-dessous : les notifications gratuites sont utiles.

## 1. Vérifier la propriété du domaine

1. Créez un compte sur HIBP avec une adresse de votre domaine, ouvrez **Domain search**, ajoutez le domaine.
2. Choisissez la vérification par **enregistrement DNS TXT** (indépendante d'une boîte mail) : publiez la valeur
   fournie (`hibp-verify=…`) dans la **zone DNS publique**, sans sous-domaine (enregistrement à la racine).
3. Vérifiez la publication depuis un DNS public, puis cliquez sur *Verify* :
   ```bash
   dig +short TXT example.org @9.9.9.9 | grep -i hibp
   ```
4. L'enregistrement peut être retiré après vérification.

## 2. Activer les notifications (gratuit)

Menu *Notifications* : activez-les, de préférence vers une **adresse générique** de l'équipe sécurité.

## 3. Abonnement et clé d'API

1. Souscrivez l'offre adaptée au nombre d'adresses touchées de votre domaine.
2. Menu *API Key* : générez la clé.
3. Sur le **serveur de collecte uniquement** (pas sur les postes) :
   ```bash
   nano /etc/exposition/exposition.ini
   ```
   ```ini
   [hibp]
   api_key = VOTRE_CLE
   ```
   Le fichier est en `640 root:exposition` : la clé n'est lisible que par root et le compte de service.
4. Relevé de référence :
   ```bash
   sudo -u exposition /usr/local/bin/exposition.py collect --publish
   ```

## Fonctionnement dans l'outil

- Appel : `GET https://haveibeenpwned.com/api/v3/breacheddomain/<domaine>` avec l'en-tête `hibp-api-key`.
- Chaque couple « adresse × fuite » est un élément ; une **nouvelle apparition** = nouveauté (gravité moyenne).
- Compteurs affichés : `adresses` touchées, `apparitions`.
- Réponses gérées :

| Code | Signification | Affichage |
|---|---|---|
| 200 | liste des adresses touchées | normal |
| 404 | aucune adresse du domaine dans une fuite | normal (0) |
| 401 | clé refusée | `clé d'API HIBP refusée (401)` |
| 403 | domaine non vérifié pour ce compte, ou offre insuffisante | message explicite |
| 429 | limite de requêtes | `limite de requêtes atteinte (429)`, dernier résultat conservé |

## Que faire d'une nouvelle apparition

1. Identifier la fuite (nom, date, données exposées : mots de passe ? en clair ou hachés ?).
2. Si des mots de passe sont concernés : forcer le changement, vérifier la MFA, rechercher la réutilisation.
3. Sensibiliser : l'adresse professionnelle ne doit pas servir à des inscriptions personnelles.

## Désactiver

Videz `api_key` : la source disparaît du rapport au relevé suivant.
