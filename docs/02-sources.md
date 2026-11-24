# 2. Les sources : ce qu'elles disent et leurs limites

Toutes les sources sont interrogées en lecture, via leurs API publiques. Aucune donnée de l'établissement n'est
envoyée, à part le **nom de domaine**, les **mots-clés** et les **adresses IP publiques** recherchés.

---

## Hudson Rock — identifiants volés par des infostealers

**Ce que c'est.** Société de renseignement spécialisée dans les *infostealers* : des logiciels malveillants qui
volent les mots de passe enregistrés dans les navigateurs, les cookies et l'historique d'une machine infectée.
Ces « logs » sont revendus sur des places de marché ; c'est aujourd'hui la première source de comptes compromis.

**Ce que l'outil récupère.** Via l'API gratuite de recherche par domaine, quatre compteurs :

| Compteur | Signification | Gravité d'une hausse |
|---|---|---|
| `employees` | machines infectées où un identifiant **de votre domaine** a été volé (vos agents) | **critique** |
| `users` | personnes extérieures (usagers, étudiants…) dont les identifiants sur **vos services en ligne** ont été volés | moyenne |
| `third_parties` | identifiants liés à votre domaine sur des services tiers | moyenne |
| `totalUrls` | nombre d'URL de vos services présentes dans ces logs | moyenne |

**Comment l'exploiter.** Le site public de Hudson Rock (recherche par domaine) détaille les URL concernées.
Le propriétaire du domaine peut demander le détail nominatif (« Ethical Disclosure »). Pour un employé :
réinitialiser le mot de passe, révoquer les sessions (M365/Entra…), vérifier les méthodes MFA, traiter la machine.
Pour vos services exposés : limitation des tentatives de connexion, MFA, détection de bourrage d'identifiants.

**Limites.** Couverture partielle (uniquement les logs collectés par Hudson Rock). Les dates d'infection ne sont
pas exposées par l'API gratuite : l'outil détecte les **hausses** de compteurs.

---

## ransomware.live — revendications des groupes de rançongiciels

**Ce que c'est.** Projet communautaire qui surveille en continu les sites de fuite (« leak sites ») des groupes de
rançongiciels et recense les victimes revendiquées.

**Ce que l'outil récupère.** Pour chaque mot-clé configuré, les revendications dont le titre, le site ou la
description contiennent ce mot **en entier**, pour éviter les faux positifs (un sigle court ne doit pas
déclencher sur un mot plus long qui le contient, par exemple dans la description d'une autre victime). Une nouvelle revendication = **critique**.

**Quels mots-clés.** Nom court et sigle de l'établissement, de la tutelle, et de vos **prestataires critiques**
(une attaque chez un prestataire peut exposer vos données ou ouvrir une porte vers votre réseau).
Évitez les mots courts ou courants.

**Comportements de l'API à connaître** (gérés par le script) :
- une recherche **sans résultat renvoie HTTP 404** : ce n'est pas une panne ;
- l'API peut répondre 404 en **IPv6** : le script force l'IPv4 pour ce site ;
- **limite de requêtes par adresse IP** (HTTP 429) : le script espace les requêtes et garde le dernier
  résultat ; évitez les relevés manuels répétés (tous les comptes sortant par la même IP publique comptent).

---

## CERT-FR — alertes et avis de sécurité

**Ce que c'est.** Le centre gouvernemental de veille, d'alerte et de réponse aux attaques informatiques (ANSSI)
publie des **alertes** (vulnérabilités activement exploitées, urgence) et des **avis** (correctifs disponibles).

**Ce que l'outil récupère.** Les flux RSS publics des alertes et des avis, filtrés sur la liste des **produits de
votre parc** (mots entiers), sur une fenêtre glissante (`days`, 30 jours par défaut).
Nouvelle alerte = **critique** ; nouvel avis = moyen.

**À adapter.** La liste `keywords` de la section `[certfr]` doit refléter **votre** parc (pare-feu, hyperviseur,
sauvegarde, applications métier, briques web). Une liste trop large noie l'information ; trop étroite, elle fait
manquer des alertes.

---

## Shodan InternetDB — ce qu'Internet voit de vos adresses

**Ce que c'est.** Shodan balaie Internet en permanence. *InternetDB* est son service **gratuit, sans clé**, qui
donne pour une adresse IP les ports ouverts, les noms d'hôtes et les CVE connues.

**Ce que l'outil récupère.** Pour chaque adresse de vos plages publiques (`ips`, notation CIDR acceptée,
1024 adresses maximum par plage) : nouveau port ouvert = moyen ; nouvelle CVE = **critique**.
Une courte pause sépare les requêtes (environ 2 minutes pour un /24).

**Limites importantes.**
- Les données ont **quelques jours** : un port fermé hier peut encore apparaître.
- Les **CVE sont déduites de la version annoncée** par le service (bannière) : faux positifs fréquents
  (correctif rétroporté par la distribution). **Vérifiez la version réelle** avant d'agir.
- Vérifiez toujours un constat **depuis l'extérieur** (connexion 4G, `nmap -Pn`), jamais depuis le réseau interne.

**Ce qu'on y trouve souvent** et qui mérite attention : SNMP (161/udp) ou NTP (123/udp) exposés,
BGP (179) ouvert à tous au lieu des seuls pairs, VPN anciens (L2TP 1701, PPTP 1723), ports d'administration web.

---

## Certificate Transparency (crt.sh) — certificats émis pour votre domaine

**Ce que c'est.** Toute autorité de certification publique doit déclarer chaque certificat dans des journaux
publics (*Certificate Transparency*). crt.sh les indexe et les rend consultables, **gratuitement, sans clé**.

**Ce que l'outil récupère.** Les noms (`domaine` et `*.domaine`) couverts par un certificat **encore valide**,
avec l'autorité émettrice. On suit le couple *nom + autorité* : un renouvellement ne déclenche rien, mais
**un nouveau nom** (service monté sans prévenir, shadow IT) ou **un nom certifié par une autorité inhabituelle**
(certificat obtenu frauduleusement) devient une nouveauté (niveau moyen).

**Limites.** crt.sh est un service bénévole souvent saturé : des erreurs 502/503 ponctuelles sont normales,
la source garde alors son dernier relevé valide. Les certificats émis par une PKI interne n'y figurent pas.

---

## Domaines sosies (typosquatting)

**Ce que c'est.** Les campagnes de phishing ciblées utilisent souvent un domaine **ressemblant** au vôtre
(`m0netab.fr`, `monetab-connexion.fr`, `monetab.online`…), enregistré quelques jours avant l'attaque.

**Ce que l'outil fait.** Il génère environ 170 variantes : lettre oubliée, doublée ou inversée, touche voisine
(clavier AZERTY), homoglyphes (`o`→`0`, `i`→`1`), sans tiret, mots accolés (`connexion`, `login`…), autres
extensions. Pour chacune, il interroge le DNS via **DNS-over-HTTPS** (indépendant de votre DNS interne) :
- domaine **enregistré** (il a des serveurs NS) = nouveauté moyenne ;
- domaine avec un **serveur de mail** (MX) = **critique** : il peut envoyer du phishing à vos usagers.
  Un MX « nul » (`0 .`, le domaine refuse le mail) n'est pas compté.

**Limites.** Seules les variantes générées sont testées : une imitation plus libre (`portail-etudiant-paris.fr`)
passe à travers, ajoutez-la dans `extra`. Déclarez dans `ignore` les variantes qui vous appartiennent.
Le premier relevé sert de référence : **relisez-le une fois à la main**.

---

## Listes noires DNS (Spamhaus, SpamCop, Barracuda)

**Ce que c'est.** Des listes de réputation interrogeables par DNS. On demande `<IP inversée>.<liste>` :
une réponse en `127.0.0.x` signifie « inscrite », une absence de réponse « propre ».

**Ce que l'outil récupère.** Vos IP publiques sur Spamhaus **ZEN**, SpamCop et Barracuda, vos domaines sur
Spamhaus **DBL**. Les codes Spamhaus sont traduits :
- **XBL** : une machine **infectée** se trouve derrière l'IP (botnet, proxy) — **critique**, à traiter en priorité ;
- **SBL / CSS** : source de spam — critique ; **DROP** : réseau détourné — critique ;
- **PBL** : plage qui n'envoie pas de mail en direct — **ignorée**, c'est normal ;
- **DBL** : domaine utilisé pour du spam, du phishing, du malware (y compris domaine légitime piraté) — critique ;
- SpamCop, Barracuda : inscription — moyen.

**Point essentiel : le résolveur DNS.** Spamhaus **refuse les requêtes passant par un résolveur public**
(Quad9, Cloudflare, Google) et répond alors `127.255.255.254`. L'outil utilise le résolveur **du système** et
teste chaque liste avant usage avec son adresse de test officielle ; une liste refusée ou muette est signalée
« inutilisable » et ses réponses ignorées (jamais de faux « propre »). Testez d'abord depuis le serveur :

```bash
dig +short 2.0.0.127.zen.spamhaus.org        # attendu : 127.0.0.2 127.0.0.4 127.0.0.10
dig +short dbltest.com.dbl.spamhaus.org      # attendu : 127.0.1.2
dig +short 2.0.0.127.bl.spamcop.net          # attendu : 127.0.0.2
dig +short 2.0.0.127.b.barracudacentral.org  # attendu : 127.0.0.2
```

Si Spamhaus répond `127.255.255.254`, faites résoudre le serveur en direct (sans résolveur public) ou ouvrez un
compte gratuit *Spamhaus Data Query Service*.

**Ce qu'on y trouve souvent.** L'IP de NAT des utilisateurs inscrite chez Barracuda (sans enregistrement PTR,
elle a envoyé du mail en direct sur le port 25) : bloquez le **port 25 sortant** pour les réseaux internes,
sauf votre relais de messagerie, puis demandez la radiation.

---

## AbuseIPDB — vos adresses signalées comme sources d'attaques

**Ce que c'est.** Base collaborative où administrateurs et pots de miel signalent les IP qui les attaquent
(balayage de ports, force brute SSH/RDP, spam web…). Clé d'API **gratuite** (1 000 vérifications d'IP par jour,
100 vérifications de plage par jour).

**Ce que l'outil récupère.** Un appel *check-block* par /24 de vos plages : chaque adresse signalée sur la période
(`max_age_days`) devient une nouveauté, **critique** si le score de confiance AbuseIPDB atteint `crit_score`.
Une adresse de NAT signalée signifie généralement qu'une machine interne attaque l'extérieur : à investiguer.

**Limites.** Un signalement isolé peut être une erreur (score faible) ; les signalements visent l'IP publique,
il faut ensuite retrouver la machine interne dans les journaux du pare-feu.

---

## abuse.ch — URLhaus et ThreatFox

**Ce que c'est.** Deux bases gratuites d'abuse.ch, alimentées par des chercheurs en sécurité :
**URLhaus** recense les URL qui distribuent des malwares, **ThreatFox** les indicateurs de compromission
(serveurs de commande de botnets, Cobalt Strike…). Une Auth-Key gratuite et commune est nécessaire.

**Ce que l'outil récupère.** Pour vos domaines et quelques IP choisies : toute URL connue d'URLhaus
(**critique** si encore en ligne — typique d'un site web piraté) et toute entrée ThreatFox (**critique**).

**Limites.** Seules les cibles listées sont interrogées (une requête par cible et par base) : déclarez vos
sorties NAT et vos serveurs exposés, pas tout le bloc.

---

## Have I Been Pwned (option payante)

Adresses e-mail de votre domaine présentes dans des fuites de données indexées. Nécessite un **abonnement** et une
**clé d'API**. Voir [05-option-hibp.md](05-option-hibp.md).
