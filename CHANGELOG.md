# Historique des versions

## 1.2 — 2026-11-23
- Nouvelle source **Listes noires DNS** (`[rbl]`) : Spamhaus ZEN et DBL, SpamCop, Barracuda.
  Codes Spamhaus traduits (XBL = machine infectée, PBL ignorée), test de chaque liste avant usage,
  liste refusée ou muette signalée « inutilisable ». Requêtes parallèles via le résolveur du système.

## 1.1 — 2026-11-23
- Nouvelle source **Certificats** (`[ct]`) : Certificate Transparency via crt.sh.
- Nouvelle source **Sosies** (`[sosies]`) : domaines ressemblants (typosquatting), enregistrement et MX,
  résolution via DNS-over-HTTPS.

## 1.0 — 2026-11-20
- Version initiale : Hudson Rock, ransomware.live, CERT-FR, Shodan InternetDB, HIBP (option).
