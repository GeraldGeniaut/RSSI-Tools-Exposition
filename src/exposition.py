#!/usr/bin/env python3
"""
exposition — Surveillance de l'exposition externe d'un établissement.

Un seul script, deux usages :

  SERVEUR DE COLLECTE — collecte, rapport HTML, mail, publication :
    exposition.py collect --publish --mail on-change    # toutes les 6 h
    exposition.py collect --publish --mail always       # résumé quotidien
    exposition.py ack                                   # « traité » : nouveautés acquittées

  POSTE (Conky) — choisit tout seul sa source :
    exposition.py client       # sur le réseau interne / VPN : récupère le JSON du serveur (scp)
                               # ailleurs                   : interroge directement les API
    exposition.py ack          # acquitte sur le serveur si joignable, sinon en local
    exposition.py show         # afficher le dernier état dans le terminal

Sources : Hudson Rock (infostealers), ransomware.live (revendications),
CERT-FR (alertes/avis filtrés sur ton parc), Shodan InternetDB (ports/CVE de
vos IP publiques), crt.sh (certificats émis pour le domaine), domaines sosies
(typosquatting, via DNS-over-HTTPS), listes noires DNS (Spamhaus, SpamCop,
Barracuda), HIBP (optionnel, nécessite une clé d'API payante).

Documentation complète : dossier docs/ du projet.

Python 3.8+, bibliothèque standard uniquement.
"""
import argparse
import concurrent.futures
import configparser
import html
import ipaddress
import json
import os
import re
import smtplib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

VERSION = "1.2"
UA = {"User-Agent": "exposition/%s" % VERSION, "Accept": "application/json"}
SEV_ORDER = {"ok": 0, "warn": 1, "crit": 2}

DEFAULT_CONF_PATHS = ["/etc/exposition/exposition.ini",
                      os.path.expanduser("~/.config/crise-alertes/exposition.ini")]

# --------------------------------------------------------------------- réseau
# api.ransomware.live répond 404 en IPv6 : IPv4 forcé pour les hôtes listés
_IPV4_ONLY = {"api.ransomware.live"}
_gai = socket.getaddrinfo


def _gai_v4(host, *a, **k):
    res = _gai(host, *a, **k)
    if host in _IPV4_ONLY:
        v4 = [r for r in res if r[0] == socket.AF_INET]
        return v4 or res
    return res


socket.getaddrinfo = _gai_v4


def http_get(url, headers=None, timeout=30, raw=False):
    h = dict(UA)
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if raw else json.loads(data.decode("utf-8", "replace") or "null")


def short_err(e):
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 429:
            return "limite de requêtes atteinte (429)"
        return "HTTP %d" % e.code
    msg = str(getattr(e, "reason", e))
    return msg[:70]


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="minutes")


def fmt_local(iso):
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d/%m %H:%M")
    except (ValueError, TypeError):
        return iso or "?"


# ================================================================ collecteurs
# Chaque collecteur renvoie {"metrics": {...}, "items": [ {id,title,date,sev,url,detail} ]}
# Les items sont comparés à l'état acquitté : tout id inconnu = nouveauté.

def col_hudsonrock(cfg, domain):
    d = http_get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain="
                 + urllib.parse.quote(domain))
    m = {k: int(d.get(k) or 0) for k in ("employees", "users", "third_parties", "totalUrls")}
    return {"metrics": m, "items": []}


def col_ransomwarelive(cfg, domain):
    kws = cfg_list(cfg, "ransomwarelive", "keywords", [])
    if not kws:
        raise ValueError("aucun mot-clé [ransomwarelive] keywords")
    items = {}
    for i, kw in enumerate(kws):
        if i:
            time.sleep(3)  # ménager la limite de requêtes
        try:
            data = http_get("https://api.ransomware.live/v2/searchvictims/" + urllib.parse.quote(kw))
        except urllib.error.HTTPError as e:
            if e.code == 404:  # l'API répond 404 quand la recherche ne trouve aucune victime
                continue
            raise
        if isinstance(data, dict):  # « aucun résultat » renvoyé sous forme de message
            data = data.get("victims") or data.get("data") or []
        rx = re.compile(r"(?<![\w-])" + re.escape(kw) + r"(?![\w])", re.I)
        for v in data or []:
            if not isinstance(v, dict):
                continue
            text = " ".join(str(v.get(k) or "") for k in ("post_title", "victim", "website", "description"))
            if not rx.search(text):
                continue  # mot entier uniquement : « etab » ne déclenche pas sur « etablissement »
            title = v.get("post_title") or v.get("victim") or "?"
            group = v.get("group_name") or v.get("group") or "?"
            date = (v.get("discovered") or v.get("attackdate") or "")[:10]
            iid = "rl:%s|%s|%s" % (group, title, date)
            items[iid] = {"id": iid, "title": "%s (%s)" % (title, group), "date": date, "sev": "crit",
                          "url": v.get("url") or "https://www.ransomware.live/search?q=" + urllib.parse.quote(kw),
                          "detail": "mot-clé « %s »" % kw}
    return {"metrics": {"revendications": len(items)}, "items": list(items.values())}


CERTFR_FEEDS = [("alerte", "https://www.cert.ssi.gouv.fr/alerte/feed/", "crit"),
                ("avis", "https://www.cert.ssi.gouv.fr/avis/feed/", "warn")]
CERTFR_DEFAULT_KW = ["Fortinet", "FortiOS", "FortiGate", "FortiClient", "FortiAnalyzer", "VMware", "vCenter",
                     "ESXi", "Omnissa", "Horizon", "Veeam", "GLPI", "Centreon", "Wazuh", "Graylog", "Tomcat",
                     "MariaDB", "MySQL", "Apache HTTP", "Nginx", "HAProxy", "OpenSSH", "WordPress", "PHP",
                     "Nextcloud", "FreeRADIUS", "Rubycat", "WAPT", "Microsoft Entra", "Active Directory"]


def col_certfr(cfg, domain):
    kws = cfg_list(cfg, "certfr", "keywords", CERTFR_DEFAULT_KW)
    days = cfg.getint("certfr", "days", fallback=30) if cfg.has_section("certfr") else 30
    rx = re.compile(r"(?<![\w])(" + "|".join(re.escape(k) for k in kws) + r")(?![\w])", re.I)
    limit = datetime.now(timezone.utc) - timedelta(days=days)
    items = []
    for kind, url, sev in CERTFR_FEEDS:
        root = ET.fromstring(http_get(url, raw=True))
        for it in root.iter("item"):
            title = (it.findtext("title") or "").strip()
            desc = re.sub(r"<[^>]+>", " ", it.findtext("description") or "")
            link = (it.findtext("link") or "").strip()
            try:
                pub = parsedate_to_datetime(it.findtext("pubDate") or "")
            except (TypeError, ValueError):
                pub = None
            if pub and pub < limit:
                continue
            m = rx.search(title + " " + desc)
            if not m:
                continue
            items.append({"id": "certfr:" + link, "title": title, "sev": sev, "url": link,
                          "date": pub.astimezone().strftime("%Y-%m-%d") if pub else "",
                          "detail": "%s — concerne : %s" % (kind.upper(), m.group(1))})
    return {"metrics": {"alertes": sum(i["sev"] == "crit" for i in items),
                        "avis": sum(i["sev"] == "warn" for i in items)}, "items": items}


def expand_ips(entries, max_hosts=1024):
    """« 203.0.113.0/24, 198.51.100.7 » -> liste d'adresses (plages limitées à max_hosts)."""
    out = []
    for e in entries:
        if "/" in e:
            net = ipaddress.ip_network(e, strict=False)
            if net.num_addresses > max_hosts:
                raise ValueError("plage %s trop grande (> %d adresses)" % (e, max_hosts))
            out.extend(str(h) for h in (net.hosts() if net.num_addresses > 2 else net))
        else:
            out.append(str(ipaddress.ip_address(e)))
    return list(dict.fromkeys(out))  # sans doublons, ordre conservé


def col_shodan(cfg, domain):
    ips = expand_ips(cfg_list(cfg, "shodan", "ips", []))
    items, ports_total, vulns_total, seen = [], 0, 0, 0
    for n, ip in enumerate(ips):
        if n:
            time.sleep(0.3)  # rester courtois avec le service gratuit
        try:
            d = http_get("https://internetdb.shodan.io/" + ip)
        except urllib.error.HTTPError as e:
            if e.code == 404:  # aucune information : rien d'exposé connu
                continue
            raise
        seen += 1
        for p in d.get("ports") or []:
            ports_total += 1
            items.append({"id": "shodan:%s:port:%s" % (ip, p), "title": "%s : port %s ouvert" % (ip, p),
                          "sev": "warn", "date": "", "url": "https://www.shodan.io/host/" + ip,
                          "detail": ", ".join(d.get("hostnames") or [])[:80]})
        for v in d.get("vulns") or []:
            vulns_total += 1
            items.append({"id": "shodan:%s:vuln:%s" % (ip, v), "title": "%s : %s" % (ip, v), "sev": "crit",
                          "date": "", "url": "https://www.cve.org/CVERecord?id=" + v,
                          "detail": "CVE signalée par Shodan (à confirmer, détection par version)"})
    return {"metrics": {"ip": len(ips), "exposées": seen, "ports": ports_total, "cve": vulns_total},
            "items": items}


# ------------------------------------------- phishing : certificats et sosies
def _issuer_org(issuer):
    m = re.search(r'(?:^|,\s*)O="?([^",]+)', issuer or "")
    if m:
        return m.group(1).strip()
    m = re.search(r'CN="?([^",]+)', issuer or "")
    return m.group(1).strip() if m else "?"


def col_ct(cfg, domain):
    """Certificate Transparency (crt.sh) : noms couverts par un certificat valide.
    Un nouveau nom, ou un nom certifié par une nouvelle autorité, devient une nouveauté."""
    items, certs = {}, set()
    for n, q in enumerate(("%." + domain, domain)):
        if n:
            time.sleep(3)
        data = http_get("https://crt.sh/?" + urllib.parse.urlencode(
            {"q": q, "output": "json", "exclude": "expired"}), timeout=120)
        for c in data or []:
            if not isinstance(c, dict):
                continue
            certs.add(c.get("id"))
            org = _issuer_org(c.get("issuer_name"))
            for name in (c.get("name_value") or "").lower().split("\n"):
                name = name.strip()
                if not (name == domain or name.endswith("." + domain)):
                    continue
                iid = "ct:%s|%s" % (name, org)
                nb, na = (c.get("not_before") or "")[:10], (c.get("not_after") or "")[:10]
                if iid not in items or nb > items[iid]["date"]:
                    items[iid] = {"id": iid, "title": "%s — certificat %s" % (name, org), "sev": "warn",
                                  "date": nb, "url": "https://crt.sh/?q=" + urllib.parse.quote(name),
                                  "detail": "valide jusqu'au %s" % na if na else ""}
    names = {i["id"][3:].split("|")[0] for i in items.values()}
    return {"metrics": {"certificats": len(certs), "noms": len(names)}, "items": list(items.values())}


HOMOGLYPHES = {"o": "0", "i": "1l", "l": "1i", "e": "3", "a": "4", "s": "5", "u": "v", "c": "k", "g": "q",
               "q": "g", "b": "d", "d": "b"}
MULTI = [("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("d", "cl")]
AZERTY = ["azertyuiop", "qsdfghjklm", "wxcvbn"]
VOISINS = {ch: [row[j] for j in (i - 1, i + 1) if 0 <= j < len(row)] for row in AZERTY for i, ch in enumerate(row)}
SOSIES_TLDS = ["fr", "com", "net", "org", "eu", "info", "online", "site", "xyz", "co", "io", "me", "app"]
SOSIES_MOTS = ["etudiant", "etudiants", "connexion", "login", "securite", "portail", "mail", "support"]
DOH_DEFAULT = "https://cloudflare-dns.com/dns-query"
RTYPE = {"A": 1, "NS": 2, "MX": 15}
_LABEL_OK = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def sosies(domain, tlds, mots, extra=()):
    """Variantes du domaine qu'un attaquant pourrait enregistrer (fautes de frappe, homoglyphes…)."""
    label, _, suffix = domain.lower().partition(".")
    L, n = set(), len(label)
    for i, ch in enumerate(label):
        L.add(label[:i] + label[i + 1:])                                    # lettre oubliée
        L.add(label[:i] + ch + label[i:])                                   # lettre doublée
        if i < n - 1:
            L.add(label[:i] + label[i + 1] + ch + label[i + 2:])            # lettres inversées
        for r in HOMOGLYPHES.get(ch, "") + "".join(VOISINS.get(ch, [])):    # homoglyphe, touche voisine
            L.add(label[:i] + r + label[i + 1:])
    for a, b in MULTI:
        if a in label:
            L.add(label.replace(a, b))
    L.add(label.replace("-", ""))
    for m in mots:
        L.add(label + "-" + m)
        L.add(m + "-" + label)
    L = {x for x in L if x != label and _LABEL_OK.match(x) and "--" not in x}
    out = {"%s.%s" % (x, t) for x in L for t in dict.fromkeys([suffix, "com"])}
    for t in tlds:
        out.add("%s.%s" % (label, t))
        out.add("%s.%s" % (label.replace("-", ""), t))
    out.update(e.lower() for e in extra)
    out.discard(domain.lower())
    return sorted(out)


def doh(url, name, rtype):
    """Résolution DNS-over-HTTPS (format JSON) : indépendante du DNS local."""
    d = http_get(url + "?" + urllib.parse.urlencode({"name": name, "type": rtype}),
                 headers={"Accept": "application/dns-json"}, timeout=10)
    ans = [a.get("data", "") for a in d.get("Answer") or [] if a.get("type") == RTYPE[rtype]]
    return d.get("Status"), ans


def col_sosies(cfg, domain):
    sec = "sosies"
    tlds = cfg_list(cfg, sec, "tlds", SOSIES_TLDS)
    mots = cfg_list(cfg, sec, "words", SOSIES_MOTS)
    ignore = {x.lower() for x in cfg_list(cfg, sec, "ignore", [])}
    url = cfg.get(sec, "doh", fallback=DOH_DEFAULT) if cfg.has_section(sec) else DOH_DEFAULT
    cands = [d for d in sosies(domain, tlds, mots, cfg_list(cfg, sec, "extra", [])) if d not in ignore]
    items, regs, mx_n, errs = [], 0, 0, 0
    for n, d in enumerate(cands):
        if n:
            time.sleep(0.1)
        try:
            status, ns = doh(url, d, "NS")
        except Exception:
            errs += 1
            continue
        if status != 0 or not ns:  # 3 = NXDOMAIN : libre ; 2 = SERVFAIL : délégation cassée, ignorée
            continue
        regs += 1
        try:
            mx = [m.split()[-1].rstrip(".") for m in doh(url, d, "MX")[1]]
            mx = [m for m in mx if m and m != "."]   # « MX 0 . » = le domaine refuse le mail
            a = doh(url, d, "A")[1]
        except Exception:
            mx, a = [], []
        who = "https://who.is/whois/" + d
        items.append({"id": "sosie:" + d, "title": "%s est enregistré" % d, "sev": "warn", "date": "",
                      "url": who, "detail": "IP : %s" % ", ".join(a[:3]) if a else "sans site web"})
        if mx:
            mx_n += 1
            items.append({"id": "sosie:%s:mx" % d, "title": "%s peut envoyer/recevoir du mail" % d,
                          "sev": "crit", "date": "", "url": who, "detail": "MX : %s" % ", ".join(mx[:3])})
    if cands and errs > len(cands) // 2:
        raise RuntimeError("résolveur DoH injoignable (%d/%d échecs)" % (errs, len(cands)))
    return {"metrics": {"testés": len(cands), "enregistrés": regs, "avec_mx": mx_n}, "items": items}


# ----------------------------------------------------- listes noires DNS (RBL)
# Interrogées avec le résolveur DNS du système : Spamhaus refuse les résolveurs
# publics (Quad9, Cloudflare, Google…) et répond alors 127.255.255.x.
SPAMHAUS_ZEN = {"127.0.0.2": ("SBL : source de spam", "crit"),
                "127.0.0.3": ("CSS : envoi de spam", "crit"),
                "127.0.0.4": ("XBL : machine infectée derrière cette IP", "crit"),
                "127.0.0.5": ("XBL : machine infectée derrière cette IP", "crit"),
                "127.0.0.6": ("XBL : machine infectée derrière cette IP", "crit"),
                "127.0.0.7": ("XBL : machine infectée derrière cette IP", "crit"),
                "127.0.0.9": ("DROP : réseau détourné", "crit"),
                "127.0.0.10": None, "127.0.0.11": None}  # PBL : plage sans envoi de mail direct, normal
SPAMHAUS_DBL = {"127.0.1.2": ("domaine de spam", "crit"), "127.0.1.4": ("domaine de phishing", "crit"),
                "127.0.1.5": ("domaine de malware", "crit"), "127.0.1.6": ("serveur de commande de botnet", "crit"),
                "127.0.1.102": ("domaine légitime détourné pour du spam", "crit"),
                "127.0.1.103": ("domaine légitime détourné : redirection", "crit"),
                "127.0.1.104": ("domaine légitime détourné : phishing", "crit"),
                "127.0.1.105": ("domaine légitime détourné : malware", "crit"),
                "127.0.1.106": ("domaine légitime détourné : botnet", "crit")}
RBL_CODES = {"zen.spamhaus.org": SPAMHAUS_ZEN, "dbl.spamhaus.org": SPAMHAUS_DBL}
RBL_TEST = {"dbl.spamhaus.org": ("dbltest.com", "127.0.1.2")}  # défaut : 2.0.0.127 -> 127.0.0.2
RBL_URL = {"zen.spamhaus.org": "https://check.spamhaus.org/results?query=%s",
           "dbl.spamhaus.org": "https://check.spamhaus.org/results?query=%s",
           "bl.spamcop.net": "https://www.spamcop.net/w3m?action=checkblock&ip=%s"}
RBL_IP_LISTS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]
RBL_DOMAIN_LISTS = ["dbl.spamhaus.org"]


class RblRefus(Exception):
    pass


def dnsbl(q):
    """Adresses renvoyées pour q ; [] si le nom n'existe pas (= non listé)."""
    try:
        addrs = sorted(set(socket.gethostbyname_ex(q)[2]))
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return []
        raise
    except socket.herror as e:
        if e.errno in (1, 4):  # HOST_NOT_FOUND, NO_DATA
            return []
        raise
    if any(a.startswith("127.255.255.") for a in addrs):  # Spamhaus : requête refusée / quota
        raise RblRefus(addrs[0])
    return addrs


def _rbl_test(lst):
    name, want = RBL_TEST.get(lst, ("2.0.0.127", "127.0.0.2"))
    try:
        got = dnsbl("%s.%s" % (name, lst))
    except RblRefus as e:
        return "refusée (%s)" % e
    except OSError as e:
        return "injoignable (%s)" % e
    return "" if want in got else "test sans réponse"


def col_rbl(cfg, domain):
    sec = "rbl"
    ip_lists = cfg_list(cfg, sec, "ip_lists", RBL_IP_LISTS)
    dom_lists = cfg_list(cfg, sec, "domain_lists", RBL_DOMAIN_LISTS)
    ips = expand_ips(cfg_list(cfg, sec, "ips", []) or cfg_list(cfg, "shodan", "ips", []))
    ips = [i for i in ips if ipaddress.ip_address(i).version == 4]
    doms = cfg_list(cfg, sec, "domains", [domain])
    ko = {}
    for lst in ip_lists + dom_lists:  # adresse de test : la liste répond-elle, et nous accepte-t-elle ?
        err = _rbl_test(lst)
        if err:
            ko[lst] = err
    jobs = [(lst, ip, "%s.%s" % (".".join(reversed(ip.split("."))), lst))
            for lst in ip_lists if lst not in ko for ip in ips]
    jobs += [(lst, d, "%s.%s" % (d, lst)) for lst in dom_lists if lst not in ko for d in doms]

    def run(job):
        try:
            return job, dnsbl(job[2]), None
        except RblRefus as e:
            return job, [], "refusée (%s)" % e
        except OSError as e:
            return job, [], "erreur DNS (%s)" % e

    items, listed = [], set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for (lst, cible, _), addrs, err in ex.map(run, jobs):
            if err:
                ko.setdefault(lst, err)
                continue
            codes = RBL_CODES.get(lst)
            for a in addrs:
                if codes is not None:
                    if a not in codes:
                        meaning = ("code %s" % a, "warn")
                    elif codes[a] is None:
                        continue  # PBL
                    else:
                        meaning = codes[a]
                else:
                    meaning = ("listée", "warn")
                listed.add(cible)
                url = RBL_URL.get(lst, "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%%3a%s") % cible
                items.append({"id": "rbl:%s:%s:%s" % (lst, cible, a), "sev": meaning[1], "date": "", "url": url,
                              "title": "%s sur %s" % (cible, lst), "detail": meaning[0]})
    total = len(ip_lists) + len(dom_lists)
    if ko and len(ko) == total:
        raise RuntimeError("aucune liste utilisable : " + "; ".join("%s %s" % kv for kv in ko.items()))
    for lst, err in ko.items():  # liste en échec : visible dans le rapport, sans bloquer les autres
        items.append({"id": "rbl-ko:%s" % lst, "sev": "warn", "date": "", "url": "",
                      "title": "liste %s inutilisable" % lst, "detail": err})
    return {"metrics": {"listes": "%d/%d" % (total - len(ko), total), "ip": len(ips),
                        "domaines": len(doms), "listées": len(listed)}, "items": items}


def col_hibp(cfg, domain):
    key = cfg.get("hibp", "api_key", fallback="").strip() if cfg.has_section("hibp") else ""
    if not key:
        return None  # source désactivée (pas d'abonnement)
    try:
        d = http_get("https://haveibeenpwned.com/api/v3/breacheddomain/" + urllib.parse.quote(domain),
                     headers={"hibp-api-key": key})
    except urllib.error.HTTPError as e:
        if e.code == 404:          # aucune adresse du domaine dans une fuite connue
            d = {}
        elif e.code == 401:
            raise RuntimeError("clé d'API HIBP refusée (401)")
        elif e.code == 403:
            raise RuntimeError("domaine non vérifié ou abonnement insuffisant (403)")
        else:
            raise
    items = []
    for alias, breaches in (d or {}).items():
        for b in breaches:
            iid = "hibp:%s@%s:%s" % (alias, domain, b)
            items.append({"id": iid, "title": "%s@%s dans « %s »" % (alias, domain, b), "sev": "warn",
                          "date": "", "url": "https://haveibeenpwned.com/PwnedWebsites#" + b, "detail": ""})
    return {"metrics": {"adresses": len(d or {}), "apparitions": len(items)}, "items": items}


SOURCES = [  # nom, libellé, fonction
    ("hudsonrock", "Hudson Rock — infostealers", col_hudsonrock),
    ("ransomwarelive", "ransomware.live — revendications", col_ransomwarelive),
    ("certfr", "CERT-FR — alertes et avis", col_certfr),
    ("shodan", "Shodan InternetDB — IP publiques", col_shodan),
    ("ct", "Certificats — crt.sh (Certificate Transparency)", col_ct),
    ("sosies", "Sosies — domaines ressemblants (typosquatting)", col_sosies),
    ("rbl", "Listes noires — Spamhaus, SpamCop, Barracuda", col_rbl),
    ("hibp", "Have I Been Pwned — domaine", col_hibp),
]
HR_LABELS = {"employees": ("Employés compromis", "crit"), "users": ("Usagers compromis", "warn"),
             "third_parties": ("Tiers", "warn"), "totalUrls": ("URL touchées", "warn")}


# ===================================================================== config
def cfg_list(cfg, section, key, default):
    if not cfg.has_section(section) or not cfg.get(section, key, fallback="").strip():
        return list(default)
    return [x.strip() for x in re.split(r"[,\n]", cfg.get(section, key)) if x.strip()]


def enabled(cfg, name):
    if name == "hibp":
        return cfg.has_section("hibp") and bool(cfg.get("hibp", "api_key", fallback="").strip())
    if name == "shodan" and not cfg_list(cfg, "shodan", "ips", []):
        return False  # pas d'IP publique déclarée
    return cfg.getboolean(name, "enabled", fallback=True) if cfg.has_section(name) else True


def load_cfg(path):
    cfg = configparser.ConfigParser()
    paths = [path] if path else DEFAULT_CONF_PATHS
    for p in paths:
        if p and os.path.exists(p):
            cfg.read(p, encoding="utf-8")
            cfg.set("DEFAULT", "_file", p)
            return cfg
    if path:
        sys.exit("Configuration introuvable : " + path)
    return cfg


def state_dir(cfg):
    d = os.path.expanduser(cfg.get("general", "state_dir",
                                   fallback="~/.cache/crise-alertes") if cfg.has_section("general")
                           else "~/.cache/crise-alertes")
    os.makedirs(d, exist_ok=True)
    return d


def domain_of(cfg):
    d = cfg.get("general", "domain", fallback="").strip() if cfg.has_section("general") else ""
    if not d:
        sys.exit("Configuration : [general] domain est obligatoire (ex. domain = example.org)")
    return d


# ====================================================================== état
def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_atomic(path, text, mode=0o640):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def collect(cfg):
    """Interroge toutes les sources actives, met à jour l'état, renvoie le rapport."""
    sd = state_dir(cfg)
    spath = os.path.join(sd, "exposition-state.json")
    st = load_json(spath, {"sources": {}, "ack": {}, "first_seen": {}, "mailed": []})
    domain = domain_of(cfg)
    for name, label, fn in SOURCES:
        if not enabled(cfg, name):
            st["sources"].pop(name, None)
            continue
        prev = st["sources"].get(name, {})
        try:
            res = fn(cfg, domain)
            if res is None:
                continue
            res.update({"ok": True, "error": "", "checked": now_iso()})
            st["sources"][name] = res
            ack = st["ack"].setdefault(name, None)
            if ack is None:  # premier relevé de cette source = référence
                st["ack"][name] = {"items": [i["id"] for i in res["items"]], "metrics": dict(res["metrics"])}
            for i in res["items"]:
                st["first_seen"].setdefault(i["id"], now_iso())
        except Exception as e:  # garde le dernier relevé valide
            prev = dict(prev) if prev else {"metrics": {}, "items": []}
            prev.update({"ok": False, "error": short_err(e)})
            st["sources"][name] = prev
    st["checked"] = now_iso()
    write_atomic(spath, json.dumps(st, ensure_ascii=False, indent=1), 0o640)
    return build_report(st, domain, origin="serveur" if cfg.has_section("server") else "direct")


def build_report(st, domain, origin):
    """Calcule les nouveautés (non acquittées) et le niveau global."""
    rep = {"domain": domain, "checked": st.get("checked"), "origin": origin, "version": VERSION,
           "sources": [], "level": "ok", "new_count": 0}
    labels = {n: l for n, l, _ in SOURCES}
    for name, data in st.get("sources", {}).items():
        ack = st.get("ack", {}).get(name) or {"items": [], "metrics": {}}
        known = set(ack.get("items", []))
        new = [dict(i, first_seen=st.get("first_seen", {}).get(i["id"], "")) for i in data.get("items", [])
               if i["id"] not in known]
        if name == "hudsonrock":  # hausses de compteurs
            for k, v in data.get("metrics", {}).items():
                base = ack.get("metrics", {}).get(k, v)
                if v > base:
                    lab, sev = HR_LABELS.get(k, (k, "warn"))
                    new.append({"id": "hr:%s:%d" % (k, v), "title": "%s : %d → %d (+%d)" % (lab, base, v, v - base),
                                "sev": sev, "date": "", "url": "https://www.hudsonrock.com/",
                                "detail": "hausse depuis le dernier acquittement", "first_seen": ""})
        lvl = max([i["sev"] for i in new] + ["ok"], key=lambda s: SEV_ORDER[s])
        rep["sources"].append({"name": name, "label": labels.get(name, name), "ok": data.get("ok", False),
                               "error": data.get("error", ""), "checked": data.get("checked", ""),
                               "metrics": data.get("metrics", {}), "new": new,
                               "items": data.get("items", []), "level": lvl})
        rep["new_count"] += len(new)
        if SEV_ORDER[lvl] > SEV_ORDER[rep["level"]]:
            rep["level"] = lvl
    order = {n: i for i, (n, _, _) in enumerate(SOURCES)}
    rep["sources"].sort(key=lambda s: order.get(s["name"], 99))
    return rep


def do_ack(cfg):
    sd = state_dir(cfg)
    spath = os.path.join(sd, "exposition-state.json")
    st = load_json(spath, None)
    if not st:
        sys.exit("Aucun relevé à acquitter.")
    for name, data in st.get("sources", {}).items():
        st["ack"][name] = {"items": [i["id"] for i in data.get("items", [])], "metrics": dict(data.get("metrics", {}))}
    st["mailed"] = []
    write_atomic(spath, json.dumps(st, ensure_ascii=False, indent=1), 0o640)
    return build_report(st, domain_of(cfg), origin="serveur" if cfg.has_section("server") else "direct")


# =================================================================== rendus
LEVEL_WORD = {"ok": "stable", "warn": "hausse", "crit": "CRITIQUE"}
METRIC_SHORT = {"employees": "employés", "users": "usagers", "third_parties": "tiers", "totalUrls": "url",
                "revendications": "revendic.", "alertes": "alertes", "avis": "avis", "ip": "ip",
                "ports": "ports", "cve": "cve", "exposées": "exposées", "adresses": "adresses", "apparitions": "appar.",
                "certificats": "certif.", "noms": "noms", "testés": "testés", "enregistrés": "enreg.",
                "avec_mx": "mx", "listes": "listes", "domaines": "dom.", "listées": "listées"}
CONKY_COL = {"ok": "green", "warn": "orange", "crit": "red"}


def render_conky(rep, max_new=3):
    any_ok = any(s["ok"] for s in rep["sources"])
    word = LEVEL_WORD[rep["level"]] if (any_ok or not rep["sources"]) else "ERREUR"
    col = CONKY_COL[rep["level"]] if word != "ERREUR" else "red"
    esc = lambda t: str(t).replace("$", "$$")
    L = ["${color1}EXPOSITION %s${color}${alignr}${color %s}%s${color}" % (esc(rep["domain"]), col, word)]
    for s in rep["sources"]:
        short = s["label"].split(" — ")[0]
        if not s["ok"]:
            L.append("${color2}%-17s${color} ${color red}%s${color}" % (esc(short), esc(s["error"])[:44]))
        elif s["new"]:
            L.append("${color %s}%-17s %d nouveauté(s)${color}" % (CONKY_COL[s["level"]], esc(short), len(s["new"])))
            for i in sorted(s["new"], key=lambda x: SEV_ORDER[x["sev"]], reverse=True)[:max_new]:
                L.append("${color %s}  %s${color}" % (CONKY_COL[i["sev"]], esc(i["title"])[:52]))
        else:
            m = " ".join("%s %s" % (METRIC_SHORT.get(k, k), v) for k, v in s["metrics"].items())
            L.append("${color2}%-17s${color} ${color green}ok${color} ${color2}%s${color}" % (esc(short), esc(m)[:44]))
    src = "via serveur" if rep.get("origin") == "serveur" else "relevé direct"
    tail = "  —  exposition.py ack après traitement" if rep["new_count"] else ""
    L.append("${color2}%s, %s%s${color}" % (src, fmt_local(rep.get("checked")), tail))
    return "\n".join(L) + "\n"


def render_text(rep):
    t = render_conky(rep, max_new=50).replace("${alignr}", "  —  ")
    return re.sub(r"\$\{[^}]*\}", "", t).replace("$$", "$")


HTML_COL = {"ok": "#1a7f37", "warn": "#b35900", "crit": "#c0262d"}


def render_html(rep):
    e = html.escape
    lvl = rep["level"]
    rows = []
    for s in rep["sources"]:
        status = ("<span style='color:%s;font-weight:600'>%s</span>" % (HTML_COL[s["level"]],
                  "%d nouveauté(s)" % len(s["new"]) if s["new"] else "rien de nouveau")
                  if s["ok"] else "<span style='color:#c0262d'>erreur : %s</span>" % e(s["error"]))
        metrics = " · ".join("%s : <b>%s</b>" % (e(str(k)), e(str(v))) for k, v in s["metrics"].items())
        rows.append("<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td style='color:#666'>%s</td></tr>"
                    % (e(s["label"]), status, metrics, e(fmt_local(s.get("checked")))))
    blocks = []
    for s in rep["sources"]:
        lst = s["new"] or []
        others = [i for i in s["items"] if i["id"] not in {n["id"] for n in lst}]
        if not lst and not others:
            continue
        li = []
        for i in sorted(lst, key=lambda x: SEV_ORDER[x["sev"]], reverse=True):
            li.append("<li><span class='b %s'>NOUVEAU</span> %s</li>" % (i["sev"], _item_html(i)))
        for i in others[:30]:
            li.append("<li class='old'>%s</li>" % _item_html(i))
        if len(others) > 30:
            li.append("<li class='old'>… %d autre(s)</li>" % (len(others) - 30))
        blocks.append("<h2>%s</h2><ul>%s</ul>" % (e(s["label"]), "".join(li)))
    return """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exposition %(dom)s — %(word)s</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#222}
h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
.banner{padding:14px 18px;border-radius:8px;color:#fff;background:%(col)s;margin:14px 0 18px;font-size:16px}
table{border-collapse:collapse;width:100%%;font-size:14px} td,th{border-bottom:1px solid #eee;padding:8px 6px;text-align:left;vertical-align:top}
th{color:#555;font-weight:600} ul{padding-left:18px;font-size:14px} li{margin:5px 0} li.old{color:#555}
.b{display:inline-block;font-size:11px;font-weight:700;color:#fff;border-radius:4px;padding:1px 6px;margin-right:4px}
.b.crit{background:#c0262d}.b.warn{background:#b35900} .m{color:#777;font-size:12px} a{color:#0b5cad}
.foot{color:#888;font-size:12px;margin-top:30px}
</style></head><body>
<h1>Exposition externe — %(dom)s</h1>
<div class="m">Relevé du %(when)s · %(origin)s</div>
<div class="banner"><b>%(word)s</b> — %(newc)d nouveauté(s) non acquittée(s)</div>
<table><tr><th>Source</th><th>État</th><th>Indicateurs</th><th>Relevé</th></tr>%(rows)s</table>
%(blocks)s
<div class="foot">Généré par exposition.py %(ver)s. Après traitement : <code>exposition.py ack</code> sur le serveur de collecte.
Document interne — diffusion restreinte.</div>
</body></html>""" % {"dom": e(rep["domain"]), "word": e(LEVEL_WORD[lvl]), "col": HTML_COL[lvl],
                     "when": e(fmt_local(rep.get("checked"))), "origin": e(rep.get("origin", "")),
                     "newc": rep["new_count"], "rows": "".join(rows), "blocks": "".join(blocks), "ver": VERSION}


def _item_html(i):
    e = html.escape
    url = i.get("url") or ""
    title = e(i["title"])
    if url.startswith(("https://", "http://")):
        title = "<a href='%s'>%s</a>" % (e(url, quote=True), title)
    extra = " ".join(x for x in [e(i.get("date") or ""), e(i.get("detail") or "")] if x)
    return "%s <span class='m'>%s</span>" % (title, extra)


# ================================================================ publication
def publish(cfg, rep):
    sd = state_dir(cfg)
    out = os.path.expanduser(cfg.get("server", "out_dir", fallback=sd))
    os.makedirs(out, exist_ok=True)
    jpath, hpath = os.path.join(out, "exposition.json"), os.path.join(out, "exposition.html")
    write_atomic(jpath, json.dumps(rep, ensure_ascii=False, indent=1), 0o644)
    write_atomic(hpath, render_html(rep), 0o644)
    target = cfg.get("server", "scp_target", fallback="").strip()
    if target:
        cmd = ["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        key = cfg.get("server", "scp_key", fallback="").strip()
        if key:
            cmd += ["-i", os.path.expanduser(key)]
        r = subprocess.run(cmd + [hpath, jpath, target], capture_output=True, text=True, timeout=60)
        if r.returncode:
            print("scp vers %s : échec — %s" % (target, r.stderr.strip()), file=sys.stderr)
            return False
    return True


def mail(cfg, rep, mode):
    if mode == "never" or not cfg.has_section("server"):
        return
    sd = state_dir(cfg)
    spath = os.path.join(sd, "exposition-state.json")
    st = load_json(spath, {})
    new_ids = sorted(i["id"] for s in rep["sources"] for i in s["new"])
    if mode == "on-change":
        unsent = [i for i in new_ids if i not in set(st.get("mailed", []))]
        if not unsent:
            return
        subject_tag = "NOUVEAU"
    else:
        subject_tag = "Résumé quotidien"
    to = [x.strip() for x in cfg.get("server", "mail_to", fallback="").split(",") if x.strip()]
    if not to:
        print("Mail non envoyé : [server] mail_to est vide.", file=sys.stderr)
        return
    msg = EmailMessage()
    msg["Subject"] = "[Exposition %s] %s — %s, %d nouveauté(s)" % (rep["domain"], subject_tag,
                                                                   LEVEL_WORD[rep["level"]], rep["new_count"])
    msg["From"] = cfg.get("server", "mail_from", fallback="exposition@" + rep["domain"])
    msg["To"] = ", ".join(to)
    msg.set_content(render_text(rep))
    msg.add_alternative(render_html(rep), subtype="html")
    host = cfg.get("server", "smtp_host", fallback="localhost")
    port = cfg.getint("server", "smtp_port", fallback=25)
    with smtplib.SMTP(host, port, timeout=30) as s:
        if cfg.getboolean("server", "smtp_starttls", fallback=False):
            s.starttls()
        s.send_message(msg)
    st["mailed"] = sorted(set(st.get("mailed", [])) | set(new_ids))
    write_atomic(spath, json.dumps(st, ensure_ascii=False, indent=1), 0o640)


# ===================================================================== poste
def remote_available(cfg):
    if not cfg.has_section("client"):
        return None
    host = cfg.get("client", "server_host", fallback="").strip()
    if not host:
        return None
    try:
        with socket.create_connection((host.split("@")[-1], 22), timeout=3):
            return host
    except OSError:
        return None


def client(cfg):
    sd = state_dir(cfg)
    host = remote_available(cfg)
    rep = None
    if host:
        rpath = cfg.get("client", "remote_json", fallback="/var/lib/exposition/www/exposition.json")
        tmp = os.path.join(sd, "exposition-remote.json")
        r = subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                            "%s:%s" % (host, rpath), tmp], capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            rep = load_json(tmp, None)
            if rep:
                rep["origin"] = "serveur"
    if rep is None:  # hors réseau interne, ou serveur injoignable : relevé direct (pas trop souvent)
        hours = cfg.getfloat("client", "direct_interval_h", fallback=6) if cfg.has_section("client") else 6
        st = load_json(os.path.join(sd, "exposition-state.json"), None)
        last = None
        try:
            last = datetime.fromisoformat(st["checked"]) if st else None
        except (KeyError, ValueError):
            pass
        if last and datetime.now().astimezone() - last < timedelta(hours=hours):
            rep = build_report(st, domain_of(cfg), "direct")  # relevé récent : on ménage les API
        else:
            rep = collect(cfg)
        rep["origin"] = "direct"
    write_atomic(os.path.join(sd, "exposition.json"), json.dumps(rep, ensure_ascii=False, indent=1), 0o600)
    write_atomic(os.path.join(sd, "exposition.txt"), render_conky(rep), 0o600)
    return rep


def ack_cmd(cfg):
    host = remote_available(cfg) if cfg.has_section("client") else None
    if host:
        cmd = cfg.get("client", "remote_ack",
                      fallback="sudo -u exposition /usr/local/bin/exposition.py ack")
        r = subprocess.run(["ssh", "-t", host, cmd])
        if r.returncode == 0:
            print("Acquitté sur le serveur de collecte.")
            client(cfg)  # rafraîchit Conky
            return
        print("Acquittement distant impossible : acquittement local.", file=sys.stderr)
    rep = do_ack(cfg)
    if cfg.has_section("server"):
        publish(cfg, rep)
    else:
        sd = state_dir(cfg)
        write_atomic(os.path.join(sd, "exposition.txt"), render_conky(rep), 0o600)
    print("Acquitté : la situation actuelle devient la référence.")


# ====================================================================== main
def main():
    p = argparse.ArgumentParser(description="Surveillance de l'exposition externe du domaine")
    p.add_argument("--config", help="fichier INI (défaut : /etc/exposition/exposition.ini "
                                    "puis ~/.config/crise-alertes/exposition.ini)")
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("collect", help="SERVEUR : interroger les sources")
    c.add_argument("--publish", action="store_true", help="écrire HTML + JSON et les copier (scp)")
    c.add_argument("--mail", choices=["never", "on-change", "always"], default="never")
    sub.add_parser("client", help="POSTE : serveur si joignable, sinon relevé direct ; écrit le fichier Conky")
    sub.add_parser("ack", help="acquitter les nouveautés (sur le serveur si joignable)")
    sub.add_parser("show", help="afficher le dernier état connu dans le terminal")
    sub.add_parser("html", help="écrire le rapport HTML du dernier état sur la sortie standard")
    args = p.parse_args()
    cfg = load_cfg(args.config)

    if args.cmd == "collect":
        rep = collect(cfg)
        if args.publish:
            publish(cfg, rep)
        mail(cfg, rep, args.mail)
        print(render_text(rep), end="")
    elif args.cmd == "client":
        print(render_text(client(cfg)), end="")
    elif args.cmd == "ack":
        ack_cmd(cfg)
    elif args.cmd in ("show", "html"):
        sd = state_dir(cfg)
        rep = load_json(os.path.join(sd, "exposition.json"), None)
        if rep is None:
            st = load_json(os.path.join(sd, "exposition-state.json"), None)
            if not st:
                sys.exit("Aucun relevé : lancer « collect » ou « client » d'abord.")
            rep = build_report(st, domain_of(cfg), "direct")
        print(render_text(rep) if args.cmd == "show" else render_html(rep), end="")
    else:
        p.print_help()


if __name__ == "__main__":
    main()
