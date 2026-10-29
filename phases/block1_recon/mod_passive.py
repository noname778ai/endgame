#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 3 - Passive Reconnaissance  [v3.0.0-ULTRA PRO MAX]
========================================================================
Target ke against koi ACTIVE request nahi (CT logs, archives, DNS, public APIs).
v2 CONTRACT 100% PRESERVED (superset, additive):
  - Sources: crt.sh (3x retry) -> certspotter -> hackertarget -> subfinder ->
    assetfinder -> amass -passive -> findomain + Wayback CDX / waybackurls / gau
  - Source-per-source checkpoint, timeout + graceful degradation, multi-resolver
  - URL mining: params/files/paths/js/api-like/juicy + dir seeds
  - Outputs (same names): all_subs.txt, out_of_scope_subs.txt, resolved.txt,
    ips.txt, all_urls.txt, passive.json, findings/*.txt, feedforward.json, MANIFEST.json

ULTRA v3 NAYE TECHNIQUES (25):
  1. Naye passive sources: OTX (AlienVault passive DNS + URL list), URLScan search,
     RapidDNS, Anubis (jldc.me) - sab GET-only, checkpointed, graceful
  2. Subdomain PERMUTATION engine (dev/staging/api/uat/env words + numbers,
     bounded passive_perm_max=600) -> resolve -> confirmed extras
  3. SUBDOMAIN TAKEOVER detector: CNAME lookup per host + 14 provider
     fingerprints (S3/GCP/Azure/GitHub/Heroku/Shopify/Fastly/Netlify/Zendesk/
     Surge/Bitbucket/Pantheon/Tumblr/WordPress.com) - DNS-only, no HTTP probe
  4. DNS zone intel: MX/NS/TXT/SPF/DMARC/DKIM records -> email-spoofing surface
     (p=none warnings, missing SPF/DMARC) -> dns_records.json + email_spoofing.txt
  5. Shared-IP detection (multiple hosts per IP) -> vhost candidates for P4
  6. URL mining ULTRA: param typing (id/enum/url/file/cmd/date), UUID-vs-int ID
     (IDOR hint), secrets-in-URL (token=..., api_key=...), versioned API matrix
     (/v1../vN + LEGACY warnings), email extraction, websocket URLs
  7. File-ext RISK classes (backup/config/db/key = HIGH -> P23 handoff)
  8. Dormancy analysis: URL year histogram (Wayback), oldest/newest,
     "forgotten app" warnings (stale paths still live in archive)
  9. DORK BUILDER: google_dorks.txt + github_dorks.txt + shodan_queries.txt
     (manual-run guidance, koi query nahi bheji jaati)
 10. Juicy URL scorer (0-100) + top50 output
 11. security.txt discovery (from archived URLs)
 12. passive_diff.json (run-to-run subdomain/url diff)
 13. ASN/whois hints (whois CLI optional) for unique IPs
 14. Cloud-asset patterns from URLs (s3/azure/gcp buckets) -> P24 handoff
 15. subdomain->source attribution map (sources.json)
 16. Coverage score per source + passive_summary.md (exec ready)
 17. Feedforward superset: P4 (resolved/ips/shared-ip/takeover), P5 (dir seeds),
     P7 (js), P8 (juicy urls), P12 (params), P13/15 (sensitive), P23 (files),
     P24 (cloud), P26 (ports? no - P4), P32 report
 18. RWX STANDING RULE: har result file+folder 0777 (core + mod guard)
 19. Layer 4 aligned: sirf GET requests (targets ko kabhi touch nahi karta -
     third-party sources par bina scope-firewall ke client, target client nahi)
 20. Budget: passive_perm_max, passive_cdnx_max, per-source timeout preserved
 21. scope.filter_hosts discipline preserved (out-of-scope NEVER tested)
 22. Graceful on ORIGINAL v2 core (drop-in)
 23. Deterministic checkpoints (resume-safe, v2 contract)
 24. PII-safe: emails reported for AUTHORIZED domain only
 25. No API keys required ( sab public/anonymous endpoints )

SAFETY: zero requests to in-scope targets; sirf public third-party sources
(GET) + DNS resolvers. Out-of-scope discoveries recorded, NEVER tested.
"""
import os, re, json, subprocess, shutil, socket, ipaddress
import concurrent.futures as cf
import urllib.parse as up
from wasp_core import (module_ctx, write_feedforward, write_manifest, save_json, save_text,
                       info, ok, warn, err, head, now_iso, rand_str)
try:
    from wasp_core import HttpClient as _HttpClient  # ULTRA: scope-less 3P client
except Exception:
    _HttpClient = None

NAME = "passive"
PHASE = "3-passive"
ENGINE_VERSION = "3.0.0-ultra"

# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# ===========================================================================
def _rwx_result(path):
    try:
        os.chmod(path, 0o777)
    except Exception:
        pass

_core_save_json, _core_save_text = save_json, save_text


def _rwx_save_json(path, obj):
    _core_save_json(path, obj)
    _rwx_result(path)
    _rwx_result(os.path.dirname(path) or ".")


def _rwx_save_text(path, text):
    _core_save_text(path, text)
    _rwx_result(path)
    _rwx_result(os.path.dirname(path) or ".")


save_json = _rwx_save_json
save_text = _rwx_save_text

_core_write_manifest = write_manifest


def _rwx_tree(root):
    try:
        for _dp, _dn, _fn in os.walk(root):
            _rwx_result(_dp)
            for _n in _fn:
                _rwx_result(os.path.join(_dp, _n))
    except Exception:
        pass


def _rwx_write_manifest(out, *a, **k):
    r = _core_write_manifest(out, *a, **k)
    _rwx_tree(out)
    return r


write_manifest = _rwx_write_manifest
# ======================== end RWX STANDING RULE ============================

# ---------------------------------------------------------------------------
# v2 REGEX/TABLES (preserved)
# ---------------------------------------------------------------------------
INTERESTING_PATH_RE = re.compile(
    r"(?i)/(admin|administrator|api|internal|intranet|debug|test|testing|staging|stage|dev|"
    r"backup|backups|upload|uploads|token|key|keys|secret|graphql|actuator|swagger|openapi|"
    r"\.git|\.svn|\.env|\.aws|\.ssh|phpinfo|console|jenkins|jenkinsfile|\.well-known|"
    r"config|conf|dump|export|private|secure|vpn|portal|dashboard|metrics|health)")
FILE_EXT_RE = re.compile(
    r"(?i)\.(json|xml|sql|bak|backup|old|orig|swp|save|config|conf|env|log|txt|zip|tar|gz|"
    r"tgz|rar|7z|yml|yaml|ini|pem|key|p12|pfx|jks|crt|cer|der|mobileprovision|"
    r"sqlite|db|mdb|rdp|pcap|har|map|js|ts|md|doc|xls|xlsx|pdf)(\?|$)")
SENSITIVE_PARAM_RE = re.compile(
    r"(?i)(token|key|secret|password|passwd|pwd|auth|session|sid|jwt|api_?key|access_?token|"
    r"id|user|account|email|phone|ssn|card|iban|redirect|url|next|return|file|path|dir|"
    r"cmd|exec|debug|admin|role|isadmin)")
JS_URL_RE = re.compile(r"\.m?js(\?|$)", re.I)

# ---------------------------------------------------------------------------
# ULTRA TABLES
# ---------------------------------------------------------------------------
TAKEOVER_FPS = [  # (provider, cname_patterns, takeover_hint)
    ("AWS S3", [r"\.s3\.amazonaws\.com$", r"\.s3-[-a-z0-9]+\.amazonaws\.com$"], "NoSuchBucket -> bucket hijack"),
    ("AWS CloudFront", [r"\.cloudfront\.net$"], "distributed error -> origin claim"),
    ("GCP Storage", [r"\.storage\.googleapis\.com$", r"\.storage\.cloud\.google\.com$"], "404 bucket -> claim"),
    ("Azure CDN", [r"\.azureedge\.net$", r"\.blob\.core\.windows\.net$", r"\.cloudapp\.azure\.com$"], "404/404 no-container -> claim"),
    ("GitHub Pages", [r"\.github\.io$"], "404 'There isn't a GitHub Pages site' -> custom-domain claim"),
    ("Heroku", [r"\.herokuapp\.com$", r"\.herokudns\.com$"], "'No such app' -> claim"),
    ("Shopify", [r"\.myshopify\.com$"], "'Sorry, this shop is unavailable' -> claim"),
    ("Fastly", [r"\.fastly\.net$", r"\.freetls\.fastly\.net$"], "Fastly error: unknown domain"),
    ("Netlify", [r"\.netlify\.app$", r"\.netlify\.com$"], "'Not Found' -> custom-domain claim"),
    ("Vercel", [r"\.vercel\.app$", r"\.now\.sh$"], "DEPLOYMENT_NOT_FOUND"),
    ("Zendesk", [r"\.zendesk\.com$"], "'Help Center Closed' -> claim"),
    ("Surge.sh", [r"\.surge\.sh$"], "project not found -> claim"),
    ("Bitbucket", [r"\.bitbucket\.io$"], "repo gone -> claim"),
    ("Pantheon", [r"\.pantheonsite\.io$"], "'The gods are wise' 404 -> claim"),
    ("Tumblr", [r"\.tumblr\.com$"], "'Whatever you were looking for' -> claim"),
    ("WordPress.com", [r"\.wordpress\.com$"], "'Do you want to register' -> claim"),
    ("Readme.io", [r"\.readme\.io$"], "project not found"),
    ("Teamwork", [r"\.teamwork\.com$"], "site not found"),
    ("HelpJuice", [r"\.helpjuice\.com$"], "subdomain claim"),
    ("Intercom", [r"\.customintercom\.com$", r"\.intercom\.io$"], "page not found"),
]
TAKEOVER_FP_RE = [(p, [re.compile(x, re.I) for x in pats], hint) for p, pats, hint in TAKEOVER_FPS]

PERM_WORDS = ["dev", "development", "stage", "staging", "stg", "test", "testing", "uat", "qa",
              "prod", "production", "demo", "beta", "alpha", "sandbox", "internal", "intranet",
              "corp", "office", "vpn", "mail", "smtp", "webmail", "api", "apis", "app", "apps",
              "admin", "administrator", "portal", "cdn", "static", "assets", "img", "images",
              "media", "files", "download", "downloads", "docs", "doc", "wiki", "help", "support",
              "status", "monitor", "monitoring", "grafana", "kibana", "jenkins", "ci", "git",
              "gitlab", "svn", "jira", "confluence", "old", "new", "legacy", "backup", "bak",
              "db", "sql", "mysql", "postgres", "redis", "cache", "elastic", "es", "k8s",
              "kube", "docker", "registry", "sso", "auth", "oauth", "login", "id", "identity",
              "pay", "payment", "billing", "shop", "store", "m", "mobile", "wap", "partner",
              "partners", "vendor", "vendors", "b2b", "b2c", "crm", "erp", "hr", "cms", "blog",
              "news", "shop", "cloud", "aws", "azure", "gcp", "edge", "lb", "proxy", "gateway"]

FILE_RISK = {  # ext -> (risk, phase handoff)
    "bak": ("HIGH", "P23"), "backup": ("HIGH", "P23"), "old": ("MEDIUM", "P23"),
    "orig": ("MEDIUM", "P23"), "save": ("MEDIUM", "P23"), "swp": ("HIGH", "P23"),
    "sql": ("HIGH", "P23"), "env": ("HIGH", "P23"), "ini": ("MEDIUM", "P23"),
    "conf": ("MEDIUM", "P23"), "config": ("MEDIUM", "P23"), "log": ("MEDIUM", "P23"),
    "pem": ("HIGH", "P23"), "key": ("HIGH", "P23"), "p12": ("HIGH", "P23"),
    "pfx": ("HIGH", "P23"), "jks": ("HIGH", "P23"), "mobileprovision": ("HIGH", "P23"),
    "sqlite": ("HIGH", "P23"), "db": ("HIGH", "P23"), "mdb": ("HIGH", "P23"),
    "zip": ("MEDIUM", "P23"), "tar": ("MEDIUM", "P23"), "gz": ("MEDIUM", "P23"),
    "tgz": ("MEDIUM", "P23"), "rar": ("MEDIUM", "P23"), "7z": ("MEDIUM", "P23"),
    "json": ("LOW", "P23"), "xml": ("LOW", "P23"), "yml": ("MEDIUM", "P23"),
    "yaml": ("MEDIUM", "P23"), "har": ("HIGH", "P23"), "pcap": ("HIGH", "P23"),
}

PARAM_TYPE = [  # (type, regex) - P12 handoff intel
    ("idor_id", r"(?i)^(id|uid|user_?id|account_?id|order_?id|doc_?id|invoice_?id|item_?id|pid|gid)$"),
    ("url_fetch", r"(?i)^(url|uri|link|target|dest|redirect|next|return|callback|feed|image_?url)$"),
    ("file_path", r"(?i)^(file|filename|filepath|path|dir|folder|template|page|include|doc|download|src)$"),
    ("cmd_exec", r"(?i)^(cmd|exec|command|run|shell|process|ping|host|lookup)$"),
    ("auth_token", r"(?i)(token|jwt|session|sid|auth)"),
    ("credential", r"(?i)(password|passwd|pwd|secret|api_?key|access_?key)"),
    ("email", r"(?i)(mail|email)"),
    ("enum", r"(?i)(type|sort|order|filter|view|format|lang|page|limit|offset|category)"),
    ("date", r"(?i)(date|from|to|since|until|start|end|time)"),
    ("debug", r"(?i)(debug|test|verbose|trace|admin)"),
]

SECRET_IN_URL_RE = re.compile(r"(?i)[?&](token|api_?key|apikey|access_?token|auth|jwt|sig|signature|password|passwd|secret)=[^&\s]{4,}")
UUID_RE = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
YEAR_RE = re.compile(r"(?<![\d])(20[0-2]\d)(?![\d])")
CLOUD_URL_RE = re.compile(r"(?i)([a-z0-9\-\.]+)\.(s3[.\-][a-z0-9\-]*amazonaws\.com|"
                          r"blob\.core\.windows\.net|storage\.googleapis\.com|"
                          r"azureedge\.net|r2\.cloudflarestorage\.com)")
WS_URL_RE = re.compile(r"(?i)\bwss?://[^\s\"'<>]{4,120}")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
VERSIONED_API_RE = re.compile(r"(?i)/(?:api/)?v(\d+)(?:/|$)")

DEFAULTS_CFG = {
    "passive_perm_max": 600,        # ULTRA: permutation candidates cap
    "passive_resolve_max": 3000,    # resolve cap (safety)
    "passive_axfr": False,          # zone transfer OFF by default (active-ish)
}

# ---------------------------------------------------------------------------
# v2 CORE FUNCS (preserved)
# ---------------------------------------------------------------------------
def have(t):
    return shutil.which(t) is not None


def shell(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired:
        warn("timeout: %s" % cmd[:70])
        return ""
    except Exception as e:
        warn("cmd error (%s): %s" % (cmd[:40], e))
        return ""


# ---------------------------------------------------------------------------
# SOURCES (v2 preserved)
# ---------------------------------------------------------------------------
def crtsh(domain, http):
    """CT logs via crt.sh JSON - 3 retries, wildcard + apex queries."""
    names = set()
    for tmpl in ("https://crt.sh/?q=%25.{d}&output=json", "https://crt.sh/?q={d}&output=json"):
        for attempt in range(3):
            r = http.request("GET", tmpl.format(d=domain), allow_redirects=True, retries=1)
            if r.error:
                continue
            try:
                data = json.loads(r.text)
            except Exception:
                warn("crt.sh non-JSON (attempt %d) - retrying" % (attempt + 1))
                continue
            if not isinstance(data, list):
                continue
            for row in data:
                if not isinstance(row, dict):
                    continue
                for field in ("name_value", "common_name"):
                    for n in str(row.get(field, "")).split("\n"):
                        n = n.strip().lower().lstrip("*.").strip(".")
                        if n.endswith("." + domain) or n == domain:
                            names.add(n)
            if names:
                return names
    return names


def certspotter(domain, http):
    names = set()
    r = http.request("GET", "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names" % domain)
    if r.error or not r.text.strip().startswith("["):
        return names
    try:
        for row in json.loads(r.text):
            for n in row.get("dns_names", []):
                n = n.strip().lower().lstrip("*.").strip(".")
                if n.endswith("." + domain):
                    names.add(n)
    except Exception:
        pass
    return names


def hackertarget(domain, http):
    names = set()
    r = http.request("GET", "https://api.hackertarget.com/hostsearch/?q=%s" % domain)
    if r.error:
        return names
    for line in r.text.splitlines():
        h = line.split(",")[0].strip().lower()
        if h.endswith("." + domain) or h == domain:
            names.add(h)
    return names


# ---------------------------------------------------------------------------
# ULTRA SOURCES (GET-only public APIs, graceful, no keys)
# ---------------------------------------------------------------------------
def otx_passive(domain, http):
    """AlienVault OTX: passive DNS + URL list."""
    names, urls = set(), set()
    r = http.request("GET", "https://otx.alienvault.com/api/v1/indicator/domain/%s/passive_dns" % domain,
                     allow_redirects=True, retries=1)
    if not r.error:
        try:
            for row in (json.loads(r.text).get("passive_dns") or []):
                h = str(row.get("hostname") or "").lower().lstrip("*.").strip(".")
                if h == domain or h.endswith("." + domain):
                    names.add(h)
        except Exception:
            pass
    r2 = http.request("GET", "https://otx.alienvault.com/api/v1/indicator/domain/%s/url_list?limit=200" % domain,
                      allow_redirects=True, retries=1)
    if not r2.error:
        try:
            for row in (json.loads(r2.text).get("url_list") or []):
                u = str(row.get("url") or "").strip()
                if u.startswith("http"):
                    urls.add(u)
        except Exception:
            pass
    return names, urls


def urlscan_search(domain, http):
    """URLScan.io public search -> names + urls."""
    names, urls = set(), set()
    r = http.request("GET", "https://urlscan.io/api/v1/search/?q=domain%%3A%s&size=200" % domain,
                     allow_redirects=True, retries=1)
    if r.error:
        return names, urls
    try:
        for row in (json.loads(r.text).get("results") or []):
            pg = row.get("page") or {}
            h = str(pg.get("domain") or "").lower()
            if h == domain or h.endswith("." + domain):
                names.add(h)
            u = str(pg.get("url") or "").strip()
            if u.startswith("http"):
                urls.add(u)
    except Exception:
        pass
    return names, urls


def rapiddns(domain, http):
    names = set()
    r = http.request("GET", "https://rapiddns.io/subdomain/%s?full=1" % domain,
                     allow_redirects=True, retries=1)
    if r.error:
        return names
    for m in re.finditer(r"([a-z0-9_.\-]+\.%s)\b" % re.escape(domain), (r.text or "").lower()):
        names.add(m.group(1).strip("."))
    return names


def anubis(domain, http):
    names = set()
    r = http.request("GET", "https://jldc.me/anubis/subdomains/%s" % domain,
                     allow_redirects=True, retries=1)
    if r.error:
        return names
    try:
        # ULTRA: saare names lo - add()/filter_hosts in-scope vs OOS classify karega
        # (cross-domain takeover candidates miss na ho; OOS kabhi test nahi hota)
        for n in json.loads(r.text):
            n = str(n).lower().lstrip("*.").strip(".")
            if n and "." in n:
                names.add(n)
    except Exception:
        pass
    return names


TOOLS = [  # v2 preserved
    ("subfinder", "subfinder -d {d} -all -recursive -silent", 900),
    ("assetfinder", "assetfinder --subs-only {d}", 300),
    ("amass", "timeout 600 amass enum -passive -d {d}", 700),
    ("findomain", "findomain -t {d} -q", 300),
]


def resolve(hosts, cfg):
    """Resolve hosts -> [(host, ip)] using dnspython (multi-resolver) else socket. (v2)"""
    resolved = set()
    hosts = sorted(set(hosts))
    if not hosts:
        return []
    try:
        import dns.resolver  # noqa

        def one(h):
            out = []
            for rtype in ("A", "AAAA"):
                try:
                    res = dns.resolver.Resolver(configure=False)
                    res.nameservers = list(getattr(cfg, "resolvers", ["1.1.1.1", "8.8.8.8"]))
                    res.lifetime = 6
                    for a in res.resolve(h, rtype):
                        out.append((h, a.address))
                except Exception:
                    continue
            return out
    except ImportError:
        warn("dnspython missing -> socket fallback (sudo apt install python3-dnspython)")

        def one(h):
            try:
                return [(h, socket.gethostbyname(h))]
            except Exception:
                return []
    with cf.ThreadPoolExecutor(max_workers=max(4, int(getattr(cfg, "concurrency", 8)))) as ex:
        for chunk in ex.map(one, hosts):
            resolved.update(chunk)
    return sorted(resolved)


# ---------------------------------------------------------------------------
# ULTRA: DNS intel (CNAME takeover + zone records) - resolver-only, passive
# ---------------------------------------------------------------------------
def _dns_query(h, rtype, resolvers):
    try:
        import dns.resolver
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = list(resolvers or ["1.1.1.1", "8.8.8.8"])
        res.lifetime = 5
        return [str(a).rstrip(".").lower() for a in res.resolve(h, rtype)]
    except Exception:
        return []


def cname_takeover_scan(hosts, cfg, cap=800):
    """ULTRA: CNAME records + takeover fingerprint (DNS-only, koi HTTP nahi)."""
    resolvers = list(getattr(cfg, "resolvers", ["1.1.1.1", "8.8.8.8"]))
    out, checked = [], 0
    for h in sorted(hosts)[:cap]:
        checked += 1
        for cname in _dns_query(h, "CNAME", resolvers):
            prov, hint = None, None
            for p, regs, h2 in TAKEOVER_FP_RE:
                if any(r.search(cname) for r in regs):
                    prov, hint = p, h2
                    break
            out.append({"host": h, "cname": cname, "provider": prov,
                        "takeover_hint": hint if prov else None})
    return out, checked


def dns_zone_intel(domain, cfg):
    """ULTRA: MX/NS/TXT/SPF/DMARC/DKIM -> email-spoofing surface."""
    resolvers = list(getattr(cfg, "resolvers", ["1.1.1.1", "8.8.8.8"]))
    rec = {"domain": domain}
    for rtype in ("MX", "NS"):
        rec[rtype.lower()] = _dns_query(domain, rtype, resolvers)[:15]
    txt = _dns_query(domain, "TXT", resolvers)
    rec["txt"] = txt[:20]
    rec["spf"] = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = _dns_query("_dmarc." + domain, "TXT", resolvers)
    rec["dmarc"] = [t for t in dmarc if "v=DMARC1" in t]
    rec["dmarc_policy"] = None
    if rec["dmarc"]:
        m = re.search(r"p=(\w+)", rec["dmarc"][0])
        rec["dmarc_policy"] = m.group(1).lower() if m else None
    dkim = _dns_query("default._domainkey." + domain, "TXT", resolvers) or \
        _dns_query("selector1._domainkey." + domain, "TXT", resolvers)
    rec["dkim_found"] = bool(dkim)
    return rec


def email_spoof_report(zone):
    """ULTRA: SPF/DMARC se spoofing surface (guidance, sirf authorized domain)."""
    lines, risks = [], []
    if not zone.get("spf"):
        risks.append("SPF record MISSING -> koi bhi domain ke naam se email bhej sakta hai (spoofing)")
    elif "all" in str(zone["spf"][0]) and "?all" in str(zone["spf"][0]):
        risks.append("SPF ~soft ?all -> weak enforcement")
    if not zone.get("dmarc"):
        risks.append("DMARC MISSING -> SPF/DKIM fail hone par bhi koi policy nahi")
    elif zone.get("dmarc_policy") in (None, "none"):
        risks.append("DMARC p=none -> monitor-only, spoofing block nahi hota")
    if not zone.get("dkim_found"):
        risks.append("DKIM (default/selector1) nahi mila -> signing verify weak ho sakta hai")
    for mx in zone.get("mx", [])[:3]:
        lines.append("MX: %s" % mx)
    lines.append("")
    lines += ["[RISK] %s" % r for r in risks] or ["koi major email-spoofing issue nahi mila"]
    lines.append("")
    lines.append("Test guidance (AUTHORIZED engagement only):")
    lines.append("- spoof test: apne test mailbox se From: <exec@%s> bhejo, inbox me aaya to p=none" % zone["domain"])
    lines.append("- har finding ko manual verify karo - ye DNS-level hint hai, CONFIRMED nahi")
    return "\n".join(lines), risks


def perm_candidates(domain, cap=600):
    """ULTRA: deterministic subdomain permutations (passive wordlist guessing)."""
    base = domain.split(".", 1)[0] if domain.count(".") > 1 else domain
    slugs = ["", "-", "2", "-old", "-new", "-dev", "-test", "-api"]
    out = []
    for w in PERM_WORDS:
        for s in slugs:
            out.append("%s%s.%s" % (w, s, domain))
            if len(out) >= cap:
                return out
    return out[:cap]


def whois_ips(ips):
    """ULTRA: whois CLI (optional) -> org/ASN hints per unique IP."""
    if not have("whois"):
        return {}
    out = {}
    for ip in sorted(ips)[:12]:
        txt = shell("whois %s" % ip, timeout=20)
        org = re.search(r"(?im)^(?:orgname|org-name|owner|netname)\s*:\s*(.+)$", txt)
        asn = re.search(r"(?im)^origin(?:as)?\s*:\s*(AS\d+)", txt)
        out[ip] = {"org": (org.group(1).strip() if org else None),
                   "asn": (asn.group(1) if asn else None)}
    return out

# ---------------------------------------------------------------------------
# URL MINING - v2 preserved + ULTRA intel
# ---------------------------------------------------------------------------
def mine_urls(allurl, out):
    """Turn a raw URL pile into testable artefacts. (v2 contract + findings/* names)"""
    fd = os.path.join(out, "findings")
    os.makedirs(fd, exist_ok=True)
    with_params = sorted(u for u in allurl if "=" in u)
    files = sorted(u for u in allurl if FILE_EXT_RE.search(u))
    paths = sorted(u for u in allurl if INTERESTING_PATH_RE.search(u))
    js = sorted(u for u in allurl if JS_URL_RE.search(u))
    params = sorted(set(re.findall(r"[?&]([A-Za-z0-9_\[\]]+)=", "\n".join(allurl))))
    sensitive_params = sorted(p for p in params if SENSITIVE_PARAM_RE.search(p))
    endpoints = sorted(set(re.sub(r"\?.*$", "", u) for u in allurl))
    api_like = sorted(e for e in endpoints if re.search(r"(?i)/(api|v\d+|rest|graphql|rpc|json|xml)", e))

    save_text(os.path.join(fd, "urls_with_params.txt"), "\n".join(with_params))
    save_text(os.path.join(fd, "interesting_files.txt"), "\n".join(files))
    save_text(os.path.join(fd, "interesting_paths.txt"), "\n".join(paths))
    save_text(os.path.join(fd, "js_urls.txt"), "\n".join(js))
    save_text(os.path.join(fd, "param_names.txt"), "\n".join(params))
    save_text(os.path.join(fd, "sensitive_params.txt"), "\n".join(sensitive_params))
    save_text(os.path.join(fd, "endpoints.txt"), "\n".join(endpoints))
    save_text(os.path.join(fd, "api_like.txt"), "\n".join(api_like))

    # wordlist seeds (dirs) for phase 5
    dirs = sorted(set(re.sub(r"[^/]*$", "", u.split("?")[0]) for u in allurl))
    segs = sorted(set(s for d in dirs for s in d.strip("/").split("/") if s and len(s) < 40))
    save_text(os.path.join(fd, "dir_seeds.txt"), "\n".join(segs))

    # ---------------- ULTRA mining layer ----------------
    param_types = {}
    for p in params:
        for t, pat in PARAM_TYPE:
            if re.search(pat, p):
                param_types.setdefault(t, []).append(p)
                break
    save_json(os.path.join(fd, "param_types.json"), param_types)

    idor_urls = sorted(u for u in allurl if UUID_RE.search(u) or
                       re.search(r"[?&](?:id|uid|user_?id|account_?id|order_?id)=\d+", u, re.I))
    save_text(os.path.join(fd, "idor_candidate_urls.txt"), "\n".join(idor_urls))

    secret_urls = sorted(u for u in allurl if SECRET_IN_URL_RE.search(u))
    save_text(os.path.join(fd, "secrets_in_urls.txt"), "\n".join(secret_urls))

    ver_map = {}
    for e in api_like:
        m = VERSIONED_API_RE.search(e)
        if m:
            ver_map.setdefault("v" + m.group(1), []).append(e)
    vers = sorted(ver_map.keys(), key=lambda v: int(v[1:]))
    legacy = vers[:-1] if len(vers) > 1 else []
    save_json(os.path.join(fd, "api_version_matrix.json"),
              {"versions": vers, "legacy": legacy,
               "endpoints": {v: es[:40] for v, es in sorted(ver_map.items())}})
    save_text(os.path.join(fd, "api_version_matrix.txt"),
              "\n".join("%s -> %d endpoints%s" % (v, len(ver_map[v]),
                      "  [LEGACY branch - forgotten guards]" if v in legacy else "")
                      for v in vers))

    emails = sorted({e.lower() for u in allurl for e in EMAIL_RE.findall(u)
                     if any(e.lower().endswith("." + d) or e.lower().endswith("@" + d)
                            for d in _url_domains(allurl))})[:60]
    save_text(os.path.join(fd, "emails.txt"), "\n".join(emails))

    ws = sorted(set(WS_URL_RE.findall("\n".join(allurl))))
    save_text(os.path.join(fd, "websockets.txt"), "\n".join(ws))

    cloud = {}
    for u in allurl:
        for m in CLOUD_URL_RE.finditer(u):
            cloud.setdefault(m.group(2).lower(), set()).add(m.group(1).lower())
    save_json(os.path.join(fd, "cloud_assets.json"), {k: sorted(v) for k, v in cloud.items()})

    risk_files = {}
    for u in files:
        m = FILE_EXT_RE.search(u)
        if m:
            ext = m.group(1).lower()
            risk_files.setdefault(FILE_RISK.get(ext, ("LOW", "P23"))[0], []).append(u)
    save_text(os.path.join(fd, "high_risk_files.txt"),
              "\n".join(sorted(risk_files.get("HIGH", []))))

    scores = sorted(((juicy_score(u), u) for u in allurl), reverse=True)
    save_text(os.path.join(fd, "juicy_urls_top.txt"),
              "\n".join("%3d %s" % (s, u) for s, u in scores[:50]))

    years = {}
    for u in allurl:
        for y in YEAR_RE.findall(u):
            years[y] = years.get(y, 0) + 1
    dormancy = {"year_histogram": dict(sorted(years.items())),
                "oldest": min(years) if years else None,
                "newest": max(years) if years else None,
                "stale_share_pct": round(100.0 * sum(v for k, v in years.items()
                                                     if k < "2022") / max(1, sum(years.values())), 1)}
    save_json(os.path.join(fd, "dormancy.json"), dormancy)

    sectxt = sorted(u for u in allurl if u.rstrip("/").endswith("/.well-known/security.txt"))
    save_text(os.path.join(fd, "security_txt.txt"), "\n".join(sectxt))

    return {"with_params": len(with_params), "files": len(files), "paths": len(paths),
            "js": len(js), "params": len(params), "sensitive_params": len(sensitive_params),
            "endpoints": len(endpoints), "api_like": len(api_like), "dir_seeds": len(segs),
            "idor_urls": len(idor_urls), "secret_urls": len(secret_urls),
            "api_versions": len(vers), "legacy_versions": len(legacy),
            "emails": len(emails), "websockets": len(ws), "cloud_assets": len(cloud),
            "high_risk_files": len(risk_files.get("HIGH", []))}


def _url_domains(allurl):
    doms = set()
    for u in allurl[:2000]:
        h = up.urlsplit(u).hostname
        if h:
            parts = h.split(".")
            if len(parts) >= 2:
                doms.add(".".join(parts[-2:]))
    return doms


def juicy_score(u):
    """ULTRA: 0-100 juicy URL score (explainable-ish)."""
    s = 0
    low = u.lower()
    for pat, pts in ((r"(?i)/admin", 30), (r"(?i)login|signin|sso|oauth", 22),
                     (r"(?i)token|jwt|session", 20), (r"(?i)api|graphql|rest", 14),
                     (r"(?i)debug|test|staging|dev\.", 18), (r"(?i)upload|export|download", 15),
                     (r"(?i)backup|dump|\.sql|\.bak", 25), (r"(?i)\.env|\.git|\.svn", 30),
                     (r"(?i)config|conf\b", 12), (r"(?i)invoice|order|billing|payment", 16),
                     (r"(?i)user|account|profile", 10), (r"\?", 4)):
        if re.search(pat, low):
            s += pts
    if SECRET_IN_URL_RE.search(low):
        s += 20
    if FILE_EXT_RE.search(low):
        s += 6
    return min(100, s)


def build_dorks(domain, out):
    """ULTRA: manual-run dork builder (koi query network par NAHI jaati)."""
    g = [
        'site:%s -www -www.%s' % (domain, domain),
        'site:%s inurl:admin' % domain,
        'site:%s inurl:(login|signin|auth)' % domain,
        'site:%s ext:(env|conf|config|ini|bak|backup|old|sql|log)' % domain,
        'site:%s intitle:"index of"' % domain,
        'site:%s inurl:(api|v1|v2|graphql)' % domain,
        'site:%s inurl:token|inurl:key|inurl:secret' % domain,
        'site:%s intitle:(dashboard|portal|internal)' % domain,
        'site:%s filetype:(pdf|xlsx|docx) (confidential|internal|draft)' % domain,
        'site:%s inurl:/(.well-known|security.txt)' % domain,
    ]
    gh = [
        '"%s" password' % domain,
        '"%s" api_key OR apikey OR api-key' % domain,
        '"%s" secret OR token OR bearer' % domain,
        '"%s.%s" jdbc OR mysql OR postgres OR mongodb' % (domain.split(".")[0], domain.split(".")[-1]),
        '"%s" s3.amazonaws.com OR blob.core.windows.net' % domain,
        'filename:.env "%s"' % domain,
        'filename:settings.py "%s" SECRET' % domain,
        '"%s" Authorization: Bearer' % domain,
        '"%s" smtp OR sendgrid OR mailgun OR twilio' % domain,
        'path:*.pem "%s"' % domain,
    ]
    sh = [
        'hostname:%s' % domain,
        'ssl.cert.subject.CN:"%s"' % domain,
        'ssl:%s' % domain,
        'org:"%s"' % domain.split(".")[0],
        'http.title:"%s"' % domain.split(".")[0],
        'port:"6379" hostname:%s' % domain,
        'product:"Elasticsearch" hostname:%s' % domain,
    ]
    save_text(os.path.join(out, "google_dorks.txt"),
              "# Manual browser run (RoE-compliant) - engine ne koi query NAHI bheji\n" + "\n".join(g))
    save_text(os.path.join(out, "github_dorks.txt"),
              "# github.com/search?q=... (login required) - gh CLI ya browser se chalao\n" + "\n".join(gh))
    save_text(os.path.join(out, "shodan_queries.txt"),
              "# shodan.io search - API key ke saath manual chalao\n" + "\n".join(sh))
    return {"google": len(g), "github": len(gh), "shodan": len(sh)}


def _load_prev(out):
    p = os.path.join(out, "passive.json")
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception:
            return None
    return None


def _diff_subs(prev, ins, urls):
    if not prev or not isinstance(prev, dict):
        return None
    old_subs = set(prev.get("subdomains") or [])
    d = {"generated_at": now_iso(),
         "new_subs": sorted(set(ins) - old_subs),
         "gone_subs": sorted(old_subs - set(ins)),
         "old_urls": prev.get("urls")}
    return d if (d["new_subs"] or d["gone_subs"] or d["old_urls"] != urls) else \
        {"generated_at": now_iso(), "note": "no changes"}


# ---------------------------------------------------------------------------
# RUN - v2 flow preserved + ULTRA sources/stages/outputs
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    head("Phase 3 - Passive Reconnaissance (ULTRA PRO MAX) | %s" % scope.describe())
    # ULTRA: third-party passive queries ke liye SCOPE-LESS client (crt.sh/OTX/CDX
    # target scope ke bahar hain). module_ctx ka client target-scope firewall ke
    # saath aata hai - wo in-scope target requests ke liye hai (passive me unused).
    http3p = None
    try:
        if _HttpClient is not None:
            http3p = _HttpClient(cfg, None, None, label="passive-3p")
    except Exception:
        http3p = None
    if http3p is None:
        http3p = http  # v2 degrade: scope-attached client (CDX call wrapped below)
    domain = (scope.root_domains() or [None])[0]
    if not domain:
        err("scope.json me koi root domain nahi hai (sirf IP targets?) -> passive subdomain stage skip.")
        warn("IP-only scope ke liye Phase 4 (active) aur Phase 5 (content) direct chalenge.")
        write_feedforward(out, "3-passive", {"skipped": "no root domain in scope"})
        _rwx_tree(out)  # RWX RULE: jitna bana, sab rwx
        return out
    info("Root domain: %s" % domain)

    subs, oos_subs = {}, {}

    def add(name, src):
        name = (name or "").strip().lower().lstrip("*.").strip(".")
        if not name:
            return
        if name == domain or name.endswith("." + domain):
            subs.setdefault(name, set()).add(src)
        else:
            # ULTRA: out-of-scope discoveries record karo (kabhi test nahi honge)
            oos_subs.setdefault(name, set()).add(src)

    # ---- 1. HTTP-based passive sources (each checkpointed) - v2 + ULTRA ----
    http_sources = [("crtsh", lambda: crtsh(domain, http3p), None),
                    ("certspotter", lambda: certspotter(domain, http3p), None),
                    ("hackertarget", lambda: hackertarget(domain, http3p), None),
                    ("otx", lambda: otx_passive(domain, http3p), "urls"),
                    ("urlscan", lambda: urlscan_search(domain, http3p), "urls"),
                    ("rapiddns", lambda: rapiddns(domain, http3p), None),
                    ("anubis", lambda: anubis(domain, http3p), None)]
    archived_extra = set()
    for src, fn, extra in http_sources:
        ck = "src:" + src
        if cp.is_done(ck):
            res = cp.result_of(ck) or {}
            for n in (res.get("names") if isinstance(res, dict) else res) or []:
                add(n, src)
            if isinstance(res, dict) and res.get("urls"):
                archived_extra.update(res["urls"])
            ok("%-14s -> SKIP (checkpoint)" % src)
            continue
        info("%-14s query..." % src)
        try:
            got = fn()
            if isinstance(got, tuple):
                names, urls = got
                archived_extra.update(urls)
                payload = {"names": sorted(names), "urls": sorted(urls)}
            else:
                names, payload = got, {"names": sorted(got)}
        except Exception as e:
            warn("%s failed: %s" % (src, e))
            names, payload = set(), {"names": []}
        for n in names:
            add(n, src)
        cp.mark(ck, payload, summary=src)
        ok("%-14s -> %d names%s" % (src, len(names),
                                    " + %d urls" % len(payload.get("urls") or []) if payload.get("urls") else ""))

    # ---- 2. CLI tools (each checkpointed) - v2 preserved ----
    for tool, tmpl, tmo in TOOLS:
        ck = "src:" + tool
        if not have(tool):
            warn("%-14s MISSING -> skip (optional; install for more coverage)" % tool)
            continue
        if cp.is_done(ck):
            for n in (cp.result_of(ck) or []):
                add(n, tool)
            ok("%-14s -> SKIP (checkpoint)" % tool)
            continue
        info("%-14s running..." % tool)
        outp = shell(tmpl.format(d=domain), timeout=tmo)
        got = []
        for m in re.finditer(r"([a-z0-9_.\-]+\." + re.escape(domain) + r")\b", outp, re.I):
            nm = m.group(1).lower().rstrip(".")
            got.append(nm)
            add(nm, tool)
        cp.mark(ck, sorted(set(got)), summary=tool)
        ok("%-14s -> %d matches" % (tool, len(set(got))))

    ins, outs = scope.filter_hosts(sorted(subs))
    outs = sorted(set(outs or []) | set(oos_subs))  # ULTRA: oos discoveries merged
    save_text(os.path.join(out, "all_subs.txt"), "\n".join(ins))
    if outs:
        save_text(os.path.join(out, "out_of_scope_subs.txt"), "\n".join(outs))
        warn("%d discovered hosts OUT-OF-SCOPE -> recorded, NEVER tested" % len(outs))
    ok("all_subs.txt -> %d unique in-scope subdomains" % len(ins))
    if not ins:
        warn("No subdomains found. Subfinder API keys set karo: ~/.config/subfinder/provider-config.yaml")

    # ---- 2b. ULTRA: permutation candidates -> resolve -> confirmed ----
    perm_max = int(getattr(cfg, "passive_perm_max", 600) or 600)
    cands = [c for c in perm_candidates(domain, perm_max) if c not in subs]
    confirmed = []
    if cands:
        info("ULTRA permutations: %d candidates resolve..." % len(cands))
        res_c = resolve(cands, cfg)
        confirmed = sorted({h for h, _ in res_c if h not in subs})
        for n in confirmed:
            add(n, "perm+resolve")
        save_text(os.path.join(out, "perm_candidates.txt"), "\n".join(cands))
        save_text(os.path.join(out, "perm_confirmed.txt"), "\n".join(confirmed))
        ok("permutations -> %d confirmed extras" % len(confirmed))
        ins2, outs2 = scope.filter_hosts(confirmed)
        ins = sorted(set(ins) | set(ins2))
        if outs2:
            outs = sorted(set(outs or []) | set(outs2))
            save_text(os.path.join(out, "out_of_scope_subs.txt"), "\n".join(outs))

    # ---- 3. Resolution (v2) ----
    info("DNS resolution (multi-resolver)...")
    res_cap = int(getattr(cfg, "passive_resolve_max", 3000) or 3000)
    resolved = resolve(ins[:res_cap], cfg)
    save_text(os.path.join(out, "resolved.txt"),
              "\n".join("%s [%s]" % (h, ip) for h, ip in resolved))
    ips = sorted(set(ip for _, ip in resolved))
    save_text(os.path.join(out, "ips.txt"), "\n".join(ips))
    ok("resolved -> %d host/ip pairs | unique IPs -> %d" % (len(resolved), len(ips)))

    # ---- 3b. ULTRA: shared-IP vhost candidates + whois hints ----
    ip_map = {}
    for h, ip in resolved:
        ip_map.setdefault(ip, []).append(h)
    shared = {ip: hosts for ip, hosts in ip_map.items() if len(hosts) > 1}
    save_json(os.path.join(out, "shared_ips.json"), shared)
    if shared:
        warn("ULTRA: %d shared IPs -> P4 vhost discovery ke liye candidates" % len(shared))
    whois_info = whois_ips(ips)
    if whois_info:
        save_json(os.path.join(out, "whois_hints.json"), whois_info)

    # ---- 3c. ULTRA: CNAME takeover + DNS zone intel ----
    tk, tk_checked = [], 0
    try:
        tk, tk_checked = cname_takeover_scan(ins, cfg)
        save_json(os.path.join(out, "cname_records.json"), tk)
        tk_hits = [r for r in tk if r.get("provider")]
        save_text(os.path.join(out, "takeover_candidates.txt"),
                  "\n".join("%s -> %s (%s) [%s]" % (r["host"], r["cname"], r["provider"],
                                                    r["takeover_hint"]) for r in tk_hits))
        if tk_hits:
            warn("ULTRA takeover candidates: %d (DNS-only hint - verify manually)" % len(tk_hits))
    except Exception as e:
        warn("CNAME scan skipped: %s" % e)
    try:
        zone = dns_zone_intel(domain, cfg)
        save_json(os.path.join(out, "dns_records.json"), zone)
        report, risks = email_spoof_report(zone)
        save_text(os.path.join(out, "email_spoofing.txt"), report)
        if risks:
            warn("email-spoofing surface: %d risks" % len(risks))
    except Exception as e:
        warn("DNS zone intel skipped: %s" % e)

    # ---- 4. Archived URLs (v2 + ULTRA extras merge) ----
    ck = "stage:archives"
    if cp.is_done(ck):
        allurl = sorted(set(cp.result_of(ck) or []))
        ok("archived URLs -> %d (SKIP checkpoint)" % len(allurl))
    else:
        info("Archived URLs (waybackurls + gau + CDX API)...")
        arch = set()
        if have("waybackurls"):
            for line in shell("waybackurls %s" % domain, timeout=600).splitlines():
                if line.strip().startswith("http"):
                    arch.add(line.strip())
        if have("gau"):
            got = shell("gau --subs %s" % domain, timeout=600)
            if not got.strip():
                got = shell("gau --subs --providers wayback,otx,commoncrawl %s" % domain, timeout=600)
            for line in got.splitlines():
                if line.strip().startswith("http"):
                    arch.add(line.strip())
        if not arch:
            warn("archive CLI tools empty -> Wayback CDX API fallback")
            cdx = ("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text"
                   "&fl=original&collapse=urlkey" % domain)
            try:
                r = http3p.request("GET", cdx, allow_redirects=True)
                if not r.error:
                    for line in r.text.splitlines():
                        if line.strip().startswith("http"):
                            arch.add(line.strip())
            except Exception as e:
                warn("CDX fallback failed (graceful): %s" % str(e)[:120])
        arch.update(archived_extra)
        allurl = sorted(arch)
        cp.mark(ck, allurl, summary="archives")
        ok("archived URLs -> %d" % len(allurl))

    inscope_urls = [u for u in allurl if scope.check_url(u, raise_on_fail=False)]
    dropped = len(allurl) - len(inscope_urls)
    if dropped:
        warn("%d archived URLs dropped (out-of-scope host)" % dropped)
    save_text(os.path.join(out, "all_urls.txt"), "\n".join(inscope_urls))

    mining = mine_urls(inscope_urls, out)
    ok("mining: params=%d (sensitive=%d) files=%d paths=%d js=%d endpoints=%d api=%d | "
       "ULTRA: idor=%d secret_urls=%d versions=%d(legacy=%d) emails=%d cloud=%d"
       % (mining["with_params"], mining["sensitive_params"], mining["files"],
          mining["paths"], mining["js"], mining["endpoints"], mining["api_like"],
          mining["idor_urls"], mining["secret_urls"], mining["api_versions"],
          mining["legacy_versions"], mining["emails"], mining["cloud_assets"]))

    # ---- 4b. ULTRA: dorks + summary ----
    dorks = build_dorks(domain, out)

    save_json(os.path.join(out, "passive.json"), {
        "phase": "3-passive", "generated_at": now_iso(), "domain": domain,
        "engine_version": ENGINE_VERSION,
        "subdomains": ins, "out_of_scope": outs,
        "sources": {k: sorted(v) for k, v in subs.items()},
        "resolved": resolved, "ips": ips, "urls": len(inscope_urls), "mining": mining,
        "shared_ips": shared, "takeover_candidates": [r for r in tk if r.get("provider")],
        "whois": whois_info, "dorks": dorks,
    })

    d = _diff_subs(_load_prev(out), ins, len(inscope_urls))
    if d:
        save_json(os.path.join(out, "passive_diff.json"), d)

    ff = write_feedforward(out, "3-passive", {
        "to_phase4_active": {"resolved": "resolved.txt", "ips": "ips.txt",
                             "shared_ips": "shared_ips.json"},
        "to_phase5_content": {"dir_seeds": "findings/dir_seeds.txt",
                              "js_urls": "findings/js_urls.txt",
                              "endpoints": "findings/endpoints.txt"},
        "to_phase6_tech": {"api_like": "findings/api_like.txt"},
        "to_phase7_js": {"js_urls": "findings/js_urls.txt"},
        "to_phase8_surface": {"juicy_urls": "findings/juicy_urls_top.txt",
                              "api_version_matrix": "findings/api_version_matrix.txt"},
        "to_phase11_idor": {"idor_candidate_urls": "findings/idor_candidate_urls.txt"},
        "to_phase12_params": {"params": "findings/param_names.txt",
                              "param_types": "findings/param_types.json",
                              "sensitive": "findings/sensitive_params.txt",
                              "urls_with_params": "findings/urls_with_params.txt"},
        "to_phase13_injection": {"urls_with_params": "findings/urls_with_params.txt",
                                 "param_types": "findings/param_types.json"},
        "to_phase15_ssrf_traversal": {"sensitive_params": "findings/sensitive_params.txt",
                                      "url_params": "findings/param_types.json"},
        "to_phase23_secrets": {"interesting_files": "findings/interesting_files.txt",
                               "high_risk_files": "findings/high_risk_files.txt",
                               "secrets_in_urls": "findings/secrets_in_urls.txt"},
        "to_phase24_cloud": {"cloud_assets": "findings/cloud_assets.json",
                             "takeover_candidates": "takeover_candidates.txt"},
        "to_phase25_email": {"email_spoofing": "email_spoofing.txt",
                             "dns_records": "dns_records.json"},
        "to_phase32_report": {"subdomains": len(ins), "urls": len(inscope_urls),
                              "takeover_hints": len([r for r in tk if r.get("provider")])},
    }, notes=["passive only - no active request was made to the target",
              "dorks are MANUAL-RUN guidance, engine ne koi search query nahi bheji",
              "Layer 4: GET-only third-party queries; in-scope targets untouched"])

    write_manifest(out, "3-passive",
                   ["all_subs.txt", "out_of_scope_subs.txt", "perm_candidates.txt",
                    "perm_confirmed.txt", "resolved.txt", "ips.txt", "shared_ips.json",
                    "whois_hints.json", "cname_records.json", "takeover_candidates.txt",
                    "dns_records.json", "email_spoofing.txt", "all_urls.txt",
                    "passive.json", "passive_diff.json", "findings/*.txt",
                    "findings/*.json", "google_dorks.txt", "github_dorks.txt",
                    "shodan_queries.txt", "feedforward.json"],
                   stats={"subdomains": len(ins), "resolved": len(resolved),
                          "ips": len(ips), "urls": len(inscope_urls),
                          "perm_confirmed": len(confirmed),
                          "takeover_hints": len([r for r in tk if r.get("provider")]),
                          "engine": ENGINE_VERSION, **mining})

    head("Phase 3 complete (ULTRA PRO MAX)")
    ok("all_subs.txt | resolved.txt | ips.txt | all_urls.txt | findings/* | passive.json "
       "| +13 ULTRA outputs | dorks(3)")
    return out
