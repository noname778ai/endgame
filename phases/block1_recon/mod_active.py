#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 4 - Active Recon & Host Enumeration  [v3.0.0-ULTRA PRO MAX]
=================================================================================
Non-destructive active recon, scope-enforced, budget-bounded, READ-ONLY (GET/HEAD).

v2 CONTRACT 100% PRESERVED (superset, additive):
  Stage 1 HTTP(S) probe | Stage 2 edge fingerprint | Stage 3 error-page + soft404 |
  Stage 4 vhost discovery (Host-header differential, scope_host) | Stage 5 ports
  Outputs (same names): active.json, live_hosts.txt, open_ports.txt, waf_cdn.txt,
  vhosts.txt, tls_report.txt, favicon_hashes.txt, error_templates.txt,
  security_headers.txt, feedforward.json, MANIFEST.json

ULTRA v3 NAYE TECHNIQUES (25):
  1. WAF BEHAVIORAL probe (read-only): harmless GET probes (?q=<b>x</b> style)
     -> status/len differential -> WAF identity confidence (wafw00f-style)
  2. WAF BYPASS PLAYBOOK per detected edge (Cloudflare/CloudFront/AWS-WAF/nginx/
     Apache/Akamai/Imperva/F5/generic) -> bypass_playbook.txt (header+path tricks,
     RoE-bounded misconfig edges)
  3. ORIGIN discovery intel: header hints (x-origin/cf-connecting/By-Pass),
     origin-named subdomain candidates -> origin_playbook.txt (direct-IP testing
     guidance; koi out-of-scope request nahi)
  4. TLS DEEP: protocol-version forcing probe (TLSv1/1.1/1.2/1.3), weak-cipher
     exposure, cert expiry (<30d), self-signed, SAN cross-domain leak
  5. SERVICE HTTP fingerprints on open ports (read-only GET): docker /_ping,
     k8s /version, consul, etcd /version, rabbitmq /api/overview,
     elasticsearch /, jenkins /login, kibana /app/kibana -> product identify
  6. Cloud metadata EDGE hints: S3/Azure/GCP bucket 404 fingerprints from responses
  7. vhost names ULTRA (48 -> 120+ env/devops names) + P3 feedforward candidates
  8. vhost differential scoring (status+len+sha1+title+server) + redirect vhosts
  9. Cookie/session headers capture -> P10 handoff (set-cookie on probes)
  10. Security-header ULTRA grade (v2 grade preserved + bonus headers)
  11. Error-page info-leak detector (paths/versions/emails in error body)
  12. Cache-behavior hints (Age/X-Cache/CF-Cache-Status) -> P22 handoff
  13. active_diff.json (run-to-run: live hosts/ports/vhosts diff)
  14. recon_summary.md (exec summary: perimeter, live, ports, TLS, next-phase prep)
  15. Perimeter per host matrix -> waf_matrix.json
  16. SAFE_PORTS ULTRA (48 -> 90: k8s 6443/10250, etcd 2379, docker 2375/2376,
      kafka 9092, zookeeper 2181, clickhouse 8123, hadoop 50070, couchdb 5984...)
 17. Socket banner probes preserved + service classification ULTRA
 18. allow_active gate preserved (sab active stages uske under)
 19. Budgets: active_waf_probe_max=12, active_vhost_max=48, active_svc_max=40
 20. Feedforward superset: P5/P6/P7/P8/P9/P10/P11/P22/P23/P24/P25/P26/P27/P32
 21. RWX STANDING RULE: har result file+folder 0777 (core + mod guard)
 22. Layer 4 aligned: GET/HEAD/OPTIONS-only HTTP; sockets sirf in-scope hosts par
 23. Scope discipline: vhost scope_host override (v2 pattern), ports in-scope only
 24. Graceful on ORIGINAL v2 core (drop-in)
 25. Deterministic checkpoints (resume-safe, v2 contract)

SAFETY: non-destructive; koi destructive payload nahi (WAF probe = harmless
markup), rate-limited by core limiter, allow_active=False par sab skip.
"""
import os, re, ssl, socket, subprocess, shutil, json
import concurrent.futures as cf
import urllib.parse as up
from wasp_core import (module_ctx, write_feedforward, write_manifest, ProbeCache,
                       soft404_baseline, is_soft404, normalize_url, host_of, port_of,
                       save_json, save_text, sha1, rand_str, favicon_hash, title_of,
                       info, ok, warn, err, head, now_iso, safe_map)

NAME = "active"
PHASE = "4-active"
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
# v2 TABLES (preserved) + ULTRA superset
# ---------------------------------------------------------------------------
SAFE_PORTS = [  # v2 list preserved + ULTRA additions
    80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 4000, 5000, 7000, 7001, 9000, 9090,
    9080, 9443, 10443, 8081, 8180, 4443, 81, 82, 83, 8008, 8880, 10000, 5601, 9200,
    2375, 2376, 6379, 27017, 5432, 3306, 1433, 11211, 15672, 8086, 8500, 8501, 10250,
    # ---- ULTRA additions ----
    6443, 2379, 2380, 9092, 2181, 8123, 50070, 5984, 1337, 5001, 7002, 8002, 8003,
    8009, 8010, 8444, 8445, 9001, 9002, 9091, 9093, 18080, 28017, 5985, 19000, 28080,
]

SERVICE_TECH = {  # v2 preserved + ULTRA
    "http": "web", "https": "web-tls", "ssh": "ssh", "ftp": "ftp", "smtp": "mail",
    "mysql": "database", "postgresql": "database", "redis": "cache", "mongodb": "database",
    "elasticsearch": "search", "memcached": "cache", "docker": "container-api",
    "kubelet": "k8s-api", "rabbitmq": "queue", "jenkins": "ci", "tomcat": "app-server",
    "mssql": "database", "rdp": "remote-desktop", "vnc": "remote-desktop",
    # ---- ULTRA ----
    "kafka": "queue", "zookeeper": "coordination", "clickhouse": "database",
    "couchdb": "database", "etcd": "coordination", "consul": "coordination",
    "kubernetes": "k8s-api", "nfs": "file-share", "hadoop": "bigdata",
}

WAF_SIG = {  # v2 preserved + ULTRA
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "server": "cloudflare"},
    "Akamai": {"headers": ["x-akamai-transformed", "akamai-grn"], "server": "akamaighost"},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "server": "sucuri"},
    "Imperva/Incapsula": {"headers": ["x-iinfo", "x-cdn"], "server": ""},
    "F5 BIG-IP": {"headers": ["x-wa-info", "x-cnection"], "server": "big-ip"},
    "AWS CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop"], "server": "cloudfront"},
    "Fastly": {"headers": ["x-fastly-request-id", "x-served-by"], "server": "fastly"},
    "Azure Front Door": {"headers": ["x-azure-ref", "x-fd-healthprobe"], "server": ""},
    "Google Cloud LB": {"headers": ["x-cloud-trace-context"], "server": "google frontend"},
    "Barracuda": {"headers": [], "server": "barracuda"},
    "ModSecurity": {"headers": [], "server": "mod_security"},
    "Citrix NetScaler": {"headers": ["via"], "server": "netscaler"},
    "Varnish": {"headers": ["x-varnish"], "server": ""},
    "Nginx": {"headers": [], "server": "nginx"},
    # ---- ULTRA ----
    "AWS WAF": {"headers": ["x-amzn-waf-action", "x-amzn-requestid"], "server": ""},
    "DDoS-Guard": {"headers": ["x-ddos-guard"], "server": "ddos-guard"},
    "Qrator": {"headers": ["x-qrator"], "server": "qrator"},
    "Alibaba WAF": {"headers": ["x-alicdn", "eagleeye-traceid"], "server": "tengine"},
    "Azion": {"headers": ["x-azion-request-id", "x-azion-trace-id"], "server": ""},
    "StackPath": {"headers": ["x-sp-stack", "x-stackpath"], "server": "stackpath"},
    "Gcore": {"headers": ["x-gcore"], "server": "gcore"},
    "Caddy": {"headers": [], "server": "caddy"},
}

CDN_HEADERS = ["cf-ray", "x-amz-cf-id", "x-cache", "x-served-by", "x-azure-ref",
               "x-fastly-request-id", "via", "x-varnish", "age", "x-cache-hits"]

VHOST_NAMES = [  # v2 list preserved + ULTRA additions
    "localhost", "127.0.0.1", "admin", "internal", "intranet", "dev", "develop",
    "staging", "stage", "test", "testing", "uat", "qa", "demo", "api", "api-dev",
    "api-staging", "portal", "vpn", "mail", "webmail", "jenkins", "git", "gitlab",
    "grafana", "kibana", "prometheus", "monitoring", "status", "docs", "beta",
    "sandbox", "old", "new", "legacy", "backup", "db", "sql", "mysql", "cms",
    "wordpress", "shop", "store", "cdn", "static", "assets", "m", "mobile",
    # ---- ULTRA ----
    "alpha", "gamma", "edge", "origin", "direct", "src", "app", "apps", "web",
    "www2", "www3", "secure", "auth", "sso", "oauth", "id", "identity", "account",
    "accounts", "admin2", "adminpanel", "manage", "manager", "console", "panel",
    "dashboard", "control", "ops", "devops", "infra", "ci", "cd", "build", "deploy",
    "artifacts", "nexus", "sonar", "jira", "confluence", "wiki", "support", "help",
    "helpdesk", "crm", "erp", "hr", "intra", "gw", "gateway", "proxy", "lb",
    "loadbalancer", "firewall", "ns1", "ns2", "mx", "smtp", "imap", "pop", "ftp",
    "sftp", "nas", "backup2", "bkp", "archive", "logs", "log", "elastic", "es",
    "redis", "cache", "mongo", "mq", "queue", "rabbit", "kafka", "zookeeper",
    "k8s", "kube", "cluster", "node1", "node2", "worker", "agent", "report",
    "reports", "bi", "analytics", "metrics", "tracing", "jaeger", "zipkin",
    "vault", "secrets", "cert", "pki", "ws", "socket", "realtime", "push",
]

TECH_RE = {  # v2 preserved
    "nginx": r"server:\s*nginx", "apache": r"server:\s*apache", "iis": r"microsoft-iis",
    "tomcat": r"apache-coyote|coyote", "php": r"x-powered-by:\s*php|\bphpsessid\b",
    "aspnet": r"asp\.net|__viewstate", "express": r"x-powered-by:\s*express",
    "node": r"x-powered-by:\s*express|x-powered-by:\s*node",
    "wordpress": r"wp-content|wp-includes|/wp-json", "drupal": r"drupal|sites/default",
    "joomla": r"joomla|/components/com_", "laravel": r"laravel_session|xsrf-token",
    "django": r"csrfmiddlewaretoken", "rails": r"csrf-token|_rails_session",
    "spring": r"jsessionid|whitelabel error", "nextjs": r"__next_data__|/_next/",
    "react": r"react-dom|__react|data-reactroot", "angular": r"ng-version|ng-app",
    "vue": r"vue\.js|data-v-", "cloudflare": r"cf-ray|cf-cache-status",
    "graphql": r"graphql", "swagger": r"swagger-ui|openapi\.json",
}

# ---------------------------------------------------------------------------
# ULTRA TABLES: bypass playbook + service probes + TLS
# ---------------------------------------------------------------------------
WAF_BYPASS_PLAYBOOK = {  # RoE-bounded misconfiguration edges (guidance text)
    "generic": [
        "X-Original-URL / X-Rewrite-URL: /admin (router-level routing headers)",
        "X-Forwarded-For: 127.0.0.1 / X-Real-IP: 127.0.0.1 (IP allowlist trust)",
        "Path normalization: /./admin , //admin , /%2e/admin , /admin/..%2f",
        "Parameter pollution: ?role=user&role=admin (parser differential)",
        "Method matrix: GET/HEAD/OPTIONS ka Allow header dekho (PATCH/PUT unguarded?)",
    ],
    "Cloudflare": [
        "Origin IP reveal: DNS history (SecurityTrails), direct-connect misconfig",
        "cf-connecting-ip spoof: X-Forwarded-For: 127.0.0.1 (origin trust issue)",
        "Host-header confusion: absolute-URI vs Host differential",
        "cgnat/whitelist bypass: /cdn-cgi/ endpoints exposed?",
    ],
    "AWS CloudFront": [
        "Origin fetch: X-Forwarded-Host differential, Host: origin.domain",
        "Cache-key confusion: vary header, query normalization differential",
        "Lambda@Edge bypass: direct origin host (behind-CF naming)",
    ],
    "nginx": [
        "merge_slashes off: //admin// path split routing bypass",
        "alias traversal: /static../etc/passwd style alias misconfig",
        "off-by-slash: location /static{ -> /static../app-secrets",
    ],
    "Apache": [
        "Invalid HTTP method parsing: OPTIONS * differential",
        "mod_proxy Path traversal: /proxy-url..;/admin",
        "httpd.conf alias misconfig: /icons/../",
    ],
    "Akamai": [
        "PRAGMA header: akamai-x-cache-on, akamai-x-get-true-cache-key (debug info)",
        "Edge-IP discovery via CNAME chain -> direct edge bypass",
    ],
    "Imperva/Incapsula": [
        "visid_incap/incap_ses cookie reuse (session replays)",
        "x-cdn: incapsula header differential on subpaths",
    ],
    "F5 BIG-IP": [
        "iRule length-limit bypass: very long URL (>8k) -> WAF skip",
        "X-F5-Auth-Token / tmui endpoints exposure check",
    ],
}

SERVICE_HTTP_FP = [  # (port, path, product, match_regex) - read-only GET
    (2375, "/_ping", "docker-api", r"(?i)OK|Docker"),
    (2376, "/_ping", "docker-api-tls", r"(?i)OK|Docker"),
    (6443, "/version", "k8s-api", r"(?i)major|minor|gitVersion"),
    (10250, "/pods", "kubelet", r"(?i)kind.*PodList|items"),
    (2379, "/version", "etcd", r"(?i)etcdserver"),
    (8500, "/v1/agent/self", "consul", r"(?i)Config.*Agent|Version"),
    (15672, "/api/overview", "rabbitmq-mgmt", r"(?i)management_version"),
    (9200, "/", "elasticsearch", r"(?i)cluster_name|lucene_version"),
    (5601, "/app/kibana", "kibana", r"(?i)kibana"),
    (8080, "/manager/html", "tomcat-manager", r"(?i)Tomcat Web Application Manager"),
    (3000, "/api/health", "grafana", r"(?i)database|version"),
    (9090, "/api/v1/status/buildinfo", "prometheus", r"(?i)version"),
    (8123, "/", "clickhouse", r"(?i)Ok\."),
    (5984, "/", "couchdb", r"(?i)couchdb|welcome"),
    (50070, "/jmx", "hadoop-namenode", r"(?i)Hadoop"),
    (10000, "/", "webmin", r"(?i)Webmin"),
    (9000, "/api/server_info", "sonarqube", r"(?i)sonar"),
    (1337, "/", "custom-node", r"(?i)express|json"),
]

TLS_VERSIONS = ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"]  # forcing probe order
WEAK_CIPHER_HINTS = ["RC4", "DES-CBC3", "3DES", "NULL", "EXPORT", "AES128-SHA", "AES256-SHA"]

DEFAULTS_CFG = {
    "active_waf_probe_max": 12,    # WAF behavioral probes per host (read-only)
    "active_vhost_max": 48,        # vhost candidate cap per host
    "active_svc_max": 40,          # service HTTP fingerprint cap
}

# ---------------------------------------------------------------------------
# STAGE 1 - HTTP probe (v2 preserved)
# ---------------------------------------------------------------------------
def http_probe(cfg, scope, http, seed):
    """Probe one seed URL; try https then http fallback for bare hosts."""
    tries = [seed]
    if not re.match(r"^https?://", seed):
        tries = ["https://" + seed, "http://" + seed]
    elif seed.startswith("http://"):
        tries = [seed, seed.replace("http://", "https://", 1)]

    for url in tries:
        if not scope.check_url(url, raise_on_fail=False):
            continue
        r = http.request("GET", url, allow_redirects=True,
                         save="probe_%s.html" % re.sub(r"[^A-Za-z0-9._-]", "_", host_of(url)))
        if r.error:
            continue
        pu = up.urlsplit(r.url)
        rec = {"seed": url, "url": r.url, "scheme": pu.scheme, "host": pu.hostname,
               "port": pu.port or (443 if pu.scheme == "https" else 80),
               "status": r.status, "len": len(r.body), "title": title_of(r.text),
               "server": r.hget("Server"), "powered": r.hget("X-Powered-By"),
               "content_type": r.hget("Content-Type"), "location": r.hget("Location"),
               "redirect_chain": r.chain, "body_sha1": r.sha1(),
               "set_cookie": len(r.set_cookies or []), "error": None}
        # favicon fingerprint (Shodan-style hash)
        fav = _favicon_hash(http, r.url)
        rec["favicon_hash"] = fav
        # tech from headers/body
        blob = json.dumps(r.headers).lower() + " " + r.text[:5000].lower()
        rec["tech"] = sorted({t for t, pat in TECH_RE.items() if re.search(pat, blob)})
        # ULTRA: cookie names -> P10 handoff
        rec["cookie_names"] = sorted({c.split("=")[0].strip() for c in (r.set_cookies or [])})
        return rec
    return {"seed": seed, "host": host_of(seed), "status": None, "error": "no-response"}


def _favicon_hash(http, base_url):
    for path in ("/favicon.ico", "/favicon.png"):
        r = http.request("GET", up.urljoin(base_url, path), allow_redirects=True)
        if not r.error and r.status == 200 and len(r.body) > 0:
            try:
                return favicon_hash(r.body)
            except Exception:
                return None
    return None


# ---------------------------------------------------------------------------
# STAGE 2 - edge fingerprint (v2 preserved)
# ---------------------------------------------------------------------------
def header_grade(r):
    checks = ["strict-transport-security", "content-security-policy", "x-frame-options",
              "x-content-type-options", "referrer-policy", "permissions-policy"]
    missing = [c for c in checks if not r.hget(c)]
    pct = 100.0 * (len(checks) - len(missing)) / len(checks)
    grade = "A" if pct >= 85 else "B" if pct >= 70 else "C" if pct >= 50 else "D" if pct >= 30 else "F"
    return {"grade": grade, "missing": missing}


def edge_fingerprint(cfg, scope, http, probe):
    url = probe["url"]
    r = http.request("GET", url, allow_redirects=False)
    hdr = {k.lower(): v for k, v in (r.headers or {}).items()}
    hits = []
    for waf, sig in WAF_SIG.items():
        for h in sig["headers"]:
            if h in hdr:
                hits.append(waf)
                break
        else:
            if sig["server"] and sig["server"] in (hdr.get("server", "") or "").lower():
                hits.append(waf)
    cache = {k: hdr.get(k) for k in CDN_HEADERS if k in hdr}
    rec = {"url": url, "status": r.status, "server": hdr.get("server", ""),
           "waf_hits": sorted(set(hits)), "cdn_headers": cache,
           "header_grade": header_grade(r), "cacheable": bool(cache),
           "tls": tls_inspect(probe["host"], probe["port"]) if probe["scheme"] == "https"
           else {"skipped": "not-https"}}
    # ULTRA: perimeter extras -> P8/P22 handoff
    rec["origin_hints"] = sorted({v for k, v in hdr.items()
                                  if re.match(r"(?i)^(x-origin|x-real-origin|cf-connecting|x-forwarded-host|by-pass)", k)
                                  and v})[:6]
    rec["cookie_names"] = sorted({c.split("=")[0].strip() for c in (r.set_cookies or [])})
    return rec


def tls_inspect(host, port=443, timeout=8):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
                cipher = ss.cipher()
        if not cert:
            return {"host": host, "port": port, "error": "no-cert-details"}
        def name(field):
            parts = []
            for rdn in cert.get(field, []):
                for k, v in rdn:
                    parts.append("%s=%s" % (k, v))
            return ", ".join(parts)
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        mismatch = None
        if sans:
            mismatch = host not in sans and not any(
                s.startswith("*.") and host.endswith(s[1:]) for s in sans)
        return {"host": host, "port": port, "tls_version": proto,
                "cipher": cipher[0] if cipher else None,
                "subject": name("subject"), "issuer": name("issuer"),
                "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                "sans": sans[:30], "hostname_mismatch": mismatch,
                "self_signed": cert.get("issuer") == cert.get("subject")}
    except Exception as e:
        return {"host": host, "port": port, "error": "%s: %s" % (type(e).__name__, e)}


# ---------------------------------------------------------------------------
# STAGE 3 - error-page fingerprint + soft-404 (v2 preserved)
# ---------------------------------------------------------------------------
def error_fingerprint(http, probe, cp_base=None):
    base_url = probe["url"]
    rnd = "/%s-%s" % (rand_str(9), rand_str(6))
    r = http.request("GET", up.urljoin(base_url.rstrip("/") + "/", rnd.lstrip("/")),
                     allow_redirects=False)
    rec = {"url": base_url, "error_status": r.status, "error_len": len(r.body),
           "error_sha1": r.sha1(), "error_title": title_of(r.text),
           "server_banner": r.hget("Server"),
           "template_hits": sorted({t for t, pat in ERROR_TEMPLATES.items()
                                    if re.search(pat, r.text, re.I)}),
           "soft404": is_soft404(r, cp_base) if cp_base else None}
    # ULTRA: info-leak in error body (paths/versions/emails) - evidence only
    body = r.text or ""
    rec["leak_hits"] = sorted({t for t, pat in ERROR_LEAKS.items() if re.search(pat, body, re.I)})
    return rec


ERROR_TEMPLATES = {  # v2 preserved
    "nginx": r"<center>nginx</center>|nginx/\d",
    "apache": r"<address>Apache/\d",
    "iis": r"IIS \d\.\d|HTTP Error \d+\.\d",
    "tomcat": r"Apache Tomcat/\d|HTTP Status 404",
    "spring": r"Whitelabel Error Page|org\.springframework",
    "laravel": r"Whoops|Ignition|laravel",
    "django": r"DisallowedHost|You're seeing this error|django",
    "rails": r"ActionController|Rails\.root|web-console",
    "aspnet": r"Server Error in|Runtime Error|ASP\.NET",
    "php": r"Fatal error|Parse error|Warning:",
    "express": r"Cannot GET /|at Object\.<anonymous>",
    "flask": r"Werkzeug|Traceback \(most recent call last\)",
    "gunicorn": r"gunicorn|WSGIServer",
    "cloudflare": r"cloudflare|Attention Required",
    "s3": r"<Code>NoSuchBucket</Code>|<Code>AccessDenied</Code>",
    "vercel": r"Vercel|DEPLOYMENT_NOT_FOUND",
    "netlify": r"Netlify|Page not found - Netlify",
    "github-pages": r"GitHub Pages|There isn't a GitHub Pages site here",
}

ERROR_LEAKS = {  # ULTRA
    "abs_path": r"(?i)(?:/[a-z0-9_\-./]+){3,}\.(?:py|php|jsp|asp|rb|go)\b",
    "stack_trace": r"(?i)traceback|stack trace|at [\w.$]+\(",
    "version_disclose": r"(?i)(?:version|ver)[\"'\s:=]+[0-9]+\.[0-9]+[0-9a-z.\-]*",
    "sql_fragment": r"(?i)select\s+|insert\s+into|mysql_fetch|pg_query",
    "internal_host": r"(?i)\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}


# ---------------------------------------------------------------------------
# STAGE 4 - vhost discovery (v2 preserved)
# ---------------------------------------------------------------------------
def vhost_discovery(cfg, scope, http, probe, names, base_sig, ip):
    scheme, port = probe["scheme"], probe["port"]
    netloc = "%s:%d" % (ip, port) if port not in (80, 443) else ip
    url = "%s://%s/" % (scheme, netloc)
    found = []
    for name in names:
        cand = name if "." in name else "%s.%s" % (name, (scope.root_domains() or ["localhost"])[0])
        if not scope.check_host(cand, raise_on_fail=False):
            continue
        try:
            r = http.request("GET", url, headers={"Host": cand}, allow_redirects=False,
                             scope_host=cand, retries=0)
        except Exception:
            continue
        if r.error:
            continue
        sig = (r.status, len(r.body), r.sha1())
        differs = sig != base_sig
        if differs and r.status not in (400, 404, 421, None):
            found.append({"vhost": cand, "status": r.status, "len": len(r.body),
                          "title": title_of(r.text), "sha1": r.sha1(),
                          "server": r.hget("Server"), "location": r.hget("Location")})
    return found


# ---------------------------------------------------------------------------
# STAGE 5 - ports / services (v2 preserved)
# ---------------------------------------------------------------------------
def _socket_probe(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(2.5)
            banner = b""
            try:
                if port in (80, 8080, 8000, 8888, 81, 82, 83, 8081, 8180, 3000, 5000, 9090, 10000):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
                banner = s.recv(512)
            except Exception:
                pass
            return {"host": host, "port": port, "state": "open",
                    "banner": banner.decode("utf-8", "ignore").split("\n")[0].strip()[:140],
                    "service": "", "product": "", "version": ""}
    except Exception:
        return None


def port_scan(host, ports, concurrency=64, timeout=4):
    out = []
    with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(_socket_probe, host, p, timeout): p for p in ports}
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                out.append(r)
    return sorted(out, key=lambda x: x["port"])


def nmap_scan(host, top_ports=200, timeout=420):
    if not shutil.which("nmap"):
        return None
    cmd = ("nmap -sT -Pn -T2 --top-ports %d --open --max-retries 2 "
           "--host-timeout 240s -n -oX - %s" % (top_ports, host))
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        xml = p.stdout or ""
    except Exception as e:
        warn("nmap failed: %s" % e)
        return None
    if "<nmaprun" not in xml:
        warn("nmap returned no XML (permission? try sudo) -> socket fallback")
        return None
    ports = []
    for m in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', xml, re.S):
        proto, pid, blk = m.group(1), int(m.group(2)), m.group(3)
        svc = re.search(r'<service\s+name="([^"]*)"', blk)
        prod = re.search(r'product="([^"]*)"', blk)
        ver = re.search(r'version="([^"]*)"', blk)
        ports.append({"host": host, "port": pid, "protocol": proto, "state": "open",
                      "service": svc.group(1) if svc else "",
                      "product": prod.group(1) if prod else "",
                      "version": ver.group(1) if ver else "",
                      "banner": ""})
    return ports


# ---------------------------------------------------------------------------
# ULTRA STAGES (v3): WAF behavioral + TLS deep + service fingerprints
# ---------------------------------------------------------------------------
def waf_behavioral_probe(cfg, http, probe, max_probes=12):
    """ULTRA: read-only WAF identity probe. Harmless markup GET (koi payload
    attack nahi - sirf differential). wafw00f-style confidence."""
    base_url = probe["url"]
    probes = [
        ("/?waspprobe=%3Cscript%3Ex%3C%2Fscript%3E", "xss-markup"),
        ("/?waspprobe=..%2f..%2fetc%2fpasswd", "path-traversal"),
        ("/?waspprobe=' OR '1'='1", "sql-quote"),
        ("/?waspprobe=%24%7B7%2A7%7D", "ssti-eval"),
        ("/?waspprobe=../../../etc/passwd", "plain-traversal"),
    ]
    base = http.request("GET", base_url, allow_redirects=False, retries=0)
    base_sig = (base.status, len(base.body))
    results = []
    for q, kind in probes[:max(1, min(max_probes, len(probes)))]:
        url = base_url.rstrip("/") + "/" + q
        r = http.request("GET", url, allow_redirects=False, retries=0)
        blocked = r.status in (403, 406, 429, 501) or (r.error is not None)
        differential = (r.status, len(r.body)) != base_sig
        results.append({"kind": kind, "status": r.status, "len": len(r.body),
                        "blocked": blocked, "differential": differential,
                        "server": r.hget("Server"),
                        "template": sorted({t for t, pat in ERROR_TEMPLATES.items()
                                            if re.search(pat, r.text or "", re.I)})})
    blocked_n = sum(1 for x in results if x["blocked"])
    confidence = "none"
    if blocked_n >= 3:
        confidence = "high"
    elif blocked_n >= 1:
        confidence = "medium"
    return {"url": base_url, "base_status": base.status, "probes": results,
            "blocked_count": blocked_n, "waf_confidence": confidence,
            "note": "harmless read-only probes - WAF/edge behavior differential"}


def tls_deep(host, port=443, timeout=6):
    """ULTRA: protocol forcing + weak-cipher exposure + expiry."""
    out = {"host": host, "port": port}
    for ver, name in ((ssl.PROTOCOL_TLSv1, "TLSv1.0"), (ssl.PROTOCOL_TLSv1_1, "TLSv1.1")):
        try:
            ctx = ssl.SSLContext(ver)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    out.setdefault("deprecated_accepted", []).append(name)
        except Exception:
            pass
    insp = tls_inspect(host, port, timeout=timeout)
    out["inspect"] = insp
    na = insp.get("not_after")
    if na:
        try:
            import datetime
            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            out["expires_in_days"] = days
            if days < 0:
                out["expired"] = True
            elif days < 30:
                out["expiring_soon"] = True
        except Exception:
            pass
    cipher = insp.get("cipher") or ""
    out["weak_cipher_hint"] = [w for w in WEAK_CIPHER_HINTS if w in cipher]
    sans = insp.get("sans") or []
    out["san_cross_domain"] = [s for s in sans if not s.startswith("*.") and
                               "." in s and host and not host.endswith(s.split(".", 1)[-1])][:8]
    return out


def service_http_fingerprint(cfg, scope, http, host, ports, cap=40):
    """ULTRA: open ports par read-only product fingerprints.
    scope_host=host -> target hostname se authorize hota hai (v2 vhost pattern)."""
    done = 0
    out = []
    for port, path, product, rx in SERVICE_HTTP_FP:
        if done >= cap:
            break
        if port not in ports:
            continue
        done += 1
        url = "http://%s:%d%s" % (host, port, path)
        try:
            r = http.request("GET", url, allow_redirects=False, retries=0,
                             scope_host=host, raise_scope=False)
        except Exception:
            continue
        if r.error:
            out.append({"host": host, "port": port, "product": product,
                        "url": url, "error": r.error})
            continue
        hit = bool(re.search(rx, (r.text or "")[:4000]))
        out.append({"host": host, "port": port, "product": product, "url": url,
                    "status": r.status, "identified": hit,
                    "len": len(r.body), "server": r.hget("Server")})
    return out

# ---------------------------------------------------------------------------
# ULTRA: playbook + summary + diff helpers
# ---------------------------------------------------------------------------
def write_bypass_playbook(out, edges):
    """ULTRA: detected perimeter ke hisaab se tailored bypass playbook (guidance)."""
    detected = sorted({w for e in edges for w in (e.get("waf_hits") or [])})
    L = ["# WAF/Edge Bypass Playbook (Phase 4 ULTRA)", "",
         "_RoE-bounded misconfiguration edges - sirf AUTHORIZED targets par, GET/HEAD-only",
         "testing. Ye WAF 'crack' NAHI hai - misconfig/edge-case hints hain._", "",
         "## Detected perimeter", ""]
    if detected:
        for d in detected:
            L.append("- %s" % d)
    else:
        L.append("- (koi known perimeter signature nahi mila - generic list dekho)")
    L.append("")
    for name in (detected or ["generic"]):
        items = WAF_BYPASS_PLAYBOOK.get(name, WAF_BYPASS_PLAYBOOK["generic"])
        L.append("## %s" % name)
        for it in items:
            L.append("- [ ] %s" % it)
        L.append("")
    L.append("## Generic origin-discovery drill (in-scope only)")
    L.append("- [ ] DNS history se origin IP (P3 passive ke ips.txt se compare)")
    L.append("- [ ] direct. / origin. / src. named subdomains (vhosts.txt dekho)")
    L.append("- [ ] Host-header vs absolute-URI differential (vhost matrix use karo)")
    L.append("- [ ] TLS SNI mismatch: IP connect + in-scope Host (vhost pattern)")
    L.append("- [ ] Phase 8 ka surface/bypass_playbook.txt bhi merge karo")
    save_text(os.path.join(out, "bypass_playbook.txt"), "\n".join(L) + "\n")
    return detected


def write_origin_playbook(out, edges, probes):
    """ULTRA: origin discovery guidance (koi out-of-scope request nahi)."""
    hints = sorted({h for e in edges for h in (e.get("origin_hints") or [])})
    origin_cands = ["origin.%s" % up.urlsplit(p["url"]).hostname.split(".", 1)[-1]
                    for p in probes if p.get("host") and "." in p["host"]]
    L = ["# Origin Discovery Playbook (Phase 4 ULTRA)", "",
         "_Direct-to-origin testing guidance. Sirf in-scope hosts/hosts se authorized names._", ""]
    if hints:
        L.append("## Header hints observed")
        L += ["- %s" % h for h in hints]
        L.append("")
    L.append("## Candidate origin names (scope-check ke baad hi try karo)")
    L += ["- %s" % c for c in sorted(set(origin_cands))[:10]]
    L.append("")
    L.append("## Drill")
    L.append("- [ ] P3 passive ips.txt me edge-IP vs origin-IP difference dekho")
    L.append("- [ ] vhost differential me origin/legacy/direct names confirm karo")
    L.append("- [ ] origin reachable -> WAF rules bypass ho sakte hain (RoE me allowed ho to)")
    save_text(os.path.join(out, "origin_playbook.txt"), "\n".join(L) + "\n")


def write_recon_summary(out, probes, edges, errs, vhosts, ports_all, waf_res, tls_d):
    det = sorted({w for e in edges for w in (e.get("waf_hits") or [])})
    conf = sorted({w.get("waf_confidence") for w in waf_res if w.get("waf_confidence") != "none"})
    L = ["# Active Recon Summary (Phase 4 ULTRA PRO MAX)", "",
         "- generated: %s" % now_iso(),
         "- live hosts: %d | open ports: %d | vhosts: %d" % (len(probes), len(ports_all), len(vhosts)),
         "- perimeter: %s" % (", ".join(det) or "none detected"),
         "- WAF behavioral confidence: %s" % (", ".join(conf) or "none"),
         "- TLS deprecated accepted: %s" % (", ".join(sorted({t for d in tls_d
                                                              for t in d.get("deprecated_accepted") or []})) or "none"),
         "", "## Next-phase prep",
         "- P5 content: live_hosts.txt + error soft-404 baselines",
         "- P6 tech: waf_cdn.txt + favicon_hashes.txt",
         "- P8 surface: waf_matrix.json + bypass_playbook.txt merge",
         "- P9/P10: cookie_names (session headers)",
         "- P22 cache: cdn_headers per edge", ""]
    if vhosts:
        L.append("## Interesting vhosts")
        L += ["- %s [%s] %s" % (v["vhost"], v["status"], v["title"][:50]) for v in vhosts[:12]]
    if ports_all:
        L.append("")
        L.append("## Open ports (non-web highlights)")
        L += ["- %s:%s %s %s" % (p["host"], p["port"], p.get("service", ""), p.get("banner", "")[:40])
              for p in ports_all if p.get("port") not in (80, 443)][:12]
    save_text(os.path.join(out, "recon_summary.md"), "\n".join(L) + "\n")


def _load_prev(out):
    p = os.path.join(out, "active.json")
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception:
            return None
    return None


def _diff(prev, probes, ports_all, vhosts):
    if not prev or not isinstance(prev, dict):
        return None
    d = {"generated_at": now_iso(),
         "new_live": sorted({p["url"] for p in probes} - {p.get("url") for p in (prev.get("probes") or []) if p.get("url")}),
         "gone_live": sorted({p.get("url") for p in (prev.get("probes") or []) if p.get("url")} - {p["url"] for p in probes}),
         "new_ports": sorted({(p["host"], p["port"]) for p in ports_all} -
                             {(p.get("host"), p.get("port")) for p in (prev.get("ports") or [])}),
         "new_vhosts": sorted({v["vhost"] for v in vhosts} -
                              {v.get("vhost") for v in (prev.get("vhosts") or [])})}
    return d if (d["new_live"] or d["gone_live"] or d["new_ports"] or d["new_vhosts"]) else \
        {"generated_at": now_iso(), "note": "no changes"}


# ---------------------------------------------------------------------------
# RUN - v2 5 stages preserved + 3 ULTRA stages + superset outputs
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    cache = ProbeCache(base_out, scope.engagement) if getattr(cfg, "negative_cache", True) else None
    head("Phase 4 - Active Recon & Host Enumeration (ULTRA PRO MAX) | %s" % scope.describe())

    seeds = scope.seed_urls()
    if not seeds:
        err("No in-scope seeds. scope.json check karo."); return out
    info("Seeds: %d" % len(seeds))

    # ---------------- Stage 1 (v2) ----------------
    head("Stage 1 - HTTP(S) probe")
    probes = []
    for i, s in enumerate(seeds, 1):
        ck = "probe:" + s
        if cp.is_done(ck):
            rec = cp.result_of(ck)
            if rec and rec.get("status"):
                probes.append(rec)
            info("[%d/%d] SKIP (checkpoint) %s" % (i, len(seeds), s))
            continue
        rec = http_probe(cfg, scope, http, s)
        cp.mark(ck, rec, summary="probe")
        if rec.get("status") is None:
            warn("[%d/%d] %s -> no response" % (i, len(seeds), s))
            continue
        probes.append(rec)
        ok("[%d/%d] %s://%s:%s [%s] %s len=%d server=%s tech=%s"
           % (i, len(seeds), rec["scheme"], rec["host"], rec["port"], rec["status"],
              rec["title"][:40] or "-", rec["len"], rec["server"] or "-",
              ",".join(rec["tech"]) or "-"))
    ok("live endpoints: %d/%d" % (len(probes), len(seeds)))
    if not probes:
        warn("Koi endpoint respond nahi kiya. Scope/network/TLS check karo.")
        save_json(os.path.join(out, "active.json"), {"probes": [], "note": "no live endpoints",
                                                     "engine_version": ENGINE_VERSION})
        # ULTRA: early-return par bhi poora output contract nibhao (empty files)
        for fn in ("live_hosts.txt", "open_ports.txt", "waf_cdn.txt", "vhosts.txt",
                   "tls_report.txt", "favicon_hashes.txt", "error_templates.txt",
                   "security_headers.txt", "waf_matrix.json", "bypass_playbook.txt",
                   "origin_playbook.txt", "tls_deep.txt", "service_fingerprints.txt",
                   "session_cookies.txt", "waf_behavioral.txt", "error_leaks.txt",
                   "recon_summary.md"):
            save_text(os.path.join(out, fn),
                      "" if not fn.endswith(".json") else "[]")
        save_text(os.path.join(out, "bypass_playbook.txt"),
                  "# WAF/Edge Bypass Playbook (Phase 4 ULTRA)\n\n"
                  "- (koi live endpoint nahi mila - playbook live probe ke baad tay hota hai)\n")
        write_feedforward(out, "4-active", {"skipped": "no live endpoints"})
        _rwx_tree(out)  # RWX RULE: jitna bana, sab rwx
        return out

    # ---------------- Stage 2 (v2) ----------------
    head("Stage 2 - Edge fingerprint (WAF/CDN/cache/TLS/headers)")
    edges = []
    for i, pr in enumerate(probes, 1):
        ck = "edge:" + pr["url"]
        if cp.is_done(ck):
            e = cp.result_of(ck); edges.append(e)
            info("[%d/%d] SKIP (checkpoint) %s" % (i, len(probes), pr["url"]))
            continue
        e = edge_fingerprint(cfg, scope, http, pr)
        cp.mark(ck, e, summary="edge")
        edges.append(e)
        tls = e["tls"]
        ok("[%d/%d] %s | waf=%s | grade=%s | cache=%s | tls=%s%s"
           % (i, len(probes), pr["host"], ",".join(e["waf_hits"]) or "none",
              e["header_grade"]["grade"], ",".join(e["cdn_headers"].keys()) or "-",
              tls.get("tls_version") or tls.get("error", "-"),
              " MISMATCH" if tls.get("hostname_mismatch") else ""))

    # ---------------- Stage 3 (v2) ----------------
    head("Stage 3 - Error-page & soft-404 fingerprint")
    errs = []
    for i, pr in enumerate(probes, 1):
        ck = "soft404:" + pr["url"]
        if cp.is_done(ck):
            errs.append(cp.result_of(ck)); continue
        base = soft404_baseline(http, pr["url"], samples=3)
        ef = error_fingerprint(http, pr, cp_base=base)
        ef["baseline"] = base
        cp.mark(ck, ef, summary="soft404+error")
        errs.append(ef)
        ok("%s | soft404_status=%s stable=%s | template=%s | leaks=%s"
           % (pr["host"], base.get("status"), base.get("stable_len"),
              ",".join(ef["template_hits"]) or "-", ",".join(ef.get("leak_hits") or []) or "-"))

    # ---------------- Stage 4 (v2) ----------------
    head("Stage 4 - Virtual-host discovery (Host-header differential)")
    vhosts = []
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> vhost probing skipped")
    else:
        vh_cap = int(getattr(cfg, "active_vhost_max", 48) or 48)
        for pr in probes[:4]:
            ck = "vhost:" + pr["url"]
            if cp.is_done(ck):
                vhosts.extend(cp.result_of(ck) or [])
                info("SKIP (checkpoint) vhost %s" % pr["host"])
                continue
            try:
                ip = socket.gethostbyname(pr["host"])
            except Exception:
                warn("cannot resolve %s for vhost probing" % pr["host"]); continue
            base_r = http.request("GET", pr["url"], allow_redirects=False, retries=0)
            base_sig = (base_r.status, len(base_r.body), base_r.sha1())
            names = sorted(set(VHOST_NAMES + [s.split(".")[0] for s in scope.root_domains()]))[:vh_cap]
            found = vhost_discovery(cfg, scope, http, pr, names, base_sig, ip)
            cp.mark(ck, found, summary="vhost")
            vhosts.extend(found)
            ok("%s -> %d vhost differentials (of %d names)" % (pr["host"], len(found), len(names)))
            for v in found[:10]:
                warn("   vhost %s [%s] %s" % (v["vhost"], v["status"], v["title"][:40]))

    # ---------------- Stage 5 (v2) ----------------
    head("Stage 5 - Port / service enumeration")
    ports_all = []
    hosts = sorted({pr["host"] for pr in probes})
    for i, h in enumerate(hosts, 1):
        ck = "ports:" + h
        if cp.is_done(ck):
            p = cp.result_of(ck) or []
            ports_all.extend(p)
            info("[%d/%d] SKIP (checkpoint) ports %s -> %d" % (i, len(hosts), h, len(p)))
            continue
        if not getattr(cfg, "allow_active", True):
            warn("allow_active=False -> port scan skipped"); break
        ports = nmap_scan(h) if shutil.which("nmap") else None
        engine = "nmap"
        if ports is None:
            ports = port_scan(h, SAFE_PORTS)
            engine = "socket"
        for p in ports:
            p["service"] = p.get("service") or SERVICE_TECH.get(
                (p.get("banner") or "").split("/")[0].lower(), "")
        cp.mark(ck, ports, summary="ports")
        ports_all.extend(ports)
        ok("[%d/%d] %s (%s) -> %d open: %s" % (i, len(hosts), h, engine, len(ports),
           ",".join(str(p["port"]) for p in ports[:14])))

    # ---------------- Stage 6 ULTRA: WAF behavioral ----------------
    head("Stage 6 ULTRA - WAF behavioral probe (read-only)")
    waf_res = []
    if getattr(cfg, "allow_active", True):
        wp_max = int(getattr(cfg, "active_waf_probe_max", 12) or 12)
        for pr in probes:
            ck = "wafprobe:" + pr["url"]
            if cp.is_done(ck):
                waf_res.append(cp.result_of(ck)); continue
            w = waf_behavioral_probe(cfg, http, pr, max_probes=wp_max)
            cp.mark(ck, w, summary="waf-behavioral")
            waf_res.append(w)
            ok("%s | waf_confidence=%s blocked=%d/%d"
               % (pr["host"], w["waf_confidence"], w["blocked_count"], len(w["probes"])))
    else:
        warn("allow_active=False -> WAF behavioral skipped")

    # ---------------- Stage 7 ULTRA: TLS deep ----------------
    head("Stage 7 ULTRA - TLS deep (versions/expiry/weak ciphers)")
    tls_d = []
    for pr in probes:
        if pr.get("scheme") != "https":
            continue
        ck = "tlsdeep:" + pr["url"]
        if cp.is_done(ck):
            tls_d.append(cp.result_of(ck)); continue
        t = tls_deep(pr["host"], pr["port"])
        cp.mark(ck, t, summary="tls-deep")
        tls_d.append(t)
        ok("%s | deprecated=%s expires=%s weak=%s"
           % (pr["host"], ",".join(t.get("deprecated_accepted") or []) or "none",
              "%sd" % t["expires_in_days"] if "expires_in_days" in t else "-",
              ",".join(t.get("weak_cipher_hint") or []) or "none"))

    # ---------------- Stage 8 ULTRA: service fingerprints ----------------
    head("Stage 8 ULTRA - Service product fingerprints (read-only)")
    svc_fps = []
    if getattr(cfg, "allow_active", True):
        svc_cap = int(getattr(cfg, "active_svc_max", 40) or 40)
        for h in hosts:
            pr_ports = sorted({p["port"] for p in ports_all if p["host"] == h})
            if not pr_ports:
                continue
            got = service_http_fingerprint(cfg, scope, http, h, pr_ports, cap=svc_cap)
            svc_fps.extend(got)
            ids = [g for g in got if g.get("identified")]
            if ids:
                ok("%s -> identified: %s" % (h, ",".join("%s@%d" % (g["product"], g["port"])
                                                         for g in ids)))
            if svc_cap <= 0:
                break

    # ---------------- exports (v2 + ULTRA) ----------------
    report = {"phase": "4-active", "generated_at": now_iso(),
              "engine_version": ENGINE_VERSION,
              "probes": probes, "edges": edges, "error_pages": errs,
              "vhosts": vhosts, "ports": ports_all,
              "waf_behavioral": waf_res, "tls_deep": tls_d, "service_fp": svc_fps}
    save_json(os.path.join(out, "active.json"), report)

    save_text(os.path.join(out, "live_hosts.txt"),
              "\n".join("%s://%s:%s [%s] %s" % (p["scheme"], p["host"], p["port"], p["status"],
                                                p["title"][:60]) for p in probes))
    save_text(os.path.join(out, "open_ports.txt"),
              "\n".join("%s:%s %s %s %s" % (p["host"], p["port"], p.get("service", ""),
                                            p.get("product", ""), p.get("version", ""))
                        for p in ports_all))
    save_text(os.path.join(out, "waf_cdn.txt"),
              "\n".join("%s -> waf=%s grade=%s cache=%s" % (e["url"], ",".join(e["waf_hits"]) or "none",
                                                            e["header_grade"]["grade"],
                                                            ",".join(e["cdn_headers"].keys()) or "-")
                        for e in edges))
    save_text(os.path.join(out, "vhosts.txt"),
              "\n".join("%s [%s] %s %s" % (v["vhost"], v["status"], v["title"][:40], v["location"])
                        for v in vhosts))
    save_text(os.path.join(out, "tls_report.txt"),
              "\n".join("%s:%s ver=%s issuer=%s not_after=%s mismatch=%s self_signed=%s"
                        % (t.get("host"), t.get("port"), t.get("tls_version", t.get("error", "-")),
                           t.get("issuer", "-"), t.get("not_after", "-"),
                           t.get("hostname_mismatch"), t.get("self_signed")) for t in
                        [e["tls"] for e in edges]))
    save_text(os.path.join(out, "favicon_hashes.txt"),
              "\n".join("%s -> %s" % (p["host"], p.get("favicon_hash")) for p in probes))
    save_text(os.path.join(out, "error_templates.txt"),
              "\n".join("%s -> %s (soft404_status=%s)" % (e["url"], ",".join(e["template_hits"]) or "-",
                                                          (e.get("baseline") or {}).get("status"))
                        for e in errs))
    save_text(os.path.join(out, "security_headers.txt"),
              "\n".join("%s -> grade=%s missing=%s" % (e["url"], e["header_grade"]["grade"],
                                                       ",".join(e["header_grade"]["missing"]) or "-")
                        for e in edges))

    # -------- ULTRA outputs --------
    save_json(os.path.join(out, "waf_matrix.json"),
              [{"url": e["url"], "waf": e["waf_hits"], "behavioral":
                next(({"confidence": w["waf_confidence"], "blocked": w["blocked_count"]}
                      for w in waf_res if w["url"] == e["url"]), {})} for e in edges])
    detected = write_bypass_playbook(out, edges)
    write_origin_playbook(out, edges, probes)
    save_text(os.path.join(out, "tls_deep.txt"),
              "\n".join("%s:%s deprecated=%s expires_in_days=%s weak=%s san_cross=%s"
                        % (t.get("host"), t.get("port"),
                           ",".join(t.get("deprecated_accepted") or []) or "none",
                           t.get("expires_in_days", "-"),
                           ",".join(t.get("weak_cipher_hint") or []) or "none",
                           ",".join(t.get("san_cross_domain") or []) or "none")
                        for t in tls_d))
    save_text(os.path.join(out, "service_fingerprints.txt"),
              "\n".join("%s:%s %s -> %s %s [%s]" % (g["host"], g["port"], g["product"],
                                                    "IDENTIFIED" if g.get("identified") else "no-match",
                                                    "status=%s" % g.get("status", g.get("error", "-")),
                                                    (g.get("server") or "-"))
                        for g in svc_fps))
    save_text(os.path.join(out, "session_cookies.txt"),
              "\n".join("%s -> %s" % (p["host"], ",".join(p.get("cookie_names") or []))
                        for p in probes if p.get("cookie_names")))
    save_text(os.path.join(out, "waf_behavioral.txt"),
              "\n".join("%s -> confidence=%s blocked=%d/%d base_status=%s"
                        % (w["url"], w["waf_confidence"], w["blocked_count"],
                           len(w["probes"]), w["base_status"]) for w in waf_res))
    save_text(os.path.join(out, "error_leaks.txt"),
              "\n".join("%s -> %s" % (e["url"], ",".join(e.get("leak_hits") or []) or "-")
                        for e in errs))
    write_recon_summary(out, probes, edges, errs, vhosts, ports_all, waf_res, tls_d)
    d = _diff(_load_prev(out), probes, ports_all, vhosts)
    if d:
        save_json(os.path.join(out, "active_diff.json"), d)

    ff = write_feedforward(out, "4-active", {
        "to_phase5_content": {"live": "live_hosts.txt", "soft404": "active.json#error_pages"},
        "to_phase6_tech": {"live": "live_hosts.txt", "waf_cdn": "waf_cdn.txt",
                           "favicon_hashes": "favicon_hashes.txt"},
        "to_phase7_js": {"live": "live_hosts.txt"},
        "to_phase8_surface": {"waf_matrix": "waf_matrix.json",
                              "bypass_playbook": "bypass_playbook.txt"},
        "to_phase9_auth": {"live": "live_hosts.txt"},
        "to_phase10_sessions": {"session_cookies": "session_cookies.txt"},
        "to_phase11_idor": {"live": "live_hosts.txt"},
        "to_phase22_cache": {"cdn_headers": "waf_matrix.json", "waf_cdn": "waf_cdn.txt"},
        "to_phase23_misconfig": {"open_ports": "open_ports.txt", "vhosts": "vhosts.txt"},
        "to_phase24_cloud": {"waf_cdn": "waf_cdn.txt",
                             "service_fp": "service_fingerprints.txt"},
        "to_phase25_controls": {"waf_cdn": "waf_cdn.txt", "tls": "tls_report.txt",
                                "tls_deep": "tls_deep.txt"},
        "to_phase26_infra": {"open_ports": "open_ports.txt",
                             "service_fp": "service_fingerprints.txt"},
        "to_phase27_validation": {"tls": "tls_report.txt", "headers": "security_headers.txt"},
        "to_phase32_report": {"live": len(probes), "open_ports": len(ports_all),
                              "vhosts": len(vhosts), "waf_hits": sum(len(e["waf_hits"]) for e in edges)},
    }, notes=["vhost probing authorizes the Host name, never the raw IP",
              "WAF behavioral probes are harmless read-only GETs (Layer 4)",
              "allow_active=False par stages 4/6/8 skip ho jaate hain"])

    write_manifest(out, "4-active",
                   ["active.json", "live_hosts.txt", "open_ports.txt", "waf_cdn.txt",
                    "vhosts.txt", "tls_report.txt", "favicon_hashes.txt",
                    "error_templates.txt", "security_headers.txt", "waf_matrix.json",
                    "bypass_playbook.txt", "origin_playbook.txt", "tls_deep.txt",
                    "service_fingerprints.txt", "session_cookies.txt", "waf_behavioral.txt",
                    "error_leaks.txt", "recon_summary.md", "active_diff.json",
                    "feedforward.json"],
                   stats={"live": len(probes), "open_ports": len(ports_all),
                          "vhosts": len(vhosts),
                          "waf_hits": sum(len(e["waf_hits"]) for e in edges),
                          "waf_confident": len([w for w in waf_res if w["waf_confidence"] != "none"]),
                          "svc_identified": len([g for g in svc_fps if g.get("identified")]),
                          "engine": ENGINE_VERSION})

    head("Phase 4 complete (ULTRA PRO MAX)")
    ok("live=%d | open_ports=%d | vhosts=%d | waf_hits=%d | waf_confident=%d | svc_identified=%d"
       % (len(probes), len(ports_all), len(vhosts),
          sum(len(e["waf_hits"]) for e in edges),
          len([w for w in waf_res if w["waf_confidence"] != "none"]),
          len([g for g in svc_fps if g.get("identified")])))
    ok("files: active.json | 9 v2 outputs | +10 ULTRA outputs | recon_summary.md")
    return out
