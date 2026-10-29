#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 5 - Web Content & Endpoint Enumeration  |  ULTRA v3
==========================================================================
Soft-404-aware content discovery + sensitive-artifact hunting + 403 bypass.

ULTRA v3 = v2 ka superset. v2 ke saare output files / JSON keys / checkpoint
keys / feedforward routing Bilkul same rehte hain -> drop-in replacement.
Neeche v3 ke naye techniques:

  1  Auth-wall detection     - 200/302 jo asal me login page hai (false-positive killer)
  2  Dir-listing parser      - "Index of /" pages -> links extract -> auto-recursion
  3  403/401 bypass engine   - 12 path variants x 8 header sets, double-confirm,
                               read-only GET only (HTML tip: "403 ko ignore karna")
  4  .DS_Store parser        - binary se filenames nikaalo -> hidden paths seed
  5  .git intel              - HEAD branch + config remote-URL extraction
  6  .env intel              - KEY names + REDACTED values only (no secret misuse)
  7  Secret sniffing         - 16 patterns (AWS/GH/Slack/Stripe/JWT/key-pem...) on
                               artifact bodies, samples REDACTED (feeds Phase 23)
  8  OpenAPI/Swagger parser  - spec hit -> endpoint list extract (feeds Phase 17)
  9  Nested sitemap crawl    - sitemap index -> child sitemaps (cap 5) -> more URLs
 10  CMS packs               - WordPress/Drupal/Joomla/Laravel/Django/Rails/Tomcat/
                               ASP.NET artifact sets (incl. wp-json users enum hint)
 11  Versioned-API prober    - /api exists -> v1..v5 variant probe
 12  Wordlist synthesis      - seclists + builtin + P2/P3 seeds + robots + sitemap
                               + discovered-basename permutations + app-name guesses
 13  Priority scoring        - har hit ko explainable score (feeds Phase 8 surface)
 14  Param harvest           - sitemap + found URLs se query-param names (Phase 12)
 15  JS hints                - discovered HTML se <script src> list (Phase 7)
 16  Chain hints             - content combos -> multi-phase attack chains (Phase 28)
 17  Findings engine         - P5-### findings + remediation (report-ready)
 18  Cookie surface          - hits ke Set-Cookie names (Phase 10 hint)
 19  Budget guard            - global cap + graceful stop on REQUEST-BUDGET-EXHAUSTED
 20  429-storm guard         - consecutive 429 detect -> limiter.penalize() + warn
 21  Advertised-methods      - Allow header se PUT/DELETE/PATCH report (bina bheje)
 22  Sub-stage checkpoints   - host:file:root/:disc/:ext/:art/:b403/:meth + composite
                               host:<h> (v2 compatible) -> resume partial-stage safe

Safety: GET/HEAD/OPTIONS only. PUT/DELETE/TRACE kabhi nahi. Scope firewall core se
aata hai. Secret values hamesha redact. Phase-5 spec: throttle on, small wordlist
first (WASP_WORDS env), off-peak suggestion jab 429 storm dikhe.

v2 -> v3 in-place contract (wasp_selftest.py ke P5 assertions):
  * content.json results.<host>.{baseline,metadata,found,dirs,extensions,
    artifacts,methods,errors,requests}  <- sab preserved, naye keys ADD hain
  * artifacts[].{path,url,status,len,ct,title,sha1,severity_hint,note}
  * found[] me soft404 hamesha False (noise kabhi report nahi hota)
  * metadata /robots.txt disallow + /sitemap.xml urls parse
  * methods OPTIONS Allow captured
  * checkpoint composite key "host:<host>" + fast resume
"""
import os, re, json, struct
import concurrent.futures as cf
import urllib.parse as up
from wasp_core import (module_ctx, write_feedforward, write_manifest, ProbeCache,
                       soft404_baseline, is_soft404, normalize_url, host_of, port_of,
                       save_json, save_text, sha1, rand_str, title_of, info, ok, warn,
                       err, head, now_iso, progress, similarity, redact)

NAME = "content"
ENGINE_VERSION = "3.0-ultra"

# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# Ye guard core ke save_json/save_text ke upar wrapper lagata hai - isliye
# IS module ka HAR result file (json/txt/md) + uska folder hamesha rwx hoga,
# ULTRA core ho ya ORIGINAL v2 core (graceful degrade par bhi).
# ===========================================================================
def _rwx_result(path):
    """Result file/folder par rwxrwxrwx (0777) enforce (best-effort, Windows-safe)."""
    try:
        os.chmod(path, 0o777)
    except Exception:
        pass

_core_save_json, _core_save_text = save_json, save_text


def _rwx_save_json(path, obj):
    _core_save_json(path, obj)
    _rwx_result(path)                           # result file -> rwx
    _rwx_result(os.path.dirname(path) or ".")   # result folder -> rwx


def _rwx_save_text(path, text):
    _core_save_text(path, text)
    _rwx_result(path)                           # result file -> rwx
    _rwx_result(os.path.dirname(path) or ".")   # result folder -> rwx


save_json = _rwx_save_json      # module rebind: is mod ke SAARE result writes rwx
save_text = _rwx_save_text

_core_write_manifest = write_manifest


def _rwx_tree(root):
    """FINAL SWEEP (RWX RULE): module ke poore result tree par rwxrwxrwx - isse
    v2 core par bhi MANIFEST/feedforward/_state/evidence sab cover ho jaata hai."""
    try:
        for _dp, _dn, _fn in os.walk(root):
            _rwx_result(_dp)
            for _n in _fn:
                _rwx_result(os.path.join(_dp, _n))
    except Exception:
        pass


def _rwx_write_manifest(out, *a, **k):
    r = _core_write_manifest(out, *a, **k)
    _rwx_tree(out)                  # FINAL SWEEP: jitna likha gaya, sab rwx
    return r


write_manifest = _rwx_write_manifest
# ======================== end RWX STANDING RULE ============================

# ---------------------------------------------------------------------------
# WORDLISTS  (builtin ALWAYS merged - seclists optional)
# ---------------------------------------------------------------------------
BUILTIN_WORDS = """admin administrator admins admin1 admin2 adminpanel admin_area admincp adm
login signin sign-in logon logout register signup sign-up auth authentication sso oauth
user users account accounts profile profiles member members customer customers
dashboard panel cpanel controlpanel control panel manager manage console backend backoffice
config configs configuration conf settings setup install installer installation update upgrade
maintenance maintenance.html backup backups bak restore export import dump dumps db database
api apis api/v1 api/v2 api/v3 api/v2/ api/v1/ rest rest/v1 graphql gql graphiql rpc json xml
soap wsdl wadl swagger openapi oas endpoints endpoint services service ws
upload uploads uploaded files file download downloads media assets static public private
tmp temp tempdir cache logs log trace audit
images img css js scripts script fonts docs doc documentation help support faq about
contact mail email webmail smtp newsletter subscribe
test tests testing dev develop development staging stage uat qa demo sandbox preview beta alpha
internal intranet secure hidden secret legacy old new v1 v2 v3
status statuspage health healthz livez readyz ping pong version build info metrics stats
debug trace diagnostics diagnostics.html server-info server-status nginx_status
index home main start default welcome root
search query filter sort list listing orders order items item products product catalog
cart checkout invoice billing payment payments pay subscription plans pricing
robots.txt sitemap.xml sitemap_index.xml sitemap-index.xml humans.txt security.txt
.well-known .git .svn .hg .bzr .env .htaccess .htpasswd .ds_store .gitignore web.config
swagger swagger-ui swagger-ui.html swagger.json swagger.yaml openapi.json openapi.yaml
api-docs api-docs/v1 api-docs/v2 docs documentation redoc api/explorer explorer
actuator actuator/health actuator/env actuator/metrics actuator/mappings actuator/beans
actuator/configprops actuator/loggers actuator/heapdump actuator/threaddump
server-status server-info nginx_status phpinfo.php info.php test.php admin.php config.php
wp-admin wp-login.php wp-content wp-includes wp-json wp-json/wp/v2/users xmlrpc.php
wp-config.php.bak wp-content/debug.log wp-content/uploads readme.html
administrator phpmyadmin pma adminer adminer.php dbadmin mysql pma/setup
backup.zip backup.tar.gz backup.tar backup.sql db.sql dump.sql database.sql site.sql data.sql
web.config crossdomain.xml clientaccesspolicy.xml manifest.json package.json composer.json
elmah.axd trace.axd manager manager/html host-manager examples jenkins ci
cgi-bin scripts includes library lib modules plugins themes
kb wiki forum blog news press shop store inventory reports analytics
gateway proxy forward lb healthcheck health-check metrics-server
console.html admin.html login.html home.html index.html test.html
.jenkins .terraform .vagrant .docker traefik portainer kibana grafana prometheus
elasticsearch solr rabbitmq activemq kafka zookeeper redis memcached"""

EXTENSIONS = ["", ".php", ".php5", ".phtml", ".asp", ".aspx", ".ashx", ".asmx", ".axd",
              ".jsp", ".jspx", ".do", ".action", ".cgi", ".pl", ".py", ".rb", ".lua",
              ".html", ".htm", ".shtml", ".json", ".xml", ".txt", ".md", ".yml", ".yaml",
              ".bak", ".old", ".orig", ".save", ".swp", ".swo", ".copy", ".disabled",
              ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".sql", ".sqlite",
              ".db", ".mdb", ".log", ".conf", ".config", ".ini", ".env", ".pem", ".key",
              ".pdf", ".csv", ".xls", ".xlsx", ".map", ".min.js", ".dist", ".sample",
              ".tpl", ".twig", ".inc", ".dat", ".dump"]

BACKUP_SUFFIXES = ["~", ".bak", ".bak1", ".bak2", ".old", ".orig", ".save", ".swp", ".swo",
                   ".tmp", ".copy", ".1", ".2", ".3", ".save.1", ".disabled", ".txt",
                   ".zip", ".tar.gz", ".rar", ".7z", ".backup", ".bkp", ".dist", ".new"]

VCS_PATHS = ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD", "/.gitignore",
             "/.git/packed-refs", "/.git/FETCH_HEAD", "/.git/description", "/.git/refs/",
             "/.svn/entries", "/.svn/wc.db", "/.svn/README.txt", "/.hg/requires",
             "/.hg/hgrc", "/.bzr/README", "/.CVS/Root", "/.CVS/Entries",
             "/.DS_Store", "/.env", "/.env.local", "/.env.production", "/.env.staging",
             "/.env.dev", "/.env.backup", "/.env.save", "/.aws/credentials",
             "/.ssh/id_rsa", "/.ssh/authorized_keys", "/.ssh/id_dsa", "/.kube/config",
             "/.npmrc", "/.yarnrc", "/.dockerenv", "/.docker/config.json",
             "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml", "/.dockerignore",
             "/Jenkinsfile", "/.gitlab-ci.yml", "/.travis.yml", "/.circleci/config.yml",
             "/bitbucket-pipelines.yml", "/.github/workflows/main.yml",
             "/package.json", "/package-lock.json", "/yarn.lock", "/composer.json",
             "/composer.lock", "/Gemfile", "/Gemfile.lock", "/requirements.txt",
             "/Pipfile", "/Pipfile.lock", "/go.mod", "/pom.xml", "/build.gradle",
             "/.terraform.lock.hcl", "/terraform.tfstate", "/terraform.tfstate.backup",
             "/serverless.yml", "/Procfile", "/.htaccess", "/.htpasswd", "/web.config",
             "/phpunit.xml", "/.editorconfig", "/.prettierrc", "/tsconfig.json",
             "/nuxt.config.js", "/next.config.js", "/vite.config.js", "/.babelrc",
             "/appsettings.json", "/app/etc/env.php", "/sites/default/settings.php",
             "/config/database.yml", "/config/secrets.yml", "/wp-config.php.bak",
             "/dump.sql", "/database.yml", "/settings.py", "/local_settings.py"]

API_DOC_PATHS = ["/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
                 "/swagger-ui/index.html", "/openapi.json", "/openapi.yaml",
                 "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json",
                 "/api-docs", "/api/docs", "/api/documentation", "/v2/api-docs",
                 "/v3/api-docs", "/api-docs/v2", "/docs/openapi.json", "/docs/api",
                 "/redoc", "/graphql", "/api/graphql", "/graphiql", "/altair",
                 "/playground", "/voyager", "/graphql/schema.json", "/api/v1/schema",
                 "/swagger-resources", "/configuration/ui", "/.well-known/openapi.json",
                 "/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics",
                 "/actuator/mappings", "/actuator/beans", "/actuator/heapdump",
                 "/actuator/threaddump", "/actuator/loggers", "/actuator/configprops",
                 "/actuator/auditevents", "/actuator/scheduledtasks",
                 "/metrics", "/healthz", "/livez", "/readyz", "/health", "/status",
                 "/debug/pprof", "/debug/pprof/heap", "/debug/vars", "/server-status",
                 "/server-info", "/nginx_status", "/phpinfo.php", "/info.php",
                 "/test.php", "/elmah.axd", "/trace.axd", "/console", "/adminer.php",
                 "/phpmyadmin/", "/pma/", "/kibana/", "/grafana/", "/prometheus/",
                 "/.well-known/security.txt", "/security.txt",
                 "/.well-known/change-password", "/.well-known/nodeinfo",
                 "/.well-known/webfinger", "/.well-known/assetlinks.json",
                 "/.well-known/apple-app-site-association", "/.well-known/ai-plugin.json",
                 "/.well-known/matrix/server", "/robots.txt", "/sitemap.xml",
                 "/sitemap_index.xml", "/sitemap-index.xml", "/humans.txt",
                 "/crossdomain.xml", "/clientaccesspolicy.xml", "/manifest.json"]

WELLKNOWN_EXTRA = ["/.well-known/security.txt", "/.well-known/assetlinks.json",
                   "/.well-known/apple-app-site-association", "/.well-known/openapi.json"]

# ---------------------------------------------------------------------------
# CMS PACKS  (read-only artifact probes; wp-json users is a GET JSON list)
# ---------------------------------------------------------------------------
CMS_PACKS = {
    "WordPress": [
        ("/wp-json/wp/v2/users", "REST user enumeration - GET list of authors (read-only)", "medium"),
        ("/wp-content/debug.log", "WP debug log exposed", "high"),
        ("/wp-content/uploads/", "uploads dir - dirlisting check", "info"),
        ("/xmlrpc.php", "XML-RPC interface present (bruteforce/pingback surface)", "info"),
        ("/readme.html", "WP readme - version disclosure", "info"),
        ("/wp-links-opml.php", "WP OPML endpoint", "info"),
        ("/wp-config.php.bak", "wp-config backup", "critical"),
    ],
    "Drupal": [
        ("/CHANGELOG.txt", "Drupal changelog - version disclosure", "info"),
        ("/user/login", "Drupal login page", "info"),
        ("/core/install.php", "install script reachable", "medium"),
        ("/sites/default/settings.php", "Drupal settings file", "critical"),
        ("/admin/config", "Drupal admin config route", "info"),
    ],
    "Joomla": [
        ("/administrator/", "Joomla admin panel", "info"),
        ("/administrator/manifests/files/joomla.xml", "Joomla version manifest", "info"),
        ("/configuration.php~", "Joomla config backup", "critical"),
        ("/installation/", "installation directory present", "medium"),
    ],
    "Laravel": [
        ("/storage/logs/laravel.log", "Laravel application log exposed", "high"),
        ("/telescope", "Laravel Telescope dashboard", "medium"),
        ("/horizon", "Laravel Horizon dashboard", "medium"),
        ("/storage/framework/sessions/", "session storage dir", "high"),
    ],
    "Django": [
        ("/admin/login/", "Django admin login", "info"),
        ("/static/", "static dir", "info"),
        ("/media/", "media dir", "info"),
        ("/accounts/login/", "Django auth route", "info"),
    ],
    "Rails": [
        ("/rails/info/routes", "Rails routes info - endpoint map", "high"),
        ("/rails/info", "Rails info page", "medium"),
        ("/config/secrets.yml", "Rails secrets file", "critical"),
        ("/config/database.yml", "Rails DB config", "critical"),
    ],
    "Tomcat": [
        ("/manager/html", "Tomcat manager", "high"),
        ("/host-manager/", "Tomcat host manager", "high"),
        ("/examples/", "Tomcat examples", "info"),
        ("/WEB-INF/web.xml", "WEB-INF access attempt", "info"),
    ],
    "ASP.NET": [
        ("/elmah.axd", "ELMAH error log", "high"),
        ("/trace.axd", "ASP.NET trace", "high"),
        ("/web.config.bak", "web.config backup", "critical"),
        ("/_vti_bin/", "FrontPage/SharePoint services", "info"),
    ],
}

# ---------------------------------------------------------------------------
# DETECTION REGEXES
# ---------------------------------------------------------------------------
IGNORE_EXT_RE = re.compile(
    r"(?i)\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|css|webp|avif|mp[34]|webm|ogg|wav)$")
HASEXT_RE = re.compile(r"\.[A-Za-z0-9]{2,6}$")

LOGIN_TITLE_RE = re.compile(
    r"(?i)(\blogin\b|\blog ?in\b|\bsign ?in\b|authenticate|authentication|unauthori[sz]ed"
    r"|access denied|forbidden|member area|portal|401|403)")
LOGIN_FORM_RE = re.compile(r"(?is)<input[^>]{0,200}type=[\"']?password")
LOGIN_LOC_RE = re.compile(r"(?i)/(login|signin|sign-in|logon|auth|sso|session)(\.|$|[/?#])")

DIRLIST_TITLE_RE = re.compile(r"(?i)(index of /|directory listing for|listdir)")
DIRLIST_BODY_RE = re.compile(r"(?is)(parent directory|<h1>index of|directory listing for)")
DIRLIST_HREF_RE = re.compile(r"(?is)href=[\"']([^\"'?&]+)[\"']")

INTERESTING_STATUS = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 501}

HIGH_VALUE_RE = re.compile(
    r"(?i)(admin|administrator|config|backup|\.env|\.git|\.svn|debug|api\b|internal|"
    r"secret|private|swagger|openapi|actuator|\.bak|\.old|upload|console|graphql|"
    r"metrics|health|server-status|phpinfo|terraform|dockerfile|jenkins|dump|export|"
    r"db\b|sql|database|creds?|password|token|key|credential|staging|dev\.|test\.|"
    r"bin/|shell|cmd|exec|install|setup|phpmyadmin|adminer|manager|panel|portal)")

WORD_HINT_RE = re.compile(r"(?i)^[a-z0-9_\-./]{2,40}$")

SEVERITY_TABLE = [
    (r"(?i)\.env(\.|$)", "critical", "environment file - secrets commonly inside"),
    (r"(?i)terraform\.tfstate", "critical", "terraform state - secrets in plain text"),
    (r"(?i)\.(pem|key|p12|pfx|jks)$", "critical", "cryptographic key material exposed"),
    (r"(?i)(id_rsa|id_dsa|authorized_keys)", "critical", "SSH key material exposed"),
    (r"(?i)\.kube/config", "critical", "Kubernetes config - cluster credentials"),
    (r"(?i)\.aws/credentials", "critical", "AWS credentials file"),
    (r"(?i)\.(sql|dump|sqlite|mdb)$", "critical", "database dump/file reachable"),
    (r"(?i)(settings\.php|secrets\.yml|database\.yml|env\.php|web\.config(\.bak)?)$",
     "critical", "application config with possible credentials"),
    (r"(?i)^/\.git/(HEAD|config|index|logs)", "high", "git repository exposed - source recoverable"),
    (r"(?i)^/\.svn/|^/\.hg/|^/\.bzr/|^/\.CVS/", "high", "VCS metadata exposed"),
    (r"(?i)\.htpasswd", "high", "htpasswd - password hashes"),
    (r"(?i)(Jenkinsfile|\.gitlab-ci|\.travis|\.circleci|bitbucket-pipelines)",
     "high", "CI/CD pipeline file - internal names, stages, possible secrets"),
    (r"(?i)docker-compose|Dockerfile|\.docker/config", "high",
     "container config - internal topology/secrets"),
    (r"(?i)(\.npmrc)", "high", "npmrc - may contain registry auth token"),
    (r"(?i)(actuator/(env|heapdump|configprops|auditevents)|/phpinfo\.php|server-status|"
     r"nginx_status|/debug/pprof|/trace\.axd|/elmah\.axd)", "high",
     "ops/diagnostics endpoint - internal data leak"),
    (r"(?i)(\.DS_Store)", "medium", "macOS metadata - filenames/dirs recoverable"),
    (r"(?i)(debug\.log|laravel\.log|\.log$)", "high", "log file exposed - sensitive data common"),
    (r"(?i)(manager/html|host-manager)", "high", "Tomcat manager interface"),
    (r"(?i)(wp-json/wp/v2/users)", "medium", "REST user enumeration (authors list)"),
    (r"(?i)(swagger|openapi|api-docs|/docs/api|graphql|graphiql|redoc|playground)",
     "info", "API specification/IDE exposed - full endpoint map"),
    (r"(?i)(robots\.txt|sitemap|humans\.txt|security\.txt|manifest\.json|package\.json"
     r"|composer\.json|readme\.html|CHANGELOG)", "info", "metadata file"),
    (r"(?i)(telescope|horizon|kibana|grafana|prometheus|adminer|phpmyadmin)",
     "medium", "admin/dev dashboard reachable"),
    (r"(?i)(crossdomain\.xml|clientaccesspolicy\.xml)", "low",
     "flash/silverlight policy - permissive values worth reviewing"),
]

# ---------------------------------------------------------------------------
# SECRET SNIFFING  (values NEVER stored raw - redact() from core)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
    ("github_token", r"\bgh[pousr]_[0-9A-Za-z]{30,}\b", "critical"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "critical"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    ("stripe_secret", r"\bsk_live_[0-9a-zA-Z]{16,}\b", "critical"),
    ("stripe_publishable", r"\bpk_live_[0-9a-zA-Z]{16,}\b", "info"),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b", "high"),
    ("twilio_sid", r"\bAC[0-9a-fA-F]{32}\b", "medium"),
    ("mailgun_key", r"\bkey-[0-9a-zA-Z]{32}\b", "high"),
    ("firebase_server_key", r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}\b", "high"),
    ("private_key_header", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "critical"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b", "medium"),
    ("db_uri_creds", r"(?i)\b(mongodb(\+srv)?|postgres(ql)?|mysql|amqp)://[^\s/\"']+:[^\s@/\"']+@", "critical"),
    ("generic_password_assign", r"(?i)\b(password|passwd|pwd|secret|token)\b[\"']?\s*[:=]\s*[\"']?[^\s\"';]{6,}", "high"),
    ("connection_string", r"(?i)\b(Server|Data Source)\s*=.*?(Password|Pwd)\s*=", "high"),
    ("generic_api_key", r"(?i)\bapi[_\-]?key\b[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", "high"),
]

# ---------------------------------------------------------------------------
# 403/401 BYPASS ENGINE TABLES  (read-only GET only)
# ---------------------------------------------------------------------------
def _bypass_path_variants(p):
    """12 curated path-shape variants for a blocked path p (p = /admin style)."""
    p = "/" + (p or "").strip("/")
    pl = p.lstrip("/")
    return [
        p + "/.",            # dot suffix (many front controllers)
        p + "//",            # double slash
        "//" + pl,           # protocol-ish double slash
        "/./" + pl,          # dot segment
        p + "/%2e",          # encoded dot
        p + "/..;/",         # Tomcat /..;/
        p + "/.;",           # Tomcat path-param
        p + "/%20",          # trailing encoded space
        p + "/%09",          # trailing TAB
        p + ".css",          # extension spoof (static allowlist)
        p + ".js",           # extension spoof
        p + "/%2e%2e/",      # encoded traversal
    ]


def _bypass_header_sets(p, base_url):
    """8 curated header trick-sets (authorisation-layer confusion)."""
    return [
        {"X-Original-URL": p},
        {"X-Rewrite-URL": p},
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1", "X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost", "X-Host": "localhost"},
        {"Referer": base_url.rstrip("/") + p, "Origin": base_url.rstrip("/")},
        {"X-Forwarded-Ssl": "on", "X-Url-Scheme": "https"},
    ]

# ---------------------------------------------------------------------------
# SMALL UTILS
# ---------------------------------------------------------------------------
def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def norm_path(p):
    p = (p or "").strip()
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    return p.split("?")[0].split("#")[0] or "/"


def basename_of(p):
    return (p or "").strip("/").split("/")[-1] if (p or "").strip("/") else ""


def safe_name(host):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host)


def gcap_get(cfg, key, default):
    return getattr(cfg, key, default)


def budget_left(http):
    """Global request budget remaining (core Budget)."""
    try:
        return http.budget.remaining()
    except Exception:
        return 999999


def collect_cookie_names(resp):
    """Set-Cookie names from a Resp (list of raw header strings)."""
    names = []
    for sc in (getattr(resp, "set_cookies", None) or []):
        m = re.match(r"\s*([^=;]+)\s*=", sc or "")
        if m:
            names.append(m.group(1))
    return names


def classify_authwall(r, body):
    """200/302 that is actually a login/auth wall -> false positive killer."""
    if r.error:
        return None
    title = title_of(body)
    if LOGIN_FORM_RE.search(body[:4000]):
        return "login-form"
    if title and LOGIN_TITLE_RE.search(title) and ("<form" in body[:4000].lower()):
        return "login-title+form"
    if title and title.lower().strip() in ("login", "sign in", "log in", "signin",
                                           "authentication", "unauthorized", "401",
                                           "403", "forbidden", "access denied"):
        return "login-title"
    loc = r.hget("Location") or ""
    if r.status in (301, 302, 303, 307, 308) and LOGIN_LOC_RE.search(loc):
        return "redirect-to-login"
    return None


def classify_dirlisting(r, body):
    """Apache/nginx autoindex detection + href extraction."""
    if r.error or r.status != 200:
        return False, []
    title = title_of(body)
    head40 = body[:400]
    if (title and DIRLIST_TITLE_RE.search(title)) or DIRLIST_BODY_RE.search(head40) \
            or DIRLIST_BODY_RE.search(body[:4000]):
        hrefs = []
        for h in DIRLIST_HREF_RE.findall(body[:60000]):
            h = h.strip()
            if not h or h.startswith(("#", "javascript:", "mailto:")):
                continue
            if h in ("..", "../", "/"):
                continue
            hrefs.append(h)
        return True, hrefs[:80]
    return False, []


def sniff_secrets(body_text, limit=12):
    """Run SECRET_PATTERNS over a body; samples are REDACTED (never raw)."""
    hits = []
    window = body_text[:200000]
    for name, rx, sev in SECRET_PATTERNS:
        try:
            m = re.search(rx, window)
        except re.error:
            continue
        if m:
            hits.append({"type": name, "severity": sev,
                         "sample_redacted": redact(m.group(0), keep=4)})
        if len(hits) >= limit:
            break
    return hits


def severity_for_path(path, note=""):
    for rx, sev, why in SEVERITY_TABLE:
        try:
            if re.search(rx, path or ""):
                return sev, why
        except re.error:
            continue
    return "", ""

# ---------------------------------------------------------------------------
# WORDLIST ENGINE
# ---------------------------------------------------------------------------
SECLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def builtin_words():
    return [w for w in (x.strip() for x in BUILTIN_WORDS.split()) if w]


def load_wordlist(limit=4000):
    """v2-compatible: seclists priority, capped by limit; builtin is ALWAYS added
    by the caller (wordlist_build) so selftest/small modes never lose core words."""
    for p in SECLISTS:
        if os.path.exists(p):
            words = []
            try:
                with open(p, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        words.append(line.lstrip("/"))
                        if len(words) >= limit:
                            break
                if words:
                    return [w for w in words if WORD_HINT_RE.match(w)], "seclists:" + os.path.basename(p)
            except Exception:
                continue
    return builtin_words(), "builtin"


def seed_words(out_dir, scope):
    """Merge Phase 2 endpoints + Phase 3 dir_seeds into the wordlist (v2 same)."""
    seeds = set()
    eng = os.path.dirname(out_dir)
    p2 = os.path.join(eng, "understand", "endpoints.txt")
    if os.path.exists(p2):
        for line in open(p2, errors="ignore"):
            s = line.strip().lstrip("/")
            if s and len(s) < 60 and not re.search(r"[?&=]", s):
                seeds.add(s)
                if "/" in s:
                    seeds.add(s.split("/")[0])
                    seeds.add(s.split("/")[-1])
    p3 = os.path.join(eng, "passive", "findings", "dir_seeds.txt")
    if os.path.exists(p3):
        for line in open(p3, errors="ignore"):
            s = line.strip().lstrip("/")
            if s and len(s) < 40:
                seeds.add(s)
    return sorted(s for s in seeds if WORD_HINT_RE.match(s))


def app_name_guesses(seeds, host):
    """ULTRA: application-name guesses for mutation (host label + tokenised seeds)."""
    guesses = set()
    host_main = (host or "").split(".")[0]
    if 2 <= len(host_main) <= 20 and re.match(r"(?i)^[a-z0-9_\-]+$", host_main) \
            and host_main not in ("www", "app", "web", "mail", "api", "dev", "test"):
        guesses.add(host_main)
    for s in seeds[:200]:
        if 3 <= len(s) <= 24 and re.match(r"(?i)^[a-z][a-z0-9\-_]+$", s):
            guesses.add(s)
    return sorted(guesses)[:12]


def mutate_words(words, guesses, cfg):
    """ULTRA: bounded permutations - app-name joins + optional case variants."""
    out = set()
    g = [x for x in guesses if x][:6]
    joiners = ["", "-", "_"]
    for base in g:
        for word in ("admin", "api", "app", "portal", "backend", "dashboard", "auth"):
            for j in joiners:
                out.add("%s%s%s" % (base, j, word))
                out.add("%s%s%s" % (word, j, base))
    if gcap_get(cfg, "content_case_variants", False):
        for w in ("admin", "api", "login", "dashboard", "config"):
            out.add(w.capitalize())
            out.add(w.upper())
    return sorted(w for w in out if WORD_HINT_RE.match(w))


def wordlist_build(cfg, out_dir, scope, robots_hints, sitemap_words, found_basenames):
    """Full ULTRA wordlist synthesis. Returns (words, source_desc)."""
    limit = int(os.environ.get("WASP_WORDS", "4000"))
    wl, wsrc = load_wordlist(limit)
    seeds = seed_words(out_dir, scope)
    guesses = app_name_guesses(seeds or [], (scope.seed_urls() or [""])[0])
    muts = mutate_words(seeds or [], guesses, cfg)
    merged = set(wl) | set(builtin_words()) | set(seeds) | set(muts)
    merged |= set(h.strip("/") for h in robots_hints if h and h.strip("/") not in ("", "*"))
    merged |= set(sitemap_words)
    merged |= set(found_basenames)
    words = sorted(w for w in merged if w and len(w) <= 60 and WORD_HINT_RE.match(w))
    return words, "%s +%d builtin +%d seeds +%d mutations +%d robots/sitemap/basenames" % (
        wsrc, len(builtin_words()), len(seeds), len(muts),
        len(robots_hints) + len(sitemap_words) + len(found_basenames))

# ---------------------------------------------------------------------------
# BASELINE (v2 core soft-404) + ULTRA auth-redirect fingerprint
# ---------------------------------------------------------------------------
def build_baseline(http, base_url, cfg):
    """soft404_baseline + auth-redirect fingerprint (random path -> login?)."""
    base = soft404_baseline(http, base_url, samples=5)
    if not base:
        return {}
    try:
        p = "/%s-%s" % (rand_str(6), rand_str(4))
        r = http.request("GET", "%s/%s" % (base_url.rstrip("/"), p), allow_redirects=False)
        if not r.error:
            loc = r.hget("Location") or ""
            base["auth_redirect"] = bool(r.status in (301, 302, 303) and LOGIN_LOC_RE.search(loc))
            base["catchall_is_json"] = bool(r.is_json())
            base["catchall_len"] = len(r.body)
    except Exception:
        pass
    return base

# ---------------------------------------------------------------------------
# DISCOVERY ENGINE  (threaded BFS, budget-guarded, 429-aware)
# ---------------------------------------------------------------------------
def _mk_rec(p, url, r, depth, base):
    rec = {"path": p, "url": url, "status": r.status, "len": len(r.body),
           "ct": r.hget("Content-Type"), "location": r.hget("Location"),
           "title": title_of(r.text), "sha1": r.sha1(), "depth": depth,
           "soft404": False}
    return rec


def discover(cfg, scope, http, base_url, words, base, cap=None, stats=None):
    """Depth-limited BFS discovery. v2 signature (cfg, scope, http, base_url,
    words, base, cap) kept; returns a RESULT DICT (v2 tuple upgraded):
      {found, dirs, errors, probed, dirlistings, authwalls, blocked_403, budget_stop}

    ULTRA behaviours:
      * auth-wall marking (200/302 login pages flagged, not treated as juicy hits)
      * dir-listing parse -> children auto-enqueued (bounded)
      * 403/401 paths collected for the bypass engine
      * 429-storm detect -> limiter.penalize + user warn (off-peak suggestion)
      * REQUEST-BUDGET-EXHAUSTED -> graceful stop, partial results kept
      * case-routing note: /Admin hit where /admin missed (Windows/IIS)
    """
    root = base_url.rstrip("/")
    max_depth = int(gcap_get(cfg, "content_max_depth", 2))
    per_level_cap = int(gcap_get(cfg, "content_level_cap", 900))
    total_cap = cap or int(gcap_get(cfg, "content_total_cap", 4000))
    max_children = int(gcap_get(cfg, "content_dirlist_children", 40))
    max_dirlist_total = int(gcap_get(cfg, "content_dirlist_max", 200))

    out = {"found": [], "dirs": [], "errors": 0, "probed": 0,
           "dirlistings": [], "authwalls": [], "blocked_403": [],
           "budget_stop": False, "throttle_events": 0}
    seen = set()
    seen_lc = set()
    enqueued = set()   # queued-but-maybe-not-yet-probed (children/redirects)
    dirlist_children_done = 0
    queue = [(w.strip("/"), 0) for w in uniq(words) if w.strip("/")]
    consecutive_429 = 0

    def probe(item):
        path, depth = item
        p = (path or "").lstrip("/")
        if not p or p in seen or p.lower() in seen_lc:
            return None
        seen.add(p)
        seen_lc.add(p.lower())
        url = "%s/%s" % (root, p)
        try:
            r = http.request("GET", url, allow_redirects=True)
        except Exception as e:
            return ("error", {"path": "/" + p, "error": str(e)})
        if r.error:
            return ("error", {"path": "/" + p, "error": r.error})
        return ("rec", ("/" + p, url, r, depth))

    for depth in range(max_depth + 1):
        level = [q for q in queue if q[1] == depth][:per_level_cap]
        if not level:
            break
        info("  depth %d: probing %d paths..." % (depth, len(level)))
        done_n = 0
        with cf.ThreadPoolExecutor(max_workers=max(4, int(getattr(cfg, "concurrency", 8)))) as ex:
            futs = {ex.submit(probe, it): it for it in level}
            for fut in cf.as_completed(futs):
                done_n += 1
                if done_n % 25 == 0 or done_n == len(level):
                    progress(done_n, len(level), "depth %d" % depth)
                out["probed"] += 1
                try:
                    res = fut.result()
                except Exception:
                    out["errors"] += 1
                    continue
                if res is None:
                    continue
                kind, val = res
                if kind == "error":
                    if "BUDGET-EXHAUSTED" in str(val.get("error", "")):
                        out["budget_stop"] = True
                        warn("  request budget exhausted -> discovery graceful-stop")
                        break
                    out["errors"] += 1
                    continue
                p, url, r, dep = val
                if r.status == 429:
                    consecutive_429 += 1
                    out["throttle_events"] += 1
                    if consecutive_429 >= 3 and consecutive_429 % 3 == 0:
                        try:
                            http.limiter.penalize()
                        except Exception:
                            pass
                        warn("  429 storm (%d) - auto-throttled; off-peak hours try karo" % consecutive_429)
                    continue
                consecutive_429 = 0
                chain0 = getattr(r, "chain", None) or []
                body = r.text
                if is_soft404(r, base):
                    continue
                authwall = classify_authwall(r, body) if gcap_get(cfg, "content_authwall_detect", True) else None
                rec = _mk_rec(p, url, r, dep, base)
                if len(chain0) > 1:
                    rec["redirect_chain"] = [{"status": h.get("status"),
                                              "location": h.get("location")}
                                             for h in chain0[:-1]]
                    rec["final_url"] = chain0[-1].get("url") or url
                if authwall:
                    rec["auth_wall"] = True
                    rec["auth_wall_reason"] = authwall
                    out["authwalls"].append({"path": rec["path"], "reason": authwall,
                                             "status": r.status, "url": url})
                if r.status in (401, 403) and rec["path"] not in out["blocked_403"]:
                    out["blocked_403"].append(rec["path"])
                # redirect intel from FOLLOWED chain (core manual-chain mode)
                if len(chain0) > 1 and chain0[0].get("status") in (301, 302, 303, 307, 308):
                    out["dirs"].append({"path": rec["path"],
                                        "location": chain0[0].get("location"),
                                        "status": chain0[0].get("status")})
                elif rec["status"] in (301, 302, 303, 307, 308) and rec["location"]:
                    # unfollowed (cross-host / out-of-scope target)
                    out["dirs"].append({"path": rec["path"], "location": rec["location"],
                                        "status": rec["status"]})
                    seg = up.urlparse(up.urljoin(rec["url"], rec["location"])).path.lstrip("/")
                    if seg and dep + 1 <= max_depth and seg not in enqueued \
                            and seg.lower() not in seen_lc and len(seg) <= 120:
                        enqueued.add(seg)
                        queue.append((seg, dep + 1))
                    if authwall:
                        continue
                if r.status in INTERESTING_STATUS and not IGNORE_EXT_RE.search(rec["path"]):
                    out["found"].append(rec)
                    cookies = collect_cookie_names(r)
                    if cookies:
                        rec["cookies"] = cookies
                    is_dl, hrefs = (False, [])
                    if gcap_get(cfg, "content_dirlisting_parse", True) and r.status == 200:
                        is_dl, hrefs = classify_dirlisting(r, body)
                    if is_dl:
                        rec["dirlisting"] = True
                        out["dirlistings"].append({"path": rec["path"], "url": url,
                                                   "links": len(hrefs)})
                        # enqueue children (bounded)
                        if dep + 1 <= max_depth and dirlist_children_done < max_dirlist_total:
                            base_dir = p.rstrip("/") if p else ""
                            take = 0
                            for h in hrefs:
                                if take >= max_children or dirlist_children_done >= max_dirlist_total:
                                    break
                                h = h.lstrip("/")
                                if not h or h.startswith(("http://", "https://")):
                                    continue
                                child = ("%s/%s" % (base_dir, h)).strip("/")
                                if not child or child.lower() in seen_lc \
                                        or child in enqueued or len(child) > 120:
                                    continue
                                enqueued.add(child)
                                queue.append((child, dep + 1))
                                dirlist_children_done += 1
                                take += 1
                    elif r.status in (301, 302, 303, 307, 308) and rec["location"]:
                        pass  # already recorded above (chain or unfollowed)
                    elif r.status == 200 and "html" in (rec["ct"] or "").lower() \
                            and not HASEXT_RE.search(rec["path"]):
                        # /x -> /x/ deeper probe (trailing slash variant)
                        deeper = p + "/"
                        if dep + 1 <= max_depth and deeper not in enqueued:
                            enqueued.add(deeper)
                            queue.append((deeper, dep + 1))
                if out["probed"] >= total_cap:
                    warn("  per-host request cap (%d) reached - stopping discovery" % total_cap)
                    return out
            if out["budget_stop"]:
                break
        if out["probed"] >= total_cap or out["budget_stop"]:
            break
    return out


def extension_sweep(http, root, base, basenames, exts, cap=600):
    """v2-compatible sweep + .js.map sourcemap flag."""
    hits, n = [], 0
    for bn in basenames:
        for e in exts:
            if not e:
                continue
            n += 1
            if n > cap:
                return hits
            if budget_left(http) <= 0:
                warn("  budget exhausted - extension sweep stopped early")
                return hits
            url = "%s/%s%s" % (root, bn, e)
            r = http.request("GET", url, allow_redirects=False)
            if r.error or r.status in (404, 400, 410) or is_soft404(r, base):
                continue
            if r.status in INTERESTING_STATUS and not IGNORE_EXT_RE.search(url):
                hits.append({"url": url, "path": "/%s%s" % (bn.strip("/"), e),
                             "status": r.status, "len": len(r.body),
                             "ct": r.hget("Content-Type"), "title": title_of(r.text),
                             "sha1": r.sha1(), "soft404": False,
                             "sourcemap": url.endswith((".map", ".js.map"))})
    return hits

# ---------------------------------------------------------------------------
# METADATA STAGE (robots / sitemap / security.txt / humans + nested crawl)
# ---------------------------------------------------------------------------
def metadata(http, base_url, base, cfg=None):
    root = base_url.rstrip("/")
    out = {}
    paths = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
             "/humans.txt", "/security.txt", "/.well-known/security.txt",
             "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association"]
    for path in paths:
        try:
            r = http.request("GET", root + path, allow_redirects=True,
                             save="meta_%s" % re.sub(r"[^A-Za-z0-9]", "_", path))
        except Exception:
            continue
        if r.error or r.status == 404 or r.status == 410 or is_soft404(r, base):
            continue
        rec = {"status": r.status, "len": len(r.body), "ct": r.hget("Content-Type")}
        body = r.text
        if "robots" in path:
            rec["disallow"] = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body)[:80]
            rec["allow"] = re.findall(r"(?im)^\s*Allow:\s*(\S+)", body)[:40]
            rec["sitemaps"] = re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", body)[:20]
            rec["wildcards"] = [d for d in rec["disallow"] if "*" in d]
        elif "sitemap" in path:
            rec["urls"] = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)[:300]
            rec["nested_sitemaps"] = [u for u in rec["urls"] if u.endswith(".xml")][:20]
            # ULTRA: nested sitemap crawl (1 level, capped)
            if cfg is not None and gcap_get(cfg, "content_nested_sitemap", True) \
                    and rec["nested_sitemaps"]:
                nested = []
                for sm in rec["nested_sitemaps"][:5]:
                    if budget_left(http) <= 0:
                        break
                    if not (sm.startswith("http://") or sm.startswith("https://")):
                        continue
                    try:
                        r2 = http.request("GET", sm, allow_redirects=True)
                    except Exception:
                        continue
                    if r2.error or r2.status != 200:
                        continue
                    got = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r2.text[:200000])[:200]
                    nested.extend(got)
                if nested:
                    rec["nested_urls"] = uniq(nested)[:300]
                    rec["urls"] = uniq(rec["urls"] + rec["nested_urls"])[:400]
        elif "security.txt" in path:
            rec["contacts"] = re.findall(r"(?im)^\s*Contact:\s*(\S+)", body)[:10]
            rec["policy"] = (re.findall(r"(?im)^\s*Policy:\s*(\S+)", body) or [""])[0]
        elif "assetlinks" in path or "app-site-association" in path:
            rec["json_ok"] = bool(r.is_json())
            rec["apps"] = re.findall(r"(?i)([a-z]{2,6}\.[\w.]+)", body)[:10]
        out[path] = rec
    return out

# ---------------------------------------------------------------------------
# ARTIFACT PARSERS  (.git / .env / .DS_Store / openapi / web.config)
# ---------------------------------------------------------------------------
def git_head_parse(text):
    m = re.match(r"ref:\s*refs/heads/(\S+)", (text or "").strip())
    return m.group(1) if m else ""


def git_config_parse(text):
    remotes = re.findall(r"(?im)^\s*url\s*=\s*(\S+)", text or "")
    return remotes[:5]


def env_parse(text, max_keys=30):
    """KEY names + REDACTED values only (no secret misuse)."""
    keys, sample = [], []
    for m in re.finditer(r"(?im)^([A-Za-z_][A-Za-z0-9_.]{1,60})\s*=\s*(.+?)\s*$", text or ""):
        k, v = m.group(1), m.group(2).strip().strip("'\"")
        if not v or v in ("-"):
            continue
        keys.append(k)
        if len(sample) < 5 and len(v) >= 4:
            sample.append({"key": k, "value_redacted": redact(v, keep=3)})
    return {"keys": keys[:max_keys], "n_keys": len(keys), "samples_redacted": sample,
            "has_secretish": any(re.search(r"(?i)(pass|secret|token|key|cred)", k) for k in keys)}


def ds_store_names(body, max_names=60):
    """Parse macOS .DS_Store binary -> extracted filenames (hidden dirs goldmine)."""
    names, i, n = [], 0, len(body)
    while i < n - 6 and len(names) < max_names:
        if body[i:i + 4] != b"\x00\x00\x00\x01":
            i += 1
            continue
        try:
            name_len = struct.unpack(">H", body[i + 4:i + 6])[0]
            raw = body[i + 6:i + 6 + name_len * 2]
            if len(raw) == name_len * 2 and 1 <= name_len <= 128:
                nm = raw.decode("utf-16-be", "ignore")
                if nm and re.match(r"^[\w .\-()#]+$", nm) and nm not in names:
                    names.append(nm)
                i += 6 + name_len * 2 + 4
                continue
        except Exception:
            pass
        i += 4
    return names


def openapi_parse(text, max_paths=300):
    """OpenAPI/Swagger spec -> path list + method count (feeds Phase 17)."""
    paths, methods = [], 0
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("paths"), dict):
            for p, ops in data["paths"].items():
                paths.append(p)
                if isinstance(ops, dict):
                    methods += len([k for k in ops if k.lower() in
                                    ("get", "post", "put", "patch", "delete", "options", "head")])
    except Exception:
        # YAML-ish fallback (regex)
        paths = uniq(re.findall(r"(?m)^\s{0,6}(/[\w\-./{}:]{1,60}):\s*$", text or ""))[:max_paths]
    return {"spec_paths": paths[:max_paths], "n_paths": len(paths), "n_methods": methods}


def webconfig_parse(text):
    out = []
    for m in re.finditer(r"(?is)<add[^>]+name=[\"']([^\"']+)[\"'][^>]+connectionString=[\"']([^\"']+)", text or ""):
        out.append({"name": m.group(1), "conn_redacted": redact(m.group(2), keep=6)})
    return out[:5]

# ---------------------------------------------------------------------------
# ARTIFACT PROBE (v2 path_list_probe upgraded: parsers + secret sniff + severity)
# ---------------------------------------------------------------------------
def path_list_probe(http, base_url, base, paths, label, save_prefix, cfg=None):
    """Probe a fixed list of sensitive paths; return non-soft-404 hits enriched with
    severity_hint, note, intel (git/env/ds_store/openapi/webconfig), secrets_sniffed."""
    root = base_url.rstrip("/")
    hits = []
    sniff_on = cfg is None or gcap_get(cfg, "content_secret_sniff", True)
    for p in paths:
        if budget_left(http) <= 0:
            warn("  budget exhausted - %s probe stopped early" % label)
            break
        try:
            r = http.request("GET", root + p, allow_redirects=False,
                             save="%s_%s" % (save_prefix, re.sub(r"[^A-Za-z0-9]", "_", p)[-40:]))
        except Exception:
            continue
        if r.error:
            continue
        if r.status in (404, 400, 410) or is_soft404(r, base):
            continue
        body = r.text
        rec = {"path": p, "url": root + p, "status": r.status, "len": len(r.body),
               "ct": r.hget("Content-Type"), "title": title_of(body), "sha1": r.sha1(),
               "soft404": False}
        sev, why = severity_for_path(p)
        if sev:
            rec["severity_hint"] = sev
            rec["note"] = why
        # --- high-signal markers (v2 kept) ---
        if p.endswith("/HEAD") and re.match(r"^ref:\s*refs/", body[:200]):
            rec["severity_hint"] = "high"
            rec["note"] = ".git exposed - source code recoverable"
        if "/.env" in p and re.search(r"(?i)(DB_|APP_KEY|SECRET|PASSWORD|API_KEY)\s*=", body[:8000]):
            rec["severity_hint"] = "critical"
            rec["note"] = "environment file with secrets exposed"
        if p.endswith((".tfstate", ".pem", ".key", "credentials")):
            rec["severity_hint"] = "high"
        if re.search(r"(?i)swagger|openapi|api-docs", p) and "json" in (rec["ct"] or ""):
            rec["severity_hint"] = rec.get("severity_hint") or "info"
            rec["note"] = rec.get("note", "API specification exposed - full endpoint map")
        if re.search(r"actuator|server-status|nginx_status|phpinfo|pprof", p) and r.status == 200:
            rec["severity_hint"] = rec.get("severity_hint", "medium")
            rec["note"] = rec.get("note", "ops/diagnostics endpoint exposed")
        # --- ULTRA intel parsers ---
        intel = {}
        if p == "/.git/HEAD":
            branch = git_head_parse(body)
            if branch:
                intel["git_branch"] = branch
                rec["severity_hint"] = "high"
                rec["note"] = ".git exposed (branch: %s) - source recoverable" % branch
        if p == "/.git/config":
            remotes = git_config_parse(body)
            if remotes:
                intel["git_remotes"] = [redact(x, keep=10) for x in remotes]
                rec["severity_hint"] = "high"
                rec["note"] = ".git/config exposes remote repository URL"
        if p == "/.git/packed-refs" or p == "/.git/FETCH_HEAD":
            if re.search(r"[0-9a-f]{40}", body[:4000]):
                intel["git_objects"] = True
        if p.startswith("/.env"):
            ev = env_parse(body)
            if ev["n_keys"]:
                intel["env"] = ev
                rec["severity_hint"] = "critical"
                rec["note"] = "environment file: %d keys (%s%s)" % (
                    ev["n_keys"], ", ".join(ev["keys"][:4]),
                    ", secrets present" if ev["has_secretish"] else "")
        if p == "/.DS_Store":
            names = ds_store_names(r.body)
            if names:
                intel["ds_store_names"] = names
                rec["severity_hint"] = "medium"
                rec["note"] = ".DS_Store reveals %d hidden filenames" % len(names)
        if p.endswith(("swagger.json", "openapi.json")) or p in ("/swagger.json", "/openapi.json"):
            try:
                op = openapi_parse(body)
                if op["n_paths"]:
                    intel["openapi"] = op
            except Exception:
                pass
        if p.endswith("web.config") or p == "/web.config.bak":
            wc = webconfig_parse(body)
            if wc:
                intel["connection_strings"] = wc
                rec["severity_hint"] = "critical"
                rec["note"] = "web.config contains connection strings"
        if p == "/.npmrc":
            if re.search(r"_authToken", body):
                intel["npm_auth_token"] = True
                rec["severity_hint"] = "critical"
                rec["note"] = ".npmrc contains auth token"
        if intel:
            rec["intel"] = intel
        # --- ULTRA secret sniff ---
        if sniff_on and r.status == 200:
            sn = sniff_secrets(body)
            if sn:
                rec["secrets_sniffed"] = sn
                worst = [s["severity"] for s in sn]
                if "critical" in worst:
                    rec["severity_hint"] = "critical"
                elif "high" in worst and rec.get("severity_hint") in ("", "info", "low", "medium"):
                    rec["severity_hint"] = "high"
                rec["note"] = (rec.get("note", "") +
                               (" | " if rec.get("note") else "") +
                               "secret patterns: " + ",".join(sorted({s["type"] for s in sn})))
        # --- dirlisting inside artifacts (uploads/, backups/) ---
        if r.status == 200 and gcap_get(cfg, "content_dirlisting_parse", True):
            is_dl, hrefs = classify_dirlisting(r, body)
            if is_dl:
                rec["dirlisting"] = True
                rec["note"] = (rec.get("note", "") +
                               (" | " if rec.get("note") else "") +
                               "directory listing open (%d entries)" % len(hrefs))
                if not rec.get("severity_hint"):
                    rec["severity_hint"] = "medium"
        hits.append(rec)
    return hits


def cms_pack_probe(http, base_url, base, cfg):
    """ULTRA: CMS-specific artifact packs (bounded by content_cms_max)."""
    if not gcap_get(cfg, "content_cms_packs", True):
        return []
    max_total = int(gcap_get(cfg, "content_cms_max", 40))
    flat = []
    for pack, items in CMS_PACKS.items():
        for p, note, sev in items:
            flat.append((p, "CMS pack %s: %s" % (pack, note), sev))
    flat = flat[:max_total]
    hits = path_list_probe(http, base_url, base, [p for p, _, _ in flat], "cms", "cms", cfg)
    by_path = {h["path"]: h for h in hits}
    for p, note, sev in flat:
        if p in by_path:
            rec = by_path[p]
            if not rec.get("severity_hint"):
                rec["severity_hint"] = sev
            rec["note"] = (rec.get("note", "") + (" | " if rec.get("note") else "") + note)
            if "/wp-json/wp/v2/users" == p and rec["status"] == 200:
                rec["note"] = note + " - user enumeration CONFIRMED (authors list readable)"
                rec["severity_hint"] = "medium"
                rec["user_enum"] = True
    return hits


def versioned_api_probe(http, base_url, base, found_paths, cfg):
    """ULTRA: /api exists -> probe version variants v1..v5 (read-only)."""
    if not gcap_get(cfg, "content_api_versions", True):
        return []
    api_dirs = set()
    for f in found_paths:
        m = re.match(r"^(/api|/v\d+|/rest)(/?$|/)", f)
        if m:
            api_dirs.add(m.group(1))
    probes = []
    for d in sorted(api_dirs)[:2]:
        stem = d.rstrip("/")
        probes += ["%s/v1" % stem, "%s/v2" % stem, "%s/v3" % stem,
                   "%s/v4" % stem, "%s/v5" % stem]
    probes = [p for p in probes if p not in found_paths][:8]
    hits = []
    for p in probes:
        if budget_left(http) <= 0:
            break
        try:
            r = http.request("GET", base_url.rstrip("/") + p, allow_redirects=False)
        except Exception:
            continue
        if r.error or r.status in (404, 400, 410) or is_soft404(r, base):
            continue
        if r.status in INTERESTING_STATUS:
            hits.append({"path": p, "url": base_url.rstrip("/") + p, "status": r.status,
                         "len": len(r.body), "ct": r.hget("Content-Type"),
                         "title": title_of(r.text), "sha1": r.sha1(), "soft404": False,
                         "severity_hint": "info", "note": "API version prefix responds"})
    return hits

# ---------------------------------------------------------------------------
# 403/401 BYPASS ENGINE  (HTML tip: "403 ko ignore karna" = #1 mistake)
# READ-ONLY: sirf GET, kabhi bhi write method nahi. Double-confirm ke saath.
# ---------------------------------------------------------------------------
def bypass_403_engine(http, base_url, base, blocked_paths, cfg):
    """For each blocked path (401/403): try path-shape variants + header trick-sets.

    Verdicts:
      CONFIRMED  - 2xx + non-soft404 + non-authwall, twice in a row (same variant)
      PARTIAL    - redirect to non-login content / 405 / ambiguous 2xx
      BLOCKED    - every attempt still 401/403/404/soft404
    Returns list of per-path verdict records (bounded by config caps).
    """
    if not gcap_get(cfg, "content_403_bypass", True) or not blocked_paths:
        return []
    max_paths = int(gcap_get(cfg, "content_403_max_paths", 10))
    root = base_url.rstrip("/")
    # prioritize admin/config/internal-looking paths first
    ranked = sorted(blocked_paths, key=lambda p: 0 if HIGH_VALUE_RE.search(p) else 1)[:max_paths]
    results = []
    for p in ranked:
        if budget_left(http) <= 0:
            warn("  budget exhausted - 403 bypass stopped early")
            break
        rec = {"path": p, "verdict": "BLOCKED", "attempts": [], "n_attempts": 0}
        attempts = []

        def try_url(u, extra_headers, tag):
            try:
                r = http.request("GET", u, headers=extra_headers or None,
                                 allow_redirects=False)
            except Exception:
                return None
            if r.error:
                return None
            attempts.append({"tag": tag, "url": u if tag.startswith("path:") else (root + p),
                             "headers": extra_headers or {}, "status": r.status,
                             "len": len(r.body)})
            return r

        def judge(r):
            """returns 'CONFIRMED' | 'PARTIAL' | None"""
            if r is None or r.error:
                return None
            if r.status in (401, 403, 404, 410):
                return None
            body = r.text
            if is_soft404(r, base):
                return None
            if classify_authwall(r, body):
                return None
            if r.status == 200:
                return "CONFIRMED"
            if r.status in (204, 301, 302, 303, 307, 308, 405, 500, 501):
                loc = r.hget("Location") or ""
                if r.status in (301, 302, 303, 307, 308) and LOGIN_LOC_RE.search(loc):
                    return None
                return "PARTIAL"
            return None

        # --- pass 1: path-shape variants ---
        if gcap_get(cfg, "content_403_variants", True):
            for u in _bypass_path_variants(p):
                if budget_left(http) <= 0 or rec["verdict"] == "CONFIRMED":
                    break
                r = try_url(root + u, None, "path:%s" % u)
                v = judge(r)
                if v == "CONFIRMED":
                    # double-confirm: same variant once more
                    r2 = try_url(root + u, None, "path:%s#confirm" % u)
                    if judge(r2) == "CONFIRMED":
                        rec["verdict"] = "CONFIRMED"
                        rec["win"] = {"kind": "path_variant", "url": root + u,
                                      "status": r.status}
        # --- pass 2: header trick-sets (on the original path) ---
        if rec["verdict"] != "CONFIRMED" and gcap_get(cfg, "content_403_headers", True):
            for hs in _bypass_header_sets(p, root):
                if budget_left(http) <= 0 or rec["verdict"] == "CONFIRMED":
                    break
                r = try_url(root + p, hs, "headers:%s" % "+".join(sorted(hs)))
                v = judge(r)
                if v == "CONFIRMED":
                    r2 = try_url(root + p, hs, "headers:%s#confirm" % "+".join(sorted(hs)))
                    if judge(r2) == "CONFIRMED":
                        rec["verdict"] = "CONFIRMED"
                        rec["win"] = {"kind": "headers", "url": root + p,
                                      "headers": hs, "status": r.status}
                elif v == "PARTIAL" and rec["verdict"] == "BLOCKED":
                    rec["verdict"] = "PARTIAL"
                    rec["win"] = {"kind": "headers", "url": root + p,
                                  "headers": hs, "status": r.status}
        rec["n_attempts"] = len(attempts)
        keep = []
        seen_tag = set()
        for a in attempts:
            if a["tag"].endswith("#confirm"):
                continue
            if a["tag"] in seen_tag:
                continue
            seen_tag.add(a["tag"])
            keep.append(a)
        rec["attempts"] = keep[:24]
        if rec["verdict"] == "CONFIRMED":
            rec["severity_hint"] = "high"
            rec["note"] = "403 bypass CONFIRMED via %s -> %s (double-checked)" % (
                rec["win"]["kind"], rec["win"]["url"])
        elif rec["verdict"] == "PARTIAL":
            rec["severity_hint"] = "low"
            rec["note"] = "403 behaviour changed with bypass attempt - manual verify"
        results.append(rec)
        if rec["verdict"] == "CONFIRMED":
            warn("  [403-BYPASS] %s -> CONFIRMED (%s)" % (p, rec["win"]["url"]))
    return results

# ---------------------------------------------------------------------------
# METHODS PROBE (OPTIONS/HEAD read-only + advertised destructive methods report)
# ---------------------------------------------------------------------------
def methods_probe(http, url):
    res = {}
    r = http.request("OPTIONS", url, allow_redirects=False)
    if not r.error:
        allow = r.hget("Allow") or r.hget("Access-Control-Allow-Methods") or ""
        res["OPTIONS"] = {"status": r.status, "allow": allow,
                          "access_control_allow_methods": r.hget("Access-Control-Allow-Methods")}
        advertised = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
        res["advertised_destructive"] = [m for m in advertised
                                         if m in ("PUT", "DELETE", "PATCH", "TRACE")]
    r = http.request("HEAD", url, allow_redirects=False)
    if not r.error:
        res["HEAD"] = {"status": r.status, "len": r.hget("Content-Length")}
    res["_note"] = "PUT/DELETE/TRACE intentionally NOT sent (destructive/state-changing); " \
                   "advertised_destructive sirf Allow header se report hota hai"
    return res

# ---------------------------------------------------------------------------
# PRIORITY SCORING (explainable; feeds Phase 8 attack-surface ranking)
# ---------------------------------------------------------------------------
KEYWORD_SCORES = [
    (r"(?i)admin|administrator|manager|panel|portal|console", 25),
    (r"(?i)\.env|\.git|\.svn|\.htpasswd|terraform|id_rsa|\.kube|credentials", 30),
    (r"(?i)backup|dump|\.sql|\.bak|\.old|export", 25),
    (r"(?i)config|settings|configuration|setup|install", 18),
    (r"(?i)swagger|openapi|api-docs|graphql|graphiql|actuator|server-status|phpinfo|pprof", 28),
    (r"(?i)upload|file|media|assets|attachments", 15),
    (r"(?i)login|auth|signin|sso|session", 10),
    (r"(?i)debug|test|dev|staging|uat|qa|sandbox", 12),
    (r"(?i)graphql|rest|rpc|/api/|v[12]/", 15),
    (r"(?i)secret|private|internal|hidden|secure", 20),
]


def score_hit(f, extra=None):
    s, reasons = 0, []
    st = f.get("status")
    st_w = {200: 30, 201: 30, 403: 22, 401: 20, 301: 12, 302: 12, 405: 8, 500: 15}.get(st, 5)
    s += st_w
    reasons.append("status=%s(+%d)" % (st, st_w))
    p = f.get("path", "")
    for rx, w in KEYWORD_SCORES:
        if re.search(rx, p):
            s += w
            reasons.append("kw:%s(+%d)" % (rx.split("|")[0].replace("(?i)", ""), w))
    if f.get("dirlisting"):
        s += 30
        reasons.append("dirlisting(+30)")
    if f.get("secrets_sniffed"):
        s += 45
        reasons.append("secrets(+45)")
    if f.get("severity_hint") == "critical":
        s += 35
        reasons.append("critical(+35)")
    elif f.get("severity_hint") == "high":
        s += 20
        reasons.append("high(+20)")
    if f.get("sourcemap"):
        s += 20
        reasons.append("sourcemap(+20)")
    if f.get("user_enum"):
        s += 20
        reasons.append("user-enum(+20)")
    if f.get("auth_wall"):
        s -= 18
        reasons.append("auth-wall(-18)")
    if IGNORE_EXT_RE.search(p):
        s -= 40
        reasons.append("static(-40)")
    s -= 2 * int(f.get("depth", 0))
    if extra:
        s += int(extra)
    return max(0, s), reasons

# ---------------------------------------------------------------------------
# CHAINS + FINDINGS + REMEDIATION
# ---------------------------------------------------------------------------
REMEDIATION_DB = {
    "git": "Web server se .git/ serve hona band karo (deny rule), repo deploy se pehle clean karo, "
           "aur git deploy directory ko webroot se bahar rakho.",
    "env": ".env ko webroot se bahar rakho, server config me dotenv files deny karo, secrets rotate "
           "karo kyunki exposure assume karo, aur environment-specific secrets ke liye vault use karo.",
    "backup": "Backups/old files webroot se hatao; deployment pipeline me artifact pruning on karo; "
              "agar backup publicly chhua hai to uske contents treat karo compromised.",
    "vcs": ".svn/.hg/.bzr/.CVS metadata web-access se deny karo aur build output se exclude karo.",
    "dirlisting": "Autoindex off karo (apache: Options -Indexes; nginx: autoindex off). Listing se "
                  "mile files ko auth ke peeche rakho aur sensitive ones rotate karo.",
    "api_docs": "Production me API docs public disable karo ya auth ke peeche rakho; spec se mile "
                "hidden endpoints ko attack-surface review + authz testing me daalo.",
    "ops": "Actuator/ops/diagnostics endpoints ko localhost ya admin network pe bind karo; management "
           "port public expose mat karo; heapdump/env endpoints critical treat karo.",
    "cms": "CMS ke debug/diagnostic endpoints production me off karo; admin areas ko IP-restrict/2FA "
           "karo; version disclosure kam karo.",
    "user_enum": "REST authors endpoint ko authenticated-only karo; public site me author usernames "
                 "ko login usernames se alag rakho.",
    "log": "Log files webroot se bahar likho; server config me *.log deny karo; exposed logs ke "
           "contents me credentials rotate karo.",
    "bypass_403": "Authorization ko application layer me enforce karo (sirf config/middleware pattern "
                  "pe rely mat karo); normalized path pe auth check karo; proxy header trust hatao "
                  "(X-Original-URL/XFF ko client-controlled samjho).",
    "ds_store": ".DS_Store files ko deployment se exclude karo (.gitignore + CI check).",
    "sourcemap": "Production build me sourcemaps generate mat karo ya serve mat karo (*.js.map deny).",
    "key": "Key material webroot me kabhi na rakho; exposed keys ko immediately rotate karo aur "
           "uske fingerprint se past usage audit karo.",
    "npmrc": "Registry auth tokens ko env vars me rakho; exposed token rotate karo.",
    "webconfig": "web.config backups webroot se hatao; connection strings ko encrypted config "
                 "sections me rakho aur credentials rotate karo.",
}

FINDING_SEQ = {"n": 0}


def _fid():
    FINDING_SEQ["n"] += 1
    return "P5-%03d" % FINDING_SEQ["n"]


def _rem(key):
    return REMEDIATION_DB.get(key, "Exposed resource remove/auth ke peeche rakho; exposure window "
                                  "audit karo aur relevant secrets rotate karo.")


def findings_from(host, host_rec, bypass):
    """Build P5-### findings: critical/high artifacts + dirlistings + bypass + user enum."""
    out = []
    for a in host_rec.get("artifacts", []):
        sev = (a.get("severity_hint") or "").lower()
        if sev not in ("critical", "high", "medium"):
            continue
        rem_key = ("git" if "/.git" in a["path"] else
                   "vcs" if re.search(r"\.svn|\.hg|\.bzr|\.CVS", a["path"]) else
                   "env" if "/.env" in a["path"] else
                   "ds_store" if ".DS_Store" in a["path"] else
                   "sourcemap" if a.get("sourcemap") or a["path"].endswith(".map") else
                   "log" if a["path"].endswith(".log") else
                   "ops" if re.search(r"actuator|server-status|nginx_status|phpinfo|pprof|trace\.axd|elmah", a["path"]) else
                   "api_docs" if re.search(r"swagger|openapi|api-docs|graphql|redoc", a["path"]) else
                   "user_enum" if a.get("user_enum") else
                   "key" if re.search(r"\.(pem|key|p12|pfx|jks)$|id_rsa|authorized_keys", a["path"]) else
                   "npmrc" if a["path"].endswith(".npmrc") else
                   "webconfig" if "web.config" in a["path"] else
                   "backup" if re.search(r"\.(bak|old|zip|tar|sql|dump|save|swp)$", a["path"]) else
                   "cms")
        chain = _chain_for_artifact(a, host_rec)
        out.append({
            "id": _fid(), "host": host, "severity": sev or "low",
            "title": "%s exposed" % a["path"],
            "evidence": {"url": a["url"], "status": a["status"], "len": a.get("len"),
                         "note": a.get("note", ""), "secrets": [
                             s["type"] for s in (a.get("secrets_sniffed") or [])]},
            "remediation": _rem(rem_key),
            "chain_hint": chain,
        })
    for dl in host_rec.get("dirlistings", []):
        out.append({
            "id": _fid(), "host": host, "severity": "medium",
            "title": "Directory listing open: %s" % dl["path"],
            "evidence": {"url": dl["url"], "links": dl.get("links", 0)},
            "remediation": _rem("dirlisting"),
            "chain_hint": "listing se mile files -> auth testing (P9) + secrets (P23)",
        })
    for b in (bypass or []):
        if b["verdict"] == "CONFIRMED":
            out.append({
                "id": _fid(), "host": host, "severity": "high",
                "title": "403 bypass CONFIRMED: %s" % b["path"],
                "evidence": {"win": b.get("win", {}), "n_attempts": b.get("n_attempts", 0)},
                "remediation": _rem("bypass_403"),
                "chain_hint": "ab is route ke peeche ke features ko P11 access-control "
                              "se test karo (IDOR/BOLA candidates)",
            })
        elif b["verdict"] == "PARTIAL":
            out.append({
                "id": _fid(), "host": host, "severity": "low",
                "title": "403 partial anomaly: %s" % b["path"],
                "evidence": {"win": b.get("win", {})},
                "remediation": _rem("bypass_403"),
                "chain_hint": "manual verify karo - kabhi kabhi behavior change hi hint hota hai",
            })
    return out


def _chain_for_artifact(a, host_rec):
    p = a.get("path", "")
    if "/.git" in p:
        return ".git source recovery -> hardcoded secrets (P23) -> admin creds -> P9 login"
    if "/.env" in p:
        return "env secrets -> DB/cloud creds (P23) -> direct access ya P15 SSRF pivot"
    if re.search(r"swagger|openapi|api-docs", p):
        return "spec endpoints -> P17 API testing -> P11 IDOR candidates"
    if re.search(r"actuator", p):
        return "env/heapdump -> runtime secrets (P23) -> internal services (P15)"
    if a.get("user_enum"):
        return "authors list -> valid usernames -> P9 password spraying / P11 IDOR"
    if a.get("dirlisting") or "uploads" in p:
        return "open listing -> upload point (P16) + sensitive files (P23)"
    if re.search(r"\.bak|\.old|backup|\.sql|dump", p):
        return "backup contents -> creds (P23) -> source review"
    return "endpoint P11/P12/P13 ke testing candidates me daalo"


def build_chains(host, host_rec, bypass):
    """Cross-phase chain hints for this host (feeds Phase 28 chaining)."""
    chains = []
    arts = {a["path"]: a for a in host_rec.get("artifacts", [])}
    found_paths = [f["path"] for f in host_rec.get("found", [])]
    api_eps = host_rec.get("api_endpoints_expanded", [])
    if any("/.git" in p for p in arts):
        chains.append({"chain": ".git exposed -> source code recover -> hardcoded secrets "
                                "-> admin credentials -> authenticated testing (P9/P11)",
                       "phases": [5, 23, 9, 11], "confidence": "high"})
    if any("/.env" in p for p in arts):
        chains.append({"chain": ".env secrets -> DB/cloud creds -> data access ya internal pivot (P15 SSRF)",
                       "phases": [5, 23, 15], "confidence": "high"})
    if any(re.search(r"swagger|openapi", p) for p in arts):
        chains.append({"chain": "API spec -> hidden endpoints -> authz gaps (P11 IDOR) + injection (P13)",
                       "phases": [5, 17, 11, 13], "confidence": "high"})
    if any(re.search(r"actuator", p) for p in arts):
        chains.append({"chain": "Spring actuator env/heapdump -> runtime secrets -> session tokens "
                                "-> account takeover (P10)",
                       "phases": [5, 23, 10], "confidence": "medium"})
    if any(a.get("dirlisting") for a in arts.values()) or host_rec.get("dirlistings"):
        chains.append({"chain": "open dirlisting -> sensitive files + upload dir -> P16 upload abuse "
                                "-> webshell (P13)",
                       "phases": [5, 16, 13], "confidence": "medium"})
    if any(b["verdict"] == "CONFIRMED" for b in (bypass or [])):
        chains.append({"chain": "403 bypass -> hidden admin surface -> auth bypass (P9) / "
                                "IDOR candidates (P11)",
                       "phases": [5, 9, 11], "confidence": "high"})
    if host_rec.get("authwalls"):
        chains.append({"chain": "auth-walled areas mapped -> P9 credential testing + P10 session "
                                "testing on these exact routes",
                       "phases": [5, 9, 10], "confidence": "info"})
    if api_eps or any(re.search(r"^/api", p) for p in found_paths):
        chains.append({"chain": "API endpoints harvested -> P11 BOLA sweep + P12 param mining",
                       "phases": [5, 11, 12], "confidence": "info"})
    if host_rec.get("sourcemaps"):
        chains.append({"chain": "sourcemaps -> original source -> client-only authz logic (P7) -> "
                                "hidden endpoints (P17)",
                       "phases": [5, 7, 17], "confidence": "medium"})
    return chains

# ---------------------------------------------------------------------------
# HTML HARVEST: <script src> js-hints + query params (P7 / P12 feeds)
# ---------------------------------------------------------------------------
SCRIPT_SRC_RE = re.compile(r"(?is)<script[^>]+src=[\"']([^\"']+)[\"']")
JS_URL_RE = re.compile(r"(?i)(/[\w\-./%]{2,80}\.js(?:\.map)?)")
PARAM_SPLIT_RE = re.compile(r"[?&]([A-Za-z_][\w\-\[\]]{0,30})=")


def harvest_html(r, base_url, js_set, param_set):
    body = r.text[:300000]
    for src in SCRIPT_SRC_RE.findall(body):
        src = src.strip()
        if not src or src.startswith(("data:", "javascript:")):
            continue
        u = up.urljoin(base_url, src)
        if u.startswith(("http://", "https://")):
            js_set.add(u.split("?")[0])
        elif src.startswith("/"):
            js_set.add(u.split("?")[0])
    q = up.urlparse(r.url or base_url).query
    for k, _v in up.parse_qsl(q):
        if k and len(k) <= 32:
            param_set.add(k)

# ---------------------------------------------------------------------------
# PER-HOST PIPELINE  (sub-stage checkpoints, resume-safe)
# ---------------------------------------------------------------------------
TECHNIQUES = [
    "soft-404 mathematical baseline (core) + auth-redirect fingerprint",
    "auth-wall detection (login form/title/redirect heuristics)",
    "dir-listing parse + bounded child recursion",
    "403/401 bypass engine (12 path variants x 8 header sets, double-confirm)",
    ".DS_Store binary filename extraction -> hidden path probes",
    ".git HEAD/config/packed-refs intel",
    ".env KEY inventory + redacted samples",
    "16-pattern secret sniffing on artifact bodies (redacted)",
    "OpenAPI/Swagger spec parse -> endpoint map",
    "nested sitemap crawl (1 level, capped)",
    "CMS packs (WordPress/Drupal/Joomla/Laravel/Django/Rails/Tomcat/ASP.NET)",
    "versioned API prefix probe (v1..v5)",
    "wordlist synthesis (seclists+builtin+seeds+robots+sitemap+mutations)",
    "explainable priority scoring (Phase 8 feed)",
    "query-param harvest (Phase 12 feed)",
    "script-src JS hints (Phase 7 feed)",
    "Set-Cookie name surface (Phase 10 feed)",
    "chain hints builder (Phase 28 feed)",
    "findings engine P5-### + remediation",
    "advertised destructive methods from Allow (reported, not sent)",
    "budget guard + 429 storm throttle",
    "redirect-chain following + trailing-slash recursion (/x -> /x/)",
]


def merge_artifact(dst, by_url, a):
    u = a.get("url")
    if not u:
        return
    if u not in by_url:
        dst.append(a)
        by_url[u] = a
        return
    cur = by_url[u]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if sev_rank.get(a.get("severity_hint", ""), 0) > sev_rank.get(cur.get("severity_hint", ""), 0):
        cur["severity_hint"] = a.get("severity_hint")
    if a.get("note") and a["note"] not in (cur.get("note") or ""):
        cur["note"] = ((cur.get("note") or "") +
                       (" | " if cur.get("note") else "") + a["note"])
    if a.get("secrets_sniffed") and not cur.get("secrets_sniffed"):
        cur["secrets_sniffed"] = a["secrets_sniffed"]
    if a.get("intel"):
        cur.setdefault("intel", {}).update(a["intel"])


def host_pass(cfg, scope, http, cp, out_dir, base_url, wl_pre, seeds_w, wsrc_pre, g):
    host = host_of(base_url)
    ck = "host:" + host
    if cp.is_done(ck):
        rec = cp.result_of(ck) or {}
        info("SKIP (checkpoint) %s -> %d paths" % (host, len(rec.get("found", []))))
        return rec
    rec = {"base_url": base_url, "baseline": {}, "metadata": {}, "found": [], "dirs": [],
           "extensions": [], "artifacts": [], "methods": {}, "errors": 0, "requests": 0,
           "dirlistings": [], "authwalls": [], "bypass_403": [], "cms": [],
           "api_versions": [], "api_endpoints_expanded": [], "params": [], "js_urls": [],
           "cookies_seen": [], "sourcemaps": [], "priority": [], "chains": [],
           "findings": [], "wordlist_source": wsrc_pre, "throttle_events": 0,
           "budget_stop": False}
    try:
        if not scope.check_url(base_url, raise_on_fail=False):
            rec["error"] = "out-of-scope"
            cp.mark(ck, rec, summary="out-of-scope")
            return rec
        # ---------------- STAGE root: baseline + metadata ----------------
        rk = "host:%s:root" % host
        if cp.is_done(rk):
            r0 = cp.result_of(rk) or {}
            rec["baseline"] = r0.get("baseline") or {}
            rec["metadata"] = r0.get("metadata") or {}
        else:
            base = build_baseline(http, base_url, cfg)
            if not base:
                err("%s -> baseline nahi bani (unreachable?), skip" % base_url)
                rec["error"] = "baseline-failed"
                cp.mark(rk, {"baseline": {}, "metadata": {}}, summary="unreachable")
                cp.mark(ck, rec, summary="unreachable")
                return rec
            rec["baseline"] = base
            rec["metadata"] = metadata(http, base_url, base, cfg)
            cp.mark(rk, {"baseline": base, "metadata": rec["metadata"]},
                    summary="root+baseline+meta")
        base = rec["baseline"]
        meta = rec["metadata"]
        ok("baseline: status=%s len=%s spread=%s stable=%s serves200=%s authredirect=%s"
           % (base.get("status"), base.get("len_min"), base.get("spread"),
              base.get("stable_len"), base.get("serves_200_on_missing"),
              base.get("auth_redirect")))
        if base.get("serves_200_on_missing") and not base.get("stable_len"):
            warn("server 200 deta hai aur length unstable -> false positives high, "
                 "threshold tight kiya")

        # robots hints + sitemap-derived words/params
        robots_hints = []
        for v in meta.values():
            robots_hints.extend(v.get("disallow") or [])
        sitemap_words = set()
        for v in meta.values():
            for u in (v.get("urls") or []):
                try:
                    pu = up.urlparse(u)
                except Exception:
                    continue
                pth = (pu.path or "").strip("/")
                if pth and len(pth) < 80 and WORD_HINT_RE.match(pth):
                    sitemap_words.add(pth)
                    if "/" in pth:
                        sitemap_words.add(pth.split("/")[-1])
                    for k, _v in up.parse_qsl(pu.query or ""):
                        if k and len(k) <= 32:
                            rec["params"].append(k)
        meta_hits = sorted({h.strip("/") for h in robots_hints
                            if h and h.strip("/") not in ("", "*")})
        words_now = sorted(set(wl_pre) | set(builtin_words()) | set(seeds_w)
                           | set(meta_hits) | sitemap_words)
        ok("wordlist: %s | robots=%d sitemap-words=%d -> %d total" %
           (wsrc_pre.split()[0], len(meta_hits), len(sitemap_words), len(words_now)))

        # ---------------- STAGE disc: discovery ----------------
        dk = "host:%s:disc" % host
        if cp.is_done(dk):
            d = cp.result_of(dk) or {"found": [], "dirs": [], "errors": 0, "probed": 0,
                                     "dirlistings": [], "authwalls": [], "blocked_403": [],
                                     "budget_stop": False, "throttle_events": 0}
        else:
            d = discover(cfg, scope, http, base_url, words_now, base)
            cp.mark(dk, d, summary="discovery")
        rec["found"] = d.get("found", [])
        rec["dirs"] = d.get("dirs", [])
        rec["errors"] += d.get("errors", 0)
        rec["requests"] += d.get("probed", 0)
        rec["dirlistings"] = d.get("dirlistings", [])
        rec["authwalls"] = d.get("authwalls", [])
        rec["throttle_events"] += d.get("throttle_events", 0)
        rec["budget_stop"] = bool(d.get("budget_stop"))
        ok("discovery: %d hits | %d dir redirects | %d dirlistings | %d authwalls | "
           "%d blocked | %d errors | %d requests"
           % (len(rec["found"]), len(rec["dirs"]), len(rec["dirlistings"]),
              len(rec["authwalls"]), len(d.get("blocked_403", [])),
              rec["errors"], rec["requests"]))

        # js/param harvest from a few HTML hits (bounded re-GET)
        js_set, param_set = set(), set(rec["params"])
        html_hits = [f for f in rec["found"]
                     if "html" in (f.get("ct") or "").lower()][:8]
        for f in html_hits:
            if budget_left(http) <= 0:
                break
            try:
                r2 = http.get(f["url"], allow_redirects=False)
            except Exception:
                continue
            if not r2.error:
                harvest_html(r2, base_url, js_set, param_set)
                rec["cookies_seen"].extend(collect_cookie_names(r2))
        rec["js_urls"] = sorted(js_set)[:60]
        rec["params"] = uniq(rec["params"] + sorted(param_set))[:120]

        # ---------------- STAGE ext: extension sweep ----------------
        basenames = uniq(sorted({f["path"].strip("/").split("/")[-1] for f in rec["found"]
                                 if not HASEXT_RE.search(f["path"])}))
        ek = "host:%s:ext" % host
        if cp.is_done(ek):
            ext_hits = cp.result_of(ek) or []
        else:
            ext_hits = extension_sweep(http, base_url.rstrip("/"), base,
                                       basenames[:80], EXTENSIONS,
                                       cap=int(gcap_get(cfg, "content_ext_max", 600))) \
                if basenames else []
            cp.mark(ek, ext_hits, summary="extensions")
        rec["extensions"] = ext_hits
        rec["sourcemaps"] = [e["url"] for e in ext_hits if e.get("sourcemap")] + \
                            [f["url"] for f in rec["found"] if f["path"].endswith(".map")]
        ok("extension sweep: %d extra hits (from %d basenames)"
           % (len(ext_hits), len(basenames)))

        # ---------------- STAGE art: artifacts (vcs/api/backup/cms/dsstore) -------
        ak = "host:%s:art" % host
        if cp.is_done(ak):
            a0 = cp.result_of(ak) or {}
            uniq_artifacts = a0.get("artifacts") or []
            rec["cms"] = a0.get("cms") or []
            rec["api_versions"] = a0.get("api_versions") or []
        else:
            artifacts = []
            by_url = {}
            for a in path_list_probe(http, base_url, base, VCS_PATHS, "vcs", "vcs", cfg):
                merge_artifact(artifacts, by_url, a)
            for a in path_list_probe(http, base_url, base, API_DOC_PATHS, "api", "api", cfg):
                merge_artifact(artifacts, by_url, a)
            bk = []
            for bn in basenames[:40]:
                for suf in BACKUP_SUFFIXES:
                    bk.append("/" + bn + suf)
            for a in path_list_probe(http, base_url, base, bk, "backup", "bak", cfg):
                merge_artifact(artifacts, by_url, a)
            # .DS_Store children -> hidden path probes
            ds_names = []
            for a in list(by_url.values()):
                if a["path"] == "/.DS_Store":
                    ds_names = ((a.get("intel") or {}).get("ds_store_names") or [])
            if ds_names:
                ds_paths = ["/" + n for n in ds_names[:20]]
                for a in path_list_probe(http, base_url, base, ds_paths, "dsstore",
                                         "dsst", cfg):
                    a["note"] = (a.get("note", "") +
                                 (" | " if a.get("note") else "") +
                                 "path from .DS_Store enumeration").strip(" |")
                    merge_artifact(artifacts, by_url, a)
            rec["cms"] = cms_pack_probe(http, base_url, base, cfg)
            for a in rec["cms"]:
                merge_artifact(artifacts, by_url, a)
            rec["api_versions"] = versioned_api_probe(
                http, base_url, base, [f["path"] for f in rec["found"]], cfg)
            for a in rec["api_versions"]:
                merge_artifact(artifacts, by_url, a)
            uniq_artifacts = artifacts
            cp.mark(ak, {"artifacts": uniq_artifacts, "cms": rec["cms"],
                         "api_versions": rec["api_versions"]}, summary="artifacts")

        # openapi intel -> expanded api endpoint list
        api_expanded = set()
        for a in uniq_artifacts:
            op = ((a.get("intel") or {}).get("openapi") or {})
            for sp in (op.get("spec_paths") or []):
                api_expanded.add(sp)
        for _, f in [(host, f) for f in rec["found"] + ext_hits]:
            if re.search(r"(?i)^/(api|v\d+|graphql|rest|json|rpc)", f["path"]):
                api_expanded.add(f["path"])
        rec["api_endpoints_expanded"] = sorted(api_expanded)[:300]

        high = [a for a in uniq_artifacts if a.get("severity_hint") in ("critical", "high")]
        ok("artifacts: %d hits (%d high/critical)" % (len(uniq_artifacts), len(high)))
        for a in high[:12]:
            warn("   [%s] %s (%s) - %s" % (a.get("severity_hint"), a["path"], a["status"],
                                           a.get("note", "")))
        rec["artifacts"] = uniq_artifacts

        # ---------------- STAGE b403: 403/401 bypass engine ----------------
        blk = "host:%s:b403" % host
        if cp.is_done(blk):
            bypass = cp.result_of(blk) or []
        else:
            blocked = list(d.get("blocked_403", []))
            for e in ext_hits:
                if e.get("status") in (401, 403) and e.get("path") not in blocked:
                    blocked.append(e["path"])
            bypass = bypass_403_engine(http, base_url, base, blocked, cfg)
            cp.mark(blk, bypass, summary="403-bypass")
        rec["bypass_403"] = bypass
        confirmed = [b for b in bypass if b["verdict"] == "CONFIRMED"]
        if confirmed:
            warn("403 BYPASS CONFIRMED on %d path(s) - details bypass_403.txt me" % len(confirmed))

        # ---------------- STAGE meth: methods probe ----------------
        mk = "host:%s:meth" % host
        if cp.is_done(mk):
            mres = cp.result_of(mk) or {}
        else:
            mres = {}
            probe_urls = [base_url] + [f["url"] for f in rec["found"][:12]] + \
                         [a["url"] for a in high[:6]]
            for u in probe_urls[:20]:
                if budget_left(http) <= 0:
                    break
                mres[u] = methods_probe(http, u)
            cp.mark(mk, mres, summary="methods")
        rec["methods"] = mres
        adv = sorted({m for v in mres.values()
                      for m in (v.get("advertised_destructive") or [])})
        if adv:
            warn("server ADVERTISES destructive methods (%s) - Allow header se, "
                 "bheje nahi gaye" % ",".join(adv))

        # ---------------- post: priority + findings + chains ----------------
        scored = []
        for f in rec["found"] + ext_hits:
            s, why = score_hit(f)
            scored.append({"path": f["path"], "url": f.get("url"), "status": f.get("status"),
                           "score": s, "reasons": ";".join(why[:6]),
                           "kind": "artifact" if f in uniq_artifacts else "path"})
        for a in uniq_artifacts:
            pseudo = {"path": a["path"], "status": a.get("status"),
                      "severity_hint": a.get("severity_hint"),
                      "dirlisting": a.get("dirlisting"),
                      "secrets_sniffed": a.get("secrets_sniffed"),
                      "user_enum": a.get("user_enum"), "depth": 0}
            s, why = score_hit(pseudo, extra=10)
            scored.append({"path": a["path"], "url": a.get("url"), "status": a.get("status"),
                           "score": s, "reasons": ";".join(why[:6]), "kind": "artifact"})
        seen_p = set()
        prio = []
        for s0 in sorted(scored, key=lambda x: -x["score"]):
            if s0["path"] in seen_p:
                continue
            seen_p.add(s0["path"])
            prio.append(s0)
        rec["priority"] = prio[:40]
        rec["findings"] = findings_from(host, rec, bypass)
        rec["chains"] = build_chains(host, rec, bypass)
        if rec["findings"]:
            ok("findings: %d (P5-###) | chains: %d" % (len(rec["findings"]), len(rec["chains"])))
    except Exception as e:
        import traceback
        traceback.print_exc()
        rec["error"] = repr(e)
    rec["requests_total"] = rec.get("requests", 0)
    cp.mark(ck, rec, summary="content host")
    return rec

# ---------------------------------------------------------------------------
# RUN  (entry point - v2 compatible signature)
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    cache = ProbeCache(base_out, scope.engagement) if getattr(cfg, "negative_cache", True) else None
    head("Phase 5 - Content & Endpoint Enumeration ULTRA v3 | %s" % scope.describe())

    # ---------------- targets (P4 live_hosts -> scope seeds fallback) ----------------
    seeds = []
    p4 = os.path.join(os.path.dirname(out), "active", "live_hosts.txt")
    if os.path.exists(p4):
        for line in open(p4, errors="ignore"):
            m = re.match(r"(https?://\S+)\s*\[", line.strip())
            if m:
                seeds.append(m.group(1))
    if not seeds:
        warn("Phase 4 output nahi mila -> scope.seed_urls() use kar rahe hain")
        seeds = scope.seed_urls()
    seeds = [s for s in uniq(sorted(set(seeds))) if scope.check_url(s, raise_on_fail=False)]
    if not seeds:
        err("No in-scope targets.")
        return out
    info("Targets: %d" % len(seeds))

    # ---------------- base wordlist (seclists + builtin + seeds) ----------------
    wl_pre, wsrc_pre = load_wordlist(int(os.environ.get("WASP_WORDS", "4000")))
    seeds_w = seed_words(out, scope)
    pre_merged = sorted(set(wl_pre) | set(builtin_words()) | set(seeds_w))
    ok("wordlist: %d words (%s) + %d seeds + builtin = %d pre-discovery total"
       % (len(wl_pre), wsrc_pre, len(seeds_w), len(pre_merged)))

    report = {"phase": "5-content", "generated_at": now_iso(),
              "engine_version": ENGINE_VERSION,
              "wordlist_source": wsrc_pre, "wordlist_size": len(pre_merged),
              "techniques": TECHNIQUES, "results": {}}
    all_found, all_dirs, all_artifacts = [], [], []
    all_findings, all_chains, all_bypass = [], [], []
    g = {"req": 0, "global_cap": int(gcap_get(cfg, "content_global_cap", 12000))}

    for i, seed in enumerate(seeds, 1):
        base_url = normalize_url(seed).rstrip("/")
        host = host_of(base_url)
        head("[%d/%d] %s" % (i, len(seeds), base_url))
        if g["req"] >= g["global_cap"]:
            warn("global request cap (%d) reached - baaki hosts skip" % g["global_cap"])
            break
        rec = host_pass(cfg, scope, http, cp, out, base_url, wl_pre, seeds_w,
                        wsrc_pre, g)
        g["req"] += int(rec.get("requests_total", 0))
        report["results"][host] = rec
        all_found.extend((host, f) for f in rec.get("found", []))
        all_found.extend((host, f) for f in rec.get("extensions", []))
        all_dirs.extend((host, d) for d in rec.get("dirs", []))
        all_artifacts.extend((host, a) for a in rec.get("artifacts", []))
        all_findings.extend(rec.get("findings", []))
        all_chains.extend(dict(c0, host=host) for c0 in rec.get("chains", []))
        all_bypass.extend((host, b) for b in rec.get("bypass_403", []))

        # per-host flat exports (v2 filenames preserved)
        safe = safe_name(host)
        save_text(os.path.join(out, "found_%s.txt" % safe),
                  "\n".join("%-6s %-8d %-55s %s" % (f.get("status"), f.get("len", 0),
                                                    f.get("path"), (f.get("title") or "")[:50])
                            for f in sorted(rec.get("found", []) + rec.get("extensions", []),
                                            key=lambda x: (x.get("status") or 0,
                                                           x.get("path", "")))))
        save_text(os.path.join(out, "dirs_%s.txt" % safe),
                  "\n".join("%s -> %s [%s]" % (d0["path"], d0.get("location"),
                                               d0.get("status"))
                            for d0 in rec.get("dirs", [])))
        save_text(os.path.join(out, "artifacts_%s.txt" % safe),
                  "\n".join("[%s] %s %s %s" % (a.get("severity_hint", "-"), a.get("status"),
                                               a.get("path"), a.get("note", ""))
                            for a in rec.get("artifacts", [])))
        if rec.get("js_urls"):
            save_text(os.path.join(out, "js_hints_%s.txt" % safe), "\n".join(rec["js_urls"]))
        if rec.get("findings"):
            save_text(os.path.join(out, "findings_%s.txt" % safe),
                      "\n".join("[%s] %s %s :: %s" % (f0["severity"].upper(), f0["id"],
                                                      f0["title"], f0.get("chain_hint", ""))
                                for f0 in rec["findings"]))

    # ---------------- global exports (v2 names + ULTRA extras) ----------------
    save_json(os.path.join(out, "content.json"), report)

    save_text(os.path.join(out, "all_found.txt"),
              "\n".join("%s %s %s" % (h, f.get("status"), f.get("path")) for h, f in all_found))
    save_text(os.path.join(out, "all_dirs.txt"),
              "\n".join("%s %s -> %s [%s]" % (h, d0.get("path"), d0.get("location"),
                                              d0.get("status")) for h, d0 in all_dirs))

    interesting = [(h, f) for h, f in all_found if re.search(
        r"(?i)(admin|config|backup|\.env|\.git|debug|api|internal|test|dev|swagger|openapi|"
        r"actuator|\.bak|\.old|upload|console|graphql|metrics|health|server-status|phpinfo|"
        r"terraform|dockerfile|jenkins|\.svn|\.hg|dump|export|private|secret)", f.get("path", ""))]
    save_text(os.path.join(out, "interesting.txt"),
              "\n".join("%s %s %s (%s)" % (h, f.get("status"), f.get("path"),
                                           (f.get("title") or "")[:40]) for h, f in interesting))

    save_text(os.path.join(out, "artifacts_high.txt"),
              "\n".join("%s [%s] %s %s %s" % (h, a.get("severity_hint"), a.get("status"),
                                              a.get("path"), a.get("note", ""))
                        for h, a in all_artifacts
                        if a.get("severity_hint") in ("critical", "high")))
    save_text(os.path.join(out, "content_notes.txt"),
              "\n".join("%s baseline: status=%s len=%s stable=%s serves200=%s | hits=%d | "
                        "artifacts=%d | findings=%d | bypass=%d%s"
                        % (h, r.get("baseline", {}).get("status"),
                           r.get("baseline", {}).get("len_min"),
                           r.get("baseline", {}).get("stable_len"),
                           r.get("baseline", {}).get("serves_200_on_missing"),
                           len(r.get("found", [])), len(r.get("artifacts", [])),
                           len(r.get("findings", [])), len(r.get("bypass_403", [])),
                           " | BUDGET-STOP" if r.get("budget_stop") else "")
                        for h, r in report["results"].items()))

    api_like = sorted({f.get("path") for _, f in all_found if f.get("path") and re.search(
        r"(?i)/(api|v\d+|graphql|rest|json|rpc|openapi|swagger)", f["path"])})
    spec_paths = sorted({p for h, r in report["results"].items()
                         for p in r.get("api_endpoints_expanded", [])})
    save_text(os.path.join(out, "api_endpoints.txt"), "\n".join(uniq(api_like + spec_paths)))

    # ULTRA extras
    prio_rows = []
    for h, r in report["results"].items():
        for p0 in r.get("priority", []):
            prio_rows.append("%-5d %-6s %-45s %s (%s)" % (p0["score"], p0.get("status"),
                                                          p0["path"], p0.get("url"),
                                                          p0.get("reasons", "")[:90]))
    save_text(os.path.join(out, "priority.txt"), "\n".join(prio_rows))

    save_text(os.path.join(out, "bypass_403.txt"),
              "\n".join("%s [%s] %s -> %s (%d attempts)%s"
                        % (h, b["verdict"], b["path"],
                           (b.get("win") or {}).get("url", "-"),
                           b.get("n_attempts", 0),
                           " | " + b.get("note", "") if b.get("note") else "")
                        for h, b in all_bypass))

    params_all = sorted({p for h, r in report["results"].items() for p in r.get("params", [])})
    save_text(os.path.join(out, "params_all.txt"), "\n".join(params_all))

    js_all = sorted({u for h, r in report["results"].items() for u in r.get("js_urls", [])})
    save_text(os.path.join(out, "js_hints.txt"), "\n".join(js_all))

    sm_all = sorted({u for h, r in report["results"].items() for u in r.get("sourcemaps", [])})
    save_text(os.path.join(out, "sourcemaps.txt"), "\n".join(sm_all))

    save_text(os.path.join(out, "dirlistings.txt"),
              "\n".join("%s %s (%s)" % (h, dl.get("path"), dl.get("reason", ""))
                        for h, r in report["results"].items()
                        for dl in (r.get("dirlistings") or []) +
                        [{"path": a["path"], "reason": "artifact-listing"}
                         for a in r.get("artifacts", []) if a.get("dirlisting")]))

    save_text(os.path.join(out, "secrets_content.txt"),
              "\n".join("%s %s [%s] %s -> %s" % (h, a.get("severity_hint"), s0["type"],
                                                 a.get("path"), s0.get("sample_redacted"))
                        for h, a in all_artifacts
                        for s0 in (a.get("secrets_sniffed") or [])))

    save_text(os.path.join(out, "chains.txt"),
              "\n".join("[%s] %s :: %s" % (c0.get("confidence", "info"), c0.get("host", ""),
                                           c0.get("chain", ""))
                        for c0 in all_chains))

    # findings file (flat, human-readable)
    save_text(os.path.join(out, "P5_FINDINGS.txt"),
              "\n".join("[%s] %s %s :: %s" % (f0["severity"].upper(), f0["id"], f0["title"],
                                              f0.get("evidence", {}).get("url", ""))
                        for f0 in all_findings) or "no findings above threshold")

    # ---------------- feedforward (v2 routing keys + ULTRA extras) ----------------
    n_high = sum(1 for _, a in all_artifacts
                 if a.get("severity_hint") in ("critical", "high"))
    upload_paths = [p for p in (f.get("path") for _, f in all_found)
                    if p and re.search(r"(?i)upload|file|media|asset", p)][:60]
    ff = write_feedforward(out, "5-content", {
        "to_phase6_tech": {"targets": "content.json#results",
                           "artifacts": "artifacts_high.txt"},
        "to_phase7_js": {"found": "all_found.txt", "js_hints": "js_hints.txt",
                         "sourcemaps": "sourcemaps.txt"},
        "to_phase8_surface": {"priority": "priority.txt",
                              "note": "explainable scores - top paths first"},
        "to_phase9_auth": {"interesting": "interesting.txt",
                           "authwalls": "content.json#results.*.authwalls"},
        "to_phase10_session": {"cookies_seen": "content.json#results.*.cookies_seen"},
        "to_phase11_idor": {"api_endpoints": "api_endpoints.txt"},
        "to_phase12_params": {"api_endpoints": "api_endpoints.txt",
                              "params": "params_all.txt"},
        "to_phase13_injection": {"interesting": "interesting.txt"},
        "to_phase16_upload": {"paths": upload_paths},
        "to_phase17_api": {"api_endpoints": "api_endpoints.txt",
                           "openapi_specs": "content.json#results.*.api_endpoints_expanded"},
        "to_phase23_secrets": {"artifacts": "artifacts_high.txt", "vcs": "VCS_PATHS hits",
                               "sniffed": "secrets_content.txt"},
        "to_phase28_chains": {"chains": "chains.txt"},
        "to_phase32_report": {"findings": "content.json#findings",
                              "high_artifacts": n_high},
    }, notes=["GET/HEAD/OPTIONS only; PUT/DELETE/TRACE deliberately not sent",
              "secrets stored REDACTED only",
              "403 bypass attempts read-only GET; double-confirmed verdicts only"])
    write_manifest(out, "5-content",
                   ["content.json", "all_found.txt", "all_dirs.txt", "interesting.txt",
                    "artifacts_high.txt", "api_endpoints.txt", "content_notes.txt",
                    "priority.txt", "bypass_403.txt", "params_all.txt", "js_hints.txt",
                    "sourcemaps.txt", "dirlistings.txt", "secrets_content.txt",
                    "chains.txt", "P5_FINDINGS.txt",
                    "found_<host>.txt", "dirs_<host>.txt", "artifacts_<host>.txt",
                    "js_hints_<host>.txt", "findings_<host>.txt", "feedforward.json"],
                   stats={"targets": len(seeds), "paths_found": len(all_found),
                          "dirs": len(all_dirs), "artifacts": len(all_artifacts),
                          "high_artifacts": n_high,
                          "findings": len(all_findings),
                          "bypass_confirmed": sum(1 for _, b in all_bypass
                                                  if b.get("verdict") == "CONFIRMED"),
                          "dirlistings": sum(len(r.get("dirlistings") or [])
                                             for r in report["results"].values()),
                          "params": len(params_all), "js_hints": len(js_all),
                          "requests": sum(r.get("requests_total", 0)
                                          for r in report["results"].values())})
    cp.mark_complete()

    head("Phase 5 complete (ULTRA v3)")
    ok("paths=%d | dirs=%d | artifacts=%d (%d high) | api_like=%d | findings=%d | "
       "bypass_confirmed=%d"
       % (len(all_found), len(all_dirs), len(all_artifacts), n_high, len(api_like),
          len(all_findings),
          sum(1 for _, b in all_bypass if b.get("verdict") == "CONFIRMED")))
    return out
