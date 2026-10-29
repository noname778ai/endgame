#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 8 - Attack Surface Mapping & Priority Queue (ULTRA v3)
=============================================================================
Phase 2-7 (+11) ka bikhra hua output ek UNIFIED ASSET GRAPH me fuse karta hai,
har node ko explainable signals par score karta hai, aur ek RANKED TEST PLAN
banata hai: "kis cheez ko pehle test karna hai, kyun, kaunsi vuln class ke
liye, kitna time lagega, aur WAF/CDN ke peeche kaise pahunche."

ULTRA v3 = v2 ke saare features 100% preserved + 25 naye techniques:

  CORE (v2, preserved):
   * Unified asset graph    - host/endpoint/param/artifact/secret/vhost/port/config/js_asset
   * 6 ingestors            - P2 understand, P3 passive, P4 active, P5 content,
                              P6 tech, P7 js  (merge-union -> corroboration)
   * 8-signal scoring       - param/path/status/tech/host/dynamic/rarity/corrobor
                              x false-positive discount, explainable har step
   * Effort model           - cheap(1m)/medium(4m)/expensive(12m)
   * Vuln-class routing     - 22 classes -> next-phase feedforward map
   * Jaccard clustering     - '/api/users/1' aur '/api/users/2' = ek test
   * MMR diversity re-rank  - top-N me clones nahi, breadth milti hai
   * 8 attack chains        - VCS/ENV/UPLOAD/SSRF/GQL/VHOST/AUTHZ/SMAP
   * Time-boxed coverage    - greedy knapsack (priority/min ratio)
   * Honest ignore list     - kya chhoda aur kyun (explainable drops)
   * 13 v2 outputs          - surface.json, priority_queue.json/.txt, test_plan.md,
                              hypotheses, quick_wins, deep_dives, clusters, chains,
                              ignore, coverage_matrix, coverage_plan, feedforward, MANIFEST

  ULTRA v3 NEW TECHNIQUES:
   1.  WAF_BYPASS_DB           - Cloudflare/AWS WAF/CloudFront/nginx/Apache/Akamai/
                                 Imperva/F5 ke liye header+path bypass playbook
   2.  bypass_playbook.txt     - DETECTED perimeter ke hisaab se tailored bypass plan
   3.  Per-node bypass field   - 403/401 targets ke rows me ready-made bypass kit
   4.  _waf_signal             - WAF-protected hosts ko stealth-effort guidance
   5.  _method_signal          - POST/PUT/DELETE/PATCH state-changers ko boost
   6.  _version_signal         - /api/v1 vs /api/v2 - legacy versions = weaker guards
   7.  _secret_adj_signal      - jis host par secret leak hai wahan ke auth params boost
   8.  Stale-tech boost        - P6 EOL/CVE-grade stack -> us host ke targets uprank
   9.  ingest_access (P11)     - mod_access ke findings/matrix se REAL authz evidence
   10. ingest_ff               - saare modules ke feedforward.json hints fuse
   11. Attack-Path DAG         - precondition ordering: cheap intel -> bypass -> exploit
   12. attack_paths.txt        - ordered exploit-readiness sequence (step-by-step)
   13. api_version_matrix      - v1/v2/v3 inventory + deprecated-version warnings
   14. api_version_matrix.txt  - version-wise target list (old = test first)
   15. authz_focus kit         - admin/config/debug group (P11 vertical-authz prep)
   16. session_focus kit       - auth/session targets (P9/P10 prep)
   17. phase_prep.txt          - P9/P10/P11 handoff: targets + bypass + creds needed
   18. Blind-spot detector     - kaunsi class me high-confidence evidence ZERO hai
   19. Chains v2 (7 naye)      - WAF-bypass, legacy-API, smap+secret, takeover,
                                 cache-poison, default-creds, edge-misrouting
   20. Kill tests v2           - naye classes ke liye falsifiable rejection tests
   21. Effort v2               - WAF-protected = stealth effort bump (explainable)
   22. MMR type-balance        - top-N me endpoint/param/artifact sab Represent
   23. surface_diff.json       - previous run se target-level diff (new/gone/rank)
   24. test_plan.md v2         - +bypass playbook, +DAG, +blind spots, +phase prep
   25. Feedforward superset    - v2 routing + waf_notes + top10 handoff targets

Safety: PURE ANALYSIS - koi network request nahi. Sab kuch Phase 2-7(+11) ke
        local artifacts se banta hai. Deterministic: same input = same plan.
        Secrets hamesha REDACTED. Scope-conscious (sirf in-scope hosts rank hote).

v2 -> v3 notes (compat intact):
   * saare v2 output filenames/formats same (superset fields additive)
   * v2 score formula floor ke roop me preserved; ULTRA bonus explainable alag
   * config keys: surface_min_priority(22) surface_top(60) surface_budget_minutes(90)
     + naye: surface_waf_aware(True) surface_diff(True) surface_dag_max(12)
"""
import os
import re
import json
import math
import time
import urllib.parse as up
from collections import defaultdict, Counter

from wasp_core import (module_ctx, write_feedforward, write_manifest, ProbeCache,
                       load_json, save_json, save_text, now_iso, host_of, port_of,
                       is_ip, normalize_url, shannon_entropy, sha1,
                       info, ok, warn, err, head, C, VERSION, median, mad, robust_z)

# ULTRA: optional core helpers (older cores par bhi chale - graceful degrade)
try:
    from wasp_core import read_feedforward as _core_read_ff  # noqa: F401
except Exception:
    _core_read_ff = None
try:
    from wasp_core import dim as _dim  # noqa: F401
except Exception:
    _dim = None

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

NAME = "surface"
PHASE = "8-surface"
PLAN_VERSION = "8.1.0-ULTRA"

# ---------------------------------------------------------------------------
# KNOWLEDGE TABLES  (data-driven; yahi phase 8 ka "brain" hai)
# ---------------------------------------------------------------------------
# Param naam -> (vuln class, hypothesis weight, reason)
PARAM_HYP = [
    (r"(?i)^(id|uid|uuid|guid|user_?id|account_?id|order_?id|invoice_?id|file_?id|"
     r"doc_?id|customer_?id|pid|gid|item_?id|product_?id|post_?id|msg_?id)$",
     "IDOR/BOLA", 0.85, "object identifier -> horizontal/vertical access control"),
    (r"(?i)^(url|uri|link|target|dest|destination|redirect|redirect_?uri|next|continue|"
     r"return|return_?url|callback|ref|referer|image_?url|avatar_?url|feed|host|domain|site)$",
     "SSRF/Open-Redirect", 0.80, "server-side fetch / redirect sink"),
    (r"(?i)^(file|filename|filepath|path|dir|folder|template|page|include|require|"
     r"load|doc|download|src|resource)$",
     "Path-Traversal/LFI", 0.75, "filesystem path sink"),
    (r"(?i)^(cmd|exec|command|run|shell|eval|system|process|ping|nslookup|lookup|"
     r"diagnose|diag)$",
     "RCE/Command-Injection", 0.90, "command execution sink"),
    (r"(?i)^(role|roles|is_?admin|admin|privilege|permission|perm|level|tier|plan|"
     r"group|scope|status|active|verified|approved|enabled|owner|tenant)$",
     "Mass-Assignment/AuthZ", 0.80, "authorization or state field"),
    (r"(?i)^(price|amount|total|subtotal|discount|coupon|qty|quantity|credits|"
     r"balance|points|rate|fee|tax)$",
     "Business-Logic", 0.80, "money / quantity value"),
    (r"(?i)^(token|api_?key|apikey|key|secret|password|passwd|pwd|otp|code|reset|"
     r"signature|sig|nonce|jwt|session|access_?token|refresh_?token)$",
     "Auth/Credential", 0.85, "credential or secret material"),
    (r"(?i)^(sort|order_?by|order|column|field|filter|where|limit|offset|page|"
     r"select|table)$",
     "SQLi/NoSQLi", 0.65, "query-construction parameter"),
    (r"(?i)^(q|query|search|s|keyword|name|title|comment|message|msg|body|content|"
     r"text|desc|description|subject|email|username|nickname|bio)$",
     "XSS/Injection", 0.60, "echoed/reflected text parameter"),
    (r"(?i)^(xml|data|payload|input|json|raw|serialized|object|node|params)$",
     "Injection/Deserialization", 0.60, "structured payload parameter"),
    (r"(?i)^(template|layout|view|theme|lang|locale|currency|format|callback|jsonp|"
     r"pretty)$",
     "SSTI/Format-Injection", 0.55, "template/format parameter"),
    # ---------------- ULTRA v3 additions (11-18) ----------------
    (r"(?i)^(jwt|id_?token|auth_?token|bearer|saml|assertion|tgt|rst)$",
     "Auth/Credential", 0.88, "token-bearing credential parameter (session forgery)"),
    (r"(?i)^(debug|dbg|trace|verbose|test|mock|staging|env)$",
     "Misconfiguration", 0.70, "debug/state toggle -> info leak / feature abuse"),
    (r"(?i)^(query|operation|mutation|variables|query_?hash|persisted)$",
     "API-Abuse", 0.72, "GraphQL operation parameter -> introspection/mutation abuse"),
    (r"(?i)^(ws|socket|channel|stream|topic|room|event)$",
     "API-Abuse", 0.62, "realtime channel parameter -> authz/replay surface"),
    (r"(?i)^(export|report|print|render|convert|preview|fetch|proxy|load)$",
     "SSRF/Open-Redirect", 0.70, "document/render verb -> server-side fetch sink"),
    (r"(?i)^(invite|share|grant|revoke|transfer|assign|delegate)$",
     "Access-Control", 0.78, "sharing/permission verb -> authz boundary test"),
    (r"(?i)^(locale|lang_?id|currency_?id|store_?id|tenant_?id|org_?id|team_?id)$",
     "IDOR/BOLA", 0.68, "tenant/org scoping parameter -> cross-tenant access"),
    (r"(?i)^(cache|ttl|expire|exp|expiry|age|max_?age)$",
     "Cache-Poisoning", 0.60, "cache-control parameter -> cache deception/poisoning"),
]

# Path keyword -> (sensitivity, reason)
PATH_SENS = [
    (r"(?i)(^|/)(admin|administrator|manage|management|console|dashboard|staff|"
     r"root|superuser|operator|backoffice)(/|$)", 0.95, "administrative area"),
    (r"(?i)(^|/)(debug|trace|test|tests|dev|staging|stage|qa|sandbox|internal|"
     r"private|tmp|temp|scratch)(/|$)", 0.90, "non-production / utility area"),
    (r"(?i)(^|/)(upload|uploads|import|export|backup|backups|dump|download|files|"
     r"media|attachments|archive)(/|$)", 0.85, "file & data handling"),
    (r"(?i)(^|/)(config|configuration|settings|env|setup|install|migrate|actuator|"
     r"health|metrics|status|info|env\.js)(/|$)", 0.85, "config / ops surface"),
    (r"(?i)(^|/)(webhook|webhooks|callback|callbacks|notify|hook|integration|"
     r"connect|sync|proxy|gateway)(/|$)", 0.80, "server-to-server callback"),
    (r"(?i)(^|/)(auth|login|signin|signup|register|logout|oauth|sso|saml|token|"
     r"session|mfa|otp|password|passwd|reset|forgot|verify|activate)(/|$)",
     0.80, "authentication surface"),
    (r"(?i)(^|/)(user|users|account|accounts|profile|profiles|customer|member|"
     r"billing|payment|payments|invoice|order|orders|subscription)(/|$)",
     0.75, "user / business object"),
    (r"(?i)(^|/)(api|rest|graphql|gql|rpc|odata|jsonapi)(/|$)|/v[0-9]+(/|$)",
     0.70, "API surface"),
    (r"(?i)(swagger|openapi|api-?docs|redoc|graphiql|playground|\.wsdl$)",
     0.80, "API documentation"),
    (r"(?i)(^|/)(\.git|\.svn|\.hg|\.bzr|cvs)(/|$)|\.(bak|old|orig|save|swp|sql|"
     r"tar|gz|tgz|zip|war|jar|pem|key|p12|log)$", 0.95, "VCS / backup artifact"),
    # ---------------- ULTRA v3 additions (11-16) ----------------
    (r"(?i)(^|/)(jenkins|grafana|kibana|sonarqube|nexus|artifactory|zabbix|"
     r"prometheus|harbor|portainer|rancher)(/|$)", 0.92, "devops/admin tooling"),
    (r"(?i)(^|/)(actuator|heapdump|threaddump|env\.json|cloudfoundryapplication)$",
     0.93, "spring boot actuator family"),
    (r"(?i)(^|/)(\.env|\.aws|\.ssh|\.docker|kube|kubernetes|\.git-?config)(/|$)",
     0.95, "deployment credential surface"),
    (r"(?i)(^|/)(s3|bucket|storage|blob|container|oss|cos)(/|$)|amazonaws\.com|"
     r"blob\.core\.windows\.net|storage\.googleapis\.com", 0.78, "cloud storage surface"),
    (r"(?i)(^|/)(soap|wsdl|xmlrpc|jmx|rmi|hessian|burlap)(/|$)", 0.80, "legacy RPC surface"),
    (r"(?i)(^|/)(\.well-known/(?:openapi|ai-plugin|security|assetlinks|apple)|"
     r"manifest\.(?:json|webmanifest))$", 0.55, "well-known metadata surface"),
]

ARTIFACT_SEV = {"critical": 1.00, "high": 0.85, "medium": 0.60, "low": 0.35}

# Kaunsi vuln class aage kis phase me test hogi (feedforward routing)
CLASS_TO_PHASE = {
    "IDOR/BOLA": "11-idor",
    "SSRF/Open-Redirect": "15-ssrf",
    "Path-Traversal/LFI": "13-injection",
    "RCE/Command-Injection": "13-injection",
    "Mass-Assignment/AuthZ": "11-idor",
    "Business-Logic": "16-logic",
    "Auth/Credential": "9-auth",
    "SQLi/NoSQLi": "13-injection",
    "XSS/Injection": "14-xss",
    "Injection/Deserialization": "13-injection",
    "SSTI/Format-Injection": "13-injection",
    "Secret-Exposure": "23-secrets",
    "Misconfiguration": "23-misconfig",
    "Cache-Poisoning": "22-cache",
    "Session-Weakness": "10-sessions",
    "Source-Disclosure": "23-secrets",
    "Hidden-Infrastructure": "4-active",
    "Network-Exposure": "4-active",
    "Access-Control": "11-idor",
    "API-Abuse": "17-api",
    # ---------------- ULTRA v3 additions ----------------
    "Subdomain-Takeover": "3-passive",
    "Legacy-API": "17-api",
    "DevOps-Exposure": "23-misconfig",
    "Unclassified": "triage",
}

# Effort estimate (minutes) per node type
EFFORT_MIN = {"cheap": 1.0, "medium": 4.0, "expensive": 12.0}

# ---------------------------------------------------------------------------
# ULTRA v3: WAF / CDN BYPASS KNOWLEDGE BASE
# (Phase 8 request NAHI bhejta - ye playbook hai jo aage ke phases execute karte)
# ---------------------------------------------------------------------------
WAF_BYPASS_DB = {
    "cloudflare": {
        "label": "Cloudflare WAF/CDN",
        "headers": [
            "X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1",
            "X-Original-URL: <target-path>", "X-Rewrite-URL: <target-path>",
            "X-Custom-IP-Authorization: 127.0.0.1", "True-Client-IP: 127.0.0.1",
            "CF-Connecting-IP: 127.0.0.1",
        ],
        "paths": ["/%2e/<path>", "/<path>/.", "/./<path>", "//<path>", "/<path>%20",
                  "/./<path>/..;/<path>"],
        "notes": "Managed rules parity: origin direct hit ho to WAF skip hota hai "
                 "(DNS history / shodan origin IP / MX records se origin dhoondo). "
                 "Rate-limit IP-based hai -> slow-low-and-slow approach.",
    },
    "cloudfront": {
        "label": "AWS CloudFront (CDN)",
        "headers": [
            "X-Original-URL: <target-path>", "X-Rewrite-URL: <target-path>",
            "X-Forwarded-Host: internal-host", "X-Forwarded-Port: 443",
            "X-AMZ-Forwarded-For: 127.0.0.1",
        ],
        "paths": ["//<path>", "/<path>//", "/./<path>", "/<path>/", "/%2f<path>"],
        "notes": "CloudFront behaviour policies path-normalize karte hain: origin "
                 "normalize alag kare to differential aa sakta hai. Cache key me "
                 "headers na ho to cache-variance poisoning bhi possible (P22).",
    },
    "aws-waf": {
        "label": "AWS WAF",
        "headers": [
            "X-Forwarded-For: 127.0.0.1", "X-Originating-IP: 127.0.0.1",
            "X-Remote-Addr: 127.0.0.1", "X-Original-URL: <target-path>",
        ],
        "paths": ["/<path>/?a=1&/../<path>", "/%252e/<path>", "/./<path>"],
        "notes": "AWS WAF rule groups URI normalization apni karti hain - double-"
                 "encoding aur path-traversal shaped strings rule bypass dete hain "
                 "jab origin ka parser alag ho. Size limits (8KB) -> payload split.",
    },
    "nginx": {
        "label": "nginx (incl. ModSecurity)",
        "headers": [
            "X-Original-URL: <target-path>", "X-Rewrite-URL: <target-path>",
            "X-Accel-Redirect: <target-path>", "X-Forwarded-For: 127.0.0.1",
            "X-Forwarded-Host: localhost",
        ],
        "paths": ["/<path>/", "//<path>", "/./<path>", "/<path>%2f", "/<path>/..;/<path>",
                  "/%2f//<path>", "/<path>.;/<path>"],
        "notes": "nginx merge_slashes + location matching origin-specific hota hai; "
                 "mer location /admin par allowlist hai to //admin/ ya /admin/./ "
                 "differential de sakta hai. alias traversal: /alias../ -> upar nikal.",
    },
    "apache": {
        "label": "Apache (httpd/modsec)",
        "headers": [
            "X-Original-URL: <target-path>", "X-Rewrite-URL: <target-path>",
            "X-Forwarded-For: 127.0.0.1", "Forwarded: for=127.0.0.1",
        ],
        "paths": ["/<path>/", "/<path>.", "/<path>..;/", "//<path>", "/%2e/<path>"],
        "notes": "mod_rewrite rules trailing-slash ko alag treat karti hain; "
                 "AllowEncodedSlashes off -> %2f decode deny; Tomcat co-located ho "
                 "to ;jsessionid tricks try karo.",
    },
    "akamai": {
        "label": "Akamai (CDN+WAF)",
        "headers": [
            "True-Client-IP: 127.0.0.1", "X-Akamai-Edge-IP: 127.0.0.1",
            "Pragma: akamai-x-cache-on", "X-Forwarded-For: 127.0.0.1",
        ],
        "paths": ["//<path>", "/<path>/.", "/./<path>"],
        "notes": "Pragma debug headers edge behaviour reveal karte hain (cache key, "
                 "route). Edge-IP rotation + slow rate se rate-limit doorsar.",
    },
    "imperva": {
        "label": "Imperva/Incapsula",
        "headers": [
            "X-Forwarded-For: 127.0.0.1", "Incapsula-Client-IP: 127.0.0.1",
            "X-Original-URL: <target-path>",
        ],
        "paths": ["/<path>;jsessionid=x", "//<path>", "/./<path>"],
        "notes": "Session cookie (_incap_*) tied hoti hai - request profile build "
                 "karne se pehle ek clean session establish karo.",
    },
    "f5": {
        "label": "F5 BIG-IP ASM",
        "headers": [
            "X-Forwarded-For: 127.0.0.1", "X-Original-URL: <target-path>",
            "TS: b60a4f4d",  # classic BIG-IP cookie-format leak probe hint
        ],
        "paths": [";/<path>", "/<path>/", "//<path>", "/./<path>"],
        "notes": "BIG-IP ASM param rules strict hote hain - attack signatures "
                 "param names me chhupao (param pollution across query+body).",
    },
    "generic": {
        "label": "Unknown/other perimeter",
        "headers": [
            "X-Original-URL: <target-path>", "X-Rewrite-URL: <target-path>",
            "X-Forwarded-For: 127.0.0.1", "X-Originating-IP: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1", "X-Client-IP: 127.0.0.1",
            "X-Host: localhost", "X-Forwarded-Host: localhost",
        ],
        "paths": ["//<path>", "/./<path>", "/<path>/", "/<path>..;/", "/%2e/<path>"],
        "notes": "Sab common header-proxies ek-ek karke try karo; response-length/"
                 "status differential se pata chalega kaunsa header origin tak "
                 "pahunch raha hai.",
    },
}

# WAF detection string -> WAF_BYPASS_DB key
WAF_ALIAS = {
    "cloudflare": "cloudflare", "cf-ray": "cloudflare", "__cfduid": "cloudflare",
    "cf-cache": "cloudflare",
    "cloudfront": "cloudfront", "x-amz-cf": "cloudfront", "via: 1.1 .*cloudfront": "cloudfront",
    "aws waf": "aws-waf", "aws-waf": "aws-waf", "x-amzn-requestid": "aws-waf",
    "awswaf": "aws-waf",
    "nginx": "nginx", "modsecurity": "nginx", "openresty": "nginx",
    "apache": "apache", "httpd": "apache", "mod_security": "apache",
    "akamai": "akamai", "x-akamai": "akamai", "akamaighost": "akamai",
    "imperva": "imperva", "incapsula": "imperva", "visiting x": "imperva",
    "bigip": "f5", "f5 ": "f5", "asm": "f5", "ts=": "f5",
    "sucuri": "generic", "wordfence": "generic", "waf": "generic", "cdn": "generic",
    "edge": "generic", "lb": "generic", "load": "generic",
}

# ---------------------------------------------------------------------------
# SMALL HELPERS
# ---------------------------------------------------------------------------
def _clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def tokens(s):
    """Path/param ko compare karne ke liye token set."""
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def split_query(url):
    """Query param NAMES (values ignore - sirf structure compare karte hain)."""
    try:
        q = up.urlparse(url).query
        return sorted({k for k, _ in up.parse_qsl(q, keep_blank_values=True) if k})
    except Exception:
        return []


def norm_endpoint(url):
    """Endpoint dedupe key: scheme+host lowercase, path case-sensitive, trailing / hata."""
    try:
        p = up.urlparse(url)
    except Exception:
        return url
    host = (p.netloc or "").lower()
    path = p.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    qs = ",".join(split_query(url))
    return "%s://%s%s%s" % (p.scheme.lower(), host, path, ("?" + qs) if qs else "")


def hostport_of(url):
    try:
        p = up.urlparse(url)
        netloc = (p.netloc or "").lower()
        if not netloc:
            return ""
        return netloc
    except Exception:
        return ""


def first_match(table, text):
    """Rows are (regex, value, [weight], reason) - weight optional."""
    for e in table:
        if re.search(e[0], text):
            return e[1], e[-1]
    return None, None


def all_matches(table, text):
    out = []
    for e in table:
        if re.search(e[0], text):
            out.append((e[1], e[-1]))
    return out


def param_match(text):
    """PARAM_HYP -> (class, weight, reason). Yehi param scoring ka core hai."""
    for rx, cls, w, why in PARAM_HYP:
        if re.search(rx, text or ""):
            return cls, float(w), why
    return None, 0.0, None


def load_phase_json(eng, mod, fname):
    p = os.path.join(eng, mod, fname)
    if not os.path.exists(p):
        return None
    return load_json(p, None)


def read_lines(eng, mod, fname, limit=None):
    p = os.path.join(eng, mod, fname)
    if not os.path.exists(p):
        return []
    out = []
    try:
        with open(p, errors="ignore") as f:
            for i, line in enumerate(f):
                if limit and i >= limit:
                    break
                line = line.rstrip("\n")
                if line.strip():
                    out.append(line)
    except Exception:
        pass
    return out


def flat_under(eng, mod, subdir="", limit=None):
    """Module ke folder (ya uske findings/ subfolder) ki saari text lines."""
    d = os.path.join(eng, mod, subdir) if subdir else os.path.join(eng, mod)
    out = []
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if fn.endswith((".txt", ".md")):
            out.extend(read_lines(eng, os.path.join(mod, subdir) if subdir else mod, fn, limit=limit))
    return out


# ---------------------------------------------------------------------------
# ULTRA v3: WAF/PERIMETER helpers
# ---------------------------------------------------------------------------
def waf_key_for(text):
    """Kisi bhi perimeter string (header/banner/config) -> WAF_BYPASS_DB key."""
    t = (text or "").lower()
    for alias, key in WAF_ALIAS.items():
        if alias in t:
            return key
    return None


def bypass_kit_for(waf_keys, path):
    """Detected WAFs ke liye per-node bypass kit (headers + path variants + notes)."""
    keys = [k for k in (waf_keys or []) if k in WAF_BYPASS_DB]
    if not keys:
        keys = ["generic"]
    seen_h, seen_p = set(), set()
    headers, paths, notes = [], [], []
    for k in keys:
        db = WAF_BYPASS_DB[k]
        for h in db["headers"]:
            h2 = h.replace("<target-path>", path or "/")
            if h2 not in seen_h:
                seen_h.add(h2)
                headers.append(h2)
        for p in db["paths"]:
            p2 = p.replace("<path>", (path or "/").lstrip("/") or "")
            if p2 not in seen_p:
                seen_p.add(p2)
                paths.append(p2)
        if db.get("notes") and db["notes"] not in notes:
            notes.append(db["notes"])
    return {"wafs": keys, "headers": headers[:14], "path_variants": paths[:10],
            "notes": notes[:3]}


def detect_host_wafs(nodes):
    """Saare nodes se host -> [waf_key] map nikalo (P4 edges + P6 tech + P2 headers)."""
    host_waf = defaultdict(set)
    for n in nodes:
        raw = n.get("raw") or {}
        h = n.get("host") or ""
        if not h:
            continue
        # P4 edge config: waf_hits list
        for w in (raw.get("waf_hits") or []):
            k = waf_key_for(str(w))
            if k:
                host_waf[h].add(k)
        # P6 tech_ranked / P2 tech list
        for t in (raw.get("tech_ranked") or raw.get("tech") or []):
            name = t.get("tech") if isinstance(t, dict) else str(t)
            cat = (t.get("category") or "").lower() if isinstance(t, dict) else ""
            k = waf_key_for(str(name) + " " + cat)
            if k and (k != "generic" or re.search(r"(?i)(waf|firewall|shield)", str(name) + cat)):
                host_waf[h].add(k)
        # server/powered strings
        for fld in ("server", "powered", "cdn_headers"):
            v = raw.get(fld)
            if isinstance(v, dict):
                v = " ".join("%s:%s" % (a, b) for a, b in v.items())
            k = waf_key_for(str(v))
            if k:
                host_waf[h].add(k)
        # P4 edge config label
        lab = " ".join(n.get("labels") or [])
        if "edge" in lab:
            k = waf_key_for(str(raw.get("waf_hits")) + " " + str(raw.get("cdn_headers")))
            if not k and raw.get("cdn_headers"):
                k = "generic"
            if k:
                host_waf[h].add(k)
    return {h: sorted(v) for h, v in host_waf.items()}


# ULTRA v3: stale/EOL tech indicators (P6 tech_ranked versions se boost)
STALE_TECH_RULES = [
    (r"(?i)jquery\s*[/< ]?\s*1\.|jquery\s*[/< ]?\s*2\.", 0.30, "jQuery 1.x/2.x = XSS CVE window"),
    (r"(?i)php[/< ]?\s*5\.|php[/< ]?\s*7\.[0-3]", 0.30, "EOL PHP branch"),
    (r"(?i)apache[/< ]?\s*2\.[0-3]\.", 0.35, "Apache 2.2/2.3 = ancient"),
    (r"(?i)nginx[/< ]?\s*1\.[0-9]\.", 0.15, "older nginx branch"),
    (r"(?i)tomcat[/< ]?\s*[7-8]\.", 0.25, "Tomcat 7/8 partial EOL"),
    (r"(?i)(struts|log4j|spring\s*4\.|django\s*[12]\.|rails\s*[45]\.)", 0.40, "CVE-heavy legacy framework"),
    (r"(?i)(wordpress|drupal|joomla)[/< ]?\s*[1-4]\.", 0.30, "legacy CMS branch"),
    (r"(?i)flash|silverlight|applet", 0.45, "dead client runtime"),
]


def stale_boost_for(host, tech_by_host):
    """Host ke tech stack se (boost, why) - ULTRA: stale/EOL priority context."""
    items = tech_by_host.get(host) or []
    best, why = 0.0, ""
    for t in items:
        name = (t.get("tech") if isinstance(t, dict) else str(t)) or ""
        ver = (t.get("version") or "") if isinstance(t, dict) else ""
        blob = "%s %s" % (name, ver)
        for rx, boost, reason in STALE_TECH_RULES:
            if re.search(rx, blob) and boost > best:
                best, why = boost, "%s (%s)" % (reason, blob.strip()[:40])
    return best, why


# ---------------------------------------------------------------------------
# NODE STORE  (unified asset graph)
# ---------------------------------------------------------------------------
class NodeStore:
    """
    Ek hi jagah saare assets. Dedupe key = (type, norm_key).
    Merge karte waqt sources/evidence/params UNION hote hain, isliye corroboration
    apne aap badhti hai - koi bhi ek phase ka claim final nahi hota.
    """

    def __init__(self):
        self.nodes = {}
        self.order = []
        self._seq = 0

    def _nid(self):
        self._seq += 1
        return "N%04d" % self._seq

    def add(self, ntype, key, **fields):
        k = (ntype, key)
        if k in self.nodes:
            self._merge(self.nodes[k], fields)
            return self.nodes[k]
        n = {"id": self._nid(), "type": ntype, "key": key,
             "url": fields.get("url") or "", "host": fields.get("host") or "",
             "method": (fields.get("method") or "GET").upper(),
             "labels": [], "sources": [], "evidence": [], "params": [],
             "raw": {}, "notes": []}
        self.nodes[k] = n
        self.order.append(k)
        self._merge(n, fields)
        return n

    @staticmethod
    def _merge(n, f):
        for l in f.get("labels") or []:
            if l and l not in n["labels"]:
                n["labels"].append(l)
        for s in f.get("sources") or []:
            if s and s not in n["sources"]:
                n["sources"].append(s)
        for e in f.get("evidence") or []:
            if e and e not in n["evidence"]:
                n["evidence"].append(e)
        for p in f.get("params") or []:
            if p and p not in n["params"]:
                n["params"].append(p)
        for k, v in (f.get("raw") or {}).items():
            if v not in (None, "", [], {}):
                n["raw"][k] = v
        for nt in f.get("notes") or []:
            if nt and nt not in n["notes"]:
                n["notes"].append(nt)
        if f.get("url") and not n["url"]:
            n["url"] = f["url"]
        if f.get("host") and not n["host"]:
            n["host"] = f["host"]
        if f.get("method") and n["method"] == "GET":
            n["method"] = str(f["method"]).upper()

    def all(self):
        return [self.nodes[k] for k in self.order]

    def by_type(self, t):
        return [self.nodes[k] for k in self.order if k[0] == t]


# ---------------------------------------------------------------------------
# INGESTORS  (har phase ka output -> nodes)
# ---------------------------------------------------------------------------
def _resolve(base_url, maybe_rel):
    if not maybe_rel:
        return ""
    u = str(maybe_rel).strip()
    if not u or u.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return ""
    if re.match(r"(?i)^(https?|wss?|ws)://", u):
        return u
    if not base_url:
        return ""
    try:
        return up.urljoin(base_url, u)
    except Exception:
        return ""


def _is_static(path):
    return bool(re.search(r"(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|"
                          r"bmp|pdf|zip|gz|tgz|rar|7z|exe|dmg|apk)$", path or ""))


def _is_noise_path(path):
    p = (path or "").lower()
    if p in ("/", ""):
        return True
    if re.match(r"^/(robots\.txt|sitemap.*\.xml|favicon\.ico|humans\.txt|security\.txt|"
                r"\.well-known/[^/]*)$", p):
        return True
    return False


def _add_param_nodes(store, ep_node, params, src, context_url):
    for p in params:
        cls, w, why = param_match(p)
        store.add("param", p, url=context_url, host=ep_node["host"], labels=["param"],
                  sources=[src], params=[p],
                  evidence=["%s: param '%s'%s" % (src, p, (" -> " + cls) if cls else "")],
                  raw={"class": cls, "why": why, "weight": w},
                  notes=(["%s: %s" % (cls, why)] if cls else []))
        if p not in ep_node["params"]:
            ep_node["params"].append(p)


def ingest_understand(store, eng):
    data = load_phase_json(eng, "understand", "understand.json")
    if not data:
        return 0
    n = 0
    for t in data.get("targets", []):
        if not t.get("reachable"):
            continue
        base = t.get("base") or t.get("final_url") or ""
        host = host_of(base)
        store.add("host", hostport_of(base) or host, url=base, host=host,
                  labels=["host", "live"], sources=["P2"],
                  evidence=["P2: homepage reachable [%s] grade=%s" % (t.get("status"), t.get("header_grade"))],
                  raw={"status": t.get("status"), "title": t.get("title"),
                       "server": t.get("server"), "powered": t.get("powered"),
                       "tech": t.get("tech"), "header_grade": t.get("header_grade"),
                       "missing_headers": t.get("missing_headers")})
        n += 1
        for e in t.get("endpoints", []):
            u = _resolve(base, e)
            if not u:
                continue
            path = up.urlparse(u).path
            if _is_static(path):
                continue
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u),
                      labels=["endpoint", "from_js"], sources=["P2"],
                      evidence=["P2: endpoint reference in homepage/JS"],
                      params=split_query(u), raw={"path": path})
            n += 1
        for f in t.get("forms", []):
            act = f.get("action") or base
            u = _resolve(base, act)
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u),
                      method=f.get("method") or "GET",
                      labels=["endpoint", "form"] + (["auth_form"] if f.get("has_password") else [])
                             + (["file_upload"] if f.get("has_file") else []),
                      sources=["P2"],
                      evidence=["P2: form (%s) fields=%d%s" % (f.get("method") or "GET",
                                                               len(f.get("fields") or []),
                                                               " [password]" if f.get("has_password") else "")],
                      params=[x for x in (f.get("fields") or []) if isinstance(x, str)],
                      raw={"path": up.urlparse(u).path, "fields": f.get("fields"),
                           "has_password": f.get("has_password"), "has_file": f.get("has_file")})
            n += 1
            ep = store.nodes.get(("endpoint", norm_endpoint(u)))
            if ep and f.get("fields"):
                _add_param_nodes(store, ep, [x for x in (f.get("fields") or []) if isinstance(x, str)],
                                 "P2", u)
    return n


def ingest_passive(store, eng):
    data = load_phase_json(eng, "passive", "passive.json")
    if not data:
        return 0
    n = 0
    domain = data.get("domain", "")
    for h in data.get("subdomains", []):
        store.add("host", h, url="https://" + h, host=h, labels=["host", "subdomain"],
                  sources=["P3"], evidence=["P3: CT/archive subdomain (domain=%s)" % domain])
        n += 1
    for h, ips in (data.get("resolved") or {}).items() if isinstance(data.get("resolved"), dict) else []:
        store.add("host", h, url="https://" + h, host=h, labels=["host", "resolved"],
                  sources=["P3"], evidence=["P3: resolves to %s" % (ips if not isinstance(ips, list) else ",".join(map(str, ips))[:80])])
        n += 1
    mining = data.get("mining") or {}
    for u in (mining.get("urls") or [])[:2000]:
        uu = _resolve("https://" + domain if domain else "", u)
        if not uu:
            continue
        store.add("endpoint", norm_endpoint(uu), url=uu, host=host_of(uu),
                  labels=["endpoint", "archived"], sources=["P3"],
                  evidence=["P3: archived URL (Wayback/CDX)"], params=split_query(uu))
        n += 1
    # ULTRA: takeover-shaped records (CNAME pointing to dangling service)
    for t in (data.get("takeover_candidates") or [])[:80]:
        h = t.get("host") or ""
        store.add("vhost", str(h) + "|takeover", url="https://" + str(h), host=str(h),
                  labels=["vhost", "takeover_hint"], sources=["P3"],
                  evidence=["P3: takeover-shaped CNAME/service=%s fingerprint=%s"
                            % (t.get("service"), t.get("fingerprint"))],
                  raw={"service": t.get("service"), "fingerprint": t.get("fingerprint"),
                       "cname": t.get("cname")})
        n += 1
    return n


def ingest_active(store, eng):
    data = load_phase_json(eng, "active", "active.json")
    if not data:
        return 0
    n = 0
    for p in data.get("probes", []):
        u = p.get("url") or ""
        host = p.get("host") or host_of(u)
        store.add("host", hostport_of(u) or host, url=u, host=host,
                  labels=["host", "live"], sources=["P4"],
                  evidence=["P4: probe %s [%s] %s" % (u, p.get("status"), p.get("title", "")[:50])],
                  raw={"status": p.get("status"), "port": p.get("port"),
                       "scheme": p.get("scheme"), "server": p.get("server"),
                       "tech": p.get("tech"), "favicon_hash": p.get("favicon_hash"),
                       "content_type": p.get("content_type")})
        n += 1
    for e in data.get("edges", []):
        u = e.get("url") or ""
        store.add("config", "edge:" + hostport_of(u), url=u, host=host_of(u),
                  labels=["config", "edge"], sources=["P4"],
                  evidence=["P4: waf=%s header_grade=%s" % (",".join(e.get("waf_hits") or []) or "none",
                                                            (e.get("header_grade") or {}).get("grade"))],
                  raw={"waf_hits": e.get("waf_hits"), "header_grade": e.get("header_grade"),
                       "cdn_headers": e.get("cdn_headers")})
        n += 1
    for v in data.get("vhosts", []):
        u = v.get("url") or ""
        hn = v.get("host") or v.get("name") or ""
        store.add("vhost", hn + "|" + hostport_of(u), url=u, host=hn,
                  labels=["vhost", "hidden_host"], sources=["P4"],
                  evidence=["P4: vhost differential (len=%s vs base=%s)" % (v.get("len"), v.get("base_len"))],
                  raw=dict(v))
        n += 1
    for p in data.get("ports", []):
        key = "%s:%s" % (p.get("host"), p.get("port"))
        store.add("port", key, url="", host=p.get("host") or "",
                  labels=["port", "service"], sources=["P4"],
                  evidence=["P4: %s open (%s %s)" % (key, p.get("service", ""), p.get("product", ""))],
                  raw=dict(p))
        n += 1
    return n


def ingest_content(store, eng):
    data = load_phase_json(eng, "content", "content.json")
    if not data:
        return 0
    n = 0
    results = data.get("results") or {}
    for host, rec in (results.items() if isinstance(results, dict) else []):
        base = rec.get("base_url") or ("https://" + host)
        base_host = host_of(base)
        baseline = rec.get("baseline") or {}
        store.add("host", hostport_of(base) or host, url=base, host=base_host,
                  labels=["host", "live"], sources=["P5"],
                  evidence=["P5: content enum baseline status=%s serves200=%s"
                            % (baseline.get("status"), baseline.get("serves_200_on_missing"))],
                  raw={"baseline": baseline})
        for f in rec.get("found", []) + rec.get("extensions", []):
            u = f.get("url") or _resolve(base, f.get("path"))
            path = f.get("path") or up.urlparse(u).path
            if _is_static(path) and not re.search(r"(?i)\.(json|xml|txt|yml|yaml|log|conf|ini)$", path):
                continue
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u) or base_host,
                      labels=["endpoint", "discovered"], sources=["P5"],
                      evidence=["P5: %s %s (%s)" % (f.get("status"), path, (f.get("title") or "")[:40])],
                      params=split_query(u), raw={"status": f.get("status"), "len": f.get("len"),
                                                  "path": path, "title": f.get("title")})
            n += 1
        for d in rec.get("dirs", []):
            u = _resolve(base, d.get("path"))
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u) or base_host,
                      labels=["endpoint", "redirect"], sources=["P5"],
                      evidence=["P5: dir %s -> %s [%s]" % (d.get("path"), d.get("location"), d.get("status"))],
                      raw=dict(d))
            n += 1
        for a in rec.get("artifacts", []):
            u = _resolve(base, a.get("path"))
            sev = (a.get("severity_hint") or "low").lower()
            store.add("artifact", norm_endpoint(u) + "#" + sev, url=u, host=host_of(u) or base_host,
                      labels=["artifact", "sensitive_file", sev], sources=["P5"],
                      evidence=["P5: [%s] %s %s %s" % (sev, a.get("status"), a.get("path"), a.get("note", ""))],
                      raw={"severity_hint": sev, "note": a.get("note"), "status": a.get("status"),
                           "path": a.get("path")})
            n += 1
    return n


def ingest_tech(store, eng):
    data = load_phase_json(eng, "tech", "tech_profile.json")
    if not data:
        return 0
    n = 0
    for r in data.get("hosts", []):
        fu = r.get("final_url") or ""
        host = host_of(fu)
        if not host:
            continue
        ranked = r.get("tech_ranked") or []
        store.add("host", hostport_of(fu) or host, url=fu, host=host,
                  labels=["host", "live"], sources=["P6"],
                  evidence=["P6: stack=%s" % ", ".join("%s(%s)" % (t.get("tech"), t.get("confidence"))
                                                       for t in ranked[:6])],
                  raw={"tech_ranked": ranked, "api_style": r.get("api_style"),
                       "session_model": r.get("session_model"), "cache_layer": r.get("cache_layer")})
        n += 1
        for c in r.get("contradictions", []):
            store.add("config", "contradiction:" + sha1(str(c))[:10], url=fu, host=host,
                      labels=["config", "misconfiguration", "banner_spoof"], sources=["P6"],
                      evidence=["P6: contradiction - %s" % c], raw={"contradiction": c})
            n += 1
        for dp in r.get("default_path_hits", []):
            store.add("artifact", "defaultpath:" + str(dp), url=_resolve(fu, str(dp)), host=host,
                      labels=["artifact", "default_install"], sources=["P6"],
                      evidence=["P6: default install path reachable: %s" % dp],
                      raw={"path": dp, "severity_hint": "medium"})
            n += 1
        sm = r.get("session_model") or {}
        if sm.get("storage_inference"):
            store.add("config", "session:" + host, url=fu, host=host,
                      labels=["config", "session", "session_weakness"], sources=["P6"],
                      evidence=["P6: session storage=%s cookies=%s jwt_in_cookie=%s"
                                % (sm.get("storage_inference"),
                                   ",".join(sm.get("cookie_names") or []) or "-", sm.get("jwt_in_cookie"))],
                      raw=dict(sm))
            n += 1
        # ULTRA: api endpoints from P6 openapi parse (api_endpoints list)
        for ae in (r.get("api_endpoints") or [])[:400]:
            u = ae.get("url") if isinstance(ae, dict) else str(ae)
            u = _resolve(fu, u)
            if not u or _is_static(up.urlparse(u).path):
                continue
            m = (ae.get("method") if isinstance(ae, dict) else None) or "GET"
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u) or host,
                      method=m, labels=["endpoint", "from_openapi"], sources=["P6"],
                      evidence=["P6: OpenAPI spec endpoint (%s)" % m],
                      params=split_query(u), raw={"path": up.urlparse(u).path, "method": m})
            n += 1
        # ULTRA: P6 graphql surface
        for g in (r.get("graphql_endpoints") or [])[:40]:
            u = _resolve(fu, g)
            if not u:
                continue
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u) or host,
                      labels=["endpoint", "graphql"], sources=["P6"],
                      evidence=["P6: GraphQL endpoint (P6 surface probe)"])
            n += 1
        # ULTRA: P6 waf/cdn detection into raw (host node same key merge hota hai)
        for k in ("waf_detected", "cdn_detected"):
            if r.get(k):
                store.add("host", hostport_of(fu) or host, url=fu, host=host,
                          sources=["P6"], raw={k: r.get(k)})
                n += 1
    return n


def ingest_js(store, eng):
    data = load_phase_json(eng, "js", "js_analysis.json")
    if not data:
        return 0
    n = 0
    for a in data.get("assets", []):
        au = a.get("url") or ""
        ahost = host_of(au)
        store.add("js_asset", norm_endpoint(au), url=au, host=ahost,
                  labels=["js_asset"] + (["has_sourcemap"] if a.get("sourcemap_ref") else []),
                  sources=["P7"],
                  evidence=["P7: JS asset, endpoints=%d sinks=%d authz=%d"
                            % (len(a.get("endpoints") or []), sum((a.get("sinks") or {}).values()),
                               sum((a.get("authz_hints") or {}).values()))],
                  raw={"sourcemap_ref": a.get("sourcemap_ref"),
                       "build_ids": a.get("build_ids"),
                       "sourcemap_sources": a.get("sourcemap_sources")})
        n += 1
        base = "https://" + ahost if ahost else ""
        for e in a.get("endpoints", []):
            u = _resolve(base, e)
            if not u:
                continue
            path = up.urlparse(u).path
            if _is_static(path):
                continue
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u) or ahost,
                      labels=["endpoint", "from_js"], sources=["P7"],
                      evidence=["P7: referenced in JS %s" % os.path.basename(up.urlparse(au).path or "")],
                      params=split_query(u), raw={"path": path})
            n += 1
        for e in a.get("graphql_endpoints", []):
            u = _resolve(base, e)
            store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u) or ahost,
                      labels=["endpoint", "graphql"], sources=["P7"],
                      evidence=["P7: GraphQL endpoint referenced in JS"])
            n += 1
        for e in a.get("websockets", []):
            store.add("endpoint", "ws:" + e, url=e, host=host_of(e) or ahost,
                      labels=["endpoint", "websocket"], sources=["P7"],
                      evidence=["P7: WebSocket endpoint referenced in JS"])
            n += 1
        for r in a.get("routes", []):
            store.add("endpoint", "route:" + str(r), url=_resolve(base, r), host=ahost,
                      labels=["endpoint", "client_route"], sources=["P7"],
                      evidence=["P7: client-side route"])
            n += 1
        for p in a.get("params", []):
            ep = store.add("endpoint", norm_endpoint(base or au), url=base or au, host=ahost,
                           labels=["endpoint"], sources=["P7"], evidence=["P7: param context host"])
            _add_param_nodes(store, ep, [p], "P7", base or au)
            n += 1
        for k, v in (a.get("authz_hints") or {}).items():
            store.add("config", "authz:" + ahost + ":" + k, url=au, host=ahost,
                      labels=["config", "authz_client_hint"], sources=["P7"],
                      evidence=["P7: client-side authz hint '%s' x%d" % (k, v)],
                      raw={"hint": k, "count": v})
            n += 1
        for k, v in (a.get("sinks") or {}).items():
            store.add("config", "sink:" + ahost + ":" + k, url=au, host=ahost,
                      labels=["config", "dom_sink"], sources=["P7"],
                      evidence=["P7: DOM sink '%s' x%d" % (k, v)], raw={"sink": k, "count": v})
            n += 1
        for s in a.get("secrets", []):
            fp = str(s.get("type")) + ":" + str(s.get("value_redacted") or s.get("fingerprint") or s.get("len"))
            store.add("secret", fp, url=au, host=ahost,
                      labels=["secret", "credential_exposure"], sources=["P7"],
                      evidence=["P7: %s pattern in JS (redacted, entropy=%s)"
                                % (s.get("type"), s.get("entropy"))],
                      raw=dict(s))
            n += 1
    for s in data.get("secret_hits", []):
        fp = str(s.get("type")) + ":" + str(s.get("value_redacted") or s.get("fingerprint") or s.get("len"))
        store.add("secret", fp, url=s.get("asset") or "", host=host_of(s.get("asset") or ""),
                  labels=["secret", "credential_exposure"], sources=["P7"],
                  evidence=["P7: %s pattern (redacted)" % s.get("type")], raw=dict(s))
        n += 1
    # ULTRA: P7 service workers + persisted query hashes -> config context
    for sw in (data.get("service_workers") or [])[:40]:
        store.add("config", "sw:" + sw, url=sw, host=host_of(sw),
                  labels=["config", "service_worker"], sources=["P7"],
                  evidence=["P7: service worker registered -> cache/authz semantics"])
        n += 1
    return n


# ---------------------------------------------------------------------------
# ULTRA v3 INGESTORS
# ---------------------------------------------------------------------------
def ingest_access(store, eng):
    """
    P11 (mod_access) ke outputs fuse karo - REAL authz evidence milta hai:
    findings.json, access_test_plan.md (kill tests), ACCESS_MATRIX.txt.
    Yeh nodes ko 'Access-Control/IDOR' class me confirmed-evidence deta hai.
    """
    n = 0
    findings = load_phase_json(eng, "access", "findings.json")
    if isinstance(findings, list):
        for f in findings[:400]:
            if not isinstance(f, dict):
                continue
            tgt = f.get("target") or f.get("url") or ""
            host = host_of(tgt)
            title = str(f.get("title") or "")[:80]
            sev = str(f.get("severity") or "low").lower()
            key = norm_endpoint(tgt) if re.match(r"(?i)https?://", tgt) else "finding:" + sha1(title + tgt)[:10]
            nd = store.add("config", "accessfinding:" + sha1(title + tgt)[:12], url=tgt, host=host,
                           labels=["config", "access_finding", sev],
                           sources=["P11"],
                           evidence=["P11: %s [%s] %s" % (title, sev, tgt[:60])],
                           raw={"severity": sev, "title": title,
                                "confidence": f.get("confidence"),
                                "remediation": f.get("remediation")})
            n += 1
            # endpoint bhi tag karo (agar url-shaped hai) -> class boost
            if re.match(r"(?i)https?://", tgt):
                ep = store.add("endpoint", key, url=tgt, host=host,
                               labels=["endpoint", "access_control_evidence"], sources=["P11"],
                               evidence=["P11: %s" % title], raw={"severity": sev})
                _add_param_nodes(store, ep, split_query(tgt), "P11", tgt)
                n += 1
                nd["notes"].append("linked endpoint: %s" % key)
    # ACCESS_MATRIX.txt lines -> role-differential confirmed endpoints
    for line in read_lines(eng, "access", "ACCESS_MATRIX.txt", limit=400):
        m = re.search(r"(https?://\S+)", line)
        if not m:
            continue
        u = m.group(1)
        if _is_static(up.urlparse(u).path):
            continue
        store.add("endpoint", norm_endpoint(u), url=u, host=host_of(u),
                  labels=["endpoint", "access_control_evidence"], sources=["P11"],
                  evidence=["P11: access matrix line: %s" % line.strip()[:100]])
        n += 1
    return n


def ingest_ff(store, eng, base_out, engagement):
    """
    ULTRA: saare modules ke feedforward.json hints fuse karo.
    Ye 'config' hint nodes banata hai - corroboration nahi, lekin routing
    intel deta hai (e.g. P5 ne kaha 'to_phase11: 3 endpoints').
    """
    if _core_read_ff is None:
        return 0
    n = 0
    try:
        ff = _core_read_ff(base_out, engagement) or {}
    except Exception:
        return 0
    for mod, routing in ff.items():
        if mod in (NAME, "surface") or not isinstance(routing, dict):
            continue
        for k, v in list(routing.items())[:20]:
            txt = ""
            if isinstance(v, dict):
                txt = "; ".join("%s=%s" % (a, str(b)[:60]) for a, b in list(v.items())[:6])
            else:
                txt = str(v)[:200]
            store.add("config", "ff:%s:%s" % (mod, k), host="",
                      labels=["config", "feedforward_hint"], sources=["FF"],
                      evidence=["FF/%s: %s -> %s" % (mod, k, txt[:120])],
                      raw={"from_module": mod, "key": k})
            n += 1
    return n


# ---------------------------------------------------------------------------
# SCORING  (weighted-mean of explicit signals -> fully explainable)
# ---------------------------------------------------------------------------
def _status_signal(node):
    st = (node["raw"] or {}).get("status")
    try:
        st = int(st)
    except (TypeError, ValueError):
        return 0.35, "status unknown (no probe data)"
    if st in (401, 403):
        return 0.85, "HTTP %d - resource EXISTS but access-controlled" % st
    if st in (500, 502, 503, 504):
        return 0.78, "HTTP %d - server error (info leak / weak input handling)" % st
    if st == 405:
        return 0.70, "HTTP 405 - method not allowed (endpoint alive, methods differ)"
    if st in (200, 201, 202, 204):
        return 0.50, "HTTP %d - live and directly reachable" % st
    if st in (301, 302, 307, 308):
        return 0.50, "HTTP %d - redirect (trust-boundary crossing)" % st
    if st in (404, 410):
        return 0.05, "HTTP %d - gone (likely stale reference)" % st
    return 0.35, "HTTP %s - neutral" % st


def _dynamic_signal(node):
    u = node.get("url") or ""
    try:
        q = up.parse_qs(up.urlparse(u).query)
    except Exception:
        return 0.0, ""
    hits = 0
    for k, vals in q.items():
        for v in vals:
            if re.match(r"^\d{1,10}$", v) or re.match(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", v, re.I) \
                    or re.match(r"^[0-9a-f]{16,}$", v, re.I):
                hits += 1
                break
    if hits:
        return _clamp(0.5 + 0.25 * hits), "%d numeric/UUID query value(s) -> object references" % hits
    return 0.0, ""


def _rarity_signal(node):
    path = up.urlparse(node.get("url") or "").path or ""
    segs = [s for s in path.split("/") if s]
    if not segs:
        return 0.1, "root path"
    depth = _clamp(len(segs) / 6.0)
    weird = 1.0 if re.search(r"[A-Za-z0-9]{12,}|\d{4,}", path) else 0.0
    v = _clamp(0.35 * depth + 0.5 * weird)
    return v, "path depth=%d, opaque-token=%s" % (len(segs), bool(weird))


def _path_signal(node):
    path = up.urlparse(node.get("url") or "").path or node.get("key") or ""
    best, why = 0.0, ""
    for rx, sens, reason in PATH_SENS:
        if re.search(rx, path):
            if sens > best:
                best, why = sens, reason
    if best:
        return best, "path keyword -> %s" % why
    return 0.15, "no sensitive path keyword"


def _param_signal(node):
    """Param node ke liye: hypothesis table ka best match."""
    names = node.get("params") or []
    if not names and node["type"] == "param":
        names = [node.get("key") or ""]
    best, why = 0.0, ""
    for p in names:
        c, w, _r = param_match(p)
        if c and w > best:
            best, why = w, "'%s' -> %s" % (p, c)
    if best:
        return best, why
    return 0.20, "generic parameter name (no strong class hypothesis)"


def _tech_signal(node, ctx):
    labels = node.get("labels") or []
    path = (up.urlparse(node.get("url") or "").path or "").lower()
    if "graphql" in labels or re.search(r"graphql|/gql(/|$)|graphiql", path):
        return 1.0, "GraphQL surface -> introspection/query abuse"
    if "websocket" in labels:
        return 0.80, "WebSocket endpoint -> authz + injection surface"
    if "auth_form" in labels or re.search(r"(login|signin|auth|oauth|token|reset|forgot|verify)", path):
        return 0.90, "authentication surface -> credential/lockout/MFA testing"
    if "file_upload" in labels or re.search(r"(upload|import)", path):
        return 0.85, "file-upload surface -> content-type/path/webshell testing"
    if re.search(r"(actuator|/env|/metrics|/debug|/console|/adminer|phpinfo|server-status)", path):
        return 0.95, "ops/debug surface -> info disclosure + RCE chains"
    if re.search(r"(swagger|openapi|api-docs|redoc|\.wsdl)", path):
        return 0.80, "API documentation -> complete endpoint inventory"
    if "client_route" in labels:
        return 0.40, "client-side route -> rendering/authz hint"
    return 0.0, ""


def _host_context(node, ctx):
    h = node.get("host") or ""
    if h in ctx["hosts_artifacts"]:
        return 0.7, "same host exposes sensitive artifact(s)"
    if h in ctx["hosts_secrets"]:
        return 0.7, "same host leaked secret pattern(s)"
    if h in ctx["hosts_vhost"]:
        return 0.5, "host discovered via virtual-host differential"
    return 0.0, ""


# ---------------------------------------------------------------------------
# ULTRA v3 SIGNALS (bonus layer - v2 base score floor ke roop me preserved)
# ---------------------------------------------------------------------------
def _method_signal(node):
    """State-changing methods = mutation surface = business-logic priority."""
    m = (node.get("method") or "GET").upper()
    if m in ("POST", "PUT", "PATCH", "DELETE"):
        return 0.85, "%s method -> state-changing (authz/business-logic test first)" % m
    if m in ("TRACE", "TRACK", "OPTIONS"):
        return 0.40, "%s method -> method-abuse / info-leak angle" % m
    return 0.15, "GET (read surface)"


def _waf_signal(node, ctx):
    """WAF/CDN ke peeche ka target: priority me neutral, par effort/stealth note."""
    h = node.get("host") or ""
    keys = (ctx.get("host_waf") or {}).get(h) or []
    if keys:
        return (0.75, "perimeter: %s -> stealth + bypass playbook zaroori (bypass_playbook.txt)"
                % ",".join(keys))
    return (0.30, "no WAF/CDN evidence (direct origin assumed)")


def _version_signal(node):
    """Legacy API versions = weaker guards + forgotten code (test FIRST)."""
    path = (up.urlparse(node.get("url") or "").path or "").lower()
    m = re.search(r"/v(\d+)(?:[/.]|$)", path)
    if not m:
        return (0.25, "no API version marker")
    ver = int(m.group(1))
    if ver <= 1:
        return (0.80, "v%d = oldest API branch -> deprecated guards possible" % ver)
    if ver <= 2:
        return (0.55, "v%d = older branch -> delta-testing vs latest" % ver)
    return (0.30, "v%d = current-ish branch" % ver)


def _secret_adj_signal(node, ctx):
    """Jis host par secret leak hai, wahan ke credential-ish targets boost."""
    h = node.get("host") or ""
    if not h or h not in (ctx.get("hosts_secrets") or set()):
        return (0.0, "")
    names = " ".join(node.get("params") or []) + " " + (up.urlparse(node.get("url") or "").path or "")
    if re.search(r"(?i)(login|auth|token|session|admin|api|key|user|account|reset|oauth)", names):
        return (0.85, "secret-leak host + credential-shaped target -> key reuse likely")
    return (0.45, "secret-leak host (creds se lateral try karo)")


def ultra_bonus(node, ctx):
    """ULTRA bonus (0..1): 4 naye signals ka weighted mean. Explainable alag layer."""
    sig = []
    t = node["type"]
    if t in ("endpoint", "param"):
        v, why = _method_signal(node);   sig.append((0.28, v, why))
        v, why = _waf_signal(node, ctx); sig.append((0.24, v, why))
        v, why = _version_signal(node);  sig.append((0.24, v, why))
        v, why = _secret_adj_signal(node, ctx); sig.append((0.24, v, why))
    else:
        v, why = _waf_signal(node, ctx)
        sig.append((1.0, v, why))
    wsum = sum(s[0] for s in sig) or 1.0
    val = sum(s[0] * s[1] for s in sig) / wsum
    return val, [{"weight": round(s[0], 3), "value": round(s[1], 3), "why": s[2]} for s in sig]


def signals_for(node, ctx):
    """Return [(weight, value, why)] - score = weighted mean. (v2 weights preserved)"""
    t = node["type"]
    sig = []
    if t == "endpoint":
        v, why = _param_signal(node);    sig.append((0.24, v, "param-hypothesis: " + (why or "-")))
        v, why = _path_signal(node);     sig.append((0.18, v, why))
        v, why = _status_signal(node);   sig.append((0.12, v, why))
        v, why = _tech_signal(node, ctx); sig.append((0.14, v, why or "no framework/API signal"))
        v, why = _host_context(node, ctx); sig.append((0.10, v, why or "host context neutral"))
        v, why = _dynamic_signal(node);  sig.append((0.08, v, why or "no dynamic values observed"))
        v, why = _rarity_signal(node);   sig.append((0.07, v, why))
        sig.append((0.07, _clamp((len(node["sources"]) - 1) / 2.0),
                    "corroborated by %d phase(s): %s" % (len(node["sources"]), ",".join(node["sources"]))))
    elif t == "param":
        v, why = _param_signal(node);    sig.append((0.55, v, why))
        v, why = _path_signal(node);     sig.append((0.15, v, why))
        v, why = _dynamic_signal(node);  sig.append((0.15, v, why or "no dynamic value observed"))
        sig.append((0.15, _clamp((len(node["sources"]) - 1) / 2.0),
                    "seen in %d phase(s): %s" % (len(node["sources"]), ",".join(node["sources"]))))
    elif t == "artifact":
        sev = ((node["raw"] or {}).get("severity_hint") or "low").lower()
        sig.append((0.65, ARTIFACT_SEV.get(sev, 0.35), "artifact severity hint = %s" % sev))
        v, why = _path_signal(node);     sig.append((0.15, v, why))
        sig.append((0.20, _clamp((len(node["sources"])) / 2.0),
                    "reported by: %s" % ",".join(node["sources"])))
    elif t == "secret":
        sig.append((0.80, 0.9, "secret-shaped string detected (pattern match, needs manual verify)"))
        sig.append((0.20, 0.8, "entropy/context filter passed"))
    elif t == "vhost":
        if "takeover_hint" in (node.get("labels") or []):
            sig.append((0.80, 0.95, "takeover-shaped dangling service fingerprint"))
        else:
            sig.append((0.70, 0.9, "hidden host revealed by vhost differential"))
        sig.append((0.30, 0.7, "not present in DNS/CT -> deliberately unlisted"))
    elif t == "port":
        raw = node["raw"] or {}
        pr = raw.get("port")
        svc = (raw.get("service") or "").lower()
        interesting = pr in (8080, 8443, 8000, 8888, 3000, 5000, 9000, 9200, 6379, 27017, 5432,
                             3306, 11211, 8081, 8180, 7001, 9042, 5601, 15672, 2375, 2376)
        sig.append((0.6, 0.85 if interesting else 0.35,
                    "port %s%s" % (pr, " (high-value admin/db/dev port)" if interesting else "")))
        sig.append((0.4, 0.8 if svc and svc not in ("http", "https", "unknown") else 0.3,
                    "banner service = %s" % (svc or "unknown")))
    elif t == "config":
        lab = " ".join(node.get("labels") or [])
        w, v = 0.5, 0.5
        if "session_weakness" in lab:
            v, w = 0.75, 0.6
        if "misconfiguration" in lab or "banner_spoof" in lab:
            v, w = 0.8, 0.6
        if "dom_sink" in lab or "authz_client_hint" in lab:
            v, w = 0.7, 0.5
        if "access_finding" in lab:
            sev = (node.get("raw") or {}).get("severity") or "low"
            v, w = {"critical": 0.95, "high": 0.88, "medium": 0.72}.get(sev, 0.55), 0.7
        if "takeover_hint" in lab:
            v, w = 0.92, 0.75
        sig.append((w, v, "config/observation: %s" % lab))
        sig.append((0.4, 0.5, "contextual signal (not directly exploitable)"))
    elif t == "js_asset":
        raw = node["raw"] or {}
        if raw.get("sourcemap_ref"):
            sig.append((0.7, 0.85, "source map available -> original source recoverable"))
            sig.append((0.3, 0.6, "build ids: %s" % (",".join(raw.get("build_ids") or []) or "-")))
        else:
            sig.append((1.0, 0.25, "plain JS asset (already mined by Phase 7)"))
    elif t == "host":
        raw = node["raw"] or {}
        sig.append((0.5, 0.7 if raw.get("status") else 0.4,
                    "live host [%s]" % raw.get("status")))
        sig.append((0.5, _clamp(len(node["sources"]) / 3.0),
                    "confirmed by %d phase(s)" % len(node["sources"])))
    else:
        sig.append((1.0, 0.3, "unclassified node"))
    return [s for s in sig if s[1] > 0 or s[0] > 0]


def score_node(node, ctx):
    sig = signals_for(node, ctx)
    wsum = sum(s[0] for s in sig) or 1.0
    base = sum(s[0] * s[1] for s in sig) / wsum
    nsrc = len(node["sources"])
    corroboration = min(1.25, 1.0 + 0.07 * max(0, nsrc - 1))

    fp = 1.0
    fp_reasons = []
    labels = node.get("labels") or []
    if nsrc == 1 and node["sources"] == ["P3"]:
        fp = min(fp, 0.75)
        fp_reasons.append("archive-only lead (not re-confirmed by an active phase)")
    if (node["raw"] or {}).get("status") in (404, 410):
        fp = min(fp, 0.45)
        fp_reasons.append("stale (404/410)")
    if node["type"] == "endpoint" and not node.get("host"):
        fp = min(fp, 0.6)
        fp_reasons.append("host not resolvable")
    if node["type"] == "endpoint" and "discovered" in labels and (node["raw"] or {}).get("len") in (0, None):
        fp = min(fp, 0.85)
        fp_reasons.append("empty response body")
    if node["type"] == "endpoint" and "takeover_hint" not in labels \
            and "archived" in labels and (node["raw"] or {}).get("status") is None:
        fp = min(fp, 0.85)
        fp_reasons.append("archived reference without live confirmation")

    # ---- ULTRA bonus layer (additive, explainable; v2 base score preserved) ----
    ubonus, ubonus_sig = ultra_bonus(node, ctx)
    stale, stale_why = stale_boost_for(node.get("host") or "", ctx.get("tech_by_host") or {})
    multiplier = (1.0 + 0.15 * ubonus + 0.10 * stale)

    score = _clamp(base * corroboration * fp * multiplier)
    if nsrc >= 3 or (nsrc >= 2 and score >= 0.60):
        conf = "high"
    elif nsrc >= 2 or score >= 0.45:
        conf = "medium"
    else:
        conf = "low"

    node["signals"] = [{"weight": round(s[0], 3), "value": round(s[1], 3), "why": s[2]} for s in sig]
    node["base_score"] = round(base, 4)
    node["corroboration"] = round(corroboration, 3)
    node["fp_discount"] = round(fp, 3)
    node["fp_reasons"] = fp_reasons
    node["ultra_bonus"] = round(ubonus, 4)
    node["ultra_signals"] = ubonus_sig
    node["stale_boost"] = round(stale, 3)
    if stale_why:
        node["stale_why"] = stale_why
    node["score"] = round(score, 4)
    node["priority"] = round(score * 100, 1)
    node["confidence"] = conf
    node["effort"] = estimate_effort(node, ctx)
    node["classes"] = classify(node)
    return node


def estimate_effort(node, ctx=None):
    """ULTRA v2: WAF-protected hosts par stealth effort bump (explainable)."""
    if node["type"] in ("param", "secret", "config", "js_asset"):
        base = "cheap"
    else:
        t = _tech_signal(node, {"hosts_artifacts": set(), "hosts_secrets": set(),
                                "hosts_vhost": set()})[0]
        if t >= 0.85:
            base = "medium"
        elif node["type"] == "artifact":
            base = "cheap"
        elif node["type"] in ("vhost", "port"):
            base = "medium"
        elif node["type"] == "endpoint":
            if "auth_form" in (node.get("labels") or []):
                base = "expensive"
            elif node["params"]:
                base = "medium"
            else:
                base = "cheap"
        else:
            base = "cheap"
    # ULTRA: WAF/403 targets -> one notch up (stealth timing + bypass tries)
    keys = ((ctx or {}).get("host_waf") or {}).get(node.get("host") or "") or []
    order = ["cheap", "medium", "expensive"]
    st = (node.get("raw") or {}).get("status")
    if (keys or st in (401, 403)) and node["type"] in ("endpoint", "host", "vhost"):
        i = min(order.index(base) + 1, len(order) - 1)
        bumped = order[i]
        node["notes"].append("effort %s->%s (perimeter stealth%s)"
                             % (base, bumped, "/403-bypass-first" if st in (401, 403) else ""))
        return bumped
    return base


def classify(node):
    out = []
    if node["type"] == "param" or (node["type"] == "endpoint" and node["params"]):
        for p in (node["params"] or ([node["key"]] if node["type"] == "param" else [])):
            c, _w, _r = param_match(p)
            if c and c not in out:
                out.append(c)
    path = up.urlparse(node.get("url") or "").path or node.get("key") or ""
    def _push(cls):
        if cls and cls not in out:
            out.append(cls)

    if node["type"] == "artifact":
        if re.search(r"(?i)(\.git|\.svn|\.hg|\.bzr)", path):
            _push("Source-Disclosure")
        if re.search(r"(?i)(\.env|\.pem|\.key|\.sql|\.log|credential|secret)", path):
            _push("Secret-Exposure")
        if re.search(r"(?i)(jenkins|grafana|kibana|actuator|heapdump|portainer|prometheus)", path):
            _push("DevOps-Exposure")
        _push("Misconfiguration")
    if node["type"] == "endpoint" and re.search(
            r"(?i)(actuator|heapdump|threaddump|debug/vars|/debug$|env\.json|"
            r"cloudfoundryapplication|jenkins|grafana|kibana|portainer|prometheus)", path):
        _push("DevOps-Exposure")
    if node["type"] == "secret":
        _push("Secret-Exposure")
    if node["type"] == "vhost":
        if "takeover_hint" in (node.get("labels") or []):
            _push("Subdomain-Takeover")
        _push("Hidden-Infrastructure")
    if node["type"] == "port":
        _push("Network-Exposure")
    if "session_weakness" in (node.get("labels") or []):
        _push("Session-Weakness")
    if "misconfiguration" in (node.get("labels") or []):
        _push("Misconfiguration")
    if "service_worker" in (node.get("labels") or []):
        _push("Cache-Poisoning")
    if "graphql" in (node.get("labels") or []):
        _push("API-Abuse")
    if "websocket" in (node.get("labels") or []):
        _push("API-Abuse")
    if "auth_form" in (node.get("labels") or []) and "Auth/Credential" not in out:
        out.append("Auth/Credential")
    if re.search(r"(?i)(admin|manage|console|dashboard|staff|backoffice)", path):
        _push("Access-Control")
    # ULTRA: legacy version branch -> Legacy-API class (old versions test first)
    vm = re.search(r"/v(\d+)(?:[/.]|$)", path)
    if vm and int(vm.group(1)) <= 1 and node["type"] == "endpoint":
        _push("Legacy-API")
    if not out and node["type"] == "endpoint":
        _push("Unclassified")
    return out


# ---------------------------------------------------------------------------
# IGNORE RULES  (explainable drops)
# ---------------------------------------------------------------------------
IGNORE_RULES = [
    (lambda n: n["type"] == "endpoint" and _is_noise_path(up.urlparse(n.get("url") or "").path),
     "static/noise path (robots, favicon, well-known) - surface value kam"),
    (lambda n: n["type"] == "endpoint" and (n["raw"] or {}).get("status") in (404, 410),
     "404/410 - stale reference"),
    (lambda n: n["type"] == "endpoint" and _is_static(up.urlparse(n.get("url") or "").path)
     and "graphql" not in (n.get("labels") or []),
     "static asset - Phase 7 me already processed"),
    (lambda n: n["type"] == "config" and "dom_sink" in (n.get("labels") or []),
     "DOM sink count akela evidence nahi hai (Phase 14 ka input)"),
    # ULTRA additions
    (lambda n: n["type"] == "config" and "feedforward_hint" in (n.get("labels") or []),
     "feedforward hint - routing intel hai, directly testable target nahi"),
    (lambda n: n["type"] == "endpoint" and "client_route" in (n.get("labels") or [])
     and not n.get("params"),
     "client-side route without params - P7 routes.txt me already listed"),
]


# ---------------------------------------------------------------------------
# CLUSTERING + DIVERSITY RE-RANK (MMR)
# ---------------------------------------------------------------------------
def cluster_nodes(nodes, thr=0.55):
    """
    Endpoint nodes ko shape-similarity se cluster karo.
    Similarity = jaccard(path tokens) + param-name agreement + same host.
    Yehi se pata chalta hai: '/api/users/1' aur '/api/users/2' ek hi test hain.
    """
    eps = [n for n in nodes if n["type"] == "endpoint"]
    clusters = []
    for n in sorted(eps, key=lambda x: -x["score"]):
        tk = tokens(up.urlparse(n.get("url") or "").path)
        pn = set(n.get("params") or [])
        placed = False
        for c in clusters:
            sim = 0.6 * jaccard(tk, c["tokens"]) + 0.25 * jaccard(pn, c["params"]) + \
                  (0.15 if n["host"] == c["host"] else 0.0)
            if sim >= thr:
                c["members"].append(n)
                c["tokens"] |= tk
                c["params"] |= pn
                c["score"] = max(c["score"], n["score"])
                placed = True
                break
        if not placed:
            clusters.append({"host": n["host"], "tokens": tk, "params": pn,
                             "members": [n], "score": n["score"]})
    for c in clusters:
        c["id"] = "C" + sha1("%s|%s" % (c["host"], ",".join(sorted(c["tokens"]))))[:6]
        c["size"] = len(c["members"])
        c["best"] = max(c["members"], key=lambda m: m["score"])
        _bp = up.urlparse(c["best"].get("url") or "").path or "/"
        c["label"] = "%s %s" % (c["host"] or "-", _bp)
        c["classes"] = sorted({x for m in c["members"] for x in m["classes"]})
    return sorted(clusters, key=lambda x: -x["score"])


def mmr_select(cands, k, lam=0.72, thr=0.60):
    """
    Maximal Marginal Relevance: score high rakhna hai PAR diversity bhi.
    Har pick ke baad uske jaise candidates ko penalise karte hain, isliye
    top-N me ek hi endpoint ke 40 clones nahi aate.
    ULTRA v2: type-balance bonus - top-N me endpoint/param/artifact sab
    represent ho (sirf endpoints ki bhid nahi).
    """
    picked, rest = [], list(cands)
    type_count = Counter()
    while rest and len(picked) < k:
        best, best_val = None, -1e9
        for n in rest:
            if not picked:
                val = n["score"]
            else:
                tk = tokens(up.urlparse(n.get("url") or "").path)
                pn = set(n.get("params") or [])
                worst = 0.0
                for p in picked:
                    sim = 0.6 * jaccard(tk, tokens(up.urlparse(p.get("url") or "").path)) + \
                          0.25 * jaccard(pn, set(p.get("params") or [])) + \
                          (0.15 if n.get("host") == p.get("host") else 0.0)
                    worst = max(worst, sim)
                val = lam * n["score"] - (1 - lam) * worst
                # ULTRA: under-represented type ko chhota sa boost
                tc = n.get("type", "")
                if type_count[tc] == 0 and type_count.get("endpoint", 0) >= 3:
                    val += 0.02
            if val > best_val:
                best, best_val = n, val
        if best is None:
            break
        picked.append(best)
        type_count[best.get("type", "")] += 1
        rest.remove(best)
    return picked


# ---------------------------------------------------------------------------
# ULTRA v3: ATTACK-PATH DAG  (precondition ordering)
# ---------------------------------------------------------------------------
def build_attack_paths(kept, ctx, max_paths=12):
    """
    Har top target ke liye PRECONDITIONS nikaalo aur ek ordered sequence banao:
      1. cheap intel pehle (artifact/secret/js_asset same host par)
      2. perimeter bypass (403/401 + WAF host)
      3. actual test
    Ye 'kis order me kya karna hai' ka DAG hai - exam me methodology dikhata hai.
    Returns: [{"id": "AP-01", "target": node, "steps": [...], "prereqs": [...],
               "estimated_min": float, "rationale": str}]
    """
    paths = []
    eps = [n for n in kept if n["type"] in ("endpoint", "param", "vhost", "port")
           and (n.get("classes") or ["Unclassified"]) != ["Unclassified"]]
    eps = sorted(eps, key=lambda n: -n["priority"])[:max_paths * 3]

    artifacts_by_host = defaultdict(list)
    secrets_by_host = defaultdict(list)
    js_by_host = defaultdict(list)
    for n in kept:
        if n["type"] == "artifact":
            artifacts_by_host[n.get("host")].append(n)
        elif n["type"] == "secret":
            secrets_by_host[n.get("host")].append(n)
        elif n["type"] == "js_asset" and (n.get("raw") or {}).get("sourcemap_ref"):
            js_by_host[n.get("host")].append(n)

    for n in eps:
        if len(paths) >= max_paths:
            break
        steps, prereqs = [], []
        h = n.get("host") or ""
        st = (n.get("raw") or {}).get("status")
        wafs = (ctx.get("host_waf") or {}).get(h) or []
        tgt = n.get("url") or n.get("key") or ""

        for a in artifacts_by_host.get(h, [])[:2]:
            steps.append("PRE: %s review karo (%s) -> creds/source intel"
                         % (a.get("url"), ",".join((a.get("labels") or [])[:3])))
            prereqs.append(a["id"])
        for s in secrets_by_host.get(h, [])[:2]:
            steps.append("PRE: leaked secret try karo (%s @ %s) -> key reuse test"
                         % (s.get("key", "")[:24], h))
            prereqs.append(s["id"])
        for j in js_by_host.get(h, [])[:1]:
            steps.append("PRE: sourcemap unpack (%s) -> hidden endpoints/creds"
                         % (j.get("url")))
            prereqs.append(j["id"])
        if st in (401, 403) or wafs:
            kit = bypass_kit_for(wafs, up.urlparse(tgt).path)
            steps.append("BYPASS: %d header variants + %d path variants try karo "
                         "(waf=%s, detail: bypass_playbook.txt)"
                         % (len(kit["headers"]), len(kit["path_variants"]),
                            ",".join(kit["wafs"]) or "generic"))
        steps.append("TEST: %s par %s test karo (classes: %s, effort: %s)"
                     % (tgt[:70], ",".join(n.get("classes") or []) or "triage",
                        ",".join(n.get("classes") or []) or "-", n.get("effort")))
        if n.get("params"):
            steps.append("DEEP: params %s -> per-param hypothesis apply karo"
                         % ",".join(n["params"][:6]))
        est = EFFORT_MIN.get(n.get("effort"), 4.0) + 1.0 * len(prereqs) \
            + (2.0 if (st in (401, 403) or wafs) else 0.0)
        paths.append({
            "id": "AP-%02d" % (len(paths) + 1),
            "target_id": n["id"],
            "target": tgt[:120],
            "host": h,
            "priority": n.get("priority"),
            "steps": steps,
            "prereqs": prereqs,
            "estimated_min": round(est, 1),
            "rationale": "; ".join([s.get("why") for s in (n.get("ultra_signals") or [])
                                    if s.get("value", 0) >= 0.6][:2])
                         or "; ".join(e[:60] for e in (n.get("evidence") or [])[:2]),
        })
    return paths


# ---------------------------------------------------------------------------
# ULTRA v3: API VERSION MATRIX + BLIND SPOTS
# ---------------------------------------------------------------------------
def build_version_matrix(queue):
    """v1/v2/v3... version-wise inventory. Old version = weaker guard hypothesis."""
    by_ver = defaultdict(lambda: {"endpoints": 0, "top": [], "hosts": set(), "methods": Counter()})
    for n in queue:
        if n["type"] != "endpoint":
            continue
        path = (up.urlparse(n.get("url") or "").path or "").lower()
        m = re.search(r"/v(\d+)(?:[/.]|$)", path)
        if not m:
            continue
        v = "v%s" % m.group(1)
        rec = by_ver[v]
        rec["endpoints"] += 1
        rec["hosts"].add(n.get("host") or "-")
        rec["methods"][(n.get("method") or "GET")] += 1
        if len(rec["top"]) < 5:
            rec["top"].append({"id": n["id"], "target": (n.get("url") or "")[:80],
                               "priority": n["priority"], "classes": n.get("classes")})
    rows = []
    vers = sorted(by_ver.keys(), key=lambda s: int(s[1:]))
    latest = vers[-1] if vers else None
    for v in vers:
        rec = by_ver[v]
        ver_int = int(v[1:])
        latest_int = int(latest[1:]) if latest else ver_int
        rows.append({
            "version": v, "endpoints": rec["endpoints"],
            "hosts": sorted(rec["hosts"]), "methods": dict(rec["methods"]),
            "top": rec["top"],
            "age": ("latest" if ver_int == latest_int else "older(%d behind)" % (latest_int - ver_int)),
            "warning": ("LEGACY: is branch me authz/rate-limit guards forget karne "
                        "ka chance sabse zyada - delta test vs latest" if ver_int < latest_int else ""),
        })
    return rows


def build_blind_spots(queue, scored, avail):
    """
    Kahan andhera hai:
      1. classes jinme koi high-confidence node nahi
      2. phase sources jo missing the (garbage-in warning)
      3. endpoint shape gaps (koi POST/mutation surface hi nahi mila?)
    """
    out = {"low_confidence_classes": [], "missing_sources": [], "shape_gaps": []}
    cls_conf = defaultdict(Counter)
    for n in scored:
        for c in (n.get("classes") or []):
            cls_conf[c][n.get("confidence")] += 1
    for c, cc in sorted(cls_conf.items()):
        if cc.get("high", 0) == 0 and cc.get("medium", 0) == 0:
            out["low_confidence_classes"].append(
                {"class": c, "total": sum(cc.values()), "note": "sirf low-confidence evidence - verify pehle"})
    for k, v in (avail or {}).items():
        if not v or v <= 0:
            out["missing_sources"].append(k)
    methods = Counter()
    for n in queue:
        if n["type"] == "endpoint":
            methods[(n.get("method") or "GET").upper()] += 1
    if methods.get("POST", 0) + methods.get("PUT", 0) + methods.get("PATCH", 0) + methods.get("DELETE", 0) == 0 \
            and sum(methods.values()) > 5:
        out["shape_gaps"].append("koi state-changing method surface nahi mila - "
                                 "form/API discovery weak hai (P2 forms / P6 openapi dobara dekho)")
    if not any("graphql" in " ".join(n.get("labels") or []) for n in queue) \
            and sum(methods.values()) > 20:
        out["shape_gaps"].append("koi GraphQL surface nahi mila - agar app SPA hai to "
                                 "P7 bundles me gql patterns manually check karo")
    return out


# ---------------------------------------------------------------------------
# CHAIN DISCOVERY  (multi-step attack paths surface se)
# ---------------------------------------------------------------------------
def build_chains(nodes, clusters):
    """
    Rule-based multi-step chains. Ye 'hypotheses' hain, proof nahi -
    lekin exam me ye dikhata hai ki tum sirf endpoint list nahi, ATTACK PATH sochte ho.
    """
    chains = []
    arts = [n for n in nodes if n["type"] == "artifact"]
    secs = [n for n in nodes if n["type"] == "secret"]
    eps = [n for n in nodes if n["type"] == "endpoint"]
    by_host = defaultdict(list)
    for n in eps:
        by_host[n["host"]].append(n)

    vcs = [a for a in arts if re.search(r"(?i)(\.git|\.svn|\.hg|\.bzr)", a.get("url") or "")]
    if vcs:
        chains.append({
            "id": "CHAIN-VCS-01", "title": "Source code disclosure -> secret extraction -> auth bypass",
            "steps": ["1. %s ko fetch karo (VCS metadata exposed)" % vcs[0].get("url"),
                      "2. Commit objects/packfile recover karo -> poora source tree",
                      "3. Source me hardcoded DB/API keys aur auth logic dhoondho",
                      "4. Usi logic se auth bypass / forge session try karo"],
            "anchors": [v.get("url") for v in vcs[:3]], "confidence": "medium",
            "phase": "23-secrets", "why": "VCS metadata publicly readable hai"})

    envs = [a for a in arts if re.search(r"(?i)(\.env|\.pem|\.key|\.sql|config)", a.get("url") or "")]
    if envs:
        chains.append({
            "id": "CHAIN-ENV-01", "title": "Config/credential file exposure -> lateral movement",
            "steps": ["1. %s fetch karo" % envs[0].get("url"),
                      "2. DB/API credentials + internal hostnames nikaalo",
                      "3. Wahi creds saare in-scope hosts/ports par try karo (credential reuse)",
                      "4. Internal-only service par admin access confirm karo"],
            "anchors": [e.get("url") for e in envs[:3]], "confidence": "high",
            "phase": "23-secrets", "why": "credential-shaped artifact file mila"})

    upload = [n for n in eps if "file_upload" in (n.get("labels") or [])]
    if upload:
        chains.append({
            "id": "CHAIN-UPLOAD-01", "title": "File upload -> stored XSS / webshell / path traversal",
            "steps": ["1. %s ka upload form analyse karo (extensions, content-type checks)" % upload[0].get("url"),
                      "2. Alternate extension + magic-byte bypass try karo",
                      "3. Uploaded file ka public URL dhoondho",
                      "4. Stored XSS (SVG/HTML) ya server-side execution confirm karo"],
            "anchors": [u.get("url") for u in upload[:3]], "confidence": "medium",
            "phase": "13-injection", "why": "file upload surface detect hui"})

    ssrf = [n for n in nodes if n["type"] == "param" and "SSRF/Open-Redirect" in (n.get("classes") or [])]
    if ssrf:
        chains.append({
            "id": "CHAIN-SSRF-01", "title": "SSRF -> cloud metadata -> credential theft",
            "steps": ["1. %s parameter par callback/listener test karo" % ssrf[0].get("key"),
                      "2. Internal ranges (127.0.0.1, 10/8, 169.254.169.254) try karo",
                      "3. Cloud metadata endpoint hit karo -> IAM creds",
                      "4. Creds se cloud resources enumerate karo"],
            "anchors": [s.get("url") for s in ssrf[:3]], "confidence": "medium",
            "phase": "15-ssrf", "why": "SSRF-shaped parameter naam mila"})

    gql = [n for n in eps if "graphql" in (n.get("labels") or [])]
    if gql:
        chains.append({
            "id": "CHAIN-GQL-01", "title": "GraphQL introspection -> hidden mutations -> mass assignment",
            "steps": ["1. %s par introspection query chalao" % gql[0].get("url"),
                      "2. Schema se saare mutation/query nikaalo (JS me na dikhe wo bhi)",
                      "3. Admin-only mutation direct call karo (authz gap)",
                      "4. Input me extra fields bhejo (mass assignment)"],
            "anchors": [g.get("url") for g in gql[:3]], "confidence": "medium",
            "phase": "18-graphql", "why": "GraphQL endpoint surface me hai"})

    vh = [n for n in nodes if n["type"] == "vhost" and "takeover_hint" not in (n.get("labels") or [])]
    if vh:
        chains.append({
            "id": "CHAIN-VHOST-01", "title": "Hidden vhost -> unpatched app -> default creds",
            "steps": ["1. %s ko Host header se access karo" % (vh[0].get("host") or vh[0].get("key")),
                      "2. Version/banner se known CVE map karo",
                      "3. Default admin creds try karo",
                      "4. Uss host ke andar poora Phase 2-7 dobara chalao (naya surface)"],
            "anchors": [v.get("url") for v in vh[:3]], "confidence": "medium",
            "phase": "23-misconfig", "why": "vhost differential se hidden host mila"})

    authz = [n for n in nodes if n["type"] == "config" and "authz_client_hint" in (n.get("labels") or [])]
    if authz and by_host:
        h = authz[0]["host"]
        eps_h = by_host.get(h, [])
        if eps_h:
            chains.append({
                "id": "CHAIN-AUTHZ-01", "title": "Client-side authz hint -> server-side authz gap (IDOR)",
                "steps": ["1. JS me client-side role check mila: %s" % (authz[0].get("raw", {}).get("hint")),
                          "2. %s jaisa endpoint low-privilege session se call karo" % eps_h[0].get("url"),
                          "3. Response me restricted data aaya? -> horizontal privesc",
                          "4. Admin-only field/method low-priv user se try karo"],
                "anchors": [authz[0].get("url"), eps_h[0].get("url")], "confidence": "medium",
                "phase": "11-idor", "why": "authz logic client par hai -> server par missing ho sakta hai"})

    smap = [n for n in nodes if n["type"] == "js_asset" and (n.get("raw") or {}).get("sourcemap_ref")]
    if smap:
        chains.append({
            "id": "CHAIN-SMAP-01", "title": "Source map -> full source review -> undisclosed endpoints",
            "steps": ["1. %s ka .map file unpack karo" % smap[0].get("url"),
                      "2. Original unminified sources recover karo",
                      "3. Undisclosed endpoints/comments/secrets nikaalo",
                      "4. Unlisted endpoints par Phase 8 dobara chalao (recursive surface growth)"],
            "anchors": [s.get("url") for s in smap[:3]], "confidence": "high",
            "phase": "7-js", "why": "source map exposed hai"})

    # ---------------- ULTRA v3 CHAINS (7 naye) ----------------
    # CHAIN-WAF-01: perimeter-blocked target -> bypass -> test
    edge_configs = [n for n in nodes if n["type"] == "config" and "edge" in (n.get("labels") or [])]
    blocked = [n for n in eps if (n.get("raw") or {}).get("status") in (401, 403)]
    if edge_configs and blocked:
        ec = edge_configs[0]
        waf_names = ",".join((ec.get("raw") or {}).get("waf_hits") or []) or "perimeter"
        chains.append({
            "id": "CHAIN-WAF-01",
            "title": "Perimeter (%s) blocked 403 -> origin/bypass -> real access test" % waf_names,
            "steps": ["1. Blocked target: %s" % blocked[0].get("url"),
                      "2. bypass_playbook.txt ke %d header variants ek-ek karke try karo "
                      "(X-Original-URL / X-Forwarded-For / X-Rewrite-URL ...)" %
                      len(WAF_BYPASS_DB.get(waf_key_for(waf_names) or "generic", WAF_BYPASS_DB["generic"])["headers"]),
                      "3. Path-variant differential (//path, /./path, /path/..;/) response "
                      "status/length compare karo",
                      "4. Origin discovery: DNS history/shodan origin IP/MX -> direct origin hit "
                      "(Host header intact) -> WAF skip",
                      "5. Access mile -> asli vuln test (authz/injection) karo"],
            "anchors": [ec.get("url"), blocked[0].get("url")], "confidence": "medium",
            "phase": "5-content", "why": "WAF-protected host par 403 target mila - "
                                         "bypass ke bina test false-negative dega"})

    # CHAIN-VER-01: legacy API version -> forgotten guards
    legacy = [n for n in eps if "Legacy-API" in (n.get("classes") or [])]
    current = [n for n in eps if re.search(r"/v[2-9](?:[/.]|$)", n.get("url") or "")]
    if legacy:
        chains.append({
            "id": "CHAIN-VER-01", "title": "Legacy API version -> forgotten authz -> data exposure",
            "steps": ["1. Old branch endpoint: %s" % legacy[0].get("url"),
                      "2. Latest branch (%s) ke authz headers/params replicate karo "
                      "-> old branch me same guard hai ya nahi compare karo"
                      % (current[0].get("url")[:60] if current else "/api/vN"),
                      "3. Old branch par ID enumeration + admin methods try karo",
                      "4. Deprecated docs (swagger v1) se undisclosed operations nikaalo"],
            "anchors": [l.get("url") for l in legacy[:3]], "confidence": "medium",
            "phase": "17-api", "why": "v1 branch mila hai - guards aksar latest me hi hote hain"})

    # CHAIN-SMAP-SECRET-01: sourcemap -> secret -> live key reuse
    if smap and secs:
        chains.append({
            "id": "CHAIN-SMAP-SEC-01", "title": "Sourcemap sources -> leaked key -> live auth bypass",
            "steps": ["1. %s unpack karo" % smap[0].get("url"),
                      "2. Recovered sources me secret-shaped strings (P7 ne %d dekhe)" % len(secs),
                      "3. Har key ko live endpoint par reuse test karo (API/admin/DB)",
                      "4. Working key -> scope ke andar access confirm -> report (no pivoting out)"],
            "anchors": [smap[0].get("url")] + [s.get("url") for s in secs[:2]], "confidence": "medium",
            "phase": "23-secrets", "why": "sourcemap + secret-shaped strings dono milte hain"})

    # CHAIN-SUB-01: takeover-shaped subdomain
    takeovers = [n for n in nodes if "takeover_hint" in (n.get("labels") or [])
                 or "Subdomain-Takeover" in (n.get("classes") or [])]
    if takeovers:
        t = takeovers[0]
        chains.append({
            "id": "CHAIN-SUB-01", "title": "Dangling CNAME -> service claim -> subdomain takeover",
            "steps": ["1. %s ka CNAME + fingerprint confirm karo (%s)"
                      % (t.get("host"), (t.get("raw") or {}).get("service") or "service=?"),
                      "2. Us service par wahi resource claim karo (RoE allow kare to)",
                      "3. Host par apna content serve -> cookie scope / CSP impact proof",
                      "4. Report: takeover = phishing + token-steal pivot"],
            "anchors": [t.get("url")], "confidence": "medium",
            "phase": "3-passive", "why": "dangling service fingerprint mila"})

    # CHAIN-CACHE-01: CDN/cache layer + param surface -> cache poisoning plan
    cache_hosts = {n.get("host") for n in nodes
                   if (n.get("raw") or {}).get("cache_layer")
                   or re.search(r"(?i)(cloudfront|cdn|cache|varnish|squid)", json.dumps(n.get("raw") or {})[:400])}
    unkeyed = [n for n in eps if n.get("host") in cache_hosts
               and re.search(r"(?i)(x-forwarded|utm|ref|lang|locale|cb=|callback)", n.get("url") or "")]
    if cache_hosts and unkeyed:
        chains.append({
            "id": "CHAIN-CACHE-01", "title": "CDN cache layer + unkeyed param -> cache poisoning",
            "steps": ["1. Cache-layer host: %s" % sorted(cache_hosts)[0],
                      "2. Unkeyed param candidates: %s (utm/x-forwarded/callback)" % unkeyed[0].get("url"),
                      "3. Param me reflect+cache-check: response cached with injected value?",
                      "4. Poisoned cache page -> stored XSS for other users (scope-limited proof)"],
            "anchors": [u.get("url") for u in unkeyed[:3]], "confidence": "low",
            "phase": "22-cache", "why": "cache layer + reflect-shaped params dono present"})

    # CHAIN-DEVOPS-01: devops tooling exposure -> default creds -> CI/CD pivot
    devops = [n for n in eps if re.search(
        r"(?i)(jenkins|grafana|kibana|portainer|prometheus|sonarqube|actuator|"
        r"heapdump|debug/vars)",
        n.get("url") or "")]
    if devops:
        chains.append({
            "id": "CHAIN-DEVOPS-01", "title": "DevOps tooling exposed -> default creds -> CI/CD RCE pivot",
            "steps": ["1. Exposed tool: %s" % devops[0].get("url"),
                      "2. Version/banner -> known default creds + CVE list",
                      "3. Login/default API (RoE limited) -> script console/pipeline access",
                      "4. CI/CD me secrets variables me hote hain -> scope-limited proof only"],
            "anchors": [d.get("url") for d in devops[:3]], "confidence": "medium",
            "phase": "23-misconfig", "why": "devops surface public hai"})

    # CHAIN-PORT-01: db/queue port -> direct connect (RoE-gated)
    risky_ports = [n for n in nodes if n["type"] == "port"
                   and (n.get("raw") or {}).get("port") in (6379, 27017, 3306, 5432, 11211, 9200, 2375)]
    if risky_ports:
        p = risky_ports[0]
        chains.append({
            "id": "CHAIN-PORT-01", "title": "Data-store port open -> unauth access -> data read",
            "steps": ["1. %s:%s (%s) se connection test karo (RoE-gated, read-only)"
                      % (p.get("host"), p.get("raw", {}).get("port"), p.get("raw", {}).get("service") or "?"),
                      "2. No-auth access? -> sirf existence + 1 record proof (no exfiltration)",
                      "3. Version banner -> known CVE note karo",
                      "4. Network segmentation gap report karo"],
            "anchors": ["%s:%s" % (p.get("host"), p.get("raw", {}).get("port"))],
            "confidence": "medium", "phase": "4-active",
            "why": "data-store port externally open mila"})

    return chains


# ---------------------------------------------------------------------------
# COVERAGE PLANNING  (time-boxed, greedily by priority per minute)
# ---------------------------------------------------------------------------
def build_coverage(queue, budget_min):
    """
    Time-box plan: har candidate ka (priority / effort_minutes) ratio.
    Greedy knapsack - 'time hai X minute, pehle kya' ka seedha jawab.
    """
    rows, used = [], 0.0
    ranked = sorted(queue, key=lambda n: -(n["priority"] / EFFORT_MIN.get(n["effort"], 4.0)))
    for n in ranked:
        e = EFFORT_MIN.get(n["effort"], 4.0)
        if used + e > budget_min:
            continue
        used += e
        rows.append({"id": n["id"], "type": n["type"], "priority": n["priority"],
                     "effort_min": e, "ratio": round(n["priority"] / e, 2),
                     "target": n.get("url") or n.get("key"), "classes": n.get("classes"),
                     "phase": CLASS_TO_PHASE.get((n.get("classes") or [None])[0], "triage")})
    return rows, used


def coverage_matrix(queue):
    """vuln class x confidence coverage - 'kahan andhera hai' dikhata hai."""
    m = defaultdict(lambda: Counter())
    for n in queue:
        for c in (n.get("classes") or ["Unclassified"]):
            m[c][n["confidence"]] += 1
    return {k: dict(v) for k, v in sorted(m.items())}


# ---------------------------------------------------------------------------
# ULTRA v3: PHASE-PREP KITS (P9/P10/P11 handoff)
# ---------------------------------------------------------------------------
def build_phase_prep(queue, scored, ctx):
    """Next-block phases ke liye ready kits: targets + kya chahiye hoga."""
    def _pick(pred, limit=12):
        return [n for n in queue if pred(n)][:limit]

    auth_targets = _pick(lambda n: n["type"] == "endpoint" and (
        "auth_form" in (n.get("labels") or [])
        or re.search(r"(?i)(login|signin|oauth|sso|token|register|reset|forgot|mfa|otp)",
                     up.urlparse(n.get("url") or "").path)))
    sess_targets = _pick(lambda n: n["type"] == "endpoint" and (
        re.search(r"(?i)(session|logout|refresh|remember|impersonate|jwt)",
                  (up.urlparse(n.get("url") or "").path + " " + " ".join(n.get("params") or [])))))
    idor_targets = _pick(lambda n: n["type"] in ("endpoint", "param") and (
        "IDOR/BOLA" in (n.get("classes") or []) or "Access-Control" in (n.get("classes") or [])
        or "Mass-Assignment/AuthZ" in (n.get("classes") or [])))
    admin_targets = _pick(lambda n: n["type"] == "endpoint" and re.search(
        r"(?i)(admin|manage|console|dashboard|backoffice|staff|actuator|debug)",
        up.urlparse(n.get("url") or "").path))
    waf_hosts = sorted((ctx.get("host_waf") or {}).keys())
    return {
        "phase9_auth": {
            "targets": [{"id": n["id"], "target": (n.get("url") or n.get("key"))[:90],
                         "why": "; ".join([s["why"] for s in n.get("signals", []) if s.get("value", 0) >= 0.6][:1])
                                or ",".join(n.get("evidence", [])[:1])}
                        for n in auth_targets],
            "needs": "valid low-priv account x1 (+ second account for lockout tests), "
                     "MFA setup access, password-policy doc/RoE limits",
            "waf_note": ("hosts %s par stealth rate chalao (playbook: bypass_playbook.txt)"
                         % ",".join(waf_hosts[:3])) if waf_hosts else "no WAF known",
        },
        "phase10_sessions": {
            "targets": [{"id": n["id"], "target": (n.get("url") or n.get("key"))[:90]}
                        for n in sess_targets],
            "needs": "2 accounts (A/B) + fresh sessions har step me, proxy (Burp) "
                     "cookie capture, JWT decode tool",
            "waf_note": "session fixation/rotation tests ko rate-limit friendly rakho",
        },
        "phase11_idor": {
            "targets": [{"id": n["id"], "target": (n.get("url") or n.get("key"))[:90],
                         "params": n.get("params") or [], "classes": n.get("classes")}
                        for n in idor_targets],
            "needs": "2 accounts (victim+attacker) + object IDs dono ke, "
                     "403-bypass kit ready (perimeter hosts)",
            "waf_note": ("403 targets par pehle bypass (attack_paths.txt BYPASS step), "
                         "fir IDOR differential" if any(
                             (n.get("raw") or {}).get("status") in (401, 403) for n in queue)
                         else "no 403-first targets queued"),
        },
        "authz_admin_focus": {
            "targets": [{"id": n["id"], "target": (n.get("url") or n.get("key"))[:90]}
                        for n in admin_targets],
            "note": "vertical-authz batch - P11 role matrix in-feed",
        },
    }


# ---------------------------------------------------------------------------
# OUTPUT WRITERS
# ---------------------------------------------------------------------------
def _row(n):
    return {"id": n["id"], "type": n["type"], "priority": n["priority"], "score": n["score"],
            "confidence": n["confidence"], "effort": n["effort"],
            "method": n["method"], "target": n.get("url") or n.get("key"),
            "host": n.get("host"), "params": n.get("params"),
            "classes": n.get("classes"), "sources": n["sources"],
            "evidence": n["evidence"][:4], "why": [s["why"] for s in n["signals"] if s["value"] >= 0.6][:4],
            "fp_discount": n["fp_discount"], "fp_reasons": n["fp_reasons"]}


def _kill_test(cls):
    KILLS = {
        "IDOR/BOLA": "victim object ID swap par attacker ko 403/404 milta hai AUR body me victim data nahi -> REJECT",
        "SSRF/Open-Redirect": "URL param me apna listener, response me koi fetch nahi + redirect closed -> REJECT",
        "Path-Traversal/LFI": "dotdot-sequence par byte-diff nahi + normalized 200 same-page -> REJECT",
        "RCE/Command-Injection": "time-delay payload par latency delta nahi + out-of-band ping nahi aaya -> REJECT",
        "Mass-Assignment/AuthZ": "extra field accept hota hai par role unchanged rehta hai server-side -> REJECT",
        "Business-Logic": "negative/overflow value reject ho jaati hai + audit log entry banti hai -> REJECT",
        "Auth/Credential": "token invalid response par bhi wahi generic 401 -> live credential nahi -> REJECT",
        "SQLi/NoSQLi": "error-based payload par identical response + boolean payload par same result -> REJECT",
        "XSS/Injection": "payload encode ho raha hai + sink tak pahunch hi nahi raha -> REJECT",
        "Injection/Deserialization": "structured payload par 400 bad-request + no parser error -> REJECT",
        "SSTI/Format-Injection": "{{7*7}} literal hi reflect hota hai, evaluated nahi -> REJECT",
        "Secret-Exposure": "secret placeholder/dummy hai ya expired (401 from vendor) -> REJECT",
        "Misconfiguration": "exposed page harmless hai + koi sensitive data nahi -> REJECT (info-level report)",
        "Cache-Poisoning": "injected value cache me store nahi hoti (vary header respected) -> REJECT",
        "Session-Weakness": "session rotate ho raha hai + flags (HttpOnly/Secure) set hain -> REJECT",
        "Source-Disclosure": "sirf minified public bundle milta hai, original source nahi -> REJECT",
        "Hidden-Infrastructure": "host dead hai ya wildcard catch-all -> REJECT",
        "Network-Exposure": "port filtered hai ya service RoE-scope ke bahar -> REJECT (note only)",
        "Access-Control": "role matrix me dono roles ka response same + server-side check -> REJECT",
        "API-Abuse": "operation schema ke according deny hota hai + audit alert -> REJECT",
        "Subdomain-Takeover": "CNAME ka target service ab bhi active claim kar leta hai fail -> REJECT",
        "Legacy-API": "old branch par bhi same authz guards active hain -> REJECT",
        "DevOps-Exposure": "tool public hai par auth required + koi default cred nahi -> REJECT",
    }
    return KILLS.get(cls, "expected behaviour milna chahiye; na mile to REJECT karo")


def write_outputs(out, store, ctx, scored, clusters, queue, mmr, chains, coverage, used, budget_min,
                  attack_paths=None, version_matrix=None, blind_spots=None, phase_prep=None,
                  bypass_wafs=None, diff=None):
    nodes = scored
    rows = [_row(n) for n in queue]
    mmr_rows = [_row(n) for n in mmr]

    # ULTRA: per-node bypass kit attach (403/401 + WAF hosts) - technique #3
    def _bypass_field(n):
        st = (n.get("raw") or {}).get("status")
        wafs = (ctx.get("host_waf") or {}).get(n.get("host") or "") or []
        if st in (401, 403) or wafs:
            path = up.urlparse(n.get("url") or "").path or "/"
            kit = bypass_kit_for(wafs, path)
            kit["reason"] = ("HTTP %s blocked target" % st if st in (401, 403)
                             else "WAF-protected host")
            return kit
        return None

    _by_id_q = {n["id"]: n for n in queue}
    _by_id_m = {n["id"]: n for n in mmr}
    for r in rows:
        nd = _by_id_q.get(r["id"])
        if nd:
            bk = _bypass_field(nd)
            if bk:
                r["bypass"] = bk
    for r in mmr_rows:
        nd = _by_id_m.get(r["id"])
        if nd:
            bk = _bypass_field(nd)
            if bk:
                r["bypass"] = bk

    save_json(os.path.join(out, "surface.json"), {
        "phase": PHASE, "plan_version": PLAN_VERSION, "generated_at": now_iso(),
        "engine_version": VERSION, "engagement": ctx["engagement"],
        "stats": ctx["stats"],
        "waf_map": {h: list(v) for h, v in (ctx.get("host_waf") or {}).items()},
        "nodes": [{"id": n["id"], "type": n["type"], "url": n.get("url"), "host": n.get("host"),
                   "method": n["method"], "score": n["score"], "priority": n["priority"],
                   "confidence": n["confidence"], "effort": n["effort"], "classes": n["classes"],
                   "labels": n["labels"], "sources": n["sources"], "params": n["params"],
                   "signals": n["signals"], "evidence": n["evidence"], "notes": n["notes"],
                   "ultra_bonus": n.get("ultra_bonus"), "stale_boost": n.get("stale_boost")}
                  for n in sorted(nodes, key=lambda x: -x["score"])]})

    save_json(os.path.join(out, "priority_queue.json"), {
        "phase": PHASE, "generated_at": now_iso(),
        "note": "score = weighted-mean(signals) x corroboration x false-positive discount x ULTRA-bonus",
        "queue": rows, "diverse_queue": mmr_rows})

    # -------- priority_queue.txt (human readable, exam-ready) --------
    L = []
    L.append("# WASP Phase 8 - PRIORITY QUEUE (%s)" % ctx["engagement"])
    L.append("# generated %s | %d nodes scored | %d ranked (diversity re-ranked)" %
             (now_iso(), len(nodes), len(mmr)))
    L.append("# score = weighted signals; conf = corroboration-based; effort = test cost")
    L.append("")
    L.append("%-6s %-5s %-8s %-6s %-9s %-6s %-46s %s" %
             ("ID", "TYPE", "PRIO", "CONF", "EFFORT", "SRC", "TARGET", "TEST FOR"))
    for n in mmr:
        L.append("%-6s %-5s %-8s %-6s %-9s %-6s %-46s %s" %
                 (n["id"], n["type"][:5], n["priority"], n["confidence"][:3], n["effort"],
                  ",".join(n["sources"]), (n.get("url") or n.get("key") or "")[:46],
                  ",".join(n["classes"]) or "-"))
    save_text(os.path.join(out, "priority_queue.txt"), "\n".join(L))

    # -------- quick wins / deep dives --------
    def eff_rank(x):
        return EFFORT_MIN.get(x["effort"], 4.0)
    quick = sorted([n for n in queue if eff_rank(n) <= 1.0], key=lambda n: -n["priority"])[:40]
    deep = sorted([n for n in queue if eff_rank(n) >= 4.0], key=lambda n: -n["priority"])[:40]
    save_text(os.path.join(out, "quick_wins.txt"),
              "\n".join("%-6s %-8s %-6s %-50s %s" % (n["id"], n["priority"], n["confidence"],
                                                    (n.get("url") or n.get("key") or "")[:50],
                                                    ",".join(n["classes"])) for n in quick))
    save_text(os.path.join(out, "deep_dives.txt"),
              "\n".join("%-6s %-8s %-6s %-50s %s" % (n["id"], n["priority"], n["confidence"],
                                                    (n.get("url") or n.get("key") or "")[:50],
                                                    ",".join(n["classes"])) for n in deep))

    # -------- hypotheses --------
    H = []
    H.append("# Phase 8 - TESTABLE HYPOTHESES")
    H.append("# Har line ek falsifiable statement hai: 'X me Y vulnerability ho sakti hai kyunki Z'.")
    H.append("")
    for n in mmr:
        for c in (n["classes"] or []):
            if c == "Unclassified":
                continue
            ph = CLASS_TO_PHASE.get(c, "triage")
            H.append("[%s] %s" % (n["confidence"].upper(), n["id"]))
            H.append("    HYPOTHESIS: %s me %s ho sakti hai." % ((n.get("url") or n.get("key") or "")[:90], c))
            H.append("    BECAUSE   : %s" % ("; ".join(n["evidence"][:2]) or "-"))
            H.append("    NEXT PHASE: %s" % ph)
            H.append("    KILL TEST : agar niche likha behavior dikhe to hypothesis REJECT karo")
            H.append("                -> %s" % _kill_test(c))
            H.append("")
    save_text(os.path.join(out, "hypotheses.txt"), "\n".join(H))

    # -------- clusters --------
    save_text(os.path.join(out, "clusters.txt"),
              "\n".join("%-9s size=%-3d score=%-6s %-60s classes=%s" %
                        (c["id"], c["size"], round(c["score"], 3), c["label"][:60],
                         ",".join(c["classes"])) +
                        "\n    best: %s" % (c["best"].get("url") or c["best"].get("key"))
                        for c in clusters))

    # -------- chains --------
    CH = ["# Phase 8 - MULTI-STEP ATTACK CHAINS (hypotheses, not proofs)", ""]
    for c in chains:
        CH.append("## [%s] %s  [confidence=%s -> %s]"
                  % (c.get("id", "-"), c["title"], c["confidence"], c["phase"]))
        CH.append("WHY: %s" % c["why"])
        CH.extend("  " + s for s in c["steps"])
        CH.append("ANCHORS: %s" % ", ".join(a for a in c["anchors"] if a))
        CH.append("")
    save_text(os.path.join(out, "chains.txt"), "\n".join(CH))

    # -------- ignore list (honest: kya chhoda aur kyun) --------
    ignored = ctx["ignored"]
    save_text(os.path.join(out, "ignore.txt"),
              "\n".join("%-5s %-30s %s" % (i["type"], str(i["key"])[:30], i["reason"]) for i in ignored) or
              "(nothing ignored)")

    # -------- coverage matrix + plan --------
    cm = coverage_matrix(queue)
    save_text(os.path.join(out, "coverage_matrix.txt"),
              "\n".join("%-28s high=%-4d medium=%-4d low=%-4d" %
                        (k, v.get("high", 0), v.get("medium", 0), v.get("low", 0))
                        for k, v in cm.items()))
    save_text(os.path.join(out, "coverage_plan.txt"),
              "\n".join("# time-boxed plan: budget=%d min, used=%.0f min, %d items" %
                        (budget_min, used, len(coverage)) for _ in [0]) + "\n" +
              "\n".join("%-6s %-5s %-8s %-6s %-6s %-44s %s" %
                        (r["id"], r["type"][:5], r["priority"], "%.1fm" % r["effort_min"],
                         r["ratio"], str(r["target"])[:44], r["phase"]) for r in coverage))

    # ---------------- ULTRA v3 outputs ----------------
    # (1) bypass_playbook.txt - detected perimeter ke liye tailored bypass plan
    BP = ["# Phase 8 ULTRA - SECURITY BYPASS PLAYBOOK (%s)" % ctx["engagement"],
          "# generated %s | detected perimeter: %s" % (now_iso(), ", ".join(bypass_wafs or []) or "none-specific"),
          "# NOTE: Phase 8 khud request NAHI bhejta. Ye playbook aage ke phases (P5/P11/P13/P15)",
          "#       execute karte hain. Sirf in-scope targets par, RoE limits ke andar use karo.",
          ""]
    keys = [k for k in (bypass_wafs or []) if k in WAF_BYPASS_DB] or ["generic"]
    for k in keys:
        db = WAF_BYPASS_DB[k]
        BP.append("## %s" % db["label"])
        BP.append("HEADER VARIANTS (ek-ek karke, response status/len compare):")
        BP.extend("  - %s" % h for h in db["headers"])
        BP.append("PATH VARIANTS (normalize-differential):")
        BP.extend("  - %s" % p for p in db["paths"])
        BP.append("NOTES: %s" % db["notes"])
        BP.append("")
    blocked = [n for n in queue if (n.get("raw") or {}).get("status") in (401, 403)]
    if blocked:
        BP.append("## 403/401 targets (bypass-first list)")
        for n in blocked[:30]:
            BP.append("  %-6s %-52s status=%s" % (n["id"], (n.get("url") or n.get("key"))[:52],
                                                   (n.get("raw") or {}).get("status")))
        BP.append("")
    BP.append("## Universal rules")
    BP.append("  - 1 variant = 1 request; response status + length + body-hash me differential hi signal hai")
    BP.append("  - Access milne ke baad WAHI target asli vuln test ke liye queue me jayega (double-confirm)")
    BP.append("  - Origin discovery (DNS history / shodan / MX) sirf in-scope hosts par")
    save_text(os.path.join(out, "bypass_playbook.txt"), "\n".join(BP))

    # (2) attack_paths.txt - ordered exploit-readiness sequence (DAG)
    AP = ["# Phase 8 ULTRA - ATTACK PATHS (precondition DAG)", ""]
    for p in (attack_paths or []):
        AP.append("## [%s] prio=%s (~%.0f min) %s" % (p["id"], p.get("priority"), p["estimated_min"], p["target"]))
        if p.get("rationale"):
            AP.append("WHY: %s" % p["rationale"])
        AP.extend("  %s" % s for s in p["steps"])
        AP.append("")
    if not attack_paths:
        AP.append("(koi classified target nahi - pehle P2-P7 outputs banao)")
    save_text(os.path.join(out, "attack_paths.txt"), "\n".join(AP))

    # (3) api_version_matrix.txt
    VM = ["# Phase 8 ULTRA - API VERSION MATRIX", ""]
    for r in (version_matrix or []):
        VM.append("%-5s endpoints=%-4d %s %s" % (r["version"], r["endpoints"], r["age"],
                                                 ("hosts: " + ",".join(r["hosts"][:3])) if r["hosts"] else ""))
        VM.append("      methods=%s" % json.dumps(r["methods"]))
        if r.get("warning"):
            VM.append("      !! %s" % r["warning"])
        for t in r["top"][:3]:
            VM.append("      top: %-6s %s" % (t["id"], t["target"]))
    if not version_matrix:
        VM.append("(koi /vN versioned API nahi mila)")
    save_text(os.path.join(out, "api_version_matrix.txt"), "\n".join(VM))

    # (4) phase_prep.txt - P9/P10/P11 handoff kits
    PP = ["# Phase 8 ULTRA - NEXT-PHASE PREP KITS", ""]
    if phase_prep:
        for key in ("phase9_auth", "phase10_sessions", "phase11_idor", "authz_admin_focus"):
            k = phase_prep.get(key) or {}
            PP.append("## %s" % key)
            PP.append("NEEDS: %s" % k.get("needs", k.get("note", "-")))
            if k.get("waf_note"):
                PP.append("WAF  : %s" % k["waf_note"])
            for t in (k.get("targets") or [])[:12]:
                PP.append("  %-6s %s" % (t.get("id", "-"), t.get("target", "")))
            PP.append("")
    save_text(os.path.join(out, "phase_prep.txt"), "\n".join(PP))

    # (5) surface_diff.json - previous run se diff
    if diff is not None:
        save_json(os.path.join(out, "surface_diff.json"), diff)

    # -------- test_plan.md (professor-facing deliverable) --------
    write_test_plan(out, ctx, mmr, clusters, chains, cm, coverage, used, budget_min,
                    attack_paths=attack_paths, version_matrix=version_matrix,
                    blind_spots=blind_spots, phase_prep=phase_prep,
                    bypass_wafs=bypass_wafs)

    # -------- feedforward --------
    routing = defaultdict(dict)
    for cls, ph in CLASS_TO_PHASE.items():
        items = [n for n in queue if cls in (n.get("classes") or [])]
        if items:
            routing["to_phase%s" % ph][cls] = "%d target(s): %s" % (
                len(items), ", ".join((i.get("url") or i.get("key") or "")[:40] for i in items[:3]))
    routing["to_phase32_report"] = {"priority_queue": "priority_queue.json",
                                    "test_plan": "test_plan.md",
                                    "coverage": "coverage_matrix.txt",
                                    "chains": "chains.txt"}
    # ULTRA superset: waf notes + top10 handoff + new outputs pointers
    if ctx.get("host_waf"):
        routing["waf_notes"] = {h: ",".join(k) for h, k in list(ctx["host_waf"].items())[:10]}
        routing["to_phase5_content"]["bypass_playbook"] = "bypass_playbook.txt"
        routing["to_phase11_idor"]["attack_paths"] = "attack_paths.txt"
    top10 = [{"id": n["id"], "target": (n.get("url") or n.get("key") or "")[:60],
              "priority": n["priority"], "classes": n.get("classes")}
             for n in mmr[:10]]
    if top10:
        routing["top_targets"] = {"top10": top10}
    ff = write_feedforward(out, PHASE, dict(routing),
                           notes=["Phase 8 = analysis-only ranked plan; koi request nahi bheja",
                                  "bypass playbook: bypass_playbook.txt (detected perimeter: %s)"
                                  % (", ".join(bypass_wafs or []) or "none")])
    files = ["surface.json", "priority_queue.json", "priority_queue.txt", "quick_wins.txt",
             "deep_dives.txt", "hypotheses.txt", "clusters.txt", "chains.txt", "ignore.txt",
             "coverage_matrix.txt", "coverage_plan.txt", "bypass_playbook.txt",
             "attack_paths.txt", "api_version_matrix.txt", "phase_prep.txt",
             "feedforward.json"]
    if diff is not None:
        files.append("surface_diff.json")
    files.append("test_plan.md")
    stats = {"nodes": len(scored), "queue": len(queue), "mmr": len(mmr),
             "clusters": len(clusters), "chains": len(chains),
             "attack_paths": len(attack_paths or []), "ignored": len(ctx["ignored"]),
             "waf_hosts": len(ctx.get("host_waf") or {})}
    write_manifest(out, PHASE, files, stats=stats,
                   notes=["plan_version=%s" % PLAN_VERSION,
                          "budget=%dmin used=%.0fmin" % (budget_min, used)])
    return ff


def write_test_plan(out, ctx, mmr, clusters, chains, cm, coverage, used, budget_min,
                    attack_paths=None, version_matrix=None, blind_spots=None,
                    phase_prep=None, bypass_wafs=None):
    L = []
    A = L.append
    A("# WASP Phase 8 - Attack Surface Test Plan")
    A("")
    A("**Engagement:** `%s`  " % ctx["engagement"])
    A("**Generated:** %s  " % now_iso())
    A("**Engine:** WASP v%s / surface plan v%s (ULTRA)  " % (VERSION, PLAN_VERSION))
    A("**Nature:** ye phase koi request nahi bhejta - ye Phase 2-7(+11) ke artifacts ka analysis hai.")
    A("")
    A("---")
    A("")
    A("## 1. Surface summary")
    A("")
    A("| Metric | Value |")
    A("|---|---|")
    for k, v in sorted(ctx["stats"].items()):
        A("| %s | %s |" % (k, v))
    A("")
    A("## 2. Ranked targets (diversity-aware top list)")
    A("")
    A("Score = weighted mean of 8 base signals x corroboration x false-positive discount "
      "x ULTRA-bonus (method/WAF/version/secret-adjacency + stale-tech). "
      "Effort = rough test cost (cheap ~1min / medium ~4min / expensive ~12min).")
    A("")
    A("| # | ID | Type | Priority | Confidence | Effort | Target | Test for | Why |")
    A("|---|---|---|---|---|---|---|---|---|")
    for i, n in enumerate(mmr[:40], 1):
        A("| %d | %s | %s | %s | %s | %s | `%s` | %s | %s |" %
          (i, n["id"], n["type"], n["priority"], n["confidence"], n["effort"],
           (n.get("url") or n.get("key") or "")[:60], ", ".join(n["classes"]),
           "; ".join([s["why"] for s in n["signals"] if s["value"] >= 0.6][:2])[:90]))
    A("")
    A("## 3. Time-boxed plan (%d minute budget, %.0f used)" % (budget_min, used))
    A("")
    A("| ID | Priority | Effort | Ratio | Target | Next phase |")
    A("|---|---|---|---|---|---|")
    for r in coverage[:40]:
        A("| %s | %s | %.1fm | %s | `%s` | %s |" %
          (r["id"], r["priority"], r["effort_min"], r["ratio"], str(r["target"])[:60], r["phase"]))
    A("")
    A("## 4. Endpoint clusters (ek test = poora cluster)")
    A("")
    for c in clusters[:25]:
        A("- **%s** (size %d, score %s) - classes: %s" %
          (c["label"], c["size"], round(c["score"], 3), ", ".join(c["classes"]) or "-"))
        A("  - representative: `%s`" % (c["best"].get("url") or c["best"].get("key")))
    A("")
    A("## 5. Multi-step attack chains")
    A("")
    for c in chains:
        A("### %s" % c["title"])
        A("")
        A("- confidence: **%s** -> suggested phase: `%s`" % (c["confidence"], c["phase"]))
        A("- why: %s" % c["why"])
        for s in c["steps"]:
            A("  %s" % s)
        A("")
    A("## 6. ULTRA: Security bypass playbook (detected perimeter)")
    A("")
    if bypass_wafs:
        A("Detected: **%s**. Full detail: `bypass_playbook.txt`. "
          "403/401 targets ko pehle bypass karo, phir asli test - warna false-negative milega." %
          ", ".join(bypass_wafs))
    else:
        A("Koi specific WAF/CDN evidence nahi mila - generic header/path variants "
          "`bypass_playbook.txt` me hain.")
    A("")
    A("## 7. ULTRA: Attack-path DAG (kis order me kya)")
    A("")
    A("| Path | Priority | ~min | Target | Sequence |")
    A("|---|---|---|---|---|")
    for p in (attack_paths or [])[:12]:
        A("| %s | %s | %.0f | `%s` | %s |" %
          (p["id"], p.get("priority"), p["estimated_min"], (p.get("target") or "")[:40],
           " -> ".join(s.split(":")[0] for s in p["steps"])))
    A("")
    A("Full steps: `attack_paths.txt`.")
    A("")
    A("## 8. ULTRA: API version matrix")
    A("")
    if version_matrix:
        A("| Version | Endpoints | Age | Warning |")
        A("|---|---|---|---|")
        for r in version_matrix:
            A("| %s | %d | %s | %s |" % (r["version"], r["endpoints"], r["age"], r.get("warning") or "-"))
    else:
        A("Koi versioned API surface (/vN) nahi mila.")
    A("")
    A("## 9. ULTRA: Blind spots (kahan evidence kamzor hai)")
    A("")
    bs = blind_spots or {}
    if bs.get("low_confidence_classes"):
        A("- Low-confidence-only classes: %s" %
          ", ".join("%s(%d)" % (x["class"], x["total"]) for x in bs["low_confidence_classes"][:8]))
    if bs.get("missing_sources"):
        A("- Missing phase sources (garbage-in risk): %s" % ", ".join(bs["missing_sources"]))
    for g in bs.get("shape_gaps", []):
        A("- %s" % g)
    if not (bs.get("low_confidence_classes") or bs.get("missing_sources") or bs.get("shape_gaps")):
        A("- koi major blind spot nahi mila (evidence balanced hai)")
    A("")
    A("## 10. Coverage matrix - kahan andhera hai")
    A("")
    A("| Vulnerability class | high | medium | low |")
    A("|---|---|---|---|")
    for k, v in cm.items():
        A("| %s | %d | %d | %d |" % (k, v.get("high", 0), v.get("medium", 0), v.get("low", 0)))
    A("")
    A("> Jis class me sirf `low` hai, wahan evidence kamzor hai - wahan pehle verification karo, "
      "seedha exploitation nahi.")
    A("")
    A("## 11. ULTRA: Next-phase prep kits (P9/P10/P11 handoff)")
    A("")
    if phase_prep:
        for key in ("phase9_auth", "phase10_sessions", "phase11_idor", "authz_admin_focus"):
            k = phase_prep.get(key) or {}
            A("### %s" % key)
            A("")
            A("- Needs: %s" % (k.get("needs") or k.get("note") or "-"))
            if k.get("waf_note"):
                A("- Perimeter: %s" % k["waf_note"])
            for t in (k.get("targets") or [])[:8]:
                A("  - `%s` (%s)" % (t.get("target", ""), t.get("id", "-")))
            A("")
    A("## 12. Kya chhoda gaya (honest scope)")
    A("")
    for i in ctx["ignored"][:40]:
        A("- `%s` (%s) - %s" % (i["key"], i["type"], i["reason"]))
    if not ctx["ignored"]:
        A("- kuch nahi chhoda gaya")
    A("")
    A("## 13. Limitations (ye plan kya NAHI hai)")
    A("")
    A("- Ye **network-free analysis** hai: scores Phase 2-7(+11) ke data par based hain, naye probes par nahi.")
    A("- `priority` **probability nahi** hai - ye ek relative ordering heuristic hai.")
    A("- Chained findings **hypotheses** hain; har chain ko kill-test se confirm ya reject karo.")
    A("- Bypass playbook **misconfiguration edges** ke liye hai - WAF crack karna nahi; "
      "har variant RoE ke andar read-only test hota hai.")
    A("- Wordlist/JS coverage jitni weak hogi, surface utni hi incomplete rahegi (garbage-in).")
    A("- Ye plan **exploitation nahi** karta; sirf 'kya, kahan, kis order me' batata hai.")
    A("")
    save_text(os.path.join(out, "test_plan.md"), "\n".join(L) + "\n")


# ---------------------------------------------------------------------------
# ULTRA v3: run-to-run diff
# ---------------------------------------------------------------------------
def build_diff(out, queue):
    """Previous priority_queue.json se target-level diff (new/gone/rank moves)."""
    prev_path = os.path.join(out, "priority_queue.json")
    if not os.path.exists(prev_path):
        return None
    prev = load_json(prev_path, None)
    if not isinstance(prev, dict):
        return None
    prev_rows = prev.get("queue") or []
    prev_rank = {}
    for i, r in enumerate(prev_rows):
        prev_rank[str(r.get("target"))] = (i, r.get("priority"))
    cur_rank = {}
    for i, r in enumerate(rows_of(queue)):
        cur_rank[str(r.get("target"))] = (i, r.get("priority"))
    added, gone, moved = [], [], []
    for tgt, (i, pr) in cur_rank.items():
        if tgt not in prev_rank:
            added.append({"target": tgt[:90], "priority": pr, "rank": i})
        else:
            pi, pp = prev_rank[tgt]
            if abs(i - pi) >= 5 or abs((pp or 0) - (pr or 0)) >= 8:
                moved.append({"target": tgt[:90], "prev_rank": pi, "new_rank": i,
                              "prev_prio": pp, "new_prio": pr})
    for tgt, (i, pr) in prev_rank.items():
        if tgt not in cur_rank:
            gone.append({"target": tgt[:90], "prev_priority": pr})
    return {"generated_at": now_iso(),
            "added": sorted(added, key=lambda x: -x["priority"])[:40],
            "gone": gone[:40],
            "rank_changed": sorted(moved, key=lambda x: abs(x["new_rank"] - x["prev_rank"]))[:40]}


def rows_of(queue):
    return [_row(n) for n in queue]


# ---------------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    head("Phase 8 - Attack Surface Mapping & Priority Queue (ULTRA) | %s" % scope.describe())
    info("Ye phase koi network request NAHI bhejta - sirf Phase 2-7(+11) artifacts fuse karta hai.")

    eng = os.path.dirname(out)
    store = NodeStore()
    avail = {}

    # ---- ingest (har phase = ek step; pure-local isliye rebuild safe hai) ----
    for label, fn, args in [("understand", ingest_understand, (store, eng)),
                            ("passive", ingest_passive, (store, eng)),
                            ("active", ingest_active, (store, eng)),
                            ("content", ingest_content, (store, eng)),
                            ("tech", ingest_tech, (store, eng)),
                            ("js", ingest_js, (store, eng)),
                            ("access(P11)", ingest_access, (store, eng)),
                            ("feedforward", ingest_ff, (store, eng, base_out, scope.engagement))]:
        try:
            n = fn(*args)
        except Exception as e:
            warn("ingest %s failed: %s: %s" % (label, type(e).__name__, e))
            n = -1
        avail[label] = n
        if n >= 0:
            ok("ingest %-12s -> %d raw records" % (label, n))

    nodes = store.all()
    if not nodes:
        err("Phase 2-7 ka koi output nahi mila. Pehle wo phases chalao:")
        err("  python3 wasp.py runall     (ya ek-ek: run --module understand ...)")
        return out

    # ---- context (host-level rollups jo scoring me use hote hain) ----
    host_waf = detect_host_wafs(nodes)
    tech_by_host = {}
    for n in nodes:
        if n["type"] == "host":
            tr = (n.get("raw") or {}).get("tech_ranked") or []
            if tr:
                h = n.get("host") or ""
                tech_by_host[h] = [t for t in tr if isinstance(t, dict)] or \
                                  [{"tech": str(t)} for t in tr]
    ctx = {
        "engagement": scope.engagement,
        "stats": {
            "hosts": len([n for n in nodes if n["type"] == "host"]),
            "endpoints": len([n for n in nodes if n["type"] == "endpoint"]),
            "params": len([n for n in nodes if n["type"] == "param"]),
            "artifacts": len([n for n in nodes if n["type"] == "artifact"]),
            "secrets": len([n for n in nodes if n["type"] == "secret"]),
            "vhosts": len([n for n in nodes if n["type"] == "vhost"]),
            "ports": len([n for n in nodes if n["type"] == "port"]),
            "js_assets": len([n for n in nodes if n["type"] == "js_asset"]),
            "configs": len([n for n in nodes if n["type"] == "config"]),
            "waf_hosts": len(host_waf),
            "sources_present": ", ".join(k for k, v in avail.items() if v and v > 0) or "-",
            "sources_missing": ", ".join(k for k, v in avail.items() if not v or v <= 0) or "-",
        },
        "ignored": [],
        "hosts_artifacts": set(), "hosts_secrets": set(), "hosts_vhost": set(),
        "host_waf": host_waf,
        "tech_by_host": tech_by_host,
    }
    for n in nodes:
        if n["type"] == "artifact":
            ctx["hosts_artifacts"].add(n["host"])
        if n["type"] == "secret":
            ctx["hosts_secrets"].add(n["host"])
        if n["type"] == "vhost":
            ctx["hosts_vhost"].add(n["host"])

    if host_waf:
        ok("perimeter detected: %s" % ", ".join(
            "%s[%s]" % (h, ",".join(k)) for h, k in list(host_waf.items())[:5]))

    # ---- score every node ----
    t0 = time.time()
    for n in nodes:
        score_node(n, ctx)
    scored = nodes
    info("scored %d nodes in %.2fs" % (len(scored), time.time() - t0))

    # ---- ignore list (explainable drops) ----
    kept = []
    for n in scored:
        reason = None
        for rule, why in IGNORE_RULES:
            try:
                if rule(n):
                    reason = why
                    break
            except Exception:
                continue
        if reason:
            ctx["ignored"].append({"id": n["id"], "type": n["type"],
                                   "key": n.get("url") or n.get("key"), "reason": reason})
        else:
            kept.append(n)

    # ---- clusters (on ALL kept endpoints, before queue truncation) ----
    clusters = cluster_nodes(kept)

    # ---- ranked queue ----
    MIN_PRIO = float(getattr(cfg, "surface_min_priority", 22.0))
    queue_types = ("endpoint", "param", "artifact", "secret", "vhost", "port")
    queue = sorted([n for n in kept
                    if n["type"] in queue_types and n["priority"] >= MIN_PRIO],
                   key=lambda n: (-n["priority"], n["id"]))
    dropped_low = [n for n in kept
                   if n["type"] in queue_types and n["priority"] < MIN_PRIO]
    for n in dropped_low:
        ctx["ignored"].append({"id": n["id"], "type": n["type"],
                               "key": n.get("url") or n.get("key"),
                               "reason": "priority %.1f < threshold %.1f (low signal)" % (n["priority"], MIN_PRIO)})

    TOPN = int(getattr(cfg, "surface_top", 60))
    mmr = mmr_select(queue, TOPN)

    # ---- ULTRA analyses ----
    dag_max = int(getattr(cfg, "surface_dag_max", 12))
    attack_paths = build_attack_paths(kept, ctx, max_paths=dag_max)
    version_matrix = build_version_matrix(queue)
    blind_spots = build_blind_spots(queue, scored, avail)
    phase_prep = build_phase_prep(queue, scored, ctx)
    bypass_wafs = sorted({k for ks in host_waf.values() for k in ks}) or \
                  (["generic"] if any((n.get("raw") or {}).get("status") in (401, 403)
                                      for n in queue) else [])

    # ---- chains + coverage ----
    chains = build_chains(kept, clusters)
    budget_min = float(getattr(cfg, "surface_budget_minutes", 90.0))
    coverage, used = build_coverage(queue, budget_min)

    # ---- diff vs previous run ----
    diff = None
    if getattr(cfg, "surface_diff", True):
        try:
            diff = build_diff(out, queue)
        except Exception as e:
            warn("diff build failed: %s" % e)

    write_outputs(out, store, ctx, scored, clusters, queue, mmr, chains, coverage, used, budget_min,
                  attack_paths=attack_paths, version_matrix=version_matrix,
                  blind_spots=blind_spots, phase_prep=phase_prep,
                  bypass_wafs=bypass_wafs, diff=diff)

    head("Phase 8 ULTRA complete")
    ok("nodes=%d | ranked=%d | shown=%d | clusters=%d | chains=%d | paths=%d | ignored=%d"
       % (len(scored), len(queue), len(mmr), len(clusters), len(chains),
          len(attack_paths), len(ctx["ignored"])))
    if bypass_wafs:
        ok("bypass playbook ready for: %s -> bypass_playbook.txt" % ", ".join(bypass_wafs))
    info("READ FIRST: test_plan.md -> attack_paths.txt -> bypass_playbook.txt -> priority_queue.txt")
    if diff:
        ok("diff vs previous run: +%d new, -%d gone, ~%d rank-changed"
           % (len(diff.get("added") or []), len(diff.get("gone") or []),
              len(diff.get("rank_changed") or [])))
    if not ctx["stats"]["sources_present"].count(","):
        warn("Sirf ek phase ka output mila - corroboration weak rahegi. Pehle aur phases chalao.")
    return out


if __name__ == "__main__":
    # standalone: python3 mod_surface.py <base_out> <scope.json>
    import sys
    if len(sys.argv) < 3:
        print("usage: python3 mod_surface.py <base_out> <scope.json>")
        sys.exit(2)
    from wasp_core import Cfg, Scope as _Scope
    _cfg = Cfg(None)
    _scope = _Scope(sys.argv[2])
    run(_cfg, _scope, sys.argv[1])
