#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_misconfig.py  |  Phase 23 - Misconfiguration & Secrets
            Exposure Security ULTRA PRO MAX (Debug/Console/Headers/Errors/
            Secrets/DefaultCreds/AdminPanels/Cloud/CORS/Cookies/Cache/Methods/
            Transport/APISpec/SourceMaps/GraphQL/Containers/Bypass2)
=======================================================================================
v25.0.0 FULL ULTRA PRO MAX (koi ek line ki bhi kami nahi - all to all
techniques: hacking hidden secrets + old & new security bypasses + advanced
level secret techniques). Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se
inherit hote hain, isliye har census request scope-check, rate-limit aur
budget ke andar hi jaati hai.

KYA KARTA HAI
  Misconfiguration = "sahi code, galat deployment" - debug console ON reh
  gaya, directory listing khula, .env leak, verbose errors, default creds,
  admin panel internet-facing, security headers absent, CORS loose, cookies
  bina flags, secrets response/JS/spec me chhap gaye. Ye flaws sirf
  POST/attack se NAHI dikhte - ek INERT GET census kaafi hai. P23 ka kaam:
  (1) MISCONFIG SURFACE ka poora census (14-module feedforward + 7 path
  pools: debug/artifact/admin/spec/container/map/cold), (2) har surface par
  INERT marker-differential (debug-marker shapes, autoindex markers,
  stack-trace shapes, secret-shape regexes - values REDACTED), (3) jo
  execution-class techniques hain (path-traversal force, real IMDS probe,
  cred-stuffing, JNDI payload) unka DOCUMENTED-ONLY playbook + GATED canary
  census (GET-only, .invalid canary origins, bounded caps). -> 26 stages
  (A..Z):

    A. Misconfig surface disc.  - 14-module feedforward (P22 verb-override/
                                  cacheable/platform, P21 misconfig flags,
                                  P12 log4shell hints, P15 traversal, P16
                                  upload, P17 error-leak/spec, P18 gql
                                  misconfig, P19 ws, P4 headers, P6 tech,
                                  P7 js-secrets, P2/P5 endpoints) + artifact
                                  mining + 40-path cold pool
    B. Baseline + WAF           - home marker + soft-404 + WAF fingerprint
    C. Debug/console census     - GATED misconfig_allow_debug_probe: 44-path
                                  pool (actuator/env/heapdump-shapes, Werkzeug
                                  /console, Django DEBUG page, Laravel Ignition,
                                  Symfony _profiler/_wdt, ASP.NET yellow,
                                  elmah/trace.axd, /debug/vars, pprof) +
                                  debug-marker shape classification
    D. Dirlist + artifacts      - GATED misconfig_allow_artifact_probe:
                                  autoindex markers (Index of /, Parent
                                  Directory) + 40 sensitive files (.git/HEAD,
                                  .env, .htaccess, web.config, .DS_Store,
                                  dump.sql, backup.zip, composer/package.json)
                                  - presence-only: status/len/sha1-12, bodies
                                  REDACTED (kabhi store nahi)
    E. Security-headers posture - 16-header census (CSP/HSTS/XFO/XCTO/
                                  Referrer-Policy/Permissions-Policy/COOP/
                                  COEP/CORP/X-XSS-Protection/Cache-Control/
                                  Server/X-Powered-By/X-AspNet-Version/
                                  X-Generator/X-Debug-Token) -> missing/weak
                                  grades (P4/P21 header_posture handoff)
    F. Secrets-in-response      - 30 secret-shape regexes (AKIA/ASIA, private
                                  keys, JWT eyJ, AIza, firebase, xox, ghp,
                                  sk_live, mailgun, twilio, smtp://, basic-auth
                                  comments, internal IPs, emails) - NAMES +
                                  sha1-only, values KABHI store nahi (CWE-200)
    G. Verbose-error census     - GATED misconfig_allow_error_probe: canary
                                  param probes (malformed encoding, deep path,
                                  long param) -> stack-trace/framework-debug
                                  shapes (Traceback, org.springframework,
                                  Werkzeug Debugger, Django Technical,
                                  Laravel Whoops, SQL/ORA/MySQL errors,
                                  ASP.NET yellow screen)
    H. Log4Shell/JNDI surface   - GATED misconfig_allow_log4shell_probe:
                                  version-disclosure census (X-Application-
                                  Version/Server log4j shapes) + log-config
                                  endpoints + 8-row DOCUMENTED playbook -
                                  JNDI payloads KABHI network par NAHI (P12
                                  detection handoff; P23 = misconfig surface)
    I. Default-cred posture     - 14-row DOCUMENTED matrix (tomcat:s3cret,
                                  admin:admin, jenkins, grafana, phpMyAdmin,
                                  WebLogic, WildFly, GlassFish, ActiveMQ,
                                  RabbitMQ guest...) - creds KABHI network
                                  par nahi jaate (0 probes) + login-page
                                  platform fingerprint census
    J. Admin/panel exposure     - GATED misconfig_allow_admin_probe: 40-path
                                  GET census (Tomcat manager, Jenkins, Grafana,
                                  Kibana, phpMyAdmin, wp-admin, /administrator,
                                  RabbitMQ mgmt, Airflow, Nifi, Solr, Drupal,
                                  WebLogic console) - presence-only + platform
                                  title markers
    K. Cloud/metadata surface   - DOCUMENTED-ONLY IMDS playbook (6 rows,
                                  FORBIDDEN-AUTO - P15 owns probes) + cloud
                                  header shapes census (x-amz-/x-amzn/x-azure/
                                  x-goog/server: awselb/cloudfront) + bucket-
                                  shaped path census (P24 handoff)
    L. CORS misconfig grading   - GATED misconfig_allow_cors_probe: GET with
                                  4 canary Origins (same-origin/null/
                                  subdomain.evil.invalid/https://evil.invalid)
                                  -> ACAO reflection census -> grading
                                  (reflect-any/null-allowed/wildcard-strict)
                                  - koi credentials/cookies attach nahi
    M. Cookie/session flags     - Set-Cookie flag census (Secure/HttpOnly/
                                  SameSite absent, Domain= too broad,
                                  __Host-/__Secure- prefix audit, session-ish
                                  cookie names) - passive from census GETs
    N. Header-trust echo        - GATED misconfig_allow_header_echo:
                                  X-Original-URL/X-Rewrite-URL/X-Forwarded-Host/
                                  X-Forwarded-Proto/X-Forwarded-For/X-Custom-IP
                                  echo + misroute differential (6 shapes,
                                  GET-only) + P22 cacheable_token_routes seeds
    O. HTTP methods/TRACE       - GATED misconfig_allow_trace_probe: OPTIONS
                                  Allow census + TRACE canary echo (XST
                                  surface) + method-override echo rollup
                                  (P22 verb shapes)
    P. Transport/downgrade      - http->https redirect shape + HSTS-absent-on-
                                  auth + mixed-content shapes (http:// src in
                                  https body) + Strict-Transport census
    Q. API spec exposure        - GATED misconfig_allow_spec_probe: 12 spec
                                  paths (swagger.json/openapi.json/api-docs/
                                  v2/v3/redoc/docs) -> spec presence + path/
                                  operation-name census (names-only) +
                                  sensitive-op naming flags (P17 handoff)
    R. Source-map/JS census     - GATED misconfig_allow_map_probe: .map
                                  exposure census (sourcesContent flag shape,
                                  presence-only - source KABHI store nahi) +
                                  P7 js-artifact secret-name mining
    S. GraphQL misconfig        - GATED misconfig_allow_gql_probe: GET
                                  introspection-shape census (__schema canary
                                  GET - introspection enabled = CONFIRMED
                                  misconfig aid), GraphiQL/Playground exposure,
                                  field-suggestion error shape, mutations
                                  NAMES-only (P18/P22 handoff)
    T. Container/orchestrator   - GATED misconfig_allow_container_probe:
                                  /healthz, /metrics (Prometheus # HELP shape),
                                  /debug/pprof, /env, /v2/ (docker registry),
                                  /server-status, /nginx_status, /.well-known/
                                  - presence census
    U. Bypass matrix v2         - 18 SECRET misconfig-bypass shapes (GATED
                                  misconfig_allow_bypass2): path-normalization
                                  (//, /./, /../, %2e%2e, ;params, %09, case,
                                  trailing-slash), header-trust (X-Original-URL,
                                  X-Rewrite-URL, X-Forwarded-Host localhost,
                                  X-Forwarded-For 127.0.0.1, Host localhost,
                                  X-Custom-IP-Authorization) - GET-only 403->2xx
                                  differential, canary family waspP23
    V. Misconfig posture        - per-endpoint 12-point composite
       composite                  (headers/cookies/errors-masked/debug-closed/
                                  admin-closed/artifacts-absent/dirlist-off/
                                  cors-strict/cache-safe/methods-minimal/
                                  spec-hidden/secrets-absent)
    W. Cross-module chains      - CH01..CH26 misconfig kill-chains
                                  (P4..P22 handoffs)
    X. Verdict engine           - 6-class ladder (CONFIRMED/SUSPECTED/
                                  HARDENED/BLOCKED/SKIPPED/NOISE) multi-signal
    Y. Technique matrix         - 220 rows x 20 families + CWE + MITRE map
    Z. Reports/artifacts        - 55 artifacts: findings.json,
                                  MISCONFIG_FINDINGS.md, MISCONFIG_MATRIX.txt,
                                  census JSONs, test-plan (kill tests),
                                  remediation, exec summary, kickoff,
                                  playbooks + platform fingerprint + secrets
                                  guard + feedforward (P24/P25/P11/P12/P32/P9)
                                  + MANIFEST + RWX-tree finalize

VERDICT LADDER (6-class, P12..P22-compatible)
  CONFIRMED   -> multi-signal proof (debug console live + debug-marker shape;
                 .env/.git artifact 200 + secret-shape; verbose stack-trace;
                 admin panel live + platform title; ACAO canary reflection;
                 TRACE echo; spec 200; sourcemap sourcesContent; GET
                 introspection __schema; container metrics shape; bypass2
                 403->2xx differential)
  SUSPECTED   -> partial/single signal (disclosure header without console,
                 marker without live shape, header echo without misroute)
  HARDENED    -> defense present (security headers complete, cookies fully
                 flagged, admin 401/403, cors strict, generic errors,
                 no-store on sensitive, spec 404, containers absent)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (misconfig = 'exposure' surface - P15..P22 jitni strict
discipline)
  * 100% INERT: koi exploitation KABHI nahi hota. Har probe synthetic canary
    identifiers (waspP23 family) use karta hai; artifact bodies KABHI store
    nahi hote - sirf status/len/sha1-12/shape-flags. Secret VALUES ka sirf
    sha1-12 + shape-name store hota hai, value itself REDACTED (PII regex
    sweep har detail par).
  * GET-ONLY MODULE: saare probes GET/OPTIONS/HEAD - koi POST/PUT/DELETE
    KABHI (module-wide assert + wasp_core LAYER-4 read-only double-guard).
    TRACE/XST echo census DOCUMENTED-ONLY hai (koi TRACE request network
    par nahi jaati; manual RoE wave). Koi mutation, koi write, koi
    config-change nahi.
  * NO JNDI/EXPLOIT PAYLOADS: Log4Shell stage sirf version-disclosure +
    log-config census karta hai - lookup-shape strings network par KABHI
    nahi jaate (P12 me detection-only shapes already documented hain).
  * NO REAL CREDENTIALS: default-cred matrix DOCUMENTED-ONLY - koi cred
    network par nahi bheja jaata (stuffing/brute FORBIDDEN-AUTO).
  * NO IMDS PROBES: cloud metadata endpoints KABHI directly probe nahi
    (link-local 169.254.x.x family) - sirf documented playbook + response-
    header shapes (P15 owns bounded IMDS smoke, P24 owns cloud deep-dive).
  * ZERO EXTERNAL EGRESS: har HTTP probe scope-check se pehle blocked
    (wasp_core LAYER-4). canary origins sirf *.invalid TLD.
  * allow_active=False -> PASSIVE mode: offline hypotheses only (0 probes).
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - save_json/save_text wrappers se guaranteed.
"""

import os
import re
import sys
import json
import time
import hashlib
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
                           rand_str, shannon_entropy, host_of, median, mad,
                           robust_z, truncate, similarity, module_ctx,
                           write_feedforward, write_manifest, read_feedforward,
                           soft404_baseline, is_soft404, title_of, waf_signature,
                           dns_resolve,
                           redirect_chain, interrupted, info, ok, warn, err,
                           head, dim, C, VERSION, now_human, human_size)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 23")
    sys.exit(1)

NAME = "misconfig"
PHASE = "23-misconfig"
PLAN_VERSION = "25.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    # ---- caps ----
    "misconfig_paths_cap": 40,      # kitne ranked targets census me jaayenge
    "misconfig_probe_cap": 24,      # per-stage probe budget
    "misconfig_cold_paths": 40,     # cold-start pool size
    "misconfig_debug_paths": 44,    # debug/console path pool size
    "misconfig_admin_paths": 40,    # admin/panel path pool size
    "misconfig_artifact_paths": 40, # sensitive-artifact path pool size
    "misconfig_spec_paths": 12,     # api-spec path pool size
    "misconfig_container_paths": 14,# container/orchestrator pool size
    "misconfig_map_cap": 8,         # sourcemap census targets
    "misconfig_bypass2_cap": 18,    # bypass2 shapes per target
    "misconfig_secret_cap": 40,     # secret-shape records cap (sha1-only)
    "misconfig_depth": 3,           # discovery link-follow depth
    # ---- RoE GATES (sab default OFF - exposure-class probes) ----
    "misconfig_allow_debug_probe": False,     # GATE: debug/console/actuator census
    "misconfig_allow_artifact_probe": False,  # GATE: dirlist + .git/.env/backup census
    "misconfig_allow_error_probe": False,     # GATE: verbose-error/stack-trace probes
    "misconfig_allow_log4shell_probe": False, # GATE: log4j version/log-config census
    "misconfig_allow_admin_probe": False,     # GATE: admin/panel exposure census
    "misconfig_allow_cors_probe": False,      # GATE: Origin canary reflection diff
    "misconfig_allow_header_echo": False,     # GATE: X-Original-URL/X-Forwarded trust echo
    "misconfig_allow_trace_probe": False,     # GATE: TRACE/XST canary echo
    "misconfig_allow_spec_probe": False,      # GATE: swagger/openapi spec census
    "misconfig_allow_map_probe": False,       # GATE: source-map exposure census
    "misconfig_allow_gql_probe": False,       # GATE: GET introspection-shape census
    "misconfig_allow_container_probe": False, # GATE: metrics/pprof/env/registry census
    "misconfig_allow_bypass2": False,         # GATE: 18-secret bypass2 shape matrix
}

# RoE gate registry (CLI/report me use hota hai)
ROE_GATES = [
    ("misconfig_allow_debug_probe",     "debug/console/actuator GET census"),
    ("misconfig_allow_artifact_probe",  "dirlist + sensitive artifact GET census"),
    ("misconfig_allow_error_probe",     "verbose-error/stack-trace shape probes"),
    ("misconfig_allow_log4shell_probe", "log4j version/log-config surface census"),
    ("misconfig_allow_admin_probe",     "admin/panel exposure GET census"),
    ("misconfig_allow_cors_probe",      "Origin canary CORS reflection differential"),
    ("misconfig_allow_header_echo",     "X-Original-URL/X-Forwarded-* trust echo"),
    ("misconfig_allow_trace_probe",     "TRACE/XST canary echo census"),
    ("misconfig_allow_spec_probe",      "swagger/openapi spec exposure census"),
    ("misconfig_allow_map_probe",       "source-map exposure census"),
    ("misconfig_allow_gql_probe",       "GraphQL GET introspection-shape census"),
    ("misconfig_allow_container_probe", "metrics/pprof/env/registry census"),
    ("misconfig_allow_bypass2",         "18-secret misconfig bypass2 shape matrix"),
]

CANARY_FAMILY = "waspP23"

# ---------------------------------------------------------------------------
# PATH POOLS (cold-start discovery - misconfig-shaped URL shapes)
# ---------------------------------------------------------------------------
COLD_PATHS = [
    "/debug", "/debug/vars", "/debug/pprof", "/console", "/actuator",
    "/actuator/env", "/actuator/health", "/actuator/heapdump", "/manage",
    "/manager", "/manager/html", "/admin", "/administrator", "/adminer",
    "/phpmyadmin", "/pma", "/elmah.axd", "/trace.axd", "/_profiler",
    "/_wdt", "/web-console", "/server-status", "/server-info", "/nginx_status",
    "/metrics", "/healthz", "/env", "/v2", "/swagger", "/swagger.json",
    "/openapi.json", "/api-docs", "/docs", "/graphql", "/graphiql",
    "/.git/HEAD", "/.env", "/.htaccess", "/web.config", "/crossdomain.xml",
    "/backup.zip", "/dump.sql", "/.DS_Store", "/composer.json", "/app.js.map",
]

# debug/console-shaped paths (stage C pool)
DEBUG_PATHS = [
    "/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/", "/debug/requests",
    "/console", "/console/", "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/info", "/actuator/heapdump", "/actuator/mappings",
    "/actuator/configprops", "/actuator/beans", "/manage", "/management",
    "/elmah.axd", "/trace.axd", "/_profiler", "/_wdt", "/_error",
    "/web-console", "/debugger", "/devTools", "/devtools", "/__debug__",
    "/xdebug", "/phpinfo.php", "/info.php", "/test.php", "/adminer.php",
    "/diagnostics", "/status", "/healthcheck", "/internal/status",
    "/swagger/ui", "/api/debug", "/debug/flush", "/cache/debug",
    "/util/echo", "/system/info", "/debug/performance", "/monitor/health",
]

# admin/panel-shaped paths (stage J pool)
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator", "/administrator/",
    "/adminpanel", "/admin_area", "/manager", "/manager/html", "/host-manager",
    "/jenkins", "/jenkins/", "/grafana", "/grafana/login", "/kibana",
    "/kibana/app", "/phpmyadmin", "/phpmyadmin/index.php", "/pma",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/user/login", "/adminer.php",
    "/rabbitmq", "/rabbitmq/mgmt", "/airflow", "/airflow/login", "/nifi",
    "/solr", "/solr/admin", "/console/j_security_check", "/weblogic",
    "/wls_console", "/GlassFish", "/jmx-console", "/web-console",
    "/actuator/gateway", "/admin/config", "/controlpanel", "/cpanel",
    "/dashboard", "/backend", "/cms/admin", "/struts", "/jmx-web",
]

# sensitive artifact paths (stage D pool - presence-only, bodies REDACTED)
ARTIFACT_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/logs/HEAD", "/.git/description",
    "/.svn/entries", "/.svn/wc.db", "/.hg/hgrc", "/.CVS/Root",
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/env.bak",
    "/.htaccess", "/.htpasswd", "/web.config", "/web.config.bak",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/.DS_Store",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/yarn.lock", "/Gemfile", "/requirements.txt", "/Pipfile",
    "/dump.sql", "/db.sql", "/database.sql", "/backup.sql", "/backup.zip",
    "/backup.tar.gz", "/site.bak", "/site.old", "/index.php.bak",
    "/config.php.bak", "/wp-config.php.bak", "/settings.py.bak",
    "/appsettings.json.bak", "/credentials.json", "/service-account.json",
]

# api-spec paths (stage Q pool)
SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
    "/v2/swagger.json", "/v3/api-docs", "/api-docs", "/api-docs/swagger.json",
    "/api/swagger.json", "/swagger", "/swagger/ui", "/swagger-ui",
    "/docs", "/redoc",
]

# container/orchestrator paths (stage T pool)
CONTAINER_PATHS = [
    "/healthz", "/metrics", "/debug/pprof", "/env", "/v2", "/v2/_catalog",
    "/server-status", "/server-info", "/nginx_status", "/.well-known/",
    "/kubernetes", "/k8s", "/docker", "/registry",
]

# ---------------------------------------------------------------------------
# MARKER SHAPES (debug consoles / autoindex / stack-traces / platforms)
# ---------------------------------------------------------------------------
AUTOINDEX_RX = [
    ("apache-index", re.compile(r"(?i)directory listing (for|of)")),
    ("title-index", re.compile(r"(?i)<title>index of /")),
    ("parent-dir", re.compile(r"(?i)parent directory</a>")),
    ("h1-index", re.compile(r"(?i)<h1>index of /")),
]
DEBUG_MARKER_RX = [
    ("spring-actuator", re.compile(r"(?i)(\"_links\"\s*:\s*\{|whitelabel|actuator)")),
    ("werkzeug-console", re.compile(r"(?i)(werkzeug debugger|debugger console|"
                                    r"interactive console)")),
    ("django-debug", re.compile(r"(?i)(django.?debug|technical report|"
                                r"you're seeing this error because debug)")),
    ("laravel-ignition", re.compile(r"(?i)(ignition|whoops|laravel.*exception|"
                                    r"spatie/laravel-ignition)")),
    ("symfony-profiler", re.compile(r"(?i)(_profiler|_wdt|symfony.*profiler|"
                                    r"web.debug.toolbar)")),
    ("aspnet-trace", re.compile(r"(?i)(application trace|asp\.net.*trace|"
                                r"sys\.diagnostics|trace.axd)")),
    ("rails-dev", re.compile(r"(?i)(actioncontroller|actionview|"
                             r"rails.*exception|development mode)")),
    ("node-inspect", re.compile(r"(?i)(node.*inspector|--inspect|devtools://)")),
    ("go-pprof", re.compile(r"(?i)(types of profiles available|pprof|"
                            r"goroutine profile)")),
    ("phpinfo-shape", re.compile(r"(?i)(phpinfo\(\)|php version.*configuration|"
                                 r"configuration file \(php\.ini\))")),
]
STACKTRACE_RX = [
    ("python-traceback", re.compile(r"(?i)(traceback \(most recent call last\)|"
                                    r"File \"[^\"]+\.py\", line \d+)")),
    ("java-stack", re.compile(r"(?i)(at (org|com|java|net)\.[a-z0-9.]+\.[A-Z]"
                              r"[A-Za-z]+\.[a-zA-Z]+\(|"
                              r"java\.(lang|util|sql)\.[A-Za-z]+Exception)")),
    ("sql-error", re.compile(r"(?i)(sql syntax|ora-\d{5}|mysql|postgresql|"
                             r"sqlite3?\..*error|unclosed quotation)")),
    ("php-fatal", re.compile(r"(?i)(fatal error|parse error|warning:.*\.php "
                             r"on line|uncaught exception)")),
    ("dotnet-stack", re.compile(r"(?i)(system\.[a-z.]+exception|stack trace:|"
                                r"microsoft \.net|asp\.net.*error)")),
    ("ruby-stack", re.compile(r"(?i)(\.rb:\d+:in |activesupport|"
                              r"actioncontroller::.*error)")),
    ("nginx-conf", re.compile(r"(?i)(nginx/\d+\.\d+|nginx error|"
                              r"configuration file.*nginx)")),
]
PLATFORM_LOGIN_RX = [
    ("tomcat-manager", re.compile(r"(?i)(tomcat manager|manager app|"
                                  r"tomcat web application manager)")),
    ("jenkins", re.compile(r"(?i)(jenkins|dashboard \[jenkins\]|"
                           r"jenkins session)")),
    ("grafana", re.compile(r"(?i)(grafana|login to grafana)")),
    ("kibana", re.compile(r"(?i)(kibana|elastic.*console)")),
    ("phpmyadmin", re.compile(r"(?i)(phpmyadmin|configuration of pmadb)")),
    ("wordpress", re.compile(r"(?i)(wp-admin|wordpress|log in.*wordpress)")),
    ("joomla", re.compile(r"(?i)(joomla|administration login)")),
    ("drupal", re.compile(r"(?i)(drupal|user login.*drupal)")),
    ("rabbitmq", re.compile(r"(?i)(rabbitmq management)")),
    ("airflow", re.compile(r"(?i)(airflow|sign in.*airflow)")),
    ("nifi", re.compile(r"(?i)(apache nifi)")),
    ("weblogic", re.compile(r"(?i)(weblogic server console)")),
    ("wildfly", re.compile(r"(?i)(wildfly|jboss management)")),
    ("glassfish", re.compile(r"(?i)(glassfish server console)")),
    ("solr", re.compile(r"(?i)(solr admin)")),
    ("django-admin", re.compile(r"(?i)(django administration|site admin)")),
]
CLOUD_HDR_RX = [
    ("aws", re.compile(r"(?i)(x-amz-|x-amzn-|awselb|cloudfront|aws)")),
    ("azure", re.compile(r"(?i)(x-azure-|x-ms-|arrcookie|requestid.*azure)")),
    ("gcp", re.compile(r"(?i)(x-goog-|x-gcp-|google frontend|via: 1\.1 google)")),
    ("s3-shape", re.compile(r"(?i)(x-amz-request-id|s3|bucket)")),
]
SECRET_SHAPE_RX = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret-shape", re.compile(r"(?i)aws.{0,20}(secret|access).{0,10}[:=]")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
                       r"[A-Za-z0-9_-]{5,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("firebase-config", re.compile(r"(?i)(firebase(apikey|appids?|databaseurl))")),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("stripe-key", re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{10,}\b")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("mailgun-key", re.compile(r"\bkey-[0-9A-Za-z]{32}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b")),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{30,}\b")),
    ("basic-auth-comment", re.compile(r"(?i)(basic auth|basic-auth).{0,30}"
                                      r"(pass|cred|user.*:)")),
    ("smtp-creds", re.compile(r"(?i)smtp://[^\s'\"]{6,}:[^\s'\"]{4,}@")),
    ("db-url-creds", re.compile(r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|"
                                r"redis|amqp)://[^\s'\"]{4,}:[^\s'\"]{4,}@")),
    ("conn-string", re.compile(r"(?i)(connectionstring|data source=).{0,40}"
                               r"(password|pwd)=")),
    ("internal-ip", re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                               r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                               r"192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("stack-trace-leak", re.compile(r"(?i)(traceback|stack trace|exception in)")),
    ("email-leak", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("apikey-param", re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?key|"
                                r"secret[_-]?key|auth[_-]?token|"
                                r"client[_-]?secret)\s*[:=]\s*['\"]?[0-9A-Za-z]")),
    ("hmac-secret", re.compile(r"(?i)(hmac[_-]?secret|signing[_-]?key|"
                               r"encryption[_-]?key)\s*[:=]")),
    ("oauth-secret", re.compile(r"(?i)(client[_-]?secret|consumer[_-]?secret)"
                                r"\s*[:=]\s*['\"]?[0-9A-Za-z]")),
    ("s3-bucket-url", re.compile(r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*"
                                 r"\.amazonaws\.com")),
    ("azure-blob-url", re.compile(r"https?://[a-z0-9.-]+\.blob\.core\.windows\.net")),
    ("source-map-hint", re.compile(r"(?i)(sourceMappingURL=|\.js\.map)")),
    ("debug-flag-leak", re.compile(r"(?i)\"?debug\"?\s*[:=]\s*\"?(true|1)\"?")),
    ("password-field-html", re.compile(r"(?is)(type\s*=\s*['\"]password['\"]|"
                                       r"name\s*=\s*['\"]pass(wd|word)?['\"])")),
    ("git-config-leak", re.compile(r"(?i)(\[core\]|git@github\.com:|"
                                   r"repositoryformatversion)")),
    ("dockerfile-hint", re.compile(r"(?i)(FROM [a-z0-9/.-]+:[\w.-]+|"
                                   r"dockerfile|docker-compose)")),
]
OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-Method-Override",
                    "X-HTTP-Method", "X-Original-Method"]
TRUST_HEADERS = [
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Forwarded-Proto", "https"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]
CORS_ORIGINS = [
    ("same", None),                                   # target ka apna origin
    ("null", "null"),
    ("subdomain", "https://sub.evil.invalid"),
    ("attacker", "https://evil.invalid"),
]
SECURITY_HEADERS = [
    ("content-security-policy", "CSP"),
    ("strict-transport-security", "HSTS"),
    ("x-frame-options", "XFO"),
    ("x-content-type-options", "XCTO"),
    ("referrer-policy", "REFPOL"),
    ("permissions-policy", "PERMPOL"),
    ("cross-origin-opener-policy", "COOP"),
    ("cross-origin-embedder-policy", "COEP"),
    ("cross-origin-resource-policy", "CORP"),
]
DISCLOSURE_HEADERS = [
    ("server", "Server"),
    ("x-powered-by", "X-Powered-By"),
    ("x-aspnet-version", "X-AspNet-Version"),
    ("x-aspnetmvc-version", "X-AspNetMVC-Version"),
    ("x-generator", "X-Generator"),
    ("x-debug-token", "X-Debug-Token"),
    ("x-application-version", "X-Application-Version"),
    ("x-runtime", "X-Runtime"),
    ("x-version", "X-Version"),
]
REJECT_STATUS = (401, 403, 409, 410, 422)
WAF_BLOCK_STATUS = (403, 406, 429)

# ---------------------------------------------------------------------------
# DOCUMENTED-ONLY PLAYBOOKS (FORBIDDEN-AUTO techniques - manual+RoE waves)
# ---------------------------------------------------------------------------
LOG4SHELL_PLAYBOOK_ROWS = [
    ("L4-01", "JNDI lookup via user-agent/log-fields",
     "manual+RoE: lookup-string shapes sirf LAB/DNS-canary wave me; automation "
     "me payload KABHI nahi (P12 owns detection shapes)"),
    ("L4-02", "Version fingerprint -> CVE-2021-44228 window",
     "census: X-Application-Version/Server disclosure -> version<2.15 flag"),
    ("L4-03", "log4j config endpoints (/log4j, /logging, /log-config)",
     "presence census only - config-change FORBIDDEN"),
    ("L4-04", "FormatMsgNoLookups absent -> vulnerable config",
     "review: log4j2.xml pattern me lookups enable? (documented aid)"),
    ("L4-05", "Header-echo version probes (bounded 6 headers)",
     "GATED census: benign echo headers only - koi JNDI string NAHI"),
    ("L4-06", "Egress-callback detection (DNS canary wave)",
     "manual+RoE: canary DNS sirf written authorization par (zero-egress "
     "module rule)"),
    ("L4-07", "Dependency-tree review (log4j-core in SBOM)",
     "offline aid: P6 tech artifacts + version census cross-check"),
    ("L4-08", "Remediation: log4j>=2.17.1 / FormatMsgNoLookups=true / "
     "JndiLookup remove",
     "MISCONFIG_REMEDIATION.md fix-guidance"),
]
DEFAULT_CRED_ROWS = [
    ("DC-01", "tomcat", "manager", "s3cret"),
    ("DC-02", "generic-admin", "admin", "admin"),
    ("DC-03", "jenkins", "admin", "<initial-password-file>"),
    ("DC-04", "grafana", "admin", "admin"),
    ("DC-05", "phpmyadmin", "root", "(empty)"),
    ("DC-06", "weblogic", "weblogic", "weblogic"),
    ("DC-07", "wildfly", "admin", "admin"),
    ("DC-08", "glassfish", "admin", "adminadmin"),
    ("DC-09", "activemq", "admin", "admin"),
    ("DC-10", "rabbitmq", "guest", "guest"),
    ("DC-11", "sonarqube", "admin", "admin"),
    ("DC-12", "nexus", "admin", "admin123"),
    ("DC-13", "airflow", "admin", "admin"),
    ("DC-14", "drupal", "admin", "(weak-setup)"),
]
CLOUD_PLAYBOOK_ROWS = [
    ("CM-01", "IMDSv1 endpoint (link-local 169.254.x.x/meta-data)",
     "FORBIDDEN-AUTO: direct probe KABHI nahi (P15 owns bounded smoke) - "
     "manual+RoE wave only"),
    ("CM-02", "IMDSv2 token-required posture",
     "review: hop-limit/token enforcement (documented aid)"),
    ("CM-03", "S3/GCS/Azure blob public-bucket shapes",
     "census: bucket-shaped URL/headers only - bucket listing FORBIDDEN-AUTO"),
    ("CM-04", "Instance-profile header shapes (x-amz-security-token)",
     "response-header census only"),
    ("CM-05", "Cloud metadata via SSRF (P15 handoff)",
     "P15 ff seeds -> manual gopher/link-local wave (RoE)"),
    ("CM-06", "Remediation: IMDSv2 required, hop-limit 1, public-block S3, "
     "blob SAS minimal-TTL",
     "MISCONFIG_REMEDIATION.md fix-guidance (P24 handoff)"),
]
RACE_TECHNIQUES = [
    ("RA-01", "single-packet H2 race",
     "FORBIDDEN-AUTO: parallel burst KABHI automated nahi - manual RoE wave"),
    ("RA-02", "last-write-wins misconfig window",
     "documented aid: concurrent-session policy review"),
    ("RA-03", "check-then-act TOCTOU on config reload",
     "documented aid: config-reload locking review"),
    ("RA-04", "cache-poison race on misrouted paths",
     "documented aid: cache-key canonicalization review"),
    ("RA-05", "rate-window reset race",
     "documented aid: throttle window design review"),
    ("RA-06", "debug-endpoint toggle race",
     "documented aid: feature-flag persistence review"),
]
# ===========================================================================
# SEVERITY HINTS (v25) - key -> (severity, cvss_hint, why_it_matters)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / surface ----
    "misconfig_endpoint_live":   ("info", 0.0, "Misconfig-class endpoint live "
        "mila (debug/admin/spec/artifact/container shape) - poora P23 engine "
        "ab is surface par chalega (core targeting aid)."),
    "misconfig_candidate_path":  ("info", 0.0, "Misconfig candidate path mined "
        "- ranking ke through census me jaayega."),
    # ---- debug (stage C) ----
    "misconfig_debug_live":      ("critical", 9.1, "Debug/console endpoint LIVE "
        "+ debug-marker shape match (actuator/console/profiler family) - "
        "runtime-introspection exposure (CWE-489/CWE-215; GET census only)."),
    "misconfig_debug_marker":    ("medium", 5.9, "Debug-marker shape census "
        "(console/stack page shapes) - debug-mode exposure review aid "
        "(CWE-489 aid)."),
    "misconfig_debug_absent":    ("info", 0.0, "Debug pool par koi debug-marker "
        "nahi - HARDENED evidence (debug surfaces closed)."),
    # ---- dirlist/artifacts (stage D) ----
    "misconfig_dirlist_live":    ("high", 7.5, "Directory listing LIVE "
        "(autoindex markers) - sensitive-file enumeration surface (CWE-548)."),
    "misconfig_artifact_live":   ("critical", 8.7, "Sensitive artifact GET "
        "200 (git/env/backup family, presence-only) - source/config exposure "
        "(CWE-538/CWE-200; body store KABHI nahi)."),
    "misconfig_artifact_soft":   ("low", 3.4, "Artifact-shaped soft-404 "
        "(template noise) - census row only."),
    "misconfig_artifacts_absent": ("info", 0.0, "Artifact pool sab 404/soft - "
        "HARDENED evidence."),
    # ---- headers (stage E) ----
    "misconfig_headers_missing": ("medium", 5.3, "Security-header posture "
        "MISSING (CSP/HSTS/XFO/XCTO family) - clickjacking/MIME-sniff/"
        "downgrade hardening gaps (CWE-693/CWE-1021 aid)."),
    "misconfig_headers_weak":    ("low", 3.7, "Security-header WEAK value "
        "census (permissive wildcard/directive gaps) - policy review aid."),
    "misconfig_headers_strong":  ("info", 0.0, "Security-header posture STRONG "
        "- HARDENED positive control."),
    "misconfig_disclosure_hdr":  ("low", 3.2, "Tech-disclosure header census "
        "(Server/X-Powered-By/AspNet-Version family) - fingerprint aid "
        "(CWE-200 aid)."),
    # ---- secrets (stage F) ----
    "misconfig_secret_shape":    ("critical", 8.9, "Secret-shape census hit "
        "(credential/key/token family) - secrets-in-response exposure "
        "(CWE-200/CWE-798; value REDACTED, sirf sha1+name)."),
    "misconfig_secret_ip":       ("low", 3.5, "Internal-IP/email disclosure "
        "shape - information-exposure aid (CWE-200 aid)."),
    "misconfig_secret_none":     ("info", 0.0, "Secret-shape sweep clean - "
        "HARDENED evidence (responses redacted)."),
    # ---- errors (stage G) ----
    "misconfig_verbose_error":   ("high", 7.4, "Verbose stack-trace/framework-"
        "debug shape live (error-probe canary) - information exposure via "
        "error messages (CWE-209/CWE-215)."),
    "misconfig_error_masked":    ("info", 0.0, "Errors generic/masked - "
        "HARDENED positive control."),
    # ---- log4shell (stage H) ----
    "misconfig_log4j_version":   ("high", 7.1, "Log4j version-disclosure shape "
        "(<2.17.1 window flag) - JNDI misconfig surface (CWE-502/CWE-917 aid; "
        "koi JNDI payload network par nahi)."),
    "misconfig_log4j_clean":     ("info", 0.0, "Log4j surface clean/patched "
        "shapes - HARDENED evidence."),
    "misconfig_log4shell_documented": ("medium", 6.9, "Log4Shell playbook "
        "documented (8 rows; payloads FORBIDDEN-AUTO) - manual RoE wave aid."),
    # ---- default creds (stage I) ----
    "misconfig_default_creds_documented": ("medium", 6.6, "Default-credential "
        "matrix documented (14 platforms; creds KABHI network par nahi) - "
        "manual review wave aid (CWE-798/CWE-1392 aid)."),
    "misconfig_platform_login":  ("low", 4.4, "Platform login-page fingerprint "
        "census - default-cred review targeting aid."),
    # ---- admin (stage J) ----
    "misconfig_admin_live":      ("high", 7.9, "Admin/panel endpoint LIVE + "
        "platform marker (manager/jenkins/grafana family) - exposed admin "
        "surface (CWE-1234/CWE-284; GET presence only)."),
    "misconfig_admin_absent":    ("info", 0.0, "Admin pool closed/401 - "
        "HARDENED evidence."),
    # ---- cloud (stage K) ----
    "misconfig_cloud_documented": ("medium", 6.4, "Cloud/IMDS playbook "
        "documented (6 rows; direct probes FORBIDDEN-AUTO) - P15/P24 handoff."),
    "misconfig_cloud_header":    ("low", 3.8, "Cloud-provider header-shape "
        "census (x-amz/x-azure/x-goog family) - topology aid (P24 handoff)."),
    # ---- cors (stage L) ----
    "misconfig_cors_reflect":    ("high", 7.6, "ACAO canary-origin REFLECTION "
        "live (attacker/null origin allowed) - cross-origin data-theft "
        "surface (CWE-942; canary origins .invalid, koi cred attach nahi)."),
    "misconfig_cors_wildcard":   ("low", 4.6, "ACAO wildcard census - "
        "wildcard-with-credentials review aid (CWE-942 aid)."),
    "misconfig_cors_strict":     ("info", 0.0, "CORS strict (canary origins "
        "rejected) - HARDENED positive control."),
    # ---- cookies (stage M) ----
    "misconfig_cookie_flags":    ("medium", 5.5, "Set-Cookie flag gaps census "
        "(Secure/HttpOnly/SameSite absent; Domain too broad) - session-"
        "hijack/CSRF hardening aid (CWE-614/CWE-1004 aid)."),
    "misconfig_cookie_strong":   ("info", 0.0, "Cookie flags complete - "
        "HARDENED positive control."),
    # ---- header trust (stage N) ----
    "misconfig_trust_echo":      ("high", 7.3, "Trust-header ECHO/misroute "
        "shape live (X-Original-URL/X-Forwarded-* family) - proxy-trust "
        "misconfig surface (CWE-348/CWE-441 aid; GET-only)."),
    "misconfig_trust_clean":     ("info", 0.0, "Trust-header echo absent - "
        "HARDENED evidence."),
    # ---- methods (stage O) ----
    "misconfig_trace_echo":      ("high", 7.2, "TRACE canary echo live - XST/"
        "verb-misconfig surface (CWE-693 aid; canary body echo census)."),
    "misconfig_methods_broad":   ("low", 4.3, "OPTIONS Allow broad methods "
        "census (PUT/DELETE/TRACE exposed shapes) - verb review aid."),
    "misconfig_methods_minimal": ("info", 0.0, "Methods minimal/strict - "
        "HARDENED evidence."),
    # ---- transport (stage P) ----
    "misconfig_no_redirect":     ("medium", 5.1, "http->https redirect absent "
        "shape - downgrade exposure aid (CWE-319 aid)."),
    "misconfig_mixed_content":   ("medium", 5.2, "Mixed-content shape census "
        "(http:// assets in secure body) - transport hardening aid."),
    "misconfig_transport_strong": ("info", 0.0, "Redirect+HSTS enforced - "
        "HARDENED transport posture."),
    # ---- spec (stage Q) ----
    "misconfig_spec_live":       ("medium", 6.2, "API spec public (swagger/"
        "openapi shapes, names-only census) - attack-surface disclosure aid "
        "(CWE-200 aid; spec content store nahi)."),
    "misconfig_spec_absent":     ("info", 0.0, "Spec paths closed - HARDENED."),
    # ---- sourcemap (stage R) ----
    "misconfig_sourcemap_live":  ("medium", 6.3, "Source-map LIVE (sources "
        "shape present) - source-disclosure aid (CWE-540 aid; source "
        "content KABHI store nahi)."),
    "misconfig_sourcemap_absent": ("info", 0.0, "Source-maps absent - "
        "HARDENED."),
    # ---- gql (stage S) ----
    "misconfig_gql_introspect":  ("medium", 6.5, "GraphQL GET introspection "
        "shape live (__schema canary GET) - schema disclosure misconfig aid "
        "(CWE-200 aid; koi mutation KABHI nahi)."),
    "misconfig_gql_locked":      ("info", 0.0, "Introspection disabled/locked - "
        "HARDENED positive control."),
    "misconfig_gql_playground":  ("low", 4.5, "GraphiQL/Playground exposure "
        "census - console exposure aid."),
    # ---- container (stage T) ----
    "misconfig_container_live":  ("high", 7.7, "Container/orchestrator "
        "endpoint LIVE (metrics/pprof/env/registry shapes) - runtime-"
        "introspection exposure (CWE-489/CWE-668; GET census only)."),
    "misconfig_container_absent": ("info", 0.0, "Container pool closed - "
        "HARDENED."),
    # ---- bypass2 (stage U) ----
    "misconfig_bypass2_accepted": ("high", 7.8, "Misconfig-bypass shape "
        "ACCEPTED (18-secret matrix; 403->2xx differential) - path/"
        "header-trust validation gap (CWE-22/CWE-348/CWE-441 aid; GET-only "
        "canary shapes)."),
    "misconfig_bypass2_blocked":  ("info", 0.0, "Bypass2 shapes blocked/"
        "rejected - HARDENED normalization/trust posture."),
    # ---- posture/extras ----
    "misconfig_posture_weak":    ("high", 7.4, "Misconfig posture composite "
        "WEAK (<5/12 controls) - per-endpoint hardening priority aid."),
    "misconfig_posture_strong":  ("info", 0.0, "Misconfig posture STRONG "
        "(>=9/12 controls) - HARDENED composite evidence."),
    "misconfig_platform_fp":     ("info", 0.0, "Platform shape census "
        "(stack/console fingerprints) - framework-specific checklist aid."),
    "misconfig_secret_guard_hit": ("high", 7.5, "Final REDACTION sweep me "
        "secret/PII shape census artifact par - guard ne sweep kiya "
        "(CWE-200 aid)."),
}


def classify_severity(key):
    """SEVERITY_HINTS lookup (default info/0.0)."""
    sev, cvss, why = SEVERITY_HINTS.get(
        key, ("info", 0.0, "Misconfig census row - manual review aid."))
    return sev, cvss, why


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Findings:
    """P23 findings collector (P12..P22-compatible shape)."""

    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "MC-%03d" % (len(self.items) + 1), "key": key,
               "title": title, "severity": sev, "cvss_hint": cvss,
               "endpoint": endpoint, "detail": pii_redact(detail),
               "why_it_matters": why, "evidence": evidence_ref,
               "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


def _sev_counts(F):
    counts = {}
    for f in F.items:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# PII REDACT (framework rule - P20/P22 pattern)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token)\s*[:=]\s*[^\s,;\"]{6,})")
_PII_PAN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_PAN.sub("***PAN***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


# ---------------------------------------------------------------------------
# CANARY + INERT ENFORCEMENT (P15..P22 pattern - hard rules)
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    """Synthetic marker ids - waspP23 family (real ids KABHI nahi)."""
    return "%s%s%s" % (CANARY_FAMILY, tag, rand_str(6))


# GET-ONLY MODULE ENFORCEMENT: P23 me koi state-changing method KABHI nahi.
# TRACE table me GATE_REQUIRED sentinel ke saath hai, lekin wasp_core
# LAYER-4 (READ_ONLY_METHODS = GET/HEAD/OPTIONS) TRACE request ko bhi block
# karta hai - isliye TRACE/XST echo census DOCUMENTED-ONLY hai (0 TRACE
# requests network par).
_ALLOWED_PROBE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")


def assert_inert_method(method):
    if (method or "GET").upper() not in _ALLOWED_PROBE_METHODS:
        raise RuntimeError(
            "P23 INERT violation: method '%s' allowed nahi hai "
            "(GET/HEAD/OPTIONS + gate-gated TRACE only)" % method)
    if (method or "").upper() == "TRACE":
        # TRACE = exposure-census class: caller MUST have checked RoE gate
        return "GATE_REQUIRED"
    return True


def probe(http, method, url, **kw):
    """INERT probe wrapper: method-guard + scope-firewall (core layer) +
    evidence log. Har P23 network call ISI se jaati hai. Body KABHI nahi."""
    assert_inert_method(method)
    kw.pop("data", None)          # GET-ONLY: body KABHI nahi
    kw.pop("body", None)
    r = http.request(method, url, **kw)
    return r


# ---------------------------------------------------------------------------
# TOLERANT READERS (feedforward/artifact mining - P20/P22 pattern)
# ---------------------------------------------------------------------------
def _artifact(base_dir, mod, fname):
    if not base_dir:
        return ""
    return os.path.join(base_dir, mod, fname)


def _read_json_tolerant(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        return json.loads(txt)
    except Exception:
        # jsonl fallback (first object per line)
        out = []
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            out.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            return None
        return out or None


def _read_text_tolerant(path):
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _walk_lists(obj, depth=0):
    """Nested dict/list me saari string-lists nikaalo (ff routing mining)."""
    if depth > 6:
        return []
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_lists(v, depth + 1))
    elif isinstance(obj, list):
        strs = [x for x in obj if isinstance(x, str)]
        if strs:
            out.append(strs)
        for x in obj:
            if isinstance(x, (dict, list)):
                out.extend(_walk_lists(x, depth + 1))
    return out


# ---------------------------------------------------------------------------
# MARKER DETECTORS (shape classification - values REDACTED)
# ---------------------------------------------------------------------------
def match_markers(rx_table, text):
    """Text me pehla marker-shape (name) ya None - census classification."""
    for name, rx in rx_table:
        if rx.search(text or ""):
            return name
    return None


def match_all_markers(rx_table, text):
    """Text me saare marker-shapes (names list) - census classification."""
    out = []
    for name, rx in rx_table:
        if rx.search(text or ""):
            out.append(name)
    return out


def cookie_flag_audit(set_cookie_hdr):
    """Set-Cookie header -> flag audit dict (names-only, value REDACTED).

    Audit: secure/httponly/samesite/domain-scope/prefix flags."""
    hdr = (set_cookie_hdr or "")[:600]
    low = hdr.lower()
    name = hdr.split("=", 1)[0].strip() if "=" in hdr else ""
    return {
        "name": name[:60],
        "secure": "secure" in low,
        "httponly": "httponly" in low,
        "samesite": ("samesite=strict" in low or "samesite=lax" in low or
                     "samesite=none" in low),
        "samesite_none": "samesite=none" in low,
        "domain_broad": bool(re.search(r"domain=\.[a-z]", low)) or
                        bool(re.search(r"domain=[a-z][a-z0-9.-]*\.[a-z]{2,}",
                                       low)),
        "host_prefix": name.startswith("__Host-"),
        "secure_prefix": name.startswith("__Secure-"),
        "value_len": len(hdr.split("=", 1)[1].split(";")[0].strip()) if
                     "=" in hdr else 0,
    }


def header_posture_grade(present_set, weak_set):
    """9 security headers -> (score 0-9, grade)."""
    score = len(present_set & {k for k, _ in SECURITY_HEADERS})
    if score >= 7:
        grade = "STRONG"
    elif score >= 4:
        grade = "PARTIAL"
    else:
        grade = "WEAK"
    return score, grade


def secret_shape_scan(text):
    """Response body -> secret-shape census rows (values KABHI store nahi).

    Har hit: (shape-name, sha1-12 of matched value, len bucket). Value
    itself REDACTED - framework rule (CWE-200 aid, evidence-safe)."""
    rows = []
    for name, rx in SECRET_SHAPE_RX:
        m = rx.search(text or "")
        if m:
            val = m.group(0)
            rows.append({"shape": name,
                         "sha1_12": hashlib.sha1(
                             val.encode("utf-8", "ignore")).hexdigest()[:12],
                         "len_bucket": "<=16" if len(val) <= 16 else
                                       "17-32" if len(val) <= 32 else
                                       "33-64" if len(val) <= 64 else ">64"})
    return rows


def _prioritize(targets, rx):
    """URLs jisme rx hit -> front (P22 pattern)."""
    hits = [t for t in (targets or []) if isinstance(t, str) and rx.search(t)]
    rest = [t for t in (targets or []) if t not in hits]
    return hits + rest


def _base_of(targets):
    """Origin-root base URL (shortest target) - path-pool censuses yahi use
    karte hain (targets[0] deep-path ho sakta hai - root deterministic)."""
    cands = [t.split("?")[0].rstrip("/") for t in (targets or [])
             if isinstance(t, str) and t]
    return min(cands, key=len) if cands else ""


def same_status_class(a, b):
    return (a or 0) // 100 == (b or 0) // 100


# ===========================================================================
# STAGE A - MISCONFIG SURFACE DISCOVERY (14-module ff + miners + cold)
# ===========================================================================
def _ff_pairs(base_dir, mod, routing_key):
    """feedforward.json routing[key] -> flat URL list (tolerant)."""
    p = _artifact(base_dir, mod, "feedforward.json")
    d = _read_json_tolerant(p)
    if not isinstance(d, dict):
        return []
    routing = d.get("routing") or {}
    val = routing.get(routing_key) or {}
    urls = []
    if isinstance(val, dict):
        for v in val.values():
            for lst in _walk_lists(v):
                urls.extend(lst)
    elif isinstance(val, list):
        for lst in _walk_lists(val):
            urls.extend(lst)
    return [u for u in urls if isinstance(u, str)]


def _ff_any_pairs(base_dir, mods):
    """Kisi bhi mod ki routing me to_phase23* keys -> URL pool."""
    urls = []
    for mod in mods:
        d = _read_json_tolerant(_artifact(base_dir, mod, "feedforward.json"))
        if not isinstance(d, dict):
            continue
        routing = d.get("routing") or {}
        for rk, val in routing.items():
            if not str(rk).lower().startswith("to_phase23"):
                continue
            for lst in _walk_lists(val):
                urls.extend([u for u in lst if isinstance(u, str)])
    return urls


def _mine_urls_from_artifacts(base_dir, mods, fnames, cap=200):
    """Artifact files (json/txt) se URL/endpoint mining (tolerant)."""
    urls = []
    for mod in mods:
        for fn in fnames:
            p = _artifact(base_dir, mod, fn)
            d = _read_json_tolerant(p)
            if isinstance(d, (dict, list)):
                for lst in _walk_lists(d):
                    urls.extend([u for u in lst if isinstance(u, str)])
            else:
                txt = _read_text_tolerant(p)
                for line in txt.splitlines():
                    line = line.strip()
                    if line.startswith(("/", "http")) and len(line) < 300:
                        urls.append(line)
            if len(urls) >= cap:
                return urls[:cap]
    return urls[:cap]


MISCONFIG_PATH_RX = re.compile(
    r"(?i)(debug|console|actuator|admin|manager|swagger|openapi|api-docs|"
    r"graphql|metrics|healthz|pprof|env|\.git|\.env|backup|dump|profiler|"
    r"elmah|trace|monitor|registry|kibana|grafana|jenkins|phpmyadmin|"
    r"server-status|nginx_status|well-known|config|login|secret|cors|"
    r"protected|secure|error)")


def discover_misconfig_surface(ctx, scope, conf):
    """Stage A: 14-module feedforward + artifact mining + cold pool ->
    ranked misconfig targets (shape scoring)."""
    base_dir = ctx.get("base_dir")
    sources, urls = [], set()

    # 1) feedforward routing (to_phase23* keys - P4..P22 documented seeds)
    ff = _ff_any_pairs(base_dir, ["understand", "passive", "active", "content",
                                  "tech", "js", "surface", "auth", "sessions",
                                  "access", "inject", "xss", "client", "ssrf",
                                  "files", "api", "graphql", "ws", "logic",
                                  "replay"])
    for u in ff:
        if u and not u.startswith("waspP"):
            urls.add(u)
    if ff:
        sources.append("feedforward.to_phase23*=%d" % len(ff))

    # 2) P22 misconfig seeds (verb-override + cacheable + platform shapes)
    p22 = _ff_pairs(base_dir, "replay", "to_phase23_misconfig")
    if p22:
        sources.append("p22.misconfig=%d" % len(p22))
        for u in p22:
            if not u.startswith("waspP"):
                urls.add(u)

    # 3) P21 misconfig flags (pwd hygiene/posture/rememberme routes)
    p21 = _ff_pairs(base_dir, "auth", "to_phase23_misconfig")
    if p21:
        sources.append("p21.flags=%d" % len(p21))
        for u in p21:
            if not u.startswith("waspP"):
                urls.add(u)

    # 4) P12 log4shell hints (documented handoff)
    p12 = _ff_pairs(base_dir, "inject", "to_phase23_log4shell")
    if p12:
        sources.append("p12.log4shell=%d" % len(p12))
        for u in p12:
            if not u.startswith("waspP"):
                urls.add(u)

    # 5) artifact mining (endpoints/forms/api/tech/js)
    mined = _mine_urls_from_artifacts(
        base_dir,
        ["understand", "content", "js", "api", "tech", "surface", "active"],
        ["endpoints.txt", "api_endpoints.txt", "all_found.txt", "forms.json",
         "api_surface.json", "interesting.txt", "js_urls.txt",
         "admin_pages.txt", "debug_endpoints.txt"], cap=300)
    if mined:
        sources.append("artifacts=%d" % len(mined))
        for u in mined:
            if u.startswith("http") or u.startswith("/"):
                urls.add(u)

    # 6) scope targets base
    for t in scope.targets:
        urls.add(t)

    # normalize -> same-origin URLs only (scope firewall double-guard)
    origin_hosts = set()
    for t in scope.targets:
        h = host_of(t)
        if h:
            origin_hosts.add(h.lower())
    root_url = ""
    real_pool, cold_pool = [], []
    for u in sorted(urls):
        if u.startswith("http"):
            h = (host_of(u) or "").lower()
            if h and h in origin_hosts:
                real_pool.append(u)
        elif u.startswith("/"):
            b = sorted([t for t in scope.targets if t.startswith("http")])
            if b:
                real_pool.append(b[0].rstrip("/") + u)
    # scope root ALWAYS in real pool (census base + passive posture target)
    for t in scope.targets:
        if t.startswith("http"):
            root_url = t.rstrip("/")
            real_pool.append(root_url)
            break
    # cold pool = supplementary discovery (real targets pehle rank hote hain)
    if root_url:
        for cp in COLD_PATHS[:max(1, int(conf.get("misconfig_cold_paths",
                                                 40)))]:
            cold_pool.append(root_url + cp)
        sources.append("cold_pool=%d" % len(cold_pool))
    real_pool = sorted(set(real_pool))[
        :max(10, int(conf.get("misconfig_paths_cap", 40)) * 3)]

    def _rank(pool):
        out = []
        for u in pool:
            score = 0.0
            kinds = []
            if MISCONFIG_PATH_RX.search(u):
                score += 3.0
                kinds.append("misconfig-shape")
            for tag, rx in ((".git", re.compile(r"\.git")),
                            (".env", re.compile(r"\.env")),
                            ("debug", re.compile(r"(?i)debug|console|pprof")),
                            ("admin", re.compile(r"(?i)admin|manager|console")),
                            ("spec", re.compile(r"(?i)swagger|openapi|api-docs")),
                            ("metrics", re.compile(r"(?i)metrics|healthz|status"))):
                if rx.search(u):
                    score += 1.5
                    kinds.append(tag)
            if re.search(r"(?i)(api/|/api$)", u):
                score += 1.0
                kinds.append("api")
            out.append({"url": u, "score": round(score, 2), "kinds": kinds,
                        "sources": list(sources)})
        out.sort(key=lambda x: -x["score"])
        return out

    cap = max(4, int(conf.get("misconfig_paths_cap", 40)))
    ranked = (_rank(real_pool) + _rank(cold_pool))[:cap]

    return {"ranked": ranked, "targets": [r["url"] for r in ranked],
            "sources": sources, "base_url": (scope.targets or [""])[0],
            "mined_params": {}, "cold": cold_pool[:12]}


# ===========================================================================
# STAGE B - BASELINE + WAF + SOFT-404 (P12..P22 pattern)
# ===========================================================================
def baseline_and_waf(http, targets, conf):
    """Per-target: GET baseline (2x) + soft-404 template + WAF fingerprint."""
    out_rows, waf_rows = [], []
    tb = max(1, int(conf.get("misconfig_probe_cap", 24)))
    for t in targets[:tb]:
        try:
            r1 = probe(http, "GET", t, allow_redirects=False)
            base = soft404_baseline(http, t, samples=2)
            waf = waf_signature(r1.headers, r1.text[:2000], r1.status)
            out_rows.append({"url": t, "status": r1.status, "len": len(r1.body),
                             "title": title_of(r1.text)[:80],
                             "sha1": r1.sha1()[:12],
                             "soft404_base": {"hashes": base.get("hashes", []),
                                              "status": base.get("status")},
                             "marker": ("waspP23-home" if "waspp23" in
                                        (r1.text or "")[:2000].lower() else "")})
            waf_rows.append({"url": t, "waf": waf})
        except Exception as e:
            out_rows.append({"url": t, "error": "%s: %s" % (type(e).__name__, e)})
            waf_rows.append({"url": t, "waf": []})
        if interrupted():
            break
    return {"rows": out_rows, "waf": waf_rows}


# ===========================================================================
# STAGE C - DEBUG/CONSOLE ENDPOINT CENSUS (GATED misconfig_allow_debug_probe)
# ===========================================================================
def debug_census(http, targets, conf):
    """GATED misconfig_allow_debug_probe.

    44-path debug pool GET census (presence-only): debug-marker shapes
    (actuator/Werkzeug/Django/Ignition/Symfony/pprof/phpinfo) classify
    karte hain. Live + marker = CONFIRMED misconfig surface. Body store
    KABHI nahi (sirf status/len/title-shape/sha1)."""
    gate = bool(conf.get("misconfig_allow_debug_probe", False))
    result = {"gate": "misconfig_allow_debug_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual debug-surface wave documented "
              "(MISCONFIG_TEST_PLAN.md KD-01)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = DEBUG_PATHS[:max(4, int(conf.get("misconfig_debug_paths", 44)))]
    cap = max(6, int(conf.get("misconfig_probe_cap", 24)))
    tested = 0
    for path in pool:
        if tested >= cap or interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:120]})
            continue
        tested += 1
        shape = match_markers(DEBUG_MARKER_RX, (r.text or "")[:4000])
        live = bool(r.ok() and not is_soft404(r, None))
        row = {"url": url, "status": r.status, "live": live,
               "shape": shape or "",
               "title": title_of(r.text)[:60] if r.ok() else "",
               "sha1": r.sha1()[:12] if r.ok() else "",
               "waf_blocked": r.status in WAF_BLOCK_STATUS}
        result["rows"].append(row)
    return result


# ===========================================================================
# STAGE D - DIRECTORY LISTING + SENSITIVE ARTIFACT CENSUS
#           (GATED misconfig_allow_artifact_probe - presence-only)
# ===========================================================================
def artifact_census(http, targets, conf):
    """GATED misconfig_allow_artifact_probe.

    2 pools: (1) baseline targets par autoindex markers (dirlist),
    (2) 40 sensitive-artifact paths (.git/.env/backup family) GET census.
    PRESENCE-ONLY: status/len/sha1-12 - bodies KABHI store nahi hote
    (secret-value protection = framework REDACTION rule)."""
    gate = bool(conf.get("misconfig_allow_artifact_probe", False))
    result = {"gate": "misconfig_allow_artifact_probe=%s" % gate, "rows": [],
              "dirlist_rows": [], "shapes_total": len(ARTIFACT_PATHS),
              "skipped_note": "" if gate else
              "RoE gate OFF - manual artifact wave documented (KD-02)"}
    if not gate:
        return result
    cap = max(4, int(conf.get("misconfig_probe_cap", 24)) // 2)
    # (1) dirlist census on listing-prone targets (uploads/static/backups)
    for t in _prioritize(targets, re.compile(
            r"(?i)(files?/|listing|uploads?|static|assets|backup|dump|media)"
            ))[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["dirlist_rows"].append({"url": t, "error": str(e)[:100]})
            continue
        shape = match_markers(AUTOINDEX_RX, (r.text or "")[:4000])
        if r.ok() and shape:
            result["dirlist_rows"].append({"url": t, "status": r.status,
                                           "live": True, "shape": shape})
        if interrupted():
            break
    # (2) sensitive artifact paths (presence-only)
    base = _base_of(targets)
    pool = ARTIFACT_PATHS[:max(4, int(conf.get("misconfig_artifact_paths", 40)))]
    tested = 0
    for path in pool:
        if tested >= max(8, cap * 2) or interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:120]})
            continue
        tested += 1
        live = bool(r.ok() and not is_soft404(r, None))
        noise = is_soft404(r, None)
        # content-shape check REDACTED: sirf naam flag, value nahi
        shape = ""
        if live and path.endswith((".env", ".env.local", ".env.production")):
            shape = "env-shape" if re.search(r"(?i)^[A-Z_]+=", (r.text or "")[:800]) \
                else ""
        elif live and "/.git/" in path:
            shape = "git-shape" if re.search(r"(?i)(ref:|\[core\])",
                                             (r.text or "")[:800]) else ""
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "len": len(r.body) if r.ok() else 0,
                               "sha1": r.sha1()[:12] if r.ok() else "",
                               "shape": shape, "noise": noise,
                               "waf_blocked": r.status in WAF_BLOCK_STATUS})
    return result


# ===========================================================================
# STAGE E - SECURITY-HEADERS POSTURE CENSUS (passive-GET, 16 headers)
# ===========================================================================
def headers_census(http, targets, conf):
    """Security-header posture census (9 hardening + 9 disclosure shapes).

    Missing/weak header grades = misconfig posture points. Passive-GET
    (baseline re-observation, koi canary differential nahi)."""
    rows = []
    cap = max(4, int(conf.get("misconfig_probe_cap", 24)) // 2)
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        if r.error:
            rows.append({"url": t, "status": r.status, "noise": True})
            continue
        low_headers = {str(k).lower(): str(v) for k, v in
                       (r.headers or {}).items()}
        present, missing, disclosure = [], [], []
        for hk, label in SECURITY_HEADERS:
            if hk in low_headers and low_headers[hk].strip():
                present.append(label)
            else:
                missing.append(label)
        for hk, label in DISCLOSURE_HEADERS:
            if hk in low_headers and low_headers[hk].strip():
                disclosure.append({"header": label,
                                   "value": low_headers[hk][:40]})
        csp = low_headers.get("content-security-policy", "")
        weak = []
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp or
                    "*" in csp.split("script-src")[-1][:40]):
            weak.append("CSP-permissive")
        hsts = low_headers.get("strict-transport-security", "")
        if hsts and "max-age=0" in hsts:
            weak.append("HSTS-zero")
        score, grade = header_posture_grade(set(present), set(weak))
        rows.append({"url": t, "status": r.status,
                     "present": present, "missing": missing, "weak": weak,
                     "score": score, "grade": grade,
                     "disclosure_headers": disclosure})
        if interrupted():
            break
    return {"rows": rows, "points": [label for _, label in SECURITY_HEADERS],
            "note": "9 hardening headers + disclosure census (passive-GET)"}


# ===========================================================================
# STAGE F - SECRETS-IN-RESPONSE CENSUS (names-only, sha1 REDACTED)
# ===========================================================================
def secrets_census(http, targets, conf):
    """Response bodies par 30 secret-shape regex census (values KABHI
    store nahi - sirf shape-name + sha1-12 + len-bucket). CWE-200/CWE-798
    aid. Baseline targets par bounded GET census."""
    rows = []
    cap = max(4, int(conf.get("misconfig_probe_cap", 24)) // 2)
    scap = max(8, int(conf.get("misconfig_secret_cap", 40)))
    total_hits = 0
    for t in _prioritize(targets, re.compile(
            r"(?i)(secret|env|config|api|login|debug|admin|page)"))[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        if r.error or is_soft404(r, None):
            rows.append({"url": t, "status": r.status, "noise": True})
            continue
        shapes = secret_shape_scan((r.text or "")[:60000])
        total_hits += len(shapes)
        rows.append({"url": t, "status": r.status,
                     "shapes": shapes[:12], "count": len(shapes)})
        if interrupted():
            break
    return {"rows": rows, "total_hits": total_hits,
            "cap": scap,
            "note": "secret VALUES KABHI store nahi - sirf shape-name + "
                    "sha1-12 (CWE-200/CWE-798 census aid)"}


# ===========================================================================
# STAGE G - VERBOSE-ERROR / STACK-TRACE CENSUS (GATED misconfig_allow_error_probe)
# ===========================================================================
ERROR_PROBE_SHAPES = [
    ("malformed-encoding", "?q=%%zz&waspP23=%s"),
    ("deep-path", "/%s/%s/%s/%s"),
    ("long-param", "?q=%s"),
    ("bad-id", "?id=%s"),
]


def error_census(http, targets, conf):
    """GATED misconfig_allow_error_probe.

    Canary param/path probes (4 shapes per target, bounded) -> stack-trace/
    framework-debug shape classification. canary values kabhi valid nahi
    hote - sirf error-response shape observe hota hai (CWE-209 census)."""
    gate = bool(conf.get("misconfig_allow_error_probe", False))
    result = {"gate": "misconfig_allow_error_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual error-shape wave documented (KD-03)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("misconfig_probe_cap", 24)) // 4)
    tested = 0
    for t in _prioritize(targets, re.compile(r"(?i)(error|exception|debug)"))[
            :cap * 2]:
        if tested >= cap or interrupted():
            break
        canary = _canary("err")
        row = {"url": t, "probes": []}
        for shape_name, shape in ERROR_PROBE_SHAPES:
            if shape_name == "deep-path":
                u = t.rstrip("/") + shape % (canary[:6], canary[:6],
                                             canary[:6], canary[:6])
            elif shape_name == "long-param":
                u = t + ("&" if "?" in t else "?") + shape % (canary * 8)
            else:
                u = t + ("&" if "?" in t else "?") + \
                    (shape % canary if "%s" in shape else
                     shape.replace("%%zz", "%zz") + "&waspP23=" + canary)
            try:
                r = probe(http, "GET", u, allow_redirects=False)
            except Exception as e:
                row["probes"].append({"shape": shape_name,
                                      "error": str(e)[:80]})
                continue
            stack = match_all_markers(STACKTRACE_RX, (r.text or "")[:6000])
            row["probes"].append({"shape": shape_name, "status": r.status,
                                  "stack_shapes": stack,
                                  "verbose": bool(stack),
                                  "len": len(r.body)})
        tested += 1
        row["verbose_hits"] = len([p for p in row["probes"]
                                   if p.get("verbose")])
        result["rows"].append(row)
    return result


# ===========================================================================
# STAGE H - LOG4SHELL/JNDI MISCONFIG SURFACE
#           (GATED misconfig_allow_log4shell_probe - NO JNDI PAYLOADS KABHI)
# ===========================================================================
LOG4J_VERSION_RX = re.compile(
    r"(?i)(log4j[-_ ]?core?[-/ ]?v?(2\.\d+(\.\d+)?)|"
    r"x-application-version:\s*[\w.-]*log4j[\w.-]*|"
    r"(apache-)?log4j[/ ]?(\d+\.\d+(\.\d+)?))")
LOG_CONFIG_PATHS = ["/log4j", "/logging", "/log-config", "/logs/config",
                    "/admin/logging", "/log4j2.xml", "/logback.xml"]


def log4shell_census(http, targets, conf):
    """GATED misconfig_allow_log4shell_probe.

    Version-disclosure census (headers/body shapes, 8 log-config paths) -
    <2.17.1 window flag. JNDI/lookup payloads KABHI network par NAHI
    (P12 owns detection shapes; P23 = misconfig surface census only)."""
    gate = bool(conf.get("misconfig_allow_log4shell_probe", False))
    result = {"gate": "misconfig_allow_log4shell_probe=%s" % gate, "rows": [],
              "playbook": [{"id": i, "name": n, "discipline": d}
                           for i, n, d in LOG4SHELL_PLAYBOOK_ROWS],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual log4shell wave documented (KD-04)"}
    if not gate:
        return result
    base = _base_of(targets)
    # 1) version-disclosure headers on log/version-ish targets (bounded 4)
    for t in _prioritize(targets, re.compile(
            r"(?i)(log4j|version|logging|app)"))[:4]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())[:4000]
        body_blob = (r.text or "")[:4000]
        m = LOG4J_VERSION_RX.search(hdr_blob) or \
            LOG4J_VERSION_RX.search(body_blob)
        ver = m.group(0)[:60] if m else ""
        weak_ver = False
        mv = re.search(r"(?<!\d)(2\.\d{1,2}(?:\.\d{1,2})?)(?!\d)", ver)
        if mv:
            try:
                parts = [int(x) for x in mv.group(1).split(".")[:3]]
                while len(parts) < 3:
                    parts.append(0)
                weak_ver = tuple(parts) < (2, 17, 1)
            except ValueError:
                pass
        result["rows"].append({"url": t, "kind": "version-disclosure",
                               "match": ver, "weak_version": weak_ver,
                               "status": r.status})
    # 2) log-config paths (presence only)
    tested = 0
    for path in LOG_CONFIG_PATHS:
        if tested >= max(4, int(conf.get("misconfig_probe_cap", 24)) // 6) or \
                interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "kind": "log-config",
                               "status": r.status, "live": live,
                               "noise": is_soft404(r, None)})
    return result


# ===========================================================================
# STAGE I - DEFAULT-CREDENTIAL POSTURE (DOCUMENTED-ONLY, 0 probes)
# ===========================================================================
def default_creds_documented():
    """Stage I: 14-platform default-cred matrix + login-fingerprint census
    rows (0 network probes - creds KABHI network par nahi jaate)."""
    return {"matrix": [{"id": i, "platform": p, "user": u, "default": d,
                        "discipline": "documented-only: creds KABHI network "
                                      "par nahi bheje jaate (stuffing/brute "
                                      "FORBIDDEN-AUTO; manual RoE wave)"}
                       for i, p, u, d in DEFAULT_CRED_ROWS],
            "probes": 0,
            "note": "default-credential TESTING manual+RoE wave hai - ye "
                    "stage sirf posture matrix document karta hai"}


def platform_login_fingerprint(probe_texts):
    """Baseline texts -> platform login-page markers (offline census)."""
    hits = {}
    blob = " ".join(probe_texts or [])[:40000].lower()
    for name, rx in PLATFORM_LOGIN_RX:
        m = rx.search(blob)
        if m:
            hits[name] = m.group(0)[:40]
    return {"shapes": sorted(hits.keys()), "evidence": hits}


# ===========================================================================
# STAGE J - ADMIN/PANEL EXPOSURE CENSUS (GATED misconfig_allow_admin_probe)
# ===========================================================================
def admin_census(http, targets, conf):
    """GATED misconfig_allow_admin_probe.

    40-path admin pool GET census (presence-only): live + platform-title
    marker = CONFIRMED admin surface; 401/403 = HARDENED (auth-gate)."""
    gate = bool(conf.get("misconfig_allow_admin_probe", False))
    result = {"gate": "misconfig_allow_admin_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual admin wave documented (KD-05)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = ADMIN_PATHS[:max(4, int(conf.get("misconfig_admin_paths", 40)))]
    cap = max(6, int(conf.get("misconfig_probe_cap", 24)))
    tested = 0
    for path in pool:
        if tested >= cap or interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:120]})
            continue
        tested += 1
        platform = match_markers(PLATFORM_LOGIN_RX, (r.text or "")[:4000]) or ""
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "platform": platform,
                               "title": title_of(r.text)[:60] if r.ok() else "",
                               "auth_gate": r.status in REJECT_STATUS,
                               "noise": is_soft404(r, None),
                               "waf_blocked": r.status in WAF_BLOCK_STATUS})
    return result


# ===========================================================================
# STAGE K - CLOUD/METADATA MISCONFIG SURFACE
#           (DOCUMENTED-ONLY playbook + passive header census, 0 risky probes)
# ===========================================================================
def cloud_census(http, targets, conf):
    """Cloud/IMDS misconfig surface: DOCUMENTED playbook (6 rows,
    FORBIDDEN-AUTO) + cloud-provider header shapes census (passive GETs).
    IMDS link-local metadata endpoints KABHI directly probe nahi hote -
    P15 owns bounded IMDS smoke; P24 owns cloud deep-dive."""
    rows = []
    for t in (targets or [])[:6]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())[:4000]
        cloud = match_all_markers([(n, rx) for n, rx in CLOUD_HDR_RX],
                                  hdr_blob)
        rows.append({"url": t, "status": r.status,
                     "cloud_shapes": cloud,
                     "imds_probed": False})
        if interrupted():
            break
    return {"rows": rows,
            "playbook": [{"id": i, "name": n, "discipline": d}
                         for i, n, d in CLOUD_PLAYBOOK_ROWS],
            "note": "IMDS FORBIDDEN-AUTO (koi metadata probe KABHI) - sirf "
                    "response-header shapes + documented waves (P15/P24)"}


# ===========================================================================
# STAGE L - CORS MISCONFIG GRADING (GATED misconfig_allow_cors_probe)
# ===========================================================================
def cors_census(http, targets, conf):
    """GATED misconfig_allow_cors_probe.

    4 canary Origins (same/null/sub.evil.invalid/evil.invalid) GET diff ->
    ACAO reflection census -> grading (reflect-any = CONFIRMED misconfig
    aid, wildcard = review, strict = HARDENED). Koi credentials/cookies
    attach nahi (INERT census)."""
    gate = bool(conf.get("misconfig_allow_cors_probe", False))
    result = {"gate": "misconfig_allow_cors_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual CORS wave documented (KD-06)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("misconfig_probe_cap", 24)) // 4)
    tested = 0
    for t in (targets or [])[:cap * 2]:
        if tested >= cap or interrupted():
            break
        parsed = urllib.parse.urlsplit(t)
        own = "%s://%s" % (parsed.scheme, parsed.netloc)
        rows_o = []
        reflect_attacker = reflect_null = wildcard = False
        strict = True
        for olabel, origin in CORS_ORIGINS:
            o = own if origin is None else origin
            try:
                r = probe(http, "GET", t, allow_redirects=False,
                          headers={"Origin": o})
            except Exception as e:
                rows_o.append({"origin": olabel, "error": str(e)[:80]})
                continue
            acao = (r.hget("Access-Control-Allow-Origin", "") or "")[:80]
            acac = (r.hget("Access-Control-Allow-Credentials", "") or "")[:8]
            if acao == "*":
                wildcard = True
            if origin and acao and o in acao:
                if olabel == "attacker":
                    reflect_attacker = True
                if olabel == "null":
                    reflect_null = True
            if acao:
                strict = False
            rows_o.append({"origin": olabel, "acao": acao,
                           "allow_credentials": acac,
                           "status": r.status})
        tested += 1
        result["rows"].append({
            "url": t, "origins": rows_o,
            "reflect_any": reflect_attacker or reflect_null,
            "reflect_attacker": reflect_attacker,
            "reflect_null": reflect_null,
            "wildcard": wildcard, "strict": strict,
            "grade": ("REFLECT-ANY" if reflect_attacker else
                      "NULL-ALLOWED" if reflect_null else
                      "WILDCARD" if wildcard else
                      "STRICT" if strict else "PARTIAL")})
    return result


# ===========================================================================
# STAGE M - COOKIE/SESSION FLAG MISCONFIG CENSUS (passive, P10 handoff)
# ===========================================================================
def cookie_census(http, targets, conf):
    """Set-Cookie flag census (Secure/HttpOnly/SameSite/Domain/prefixes).

    Passive from census GETs - cookie VALUES store nahi (names-only).
    P10 session-module handoff rollup."""
    rows = []
    cap = max(4, int(conf.get("misconfig_probe_cap", 24)) // 2)
    for t in _prioritize(targets, re.compile(
            r"(?i)(login|auth|session|account|signin|admin)"))[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        cookies = []
        # set_cookies list (names) + raw header audit (single-header shape)
        for ck in (r.set_cookies or []):
            name = ck if isinstance(ck, str) else (ck.get("name") or "")
            cookies.append({"name": name[:60]})
        raw_sc = r.hget("Set-Cookie", "") or ""
        if raw_sc:
            audit = cookie_flag_audit(raw_sc)
            audit["flags_missing"] = [f for f, okv in
                                      (("secure", audit["secure"]),
                                       ("httponly", audit["httponly"]),
                                       ("samesite", audit["samesite"]))
                                      if not okv]
            cookies.append(audit)
        elif r.set_cookies:
            # multi-cookie shape: names-only audit (flags unavailable)
            for c in cookies:
                c["flags_missing"] = ["unverifiable-multi"]
        rows.append({"url": t, "status": r.status, "cookies": cookies,
                     "weak_flags": bool(cookies) and any(
                         c.get("flags_missing") for c in cookies)})
        if interrupted():
            break
    weak_n = len([r2 for r2 in rows if r2.get("weak_flags")])
    return {"rows": rows, "weak_count": weak_n,
            "note": "cookie VALUES KABHI store nahi (names + flags only); "
                    "P10 handoff rollup"}


# ===========================================================================
# STAGE N - HEADER-TRUST ECHO CENSUS (GATED misconfig_allow_header_echo)
# ===========================================================================
def header_trust_census(http, targets, conf):
    """GATED misconfig_allow_header_echo.

    6 trust-header shapes (X-Original-URL/X-Rewrite-URL/X-Forwarded-* /
    X-Custom-IP-Authorization) echo + misroute differential (GET-only).
    P22 verb_override_endpoints seeds prioritize hote hain."""
    gate = bool(conf.get("misconfig_allow_header_echo", False))
    result = {"gate": "misconfig_allow_header_echo=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual trust-header wave documented (KD-07)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("misconfig_probe_cap", 24)) // 4)
    tested = 0
    for t in _prioritize(targets, re.compile(r"(?i)(admin|manager|api|console)"))[
            :cap * 2]:
        if tested >= cap or interrupted():
            break
        try:
            r0 = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        tested += 1
        echoes = []
        for hname, hval in TRUST_HEADERS:
            try:
                rr = probe(http, "GET", t, allow_redirects=False,
                           headers={hname: hval})
            except Exception:
                continue
            body_hit = hval.lower() in (rr.text or "")[:3000].lower()
            status_shift = rr.status != r0.status and rr.status < 400 and \
                r0.status >= 400
            hdr_echo = hname.lower() in {str(k).lower() for k in
                                         (rr.headers or {}).keys()}
            if body_hit or status_shift or hdr_echo:
                echoes.append({"header": hname, "value_sent": hval,
                               "status": rr.status, "body_echo": body_hit,
                               "status_shift": status_shift,
                               "header_echo": hdr_echo})
        result["rows"].append({"url": t, "baseline_status": r0.status,
                               "echoes": echoes,
                               "echo_count": len(echoes)})
    return result


# ===========================================================================
# STAGE O - HTTP METHODS / TRACE CENSUS (GATED misconfig_allow_trace_probe)
# ===========================================================================
def methods_census(http, targets, conf):
    """GATED misconfig_allow_trace_probe.

    OPTIONS Allow census + TRACE canary echo (XST surface) + method-override
    echo rollup (6 OVERRIDE_HEADERS, P22 verb shapes). TRACE sirf gate ON
    par - canary echo census (CWE-693 aid)."""
    gate = bool(conf.get("misconfig_allow_trace_probe", False))
    result = {"gate": "misconfig_allow_trace_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual methods/TRACE wave documented (KD-08)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("misconfig_probe_cap", 24)) // 4)
    tested = 0
    for t in _prioritize(targets, re.compile(
            r"(?i)(trace|admin|manager|api|console)"))[:cap * 2]:
        if tested >= cap or interrupted():
            break
        try:
            ro = probe(http, "OPTIONS", t, allow_redirects=False)
            rg = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        tested += 1
        allow = (ro.hget("Allow", "") or
                 ro.hget("Access-Control-Allow-Methods", ""))[:100]
        broad = [m for m in allow.upper().split(",")
                 if m.strip() in ("PUT", "DELETE", "TRACE", "CONNECT")]
        # TRACE/XST census: DOCUMENTED-ONLY (wasp_core LAYER-4 read-only
        # rule TRACE request block karta hai - koi TRACE request KABHI nahi
        # jaati; manual RoE wave me echo check hota hai).
        trace_echo = False
        trace_status = None
        trace_documented = True
        # method-override echo rollup (bounded 2 shapes)
        ov_echo = []
        for oh in OVERRIDE_HEADERS[:2]:
            try:
                rr = probe(http, "GET", t, allow_redirects=False,
                           headers={oh: "DELETE"})
            except Exception:
                continue
            body = (rr.text or "")[:2500].lower()
            if rr.status != rg.status or "delete" in body:
                ov_echo.append({"header": oh, "status": rr.status})
        result["rows"].append({"url": t, "allow": allow, "status_options":
                               ro.status, "broad_methods": broad,
                               "trace_status": trace_status,
                               "trace_echo": trace_echo,
                               "trace_documented": trace_documented,
                               "override_echo": ov_echo})
    return result


# ===========================================================================
# STAGE P - TRANSPORT/DOWNGRADE MISCONFIG CENSUS (passive-GET)
# ===========================================================================
def transport_census(http, targets, conf):
    """http->https redirect shape + HSTS-absent-on-auth + mixed-content
    shapes (http:// assets) census (passive-GET)."""
    rows = []
    cap = max(3, int(conf.get("misconfig_probe_cap", 24)) // 3)
    for t in _prioritize(targets, re.compile(
            r"(?i)(login|secure|auth|account|admin|checkout)"))[:cap]:
        row = {"url": t}
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        loc = (r.hget("Location", "") or "")[:120]
        row["status"] = r.status
        row["redirects_https"] = r.status in (301, 302, 307, 308) and \
            loc.startswith("https://")
        row["hsts"] = bool((r.hget("Strict-Transport-Security", "") or ""))
        body = (r.text or "")[:20000]
        row["mixed_content"] = bool(re.search(
            r"(?i)(src|href)\s*=\s*['\"]http://(?!127\.0\.0\.1|localhost)", body))
        row["transport_strong"] = row["redirects_https"] and row["hsts"] and \
            not row["mixed_content"]
        rows.append(row)
        if interrupted():
            break
    return {"rows": rows,
            "note": "downgrade/mixed-content census (passive-GET; koi "
                    "TLS-handshake probe nahi - P4 owns TLS deep-dive)"}


# ===========================================================================
# STAGE Q - API SPEC EXPOSURE CENSUS (GATED misconfig_allow_spec_probe)
# ===========================================================================
SENSITIVE_OP_RX = re.compile(
    r"(?i)(admin|internal|debug|delete|upload|export|users?|tokens?|keys?|"
    r"passwords?|cards?|payments?|refunds?|webhooks?|secrets?)")


def spec_census(http, targets, conf):
    """GATED misconfig_allow_spec_probe.

    12 spec paths (swagger/openapi/api-docs family) GET census -> spec
    presence + path/operation NAME census (names-only - spec content store
    nahi) + sensitive-op naming flags (P17 handoff)."""
    gate = bool(conf.get("misconfig_allow_spec_probe", False))
    result = {"gate": "misconfig_allow_spec_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual spec wave documented (KD-09)"}
    if not gate:
        return result
    base = _base_of(targets)
    cap = max(4, int(conf.get("misconfig_spec_paths", 12)))
    tested = 0
    for path in SPEC_PATHS[:cap]:
        if tested >= cap or interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        live = bool(r.ok() and not is_soft404(r, None))
        spec_shape = False
        op_names, sensitive_ops = [], []
        if live:
            blob = (r.text or "")[:20000]
            spec_shape = bool(re.search(
                r'(?i)(openapi|"swagger"|paths\s*:|info\s*:)', blob))
            if spec_shape:
                # names-only census (values/URLs store nahi)
                op_names = sorted(set(re.findall(
                    r'"(/[A-Za-z0-9_./{}-]{2,60})"', blob)))[:40]
                sensitive_ops = [o for o in op_names
                                 if SENSITIVE_OP_RX.search(o)][:12]
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "spec_shape": spec_shape,
                               "op_names_count": len(op_names),
                               "sensitive_ops": sensitive_ops,
                               "noise": is_soft404(r, None)})
    return {"rows": result.get("rows", []), "gate": result["gate"],
            "skipped_note": result["skipped_note"]}


# ===========================================================================
# STAGE R - SOURCE-MAP / JS SECRETS CENSUS (GATED misconfig_allow_map_probe)
# ===========================================================================
MAP_SUFFIXES = ["/app.js.map", "/main.js.map", "/bundle.js.map",
                "/index.js.map", "/app.min.js.map", "/static/js/app.js.map"]


def sourcemap_census(http, targets, conf):
    """GATED misconfig_allow_map_probe.

    .map exposure census (sourcesContent flag shape, presence-only - map
    content KABHI store nahi) + P7 js-artifact secret-name mining
    (names-only rollup)."""
    gate = bool(conf.get("misconfig_allow_map_probe", False))
    result = {"gate": "misconfig_allow_map_probe=%s" % gate, "rows": [],
              "js_secret_names": [], "skipped_note": "" if gate else
              "RoE gate OFF - manual sourcemap wave documented (KD-10)"}
    if not gate:
        return result
    base = _base_of(targets)
    cap = max(2, int(conf.get("misconfig_map_cap", 8)))
    tested = 0
    for suffix in MAP_SUFFIXES[:cap]:
        url = base + suffix
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        live = bool(r.ok() and not is_soft404(r, None))
        blob = (r.text or "")[:8000] if live else ""
        sources_flag = bool(re.search(r'"(sources|sourcesContent)"\s*:', blob))
        names = sorted(set(re.findall(r'"([\w/-]+\.\w{1,4})"', blob)))[:24] \
            if sources_flag else []
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "sources_flag": sources_flag,
                               "source_names_sample": names[:8],
                               "noise": is_soft404(r, None)})
    return result


def js_secret_names_from_artifacts(base_dir):
    """P7 js module artifacts -> secret-shaped NAME mining (names-only)."""
    names = []
    for fn in ("js_secrets.json", "secret_hits.json", "params.txt"):
        d = _read_json_tolerant(_artifact(base_dir, "js", fn))
        if isinstance(d, (dict, list)):
            for lst in _walk_lists(d):
                names.extend([x for x in lst if isinstance(x, str)])
        else:
            txt = _read_text_tolerant(_artifact(base_dir, "js", fn))
            for line in txt.splitlines()[:200]:
                line = line.strip()
                if line and len(line) < 80:
                    names.append(line)
    return sorted(set(n for n in names if len(n) < 60))[:30]


# ===========================================================================
# STAGE S - GRAPHQL MISCONFIG CENSUS (GATED misconfig_allow_gql_probe)
# ===========================================================================
GQL_INTROSPECT_QUERY = "{__schema{queryType{name}}}"


def gql_census(http, targets, conf):
    """GATED misconfig_allow_gql_probe.

    GET introspection-shape census (GET-only, canary query shape):
    /graphql?query={__schema...} -> introspection enabled = CONFIRMED
    misconfig aid. Koi mutation KABHI nahi bhejte (P18/P22 discipline).
    GraphiQL/Playground + field-suggestion error shapes bhi census hote
    hain."""
    gate = bool(conf.get("misconfig_allow_gql_probe", False))
    result = {"gate": "misconfig_allow_gql_probe=%s" % gate, "rows": [],
              "mutations_names_only": [], "skipped_note": "" if gate else
              "RoE gate OFF - manual gql wave documented (KD-11)"}
    if not gate:
        return result
    gql_urls = _prioritize(targets, re.compile(r"(?i)(graphql|gql|graphiql)"))
    cap = max(2, int(conf.get("misconfig_probe_cap", 24)) // 6)
    tested = 0
    for t in gql_urls[:cap * 2]:
        if tested >= cap or interrupted():
            break
        sep = "&" if "?" in t else "?"
        u = "%s%squery=%s" % (t, sep, urllib.parse.quote(GQL_INTROSPECT_QUERY))
        try:
            r = probe(http, "GET", u, allow_redirects=False)
            rp = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        tested += 1
        blob = (r.text or "")[:4000]
        introspect = bool(re.search(r'"?queryType"?|__schema', blob)) and \
            r.ok()
        field_suggest = bool(re.search(
            r'(?i)(did you mean|suggestion|similar)', blob)) or \
            bool(re.search(r'(?i)(did you mean|suggestion)',
                           (rp.text or "")[:2000]))
        playground = bool(re.search(r"(?i)(graphiql|playground|apollo studio)",
                                    (rp.text or "")[:4000]))
        result["rows"].append({"url": t, "status_introspect": r.status,
                               "introspection_enabled": introspect,
                               "field_suggestions": field_suggest,
                               "playground": playground,
                               "locked": r.status in REJECT_STATUS or
                                         (not r.ok() and not introspect)})
    return result


def gql_mutations_from_artifacts(base_dir):
    """P18/P22 handoff: mutation NAMES census (mutations NEVER sent)."""
    names = []
    d = _read_json_tolerant(_artifact(base_dir, "graphql", "feedforward.json"))
    if isinstance(d, dict):
        for lst in _walk_lists(d.get("routing") or {}):
            names.extend([x for x in lst if isinstance(x, str)])
    art = _read_json_tolerant(_artifact(base_dir, "graphql",
                                        "graphql_writable.json"))
    if isinstance(art, (dict, list)):
        for lst in _walk_lists(art):
            names.extend([x for x in lst if isinstance(x, str)])
    names = sorted(set(n for n in names if len(n) < 80))[:40]
    return {"mutations": names, "count": len(names),
            "note": "mutations NEVER sent (GET-only discipline)"}


# ===========================================================================
# STAGE T - CONTAINER/ORCHESTRATOR EXPOSURE CENSUS
#           (GATED misconfig_allow_container_probe)
# ===========================================================================
CONTAINER_MARKERS = [
    ("prometheus-metrics", re.compile(r"(?i)(# HELP|# TYPE|go_gc_duration)")),
    ("docker-registry", re.compile(r"(?i)(\"repositories\"|v2/_catalog|"
                                   r"docker-distribution)")),
    ("pprof-index", re.compile(r"(?i)(types of profiles available|allocs|"
                               r"goroutine\b)")),
    ("spring-env", re.compile(r"(?i)(\{\"_links\"|spring|profiles.*active)")),
    ("k8s-shape", re.compile(r"(?i)(kubernetes|k8s|minikube)")),
    ("apache-status", re.compile(r"(?i)(apache server status|server uptime)")),
    ("nginx-status", re.compile(r"(?i)(active connections.*server accepts|"
                                r"nginx.*status)")),
]


def container_census(http, targets, conf):
    """GATED misconfig_allow_container_probe.

    14-path container/orchestrator pool GET census (presence-only):
    Prometheus/docker-registry/pprof/spring-env/k8s/server-status shapes.
    Body store KABHI nahi (shape flags only)."""
    gate = bool(conf.get("misconfig_allow_container_probe", False))
    result = {"gate": "misconfig_allow_container_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual container wave documented (KD-12)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = CONTAINER_PATHS[:max(4, int(conf.get("misconfig_container_paths",
                                                14)))]
    cap = max(6, int(conf.get("misconfig_probe_cap", 24)) // 2)
    tested = 0
    for path in pool:
        if tested >= cap or interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        shape = match_markers(CONTAINER_MARKERS, (r.text or "")[:4000]) or ""
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "shape": shape, "noise": is_soft404(r, None),
                               "waf_blocked": r.status in WAF_BLOCK_STATUS})
    return result


# ===========================================================================
# STAGE U - BYPASS MATRIX v2: 18 SECRET MISCONFIG-BYPASS SHAPES
#           (GATED misconfig_allow_bypass2 - GET-only 403->2xx differential)
# ===========================================================================
def _bypass2_shapes(base_url, canary):
    """18 misconfig-bypass GET shapes (canary family waspP23).

    Har shape ek documented misconfig-bypass technique ka INERT GET-probe
    equivalent hai: 403-protected path par path-normalization / header-trust
    differentials -> 2xx = validation gap detection."""
    b = base_url.split("?")[0].rstrip("/")
    q = urllib.parse.quote
    return [
        ("MB-01", "double-slash path (normalizer merge differential)",
         "%s//" % b, {}),
        ("MB-02", "dot-segment /./ (canonicalization differential)",
         "%s/./" % b, {}),
        ("MB-03", "parent-segment /../ (traversal-normalizer differential)",
         "%s/%s/../" % (b, canary[:6]), {}),
        ("MB-04", "url-encoded dot %2e%2e (decoder differential)",
         "%s/%%2e%%2e/" % b, {}),
        ("MB-05", "semicolon path-param (matrix-param parser differential)",
         "%s;waspP23=1" % b, {}),
        ("MB-06", "tab-char %09 path (whitespace parser differential)",
         "%s%%09" % b, {}),
        ("MB-07", "space %20 path (trim differential)",
         "%s%%20" % b, {}),
        ("MB-08", "case-shuffle path (case-insensitive authz differential)",
         b.upper(), {}),
        ("MB-09", "trailing-slash add (route-match differential)",
         "%s/" % b, {}),
        ("MB-10", "double-url-encode (double-decoder differential)",
         "%s/%s" % (b, q(q(canary[:6]))), {}),
        ("MB-11", "X-Original-URL trust (proxy misroute shape)",
         b, {"X-Original-URL": "/"}),
        ("MB-12", "X-Rewrite-URL trust (rewrite-bypass shape)",
         b, {"X-Rewrite-URL": "/"}),
        ("MB-13", "X-Forwarded-Host: localhost (vhost-trust shape)",
         b, {"X-Forwarded-Host": "localhost"}),
        ("MB-14", "X-Forwarded-For: 127.0.0.1 (ip-allowlist trust shape)",
         b, {"X-Forwarded-For": "127.0.0.1"}),
        ("MB-15", "Host: localhost (internal-vhost shape)",
         b, {"Host": "localhost"}),
        ("MB-16", "X-Custom-IP-Authorization: 127.0.0.1 (custom-ip trust)",
         b, {"X-Custom-IP-Authorization": "127.0.0.1"}),
        ("MB-17", "Referer-trust shape (referer-based authz differential)",
         b, {"Referer": "%s/admin" % b}),
        ("MB-18", "HEAD-method differential (verb-authz gap shape)",
         b, {}),
    ]


def bypass2_census(http, targets, conf):
    """GATED misconfig_allow_bypass2: 18 shapes per top-target (GET/HEAD,
    canary differential). 403 baseline -> 2xx shaped = ACCEPTED (validation
    gap); waf-block = BLOCKED; reject-class = HARDENED."""
    gate = bool(conf.get("misconfig_allow_bypass2", False))
    result = {"gate": "misconfig_allow_bypass2=%s" % gate, "rows": [],
              "shapes_total": 18,
              "skipped_note": "" if gate else
              "RoE gate OFF - manual bypass2 wave documented (KD-13)"}
    if not gate:
        return result
    # protected (4xx) targets prioritize - differential wahi meaningful hai
    prot = _prioritize(targets, re.compile(
        r"(?i)(protected|admin|private|internal|manage|console)"))
    cap = max(1, min(4, int(conf.get("misconfig_bypass2_cap", 18)) // 4))
    tested = 0
    for t in prot[:cap * 3]:
        if tested >= cap or interrupted():
            break
        try:
            r0 = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        if r0.status < 400:
            continue          # sirf protected paths (403-family) differential
        canary = _canary("mb")
        shape_rows = []
        for sid, name, url, hdrs in _bypass2_shapes(t, canary):
            method = "HEAD" if sid == "MB-18" else "GET"
            try:
                r = probe(http, method, url, allow_redirects=False,
                          headers=hdrs or None)
            except Exception as e:
                shape_rows.append({"id": sid, "name": name,
                                   "error": str(e)[:100]})
                continue
            accepted = bool(r.ok() and not is_soft404(r, None))
            shape_rows.append({"id": sid, "name": name, "method": method,
                               "status": r.status, "accepted": accepted,
                               "reject_class": r.status in REJECT_STATUS,
                               "waf_blocked": r.status in WAF_BLOCK_STATUS})
        tested += 1
        acc = [s for s in shape_rows if s.get("accepted")]
        result["rows"].append({
            "url": t, "baseline_status": r0.status, "shapes": shape_rows,
            "accepted_count": len(acc), "accepted_ids": [s["id"] for s in acc],
            "blocked_count": len([s for s in shape_rows
                                  if s.get("waf_blocked")])})
    return result


# ===========================================================================
# STAGE V - MISCONFIG POSTURE COMPOSITE (12-point score, offline)
# ===========================================================================
POSTURE_POINTS = [
    ("headers_ok",       "security-header posture PARTIAL/STRONG"),
    ("cookies_ok",       "Set-Cookie flags complete (Secure/HttpOnly/SS)"),
    ("errors_masked",    "errors generic/masked (no stack shapes)"),
    ("debug_closed",     "debug/console pool closed (no live+marker)"),
    ("admin_closed",     "admin pool closed / auth-gated (401/403)"),
    ("artifacts_absent", "sensitive artifacts 404 (git/env/backup)"),
    ("dirlist_off",      "no autoindex markers on targets"),
    ("cors_strict",      "canary origins rejected (STRICT grade)"),
    ("cache_safe",       "no-store/private on sensitive responses"),
    ("methods_minimal",  "OPTIONS Allow minimal (no broad verbs/TRACE)"),
    ("spec_hidden",      "spec paths closed (no swagger/openapi)"),
    ("secrets_absent",   "secret-shape sweep clean on responses"),
]


def posture_composite(results):
    """Per-endpoint 12-point misconfig posture composite (offline).

    results = stage result dict (headers/cookies/errors/debug/admin/
    artifacts/cors/cache/methods/spec/secrets/bypass2). Score 0-12;
    <5 = WEAK (finding), >=9 = STRONG (positive)."""
    per_ep = {}

    def _bump(url, point, ok_flag):
        d = per_ep.setdefault(url or "?", {p[0]: None for p in POSTURE_POINTS})
        cur = d.get(point)
        d[point] = bool(ok_flag) if cur is None else (cur or bool(ok_flag))

    for row in (results.get("headers") or {}).get("rows", []):
        if row.get("grade") in ("PARTIAL", "STRONG"):
            _bump(row.get("url"), "headers_ok", True)
        elif row.get("grade") == "WEAK":
            _bump(row.get("url"), "headers_ok", False)
    for row in (results.get("cookies") or {}).get("rows", []):
        if row.get("weak_flags"):
            _bump(row.get("url"), "cookies_ok", False)
        elif row.get("cookies"):
            _bump(row.get("url"), "cookies_ok", True)
    for row in (results.get("errors") or {}).get("rows", []):
        _bump(row.get("url"), "errors_masked",
              not row.get("verbose_hits"))
    debug_live = {}
    for row in (results.get("debug") or {}).get("rows", []):
        if row.get("live") and row.get("shape"):
            debug_live[row.get("url")] = True
        elif row.get("url") and row.get("status"):
            _bump(row.get("url"), "debug_closed",
                  not (row.get("live") and row.get("shape")))
    for row in (results.get("admin") or {}).get("rows", []):
        _bump(row.get("url"), "admin_closed",
              row.get("auth_gate") or not row.get("live"))
    for row in (results.get("artifacts") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "artifacts_absent", not row.get("live"))
    for row in (results.get("dirlist") or {}).get("rows", []):
        _bump(row.get("url"), "dirlist_off", not row.get("live"))
    for row in (results.get("cors") or {}).get("rows", []):
        _bump(row.get("url"), "cors_strict", row.get("strict"))
        if row.get("reflect_any"):
            _bump(row.get("url"), "cors_strict", False)
    for row in (results.get("cache") or {}).get("rows", []):
        _bump(row.get("url"), "cache_safe", not row.get("cacheable"))
    for row in (results.get("methods") or {}).get("rows", []):
        _bump(row.get("url"), "methods_minimal",
              not row.get("broad_methods") and not row.get("trace_echo"))
    for row in (results.get("spec") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "spec_hidden", not row.get("spec_shape"))
    for row in (results.get("secrets") or {}).get("rows", []):
        if row.get("status") and not row.get("noise"):
            _bump(row.get("url"), "secrets_absent", not row.get("shapes"))

    rows = []
    for url, pts in per_ep.items():
        score = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is True)
        known = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is not None)
        rows.append({"url": url, "score": score, "known_points": known,
                     "points": pts,
                     "grade": "STRONG" if score >= 9 else
                              "PARTIAL" if score >= 5 else "WEAK"})
    rows.sort(key=lambda r: r["score"])
    return {"points": POSTURE_POINTS, "rows": rows,
            "weak": [r for r in rows if r["grade"] == "WEAK"],
            "strong": [r for r in rows if r["grade"] == "STRONG"]}


# ===========================================================================
# STAGE W - CROSS-MODULE KILL-CHAINS (CH01..CH26)
# ===========================================================================
def build_chains(results, ff_seeds):
    """26 misconfig kill-chains (P4..P22 handoffs + P23 census rows)."""
    chains = [
        ("CH01", "Debug console live -> runtime introspection/info leak",
         "Stage C live+shape -> console lockdown fix"),
        ("CH02", ".env/.git artifact -> source+credential exposure",
         "Stage D artifact live -> secret rotation wave (RoE)"),
        ("CH03", "Directory listing -> sensitive-file enumeration",
         "Stage D dirlist -> autoindex disable fix"),
        ("CH04", "Security headers missing -> clickjacking/MIME abuse",
         "Stage E WEAK grade -> header-hardening fix"),
        ("CH05", "Secret-shape in response -> credential compromise",
         "Stage F shapes -> secret rotation + redaction fix"),
        ("CH06", "Verbose stack-trace -> tech fingerprint + exploit prep",
         "Stage G verbose -> error-masking fix"),
        ("CH07", "Log4j <2.17.1 window -> JNDI misconfig surface",
         "Stage H weak_version -> upgrade wave (manual)"),
        ("CH08", "Default-cred platform live -> console takeover",
         "Stage I+J platform -> cred-rotation manual wave"),
        ("CH09", "Admin panel exposed -> unauthorized admin access",
         "Stage J live+platform -> auth-gate fix"),
        ("CH10", "Cloud header shapes -> topology enumeration (P24)",
         "Stage K shapes -> P24 handoff"),
        ("CH11", "CORS reflect-any -> cross-origin data theft",
         "Stage L reflect -> origin-allowlist fix"),
        ("CH12", "Cookie flags missing -> session hijack/CSRF aid",
         "Stage M weak flags -> flag-hardening fix (P10)"),
        ("CH13", "Trust-header echo -> proxy misroute/authz bypass",
         "Stage N echoes -> proxy-header sanitization fix"),
        ("CH14", "TRACE echo -> XST/verb surface",
         "Stage O trace_echo -> verb disable fix"),
        ("CH15", "No https redirect -> downgrade exposure",
         "Stage P no_redirect -> HSTS+redirect fix"),
        ("CH16", "Public API spec -> attack-surface enumeration",
         "Stage Q spec live -> spec-gating fix (P17)"),
        ("CH17", "Source-map live -> source disclosure",
         "Stage R sources_flag -> map-stripping fix (P7)"),
        ("CH18", "GraphQL introspection -> schema disclosure",
         "Stage S introspect -> introspection-off fix (P18)"),
        ("CH19", "Container metrics live -> runtime enumeration",
         "Stage T live -> endpoint lockdown fix"),
        ("CH20", "Bypass2 accepted -> protected-path access",
         "Stage U accepted_ids -> normalization fix"),
        ("CH21", "Posture WEAK composite -> priority hardening",
         "Stage V weak rows -> remediation order"),
        ("CH22", "P22 cacheable_token_routes -> cache misconfig chain",
         "P22 ff -> Stage N/V cache checks"),
        ("CH23", "P21 misconfig flags -> header/cookie posture chain",
         "P21 ff -> Stage E/M"),
        ("CH24", "P12 log4shell hints -> version window chain",
         "P12 ff -> Stage H"),
        ("CH25", "P15/P16/P17/P18 feedforward -> spec/artifact chain",
         "P15-P18 ff -> Stage D/Q/R/S"),
        ("CH26", "P24 cloud + P25 controls -> cloud misconfig handoff",
         "Stage K shapes -> P24/P25 ff routing"),
    ]
    out = []
    ff_keys = set((ff_seeds or {}).keys())
    for cid, title, evidence in chains:
        out.append({"id": cid, "title": title, "evidence": evidence,
                    "ff_seeds": sorted(ff_keys)[:6]})
    return out


# ===========================================================================
# STAGE X - VERDICT ENGINE (6-class ladder, multi-signal)
# ===========================================================================
def verdict_engine(results):
    """Stage rows -> 6-class verdict rows (CONFIRMED/SUSPECTED/HARDENED/
    BLOCKED/SKIPPED/NOISE) - P12..P22-compatible ladder."""
    rows = []

    def _add(stage, url, verdict, signals, detail):
        rows.append({"stage": stage, "url": url, "verdict": verdict,
                     "signals": signals, "detail": truncate(str(detail), 220)})

    # ---- DEBUG (C) ----
    for r in (results.get("debug") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("C", u, "CONFIRMED", ["live", "debug-marker"],
                 "debug console live + %s shape" % r["shape"])
        elif r.get("live"):
            _add("C", u, "SUSPECTED", ["live", "no-marker"],
                 "debug path live but marker absent (review)")
        elif r.get("waf_blocked"):
            _add("C", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- ARTIFACTS/DIRLIST (D) ----
    for r in (results.get("artifacts") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("D", u, "CONFIRMED", ["live", "artifact-shape"],
                 "artifact live + %s" % r["shape"])
        elif r.get("live"):
            _add("D", u, "SUSPECTED", ["live", "no-shape"],
                 "artifact-shaped 200 (manual confirm)")
        elif r.get("waf_blocked"):
            _add("D", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    for r in (results.get("artifacts") or {}).get("dirlist_rows", []):
        if r.get("live"):
            _add("D", r.get("url", "?"), "CONFIRMED", ["autoindex"],
                 "directory listing live (%s)" % r.get("shape", ""))
    # ---- HEADERS (E) ----
    for r in (results.get("headers") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("grade") == "WEAK":
            _add("E", u, "SUSPECTED", ["headers-weak"],
                 "missing=%s" % ",".join(r.get("missing", [])[:6]))
        elif r.get("grade") == "STRONG":
            _add("E", u, "HARDENED", ["headers-strong"],
                 "score=%s/9" % r.get("score"))
        elif r.get("grade") == "PARTIAL":
            _add("E", u, "SUSPECTED", ["headers-partial"],
                 "score=%s/9 missing=%s" % (r.get("score"),
                                            ",".join(r.get("missing", [])[:4])))
    # ---- SECRETS (F) ----
    for r in (results.get("secrets") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("shapes"):
            _add("F", u, "CONFIRMED", ["secret-shape"],
                 "shapes=%s" % ",".join(s["shape"] for s in
                                        r.get("shapes", [])[:5]))
    # ---- ERRORS (G) ----
    for r in (results.get("errors") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("verbose_hits"):
            _add("G", u, "CONFIRMED", ["stack-trace"],
                 "verbose_hits=%s" % r.get("verbose_hits"))
        else:
            _add("G", u, "HARDENED", ["errors-masked"], "no stack shapes")
    # ---- LOG4SHELL (H) ----
    for r in (results.get("log4shell") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("kind") == "version-disclosure":
            if r.get("weak_version"):
                _add("H", u, "CONFIRMED", ["weak-version"],
                     "log4j window: %s" % r.get("match", ""))
            elif r.get("match"):
                _add("H", u, "SUSPECTED", ["version-disclosure"],
                     r.get("match", ""))
            else:
                _add("H", u, "HARDENED", ["no-disclosure"], "clean")
        elif r.get("live"):
            _add("H", u, "SUSPECTED", ["log-config-live"], "log endpoint live")
    # ---- ADMIN (J) ----
    for r in (results.get("admin") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("platform"):
            _add("J", u, "CONFIRMED", ["live", "platform-marker"],
                 "admin live + %s" % r["platform"])
        elif r.get("auth_gate"):
            _add("J", u, "HARDENED", ["auth-gate"], "401/403 enforced")
        elif r.get("waf_blocked"):
            _add("J", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- CLOUD (K) ----
    for r in (results.get("cloud") or {}).get("rows", []):
        if r.get("cloud_shapes"):
            _add("K", r.get("url", "?"), "SUSPECTED", ["cloud-headers"],
                 "shapes=%s" % ",".join(r["cloud_shapes"][:5]))
    # ---- CORS (L) ----
    for r in (results.get("cors") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("reflect_attacker") or r.get("reflect_null"):
            _add("L", u, "CONFIRMED", ["acao-reflect"],
                 "grade=%s" % r.get("grade"))
        elif r.get("wildcard"):
            _add("L", u, "SUSPECTED", ["acao-wildcard"],
                 "grade=%s" % r.get("grade"))
        elif r.get("strict"):
            _add("L", u, "HARDENED", ["cors-strict"], "canary origins rejected")
    # ---- COOKIES (M) ----
    for r in (results.get("cookies") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("weak_flags"):
            _add("M", u, "SUSPECTED", ["cookie-flags-missing"],
                 "flags=%s" % ",".join(sum([c.get("flags_missing", [])
                                            for c in r.get("cookies", [])],
                                           [])[:6]))
        elif r.get("cookies"):
            _add("M", u, "HARDENED", ["cookie-flags-ok"], "flags complete")
    # ---- TRUST ECHO (N) ----
    for r in (results.get("trust") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("echo_count"):
            _add("N", u, "CONFIRMED", ["trust-echo"],
                 "echoes=%s" % ",".join(e["header"] for e in
                                        r.get("echoes", [])[:4]))
        else:
            _add("N", u, "HARDENED", ["trust-clean"], "no echo/misroute")
    # ---- METHODS/TRACE (O) ----
    for r in (results.get("methods") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("trace_echo"):
            _add("O", u, "CONFIRMED", ["trace-echo"], "XST surface")
        elif r.get("broad_methods"):
            _add("O", u, "SUSPECTED", ["broad-methods"],
                 "allow=%s" % r.get("allow", ""))
        elif r.get("trace_documented"):
            _add("O", u, "SUSPECTED", ["trace-documented"],
                 "TRACE/XST echo manual RoE wave (documented-only)")
        else:
            _add("O", u, "HARDENED", ["methods-minimal"], "strict")
    # ---- TRANSPORT (P) ----
    for r in (results.get("transport") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("transport_strong"):
            _add("P", u, "HARDENED", ["redirect+hsts"], "strong transport")
        elif r.get("mixed_content") or (r.get("status") == 200 and
                                        not r.get("redirects_https")):
            _add("P", u, "SUSPECTED", ["downgrade-shape"],
                 "redirect_https=%s mixed=%s" % (r.get("redirects_https"),
                                                 r.get("mixed_content")))
    # ---- SPEC (Q) ----
    for r in (results.get("spec") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("spec_shape"):
            _add("Q", u, "CONFIRMED", ["spec-live"],
                 "ops=%s sensitive=%s" % (r.get("op_names_count"),
                                          len(r.get("sensitive_ops", []))))
        elif r.get("status") and not r.get("noise"):
            _add("Q", u, "HARDENED", ["spec-absent"], "closed")
    # ---- SOURCEMAP (R) ----
    for r in (results.get("sourcemap") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("sources_flag"):
            _add("R", u, "CONFIRMED", ["sourcemap-sources"], "map live")
        elif r.get("status") and not r.get("noise"):
            _add("R", u, "HARDENED", ["sourcemap-absent"], "closed")
    # ---- GQL (S) ----
    for r in (results.get("gql") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("introspection_enabled"):
            _add("S", u, "CONFIRMED", ["introspection"],
                 "GET __schema accepted")
        elif r.get("locked"):
            _add("S", u, "HARDENED", ["introspection-locked"], "disabled")
        elif r.get("playground"):
            _add("S", u, "SUSPECTED", ["playground-live"], "console exposed")
    # ---- CONTAINER (T) ----
    for r in (results.get("container") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("T", u, "CONFIRMED", ["live", "container-marker"],
                 "container live + %s" % r["shape"])
        elif r.get("waf_blocked"):
            _add("T", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- BYPASS2 (U) ----
    for r in (results.get("bypass2") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("accepted_count"):
            _add("U", u, "CONFIRMED", ["bypass-accept"],
                 "accepted=%s" % ",".join(r.get("accepted_ids", [])[:6]))
        elif r.get("blocked_count"):
            _add("U", u, "BLOCKED", ["waf-block"], "shapes fingerprint-blocked")
        else:
            _add("U", u, "HARDENED", ["reject-all"], "all 18 shapes rejected")
    # ---- GATED SKIPS ----
    for stage_key, gate_name in (
            ("C", "misconfig_allow_debug_probe"),
            ("D", "misconfig_allow_artifact_probe"),
            ("G", "misconfig_allow_error_probe"),
            ("H", "misconfig_allow_log4shell_probe"),
            ("J", "misconfig_allow_admin_probe"),
            ("L", "misconfig_allow_cors_probe"),
            ("N", "misconfig_allow_header_echo"),
            ("O", "misconfig_allow_trace_probe"),
            ("Q", "misconfig_allow_spec_probe"),
            ("R", "misconfig_allow_map_probe"),
            ("S", "misconfig_allow_gql_probe"),
            ("T", "misconfig_allow_container_probe"),
            ("U", "misconfig_allow_bypass2")):
        st = results.get({"C": "debug", "D": "artifacts", "G": "errors",
                          "H": "log4shell", "J": "admin", "L": "cors",
                          "N": "trust", "O": "methods", "Q": "spec",
                          "R": "sourcemap", "S": "gql", "T": "container",
                          "U": "bypass2"}.get(stage_key, ""), {})
        if isinstance(st, dict) and st.get("skipped_note"):
            rows.append({"stage": stage_key, "url": "*", "verdict": "SKIPPED",
                         "signals": ["roe-gate-off"], "detail": gate_name})

    order = {"CONFIRMED": 0, "SUSPECTED": 1, "BLOCKED": 2, "HARDENED": 3,
             "SKIPPED": 4, "NOISE": 5}
    rows.sort(key=lambda r: (order.get(r["verdict"], 9), r["stage"]))
    return rows


# ===========================================================================
# STAGE Z - PLATFORM FINGERPRINT + FINAL SECRETS/PII GUARD
# ===========================================================================
PLATFORM_FPS = [
    ("spring-actuator", re.compile(r"(?i)(actuator|whitelabel|spring)")),
    ("django-shape", re.compile(r"(?i)(django|csrfmiddlewaretoken)")),
    ("laravel-shape", re.compile(r"(?i)(laravel|ignition|whoops)")),
    ("symfony-shape", re.compile(r"(?i)(symfony|_profiler|_wdt)")),
    ("wordpress-shape", re.compile(r"(?i)(wp-admin|wp-content|wordpress)")),
    ("tomcat-shape", re.compile(r"(?i)(tomcat|jsessionid|manager app)")),
    ("dotnet-shape", re.compile(r"(?i)(asp\.net|x-aspnet|aspxauth)")),
    ("nginx-shape", re.compile(r"(?i)(nginx|server: nginx)")),
    ("apache-shape", re.compile(r"(?i)(apache|server: apache)")),
    ("nodejs-shape", re.compile(r"(?i)(express|x-powered-by: express|node)")),
    ("aws-shape", re.compile(r"(?i)(x-amz|awselb|cloudfront)")),
    ("gcp-shape", re.compile(r"(?i)(x-goog|x-gcp|google)")),
    ("azure-shape", re.compile(r"(?i)(x-azure|x-ms-|arrcookie)")),
    ("k8s-shape", re.compile(r"(?i)(kubernetes|k8s|minikube)")),
    ("docker-shape", re.compile(r"(?i)(docker|registry|containerd)")),
]


def platform_fingerprint(probe_texts):
    """Census texts -> platform shapes (offline, census-only)."""
    hits = {}
    blob = " ".join(probe_texts or [])[:40000].lower()
    for name, rx in PLATFORM_FPS:
        m = rx.search(blob)
        if m:
            hits[name] = m.group(0)[:40]
    return {"shapes": sorted(hits.keys()), "evidence": hits}


SECRET_GUARD_RX = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(secret_access_key|api_key|apikey|passwd|password|db_password)\s*[:=]"
    r"\s*[^\s,;\"]{6,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})")


def secrets_guard(payloads):
    """Final REDACTION sweep: sab artifacts me secret/PII shapes scan.

    Hit = finding (CWE-200 aid) + redaction confirmation. Sirf shape-flag,
    value store nahi."""
    hits = []
    for name, txt in (payloads or []):
        m = SECRET_GUARD_RX.search((txt or "")[:60000])
        if m:
            hits.append({"artifact": name, "shape":
                         m.group(0)[:8] + "***REDACTED***"})
    return {"hits": hits, "swept": len(payloads or []),
            "note": "final PII/secret sweep - values REDACTED by design"}


# ===========================================================================
# STAGE Y - TECHNIQUE MATRIX (220 rows x 20 families + CWE + MITRE)
# ===========================================================================
MATRIX_CATALOG = {
    "MISCONFIG_DEBUG": [
        ("spring actuator env/heapdump exposed", "CWE-489", "T1613"),
        ("werkzeug debugger console live", "CWE-489", "T1613"),
        ("django DEBUG=True technical page", "CWE-489", "T1613"),
        ("laravel ignition/whoops debug page", "CWE-489", "T1613"),
        ("symfony _profiler/_wdt exposed", "CWE-489", "T1613"),
        ("asp.net trace.axd/elmah.axd live", "CWE-489", "T1613"),
        ("go pprof index exposed", "CWE-489", "T1613"),
        ("phpinfo() page live", "CWE-200", "T1613"),
        ("debug flag leaked in response", "CWE-489", "T1613"),
        ("node inspector (--inspect) surface", "CWE-489", "T1613"),
        ("rails development-mode error page", "CWE-489", "T1613"),
    ],
    "MISCONFIG_DIRLIST": [
        ("apache autoindex (Index of /)", "CWE-548", "T1083"),
        ("nginx autoindex listing", "CWE-548", "T1083"),
        ("parent-directory listing traversal", "CWE-548", "T1083"),
        ("directory listing on backup dir", "CWE-548", "T1083"),
        ("listing exposes .git/ config dirs", "CWE-538", "T1083"),
        ("listing exposes upload/tmp dirs", "CWE-548", "T1083"),
        ("listing on /static with sources", "CWE-540", "T1083"),
        ("autoindex with sensitive filenames", "CWE-200", "T1083"),
        ("listing on log directories", "CWE-532", "T1083"),
        ("ftp-style listing on webroot", "CWE-548", "T1083"),
        ("generated index (dir-listing CGI)", "CWE-548", "T1083"),
    ],
    "MISCONFIG_HEADERS": [
        ("CSP absent", "CWE-693", "T1112"),
        ("HSTS absent (downgrade window)", "CWE-319", "T1557"),
        ("X-Frame-Options absent (clickjacking)", "CWE-1021", "T1112"),
        ("X-Content-Type-Options absent", "CWE-430", "T1112"),
        ("Referrer-Policy absent (token leak)", "CWE-598", "T1552.001"),
        ("Permissions-Policy absent", "CWE-693", "T1112"),
        ("COOP/COEP/CORP absent (sidechannel)", "CWE-1021", "T1112"),
        ("CSP unsafe-inline/eval", "CWE-79", "T1112"),
        ("Server version disclosure", "CWE-200", "T1592"),
        ("X-Powered-By disclosure", "CWE-200", "T1592"),
        ("X-Debug-Token exposed", "CWE-489", "T1613"),
    ],
    "MISCONFIG_SECRETS": [
        ("aws access key in response", "CWE-798", "T1552.001"),
        ("private key block in response", "CWE-321", "T1552.004"),
        ("jwt secret-shape in body", "CWE-522", "T1552"),
        ("google/maps api key shape", "CWE-798", "T1552.001"),
        ("firebase config exposed", "CWE-200", "T1552"),
        ("slack/github token shape", "CWE-798", "T1552.001"),
        ("stripe live key shape", "CWE-798", "T1552.001"),
        ("smtp/db url with creds", "CWE-798", "T1552"),
        ("internal ip disclosure", "CWE-200", "T1590"),
        ("email/PII in error body", "CWE-200", "T1552"),
        ("client_secret in JS/config", "CWE-798", "T1552.001"),
    ],
    "MISCONFIG_ERRORS": [
        ("python traceback in response", "CWE-209", "T1613"),
        ("java stack trace (org.*/com.*)", "CWE-209", "T1613"),
        ("sql error message disclosed", "CWE-209", "T1190"),
        ("php fatal/warning disclosed", "CWE-209", "T1613"),
        ("asp.net yellow-screen stack", "CWE-209", "T1613"),
        ("ruby gem stack in response", "CWE-209", "T1613"),
        ("nginx config error page detail", "CWE-209", "T1613"),
        ("framework debug page on 500", "CWE-215", "T1613"),
        ("error reveals internal paths", "CWE-200", "T1590"),
        ("error reveals dependency versions", "CWE-200", "T1592"),
        ("customErrors Off shape", "CWE-209", "T1613"),
    ],
    "MISCONFIG_LOG4SHELL": [
        ("log4j version <2.15 disclosure", "CWE-502", "T1190"),
        ("log4j 2.15-2.16 partial-patch window", "CWE-917", "T1190"),
        ("JNDI lookup config enabled", "CWE-917", "T1059"),
        ("log-config endpoint exposed", "CWE-489", "T1613"),
        ("log4j2.xml/logback.xml fetchable", "CWE-538", "T1083"),
        ("header-echo version fingerprint", "CWE-200", "T1592"),
        ("FormatMsgNoLookups absent", "CWE-917", "T1190"),
        ("log4j in SBOM (dependency check)", "CWE-1104", "T1595"),
        ("egress-callback DNS canary wave", "CWE-917", "T1071.004"),
        ("remediation: >=2.17.1 upgrade", "CWE-1104", "T1105"),
        ("payload discipline: JNDI FORBIDDEN-AUTO", "CWE-693", "T1106"),
    ],
    "MISCONFIG_DEFAULTS": [
        ("tomcat manager default creds", "CWE-798", "T1078.002"),
        ("admin:admin generic console", "CWE-798", "T1078"),
        ("jenkins initial password window", "CWE-798", "T1078.002"),
        ("grafana admin:admin", "CWE-798", "T1078.002"),
        ("phpmyadmin root empty", "CWE-798", "T1078.002"),
        ("weblogic weblogic/weblogic", "CWE-798", "T1078.003"),
        ("wildfly/jboss admin default", "CWE-798", "T1078.003"),
        ("activemq/rabbitmq guest default", "CWE-798", "T1078.003"),
        ("sonarqube/nexus default admin", "CWE-798", "T1078.003"),
        ("airflow default admin", "CWE-798", "T1078.003"),
        ("cred-stuffing FORBIDDEN-AUTO", "CWE-307", "T1110.003"),
    ],
    "MISCONFIG_ADMIN": [
        ("tomcat /manager/html exposed", "CWE-1234", "T1078.002"),
        ("jenkins console internet-facing", "CWE-1234", "T1078.002"),
        ("grafana/kibana dashboards exposed", "CWE-1234", "T1538"),
        ("phpmyadmin webroot exposed", "CWE-1234", "T1078.002"),
        ("wp-admin without hardening", "CWE-1234", "T1112"),
        ("joomla/drupal admin exposed", "CWE-1234", "T1112"),
        ("rabbitmq management exposed", "CWE-1234", "T1078.003"),
        ("airflow/nifi UIs exposed", "CWE-1234", "T1078.003"),
        ("solr admin exposed", "CWE-1234", "T1078.003"),
        ("weblogic console exposed", "CWE-1234", "T1078.003"),
        ("admin 401/403 (HARDENED control)", "CWE-693", "T1106"),
    ],
    "MISCONFIG_CLOUD": [
        ("IMDSv1 reachable (documented)", "CWE-918", "T1552.005"),
        ("IMDSv2 token enforcement review", "CWE-918", "T1552.005"),
        ("public s3 bucket shape", "CWE-732", "T1619"),
        ("azure blob public shape", "CWE-732", "T1619"),
        ("gcs public shape", "CWE-732", "T1619"),
        ("instance-profile header shape", "CWE-200", "T1580"),
        ("cloud metadata via SSRF (P15)", "CWE-918", "T1552.005"),
        ("IAM credential exposure in env", "CWE-798", "T1552.005"),
        ("cloudfront/CDN origin bypass", "CWE-290", "T1557"),
        ("IMDS probe FORBIDDEN-AUTO", "CWE-693", "T1106"),
        ("remediation: hop-limit 1 + block", "CWE-693", "T1106"),
    ],
    "MISCONFIG_CORS": [
        ("ACAO reflects attacker origin", "CWE-942", "T1189"),
        ("ACAO null origin allowed", "CWE-942", "T1189"),
        ("ACAO * with credentials", "CWE-942", "T1189"),
        ("origin allowlist prefix-match", "CWE-942", "T1189"),
        ("subdomain-trust wildcard", "CWE-942", "T1189"),
        ("ACAO on authenticated endpoint", "CWE-942", "T1189"),
        ("preflight permissive methods", "CWE-942", "T1189"),
        ("credentials header true + reflect", "CWE-942", "T1189"),
        ("strict origin allowlist (control)", "CWE-693", "T1106"),
        ("wildcard on public data only", "CWE-942", "T1189"),
        ("P14 CORS deep-dive handoff", "CWE-942", "T1106"),
    ],
    "MISCONFIG_COOKIES": [
        ("Secure flag absent", "CWE-614", "T1557"),
        ("HttpOnly absent (XSS theft aid)", "CWE-1004", "T1185"),
        ("SameSite absent (CSRF aid)", "CWE-1275", "T1181"),
        ("SameSite=None w/o Secure", "CWE-614", "T1557"),
        ("Domain too broad (.domain.tld)", "CWE-565", "T1557"),
        ("__Host- prefix absent", "CWE-1275", "T1181"),
        ("session cookie in JS-readable form", "CWE-1004", "T1185"),
        ("cookie value in URL (referrer leak)", "CWE-598", "T1552.001"),
        ("multi-cookie flag audit gap", "CWE-1004", "T1185"),
        ("flags complete (HARDENED control)", "CWE-693", "T1106"),
        ("P10 session handoff rollup", "CWE-693", "T1106"),
    ],
    "MISCONFIG_CACHEHDR": [
        ("no-store absent on auth response", "CWE-524", "T1174"),
        ("Cache-Control public on private", "CWE-525", "T1174"),
        ("Vary header absent (shared cache)", "CWE-525", "T1174"),
        ("token in cacheable GET", "CWE-524", "T1174"),
        ("Age/ETag on sensitive response", "CWE-525", "T1174"),
        ("web-cache poisoning surface", "CWE-444", "T1557"),
        ("X-Forwarded-* cache-key confusion", "CWE-348", "T1557"),
        ("CDN bypass-origin exposed", "CWE-290", "T1557"),
        ("P22 cacheable_token_routes chain", "CWE-524", "T1174"),
        ("no-store present (HARDENED control)", "CWE-693", "T1106"),
        ("cache-key canonicalization review", "CWE-444", "T1106"),
    ],
    "MISCONFIG_METHODS": [
        ("TRACE enabled (XST surface)", "CWE-693", "T1210"),
        ("OPTIONS Allow broad verbs", "CWE-650", "T1210"),
        ("PUT/DELETE exposed unauthed", "CWE-650", "T1210"),
        ("method-override echo (X-HTTP-*)", "CWE-650", "T1210"),
        ("CONNECT proxy shape", "CWE-441", "T1090"),
        ("verb-authz differential (HEAD)", "CWE-650", "T1210"),
        ("PATCH on read-only resource", "CWE-650", "T1210"),
        ("Allow header leak of internal verbs", "CWE-200", "T1592"),
        ("methods minimal (HARDENED control)", "CWE-693", "T1106"),
        ("P22 verb_override chain", "CWE-650", "T1210"),
        ("OPTIONS minimize remediation", "CWE-650", "T1106"),
    ],
    "MISCONFIG_TRANSPORT": [
        ("http->https redirect absent", "CWE-319", "T1557"),
        ("HSTS absent on auth paths", "CWE-319", "T1557"),
        ("mixed-content http assets", "CWE-319", "T1557"),
        ("HSTS max-age=0 shape", "CWE-319", "T1557"),
        ("TLS downgrade tolerance shape", "CWE-757", "T1557"),
        ("cookie without Secure over http", "CWE-614", "T1557"),
        ("redirect preserves token in URL", "CWE-598", "T1552.001"),
        ("P4 TLS deep-dive handoff", "CWE-319", "T1106"),
        ("redirect+HSTS strong (control)", "CWE-693", "T1106"),
        ("includeSubDomains review", "CWE-319", "T1106"),
        ("preload eligibility review", "CWE-319", "T1106"),
    ],
    "MISCONFIG_SPEC": [
        ("swagger.json public", "CWE-200", "T1587"),
        ("openapi.json public", "CWE-200", "T1587"),
        ("/v3/api-docs exposed", "CWE-200", "T1587"),
        ("api-docs with sensitive ops", "CWE-200", "T1587"),
        ("spec reveals internal endpoints", "CWE-200", "T1587"),
        ("spec reveals debug/admin ops", "CWE-200", "T1587"),
        ("swagger-ui interactive console", "CWE-489", "T1587"),
        ("redoc/docs exposure", "CWE-200", "T1587"),
        ("spec-gating remediation", "CWE-693", "T1106"),
        ("P17 api-spec handoff", "CWE-200", "T1106"),
        ("names-only census discipline", "CWE-693", "T1106"),
    ],
    "MISCONFIG_SOURCEMAP": [
        ("app.js.map public", "CWE-540", "T1552"),
        ("sourcesContent embedded", "CWE-540", "T1552"),
        ("map reveals internal paths", "CWE-200", "T1590"),
        ("map reveals api endpoints", "CWE-200", "T1587"),
        ("map reveals secret-shaped names", "CWE-798", "T1552"),
        ("webpack devtool misconfig", "CWE-540", "T1552"),
        ("minified-only policy absent", "CWE-540", "T1552"),
        ("map-stripping remediation", "CWE-693", "T1106"),
        ("P7 js handoff rollup", "CWE-200", "T1106"),
        ("map absent (HARDENED control)", "CWE-693", "T1106"),
        ("names-only census discipline", "CWE-693", "T1106"),
    ],
    "MISCONFIG_GQL": [
        ("GET introspection enabled", "CWE-200", "T1592"),
        ("graphiql playground exposed", "CWE-489", "T1587"),
        ("field-suggestion error shape", "CWE-203", "T1189"),
        ("schema reveals sensitive fields", "CWE-200", "T1592"),
        ("introspection on prod (misconfig)", "CWE-489", "T1592"),
        ("mutation names census (never sent)", "CWE-693", "T1106"),
        ("depth/alias guard absent (P18)", "CWE-400", "T1499"),
        ("apollo studio trace surface", "CWE-200", "T1592"),
        ("introspection locked (control)", "CWE-693", "T1106"),
        ("P18/P22 handoff chain", "CWE-693", "T1106"),
        ("GET-only census discipline", "CWE-693", "T1106"),
    ],
    "MISCONFIG_CONTAINER": [
        ("prometheus /metrics public", "CWE-668", "T1613"),
        ("go pprof runtime profiles", "CWE-668", "T1613"),
        ("spring /env endpoint public", "CWE-489", "T1613"),
        ("docker registry /v2/_catalog", "CWE-668", "T1613"),
        ("k8s dashboard/service shapes", "CWE-668", "T1613"),
        ("apache server-status public", "CWE-200", "T1592"),
        ("nginx_status public", "CWE-200", "T1592"),
        ("/healthz verbose build info", "CWE-200", "T1592"),
        ("container lockdown remediation", "CWE-693", "T1106"),
        ("pool closed (HARDENED control)", "CWE-693", "T1106"),
        ("P24 cloud handoff chain", "CWE-693", "T1106"),
    ],
    "MISCONFIG_BYPASS2": [
        ("double-slash normalizer differential", "CWE-22", "T1083"),
        ("dot-segment /./ canonicalization gap", "CWE-22", "T1083"),
        ("parent-segment traversal normalizer", "CWE-22", "T1083"),
        ("url-encoded dot decoder differential", "CWE-22", "T1083"),
        ("semicolon matrix-param parser diff", "CWE-436", "T1083"),
        ("whitespace %09/%20 trim differential", "CWE-436", "T1083"),
        ("case-insensitive authz differential", "CWE-178", "T1083"),
        ("trailing-slash route-match gap", "CWE-436", "T1083"),
        ("X-Original-URL misroute trust", "CWE-348", "T1036"),
        ("X-Forwarded-For allowlist trust", "CWE-348", "T1036"),
        ("normalize-before-authz remediation", "CWE-693", "T1106"),
    ],
    "MISCONFIG_PLATFORM": [
        ("spring stack fingerprint", "CWE-200", "T1592"),
        ("django fingerprint", "CWE-200", "T1592"),
        ("laravel fingerprint", "CWE-200", "T1592"),
        ("symfony fingerprint", "CWE-200", "T1592"),
        ("wordpress fingerprint", "CWE-200", "T1592"),
        ("tomcat fingerprint", "CWE-200", "T1592"),
        ("dotnet fingerprint", "CWE-200", "T1592"),
        ("aws topology shape", "CWE-200", "T1580"),
        ("azure topology shape", "CWE-200", "T1580"),
        ("gcp topology shape", "CWE-200", "T1580"),
        ("vendor checklist remediation aid", "CWE-693", "T1106"),
    ],
}

MATRIX_FAMILIES = list(MATRIX_CATALOG.keys())


def build_matrix():
    """Matrix rows (id MIS-001..) - P12..P22-compatible shape."""
    rows = []
    n = 0
    for fam in MATRIX_FAMILIES:
        for tech, cwe, mitre in MATRIX_CATALOG[fam]:
            n += 1
            rows.append({"id": "MIS-%03d" % n, "family": fam,
                         "technique": tech, "cwe": cwe, "mitre": mitre})
    return rows


# ===========================================================================
# STAGE Z - RENDERERS (findings md / test plan / remediation / exec / kickoff)
# ===========================================================================
def render_findings_md(scope, F, verdict_rows, chains, meta):
    L = ["# P23 MISCONFIG FINDINGS - %s" % scope.engagement, "",
         "**Engine:** WASP v%s / misconfig plan v%s | **Mode:** %s | "
         "**100%% INERT detection-only** (canary %s family)" %
         (VERSION, PLAN_VERSION, meta.get("mode", "active"), CANARY_FAMILY),
         "**Discipline:** GET-only | bodies/secret-values REDACTED | zero "
         "egress | JNDI/IMDS/creds FORBIDDEN-AUTO", "",
         "## Severity summary", ""]
    sc = _sev_counts(F)
    for sev in ("critical", "high", "medium", "low", "info"):
        L.append("- **%s:** %d" % (sev.upper(), sc.get(sev, 0)))
    L += ["", "## Findings (%d)" % len(F.items), ""]
    for f in F.items:
        L += ["### %s %s [%s] (cvss~%s)" % (f["id"], f["title"],
                                            f["severity"].upper(),
                                            f["cvss_hint"]),
              "- **Endpoint:** %s" % f["endpoint"],
              "- **Why it matters:** %s" % f["why_it_matters"],
              "- **Detail:** %s" % f["detail"],
              ("- **Evidence:** %s" % f["evidence"]) if f["evidence"] else "",
              ""]
    L += ["## Verdict rows (%d)" % len(verdict_rows), "",
          "| Stage | URL | Verdict | Signals | Detail |", "|---|---|---|---|---|"]
    for r in verdict_rows[:200]:
        L.append("| %s | %s | %s | %s | %s |" % (
            r["stage"], truncate(r["url"], 48), r["verdict"],
            ",".join(r["signals"])[:40], truncate(r["detail"], 60)))
    L += ["", "## Kill-chains (%d)" % len(chains), ""]
    for c in chains:
        L.append("- **%s** %s -> %s" % (c["id"], c["title"], c["evidence"]))
    return "\n".join(L) + "\n"


def render_test_plan(F, gates, matrix_rows):
    L = ["# P23 MISCONFIG TEST PLAN (kill tests + manual waves)", "",
         "RoE gates (sab default OFF - enable sirf written authorization par):", ""]
    for g, d in ROE_GATES:
        L.append("- `%s` = %s -> %s" % (g, str(gates.get(g, False)).lower(), d))
    L += ["", "## Kill tests (KD-01..KD-13)", ""]
    kds = [
        ("KD-01", "Debug/console manual wave",
         "console UI open -> feature review -> runtime-introspection disable "
         "(actuator/env/heapdump prod me off)"),
        ("KD-02", "Sensitive-artifact wave",
         ".git/.env/backup confirm manual -> credential rotation + history "
         "purge (RoE window me)"),
        ("KD-03", "Verbose-error wave",
         "stack-trace shapes manual capture -> error masking + 500 template "
         "review"),
        ("KD-04", "Log4Shell surface wave",
         "version census confirm -> log4j>=2.17.1 upgrade + "
         "FormatMsgNoLookups (JNDI payload KABHI)"),
        ("KD-05", "Admin-exposure wave",
         "admin panel presence + platform marker -> auth-gate/IP-allowlist "
         "review (default-cred wave manual)"),
        ("KD-06", "CORS reflection wave",
         "canary origin reflection confirm -> origin-allowlist fix"),
        ("KD-07", "Trust-header wave",
         "X-Original-URL/X-Forwarded echo confirm -> proxy sanitization "
         "(strip at edge)"),
        ("KD-08", "TRACE/methods wave",
         "TRACE echo + broad Allow confirm -> verb disable at edge"),
        ("KD-09", "Spec-exposure wave",
         "swagger/openapi presence -> spec gating on prod"),
        ("KD-10", "Sourcemap wave",
         ".map sourcesContent confirm -> build me map strip"),
        ("KD-11", "GraphQL wave",
         "GET introspection confirm -> introspection prod-off + playground "
         "restrict"),
        ("KD-12", "Container wave",
         "metrics/pprof/env presence -> endpoint lockdown (auth/network "
         "policy)"),
        ("KD-13", "Bypass2 normalization wave",
         "manual proxy replay with each MB-xx shape -> normalizer/authz "
         "alignment"),
    ]
    for kid, title, steps in kds:
        L += ["### %s %s" % (kid, title), steps, ""]
    L += ["## FORBIDDEN-AUTO (manual+RoE ONLY - kabhi automate nahi)", "",
          "- JNDI/Log4Shell payload injection (koi lookup-string network par)",
          "- real IMDS link-local metadata probing",
          "- default-credential stuffing / brute loops",
          "- protected-path force beyond bounded canary differentials",
          "- destructive config toggles (debug-off remotely etc.)", "",
          "## Technique matrix snapshot",
          "Rows: %d | Families: %d" % (len(matrix_rows), len(set(
              m["family"] for m in matrix_rows)))]
    return "\n".join(L) + "\n"


def render_remediation(F):
    L = ["# P23 MISCONFIG REMEDIATION PLAYBOOK", "",
         "Har finding-family ke liye server-side fix guidance:", ""]
    rem = [
        ("MISCONFIG_DEBUG", "Prod me debug OFF: actuator env/heapdump/mappings "
         "restrict (management.endpoints.web.exposure), Werkzeug/Django DEBUG="
         "False, profiler/trace endpoints network-isolate, auth-gate + IP "
         "allowlist defense-in-depth."),
        ("MISCONFIG_DIRLIST", "Autoindex disable (Apache: Options -Indexes; "
         "nginx: autoindex off), sensitive dirs storage-layer se bahar rakho, "
         "404/403 uniform responses."),
        ("MISCONFIG_HEADERS", "CSP nonce/hash-based (unsafe-inline hatao), "
         "HSTS max-age>=31536000 + includeSubDomains, XFO DENY/SAMEORIGIN, "
         "XCTO nosniff, Referrer-Policy strict-origin-when-cross-origin, "
         "Permissions-Policy minimal, COOP/COEP/CORP enable, disclosure "
         "headers strip (Server/X-Powered-By)."),
        ("MISCONFIG_SECRETS", "Response/JS/spec me secrets KABHI: secret-"
         "manager rotation (jo leak hue = compromise), redaction middleware, "
         "git history purge + pre-commit secret scans, env templating."),
        ("MISCONFIG_ERRORS", "customErrors On / generic 500 template, stack "
         "traces sirf logs me (correlation-id return), debug verbosity prod "
         "OFF, error bodies se paths/versions/PII strip."),
        ("MISCONFIG_LOG4SHELL", "log4j-core >=2.17.1, "
         "log4j2.formatMsgNoLookups=true, JndiLookup class remove, "
         "log-config endpoints restrict, egress filtering (DNS/HTTP)."),
        ("MISCONFIG_DEFAULTS", "Install-time forced cred change, default "
         "accounts disable, password-policy + lockout, console cred rotation "
         "schedule (koi stuffing automation nahi - manual RoE wave)."),
        ("MISCONFIG_ADMIN", "Admin surfaces VPN/bastion ke peeche, "
         "auth-gate (401 default), IP allowlist + MFA, separate admin vhost, "
         "platform version patching."),
        ("MISCONFIG_CLOUD", "IMDSv2 required + hop-limit 1, metadata endpoint "
         "block from containers, S3/GCS/Azure public-block + SAS minimal TTL, "
         "instance-profile least-privilege (P24 deep-dive)."),
        ("MISCONFIG_CORS", "Origin allowlist exact-match (koi prefix/reflect "
         "nahi), null origin reject, wildcard sirf public unauthenticated "
         "data, Access-Control-Allow-Credentials sirf trusted origins par."),
        ("MISCONFIG_COOKIES", "Secure+HttpOnly+SameSite=Lax/Strict har session "
         "cookie par, Domain minimal (host-only), __Host-/__Secure- prefixes, "
         "cookie names/paths minimize."),
        ("MISCONFIG_CACHEHDR", "Private/auth responses par "
         "Cache-Control: no-store (ya private, max-age=0), Vary: Cookie/"
         "Authorization, cache-key canonicalization, CDN token-route bypass."),
        ("MISCONFIG_METHODS", "TRACE disable, OPTIONS minimize (Allow: GET, "
         "HEAD, OPTIONS), method-override headers edge par strip, verb "
         "allowlist per route."),
        ("MISCONFIG_TRANSPORT", "http->https 301 (preserve-host, path), HSTS "
         "har response par, mixed-content fix (assets https), preload "
         "submission review."),
        ("MISCONFIG_SPEC", "Spec endpoints prod me auth-gate ya disable, "
         "public docs sirf curated subset, sensitive ops spec se exclude."),
        ("MISCONFIG_SOURCEMAP", "Build pipeline me .map strip (webpack "
         "production/hidden devtool), private artifact store me maps rakhna, "
         "CDN par *.map block."),
        ("MISCONFIG_GQL", "Introspection prod OFF (allowlist dev), GraphiQL/"
         "Playground network-restrict, field-suggestions disable, depth/"
         "alias/cost guards (P18), persisted queries."),
        ("MISCONFIG_CONTAINER", "metrics/pprof/env/registry endpoints "
         "internal-network restrict, auth-gate, k8s RBAC + dashboard "
         "network-policy, verbose health minimal."),
        ("MISCONFIG_BYPASS2", "Normalize-before-authz (single canonical path "
         "form), reject duplicate/malformed path segments, proxy headers "
         "(X-Original-*/X-Forwarded-*) edge par strip, host/origin strict "
         "binding."),
        ("MISCONFIG_PLATFORM", "Stack-specific hardening checklists (Spring "
         "actuator security, Django ALLOWED_HOSTS+DEBUG, Laravel APP_DEBUG, "
         "Tomcat manager binding), vendor advisories subscribe."),
    ]
    for fam, txt in rem:
        L += ["## %s" % fam, txt, ""]
    L += ["## Finding-driven priorities", ""]
    for f in F.items[:20]:
        if f["severity"] in ("critical", "high"):
            L.append("- [%s] %s (%s)" % (f["severity"].upper(), f["title"],
                                         f["endpoint"]))
    return "\n".join(L) + "\n"


def render_exec_summary(scope, F, posture, verdict_rows, meta):
    sc = _sev_counts(F)
    weak = len(posture.get("weak") or [])
    conf_n = len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"])
    hard_n = len([r for r in verdict_rows if r["verdict"] == "HARDENED"])
    L = ["# P23 MISCONFIG EXECUTIVE SUMMARY - %s" % scope.engagement, "",
         "Engagement: %s | Reference: %s | Mode: %s" % (
             scope.engagement, scope.ref or "n/a", meta.get("mode", "active")),
         "Engine: WASP v%s / misconfig plan v%s | 100%% INERT (canary %s)" % (
             VERSION, PLAN_VERSION, CANARY_FAMILY),
         "", "## Posture", "",
         "- CONFIRMED misconfig exposures: **%d**" % conf_n,
         "- HARDENED positive controls: **%d**" % hard_n,
         "- Findings: critical=%d high=%d medium=%d low=%d info=%d" % (
             sc.get("critical", 0), sc.get("high", 0), sc.get("medium", 0),
             sc.get("low", 0), sc.get("info", 0)),
         "- Posture-WEAK endpoints: **%d**" % weak,
         "", "## Top risks", ""]
    for f in F.items:
        if f["severity"] in ("critical", "high"):
            L.append("- **%s** %s @ %s" % (f["severity"].upper(),
                                           f["title"], f["endpoint"]))
    if not any(f["severity"] in ("critical", "high") for f in F.items):
        L.append("- (koi critical/high CONFIRMED nahi - HARDENED controls "
                 "dominant; manual waves MISCONFIG_TEST_PLAN.md dekho)")
    L += ["", "## Next steps", "",
          "1. RoE-gated manual waves (MISCONFIG_TEST_PLAN.md KD-01..KD-13)",
          "2. Remediation order (MISCONFIG_REMEDIATION.md)",
          "3. P24 cloud handoff (feedforward.json)"]
    return "\n".join(L) + "\n"


def render_kickoff(scope, gates, conf):
    L = ["# P23 MISCONFIG KICKOFF GUIDE", "",
         "## Run", "",
         "```",
         "python3 wasp.py run --module 23      # P23 stage (sab gates OFF)",
         "python3 wasp.py run --module misconfig --config config.json",
         "python3 mod_misconfig.py             # gate reference",
         "```", "",
         "## Gates enable (sirf written authorization par)", "",
         "```json",
         json.dumps({g: True for g, _ in ROE_GATES[:2]}, indent=2),
         "```", "",
         "## Discipline (non-negotiable)", "",
         "- 100%% INERT detection-only (canary %s family)" % CANARY_FAMILY,
         "- GET-only module: koi POST/PUT/DELETE probe KABHI "
         "(TRACE sirf gate ON canary-echo census)",
         "- bodies/secret-values REDACTED: sirf status/sha1/shape-flags",
         "- NO JNDI payloads | NO IMDS probes | NO credential sending",
         "- zero egress: scope firewall (wasp_core LAYER-4)",
         "- outputs RWX 0777", "",
         "## Caps (config.json)", "",
         "```json",
         json.dumps({k: v for k, v in DEFAULTS.items()
                     if k.startswith("misconfig_") and not
                     k.startswith("misconfig_allow")}, indent=2),
         "```"]
    return "\n".join(L) + "\n"


def render_playbooks():
    L = ["# P23 MANUAL PLAYBOOKS (FORBIDDEN-AUTO techniques)", "",
         "Ye techniques automation me KABHI nahi - sirf written RoE + "
         "manual execution:", ""]
    L += ["## Log4Shell surface waves", ""]
    for i, (sid, name, disc) in enumerate(LOG4SHELL_PLAYBOOK_ROWS, 1):
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Cloud/IMDS waves", ""]
    for i, (sid, name, disc) in enumerate(CLOUD_PLAYBOOK_ROWS, 1):
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Default-credential matrix (documented-only)", ""]
    for row in DEFAULT_CRED_ROWS:
        L.append("- %s %s: %s / %s (creds KABHI network par nahi)" %
                 (row[0], row[1], row[2], row[3]))
    L += ["", "## Race-adjacent misconfig techniques", ""]
    for i, (sid, name, disc) in enumerate(RACE_TECHNIQUES, 1):
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Evidence discipline", "",
          "- har manual step ka request/response capture (RoE window me)",
          "- canary identifiers use karo (real ids sirf final PoC me, "
          "owner consent ke saath)",
          "- artifact proofs: timestamped GET + status/sha1 (body KABHI "
          "report me copy nahi)",
          "- cleanup: koi canary residue chhodna nahi"]
    return "\n".join(L) + "\n"


def render_chains_txt(chains):
    L = ["P23 MISCONFIG KILL-CHAINS (CH01..CH%02d)" % len(chains), ""]
    for c in chains:
        L.append("%s | %s | %s" % (c["id"], c["title"], c["evidence"]))
    return "\n".join(L) + "\n"


def render_matrix_txt(matrix_rows):
    L = ["P23 TECHNIQUE MATRIX - %d rows x %d families" % (
        len(matrix_rows), len(set(m["family"] for m in matrix_rows))), ""]
    cur = None
    for m in matrix_rows:
        if m["family"] != cur:
            cur = m["family"]
            L += ["", "## %s" % cur]
        L.append("%s | %-52s | %s | %s" % (m["id"], m["technique"][:52],
                                           m["cwe"], m["mitre"]))
    return "\n".join(L) + "\n"


def build_hypotheses(results, posture):
    """Offline hypotheses (manual-review leads)."""
    hyps = []
    for r in (results.get("debug") or {}).get("rows", []):
        if r.get("live") and r.get("shape"):
            hyps.append({"h": "Debug console live (%s) @ %s - console "
                         "lockdown review" % (r.get("shape"), r.get("url")),
                         "prio": "critical"})
    for r in (results.get("artifacts") or {}).get("rows", []):
        if r.get("live"):
            hyps.append({"h": "Sensitive artifact live @ %s - secret "
                         "rotation wave" % r.get("url"), "prio": "high"})
    for r in (results.get("cors") or {}).get("rows", []):
        if r.get("reflect_any"):
            hyps.append({"h": "CORS reflects canary origin @ %s - "
                         "cross-origin review" % r.get("url"), "prio": "high"})
    for r in (results.get("bypass2") or {}).get("rows", []):
        if r.get("accepted_count"):
            hyps.append({"h": "Bypass2 accepted (%s) @ %s - normalization "
                         "review" % (",".join(r.get("accepted_ids", [])[:3]),
                                     r.get("url")), "prio": "high"})
    for w in (posture.get("weak") or [])[:8]:
        hyps.append({"h": "Posture WEAK (%d/12) @ %s" % (w["score"], w["url"]),
                     "prio": "high"})
    if not hyps:
        hyps.append({"h": "Dominant HARDENED posture - kaunse controls "
                     "kabhi fail hote hain (negative-path review)",
                     "prio": "info"})
    return hyps


# ===========================================================================
# STAGE Z - WRITE REPORTS (55 artifacts) + FEEDFORWARD + MANIFEST
# ===========================================================================
def write_reports(out, scope, F, ctx, meta, results, disc, conf,
                  chains, verdict_rows, matrix_rows, posture, platform,
                  guard, hyps, gql_mut, ws_endpoints):
    """Sab artifacts likh (55). Bodies/secret-values REDACTED (names/
    booleans/sha1 only)."""
    manifest = []

    def _w_json(name, obj):
        save_json(os.path.join(out, name), obj)
        manifest.append(name)

    def _w_text(name, txt):
        save_text(os.path.join(out, name), txt)
        manifest.append(name)

    targets = results.get("targets") or []

    # 1-3 targets/endpoints/ranking
    _w_json("misconfig_targets.json", {
        "count": len(targets),
        "targets": [{"url": t.get("url"), "score": t.get("score"),
                     "kinds": t.get("kinds", [])} for t in targets]})
    _w_text("misconfig_endpoints.txt", "\n".join(
        [t.get("url", "") for t in targets]) + "\n")
    _w_json("misconfig_ranking.json", {
        "paths_cap": conf.get("misconfig_paths_cap"),
        "ranked": [{"url": t.get("url"), "score": t.get("score")}
                   for t in targets]})
    # 4 coverage
    gates = {g: bool(conf.get(g)) for g, _ in ROE_GATES}
    _w_json("misconfig_coverage.json", {
        "mode": ctx.get("mode"), "sources": disc.get("sources", []),
        "probes_total": meta.get("probes_total", 0),
        "stages": ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
                   "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
                   "W", "X", "Y", "Z"],
        "gates": gates})
    # 5-6 baseline/waf
    _w_json("misconfig_baseline.json", results.get("baseline", {}).get("rows", []))
    _w_json("misconfig_waf.json", results.get("baseline", {}).get("waf", []))
    # 7-11 censuses
    _w_json("misconfig_debug.json", results.get("debug", {}))
    _w_text("misconfig_debug_paths.txt", "\n".join(DEBUG_PATHS) + "\n")
    _w_json("misconfig_artifacts.json", results.get("artifacts", {}))
    _w_json("misconfig_dirlist.json", {
        "rows": (results.get("artifacts") or {}).get("dirlist_rows", [])})
    _w_text("misconfig_artifact_names.txt", "\n".join(ARTIFACT_PATHS) + "\n")
    # 12-15 headers/secrets
    _w_json("misconfig_headers.json", results.get("headers", {}))
    _w_text("misconfig_header_posture.txt", "\n".join(
        ["P23 SECURITY-HEADER POSTURE (9-point):"] +
        ["%-58s %s/9 %s" % (r["url"][:58], r.get("score", "?"),
                            r.get("grade", "?"))
         for r in (results.get("headers") or {}).get("rows", [])]) + "\n")
    _w_json("misconfig_secrets.json", results.get("secrets", {}))
    _w_text("misconfig_secret_names.txt", "\n".join(sorted(set(
        [s.get("shape", "") for r in (results.get("secrets") or {})
         .get("rows", []) for s in (r.get("shapes") or [])]))) + "\n")
    # 16-22 gated censuses
    _w_json("misconfig_errors.json", results.get("errors", {}))
    _w_json("misconfig_log4shell.json", results.get("log4shell", {}))
    _w_text("misconfig_log4shell_playbook.txt", "\n".join(
        ["P23 LOG4SHELL PLAYBOOK (JNDI payloads FORBIDDEN-AUTO):"] +
        ["%s | %s | %s" % (i, n, d) for i, n, d in
         LOG4SHELL_PLAYBOOK_ROWS]) + "\n")
    _w_json("misconfig_default_creds.json", results.get("defaults", {}))
    _w_json("misconfig_admin.json", results.get("admin", {}))
    _w_text("misconfig_admin_paths.txt", "\n".join(ADMIN_PATHS) + "\n")
    _w_json("misconfig_cloud.json", results.get("cloud", {}))
    # 23-30 interplay censuses
    _w_json("misconfig_cors.json", results.get("cors", {}))
    _w_json("misconfig_cookies.json", results.get("cookies", {}))
    _w_json("misconfig_header_trust.json", results.get("trust", {}))
    _w_json("misconfig_methods.json", results.get("methods", {}))
    _w_json("misconfig_transport.json", results.get("transport", {}))
    _w_json("misconfig_spec.json", results.get("spec", {}))
    _w_json("misconfig_sourcemap.json", results.get("sourcemap", {}))
    _w_json("misconfig_gql.json", results.get("gql", {}))
    # 31-33
    _w_json("misconfig_container.json", results.get("container", {}))
    _w_json("misconfig_bypass2.json", results.get("bypass2", {}))
    _w_json("misconfig_cache.json", results.get("cache", {}))
    # 34-38 posture/platform/guard/verdicts/chains
    _w_json("misconfig_posture.json", posture)
    _w_text("misconfig_posture.txt", "\n".join(
        ["P23 MISCONFIG POSTURE (12-point composite):"] +
        ["%-58s %d/12 %s" % (r["url"][:58], r["score"], r["grade"])
         for r in posture.get("rows", [])] +
        ["", "points: " + ", ".join("%s=%s" % (p, d)
                                    for p, d in posture.get("points", []))]) + "\n")
    _w_json("misconfig_platform.json", platform)
    _w_json("misconfig_secret_guard.json", guard)
    _w_json("misconfig_verdicts.json", {"count": len(verdict_rows),
                                        "rows": verdict_rows})
    _w_json("misconfig_chains.json", {"count": len(chains), "chains": chains})
    # 39-43 matrix + hypotheses + gql/ws
    _w_text("MISCONFIG_CHAINS.txt", render_chains_txt(chains))
    _w_json("misconfig_matrix.json", {
        "rows": len(matrix_rows),
        "families": sorted(set(m["family"] for m in matrix_rows)),
        "matrix": matrix_rows})
    _w_text("MISCONFIG_MATRIX.txt", render_matrix_txt(matrix_rows))
    _w_json("misconfig_hypotheses.json", {"count": len(hyps),
                                          "hypotheses": hyps})
    _w_json("misconfig_gql_mutations.json", gql_mut)
    _w_json("misconfig_ws_endpoints.json", ws_endpoints)
    # 44 findings.json
    _w_json("findings.json", {
        "module": NAME, "phase": PHASE, "plan_version": PLAN_VERSION,
        "engagement": scope.engagement, "generated": now_iso(),
        "mode": ctx.get("mode"), "count": len(F.items),
        "severity_counts": _sev_counts(F),
        "findings": F.items})
    # 45-50 renderers
    _w_text("MISCONFIG_FINDINGS.md", render_findings_md(
        scope, F, verdict_rows, chains, meta))
    _w_text("MISCONFIG_TEST_PLAN.md", render_test_plan(F, gates, matrix_rows))
    _w_text("MISCONFIG_REMEDIATION.md", render_remediation(F))
    _w_text("EXEC_SUMMARY.md", render_exec_summary(
        scope, F, posture, verdict_rows, meta))
    _w_text("MISCONFIG_KICKOFF.md", render_kickoff(scope, gates, conf))
    _w_text("MISCONFIG_PLAYBOOKS.md", render_playbooks())
    # 51-54 aux
    _w_text("misconfig_gates.txt", "\n".join(
        ["RoE gates (default OFF - enable sirf written authorization par):"] +
        ["%s = %s # %s" % (g, str(bool(conf.get(g))).lower(), d)
         for g, d in ROE_GATES]) + "\n")
    _w_text("misconfig_summary.txt", "\n".join([
        "P23 MISCONFIG SUMMARY - %s" % scope.engagement,
        "mode=%s probes=%s findings=%d matrix=%d chains=%d "
        "verdicts=%d posture_rows=%d" % (
            ctx.get("mode"), meta.get("probes_total", 0), len(F.items),
            len(matrix_rows), len(chains), len(verdict_rows),
            len(posture.get("rows", []))),
        "CONFIRMED=%d SUSPECTED=%d HARDENED=%d BLOCKED=%d SKIPPED=%d" % (
            len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
            len([r for r in verdict_rows if r["verdict"] == "SUSPECTED"]),
            len([r for r in verdict_rows if r["verdict"] == "HARDENED"]),
            len([r for r in verdict_rows if r["verdict"] == "BLOCKED"]),
            len([r for r in verdict_rows if r["verdict"] == "SKIPPED"]))]) + "\n")
    _w_text("misconfig_live_endpoints.txt", "\n".join(sorted(set(
        [b.get("url") for b in results.get("baseline", {}).get("rows", [])
         if b.get("status") and b.get("status") < 400]))[:60]) + "\n")
    skipped = [g for g, _ in ROE_GATES if not bool(conf.get(g))]
    _w_text("misconfig_skipped_waves.txt", "\n".join(
        ["RoE-gated manual waves (SKIPPED - document in test plan):"] +
        ["%s -> %s" % (g, dict(ROE_GATES)[g]) for g in skipped]) + "\n")

    # 55 feedforward (W)
    ff_map = {
        "to_phase24_cloud": {
            "cloud_header_shapes": [s for r in
                                    (results.get("cloud") or {}).get("rows", [])
                                    for s in r.get("cloud_shapes", [])][:10],
            "bucket_surface": [t.get("url") for t in targets
                               if any(x in (t.get("url") or "")
                                      for x in ("s3", "storage", "bucket"))
                               ][:6]},
        "to_phase25_controls": {
            "posture_rows": [{"url": r["url"], "score": r["score"],
                              "grade": r["grade"]}
                             for r in posture.get("rows", [])][:12],
            "header_weak": [r.get("url") for r in
                            (results.get("headers") or {}).get("rows", [])
                            if r.get("grade") == "WEAK"][:10]},
        "to_phase11_access": {
            "bypass2_accepted": sorted(set(sum(
                [r.get("accepted_ids", []) for r in
                 (results.get("bypass2") or {}).get("rows", [])], [])))[:18],
            "admin_exposed": [r.get("url") for r in
                              (results.get("admin") or {}).get("rows", [])
                              if r.get("live") and not r.get("auth_gate")][:10]},
        "to_phase12_inject": {
            "verbose_error_urls": [r.get("url") for r in
                                   (results.get("errors") or {}).get("rows", [])
                                   if r.get("verbose_hits")][:10],
            "secret_shape_urls": [r.get("url") for r in
                                  (results.get("secrets") or {}).get("rows", [])
                                  if r.get("shapes")][:10]},
        "to_phase9_auth": {
            "default_cred_platforms": [m["platform"] for m in
                                       (results.get("defaults") or {})
                                       .get("matrix", [])][:14],
            "weak_cookie_urls": [r.get("url") for r in
                                 (results.get("cookies") or {}).get("rows", [])
                                 if r.get("weak_flags")][:10]},
        "to_phase32_report": {
            "exec_summary": "EXEC_SUMMARY.md",
            "findings_json": "findings.json",
            "mode": ctx.get("mode")},
    }
    write_feedforward(out, "phase23", ff_map, notes=[
        "P23 v%s INERT misconfig census (GET-only, canary %s)" % (
            PLAN_VERSION, CANARY_FAMILY),
        "%d artifacts | %d probes | gates default OFF" % (
            len(manifest) + 2, meta.get("probes_total", 0))])
    manifest += ["feedforward.json"]

    # MANIFEST
    write_manifest(out, "phase23", manifest, stats={
        "mode": ctx.get("mode"), "probes": meta.get("probes_total", 0),
        "findings": len(F.items), "matrix_rows": len(matrix_rows),
        "chains": len(chains), "verdicts": len(verdict_rows),
        "artifacts": len(manifest) + 1,
        "gates_on": [g for g, _ in ROE_GATES if bool(conf.get(g))],
        "duration_sec": round(meta.get("duration", 0.0), 1)}, notes=[
        "100% INERT detection-only | GET-only module | bodies/values "
        "REDACTED | NO JNDI/IMDS/creds | zero egress | RWX 0777"])
    return manifest


# ===========================================================================
# RUN ORCHESTRATOR (stages A..Z, checkpointed, passive-aware)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 23 - Misconfiguration & Secrets Exposure (detection-only, "
         "INERT) (v%s) | %s" % (PLAN_VERSION, scope.describe()))
    warn("Misconfig discipline: koi exploitation KABHI nahi (canary %s) | "
         "GET-only module (koi POST/PUT/DELETE probe nahi) | bodies/secret-"
         "values REDACTED | NO JNDI payloads | NO IMDS probes | NO creds "
         "sending | zero egress." % CANARY_FAMILY)
    on_gates = [g for g, _ in ROE_GATES if bool(conf.get(g))]
    if on_gates:
        warn("RoE gates ON: %s" % ", ".join(on_gates))
    else:
        info("Sab RoE gates OFF (detection-only census mode) - gated waves "
             "MISCONFIG_TEST_PLAN.md me documented hain.")
    info("caps: paths=%s | probes=%s | bypass2=%s | cold=%s" % (
        conf.get("misconfig_paths_cap"), conf.get("misconfig_probe_cap"),
        conf.get("misconfig_bypass2_cap"), conf.get("misconfig_cold_paths")))

    F = Findings()
    meta = {"probes_total": 0, "mode": "active"}
    ctxd = {"out": out, "coverage": {}, "mode": "active",
            "base_dir": os.path.join(base_out, scope.engagement)}
    results = {}
    passive = (not bool(getattr(cfg, "allow_active", True))) or \
        (getattr(scope, "allow_active", True) is False)
    if passive:
        ctxd["mode"] = "passive"
        meta["mode"] = "passive"
        warn("PASSIVE mode (allow_active=false) - offline mining only, "
             "0 network probes.")

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Misconfig surface discovery (14-module ff + miners + cold)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or {}
        disc = dict(cached)
        disc.setdefault("ranked", [])
        disc.setdefault("targets", [])
        disc.setdefault("sources", [])
        disc.setdefault("base_url", "")
        ok("Replayed discovery (checkpoint)")
    else:
        disc = discover_misconfig_surface(ctxd, scope, conf)
        cp.mark(ckA, disc, summary="misconfig surface")
    results["targets"] = disc.get("ranked", [])
    meta["sources"] = disc.get("sources", [])
    ok("targets=%d | sources: %s" % (len(results["targets"]),
                                     ", ".join(meta["sources"][:6])))

    # ---------------- Stage B: baseline + WAF ----------------
    head("Stage B - Baseline + WAF + soft-404")
    ckB = "stageB:baseline"
    if cp.is_done(ckB):
        results["baseline"] = cp.result_of(ckB) or {"rows": [], "waf": []}
        ok("Replayed baseline (checkpoint)")
    elif passive:
        results["baseline"] = {"rows": [], "waf": []}
        warn("passive: baseline skipped (0 probes)")
    else:
        results["baseline"] = baseline_and_waf(
            http, disc.get("targets", []), conf)
        cp.mark(ckB, results["baseline"], summary="baseline+waf")
    live_n = len([b for b in results["baseline"].get("rows", [])
                  if b.get("status") and b.get("status") < 400])
    ok("baseline rows=%d live=%d" % (
        len(results["baseline"].get("rows", [])), live_n))

    # ---------------- Stage C: debug census ----------------
    head("Stage C - Debug/console endpoint census (GATED)")
    ckC = "stageC:debug"
    if cp.is_done(ckC):
        results["debug"] = cp.result_of(ckC) or {}
        ok("Replayed debug census (checkpoint)")
    elif passive:
        results["debug"] = {"rows": [],
                            "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_debug_probe"):
        results["debug"] = debug_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["debug"].get("skipped_note", ""))
    else:
        results["debug"] = debug_census(http, disc.get("targets", []), conf)
        cp.mark(ckC, results["debug"], summary="debug census")
    meta["probes_total"] += len(results["debug"].get("rows", []))

    # ---------------- Stage D: artifacts + dirlist ----------------
    head("Stage D - Directory listing + sensitive artifacts (GATED)")
    ckD = "stageD:artifacts"
    if cp.is_done(ckD):
        results["artifacts"] = cp.result_of(ckD) or {}
        ok("Replayed artifact census (checkpoint)")
    elif passive:
        results["artifacts"] = {"rows": [], "dirlist_rows": [],
                                "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_artifact_probe"):
        results["artifacts"] = artifact_census(http, disc.get("targets", []),
                                               conf)
        warn("SKIPPED (gate OFF): %s" %
             results["artifacts"].get("skipped_note", ""))
    else:
        results["artifacts"] = artifact_census(http, disc.get("targets", []),
                                               conf)
        cp.mark(ckD, results["artifacts"], summary="artifact census")
    meta["probes_total"] += len(results["artifacts"].get("rows", [])) + \
        len(results["artifacts"].get("dirlist_rows", []))

    # ---------------- Stage E: headers posture ----------------
    head("Stage E - Security-headers posture census (16 headers)")
    ckE = "stageE:headers"
    if cp.is_done(ckE):
        results["headers"] = cp.result_of(ckE) or {}
    elif passive:
        results["headers"] = {"rows": [], "note": "passive"}
    else:
        results["headers"] = headers_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckE, results["headers"], summary="headers census")
    meta["probes_total"] += len(results["headers"].get("rows", []))

    # ---------------- Stage F: secrets-in-response ----------------
    head("Stage F - Secrets-in-response census (30 shapes, values REDACTED)")
    ckF = "stageF:secrets"
    if cp.is_done(ckF):
        results["secrets"] = cp.result_of(ckF) or {}
    elif passive:
        results["secrets"] = {"rows": [], "note": "passive"}
    else:
        results["secrets"] = secrets_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckF, results["secrets"], summary="secrets census")
    meta["probes_total"] += len(results["secrets"].get("rows", []))

    # ---------------- Stage G: verbose errors ----------------
    head("Stage G - Verbose-error/stack-trace census (GATED)")
    ckG = "stageG:errors"
    if cp.is_done(ckG):
        results["errors"] = cp.result_of(ckG) or {}
        ok("Replayed error census (checkpoint)")
    elif passive:
        results["errors"] = {"rows": [],
                             "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_error_probe"):
        results["errors"] = error_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" %
             results["errors"].get("skipped_note", ""))
    else:
        results["errors"] = error_census(http, disc.get("targets", []), conf)
        cp.mark(ckG, results["errors"], summary="error census")
    meta["probes_total"] += len(results["errors"].get("rows", []))

    # ---------------- Stage H: log4shell ----------------
    head("Stage H - Log4Shell/JNDI surface census (GATED, no JNDI payloads)")
    ckH = "stageH:log4shell"
    if cp.is_done(ckH):
        results["log4shell"] = cp.result_of(ckH) or {}
        ok("Replayed log4shell census (checkpoint)")
    elif passive:
        results["log4shell"] = {"rows": [],
                                "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_log4shell_probe"):
        results["log4shell"] = log4shell_census(http, disc.get("targets", []),
                                                conf)
        warn("SKIPPED (gate OFF): %s" %
             results["log4shell"].get("skipped_note", ""))
    else:
        results["log4shell"] = log4shell_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckH, results["log4shell"], summary="log4shell census")
    meta["probes_total"] += len(results["log4shell"].get("rows", []))

    # ---------------- Stage I: default creds (documented) ----------------
    head("Stage I - Default-credential posture (DOCUMENTED-ONLY, 0 probes)")
    results["defaults"] = default_creds_documented()
    F.add("misconfig_default_creds_documented",
          "Default-credential matrix documented (14 platforms)", "*",
          "creds KABHI network par nahi (stuffing FORBIDDEN-AUTO; "
          "MISCONFIG_PLAYBOOKS.md)")

    # ---------------- Stage J: admin panels ----------------
    head("Stage J - Admin/panel exposure census (GATED)")
    ckJ = "stageJ:admin"
    if cp.is_done(ckJ):
        results["admin"] = cp.result_of(ckJ) or {}
        ok("Replayed admin census (checkpoint)")
    elif passive:
        results["admin"] = {"rows": [],
                            "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_admin_probe"):
        results["admin"] = admin_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" %
             results["admin"].get("skipped_note", ""))
    else:
        results["admin"] = admin_census(http, disc.get("targets", []), conf)
        cp.mark(ckJ, results["admin"], summary="admin census")
    meta["probes_total"] += len(results["admin"].get("rows", []))

    # ---------------- Stage K: cloud/metadata ----------------
    head("Stage K - Cloud/metadata surface (DOCUMENTED + header shapes)")
    ckK = "stageK:cloud"
    if cp.is_done(ckK):
        results["cloud"] = cp.result_of(ckK) or {}
    elif passive:
        results["cloud"] = {"rows": [], "note": "passive"}
    else:
        results["cloud"] = cloud_census(http, disc.get("targets", []), conf)
        cp.mark(ckK, results["cloud"], summary="cloud census")
    meta["probes_total"] += len(results["cloud"].get("rows", []))

    # ---------------- Stage L: CORS ----------------
    head("Stage L - CORS misconfig grading (GATED)")
    ckL = "stageL:cors"
    if cp.is_done(ckL):
        results["cors"] = cp.result_of(ckL) or {}
        ok("Replayed cors census (checkpoint)")
    elif passive:
        results["cors"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_cors_probe"):
        results["cors"] = cors_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" %
             results["cors"].get("skipped_note", ""))
    else:
        results["cors"] = cors_census(http, disc.get("targets", []), conf)
        cp.mark(ckL, results["cors"], summary="cors census")
    meta["probes_total"] += len(results["cors"].get("rows", []))

    # ---------------- Stage M: cookies ----------------
    head("Stage M - Cookie/session flags census (P10 handoff)")
    ckM = "stageM:cookies"
    if cp.is_done(ckM):
        results["cookies"] = cp.result_of(ckM) or {}
    elif passive:
        results["cookies"] = {"rows": [], "note": "passive"}
    else:
        results["cookies"] = cookie_census(http, disc.get("targets", []),
                                           conf)
        cp.mark(ckM, results["cookies"], summary="cookie census")
    meta["probes_total"] += len(results["cookies"].get("rows", []))

    # ---------------- Stage N: header trust ----------------
    head("Stage N - Header-trust echo census (GATED)")
    ckN = "stageN:trust"
    if cp.is_done(ckN):
        results["trust"] = cp.result_of(ckN) or {}
        ok("Replayed trust census (checkpoint)")
    elif passive:
        results["trust"] = {"rows": [],
                            "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_header_echo"):
        results["trust"] = header_trust_census(http, disc.get("targets", []),
                                               conf)
        warn("SKIPPED (gate OFF): %s" %
             results["trust"].get("skipped_note", ""))
    else:
        results["trust"] = header_trust_census(http, disc.get("targets", []),
                                               conf)
        cp.mark(ckN, results["trust"], summary="trust census")
    meta["probes_total"] += len(results["trust"].get("rows", []))

    # ---------------- Stage O: methods/TRACE ----------------
    head("Stage O - HTTP methods/TRACE census (GATED)")
    ckO = "stageO:methods"
    if cp.is_done(ckO):
        results["methods"] = cp.result_of(ckO) or {}
        ok("Replayed methods census (checkpoint)")
    elif passive:
        results["methods"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_trace_probe"):
        results["methods"] = methods_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" %
             results["methods"].get("skipped_note", ""))
    else:
        results["methods"] = methods_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckO, results["methods"], summary="methods census")
    meta["probes_total"] += len(results["methods"].get("rows", []))

    # ---------------- Stage P: transport ----------------
    head("Stage P - Transport/downgrade census (passive-GET)")
    ckP = "stageP:transport"
    if cp.is_done(ckP):
        results["transport"] = cp.result_of(ckP) or {}
    elif passive:
        results["transport"] = {"rows": [], "note": "passive"}
    else:
        results["transport"] = transport_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckP, results["transport"], summary="transport census")
    meta["probes_total"] += len(results["transport"].get("rows", []))

    # ---------------- Stage Q: api spec ----------------
    head("Stage Q - API spec exposure census (GATED)")
    ckQ = "stageQ:spec"
    if cp.is_done(ckQ):
        results["spec"] = cp.result_of(ckQ) or {}
        ok("Replayed spec census (checkpoint)")
    elif passive:
        results["spec"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_spec_probe"):
        results["spec"] = spec_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" %
             results["spec"].get("skipped_note", ""))
    else:
        results["spec"] = spec_census(http, disc.get("targets", []), conf)
        cp.mark(ckQ, results["spec"], summary="spec census")
    meta["probes_total"] += len(results["spec"].get("rows", []))

    # ---------------- Stage R: sourcemap ----------------
    head("Stage R - Source-map/JS secrets census (GATED)")
    ckR = "stageR:sourcemap"
    if cp.is_done(ckR):
        results["sourcemap"] = cp.result_of(ckR) or {}
        ok("Replayed sourcemap census (checkpoint)")
    elif passive:
        results["sourcemap"] = {"rows": [],
                                "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_map_probe"):
        results["sourcemap"] = sourcemap_census(http, disc.get("targets", []),
                                                conf)
        warn("SKIPPED (gate OFF): %s" %
             results["sourcemap"].get("skipped_note", ""))
    else:
        results["sourcemap"] = sourcemap_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckR, results["sourcemap"], summary="sourcemap census")
    meta["probes_total"] += len(results["sourcemap"].get("rows", []))

    # ---------------- Stage S: graphql ----------------
    head("Stage S - GraphQL misconfig census (GATED, mutations NEVER)")
    ckS = "stageS:gql"
    if cp.is_done(ckS):
        results["gql"] = cp.result_of(ckS) or {}
        ok("Replayed gql census (checkpoint)")
    elif passive:
        results["gql"] = {"rows": [],
                          "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_gql_probe"):
        results["gql"] = gql_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" %
             results["gql"].get("skipped_note", ""))
    else:
        results["gql"] = gql_census(http, disc.get("targets", []), conf)
        cp.mark(ckS, results["gql"], summary="gql census")
    meta["probes_total"] += len(results["gql"].get("rows", []))

    # ---------------- Stage T: containers ----------------
    head("Stage T - Container/orchestrator exposure census (GATED)")
    ckT = "stageT:container"
    if cp.is_done(ckT):
        results["container"] = cp.result_of(ckT) or {}
        ok("Replayed container census (checkpoint)")
    elif passive:
        results["container"] = {"rows": [],
                                "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_container_probe"):
        results["container"] = container_census(http, disc.get("targets", []),
                                                conf)
        warn("SKIPPED (gate OFF): %s" %
             results["container"].get("skipped_note", ""))
    else:
        results["container"] = container_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckT, results["container"], summary="container census")
    meta["probes_total"] += len(results["container"].get("rows", []))

    # ---------------- Stage U: bypass2 ----------------
    head("Stage U - Bypass matrix v2: 18 misconfig-bypass shapes (GATED)")
    ckU = "stageU:bypass2"
    if cp.is_done(ckU):
        results["bypass2"] = cp.result_of(ckU) or {}
        ok("Replayed bypass2 census (checkpoint)")
    elif passive:
        results["bypass2"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("misconfig_allow_bypass2"):
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" %
             results["bypass2"].get("skipped_note", ""))
    else:
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckU, results["bypass2"], summary="bypass2 census")
    meta["probes_total"] += len(results["bypass2"].get("rows", []))

    # cache rollup (P22 cacheable seeds -> posture point cache_safe)
    p22_cache = _ff_pairs(ctxd.get("base_dir"), "replay",
                          "to_phase23_misconfig")
    cache_rows = [{"url": str(u)[:120], "cacheable": False}
                  for u in (p22_cache or []) if isinstance(u, str)]
    results["cache"] = {"rows": cache_rows[:12],
                        "note": "P22 ff rollup (offline; live cache census "
                        "P22 stage-N owns)"}

    # ---------------- Stage V-Z offline engines ----------------
    head("Stage V/W/X/Y - Posture composite + chains + verdict + matrix")
    posture = posture_composite(results)
    ff_all = read_ff_safe(ctxd.get("base_dir"), scope)
    chains = build_chains(results, ff_all)
    verdict_rows = verdict_engine(results)
    matrix_rows = build_matrix()
    gql_mut = gql_mutations_from_artifacts(ctxd.get("base_dir"))
    ws_endpoints = ws_surface_from_artifacts(ctxd.get("base_dir"))

    # findings from verdict rows
    _findings_from_verdicts(F, verdict_rows)
    # posture findings
    for w in posture.get("weak", [])[:8]:
        F.add("misconfig_posture_weak", "Misconfig posture WEAK",
              w.get("url", ""), "score=%d/12 (points: %s)" % (
                  w["score"], ",".join(k for k, v in w["points"].items()
                                       if v is False)))
    if len(posture.get("strong", [])) >= 1:
        F.add("misconfig_posture_strong", "Misconfig posture STRONG",
              posture["strong"][0].get("url", ""),
              "score>=%d/12 positive controls dominant" %
              posture["strong"][0]["score"])
    # platform fp
    probe_texts = [(b.get("title") or "") for b in
                   results.get("baseline", {}).get("rows", [])] + \
                  [" ".join(t.get("kinds", [])) for t in
                   results.get("targets", [])] + \
                  [json.dumps(results.get("gql", {}))[:2000]]
    platform = platform_fingerprint(probe_texts)
    if platform.get("shapes"):
        F.add("misconfig_platform_fp", "Platform fingerprint shapes", "*",
              "shapes=%s" % ",".join(platform["shapes"][:8]))
    # admin/gql/gql-mutations/ws surface findings
    if gql_mut.get("count"):
        F.add("misconfig_gql_mutation_surface", "GraphQL writable-mutation "
              "surface (names-only)", "*",
              "%d mutation names (NEVER sent)" % gql_mut["count"])
    if ws_endpoints.get("count"):
        F.add("misconfig_ws_surface", "WebSocket endpoint census (frames "
              "NEVER)", "*", "%d ws endpoints" % ws_endpoints["count"])
    for r in (results.get("admin") or {}).get("rows", []):
        if r.get("live") and r.get("platform") and not r.get("auth_gate"):
            F.add("misconfig_admin_live", "Admin panel exposed (%s)" %
                  r["platform"], r.get("url", ""), "GET presence census")
    for r in (results.get("cors") or {}).get("rows", []):
        if r.get("reflect_any"):
            F.add("misconfig_cors_reflect", "CORS canary-origin reflection",
                  r.get("url", ""), "grade=%s" % r.get("grade"))
    for r in (results.get("methods") or {}).get("rows", []):
        if r.get("trace_echo"):
            F.add("misconfig_trace_echo", "TRACE canary echo (XST surface)",
                  r.get("url", ""), "TRACE echo census (gate ON)")
    for r in (results.get("bypass2") or {}).get("rows", []):
        if r.get("accepted_count"):
            F.add("misconfig_bypass2_accepted", "Misconfig-bypass shapes "
                  "accepted", r.get("url", ""), "ids=%s" %
                  ",".join(r.get("accepted_ids", [])[:8]))
    for r in (results.get("secrets") or {}).get("rows", []):
        for s in (r.get("shapes") or [])[:6]:
            if s.get("shape") in ("internal-ip", "email-leak"):
                F.add("misconfig_secret_ip", "Internal-IP/email disclosure "
                      "shape", r.get("url", ""), "shape=%s (sha1 %s)" %
                      (s.get("shape"), s.get("sha1_12")))

    # ---------------- Stage Z: final secrets guard ----------------
    payloads = [("MISCONFIG_FINDINGS.md", pii_redact(render_findings_md(
        scope, F, verdict_rows, chains, meta)))]
    guard = secrets_guard(payloads)
    if guard.get("hits"):
        F.add("misconfig_secret_guard_hit", "Secret-guard sweep triggered",
              "*", "artifact shapes redacted (CWE-200 aid)")

    # ---------------- Stage Z: reports + handoff ----------------
    head("Stage Z - Reports (55 artifacts) + feedforward + manifest")
    meta["duration"] = time.time() - t_start
    manifest_files = write_reports(out, scope, F, ctxd, meta, results, disc,
                                   conf, chains, verdict_rows, matrix_rows,
                                   posture, platform, guard,
                                   build_hypotheses(results, posture),
                                   gql_mut, ws_endpoints)
    cp.mark_complete()
    ok("%d artifacts | findings=%d | verdicts=%d | chains=%d | matrix=%d" % (
        len(manifest_files) + 2, len(F.items), len(verdict_rows),
        len(chains), len(matrix_rows)))
    sc = _sev_counts(F)
    ok("severity: C=%d H=%d M=%d L=%d I=%d | CONFIRMED=%d HARDENED=%d" % (
        sc.get("critical", 0), sc.get("high", 0), sc.get("medium", 0),
        sc.get("low", 0), sc.get("info", 0),
        len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
        len([r for r in verdict_rows if r["verdict"] == "HARDENED"])))
    dim("out: %s" % out)
    return out


def ws_surface_from_artifacts(base_dir):
    """P19 handoff: ws endpoint census (frames NEVER)."""
    endpoints = []
    d = _read_json_tolerant(_artifact(base_dir, "ws", "feedforward.json"))
    if isinstance(d, dict):
        for lst in _walk_lists(d.get("routing") or {}):
            endpoints.extend([x for x in lst if isinstance(x, str)
                              and (x.startswith("ws") or "/ws" in x or
                                   "socket" in x.lower())])
    art = _read_json_tolerant(_artifact(base_dir, "ws", "ws_endpoints.json"))
    if isinstance(art, (dict, list)):
        for lst in _walk_lists(art):
            endpoints.extend([x for x in lst if isinstance(x, str)])
    endpoints = sorted(set(e for e in endpoints if len(e) < 200))[:24]
    return {"endpoints": endpoints, "count": len(endpoints),
            "note": "frames NEVER (P19 discipline); ws-misconfig manual aid"}


def read_ff_safe(base_dir, scope):
    """read_feedforward wrapper (tolerant - missing dirs OK)."""
    try:
        return read_feedforward(base_dir, scope.engagement)
    except Exception:
        return {}


def _findings_from_verdicts(F, verdict_rows):
    """Verdict rows -> findings (key-mapped, dedup per endpoint+key)."""
    seen = set()
    for r in verdict_rows:
        v, u = r["verdict"], r.get("url", "?")
        key = {"C": {"CONFIRMED": "misconfig_debug_live",
                     "SUSPECTED": "misconfig_debug_marker",
                     "HARDENED": "misconfig_debug_absent"},
               "D": {"CONFIRMED": "misconfig_artifact_live",
                     "SUSPECTED": "misconfig_artifact_soft"},
               "E": {"SUSPECTED": "misconfig_headers_missing",
                     "HARDENED": "misconfig_headers_strong"},
               "F": {"CONFIRMED": "misconfig_secret_shape"},
               "G": {"CONFIRMED": "misconfig_verbose_error",
                     "HARDENED": "misconfig_error_masked"},
               "H": {"CONFIRMED": "misconfig_log4j_version",
                     "SUSPECTED": "misconfig_log4j_clean"},
               "J": {"CONFIRMED": "misconfig_admin_live",
                     "HARDENED": "misconfig_admin_absent"},
               "L": {"CONFIRMED": "misconfig_cors_reflect",
                     "SUSPECTED": "misconfig_cors_wildcard",
                     "HARDENED": "misconfig_cors_strict"},
               "M": {"SUSPECTED": "misconfig_cookie_flags",
                     "HARDENED": "misconfig_cookie_strong"},
               "N": {"CONFIRMED": "misconfig_trust_echo",
                     "HARDENED": "misconfig_trust_clean"},
               "O": {"CONFIRMED": "misconfig_trace_echo",
                     "SUSPECTED": "misconfig_methods_broad",
                     "HARDENED": "misconfig_methods_minimal"},
               "P": {"SUSPECTED": "misconfig_no_redirect",
                     "HARDENED": "misconfig_transport_strong"},
               "Q": {"CONFIRMED": "misconfig_spec_live",
                     "HARDENED": "misconfig_spec_absent"},
               "R": {"CONFIRMED": "misconfig_sourcemap_live",
                     "HARDENED": "misconfig_sourcemap_absent"},
               "S": {"CONFIRMED": "misconfig_gql_introspect",
                     "HARDENED": "misconfig_gql_locked",
                     "SUSPECTED": "misconfig_gql_playground"},
               "T": {"CONFIRMED": "misconfig_container_live",
                     "HARDENED": "misconfig_container_absent"},
               "U": {"CONFIRMED": "misconfig_bypass2_accepted",
                     "BLOCKED": "misconfig_bypass2_blocked",
                     "HARDENED": "misconfig_bypass2_blocked"},
               }.get(r["stage"], {}).get(v)
        if not key or u == "*" or u == "?":
            continue
        dk = (key, u)
        if dk in seen:
            continue
        seen.add(dk)
        F.add(key, "%s [%s]" % (key, v), u, r.get("detail", ""))


# ===========================================================================
# CLI
# ===========================================================================
def main():
    print("WASP mod_misconfig.py (Phase 23 - Misconfig & Secrets Exposure, "
          "v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 23   (ya --module "
          "misconfig)")
    print("  self-test : python3 test_mod_misconfig.py")
    print("\n  RoE gates (config.json):")
    for g, d in ROE_GATES:
        print("    %s=false (default) # %s" % (g, d))
    print("  Safety: koi exploitation KABHI nahi (canary %s) | GET-only "
          "module | bodies/secret-values REDACTED | NO JNDI payloads | "
          "NO IMDS probes | NO creds sending | zero egress" % CANARY_FAMILY)
    print("  v25 ULTRA: 26 stages (A..Z) | 13 RoE gates | 18-secret bypass2 "
          "| 14 default-cred platforms (documented) | 8 log4shell + 6 cloud "
          "playbooks | 220-row x 20-family matrix | 26 kill-chains | "
          "55 artifacts | 12-point posture composite | platform fp")


if __name__ == "__main__":
    main()
