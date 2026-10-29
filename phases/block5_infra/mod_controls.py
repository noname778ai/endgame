#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_controls.py  |  Phase 25 - Security Controls Validation &
            Remediation (ControlsInv/HeaderCtl/WAF-Ctl/Rate-Ctl/CORS-Ctl/
            Cookie-Ctl/AuthGate/Methods/ErrorMask/TLS/CSP/Echo/Patching/
            Observability/Secrets-Hygiene/API-Ctl/CICD-Guard/Edge-Trust/
            Cache-Ctl/Bypass2/Remediation-Engine)
=======================================================================================
v30.0.0 FULL ULTRA PRO MAX (koi ek line ki bhi kami nahi - all to all
techniques: hacking hidden secrets + old & new security bypasses + advanced
level secret techniques - SAB INERT detection-only + RoE-gated). Authorized
security testing ONLY. Scope firewall + rate limiter + request budget +
evidence + checkpoint sab wasp_core se inherit hote hain, isliye har census
request scope-check, rate-limit aur budget ke andar hi jaati hai.

KYA KARTA HAI
  P25 = framework ka CONTROL VALIDATION phase. P2..P24 ne flaws dhoonde;
  P25 verify karta hai ki DEFENSE CONTROLS exist karte hain AUR kaam karte
  hain - aur jo control gap mila use prioritized REMEDIATION plan me convert
  karta hai (P1..P5 priority + effort + owner + verification kill-test).
  Controls declared hona kaafi nahi - ENFORCED hona zaroori hai: WAF header
  dikhana alag cheez, canary block karna alag; CSP header likhna alag,
  unsafe-inline na hona alag; rate-limit docs alag cheez, 429 shape alag.
  Ye sab INERT differentials se verify hota hai - koi attack KABHI nahi.
  -> 26 stages (A..Z):

    A. Controls surface disc.  - 20-module feedforward (P23 misconfig flags
                                  + P24 posture/provider + P22 cacheable/
                                  stuffing-posture + P9 session + P11
                                  access + P12 inject + P15 ssrf + P18 gql
                                  + P19 ws + P20 logic + P21 authz + P7 js
                                  + P5 content + P6 tech + P4 headers +
                                  P17 api + P10 sessions + P2 endpoints +
                                  P3/P8) + artifact mining + 46-path cold
                                  pool + real-vs-cold ranking
    B. Baseline + WAF-declared - home marker + soft-404 + WAF fingerprint
                                  (declared control inventory)
    C. Header controls audit   - 18 hardening header controls presence +
                                  value grading (CSP/HSTS/XFO/XCTO/Referrer/
                                  Permissions/COOP/COEP/CORP/Cache-Ctl...) +
                                  10 disclosure headers audit (Server/X-Powered)
    D. WAF enforcement diff.   - GATED controls_allow_waf_probe: INERT canary
                                  marker-string census (synthetic waspP25
                                  token, NO attack payloads) -> block-shape
                                  grading (declared-vs-enforced differential)
    E. Rate-limit control      - GATED controls_allow_rate_probe: 6-sequential
                                  HARD cap canary GETs (>=0.4s spacing, single
                                  endpoint) -> 429/Retry-After shape census;
                                  full-burst wave DOCUMENTED-ONLY playbook
    F. CORS control validation - GATED controls_allow_cors_probe: 4 canary
                                  Origins (.invalid TLD) -> strict/reflect
                                  grading (P23/P24-compatible)
    G. Cookie/session controls - Set-Cookie flag census (Secure/HttpOnly/
                                  SameSite/Prefix/Expires) per-endpoint
                                  hardening grade (P10 handoff cross-check)
    H. Auth-gate control       - GATED controls_allow_authgate_probe: protected
                                  path pool par anon GET differential ->
                                  uniform 302/401/403 = gate enforced;
                                  200-leak = control gap (no creds KABHI)
    I. Method-control census   - GATED controls_allow_method_probe: OPTIONS
                                  Allow-header census + advertised destructive
                                  methods flag (koi destructive method sent
                                  KABHI nahi - wasp_core L4 double-guard)
    J. Error-masking control   - GATED controls_allow_error_probe: canary-param
                                  probes -> verbose vs generic error shapes
                                  (RequestID/traceback/framework marks)
    K. TLS/transport controls  - passive GET: HSTS/preload/max-age grade +
                                  http->https redirect shape + mixed-content
                                  shapes (CWE-319 aid)
    L. CSP deep grading        - offline CSP directive parser: default-src/
                                  object-src/base-uri/frame-ancestors/
                                  script-src + unsafe-inline/unsafe-eval/
                                  wildcard/nonce/hash detection -> strict/
                                  partial/decorative grade
    M. Echo-sanitization ctl   - GATED controls_allow_echo_probe: synthetic
                                  waspP25 marker echo census (NO XSS payloads)
                                  -> reflected/raw/encoded/stripped grading
    N. Dependency/patch ctl    - versioned tech shapes -> EOL/stale advisory
                                  windows (P6 cross-check, documented-only)
    O. Observability controls  - X-Request-Id/X-Trace/correlation-header
                                  presence census (audit-log enablement aid,
                                  documented-only log review)
    P. Secrets-hygiene ctl     - sampled pages par secret-shape re-scan
                                  (sha1-12 REDACTED) -> rotation-need flags
                                  (P7/P23/P24 cross-check)
    Q. API-surface controls    - GATED controls_allow_api_probe: spec exposure
                                  census + GQL introspection-off control +
                                  WS origin-policy rollup (names-only, NEVER
                                  mutations/frames)
    R. CI/CD + IaC guards      - GATED controls_allow_cicd_probe: artifact
                                  presence census (P24 cross-check) ->
                                  guardrail-gap flags
    S. Edge trust-header ctl   - GATED controls_allow_edge_probe: X-Forwarded-
                                  Host/X-Original-URL echo differential ->
                                  edge-strip control validated ya gap
    T. Cache-control validation- GATED controls_allow_cache_probe: sensitive
                                  pages par cacheability shapes (no-store/
                                  private vs public/max-age) + CDN interplay
                                  (P22/P24 cross-check)
    U. Bypass2 control matrix  - 22 SECRET control-bypass shapes (GATED
                                  controls_allow_bypass2): path-normalization
                                  (//, /./, /../, %2e%2e, ;params, %09, case,
                                  trailing-slash, double-encode), header-trust
                                  (X-Original-URL, X-Rewrite-URL, X-Forwarded-
                                  Host, X-Forwarded-For, Host, X-Custom-IP),
                                  control-flavored (Referer-trust, HEAD
                                  differential, Range partial, method-override
                                  ABSENT check, marker-param) - GET-only
                                  403->2xx differential, canary waspP25.
                                  ACCEPTED = control gap (CONFIRMED);
                                  REJECTED = control enforced (HARDENED)
    V. Controls posture comp.  - per-endpoint 16-point composite (headers_
                                  present/csp_strict/waf_enforced/rate_limited/
                                  cors_strict/cookies_hardened/auth_gated/
                                  methods_locked/errors_masked/tls_strict/
                                  echo_sanitized/deps_patched/observability_
                                  on/secrets_absent/api_locked/bypass2_blocked)
    W. Cross-module chains     - CH01..CH30 control-gap kill-chains
    X. Verdict engine          - 6-class ladder (CONFIRMED=control-gap,
                                  SUSPECTED/HARDENED=control-enforced,
                                  BLOCKED/SKIPPED/NOISE) multi-signal
    Y. Technique matrix        - 250 rows x 24 families + CWE + MITRE map
    Z. Reports/artifacts       - 62 artifacts: findings.json,
                                  CONTROLS_FINDINGS.md, CONTROLS_MATRIX.txt,
                                  REMEDIATION_PLAN.md (P1..P5 + owner/effort/
                                  verification), HARDENING_CHECKLIST.md
                                  (CIS-style), control-catalog, drift
                                  baseline, census JSONs, test-plan (kill
                                  tests), exec summary, kickoff, playbooks +
                                  feedforward (P26/P32/P11/P12/P9/P23/P24)
                                  + MANIFEST + RWX-tree finalize

VERDICT LADDER (6-class, P12..P24-compatible - P25 orientation: HARDENED =
  control VERIFIED working; CONFIRMED = control GAP)
  CONFIRMED   -> control-gap multi-signal proof (headers absent on live page;
                 CSP decorative (unsafe-inline/wildcard); WAF declared par
                 canary block-shape absent; rate shape absent; CORS canary
                 reflect; auth-gate 200-leak; verbose error; raw echo;
                 EOL dep shape; artifact live; edge echo; cacheable
                 sensitive; bypass2 403->2xx accepted)
  SUSPECTED   -> partial/single signal (1 header missing, dep version
                 unparseable, spec live, token param)
  HARDENED    -> control ENFORCED verified (full header posture; strict CSP;
                 WAF block-shape; 429 shape; CORS strict; cookies hardened;
                 auth uniform 30x/40x; methods locked; errors generic; echo
                 stripped; deps current; observability headers on; bypass2
                 rejected)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (controls = 'defense validation' surface - P15..P24 jitni
  strict discipline, plus: koi bhi control-check sirf INERT differential)
  * 100% INERT: koi exploitation KABHI nahi hota. Har probe synthetic canary
    identifiers (waspP25 family) use karta hai; artifact bodies KABHI store
    nahi hote - sirf status/len/sha1-12/shape-flags. Secret VALUES ka sirf
    sha1-12 + shape-name store hota hai, value itself REDACTED (PII regex
    sweep har detail par).
  * GET-ONLY MODULE: saare probes GET/HEAD/OPTIONS - koi POST/PUT/DELETE/
    PATCH KABHI (module-wide assert + wasp_core LAYER-4 read-only
    double-guard). Method-control stage OPTIONS census karta hai - Allow
    header se ADVERTISED methods flag karta hai, method SEND nahi karta.
  * NO ATTACK PAYLOADS: WAF/echo stages sirf synthetic waspP25 marker
    strings use karte hain - koi XSS/SQLi/RCE payload string network par
    KABHI nahi jaati (payload catalogs sirf DOCUMENTED-ONLY playbooks me).
  * RATE BURST FORBIDDEN: rate-control stage 6-sequential HARD cap + >=0.4s
    spacing (single canary endpoint); parallel burst / hammer KABHI nahi
    (full-burst = documented manual wave).
  * NO CREDS/STUFFING: auth-gate stage anon differential hai - koi
    credential/brute/stuff KABHI network par nahi jaata (FORBIDDEN-AUTO).
  * NO THIRD-PARTY EGRESS: har HTTP probe scope-check se pehle blocked
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
                           module_ctx, save_json, save_text, load_json, write_manifest,
                           write_feedforward, read_feedforward,
                           info, ok, warn, err, head, dim, truncate,
                           now_iso, host_of, is_soft404, waf_signature,
                           title_of, interrupted, rand_str, Resp)
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 25")
    sys.exit(1)

NAME = "controls"
PHASE = "25-controls"
PLAN_VERSION = "30.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    # ---- caps ----
    "controls_paths_cap": 40,        # kitne ranked targets census me jaayenge
    "controls_probe_cap": 24,        # per-stage probe budget
    "controls_cold_paths": 46,       # cold-start pool size
    "controls_authgate_paths": 20,   # auth-gate control pool size
    "controls_artifact_paths": 22,   # CI/CD + IaC guard pool size
    "controls_spec_paths": 12,       # api-spec control pool size
    "controls_bypass2_cap": 22,      # bypass2 shapes per target
    "controls_secret_cap": 40,       # secret-shape records cap (sha1-only)
    "controls_depth": 3,             # discovery link-follow depth
    "controls_rate_cap": 6,          # rate-control sequential HARD cap
    "controls_rate_gap": 0.4,        # rate-control min spacing (sec)
    # ---- RoE GATES (sab default OFF - control-differential probes) ----
    "controls_allow_waf_probe": False,      # GATE: WAF canary enforcement diff
    "controls_allow_rate_probe": False,     # GATE: rate-limit shape census
    "controls_allow_cors_probe": False,     # GATE: Origin canary CORS diff
    "controls_allow_authgate_probe": False, # GATE: anon auth-gate differential
    "controls_allow_method_probe": False,   # GATE: OPTIONS/Allow census
    "controls_allow_error_probe": False,    # GATE: error-masking canary probes
    "controls_allow_echo_probe": False,     # GATE: echo-sanitization census
    "controls_allow_api_probe": False,      # GATE: spec/gql/ws control census
    "controls_allow_cicd_probe": False,     # GATE: CI/CD + IaC guard census
    "controls_allow_edge_probe": False,     # GATE: trust-header echo diff
    "controls_allow_cache_probe": False,    # GATE: cacheability validation
    "controls_allow_bypass2": False,        # GATE: 22-secret bypass2 matrix
}

# RoE gate registry (CLI/report me use hota hai)
ROE_GATES = [
    ("controls_allow_waf_probe",      "WAF canary enforcement differential"),
    ("controls_allow_rate_probe",     "rate-limit shape census (6-seq cap)"),
    ("controls_allow_cors_probe",     "Origin canary CORS differential"),
    ("controls_allow_authgate_probe", "anon auth-gate differential"),
    ("controls_allow_method_probe",   "OPTIONS/Allow-header census"),
    ("controls_allow_error_probe",    "error-masking canary probes"),
    ("controls_allow_echo_probe",     "echo-sanitization canary census"),
    ("controls_allow_api_probe",      "spec/gql/ws control census"),
    ("controls_allow_cicd_probe",     "CI/CD + IaC guardrail census"),
    ("controls_allow_edge_probe",     "trust-header echo differential"),
    ("controls_allow_cache_probe",    "cacheability validation census"),
    ("controls_allow_bypass2",        "22-secret control-bypass2 matrix"),
]

CANARY_FAMILY = "waspP25"

# ---------------------------------------------------------------------------
# PATH POOLS (cold-start discovery - control-check shaped URLs)
# ---------------------------------------------------------------------------
COLD_PATHS = [
    "/", "/index.html", "/login", "/signin", "/auth", "/logout", "/register",
    "/signup", "/admin", "/admin/", "/dashboard", "/profile", "/settings",
    "/account", "/user", "/users", "/api", "/api/", "/api/v1", "/api/v2",
    "/graphql", "/graphiql", "/ws", "/socket.io", "/docs", "/swagger",
    "/swagger.json", "/openapi.json", "/api-docs", "/health", "/healthz",
    "/status", "/metrics", "/debug", "/env", "/errors", "/error", "/403",
    "/404", "/500", "/strong", "/hardened", "/security", "/security.txt",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/cdn-cgi/trace",
    "/cacheable", "/download", "/share",
]

# auth-gate control pool (stage H - anon differential, no creds KABHI)
AUTHGATE_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/dashboard", "/profile", "/settings", "/account", "/billing",
    "/api/admin", "/api/admin/users", "/api/me", "/api/profile",
    "/api/settings", "/internal", "/internal/admin", "/console",
    "/manage", "/controlpanel", "/wp-admin/", "/user/profile",
]

# CI/CD + IaC guard paths (stage R pool - presence-only, bodies REDACTED)
GUARD_PATHS = [
    "/.github/workflows/", "/.gitlab-ci.yml", "/Jenkinsfile",
    "/.circleci/config.yml", "/azure-pipelines.yml", "/bitbucket-pipelines.yml",
    "/Dockerfile", "/docker-compose.yml", "/k8s.yaml", "/deployment.yaml",
    "/terraform.tfstate", "/terraform.tfvars", "/main.tf", "/.env",
    "/.env.bak", "/kubeconfig", "/helm/values.yaml", "/appspec.yml",
    "/cloudbuild.yaml", "/.travis.yml", "/build.gradle", "/pom.xml",
]

# api-spec control paths (stage Q pool)
SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
    "/v2/swagger.json", "/v3/api-docs", "/api-docs", "/api-docs/swagger.json",
    "/api/swagger.json", "/swagger", "/swagger-ui", "/docs", "/redoc",
]

# cache-validation paths (stage T pool - sensitive-page shapes)
CACHE_PATHS = [
    "/", "/login", "/account", "/profile", "/settings", "/dashboard",
    "/api/me", "/admin", "/download", "/share", "/billing",
]

# ---------------------------------------------------------------------------
# HEADER CONTROL TABLE (stage C - 18 hardening + 10 disclosure)
# format: (control-name, header, present-rx, strict-rx, fix-note)
# ---------------------------------------------------------------------------
HEADER_CONTROLS = [
    ("csp", "Content-Security-Policy", r"(?i)content-security-policy:",
     r"(?i)content-security-policy:\s*(?!$).+",
     "CSP add karo (default-src 'self'; no unsafe-inline)"),
    ("hsts", "Strict-Transport-Security", r"(?i)strict-transport-security:",
     r"(?i)strict-transport-security:\s*max-age=\d{5,}",
     "HSTS max-age>=31536000; includeSubDomains; preload"),
    ("xfo", "X-Frame-Options", r"(?i)x-frame-options:",
     r"(?i)x-frame-options:\s*(DENY|SAMEORIGIN)\s*$",
     "X-Frame-Options DENY/SAMEORIGIN"),
    ("xcto", "X-Content-Type-Options", r"(?i)x-content-type-options:",
     r"(?i)x-content-type-options:\s*nosniff\s*$",
     "X-Content-Type-Options: nosniff"),
    ("referrer", "Referrer-Policy", r"(?i)referrer-policy:",
     r"(?i)referrer-policy:\s*(no-referrer|strict-origin|"
     r"strict-origin-when-cross-origin|same-origin)",
     "Referrer-Policy strict-origin-when-cross-origin (ya tighter)"),
    ("permissions", "Permissions-Policy", r"(?i)permissions-policy:",
     r"(?i)permissions-policy:\s*\S+",
     "Permissions-Policy: sensitive features deny-by-default"),
    ("coop", "Cross-Origin-Opener-Policy", r"(?i)cross-origin-opener-policy:",
     r"(?i)cross-origin-opener-policy:\s*(same-origin|"
     r"same-origin-allow-popups)",
     "COOP: same-origin"),
    ("coep", "Cross-Origin-Embedder-Policy", r"(?i)cross-origin-embedder-policy:",
     r"(?i)cross-origin-embedder-policy:\s*(require-corp|credentialless)",
     "COEP: require-corp"),
    ("corp", "Cross-Origin-Resource-Policy", r"(?i)cross-origin-resource-policy:",
     r"(?i)cross-origin-resource-policy:\s*(same-origin|same-site)",
     "CORP: same-origin/same-site"),
    ("cache-ctl", "Cache-Control", r"(?i)cache-control:",
     r"(?i)cache-control:\s*(no-store|no-cache|private|max-age=0)",
     "Sensitive pages: Cache-Control no-store/private"),
    ("xss-prot", "X-XSS-Protection", r"(?i)x-xss-protection:",
     r"(?i)x-xss-protection:\s*1; mode=block",
     "Legacy X-XSS-Protection 1; mode=block (CSP ke saath)"),
    ("xaclo", "X-Permitted-Cross-Domain-Policies", r"(?i)x-permitted-cross-domain",
     r"(?i)x-permitted-cross-domain-policies:\s*none",
     "X-Permitted-Cross-Domain-Policies: none"),
    ("expect-ct", "Expect-CT", r"(?i)expect-ct:", r"(?i)expect-ct:.+",
     "Expect-CT (legacy; HSTS ke saath review)"),
    ("nel", "NEL", r"(?i)\bnel:", r"(?i)nel:\s*\{",
     "NEL reporting on karo (observability aid)"),
    ("report-to", "Report-To", r"(?i)report-to:", r"(?i)report-to:\s*\{",
     "Report-To endpoint define karo (CSP/NEL reporting)"),
    ("csrf-cookie", "Set-Cookie(SameSite)", r"(?i)set-cookie:",
     r"(?i)set-cookie:.*samesite=(strict|lax)",
     "Cookies par SameSite attribute set karo"),
    ("origin-agent", "Origin-Agent-Cluster", r"(?i)origin-agent-cluster:",
     r"(?i)origin-agent-cluster:\s*\?1",
     "Origin-Agent-Cluster: ?1 (process isolation aid)"),
    ("crossorig-embed", "Document-Policy", r"(?i)document-policy:",
     r"(?i)document-policy:\s*\S+",
     "Document-Policy review (feature policy aid)"),
]
DISCLOSURE_HEADERS = [
    ("server-banner", re.compile(r"(?i)^server:\s*(.+)")),
    ("x-powered", re.compile(r"(?i)^x-powered-by:\s*(.+)")),
    ("aspnet-version", re.compile(r"(?i)^x-aspnet-version:\s*(.+)")),
    ("aspnetmvc-version", re.compile(r"(?i)^x-aspnetmvc-version:\s*(.+)")),
    ("x-runtime", re.compile(r"(?i)^x-runtime:\s*(.+)")),
    ("x-version", re.compile(r"(?i)^x-version:\s*(.+)")),
    ("generator-meta", re.compile(r"(?i)<meta[^>]+name=[\"']generator[\"']"
                                  r"[^>]+content=[\"']([^\"']+)")),
    ("via-hop", re.compile(r"(?i)^via:\s*(.+)")),
    ("forwarded", re.compile(r"(?i)^forwarded:\s*(.+)")),
    ("x-host", re.compile(r"(?i)^x-host:\s*(.+)")),
]

# ---------------------------------------------------------------------------
# WAF SHAPES (stage D - enforcement differential)
# ---------------------------------------------------------------------------
WAF_BLOCK_RX = [
    ("cf-waf-block", re.compile(r"(?i)(cloudflare|cf-ray).*(error 1020|"
                                r"access denied|attention required)", re.S)),
    ("aws-waf-block", re.compile(r"(?i)(aws\s*waf|403).*(blocked|"
                                 r"forbidden request)", re.S)),
    ("akamai-ref", re.compile(r"(?i)(reference #\d+\.[0-9a-f]+|"
                              r"akamai.*access denied)", re.S)),
    ("imperva", re.compile(r"(?i)(incapsula|imperva|request unsuccessful)")),
    ("sucuri", re.compile(r"(?i)(sucuri|cloudproxy.*(access denied|blocked))")),
    ("f5-asm", re.compile(r"(?i)(the requested url was rejected|"
                          r"f5.*support id)")),
    ("modsec", re.compile(r"(?i)(mod_security|modsecurity.*(not allowed|"
                          r"blocked))")),
    ("generic-block", re.compile(r"(?i)(request blocked|access denied|"
                                 r"forbidden|not allowed|rejected)")),
]
WAF_DECL_RX = [
    ("cf-declared", re.compile(r"(?i)(cf-ray|cf-cache-status|server: cloudflare)")),
    ("aws-declared", re.compile(r"(?i)(x-amzn-requestid|x-amz-cf-id|awswaf)")),
    ("akamai-declared", re.compile(r"(?i)(x-akamai|server: akamai)")),
    ("imperva-declared", re.compile(r"(?i)(x-iinfo|incapsula)")),
    ("sucuri-declared", re.compile(r"(?i)(x-sucuri-id|sucuri)")),
    ("f5-declared", re.compile(r"(?i)(x-waasinfo|x-f5|bigip)")),
    ("modsec-declared", re.compile(r"(?i)(x-modsec|server:.*mod_security)")),
]

# ---------------------------------------------------------------------------
# RATE-LIMIT SHAPES (stage E)
# ---------------------------------------------------------------------------
RATE_SHAPE_RX = [
    ("429-status", re.compile(r"(?i)\b429\b")),
    ("retry-after", re.compile(r"(?i)\bretry-after:\s*\d+")),
    ("ratelimit-hdr", re.compile(r"(?i)\bratelimit-(limit|remaining|reset):")),
    ("x-ratelimit", re.compile(r"(?i)\bx-ratelimit-(limit|remaining|reset):")),
    ("throttle-body", re.compile(r"(?i)(rate limit|too many requests|"
                                 r"throttl|quota exceeded)")),
    ("cf-throttle", re.compile(r"(?i)(error 1015|you are being rate limited)")),
]

# ---------------------------------------------------------------------------
# CORS / ERROR / ECHO / AUTHGATE SHAPES (stages F/J/M/H)
# ---------------------------------------------------------------------------
CORS_CANARY_ORIGINS = [
    "https://sub.evil.invalid", "https://evil.invalid", "null",
    "https://same.evil.invalid",
]
ERROR_VERBOSE_RX = [
    ("request-id", re.compile(r"(?i)(request id|requestid|x-request-id)[:=]"
                              r"\s*[0-9a-f-]{6,}")),
    ("traceback", re.compile(r"(?i)(traceback \(most recent call last\)|"
                             r"stack trace|at [a-z0-9_.]+\([a-z0-9_.]+:\d+\))")),
    ("sql-shape", re.compile(r"(?i)(sql syntax|mysql|postgres|sqlite|"
                             r"ora-\d{5}|sqlstate)")),
    ("path-disclosure", re.compile(r"(?i)(/[a-z0-9_.-]+/[a-z0-9_.-]+/"
                                   r"[a-z0-9_.-]+\.(py|js|php|rb|java|go))")),
    ("framework-mark", re.compile(r"(?i)(django debug|laravel|whoops|"
                                  r"stackify|spring boot|actuator|"
                                  r"asp\.net|.net framework|node\.js)")),
    ("exception-class", re.compile(r"(?i)(exception|error):\s*[A-Za-z_]+"
                                   r"(Error|Exception)")),
    ("internal-ip", re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                               r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                               r"192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("port-stack", re.compile(r"(?i)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                              r":\d{2,5}\b")),
    ("debug-token", re.compile(r"(?i)(debug|trace|verbose)[:=]\s*true")),
    ("env-leak", re.compile(r"(?i)(HOME=|PATH=|PWD=|USER=|SHELL=)")),
]
AUTHGATE_SHAPES = [
    ("redirect-30x", re.compile(r"(?i)^30[1278]$")),
    ("401-unauth", re.compile(r"(?i)^401$")),
    ("403-forbidden", re.compile(r"(?i)^403$")),
    ("login-body", re.compile(r"(?i)(sign in|log ?in|authenticate|"
                              r"password|credentials)")),
]
ECHO_SHAPES = [
    ("raw-reflected", re.compile(r"(?i)waspP25(echo)?[0-9a-z]*<")),
    ("encoded-reflected", re.compile(r"(?i)(&lt;|%3C)waspP25|waspP25[0-9a-z]*"
                                     r"(&gt;|%3E)")),
    ("stripped", re.compile(r"^(?:(?!waspP25).)*$", re.I)),
]

# ---------------------------------------------------------------------------
# OBSERVABILITY / DEPS / SECRETS TABLES (stages O/N/P)
# ---------------------------------------------------------------------------
OBSERVABILITY_RX = [
    ("x-request-id", re.compile(r"(?i)\bx-request-id:\s*\S+")),
    ("x-trace-id", re.compile(r"(?i)\bx-trace-id:\s*\S+")),
    ("x-correlation-id", re.compile(r"(?i)\bx-correlation-id:\s*\S+")),
    ("x-amzn-trace", re.compile(r"(?i)\bx-amzn-trace-id:\s*\S+")),
    ("sentry-trace", re.compile(r"(?i)\bsentry-trace:\s*\S+")),
    ("traceparent", re.compile(r"(?i)\btraceparent:\s*\S+")),
    ("x-response-time", re.compile(r"(?i)\bx-response-time:\s*\S+")),
    ("server-timing", re.compile(r"(?i)\bserver-timing:\s*\S+")),
]
DEP_VERSION_ROWS = [
    ("jquery-stale", re.compile(r"(?i)jquery[./-@ ](\d+)\.(\d+)(?:\.(\d+))?"),
     lambda m: (int(m.group(1)), int(m.group(2) or 0)) < (3, 5),
     "jQuery<3.5 XSS window (CVE-2020-11022/11023)"),
    ("bootstrap-stale", re.compile(r"(?i)bootstrap[./-@ ](\d+)\.(\d+)"),
     lambda m: (int(m.group(1)), int(m.group(2) or 0)) < (4, 6),
     "Bootstrap<4.6/5.0 XSS advisory window"),
    ("angularjs-eol", re.compile(r"(?i)angular(?:js)?[./-@ ]1\.(\d+)\.(\d+)"),
     lambda m: True,
     "AngularJS 1.x EOL (unpatched since 2022)"),
    ("react-legacy", re.compile(r"(?i)react[./-@ ](?:0\.|1[0-5]\.)"),
     lambda m: True, "React<16 legacy advisory window"),
    ("vue-legacy", re.compile(r"(?i)vue[./-@ ](?:0\.|1\.|2\.[0-5])"),
     lambda m: True, "Vue<2.6 advisory window"),
    ("php-eol", re.compile(r"(?i)php[/ ](\d+)\.(\d+)"),
     lambda m: (int(m.group(1)), int(m.group(2) or 0)) < (8, 1),
     "PHP<8.1 EOL (no security fixes)"),
    ("node-eol", re.compile(r"(?i)node(?:\.js)?[/ ]v?(\d+)\."),
     lambda m: int(m.group(1)) < 18, "Node<18 EOL window"),
    ("nginx-stale", re.compile(r"(?i)nginx[/ ](\d+)\.(\d+)\.(\d+)"),
     lambda m: (int(m.group(1)), int(m.group(2) or 0)) < (1, 25),
     "nginx<1.25 (older stable line; review advisories)"),
    ("apache-path", re.compile(r"(?i)apache[/ ](\d+)\.(\d+)\.(\d+)"),
     lambda m: (int(m.group(1)), int(m.group(2) or 0)) < (2, 4, 60)
     if m.group(3) else (int(m.group(1)), int(m.group(2) or 0)) < (2, 4),
     "Apache httpd advisory window (CVE-2021-41773 family)"),
    ("iis-legacy", re.compile(r"(?i)(microsoft-iis[/ ]([5-7])\.)"),
     lambda m: True, "IIS<=7 legacy platform"),
    ("tomcat-stale", re.compile(r"(?i)tomcat[/ ]([89])\."),
     lambda m: True, "Tomcat 8/9 older line (review advisories)"),
    ("openssl-stale", re.compile(r"(?i)openssl[/ ]1\.(0|1)\."),
     lambda m: True, "OpenSSL 1.0/1.1 EOL window"),
]
SECRET_SHAPES = [
    ("aws-access-key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("gcp-api-key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("azure-conn-key", re.compile(r"(?i)(AccountKey=[A-Za-z0-9+/=]{40,})")),
    ("sas-token", re.compile(r"(?i)(sig=[0-9a-zA-Z%]{20,})")),
    ("firebase-url", re.compile(r"(https://[a-z0-9-]+\.firebaseio\.com)")),
    ("private-key", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("jwt", re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
                       r"[A-Za-z0-9_-]{5,})")),
    ("slack-token", re.compile(r"(xox[baprs]-[0-9A-Za-z-]{10,})")),
    ("gh-token", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{30,})\b")),
    ("stripe-key", re.compile(r"\b((?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,})\b")),
    ("twilio-key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("sendgrid-key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b")),
    ("mailgun-key", re.compile(r"\b(key-[0-9A-Za-z]{30,})\b")),
    ("db-url-creds", re.compile(r"(?i)((?:postgres|mysql|mongodb(?:\+srv)?)://"
                                r"[^:/\s]+:[^@/\s]+@[^\s]+)")),
    ("basic-auth-url", re.compile(r"(https?://[^/\s:]+:[^@\s/]+@)")),
    ("kube-config", re.compile(r"(?i)(kubeconfig|kubernetes.*serviceaccount)")),
    ("ssh-key-shape", re.compile(r"(ssh-rsa AAAA[0-9A-Za-z+/]{40,})")),
    ("api-key-param", re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?token)"
                                 r"[=:]\s*[A-Za-z0-9_-]{16,}")),
    ("bearer-token", re.compile(r"(?i)(bearer\s+[A-Za-z0-9._-]{20,})")),
    ("auth-cookie", re.compile(r"(?i)(session|auth|sid)[_=]\s*"
                               r"[A-Za-z0-9+/=]{20,}")),
    ("internal-host", re.compile(r"(?i)((?:https?://)?(?:[a-z0-9-]+\.)?"
                                 r"(?:internal|intranet|corp|local)[^\"\s<]*)")),
    ("ip-port-shape", re.compile(r"\b((?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
                                 r"\.\d{1,3}\.\d{1,3}:\d{2,5})\b")),
    ("email-internal", re.compile(r"([A-Za-z0-9._%+-]+@(?:internal|corp|"
                                  r"company)\.[a-z]{2,})", re.I)),
    ("presigned-url", re.compile(r"(X-Amz-Signature=[0-9a-f]{16,})")),
    ("gcp-sa-json", re.compile(r"(\"type\":\s*\"service_account\")")),
    ("docker-cfg", re.compile(r"(\"auths\":\s*\{)")),
    ("htpasswd", re.compile(r"([a-z0-9._-]+:\$?(?:apr1|\d+)\$[A-Za-z0-9/+=.]{8,})")),
    ("password-field", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*"
                                  r"[\"']?[A-Za-z0-9!@#$%^&*_-]{6,}")),
    ("secret-param", re.compile(r"(?i)(secret|client_secret)\s*[:=]\s*"
                                r"[A-Za-z0-9_-]{16,}")),
    ("token-param", re.compile(r"(?i)(token|access_token)\s*[:=]\s*"
                               r"[A-Za-z0-9._-]{16,}")),
]

# ===========================================================================
# SEVERITY HINTS (v30) - key -> (severity, cvss_hint, why_it_matters)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / surface ----
    "controls_endpoint_live":    ("info", 0.0, "Control-check target live mila "
        "- poora P25 engine ab is surface par chalega (targeting aid)."),
    "controls_candidate_path":   ("info", 0.0, "Control candidate path mined "
        "(ff/cold pool) - ranking ke through census me jaayega."),
    # ---- headers (stage C) ----
    "controls_headers_missing":  ("medium", 5.3, "Hardening header controls "
        "absent (CSP/HSTS/XFO family) - browser-enforced defense layer off; "
        "header middleware fix (HARDENING_CHECKLIST.md HC-01)."),
    "controls_headers_strong":   ("info", 0.0, "Hardening header controls "
        "present + strict values - positive control verified."),
    "controls_disclosure_hdr":   ("low", 3.1, "Disclosure header shape "
        "(Server/X-Powered-By banner) - tech fingerprint aid; banner-strip "
        "fix (HC-02)."),
    # ---- WAF (stage D) ----
    "controls_waf_enforced":     ("info", 0.0, "WAF block-shape canary par "
        "verified - edge control enforced (positive)."),
    "controls_waf_declared_only": ("medium", 5.8, "WAF declared (marker/headers) "
        "par canary block-shape absent - declared-vs-enforced gap; rule-tuning "
        "fix (HC-03)."),
    "controls_waf_absent":       ("low", 3.4, "Koi WAF marker/block shape nahi "
        "- edge filtering control absent (hosting-WAF review aid)."),
    # ---- rate (stage E) ----
    "controls_rate_enforced":    ("info", 0.0, "Rate-limit shape verified "
        "(429/Retry-After/throttle headers) - throttle control enforced."),
    "controls_rate_gap":         ("medium", 6.0, "Rate-limit shape absent "
        "(bounded sequential canary) - throttling control gap; rate middleware "
        "fix (HC-04). Full-burst wave documented-only."),
    # ---- CORS (stage F) ----
    "controls_cors_reflect":     ("high", 8.1, "ACAO canary-origin reflection "
        "- cross-origin read control gap; origin-allowlist fix (HC-05)."),
    "controls_cors_strict":      ("info", 0.0, "CORS strict (canary origins "
        "rejected) - positive control verified."),
    # ---- cookies (stage G) ----
    "controls_cookies_weak":     ("medium", 6.3, "Session cookie flags weak "
        "(Secure/HttpOnly/SameSite missing) - session-hygiene gap; cookie "
        "middleware fix (HC-06)."),
    "controls_cookies_hardened": ("info", 0.0, "Cookie flags hardened "
        "(Secure+HttpOnly+SameSite) - positive control verified."),
    # ---- auth-gate (stage H) ----
    "controls_authgate_gap":     ("critical", 9.1, "Protected path anon-GET "
        "200-leak - auth-gate control GAP (no creds used, INERT differential); "
        "deny-by-default middleware fix (HC-07)."),
    "controls_authgate_ok":      ("info", 0.0, "Protected paths uniformly "
        "30x/40x gated - auth control enforced."),
    # ---- methods (stage I) ----
    "controls_methods_advertised": ("medium", 5.9, "Destructive methods "
        "advertised (Allow header) - method-control review; method-allowlist "
        "fix (HC-08)."),
    "controls_methods_locked":   ("info", 0.0, "Methods locked (GET/HEAD/"
        "OPTIONS only advertised) - positive control."),
    # ---- errors (stage J) ----
    "controls_error_verbose":    ("high", 7.5, "Verbose error shape canary par "
        "(RequestID/traceback/framework mark) - error-masking control gap; "
        "generic-error handler fix (HC-09)."),
    "controls_error_masked":     ("info", 0.0, "Errors generic/masked - "
        "positive control verified."),
    # ---- TLS (stage K) ----
    "controls_tls_weak":         ("medium", 6.1, "Transport controls weak "
        "(HSTS absent ya redirect shape off) - downgrade-window aid; HSTS + "
        "redirect fix (HC-10)."),
    "controls_tls_strong":       ("info", 0.0, "Transport controls strong "
        "(HSTS + https-enforce) - positive control."),
    # ---- CSP (stage L) ----
    "controls_csp_decorative":   ("high", 7.2, "CSP decorative/weak "
        "(unsafe-inline/eval/wildcard, default-src missing) - XSS-exposure "
        "control gap; nonce/hash CSP fix (HC-11)."),
    "controls_csp_strict":       ("info", 0.0, "CSP strict (no unsafe-*, "
        "default-src set) - positive control verified."),
    # ---- echo (stage M) ----
    "controls_echo_raw":         ("high", 7.8, "Raw marker echo (sanitization "
        "control gap) - output-encoding aid; contextual-encode fix (HC-12). "
        "INERT marker only - koi payload KABHI nahi."),
    "controls_echo_sanitized":   ("info", 0.0, "Echo stripped/encoded - "
        "sanitization control verified."),
    # ---- deps (stage N) ----
    "controls_dep_stale":        ("medium", 6.2, "Stale/EOL dependency shape "
        "(versioned fingerprint advisory window) - patch-management control "
        "gap; upgrade fix (HC-13)."),
    "controls_dep_current":      ("info", 0.0, "Fingerprinted deps current - "
        "patch control positive."),
    # ---- observability (stage O) ----
    "controls_observability_off": ("low", 3.3, "Correlation/trace headers "
        "absent - detection/observability aid weak; request-id middleware fix "
        "(HC-14)."),
    "controls_observability_on": ("info", 0.0, "Observability headers present "
        "- detection aid positive (audit-log review documented)."),
    # ---- secrets hygiene (stage P) ----
    "controls_secret_shape":     ("critical", 9.3, "Secret-shape re-scan hit "
        "(values sha1-12 REDACTED) - rotation + vault fix (HC-15); P7/P23/P24 "
        "cross-check."),
    "controls_secrets_absent":   ("info", 0.0, "Sampled pages secret-clean - "
        "hygiene positive."),
    # ---- API controls (stage Q) ----
    "controls_api_spec_live":    ("medium", 5.5, "API spec publicly enumerable "
        "- surface-control review; spec-gating fix (HC-16)."),
    "controls_gql_introspection": ("medium", 6.4, "GraphQL introspection open "
        "- schema enumeration aid; introspection-off fix (HC-17)."),
    "controls_api_locked":       ("info", 0.0, "Spec closed + introspection "
        "locked - API surface positive."),
    # ---- CICD guards (stage R) ----
    "controls_cicd_guard_gap":   ("high", 8.4, "CI/CD + IaC artifact publicly "
        "reachable - guardrail gap; artifact removal + rotation fix (HC-18)."),
    "controls_cicd_guarded":     ("info", 0.0, "Artifact pool closed - "
        "guardrail positive."),
    # ---- edge trust (stage S) ----
    "controls_edge_echo":        ("high", 7.7, "Trust-header echo on edge "
        "(X-Forwarded-Host/X-Original-URL) - edge-strip control gap; proxy "
        "strip fix (HC-19)."),
    "controls_edge_strict":      ("info", 0.0, "No trust-header echo - edge "
        "control verified."),
    # ---- cache (stage T) ----
    "controls_cache_unsafe":     ("medium", 5.6, "Sensitive page cacheable "
        "(public/max-age, no-store absent) - cache-deception aid; no-store + "
        "Vary fix (HC-20)."),
    "controls_cache_safe":       ("info", 0.0, "Sensitive pages no-store/"
        "private - cache control verified."),
    # ---- bypass2 (stage U) ----
    "controls_bypass2_gap":      ("critical", 9.2, "Control-bypass shapes "
        "accepted (403->2xx differential) - access-control normalization gap; "
        "normalize-before-authz fix (HC-21)."),
    "controls_bypass2_blocked":  ("info", 0.0, "Bypass shapes rejected - "
        "control enforced (positive)."),
    # ---- posture/remediation/report ----
    "controls_posture_weak":     ("medium", 5.0, "Controls posture composite "
        "WEAK - priority hardening (REMEDIATION_PLAN.md P1/P2 rows)."),
    "controls_posture_strong":   ("info", 0.0, "Controls posture STRONG - "
        "positive controls dominant."),
    "controls_remediation_plan": ("info", 0.0, "P1..P5 prioritized remediation "
        "plan generated (effort/owner/verification kill-tests)."),
    "controls_drift_baseline":   ("info", 0.0, "Control drift baseline "
        "captured (next run me diff aid)."),
    "controls_secret_guard_hit": ("low", 3.0, "Secret/PII sweep artifacts par "
        "trigger - guard ne redact kiya (CWE-200 aid)."),
    "controls_rate_playbook":    ("info", 0.0, "Full-burst rate wave "
        "documented-only (8-row playbook) - koi burst KABHI network par "
        "nahi (FORBIDDEN-AUTO)."),
    "controls_waf_playbook":     ("info", 0.0, "WAF validation playbook "
        "documented (10-row catalog, payloads NEVER network par) - manual "
        "RoE wave."),
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Findings:
    """P25 findings collector (P12..P24-compatible shape)."""

    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "CT-%03d" % (len(self.items) + 1), "key": key,
               "title": title, "severity": sev, "cvss_hint": cvss,
               "endpoint": endpoint, "detail": pii_redact(detail),
               "why_it_matters": why, "evidence": evidence_ref,
               "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


def classify_severity(key):
    """SEVERITY_HINTS lookup (default info/0.0)."""
    sev, cvss, why = SEVERITY_HINTS.get(
        key, ("info", 0.0, "Controls census row - manual review aid."))
    return sev, cvss, why


def _sev_counts(F):
    counts = {}
    for f in F.items:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# PII REDACT (framework rule - P20..P24 pattern)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token|AccountKey|sig)\s*[:=]\s*[^\s,;\"]{6,})")
_PII_PAN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_PAN.sub("***PAN***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


# ---------------------------------------------------------------------------
# CANARY + INERT ENFORCEMENT (P15..P24 pattern - hard rules)
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    """Synthetic marker ids - waspP25 family (real ids KABHI nahi)."""
    return "%s%s%s" % (CANARY_FAMILY, tag, rand_str(6))


# GET-ONLY MODULE ENFORCEMENT: P25 me koi state-changing method KABHI nahi.
# wasp_core LAYER-4 (READ_ONLY_METHODS = GET/HEAD/OPTIONS) double-guard hai.
_ALLOWED_PROBE_METHODS = ("GET", "HEAD", "OPTIONS")


def assert_inert_method(method):
    if (method or "GET").upper() not in _ALLOWED_PROBE_METHODS:
        raise RuntimeError(
            "P25 INERT violation: method '%s' allowed nahi hai "
            "(GET/HEAD/OPTIONS only)" % method)
    return True


def probe(http, method, url, **kw):
    """INERT probe wrapper: method-guard + scope-firewall (core layer) +
    evidence log. Har P25 network call ISI se jaati hai. Body KABHI nahi."""
    assert_inert_method(method)
    kw.pop("data", None)          # GET-ONLY: body KABHI nahi
    kw.pop("body", None)
    r = http.request(method, url, **kw)
    return r


# ---------------------------------------------------------------------------
# TOLERANT READERS (feedforward/artifact mining - P20..P24 pattern)
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
# MARKER HELPERS (shape classification)
# ---------------------------------------------------------------------------
def match_markers(rx_table, text):
    """Text me pehla marker-shape (name) ya None."""
    for name, rx in rx_table:
        if rx.search(text or ""):
            return name
    return None


def match_all_markers(rx_table, text):
    """Text me saare marker-shapes (names list)."""
    out = []
    for name, rx in rx_table:
        if rx.search(text or ""):
            out.append(name)
    return out


def secret_shape_scan(text):
    """Response body -> secret-shape census rows (values KABHI store nahi).
    Har hit: (shape-name, sha1-12, len bucket) - evidence-safe."""
    rows = []
    for name, rx in SECRET_SHAPES:
        if name.startswith(" "):
            name = name.strip()
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
    """URLs jisme rx hit -> front (P22..P24 pattern)."""
    hits = [t for t in (targets or []) if isinstance(t, str) and rx.search(t)]
    rest = [t for t in (targets or []) if t not in hits]
    return hits + rest


def _two_stage(targets, rx_primary, rx_secondary=None):
    """Primary-rx hits pehle, phir secondary, phir rest (crowd-out guard)."""
    pri = [t for t in (targets or []) if isinstance(t, str) and rx_primary.search(t)]
    sec = [t for t in (targets or []) if isinstance(t, str) and rx_secondary
           and rx_secondary.search(t) and t not in pri]
    rest = [t for t in (targets or []) if t not in pri and t not in sec]
    return pri + sec + rest


def _base_of(targets):
    """Shortest http(s) base URL (root-deterministic, P23/P24 pattern)."""
    urls = [t for t in (targets or []) if isinstance(t, str) and
            t.startswith(("http://", "https://"))]
    if not urls:
        return ""
    roots = [u.rstrip("/") for u in urls]
    return min(roots, key=len)


def _url_like(u):
    """Mining hygiene: sirf http(s) URL-shapes (P24 pattern - shape-names/keys
    jaise 'aws' root nahi ban sakte)."""
    return isinstance(u, str) and u.startswith(("http://", "https://"))


def same_status_class(a, b):
    return (a // 100 if a else 0) == (b // 100 if b else 0)


def parse_set_cookies(r):
    """Resp.headers.get('Set-Cookie') shapes -> flag census (P25 grading)."""
    raw = ""
    try:
        raw = (r.headers or {}).get("Set-Cookie", "") or ""
    except Exception:
        raw = ""
    out = []
    for part in raw.split(","):
        if "=" not in part or ";" not in part:
            continue
        name = part.split("=", 1)[0].strip()
        low = part.lower()
        out.append({"cookie": name[:40],
                    "secure": "secure" in low,
                    "httponly": "httponly" in low,
                    "samesite": ("strict" if "samesite=strict" in low else
                                 "lax" if "samesite=lax" in low else
                                 "none" if "samesite=none" in low else ""),
                    "expires_or_maxage": ("expires=" in low or
                                          "max-age=" in low),
                    "prefix": name.startswith(("__Host-", "__Secure-"))})
    return out


def cookie_grade(rows):
    """Cookie rows -> (grade, flags). grade: hardened/weak/partial/none."""
    if not rows:
        return "none", []
    flags = []
    for c in rows:
        if not (c.get("secure") and c.get("httponly") and
                c.get("samesite") in ("strict", "lax")):
            flags.append(c.get("cookie", "?"))
    if not flags:
        return "hardened", []
    if len(flags) == len(rows):
        return "weak", flags
    return "partial", flags


def parse_csp(csp_value):
    """CSP header value -> directive dict + grading flags (offline parser)."""
    d = {"directives": {}, "unsafe_inline": False, "unsafe_eval": False,
         "wildcard": False, "has_nonce": False, "has_hash": False,
         "default_src": False, "object_src_none": False,
         "base_uri": False, "frame_ancestors": False}
    if not csp_value:
        return d
    for part in (csp_value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split()
        name = bits[0].lower()
        vals = bits[1:]
        d["directives"][name] = vals[:8]
        if name == "default-src":
            d["default_src"] = True
        blob = " ".join(vals)
        if name in ("default-src", "script-src", "style-src"):
            if "'unsafe-inline'" in blob:
                d["unsafe_inline"] = True
            if "'unsafe-eval'" in blob:
                d["unsafe_eval"] = True
            if "*" in vals or ("http:" in vals) or ("https:" in vals):
                d["wildcard"] = True
        if "'nonce-" in blob:
            d["has_nonce"] = True
        if "'sha256-" in blob or "'sha384-" in blob or "'sha512-" in blob:
            d["has_hash"] = True
        if name == "object-src" and ("'none'" in vals):
            d["object_src_none"] = True
        if name == "base-uri":
            d["base_uri"] = True
        if name == "frame-ancestors":
            d["frame_ancestors"] = True
    return d


def csp_grade(parsed):
    """Parsed CSP -> grade strict/partial/decorative/none + flags list."""
    if not parsed or not parsed.get("directives"):
        return "none", []
    flags = []
    if parsed.get("unsafe_inline"):
        flags.append("unsafe-inline")
    if parsed.get("unsafe_eval"):
        flags.append("unsafe-eval")
    if parsed.get("wildcard"):
        flags.append("wildcard-src")
    if not parsed.get("default_src"):
        flags.append("no-default-src")
    if not parsed.get("object_src_none"):
        flags.append("object-src-not-none")
    if not parsed.get("base_uri"):
        flags.append("no-base-uri")
    strictish = (parsed.get("default_src") and not parsed.get("unsafe_inline")
                 and not parsed.get("wildcard"))
    if not flags:
        return "strict", []
    if strictish:
        return "partial", flags
    return "decorative", flags


def dep_scan(text):
    """Body/headers -> stale/EOL dependency rows (P6 cross-check aid)."""
    rows = []
    for name, rx, checker, note in DEP_VERSION_ROWS:
        m = rx.search(text or "")
        if not m:
            continue
        try:
            stale = bool(checker(m))
        except Exception:
            stale = False
        rows.append({"dep": name, "version": m.group(0)[:32],
                     "stale": stale, "note": note})
    return rows


def echo_grade(body, canary_tok):
    """Body + canary token -> (grade, detail) - sanitization control census.
    grade: raw (unencoded marker+tag shape), encoded (escaped), stripped
    (absent). Sirf synthetic waspP25 token - koi payload KABHI nahi."""
    b = body or ""
    if canary_tok not in b:
        return "stripped", "marker absent (control stripped/encoded)"
    idx = b.find(canary_tok)
    ctx = b[max(0, idx - 4):idx + len(canary_tok) + 12]
    if re.search(r"<", ctx) and re.search(r">", ctx[len(canary_tok) - 2:]):
        return "raw", "raw reflection context=%r" % ctx[:40]
    if re.search(r"&lt;|&gt;|%3C|%3E|\\u003c|\\u003e", ctx):
        return "encoded", "contextual encoding detected"
    return "reflected-plain", "marker echoed without tag context"


# ---------------------------------------------------------------------------
# REMEDIATION PRIORITY ENGINE (P1..P5 + effort/owner/verification)
# ---------------------------------------------------------------------------
REMEDIATION_RULES = [
    ("P1", ("critical",), "0-48h", "AppSec + Infra lead",
     ["controls_authgate_gap", "controls_bypass2_gap",
      "controls_secret_shape", "controls_cicd_guard_gap"],
     "Immediate containment + rotate/expose-surface fix + verification "
     "kill-test"),
    ("P2", ("high",), "2-7d", "AppSec eng",
     ["controls_cors_reflect", "controls_echo_raw",
      "controls_error_verbose", "controls_edge_echo",
      "controls_csp_decorative", "controls_waf_declared_only"],
     "Sprint-priority fix + regression test + control re-verify"),
    ("P3", ("medium",), "next sprint", "Platform eng",
     ["controls_headers_missing", "controls_rate_gap",
      "controls_cookies_weak", "controls_methods_advertised",
      "controls_tls_weak", "controls_dep_stale",
      "controls_cache_unsafe", "controls_api_spec_live",
      "controls_gql_introspection", "controls_posture_weak"],
     "Backlog hardening + checklist verification"),
    ("P4", ("low",), "quarter", "Platform eng",
     ["controls_disclosure_hdr", "controls_observability_off",
      "controls_waf_absent", "controls_secret_guard_hit"],
     "Info-hygiene + detection-aid improvements"),
    ("P5", ("info",), "continuous", "Security champion",
     ["controls_posture_strong", "controls_drift_baseline",
      "controls_remediation_plan"],
     "Maintain + drift monitor + periodic re-validation"),
]


def build_remediation(F):
    """Findings -> prioritized remediation rows (P1..P5, dedup per key)."""
    rows = []
    seen = set()
    by_key = {}
    for f in F.items:
        base_key = f["key"]
        by_key.setdefault(base_key, []).append(f)
    for pri, sevs, sla, owner, keys, action in REMEDIATION_RULES:
        for k in keys:
            fl = by_key.get(k) or []
            if not fl:
                continue
            for f in fl[:6]:
                dk = (pri, k, f.get("endpoint", ""))
                if dk in seen:
                    continue
                seen.add(dk)
                rows.append({"priority": pri, "key": k,
                             "severity": f.get("severity"),
                             "endpoint": f.get("endpoint", ""),
                             "sla": sla, "owner": owner, "action": action,
                             "finding_id": f.get("id"),
                             "verification": _verify_for(k)})
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "P5": 4}
    rows.sort(key=lambda r: (order.get(r["priority"], 9), r["key"]))
    return rows


def _verify_for(key):
    """Control verification kill-test string per finding-key."""
    table = {
        "controls_authgate_gap": "Kill-test: anon GET protected path -> expect 30x/40x "
                        "(200-leak = FAIL)",
        "controls_bypass2_gap": "Kill-test: 22-shape matrix re-run gated -> expect all "
                       "rejected (any 2xx = FAIL)",
        "controls_secret_shape": "Kill-test: sha1-12 re-scan sampled pages -> expect "
                        "shape absent (hit = FAIL) + rotation proof",
        "controls_cicd_guard_gap": "Kill-test: artifact paths GET -> expect 403/404 "
                          "uniform (200 with content = FAIL)",
        "controls_cors_reflect": "Kill-test: canary Origins -> expect no ACAO echo "
                        "(reflection = FAIL)",
        "controls_echo_raw": "Kill-test: waspP25 marker echo -> expect stripped/"
                    "encoded (raw = FAIL)",
        "controls_error_verbose": "Kill-test: canary param -> expect generic error "
                         "(verbose shape = FAIL)",
        "controls_edge_echo": "Kill-test: trust-header echo -> expect no echo "
                     "(misroute = FAIL)",
        "controls_csp_decorative": "Kill-test: CSP re-parse -> expect no unsafe-*/"
                          "wildcard (present = FAIL)",
        "controls_waf_declared_only": "Kill-test: canary marker re-probe -> expect "
                             "block-shape (200 pass-through = FAIL)",
        "controls_headers_missing": "Kill-test: header audit re-run -> expect all 18 "
                           "controls present-or-documented",
        "controls_rate_gap": "Kill-test: 6-seq canary re-run gated -> expect 429/"
                    "Retry-After shape",
        "controls_cookies_weak": "Kill-test: Set-Cookie flags -> expect Secure+"
                        "HttpOnly+SameSite on all session cookies",
        "controls_methods_advertised": "Kill-test: OPTIONS -> expect GET/HEAD/OPTIONS "
                              "only advertised",
        "controls_tls_weak": "Kill-test: HSTS max-age>=31536000 + http->https 301",
        "controls_dep_stale": "Kill-test: versioned fp re-scan -> expect current "
                     "versions",
        "controls_cache_unsafe": "Kill-test: sensitive pages -> expect no-store/"
                        "private",
        "controls_api_spec_live": "Kill-test: spec paths -> expect 403/404 (200 = "
                         "documented decision)",
        "controls_gql_introspection": "Kill-test: introspection query (manual RoE) -> "
                             "expect disabled",
        "controls_disclosure_hdr": "Kill-test: banner headers absent",
        "controls_observability_off": "Kill-test: x-request-id present on responses",
        "controls_waf_absent": "Decision: edge-WAF adoption review",
        "controls_posture_weak": "Kill-test: posture composite re-run -> score>=9/16",
    }
    return table.get(key, "Kill-test: manual re-validation (RoE)")


# ---------------------------------------------------------------------------
# DRIFT BASELINE (control state hash - next-run diff aid)
# ---------------------------------------------------------------------------
def drift_baseline(posture, verdict_rows):
    """Posture rows + verdict counts -> compact drift fingerprint dict."""
    counts = {}
    for r in verdict_rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    rows = [{"url": r["url"], "score": r["score"], "grade": r["grade"]}
            for r in posture.get("rows", [])][:40]
    blob = json.dumps({"rows": rows, "counts": counts},
                      sort_keys=True, separators=(",", ":"))
    return {"sha1_16": hashlib.sha1(blob.encode("utf-8", "ignore"))
            .hexdigest()[:16], "rows": len(rows), "counts": counts,
            "captured": now_iso()}


# ---------------------------------------------------------------------------
# DOCUMENTED-ONLY PLAYBOOKS (koi row network par KABHI nahi)
# ---------------------------------------------------------------------------
RATE_BURST_PLAYBOOK = [
    ("RB-01", "Baseline load profile doc (RPS/peaks) - RoE review"),
    ("RB-02", "Single-endpoint canary burst (manual, staged 10->50 rps)"),
    ("RB-03", "429/Retry-After shape + header (limit/remaining/reset) capture"),
    ("RB-04", "Distributed-source throttle verification (staged)"),
    ("RB-05", "Login/OTP/reset endpoint throttle verify (manual)"),
    ("RB-06", "API-key quota shape verify (per-key vs per-IP)"),
    ("RB-07", "Burst-recovery behavior (backoff window)"),
    ("RB-08", "Alerting/observability trigger verify (SOC log check)"),
]
WAF_PAYLOAD_CATALOG = [
    ("WP-01", "Reflected-XSS probe family (documented) - INERT canary only "
              "in P25 engine; payloads manual RoE wave"),
    ("WP-02", "SQLi probe family (documented) - NEVER network par engine se"),
    ("WP-03", "Path-traversal family (documented)"),
    ("WP-04", "Command-injection family (documented)"),
    ("WP-05", "SSRF parameter family (documented)"),
    ("WP-06", "SSTI family (documented)"),
    ("WP-07", "XXE family (documented)"),
    ("WP-08", "Deserialization family (documented)"),
    ("WP-09", "Log4Shell header family (documented; P23 owns surface)"),
    ("WP-10", "Prototype-pollution family (documented)"),
]
CHECKLIST_CATALOG = [
    ("HC-01", "Hardening headers (CSP/HSTS/XFO/XCTO/Referrer/Permissions/"
              "COOP/COEP/CORP) sab live pages par", "P3"),
    ("HC-02", "Server/X-Powered-By banners strip", "P4"),
    ("HC-03", "WAF rules tune + block-shape verify (declared!=enforced)",
     "P2"),
    ("HC-04", "Rate-limit middleware (429 + Retry-After + quota headers)",
     "P3"),
    ("HC-05", "CORS origin-allowlist (no reflect-any/null)", "P2"),
    ("HC-06", "Cookie flags Secure+HttpOnly+SameSite (+__Host prefix)",
     "P3"),
    ("HC-07", "Auth-gate deny-by-default (protected pool uniform 30x/40x)",
     "P1"),
    ("HC-08", "Method allowlist (GET/HEAD/OPTIONS public; destructive "
              "authenticated-only)", "P3"),
    ("HC-09", "Generic error handler (no RequestID/traceback/framework)",
     "P2"),
    ("HC-10", "HSTS preload + http->https 301 across all routes", "P3"),
    ("HC-11", "CSP nonce/hash based (no unsafe-inline/eval/wildcard)", "P2"),
    ("HC-12", "Contextual output encoding (echo control)", "P2"),
    ("HC-13", "Dependency patch SLA (EOL runtimes + stale libs)", "P3"),
    ("HC-14", "Request-id/trace middleware (observability)", "P4"),
    ("HC-15", "Secrets vault + rotation (pages/JS clean)", "P1"),
    ("HC-16", "API spec gating (prod spec closed/authorized)", "P3"),
    ("HC-17", "GQL introspection off in prod", "P3"),
    ("HC-18", "CI/CD + IaC artifacts repo-only (no web root)", "P1"),
    ("HC-19", "Edge trust-header strip (X-Forwarded-*/X-Original-*)", "P2"),
    ("HC-20", "Cache-Control no-store/private on sensitive", "P3"),
    ("HC-21", "Path/header normalization before authz (bypass2 control)",
     "P1"),
    ("HC-22", "Periodic control drift re-validation (P25 cadence)", "P5"),
]

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
    """Kisi bhi mod ki routing me to_phase25* keys -> URL pool."""
    urls = []
    for mod in mods:
        d = _read_json_tolerant(_artifact(base_dir, mod, "feedforward.json"))
        if not isinstance(d, dict):
            continue
        routing = d.get("routing") or {}
        for rk, val in routing.items():
            if not str(rk).lower().startswith("to_phase25"):
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


CONTROLS_PATH_RX = re.compile(
    r"(?i)(login|signin|auth|logout|register|signup|admin|dashboard|profile|"
    r"settings|account|billing|user|users|api|graphql|graphiql|ws|socket|"
    r"docs|swagger|openapi|api-docs|health|healthz|status|metrics|debug|env|"
    r"error|strong|hardened|security|cacheable|download|share|console|"
    r"internal|manage|controlpanel|wp-admin|protected|secret|token|cors|"
    r"trust|echo|errors|verified|ctl)")


def discover_controls_surface(ctx, scope, conf):
    """Stage A: 20-module feedforward + artifact mining + cold pool ->
    ranked control-check targets (shape scoring, real-vs-cold split)."""
    base_dir = ctx.get("base_dir")
    sources, urls = [], set()

    # 1) feedforward routing (to_phase25* keys - P4..P24 documented seeds)
    ff = _ff_any_pairs(base_dir, ["understand", "passive", "active", "content",
                                  "tech", "js", "auth", "sessions", "access",
                                  "inject", "ssrf", "files", "api", "graphql",
                                  "ws", "logic", "replay", "misconfig",
                                  "cloud", "surface"])
    if ff:
        sources.append("ff_routing(to_phase25*)")
        for u in ff:
            if _url_like(u):
                urls.add(u)

    # 2) P23 misconfig controls seeds (to_phase25_controls routing)
    p23 = _ff_pairs(base_dir, "misconfig", "to_phase25_controls")
    if p23:
        sources.append("p23_controls_seeds")
        for u in p23:
            if _url_like(u):
                urls.add(u)

    # 3) P24 cloud controls seeds (posture rows + provider-identified)
    p24 = _ff_pairs(base_dir, "cloud", "to_phase25_controls")
    if p24:
        sources.append("p24_controls_seeds")
        for u in p24:
            if _url_like(u):
                urls.add(u)

    # 4) P22 replay/stuffing posture seeds + P9 session + P11 access
    for mod, key in (("replay", "to_phase25_controls"),
                     ("auth", "to_phase25_controls"),
                     ("access", "to_phase25_controls")):
        got = _ff_pairs(base_dir, mod, key)
        if got:
            sources.append("%s_seeds" % mod)
            for u in got:
                if _url_like(u):
                    urls.add(u)

    # 5) direct artifact mining (endpoints/urls pools of other modules)
    mined = _mine_urls_from_artifacts(
        base_dir,
        ["understand", "content", "js", "api", "ssrf", "active", "tech",
         "replay", "misconfig", "auth", "access", "sessions", "cloud",
         "logic", "inject"],
        ["endpoints.txt", "api_endpoints.txt", "js_urls.txt", "all_urls.txt",
         "cloud_endpoints.txt", "misconfig_endpoints.txt",
         "ssrf_targets.txt", "inject_targets.txt", "access_endpoints.txt",
         "targets.json", "surface_endpoints.txt", "login_endpoints.txt"],
        cap=220)
    if mined:
        sources.append("artifact_mining(%d)" % len(mined))
        for u in mined:
            if _url_like(u):
                urls.add(u)

    # 6) scope targets (root always included)
    for t in (getattr(scope, "targets", None) or []):
        if _url_like(t) and not t.startswith("/"):
            urls.add(t)

    # 7) cold pool (control-shaped paths on base)
    base = None
    if urls:
        base = _base_of(sorted(urls))
    if not base:
        for t in (getattr(scope, "targets", None) or []):
            if isinstance(t, str) and t:
                base = t.split("?")[0].rstrip("/")
                break
    cold = []
    if base:
        for p in COLD_PATHS[:max(8, int(conf.get("controls_cold_paths", 46)))]:
            cold.append(base + p)
        sources.append("cold_pool(%d)" % len(cold))
        for u in cold:
            urls.add(u)

    # scoring: control-shaped first (real-vs-cold split - root always in)
    ranked = []
    for u in sorted(urls):
        if not isinstance(u, str) or not u:
            continue
        score = 0
        if CONTROLS_PATH_RX.search(u):
            score += 4
        if any(k in u.lower() for k in ("login", "admin", "profile",
                                        "account", "settings", "dashboard",
                                        "api/", "graphql", "protected",
                                        "error", "cors", "trust", "strong",
                                        "cacheable", "secret")):
            score += 3
        if u.startswith("http"):
            score += 1
        ranked.append({"url": u[:300], "score": score,
                       "kinds": (["controls-shape"] if
                                 CONTROLS_PATH_RX.search(u)
                                 else ["generic"])})
    ranked.sort(key=lambda r: (-r["score"], r["url"]))
    cap = max(6, int(conf.get("controls_paths_cap", 40)))
    root = (base or "")
    if root:
        root_rec = {"url": root, "score": 99, "kinds": ["root"]}
        ranked = [r for r in ranked if r["url"] != root]
        ranked.insert(0, root_rec)
    ranked = ranked[:cap]
    return {"ranked": ranked, "targets": [r["url"] for r in ranked],
            "sources": sources, "base_url": root or ""}


# ===========================================================================
# STAGE B - BASELINE + WAF-DECLARED + SOFT-404
# ===========================================================================
def baseline_and_waf(http, targets, conf):
    """Baseline rows (status/title/sha1-len) + declared-WAF markers."""
    rows, waf = [], []
    base = _base_of(targets)
    for t in (targets or [])[:max(3, int(conf.get("controls_probe_cap", 24))
                                  // 3)]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())[:3000]
        rows.append({"url": t, "status": r.status, "title": title_of(
            (r.text or "")[:4000]),
            "len": len(r.text or ""), "ok": bool(r.ok()),
            "soft404": is_soft404(r, None)})
        wf = waf_signature(r.headers, (r.text or "")[:2000], r.status)
        decl = match_all_markers(WAF_DECL_RX, hdr_blob)
        if wf or decl:
            waf.append({"url": t, "waf": wf, "declared": decl})
        if interrupted():
            break
    try:
        if base:
            soft404_baseline(http, base, samples=3, paths=None)
    except Exception:
        pass
    return {"rows": rows, "waf": waf}


# ===========================================================================
# STAGE C - HEADER CONTROLS AUDIT (18 hardening + 10 disclosure)
# ===========================================================================
def headers_census(http, targets, conf):
    """Header control audit: per-target 18 hardening controls presence +
    strict-value grading + disclosure-banner census (P4/P23 cross-check)."""
    rows = []
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in _two_stage(targets, re.compile(r"(?i)(login|admin|profile|"
                                            r"account|dashboard|api|"
                                            r"strong|hardened)"))[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())
        present, strict, missing = [], [], []
        for name, _hdr, present_rx, strict_rx, _fix in HEADER_CONTROLS:
            prx = re.compile(present_rx, re.M)
            srx = re.compile(strict_rx, re.M)
            if prx.search(hdr_blob):
                present.append(name)
                if srx.search(hdr_blob):
                    strict.append(name)
                else:
                    missing.append(name + ":weak-value")
            else:
                missing.append(name + ":absent")
        disc = match_all_markers(DISCLOSURE_HEADERS, hdr_blob)
        body_disc = match_all_markers(
            [t2 for t2 in DISCLOSURE_HEADERS if t2[0] == "generator-meta"],
            (r.text or "")[:4000])
        csp_raw = ""
        for k, v in (r.headers or {}).items():
            if k.lower() == "content-security-policy":
                csp_raw = str(v)
                break
        rows.append({"url": t, "status": r.status,
                     "present": present, "strict": strict,
                     "missing": missing, "disclosure": sorted(
                         set(disc) | set(body_disc)),
                     "csp_raw": csp_raw[:600],
                     "noise": is_soft404(r, None),
                     "hardening_score": "%d/18" % len(present),
                     "strict_score": "%d/18" % len(strict)})
        if interrupted():
            break
    strong = len([r for r in rows if r.get("strict") and
                  len(r["strict"]) >= 12])
    return {"rows": rows, "strong_count": strong,
            "note": "18 hardening header controls + 10 disclosure shapes "
                    "(P4/P23 handoff cross-check)"}


# ===========================================================================
# STAGE D - WAF ENFORCEMENT DIFFERENTIAL (GATED controls_allow_waf_probe)
# ===========================================================================
def waf_enforcement_census(http, targets, conf):
    """GATED controls_allow_waf_probe.

    INERT canary marker-string census: synthetic waspP25 token harmless
    param me jaata hai (NO attack payloads KABHI). Grading:
      block-shape = WAF enforced (HARDENED), 200 pass-through + declared
      marker = declared-only gap, no marker = absent.
    Payload families sirf WAF_PAYLOAD_CATALOG (documented-only)."""
    gate = bool(conf.get("controls_allow_waf_probe", False))
    result = {"gate": "controls_allow_waf_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual WAF wave documented (WP-01..WP-10)"}
    if not gate:
        return result
    tok = _canary("w")
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in _two_stage(targets, re.compile(r"(?i)(search|q=|api|login|"
                                            r"protected|admin|waf)"))[:cap]:
        sep = "&" if "?" in t else "?"
        url = "%s%swaspP25=%s" % (t, sep, tok)
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        blob = ((r.text or "")[:3000] + " " + " ".join(
            "%s: %s" % (k, v) for k, v in (r.headers or {}).items()))
        block = match_all_markers(WAF_BLOCK_RX, blob)
        decl = match_all_markers(WAF_DECL_RX, blob)
        enforced = bool(block) or r.status in (403, 406, 429)
        result["rows"].append({
            "url": t, "probe_status": r.status, "block_shapes": block,
            "declared": decl, "enforced": enforced,
            "grade": ("enforced" if enforced else
                      "declared-only" if decl else "absent")})
        if interrupted():
            break
    enf = len([r for r in result["rows"] if r.get("enforced")])
    decl_only = len([r for r in result["rows"]
                     if r.get("grade") == "declared-only"])
    result["enforced_count"] = enf
    result["declared_only_count"] = decl_only
    return result


# ===========================================================================
# STAGE E - RATE-LIMIT CONTROL CENSUS (GATED controls_allow_rate_probe)
# ===========================================================================
def rate_control_census(http, targets, conf):
    """GATED controls_allow_rate_probe.

    6-sequential HARD cap (controls_rate_cap) + >=0.4s spacing (single
    canary endpoint) -> 429/Retry-After/throttle-header shape census.
    Parallel burst / hammer FORBIDDEN-AUTO; full-burst wave =
    RATE_BURST_PLAYBOOK documented-only."""
    gate = bool(conf.get("controls_allow_rate_probe", False))
    result = {"gate": "controls_allow_rate_probe=%s" % gate, "rows": [],
              "playbook": [i for i, _ in RATE_BURST_PLAYBOOK],
              "skipped_note": "" if gate else
              "RoE gate OFF - full-burst wave documented-only (RB-01..08)"}
    if not gate:
        return result
    cap_seq = max(2, min(6, int(conf.get("controls_rate_cap", 6))))
    gap = max(0.4, float(conf.get("controls_rate_gap", 0.4)))
    target = None
    for t in _two_stage(targets, re.compile(r"(?i)ratelimit"),
                        re.compile(r"(?i)(login|api|auth|search)")):
        target = t
        break
    if not target:
        target = _base_of(targets)
    if not target:
        result["skipped_note"] = "no target"
        return result
    seq = []
    for i in range(cap_seq):
        if interrupted():
            break
        try:
            r = probe(http, "GET", target, allow_redirects=False)
        except Exception as e:
            seq.append({"seq": i + 1, "error": str(e)[:100]})
            break
        blob = " ".join("%s: %s" % (k, v) for k, v in
                        (r.headers or {}).items()) + (r.text or "")[:1500]
        shapes = match_all_markers(RATE_SHAPE_RX, blob)
        seq.append({"seq": i + 1, "status": r.status, "shapes": shapes,
                    "throttled": bool(shapes) or r.status == 429})
        if r.status == 429 or shapes:
            break
        time.sleep(gap)
    throttled = [s for s in seq if s.get("throttled")]
    result["rows"] = [{"url": target, "sequence": seq,
                       "throttled_within_cap": bool(throttled),
                       "cap": cap_seq, "gap_sec": gap}]
    result["enforced"] = bool(throttled)
    return result

# ===========================================================================
# STAGE F - CORS CONTROL VALIDATION (GATED controls_allow_cors_probe)
# ===========================================================================
def cors_control_census(http, targets, conf):
    """GATED controls_allow_cors_probe.

    4 canary Origins (sab .invalid TLD) -> ACAO reflection grading:
      REFLECT-ANY (evil.invalid echoed) = control gap CONFIRMED-aid;
      NULL-ALLOWED = partial; strict (no echo) = control verified."""
    gate = bool(conf.get("controls_allow_cors_probe", False))
    result = {"gate": "controls_allow_cors_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual CORS wave documented (HC-05)"}
    if not gate:
        return result
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 3)
    cands = _two_stage(targets, re.compile(r"(?i)(api|graphql|cors|storage|"
                                           r"download|share)"))
    for t in cands[:cap]:
        grades = []
        for org in CORS_CANARY_ORIGINS:
            try:
                r = probe(http, "GET", t, allow_redirects=False,
                          headers={"Origin": org})
            except Exception as e:
                grades.append({"origin": org, "error": str(e)[:80]})
                continue
            acao = ""
            for k, v in (r.headers or {}).items():
                if k.lower() == "access-control-allow-origin":
                    acao = str(v)
                    break
            grades.append({"origin": org, "status": r.status, "acao": acao[:60],
                           "reflected": bool(acao and
                                             acao.strip() == org)})
        refl_any = any(g.get("reflected") and "evil.invalid" in
                       (g.get("origin") or "") for g in grades)
        refl_null = any(g.get("reflected") and g.get("origin") == "null"
                        for g in grades)
        result["rows"].append({
            "url": t, "grades": grades, "reflect_any": refl_any,
            "reflect_null": refl_null,
            "grade": ("REFLECT-ANY" if refl_any else
                      "NULL-ALLOWED" if refl_null else "STRICT"),
            "strict": not (refl_any or refl_null)})
        if interrupted():
            break
    result["strict_count"] = len([r for r in result["rows"]
                                  if r.get("strict")])
    return result


# ===========================================================================
# STAGE G - COOKIE/SESSION CONTROLS (passive-GET)
# ===========================================================================
def cookie_control_census(http, targets, conf):
    """Set-Cookie flag census per-target -> hardened/partial/weak/none grade
    (P10 handoff cross-check; cookie VALUES KABHI store nahi - sirf flags)."""
    rows = []
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in _two_stage(targets, re.compile(r"(?i)(login|signin|auth|"
                                            r"account|session|profile)"))[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        crows = parse_set_cookies(r)
        grade, flags = cookie_grade(crows)
        rows.append({"url": t, "status": r.status, "cookies": crows,
                     "grade": grade, "weak_flags": flags[:6],
                     "noise": is_soft404(r, None)})
        if interrupted():
            break
    weak = len([r for r in rows if r.get("grade") in ("weak", "partial")])
    return {"rows": rows, "weak_count": weak,
            "note": "cookie VALUES store nahi hote - sirf flag booleans "
                    "(P10 session handoff cross-check)"}


# ===========================================================================
# STAGE H - AUTH-GATE CONTROL (GATED controls_allow_authgate_probe)
# ===========================================================================
def authgate_census(http, targets, conf):
    """GATED controls_allow_authgate_probe.

    Protected-path pool par anon GET differential (NO creds KABHI):
      uniform 302/401/403 = auth-gate enforced (positive);
      200-leak = control gap CONFIRMED-aid (deny-by-default fix)."""
    gate = bool(conf.get("controls_allow_authgate_probe", False))
    result = {"gate": "controls_allow_authgate_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual authz wave documented (HC-07; P11 owns "
              "deep authz)"}
    if not gate:
        return result
    base = _base_of(targets)
    if not base:
        result["skipped_note"] = "no base"
        return result
    cap = max(6, int(conf.get("controls_authgate_paths", 20)))
    pool = AUTHGATE_PATHS[:cap]
    for path in pool:
        url = base + path
        if interrupted():
            break
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        gated = r.status in (301, 302, 303, 307, 308, 401, 403)
        login_shape = bool(match_markers(AUTHGATE_SHAPES[3:4],
                                         (r.text or "")[:2500])) \
            if r.status < 400 else False
        result["rows"].append({
            "url": url, "status": r.status, "gated": gated,
            "login_shape": login_shape,
            "leak": bool(r.status == 200 and not login_shape and
                         not is_soft404(r, None))})
    leaks = [r for r in result["rows"] if r.get("leak")]
    gated_n = len([r for r in result["rows"] if r.get("gated")])
    result["leak_count"] = len(leaks)
    result["gated_count"] = gated_n
    result["uniform_gate"] = gated_n >= 1 and not leaks
    return result


# ===========================================================================
# STAGE I - METHOD CONTROL CENSUS (GATED controls_allow_method_probe)
# ===========================================================================
def method_control_census(http, targets, conf):
    """GATED controls_allow_method_probe.

    OPTIONS/Allow-header census - ADVERTISED destructive methods flag karta
    hai. Koi destructive method SEND KABHI nahi hota (wasp_core L4
    double-guard + INERT module assert)."""
    gate = bool(conf.get("controls_allow_method_probe", False))
    result = {"gate": "controls_allow_method_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual method wave documented (HC-08)"}
    if not gate:
        return result
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 3)
    dangerous = ("PUT", "DELETE", "PATCH", "TRACE", "TRACK", "CONNECT",
                 "PROPFIND", "MKCOL", "MOVE", "COPY")
    for t in _two_stage(targets, re.compile(r"(?i)(api|upload|files|admin)"))[:cap]:
        try:
            r = probe(http, "OPTIONS", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        allow = ""
        for k, v in (r.headers or {}).items():
            if k.lower() in ("allow", "access-control-allow-methods"):
                allow += " %s" % v
        adv = [m for m in dangerous if
               re.search(r"(?<![A-Z])%s(?![A-Z])" % m, allow.upper())]
        result["rows"].append({"url": t, "status": r.status,
                               "allow": allow.strip()[:120],
                               "advertised_destructive": adv,
                               "locked": not adv})
        if interrupted():
            break
    result["unlocked_count"] = len([r for r in result["rows"]
                                    if r.get("advertised_destructive")])
    return result


# ===========================================================================
# STAGE J - ERROR-MASKING CONTROL (GATED controls_allow_error_probe)
# ===========================================================================
def error_mask_census(http, targets, conf):
    """GATED controls_allow_error_probe.

    Canary-param probes (synthetic waspP25 values only) -> verbose vs
    generic error shapes. Verbose shape = masking control gap."""
    gate = bool(conf.get("controls_allow_error_probe", False))
    result = {"gate": "controls_allow_error_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual error wave documented (HC-09)"}
    if not gate:
        return result
    tok = _canary("e")
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in _two_stage(targets, re.compile(r"(?i)(api|search|q=|item|id=|"
                                            r"error|debug)"))[:cap]:
        sep = "&" if "?" in t else "?"
        url = "%s%swaspP25id=%s" % (t, sep, tok)
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        verbose = match_all_markers(ERROR_VERBOSE_RX, (r.text or "")[:6000])
        generic = ("something went wrong" in (r.text or "").lower() or
                   "ref:" in (r.text or "").lower()) and not verbose
        result["rows"].append({
            "url": t, "status": r.status, "verbose_hits": verbose,
            "generic": generic,
            "grade": ("verbose" if verbose else
                      "masked" if generic or r.status < 500 else
                      "unknown")})
        if interrupted():
            break
    result["verbose_count"] = len([r for r in result["rows"]
                                   if r.get("verbose_hits")])
    return result


# ===========================================================================
# STAGE K - TLS/TRANSPORT CONTROLS (passive-GET)
# ===========================================================================
def tls_control_census(http, targets, conf):
    """HSTS grade + http->https redirect shape + mixed-content shapes
    (passive GETs; CWE-319 aid)."""
    rows = []
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in (targets or [])[:cap]:
        if not isinstance(t, str) or not t.startswith("http"):
            continue
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hsts = ""
        for k, v in (r.headers or {}).items():
            if k.lower() == "strict-transport-security":
                hsts = str(v)
                break
        m = re.search(r"max-age=(\d+)", hsts or "")
        maxage = int(m.group(1)) if m else 0
        mixed = len(re.findall(
            r"(?i)(?:src|href)=[\"']http://(?!127\.0\.0\.1|localhost)",
            (r.text or "")[:8000]))
        rows.append({"url": t, "status": r.status, "hsts": hsts[:80],
                     "hsts_maxage": maxage, "preload": "preload" in
                     (hsts or "").lower(),
                     "mixed_content_hits": mixed,
                     "grade": ("strong" if maxage >= 31536000 else
                               "partial" if maxage > 0 else "weak")})
        if interrupted():
            break
    weak = len([r for r in rows if r.get("grade") == "weak"])
    return {"rows": rows, "weak_count": weak,
            "note": "transport control census (HSTS/preload/mixed-shapes)"}


# ===========================================================================
# STAGE L - CSP DEEP GRADING (offline parser on stage-C responses)
# ===========================================================================
def csp_deep_grade(header_rows):
    """Stage-C header rows -> CSP deep grade per URL (offline; no requests)."""
    rows = []
    for r in (header_rows or []):
        if r.get("error") or "csp" not in (r.get("present") or []):
            continue
        # re-derive CSP value from census text is not possible offline, so
        # stage-C rows carry the raw CSP value (see headers_census csp_raw)
        raw = r.get("csp_raw", "")
        parsed = parse_csp(raw)
        grade, flags = csp_grade(parsed)
        rows.append({"url": r.get("url"), "grade": grade, "flags": flags,
                     "directives": sorted(parsed.get("directives", {})
                                          .keys())[:14],
                     "nonce": parsed.get("has_nonce"),
                     "hash": parsed.get("has_hash")})
    strict_n = len([r for r in rows if r.get("grade") == "strict"])
    return {"rows": rows, "strict_count": strict_n,
            "note": "CSP directive-level grading (nonce/hash/unsafe-*/"
                    "wildcard/default-src)"}

# ===========================================================================
# STAGE M - ECHO-SANITIZATION CONTROL (GATED controls_allow_echo_probe)
# ===========================================================================
def echo_control_census(http, targets, conf):
    """GATED controls_allow_echo_probe.

    Synthetic waspP25 marker (NO XSS payloads KABHI) reflection census:
      raw (unencoded tag context) = sanitization gap;
      encoded/stripped = control verified. GET-only."""
    gate = bool(conf.get("controls_allow_echo_probe", False))
    result = {"gate": "controls_allow_echo_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual echo wave documented (HC-12)"}
    if not gate:
        return result
    tok = _canary("echo")
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in _two_stage(targets, re.compile(r"(?i)(search|q=|item|name=|"
                                            r"page|ref|api)"))[:cap]:
        sep = "&" if "?" in t else "?"
        url = "%s%swaspP25q=<waspP25marker%%2522%s>" % (t, sep, tok)
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        grade, detail = echo_grade((r.text or "")[:12000], tok)
        result["rows"].append({"url": t, "status": r.status,
                               "grade": grade, "detail": detail[:120]})
        if interrupted():
            break
    raw_n = len([r for r in result["rows"] if r.get("grade") == "raw"])
    result["raw_count"] = raw_n
    return result


# ===========================================================================
# STAGE N - DEPENDENCY/PATCH CONTROL (passive versioned fp)
# ===========================================================================
def dep_control_census(http, targets, conf):
    """Versioned dependency fingerprints -> stale/EOL advisory rows
    (patch-management control aid; P6 tech cross-check)."""
    rows = []
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        blob = (r.text or "")[:12000]
        deps = dep_scan(blob)
        stale = [d for d in deps if d.get("stale")]
        rows.append({"url": t, "status": r.status, "deps": deps[:8],
                     "stale_deps": [d["dep"] for d in stale],
                     "noise": is_soft404(r, None)})
        if interrupted():
            break
    stale_n = len([r for r in rows if r.get("stale_deps")])
    return {"rows": rows, "stale_count": stale_n,
            "note": "versioned fingerprint -> advisory window (documented "
                    "mapping; P6 handoff)"}


# ===========================================================================
# STAGE O - OBSERVABILITY CONTROLS (passive-GET)
# ===========================================================================
def observability_census(http, targets, conf):
    """Correlation/trace header census (audit-log enablement aid; headers
    response-side only, documented-only log review)."""
    rows = []
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 2)
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())
        shapes = match_all_markers(OBSERVABILITY_RX, hdr_blob)
        rows.append({"url": t, "status": r.status, "shapes": shapes,
                     "observability_on": bool(shapes),
                     "noise": is_soft404(r, None)})
        if interrupted():
            break
    on_n = len([r for r in rows if r.get("observability_on")])
    return {"rows": rows, "on_count": on_n,
            "note": "detection-aid census (x-request-id/traceparent family)"}


# ===========================================================================
# STAGE P - SECRETS-HYGIENE CONTROL (passive re-scan, sha1-only)
# ===========================================================================
def secrets_hygiene_census(http, targets, conf):
    """Sampled targets par secret-shape re-scan (values REDACTED sha1-12) ->
    rotation-need flags (P7/P23/P24 cross-check; CWE-798 aid)."""
    rows = []
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 3)
    secret_cap = max(6, int(conf.get("controls_secret_cap", 40)))
    count = 0
    for t in _two_stage(targets, re.compile(r"(?i)(js|config|env|secret|"
                                            r"api|token|settings)"))[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        shapes = secret_shape_scan((r.text or "")[:20000])
        count += len(shapes)
        rows.append({"url": t, "status": r.status, "shapes": shapes[:10],
                     "noise": is_soft404(r, None)})
        if count >= secret_cap or interrupted():
            break
    hit = len([r for r in rows if r.get("shapes")])
    return {"rows": rows, "hit_count": hit,
            "note": "secret VALUES store nahi hote - sirf shape + sha1-12 "
                    "(rotation wave RoE)"}


# ===========================================================================
# STAGE Q - API-SURFACE CONTROLS (GATED controls_allow_api_probe)
# ===========================================================================
def api_control_census(http, targets, conf):
    """GATED controls_allow_api_probe.

    Spec exposure census (12 paths) + GQL introspection-off control
    (GET-only query endpoint check, mutations NEVER) + WS origin-policy
    rollup (names-only, frames NEVER)."""
    gate = bool(conf.get("controls_allow_api_probe", False))
    result = {"gate": "controls_allow_api_probe=%s" % gate, "rows": [],
              "gql_rows": [], "ws_rollup": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual API wave documented (HC-16/HC-17)"}
    if not gate:
        return result
    base = _base_of(targets)
    if base:
        spec_cap = max(4, int(conf.get("controls_spec_paths", 12)))
        for path in SPEC_PATHS[:spec_cap]:
            if interrupted():
                break
            url = base + path
            try:
                r = probe(http, "GET", url, allow_redirects=False)
            except Exception as e:
                result["rows"].append({"url": url, "error": str(e)[:100]})
                continue
            live = bool(r.ok() and not is_soft404(r, None) and
                        ("openapi" in (r.text or "")[:800].lower() or
                         "swagger" in (r.text or "")[:800].lower() or
                         (r.text or "")[:1].strip() in ("{", "<")))
            result["rows"].append({"url": url, "status": r.status,
                                   "live": live,
                                   "gated": r.status in (401, 403)})
        # GQL introspection-off control (GET echo check only; no mutation)
        gql_url = None
        for t in (targets or []):
            if isinstance(t, str) and "graphql" in t.lower():
                gql_url = t
                break
        if gql_url:
            try:
                r = probe(http, "GET", gql_url, allow_redirects=False)
                body = (r.text or "")[:3000].lower()
                intro_off = ("introspection" in body and
                             ("disabled" in body or "disabled" in body))
                result["gql_rows"].append({
                    "url": gql_url, "status": r.status,
                    "introspection_off": intro_off,
                    "note": "introspection control aid (mutations NEVER "
                            "sent; P18 owns deep GQL)"})
            except Exception as e:
                result["gql_rows"].append({"url": gql_url,
                                           "error": str(e)[:100]})
    result["spec_live_count"] = len([r for r in result["rows"]
                                     if r.get("live")])
    return result


# ===========================================================================
# STAGE R - CI/CD + IaC GUARDRAIL CENSUS (GATED controls_allow_cicd_probe)
# ===========================================================================
def cicd_guard_census(http, targets, conf):
    """GATED controls_allow_cicd_probe.

    22-path artifact pool presence census (P24 cross-check) - live artifact
    = guardrail gap (repo-only policy fix); bodies REDACTED."""
    gate = bool(conf.get("controls_allow_cicd_probe", False))
    result = {"gate": "controls_allow_cicd_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual artifact wave documented (HC-18)"}
    if not gate:
        return result
    base = _base_of(targets)
    if not base:
        result["skipped_note"] = "no base"
        return result
    pool = GUARD_PATHS[:max(6, int(conf.get("controls_artifact_paths", 22)))]
    for path in pool:
        if interrupted():
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "noise": is_soft404(r, None),
                               "len": len(r.text or "")})
    live_n = len([r for r in result["rows"] if r.get("live")])
    result["live_count"] = live_n
    return result


# ===========================================================================
# STAGE S - EDGE TRUST-HEADER CONTROL (GATED controls_allow_edge_probe)
# ===========================================================================
EDGE_TRUST_HEADERS = [
    ("X-Original-URL", "/waspP25-edge"),
    ("X-Rewrite-URL", "/waspP25-edge"),
    ("X-Forwarded-Host", "waspP25.evil.invalid"),
    ("X-Forwarded-For", "203.0.113.9"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]


def edge_control_census(http, targets, conf):
    """GATED controls_allow_edge_probe.

    Trust-header echo differential (6 shapes, GET-only) - edge-strip control
    validated (no echo) ya gap (echo/misroute shape)."""
    gate = bool(conf.get("controls_allow_edge_probe", False))
    result = {"gate": "controls_allow_edge_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual edge wave documented (HC-19)"}
    if not gate:
        return result
    cap = max(3, int(conf.get("controls_probe_cap", 24)) // 3)
    for t in _two_stage(targets, re.compile(r"(?i)(admin|protected|api|"
                                            r"internal|console)"))[:cap]:
        echoes = []
        for hname, hval in EDGE_TRUST_HEADERS:
            try:
                r = probe(http, "GET", t, allow_redirects=False,
                          headers={hname: hval})
            except Exception as e:
                echoes.append({"header": hname, "error": str(e)[:80]})
                continue
            blob = ((r.text or "")[:3000] + " " + " ".join(
                "%s: %s" % (k, v) for k, v in (r.headers or {}).items()))
            echoed = hval.lower() in blob.lower()
            echoes.append({"header": hname, "status": r.status,
                           "echoed": echoed})
        n_echo = len([e for e in echoes if e.get("echoed")])
        result["rows"].append({"url": t, "echoes": echoes,
                               "echo_count": n_echo,
                               "edge_strict": n_echo == 0})
        if interrupted():
            break
    result["echo_urls"] = len([r for r in result["rows"]
                               if r.get("echo_count")])
    return result


# ===========================================================================
# STAGE T - CACHE-CONTROL VALIDATION (GATED controls_allow_cache_probe)
# ===========================================================================
def cache_control_census(http, targets, conf):
    """GATED controls_allow_cache_probe.

    Sensitive-page pool par cacheability shapes (no-store/private vs
    public/max-age) + CDN marker interplay (P22/P24 cross-check)."""
    gate = bool(conf.get("controls_allow_cache_probe", False))
    result = {"gate": "controls_allow_cache_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual cache wave documented (HC-20)"}
    if not gate:
        return result
    base = _base_of(targets)
    if not base:
        result["skipped_note"] = "no base"
        return result
    pool = CACHE_PATHS[:max(4, int(conf.get("controls_probe_cap", 24)) // 2)]
    for path in pool:
        url = base + path
        if interrupted():
            break
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        cc = ""
        for k, v in (r.headers or {}).items():
            if k.lower() == "cache-control":
                cc = str(v).lower()
                break
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())
        cdn = match_all_markers(WAF_DECL_RX, hdr_blob) or []
        sensitive = bool(re.search(r"(?i)(login|account|profile|admin|api/"
                                   r"me|billing|settings)", path))
        safe = ("no-store" in cc or "private" in cc or
                "max-age=0" in cc or not sensitive)
        result["rows"].append({"url": url, "status": r.status,
                               "cache_control": cc[:80], "sensitive":
                               sensitive, "cacheable": bool(cc) and
                               not ("no-store" in cc or "private" in cc),
                               "cdn_markers": cdn[:4],
                               "safe": safe})
    unsafe = len([r for r in result["rows"]
                  if r.get("sensitive") and not r.get("safe")])
    result["unsafe_count"] = unsafe
    return result

# ===========================================================================
# STAGE U - BYPASS2 CONTROL MATRIX (22 SECRET control-bypass shapes, GATED)
# ===========================================================================
def _bypass2_shapes(base_url, canary):
    """22 control-bypass GET shapes (canary family waspP25).

    Har shape ek documented access-control/edge-bypass technique ka INERT
    GET-probe equivalent hai: 403-protected path par path-normalization /
    header-trust / control-differential -> 2xx = control-gap detection.
    ACCEPTED = control gap (CONFIRMED-aid); REJECTED = control enforced
    (HARDENED). Method-override headers KABHI nahi (GET-only module)."""
    b = base_url.split("?")[0].rstrip("/")
    q = urllib.parse.quote
    return [
        ("CB-01", "double-slash path (normalizer merge differential)",
         "%s//" % b, {}),
        ("CB-02", "dot-segment /./ (canonicalization differential)",
         "%s/./" % b, {}),
        ("CB-03", "parent-segment /../ (traversal-normalizer differential)",
         "%s/%s/../" % (b, canary[:6]), {}),
        ("CB-04", "url-encoded dot %2e%2e (decoder differential)",
         "%s/%%2e%%2e/" % b, {}),
        ("CB-05", "semicolon path-param (matrix-param parser differential)",
         "%s;waspP25=1" % b, {}),
        ("CB-06", "tab-char %09 path (whitespace parser differential)",
         "%s%%09" % b, {}),
        ("CB-07", "space %20 path (trim differential)",
         "%s%%20" % b, {}),
        ("CB-08", "case-shuffle path (case-insensitive authz differential)",
         b.upper(), {}),
        ("CB-09", "trailing-slash add (route-match differential)",
         "%s/" % b, {}),
        ("CB-10", "double-url-encode (double-decoder differential)",
         "%s/%s" % (b, q(q(canary[:6]))), {}),
        ("CB-11", "X-Original-URL trust (proxy misroute shape)",
         b, {"X-Original-URL": "/"}),
        ("CB-12", "X-Rewrite-URL trust (rewrite-bypass shape)",
         b, {"X-Rewrite-URL": "/"}),
        ("CB-13", "X-Forwarded-Host: localhost (vhost-trust shape)",
         b, {"X-Forwarded-Host": "localhost"}),
        ("CB-14", "X-Forwarded-For: 127.0.0.1 (ip-allowlist trust shape)",
         b, {"X-Forwarded-For": "127.0.0.1"}),
        ("CB-15", "Host: localhost (internal-vhost shape)",
         b, {"Host": "localhost"}),
        ("CB-16", "X-Custom-IP-Authorization: 127.0.0.1 (custom-ip trust)",
         b, {"X-Custom-IP-Authorization": "127.0.0.1"}),
        ("CB-17", "Referer-trust shape (referer-based authz differential)",
         b, {"Referer": "%s/admin" % b}),
        ("CB-18", "HEAD-method differential (verb-authz gap shape)",
         b, {}),
        ("CB-19", "marker-param (list-normalizer differential)",
         "%s?marker=%s" % (b, canary[:6]), {}),
        ("CB-20", "Range partial-content (partial-authz gap shape)",
         b, {"Range": "bytes=0-0"}),
        ("CB-21", "method-override ABSENT check (X-HTTP-Method-Override "
         "kabhi bheja nahi - header-drop control aid; GET-only proof)",
         b, {}),
        ("CB-22", "accept-encoding confusion (decompress-differential aid)",
         b, {"Accept-Encoding": "gzip, identity"}),
    ]


def bypass2_census(http, targets, conf):
    """GATED controls_allow_bypass2: 22 shapes per top-target (GET/HEAD,
    canary differential). 403 baseline -> 2xx shaped = ACCEPTED (control
    gap); waf-block = BLOCKED; reject-class = control enforced (HARDENED)."""
    gate = bool(conf.get("controls_allow_bypass2", False))
    result = {"gate": "controls_allow_bypass2=%s" % gate, "rows": [],
              "shapes_total": 22,
              "skipped_note": "" if gate else
              "RoE gate OFF - manual bypass2 wave documented (HC-21)"}
    if not gate:
        return result
    # protected (4xx) targets prioritize - differential wahi meaningful hai
    prot = _prioritize(targets, re.compile(
        r"(?i)(protected|admin|internal|private|secure|console|s3|storage)"))
    cap = max(1, min(4, int(conf.get("controls_bypass2_cap", 22)) // 4))
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
        canary = _canary("cb")
        shape_rows = []
        for sid, name, url, hdrs in _bypass2_shapes(t, canary):
            method = "HEAD" if sid == "CB-18" else "GET"
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
                               "reject_class": r.status in (401, 403, 409,
                                                            410, 422),
                               "waf_blocked": r.status in (403, 406, 429),
                               "range_shape": sid == "CB-20" and
                               r.status == 206})
        tested += 1
        acc = [s for s in shape_rows if s.get("accepted")]
        result["rows"].append({
            "url": t, "baseline_status": r0.status, "shapes": shape_rows,
            "accepted_count": len(acc), "accepted_ids": [s["id"] for s in acc],
            "blocked_count": len([s for s in shape_rows
                                  if s.get("waf_blocked")])})
    return result


# ===========================================================================
# STAGE V - CONTROLS POSTURE COMPOSITE (16-point score, offline)
# ===========================================================================
POSTURE_POINTS = [
    ("headers_present",    "18 hardening header controls present"),
    ("csp_strict",         "CSP strict (no unsafe-*/wildcard)"),
    ("waf_enforced",       "WAF canary block-shape verified"),
    ("rate_limited",       "429/Retry-After shape verified"),
    ("cors_strict",        "canary origins rejected (STRICT grade)"),
    ("cookies_hardened",   "Secure+HttpOnly+SameSite flags present"),
    ("auth_gated",         "protected pool uniform 30x/40x gated"),
    ("methods_locked",     "no destructive methods advertised"),
    ("errors_masked",      "errors generic/masked (no verbose shapes)"),
    ("tls_strong",         "HSTS max-age>=31536000 (+redirect shape)"),
    ("echo_sanitized",     "marker echo stripped/encoded"),
    ("deps_patched",       "no stale/EOL dependency shapes"),
    ("observability_on",   "correlation/trace headers present"),
    ("secrets_absent",     "secret-shape re-scan clean"),
    ("api_locked",         "spec closed + introspection locked"),
    ("bypass2_blocked",    "bypass2 shapes rejected/blocked"),
]


def posture_composite(results):
    """Per-endpoint 16-point controls posture composite (offline).

    results = stage result dict (headers/csp/waf/rate/cors/cookies/authgate/
    methods/errors/tls/echo/deps/observability/secrets/api/cicd/edge/cache/
    bypass2). Score 0-16; <6 = WEAK (finding), >=10 = STRONG (positive)."""
    per_ep = {}

    def _bump(url, point, ok_flag):
        d = per_ep.setdefault(url or "?", {p[0]: None for p in POSTURE_POINTS})
        cur = d.get(point)
        d[point] = bool(ok_flag) if cur is None else (cur or bool(ok_flag))

    for row in (results.get("headers") or {}).get("rows", []):
        if row.get("url") and row.get("present") is not None:
            _bump(row.get("url"), "headers_present",
                  len(row.get("present") or []) >= 12)
    for row in (results.get("csp") or {}).get("rows", []):
        _bump(row.get("url"), "csp_strict", row.get("grade") == "strict")
    for row in (results.get("waf") or {}).get("rows", []):
        _bump(row.get("url"), "waf_enforced", row.get("enforced"))
    for row in (results.get("rate") or {}).get("rows", []):
        _bump(row.get("url"), "rate_limited", row.get("throttled_within_cap"))
    for row in (results.get("cors") or {}).get("rows", []):
        _bump(row.get("url"), "cors_strict", row.get("strict"))
        if row.get("reflect_any"):
            _bump(row.get("url"), "cors_strict", False)
    for row in (results.get("cookies") or {}).get("rows", []):
        _bump(row.get("url"), "cookies_hardened",
              row.get("grade") == "hardened")
    for row in (results.get("authgate") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "auth_gated",
                  row.get("gated") or row.get("login_shape"))
    if (results.get("authgate") or {}).get("uniform_gate"):
        for r in (results.get("authgate") or {}).get("rows", []):
            _bump(r.get("url"), "auth_gated", True)
    for row in (results.get("methods") or {}).get("rows", []):
        _bump(row.get("url"), "methods_locked", row.get("locked"))
    for row in (results.get("errors") or {}).get("rows", []):
        _bump(row.get("url"), "errors_masked",
              not row.get("verbose_hits"))
    for row in (results.get("tls") or {}).get("rows", []):
        _bump(row.get("url"), "tls_strong",
              row.get("grade") == "strong")
    for row in (results.get("echo") or {}).get("rows", []):
        _bump(row.get("url"), "echo_sanitized",
              row.get("grade") in ("encoded", "stripped"))
    for row in (results.get("deps") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "deps_patched",
                  not row.get("stale_deps"))
    for row in (results.get("observability") or {}).get("rows", []):
        _bump(row.get("url"), "observability_on",
              row.get("observability_on"))
    for row in (results.get("secrets") or {}).get("rows", []):
        if row.get("status") and not row.get("noise"):
            _bump(row.get("url"), "secrets_absent",
                  not row.get("shapes"))
    for row in (results.get("api") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "api_locked",
                  not row.get("live") or row.get("gated"))
    for row in (results.get("api") or {}).get("gql_rows", []):
        _bump(row.get("url"), "api_locked",
              row.get("introspection_off"))
    for row in (results.get("cicd") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "api_locked", not row.get("live"))
    for row in (results.get("edge") or {}).get("rows", []):
        _bump(row.get("url"), "echo_sanitized", row.get("edge_strict"))
    for row in (results.get("cache") or {}).get("rows", []):
        if row.get("sensitive"):
            _bump(row.get("url"), "errors_masked", row.get("safe"))
    for row in (results.get("bypass2") or {}).get("rows", []):
        _bump(row.get("url"), "bypass2_blocked",
              not row.get("accepted_count"))

    rows = []
    for url, pts in per_ep.items():
        score = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is True)
        known = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is not None)
        rows.append({"url": url, "score": score, "known_points": known,
                     "points": pts,
                     "grade": "STRONG" if score >= 10 else
                              "PARTIAL" if score >= 6 else "WEAK"})
    rows.sort(key=lambda r: r["score"])
    return {"points": POSTURE_POINTS, "rows": rows,
            "weak": [r for r in rows if r["grade"] == "WEAK"],
            "strong": [r for r in rows if r["grade"] == "STRONG"]}

# ===========================================================================
# STAGE W - CROSS-MODULE CONTROL KILL-CHAINS (CH01..CH30)
# ===========================================================================
def build_chains(results, ff_seeds):
    """30 control-gap kill-chains (P2..P24 handoffs + P25 census rows)."""
    chains = [
        ("CH01", "Hardening headers absent -> browser-defense layer off",
         "Stage C missing -> HC-01 header middleware fix"),
        ("CH02", "Disclosure banner -> tech fingerprint -> targeted attacks",
         "Stage C disclosure -> HC-02 banner-strip fix"),
        ("CH03", "WAF declared-not-enforced -> canary pass-through",
         "Stage D declared-only -> HC-03 rule-tune fix"),
        ("CH04", "No WAF shape -> direct-to-origin attack surface",
         "Stage D absent -> edge-WAF adoption review"),
        ("CH05", "Rate-limit gap -> brute/stuff window (P22/P9 handoff)",
         "Stage E gap -> HC-04 throttle middleware fix"),
        ("CH06", "CORS reflect-any -> cross-origin data theft",
         "Stage F REFLECT-ANY -> HC-05 origin-allowlist fix"),
        ("CH07", "Weak cookie flags -> session hijack aid (P10 handoff)",
         "Stage G weak -> HC-06 cookie middleware fix"),
        ("CH08", "Auth-gate 200-leak -> protected data anon access",
         "Stage H leak -> HC-07 deny-by-default fix (P11 handoff)"),
        ("CH09", "Destructive methods advertised -> state-change surface",
         "Stage I advertised -> HC-08 method-allowlist fix"),
        ("CH10", "Verbose errors -> fingerprint + RequestID aid (P12)",
         "Stage J verbose -> HC-09 generic-error fix"),
        ("CH11", "HSTS absent -> downgrade window (MITM aid)",
         "Stage K weak -> HC-10 HSTS preload fix"),
        ("CH12", "Decorative CSP -> XSS exposure (P12/XSS handoff)",
         "Stage L decorative -> HC-11 nonce/hash CSP fix"),
        ("CH13", "Raw echo -> sanitization gap (payload-aid, INERT-only)",
         "Stage M raw -> HC-12 contextual-encode fix"),
        ("CH14", "EOL dependency -> known-CVE window (P6 handoff)",
         "Stage N stale -> HC-13 patch-SLA fix"),
        ("CH15", "No trace headers -> detection blind spot (SOC aid)",
         "Stage O off -> HC-14 request-id middleware fix"),
        ("CH16", "Secret shape re-scan hit -> rotation wave (P7/P23/P24)",
         "Stage P hit -> HC-15 vault+rotation fix"),
        ("CH17", "Spec enumerable -> API surface map (P17 handoff)",
         "Stage Q spec live -> HC-16 spec-gating fix"),
        ("CH18", "GQL introspection open -> schema enumeration (P18)",
         "Stage Q introspection -> HC-17 introspection-off fix"),
        ("CH19", "CI/CD artifact live -> pipeline secret exposure (P24)",
         "Stage R live -> HC-18 artifact-removal fix"),
        ("CH20", "tfstate/IaC public -> infra disclosure (P24 handoff)",
         "Stage R tfstate -> state-store hardening"),
        ("CH21", "Edge trust echo -> misroute access (P11 handoff)",
         "Stage S echo -> HC-19 edge-strip fix"),
        ("CH22", "Cacheable sensitive -> cache deception (P22/P24)",
         "Stage T unsafe -> HC-20 no-store fix"),
        ("CH23", "Bypass2 accepted -> normalize-before-authz gap (P11)",
         "Stage U accepted_ids -> HC-21 normalizer fix"),
        ("CH24", "Posture WEAK composite -> priority hardening order",
         "Stage V weak rows -> REMEDIATION_PLAN P1/P2"),
        ("CH25", "P23 misconfig handoff -> control cross-verify chain",
         "P23 ff -> Stage C/L/K cross-check"),
        ("CH26", "P24 cloud posture handoff -> controls drift chain",
         "P24 ff -> Stage A targeting + Stage V drift"),
        ("CH27", "P22 replay/cacheable handoff -> throttle+cache controls",
         "P22 ff -> Stage E/T cross-check"),
        ("CH28", "P9/P21 auth handoff -> auth-gate + cookie controls",
         "P9/P21 ff -> Stage G/H cross-check"),
        ("CH29", "P7/P5 secrets handoff -> hygiene re-scan controls",
         "P7/P5 ff -> Stage P census"),
        ("CH30", "P25 controls + P26/P32 report -> hardening handoff",
         "Stage V/Z -> P26/P32 ff routing"),
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
    """Stage rows -> 6-class verdict rows (CONFIRMED=control-gap /
    SUSPECTED / HARDENED=control-enforced / BLOCKED / SKIPPED / NOISE)."""
    rows = []

    def _add(stage, url, verdict, signals, detail):
        rows.append({"stage": stage, "url": url, "verdict": verdict,
                     "signals": signals, "detail": truncate(str(detail), 220)})

    # ---- HEADERS (C) ----
    for r in (results.get("headers") or {}).get("rows", []):
        if r.get("noise"):
            continue
        u = r.get("url", "?")
        present = len(r.get("present") or [])
        strict = len(r.get("strict") or [])
        if present == 0:
            _add("C", u, "CONFIRMED", ["headers-absent"],
                 "0/18 hardening controls present")
        elif strict >= 12:
            _add("C", u, "HARDENED", ["headers-strict"],
                 "%d/18 strict" % strict)
        elif present < 8:
            _add("C", u, "CONFIRMED", ["headers-partial"],
                 "only %d/18 present (gap)" % present)
        else:
            _add("C", u, "SUSPECTED", ["headers-mixed"],
                 "present=%d strict=%d" % (present, strict))
    # ---- WAF (D) ----
    for r in (results.get("waf") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("enforced"):
            _add("D", u, "HARDENED", ["waf-block-shape"],
                 "block=%s" % ",".join((r.get("block_shapes") or [])[:3]))
        elif r.get("grade") == "declared-only":
            _add("D", u, "CONFIRMED", ["declared-not-enforced"],
                 "declared=%s pass-through" % ",".join(
                     (r.get("declared") or [])[:2]))
        elif r.get("grade") == "absent":
            _add("D", u, "SUSPECTED", ["waf-absent"],
                 "no block/declared shape")
    # ---- RATE (E) ----
    for r in (results.get("rate") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("throttled_within_cap"):
            _add("E", u, "HARDENED", ["429-shape"], "throttle verified")
        else:
            _add("E", u, "CONFIRMED", ["rate-gap"],
                 "no throttle shape within cap=%s" % r.get("cap"))
    # ---- CORS (F) ----
    for r in (results.get("cors") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("reflect_any"):
            _add("F", u, "CONFIRMED", ["acao-reflect"],
                 "grade=%s" % r.get("grade"))
        elif r.get("reflect_null"):
            _add("F", u, "SUSPECTED", ["acao-null"],
                 "null-origin allowed")
        elif r.get("strict"):
            _add("F", u, "HARDENED", ["cors-strict"], "canaries rejected")
    # ---- COOKIES (G) ----
    for r in (results.get("cookies") or {}).get("rows", []):
        if r.get("noise"):
            continue
        u = r.get("url", "?")
        g = r.get("grade")
        if g == "hardened":
            _add("G", u, "HARDENED", ["cookie-flags"], "all flags set")
        elif g in ("weak", "partial"):
            _add("G", u, "CONFIRMED", ["cookie-flags-weak"],
                 "weak=%s" % ",".join(r.get("weak_flags") or []))
    # ---- AUTHGATE (H) ----
    for r in (results.get("authgate") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("leak"):
            _add("H", u, "CONFIRMED", ["anon-200-leak"],
                 "protected path anon-GET 200 (no login shape)")
        elif r.get("gated"):
            _add("H", u, "HARDENED", ["gate-30x-40x"], "uniform gate")
    # ---- METHODS (I) ----
    for r in (results.get("methods") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("advertised_destructive"):
            _add("I", u, "CONFIRMED", ["methods-advertised"],
                 "allow=%s" % ",".join(r["advertised_destructive"][:5]))
        elif r.get("locked"):
            _add("I", u, "HARDENED", ["methods-locked"], "GET/HEAD/OPTIONS")
    # ---- ERRORS (J) ----
    for r in (results.get("errors") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("verbose_hits"):
            _add("J", u, "CONFIRMED", ["verbose-error"],
                 "shapes=%s" % ",".join(r["verbose_hits"][:4]))
        elif r.get("grade") == "masked":
            _add("J", u, "HARDENED", ["errors-masked"], "generic shape")
    # ---- TLS (K) ----
    for r in (results.get("tls") or {}).get("rows", []):
        if r.get("noise"):
            continue
        u = r.get("url", "?")
        if r.get("grade") == "strong":
            _add("K", u, "HARDENED", ["hsts-strong"], "max-age>=31536000")
        elif r.get("grade") == "weak" or r.get("mixed_content_hits"):
            _add("K", u, "CONFIRMED", ["tls-weak"],
                 "hsts=%r mixed=%s" % (r.get("hsts"),
                                       r.get("mixed_content_hits")))
    # ---- CSP (L) ----
    for r in (results.get("csp") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("grade") == "strict":
            _add("L", u, "HARDENED", ["csp-strict"], "no unsafe-*")
        elif r.get("grade") == "decorative":
            _add("L", u, "CONFIRMED", ["csp-decorative"],
                 "flags=%s" % ",".join((r.get("flags") or [])[:4]))
        elif r.get("grade") == "partial":
            _add("L", u, "SUSPECTED", ["csp-partial"],
                 "flags=%s" % ",".join((r.get("flags") or [])[:4]))
    # ---- ECHO (M) ----
    for r in (results.get("echo") or {}).get("rows", []):
        u = r.get("url", "?")
        g = r.get("grade")
        if g == "raw":
            _add("M", u, "CONFIRMED", ["raw-echo"], str(r.get("detail")))
        elif g in ("encoded", "stripped"):
            _add("M", u, "HARDENED", ["echo-controlled"], g)
    # ---- DEPS (N) ----
    for r in (results.get("deps") or {}).get("rows", []):
        if r.get("noise"):
            continue
        u = r.get("url", "?")
        if r.get("stale_deps"):
            _add("N", u, "CONFIRMED", ["dep-stale"],
                 "deps=%s" % ",".join(r["stale_deps"][:4]))
    # ---- OBSERVABILITY (O) ----
    for r in (results.get("observability") or {}).get("rows", []):
        if r.get("noise"):
            continue
        u = r.get("url", "?")
        if r.get("observability_on"):
            _add("O", u, "HARDENED", ["trace-headers"],
                 "shapes=%s" % ",".join((r.get("shapes") or [])[:3]))
        else:
            _add("O", u, "SUSPECTED", ["observability-off"],
                 "no correlation headers")
    # ---- SECRETS (P) ----
    for r in (results.get("secrets") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("shapes"):
            _add("P", u, "CONFIRMED", ["secret-shape"],
                 "shapes=%s" % ",".join([s.get("shape", "") for s in
                                         (r.get("shapes") or [])[:4]]))
    # ---- API (Q) ----
    for r in (results.get("api") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and not r.get("gated"):
            _add("Q", u, "CONFIRMED", ["spec-live"], "spec enumerable")
        elif r.get("gated"):
            _add("Q", u, "HARDENED", ["spec-gated"], "401/403")
    for r in (results.get("api") or {}).get("gql_rows", []):
        u = r.get("url", "?")
        if r.get("introspection_off"):
            _add("Q", u, "HARDENED", ["introspection-off"], "locked")
        else:
            _add("Q", u, "SUSPECTED", ["introspection-open"],
                 "P18 handoff aid")
    # ---- CICD (R) ----
    for r in (results.get("cicd") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and not r.get("noise"):
            _add("R", u, "CONFIRMED", ["artifact-live"], "guardrail gap")
        elif r.get("status") and not r.get("live"):
            _add("R", u, "HARDENED", ["artifact-absent"], "repo-only OK")
    # ---- EDGE (S) ----
    for r in (results.get("edge") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("echo_count"):
            _add("S", u, "CONFIRMED", ["edge-echo"],
                 "echoes=%d" % r["echo_count"])
        elif r.get("edge_strict"):
            _add("S", u, "HARDENED", ["edge-strict"], "no echo")
    # ---- CACHE (T) ----
    for r in (results.get("cache") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("sensitive") and not r.get("safe"):
            _add("T", u, "CONFIRMED", ["cacheable-sensitive"],
                 "cc=%r" % r.get("cache_control"))
        elif r.get("sensitive") and r.get("safe"):
            _add("T", u, "HARDENED", ["cache-safe"], "no-store/private")
    # ---- BYPASS2 (U) ----
    for r in (results.get("bypass2") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("accepted_count"):
            _add("U", u, "CONFIRMED", ["bypass2-accepted"],
                 "ids=%s" % ",".join(r.get("accepted_ids", [])[:8]))
        elif r.get("baseline_status"):
            _add("U", u, "HARDENED", ["bypass2-rejected"],
                 "baseline=%s" % r.get("baseline_status"))
    return rows

# ===========================================================================
# STAGE Y - TECHNIQUE MATRIX (24 families x 247 rows + CWE + MITRE)
# ===========================================================================
MATRIX_CATALOG = {
    "CONTROL_HEADERS": [
        ("CSP presence control", "CWE-693", "T1018"),
        ("CSP strict value (no unsafe-inline)", "CWE-79", "T1018"),
        ("HSTS max-age>=31536000", "CWE-319", "T1040"),
        ("X-Frame-Options DENY/SAMEORIGIN", "CWE-1021", "T1018"),
        ("X-Content-Type-Options nosniff", "CWE-430", "T1018"),
        ("Referrer-Policy strict", "CWE-200", "T1018"),
        ("Permissions-Policy deny-default", "CWE-693", "T1018"),
        ("COOP same-origin", "CWE-1021", "T1018"),
        ("COEP require-corp", "CWE-1021", "T1018"),
        ("CORP same-origin", "CWE-1021", "T1018"),
        ("Cache-Control no-store on sensitive", "CWE-524", "T1018"),
    ],
    "CSP_CONTROL": [
        ("default-src directive present", "CWE-693", "T1018"),
        ("object-src 'none'", "CWE-693", "T1018"),
        ("base-uri restricted", "CWE-79", "T1018"),
        ("frame-ancestors restricted", "CWE-1021", "T1018"),
        ("unsafe-inline detection", "CWE-79", "T1018"),
        ("unsafe-eval detection", "CWE-79", "T1018"),
        ("wildcard source detection", "CWE-79", "T1018"),
        ("nonce-based script policy", "CWE-693", "T1018"),
        ("hash-based script policy", "CWE-693", "T1018"),
        ("report-to endpoint defined", "CWE-778", "T1018"),
        ("decorative-CSP grading", "CWE-693", "T1018"),
    ],
    "WAF_CONTROL": [
        ("WAF declared-marker census", "CWE-693", "T1018"),
        ("canary block-shape differential", "CWE-693", "T1018"),
        ("declared-vs-enforced grading", "CWE-693", "T1018"),
        ("403/406/429 block classes", "CWE-693", "T1018"),
        ("block-page fingerprint", "CWE-693", "T1018"),
        ("rule-tune gap detection", "CWE-693", "T1018"),
        ("XSS-family rule coverage (documented)", "CWE-79", "T1018"),
        ("SQLi-family rule coverage (documented)", "CWE-89", "T1018"),
        ("traversal-family rule coverage (documented)", "CWE-22", "T1018"),
        ("edge-WAF absence detection", "CWE-693", "T1018"),
    ],
    "RATE_CONTROL": [
        ("429 shape census", "CWE-770", "T1110"),
        ("Retry-After header control", "CWE-770", "T1110"),
        ("RateLimit-* header control", "CWE-770", "T1110"),
        ("X-RateLimit header control", "CWE-770", "T1110"),
        ("throttle-body shape", "CWE-770", "T1110"),
        ("6-sequential bounded canary", "CWE-770", "T1110"),
        ("burst-recovery (documented)", "CWE-770", "T1110"),
        ("per-key quota shape (documented)", "CWE-770", "T1110"),
        ("full-burst FORBIDDEN-AUTO discipline", "CWE-693", "T1110"),
    ],
    "CORS_CONTROL": [
        ("canary origin reflection grading", "CWE-942", "T1018"),
        ("null-origin allowance", "CWE-942", "T1018"),
        ("ACAO wildcard detection", "CWE-942", "T1018"),
        ("credential-reflection shape", "CWE-942", "T1018"),
        ("origin-allowlist verification", "CWE-942", "T1018"),
        ("STRICT grade verification", "CWE-942", "T1018"),
        ("storage-endpoint CORS interplay", "CWE-942", "T1018"),
        ("preflight policy shape", "CWE-942", "T1018"),
        ("canary *.invalid discipline", "CWE-693", "T1018"),
    ],
    "COOKIE_CONTROL": [
        ("Secure flag census", "CWE-614", "T1557"),
        ("HttpOnly flag census", "CWE-1004", "T1539"),
        ("SameSite strict/lax census", "CWE-1275", "T1539"),
        ("__Host/__Secure prefix", "CWE-1275", "T1539"),
        ("Expires/Max-Age lifecycle", "CWE-613", "T1539"),
        ("weak-flag grading", "CWE-614", "T1539"),
        ("session-cookie inventory", "CWE-384", "T1539"),
        ("P10 handoff cross-check", "CWE-693", "T1018"),
        ("cookie value never stored", "CWE-200", "T1018"),
        ("hardened grade verification", "CWE-693", "T1018"),
    ],
    "AUTHGATE_CONTROL": [
        ("anon-GET differential (no creds)", "CWE-306", "T1018"),
        ("uniform 30x gate shape", "CWE-285", "T1018"),
        ("uniform 401/403 gate shape", "CWE-285", "T1018"),
        ("200-leak detection", "CWE-284", "T1018"),
        ("login-shape redirect aid", "CWE-287", "T1018"),
        ("protected-path pool (20)", "CWE-693", "T1018"),
        ("deny-by-default verification", "CWE-285", "T1018"),
        ("soft-404 noise guard", "CWE-693", "T1018"),
        ("P11 deep-authz handoff", "CWE-284", "T1018"),
        ("no credential stuffing (FORBIDDEN-AUTO)", "CWE-307", "T1110"),
        ("admin-pool coverage", "CWE-284", "T1018"),
    ],
    "METHOD_CONTROL": [
        ("OPTIONS Allow census", "CWE-433", "T1018"),
        ("ACAM census", "CWE-433", "T1018"),
        ("destructive-advertise detection", "CWE-433", "T1018"),
        ("PUT/DELETE/PATCH flag", "CWE-434", "T1018"),
        ("TRACE/TRACK flag (documented)", "CWE-16", "T1018"),
        ("PROPFIND/MKCOL flag", "CWE-433", "T1018"),
        ("locked-grade verification", "CWE-693", "T1018"),
        ("method NEVER sent discipline", "CWE-693", "T1018"),
        ("wasp_core L4 double-guard", "CWE-693", "T1018"),
    ],
    "ERROR_CONTROL": [
        ("RequestID shape detection", "CWE-209", "T1018"),
        ("traceback shape detection", "CWE-209", "T1018"),
        ("SQL-shape error detection", "CWE-209", "T1018"),
        ("path-disclosure detection", "CWE-209", "T1018"),
        ("framework-mark detection", "CWE-200", "T1018"),
        ("exception-class detection", "CWE-209", "T1018"),
        ("internal-ip leak detection", "CWE-200", "T1018"),
        ("debug-token detection", "CWE-489", "T1018"),
        ("env-leak detection", "CWE-526", "T1018"),
        ("generic-mask verification", "CWE-209", "T1018"),
    ],
    "TLS_CONTROL": [
        ("HSTS presence control", "CWE-319", "T1040"),
        ("HSTS max-age grading", "CWE-319", "T1040"),
        ("preload flag control", "CWE-319", "T1040"),
        ("http->https redirect shape", "CWE-319", "T1557"),
        ("mixed-content shape detection", "CWE-311", "T1557"),
        ("Expect-CT review", "CWE-319", "T1040"),
        ("transport-strong verification", "CWE-693", "T1018"),
        ("weak-grade detection", "CWE-319", "T1040"),
        ("secure-cookie interplay", "CWE-614", "T1557"),
        ("P23 transport cross-check", "CWE-693", "T1018"),
    ],
    "ECHO_CONTROL": [
        ("synthetic marker reflection", "CWE-79", "T1018"),
        ("raw-context grading", "CWE-79", "T1018"),
        ("encoded-context verification", "CWE-79", "T1018"),
        ("stripped verification", "CWE-79", "T1018"),
        ("no-payload discipline", "CWE-693", "T1018"),
        ("contextual-encode detection", "CWE-116", "T1018"),
        ("double-echo surface aid", "CWE-79", "T1018"),
        ("GET-only echo census", "CWE-693", "T1018"),
        ("XSS-handoff (P12) aid", "CWE-79", "T1018"),
    ],
    "DEP_CONTROL": [
        ("jQuery stale-window detection", "CWE-1104", "T1018"),
        ("Bootstrap stale-window", "CWE-1104", "T1018"),
        ("AngularJS EOL detection", "CWE-1104", "T1018"),
        ("React legacy-window", "CWE-1104", "T1018"),
        ("Vue legacy-window", "CWE-1104", "T1018"),
        ("PHP EOL detection", "CWE-1104", "T1018"),
        ("Node EOL detection", "CWE-1104", "T1018"),
        ("nginx/apache/IIS advisory-window", "CWE-1104", "T1018"),
        ("OpenSSL EOL detection", "CWE-326", "T1018"),
        ("patch-SLA verification aid", "CWE-1104", "T1018"),
    ],
    "OBSERVABILITY": [
        ("x-request-id presence", "CWE-778", "T1018"),
        ("x-trace-id presence", "CWE-778", "T1018"),
        ("x-correlation-id presence", "CWE-778", "T1018"),
        ("amzn-trace presence", "CWE-778", "T1018"),
        ("sentry-trace presence", "CWE-778", "T1018"),
        ("traceparent (W3C) presence", "CWE-778", "T1018"),
        ("server-timing presence", "CWE-778", "T1018"),
        ("detection-aid grading", "CWE-778", "T1018"),
        ("audit-log review (documented)", "CWE-778", "T1562"),
    ],
    "SECRETS_HYGIENE": [
        ("30-shape re-scan (sha1-only)", "CWE-798", "T1552"),
        ("AWS-key shape", "CWE-798", "T1552"),
        ("GCP/AIza shape", "CWE-798", "T1552"),
        ("Azure-conn/SAS shape", "CWE-798", "T1552"),
        ("JWT-in-page shape", "CWE-798", "T1552"),
        ("private-key shape", "CWE-321", "T1552"),
        ("db-url-creds shape", "CWE-798", "T1552"),
        ("internal-host/ip shapes", "CWE-200", "T1018"),
        ("rotation-need flagging", "CWE-320", "T1552"),
        ("vault-adoption aid", "CWE-798", "T1552"),
    ],
    "API_CONTROL": [
        ("spec exposure census (12)", "CWE-538", "T1018"),
        ("spec-gating verification", "CWE-538", "T1018"),
        ("GQL introspection-off control", "CWE-200", "T1018"),
        ("WS origin-policy rollup", "CWE-346", "T1018"),
        ("mutation NEVER discipline", "CWE-693", "T1018"),
        ("frames NEVER discipline", "CWE-693", "T1018"),
        ("names-only census", "CWE-200", "T1018"),
        ("P17/P18/P19 handoffs", "CWE-693", "T1018"),
        ("api-locked verification", "CWE-693", "T1018"),
        ("401/403 gating shape", "CWE-285", "T1018"),
    ],
    "CICD_GUARD": [
        ("workflows artifact census", "CWE-538", "T1213"),
        ("gitlab/jenkins census", "CWE-538", "T1213"),
        ("Dockerfile/compose census", "CWE-538", "T1213"),
        ("tfstate/tfvars census", "CWE-540", "T1213"),
        (".env/.env.bak census", "CWE-540", "T1213"),
        ("kubeconfig/values census", "CWE-540", "T1213"),
        ("bodies REDACTED discipline", "CWE-200", "T1018"),
        ("guardrail-gap flagging", "CWE-693", "T1018"),
        ("P24 cross-check", "CWE-693", "T1018"),
    ],
    "EDGE_CONTROL": [
        ("X-Original-URL echo differential", "CWE-348", "T1036"),
        ("X-Rewrite-URL echo differential", "CWE-348", "T1036"),
        ("X-Forwarded-Host echo", "CWE-348", "T1036"),
        ("X-Forwarded-For echo", "CWE-290", "T1036"),
        ("X-Custom-IP-Authorization echo", "CWE-290", "T1036"),
        ("edge-strip verification", "CWE-693", "T1018"),
        ("misroute-shape detection", "CWE-348", "T1036"),
        ("GET-only discipline", "CWE-693", "T1018"),
        ("HC-19 remediation mapping", "CWE-693", "T1018"),
    ],
    "CACHE_CONTROL": [
        ("sensitive-page cacheability", "CWE-524", "T1018"),
        ("no-store verification", "CWE-524", "T1018"),
        ("private verification", "CWE-524", "T1018"),
        ("public/max-age unsafe shape", "CWE-524", "T1018"),
        ("CDN marker interplay", "CWE-525", "T1018"),
        ("cache-deception aid", "CWE-524", "T1018"),
        ("P22 cacheable rollup", "CWE-525", "T1018"),
        ("safe-grade verification", "CWE-693", "T1018"),
        ("HC-20 mapping", "CWE-693", "T1018"),
    ],
    "BYPASS2_CONTROL": [
        ("double-slash normalizer differential", "CWE-436", "T1036"),
        ("dot-segment canonicalization", "CWE-436", "T1036"),
        ("parent-segment traversal normalizer", "CWE-436", "T1036"),
        ("encoded-dot decoder differential", "CWE-436", "T1036"),
        ("semicolon matrix-param parser", "CWE-436", "T1036"),
        ("tab-char whitespace parser", "CWE-436", "T1036"),
        ("space-trim differential", "CWE-436", "T1036"),
        ("case-shuffle authz differential", "CWE-178", "T1036"),
        ("trailing-slash route-match", "CWE-436", "T1036"),
        ("double-url-encode differential", "CWE-436", "T1036"),
        ("X-Original-URL trust", "CWE-348", "T1036"),
        ("X-Rewrite-URL trust", "CWE-348", "T1036"),
        ("X-Forwarded-Host vhost-trust", "CWE-348", "T1036"),
        ("X-Forwarded-For allowlist-trust", "CWE-290", "T1036"),
        ("Host internal-vhost trust", "CWE-348", "T1036"),
        ("X-Custom-IP-Authorization trust", "CWE-290", "T1036"),
        ("Referer-trust authz differential", "CWE-290", "T1036"),
        ("HEAD verb-authz differential", "CWE-433", "T1036"),
        ("marker-param normalizer", "CWE-436", "T1036"),
        ("Range partial-content gap", "CWE-830", "T1036"),
        ("method-override absent proof (GET-only)", "CWE-433", "T1036"),
        ("accept-encoding confusion aid", "CWE-437", "T1036"),
    ],
    "POSTURE": [
        ("16-point composite scoring", "CWE-693", "T1106"),
        ("headers_present point", "CWE-693", "T1106"),
        ("csp_strict point", "CWE-79", "T1106"),
        ("waf_enforced point", "CWE-693", "T1106"),
        ("rate_limited point", "CWE-770", "T1106"),
        ("cors_strict point", "CWE-942", "T1106"),
        ("auth_gated point", "CWE-285", "T1106"),
        ("errors_masked point", "CWE-209", "T1106"),
        ("bypass2_blocked point", "CWE-436", "T1106"),
        ("weak-row prioritization", "CWE-693", "T1106"),
    ],
    "REMEDIATION": [
        ("P1 critical SLA mapping (0-48h)", "CWE-693", "T1106"),
        ("P2 high SLA mapping (2-7d)", "CWE-693", "T1106"),
        ("P3 medium SLA mapping (sprint)", "CWE-693", "T1106"),
        ("P4 low SLA mapping (quarter)", "CWE-693", "T1106"),
        ("P5 continuous mapping", "CWE-693", "T1106"),
        ("owner/effort assignment", "CWE-693", "T1106"),
        ("verification kill-tests", "CWE-693", "T1106"),
        ("hardening checklist (22 rows)", "CWE-693", "T1106"),
        ("REMEDIATION_PLAN renderer", "CWE-693", "T1106"),
        ("re-verification cadence", "CWE-693", "T1106"),
    ],
    "COMPLIANCE": [
        ("CIS-style header benchmark mapping", "CWE-693", "T1106"),
        ("OWASP ASVS control mapping aid", "CWE-693", "T1106"),
        ("CWE coverage map", "CWE-693", "T1106"),
        ("MITRE technique map", "CWE-693", "T1106"),
        ("RoE-gate documentation", "CWE-693", "T1106"),
        ("INERT/detection-only attestation", "CWE-693", "T1106"),
        ("scope-firewall discipline", "CWE-284", "T1018"),
        ("PII/secret redaction discipline", "CWE-200", "T1018"),
        ("RWX 0777 artifact discipline", "CWE-732", "T1018"),
        ("checkpoint resume discipline", "CWE-693", "T1018"),
        ("zero-egress discipline", "CWE-693", "T1018"),
    ],
    "DRIFT": [
        ("baseline sha1-16 fingerprint", "CWE-693", "T1106"),
        ("verdict-count drift snapshot", "CWE-693", "T1106"),
        ("posture-row drift snapshot", "CWE-693", "T1106"),
        ("next-run diff aid", "CWE-693", "T1106"),
        ("regression flagging aid", "CWE-693", "T1106"),
        ("control-cadence documentation", "CWE-693", "T1106"),
        ("HARDENED-count trend", "CWE-693", "T1106"),
        ("CONFIRMED-gap trend", "CWE-693", "T1106"),
    ],
    "HANDOFF": [
        ("P23 misconfig cross-verify", "CWE-693", "T1106"),
        ("P24 cloud posture cross-verify", "CWE-693", "T1106"),
        ("P22 throttle/cache cross-verify", "CWE-693", "T1106"),
        ("P11 authz handoff", "CWE-284", "T1106"),
        ("P12 inject handoff (echo/errors)", "CWE-209", "T1106"),
        ("P9 auth handoff (cookies)", "CWE-287", "T1106"),
        ("P10 session handoff", "CWE-384", "T1106"),
        ("P17/P18/P19 api handoffs", "CWE-693", "T1106"),
        ("P26 reporting handoff", "CWE-693", "T1106"),
        ("P32 exec-report handoff", "CWE-693", "T1106"),
        ("ff routing (to_phase26/32/11/12/9)", "CWE-693", "T1106"),
    ],
}


def build_matrix():
    """Matrix rows (id CONTROLS-001..) - P12..P24-compatible shape."""
    rows = []
    n = 0
    for fam in MATRIX_CATALOG:
        for tech, cwe, mitre in MATRIX_CATALOG[fam]:
            n += 1
            rows.append({"id": "CONTROLS-%03d" % n, "family": fam,
                         "technique": tech, "cwe": cwe, "mitre": mitre})
    return rows

# ===========================================================================
# STAGE Z - RENDERERS (findings md / test plan / remediation / checklist /
#            exec summary / kickoff / playbooks)
# ===========================================================================
def render_findings_md(scope, F, verdict_rows, chains, meta):
    L = ["# P25 CONTROLS FINDINGS - %s" % scope.engagement, "",
         "- generated: %s" % now_iso(),
         "- mode: %s | probes: %s | INERT detection-only (canary %s)" % (
             meta.get("mode"), meta.get("probes_total", 0), CANARY_FAMILY),
         "- verdict orientation: HARDENED = control verified working; "
         "CONFIRMED = control GAP", ""]
    sc = _sev_counts(F)
    L.append("## Severity summary")
    L.append("")
    L.append("| sev | count |")
    L.append("|-----|-------|")
    for s in ("critical", "high", "medium", "low", "info"):
        L.append("| %s | %d |" % (s, sc.get(s, 0)))
    L.append("")
    L.append("## Findings")
    L.append("")
    for f in F.items:
        L.append("### %s %s [%s] (%s)" % (f["id"], f["title"],
                                          f["severity"].upper(),
                                          f["key"]))
        L.append("- endpoint: `%s`" % f["endpoint"])
        L.append("- detail: %s" % f["detail"])
        L.append("- why: %s" % f["why_it_matters"])
        L.append("")
    L.append("## Verdict census")
    L.append("")
    L.append("| stage | url | verdict | signals |")
    L.append("|-------|-----|---------|---------|")
    for r in verdict_rows[:80]:
        L.append("| %s | `%s` | %s | %s |" % (
            r["stage"], r.get("url", "")[:60], r["verdict"],
            ",".join(r.get("signals", []))[:60]))
    L.append("")
    L.append("## Control kill-chains (CH01..CH30)")
    L.append("")
    for c in chains:
        L.append("- **%s** %s -> %s" % (c["id"], c["title"], c["evidence"]))
    L.append("")
    return "\n".join(L) + "\n"


def render_test_plan(F, gates, matrix_rows):
    L = ["# P25 CONTROLS TEST PLAN (gated manual waves + kill-tests)", "",
         "RoE gates (default OFF - sirf written authorization par ON karo):",
         ""]
    for g, d in ROE_GATES:
        state = "ON" if gates.get(g) else "OFF"
        L.append("- %s = %s # %s" % (g, state, d))
    L.append("")
    L.append("## Gated manual waves (SKIPPED waves engine ne document kiye)")
    L.append("")
    L.append("- W1: full-burst rate wave (RB-01..RB-08) - engine 6-seq cap "
             "ke andar hi rehta hai")
    L.append("- W2: WAF payload-family wave (WP-01..WP-10) - engine sirf "
             "INERT canary; payloads manual RoE")
    L.append("- W3: deep authz wave (P11 owns; P25 = gate census only)")
    L.append("- W4: GQL mutation wave (P18 owns; P25 names-only)")
    L.append("- W5: WS frame wave (P19 owns; P25 origin-rollup only)")
    L.append("- W6: artifact-body review (P25 presence-only; bodies "
             "REDACTED)")
    L.append("")
    L.append("## Verification kill-tests (per finding-key)")
    L.append("")
    L.append("| key | kill-test |")
    L.append("|-----|-----------|")
    seen = set()
    for f in F.items:
        if f["key"] in seen:
            continue
        seen.add(f["key"])
        L.append("| %s | %s |" % (f["key"], _verify_for(f["key"])))
    L.append("")
    L.append("## Technique matrix coverage (%d rows x %d families)" % (
        len(matrix_rows), len(MATRIX_CATALOG)))
    L.append("")
    fams = {}
    for m in matrix_rows:
        fams[m["family"]] = fams.get(m["family"], 0) + 1
    for fam in sorted(fams):
        L.append("- %s: %d rows" % (fam, fams[fam]))
    L.append("")
    return "\n".join(L) + "\n"


def render_remediation_plan(rows):
    L = ["# P25 REMEDIATION PLAN (P1..P5 prioritized)", "",
         "Priority ladder: P1=critical 0-48h | P2=high 2-7d | P3=medium "
         "next-sprint | P4=low quarter | P5=info continuous", ""]
    for pri in ("P1", "P2", "P3", "P4", "P5"):
        sub = [r for r in rows if r["priority"] == pri]
        if not sub:
            continue
        sla = sub[0]["sla"]
        owner = sub[0]["owner"]
        L.append("## %s (SLA: %s | owner: %s) - %d rows" % (
            pri, sla, owner, len(sub)))
        L.append("")
        L.append("| finding | key | endpoint | action | verification |")
        L.append("|---------|-----|----------|--------|--------------|")
        for r in sub:
            L.append("| %s | %s | `%s` | %s | %s |" % (
                r.get("finding_id"), r["key"],
                (r.get("endpoint") or "")[:44], r["action"],
                r.get("verification", ""))[:400])
        L.append("")
    L.append("## Effort guidance")
    L.append("")
    L.append("- P1 rows: containment-first (expose-surface fix + rotation); "
             "verification kill-test same-day.")
    L.append("- P2 rows: sprint-fix + regression test; control re-verify "
             "next P25 run (drift baseline).")
    L.append("- P3 rows: hardening checklist batch (HC-xx); next sprint.")
    L.append("- P4/P5 rows: hygiene + cadence; security-champion owned.")
    L.append("")
    return "\n".join(L) + "\n"


def render_hardening_checklist():
    L = ["# P25 HARDENING CHECKLIST (CIS-style, 22 controls)", "",
         "| id | control | priority | done? |", "|----|---------|----------|-------|"]
    for cid, ctrl, pri in CHECKLIST_CATALOG:
        L.append("| %s | %s | %s | [ ] |" % (cid, ctrl, pri))
    L.append("")
    L.append("Usage: har P25 run ke baad checklist update karo; drift "
             "baseline (controls_drift.json) se regression track hota hai.")
    L.append("")
    return "\n".join(L) + "\n"


def render_exec_summary(scope, F, posture, verdict_rows, meta):
    sc = _sev_counts(F)
    hard = len([r for r in verdict_rows if r["verdict"] == "HARDENED"])
    conf = len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"])
    L = ["# P25 EXEC SUMMARY - %s" % scope.engagement, "",
         "Security-controls validation (INERT detection-only, v%s)." %
         PLAN_VERSION, "",
         "## Control posture",
         "- verified-enforced controls (HARDENED verdicts): **%d**" % hard,
         "- control gaps (CONFIRMED verdicts): **%d**" % conf,
         "- findings: %d (C=%d H=%d M=%d L=%d I=%d)" % (
             len(F.items), sc.get("critical", 0), sc.get("high", 0),
             sc.get("medium", 0), sc.get("low", 0), sc.get("info", 0)),
         "- posture rows: %d (weak=%d strong=%d)" % (
             len(posture.get("rows", [])), len(posture.get("weak", [])),
             len(posture.get("strong", []))),
         "- mode: %s | probes: %s" % (meta.get("mode"),
                                      meta.get("probes_total", 0)),
         ""]
    if posture.get("weak"):
        L.append("## WEAK control endpoints (priority order)")
        L.append("")
        for w in posture["weak"][:6]:
            L.append("- `%s` score=%d/16 (missing: %s)" % (
                w["url"][:56], w["score"],
                ",".join(k for k, v in w["points"].items()
                         if v is False)[:90]))
        L.append("")
    if posture.get("strong"):
        L.append("## STRONG control endpoints (positive signals)")
        L.append("")
        for s in posture["strong"][:4]:
            L.append("- `%s` score=%d/16" % (s["url"][:56], s["score"]))
        L.append("")
    L.append("## Top remediation (P1)")
    L.append("")
    p1 = [f for f in F.items if f["severity"] == "critical"][:6]
    if p1:
        for f in p1:
            L.append("- **%s** %s @ `%s` -> %s" % (
                f["id"], f["title"], f["endpoint"][:44],
                _verify_for(f["key"])[:80]))
    else:
        L.append("- koi P1 critical control-gap nahi (positive posture).")
    L.append("")
    return "\n".join(L) + "\n"


def render_kickoff(scope, gates, conf):
    L = ["# P25 CONTROLS KICKOFF - %s" % scope.engagement, "",
         "Authorized-controls-validation run config (v%s):" % PLAN_VERSION,
         "",
         "- scope: %s" % scope.describe(),
         "- targets: %s" % ", ".join((getattr(scope, "targets", None) or
                                      [])[:6]),
         "- mode discipline: 100%% INERT detection-only (canary %s)" %
         CANARY_FAMILY,
         "- GET-only module: GET/HEAD/OPTIONS (body KABHI nahi)",
         "- no attack payloads (WAF/echo stages sirf synthetic marker)",
         "- rate census 6-sequential HARD cap (burst FORBIDDEN-AUTO)",
         "- no creds/stuffing (auth-gate = anon differential only)",
         "- zero egress (scope firewall LAYER-4)", "",
         "## RoE gates (config.json me enable karo, written auth par)", ""]
    for g, d in ROE_GATES:
        L.append("- %s = %s # %s" % (g, str(bool(conf.get(g))).lower(), d))
    L.append("")
    L.append("## Next steps")
    L.append("")
    L.append("1. Gates ON karke re-run (gated censuses verify honge).")
    L.append("2. REMEDIATION_PLAN.md rows ko backlog me push karo.")
    L.append("3. HARDENING_CHECKLIST.md update + drift baseline compare.")
    L.append("4. Next run: P26/P32 reporting consolidation.")
    L.append("")
    return "\n".join(L) + "\n"


def render_playbooks():
    L = ["# P25 DOCUMENTED-ONLY PLAYBOOKS (koi row network par KABHI nahi)",
         "", "## Rate full-burst wave (RB-01..RB-08)", ""]
    for i, txt in RATE_BURST_PLAYBOOK:
        L.append("- **%s** %s" % (i, txt))
    L.append("")
    L.append("## WAF payload-family catalog (WP-01..WP-10; engine INERT "
             "canary only - payloads manual RoE wave)")
    L.append("")
    for i, txt in WAF_PAYLOAD_CATALOG:
        L.append("- **%s** %s" % (i, txt))
    L.append("")
    L.append("Discipline: ye playbooks manual, RoE-approved waves ke liye "
             "hain - P25 engine inme se KUCH BHI network par nahi bhejta.")
    L.append("")
    return "\n".join(L) + "\n"


def render_chains_txt(chains):
    L = ["P25 CONTROL KILL-CHAINS (%d)" % len(chains), "=" * 52, ""]
    for c in chains:
        L.append("%s | %s" % (c["id"], c["title"]))
        L.append("      -> %s" % c["evidence"])
    return "\n".join(L) + "\n"


def render_matrix_txt(matrix_rows):
    L = ["P25 TECHNIQUE MATRIX (%d rows x %d families)" % (
        len(matrix_rows), len(MATRIX_CATALOG)), "=" * 52, ""]
    for m in matrix_rows:
        L.append("%s | %-18s | %-52s | %-9s | %s" % (
            m["id"], m["family"], m["technique"][:52], m["cwe"],
            m["mitre"]))
    return "\n".join(L) + "\n"


def build_hypotheses(results, posture):
    """Next-run hypotheses (P26/P32 planning aid, offline)."""
    hyps = []
    if (results.get("waf") or {}).get("declared_only_count"):
        hyps.append({"id": "H-01", "h": "WAF declared-but-not-enforced on "
                     "some routes -> rule-tune + re-probe gated wave"})
    if (results.get("rate") or {}).get("rows"):
        if not (results.get("rate") or {}).get("enforced"):
            hyps.append({"id": "H-02", "h": "Rate-limit absent on login/api "
                         "-> throttle middleware + manual burst wave (RoE)"})
    if (results.get("cors") or {}).get("rows"):
        if any(r.get("reflect_any") for r in
               (results.get("cors") or {}).get("rows", [])):
            hyps.append({"id": "H-03", "h": "CORS reflect-any endpoint -> "
                         "origin-allowlist fix + regression probe"})
    for w in posture.get("weak", [])[:3]:
        hyps.append({"id": "H-%02d" % (len(hyps) + 4),
                     "h": "Posture WEAK %s -> HC checklist batch + "
                          "re-validation" % w.get("url", "")[:50]})
    if (results.get("bypass2") or {}).get("rows"):
        if any(r.get("accepted_count") for r in
               (results.get("bypass2") or {}).get("rows", [])):
            hyps.append({"id": "H-10", "h": "Bypass2 accepted shapes -> "
                         "normalize-before-authz fix + P11 joint wave"})
    if not hyps:
        hyps.append({"id": "H-00", "h": "Controls dominant (HARDENED "
                     "majority) -> drift monitor + cadence run"})
    return hyps

# ===========================================================================
# STAGE Z - REPORTS/ARTIFACTS (60 artifacts + feedforward + manifest)
# ===========================================================================
def write_reports(out, scope, F, ctx, meta, results, disc, conf,
                  chains, verdict_rows, matrix_rows, posture, guard, hyps,
                  remediation_rows, drift):
    """Sab artifacts likh (60). Bodies/secret-values REDACTED (names/
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
    _w_json("controls_targets.json", {
        "count": len(targets),
        "targets": [{"url": t.get("url"), "score": t.get("score"),
                     "kinds": t.get("kinds", [])} for t in targets]})
    _w_text("controls_endpoints.txt", "\n".join(
        [t.get("url", "") for t in targets]) + "\n")
    _w_json("controls_ranking.json", {
        "paths_cap": conf.get("controls_paths_cap"),
        "ranked": [{"url": t.get("url"), "score": t.get("score")}
                   for t in targets]})
    # 4 coverage
    gates = {g: bool(conf.get(g)) for g, _ in ROE_GATES}
    _w_json("controls_coverage.json", {
        "mode": ctx.get("mode"), "sources": disc.get("sources", []),
        "probes_total": meta.get("probes_total", 0),
        "stages": list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "gates": gates})
    # 5-6 baseline/waf-declared
    _w_json("controls_baseline.json",
            results.get("baseline", {}).get("rows", []))
    _w_json("controls_waf_declared.json",
            results.get("baseline", {}).get("waf", []))
    # 7-12 headers/waf/rate/cors/cookies/authgate
    _w_json("controls_headers.json", results.get("headers", {}))
    _w_text("controls_header_controls.txt", "\n".join(
        ["P25 header-control table (18 hardening):"] +
        ["%s -> %s" % (n, h) for n, h, *_ in HEADER_CONTROLS]) + "\n")
    _w_json("controls_waf.json", results.get("waf", {}))
    _w_text("controls_waf_playbook.txt", "\n".join(
        ["P25 WAF payload-family catalog (DOCUMENTED-ONLY; engine INERT "
         "canary only):"] +
        ["%s | %s" % (i, t) for i, t in WAF_PAYLOAD_CATALOG]) + "\n")
    _w_json("controls_rate.json", results.get("rate", {}))
    _w_text("controls_rate_playbook.txt", "\n".join(
        ["P25 rate full-burst playbook (DOCUMENTED-ONLY; engine 6-seq cap):"] +
        ["%s | %s" % (i, t) for i, t in RATE_BURST_PLAYBOOK]) + "\n")
    _w_json("controls_cors.json", results.get("cors", {}))
    _w_json("controls_cookies.json", results.get("cookies", {}))
    _w_json("controls_authgate.json", results.get("authgate", {}))
    _w_text("controls_authgate_paths.txt", "\n".join(AUTHGATE_PATHS) + "\n")
    # 13-20 methods/errors/tls/csp/echo/deps/observability/secrets
    _w_json("controls_methods.json", results.get("methods", {}))
    _w_json("controls_errors.json", results.get("errors", {}))
    _w_json("controls_tls.json", results.get("tls", {}))
    _w_json("controls_csp.json", results.get("csp", {}))
    _w_text("controls_csp_flags.txt", "\n".join(sorted(set(
        [f for r in (results.get("csp") or {}).get("rows", [])
         for f in (r.get("flags") or [])]))) + "\n")
    _w_json("controls_echo.json", results.get("echo", {}))
    _w_json("controls_deps.json", results.get("deps", {}))
    _w_json("controls_observability.json", results.get("observability", {}))
    _w_json("controls_secrets.json", results.get("secrets", {}))
    _w_text("controls_secret_names.txt", "\n".join(sorted(set(
        [s.get("shape", "") for r in (results.get("secrets") or {})
         .get("rows", []) for s in (r.get("shapes") or [])]))) + "\n")
    # 21-29 api/cicd/edge/cache/bypass2
    _w_json("controls_api.json", results.get("api", {}))
    _w_text("controls_spec_paths.txt", "\n".join(SPEC_PATHS) + "\n")
    _w_json("controls_gqlws.json", {
        "gql_rows": (results.get("api") or {}).get("gql_rows", []),
        "ws_rollup": (results.get("api") or {}).get("ws_rollup", [])})
    _w_json("controls_cicd.json", results.get("cicd", {}))
    _w_text("controls_cicd_paths.txt", "\n".join(GUARD_PATHS) + "\n")
    _w_json("controls_edge.json", results.get("edge", {}))
    _w_json("controls_cache.json", results.get("cache", {}))
    _w_json("controls_bypass2.json", results.get("bypass2", {}))
    _w_text("controls_bypass2_shapes.txt", "\n".join(
        ["P25 bypass2 control matrix (22 shapes; GET/HEAD only):"] +
        ["%s | %s" % (s[0], s[1]) for s in _bypass2_shapes("BASE",
                                                           "canary")]) + "\n")
    # 30-38 posture/verdicts/chains/matrix/hypotheses/remediation/drift
    _w_json("controls_posture.json", posture)
    _w_text("controls_posture.txt", "\n".join(
        ["P25 CONTROLS POSTURE (16-point composite):"] +
        ["%-58s %d/16 %s" % (r["url"][:58], r["score"], r["grade"])
         for r in posture.get("rows", [])] +
        ["", "points: " + ", ".join("%s=%s" % (p, d)
                                    for p, d in posture.get("points", []))])
        + "\n")
    _w_json("controls_verdicts.json", {"count": len(verdict_rows),
                                       "rows": verdict_rows})
    _w_json("controls_chains.json", {"count": len(chains),
                                     "chains": chains})
    _w_text("CONTROLS_CHAINS.txt", render_chains_txt(chains))
    _w_json("controls_matrix.json", {
        "rows": len(matrix_rows),
        "families": sorted(set(m["family"] for m in matrix_rows)),
        "matrix": matrix_rows})
    _w_text("CONTROLS_MATRIX.txt", render_matrix_txt(matrix_rows))
    _w_json("controls_hypotheses.json", {"count": len(hyps),
                                         "hypotheses": hyps})
    _w_json("controls_remediation.json", {
        "count": len(remediation_rows), "rows": remediation_rows})
    _w_text("REMEDIATION_PLAN.md", render_remediation_plan(remediation_rows))
    _w_text("HARDENING_CHECKLIST.md", render_hardening_checklist())
    _w_json("controls_drift.json", drift)
    # 39-44 gates/skipped/findings + renderers
    _w_text("controls_gates.txt", "\n".join(
        ["RoE gates (default OFF - enable sirf written authorization par):"] +
        ["%s = %s # %s" % (g, str(bool(conf.get(g))).lower(), d)
         for g, d in ROE_GATES]) + "\n")
    skipped = [g for g, _ in ROE_GATES if not bool(conf.get(g))]
    _w_text("controls_skipped_waves.txt", "\n".join(
        ["RoE-gated manual waves (SKIPPED - document in test plan):"] +
        ["%s -> %s" % (g, dict(ROE_GATES)[g]) for g in skipped]) + "\n")
    _w_json("findings.json", {
        "module": NAME, "phase": PHASE, "plan_version": PLAN_VERSION,
        "engagement": scope.engagement, "generated": now_iso(),
        "mode": ctx.get("mode"), "count": len(F.items),
        "severity_counts": _sev_counts(F),
        "findings": F.items})
    _w_text("CONTROLS_FINDINGS.md", render_findings_md(
        scope, F, verdict_rows, chains, meta))
    _w_text("CONTROLS_TEST_PLAN.md", render_test_plan(F, gates, matrix_rows))
    _w_text("EXEC_SUMMARY.md", render_exec_summary(
        scope, F, posture, verdict_rows, meta))
    _w_text("CONTROLS_KICKOFF.md", render_kickoff(scope, gates, conf))
    _w_text("CONTROLS_PLAYBOOKS.md", render_playbooks())
    # 45-48 aux
    _w_text("controls_summary.txt", "\n".join([
        "P25 CONTROLS SUMMARY - %s" % scope.engagement,
        "mode=%s probes=%s findings=%d matrix=%d chains=%d "
        "verdicts=%d posture_rows=%d remediation=%d" % (
            ctx.get("mode"), meta.get("probes_total", 0), len(F.items),
            len(matrix_rows), len(chains), len(verdict_rows),
            len(posture.get("rows", [])), len(remediation_rows)),
        "CONFIRMED(gap)=%d HARDENED(verified)=%d SUSPECTED=%d BLOCKED=%d "
        "SKIPPED=%d" % (
            len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
            len([r for r in verdict_rows if r["verdict"] == "HARDENED"]),
            len([r for r in verdict_rows if r["verdict"] == "SUSPECTED"]),
            len([r for r in verdict_rows if r["verdict"] == "BLOCKED"]),
            len([r for r in verdict_rows if r["verdict"] == "SKIPPED"]))])
        + "\n")
    _w_text("controls_live_endpoints.txt", "\n".join(sorted(set(
        [b.get("url") for b in results.get("baseline", {}).get("rows", [])
         if b.get("status") and b.get("status") < 400]))[:60]) + "\n")
    _w_json("controls_checklist_state.json", {
        "generated": now_iso(),
        "controls": [{"id": cid, "priority": p, "done": False}
                     for cid, _, p in CHECKLIST_CATALOG]})
    _w_text("controls_disclosure.txt", "\n".join(
        ["Disclosure shapes census (HC-02 aid):"] +
        ["%s -> %s" % (r.get("url"), ",".join(r.get("disclosure") or []))
         for r in (results.get("headers") or {}).get("rows", [])
         if r.get("disclosure")]) + "\n")

    # feedforward (W)
    ff_map = {
        "to_phase26_report": {
            "posture_rows": [{"url": r["url"], "score": r["score"],
                              "grade": r["grade"]}
                             for r in posture.get("rows", [])][:12],
            "exec_summary": "EXEC_SUMMARY.md"},
        "to_phase32_report": {
            "exec_summary": "EXEC_SUMMARY.md",
            "findings_json": "findings.json",
            "remediation_plan": "REMEDIATION_PLAN.md",
            "mode": ctx.get("mode")},
        "to_phase11_access": {
            "bypass2_accepted": sorted(set(sum(
                [r.get("accepted_ids", []) for r in
                 (results.get("bypass2") or {}).get("rows", [])],
                [])))[:22],
            "authgate_leaks": [r.get("url") for r in
                               (results.get("authgate") or {})
                               .get("rows", []) if r.get("leak")][:10]},
        "to_phase12_inject": {
            "echo_raw_urls": [r.get("url") for r in
                              (results.get("echo") or {}).get("rows", [])
                              if r.get("grade") == "raw"][:10],
            "verbose_error_urls": [r.get("url") for r in
                                   (results.get("errors") or {})
                                   .get("rows", [])
                                   if r.get("verbose_hits")][:10]},
        "to_phase9_auth": {
            "cookie_weak_urls": [r.get("url") for r in
                                 (results.get("cookies") or {})
                                 .get("rows", [])
                                 if r.get("grade") in ("weak",
                                                       "partial")][:10],
            "rate_gap_urls": [r.get("url") for r in
                              (results.get("rate") or {}).get("rows", [])
                              if not r.get("throttled_within_cap")][:10]},
        "to_phase23_misconfig": {
            "headers_missing_urls": [r.get("url") for r in
                                     (results.get("headers") or {})
                                     .get("rows", [])
                                     if len(r.get("present") or []) < 8][:10],
            "csp_flags": sorted(set(sum(
                [r.get("flags") or [] for r in
                 (results.get("csp") or {}).get("rows", [])], [])))[:10]},
        "to_phase24_cloud": {
            "cicd_live": [r.get("url") for r in
                          (results.get("cicd") or {}).get("rows", [])
                          if r.get("live")][:10],
            "cache_unsafe": [r.get("url") for r in
                             (results.get("cache") or {}).get("rows", [])
                             if r.get("sensitive") and
                             not r.get("safe")][:10]},
    }
    write_feedforward(out, "phase25", ff_map, notes=[
        "P25 v%s INERT controls census (GET-only, canary %s)" % (
            PLAN_VERSION, CANARY_FAMILY),
        "%d artifacts | %d probes | gates default OFF" % (
            len(manifest) + 2, meta.get("probes_total", 0))])
    manifest += ["feedforward.json"]

    write_manifest(out, "phase25", manifest, stats={
        "mode": ctx.get("mode"), "probes": meta.get("probes_total", 0),
        "findings": len(F.items), "matrix_rows": len(matrix_rows),
        "chains": len(chains), "verdicts": len(verdict_rows),
        "remediation_rows": len(remediation_rows),
        "artifacts": len(manifest) + 1,
        "gates_on": [g for g, _ in ROE_GATES if bool(conf.get(g))],
        "duration_sec": round(meta.get("duration", 0.0), 1)}, notes=[
        "100% INERT detection-only | GET-only module | bodies/values "
        "REDACTED | NO attack payloads | NO burst | NO creds/stuffing | "
        "zero egress | RWX 0777"])
    return manifest

def read_ff_safe(base_dir, scope):
    """read_feedforward wrapper (tolerant - missing dirs OK).

    base_dir = <base>/<engagement> (module_ctx pattern); read_feedforward
    (base_out, engagement) khud engagement join karta hai -> parent pass."""
    try:
        root = os.path.dirname(base_dir) if base_dir else ""
        return read_feedforward(root, scope.engagement)
    except Exception:
        return {}


def _findings_from_verdicts(F, verdict_rows):
    """Verdict rows -> findings (key-mapped, dedup per endpoint+key)."""
    seen = set()
    for r in verdict_rows:
        v, u = r["verdict"], r.get("url", "?")
        key = {"C": {"CONFIRMED": "controls_headers_missing",
                     "SUSPECTED": "controls_headers_missing",
                     "HARDENED": "controls_headers_strong"},
               "D": {"HARDENED": "controls_waf_enforced",
                     "CONFIRMED": "controls_waf_declared_only",
                     "SUSPECTED": "controls_waf_absent"},
               "E": {"HARDENED": "controls_rate_enforced",
                     "CONFIRMED": "controls_rate_gap"},
               "F": {"CONFIRMED": "controls_cors_reflect",
                     "SUSPECTED": "controls_cors_reflect",
                     "HARDENED": "controls_cors_strict"},
               "G": {"CONFIRMED": "controls_cookies_weak",
                     "HARDENED": "controls_cookies_hardened"},
               "H": {"CONFIRMED": "controls_authgate_gap",
                     "HARDENED": "controls_authgate_ok"},
               "I": {"CONFIRMED": "controls_methods_advertised",
                     "HARDENED": "controls_methods_locked"},
               "J": {"CONFIRMED": "controls_error_verbose",
                     "HARDENED": "controls_error_masked"},
               "K": {"CONFIRMED": "controls_tls_weak",
                     "HARDENED": "controls_tls_strong"},
               "L": {"CONFIRMED": "controls_csp_decorative",
                     "SUSPECTED": "controls_csp_decorative",
                     "HARDENED": "controls_csp_strict"},
               "M": {"CONFIRMED": "controls_echo_raw",
                     "HARDENED": "controls_echo_sanitized"},
               "N": {"CONFIRMED": "controls_dep_stale"},
               "O": {"HARDENED": "controls_observability_on",
                     "SUSPECTED": "controls_observability_off"},
               "P": {"CONFIRMED": "controls_secret_shape"},
               "Q": {"CONFIRMED": "controls_api_spec_live",
                     "HARDENED": "controls_api_locked",
                     "SUSPECTED": "controls_gql_introspection"},
               "R": {"CONFIRMED": "controls_cicd_guard_gap",
                     "HARDENED": "controls_cicd_guarded"},
               "S": {"CONFIRMED": "controls_edge_echo",
                     "HARDENED": "controls_edge_strict"},
               "T": {"CONFIRMED": "controls_cache_unsafe",
                     "HARDENED": "controls_cache_safe"},
               "U": {"CONFIRMED": "controls_bypass2_gap",
                     "HARDENED": "controls_bypass2_blocked"},
               }.get(r["stage"], {}).get(v)
        if not key or u == "*" or u == "?":
            continue
        dk = (key, u)
        if dk in seen:
            continue
        seen.add(dk)
        F.add(key, "%s [%s]" % (key, v), u, r.get("detail", ""))


def control_inventory(results):
    """Verified-control inventory (offline rollup - exec-summary aid)."""
    inv = {"waf_enforced": 0, "rate_enforced": 0, "cors_strict": 0,
           "authgated": 0, "errors_masked": 0, "csp_strict": 0,
           "headers_strong": 0, "bypass2_blocked": 0, "edge_strict": 0,
           "cache_safe": 0, "introspection_off": 0, "artifacts_absent": 0}
    for r in (results.get("waf") or {}).get("rows", []):
        inv["waf_enforced"] += 1 if r.get("enforced") else 0
    for r in (results.get("rate") or {}).get("rows", []):
        inv["rate_enforced"] += 1 if r.get("throttled_within_cap") else 0
    for r in (results.get("cors") or {}).get("rows", []):
        inv["cors_strict"] += 1 if r.get("strict") else 0
    for r in (results.get("authgate") or {}).get("rows", []):
        inv["authgated"] += 1 if r.get("gated") else 0
    for r in (results.get("errors") or {}).get("rows", []):
        inv["errors_masked"] += 1 if r.get("grade") == "masked" else 0
    for r in (results.get("csp") or {}).get("rows", []):
        inv["csp_strict"] += 1 if r.get("grade") == "strict" else 0
    for r in (results.get("headers") or {}).get("rows", []):
        inv["headers_strong"] += 1 if len(r.get("strict") or []) >= 12 else 0
    for r in (results.get("bypass2") or {}).get("rows", []):
        inv["bypass2_blocked"] += 1 if not r.get("accepted_count") else 0
    for r in (results.get("edge") or {}).get("rows", []):
        inv["edge_strict"] += 1 if r.get("edge_strict") else 0
    for r in (results.get("cache") or {}).get("rows", []):
        inv["cache_safe"] += 1 if (r.get("sensitive") and
                                   r.get("safe")) else 0
    for r in (results.get("api") or {}).get("gql_rows", []):
        inv["introspection_off"] += 1 if r.get("introspection_off") else 0
    for r in (results.get("cicd") or {}).get("rows", []):
        inv["artifacts_absent"] += 1 if (r.get("status") and
                                         not r.get("live")) else 0
    return inv


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

    head("Phase 25 - Security Controls Validation & Remediation "
         "(detection-only, INERT) (v%s) | %s" % (PLAN_VERSION,
                                                 scope.describe()))
    warn("Controls discipline: koi exploitation KABHI nahi (canary %s) | "
         "GET-only module (koi POST/PUT/DELETE/PATCH probe nahi) | "
         "bodies/secret-values REDACTED | NO attack payloads (WAF/echo "
         "sirf synthetic marker) | rate census 6-seq HARD cap | NO creds/"
         "stuffing | zero egress." % CANARY_FAMILY)
    on_gates = [g for g, _ in ROE_GATES if bool(conf.get(g))]
    if on_gates:
        warn("RoE gates ON: %s" % ", ".join(on_gates))
    else:
        info("Sab RoE gates OFF (detection-only census mode) - gated waves "
             "CONTROLS_TEST_PLAN.md me documented hain.")
    info("caps: paths=%s | probes=%s | bypass2=%s | cold=%s | rate=%s" % (
        conf.get("controls_paths_cap"), conf.get("controls_probe_cap"),
        conf.get("controls_bypass2_cap"), conf.get("controls_cold_paths"),
        conf.get("controls_rate_cap")))

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
    head("Stage A - Controls surface discovery (20-module ff + miners + cold)")
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
        disc = discover_controls_surface(ctxd, scope, conf)
        cp.mark(ckA, disc, summary="controls surface")
    results["targets"] = disc.get("ranked", [])
    meta["sources"] = disc.get("sources", [])
    ok("targets=%d | sources: %s" % (len(results["targets"]),
                                     ", ".join(meta["sources"][:6])))

    # ---------------- Stage B: baseline + WAF-declared ----------------
    head("Stage B - Baseline + WAF-declared + soft-404")
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
        cp.mark(ckB, results["baseline"], summary="baseline+waf-declared")
    live_n = len([b for b in results["baseline"].get("rows", [])
                  if b.get("status") and b.get("status") < 400])
    ok("baseline rows=%d live=%d" % (
        len(results["baseline"].get("rows", [])), live_n))

    # ---------------- Stage C: header controls ----------------
    head("Stage C - Header controls audit (18 hardening + 10 disclosure)")
    ckC = "stageC:headers"
    if cp.is_done(ckC):
        results["headers"] = cp.result_of(ckC) or {}
        ok("Replayed headers census (checkpoint)")
    elif passive:
        results["headers"] = {"rows": [], "note": "passive"}
    else:
        results["headers"] = headers_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckC, results["headers"], summary="headers census")
    meta["probes_total"] += len(results["headers"].get("rows", []))

    # ---------------- Stage D: WAF enforcement ----------------
    head("Stage D - WAF enforcement differential (GATED, INERT canary)")
    ckD = "stageD:waf"
    if cp.is_done(ckD):
        results["waf"] = cp.result_of(ckD) or {}
        ok("Replayed waf census (checkpoint)")
    elif passive:
        results["waf"] = {"rows": [],
                          "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_waf_probe"):
        results["waf"] = waf_enforcement_census(http,
                                                disc.get("targets", []),
                                                conf)
        warn("SKIPPED (gate OFF): %s" % results["waf"].get("skipped_note",
                                                           ""))
    else:
        results["waf"] = waf_enforcement_census(http,
                                                disc.get("targets", []),
                                                conf)
        cp.mark(ckD, results["waf"], summary="waf census")
    meta["probes_total"] += len(results["waf"].get("rows", []))

    # ---------------- Stage E: rate control ----------------
    head("Stage E - Rate-limit control census (GATED, 6-seq HARD cap)")
    ckE = "stageE:rate"
    if cp.is_done(ckE):
        results["rate"] = cp.result_of(ckE) or {}
        ok("Replayed rate census (checkpoint)")
    elif passive:
        results["rate"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_rate_probe"):
        results["rate"] = rate_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["rate"].get("skipped_note",
                                                            ""))
    else:
        results["rate"] = rate_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        cp.mark(ckE, results["rate"], summary="rate census")
    meta["probes_total"] += sum(len(r.get("sequence") or [])
                                for r in results["rate"].get("rows", []))

    # ---------------- Stage F: CORS control ----------------
    head("Stage F - CORS control validation (GATED, .invalid canaries)")
    ckF = "stageF:cors"
    if cp.is_done(ckF):
        results["cors"] = cp.result_of(ckF) or {}
        ok("Replayed cors census (checkpoint)")
    elif passive:
        results["cors"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_cors_probe"):
        results["cors"] = cors_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["cors"].get("skipped_note",
                                                            ""))
    else:
        results["cors"] = cors_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        cp.mark(ckF, results["cors"], summary="cors census")
    meta["probes_total"] += len(results["cors"].get("rows", []))

    # ---------------- Stage G: cookie controls ----------------
    head("Stage G - Cookie/session controls census (passive-GET)")
    ckG = "stageG:cookies"
    if cp.is_done(ckG):
        results["cookies"] = cp.result_of(ckG) or {}
        ok("Replayed cookies census (checkpoint)")
    elif passive:
        results["cookies"] = {"rows": [], "note": "passive"}
    else:
        results["cookies"] = cookie_control_census(http,
                                                   disc.get("targets", []),
                                                   conf)
        cp.mark(ckG, results["cookies"], summary="cookies census")
    meta["probes_total"] += len(results["cookies"].get("rows", []))

    # ---------------- Stage H: auth-gate control ----------------
    head("Stage H - Auth-gate control differential (GATED, no creds)")
    ckH = "stageH:authgate"
    if cp.is_done(ckH):
        results["authgate"] = cp.result_of(ckH) or {}
        ok("Replayed authgate census (checkpoint)")
    elif passive:
        results["authgate"] = {"rows": [],
                               "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_authgate_probe"):
        results["authgate"] = authgate_census(http,
                                              disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" %
             results["authgate"].get("skipped_note", ""))
    else:
        results["authgate"] = authgate_census(http,
                                              disc.get("targets", []),
                                              conf)
        cp.mark(ckH, results["authgate"], summary="authgate census")
    meta["probes_total"] += len(results["authgate"].get("rows", []))

    # ---------------- Stage I: method control ----------------
    head("Stage I - Method-control census (GATED, OPTIONS-only)")
    ckI = "stageI:methods"
    if cp.is_done(ckI):
        results["methods"] = cp.result_of(ckI) or {}
        ok("Replayed methods census (checkpoint)")
    elif passive:
        results["methods"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_method_probe"):
        results["methods"] = method_control_census(http,
                                                   disc.get("targets", []),
                                                   conf)
        warn("SKIPPED (gate OFF): %s" %
             results["methods"].get("skipped_note", ""))
    else:
        results["methods"] = method_control_census(http,
                                                   disc.get("targets", []),
                                                   conf)
        cp.mark(ckI, results["methods"], summary="methods census")
    meta["probes_total"] += len(results["methods"].get("rows", []))

    # ---------------- Stage J: error masking ----------------
    head("Stage J - Error-masking control census (GATED, canary params)")
    ckJ = "stageJ:errors"
    if cp.is_done(ckJ):
        results["errors"] = cp.result_of(ckJ) or {}
        ok("Replayed errors census (checkpoint)")
    elif passive:
        results["errors"] = {"rows": [],
                             "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_error_probe"):
        results["errors"] = error_mask_census(http,
                                              disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" %
             results["errors"].get("skipped_note", ""))
    else:
        results["errors"] = error_mask_census(http,
                                              disc.get("targets", []),
                                              conf)
        cp.mark(ckJ, results["errors"], summary="errors census")
    meta["probes_total"] += len(results["errors"].get("rows", []))

    # ---------------- Stage K: TLS controls ----------------
    head("Stage K - TLS/transport controls census (passive-GET)")
    ckK = "stageK:tls"
    if cp.is_done(ckK):
        results["tls"] = cp.result_of(ckK) or {}
        ok("Replayed tls census (checkpoint)")
    elif passive:
        results["tls"] = {"rows": [], "note": "passive"}
    else:
        results["tls"] = tls_control_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckK, results["tls"], summary="tls census")
    meta["probes_total"] += len(results["tls"].get("rows", []))

    # ---------------- Stage L: CSP deep grade (offline) ----------------
    head("Stage L - CSP deep grading (offline parser, 0 probes)")
    ckL = "stageL:csp"
    if cp.is_done(ckL):
        results["csp"] = cp.result_of(ckL) or {}
        ok("Replayed csp grading (checkpoint)")
    else:
        results["csp"] = csp_deep_grade(
            (results.get("headers") or {}).get("rows", []))
        cp.mark(ckL, results["csp"], summary="csp grading")
    ok("csp rows=%d strict=%d" % (len(results["csp"].get("rows", [])),
                                  results["csp"].get("strict_count", 0)))

    # ---------------- Stage M: echo control ----------------
    head("Stage M - Echo-sanitization control (GATED, synthetic marker)")
    ckM = "stageM:echo"
    if cp.is_done(ckM):
        results["echo"] = cp.result_of(ckM) or {}
        ok("Replayed echo census (checkpoint)")
    elif passive:
        results["echo"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_echo_probe"):
        results["echo"] = echo_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["echo"].get("skipped_note",
                                                            ""))
    else:
        results["echo"] = echo_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        cp.mark(ckM, results["echo"], summary="echo census")
    meta["probes_total"] += len(results["echo"].get("rows", []))

    # ---------------- Stage N: deps control ----------------
    head("Stage N - Dependency/patch control census (passive fp)")
    ckN = "stageN:deps"
    if cp.is_done(ckN):
        results["deps"] = cp.result_of(ckN) or {}
        ok("Replayed deps census (checkpoint)")
    elif passive:
        results["deps"] = {"rows": [], "note": "passive"}
    else:
        results["deps"] = dep_control_census(http, disc.get("targets", []),
                                             conf)
        cp.mark(ckN, results["deps"], summary="deps census")
    meta["probes_total"] += len(results["deps"].get("rows", []))

    # ---------------- Stage O: observability ----------------
    head("Stage O - Observability controls census (passive-GET)")
    ckO = "stageO:obs"
    if cp.is_done(ckO):
        results["observability"] = cp.result_of(ckO) or {}
        ok("Replayed observability census (checkpoint)")
    elif passive:
        results["observability"] = {"rows": [], "note": "passive"}
    else:
        results["observability"] = observability_census(
            http, disc.get("targets", []), conf)
        cp.mark(ckO, results["observability"], summary="observability census")
    meta["probes_total"] += len(results["observability"].get("rows", []))

    # ---------------- Stage P: secrets hygiene ----------------
    head("Stage P - Secrets-hygiene re-scan (passive, sha1-only REDACTED)")
    ckP = "stageP:secrets"
    if cp.is_done(ckP):
        results["secrets"] = cp.result_of(ckP) or {}
        ok("Replayed secrets census (checkpoint)")
    elif passive:
        results["secrets"] = {"rows": [], "note": "passive"}
    else:
        results["secrets"] = secrets_hygiene_census(
            http, disc.get("targets", []), conf)
        cp.mark(ckP, results["secrets"], summary="secrets census")
    meta["probes_total"] += len(results["secrets"].get("rows", []))

    # ---------------- Stage Q: API controls ----------------
    head("Stage Q - API-surface controls census (GATED, names-only)")
    ckQ = "stageQ:api"
    if cp.is_done(ckQ):
        results["api"] = cp.result_of(ckQ) or {}
        ok("Replayed api census (checkpoint)")
    elif passive:
        results["api"] = {"rows": [], "gql_rows": [], "ws_rollup": [],
                          "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_api_probe"):
        results["api"] = api_control_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" % results["api"].get("skipped_note",
                                                           ""))
    else:
        results["api"] = api_control_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckQ, results["api"], summary="api census")
    meta["probes_total"] += len(results["api"].get("rows", []))

    # ---------------- Stage R: CI/CD guards ----------------
    head("Stage R - CI/CD + IaC guardrail census (GATED, presence-only)")
    ckR = "stageR:cicd"
    if cp.is_done(ckR):
        results["cicd"] = cp.result_of(ckR) or {}
        ok("Replayed cicd census (checkpoint)")
    elif passive:
        results["cicd"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_cicd_probe"):
        results["cicd"] = cicd_guard_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" % results["cicd"].get("skipped_note",
                                                            ""))
    else:
        results["cicd"] = cicd_guard_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckR, results["cicd"], summary="cicd census")
    meta["probes_total"] += len(results["cicd"].get("rows", []))

    # ---------------- Stage S: edge trust ----------------
    head("Stage S - Edge trust-header control (GATED, echo differential)")
    ckS = "stageS:edge"
    if cp.is_done(ckS):
        results["edge"] = cp.result_of(ckS) or {}
        ok("Replayed edge census (checkpoint)")
    elif passive:
        results["edge"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_edge_probe"):
        results["edge"] = edge_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["edge"].get("skipped_note",
                                                            ""))
    else:
        results["edge"] = edge_control_census(http,
                                              disc.get("targets", []),
                                              conf)
        cp.mark(ckS, results["edge"], summary="edge census")
    meta["probes_total"] += len(results["edge"].get("rows", []))

    # ---------------- Stage T: cache validation ----------------
    head("Stage T - Cache-control validation (GATED, sensitive pool)")
    ckT = "stageT:cache"
    if cp.is_done(ckT):
        results["cache"] = cp.result_of(ckT) or {}
        ok("Replayed cache census (checkpoint)")
    elif passive:
        results["cache"] = {"rows": [],
                            "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_cache_probe"):
        results["cache"] = cache_control_census(http,
                                                disc.get("targets", []),
                                                conf)
        warn("SKIPPED (gate OFF): %s" % results["cache"].get("skipped_note",
                                                             ""))
    else:
        results["cache"] = cache_control_census(http,
                                                disc.get("targets", []),
                                                conf)
        cp.mark(ckT, results["cache"], summary="cache census")
    meta["probes_total"] += len(results["cache"].get("rows", []))

    # ---------------- Stage U: bypass2 ----------------
    head("Stage U - Bypass matrix v2: 22 control-bypass shapes (GATED)")
    ckU = "stageU:bypass2"
    if cp.is_done(ckU):
        results["bypass2"] = cp.result_of(ckU) or {}
        ok("Replayed bypass2 census (checkpoint)")
    elif passive:
        results["bypass2"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("controls_allow_bypass2"):
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" %
             results["bypass2"].get("skipped_note", ""))
    else:
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckU, results["bypass2"], summary="bypass2 census")
    meta["probes_total"] += len(results["bypass2"].get("rows", []))

    # ---------------- Stage V-Z offline engines ----------------
    head("Stage V/W/X/Y - Posture composite + chains + verdict + matrix")
    posture = posture_composite(results)
    ff_all = read_ff_safe(ctxd.get("base_dir"), scope)
    chains = build_chains(results, ff_all)
    verdict_rows = verdict_engine(results)
    matrix_rows = build_matrix()
    inventory = control_inventory(results)
    # ws surface rollup (names-only, frames NEVER - P19 handoff aid)
    ws_eps = []
    for lst in _walk_lists((ff_all.get("ws") or {})
                           .get("to_phase25_controls", {})):
        ws_eps.extend([u for u in lst if isinstance(u, str)])
    if ws_eps:
        results["api"]["ws_rollup"] = ws_eps[:12]
        F.add("controls_ws_surface", "WebSocket endpoint census "
              "(names-only, frames NEVER)", "*",
              "%d ws endpoints (P19 owns deep wave)" % len(ws_eps[:12]))
    # gql mutation names rollup (names-only, NEVER sent - P18 handoff aid)
    gql_mut = []
    for lst in _walk_lists((ff_all.get("graphql") or {})
                           .get("to_phase25_controls", {})):
        gql_mut.extend([u for u in lst if isinstance(u, str)])
    if gql_mut:
        results["api"]["gql_mutation_names"] = gql_mut[:12]
        F.add("controls_gql_mutation_surface", "GraphQL mutation names "
              "rollup (NEVER sent)", "*",
              "%d mutation names (P18 owns deep wave)" % len(gql_mut[:12]))

    # findings from verdict rows
    _findings_from_verdicts(F, verdict_rows)
    # posture findings
    for w in posture.get("weak", [])[:8]:
        F.add("controls_posture_weak", "Controls posture WEAK",
              w.get("url", ""), "score=%d/16 (points missing: %s)" % (
                  w["score"], ",".join(k for k, v in w["points"].items()
                                       if v is False)))
    if len(posture.get("strong", [])) >= 1:
        F.add("controls_posture_strong", "Controls posture STRONG",
              posture["strong"][0].get("url", ""),
              "score>=%d/16 positive controls dominant" %
              posture["strong"][0]["score"])
    # documented-only playbooks (0 network)
    F.add("controls_rate_playbook",
          "Rate full-burst playbook documented (8 rows)", "*",
          "burst KABHI network par nahi (FORBIDDEN-AUTO; RB-01..08)")
    F.add("controls_waf_playbook",
          "WAF payload-family catalog documented (10 rows)", "*",
          "payloads KABHI network par nahi (engine sirf INERT canary)")
    # targeted findings
    for r in (results.get("cors") or {}).get("rows", []):
        if r.get("reflect_any"):
            F.add("controls_cors_reflect", "CORS canary-origin reflection",
                  r.get("url", ""), "grade=%s" % r.get("grade"))
    for r in (results.get("bypass2") or {}).get("rows", []):
        if r.get("accepted_count"):
            F.add("controls_bypass2_gap",
                  "Control-bypass shapes accepted", r.get("url", ""),
                  "ids=%s" % ",".join(r.get("accepted_ids", [])[:8]))
    for r in (results.get("authgate") or {}).get("rows", []):
        if r.get("leak"):
            F.add("controls_authgate_gap", "Auth-gate anon-200 leak",
                  r.get("url", ""), "protected path anon-accessible")
    if inventory.get("headers_strong"):
        F.add("controls_headers_strong", "Header controls dominant",
              "*", "%d target(s) >=12/18 strict" %
              inventory["headers_strong"])

    # ---------------- Stage Z: final secrets guard ----------------
    payloads = [("CONTROLS_FINDINGS.md", pii_redact(render_findings_md(
        scope, F, verdict_rows, chains, meta)))]
    guard = secrets_guard(payloads)
    if guard.get("hits"):
        F.add("controls_secret_guard_hit", "Secret-guard sweep triggered",
              "*", "artifact shapes redacted (CWE-200 aid)")

    # ---------------- Stage Z: remediation + drift + reports ----------------
    head("Stage Z - Remediation plan + drift + reports (%d artifacts) + "
         "feedforward + manifest")
    remediation_rows = build_remediation(F)
    drift = drift_baseline(posture, verdict_rows)
    F.add("controls_remediation_plan", "P1..P5 remediation plan generated",
          "*", "%d rows (REMEDIATION_PLAN.md)" % len(remediation_rows))
    F.add("controls_drift_baseline", "Control drift baseline captured",
          "*", "sha1_16=%s (controls_drift.json)" % drift.get("sha1_16"))
    meta["duration"] = time.time() - t_start
    manifest_files = write_reports(out, scope, F, ctxd, meta, results, disc,
                                   conf, chains, verdict_rows, matrix_rows,
                                   posture, guard, build_hypotheses(results,
                                                                    posture),
                                   remediation_rows, drift)
    cp.mark_complete()
    ok("%d artifacts | findings=%d | verdicts=%d | chains=%d | matrix=%d" % (
        len(manifest_files) + 2, len(F.items), len(verdict_rows),
        len(chains), len(matrix_rows)))
    sc = _sev_counts(F)
    ok("severity: C=%d H=%d M=%d L=%d I=%d | CONFIRMED(gap)=%d "
       "HARDENED(verified)=%d" % (
           sc.get("critical", 0), sc.get("high", 0), sc.get("medium", 0),
           sc.get("low", 0), sc.get("info", 0),
           len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
           len([r for r in verdict_rows if r["verdict"] == "HARDENED"])))
    dim("out: %s" % out)
    return out


# ===========================================================================
# SECRETS GUARD (final artifact sweep - P24 pattern)
# ===========================================================================
_GUARD_RX = [
    re.compile(r"(?i)(AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"(?i)postgres(ql)?://[^:/\s]+:[^@/\s]+@"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b"),
    re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
]


def secrets_guard(payloads):
    """Artifact text sweep - secret-shape hits -> redaction + aid (values
    KABHI store nahi; sirf hit-count)."""
    hits = []
    for name, txt in (payloads or []):
        for rx in _GUARD_RX:
            for m in (rx.findall(txt or "") or [])[:4]:
                hits.append({"artifact": name,
                             "shape": rx.pattern[:28],
                             "sha1_12": hashlib.sha1(
                                 str(m).encode("utf-8", "ignore"))
                             .hexdigest()[:12]})
    return {"hits": hits, "redacted": len(hits)}


# ===========================================================================
# CLI
# ===========================================================================
def main():
    print("WASP mod_controls.py (Phase 25 - Security Controls Validation & "
          "Remediation, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 25   (ya --module "
          "controls)")
    print("  self-test : python3 test_mod_controls.py")
    print("\n  RoE gates (config.json):")
    for g, d in ROE_GATES:
        print("    %s=false (default) # %s" % (g, d))
    print("  Safety: koi exploitation KABHI nahi (canary %s) | GET-only "
          "module | bodies/secret-values REDACTED | NO attack payloads | "
          "rate census 6-seq HARD cap | NO creds/stuffing | zero egress" %
          CANARY_FAMILY)
    print("  v30 ULTRA: 26 stages (A..Z) | 12 RoE gates | 22-secret "
          "bypass2 | 8 rate + 10 WAF playbook rows (documented) | "
          "247-row x 24-family matrix | 30 kill-chains | 60 artifacts | "
          "16-point posture composite | 30 secret-shapes | P1-P5 "
          "remediation engine | CIS checklist | drift baseline")


if __name__ == "__main__":
    main()
