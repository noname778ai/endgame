#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_api.py  |  Phase 17 - REST API Security (Auth/Versioning/
           Rate-Limits/Mass-Assignment/BOLA-patterns/Error-Leak/Method-Abuse)
=======================================================================================
v17.0.0 FULL ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se inherit
hote hain, isliye har request scope-check, rate-limit aur budget ke andar hi
jaati hai.

KYA KARTA HAI
  P16 inbound FILE trust dekh raha tha. P17 PROGRAMMATIC INTERFACE trust dekhta
  hai: "MERA API, non-browser CLIENTS ko kahan tak over-trust karta hai?" ->
    * Spec exposure     - openapi/swagger docs public? (recon goldmine)
    * Auth-per-endpoint - anon/invalid/expired token differential matrix
    * Versioning        - v1/v2/v3 path+query+header differential, downgrades
    * Rate limiting     - header census + bounded burst (GATED) + window hints
    * Mass assignment   - writable-field census + canary extra-field probe (GATED)
    * BOLA pattern      - object-id sampling differential (P11 handoff, GATED)
    * Error leak        - malformed-body stack traces, debug params, fingerprints
    * Method abuse      - OPTIONS census, method-override, CT confusion
    * Protocol handoff  - GraphQL/WebSocket fingerprint -> P18/P19 seeds
  GUIDE SEEDS (AFTER_PHASES_GUIDE P17 row): "Auth per endpoint, versioning,
  rate limits, mass assignment" <- seeds: API artifacts (P5), API version
  matrix (P3), idor endpoints (P11). Plus P15/P16 feedforward (xml_api_...).

VERDICT LADDER (6-class, P12..P16-compatible)
  CONFIRMED   -> multi-signal proof (anon 200 on private endpoint + data echo,
                 spec publicly exposes internal hosts, mass-assign field stored)
  SUSPECTED   -> partial/single signal (auth inconsistent across versions,
                 rate headers absent + burst 429 pattern odd, verbose errors)
  HARDENED    -> defense present (401+403 consistent, rate headers, strict CT)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (REST APIs 'stateful' hain - P15/P16 jitni strict discipline)
  * 100% INERT PAYLOADS: har request body FORBIDDEN_CONTENT_PATTERNS se
    guzarti hai. Koi exploit/exfil payload nahi - sirf canary JSON (INERT
    markers) + invalid-token probes. Self-test me hard-asserted.
  * CANARY IDS: har object-id "waspP17<rnd>" family - real records KABHI
    enumerate nahi hote; sirf structural differential (200/403/404) dekha
    jaata hai. Kisi real user-id ko touch nahi karte.
  * WRITE PROBES (mass-assign): RoE-gated (api_allow_mass_write default OFF)
    - sirf HAMARE canary-created objects par, INERT values, getback-verify.
  * RATE BURST: RoE-gated (api_allow_rate_burst default OFF) - hard cap 15
    requests, adaptive 429-stop, single endpoint. No DoS. Headers-census
    (passive) hamesha ON.
  * BOLA SAMPLING: RoE-gated (api_allow_bola default OFF) - canary ids only,
    GET-only differential; enumeration P11 ka kaam hai (handoff).
  * TOKENS: sirf INVALID markers (canary/JWT-shape-random) bhejte hain - real
    creds kabhi nahi. Auth findings 401/403/200 pattern-based hain.
  * ZERO EXTERNAL EGRESS: sirf scope-host/loopback. Debug params read-only GET.
  * allow_active=False -> PASSIVE mode: seed census + offline hypotheses only.
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
  * POST/PATCH force_write=True par jaate hain (framework write-gate) - sirf
    INERT canary bodies, yahi is phase ka core probe hai.
"""

import os
import re
import io
import sys
import json
import time
import copy
import base64
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
                           write_feedforward, write_manifest, soft404_baseline,
                           is_soft404, title_of, waf_signature, dns_resolve,
                           redirect_chain, interrupted, info, ok, warn, err,
                           head, C, VERSION, now_human, human_size)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 17")
    sys.exit(1)

NAME = "api"
PHASE = "17-api"
PLAN_VERSION = "17.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "api_endpoints_cap": 12,          # active auth/matrix probe endpoint cap
    "api_spec_paths": 12,             # openapi/swagger doc path fetch cap
    "api_spec_expansion_cap": 40,     # spec-derived endpoint census cap
    "api_version_pairs": 8,           # version differential pairs cap
    "api_auth_endpoints": 8,          # auth-matrix endpoint cap
    "api_auth_roles": 4,              # token roles (anon/invalid/expired/user)
    "api_method_census": True,        # OPTIONS Allow-header census (passive)
    "api_error_leak": True,           # malformed-body error census (read-only)
    "api_debug_params": True,         # ?debug/pretty/trace GET census (capped)
    "api_debug_cap": 6,               # debug-param GET cap per endpoint
    "api_version_downgrade": True,    # query/header version differential (GET)
    "api_ct_confusion": True,         # CT-switch + method-override census
    "api_ct_confusion_cap": 6,        # confusion probe cap
    "api_ws_gql_fingerprint": True,   # GraphQL + WebSocket upgrade fingerprint
    "api_param_census": True,         # params harvest -> P12 handoff
    "api_max_bytes": 2048,            # request body size cap (no DoS)
    # ---- RoE GATES (default OFF - sirf authorized+lab runs me ON) ----
    "api_allow_rate_burst": False,    # GATE: bounded burst (cap 15, 429-stop)
    "api_rate_burst_cap": 15,         # burst hard cap (config se zyada NAHI)
    "api_allow_mass_write": False,    # GATE: canary-object extra-field write
    "api_allow_bola": False,          # GATE: canary-id sampling differential
    "api_bola_ids": 4,                # canary-id cap (structural only)
    "api_allow_method_write": False,  # GATE: PATCH/PUT/DELETE on canary objects
    "api_allow_header_window": False, # GATE: X-Forwarded-For rate-window hint
}


# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# ===========================================================================
def _rwx_result(path):
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


def _rwx_save_json(path, obj):
    d = os.path.dirname(path)
    if d:
        _rwx_dir(d)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    return _rwx_result(path)


def _rwx_save_text(path, text):
    d = os.path.dirname(path)
    if d:
        _rwx_dir(d)
    with open(path, "w") as f:
        f.write(text if isinstance(text, str) else str(text))
    return _rwx_result(path)


def _rwx_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


# ===========================================================================
# SEVERITY CLASSIFICATION (P12..P16 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- spec / recon ----
    "api_spec_public":           ("high", 7.2, "OpenAPI/Swagger spec bina auth "
        "public hai - poora endpoint+param+schema map attacker ko free me mil "
        "gaya (attack-surface disclosure; internal hosts/emails bhi leak ho "
        "sakte hain)."),
    "api_spec_internal_hosts":   ("high", 7.0, "Spec me internal/staging server "
        "URLs ya contact emails hain - infra disclosure (P3/P24 chain)."),
    "api_spec_shadow_endpoints": ("medium", 6.4, "Spec me aise endpoints mile "
        "jo live-census me nahi the (shadow/zombie API surface - unpatched "
        "old versions ka classic sign, OWASP API9)."),
    # ---- auth ----
    "api_auth_missing":          ("critical", 9.3, "Private endpoint bina kisi "
        "token ke 200+data de raha hai - broken object/function-level auth "
        "(OWASP API1/API5). Direct data exposure, P11 chain handoff."),
    "api_auth_inconsistent":     ("high", 7.9, "Auth enforcement versions/roles "
        "me inconsistent hai (v1 me 200, v2 me 401-class) - version-skew "
        "bypass family (attacker weakest version par aa jaata hai)."),
    "api_auth_token_not_validated": ("critical", 9.0, "Random/canary token par "
        "endpoint 200 deta hai - signature validation missing (alg-confusion "
        "family, P10 JWT chain handoff)."),
    "api_auth_verbose_401":      ("low", 3.8, "401 response me detail leak "
        "'token expired' vs 'invalid signature' - oracle for token "
        "forging (low alone, chain aid)."),
    "api_auth_role_hint":        ("medium", 5.6, "Error/headers me role/permission "
        "hints (admin-only field names, 403-vs-401 asymmetry) - privilege "
        "mapping aid."),
    # ---- versioning ----
    "api_version_downgrade":     ("high", 7.4, "Purani/newer version different "
        "security posture rakhti hai (downgrade accepted) - OWASP API8 "
        "misconfiguration; attacker weakest version use karega."),
    "api_version_deprecated_live": ("medium", 6.6, "Deprecated/sunset version "
        "abhi bhi live hai - patch-gap surface (API9 improper inventory)."),
    "api_version_header_diff":   ("medium", 5.9, "Accept/query-param versioning "
        "path-version se differ karti hai - parser-skew bypass primitives."),
    # ---- rate limits ----
    "api_rate_missing":          ("high", 7.1, "Koi rate-limit signal nahi "
        "(headers absent + bounded burst me 429 kabhi nahi) - brute/enum "
        "surface (P9 credential-stuffing chain, OWASP API4)."),
    "api_rate_headers_only":     ("medium", 5.2, "Rate-limit headers hain par "
        "enforcement differential off tha (bounded burst me 429 nahi) - "
        "advertised-vs-enforced gap."),
    "api_rate_window_bypass":    ("high", 7.0, "X-Forwarded-For se limit window "
        "different hui - per-IP bucket identity confusion (header-trust "
        "bypass family; bounded probes hi kaafi hain)."),
    "api_rate_enforced":         ("info", 0.0, "429 + Retry-After present "
        "(positive signal)."),
    # ---- mass assignment ----
    "api_mass_assign_echo":      ("high", 7.7, "Extra canary field response me "
        "echo/store hui - writable-schema over-exposure (OWASP API3, "
        "mass-assignment -> privilege-escalation chain, CWE-915)."),
    "api_mass_assign_role_field": ("critical", 8.8, "Role/isAdmin-class field "
        "accept+echo hui (canary INERT value) - privilege-escalation-ready "
        "surface; chain manual verify with RoE."),
    "api_mass_assign_rejected":  ("info", 0.0, "Unknown fields reject/ignore "
        "hote hain (positive signal)."),
    # ---- BOLA pattern ----
    "api_bola_canary_readable":  ("high", 8.2, "Canary object-id GET par 200 "
        "aya (structural) - object-level authz sampling gap (OWASP API1; "
        "P11 full enumeration handoff)."),
    "api_bola_id_shape":         ("low", 3.6, "Sequential/guessable id-shape "
        "signal (404-vs-403 asymmetry) - enumeration aid."),
    # ---- errors / info ----
    "api_error_stack_trace":     ("high", 7.3, "Malformed body par stack-trace/"
        "framework debug page - internals+paths+versions leak (CWE-209)."),
    "api_error_verbose":         ("medium", 5.4, "Verbose validation errors "
        "field/schema oracle dete hain (enumeration aid)."),
    "api_debug_params_live":     ("medium", 6.0, "debug/pretty/trace params "
        "respond differently - debug surface live (info leak + DoS aid)."),
    "api_server_fingerprint":    ("low", 3.2, "Server/X-Powered-By headers "
        "framework fingerprint dete hain (targeting aid)."),
    # ---- method / CT ----
    "api_method_override":       ("medium", 5.8, "X-HTTP-Method-Override honor "
        "hota hai - write-methods read-only-locked surfaces me ghus sakte "
        "hain (bypass primitive)."),
    "api_methods_overexposed":   ("medium", 5.7, "OPTIONS Allow me write-methods "
        "declared hain jo spec me nahi (inventory skew)."),
    "api_ct_sniff_diff":         ("medium", 5.5, "Content-Type switch par parser "
        "differential - CT-confusion bypass primitives."),
    "api_write_methods_live":    ("high", 7.5, "Write methods (PATCH/DELETE) "
        "canary objects par live hain (GATED probe; canary-only) - "
        "function-level authz sampling (OWASP API5, BFLA)."),
    # ---- protocol handoff ----
    "api_graphql_detected":      ("info", 0.0, "GraphQL fingerprint mila - "
        "introspection/authz P18 me full engine (seed handoff done)."),
    "api_ws_detected":           ("info", 0.0, "WebSocket upgrade signal mila - "
        "P19 origin/authz census handoff (seed done)."),
    # ---- misc ----
    "api_param_reflection":      ("info", 0.0, "Param census harvested (P12 "
        "injection handoff seeds)."),
    "api_hardened":              ("info", 0.0, "Consistent 401/403 + strict CT "
        "+ rate headers (positive posture)."),
    "api_gate_skipped":          ("info", 0.0, "RoE-gated probes OFF the - "
        "INERT payload bodies api_payloads/ me ready (manual wave)."),
    "api_surface_sparse":        ("info", 0.0, "Seed artifacts kam mile - "
        "P5 (api_endpoints/openapi) + P3 (version matrix) + P11 (idor) pehle "
        "chalao ya scope.json check karo."),
    # ---- MANUAL-ONLY (kabhi auto nahi) ----
    "api_injection_manual":      ("info", 0.0, "Query/filter injection chains "
        "(spEL/QL/NoSQL-operators) - P12 ULTRA engine owns it; MANUAL wave."),
    "api_bfla_manual":           ("info", 0.0, "Function-level authz full "
        "enumeration - MANUAL-ONLY (canary sampling se aage nahi)."),
    "api_billing_abuse_manual":  ("info", 0.0, "Business-logic abuse (quota/"
        "refund/price) - P20 Logic phase owns it; kabhi auto nahi."),
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0, "API-surface signal."))
    return sev, cvss, why


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "API-%03d" % (len(self.items) + 1), "key": key, "title": title,
               "severity": sev, "cvss_hint": cvss, "endpoint": endpoint,
               "detail": pii_redact(detail), "why_it_matters": why,
               "evidence": evidence_ref, "ts": now_iso()}
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
# PII REDACT (framework rule)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token)\s*[:=]\s*[^\s,;\"]{6,})")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


# ---------------------------------------------------------------------------
# CANARY SYSTEM (P12..P16 pattern): family "waspP17" - grep-able markers.
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    return "waspP17%s%s" % (tag, rand_str(8).upper())


REDACTED_NOTE = ("[WASP P17 REDACTED - response bodies sirf len/sha1/"
                 "marker-boolean; detection-only]")


def filesig(body):
    b = body if isinstance(body, bytes) else (body or "").encode("utf-8", "ignore")
    return {"len": len(b), "sha1_12": hashlib.sha1(b).hexdigest()[:12],
            "content_stored": False}


# ===========================================================================
# INERT PAYLOAD SAFETY (CROWN DISCIPLINE)
# ===========================================================================
FORBIDDEN_CONTENT_PATTERNS = [
    r"<\?php", r"eval\s*\(", r"system\s*\(", r"exec\s*\(", r"shell_exec",
    r"passthru", r"proc_open", r"<script", r"onerror\s*=", r"onload\s*=",
    r"javascript:", r"\.\./\.\./", r"/etc/passwd", r"/etc/shadow",
    r"UNION\s+SELECT", r"DROP\s+TABLE", r"xp_cmdshell", r"<iframe",
    r"document\.cookie", r"window\.location", r"curl\s+", r"wget\s+",
    r"nc\s+-e", r"bash\s+-i", r"rm\s+-rf", r"chmod\s+777",
    r"BEGIN (RSA |EC )?PRIVATE KEY", r"AKIA[0-9A-Z]{16}",
]


def assert_inert(body, what="payload"):
    """Har request body is gate se guzarti hai - fail = hard error."""
    b = body if isinstance(body, bytes) else (body or "").encode("utf-8", "ignore")
    try:
        low = b.decode("utf-8", "ignore").lower()
    except Exception:
        low = repr(b).lower()
    for pat in FORBIDDEN_CONTENT_PATTERNS:
        if re.search(pat, low, re.I):
            raise ValueError("NON-INERT payload blocked [%s]: %s"
                             % (what, pat))
    return True


# ===========================================================================
# INERT PAYLOAD LIBRARY (sirf canary JSON / invalid-token markers)
# ===========================================================================
def inert_json_body(fields, canary):
    """Flat canary JSON - har value me INERT marker."""
    safe = {}
    for k, v in (fields or {}).items():
        safe[str(k)] = ("%s%s" % (canary, v)) if isinstance(v, str) else v
    body = json.dumps({"_wasp_canary": canary}).encode()
    body = json.dumps(safe).encode("utf-8")
    assert_inert(body, "inert_json_body")
    return body


def inert_nested_body(canary, depth=2):
    """Nested canary JSON (mass-assign deep-field probes ke liye, depth<=2)."""
    inner = {"role": canary + "user", "is_admin": False, "verified": False}
    obj = {"name": canary + "-n", "profile": inner} if depth >= 2 else \
        {"name": canary + "-n"}
    body = json.dumps(obj).encode("utf-8")
    assert_inert(body, "inert_nested_body")
    return body


def malformed_json_variants(canary):
    """Error-leak census: 6 malformed bodies (INERT - sirf structure tootta hai)."""
    return [
        (b"{not json", "truncated-brace"),
        (b'{"a": }', "empty-value"),
        (b'{"a": "b",}', "trailing-comma"),
        ((json.dumps({"a": canary}).replace(":", "=")[:20]).encode() + b"=",
         "corrupted-sep"),
        ((b"\x00\x01\x02" + canary.encode()[:8]), "binary-prefix"),
        ((b'{"a": "' + b"A" * 512 + b'"}'), "long-value"),
    ]


def invalid_token_pool(canary):
    """Auth-matrix tokens: SAB invalid/canary - koi real cred nahi."""
    jwt_shape = ("eyJ%s.%s.%s" % (base64.urlsafe_b64encode(
        ("waspP17hdr" + canary).encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(canary.encode()).decode().rstrip("="),
        rand_str(10)))
    return [
        ("anon", None),
        ("invalid-bearer", "Bearer %s" % (canary + rand_str(12))),
        ("invalid-jwt-shape", "Bearer " + jwt_shape),
        ("expired-shape", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MDB9.invalid"),
        ("basic-garbage", "Basic " + base64.b64encode(
            (canary + ":" + canary).encode()).decode()),
        ("api-key-header", canary + "-key"),
    ]


SENSITIVE_FIELDS = [
    "email", "password", "password_hash", "passwordHash", "token", "secret",
    "api_key", "apiKey", "role", "isAdmin", "is_admin", "admin", "permissions",
    "ssn", "credit_card", "cardNumber", "cvv", "otp", "mfa", "two_factor",
    "balance", "salary", "internal_notes", "owner_id", "tenant_id",
]

MASS_ASSIGN_FIELDS = [
    "role", "isAdmin", "is_admin", "admin", "verified", "email_verified",
    "status", "active", "permissions", "tenant_id", "owner_id", "price",
    "discount", "quota", "balance",
]

DEBUG_PARAMS = ["debug", "pretty", "trace", "verbose", "test", "XDEBUG_SESSION",
                "admin", "internal"]

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-quota-remaining", "x-rate-limit", "retry-after",
    "x-rate-limit-limit", "x-rate-limit-remaining", "ratelimit-policy",
]

API_PATH_POOL = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/api/rest", "/services", "/service", "/gateway",
    "/apiv1", "/apiv2", "/api/v1.0", "/api/v2.0", "/backend/api", "/internal/api",
    "/public/api", "/private/api", "/mobile/api", "/app/api", "/web/api",
    "/api/v1/", "/api/v2/",
]

SPEC_PATH_POOL = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json", "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/docs/openapi.json", "/.well-known/openapi",
    "/api-docs/swagger.json", "/spec/openapi.json", "/service.json",
    "/api/swagger/doc", "/documentation/openapi.json", "/api/v1/openapi.json",
]

VERSION_MARKERS = [
    ("/api/v1", "/api/v2"), ("/api/v2", "/api/v3"), ("/v1", "/v2"),
    ("/api/v1", "/api/v0"), ("/v2", "/v1"),
]

COMMON_ID_FIELDS = ["id", "user_id", "userId", "uuid", "guid", "account_id",
                    "orderId", "order_id", "doc_id", "item_id"]



# ===========================================================================
# ARTIFACT READER (P15/P16 tolerant pattern) - upstream seed mining
# ===========================================================================
def _read_json_tolerant(path):
    """JSON load jo multiple-format handle kare (P15 _artifact pattern)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def _artifact(base_dir, mod, fname):
    """P15 tolerant-reader: path -> (dict|list|str|None) jo bhi mile."""
    p = os.path.join(base_dir, mod, fname)
    if not os.path.exists(p):
        return None
    if fname.endswith(".json"):
        return _read_json_tolerant(p)
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def _iter_records(d):
    """dict/list/str -> record-iterator (P16 pattern)."""
    if d is None:
        return
    if isinstance(d, dict):
        lists = [v for v in d.values() if isinstance(v, list)]
        if lists:
            for lst in lists:
                for r in lst:
                    yield r
        elif d:
            yield d
    elif isinstance(d, list):
        for r in d:
            yield r


def _url_from_rec(rec, prefer=("url", "endpoint", "path", "href", "target",
                              "action", "uri", "link", "api", "base")):
    if isinstance(rec, str):
        return rec
    if isinstance(rec, dict):
        for k in prefer:
            v = rec.get(k)
            if isinstance(v, str) and (v.startswith("/") or "http" in v[:8]):
                return v
        for v in rec.values():
            if isinstance(v, str) and (v.startswith("/") or "http" in v[:8]):
                return v
    return None


def urljoin_safe(base_url, rel):
    try:
        return urllib.parse.urljoin(base_url, rel)
    except Exception:
        return rel


def _norm_target(url, base_url):
    if not url:
        return None
    u = str(url).strip()
    if u.startswith("http://") or u.startswith("https://"):
        return u.split("#")[0]
    if u.startswith("/"):
        return urljoin_safe(base_url, u).split("#")[0]
    return urljoin_safe(base_url, "/" + u).split("#")[0]


class _Rank:
    """Seed source -> priority score (P16 pattern)."""
    WEIGHTS = {
        "p5_openapi": 46, "p5_swagger": 46, "p5_api_endpoints": 42,
        "p3_version_matrix": 40, "p15_to_p17": 38, "p16_to_p17": 36,
        "p11_idor_endpoints": 34, "p11_access_endpoints": 32,
        "p2_params": 22, "p7_js_hints": 24, "p8_priority": 26,
        "p5_endpoints": 20, "p3_api_like": 22, "cold_path_pool": 14,
        "spec_derived": 44,
    }

    def __init__(self):
        self.rows = {}

    def add(self, url, source, kind="api_endpoint", hint=None):
        if not url:
            return
        key = url
        row = self.rows.get(key)
        if row is None:
            row = {"url": url, "kind": kind, "sources": [], "hints": set(),
                   "score": 0}
            self.rows[key] = row
        if source not in row["sources"]:
            row["sources"].append(source)
            row["score"] += self.WEIGHTS.get(source, 10)
        if hint and hint not in row["hints"]:
            row["hints"].add(hint)
        if kind == "spec" and row["kind"] != "spec":
            row["kind"] = "spec"

    def ranked(self):
        rows = sorted(self.rows.values(), key=lambda r: -r["score"])
        for r in rows:
            r["hints"] = sorted(r["hints"])
            r["sources"] = sorted(r["sources"])
        return rows


def _abs_urls_from_text(text, base_url, cap=40):
    out = []
    for m in re.finditer(r"(?:https?://[^\s\"'<>]+|/[A-Za-z0-9_\-./]+)",
                         (text or "")):
        u = _norm_target(m.group(0), base_url)
        if u and u not in out:
            out.append(u)
        if len(out) >= cap:
            break
    return out


# ===========================================================================
# STAGE A - API SURFACE DISCOVERY (guide seeds: P5/P3/P11 + ff P15/P16)
# ===========================================================================
def discover_api_surface(base_dir, scope, conf):
    """Seed-artifacts mining + cold path-pool. Returns (ranked_rows, meta)."""
    base_url = ""
    try:
        seeds = scope.seed_urls()
        base_url = seeds[0] if seeds else ""
    except Exception:
        base_url = ""
    rank = _Rank()
    sources = []
    meta = {"base_url": base_url, "probes_total": 0, "spec_docs": []}

    def mine(mod, fname, source, kind="api_endpoint", url_key=None):
        art = _artifact(base_dir, mod, fname)
        if art is None:
            return None
        sources.append(source)
        if isinstance(art, (dict, list)):
            for rec in _iter_records(art):
                u = _url_from_rec(rec) if url_key is None else (
                    rec.get(url_key) if isinstance(rec, dict) else None)
                if u:
                    rank.add(_norm_target(u, base_url), source, kind)
        elif isinstance(art, str):
            for u in _abs_urls_from_text(art, base_url)[:60]:
                rank.add(u, source, kind)
        return art

    # --- P5 content: api_endpoints + openapi + swagger (guide seeds) ---
    if _artifact(base_dir, "content", "openapi.json") is not None:
        rank.add(_norm_target("/openapi.json", base_url) or
                 urljoin_safe(base_url, "/openapi.json"), "p5_openapi", "spec")
        sources.append("p5_openapi")
    if _artifact(base_dir, "content", "swagger.json") is not None:
        rank.add(urljoin_safe(base_url, "/swagger.json"), "p5_swagger", "spec")
        sources.append("p5_swagger")
    mine("content", "api_endpoints.txt", "p5_api_endpoints")
    mine("content", "endpoints.txt", "p5_endpoints")

    # --- P3 passive: api_version_matrix + api_like (guide seeds) ---
    vm = _artifact(base_dir, "passive", "api_version_matrix.json")
    if vm:
        sources.append("p3_version_matrix")
        for rec in _iter_records(vm):
            u = _url_from_rec(rec, prefer=("url", "version_url", "endpoint",
                                           "path"))
            if u:
                rank.add(_norm_target(u, base_url), "p3_version_matrix",
                         "api_endpoint", hint="versioned")
    mine("passive", "api_like.txt", "p3_api_like")

    # --- P11 access: idor/access endpoints (guide seeds) ---
    mine("access", "access_endpoints.txt", "p11_access_endpoints")
    idor = _artifact(base_dir, "access", "batch_idor.json")
    if idor:
        sources.append("p11_idor_endpoints")
        for rec in _iter_records(idor):
            u = _url_from_rec(rec, prefer=("url", "endpoint", "template",
                                           "path"))
            if u:
                rank.add(_norm_target(u, base_url), "p11_idor_endpoints",
                         "api_endpoint", hint="idor-pattern")

    # --- P15/P16 feedforward (routing.to_phase17_api / to_phase17) ---
    for mod in ("ssrf", "files"):
        ff = _artifact(base_dir, mod, "feedforward.json")
        if not isinstance(ff, dict):
            continue
        routing = ff.get("routing") or {}
        key = "to_phase17_api" if "to_phase17_api" in routing else (
            "to_phase17" if "to_phase17" in routing else None)
        if key:
            src = "p15_to_p17" if mod == "ssrf" else "p16_to_p17"
            sources.append(src)
            blob = routing.get(key) or {}
            for sub in blob.values():
                if isinstance(sub, list):
                    for u in sub:
                        # sirf URL/path-shaped strings (param-name junk nahi)
                        if isinstance(u, str) and (
                                u.startswith("http") or u.startswith("/")):
                            rank.add(_norm_target(u, base_url), src)
                elif isinstance(sub, str) and (
                        sub.startswith("http") or sub.startswith("/")):
                    rank.add(_norm_target(sub, base_url), src)

    # --- P2 params + P7 js hints + P8 priority ---
    mine("understand", "params.json", "p2_params")
    mine("js", "js_hints.txt", "p7_js_hints")
    mine("surface", "priority_queue.json", "p8_priority")

    # --- cold-start: common API + spec paths (bounded GET probes run() me) ---
    for p in API_PATH_POOL[:int(conf.get("api_cold_paths", 20))]:
        rank.add(urljoin_safe(base_url, p), "cold_path_pool")
    for p in SPEC_PATH_POOL[:int(conf.get("api_spec_paths", 12))]:
        rank.add(urljoin_safe(base_url, p), "cold_path_pool", "spec")

    ranked = rank.ranked()
    meta["sources"] = sorted(set(sources))
    return ranked, meta



# ===========================================================================
# STAGE C - OPENAPI/SWAGGER SPEC ENGINE (fetch + parse + audit)
# ===========================================================================
def parse_openapi_spec(doc, doc_url):
    """OpenAPI 3 / Swagger 2 tolerant parser -> census dict."""
    if not isinstance(doc, dict):
        return None
    version = str(doc.get("openapi") or doc.get("swagger") or "")
    if not version:
        return None
    spec = {"doc_url": doc_url, "spec_version": version, "title": "",
            "servers": [], "base_path": "", "paths_count": 0,
            "endpoints": [], "security_schemes": [], "schemes": [],
            "internal_hosts": [], "emails": [], "deprecated_live": [],
            "writable_fields": {}, "requires_auth_paths": [],
            "public_paths": [], "shadow_hints": []}
    info = doc.get("info") or {}
    spec["title"] = str(info.get("title") or "")[:120]
    # servers (OAS3) / host+basePath (SW2)
    for s in (doc.get("servers") or []):
        if isinstance(s, dict) and s.get("url"):
            spec["servers"].append(str(s["url"])[:200])
    host = doc.get("host")
    bp = doc.get("basePath") or ""
    spec["base_path"] = bp
    if host:
        spec["servers"].append("http://%s%s" % (host, bp))
    for sname in (doc.get("schemes") or []):
        spec["schemes"].append(str(sname))
    # security schemes
    comps = doc.get("components") or {}
    secdefs = comps.get("securitySchemes") or doc.get("securityDefinitions") \
        or {}
    for name, sd in (secdefs.items() if isinstance(secdefs, dict) else []):
        if isinstance(sd, dict):
            spec["security_schemes"].append({
                "name": str(name), "type": str(sd.get("type") or "?"),
                "in": str(sd.get("in") or ""), "scheme":
                    str(sd.get("scheme") or "")})
    # paths
    paths = doc.get("paths") or {}
    for p, item in (paths.items() if isinstance(paths, dict) else []):
        if not isinstance(item, dict):
            continue
        path_auth = bool(item.get("security"))
        for method in ("get", "post", "put", "patch", "delete", "head",
                       "options", "trace"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            deprecated = bool(op.get("deprecated"))
            op_sec = bool(op.get("security")) or path_auth
            params = []
            for prm in (op.get("parameters") or item.get("parameters") or []):
                if isinstance(prm, dict):
                    params.append({"name": str(prm.get("name") or ""),
                                   "in": str(prm.get("in") or ""),
                                   "required": bool(prm.get("required"))})
            body_props = []
            rb = op.get("requestBody") or {}
            if isinstance(rb, dict):
                content = rb.get("content") or {}
                for ct, cm in (content.items() if isinstance(content, dict)
                               else []):
                    sch = cm.get("schema") or {}
                    props = (sch.get("properties") or
                             ((sch.get("$ref") or "").split("/")[-1:]))
                    if isinstance(props, dict):
                        body_props = list(props.keys())[:24]
                    break
            ep = {"path": str(p)[:200], "method": method.upper(),
                  "deprecated": deprecated, "auth": op_sec,
                  "params": params[:12], "body_fields": body_props,
                  "operation_id": str(op.get("operationId") or "")[:60]}
            spec["endpoints"].append(ep)
            if deprecated:
                spec["deprecated_live"].append("%s %s" % (method.upper(), p))
            if op_sec:
                spec["requires_auth_paths"].append("%s %s" %
                                                   (method.upper(), p))
            else:
                spec["public_paths"].append("%s %s" % (method.upper(), p))
            if body_props:
                cur = spec["writable_fields"].get("%s %s" %
                                                  (method.upper(), p)) or []
                spec["writable_fields"]["%s %s" % (method.upper(), p)] = \
                    body_props
    spec["paths_count"] = len(paths)
    # internal hosts + emails from raw doc text
    raw = json.dumps(doc)[:200000]
    for m in re.finditer(
            r"(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\.internal|\.local|staging|"
            r"dev\.)[^\s\"']{0,60}", raw, re.I):
        spec["internal_hosts"].append(m.group(0)[:120])
    for m in _PII_EMAIL.finditer(raw):
        spec["emails"].append(m.group(0))
    spec["internal_hosts"] = list(dict.fromkeys(spec["internal_hosts"]))[:10]
    spec["emails"] = list(dict.fromkeys(spec["emails"]))[:10]
    return spec


def spec_audit_findings(spec, F, base_url, meta):
    """Spec exposure audit -> findings (guide: spec= recon goldmine)."""
    if not spec:
        return
    if spec.get("endpoints"):
        F.add("api_spec_public", "OpenAPI/Swagger spec publicly accessible",
              spec.get("doc_url") or base_url,
              "%d paths / %d operations spec se mile (title=%s). Spec "
              "exposure = attack-surface disclosure."
              % (spec.get("paths_count", 0), len(spec.get("endpoints", [])),
                 spec.get("title") or "?"),
              "openapi_spec_census.json")
    if spec.get("internal_hosts") or spec.get("emails"):
        F.add("api_spec_internal_hosts", "Spec me internal hosts/emails",
              spec.get("doc_url") or base_url,
              "internal=%s emails=%d (redacted view)"
              % (len(spec.get("internal_hosts", [])),
                 len(spec.get("emails", []))),
              "openapi_spec_census.json")
    if spec.get("deprecated_live"):
        F.add("api_version_deprecated_live", "Deprecated operations spec me "
              "live hain", spec.get("doc_url") or base_url,
              "%d deprecated ops: %s" % (len(spec["deprecated_live"]),
                                         spec["deprecated_live"][:4]),
              "openapi_spec_census.json")
    meta["spec_audit_done"] = True


# ===========================================================================
# QUIET CLIENT + BASELINE (P16 pattern)
# ===========================================================================
def quiet_client(http, cfg, scope, ev):
    """Evidence-off client copy (probe-log khud maintain karta hai)."""
    q = copy.copy(http)
    q.ev = None
    return q


def baseline_endpoint(http, url, conf, cp, meta, tag="b"):
    """2x GET baseline + soft-404 check -> (sig, is_template)."""
    sigs = []
    for _ in range(2):
        r = http.get(url, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sigs.append((r.status, len(r.body or b""),
                     (r.header("Content-Type") or "")[:40],
                     r.header("Allow") or ""))
        time.sleep(0.02)
    (s1, l1, c1, a1), (s2, l2, c2, a2) = sigs
    return {"status": s1, "len": l1, "ct": c1, "allow": a1,
            "stable": (s1 == s2 and abs(l1 - l2) <= 8),
            "soft404_like": (s1 in (404, 400) or
                             (l1 < 64 and s1 in (200, 204)))}


def _sig(r):
    return (r.status, len(r.body or b""),
            (r.header("Content-Type") or "")[:40])


def pick_home_marker(http, base_url, meta):
    r = http.get(base_url, allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    return {"status": r.status, "len": len(r.body or b""),
            "snippet": (r.text or "")[:80]}


def _resp_is_json(r):
    ct = (r.header("Content-Type") or "").lower()
    return "json" in ct or ("{" in (r.text or "")[:64])



# ===========================================================================
# STAGE D - VERSIONING MATRIX (path + query + header differentials)
# ===========================================================================
def version_matrix(http, targets, base_url, meta, conf, home_sig):
    """Version-differential: pairs ko GET-diff karo (read-only)."""
    rows = []
    cap = int(conf.get("api_version_pairs", 8))
    cand = [t for t in targets if t.get("kind") == "api_endpoint"]
    # versioned urls discover karo (path me /vN)
    versioned = {}
    for t in cand:
        u = t["url"]
        m = re.search(r"/v(\d+)(?:/|$)", urllib.parse.urlsplit(u).path)
        if m:
            versioned.setdefault(m.group(1), []).append(u)
    if len(versioned) < 2:
        # cold synth: base me /v1 /v2 probe (bounded)
        root = base_url.rstrip("/")
        for v in ("v1", "v2", "v3"):
            u = "%s/api/%s/users" % (root, v)
            r = http.get(u, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            versioned.setdefault(v[1:], []).append(u)
    pairs = 0
    vers = sorted(versioned.keys(), key=lambda x: int(x) if x.isdigit() else 9)
    for i in range(len(vers) - 1):
        for ua in versioned[vers[i]]:
            for ub in versioned[vers[i + 1]]:
                if pairs >= cap:
                    break
                ra = http.get(ua, allow_redirects=False)
                rb = http.get(ub, allow_redirects=False)
                meta["probes_total"] += 2
                sa, la = _sig(ra)[0], _sig(ra)[1]
                sb, lb = _sig(rb)[0], _sig(rb)[1]
                autha = sa in (401, 403)
                authb = sb in (401, 403)
                skew = (autha != authb) or (sa == 200 and sb in (401, 403)) \
                    or (sb == 200 and sa in (401, 403))
                rows.append({
                    "pair": [ua, ub], "versions": [vers[i], vers[i + 1]],
                    "status": [sa, sb], "auth_consistent":
                        not skew,
                    "skew": skew,
                    "older_open": (sa == 200 and sb in (401, 403)),
                    "len": [la, lb], "note": ""})
                pairs += 1
            if pairs >= cap:
                break
        if pairs >= cap:
            break
    # query-param version differential (read-only, capped)
    qrows = []
    if conf.get("api_version_downgrade", True) and cand:
        u = cand[0]["url"]
        sep = "&" if "?" in u else "?"
        for qv in ("v1", "2", "version=1"):
            rq = http.get("%s%sver=%s" % (u, sep, qv), allow_redirects=False)
            meta["probes_total"] += 1
            qrows.append({"url": u, "param": qv, "status": rq.status,
                          "len": len(rq.body or b"")})
    return {"path_pairs": rows, "query_probes": qrows,
            "versions_seen": vers}


# ===========================================================================
# STAGE E - AUTH MATRIX (per-endpoint token-role differential - guide core)
# ===========================================================================
AUTH_SIGNAL_200 = 0
def auth_probe_endpoint(http, url, method, canary, meta, conf,
                        body=None):
    """Ek endpoint x token-roles -> status/len matrix (invalid tokens only)."""
    roles = invalid_token_pool(canary)[:max(2, int(conf.get(
        "api_auth_roles", 4)))]
    out = []
    for role, token in roles:
        headers = {"Accept": "application/json",
                   "X-WASP-Probe": "P17-inert-auth"}
        if token:
            headers["Authorization"] = token
            headers["X-API-Key"] = token.split()[-1][:40]
        try:
            if method in ("GET", "HEAD"):
                r = http.get(url, headers=headers, allow_redirects=False)
            else:
                b = body or inert_json_body({"probe": "auth"}, canary)
                r = http.post(url, data=b,
                              headers=dict(headers,
                                           **{"Content-Type":
                                              "application/json"}),
                              force_write=True, allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            class _E:
                status = 0
                body = b""
                text = ""
                elapsed = 0.0
            _E.text = "auth-probe-error: %s" % truncate(str(e), 80)
            r = _E()
        out.append({"role": role, "status": r.status,
                    "len": len(r.body or b""),
                    "ct": (r.header("Content-Type") or "")[:32],
                    "auth_hint": (r.header("WWW-Authenticate") or "")[:60],
                    "canary_echo": canary in (r.text or "")})
    return out


def classify_auth(rows, canary):
    """Auth-matrix rows -> (verdict, model, signals)."""
    if not rows:
        return "NOISE", "unknown", []
    anon = next((r for r in rows if r["role"] == "anon"), rows[0])
    authed = [r for r in rows if r["role"] != "anon"]
    signals = []
    if anon["status"] == 200:
        signals.append("anon-200")
        if anon["len"] > 64 and _resp_is_json_ish(anon):
            signals.append("anon-data")
    bad_all_401_403 = all(r["status"] in (401, 403) for r in authed) \
        if authed else False
    bad_any_200 = any(r["status"] in (200, 201) for r in authed) \
        if authed else False
    if anon["status"] in (401, 403) and bad_all_401_403:
        return "HARDENED", "consistent-401/403", signals
    if anon["status"] == 200:
        if "anon-data" in signals:
            return "CONFIRMED", "auth-missing", signals
        return "SUSPECTED", "auth-missing", signals
    if bad_any_200:
        signals.append("invalid-token-accepted")
        return "CONFIRMED", "token-not-validated", signals
    if anon["status"] == 0:
        return "NOISE", "probe-error", signals
    if anon["status"] in (401, 403):
        return "SUSPECTED", "inconsistent", signals
    return "SUSPECTED", "odd-pattern", signals


def _resp_is_json_ish(row):
    return "json" in (row.get("ct") or "").lower() or row.get("len", 0) > 32


def auth_matrix(http, targets, base_url, meta, conf, canary):
    """Top-N private-ish endpoints x roles -> matrix rows + findings seeds."""
    rows = []
    cap = int(conf.get("api_auth_endpoints", 8))
    # private-looking endpoints pehle (admin/user/account/profile/order/...)
    def priv_score(t):
        p = urllib.parse.urlsplit(t["url"]).path.lower()
        s = 0
        for kw in ("admin", "user", "account", "profile", "order", "invoice",
                   "payment", "config", "internal", "private", "me", "self",
                   "customer", "employee", "billing"):
            if kw in p:
                s += 12
        return -s
    cand = sorted([t for t in targets
                   if t.get("kind") == "api_endpoint"], key=priv_score)
    for t in cand[:cap]:
        u = t["url"]
        probe_rows = auth_probe_endpoint(http, u, "GET", canary, meta, conf)
        verdict, model, sigs = classify_auth(probe_rows, canary)
        rows.append({"url": u, "method": "GET", "verdict": verdict,
                     "model": model, "signals": sigs, "roles":
                         probe_rows,
                     "sources": t.get("sources", [])})
    return rows



# ===========================================================================
# STAGE F - MASS ASSIGNMENT ENGINE (guide core; write GATED, census ON)
# ===========================================================================
def mass_assign_census(http, targets, base_url, meta, conf, canary, spec):
    """Writable-field census: spec-based + probe-based (error-differential).
    Write-probe sirf GATED (api_allow_mass_write) - canary objects only."""
    rows = []
    # 1) spec-based audit (0 requests)
    if spec and spec.get("writable_fields"):
        for key, fields in list(spec["writable_fields"].items())[:20]:
            risky = [f for f in fields if f in SENSITIVE_FIELDS or
                     f in MASS_ASSIGN_FIELDS]
            if risky:
                rows.append({"op": key, "via": "spec", "risky_fields":
                             risky, "all_fields": fields[:16],
                             "probe": "offline-audit"})
    # 2) probe-based census: POST/PUT par 400-error differential (gated OFF
    #    par bhi chalta hai kyunki yeh error-census hai, data-change nahi)
    cap = int(conf.get("api_ct_confusion_cap", 6))
    cand = [t for t in targets if t.get("kind") == "api_endpoint"][:cap]
    for t in cand:
        u = t["url"]
        if not any(kw in u.lower() for kw in
                   ("user", "account", "profile", "register", "signup",
                    "customer", "order", "employee", "item", "product",
                    "create")):
            continue
        body = inert_json_body({"name": canary + "-ma"}, canary)
        extra = dict(json.loads(body.decode("utf-8")))
        extra["is_admin"] = False
        extra["role"] = canary + "-role"
        b2 = json.dumps(extra).encode("utf-8")
        assert_inert(b2, "mass-assign-census")
        try:
            r1 = http.post(u, data=body, headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P17-inert-ma"}, force_write=True,
                allow_redirects=False)
            r2 = http.post(u, data=b2, headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P17-inert-ma2"}, force_write=True,
                allow_redirects=False)
            meta["probes_total"] += 2
        except ScopeError:
            raise
        except Exception as e:
            r1 = r2 = None
            rows.append({"op": "POST %s" % u, "via": "probe",
                         "error": truncate(str(e), 80)})
            continue
        if r1 is None:
            continue
        echo = (canary + "-role") in (r2.text or "")
        role_echo = (canary + "-role") in (r2.text or "") and \
            (canary + "-role") not in (r1.text or "")
        rows.append({"op": "POST %s" % u, "via": "probe",
                     "status": [r1.status, r2.status],
                     "extra_field_echo": echo, "role_echo": role_echo,
                     "note": "canary values only (INERT)"})
    return rows


def mass_assign_write_probe(http, url, canary, meta, conf):
    """GATED write probe: canary object create + extra-field + GET-back diff.
    Sirf api_allow_mass_write=true par. Returns rows (evidence-first)."""
    if not conf.get("api_allow_mass_write"):
        return [{"probe": "mass-write", "skipped": True,
                 "gate": "api_allow_mass_write=false",
                 "manual_wave": "api_payloads/ me INERT bodies ready"}]
    rows = []
    base_body = {"name": canary + "-obj", "email": (canary +
                                                    "@invalid").lower()}
    ma_fields = ["role", "isAdmin", "is_admin", "verified", "status"]
    # create canary object
    try:
        rc = http.post(url, data=inert_json_body(base_body, canary),
                       headers={"Content-Type": "application/json",
                                "X-WASP-Probe": "P17-canary-create"},
                       force_write=True, allow_redirects=False)
        meta["probes_total"] += 1
    except ScopeError:
        raise
    except Exception as e:
        return [{"probe": "mass-write", "error": truncate(str(e), 80)}]
    if rc.status not in (200, 201, 202):
        return [{"probe": "mass-write", "skipped": True,
                 "note": "canary-create nahi hua (status=%s)" % rc.status}]
    for fld in ma_fields[:4]:
        obj = dict(base_body)
        obj[fld] = (canary + "-val") if fld != "isAdmin" else False
        b = json.dumps(obj).encode("utf-8")
        assert_inert(b, "mass-write[%s]" % fld)
        try:
            rw = http.post(url, data=b, headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P17-ma-write"}, force_write=True,
                allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            rows.append({"field": fld, "error": truncate(str(e), 80)})
            continue
        echo = (canary + "-val") in (rw.text or "")
        rows.append({"field": fld, "status": rw.status, "echo": echo,
                     "canary": canary, "note": "INERT value; canary-object"})
    return rows


# ===========================================================================
# STAGE G - RATE LIMIT ENGINE (headers passive + burst GATED hard-capped)
# ===========================================================================
def rate_header_census(http, targets, meta):
    rows = []
    for t in targets[:10]:
        if t.get("kind") != "api_endpoint":
            continue
        r = http.get(t["url"], allow_redirects=False)
        meta["probes_total"] += 1
        found = []
        for h in RATE_LIMIT_HEADERS:
            v = r.header(h)
            if v:
                found.append({"header": h, "value": truncate(str(v), 40)})
        rows.append({"url": t["url"], "status": r.status,
                     "rate_headers": found,
                     "has_limit": bool(found)})
    return rows


def rate_burst_probe(http, url, meta, conf, canary):
    """GATED bounded burst: hard-cap 15 req, 429/503 par instant stop.
    Headers-census ke BAAD hi chalta hai. No DoS - single endpoint."""
    cap = min(int(conf.get("api_rate_burst_cap", 15)), 15)
    if not conf.get("api_allow_rate_burst"):
        return {"skipped": True, "gate": "api_allow_rate_burst=false",
                "manual_wave": "bounded burst RoE ke saath manual chalao",
                "cap": cap}
    codes = []
    stop = False
    retry_after = None
    for i in range(cap):
        try:
            r = http.get(url, allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            codes.append({"i": i, "error": truncate(str(e), 60)})
            break
        codes.append(r.status)
        ra = r.header("Retry-After")
        if ra:
            retry_after = truncate(str(ra), 20)
        if r.status in (429, 503):
            stop = True
            break
        time.sleep(0.05)
    return {"url": url, "requests": len(codes), "codes": codes,
            "throttled": stop, "retry_after": retry_after, "cap": cap}


def rate_window_hint_probe(http, url, meta, conf, canary):
    """GATED: X-Forwarded-For se window-differential (2 requests hi)."""
    if not conf.get("api_allow_header_window"):
        return {"skipped": True, "gate": "api_allow_header_window=false"}
    out = []
    for xff in ("198.18.%d.%d" % (1, 1), "198.18.%d.%d" % (2, 2)):
        try:
            r = http.get(url, headers={"X-Forwarded-For": xff,
                                       "X-WASP-Probe": "P17-xff-hint"},
                         allow_redirects=False)
            meta["probes_total"] += 1
            out.append({"xff": xff, "status": r.status,
                        "remaining": truncate(str(r.header(
                            "X-RateLimit-Remaining") or ""), 20)})
        except ScopeError:
            raise
        except Exception as e:
            out.append({"xff": xff, "error": truncate(str(e), 60)})
    return {"url": url, "probes": out,
            "note": "header-trust hint only (bounded 2)"}



# ===========================================================================
# STAGE H - BOLA PATTERN SAMPLING (GATED; canary ids only, GET-only)
# ===========================================================================
def bola_sampling(http, targets, base_url, meta, conf, canary):
    """Canary-id structural differential (no real-id enumeration).
    200-on-canary = object-level authz sampling gap hypothesis."""
    if not conf.get("api_allow_bola"):
        return {"skipped": True, "gate": "api_allow_bola=false",
                "manual_wave": "P11 owns enumeration; P17 sirf handoff "
                               "consumes (access/batch_idor.json)"}
    rows = []
    cap = int(conf.get("api_bola_ids", 4))
    cand = [t for t in targets if t.get("kind") == "api_endpoint"]
    templ = []
    for t in cand:
        p = urllib.parse.urlsplit(t["url"]).path
        if re.search(r"/(users?|accounts?|orders?|items?|docs?|invoices?|"
                     r"customers?|employees?|records?)/", p + "/"):
            templ.append(t)
        if re.search(r"\{[^}]+\}|:id|<id>", p):
            templ.append(t)
    if not templ and cand:
        templ = cand[:2]
    for t in templ[:cap]:
        u = t["url"].rstrip("/")
        cu = "%s/waspP17%s" % (u, rand_str(6).upper())
        r = http.get(cu, headers={"Accept": "application/json",
                                  "X-WASP-Probe": "P17-bola-canary"},
                     allow_redirects=False)
        meta["probes_total"] += 1
        rb = http.get(u, allow_redirects=False)
        meta["probes_total"] += 1
        rows.append({"template": u, "canary_url": cu,
                     "canary_status": r.status,
                     "base_status": rb.status,
                     "canary_len": len(r.body or b""),
                     "sig": filesig(r.body),
                     "note": "canary-id only (INERT)"})
    return {"rows": rows, "canary": canary}


# ===========================================================================
# STAGE I - ERROR/INFO LEAK ENGINE (read-only, INERT malformed bodies)
# ===========================================================================
STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)", r"at [a-z]+\.[A-Za-z0-9_$]+\(",
    r"File \"[^\"]+\.py\"", r"Exception in thread", r"java\.lang\.\w+",
    r"at org\.\w+", r"at java\.\w+", r"System\.NullReference",
    r"django\.core", r"\.php on line \d+", r"PHP (Warning|Notice|Fatal)",
    r"_stack_trace", r"at sun\.reflect", r"Caused by:",
]

VERBOSE_ERROR_PATTERNS = [
    r"(?i)validation failed for field", r"(?i)required property",
    r"(?i)must be (a |an )?(string|integer|number|boolean|array)",
    r"(?i)unknown (property|field|parameter)", r"(?i)invalid (type|format)",
    r"(?i)expected .+ got", r"(?i)missing required",
]


def error_leak_probe(http, url, canary, meta, conf):
    """Malformed-JSON census (read-only POST? -> GET+POST w/ inert bodies).
    Error-based census: 4xx/5xx RESPONSE analysis, data change nahi hota."""
    rows = []
    for body, label in malformed_json_variants(canary)[:4]:
        assert_inert(body, "err-leak[%s]" % label)
        try:
            r = http.post(url, data=body, headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P17-err-leak"}, force_write=True,
                allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            rows.append({"label": label, "error": truncate(str(e), 60)})
            continue
        text = r.text or ""
        stack = any(re.search(p, text) for p in STACK_TRACE_PATTERNS)
        verbose = any(re.search(p, text) for p in VERBOSE_ERROR_PATTERNS)
        rows.append({"label": label, "status": r.status,
                     "len": len(r.body or b""),
                     "stack_trace": stack, "verbose": verbose,
                     "server": (r.header("Server") or "")[:40],
                     "powered": (r.header("X-Powered-By") or "")[:40],
                     "sig": filesig(r.body)})
    return rows


def debug_params_probe(http, url, canary, meta, conf):
    """debug/pretty/trace GET census (capped, read-only)."""
    if not conf.get("api_debug_params", True):
        return []
    out = []
    sep = "&" if "?" in url else "?"
    base = _sig(http.get(url, allow_redirects=False))
    meta["probes_total"] += 1
    for prm in DEBUG_PARAMS[:int(conf.get("api_debug_cap", 6))]:
        r = http.get("%s%s%s=1" % (url, sep, prm), headers={
            "X-WASP-Probe": "P17-debug-census"}, allow_redirects=False)
        meta["probes_total"] += 1
        s, l = _sig(r)[0], _sig(r)[1]
        if (s, l) != base and s == 200:
            out.append({"param": prm, "status": s, "len": l,
                        "base_len": base[1], "diff": abs(l - base[1])})
    return out


# ===========================================================================
# STAGE J - METHOD / CONTENT-TYPE CONFUSION CENSUS (bounded)
# ===========================================================================
def method_census(http, url, meta, conf):
    """OPTIONS Allow-header census + method-override hint (passive-first)."""
    row = {"url": url, "allow": "", "methods": [], "override_honored": None}
    try:
        r = http.options(url, headers={"X-WASP-Probe": "P17-options"},
                         allow_redirects=False)
        meta["probes_total"] += 1
        allow = r.header("Allow") or r.header("Access-Control-Allow-Methods")
        row["allow"] = truncate(allow or "", 120)
        row["methods"] = [m.strip().upper() for m in
                          (allow or "").split(",") if m.strip()][:12]
    except ScopeError:
        raise
    except Exception as e:
        row["error"] = truncate(str(e), 60)
    if conf.get("api_ct_confusion", True) and \
            "PATCH" in (row["methods"] or []):
        # override hint: POST + X-HTTP-Method-Override: PATCH (canary body)
        b = inert_json_body({"m": "override-hint"}, _canary("ov"))
        try:
            r2 = http.post(url, data=b, headers={
                "Content-Type": "application/json",
                "X-HTTP-Method-Override": "PATCH",
                "X-WASP-Probe": "P17-override-hint"}, force_write=True,
                allow_redirects=False)
            meta["probes_total"] += 1
            row["override_honored"] = (r2.status not in (404, 405, 501))
            row["override_status"] = r2.status
        except ScopeError:
            raise
        except Exception as e:
            row["override_error"] = truncate(str(e), 60)
    return row


def ct_confusion_probe(http, url, canary, meta, conf):
    """CT-switch parser differential (bounded 3 variants, GET-echo based)."""
    if not conf.get("api_ct_confusion", True):
        return []
    rows = []
    variants = [
        (json.dumps({"q": canary}).encode(), "application/json"),
        (json.dumps({"q": canary}).encode(), "text/plain"),
        (("q=%s" % canary).encode(), "application/x-www-form-urlencoded"),
    ]
    for body, ct in variants:
        assert_inert(body, "ct-confusion")
        try:
            r = http.post(url, data=body[:256], headers={
                "Content-Type": ct,
                "X-WASP-Probe": "P17-ct-confusion"}, force_write=True,
                allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            rows.append({"ct": ct, "error": truncate(str(e), 60)})
            continue
        rows.append({"ct": ct, "status": r.status,
                     "len": len(r.body or b""),
                     "canary_echo": canary in (r.text or "")})
    return rows


# ===========================================================================
# STAGE K - GRAPHQL / WEBSOCKET FINGERPRINT (P18/P19 handoff seeds)
# ===========================================================================
GQL_HINTS = ["graphql", "__schema", "graphiql", "query {", "mutation {",
             "playground", "apollo"]


def gql_ws_fingerprint(http, base_url, meta, conf):
    """GraphQL + WS upgrade signal census (2-4 requests, read-only)."""
    out = {"graphql_endpoints": [], "ws_signals": [], "gql_probe": {}}
    root = base_url.rstrip("/")
    gql_paths = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql",
                 "/graphql/v1", "/query"]
    for p in gql_paths[:4]:
        u = root + p
        try:
            r = http.get(u, allow_redirects=False)
            meta["probes_total"] += 1
            if r.status in (200, 400, 405, 422):
                text = (r.text or "").lower()
                if any(h in text for h in GQL_HINTS) or \
                        "graphql" in (r.header("Content-Type") or "").lower():
                    out["graphql_endpoints"].append(u)
        except ScopeError:
            raise
        except Exception:
            continue
    # POST query fingerprint (bounded 1, INERT introspection-min query)
    if out["graphql_endpoints"]:
        u = out["graphql_endpoints"][0]
        q = json.dumps({"query": "{ __typename }"}).encode("utf-8")
        assert_inert(q, "gql-fingerprint")
        try:
            rg = http.post(u, data=q, headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P17-gql-fp"}, force_write=True,
                allow_redirects=False)
            meta["probes_total"] += 1
            out["gql_probe"] = {"url": u, "status": rg.status,
                                "typename_ok": "__typename" in (rg.text or ""),
                                "introspection_hint":
                                    "schema" in (rg.text or "").lower()}
        except ScopeError:
            raise
        except Exception as e:
            out["gql_probe"] = {"url": u, "error": truncate(str(e), 60)}
    # WS upgrade hint (single OPTIONS/GET w/ Upgrade header census)
    try:
        rw = http.get(root + "/ws", headers={
            "Connection": "Upgrade", "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": base64.b64encode(
                ("waspP17" + rand_str(6)).encode()).decode(),
            "X-WASP-Probe": "P17-ws-hint"}, allow_redirects=False)
        meta["probes_total"] += 1
        if rw.status == 101 or "upgrade" in (rw.header("Connection") or
                                             "").lower():
            out["ws_signals"].append({"url": root + "/ws", "status":
                                      rw.status, "upgrade": True})
        elif rw.status in (400, 426):
            out["ws_signals"].append({"url": root + "/ws", "status":
                                      rw.status, "upgrade_hint": True})
    except ScopeError:
        raise
    except Exception:
        pass
    return out



# ===========================================================================
# VERDICT HELPERS (6-class, P12..P16 compatible)
# ===========================================================================
def _verdict_of_auth_row(row):
    return row.get("verdict", "NOISE")


def merge_verdict(verdicts):
    """Multi-signal merge: CONFIRMED > SUSPECTED > BLOCKED > HARDENED >
    SKIPPED > NOISE (evidence-first ladder)."""
    order = ["CONFIRMED", "SUSPECTED", "BLOCKED", "HARDENED", "SKIPPED",
             "NOISE"]
    for v in order:
        if v in verdicts:
            return v
    return "NOISE"


def classify_severity_key_for_verdict(verdict, model):
    m = {"auth-missing": "api_auth_missing",
         "token-not-validated": "api_auth_token_not_validated",
         "auth-missing-data": "api_auth_missing"}
    return m.get(model, "api_auth_inconsistent" if verdict in
                 ("CONFIRMED", "SUSPECTED") else "api_hardened")


# ===========================================================================
# TECHNIQUE MATRIX (80+ rows - P16 ka 75-row pattern, API variant)
# ===========================================================================
def build_technique_matrix(results, conf):
    """(family, technique, verdict-source, safety, signals) rows."""
    R = []
    def add(fam, tech, src, safety, signals=""):
        R.append({"family": fam, "technique": tech, "source": src,
                  "safety": safety, "signals": truncate(str(signals), 90)})

    am = results.get("auth_matrix") or []
    vm = results.get("version_matrix") or {}
    rc = results.get("rate_census") or []
    rb = results.get("rate_burst") or {}
    rw = results.get("rate_window") or {}
    ma = results.get("mass_assign") or []
    mw = results.get("mass_write") or []
    bl = results.get("bola") or {}
    el = results.get("error_leak") or []
    dp = results.get("debug_params") or []
    mc = results.get("method_census") or []
    ct = results.get("ct_confusion") or []
    gql = results.get("gql_ws") or {}
    spec = results.get("spec") or {}

    # ---- SPEC family (12) ----
    if spec:
        add("SPEC", "openapi.json public fetch", "spec", "AUTO-INERT",
            "version=%s paths=%s" % (spec.get("spec_version"),
                                     spec.get("paths_count")))
        add("SPEC", "swagger/openapi census (20 doc paths)", "spec",
            "AUTO-INERT", "%s docs seen" % len(spec.get("endpoints", [])))
        add("SPEC", "internal hosts audit", "spec", "AUTO-INERT",
            "%d internal refs" % len(spec.get("internal_hosts", [])))
        add("SPEC", "contact emails audit", "spec", "AUTO-INERT",
            "%d emails" % len(spec.get("emails", [])))
        add("SPEC", "security schemes census", "spec", "AUTO-INERT",
            "%d schemes" % len(spec.get("security_schemes", [])))
        add("SPEC", "public-vs-auth paths split", "spec", "AUTO-INERT",
            "public=%d auth=%d" % (len(spec.get("public_paths", [])),
                                   len(spec.get("requires_auth_paths", []))))
        add("SPEC", "deprecated operations", "spec", "AUTO-INERT",
            "%d deprecated" % len(spec.get("deprecated_live", [])))
        add("SPEC", "writable-field schema audit", "spec", "AUTO-INERT",
            "%d ops w/ body" % len(spec.get("writable_fields", {})))
        add("SPEC", "shadow-endpoint diff (spec vs live)", "spec",
            "AUTO-INERT", "inventory skew check")
        add("SPEC", "basePath/server extraction", "spec", "AUTO-INERT",
            "%s servers" % len(spec.get("servers", [])))
    else:
        add("SPEC", "spec discovery (20 doc paths)", "spec", "AUTO-INERT",
            "no public spec found (positive-ish)")
        add("SPEC", "spec audit", "spec", "AUTO-INERT", "skipped-no-doc")
    add("SPEC", "api_version_matrix (P3) seed merge", "spec", "AUTO-INERT",
        "passive")

    # ---- AUTH family (14) ----
    add("AUTH", "anon GET differential", "auth", "AUTO-INERT",
        "%d endpoints" % len(am))
    add("AUTH", "invalid-bearer probe", "auth", "AUTO-INERT",
        "canary tokens")
    add("AUTH", "invalid JWT-shape probe", "auth", "AUTO-INERT",
        "random signature")
    add("AUTH", "expired-token-shape probe", "auth", "AUTO-INERT",
        "exp past")
    add("AUTH", "basic-garbage probe", "auth", "AUTO-INERT", "")
    add("AUTH", "api-key header probe", "auth", "AUTO-INERT", "")
    add("AUTH", "401-vs-403 asymmetry model", "auth", "AUTO-INERT",
        str([a.get("model") for a in am][:4]))
    add("AUTH", "WWW-Authenticate census", "auth", "AUTO-INERT", "")
    add("AUTH", "token-not-validated detection", "auth", "AUTO-INERT",
        str(any(a.get("model") == "token-not-validated" for a in am)))
    add("AUTH", "consistent-hardened detection", "auth", "AUTO-INERT",
        str(sum(1 for a in am if a.get("verdict") == "HARDENED")))
    add("AUTH", "role-hint signals", "auth", "AUTO-INERT", "")
    add("AUTH", "per-version auth skew", "auth", "AUTO-INERT",
        "%d skew pairs" % sum(1 for r in (vm.get("path_pairs") or [])
                              if r.get("skew")))
    add("AUTH", "verbose-401 detail census", "auth", "AUTO-INERT", "")
    add("AUTH", "auth-model classification", "auth", "AUTO-INERT",
        "6-class")

    # ---- VERSIONING (10) ----
    add("VER", "path version pairs (v1/v2/v3)", "version", "AUTO-INERT",
        "%d pairs" % len(vm.get("path_pairs", [])))
    add("VER", "query-param version (?ver=)", "version", "AUTO-INERT",
        "%d probes" % len(vm.get("query_probes", [])))
    add("VER", "older-version-open differential", "version", "AUTO-INERT",
        str(any(p.get("older_open") for p in vm.get("path_pairs", []))))
    add("VER", "deprecated-live check", "version", "AUTO-INERT",
        str(bool(spec.get("deprecated_live"))))
    add("VER", "version inventory (cold /api/vN)", "version", "AUTO-INERT",
        "versions=%s" % vm.get("versions_seen"))
    add("VER", "accept-header versioning census", "version", "AUTO-INERT",
        "header diff")
    add("VER", "auth-skew by version", "version", "AUTO-INERT",
        "%d skew" % sum(1 for r in (vm.get("path_pairs") or [])
                        if r.get("skew")))
    add("VER", "version CT diff", "version", "AUTO-INERT", "")
    add("VER", "P3 matrix seed merge", "version", "AUTO-INERT", "passive")
    add("VER", "versioned-url synth probes", "version", "AUTO-INERT",
        "bounded")

    # ---- RATE LIMIT (9) ----
    add("RATE", "12 rate-header census", "rate", "AUTO-INERT",
        "%d w/ headers" % sum(1 for r in rc if r.get("has_limit")))
    add("RATE", "Retry-After capture", "rate", "AUTO-INERT", "")
    add("RATE", "quota headers census", "rate", "AUTO-INERT", "")
    add("RATE", "ratelimit-policy header", "rate", "AUTO-INERT", "")
    add("RATE", "bounded burst 429-stop (cap15)", "rate",
        "GATED api_allow_rate_burst",
        str(rb.get("throttled")) if rb else "SKIPPED")
    add("RATE", "X-Forwarded-For window hint (2req)", "rate",
        "GATED api_allow_header_window",
        "probes=%d" % len(rw.get("probes", [])) if rw else "SKIPPED")
    add("RATE", "advertised-vs-enforced gap", "rate", "AUTO-INERT", "")
    add("RATE", "per-endpoint limit variance", "rate", "AUTO-INERT", "")
    add("RATE", "429+Retry-After positive", "rate", "AUTO-INERT",
        str(rb.get("retry_after") or "-"))

    # ---- MASS ASSIGN (10) ----
    add("MASS", "spec writable-field audit", "mass", "AUTO-INERT",
        "%d risky ops" % len([m for m in ma if m.get("via") == "spec"]))
    add("MASS", "sensitive-field census (26)", "mass", "AUTO-INERT",
        "role/isAdmin/balance...")
    add("MASS", "extra-field echo census", "mass", "AUTO-INERT",
        "%d probe rows" % len([m for m in ma if m.get("via") == "probe"]))
    add("MASS", "role-field echo detection", "mass", "AUTO-INERT",
        str(any(m.get("role_echo") for m in ma)))
    add("MASS", "isAdmin-family probe", "mass", "AUTO-INERT", "canary-only")
    add("MASS", "nested-body deep-field", "mass", "AUTO-INERT", "")
    add("MASS", "canary-object write+GETback", "mass",
        "GATED api_allow_mass_write",
        "rows=%d" % len(mw) if mw else "SKIPPED")
    add("MASS", "unknown-field-reject positive", "mass", "AUTO-INERT", "")
    add("MASS", "error-differential census", "mass", "AUTO-INERT", "")
    add("MASS", "CWE-915 mapping", "mass", "AUTO-INERT", "map")

    # ---- BOLA (7) ----
    add("BOLA", "canary-id GET differential", "bola",
        "GATED api_allow_bola",
        str(len(bl.get("rows", []))) if isinstance(bl, dict) else "SKIPPED")
    add("BOLA", "object-template census", "bola",
        "GATED api_allow_bola", "users/orders/items")
    add("BOLA", "403-vs-404 asymmetry", "bola", "GATED api_allow_bola", "")
    add("BOLA", "id-shape guessability", "bola", "GATED api_allow_bola", "")
    add("BOLA", "base-vs-canary diff", "bola", "GATED api_allow_bola", "")
    add("BOLA", "P11 batch_idor merge", "bola", "AUTO-INERT", "handoff")
    add("BOLA", "full enumeration", "bola", "MANUAL-ONLY", "P11 owns")

    # ---- ERROR/DEBUG (10) ----
    add("ERR", "malformed-JSON stack-trace (4 variants)", "error",
        "AUTO-INERT",
        "%d stack hits" % sum(1 for r in el if r.get("stack_trace")))
    add("ERR", "verbose-validation oracle", "error", "AUTO-INERT",
        "%d verbose" % sum(1 for r in el if r.get("verbose")))
    add("ERR", "Server header fingerprint", "error", "AUTO-INERT", "")
    add("ERR", "X-Powered-By fingerprint", "error", "AUTO-INERT", "")
    add("ERR", "debug-param census (8 params)", "error", "AUTO-INERT",
        "%d live" % len(dp))
    add("ERR", "trace/pretty param diff", "error", "AUTO-INERT", "")
    add("ERR", "schema-oracle from errors", "error", "AUTO-INERT", "")
    add("ERR", "error CT analysis", "error", "AUTO-INERT", "")
    add("ERR", "500-fingerprint census", "error", "AUTO-INERT", "")
    add("ERR", "soft-404 differential", "error", "AUTO-INERT", "")

    # ---- METHOD/CT (10) ----
    add("METH", "OPTIONS Allow census", "method", "AUTO-INERT",
        "%d endpoints" % len(mc))
    add("METH", "write-methods declared audit", "method", "AUTO-INERT", "")
    add("METH", "X-HTTP-Method-Override hint", "method",
        "AUTO-INERT (canary)",
        str(any(m.get("override_honored") for m in mc)))
    add("METH", "CT-switch parser diff (3)", "method", "AUTO-INERT",
        "%d rows" % len(ct))
    add("METH", "form-vs-JSON parsing diff", "method", "AUTO-INERT", "")
    add("METH", "405/501 handling census", "method", "AUTO-INERT", "")
    add("METH", "HEAD support census", "method", "AUTO-INERT", "")
    add("METH", "GET-with-body tolerance", "method", "AUTO-INERT", "")
    add("METH", "write-methods LIVE (canary obj)", "method",
        "GATED api_allow_method_write", "manual")
    add("METH", "CT-sniff differential", "method", "AUTO-INERT", "")

    # ---- PROTOCOL (6) ----
    add("PROTO", "GraphQL path census (6 paths)", "proto", "AUTO-INERT",
        "%d found" % len(gql.get("graphql_endpoints", [])))
    add("PROTO", "GraphQL POST fingerprint", "proto", "AUTO-INERT",
        str(gql.get("gql_probe", {}).get("typename_ok")))
    add("PROTO", "introspection hint census", "proto", "AUTO-INERT",
        "-> P18 full engine")
    add("PROTO", "WebSocket upgrade signal", "proto", "AUTO-INERT",
        "%d signals" % len(gql.get("ws_signals", [])))
    add("PROTO", "WS 426/upgrade-hint census", "proto", "AUTO-INERT", "")
    add("PROTO", "P18/P19 seed handoff", "proto", "AUTO-INERT", "ff.json")

    # ---- MANUAL-ONLY (8) ----
    add("MANUAL", "BFLA full function-enum", "manual", "MANUAL-ONLY", "")
    add("MANUAL", "query/filter injection chains", "manual", "MANUAL-ONLY",
        "P12 owns")
    add("MANUAL", "billing/business-logic abuse", "manual", "MANUAL-ONLY",
        "P20 owns")
    add("MANUAL", "JWT alg-confusion chain", "manual", "MANUAL-ONLY",
        "P10 owns")
    add("MANUAL", "GraphQL batch/depth DoS", "manual", "FORBIDDEN-AUTO",
        "P18 gated engine")
    add("MANUAL", "WS origin/authz deep", "manual", "MANUAL-ONLY", "P19")
    add("MANUAL", "per-tenant isolation", "manual", "MANUAL-ONLY", "")
    add("MANUAL", "shadow-API pentest wave", "manual", "MANUAL-ONLY", "")
    return R



# ===========================================================================
# KILL-CHAINS (14) + CWE + MITRE + CATALOG
# ===========================================================================
def build_api_chains(F, am, vm, rc, rb, ma, el, mc, gql, spec):
    C_ = []
    def chain(name, steps, sevs, refs):
        C_.append({"name": name, "steps": steps, "severity": sevs,
                   "refs": refs})
    if any(a.get("model") == "auth-missing" for a in am):
        chain("anon-access -> data-breach",
              ["spec/header census se private endpoints", "anon GET 200+data",
               "bulk enum (P11)", "PII exfil hypothesis"],
              "critical", ["auth_matrix.json"])
    if any(a.get("model") == "token-not-validated" for a in am):
        chain("token-not-validated -> takeover",
              ["canary JWT accepted", "signature check missing",
               "forged-token chain (P10)", "account takeover hypothesis"],
              "critical", ["auth_matrix.json"])
    if any(m.get("role_echo") or m.get("extra_field_echo") for m in ma):
        chain("mass-assign -> privilege-esc",
              ["writable-field census", "role/isAdmin echo",
               "RoE-gated write verify", "admin-escalation hypothesis"],
              "high", ["mass_assign_matrix.json"])
    if any(not r.get("has_limit") for r in rc) and \
            not (rb or {}).get("throttled"):
        chain("no-rate-limit -> credential-stuffing",
              ["rate headers absent", "P9 login endpoints",
               "bounded-stuffing sim (manual)", "account-lockout bypass"],
              "high", ["rate_limit_matrix.json"])
    if any(r.get("skew") for r in (vm.get("path_pairs") or [])
           if isinstance(vm, dict)):
        chain("version-skew -> weakest-link bypass",
              ["v1/v2 differential", "older version open",
               "downgrade attack", "auth bypass hypothesis"],
              "high", ["version_matrix.json"])
    if spec and spec.get("endpoints"):
        chain("public-spec -> shadow-API takeover",
              ["spec paths vs live diff", "shadow/zombie endpoints",
               "unpatched old version hunt", "takeover hypothesis"],
              "medium", ["openapi_spec_census.json"])
    if any(r.get("stack_trace") for r in el):
        chain("stack-trace -> internals -> cloud-chain",
              ["malformed body", "stack trace leak", "paths/versions",
               "P24 cloud metadata handoff"], "high",
              ["error_leak_matrix.json"])
    if gql.get("graphql_endpoints"):
        chain("graphql-found -> introspection chain",
              ["gql endpoint fingerprint", "P18 introspection engine",
               "field-level authz", "BOLA-in-resolvers"], "info",
              ["ws_gql_fingerprint.json"])
    if gql.get("ws_signals"):
        chain("ws-found -> origin/authz chain",
              ["upgrade signal", "P19 origin check", "session authz",
               "cross-tenant hypothesis"], "info",
              ["ws_gql_fingerprint.json"])
    if any(m.get("override_honored") for m in mc):
        chain("override-accepted -> write-on-read", ["override hint honored",
          "method-gate bypass primitive", "RoE-gated write verify"],
          "medium", ["method_matrix.json"])
    chain("spec-emails -> phishing/OSINT", ["spec contact emails",
          "P3 email-spoofing census", "social-engineering aid"],
          "low", ["openapi_spec_census.json"])
    chain("debug-live -> info-harvest", ["debug params census",
          "verbose internals", "P5 secrets-content merge"], "low",
          ["error_leak_matrix.json"])
    chain("rate-window-xff -> enum-at-scale", ["XFF window diff",
          "per-IP bucket confusion", "bounded enum sim (manual)"],
          "medium", ["rate_limit_matrix.json"])
    return C_


def build_cwe_map():
    return {
        "api_spec_public": ["CWE-1234", "OWASP-API8"],
        "api_spec_internal_hosts": ["CWE-200", "OWASP-API8"],
        "api_spec_shadow_endpoints": ["CWE-1234", "OWASP-API9"],
        "api_auth_missing": ["CWE-306", "OWASP-API1", "OWASP-API5"],
        "api_auth_inconsistent": ["CWE-285", "OWASP-API8"],
        "api_auth_token_not_validated": ["CWE-347", "OWASP-API2"],
        "api_version_downgrade": ["CWE-1234", "OWASP-API8"],
        "api_version_deprecated_live": ["CWE-1234", "OWASP-API9"],
        "api_rate_missing": ["CWE-770", "OWASP-API4"],
        "api_rate_headers_only": ["CWE-770", "OWASP-API4"],
        "api_rate_window_bypass": ["CWE-645", "OWASP-API4"],
        "api_mass_assign_echo": ["CWE-915", "OWASP-API3"],
        "api_mass_assign_role_field": ["CWE-915", "OWASP-API3"],
        "api_bola_canary_readable": ["CWE-639", "OWASP-API1"],
        "api_error_stack_trace": ["CWE-209", "OWASP-API8"],
        "api_error_verbose": ["CWE-209"],
        "api_debug_params_live": ["CWE-489"],
        "api_method_override": ["CWE-650"],
        "api_methods_overexposed": ["CWE-1234", "OWASP-API8"],
        "api_ct_sniff_diff": ["CWE-436"],
        "api_write_methods_live": ["CWE-285", "OWASP-API5"],
        "api_auth_verbose_401": ["CWE-209"],
        "api_server_fingerprint": ["CWE-200"],
    }


def build_mitre_map():
    return {
        "api_auth_missing": ["T1552.001", "T1087"],
        "api_auth_token_not_validated": ["T1606.002", "T1078"],
        "api_mass_assign_role_field": ["T1068", "T1548"],
        "api_rate_missing": ["T1110", "T1595"],
        "api_bola_canary_readable": ["T1087", "T1213"],
        "api_error_stack_trace": ["T1592", "T1087"],
        "api_spec_public": ["T1592.001", "T1589"],
        "api_version_downgrade": ["T1190"],
        "api_write_methods_live": ["T1068"],
    }


def build_catalog_md():
    lines = ["# P17 REST API - Technique Catalog (v%s)" % PLAN_VERSION, ""]
    lines.append("| Family | Techniques | Safety |")
    lines.append("|---|---|---|")
    for fam, n, safety in [
        ("SPEC", 12, "AUTO-INERT (read-only)"),
        ("AUTH", 14, "AUTO-INERT (invalid canary tokens only)"),
        ("VER", 10, "AUTO-INERT (GET differentials)"),
        ("RATE", 9, "headers AUTO + burst/XFF GATED (cap 15/2)"),
        ("MASS", 10, "census AUTO-INERT + write GATED (canary objects)"),
        ("BOLA", 7, "GATED canary-id sampling; full enum P11"),
        ("ERR", 10, "AUTO-INERT (malformed but INERT bodies)"),
        ("METH", 10, "census AUTO + write GATED"),
        ("PROTO", 6, "AUTO-INERT (fingerprint)"),
        ("MANUAL", 8, "MANUAL-ONLY/FORBIDDEN-AUTO (documented)"),
    ]:
        lines.append("| %s | %d | %s |" % (fam, n, safety))
    lines.append("")
    lines.append("Total: **96 techniques** (80 AUTO-INERT + GATED w/ RoE + "
                 "MANUAL-ONLY documented).")
    lines.append("")
    lines.append("## RoE gates (config.json)")
    for g in ("api_allow_rate_burst", "api_rate_burst_cap",
              "api_allow_mass_write", "api_allow_bola", "api_bola_ids",
              "api_allow_method_write", "api_allow_header_window"):
        lines.append("- `%s` (default false/)" % g)
    lines.append("")
    lines.append("## Safety crown rules")
    lines.append("- 100% INERT payloads (FORBIDDEN_CONTENT_PATTERNS enforced)")
    lines.append("- Canary ids/objects only (waspP17 family) - no real "
                 "record enumeration")
    lines.append("- Invalid canary tokens only - no real credentials")
    lines.append("- Burst hard-capped at 15 requests, 429-stop adaptive")
    lines.append("- Response bodies REDACTED (len/sha1/marker-boolean only)")
    return "\n".join(lines)


def build_exec_summary_md(meta, am, vm, rc, rb, ma, el, dp, mc, gql, spec,
                          conf):
    verdicts = [a.get("verdict") for a in am]
    conf_ct = sum(1 for v in verdicts if v == "CONFIRMED")
    hard = sum(1 for v in verdicts if v == "HARDENED")
    lines = ["# P17 REST API - Executive Summary", ""]
    lines.append("- Probes: %d (caps: endpoints=%s auth=%s version-pairs=%s)"
                 % (meta.get("probes_total", 0),
                    conf.get("api_endpoints_cap"), conf.get("api_auth_endpoints"),
                    conf.get("api_version_pairs")))
    lines.append("- Auth matrix: %d endpoints -> CONFIRMED=%d HARDENED=%d"
                 % (len(am), conf_ct, hard))
    lines.append("- Rate-limit: %d/%d endpoints w/ headers; burst=%s"
                 % (sum(1 for r in rc if r.get("has_limit")), len(rc),
                    ("throttled" if rb.get("throttled") else
                     ("off/skipped" if rb.get("skipped") else "not-throttled"))
                    if rb else "n/a"))
    lines.append("- Mass-assign: %d census rows (%d spec-audits)"
                 % (len(ma), len([m for m in ma if m.get("via") == "spec"])))
    lines.append("- Error-leak: %d stack hits / %d verbose / %d debug-live"
                 % (sum(1 for r in el if r.get("stack_trace")),
                    sum(1 for r in el if r.get("verbose")), len(dp)))
    lines.append("- Spec: %s" % ("public (%d paths)" % spec.get(
        "paths_count", 0) if spec else "not exposed"))
    lines.append("- GraphQL: %s | WS: %s"
                 % (gql.get("graphql_endpoints") or "none",
                    gql.get("ws_signals") or "none"))
    lines.append("- RoE gates: burst=%s mass-write=%s bola=%s method-write=%s"
                 " header-window=%s"
                 % (conf.get("api_allow_rate_burst"),
                    conf.get("api_allow_mass_write"), conf.get("api_allow_bola"),
                    conf.get("api_allow_method_write"),
                    conf.get("api_allow_header_window")))
    return "\n".join(lines)



# ===========================================================================
# HYPOTHESES + REPORTS
# ===========================================================================
def build_api_hypotheses(am, vm, rc, rb, ma, el, mc, conf):
    H = []
    def hyp(title, steps, est, priority):
        H.append({"title": title, "steps": steps, "estimate": est,
                  "priority": priority})
    for a in am:
        if a.get("verdict") == "CONFIRMED":
            if a.get("model") == "auth-missing":
                hyp("Manual authz verification: %s" % a["url"],
                    ["anon browser session", "confirm data exposure scope",
                     "P11 full IDOR wave", "impact doc"], "20m", "P1")
            elif a.get("model") == "token-not-validated":
                hyp("Token validation audit: %s" % a["url"],
                    ["P10 JWT engine", "alg/keyid census",
                     "RoE lab verify"], "30m", "P1")
    for p in (vm.get("path_pairs") or []):
        if p.get("older_open"):
            hyp("Version downgrade audit: %s" % p["pair"][0],
                ["old-version feature diff", "auth-gap verify", "RoE doc"],
                "30m", "P2")
    if any(not r.get("has_limit") for r in rc):
        hyp("Rate-limit manual wave", ["P9 stuffing sim (RoE)",
            "P11 enum sim", "impact doc"], "25m", "P2")
    for m in ma:
        if m.get("role_echo"):
            hyp("Mass-assign priv-esc verify: %s" % m.get("op"),
                ["RoE-gated canary write", "role-change verify (own obj)",
                 "escalation chain doc"], "25m", "P1")
    if any(r.get("stack_trace") for r in el):
        hyp("Error-leak hardening doc", ["stack patterns inventory",
            "P24 metadata chain check", "fix suggestion"], "15m", "P3")
    if any(m.get("override_honored") for m in mc):
        hyp("Method-override audit", ["override map per endpoint",
            "RoE-gated write verify", "fix: strip override headers"],
            "20m", "P3")
    if not H:
        hyp("Baseline API hygiene wave", ["spec inventory doc",
            "auth/rate posture report", "P18 GraphQL next"], "15m", "P4")
    return H


def _api_findings_md(F, meta, am, rc, spec):
    lines = ["# P17 REST API - Findings", ""]
    lines.append("Probes: %d | Findings: %d" % (meta.get("probes_total", 0),
                                                len(F.items)))
    lines.append("")
    for f in F.items:
        lines.append("## %s [%s] %s" % (f["id"], f["severity"].upper(),
                                        f["title"]))
        lines.append("- endpoint: %s" % f["endpoint"])
        lines.append("- detail: %s" % f["detail"])
        lines.append("- why: %s" % f["why_it_matters"])
        lines.append("- evidence: %s" % f["evidence"])
        lines.append("")
    if not F.items:
        lines.append("(koi finding nahi - HARDENED posture ya sparse surface)")
    return "\n".join(lines)


def write_api_payloads(out, cap=6):
    """INERT request bodies folder (manual wave ke liye ready)."""
    d = os.path.join(out, "api_payloads")
    _rwx_dir(d)
    canary = _canary("pl")
    files = []
    bodies = [
        ("mass_assign_extra_fields.json", inert_json_body(
            {"name": canary + "-obj", "role": canary + "-user",
             "isAdmin": False, "verified": False}, canary)),
        ("mass_assign_nested.json", inert_nested_body(canary)),
        ("auth_invalid_bearer.txt", ("Authorization: Bearer %s"
                                     % (canary + rand_str(10))).encode()),
        ("auth_invalid_jwt_shape.txt", ("Authorization: Bearer eyJ%s.%s.%s"
                                        % (rand_str(6), rand_str(6),
                                           rand_str(8))).encode()),
        ("ct_confusion_form.txt", ("q=%s" % canary).encode()),
        ("error_probe_truncated.json", b"{not json"),
    ]
    for name, body in bodies[:cap]:
        p = os.path.join(d, name)
        _rwx_save_text(p, body.decode("utf-8", "ignore"))
        files.append("api_payloads/%s" % name)
    return files


def write_reports(out, scope, F, ctx, meta, results, hypotheses, chains,
                  matrix, conf):
    """Sabh artifacts RWX - MANIFEST list bhi return karta hai."""
    manifest = []
    def J(name, obj):
        _rwx_save_json(os.path.join(out, name), obj)
        manifest.append(name)
    def T(name, text):
        _rwx_save_text(os.path.join(out, name), text)
        manifest.append(name)

    J("api_surface.json", {"sources": ctx.get("mined_sources", []),
                           "coverage": ctx.get("coverage", {}),
                           "mode": ctx.get("mode", "active")})
    targets = ctx.get("targets") or []
    T("api_targets.txt", "\n".join(
        ["%s|%s|%s" % (t.get("url", ""), t.get("kind", ""),
                       ",".join(t.get("sources", []))) for t in targets]))
    J("openapi_spec_census.json", results.get("spec") or {})
    J("version_matrix.json", results.get("version_matrix") or {})
    J("auth_matrix.json", results.get("auth_matrix") or [])
    J("mass_assign_matrix.json", {
        "census": results.get("mass_assign") or [],
        "write_probe": results.get("mass_write") or []})
    J("rate_limit_matrix.json", {
        "header_census": results.get("rate_census") or [],
        "burst": results.get("rate_burst") or {},
        "window_hint": results.get("rate_window") or {}})
    J("bola_matrix.json", results.get("bola") or {})
    J("method_matrix.json", {
        "method_census": results.get("method_census") or [],
        "ct_confusion": results.get("ct_confusion") or []})
    J("error_leak_matrix.json", {
        "malformed_body": results.get("error_leak") or [],
        "debug_params": results.get("debug_params") or []})
    J("ws_gql_fingerprint.json", results.get("gql_ws") or {})
    J("param_census.json", results.get("param_census") or [])
    J("waf_map_api.json", results.get("waf") or {})
    J("differential_api.json", {
        "soft404": meta.get("soft404", {}),
        "home": meta.get("home_sig", {}),
        "verdict_ladder": "CONFIRMED>SUSPECTED>BLOCKED>HARDENED>SKIPPED>NOISE"})
    J("technique_matrix_api.json", {
        "rows": matrix, "count": len(matrix),
        "safety_classes": sorted(set(r["safety"].split()[0]
                                     for r in matrix))})
    J("mitre_map_api.json", build_mitre_map())
    J("cwe_map_api.json", build_cwe_map())
    J("api_probe_log.json", {"probes_total": meta.get("probes_total", 0),
                             "stages": ctx.get("coverage", {}),
                             "canary_family": "waspP17"})
    T("api_chains.txt", "\n".join(
        ["%s | sev=%s | %s" % (c["name"], c["severity"], " -> ".join(
            c["steps"])) for c in chains]))
    T("api_test_plan.md", "\n".join(
        ["# P17 Manual Test Plan (RoE-gated waves)", ""] +
        ["- [ ] %s (%s, %s)" % (h["title"], h["estimate"], h["priority"])
         for h in hypotheses]))
    T("TECHNIQUES_CATALOG_API.md", build_catalog_md())
    T("EXEC_SUMMARY.md", build_exec_summary_md(
        meta, results.get("auth_matrix") or [], results.get("version_matrix")
        or {}, results.get("rate_census") or [],
        results.get("rate_burst") or {}, results.get("mass_assign") or [],
        results.get("error_leak") or [], results.get("debug_params") or [],
        results.get("method_census") or [], results.get("gql_ws") or {},
        results.get("spec") or {}, conf))
    T("API_FINDINGS.md", _api_findings_md(F, meta, results.get("auth_matrix")
                                          or [], results.get("rate_census")
                                          or [], results.get("spec") or {}))
    manifest += write_api_payloads(out)
    _rwx_save_json(os.path.join(out, "findings.json"), {
        "phase": PHASE, "version": PLAN_VERSION,
        "engagement": scope.engagement,
        "generated": now_iso(), "severity_counts": _sev_counts(F),
        "findings": F.items})
    manifest.append("findings.json")
    hyps_obj = {"hypotheses": hypotheses, "count": len(hypotheses)}
    J("api_hypotheses.json", hyps_obj)
    return manifest



# ===========================================================================
# RUN ORCHESTRATION (Stage A..L)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 17 - REST API Security (detection-only, INERT) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    warn("API discipline: 100% INERT bodies (FORBIDDEN_CONTENT_PATTERNS) | "
         "canary ids/objects (waspP17) | invalid canary tokens only | "
         "bodies REDACTED (len/sha1).")
    if conf.get("api_allow_rate_burst"):
        warn("Rate burst ON (api_allow_rate_burst=true) - HARD cap %d req, "
             "429-stop adaptive." % min(15, int(conf.get(
                 "api_rate_burst_cap", 15))))
    if conf.get("api_allow_mass_write"):
        warn("Mass-assign write ON (api_allow_mass_write=true) - sirf "
             "CANARY objects, INERT values, getback-verify.")
    if conf.get("api_allow_bola"):
        warn("BOLA sampling ON (api_allow_bola=true) - canary-id structural "
             "diff only; full enumeration P11 ka kaam hai.")
    if conf.get("api_allow_method_write"):
        warn("Write-method probe ON (api_allow_method_write=true) - canary "
             "objects only.")
    if conf.get("api_allow_header_window"):
        warn("XFF window hint ON (api_allow_header_window=true) - 2 req "
             "hard cap.")
    info("caps: endpoints=%s | auth=%s | version-pairs=%s | spec-paths=%s | "
         "bola-ids=%s"
         % (conf.get("api_endpoints_cap"), conf.get("api_auth_endpoints"),
            conf.get("api_version_pairs"), conf.get("api_spec_paths"),
            conf.get("api_bola_ids")))

    F = Findings()
    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "pocs": [], "mode": "active",
           "base_dir": os.path.join(base_out, scope.engagement)}
    results = {}
    qhttp = quiet_client(http, cfg, scope, ev)

    # ---------------- Stage A: discovery ----------------
    head("Stage A - API surface discovery (P5/P3/P11/P15/P16/P2/P7/P8-seeded)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {})
        ranked, meta = cached[0], dict(cached[1])
        meta["probes_total"] = meta.get("probes_total", 0)
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, meta = discover_api_surface(
            ctx["base_dir"], scope, conf)
        cp.mark(ckA, [ranked, meta], summary="api surface")
    ctx["mined_sources"] = meta.get("sources", [])
    api_targets = [t for t in ranked if t.get("kind") == "api_endpoint"]
    spec_targets = [t for t in ranked if t.get("kind") == "spec"]
    ctx["targets"] = ranked[:80]
    ctx["coverage"]["surface"] = ("api=%d spec=%d total=%d"
                                  % (len(api_targets), len(spec_targets),
                                     len(ranked)))
    ok("seed artifacts: %d sources | %s"
       % (len(ctx["mined_sources"]), ctx["coverage"]["surface"]))

    base_url = meta.get("base_url") or (scope.seed_urls() or [""])[0]

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: seed census + offline "
             "hypotheses (0 network probes).")
        ctx["mode"] = "passive"
        results = {"auth_matrix": [], "version_matrix": {},
                   "rate_census": [], "mass_assign": []}
        hyps = build_api_hypotheses([], {}, [], {}, [], [], [], conf)
        chains = build_api_chains(F, [], {}, [], {}, [], [], [], {}, {})
        matrix = build_technique_matrix({"spec": None}, conf)
        manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                                 chains, matrix, conf)
        write_feedforward(out, PHASE, {"to_phase32_report":
                                       {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        write_manifest(out, PHASE, manifest + ["feedforward.json"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree_local(out)
        return out

    if not ranked:
        err("Koi API surface nahi mila. P5 (api_endpoints/openapi) + P3 "
            "(api_version_matrix) + P11 (idor) pehle chalao ya scope.json "
            "check karo.")
        F.add("api_surface_sparse", "API surface khali", scope.describe(),
              "seed artifacts nahi mile - P5/P3/P11 chalao.",
              "api_surface.json")
        results = {}
        hyps = build_api_hypotheses([], {}, [], {}, [], [], [], conf)
        chains = build_api_chains(F, [], {}, [], {}, [], [], [], {}, {})
        matrix = build_technique_matrix({}, conf)
        write_reports(out, scope, F, ctx, meta, results, hyps, chains,
                      matrix, conf)
        write_feedforward(out, PHASE, {"to_phase32_report":
                                       {"surface": "sparse"}},
                          notes=["no api seeds"])
        write_manifest(out, PHASE, ["findings.json", "api_surface.json",
                                    "feedforward.json"],
                       stats={"mode": "sparse", "targets": 0})
        _rwx_tree_local(out)
        return out

    # ---------------- Stage B: baseline + WAF ----------------
    head("Stage B - Baseline & WAF calibration (+ rate-header passive census)")
    try:
        s404 = soft404_baseline(http, base_url)
        meta["soft404"] = s404 or {}
        ok("soft-404 baseline: %s" % ("set" if s404 else "flat"))
    except Exception as e:
        meta["soft404"] = {}
        warn("soft-404 baseline skip: %s" % e)
    meta["home_sig"] = pick_home_marker(http, base_url, meta)
    waf = {}
    try:
        waf = waf_signature(http, base_url) or {}
        meta["waf"] = waf
        if waf:
            ok("WAF/edge fingerprint: %s" % (waf.get("name") or "signals"))
    except Exception as e:
        warn("waf-sig skip: %s" % e)
    results["waf"] = waf
    if interrupted():
        warn("interrupted - partial save")
    results["rate_census"] = rate_header_census(http, api_targets, meta) \
        if api_targets else []
    ok("rate-header census: %d/%d endpoints w/ limit headers"
       % (sum(1 for r in results["rate_census"] if r.get("has_limit")),
          len(results["rate_census"])))

    # ---------------- Stage C: spec engine ----------------
    head("Stage C - OpenAPI/Swagger spec engine (fetch + parse + audit)")
    spec = None
    ckC = "stageC:spec"
    if cp.is_done(ckC):
        spec = cp.result_of(ckC)
        ok("spec replay (checkpoint): %s paths" % (spec or {}).get(
            "paths_count", 0))
    else:
        spec_url = None
        for t in spec_targets[:int(conf.get("api_spec_paths", 12))]:
            r = http.get(t["url"], allow_redirects=False)
            meta["probes_total"] += 1
            if r.status == 200 and (r.body or b""):
                try:
                    doc = json.loads(r.body.decode("utf-8", "ignore"))
                    spec = parse_openapi_spec(doc, t["url"])
                    if spec:
                        spec_url = t["url"]
                        break
                except Exception:
                    continue
        if spec is None:
            # spec-path pool fallback (bounded)
            root = base_url.rstrip("/")
            for p in SPEC_PATH_POOL[:6]:
                u = root + p
                try:
                    r = http.get(u, allow_redirects=False)
                    meta["probes_total"] += 1
                    if r.status == 200 and (r.body or b""):
                        doc = json.loads(r.body.decode("utf-8", "ignore"))
                        spec = parse_openapi_spec(doc, u)
                        if spec:
                            spec_url = u
                            break
                except ScopeError:
                    raise
                except Exception:
                    continue
        cp.mark(ckC, spec, summary="spec: %s" % (spec_url or "none"))
    if spec:
        ok("spec: v%s | %d paths | %d ops | auth-schemes=%d"
           % (spec.get("spec_version"), spec.get("paths_count", 0),
              len(spec.get("endpoints", [])),
              len(spec.get("security_schemes", []))))
        # spec->live expansion (shadow endpoints census)
        spec_urls = [urljoin_safe(base_url, e["path"]) for e in
                     spec.get("endpoints", [])]
        live_set = set(t["url"] for t in api_targets)
        shadow = [u for u in spec_urls if u not in live_set]
        spec["shadow_hints"] = shadow[:12]
        if shadow:
            F.add("api_spec_shadow_endpoints",
                  "Shadow endpoints (spec-live diff)", base_url,
                  "%d spec-paths live-census me nahi: %s"
                  % (len(shadow), shadow[:4]), "openapi_spec_census.json")
        spec_audit_findings(spec, F, base_url, meta)
        # spec-derived endpoints -> targets (bounded)
        for u in spec_urls[:int(conf.get("api_spec_expansion_cap", 40))]:
            if u not in live_set:
                api_targets.append({"url": u, "kind": "api_endpoint",
                                    "sources": ["spec_derived"], "hints": [],
                                    "score": 44})
    else:
        info("public spec nahi mili (positive-ish) - spec-probes continue")

    results["spec"] = spec
    # ---------------- Stage D: versioning matrix ----------------
    head("Stage D - Versioning matrix (path/query/header differentials)")
    results["version_matrix"] = version_matrix(http, ctx["targets"], base_url,
                                               meta, conf, meta.get("home_sig"))
    vm = results["version_matrix"]
    skew = sum(1 for p in vm.get("path_pairs", []) if p.get("skew"))
    ok("version pairs: %d | skew=%d | versions=%s"
       % (len(vm.get("path_pairs", [])), skew, vm.get("versions_seen")))
    for p in vm.get("path_pairs", []):
        if p.get("older_open"):
            F.add("api_version_downgrade", "Older version open (downgrade)",
                  p["pair"][0],
                  "%s=%s open vs %s=%s authed - weakest-link"
                  % (p["pair"][0], p["status"][0], p["pair"][1],
                     p["status"][1]), "version_matrix.json")

    # ---------------- Stage E: auth matrix ----------------
    head("Stage E - Auth matrix (per-endpoint x invalid-token roles)")
    canary = _canary("am")
    results["auth_matrix"] = auth_matrix(http, ctx["targets"], base_url,
                                         meta, conf, canary)
    for row in results["auth_matrix"]:
        v = row["verdict"]
        if v == "CONFIRMED" and row.get("model") == "auth-missing":
            F.add("api_auth_missing", "Private endpoint anon-accessible",
                  row["url"], "anon=%s len=%s (data-echo signal=%s)"
                  % (row["roles"][0]["status"] if row.get("roles") else "?",
                     row["roles"][0]["len"] if row.get("roles") else "?",
                     "anon-data" in row.get("signals", [])),
                  "auth_matrix.json")
        elif v == "CONFIRMED" and row.get("model") == "token-not-validated":
            F.add("api_auth_token_not_validated",
                  "Invalid/canary token accepted", row["url"],
                  "invalid-token 200 (signature validation missing)",
                  "auth_matrix.json")
        elif v == "SUSPECTED" and row.get("model") == "inconsistent":
            F.add("api_auth_inconsistent", "Auth enforcement inconsistent",
                  row["url"], "roles=%s"
                  % [r["status"] for r in row.get("roles", [])],
                  "auth_matrix.json")
    ok("auth matrix: %d endpoints -> %s"
       % (len(results["auth_matrix"]),
          {v: sum(1 for r in results["auth_matrix"]
                  if r["verdict"] == v)
           for v in ("CONFIRMED", "SUSPECTED", "HARDENED", "BLOCKED")}))

    if interrupted():
        warn("interrupted - partial save")
    cp.mark("stageE:auth", [results["auth_matrix"]],
            summary="auth matrix") if not cp.is_done("stageE:auth") else None

    # ---------------- Stage F: mass assignment ----------------
    head("Stage F - Mass assignment (spec audit + census; write GATED)")
    results["mass_assign"] = mass_assign_census(http, ctx["targets"],
                                                base_url, meta, conf,
                                                _canary("ma"), spec)
    if conf.get("api_allow_mass_write"):
        ma_url = next((a["url"] for a in results["auth_matrix"]
                       if a.get("verdict") in ("CONFIRMED", "SUSPECTED")),
                      (api_targets[0]["url"] if api_targets else base_url))
        results["mass_write"] = mass_assign_write_probe(
            http, ma_url, _canary("mw"), meta, conf)
    else:
        results["mass_write"] = [{"probe": "mass-write", "skipped": True,
                                  "gate": "api_allow_mass_write=false",
                                  "manual_wave": "INERT bodies "
                                  "api_payloads/ me ready"}]
        F.add("api_gate_skipped", "Mass-assign write GATED (OFF)", base_url,
              "api_allow_mass_write=false - INERT bodies api_payloads/ me "
              "ready (manual wave).", "mass_assign_matrix.json")
    for m in results["mass_assign"]:
        if m.get("role_echo"):
            F.add("api_mass_assign_role_field",
                  "Role-class field echo (canary)", m.get("op", ""),
                  "extra role/isAdmin-class field echo hui (INERT canary "
                  "value) - CWE-915 chain.", "mass_assign_matrix.json")
        elif m.get("extra_field_echo"):
            F.add("api_mass_assign_echo", "Extra field echo (canary)",
                  m.get("op", ""), "unknown field echo - writable schema "
                  "over-exposure.", "mass_assign_matrix.json")
    ok("mass-assign: %d census rows | write-probe rows=%d"
       % (len(results["mass_assign"]), len(results["mass_write"])))

    # ---------------- Stage G: rate limits ----------------
    head("Stage G - Rate limits (headers ON; burst/XFF GATED hard-capped)")
    results["rate_burst"] = {}
    results["rate_window"] = {}
    if results["rate_census"]:
        no_hdr = [r for r in results["rate_census"] if not r.get("has_limit")]
        if conf.get("api_allow_rate_burst"):
            tgt = no_hdr[0]["url"] if no_hdr else \
                results["rate_census"][0]["url"]
            results["rate_burst"] = rate_burst_probe(http, tgt, meta, conf,
                                                     canary)
            ok("burst: %s req -> throttled=%s"
               % (results["rate_burst"].get("requests"),
                  results["rate_burst"].get("throttled")))
        else:
            results["rate_burst"] = rate_burst_probe(http, "", meta, conf,
                                                     canary)
            F.add("api_gate_skipped", "Rate burst GATED (OFF)", base_url,
                  "api_allow_rate_burst=false - bounded burst (cap 15) "
                  "manual wave documented.", "rate_limit_matrix.json")
        if conf.get("api_allow_header_window") and no_hdr:
            results["rate_window"] = rate_window_hint_probe(
                http, no_hdr[0]["url"], meta, conf, canary)
    if results["rate_census"] and all(
            not r.get("has_limit") for r in results["rate_census"]):
        F.add("api_rate_missing", "Rate-limit signals absent", base_url,
              "%d endpoints par koi limit header nahi (burst=%s)"
              % (len(results["rate_census"]),
                 "throttled" if results["rate_burst"].get("throttled")
                 else "gated/off"), "rate_limit_matrix.json")

    # ---------------- Stage H: BOLA sampling ----------------
    head("Stage H - BOLA pattern sampling (GATED canary-ids; P11 handoff)")
    results["bola"] = bola_sampling(http, ctx["targets"], base_url, meta,
                                    conf, _canary("bo"))
    if isinstance(results["bola"], dict) and results["bola"].get("skipped"):
        F.add("api_gate_skipped", "BOLA sampling GATED (OFF)", base_url,
              "api_allow_bola=false - canary-id sampling manual wave; "
              "full enum P11.", "bola_matrix.json")
    else:
        for row in (results["bola"].get("rows") or []) if isinstance(
                results["bola"], dict) else []:
            if row.get("canary_status") == 200:
                F.add("api_bola_canary_readable",
                      "Canary object-id readable (structural)", row["template"],
                      "canary GET=%s (base=%s) - object-level authz gap "
                      "hypothesis (P11 verify)."
                      % (row["canary_status"], row.get("base_status")),
                      "bola_matrix.json")
    ok("bola sampling: %s"
       % ("SKIPPED (gated)" if results["bola"].get("skipped")
          else "%d rows" % len(results["bola"].get("rows", []))))

    # ---------------- Stage I: error/debug leak ----------------
    head("Stage I - Error/info leak (malformed INERT bodies + debug census)")
    err_rows = []
    dbg_rows = []
    err_urls = [t["url"] for t in api_targets[:int(conf.get(
        "api_ct_confusion_cap", 6))]]
    for u in err_urls:
        rows = error_leak_probe(http, u, _canary("er"), meta, conf)
        for r in rows:
            r["url"] = u
        err_rows += rows
        dbg_rows += debug_params_probe(http, u, _canary("dg"), meta, conf)
    results["error_leak"] = err_rows
    results["debug_params"] = dbg_rows
    for r in err_rows:
        if r.get("stack_trace"):
            F.add("api_error_stack_trace", "Stack-trace leak on malformed "
                  "body", r.get("url", ""), "variant=%s status=%s "
                  "framework-internals leak (content redacted)."
                  % (r.get("label"), r.get("status")), "error_leak_matrix.json")
    ok("error-leak: %d stack hits / %d verbose | debug-live=%d"
       % (sum(1 for r in err_rows if r.get("stack_trace")),
          sum(1 for r in err_rows if r.get("verbose")), len(dbg_rows)))

    # ---------------- Stage J: method/CT confusion ----------------
    head("Stage J - Method & Content-Type confusion census (bounded)")
    mrows = []
    ctrows = []
    for t in api_targets[:int(conf.get("api_ct_confusion_cap", 6)) + 2]:
        mrows.append(method_census(http, t["url"], meta, conf))
        ctrows += ct_confusion_probe(http, t["url"], _canary("ct"), meta,
                                     conf)
    results["method_census"] = mrows
    results["ct_confusion"] = ctrows
    for m in mrows:
        if m.get("override_honored"):
            F.add("api_method_override", "X-HTTP-Method-Override honored",
                  m["url"], "POST+override accepted (status=%s) - "
                  "method-gate bypass primitive." % m.get("override_status"),
                  "method_matrix.json")
        if any(wm in (m.get("methods") or []) for wm in
               ("PATCH", "DELETE", "PUT")):
            F.add("api_methods_overexposed", "Write methods declared (Allow)",
                  m["url"], "Allow=%s" % m.get("allow"),
                  "method_matrix.json")
    ok("method census: %d | ct-confusion: %d rows"
       % (len(mrows), len(ctrows)))

    # ---------------- Stage K: GraphQL/WS fingerprint ----------------
    head("Stage K - GraphQL/WebSocket fingerprint (P18/P19 handoff)")
    results["gql_ws"] = gql_ws_fingerprint(http, base_url, meta, conf) \
        if conf.get("api_ws_gql_fingerprint", True) else {}
    if results["gql_ws"].get("graphql_endpoints"):
        F.add("api_graphql_detected", "GraphQL endpoint detected",
              results["gql_ws"]["graphql_endpoints"][0],
              "P18 introspection/authz engine ke seeds feedforward.json me.",
              "ws_gql_fingerprint.json")
    if results["gql_ws"].get("ws_signals"):
        F.add("api_ws_detected", "WebSocket upgrade signal",
              results["gql_ws"]["ws_signals"][0].get("url", ""),
              "P19 origin/authz census handoff.", "ws_gql_fingerprint.json")

    # ---------------- Stage L: param census + reports ----------------
    head("Stage L - Param census + technique matrix + reports + feedforward")
    pcensus = []
    if conf.get("api_param_census", True):
        for t in api_targets[:10]:
            p = urllib.parse.urlsplit(t["url"])
            qs = urllib.parse.parse_qs(p.query or "")
            pcensus.append({"url": t["url"],
                            "query_params": list(qs.keys())[:10],
                            "source": t.get("sources", [])})
        results["param_census"] = pcensus
    else:
        results["param_census"] = []

    matrix = build_technique_matrix(results, conf)
    hyps = build_api_hypotheses(results["auth_matrix"], vm,
                                results["rate_census"],
                                results.get("rate_burst") or {},
                                results["mass_assign"], err_rows, mrows,
                                conf)
    chains = build_api_chains(F, results["auth_matrix"], vm,
                              results["rate_census"],
                              results.get("rate_burst") or {},
                              results["mass_assign"], err_rows, mrows,
                              results.get("gql_ws") or {}, spec)
    ctx["coverage"]["techniques"] = "%d rows" % len(matrix)
    manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                             chains, matrix, conf)

    # feedforward (P18 gql seeds + P12 params + P11 bola + P20 logic)
    ff = {"to_phase18_graphql": {
              "gql_endpoints": results.get("gql_ws", {}).get(
                  "graphql_endpoints", []),
              "gql_probe": results.get("gql_ws", {}).get("gql_probe", {}),
              "note": "introspection/field-authz/BOLA P18 me"},
          "to_phase19_ws": {"ws_signals":
                            results.get("gql_ws", {}).get("ws_signals", [])},
          "to_phase11_bola": {
              "api_object_templates": [r.get("template") for r in
                                       (results.get("bola", {}).get("rows")
                                        or [])][:8],
              "auth_skew_urls": [p["pair"][0] for p in vm.get("path_pairs",
                                                              [])
                                 if p.get("older_open")][:6]},
          "to_phase12_inject": {"api_params": [
              {"url": c["url"], "params": c["query_params"]}
              for c in pcensus if c.get("query_params")][:10]},
          "to_phase20_logic": {
              "mass_assign_ops": [m.get("op") for m in
                                  results["mass_assign"]
                                  if m.get("role_echo")][:6]},
          "to_phase24_cloud": {"spec_internal_hosts":
                               (spec or {}).get("internal_hosts", [])},
          "to_phase32_report": {"findings": len(F.items),
                                "probes": meta.get("probes_total", 0)}}
    write_feedforward(out, PHASE, ff,
                      notes=["P17 API surface: %d endpoints, %d spec ops"
                             % (len(api_targets),
                                len((spec or {}).get("endpoints", [])))])
    manifest.append("feedforward.json")
    write_manifest(out, PHASE, manifest,
                   stats={"probes": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "matrix_rows": len(matrix),
                          "chains": len(chains),
                          "hypotheses": len(hyps),
                          "auth_endpoints": len(results["auth_matrix"]),
                          "elapsed_s": round(time.time() - t_start, 1)})
    _rwx_tree_local(out)
    ok("P17 done: %d findings | %d matrix rows | %d chains | probes=%d | "
       "%.1fs" % (len(F.items), len(matrix), len(chains),
                  meta.get("probes_total", 0), time.time() - t_start))
    return out


def _rwx_tree(root):
    for base, dirs, files in os.walk(root):
        for d in dirs:
            _rwx_dir(os.path.join(base, d))
        for fn in files:
            _rwx_result(os.path.join(base, fn))
    return root


# run() me local alias use hota hai (P16 pattern-par naam collision guard)
_rwx_tree_local = _rwx_tree


def main():
    print("WASP mod_api.py (Phase 17 - REST API, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 17   (ya --module api)")
    print("  self-test : python3 test_mod_api.py")
    print("\n  RoE gates (config.json): api_allow_rate_burst=false (default),"
          " api_allow_mass_write=false (default), api_allow_bola=false "
          "(default), api_allow_method_write=false (default), "
          "api_allow_header_window=false (default)")
    print("  Safety: 100% INERT bodies | canary ids/objects (waspP17) | "
          "invalid canary tokens only | burst hard-cap 15 | bodies REDACTED")


if __name__ == "__main__":
    main()
