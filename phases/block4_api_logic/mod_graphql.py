#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_graphql.py  |  Phase 18 - GraphQL Security ULTRA++ (Introspection/
           WAF-Bypass-v2/Federation-Deep/Input-Census/Field-Authz/BOLA/Guards)
=======================================================================================
v19.0.0 FULL ULTRA PRO MAX++ (advanced upgrade - koi kami nahi). Authorized
security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se inherit
hote hain, isliye har request scope-check, rate-limit aur budget ke andar hi
jaati hai.

KYA KARTA HAI
  P17 REST API ne GraphQL/WebSocket fingerprints P18 ko handoff kiye the. P18
  poora GRAPHQL TRUST dekhta hai: "MERA GraphQL layer, schema-level trust kahan
  tak todta hai?" -> 19 stages (A..S):
    A. GQL surface discovery   - P17 ff + P6/P11/P7/P5/P8 seeds + 26-path cold pool
    B. Endpoint validation     - method-support map + engine fingerprint + IDE census
    C. Introspection engine    - full/shallow/stepwise schema census (INERT)
    D. Introspection bypass    - 14-technique bypass matrix (GET/CT/case/federation)
    E. Error-based mining      - "Did you mean" + NESTED suggestion-BFS
    F. Field-level authz       - sensitive-field x 3-role differential matrix
    G. BOLA in resolvers       - canary-id + alias-amplified structural diff (GATED)
    H. Depth/cost/batch guards - bounded deep/alias/batch probes + guard classifier
    I. SSRF/fetch surface      - URL-arg census + canary-DNS differential (P15 handoff)
    J. Injection surface       - arg-error fingerprint census (P12 handoff, INERT)
    K. Misconfig/debug census  - IDE/tracing/federation/CSRF-CT/CORS/health/subs
    N. WAF-bypass matrix v2    - 17 SECRET techniques (JSON \u005f unicode-escape,
                                 duplicate-keys smuggling, variables-carried
                                 introspection, multipart, charset-utf16, GET-
                                 body-miss, X-Original-URL misroute, HPP...)
    O. Federation/platform deep- _entities canary, X-Hasura-Role trust diff,
                                 AppSync key-lenient, ftv1 tracing, raw SDL
    P. Input-type census       - *Input/*WhereInput writable sensitive fields
                                 (mass-assignment surface, census-only)
    Q. Subscriptions deep      - ws-path census 4 paths (GATED, P19 handoff)
    R. Timing/cost oracle      - alias-count elapsed differential (GATED)
    S. Shadow schema diff      - multi-endpoint introspection diff (0 probes)
    L/M. Matrix + reports      - 150+ rows x 18 families + 19 kill-chains
                                 + CWE(42) + MITRE(16) + 35+ artifacts
  GUIDE SEEDS (AFTER_PHASES_GUIDE P18 row): "Introspection, field-level authz,
  BOLA in resolvers" <- seeds: P11 ka GraphQL BOLA engine + P6 introspection
  (read-only). Plus P17 feedforward (to_phase18_graphql: gql_endpoints+gql_probe)
  and P7 graphql_ops/graphql_endpoints mining.

VERDICT LADDER (6-class, P12..P17-compatible)
  CONFIRMED   -> multi-signal proof (anon data on sensitive field, batch array
                 accepted + N responses, introspection open + IDE exposed)
  SUSPECTED   -> partial/single signal (suggestions leak but introspection off,
                 GET-query supported, tracing on)
  HARDENED    -> defense present (introspection disabled cleanly, field 401/403,
                 depth/cost guard errors, batch rejected)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (GraphQL 'schema-trust' hai - P15/P16/P17 jitni strict discipline)
  * 100% INERT PAYLOADS: har request body FORBIDDEN_CONTENT_PATTERNS se
    guzarti hai. Koi exploit/exfil payload nahi - sirf canary queries (INERT
    markers) + invalid-token probes. Self-test me hard-asserted.
  * MUTATIONS KABHI EXECUTE NAHI HOTE: mutation authz sirf VALIDATION-stage
    probes se dekha jaata hai (deliberately-wrong argument type -> jo error
    pehle aata hai: validation ya unauthorized). Well-formed mutation = FORBIDDEN.
  * CANARY IDS: har object-id "waspP18<rnd>" family - real records KABHI
    enumerate nahi hote; sirf structural differential (200/errors-shape) dekha
    jaata hai. Kisi real user-id ko touch nahi karte.
  * BATCH/ALIAS/DEPTH PROBES: RoE-gated (gql_allow_batch / gql_allow_depth
    default OFF) - hard caps: batch <= 2 elements, aliases <= 5, nesting <= 5
    levels, 1 request each. Circular-fragment payloads sirf DOCUMENTED hote
    hain (wire par kabhi nahi jaate - DoS surface FORBIDDEN-AUTO).
  * SSRF SURFACE: canary host ".invalid" TLD (RFC 2606 - kabhi resolve nahi
    hota). Zero external egress; sirf error-text differential dekha jaata hai.
  * TOKENS: sirf INVALID markers (canary/JWT-shape-random) bhejte hain - real
    creds kabhi nahi. Auth findings 200/errors-pattern-based hain.
  * SCHEMA DUMPS: census-only storage (type/field counts + names) - poora
    schema body store NAHI hota (redaction rule).
  * WAF-BYPASS V2: unicode-escape/dup-keys/charset/BOM variants sirf PARSING-
    differential census ke liye - payload content INERT read-only
    introspection/typename hi hai (koi destructive semantic nahi).
  * allow_active=False -> PASSIVE mode: seed census + offline hypotheses only.
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
  * POST probes read_only_post=True (wasp_core LAYER-4 "pure-read POST"
    semantics - GraphQL queries modify kuch nahi karte).
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
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 18")
    sys.exit(1)

NAME = "graphql"
PHASE = "18-graphql"
PLAN_VERSION = "19.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "gql_endpoints_cap": 10,          # active validation/fingerprint endpoint cap
    "gql_cold_paths": 26,             # cold path-pool size (discovery)
    "gql_introspection_bypass": True, # bypass matrix (14 techniques, bounded)
    "gql_bypass_cap": 14,             # bypass technique cap per endpoint
    "gql_error_mining": True,         # field-suggestion mining (introspection off)
    "gql_mining_fields": 40,          # field wordlist cap for suggestions
    "gql_field_authz": True,          # sensitive-field authz matrix (invalid tok)
    "gql_authz_fields": 10,           # sensitive-field probe cap
    "gql_auth_roles": 3,              # token roles (anon/invalid-bearer/invalid-jwt)
    "gql_authz_errors": 3,            # validation-order mutation probes (INERT)
    "gql_ssrf_args": True,            # URL-arg census + canary differential
    "gql_inject_census": True,        # arg-error fingerprint census (detection-only)
    "gql_misconfig": True,            # IDE/tracing/federation/CORS/GET/health
    "gql_ide_paths": 10,              # IDE/console path cap
    "gql_max_bytes": 4096,            # request body size cap (no DoS)
    # ---- RoE GATES (default OFF - sirf authorized+lab runs me ON) ----
    "gql_allow_bola": False,          # GATE: canary-id resolver sampling diff
    "gql_bola_ids": 4,                # canary-id cap (structural only)
    "gql_allow_batch": False,         # GATE: JSON-array batching probes (cap 2)
    "gql_allow_depth": False,         # GATE: deep/alias guard probes (cap 5lvl/5al)
    "gql_allow_csrf": False,          # GATE: cross-CT query probes (text/plain)
    "gql_allow_ws": False,            # GATE: subscription upgrade hint probe
    # ---- v19 ULTRA++ tunables ----
    "gql_bypass2_cap": 17,            # WAF/parser bypass matrix v2 cap
    "gql_federation_deep": True,      # _entities/role-header/ftv1 census
    "gql_input_census": True,         # *Input writable-sensitive census
    "gql_shadow_diff": True,          # multi-endpoint schema diff (offline)
    "gql_subs_paths": 4,              # ws-path census cap (GATED allow_ws)
    "gql_timing_oracle": True,        # alias timing diff (GATED depth)
    "gql_mining_bfs": 6,              # nested suggestion-BFS request cap
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
# SEVERITY CLASSIFICATION (P12..P17 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / fingerprint ----
    "gql_endpoint_live":         ("info", 0.0, "GraphQL endpoint live mila - "
        "poora schema-level engine ab is surface par chalega (P18 core)."),
    "gql_engine_fingerprint":    ("low", 3.1, "GraphQL engine/stack fingerprint "
        "(Apollo/Hasura/AppSync/graphene...) - engine-specific CVE bypass "
        "research aid (targeting)."),
    "gql_ide_exposed":           ("medium", 5.4, "GraphiQL/Playground/Altair/"
        "Voyager console publicly accessible - dev tooling prod me exposed "
        "(CWE-489 active debug surface; interactive query firing free me)."),
    "gql_ws_signal":             ("info", 0.0, "WebSocket upgrade signal "
        "GraphQL surface par - subscription census P19 me handoff (seed "
        "done)."),
    "gql_server_health":         ("low", 3.3, "Apollo server-health endpoint "
        "exposed - infra signal (uptime probe aid, staging detect)."),
    # ---- introspection ----
    "gql_introspection_open":    ("high", 7.2, "Introspection OPEN - poora "
        "schema (types/fields/mutations/args/deprecated) attacker ko free me "
        "mil gaya (CWE-200; har authz bypass ka schema-map ban jata hai)."),
    "gql_introspection_partial": ("medium", 5.8, "Introspection partial/filter "
        "hota hai (kuch queries pass, kuch block) - inconsistent hardening, "
        "bypass primitives (CWE-693 gap)."),
    "gql_introspection_bypass":  ("critical", 8.6, "Introspection DISABLED ke "
        "baad bhi bypass technique se schema nikal gaya (GET/CT/case/"
        "federation/batch variant) - guard sirf ek path par lagta hai "
        "(CWE-693; defense-in-depth missing)."),
    "gql_federation_sdl":        ("medium", 6.2, "Apollo Federation _service "
        "SDL public hai - graph-wide types/federation topology disclosure "
        "(gateway bypass research aid)."),
    # ---- error mining ----
    "gql_field_suggestions":     ("medium", 5.6, "Validation errors me field "
        "suggestions ('Did you mean') ON hain - introspection-off ke bawajood "
        "schema enumeration possible (error-based oracle, CWE-209 family)."),
    "gql_type_suggestions":      ("low", 4.2, "Type-name suggestions errors se "
        "mile - schema-shape oracle (enumeration aid)."),
    "gql_error_verbose":         ("medium", 5.1, "Rich error disclosure "
        "(paths/resolvers/stack/versions errors me) - internals leak "
        "(CWE-209)."),
    "gql_error_stack_trace":     ("high", 7.0, "GraphQL errors me stack-trace/"
        "file-path leak - framework internals + versions expose (CWE-209)."),
    # ---- field-level authz ----
    "gql_field_authz_missing":   ("critical", 9.1, "Sensitive schema field "
        "bina kisi token ke 200+data de raha hai - field-level authorization "
        "missing (CWE-862; resolver-level check nahi hai)."),
    "gql_field_authz_inconsistent": ("high", 7.6, "Field-level authz fields "
        "me inconsistent hai (kuch 401, kuch open) - resolver-trust skew "
        "(CWE-285)."),
    "gql_field_authz_hint":      ("low", 3.9, "Field errors me authz hints "
        "(UNAUTHENTICATED/FORBIDDEN codes) - permission-model mapping aid."),
    "gql_deprecated_field_live": ("medium", 5.9, "Deprecated fields abhi bhi "
        "resolve hote hain - old-authz surface (schema hygiene gap)."),
    "gql_mutation_authz_order":  ("medium", 6.4, "Mutation validation-vs-authz "
        "error ordering differential - authz-layer bypass primitives "
        "(mutation EXECUTE nahi hua - INERT validation-order probe)."),
    # ---- BOLA in resolvers ----
    "gql_bola_canary_readable":  ("critical", 8.9, "Canary object-id resolver "
        "se 200+data mila (structural) - object-level authz resolver me "
        "missing (CWE-639; OWASP API1 GraphQL variant; P11 chain)."),
    "gql_bola_alias_amplified":  ("critical", 9.0, "Alias-multiplication se "
        "ek request me multiple canary objects ke data ek saath aaye - "
        "BOLA amplification (enumeration speed-up primitive)."),
    "gql_id_arg_live":           ("medium", 5.3, "ID-argument types live hain "
        "(user(id:...) family) - object-authz sampling targets (P11 handoff)."),
    # ---- depth/cost/batch ----
    "gql_batch_accepted":        ("high", 7.3, "JSON-array batching accepted "
        "(N queries ek request me) - rate-limit/depth-guard bypass primitive "
        "(array-of-queries abuse family; CVE-2018-11452 class)."),
    "gql_no_depth_guard":        ("high", 7.1, "Deep nesting queries bina "
        "depth/cost error ke resolve hui - resource-exhaustion surface "
        "(CWE-400/770; resolver-cost uncapped)."),
    "gql_depth_guard_present":   ("info", 0.0, "Depth/cost/complexity guard "
        "active (positive signal)."),
    "gql_alias_guard_missing":   ("medium", 5.9, "Alias-multiplication bina "
        "limit ke accepted - field-duplication abuse surface (CWE-770)."),
    "gql_apq_supported":         ("low", 3.7, "Automatic Persisted Queries "
        "supported - persisted-hash replay primitives (cache-poisoning "
        "research aid)."),
    # ---- ssrf / fetch surface ----
    "gql_ssrf_arg_surface":      ("high", 7.4, "Schema me URL-accepting args "
        "fetch behavior dikhate hain (canary DNS differential) - SSRF via "
        "GraphQL (CWE-918; P15 chain handoff)."),
    "gql_upload_scalar":         ("medium", 5.5, "Upload file-scalar/multipart "
        "args schema me - P16 upload-chain GraphQL variant handoff."),
    # ---- injection surface ----
    "gql_inject_error_sig":      ("medium", 6.1, "Argument-census errors me "
        "SQL/NoSQL/template signatures - injection-oracle surface (P12 "
        "full engine handoff; detection-only census)."),
    # ---- misconfig / csrf ----
    "gql_get_query_enabled":     ("medium", 5.7, "GET-method queries supported "
        "- CSRF/link-inclusion surface (query URL me chala jaata hai; "
        "CWE-352 aid)."),
    "gql_csrf_ct_confusion":     ("medium", 6.0, "text/plain/form-urlencoded "
        "content-type se query accept hui - CSRF-prone parser (browser "
        "simple-request family; GATED probe)."),
    "gql_cors_wildcard":         ("medium", 5.8, "Access-Control-Allow-Origin: "
        "* GraphQL par - any-origin browser-read surface (CWE-942)."),
    "gql_tracing_enabled":       ("medium", 5.0, "Apollo tracing/debug metrics "
        "response me leak - resolver timings/internals disclosure."),
    "gql_batch_disabled":        ("info", 0.0, "Batching rejected (positive "
        "posture)."),
    "gql_introspection_disabled": ("info", 0.0, "Introspection cleanly "
        "disabled (positive posture; bypass matrix verify karta hai)."),
    # ---- misc ----
    "gql_waf_detected":          ("low", 3.4, "WAF/edge fingerprint GraphQL "
        "surface par - probe-adaptation note."),
    "gql_hardened":              ("info", 0.0, "Consistent 401/403 + "
        "introspection-off + guards (positive posture)."),
    "gql_gate_skipped":          ("info", 0.0, "RoE-gated probes OFF the - "
        "INERT payloads gql_payloads/ me ready (manual wave)."),
    "gql_surface_sparse":        ("info", 0.0, "GraphQL seeds kam mile - "
        "P17 (api ff) + P6 (graphql_surface) + P11 (graphql_bola) + P7 "
        "(graphql_endpoints) pehle chalao ya scope.json check karo."),
    # ---- v19 ULTRA++: WAF-bypass-v2 / federation-deep / input-census ----
    "gql_waf_bypass_v2":         ("critical", 8.8, "WAF/edge literal-filter "
        "bypass ho gaya (unicode-escape/GET-miss/charset/multipart/misroute) "
        "- introspection guard sirf WAF-layer par hai (CWE-693; app-layer "
        "enforcement missing)."),
    "gql_parser_confusion":      ("medium", 5.2, "Duplicate-keys/charset/BOM "
        "parser-differential signals - edge-vs-app JSON interpretation gap "
        "(CWE-436; request-smuggling research aid)."),
    "gql_entities_exposed":      ("high", 7.8, "Federation _entities canary "
        "representation resolve hui - entity-resolution BOLA surface "
        "(CWE-639 graph variant; P11 handoff)."),
    "gql_role_header_trusted":   ("high", 7.9, "Role-identity header "
        "(X-Hasura-Role family) server-trusted differential - authz spoof "
        "surface (CWE-284; header-trust gap)."),
    "gql_apikey_lenient":        ("low", 3.5, "Invalid API-key differential "
        "lenient - key-validation weakness hint (CWE-287)."),
    "gql_ftv1_tracing":          ("medium", 5.0, "Federation ftv1 tracing "
        "header se resolver-trace leak (CWE-532)."),
    "gql_sdl_endpoint":          ("high", 7.5, "Raw SDL/schema endpoint "
        "public (schema.graphql/schema.json) - introspection-off ke saath "
        "bypass-class disclosure (CWE-200)."),
    "gql_input_massassign":      ("high", 7.7, "Writable sensitive input "
        "fields (isAdmin/role/owner family) schema me - mass-assignment "
        "surface (CWE-915; write probes manual)."),
    "gql_shadow_schema":         ("medium", 6.6, "Multi-endpoint schema diff "
        "- shadow/older API zyada expose kar rahi hai (CWE-1104; version-"
        "skew surface)."),
    "gql_subs_surface":          ("info", 0.0, "Subscription ws-path hints - "
        "P19 WebSocket deep handoff."),
    "gql_timing_oracle":         ("low", 3.2, "Alias-count timing "
        "differential - resolver-cost/N+1 fingerprint aid (bounded)."),
    "gql_nested_suggestions":    ("medium", 5.4, "Nested-type suggestions se "
        "deep schema reconstruction - error-oracle depth (CWE-209)."),
    # ---- MANUAL-ONLY (kabhi auto nahi) ----
    "gql_injection_manual":      ("info", 0.0, "GraphQL argument injection "
        "full chains (NoSQL/SQL/SSTI) - P12 ULTRA engine owns; MANUAL wave."),
    "gql_dos_manual":            ("info", 0.0, "Resource-exhaustion PoC "
        "(circular fragments / mega-batch) - FORBIDDEN-AUTO; RoE lab only."),
    "gql_subscription_manual":   ("info", 0.0, "Subscription authz/replay "
        "deep - P19 WebSocket phase owns it; MANUAL."),
    "gql_authz_bfla_manual":     ("info", 0.0, "Function-level (mutation) "
        "authz full enumeration - MANUAL-ONLY (canary sampling se aage "
        "nahi; mutations kabhi auto-execute nahi)."),
    "gql_cache_manual":          ("info", 0.0, "APQ/cache-poisoning chain - "
        "P22 cache phase ke saath manual wave."),
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0,
                                              "GraphQL-surface signal."))
    return sev, cvss, why


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "GQL-%03d" % (len(self.items) + 1), "key": key,
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
# CANARY SYSTEM (P12..P17 pattern): family "waspP18" - grep-able markers.
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    return "waspP18%s%s" % (tag, rand_str(8).upper())


REDACTED_NOTE = ("[WASP P18 REDACTED - response bodies sirf len/sha1/"
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


_MUT_RE = re.compile(r"^\s*mutation\b", re.I)
_MUT_FIELD_RE = re.compile(
    r"mutation\b[^{]*\{\s*(?:[A-Za-z_]\w*\s*:\s*)?([A-Za-z_][A-Za-z0-9_]*)",
    re.I)


def _assert_mutation_inert(query):
    """WELL-FORMED MUTATIONS KABHI WIRE PAR NAHI JAATE (P18 crown rule).
    Sirf waspp18-prefixed canary-field validation-order probes allowed -
    unknown field = guaranteed validation error, execution impossible by
    construction. Koi bhi real-looking mutation field = hard block."""
    if not _MUT_RE.match(query or ""):
        return True
    m = _MUT_FIELD_RE.search(query or "")
    fld = (m.group(1) if m else "")
    if not fld.lower().startswith("waspp18"):
        raise ValueError("NON-INERT mutation blocked (field '%s') - sirf "
                         "waspP18 canary-field validation-order probes "
                         "allowed (well-formed mutations kabhi nahi)" % fld)
    return True


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
    try:
        txt = b.decode("utf-8", "ignore")
    except Exception:
        txt = ""
    _assert_mutation_inert(txt)
    return True


# ===========================================================================
# GRAPHQL QUERY BUILDERS (sab INERT - canary/read-only queries only)
# ===========================================================================
def gql_json_body(query, variables=None, opname=None):
    """Standard {query, variables} JSON body (assert_inert guaranteed)."""
    obj = {"query": query}
    if variables:
        obj["variables"] = variables
    if opname:
        obj["operationName"] = opname
    body = json.dumps(obj).encode("utf-8")
    assert_inert(body, "gql_json_body")
    return body


Q_TYPENAME = "{ __typename }"

Q_QUERY_TYPE_NAME = "{ __schema { queryType { name } } }"

Q_INTROSPECTION_SHALLOW = "{ __schema { queryType { name } mutationType " \
    "{ name } subscriptionType { name } } }"

# Stepwise introspection: pehle types{nama}, phir per-type fields drill.
Q_INTROSPECTION_STEP1 = "{ __schema { types { name kind } } }"

Q_INTROSPECTION_STEP2_TMPL = "{ __type(name: \"%s\") { name kind fields " \
    "{ name type { kind name ofType { kind name ofType { kind name } } } " \
    "args { name type { kind name ofType { kind name } } } } } }"

# Full classic introspection (census-only storage - dump body store nahi hota)
FULL_INTROSPECTION_QUERY = ("query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } subscriptionType { name } "
    "types { ...FullType } directives { name description locations args "
    "{ ...InputValue } } } } fragment FullType on __Type { kind name "
    "description fields(includeDeprecated: true) { name description args "
    "{ ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } "
    "inputFields { ...InputValue } interfaces { ...TypeRef } enumValues "
    "(includeDeprecated: true) { name deprecationReason } possibleTypes "
    "{ ...TypeRef } } fragment InputValue on __InputValue { name "
    "description type { ...TypeRef } defaultValue } fragment TypeRef on "
    "__Type { kind name ofType { kind name ofType { kind name ofType "
    "{ kind name ofType { kind name ofType { kind name ofType { kind name "
    "ofType { kind name } } } } } } } }")

Q_FEDERATION_SDL = "query { _service { sdl } }"

# v19: federation entity-resolution probe (canary representation, read-only)
Q_ENTITIES = ("query WaspEnt($r:[_Any!]!){_entities(representations:$r)"
              "{__typename}}")

# v19: variables-carried introspection (WAF literal-regex miss technique)
Q_VARIABLES_INTROSPECTION = ("query WaspQ($t:String){__type(name:$t){name "
                             "kind fields { name } }}")

# v19: raw SDL/schema endpoint census paths
SDL_PATHS = ["/schema.graphql", "/graphql/schema.json", "/graphql/schema",
             "/schema.graphqls", "/graphql/schema.graphql",
             "/api/schema.json"]

# v19: subscription ws-path census (GATED; P19 handoff)
WS_PATHS = ["/graphql", "/graphql/ws", "/subscriptions", "/ws"]

Q_INTROSPECTION_ALIASED = "query { a: __schema { queryType { name } } " \
    "b: __schema { types { name } } }"

Q_INTROSPECTION_SKIP_DIRECTIVE = ("query { __schema { queryType { name } } "
                                  "@skip(if: false) }")

Q_INTROSPECTION_FRAGMENT = ("query { __schema { ...s } } fragment s on "
                            "__Schema { queryType { name } }")

Q_DEEP_TMPL = "{ %s }"  # filled with nested canary chain (<=5 levels)


def deep_query(levels=5, leaf="__typename"):
    """Bounded deep-nesting probe (levels<=5, INERT, no circular fragments).
    c0{c1{c2{...leaf}}} deterministic build - non-destructive read-only."""
    levels = max(1, min(int(levels), 5))
    if levels == 1:
        return "{ %s }" % leaf
    inner = leaf
    for i in range(levels - 1, 0, -1):
        inner = "c%d { %s }" % (i, inner)
    return "{ c0 { %s } }" % inner


def alias_query(field, count=5):
    """Alias-multiplication probe (count<=5, same field aliased - INERT)."""
    count = max(2, min(int(count), 5))
    parts = ["a%d: %s" % (i, field) for i in range(count)]
    return "{ %s }" % " ".join(parts)


def batch_body(queries, canary):
    """JSON-array batch body (elements<=2 hard cap - INERT queries only)."""
    queries = list(queries)[:2]
    arr = [{"query": q} for q in queries]
    body = json.dumps(arr).encode("utf-8")
    assert_inert(body, "batch_body")
    return body


# ---------------------------------------------------------------------------
# v19 SECRET-TECH BODY BUILDERS: unicode-escape / duplicate-keys / multipart
# / charset variants - sab INERT (content = read-only introspection/typename)
# ---------------------------------------------------------------------------
def gql_json_body_unicode(query):
    """JSON body jisme query ke underscores \\u005f escape me hain - raw
    body par WAF literal-regex MISS karta hai, JSON parser decode karke
    normal introspection dekhta hai (parser-normalization differential).
    Content read-only (INERT)."""
    esc = query.replace("_", "\\u005f")
    raw = '{"query":"%s"}' % esc
    try:
        obj = json.loads(raw)          # round-trip guard: decode == original
        assert obj.get("query") == query
    except Exception:
        raise ValueError("unicode-escape round-trip failed")
    body = raw.encode("utf-8")
    assert_inert(body, "gql_json_body_unicode")
    return body


def gql_json_body_dupkeys(q1, q2):
    """Duplicate 'query' keys - naive WAF/inspector pehli value dekhta hai,
    JSON parsers LAST key leta hai (RFC-ambiguous smuggling class).
    Content read-only (INERT)."""
    raw = '{"query":%s,"query":%s}' % (json.dumps(q1), json.dumps(q2))
    body = raw.encode("utf-8")
    assert_inert(body, "gql_json_body_dupkeys")
    return body


def multipart_query_body(query, boundary="waspP18bnd"):
    """multipart/form-data GraphQL body (graphql-multipart-request spec
    variant) - JSON-only WAF rules miss karte hain. Content read-only."""
    raw = ("--%s\r\nContent-Disposition: form-data; name=\"query\"\r\n"
           "\r\n%s\r\n--%s--\r\n" % (boundary, query, boundary)).encode()
    assert_inert(raw, "multipart_query_body")
    return raw


# ---- introspection bypass techniques (14) - sirf structural variants ----
def bypass_variants(base_url):
    """(id, desc, method, path_variant, body, headers, ct) tuples.
    Har variant 1-2 request; sab INERT; sirf PARSING-DIFFERENTIAL test."""
    v = []
    q = Q_QUERY_TYPE_NAME
    jbody = gql_json_body(q)
    v.append(("get-query", "GET ?query= (method confusion)",
              "GET", None, None, {}, None,
              {"query": q}))
    v.append(("ct-application-graphql", "POST application/graphql "
              "(raw-CT bypass)", "POST", None,
              q.encode("utf-8"), {}, "application/graphql", None))
    v.append(("ct-form-urlencoded", "POST form-urlencoded query="
              "(CT confusion)", "POST", None,
              ("query=%s" % urllib.parse.quote(q)).encode("utf-8"),
              {}, "application/x-www-form-urlencoded", None))
    v.append(("ct-text-plain", "POST text/plain JSON (simple-request "
              "bypass)", "POST", None, jbody, {}, "text/plain", None))
    v.append(("ct-charset", "POST application/json; charset=utf-8 "
              "(parser variant)", "POST", None, jbody, {},
              "application/json; charset=utf-8", None))
    v.append(("case-__Schema", "__schema case-variant (proxy normalize)",
              "POST", None, gql_json_body(
                  "{ __Schema { queryType { name } } }"), {}, None, None))
    v.append(("case-__SCHEMA", "__SCHEMA upper-variant", "POST", None,
              gql_json_body("{ __SCHEMA { queryType { name } } }"),
              {}, None, None))
    v.append(("alias-split", "alias-split introspection", "POST", None,
              gql_json_body(Q_INTROSPECTION_ALIASED), {}, None, None))
    v.append(("fragment-wrap", "fragment-wrapped introspection", "POST",
              None, gql_json_body(Q_INTROSPECTION_FRAGMENT), {}, None, None))
    v.append(("skip-directive", "@skip(if:false) directive trick", "POST",
              None, gql_json_body(Q_INTROSPECTION_SKIP_DIRECTIVE),
              {}, None, None))
    v.append(("federation-sdl", "Apollo Federation _service{sdl}", "POST",
              None, gql_json_body(Q_FEDERATION_SDL), {}, None, None))
    v.append(("batch-wrapped", "batching-wrapped introspection (1-elem "
              "array)", "POST", None,
              json.dumps([{"query": q}]).encode("utf-8"), {}, None, None))
    v.append(("path-slash", "path confusion /graphql/ (trailing slash)",
              "POST", "/", gql_json_body(q), {}, None, None))
    v.append(("path-doubleslash", "path confusion //graphql (joiner)",
              "POST", None, gql_json_body(q), {}, None, None))
    return v


# ---- v19 WAF/parser bypass techniques (17 SECRET) - structural variants ----
def bypass_variants_v2(base_url):
    """v19 SECRET matrix: (id, desc, method, path_variant, body, headers,
    ct, getq) x 17. WAF/parser-layer bypass census - har body INERT
    read-only introspection/typename. path_variant: None | 'ROOT' | suffix
    ('/.', ';.css') | '?query=...' append."""
    q = Q_QUERY_TYPE_NAME
    jbody = gql_json_body(q)
    v = []
    # 1 unicode-escape: raw body me __schema literal NAHI (\\u005f) - WAF
    #   literal-regex miss; parser normalize karke introspection de deta hai
    v.append(("json-unicode-escape", "JSON \\u005f escape of __schema "
              "(literal-WAF miss)", "POST", None,
              gql_json_body_unicode(q), {}, None, None))
    # 2 duplicate-keys: inspector pehli value, parser last value
    v.append(("json-duplicate-keys", "duplicate query keys (parser last-"
              "win smuggling)", "POST", None,
              gql_json_body_dupkeys("{ __typename }", q), {}, None, None))
    # 3 variables-carried introspection: sensitive token variable me
    vb = json.dumps({"query": Q_VARIABLES_INTROSPECTION,
                     "variables": {"t": "Query"}}).encode("utf-8")
    assert_inert(vb, "bypass2-variables")
    v.append(("variables-introspection", "type-name via variables (literal "
              "miss)", "POST", None, vb, {}, None, None))
    # 4 multipart form-data (JSON-only WAF rules miss)
    v.append(("ct-multipart-form", "multipart/form-data query field",
              "POST", None, multipart_query_body(q), {},
              "multipart/form-data; boundary=waspP18bnd", None))
    # 5 HPP: query query-string AUR body dono me
    v.append(("hpp-query-and-body", "HPP: query in query-string AND body",
              "POST", "?query=%s" % urllib.parse.quote(Q_TYPENAME),
              jbody, {}, None, None))
    # 6 minified no-space (spaced-regex WAF bypass attempt)
    v.append(("minified-query", "minified {__schema{queryType{name}}} "
              "(no-space)", "POST", None,
              gql_json_body("{__schema{queryType{name}}}"), {}, None, None))
    # 7 comment token-split
    v.append(("whitespace-comment", "# comment + newline token-split",
              "POST", None, gql_json_body("{ __schema #c\n { queryType "
                                          "{ name } } }"), {}, None, None))
    # 8 operationName mismatch (parser-behavior fingerprint)
    v.append(("opname-mismatch", "operationName mismatch fingerprint",
              "POST", None, gql_json_body(q, opname="waspP18Nope"), {},
              None, None))
    # 9 GET + variables (Apollo GET-protocol census)
    v.append(("get-json-variables", "GET ?query&variables (GET-protocol)",
              "GET", None, None, {}, None,
              {"query": Q_TYPENAME, "variables": "{}"}))
    # 10 GET introspection (POST-body-only WAF miss - classic edge gap)
    v.append(("get-query-introspection", "GET ?query=introspection "
              "(POST-only WAF miss)", "GET", None, None, {}, None,
              {"query": q}))
    # 11 charset utf-16: ASCII WAF regex garbage dekhta hai
    v.append(("charset-utf16", "UTF-16LE body (ASCII WAF regex miss)",
              "POST", None, jbody.decode("utf-8").encode("utf-16-le"), {},
              "application/json; charset=utf-16", None))
    # 12 utf-8 BOM prefix (WAF parser confusion)
    v.append(("utf8-bom", "UTF-8 BOM prefix (WAF parser confusion)",
              "POST", None, b"\xef\xbb\xbf" + jbody, {}, None, None))
    # 13 X-Original-URL edge misroute (path-scoped WAF miss)
    v.append(("header-x-original-url", "X-Original-URL edge misroute",
              "POST", "ROOT", jbody, {"X-Original-URL": "/graphql"},
              None, None))
    # 14 X-Rewrite-URL edge misroute
    v.append(("header-x-rewrite-url", "X-Rewrite-URL edge misroute",
              "POST", "ROOT", jbody, {"X-Rewrite-URL": "/graphql"},
              None, None))
    # 15 method override
    v.append(("method-override-get", "X-HTTP-Method-Override: GET",
              "POST", None, jbody, {"X-HTTP-Method-Override": "GET"},
              None, None))
    # 16 dot-segment path normalization
    v.append(("path-dot-segment", "/. dot-segment normalize confusion",
              "POST", "/.", jbody, {}, None, None))
    # 17 semicolon path-param (parser strip-after-; confusion)
    v.append(("path-semicolon", ";.css path-param confusion",
              "POST", ";.css", jbody, {}, None, None))
    return v


V2_PARSER_CONFUSION = ("json-duplicate-keys", "utf8-bom",
                       "hpp-query-and-body", "charset-utf16", "whitespace-"
                       "comment", "minified-query")


def bypass_matrix_v2(http, url, meta, conf):
    """v19 SECRET WAF/parser-bypass matrix (17 techniques, INERT).
    Returns rows: {technique, status, schema_leaked, parser_confusion}."""
    rows = []
    cap = int(conf.get("gql_bypass2_cap", 17))
    for vid, desc, method, path_variant, body, extra_h, ct, getq in \
            bypass_variants_v2(url)[:cap]:
        u = url
        if path_variant == "ROOT":
            sp = urllib.parse.urlsplit(url)
            u = "%s://%s/" % (sp.scheme, sp.netloc)
        elif path_variant:
            u = url + path_variant
        try:
            if method == "GET":
                sep = "&" if "?" in u else "?"
                r = http.get("%s%s%s" % (u, sep,
                                         urllib.parse.urlencode(getq)),
                             headers={"Accept": "application/json",
                                      "X-WASP-Probe":
                                          "P18-b2-%s" % vid},
                             allow_redirects=False)
            else:
                hdrs = {"Accept": "application/json",
                        "X-WASP-Probe": "P18-b2-%s" % vid,
                        "Content-Type": ct or "application/json"}
                hdrs.update(extra_h or {})
                r = http.post(u, data=body, headers=hdrs,
                              read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            rows.append({"technique": vid, "desc": desc, "status": 0,
                         "schema_leaked": False,
                         "error": truncate(str(e), 60)})
            continue
        text = r.text or ""
        leaked = r.status == 200 and (
            '"queryType"' in text or "__schema" in text or
            ("_service" in text and "sdl" in text) or
            ('"fields"' in text and '"name"' in text))
        rows.append({"technique": vid, "desc": desc, "status": r.status,
                     "schema_leaked": leaked,
                     "parser_confusion": vid in V2_PARSER_CONFUSION and
                     r.status == 200,
                     "waf_block": r.status == 403,
                     "len": len(r.body or b""), "sig": filesig(r.body),
                     "note": "v19 INERT structural variant"})
    return rows


# ===========================================================================
# WORDLISTS + SENSITIVE-FIELD SCORING (error-mining + authz matrix)
# ===========================================================================
MINING_FIELD_WORDLIST = [
    "me", "user", "users", "account", "accounts", "profile", "admin",
    "adminConfig", "config", "settings", "secrets", "secret", "token",
    "tokens", "apiKey", "apiKeys", "credentials", "email", "emails",
    "session", "sessions", "order", "orders", "payment", "payments",
    "invoice", "invoices", "file", "files", "upload", "uploads",
    "health", "status", "metrics", "debug", "internal", "internalNotes",
    "audit", "logs", "search", "export", "exports", "import", "webhooks",
    "notifications", "roles", "permissions", "balance", "salary",
]

SENSITIVE_FIELD_PATTERNS = [
    "admin", "internal", "secret", "password", "passwd", "token",
    "apiKey", "api_key", "credential", "email", "ssn", "salary",
    "balance", "role", "permission", "auth", "debug", "config",
    "private", "key", "hash", "otp", "mfa", "session", "invoice",
    "payment", "card", "audit", "export", "import", "webhook",
]

RESOLVER_ID_ARGS = ["id", "userId", "userID", "user_id", "accountId",
                    "account_id", "orderId", "order_id", "uuid", "guid",
                    "email", "username", "token", "slug", "key"]

URL_ARG_PATTERNS = ["url", "uri", "link", "href", "fetch", "webhook",
                    "callback", "avatar", "imageUrl", "image_url",
                    "target", "source", "import", "remote", "endpoint",
                    "fileUrl", "file_url", "download", "redirect"]

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)", r"at [a-z]+\.[A-Za-z0-9_$]+\(",
    r"File \"[^\"]+\.py\"", r"Exception in thread", r"java\.lang\.\w+",
    r"at org\.\w+", r"at java\.\w+", r"\.php on line \d+",
    r"PHP (Warning|Notice|Fatal)", r"Caused by:", r"_stack_trace",
]

VERBOSE_ERROR_PATTERNS = [
    r"(?i)cannot query field", r"(?i)did you mean", r"(?i)unknown argument",
    r"(?i)unknown (type|field|argument)", r"(?i)must be (a |an )?(type|of)",
    r"(?i)expected (type|value)", r"(?i)not a valid .*(type|field)",
]

INJECT_SIG_PATTERNS = [
    (r"(?i)(sql|sqlite|postgres|mysql|psql)[^\n]{0,40}(error|syntax|"
     r"exception)", "sql"),
    (r"(?i)MongoError|BSON|no-sql|pymongo", "nosql"),
    (r"(?i)(jinja|twig|smarty|velocity|freemarker)[^\n]{0,30}(error|"
     r"exception)", "ssti"),
    (r"(?i)GraphQLParseError|SyntaxError|syntax error", "parse"),
    (r"(?i)django\.core|graphql-(core|java|yoga)|graphene", "framework"),
]


def sensitive_score(field_name):
    """Field-name -> sensitivity score (0..N pattern hits)."""
    n = field_name or ""
    score = 0
    for p in SENSITIVE_FIELD_PATTERNS:
        if p.lower() in n.lower():
            score += 6
    if n and n[0].isupper() and any(c.isupper() for c in n[1:]):
        score += 1  # CamelCase type-ish
    return score


def parse_field_suggestions(error_text):
    """"Did you mean 'x', 'y'?" -> candidate field names (error-mining)."""
    out = []
    if not error_text:
        return out
    for m in re.finditer(r"[Dd]id you mean\s+(.+?)\s*\?", error_text):
        blob = m.group(1)
        for cand in re.findall(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", blob):
            if cand not in out:
                out.append(cand)
    return out[:12]


def parse_error_kind(text):
    """Error-text -> structure-kind (suggestion/authz/introspection-off/...)."""
    t = (text or "").lower()
    kinds = []
    if "did you mean" in t:
        kinds.append("suggestion")
    if "introspection" in t and ("not allowed" in t or "disabled" in t or
                                 "forbidden" in t or "blocked" in t):
        kinds.append("introspection-off")
    if "unauthorized" in t or "unauthenticated" in t or "forbidden" in t or \
            "access denied" in t or "not authorized" in t:
        kinds.append("authz")
    if "depth" in t or "complexity" in t or "cost" in t or \
            "too many" in t or "too deep" in t or "maximum" in t:
        kinds.append("guard")
    if "persistedquery" in t or "persisted" in t:
        kinds.append("apq")
    if "batch" in t and ("not" in t or "disable" in t or "reject" in t):
        kinds.append("batch-off")
    if "syntax" in t or "parse" in t:
        kinds.append("parse")
    return kinds


def invalid_token_pool(canary):
    """Authz-matrix tokens: SAB invalid/canary - koi real cred nahi."""
    jwt_shape = ("eyJ%s.%s.%s" % (base64.urlsafe_b64encode(
        ("waspP18hdr" + canary).encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(canary.encode()).decode().rstrip("="),
        rand_str(10)))
    return [
        ("anon", None),
        ("invalid-bearer", "Bearer %s" % (canary + rand_str(12))),
        ("invalid-jwt-shape", "Bearer " + jwt_shape),
    ]



# ===========================================================================
# ARTIFACT READER (P15..P17 tolerant pattern) - upstream seed mining
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
    """Seed source -> priority score (P16/P17 pattern)."""
    WEIGHTS = {
        "p17_to_p18_gql": 50, "p17_gql_probe": 46,
        "p6_graphql_surface": 44, "p11_graphql_bola": 42,
        "p7_gql_endpoints": 38, "p7_gql_ops": 34,
        "p5_api_endpoints": 26, "p5_endpoints": 22,
        "p8_priority": 28, "p3_api_like": 20,
        "gql_spec_derived": 40, "cold_path_pool": 16,
    }

    def __init__(self):
        self.rows = {}

    def add(self, url, source, kind="gql_endpoint", hint=None):
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
        if kind == "gql_endpoint" and row["kind"] != "gql_endpoint":
            row["kind"] = "gql_endpoint"

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
# PATH POOLS (cold discovery) + ENGINE FINGERPRINTS
# ===========================================================================
GQL_PATH_POOL = [
    "/graphql", "/api/graphql", "/graphiql", "/gql", "/query",
    "/api/gql", "/v1/graphql", "/v2/graphql", "/graphql/v1",
    "/api/v1/graphql", "/api/v2/graphql", "/graphql/batch",
    "/hasura/v1/graphql", "/appsync", "/wp-json/graphql",
    "/service/graphql", "/_graphql", "/api/graph", "/graphql/console",
    "/graphql/schema.json", "/graphql/playground", "/playground",
    "/altair", "/voyager", "/.well-known/apollo/server-health",
    "/api/v1/gql",
]

IDE_PATHS = ["/graphiql", "/playground", "/altair", "/voyager",
             "/graphql", "/graphql/console", "/graphql/playground",
             "/gql-console", "/api/graphiql", "/graphiql/"]

IDE_MARKERS = {
    "graphiql": ["graphiql", "graphiql.min", "graphiql.js", "GraphiQL"],
    "playground": ["graphql-playground", "GraphQL Playground",
                   "playground.min"],
    "altair": ["altair", "Altair GraphQL"],
    "voyager": ["voyager", "GraphQL Voyager", "graphql-voyager"],
}

ENGINE_SIGS = {
    "apollo-server": [
        (r"apollo-server", "b", 4), (r"X-Apollo-", "h", 3),
        (r'"extensions"', "b", 1), (r"graphql-playground", "b", 2),
        (r"APOLLO_", "b", 1)],
    "graphql-yoga": [(r"graphql-yoga", "b", 4), (r"yoga", "b", 2)],
    "hasura": [(r"hasura", "b", 5), (r"/v1/graphql", "d", 3),
               (r"hasuradb", "b", 3)],
    "appsync": [(r"appsync", "b", 5), (r"aws-appsync", "b", 4)],
    "graphql-java": [(r"graphql-java", "b", 4),
                     (r"com\.graphqljava", "b", 3),
                     (r"ServerError\.Exception", "b", 2)],
    "graphene": [(r"graphene-django", "b", 4), (r"graphene", "b", 2)],
    "strawberry": [(r"strawberry", "b", 3)],
    "wpgraphql": [(r"wpgraphql", "b", 5), (r"/wp-json/graphql", "d", 4)],
    "lighthouse": [(r"lighthouse-php|nuwave", "b", 4)],
    "sangria": [(r"sangria", "b", 4)],
    "shopify": [(r"shopify", "h", 2), (r"storefront-api", "b", 3)],
}

INTROSPECTION_BLOCK_MSGS = [
    "introspection is not allowed", "introspection is disabled",
    "introspection disabled", "queryintrospectionnotallowed",
    "introspectionnotallowed", "not allowed introspection",
    "forbidden.*__schema", "__schema.*forbidden",
    "introspection.*blocked", "schema introspection.*denied",
]

VERSION_HINTS = [
    (r"graphql-core ([0-9.]+)", "graphql-core"),
    (r"apollo-server[ /]?([0-9.]+)", "apollo-server"),
    (r"graphql-java ([0-9.]+)", "graphql-java"),
    (r"hasura/[v]?([0-9.]+)", "hasura"),
]



# ===========================================================================
# STAGE A - GQL SURFACE DISCOVERY (guide seeds: P11+P6 + ff P17 + P7/P5/P8)
# ===========================================================================
def discover_gql_surface(base_dir, scope, conf):
    """Seed-artifacts mining + cold path-pool. Returns (ranked_rows, meta).
    Sources: P17 feedforward (gql_endpoints+gql_probe), P6 graphql_surface
    hosts, P11 graphql_bola endpoints_live, P7 graphql_endpoints/ops,
    P5 api/endpoints, P3 api_like, P8 priority_queue, cold pool."""
    base_url = ""
    try:
        seeds = scope.seed_urls()
        base_url = seeds[0] if seeds else ""
    except Exception:
        base_url = ""
    rank = _Rank()
    sources = []
    ops = []
    meta = {"base_url": base_url, "probes_total": 0, "seed_ops": [],
            "p6_hosts": 0, "p11_endpoints": 0}

    def mine(mod, fname, source, kind="gql_endpoint", url_key=None,
             is_gql=False):
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
            for line in art.splitlines()[:120]:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                u = _norm_target(line.split()[0], base_url)
                if u:
                    rank.add(u, source, kind)
        return art

    # --- P17 feedforward: routing.to_phase18_graphql (STRONGEST seed) ---
    p17ff = _artifact(base_dir, "api", "feedforward.json")
    if isinstance(p17ff, dict):
        routing = p17ff.get("routing") or {}
        blob = routing.get("to_phase18_graphql") or {}
        if blob:
            sources.append("p17_to_p18_gql")
            for u in (blob.get("gql_endpoints") or []):
                if isinstance(u, str):
                    rank.add(_norm_target(u, base_url), "p17_to_p18_gql",
                             "gql_endpoint", hint="p17-fingerprinted")
            probe = blob.get("gql_probe") or {}
            if isinstance(probe, dict) and probe.get("url"):
                rank.add(_norm_target(probe["url"], base_url),
                         "p17_gql_probe", "gql_endpoint",
                         hint="typename_ok=%s" % probe.get("typename_ok"))
            meta["p17_probe"] = probe

    # --- P6 tech: graphql_surface.json hosts (guide seed: introspection) ---
    p6 = _artifact(base_dir, "tech", "graphql_surface.json")
    if isinstance(p6, dict):
        hosts = p6.get("hosts") or {}
        if hosts:
            sources.append("p6_graphql_surface")
            meta["p6_hosts"] = len(hosts)
            for hurl, g in (hosts.items() if isinstance(hosts, dict) else []):
                if not isinstance(g, dict):
                    continue
                for u in (g.get("endpoints") or []):
                    rank.add(_norm_target(u, base_url),
                             "p6_graphql_surface", "gql_endpoint",
                             hint="p6-verified")
                if g.get("introspection", {}).get("open"):
                    meta["p6_introspection_open"] = True

    # --- P11 access: graphql_bola.json (guide seed: BOLA engine) ---
    p11 = _artifact(base_dir, "access", "graphql_bola.json")
    if isinstance(p11, dict):
        sources.append("p11_graphql_bola")
        for u in (p11.get("endpoints_live") or []):
            rank.add(_norm_target(u, base_url), "p11_graphql_bola",
                     "gql_endpoint", hint="p11-bola-live")
        meta["p11_endpoints"] = len(p11.get("endpoints_live") or [])
        for t in (p11.get("id_arg_live") or [])[:8]:
            ops.append("id_arg:%s" % t)
        if isinstance(p11.get("bola"), dict) and p11["bola"].get("type"):
            ops.append("bola_type:%s" % p11["bola"]["type"])
    p11ff = _artifact(base_dir, "access", "feedforward.json")
    if isinstance(p11ff, dict):
        blob = (p11ff.get("routing") or {}).get("to_phase18_graphql") or {}
        if blob:
            for u in (blob.get("live_endpoints") or []):
                rank.add(_norm_target(u, base_url), "p11_graphql_bola",
                         "gql_endpoint", hint="p11-ff-live")
            ultra = blob.get("ultra") or {}
            for u in (ultra.get("introspection_bypass") or [])[:5]:
                rank.add(_norm_target(u, base_url), "p11_graphql_bola",
                         "gql_endpoint", hint="p11-bypass-seen")
            for t in (blob.get("ops") or [])[:10]:
                if t and t not in ops:
                    ops.append(str(t)[:60])

    # --- P7 js: graphql_endpoints.txt + graphql_ops.txt ---
    mine("js", "graphql_endpoints.txt", "p7_gql_endpoints")
    gops = _artifact(base_dir, "js", "graphql_ops.txt")
    if gops:
        sources.append("p7_gql_ops")
        for line in gops.splitlines()[:20]:
            line = line.strip()
            if line and line not in ops:
                ops.append(line[:60])
    p7ff = _artifact(base_dir, "js", "feedforward.json")
    if isinstance(p7ff, dict):
        blob = (p7ff.get("routing") or {}).get("to_phase18_graphql") or {}
        for k in ("ops", "endpoints"):
            if isinstance(blob.get(k), list):
                for v in blob[k][:20]:
                    if isinstance(v, str) and (v.startswith("http") or
                                               v.startswith("/")):
                        rank.add(_norm_target(v, base_url),
                                 "p7_gql_endpoints")
                    elif isinstance(v, str) and k == "ops" and \
                            v not in ops:
                        ops.append(v[:60])

    # --- P5 content + P3 passive + P8 priority (weak seeds) ---
    mine("content", "api_endpoints.txt", "p5_api_endpoints")
    mine("content", "endpoints.txt", "p5_endpoints")
    mine("passive", "api_like.txt", "p3_api_like")
    pq = _artifact(base_dir, "surface", "priority_queue.json")
    if pq:
        sources.append("p8_priority")
        for rec in _iter_records(pq):
            u = _url_from_rec(rec)
            if u and ("graph" in u.lower() or "gql" in u.lower() or
                      "query" in u.lower()):
                rank.add(_norm_target(u, base_url), "p8_priority",
                         "gql_endpoint", hint="p8-priority")

    # --- cold-start: GQL_PATH_POOL (bounded GET/POST probes run() me) ---
    for p in GQL_PATH_POOL[:int(conf.get("gql_cold_paths", 26))]:
        rank.add(urljoin_safe(base_url, p), "cold_path_pool")

    ranked = rank.ranked()
    meta["sources"] = sorted(set(sources))
    meta["seed_ops"] = ops[:24]
    return ranked, meta


def gql_spec_derive(ranked, base_url):
    """api_endpoints me graph-ish paths -> extra gql candidates (bounded)."""
    out = []
    seen = set(t["url"] for t in ranked)
    for t in ranked:
        p = urllib.parse.urlsplit(t["url"]).path.lower()
        if any(k in p for k in ("graph", "gql", "query")) and \
                t["url"] not in seen:
            out.append(t)
            seen.add(t["url"])
    return out[:6]



# ===========================================================================
# QUIET CLIENT + BASELINE (P16/P17 pattern)
# ===========================================================================
def quiet_client(http, cfg, scope, ev):
    """Evidence-off client copy (probe-log khud maintain karta hai)."""
    q = copy.copy(http)
    q.ev = None
    return q


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
# STAGE B - ENDPOINT VALIDATION + ENGINE FINGERPRINT + IDE CENSUS
# ===========================================================================
def probe_gql_endpoint(http, url, meta, conf, canary):
    """Ek candidate par method-support map + __typename INERT fingerprint.
    Returns row (validated endpoints -> findings). 0 errors-as-data."""
    row = {"url": url, "methods": {}, "fingerprint": {}, "valid": False,
           "typename_ok": False, "introspection_hint": None}
    headers = {"Accept": "application/json",
               "X-WASP-Probe": "P18-fingerprint"}

    # ---- GET census (query support? IDE marker?) ----
    try:
        rg = http.get(url, headers=headers, allow_redirects=False)
        meta["probes_total"] += 1
        row["methods"]["GET"] = rg.status
        t = rg.text or ""
        if rg.status == 200 and ("graphiql" in t.lower() or
                                 "playground" in t.lower() or
                                 "altair" in t.lower() or
                                 "voyager" in t.lower()):
            row["ide_on_endpoint"] = _ide_kind(t)
        # GET-based query probe (?query={__typename}) - method confusion
        sep = "&" if "?" in url else "?"
        rq = http.get("%s%squery=%s" % (url, sep,
                                        urllib.parse.quote(Q_TYPENAME)),
                      headers=headers, allow_redirects=False)
        meta["probes_total"] += 1
        row["methods"]["GET-query"] = rq.status
        if rq.status == 200 and "__typename" in (rq.text or ""):
            row["valid"] = True
            row["typename_ok"] = True
            row["get_query_enabled"] = True
    except ScopeError:
        raise
    except Exception as e:
        row["get_error"] = truncate(str(e), 60)

    # ---- POST json {__typename} (core fingerprint) ----
    body = gql_json_body(Q_TYPENAME)
    try:
        rp = http.post(url, data=body, headers=dict(
            headers, **{"Content-Type": "application/json"}),
            read_only_post=True, allow_redirects=False)
        meta["probes_total"] += 1
        row["methods"]["POST-json"] = rp.status
        text = rp.text or ""
        if "__typename" in text or '"data"' in text:
            row["valid"] = True
        if "__typename" in text and '"errors"' not in text:
            row["typename_ok"] = True
        # response hints -> engine fingerprint + misconfig census
        row["resp_hints"] = {
            "server": (rp.header("Server") or "")[:60],
            "powered": (rp.header("X-Powered-By") or "")[:40],
            "via": (rp.header("Via") or "")[:40],
            "extensions": '"extensions"' in text,
            "graphql_ct": "graphql" in (rp.header("Content-Type") or
                                        "").lower()}
        # rate headers census (passive)
        rl = [h for h in ("x-ratelimit-limit", "x-ratelimit-remaining",
                          "retry-after") if rp.header(h)]
        if rl:
            row["rate_headers"] = rl
        # CORS census (passive)
        acao = rp.header("Access-Control-Allow-Origin")
        if acao:
            row["cors"] = truncate(acao, 40)
        # tracing probe (passive detection: header bhejo, response census)
        if "tracing" in text.lower() or rp.header("X-Apollo-Tracing"):
            row["tracing_enabled"] = True
    except ScopeError:
        raise
    except Exception as e:
        row["post_error"] = truncate(str(e), 60)

    # ---- application/graphql CT (raw protocol support) ----
    try:
        rraw = http.post(url, data=Q_TYPENAME.encode("utf-8"), headers=dict(
            headers, **{"Content-Type": "application/graphql"}),
            read_only_post=True, allow_redirects=False)
        meta["probes_total"] += 1
        row["methods"]["POST-application/graphql"] = rraw.status
        if rraw.status == 200 and "__typename" in (rraw.text or ""):
            row["raw_ct_ok"] = True
    except ScopeError:
        raise
    except Exception as e:
        row["rawct_error"] = truncate(str(e), 60)

    # ---- tracing header probe (X-Apollo-Tracing: 1 req) ----
    try:
        rt = http.post(url, data=gql_json_body(Q_TYPENAME), headers=dict(
            headers, **{"Content-Type": "application/json",
                        "X-Apollo-Tracing": "1"}),
            read_only_post=True, allow_redirects=False)
        meta["probes_total"] += 1
        if "tracing" in (rt.text or "").lower() or \
                rt.header("X-Apollo-Tracing"):
            row["tracing_enabled"] = True
    except ScopeError:
        raise
    except Exception:
        pass

    row["introspection_hint"] = _introspection_hint(row)
    row["fingerprint"] = _engine_fingerprint(row)
    return row


def _introspection_hint(row):
    """typename response se introspection-state hint (1-word census)."""
    if row.get("typename_ok"):
        return "alive"
    if row.get("methods", {}).get("POST-json") in (400, 405, 406, 415, 422):
        return "strict"
    if row.get("methods", {}).get("GET") == 404:
        return "missing"
    return "unknown"


def _engine_fingerprint(row):
    """Row signals + response hints -> engine guesses (confidence-scored)."""
    guesses = {}
    text = json.dumps(row).lower()
    hints = row.get("resp_hints") or {}
    hint_text = " ".join(str(v) for v in hints.values()).lower()
    for eng, sigs in ENGINE_SIGS.items():
        sc = 0
        for pat, _k, w in sigs:
            if re.search(pat, text, re.I) or (hint_text and
                                              re.search(pat, hint_text,
                                                        re.I)):
                sc += w
        if sc:
            guesses[eng] = min(95, 20 + sc * 10)
    if row.get("raw_ct_ok"):
        guesses["core-spec-compliant"] = guesses.get("core-spec-compliant",
                                                     30) + 20
    if hints.get("extensions") or hints.get("graphql_ct"):
        guesses["spec-errors-shape"] = guesses.get("spec-errors-shape",
                                                   25) + 15
    if row.get("typename_ok") and row.get("methods", {}).get(
            "POST-json") == 200:
        guesses["live-gql-runtime"] = max(
            guesses.get("live-gql-runtime", 0), 40)
    return dict(sorted(guesses.items(), key=lambda kv: -kv[1])[:4])


def _ide_kind(text):
    t = (text or "").lower()
    for kind, markers in IDE_MARKERS.items():
        if any(m.lower() in t for m in markers):
            return kind
    return None


def ide_census(http, base_url, meta, conf):
    """IDE/console path census (graphiql/playground/altair/voyager)."""
    rows = []
    root = base_url.rstrip("/")
    for p in IDE_PATHS[:int(conf.get("gql_ide_paths", 10))]:
        u = root + p
        try:
            r = http.get(u, headers={"X-WASP-Probe": "P18-ide-census"},
                         allow_redirects=False)
            meta["probes_total"] += 1
            if r.status == 200 and (r.body or b""):
                kind = _ide_kind(r.text or "")
                if kind:
                    rows.append({"url": u, "kind": kind,
                                 "len": len(r.body or b""),
                                 "sig": filesig(r.body)})
        except ScopeError:
            raise
        except Exception:
            continue
    return rows


def health_probe(http, base_url, meta):
    """Apollo server-health census (1 req)."""
    u = urljoin_safe(base_url, "/.well-known/apollo/server-health")
    try:
        r = http.get(u, headers={"X-WASP-Probe": "P18-health"},
                     allow_redirects=False)
        meta["probes_total"] += 1
        if r.status == 200 and ("pass" in (r.text or "").lower() or
                                "status" in (r.text or "").lower()):
            return {"url": u, "status": r.status, "body_hint":
                    (r.text or "")[:60]}
    except ScopeError:
        raise
    except Exception:
        pass
    return None


def validate_endpoints(http, ranked, meta, conf, canary):
    """Ranked candidates -> validated gql rows (cap, dedupe)."""
    rows = []
    cap = int(conf.get("gql_endpoints_cap", 10))
    seen = set()
    for t in ranked:
        if len(rows) >= cap:
            break
        if t.get("kind") != "gql_endpoint" and \
                not any("gql" in s or "graphql" in s
                        for s in t.get("sources", [])):
            # cold/api seeds bhi validate kar sakte hain (kind any)
            pass
        u = t["url"]
        if u in seen:
            continue
        seen.add(u)
        row = probe_gql_endpoint(http, u, meta, conf, canary)
        row["sources"] = t.get("sources", [])
        row["score"] = t.get("score", 0)
        rows.append(row)
    valid = [r for r in rows if r.get("valid")]
    return rows, valid



# ===========================================================================
# STAGE C - INTROSPECTION ENGINE (full/shallow/stepwise census - INERT)
# ===========================================================================
def run_introspection(http, url, meta, conf, canary):
    """Introspection state census: shallow -> stepwise -> full (census-only).
    Returns {"state": OPEN|PARTIAL|DISABLED|BLOCKED|ERROR, "schema": census}.
    Schema dump body store NAHI hota - sirf type/field names census."""
    out = {"url": url, "state": "ERROR", "schema": None, "attempts": []}

    def _post(q, tag, headers=None, ct="application/json"):
        try:
            body = gql_json_body(q)
            r = http.post(url, data=body, headers=dict(
                {"Accept": "application/json",
                 "X-WASP-Probe": "P18-introspect-%s" % tag},
                **{"Content-Type": ct}, **(headers or {})),
                read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
            return r
        except ScopeError:
            raise
        except Exception as e:
            class _E:
                status = 0
                body = b""
                text = "introspect-error: %s" % truncate(str(e), 60)
            return _E()

    # --- 1) shallow: queryType/mutationType/subscriptionType names ---
    r = _post(Q_INTROSPECTION_SHALLOW, "shallow")
    out["attempts"].append({"step": "shallow", "status": r.status,
                            "sig": filesig(r.body)})
    text = r.text or ""
    kinds = parse_error_kind(text)
    if r.status == 200 and "__schema" in text and '"queryType"' in text:
        out["state"] = "OPEN"
    elif any(k == "introspection-off" for k in kinds) or \
            _blocked_msg(text):
        out["state"] = "DISABLED"
        out["block_msg_sample"] = truncate(text, 160)
        return out
    elif r.status in (401, 403):
        out["state"] = "BLOCKED"
        out["authz_block"] = True
        return out
    elif r.status == 0:
        return out
    else:
        out["state"] = "PARTIAL"

    # --- 2) step1: types{name kind} (bounded census) ---
    r1 = _post(Q_INTROSPECTION_STEP1, "step1")
    out["attempts"].append({"step": "step1", "status": r1.status,
                            "sig": filesig(r1.body)})
    schema = {"types": [], "query_type": None, "mutation_type": None,
              "subscription_type": None, "field_census": {},
              "arg_census": {}, "deprecated": [], "dangerous": [],
              "total_fields": 0}
    try:
        d = json.loads((r1.text or "{}"))
        tnames = [t.get("name") for t in
                  ((d.get("data") or {}).get("__schema") or {}).get(
                      "types", []) if isinstance(t, dict) and t.get("name")]
        schema["types"] = tnames[:80]
    except Exception:
        tnames = []

    # --- 3) shallow parse: query/mutation/subscription names ---
    try:
        d = json.loads(text)
        sch = (d.get("data") or {}).get("__schema") or {}
        schema["query_type"] = ((sch.get("queryType") or {}).get("name"))
        schema["mutation_type"] = ((sch.get("mutationType") or {}).get(
            "name"))
        schema["subscription_type"] = ((sch.get("subscriptionType") or
                                        {}).get("name"))
    except Exception:
        pass

    # --- 4) full introspection (bounded census-only) ---
    rf = _post(FULL_INTROSPECTION_QUERY, "full")
    out["attempts"].append({"step": "full", "status": rf.status,
                            "sig": filesig(rf.body)})
    ftext = rf.text or ""
    if rf.status == 200 and '"types"' in ftext and "__schema" in ftext:
        out["state"] = "OPEN"
        _census_from_full(ftext, schema)
    elif out["state"] == "PARTIAL" and tnames:
        # stepwise drill: top-N types (bounded) - per-type fields
        drill = [t for t in tnames if not t.startswith("__")][:6]
        for tn in drill:
            rt = _post(Q_INTROSPECTION_STEP2_TMPL % tn, "drill")
            _census_from_type(rt.text, tn, schema)
    out["schema"] = schema
    return out


def _blocked_msg(text):
    tl = (text or "").lower()
    for pat in INTROSPECTION_BLOCK_MSGS:
        if re.search(pat, tl):
            return True
    return False


def _census_from_full(text, schema):
    """Full introspection JSON -> census-only (names/counts; dump stored
    nahi). Fields/args/deprecated/dangerous census."""
    try:
        d = json.loads(text)
        types = ((d.get("data") or {}).get("__schema") or {}).get(
            "types", [])
    except Exception:
        return
    for t in types[:120]:
        if not isinstance(t, dict):
            continue
        tn = t.get("name") or ""
        if not tn or tn.startswith("__"):
            continue
        kind = t.get("kind") or ""
        fields = t.get("fields") or []
        fnames = []
        for f in fields[:60]:
            if not isinstance(f, dict):
                continue
            fn = f.get("name") or ""
            if not fn:
                continue
            fnames.append(fn)
            schema["total_fields"] += 1
            if f.get("isDeprecated"):
                schema["deprecated"].append("%s.%s" % (tn, fn))
            # args census (URL-ish + id-ish)
            for a in (f.get("args") or [])[:12]:
                if not isinstance(a, dict):
                    continue
                an = a.get("name") or ""
                if an in URL_ARG_PATTERNS:
                    schema.setdefault("url_args", []).append(
                        "%s.%s(%s)" % (tn, fn, an))
                if an in RESOLVER_ID_ARGS:
                    schema.setdefault("id_args", []).append(
                        "%s.%s(%s)" % (tn, fn, an))
                schema["arg_census"]["%s.%s" % (tn, fn)] = \
                    schema["arg_census"].get("%s.%s" % (tn, fn), 0) + 1
        schema["field_census"][tn] = fnames[:40]
        # v19: INPUT_OBJECT census (mass-assignment surface, census-only)
        if kind == "INPUT_OBJECT" or tn.endswith(("Input", "Input!")):
            ifs = [i.get("name") for i in (t.get("inputFields") or [])[:24]
                   if isinstance(i, dict) and i.get("name")]
            if ifs:
                schema.setdefault("input_types", {})[tn] = ifs
                for f2 in ifs:
                    if sensitive_score(f2):
                        schema.setdefault("writable_sensitive", []).append(
                            "%s.%s" % (tn, f2))
        # dangerous-type census (File/Upload/exec/debug families)
        if re.search(r"(?i)(upload|file|exec|shell|debug|internal|secret|"
                     r"admin)", tn):
            schema["dangerous"].append({"type": tn, "kind": kind,
                                        "fields": fnames[:12]})


def _census_from_type(text, tname, schema):
    """Stepwise per-type drill -> census (same redaction rules)."""
    try:
        d = json.loads(text)
        t = ((d.get("data") or {}).get("__type") or {})
    except Exception:
        return
    if not isinstance(t, dict):
        return
    fnames = []
    for f in (t.get("fields") or [])[:40]:
        if not isinstance(f, dict):
            continue
        fn = f.get("name") or ""
        if not fn:
            continue
        fnames.append(fn)
        schema["total_fields"] += 1
        if f.get("isDeprecated"):
            schema["deprecated"].append("%s.%s" % (tname, fn))
        for a in (f.get("args") or [])[:8]:
            an = (a.get("name") if isinstance(a, dict) else "") or ""
            if an in URL_ARG_PATTERNS:
                schema.setdefault("url_args", []).append(
                    "%s.%s(%s)" % (tname, fn, an))
            if an in RESOLVER_ID_ARGS:
                schema.setdefault("id_args", []).append(
                    "%s.%s(%s)" % (tname, fn, an))
    if fnames:
        schema["field_census"][tname] = fnames


# ===========================================================================
# STAGE D - INTROSPECTION BYPASS MATRIX (14 techniques, bounded 1-2 req each)
# ===========================================================================
def bypass_matrix(http, url, meta, conf, canary):
    """Introspection-off/partial endpoints par bypass variants (INERT).
    Returns rows: {technique, status, schema_leaked, note}."""
    rows = []
    cap = int(conf.get("gql_bypass_cap", 14))
    base_url = url
    for vid, desc, method, path_variant, body, extra_h, ct, getq in \
            bypass_variants(base_url)[:cap]:
        u = url
        if path_variant == "/" and not url.endswith("/"):
            u = url + "/"
        elif path_variant is None:
            u = url
        if path_variant == "//" or vid == "path-doubleslash":
            sp = urllib.parse.urlsplit(url)
            u = "%s://%s//%s" % (sp.scheme, sp.netloc,
                                 sp.path.lstrip("/"))
        try:
            if method == "GET":
                sep = "&" if "?" in u else "?"
                r = http.get("%s%s%s" % (u, sep,
                                         urllib.parse.urlencode(getq)),
                             headers={"Accept": "application/json",
                                      "X-WASP-Probe":
                                          "P18-bypass-%s" % vid},
                             allow_redirects=False)
            else:
                hdrs = {"Accept": "application/json",
                        "X-WASP-Probe": "P18-bypass-%s" % vid,
                        # explicit CT - urllib default form-urlencoded ko
                        # kabhi hijack nahi karna (deterministic bypass
                        # semantics; form variant apna CT khud lete hai)
                        "Content-Type": ct or "application/json"}
                hdrs.update(extra_h or {})
                r = http.post(u, data=body, headers=hdrs,
                              read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
        except ScopeError:
            raise
        except Exception as e:
            rows.append({"technique": vid, "desc": desc, "status": 0,
                         "schema_leaked": False,
                         "error": truncate(str(e), 60)})
            continue
        text = r.text or ""
        leaked = ("__schema" in text and '"queryType"' in text) or \
            ("_service" in text and "sdl" in text) or \
            ('"types"' in text and '"name"' in text and r.status == 200)
        federated = "_service" in text and "sdl" in text
        rows.append({"technique": vid, "desc": desc, "status": r.status,
                     "schema_leaked": leaked, "federation_sdl": federated,
                     "len": len(r.body or b""), "sig": filesig(r.body),
                     "note": "INERT structural variant"})
        if vid == "federation-sdl" and federated:
            # SDL census bhi capture karo (census-only)
            try:
                d = json.loads(text)
                sdl = ((d.get("data") or {}).get("_service") or {}).get(
                    "sdl") or ""
                rows[-1]["sdl_census"] = _sdl_census(sdl)
            except Exception:
                pass
    return rows


def federation_probe(http, url, meta):
    """Apollo Federation _service{sdl} probe (1 req, OPEN endpoints par bhi).
    Returns {"sdl_found": bool, "sdl_census": {...}} ya {}."""
    try:
        r = http.post(url, data=gql_json_body(Q_FEDERATION_SDL), headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-WASP-Probe": "P18-federation"}, read_only_post=True,
            allow_redirects=False)
        meta["probes_total"] += 1
        t = r.text or ""
        if "_service" in t and "sdl" in t and r.status == 200:
            sdl = ""
            try:
                d = json.loads(t)
                sdl = ((d.get("data") or {}).get("_service") or {}).get(
                    "sdl") or ""
            except Exception:
                pass
            return {"sdl_found": True, "sdl_census": _sdl_census(sdl)}
    except ScopeError:
        raise
    except Exception:
        pass
    return {}


def _sdl_census(sdl):
    """SDL text -> type/field census (names only, trunc)."""
    types = re.findall(r"type\s+([A-Za-z_][A-Za-z0-9_]*)", sdl or "")
    fields = re.findall(r"^\s{2}([A-Za-z_][A-Za-z0-9_]*)", sdl or "",
                        re.M)
    return {"types": types[:24], "fields": fields[:40],
            "bytes": len(sdl or "")}



# ===========================================================================
# STAGE E - ERROR-BASED SCHEMA MINING (field suggestions -> partial schema)
# ===========================================================================
def error_mining(http, url, meta, conf, canary):
    """"Did you mean" suggestion mining jab introspection OFF ho.
    Field wordlist + type-probing -> reconstructed partial schema census."""
    out = {"url": url, "suggestions": [], "probe_rows": [],
           "mined_fields": [], "mined_types": [], "errors_verbose": False,
           "stack_trace": False}
    if not conf.get("gql_error_mining", True):
        return out

    # --- 1) baseline error shape: probe 1 invalid field ---
    q = "{ %s%s }" % (canary[:8].lower(), rand_str(4).lower())
    r = _mine_post(http, url, q, meta, "baseline")
    text = r.text or ""
    out["errors_verbose"] = any(re.search(p, text)
                                for p in VERBOSE_ERROR_PATTERNS)
    out["stack_trace"] = any(re.search(p, text)
                             for p in STACK_TRACE_PATTERNS)
    sugg = parse_field_suggestions(text)
    for s in sugg:
        if s not in out["suggestions"]:
            out["suggestions"].append(s)
    out["probe_rows"].append({"probe": "baseline-invalid-field",
                              "status": r.status,
                              "suggestions": sugg,
                              "sig": filesig(r.body)})

    # --- 2) type-name mining: mutation root probe (validation-only, no
    #        execution - invalid mutation field = pure validation error) ---
    qm = "mutation { %s%s }" % (canary[:6].lower(), rand_str(4).lower())
    rm = _mine_post(http, url, qm, meta, "mutation-baseline")
    mtext = rm.text or ""
    msugg = parse_field_suggestions(mtext)
    for s in msugg:
        tag = "mutation:%s" % s
        if tag not in out["mined_types"]:
            out["mined_types"].append(tag)
    out["probe_rows"].append({"probe": "mutation-invalid-field",
                              "status": rm.status, "suggestions": msugg,
                              "sig": filesig(rm.body)})

    # --- 3) wordlist census: fields + suggestions oracle (bounded) ---
    word_cap = int(conf.get("gql_mining_fields", 40))
    codes = set()
    for wf in MINING_FIELD_WORDLIST[:word_cap]:
        q = "{ %s %s }" % ("__typename", wf)
        rw = _mine_post(http, url, q, meta, "word")
        t = rw.text or ""
        kinds = parse_error_kind(t)
        ws = parse_field_suggestions(t)
        for cd in re.findall(r'"code"\s*:\s*"([A-Z_]{4,30})"', t):
            codes.add(cd)
        row = {"word": wf, "status": rw.status, "kinds": kinds,
               "sig": filesig(rw.body)}
        if ws:
            row["suggestions"] = ws
            for s in ws:
                if s not in out["mined_fields"] and \
                        s not in ("__typename",):
                    out["mined_fields"].append(s)
        if rw.status == 200 and '"data"' in t and '"errors"' not in t:
            row["field_exists"] = True
            if wf not in out["mined_fields"]:
                out["mined_fields"].append(wf)
        out["probe_rows"].append(row)
        if interrupted():
            break

    # --- 4) authz-error shape census (field errors me codes?) ---
    for cd in re.findall(r'"code"\s*:\s*"([A-Z_]{4,30})"', text + mtext):
        codes.add(cd)
    out["authz_codes"] = sorted(codes)[:8]

    # --- 5) v19 NESTED suggestion-BFS: mined fields ke andar ka schema ---
    #     "{ users { bogus } }" -> "Cannot query field 'bogus' on type
    #     'User'. Did you mean...?" -> nested-type field reconstruction.
    out["mined_nested"] = []
    bfs_cap = int(conf.get("gql_mining_bfs", 6))
    bfs_reqs = 0
    for parent in out["mined_fields"][:3]:
        if bfs_reqs >= bfs_cap or interrupted():
            break
        qb = "{ %s { %s } }" % (parent, canary[:6].lower() +
                                rand_str(4).lower())
        rb = _mine_post(http, url, qb, meta, "bfs-%s" % parent)
        bfs_reqs += 1
        tb = rb.text or ""
        sb = parse_field_suggestions(tb)
        row = {"parent": parent, "status": rb.status,
               "children": sb[:8] if sb else [], "sig": filesig(rb.body)}
        out["mined_nested"].append(row)
        for s in sb[:8]:
            tag = "%s.%s" % (parent, s)
            if tag not in out["mined_fields"] and s != "__typename":
                out["mined_fields"].append(tag)
    if out["mined_nested"]:
        out["nested_depth"] = 2
        out["note"] = ("v19 suggestion-BFS: nested-type reconstruction "
                       "(error-oracle depth 2, bounded)")
    return out


def _mine_post(http, url, q, meta, tag):
    try:
        r = http.post(url, data=gql_json_body(q), headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-WASP-Probe": "P18-mine-%s" % tag},
            read_only_post=True, allow_redirects=False)
        meta["probes_total"] += 1
        return r
    except ScopeError:
        raise
    except Exception as e:
        class _E:
            status = 0
            body = b""
            text = "mine-error: %s" % truncate(str(e), 60)
        return _E()


# ===========================================================================
# STAGE F - FIELD-LEVEL AUTHORIZATION MATRIX (x 3 invalid-token roles)
# ===========================================================================
def field_authz_matrix(http, url, schema, mined_fields, meta, conf, canary):
    """Sensitive fields (schema-census + mined) x roles -> authz verdicts.
    INERT: queries read-only; mutations SIRF validation-order probes
    (well-formed mutation = FORBIDDEN - kabhi execute nahi hota)."""
    rows = []
    if not conf.get("gql_field_authz", True):
        return rows

    # --- field candidates: schema census + mining merge ---
    cands = []
    for tn, fnames in ((schema or {}).get("field_census") or {}).items():
        for fn in fnames:
            sc = sensitive_score(fn)
            if sc:
                cands.append((fn, sc, "schema:%s" % tn))
    for fn in (mined_fields or [])[:20]:
        sc = sensitive_score(fn)
        if sc:
            cands.append((fn, sc, "mined"))
    cands.sort(key=lambda x: -x[1])
    seen = set()
    cands = [c for c in cands if not (c[0] in seen or seen.add(c[0]))]
    roles = invalid_token_pool(canary)[:max(2, int(conf.get(
        "gql_auth_roles", 3)))]

    for fname, sc, via in cands[:int(conf.get("gql_authz_fields", 10))]:
        # query shape: root-type fields root-level, nested types common
        # root-list path ke through (User.email -> { users { email } })
        vtype = via.split(":", 1)[1] if ":" in via else ""
        if via.startswith("mined"):
            q = "{ %s }" % fname
        elif vtype == "Mutation":
            continue  # mutations KABHI query nahi hote (INERT discipline)
        elif vtype in ("Query", "query", "Subscription", ""):
            q = "{ %s { __typename } }" % fname
        else:
            q = "{ users { %s } }" % fname
        probe_rows = []
        for role, token in roles:
            headers = {"Content-Type": "application/json",
                       "Accept": "application/json",
                       "X-WASP-Probe": "P18-authz"}
            if token:
                headers["Authorization"] = token
            try:
                r = http.post(url, data=gql_json_body(q),
                              headers=headers, read_only_post=True,
                              allow_redirects=False)
                meta["probes_total"] += 1
            except ScopeError:
                raise
            except Exception as e:
                probe_rows.append({"role": role, "status": 0,
                                   "error": truncate(str(e), 60)})
                continue
            t = r.text or ""
            kinds = parse_error_kind(t)
            probe_rows.append({
                "role": role, "status": r.status,
                "len": len(r.body or b""),
                "has_data": '"data"' in t and '"errors"' not in t,
                "kinds": kinds,
                "canary_echo": canary in t,
                "authz_code": (re.findall(r'"code"\s*:\s*"([A-Z_]{4,30})"',
                                          t) or [None])[0]})
        verdict, model = classify_field_authz(probe_rows)
        rows.append({"field": fname, "score": sc, "via": via,
                     "verdict": verdict, "model": model,
                     "roles": probe_rows})
        if interrupted():
            break

    # --- deprecated-fields census (schema) ---
    for dep in ((schema or {}).get("deprecated") or [])[:8]:
        dfield = dep.split(".")[-1] if "." in dep else dep
        r = _mine_post(http, url, "{ %s { __typename } }" % dfield, meta,
                       "deprecated")
        t = r.text or ""
        if r.status == 200 and '"data"' in t and '"errors"' not in t:
            rows.append({"field": dfield, "score": 4,
                         "via": "deprecated-live", "verdict": "SUSPECTED",
                         "model": "deprecated-still-live",
                         "roles": [{"role": "anon", "status": r.status,
                                    "has_data": True}]})

    # --- mutation validation-order probes (INERT - kabhi execute nahi) ---
    for i in range(int(conf.get("gql_authz_errors", 3))):
        # deliberately wrong-typed mutation args -> error-order oracle
        # (canary-field prefix = guaranteed unknown -> validation-only)
        bogus = "mutation { waspp18m%s(bogusArg: 12345) { __typename } }" % \
            (rand_str(5).lower())
        r = _mine_post(http, url, bogus, meta, "mutval")
        t = r.text or ""
        kinds = parse_error_kind(t)
        rows.append({"field": "mutation-validation-%d" % (i + 1),
                     "score": 3, "via": "mutation-validation-order",
                     "verdict": "INFO",
                     "model": ("authz-first" if "authz" in kinds else
                               ("validation-first" if "parse" in kinds or
                                "Did you mean" in t else "unknown")),
                     "roles": [{"role": "anon", "status": r.status,
                                "kinds": kinds}],
                     "note": "validation-order probe; mutation NEVER "
                             "executed (INERT)"})
    return rows


def classify_field_authz(probe_rows):
    """Field-authz rows -> (verdict, model) 6-class ladder se."""
    if not probe_rows:
        return "NOISE", "no-probes"
    anon = next((r for r in probe_rows if r.get("role") == "anon"),
                probe_rows[0])
    authed = [r for r in probe_rows if r.get("role") != "anon"]
    if anon.get("has_data"):
        return "CONFIRMED", "field-authz-missing"
    if any(r.get("has_data") for r in authed):
        return "CONFIRMED", "token-not-validated-field"
    if anon.get("status") in (401, 403) or \
            any("authz" in (r.get("kinds") or []) for r in probe_rows):
        return "HARDENED", "field-authz-enforced"
    if anon.get("status") == 0:
        return "NOISE", "probe-error"
    return "SUSPECTED", "odd-pattern"



# ===========================================================================
# STAGE G - BOLA IN RESOLVERS (GATED; canary ids only, P11 handoff)
# ===========================================================================
def bola_resolver_sampling(http, url, schema, meta, conf, canary):
    """Canary-id structural differential (no real-id enumeration):
    - id-arg types schema se ya cold synth (user(id:"waspP18..."))
    - anon vs invalid-token differential (200+data = authz gap hypothesis)
    - alias-amplified canary (GATED, cap 4 aliases)
    Returns {"rows": [...], "alias": {...}} ya skipped-dict."""
    if not conf.get("gql_allow_bola"):
        return {"skipped": True, "gate": "gql_allow_bola=false",
                "manual_wave": "P11 owns enumeration; P18 sirf handoff "
                               "consumes (access/graphql_bola.json)"}
    rows = []
    # --- id-arg candidates: schema census -> synth fallback ---
    id_targets = []
    for entry in ((schema or {}).get("id_args") or [])[:8]:
        m = re.match(r"([A-Za-z_][\w]*)\.([A-Za-z_]\w*)\((\w+)\)", entry)
        if m:
            id_targets.append({"field": m.group(2), "arg": m.group(3),
                               "via": "schema:%s" % m.group(1)})
    if not id_targets:
        for f, a in (("user", "id"), ("users", "id"), ("account", "id"),
                     ("order", "id")):
            id_targets.append({"field": f, "arg": a, "via": "cold-synth"})
    roles = invalid_token_pool(canary)[:2]
    for tgt in id_targets[:int(conf.get("gql_bola_ids", 4))]:
        cid = canary + rand_str(6).upper()
        q = '{ %s(%s: "%s") { __typename } }' % (tgt["field"],
                                                 tgt["arg"], cid)
        probe_rows = []
        for role, token in roles:
            headers = {"Content-Type": "application/json",
                       "X-WASP-Probe": "P18-bola"}
            if token:
                headers["Authorization"] = token
            try:
                r = http.post(url, data=gql_json_body(q), headers=headers,
                              read_only_post=True, allow_redirects=False)
                meta["probes_total"] += 1
            except ScopeError:
                raise
            except Exception as e:
                probe_rows.append({"role": role, "status": 0,
                                   "error": truncate(str(e), 60)})
                continue
            t = r.text or ""
            probe_rows.append({
                "role": role, "status": r.status,
                "len": len(r.body or b""),
                "has_data": '"data"' in t and '"errors"' not in t,
                "canary_echo": cid in t,
                "kinds": parse_error_kind(t), "sig": filesig(r.body)})
        verdict, model = classify_field_authz(probe_rows)
        rows.append({"target": tgt, "canary": cid, "verdict": verdict,
                     "model": model, "roles": probe_rows,
                     "note": "canary-id only (INERT)"})
    # --- alias-amplified canary (4 aliases, ek hi request) ---
    alias = {}
    if rows:
        tgt = rows[0]["target"]
        cid = canary + rand_str(6).upper()
        parts = ["c%d: %s(%s: \"%s\") { __typename }"
                 % (i, tgt["field"], tgt["arg"], cid) for i in range(4)]
        q = "{ %s }" % " ".join(parts)
        try:
            r = http.post(url, data=gql_json_body(q), headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P18-bola-alias"},
                read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
            t = r.text or ""
            ndata = t.count('"__typename"')
            alias = {"aliases": 4, "status": r.status,
                     "typename_echoes": ndata,
                     "canary_echo": cid in t,
                     "amplified": ndata >= 4,
                     "note": "ek request me 4 canary objects (cap 4)"}
        except ScopeError:
            raise
        except Exception as e:
            alias = {"error": truncate(str(e), 60)}
    return {"rows": rows, "alias": alias, "canary": canary}


# ===========================================================================
# STAGE H - DEPTH/COST/COMPLEXITY + BATCHING GUARDS (GATED, hard caps)
# ===========================================================================
def guard_census(http, url, meta, conf, canary):
    """Bounded guard probes (GATED gql_allow_depth / gql_allow_batch):
    - deep nesting (5 levels) -> depth/cost error fingerprint
    - alias multiplication (5) -> alias-limit error fingerprint
    - JSON-array batch (2 elements) -> N-response differential
    - APQ (persistedQuery extensions) 1 req
    Circular fragments / mega-batch = FORBIDDEN-AUTO (documented only)."""
    out = {"deep": {}, "alias": {}, "batch": {}, "apq": {}}
    if conf.get("gql_allow_depth"):
        # --- deep nesting (5 levels, INERT) ---
        q = deep_query(5)
        try:
            r = http.post(url, data=gql_json_body(q), headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P18-depth"},
                read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
            t = r.text or ""
            kinds = parse_error_kind(t)
            guarded = any(k == "guard" for k in kinds)
            out["deep"] = {"levels": 5, "status": r.status,
                           "guard": ("depth/cost" if guarded else None),
                           "resolved": '"data"' in t and
                           '"errors"' not in t,
                           "sig": filesig(r.body)}
        except ScopeError:
            raise
        except Exception as e:
            out["deep"] = {"error": truncate(str(e), 60)}
        # --- alias multiplication (5 aliases, INERT) ---
        q = alias_query("__typename", 5)
        try:
            r = http.post(url, data=gql_json_body(q), headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P18-alias"},
                read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
            t = r.text or ""
            kinds = parse_error_kind(t)
            echoes = t.count("__typename")
            out["alias"] = {"aliases": 5, "status": r.status,
                            "echoes": echoes,
                            "guard": any(k == "guard" for k in kinds),
                            "resolved": '"data"' in t and
                            '"errors"' not in t,
                            "sig": filesig(r.body)}
        except ScopeError:
            raise
        except Exception as e:
            out["alias"] = {"error": truncate(str(e), 60)}
    else:
        out["deep"] = {"skipped": True, "gate": "gql_allow_depth=false"}
        out["alias"] = {"skipped": True, "gate": "gql_allow_depth=false"}
    # --- JSON-array batching (2 elements, GATED) ---
    if conf.get("gql_allow_batch"):
        try:
            r = http.post(url, data=batch_body(
                [Q_TYPENAME, Q_QUERY_TYPE_NAME], canary), headers={
                "Content-Type": "application/json",
                "X-WASP-Probe": "P18-batch"},
                read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
            t = r.text or ""
            is_array = t.strip().startswith("[")
            nresp = t.count('"data"') if is_array else 0
            out["batch"] = {"elements": 2, "status": r.status,
                            "array_response": is_array,
                            "responses_seen": nresp,
                            "accepted": is_array and nresp >= 2,
                            "sig": filesig(r.body)}
        except ScopeError:
            raise
        except Exception as e:
            out["batch"] = {"error": truncate(str(e), 60)}
    else:
        out["batch"] = {"skipped": True, "gate": "gql_allow_batch=false"}
    # --- APQ probe (1 req, extensions.persistedQuery) ---
    try:
        apq_body = json.dumps({
            "extensions": {"persistedQuery": {"version": 1,
                            "sha256Hash": hashlib.sha256(
                                canary.encode()).hexdigest()}}}).encode()
        assert_inert(apq_body, "apq")
        r = http.post(url, data=apq_body, headers={
            "Content-Type": "application/json",
            "X-WASP-Probe": "P18-apq"}, read_only_post=True,
            allow_redirects=False)
        meta["probes_total"] += 1
        t = r.text or ""
        out["apq"] = {"status": r.status,
                      "supported": "PersistedQueryNotFound" in t or
                      "persisted" in t.lower(),
                      "sig": filesig(r.body)}
    except ScopeError:
        raise
    except Exception as e:
        out["apq"] = {"error": truncate(str(e), 60)}
    return out


# ===========================================================================
# STAGE I - SSRF/FETCH SURFACE (P15 handoff; canary .invalid host)
# ===========================================================================
def ssrf_surface(http, url, schema, meta, conf, canary):
    """URL-arg census (schema) + canary-DNS differential (1-2 req):
    url arg me http://waspP18ssrf.invalid/x -> error-text differential
    (DNS-resolve attempt = fetch-behavior hint). Zero external egress."""
    out = {"url_args": [], "probe": {}, "upload_scalar": False}
    # --- schema census: URL-ish args ---
    for entry in ((schema or {}).get("url_args") or [])[:12]:
        out["url_args"].append(entry)
    # upload-scalar census
    blob = json.dumps(schema or {}).lower()
    if "upload" in blob or "filescalar" in blob or "multipart" in blob:
        out["upload_scalar"] = True
    # --- canary DNS differential (INERT; .invalid kabhi resolve nahi) ---
    cid = "http://%s.invalid/x" % (canary + "ssrf").lower()
    probe_fields = []
    for entry in ((schema or {}).get("url_args") or [])[:3]:
        m = re.match(r"([A-Za-z_]\w*)\.([A-Za-z_]\w*)\((\w+)\)", entry)
        if m:
            probe_fields.append((m.group(2), m.group(3)))
    if not probe_fields:
        probe_fields = [("fetchUrl", "url")]
    field, arg = probe_fields[0]
    q = '{ %s(%s: "%s") { __typename } }' % (field, arg, cid)
    try:
        r = http.post(url, data=gql_json_body(q), headers={
            "Content-Type": "application/json",
            "X-WASP-Probe": "P18-ssrf"}, read_only_post=True,
            allow_redirects=False)
        meta["probes_total"] += 1
        t = r.text or ""
        resolved_hint = bool(re.search(
            r"(?i)(could not resolve|dns|name or service not known|"
            r"getaddrinfo|enotfound|connection|timeout|unreachable)", t))
        canary_echo = canary in t
        out["probe"] = {"field": field, "arg": arg, "canary_url":
                        "[REDACTED:canary-host]", "status": r.status,
                        "dns_attempt_hint": resolved_hint,
                        "canary_echo": canary_echo,
                        "sig": filesig(r.body),
                        "note": ".invalid TLD - zero egress"}
    except ScopeError:
        raise
    except Exception as e:
        out["probe"] = {"error": truncate(str(e), 60)}
    return out


# ===========================================================================
# STAGE J - INJECTION SURFACE CENSUS (detection-only; P12 handoff)
# ===========================================================================
def inject_census(http, url, schema, meta, conf, canary):
    """Arg-error fingerprint census (INERT markers only):
    quote-in-string-arg -> error-text SQL/NoSQL/SSTI signature census.
    Sirf PATTERN census - koi injection payload nahi (P12 owns chains)."""
    out = {"probes": [], "signatures": {}, "stack_trace": False,
           "verbose": False}
    if not conf.get("gql_inject_census", True):
        return out
    # census probes: 2 malformed-ish INERT args (canary quote marker)
    probes = [
        ("quote-marker", '{ user(id: "%s") { __typename } }'
         % (canary + "sq")),
        ("brace-marker", '{ user(id: "%s") { __typename } }'
         % (canary + "br}")),
    ]
    for tag, q in probes:
        r = _mine_post(http, url, q, meta, "inj-%s" % tag)
        t = r.text or ""
        sigs = []
        for pat, name in INJECT_SIG_PATTERNS:
            if re.search(pat, t):
                sigs.append(name)
                out["signatures"][name] = \
                    out["signatures"].get(name, 0) + 1
        out["probes"].append({"tag": tag, "status": r.status,
                              "signatures": sigs,
                              "stack_trace": any(re.search(p, t)
                                                 for p in
                                                 STACK_TRACE_PATTERNS),
                              "sig": filesig(r.body)})
        if any(re.search(p, t) for p in STACK_TRACE_PATTERNS):
            out["stack_trace"] = True
        out["verbose"] = out["verbose"] or \
            any(re.search(p, t) for p in VERBOSE_ERROR_PATTERNS)
    out["note"] = "detection-only census; injection chains P12 MANUAL"
    return out


# ===========================================================================
# STAGE K - MISCONFIG / DEBUG / CSRF / SUBSCRIPTIONS CENSUS
# ===========================================================================
def misconfig_census(http, url, base_url, eprow, meta, conf, canary):
    """GET-query/CSRF-CT/CORS/tracing/IDE/health/federation/WS census.
    CSRF-CT + WS GATED (gql_allow_csrf / gql_allow_ws)."""
    out = {"get_query": bool(eprow.get("get_query_enabled")),
           "cors": eprow.get("cors"), "tracing":
               bool(eprow.get("tracing_enabled")),
           "csrf_ct": {}, "ws": {}}
    # --- CSRF cross-CT probes (GATED; read-only __typename only) ---
    if conf.get("gql_allow_csrf"):
        for ct in ("text/plain", "application/x-www-form-urlencoded"):
            try:
                if ct == "text/plain":
                    body = json.dumps({"query": Q_TYPENAME}).encode()
                else:
                    body = ("query=%s" % urllib.parse.quote(
                        Q_TYPENAME)).encode()
                assert_inert(body, "csrf-ct")
                r = http.post(url, data=body, headers={
                    "Content-Type": ct,
                    "X-WASP-Probe": "P18-csrf"}, read_only_post=True,
                    allow_redirects=False)
                meta["probes_total"] += 1
                t = r.text or ""
                out["csrf_ct"][ct] = {
                    "status": r.status,
                    "accepted": r.status == 200 and
                    '"__typename"' in t and '"errors"' not in t}
            except ScopeError:
                raise
            except Exception as e:
                out["csrf_ct"][ct] = {"error": truncate(str(e), 60)}
    else:
        out["csrf_ct"] = {"skipped": True, "gate": "gql_allow_csrf=false"}
    # --- subscription upgrade hint (GATED; P19 handoff) ---
    if conf.get("gql_allow_ws"):
        try:
            r = http.get(base_url.rstrip("/") + "/ws", headers={
                "Connection": "Upgrade", "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": base64.b64encode(
                    ("waspP18" + rand_str(6)).encode()).decode(),
                "X-WASP-Probe": "P18-ws-hint"}, allow_redirects=False)
            meta["probes_total"] += 1
            if r.status == 101 or "upgrade" in (
                    r.header("Connection") or "").lower():
                out["ws"] = {"url": base_url.rstrip("/") + "/ws",
                             "status": r.status, "upgrade": True}
            elif r.status in (400, 426):
                out["ws"] = {"url": base_url.rstrip("/") + "/ws",
                             "status": r.status, "upgrade_hint": True}
        except ScopeError:
            raise
        except Exception as e:
            out["ws"] = {"error": truncate(str(e), 60)}
    else:
        out["ws"] = {"skipped": True, "gate": "gql_allow_ws=false"}
    return out


# ===========================================================================
# STAGE O (v19) - FEDERATION / PLATFORM DEEP (_entities/role-trust/ftv1)
# ===========================================================================
def federation_deep(http, url, meta, conf, canary):
    """v19 deep census (sab INERT canary, 5 req):
    - _entities canary representation (federation entity-resolver BOLA)
    - X-Hasura-Role family trust differential (baseline vs role header)
    - AppSync-style x-api-key lenient differential
    - apollo-federation-include-trace: ftv1 tracing leak census"""
    out = {"entities": {}, "role_header": {}, "api_key": {}, "ftv1": {}}
    if not conf.get("gql_federation_deep", True):
        return out
    base_h = {"Content-Type": "application/json",
              "Accept": "application/json",
              "X-WASP-Probe": "P18-fed2"}

    def _post(extra_h, body, tag):
        try:
            r = http.post(url, data=body, headers=dict(base_h, **extra_h),
                          read_only_post=True, allow_redirects=False)
            meta["probes_total"] += 1
            return r
        except ScopeError:
            raise
        except Exception as e:
            class _E:
                status = 0
                body = b""
                text = "fed2-error: %s" % truncate(str(e), 60)
            return _E()

    # --- _entities canary representation (read-only __typename) ---
    try:
        body = json.dumps({"query": Q_ENTITIES,
                           "variables": {"r": [{"__typename": "User",
                                                "id": canary}]}}).encode()
        assert_inert(body, "entities")
        r = _post({}, body, "entities")
        t = r.text or ""
        out["entities"] = {"status": r.status,
                           "entities_resolved": '"_entities"' in t and
                           '"__typename"' in t and '"errors"' not in t,
                           "canary_echo": canary in t,
                           "sig": filesig(r.body),
                           "note": "canary representation (INERT)"}
    except ScopeError:
        raise
    except Exception as e:
        out["entities"] = {"error": truncate(str(e), 60)}

    # --- role-header trust differential (2 req: baseline vs header) ---
    try:
        r0 = _post({}, gql_json_body(Q_TYPENAME), "role-baseline")
        t0 = r0.text or ""
        rh = "waspP18" + rand_str(6).upper()
        r1 = _post({"X-Hasura-Role": rh}, gql_json_body(Q_TYPENAME),
                   "role-header")
        t1 = r1.text or ""
        out["role_header"] = {"status": r1.status,
                              "baseline": t0[:0] or filesig(r0.body),
                              "with_role": filesig(r1.body),
                              "echo_differs": ("HasuraRoleEcho" in t1) !=
                              ("HasuraRoleEcho" in t0) and r1.status == 200,
                              "trusted": "HasuraRoleEcho" in t1 and
                              "HasuraRoleEcho" not in t0,
                              "canary_role": rh}
    except ScopeError:
        raise
    except Exception as e:
        out["role_header"] = {"error": truncate(str(e), 60)}

    # --- AppSync-style x-api-key lenient differential (1 req) ---
    try:
        rk = _post({"x-api-key": canary + "invalidkey"},
                   gql_json_body(Q_TYPENAME), "apikey")
        tk = rk.text or ""
        out["api_key"] = {"status": rk.status,
                          "lenient": rk.status == 200 and
                          '"__typename"' in tk and '"errors"' not in tk,
                          "sig": filesig(rk.body)}
    except ScopeError:
        raise
    except Exception as e:
        out["api_key"] = {"error": truncate(str(e), 60)}

    # --- ftv1 tracing leak (1 req) ---
    try:
        rf = _post({"apollo-federation-include-trace": "ftv1"},
                   gql_json_body(Q_TYPENAME), "ftv1")
        tf = rf.text or ""
        out["ftv1"] = {"status": rf.status,
                       "leak": '"tracing"' in tf or "ftv1" in tf,
                       "sig": filesig(rf.body)}
    except ScopeError:
        raise
    except Exception as e:
        out["ftv1"] = {"error": truncate(str(e), 60)}
    return out


def sdl_endpoint_census(http, base_url, meta):
    """v19 raw SDL/schema endpoint census (6 GET) - introspection-off
    endpoints ke liye bypass-class disclosure check."""
    rows = []
    root = base_url.rstrip("/")
    for p in SDL_PATHS:
        u = root + p
        try:
            r = http.get(u, headers={"X-WASP-Probe": "P18-sdl"},
                         allow_redirects=False)
            meta["probes_total"] += 1
            t = r.text or ""
            if r.status == 200 and ("type " in t or '"__schema"' in t):
                rows.append({"url": u, "status": r.status,
                             "kind": ("sdl" if "type " in t
                                      else "schema-json"),
                             "bytes": len(r.body or b""),
                             "census": _sdl_census(t),
                             "sig": filesig(r.body)})
        except ScopeError:
            raise
        except Exception:
            continue
    return rows


def input_type_census(schema, conf):
    """v19 *Input type census (census-only, kabhi execute nahi):
    writable sensitive fields (isAdmin/role/owner family) -> mass-
    assignment surface map; Prisma-style WhereInput census."""
    it = (schema or {}).get("input_types") or {}
    out = {"input_types": sorted(it.keys())[:12],
           "input_fields": {k: v[:12] for k, v in list(it.items())[:8]},
           "writable_sensitive": (schema or {}).get(
               "writable_sensitive", [])[:12],
           "where_inputs": [t for t in it
                            if t.endswith(("WhereInput",
                                           "WhereUniqueInput"))][:8],
           "note": "census-only; write probes manual (P20 logic wave)"}
    return out


# ===========================================================================
# STAGE Q/R/S (v19) - SUBS DEEP + TIMING ORACLE + SHADOW SCHEMA DIFF
# ===========================================================================
def subs_deep(http, base_url, meta, conf):
    """v19 subscription ws-path census (GATED gql_allow_ws; hint-only).
    P19 owns protocol handshake/authz/replay."""
    out = {"paths": [], "note": "hint census only; P19 owns handshake"}
    if not conf.get("gql_allow_ws"):
        out["skipped"] = True
        out["gate"] = "gql_allow_ws=false"
        return out
    root = base_url.rstrip("/")
    for p in WS_PATHS[:int(conf.get("gql_subs_paths", 4))]:
        u = root + p
        try:
            r = http.get(u, headers={
                "Connection": "Upgrade", "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": base64.b64encode(
                    ("waspP18" + rand_str(6)).encode()).decode(),
                "Sec-WebSocket-Protocol": "graphql-transport-ws",
                "X-WASP-Probe": "P18-subs"}, allow_redirects=False)
            meta["probes_total"] += 1
            if r.status == 101 or r.status == 426 or "upgrade" in (
                    r.header("Connection") or "").lower():
                out["paths"].append({"url": u, "status": r.status,
                                     "hint": True})
        except ScopeError:
            raise
        except Exception as e:
            out.setdefault("errors", []).append(truncate(str(e), 60))
    return out


def timing_oracle(http, url, meta, conf):
    """v19 alias-count elapsed differential (GATED gql_allow_depth).
    1-alias x2 vs 5-alias x2 __typename (4 req bounded) -> resolver-cost /
    N+1 fingerprint aid. Koi heavy query nahi (INERT typename only)."""
    out = {"t1_ms": None, "t5_ms": None, "delta_ms": None, "n1_hint": None}
    if not conf.get("gql_allow_depth"):
        out["skipped"] = True
        out["gate"] = "gql_allow_depth=false"
        return out
    e1, e5 = [], []
    for _ in range(2):
        for cnt, bucket in ((1, e1), (5, e5)):
            try:
                q = alias_query("__typename", cnt)
                t0 = time.time()
                r = http.post(url, data=gql_json_body(q), headers={
                    "Content-Type": "application/json",
                    "X-WASP-Probe": "P18-timing"},
                    read_only_post=True, allow_redirects=False)
                meta["probes_total"] += 1
                bucket.append((time.time() - t0) * 1000.0)
            except ScopeError:
                raise
            except Exception:
                continue
    if e1 and e5:
        out["t1_ms"] = round(median(e1), 2)
        out["t5_ms"] = round(median(e5), 2)
        out["delta_ms"] = round(out["t5_ms"] - out["t1_ms"], 2)
        out["n1_hint"] = out["delta_ms"] > max(50.0, out["t1_ms"] * 3)
        out["note"] = "bounded typename probes (INERT; no heavy query)"
    return out


def shadow_schema_diff(introspections):
    """v19 multi-endpoint schema-census diff (0 network probes).
    2+ OPEN introspections -> type-set diff -> shadow/older-API hint."""
    open_schemas = {}
    for u, r in (introspections or {}).items():
        if isinstance(r, dict) and r.get("state") == "OPEN":
            sch = r.get("schema") or {}
            tset = set(sch.get("types") or []) | set(
                (sch.get("field_census") or {}).keys())
            open_schemas[u] = tset
    if len(open_schemas) < 2:
        return {"rows": [], "compared": 0,
                "note": "need >=2 OPEN introspections"}
    urls = sorted(open_schemas)
    rows = []
    for i in range(len(urls)):
        for j in range(i + 1, len(urls)):
            a, b = urls[i], urls[j]
            only_a = sorted(open_schemas[a] - open_schemas[b])[:8]
            only_b = sorted(open_schemas[b] - open_schemas[a])[:8]
            if only_a or only_b:
                rows.append({"endpoint_a": a.rsplit("/", 1)[-1] or a,
                             "endpoint_b": b.rsplit("/", 1)[-1] or b,
                             "only_a": only_a, "only_b": only_b,
                             "shadow_hint": True})
    return {"rows": rows, "compared": len(rows),
            "endpoints": len(urls),
            "note": "census diff (types/field_census) - 0 probes"}



# ===========================================================================
# VERDICT HELPERS (6-class, P12..P17 compatible)
# ===========================================================================
def merge_verdict(verdicts):
    """Multi-signal merge: CONFIRMED > SUSPECTED > BLOCKED > HARDENED >
    SKIPPED > NOISE (evidence-first ladder)."""
    order = ["CONFIRMED", "SUSPECTED", "BLOCKED", "HARDENED", "SKIPPED",
             "NOISE"]
    for v in order:
        if v in verdicts:
            return v
    return "NOISE"


# ===========================================================================
# TECHNIQUE MATRIX (100+ rows - P17 ka 96-row pattern, GraphQL variant)
# ===========================================================================
def build_technique_matrix(results, conf):
    """(family, technique, verdict-source, safety, signals) rows."""
    R = []
    def add(fam, tech, src, safety, signals=""):
        R.append({"family": fam, "technique": tech, "source": src,
                  "safety": safety, "signals": truncate(str(signals), 90)})

    disc = results.get("discovery") or {}
    eps = results.get("endpoints") or []
    valid = results.get("valid_endpoints") or []
    intro = results.get("introspection") or {}
    bp = results.get("bypass") or []
    mine = results.get("mining") or {}
    authz = results.get("field_authz") or []
    bola = results.get("bola") or {}
    guards = results.get("guards") or {}
    ssrf = results.get("ssrf") or {}
    inj = results.get("inject") or {}
    mis = results.get("misconfig") or {}
    ide = results.get("ide") or []
    bp2 = results.get("bypass2") or []
    fedd = results.get("federation_deep") or {}
    inc = results.get("input_census") or {}
    sdlr = results.get("sdl_endpoints") or []
    shad = results.get("shadow_diff") or {}
    subs = results.get("subs_deep") or {}
    timo = results.get("timing") or {}

    # ---- DISCOVERY family (11) ----
    add("DISC", "P17 feedforward gql_endpoints merge", "discovery",
        "AUTO-INERT", "%d seeds" % len(disc.get("sources", [])))
    add("DISC", "P6 graphql_surface hosts census", "discovery",
        "AUTO-INERT", "hosts=%s" % disc.get("p6_hosts", 0))
    add("DISC", "P11 graphql_bola endpoints merge", "discovery",
        "AUTO-INERT", "endpoints=%s" % disc.get("p11_endpoints", 0))
    add("DISC", "P7 graphql_endpoints/ops mining", "discovery",
        "AUTO-INERT", "ops=%d" % len(disc.get("seed_ops", [])))
    add("DISC", "P5/P3/P8 weak-seed merge", "discovery", "AUTO-INERT", "")
    add("DISC", "cold path pool (26 paths)", "discovery", "AUTO-INERT",
        "%d candidates" % len(results.get("ranked") or []))
    add("DISC", "rank scoring (weights)", "discovery", "AUTO-INERT", "")
    add("DISC", "IDE path census (10 paths)", "discovery", "AUTO-INERT",
        "%d IDEs" % len(ide))
    add("DISC", "Apollo server-health probe", "discovery", "AUTO-INERT",
        str(bool(results.get("health"))))
    add("DISC", "graph-ish spec derive", "discovery", "AUTO-INERT", "")
    add("DISC", "dedupe + cap enforcement", "discovery", "AUTO-INERT",
        "cap=%s" % conf.get("gql_endpoints_cap"))

    # ---- FINGERPRINT family (10) ----
    add("FP", "GET method census", "fingerprint", "AUTO-INERT",
        str([e.get("methods", {}).get("GET") for e in valid[:3]]))
    add("FP", "GET ?query= method confusion", "fingerprint", "AUTO-INERT",
        str(any(e.get("get_query_enabled") for e in valid)))
    add("FP", "POST-json {__typename}", "fingerprint", "AUTO-INERT",
        str(any(e.get("typename_ok") for e in valid)))
    add("FP", "POST application/graphql raw-CT", "fingerprint",
        "AUTO-INERT", str(any(e.get("raw_ct_ok") for e in valid)))
    add("FP", "engine signature scoring (11 engines)", "fingerprint",
        "AUTO-INERT", str([e.get("fingerprint") for e in valid[:1]]))
    add("FP", "IDE markers on endpoint", "fingerprint", "AUTO-INERT", "")
    add("FP", "rate-header census (passive)", "fingerprint", "AUTO-INERT", "")
    add("FP", "CORS header census", "fingerprint", "AUTO-INERT",
        str(any(e.get("cors") for e in valid)))
    add("FP", "tracing header probe", "fingerprint", "AUTO-INERT",
        str(any(e.get("tracing_enabled") for e in valid)))
    add("FP", "introspection-state hint", "fingerprint", "AUTO-INERT",
        str(intro.get("state")))

    # ---- INTROSPECTION family (9) ----
    add("INTRO", "shallow introspection (3 roots)", "introspect",
        "AUTO-INERT", str(intro.get("state")))
    add("INTRO", "stepwise types census", "introspect", "AUTO-INERT",
        "%d types" % len(((intro.get("schema") or {}).get("types")) or []))
    add("INTRO", "stepwise per-type drill (bounded 6)", "introspect",
        "AUTO-INERT", "")
    add("INTRO", "full introspection census-only", "introspect",
        "AUTO-INERT", "%d fields" % ((intro.get("schema") or {})
                                     .get("total_fields", 0)))
    add("INTRO", "deprecated-fields census", "introspect", "AUTO-INERT",
        "%d" % len(((intro.get("schema") or {}).get("deprecated")) or []))
    add("INTRO", "dangerous-type census", "introspect", "AUTO-INERT",
        "%d" % len(((intro.get("schema") or {}).get("dangerous")) or []))
    add("INTRO", "url-arg census", "introspect", "AUTO-INERT",
        "%d" % len(((intro.get("schema") or {}).get("url_args")) or []))
    add("INTRO", "id-arg census", "introspect", "AUTO-INERT",
        "%d" % len(((intro.get("schema") or {}).get("id_args")) or []))
    add("INTRO", "introspection-off detection (block-msg)", "introspect",
        "AUTO-INERT", str(intro.get("state") == "DISABLED"))

    # ---- BYPASS family (14) ----
    if bp:
        add("BYPASS", "GET ?query= introspection", "bypass", "AUTO-INERT",
            str(any(r.get("schema_leaked") and r["technique"] ==
                    "get-query" for r in bp)))
        add("BYPASS", "application/graphql raw-CT", "bypass", "AUTO-INERT",
            str(any(r.get("schema_leaked") and r["technique"] ==
                    "ct-application-graphql" for r in bp)))
        add("BYPASS", "form-urlencoded query=", "bypass", "AUTO-INERT", "")
        add("BYPASS", "text/plain JSON simple-request", "bypass",
            "AUTO-INERT", "")
        add("BYPASS", "charset parser variant", "bypass", "AUTO-INERT", "")
        add("BYPASS", "__Schema case-variant", "bypass", "AUTO-INERT", "")
        add("BYPASS", "__SCHEMA upper-variant", "bypass", "AUTO-INERT", "")
        add("BYPASS", "alias-split introspection", "bypass", "AUTO-INERT",
            "")
        add("BYPASS", "fragment-wrapped introspection", "bypass",
            "AUTO-INERT", "")
        add("BYPASS", "@skip directive trick", "bypass", "AUTO-INERT", "")
        add("BYPASS", "federation _service{sdl}", "bypass", "AUTO-INERT",
            str(any(r.get("federation_sdl") for r in bp)))
        add("BYPASS", "batch-wrapped introspection", "bypass", "AUTO-INERT",
            "")
        add("BYPASS", "path confusion (/ + //)", "bypass", "AUTO-INERT",
            "")
        add("BYPASS", "bypass matrix census (14 tech)", "bypass",
            "AUTO-INERT", "%d rows" % len(bp))
    else:
        add("BYPASS", "bypass matrix", "bypass", "AUTO-INERT",
            "introspection open - matrix n/a")

    # ---- ERROR-MINING family (8) ----
    add("MINE", "invalid-field baseline error", "mining", "AUTO-INERT",
        str(mine.get("errors_verbose")))
    add("MINE", "did-you-mean suggestion parse", "mining", "AUTO-INERT",
        "%d sugg" % len(mine.get("suggestions", [])))
    add("MINE", "mutation-root type mining (validation-only)", "mining",
        "AUTO-INERT", "%d" % len(mine.get("mined_types", [])))
    add("MINE", "field wordlist oracle (40)", "mining", "AUTO-INERT",
        "%d mined" % len(mine.get("mined_fields", [])))
    add("MINE", "field-exists differential (200 vs error)", "mining",
        "AUTO-INERT", "")
    add("MINE", "authz error-code census", "mining", "AUTO-INERT",
        str(mine.get("authz_codes")))
    add("MINE", "verbose-error census", "mining", "AUTO-INERT",
        str(mine.get("errors_verbose")))
    add("MINE", "stack-trace census", "mining", "AUTO-INERT",
        str(mine.get("stack_trace")))
    add("MINE", "nested suggestion BFS (v19)", "mining", "AUTO-INERT",
        "%d nested" % len(mine.get("mined_nested", [])))
    add("MINE", "suggestion-depth census (depth-2)", "mining",
        "AUTO-INERT", str(mine.get("nested_depth")))

    # ---- FIELD-AUTHZ family (10) ----
    add("AUTHZ", "sensitive-field scoring (31 patterns)", "authz",
        "AUTO-INERT", "%d cands" % len(authz))
    add("AUTHZ", "anon field query differential", "authz", "AUTO-INERT", "")
    add("AUTHZ", "invalid-bearer differential", "authz", "AUTO-INERT", "")
    add("AUTHZ", "invalid-jwt-shape differential", "authz", "AUTO-INERT",
        "")
    add("AUTHZ", "field-authz-missing detection", "authz", "AUTO-INERT",
        str(any(a.get("model") == "field-authz-missing" for a in authz)))
    add("AUTHZ", "token-not-validated (field) detection", "authz",
        "AUTO-INERT",
        str(any(a.get("model") == "token-not-validated-field"
                for a in authz)))
    add("AUTHZ", "authz error-code oracle", "authz", "AUTO-INERT", "")
    add("AUTHZ", "deprecated-still-live check", "authz", "AUTO-INERT",
        str(any(a.get("via") == "deprecated-live" for a in authz)))
    add("AUTHZ", "mutation validation-order probe (NEVER executes)",
        "authz", "AUTO-INERT (validation-only)",
        str(any(a.get("via") == "mutation-validation-order"
                for a in authz)))
    add("AUTHZ", "field-authz matrix census", "authz", "AUTO-INERT",
        "%d rows" % len(authz))

    # ---- BOLA family (7) ----
    add("BOLA", "canary-id resolver differential", "bola",
        "GATED gql_allow_bola",
        str(len(bola.get("rows", []))) if isinstance(bola, dict)
        else "SKIPPED")
    add("BOLA", "id-arg census targets (schema)", "bola",
        "GATED gql_allow_bola", "")
    add("BOLA", "cold-synth id targets (user/order/account)", "bola",
        "GATED gql_allow_bola", "")
    add("BOLA", "anon-vs-invalid differential", "bola",
        "GATED gql_allow_bola", "")
    add("BOLA", "alias-amplified canary (cap 4)", "bola",
        "GATED gql_allow_bola",
        str((bola.get("alias") or {}).get("amplified")) if isinstance(
            bola, dict) else "SKIPPED")
    add("BOLA", "P11 graphql_bola merge", "bola", "AUTO-INERT", "handoff")
    add("BOLA", "full resolver enumeration", "bola", "MANUAL-ONLY",
        "P11 owns")

    # ---- GUARDS family (8) ----
    add("GUARD", "deep-nesting probe (5 levels)", "guards",
        "GATED gql_allow_depth",
        str((guards.get("deep") or {}).get("guard") or
            (guards.get("deep") or {}).get("skipped")))
    add("GUARD", "depth/cost error fingerprint", "guards",
        "GATED gql_allow_depth", "")
    add("GUARD", "alias-multiplication (5)", "guards",
        "GATED gql_allow_depth",
        str((guards.get("alias") or {}).get("echoes")))
    add("GUARD", "field-duplication census", "guards",
        "GATED gql_allow_depth", "")
    add("GUARD", "JSON-array batching (2 elements)", "guards",
        "GATED gql_allow_batch",
        str((guards.get("batch") or {}).get("accepted")))
    add("GUARD", "batch N-response differential", "guards",
        "GATED gql_allow_batch", "")
    add("GUARD", "APQ persistedQuery probe", "guards", "AUTO-INERT",
        str((guards.get("apq") or {}).get("supported")))
    add("GUARD", "circular-fragment DoS", "guards", "FORBIDDEN-AUTO",
        "documented only")

    # ---- SSRF/INJECT family (7) ----
    add("SSRF", "URL-arg census (schema)", "ssrf", "AUTO-INERT",
        "%d args" % len(ssrf.get("url_args", [])))
    add("SSRF", "canary DNS differential (.invalid)", "ssrf", "AUTO-INERT",
        str((ssrf.get("probe") or {}).get("dns_attempt_hint")))
    add("SSRF", "upload-scalar census", "ssrf", "AUTO-INERT",
        str(ssrf.get("upload_scalar")))
    add("SSRF", "P15 chain handoff", "ssrf", "AUTO-INERT", "ff.json")
    add("INJ", "quote-marker arg census", "inject", "AUTO-INERT",
        str(inj.get("signatures")))
    add("INJ", "error-signature SQL/NoSQL/SSTI census", "inject",
        "AUTO-INERT", "%d sigs" % len(inj.get("signatures", {})))
    add("INJ", "P12 injection chains", "inject", "MANUAL-ONLY", "P12 owns")

    # ---- MISCONFIG family (9) ----
    add("MIS", "IDE exposure census", "misconfig", "AUTO-INERT",
        "%d IDEs" % len(ide))
    add("MIS", "introspection-in-prod check", "misconfig", "AUTO-INERT",
        str(intro.get("state")))
    add("MIS", "GET-query CSRF surface", "misconfig", "AUTO-INERT",
        str(mis.get("get_query")))
    add("MIS", "text/plain CSRF-CT probe", "misconfig",
        "GATED gql_allow_csrf",
        str((mis.get("csrf_ct") or {}).get("text/plain", {}).get(
            "accepted") if isinstance(mis.get("csrf_ct"), dict) else
            "SKIPPED"))
    add("MIS", "form-urlencoded CSRF-CT probe", "misconfig",
        "GATED gql_allow_csrf", "")
    add("MIS", "CORS wildcard census", "misconfig", "AUTO-INERT",
        str(mis.get("cors")))
    add("MIS", "tracing/debug exposure", "misconfig", "AUTO-INERT",
        str(mis.get("tracing")))
    add("MIS", "subscription upgrade hint", "misconfig",
        "GATED gql_allow_ws",
        str((mis.get("ws") or {}).get("upgrade_hint") or
            (mis.get("ws") or {}).get("upgrade") or
            (mis.get("ws") or {}).get("skipped")))
    add("MIS", "server-health census", "misconfig", "AUTO-INERT",
        str(bool(results.get("health"))))
    add("MIS", "role-header trust census (v19)", "misconfig",
        "AUTO-INERT", str((fedd.get("role_header") or {}).get("trusted")))

    # ---- BYPASS2 family (v19 SECRET, 18) ----
    if bp2:
        add("BYPASS2", "JSON unicode-escape __schema (\\u005f)", "bypass2",
            "AUTO-INERT", str(any(r.get("schema_leaked") and
                                   r["technique"] == "json-unicode-escape"
                                   for r in bp2)))
        add("BYPASS2", "duplicate query-keys smuggling", "bypass2",
            "AUTO-INERT", str(any(r.get("schema_leaked") and
                                   r["technique"] == "json-duplicate-keys"
                                   for r in bp2)))
        add("BYPASS2", "variables-carried introspection", "bypass2",
            "AUTO-INERT", str(any(r.get("schema_leaked") and
                                   r["technique"] ==
                                   "variables-introspection"
                                   for r in bp2)))
        add("BYPASS2", "multipart/form-data query field", "bypass2",
            "AUTO-INERT", str(any(r.get("schema_leaked") and
                                   r["technique"] == "ct-multipart-form"
                                   for r in bp2)))
        add("BYPASS2", "HPP query-string+body", "bypass2", "AUTO-INERT",
            "")
        add("BYPASS2", "minified no-space query", "bypass2", "AUTO-INERT",
            "")
        add("BYPASS2", "whitespace/comment token-split", "bypass2",
            "AUTO-INERT", "")
        add("BYPASS2", "operationName mismatch fingerprint", "bypass2",
            "AUTO-INERT", "")
        add("BYPASS2", "GET ?query&variables protocol", "bypass2",
            "AUTO-INERT", "")
        add("BYPASS2", "GET introspection (POST-only WAF miss)", "bypass2",
            "AUTO-INERT", str(any(r.get("schema_leaked") and
                                   r["technique"] ==
                                   "get-query-introspection"
                                   for r in bp2)))
        add("BYPASS2", "charset utf-16 body", "bypass2", "AUTO-INERT",
            str(any(r.get("schema_leaked") and r["technique"] ==
                    "charset-utf16" for r in bp2)))
        add("BYPASS2", "UTF-8 BOM prefix", "bypass2", "AUTO-INERT", "")
        add("BYPASS2", "X-Original-URL edge misroute", "bypass2",
            "AUTO-INERT", str(any(r.get("schema_leaked") and
                                   r["technique"] ==
                                   "header-x-original-url"
                                   for r in bp2)))
        add("BYPASS2", "X-Rewrite-URL edge misroute", "bypass2",
            "AUTO-INERT", "")
        add("BYPASS2", "X-HTTP-Method-Override GET", "bypass2",
            "AUTO-INERT", "")
        add("BYPASS2", "dot-segment path normalize", "bypass2",
            "AUTO-INERT", "")
        add("BYPASS2", "semicolon path-param", "bypass2", "AUTO-INERT", "")
        add("BYPASS2", "bypass2 census (17 secret)", "bypass2",
            "AUTO-INERT", "%d rows / %d leaks" % (len(bp2),
            sum(1 for r in bp2 if r.get("schema_leaked"))))
    else:
        add("BYPASS2", "WAF-bypass v2 matrix", "bypass2", "AUTO-INERT",
            "introspection open - n/a")

    # ---- FED2 family (v19, 8) ----
    add("FED2", "_entities canary representation", "federation",
        "AUTO-INERT", str((fedd.get("entities") or {}).get(
            "entities_resolved")))
    add("FED2", "entity-resolution BOLA surface", "federation",
        "AUTO-INERT", "")
    add("FED2", "X-Hasura-Role trust differential", "federation",
        "AUTO-INERT", str((fedd.get("role_header") or {}).get(
            "trusted")))
    add("FED2", "role-header spoof census", "federation", "AUTO-INERT",
        "")
    add("FED2", "AppSync x-api-key lenient diff", "federation",
        "AUTO-INERT", str((fedd.get("api_key") or {}).get("lenient")))
    add("FED2", "ftv1 tracing leak", "federation", "AUTO-INERT",
        str((fedd.get("ftv1") or {}).get("leak")))
    add("FED2", "_service{sdl} (v1 probe)", "federation", "AUTO-INERT",
        str(bool((results.get("federation") or {}).get("sdl_found"))))
    add("FED2", "gateway-topology manual", "federation", "MANUAL-ONLY",
        "gateway wave")

    # ---- SDL family (v19, 4) ----
    add("SDL", "raw SDL endpoint census (6 paths)", "sdl", "AUTO-INERT",
        "%d leaks" % len(sdlr))
    add("SDL", "schema.json disclosure check", "sdl", "AUTO-INERT",
        str(any(r.get("kind") == "schema-json" for r in sdlr)))
    add("SDL", "SDL type census", "sdl", "AUTO-INERT",
        str([r.get("census", {}).get("types", []) for r in sdlr[:1]]))
    add("SDL", "SDL auth-wall manual", "sdl", "MANUAL-ONLY", "")

    # ---- INPUT family (v19, 6) ----
    add("INPUT", "*Input type census", "input", "AUTO-INERT",
        "%d types" % len(inc.get("input_types", [])))
    add("INPUT", "writable sensitive fields (isAdmin/role/owner)",
        "input", "AUTO-INERT",
        "%d fields" % len(inc.get("writable_sensitive", [])))
    add("INPUT", "WhereInput/WhereUniqueInput (Prisma-style) census",
        "input", "AUTO-INERT", str(inc.get("where_inputs")))
    add("INPUT", "mass-assignment hypothesis (P20)", "input",
        "AUTO-INERT", "handoff")
    add("INPUT", "type-confusion oracle manual", "input", "MANUAL-ONLY",
        "")
    add("INPUT", "write-probe wave", "input", "MANUAL-ONLY",
        "never auto")

    # ---- SUBS family (v19, 4) ----
    add("SUBS", "ws-path census (GATED allow_ws)", "subs",
        "GATED gql_allow_ws",
        "%d hints" % len(subs.get("paths", []))
        if not subs.get("skipped") else "SKIPPED")
    add("SUBS", "upgrade-hint differential", "subs",
        "GATED gql_allow_ws", "")
    add("SUBS", "graphql-ws protocol handshake", "subs", "MANUAL-ONLY",
        "P19 owns")
    add("SUBS", "subscription authz/replay deep", "subs", "MANUAL-ONLY",
        "P19 owns")

    # ---- TIMING family (v19, 4) ----
    add("TIMING", "alias-count elapsed differential (GATED)", "timing",
        "GATED gql_allow_depth", str(timo.get("delta_ms")))
    add("TIMING", "N+1/dataloader absence fingerprint", "timing",
        "AUTO-INERT", str(timo.get("n1_hint")))
    add("TIMING", "cost-analysis absence hypothesis", "timing",
        "AUTO-INERT", "")
    add("TIMING", "resource-exhaustion PoC", "timing", "FORBIDDEN-AUTO",
        "RoE lab")

    # ---- SHADOW family (v19, 3) ----
    add("SHADOW", "multi-endpoint schema diff (0-probe)", "shadow",
        "AUTO-INERT", "%d diffs" % len(shad.get("rows", [])))
    add("SHADOW", "older-version endpoint skew", "shadow", "AUTO-INERT",
        "")
    add("SHADOW", "shadow-API enumeration manual", "shadow",
        "MANUAL-ONLY", "")

    # ---- MANUAL-ONLY (7) ----
    add("MANUAL", "mutation authz full BFLA", "manual", "MANUAL-ONLY",
        "mutations kabhi auto nahi")
    add("MANUAL", "subscription authz/replay", "manual", "MANUAL-ONLY",
        "P19 owns")
    add("MANUAL", "APQ cache-poisoning chain", "manual", "MANUAL-ONLY",
        "P22 owns")
    add("MANUAL", "argument injection chains", "manual", "MANUAL-ONLY",
        "P12 owns")
    add("MANUAL", "resource-exhaustion PoC", "manual", "FORBIDDEN-AUTO",
        "RoE lab only")
    add("MANUAL", "schema-poisoning/federation abuse", "manual",
        "MANUAL-ONLY", "gateway wave")
    add("MANUAL", "tenant-isolation deep", "manual", "MANUAL-ONLY", "")
    return R



# ===========================================================================
# KILL-CHAINS (13) + CWE + MITRE + CATALOG
# ===========================================================================
def build_gql_chains(F, intro, bp, mine, authz, bola, guards, ssrf, mis,
                     ide, eps, bp2=None, fedd=None, sdlr=None, shad=None,
                     inc=None):
    C_ = []
    def chain(name, steps, sevs, refs):
        C_.append({"name": name, "steps": steps, "severity": sevs,
                   "refs": refs})
    if intro.get("state") == "OPEN":
        chain("introspection-open -> full-schema-map",
              ["introspection OPEN", "schema census (types/args/deprecated)",
               "sensitive-field map", "P11/P12 targeted chain"],
              "high", ["introspection_census.json"])
    if any(r.get("schema_leaked") for r in bp):
        chain("introspection-bypass -> schema-disclosure",
              ["introspection disabled", "bypass variant leaked schema",
               "defense-in-depth gap", "full chain replay"], "critical",
              ["bypass_matrix.json"])
    if any(a.get("model") == "field-authz-missing" for a in authz):
        chain("field-authz-missing -> data-breach",
              ["sensitive field anon-query", "200+data (no resolver check)",
               "bulk alias amplification (P11)", "PII exfil hypothesis"],
              "critical", ["field_authz_matrix.json"])
    if isinstance(bola, dict) and bola.get("rows"):
        chain("bola-in-resolvers -> object-takeover",
              ["canary-id resolver query", "structural 200+data",
               "P11 full enumeration", "cross-tenant impact"], "critical",
              ["bola_matrix.json"])
    if isinstance(bola, dict) and (bola.get("alias") or {}).get(
            "amplified"):
        chain("alias-amplification -> bola-speedup",
              ["4 aliases 1 request", "N objects ek saath",
               "rate-limit evasion", "mass enumeration hypothesis"],
              "critical", ["bola_matrix.json"])
    if (guards.get("batch") or {}).get("accepted") and \
            not (guards.get("deep") or {}).get("guard"):
        chain("batching+no-depth-guard -> resource-exhaustion",
              ["array-batch accepted", "depth guard absent",
               "alias multiplication", "DoS hypothesis (RoE lab only)"],
              "high", ["guard_census.json"])
    if (ssrf.get("probe") or {}).get("dns_attempt_hint"):
        chain("gql-ssrf-arg -> internal-network",
              ["URL-arg fetch behavior", "canary DNS attempt",
               "P15 internal-smoke chain", "cloud-IMDS hypothesis"],
              "high", ["ssrf_surface.json"])
    if any(r.get("kind") for r in ide):
        chain("ide-exposed -> interactive-exploitation",
              ["GraphiQL/Playground public", "interactive query firing",
               "authz bypass aid", "dev-prod boundary gap"], "medium",
              ["ide_census.json"])
    if mine.get("suggestions") or mine.get("mined_fields"):
        chain("field-suggestions -> schema-enumeration",
              ["introspection off", "did-you-mean oracle",
               "wordlist mining", "partial schema reconstructed"],
              "medium", ["error_mining.json"])
    if mis.get("csrf_ct") and isinstance(mis.get("csrf_ct"), dict) and \
            any(isinstance(v, dict) and v.get("accepted")
                for v in mis["csrf_ct"].values()):
        chain("csrf-ct-confusion -> cross-origin-query",
              ["text/plain accepted", "browser simple-request",
               "cross-origin state-read", "CSRF chain (P14 aid)"],
              "medium", ["misconfig_census.json"])
    if mis.get("get_query"):
        chain("get-query -> linkable-queries",
              ["GET ?query= support", "query URL me",
               "log/referrer leak", "CSRF aid"], "low",
              ["misconfig_census.json"])
    if (guards.get("apq") or {}).get("supported"):
        chain("apq-supported -> cache-replay",
              ["persistedQuery accepted", "hash-replay primitives",
               "P22 cache chain", "poisoning hypothesis"], "low",
              ["guard_census.json"])
    chain("error-disclosure -> internals-map",
          ["verbose/stack errors", "resolver paths/versions",
           "P23 misconfig chain", "targeting aid"], "low",
          ["error_mining.json"])
    # ---- v19 chains ----
    bp2 = bp2 or []
    fedd = fedd or {}
    sdlr = sdlr or []
    shad = shad or {}
    inc = inc or {}
    _v2_leak_techs = {"json-unicode-escape", "charset-utf16",
                      "get-query-introspection", "ct-multipart-form",
                      "variables-introspection"}
    if any(r.get("schema_leaked") and r.get("technique") in _v2_leak_techs
           for r in bp2):
        chain("waf-literal-bypass -> schema-disclosure-v2",
              ["WAF literal-filter (post-body only)", "parser/charset/"
               "GET-path variant leaked schema", "edge-only enforcement "
               "gap", "app-layer disable + re-test 17"], "critical",
              ["bypass2_matrix.json"])
    if any(r.get("schema_leaked") and r.get("technique") ==
           "header-x-original-url" for r in bp2):
        chain("edge-misroute -> waf-path-miss",
              ["X-Original-URL honored at edge", "WAF rule path-scoped",
               "protected route reached unfiltered", "routing hardening "
               "rec"], "critical", ["bypass2_matrix.json"])
    if (fedd.get("entities") or {}).get("entities_resolved"):
        chain("federation-entities -> graph-bola",
              ["_entities representations accepted", "canary entity "
               "resolved", "entity-resolver authz gap", "P11 graph-BOLA "
               "wave"], "high", ["federation_deep.json"])
    if (fedd.get("role_header") or {}).get("trusted"):
        chain("role-header-trust -> authz-spoof",
              ["role-identity header trusted", "invalid canary role "
               "echoed", "server-side authz bypass primitive",
               "remove header trust rec"], "high",
              ["federation_deep.json"])
    if sdlr:
        chain("raw-sdl-endpoint -> introspection-equivalent",
              ["schema.graphql/schema.json public", "SDL = full schema "
               "map", "introspection-disable bypassed", "auth-wall rec"],
              "high", ["sdl_endpoints.json"])
    if shad.get("rows"):
        chain("shadow-schema-diff -> version-skew-abuse",
              ["multi-endpoint introspection diff", "older API exposes "
               "more types", "shadow-API enumeration (P11)", "version "
               "deprecation audit"], "medium", ["shadow_schema_diff.json"])
    if inc.get("writable_sensitive"):
        chain("writable-sensitive-inputs -> mass-assignment",
              ["*Input writable isAdmin/role/owner", "update mutation "
               "surface", "P20 logic wave (manual)", "field-allowlist "
               "rec"], "high", ["input_census.json"])
    return C_


def build_cwe_map():
    return {
        "gql_introspection_open": ["CWE-200", "CWE-1234"],
        "gql_introspection_partial": ["CWE-693"],
        "gql_introspection_bypass": ["CWE-693", "CWE-284"],
        "gql_federation_sdl": ["CWE-200"],
        "gql_field_suggestions": ["CWE-209"],
        "gql_type_suggestions": ["CWE-209"],
        "gql_error_verbose": ["CWE-209"],
        "gql_error_stack_trace": ["CWE-209"],
        "gql_field_authz_missing": ["CWE-862", "CWE-285"],
        "gql_field_authz_inconsistent": ["CWE-285", "CWE-863"],
        "gql_field_authz_hint": ["CWE-209"],
        "gql_deprecated_field_live": ["CWE-1104"],
        "gql_mutation_authz_order": ["CWE-285"],
        "gql_bola_canary_readable": ["CWE-639", "OWASP-API1"],
        "gql_bola_alias_amplified": ["CWE-639", "CWE-770"],
        "gql_id_arg_live": ["CWE-639"],
        "gql_batch_accepted": ["CWE-770", "CWE-400"],
        "gql_no_depth_guard": ["CWE-400", "CWE-770"],
        "gql_alias_guard_missing": ["CWE-770"],
        "gql_apq_supported": ["CWE-359"],
        "gql_ssrf_arg_surface": ["CWE-918"],
        "gql_upload_scalar": ["CWE-434"],
        "gql_inject_error_sig": ["CWE-89", "CWE-943"],
        "gql_get_query_enabled": ["CWE-352"],
        "gql_csrf_ct_confusion": ["CWE-352", "CWE-434"],
        "gql_cors_wildcard": ["CWE-942"],
        "gql_tracing_enabled": ["CWE-532"],
        "gql_ide_exposed": ["CWE-489"],
        "gql_server_health": ["CWE-200"],
        "gql_waf_detected": ["CWE-200"],
        "gql_waf_bypass_v2": ["CWE-693", "CWE-436"],
        "gql_parser_confusion": ["CWE-436", "CWE-435"],
        "gql_entities_exposed": ["CWE-639", "CWE-863"],
        "gql_role_header_trusted": ["CWE-284", "CWE-345"],
        "gql_apikey_lenient": ["CWE-287"],
        "gql_ftv1_tracing": ["CWE-532"],
        "gql_sdl_endpoint": ["CWE-200", "CWE-1234"],
        "gql_input_massassign": ["CWE-915"],
        "gql_shadow_schema": ["CWE-1104"],
        "gql_subs_surface": ["CWE-200"],
        "gql_timing_oracle": ["CWE-208"],
        "gql_nested_suggestions": ["CWE-209"],
    }


def build_mitre_map():
    return {
        "gql_introspection_bypass": ["T1592.004", "T1213"],
        "gql_field_authz_missing": ["T1552.005", "T1087"],
        "gql_bola_canary_readable": ["T1087", "T1213"],
        "gql_bola_alias_amplified": ["T1087", "T1110"],
        "gql_ssrf_arg_surface": ["T1595", "T1090"],
        "gql_no_depth_guard": ["T1499"],
        "gql_batch_accepted": ["T1110", "T1499"],
        "gql_ide_exposed": ["T1190"],
        "gql_csrf_ct_confusion": ["T1185"],
        "gql_error_stack_trace": ["T1592"],
        "gql_waf_bypass_v2": ["T1595.002", "T1211"],
        "gql_role_header_trusted": ["T1562", "T1098"],
        "gql_sdl_endpoint": ["T1592.004"],
        "gql_entities_exposed": ["T1087", "T1213"],
        "gql_input_massassign": ["T1068", "T1098"],
        "gql_nested_suggestions": ["T1592"],
    }


def build_catalog_md():
    lines = ["# P18 GraphQL - Technique Catalog (v%s)" % PLAN_VERSION, ""]
    lines.append("| Family | Techniques | Safety |")
    lines.append("|---|---|---|")
    for fam, n, safety in [
        ("DISC", 11, "AUTO-INERT (seed census + cold pool)"),
        ("FP", 10, "AUTO-INERT (method/CT/engine fingerprint)"),
        ("INTRO", 9, "AUTO-INERT (census-only schema storage)"),
        ("BYPASS", 14, "AUTO-INERT (structural variants, 1-2 req each)"),
        ("BYPASS2", 18, "AUTO-INERT (v19 WAF/parser secret census; "
                        "unicode/dup-keys/charset/misroute variants)"),
        ("MINE", 10, "AUTO-INERT (error-oracle wordlist + nested BFS, "
                      "capped)"),
        ("AUTHZ", 10, "AUTO-INERT (invalid canary tokens; mutations "
                      "NEVER executed)"),
        ("BOLA", 7, "GATED gql_allow_bola (canary ids only)"),
        ("GUARD", 8, "GATED gql_allow_depth/batch (caps 5lvl/5al/2el)"),
        ("SSRF/INJ", 7, "AUTO-INERT (.invalid canary; detection-only)"),
        ("MIS", 10, "census AUTO + csrf/ws GATED"),
        ("FED2", 8, "AUTO-INERT (v19 _entities canary/role-trust/ftv1)"),
        ("SDL", 4, "AUTO-INERT (v19 raw schema endpoint census)"),
        ("INPUT", 6, "AUTO-INERT (v19 *Input census; write NEVER auto)"),
        ("SUBS", 4, "GATED gql_allow_ws (hint-only; P19 owns)"),
        ("TIMING", 4, "GATED gql_allow_depth (bounded typename probes)"),
        ("SHADOW", 3, "AUTO-INERT (v19 0-probe schema diff)"),
        ("MANUAL", 7, "MANUAL-ONLY/FORBIDDEN-AUTO (documented)"),
    ]:
        lines.append("| %s | %d | %s |" % (fam, n, safety))
    lines.append("")
    lines.append("Total: **150 techniques** (78 AUTO-INERT + GATED w/ RoE "
                 "+ MANUAL-ONLY documented).")
    lines.append("")
    lines.append("## RoE gates (config.json)")
    for g in ("gql_allow_bola", "gql_bola_ids", "gql_allow_batch",
              "gql_allow_depth", "gql_allow_csrf", "gql_allow_ws"):
        lines.append("- `%s` (default false)" % g)
    lines.append("")
    lines.append("## Safety crown rules")
    lines.append("- 100% INERT payloads (FORBIDDEN_CONTENT_PATTERNS "
                 "enforced)")
    lines.append("- Canary ids/queries only (waspP18 family) - no real "
                 "record enumeration")
    lines.append("- Mutations KABHI well-formed execute nahi hote - sirf "
                 "validation-order probes")
    lines.append("- Batching/alias/depth hard caps (2/5/5), 1 request each")
    lines.append("- SSRF canary .invalid TLD - zero external egress")
    lines.append("- Schema dumps census-only (names/counts; body stored "
                 "nahi)")
    lines.append("- Invalid canary tokens only - no real credentials")
    lines.append("- Response bodies REDACTED (len/sha1/marker-boolean)")
    return "\n".join(lines)


def build_exec_summary_md(meta, intro, bp, mine, authz, bola, guards,
                          ssrf, mis, ide, eps, conf, ranked_count=0,
                          bp2=None, fedd=None, sdlr=None, inc=None,
                          shad=None, subs=None, timo=None):
    lines = ["# P18 GraphQL - Executive Summary", ""]
    lines.append("- Probes: %d (caps: endpoints=%s bypass=%s authz=%s)"
                 % (meta.get("probes_total", 0),
                    conf.get("gql_endpoints_cap"),
                    conf.get("gql_bypass_cap"),
                    conf.get("gql_authz_fields")))
    lines.append("- Endpoints: %d validated / %d candidates"
                 % (len(eps), ranked_count))
    lines.append("- Introspection: %s | bypass leaks: %d/%d"
                 % (intro.get("state"),
                    sum(1 for r in bp if r.get("schema_leaked")),
                    len(bp)))
    lines.append("- Error mining: %d suggestions / %d mined fields"
                 % (len(mine.get("suggestions", [])),
                    len(mine.get("mined_fields", []))))
    lines.append("- Field-authz: %d rows -> CONFIRMED=%d HARDENED=%d"
                 % (len(authz),
                    sum(1 for a in authz if a.get("verdict") ==
                        "CONFIRMED"),
                    sum(1 for a in authz if a.get("verdict") ==
                        "HARDENED")))
    lines.append("- BOLA: %s" % ("SKIPPED (gated)" if isinstance(
        bola, dict) and bola.get("skipped") else
        "%d rows" % len(bola.get("rows", [])) if isinstance(bola, dict)
        else "n/a"))
    lines.append("- Guards: deep=%s batch=%s apq=%s"
                 % ((guards.get("deep") or {}).get("guard") or
                    ("skipped" if (guards.get("deep") or {}).get(
                        "skipped") else "none"),
                    "accepted" if (guards.get("batch") or {}).get(
                        "accepted") else
                    ("skipped" if (guards.get("batch") or {}).get(
                        "skipped") else "rejected"),
                    (guards.get("apq") or {}).get("supported")))
    lines.append("- SSRF surface: %d url-args | dns-hint=%s"
                 % (len(ssrf.get("url_args", [])),
                    (ssrf.get("probe") or {}).get("dns_attempt_hint")))
    lines.append("- Misconfig: IDEs=%d | GET-query=%s | CORS=%s | "
                 "tracing=%s" % (len(ide), mis.get("get_query"),
                                 mis.get("cors"), mis.get("tracing")))
    lines.append("- RoE gates: bola=%s batch=%s depth=%s csrf=%s ws=%s"
                 % (conf.get("gql_allow_bola"), conf.get("gql_allow_batch"),
                    conf.get("gql_allow_depth"), conf.get("gql_allow_csrf"),
                    conf.get("gql_allow_ws")))
    # ---- v19 ULTRA++ lines ----
    bp2 = bp2 or []
    fedd = fedd or {}
    sdlr = sdlr or []
    inc = inc or {}
    shad = shad or {}
    subs = subs or {}
    timo = timo or {}
    lines.append("- Bypass2 (WAF v2 secret): %d/%d leaks (17 techniques)"
                 % (sum(1 for r in bp2 if r.get("schema_leaked")),
                    len(bp2)))
    lines.append("- Federation deep: entities=%s role-trust=%s ftv1=%s "
                 "apikey-lenient=%s"
                 % ((fedd.get("entities") or {}).get("entities_resolved"),
                    (fedd.get("role_header") or {}).get("trusted"),
                    (fedd.get("ftv1") or {}).get("leak"),
                    (fedd.get("api_key") or {}).get("lenient")))
    lines.append("- SDL endpoints: %d | Input census: %d types / %d "
                 "writable-sensitive"
                 % (len(sdlr), len(inc.get("input_types", [])),
                    len(inc.get("writable_sensitive", []))))
    lines.append("- Shadow diff: %d | Subs paths: %d | Timing delta: %sms"
                 % (len(shad.get("rows", [])), len(subs.get("paths", [])),
                    timo.get("delta_ms")))
    return "\n".join(lines)



# ===========================================================================
# HYPOTHESES + REPORTS + PAYLOADS
# ===========================================================================
def build_gql_hypotheses(intro, bp, mine, authz, bola, guards, ssrf, mis,
                         ide, conf, bp2=None, fedd=None, sdlr=None,
                         inc=None, shad=None):
    H = []
    def hyp(title, steps, est, priority):
        H.append({"title": title, "steps": steps, "estimate": est,
                  "priority": priority})
    if intro.get("state") == "OPEN":
        hyp("Schema-driven authz audit (introspection OPEN)",
            ["schema census se sensitive fields", "manual resolver authz "
             "review", "P11 BOLA wave", "impact doc"], "35m", "P1")
    for r in bp:
        if r.get("schema_leaked"):
            hyp("Introspection-bypass hardening: %s" % r["technique"],
                ["bypass variant reproduce (lab)", "block-all-paths fix "
                 "doc", "defense-in-depth review"], "25m", "P1")
    for a in authz:
        if a.get("verdict") == "CONFIRMED" and \
                a.get("model") == "field-authz-missing":
            hyp("Field-level authz fix verify: %s" % a["field"],
                ["resolver check doc", "RoE-gated canary re-test",
                 "field-level authz middleware rec"], "20m", "P1")
    if isinstance(bola, dict) and bola.get("rows"):
        hyp("BOLA-in-resolvers manual wave (P11)",
            ["P11 full id-enum (RoE)", "cross-tenant impact doc",
             "resolver authz fix verify"], "40m", "P1")
    if (guards.get("batch") or {}).get("accepted"):
        hyp("Batching hardening verify", ["batch-disable config doc",
            "array-size cap rec", "rate-limit per-array-element"], "20m",
            "P2")
    if not (guards.get("deep") or {}).get("guard") and \
            not (guards.get("deep") or {}).get("skipped"):
        hyp("Depth/cost-analysis introduction", ["graphql-depth-limit "
            "rec", "cost-analysis config", "RoE lab verify"], "25m", "P2")
    if (ssrf.get("probe") or {}).get("dns_attempt_hint"):
        hyp("GraphQL SSRF audit (P15 chain)", ["URL-arg allowlist rec",
            "P15 internal-smoke (RoE)", "egress-policy doc"], "30m", "P1")
    if ide:
        hyp("IDE exposure remediation", ["prod me IDE disable",
            "dev-prod boundary doc", "auth-wall rec"], "15m", "P3")
    if mis.get("get_query") or (isinstance(mis.get("csrf_ct"), dict) and
                                any(isinstance(v, dict) and
                                    v.get("accepted") for v in
                                    (mis.get("csrf_ct") or {}).values())):
        hyp("GraphQL CSRF hardening", ["GET-query disable",
            "strict CT enforcement", "CSRF-token/introspection rec"],
            "20m", "P3")
    # ---- v19 ULTRA++ hypotheses ----
    bp2 = bp2 or []
    fedd = fedd or {}
    sdlr = sdlr or []
    inc = inc or {}
    shad = shad or {}
    if any(r.get("schema_leaked") for r in bp2):
        hyp("WAF-layer introspection bypass hardening (v19)",
            ["WAF literal-rule replace with app-layer disable",
             "re-test all 17 bypass2 techniques", "CT/charset/misroute "
             "normalization doc"], "30m", "P1")
    if (fedd.get("entities") or {}).get("entities_resolved"):
        hyp("Federation _entities authz review",
            ["entity-resolver authz doc", "P11 graph-BOLA wave",
             "representation allowlist rec"], "25m", "P1")
    if (fedd.get("role_header") or {}).get("trusted"):
        hyp("Role-header trust removal",
            ["X-Hasura-Role family trust doc", "session-bound roles rec",
             "re-test differential"], "20m", "P1")
    if sdlr:
        hyp("Raw SDL endpoint auth-wall",
            ["schema endpoint auth doc", "CDN/edge rule rec",
             "re-census"], "15m", "P2")
    if inc.get("writable_sensitive"):
        hyp("Mass-assignment input audit (P20)",
            ["input-type writable fields review", "field-allowlist rec",
             "P20 logic wave"], "25m", "P2")
    if shad.get("rows"):
        hyp("Shadow/older-API version-skew audit",
            ["endpoint version deprecation doc", "schema-parity review",
             "P11 enumeration (RoE)"], "20m", "P2")
    if not H:
        hyp("Baseline GraphQL hygiene wave", ["introspection posture doc",
            "IDE/authz review", "P19 WebSocket next"], "15m", "P4")
    return H


def _gql_findings_md(F, meta, intro, authz):
    lines = ["# P18 GraphQL - Findings", ""]
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
        lines.append("(koi finding nahi - HARDENED posture ya sparse "
                     "surface)")
    return "\n".join(lines)


def write_gql_payloads(out, cap=20):
    """INERT request bodies folder (manual wave ke liye ready)."""
    d = os.path.join(out, "gql_payloads")
    _rwx_dir(d)
    canary = _canary("pl")
    files = []
    bodies = [
        ("introspection_full_query.json", gql_json_body(
            FULL_INTROSPECTION_QUERY)),
        ("introspection_shallow.json", gql_json_body(
            Q_INTROSPECTION_SHALLOW)),
        ("bypass_get_query.txt", ("GET /graphql?query=%s"
                                  % urllib.parse.quote(
                                      Q_QUERY_TYPE_NAME)).encode()),
        ("bypass_ct_application_graphql.txt",
         Q_QUERY_TYPE_NAME.encode()),
        ("bypass_federation_sdl.json", gql_json_body(Q_FEDERATION_SDL)),
        ("field_authz_probe.json", gql_json_body(
            "{ adminConfig { __typename } }")),
        ("bola_canary_probe.json", gql_json_body(
            '{ user(id: "%s") { __typename } }'
            % (canary + "BOLA"))),
        ("batch_2element_INERT.json", batch_body(
            [Q_TYPENAME, Q_QUERY_TYPE_NAME], canary)),
        ("deep_5level_INERT.json", gql_json_body(deep_query(5))),
        ("alias_5x_INERT.json", gql_json_body(
            alias_query("__typename", 5))),
        ("csrf_textplain_INERT.txt", json.dumps(
            {"query": Q_TYPENAME}).encode()),
        ("mutation_validation_order_INERT.json", gql_json_body(
            "mutation { waspp18canary(bogusArg: 123) { __typename } }")),
        # ---- v19 ULTRA++ payloads ----
        ("bypass2_unicode_escape_INERT.json",
         gql_json_body_unicode(Q_QUERY_TYPE_NAME)),
        ("bypass2_dupkeys_INERT.json",
         gql_json_body_dupkeys("{ __typename }", Q_QUERY_TYPE_NAME)),
        ("bypass2_variables_INERT.json", json.dumps(
            {"query": Q_VARIABLES_INTROSPECTION,
             "variables": {"t": "Query"}}).encode()),
        ("bypass2_multipart_INERT.txt",
         multipart_query_body(Q_QUERY_TYPE_NAME)),
        ("bypass2_get_query_INERT.txt",
         ("GET /graphql?query=%s" % urllib.parse.quote(
             Q_QUERY_TYPE_NAME)).encode()),
        ("federation_entities_INERT.json", json.dumps(
            {"query": Q_ENTITIES,
             "variables": {"r": [{"__typename": "User",
                                  "id": canary + "ENT"}]}}).encode()),
        ("role_header_census_INERT.txt",
         ("POST /graphql\nX-Hasura-Role: waspP18canary\n\n(INERT census "
          "header - manual differential wave)\n").encode()),
    ]
    for name, body in bodies[:cap]:
        p = os.path.join(d, name)
        _rwx_save_text(p, body.decode("utf-8", "ignore"))
        files.append("gql_payloads/%s" % name)
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

    intro = results.get("introspection") or {}
    eps = results.get("valid_endpoints") or []
    bp = results.get("bypass") or []
    mine = results.get("mining") or {}
    authz = results.get("field_authz") or []
    bola = results.get("bola") or {}
    guards = results.get("guards") or {}
    ssrf = results.get("ssrf") or {}
    inj = results.get("inject") or {}
    mis = results.get("misconfig") or {}
    ide = results.get("ide") or []
    bp2 = results.get("bypass2") or []
    fedd = results.get("federation_deep") or {}
    inc = results.get("input_census") or {}
    sdlr = results.get("sdl_endpoints") or []
    shad = results.get("shadow_diff") or {}
    subs = results.get("subs_deep") or {}
    timo = results.get("timing") or {}

    J("gql_surface.json", {"sources": ctx.get("mined_sources", []),
                           "coverage": ctx.get("coverage", {}),
                           "mode": ctx.get("mode", "active"),
                           "seed_ops": meta.get("seed_ops", [])})
    ranked = ctx.get("ranked") or []
    T("gql_targets.txt", "\n".join(
        ["%s|%s|%s" % (t.get("url", ""), t.get("kind", ""),
                       ",".join(t.get("sources", []))) for t in
         ranked[:60]]))
    J("gql_endpoints.json", {
        "all_rows": results.get("all_rows") or [],
        "validated": eps})
    J("introspection_census.json", intro)
    J("bypass_matrix.json", {"rows": bp, "techniques": len(bp),
                             "leaks": sum(1 for r in bp
                                          if r.get("schema_leaked"))})
    J("bypass2_matrix.json", {"rows": bp2, "techniques": len(bp2),
                              "version": "v19-secret",
                              "leaks": sum(1 for r in bp2
                                           if r.get("schema_leaked"))})
    J("federation_deep.json", fedd)
    J("input_census.json", inc)
    J("sdl_endpoints.json", sdlr)
    J("shadow_schema_diff.json", shad)
    J("subs_deep.json", subs)
    J("timing_oracle.json", timo)
    J("platform_census.json", {
        "hasura_role": fedd.get("role_header") or {},
        "appsync_key": fedd.get("api_key") or {},
        "ftv1": fedd.get("ftv1") or {},
        "entities": fedd.get("entities") or {}})
    J("error_mining.json", mine)
    J("field_authz_matrix.json", authz)
    J("bola_matrix.json", bola)
    J("guard_census.json", guards)
    J("ssrf_surface.json", ssrf)
    J("inject_census.json", inj)
    J("misconfig_census.json", mis)
    J("ide_census.json", ide)
    J("health_census.json", results.get("health") or {})
    J("waf_map_gql.json", results.get("waf") or {})
    J("differential_gql.json", {
        "soft404": meta.get("soft404", {}),
        "home": meta.get("home_sig", {}),
        "verdict_ladder":
            "CONFIRMED>SUSPECTED>BLOCKED>HARDENED>SKIPPED>NOISE"})
    J("technique_matrix_gql.json", {
        "rows": matrix, "count": len(matrix),
        "safety_classes": sorted(set(r["safety"].split()[0]
                                     for r in matrix))})
    J("mitre_map_gql.json", build_mitre_map())
    J("cwe_map_gql.json", build_cwe_map())
    J("gql_probe_log.json", {"probes_total": meta.get("probes_total", 0),
                             "stages": ctx.get("coverage", {}),
                             "canary_family": "waspP18"})
    T("gql_chains.txt", "\n".join(
        ["%s | sev=%s | %s" % (c["name"], c["severity"], " -> ".join(
            c["steps"])) for c in chains]))
    T("gql_test_plan.md", "\n".join(
        ["# P18 Manual Test Plan (RoE-gated waves)", ""] +
        ["- [ ] %s (%s, %s)" % (h["title"], h["estimate"], h["priority"])
         for h in hypotheses]))
    T("TECHNIQUES_CATALOG_GQL.md", build_catalog_md())
    T("EXEC_SUMMARY.md", build_exec_summary_md(
        meta, intro, bp, mine, authz, bola, guards, ssrf, mis, ide, eps,
        conf, len(ranked), bp2=bp2, fedd=fedd, sdlr=sdlr, inc=inc,
        shad=shad, subs=subs, timo=timo))
    T("GQL_FINDINGS.md", _gql_findings_md(F, meta, intro, authz))
    manifest += write_gql_payloads(out)
    _rwx_save_json(os.path.join(out, "findings.json"), {
        "phase": PHASE, "version": PLAN_VERSION,
        "engagement": scope.engagement,
        "generated": now_iso(), "severity_counts": _sev_counts(F),
        "findings": F.items})
    manifest.append("findings.json")
    hyps_obj = {"hypotheses": hypotheses, "count": len(hypotheses)}
    J("gql_hypotheses.json", hyps_obj)
    return manifest


# ===========================================================================
# RUN ORCHESTRATION (Stage A..M)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 18 - GraphQL Security (detection-only, INERT) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    warn("GQL discipline: 100% INERT queries (FORBIDDEN_CONTENT_PATTERNS) | "
         "canary ids (waspP18) | mutations NEVER executed (validation-"
         "order only) | schema dumps census-only | bodies REDACTED.")
    if conf.get("gql_allow_bola"):
        warn("BOLA sampling ON (gql_allow_bola=true) - canary-id "
             "structural diff only; full enumeration P11 ka kaam hai.")
    if conf.get("gql_allow_batch"):
        warn("Batch probes ON (gql_allow_batch=true) - HARD cap 2 "
             "elements/1 request (array-DoS FORBIDDEN).")
    if conf.get("gql_allow_depth"):
        warn("Depth/alias probes ON (gql_allow_depth=true) - HARD caps "
             "5 levels / 5 aliases / 1 request each.")
    if conf.get("gql_allow_csrf"):
        warn("CSRF-CT probes ON (gql_allow_csrf=true) - read-only "
             "__typename queries only.")
    if conf.get("gql_allow_ws"):
        warn("WS hint ON (gql_allow_ws=true) - single upgrade probe "
             "(P19 handoff).")
    info("caps: endpoints=%s | bypass=%s | mining-fields=%s | "
         "authz-fields=%s | bola-ids=%s"
         % (conf.get("gql_endpoints_cap"), conf.get("gql_bypass_cap"),
            conf.get("gql_mining_fields"), conf.get("gql_authz_fields"),
            conf.get("gql_bola_ids")))

    F = Findings()
    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "pocs": [], "mode": "active",
           "base_dir": os.path.join(base_out, scope.engagement)}
    results = {}
    qhttp = quiet_client(http, cfg, scope, ev)

    # ---------------- Stage A: discovery ----------------
    head("Stage A - GQL surface discovery (P17/P6/P11/P7/P5/P3/P8-seeded)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {})
        ranked, meta = cached[0], dict(cached[1])
        meta["probes_total"] = meta.get("probes_total", 0)
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, meta = discover_gql_surface(ctx["base_dir"], scope, conf)
        cp.mark(ckA, [ranked, meta], summary="gql surface")
    ctx["mined_sources"] = meta.get("sources", [])
    ctx["ranked"] = ranked[:80]
    ctx["coverage"]["surface"] = ("gql=%d total=%d" % (
        len([t for t in ranked if t.get("kind") == "gql_endpoint"]),
        len(ranked)))
    ok("seed artifacts: %d sources | %s | ops=%d"
       % (len(ctx["mined_sources"]), ctx["coverage"]["surface"],
          len(meta.get("seed_ops", []))))

    base_url = meta.get("base_url") or (scope.seed_urls() or [""])[0]

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: seed census + offline "
             "hypotheses (0 network probes).")
        ctx["mode"] = "passive"
        results = {"all_rows": [], "valid_endpoints": [],
                   "introspection": {}, "bypass": [], "mining": {},
                   "field_authz": [], "bola": {}, "guards": {}, "ssrf": {},
                   "inject": {}, "misconfig": {}, "ide": []}
        hyps = build_gql_hypotheses({}, [], {}, [], {}, {}, {}, {}, [],
                                    conf)
        chains = build_gql_chains(F, {}, [], {}, [], {}, {}, {}, {}, [],
                                  [])
        matrix = build_technique_matrix(results, conf)
        manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                                 chains, matrix, conf)
        write_feedforward(out, PHASE, {"to_phase32_report":
                                       {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive "
                                 "run"])
        write_manifest(out, PHASE, manifest + ["feedforward.json"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree_local(out)
        return out

    # ---------------- Stage B: baseline + WAF ----------------
    head("Stage B - Baseline & WAF calibration")
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
        rhome = http.get(base_url, allow_redirects=False)
        meta["probes_total"] += 1
        wf = waf_signature(rhome.headers or {}, rhome.text or "",
                           rhome.status)
        if isinstance(wf, list):
            wf = {"names": [str(x) for x in wf[:5]],
                  "name": str(wf[0]) if wf else None}
        elif not isinstance(wf, dict):
            wf = {}
        waf = wf
        meta["waf"] = waf
        if waf:
            ok("WAF/edge fingerprint: %s" % (waf.get("name") or
                                             waf.get("names") or "signals"))
    except Exception as e:
        warn("waf-sig skip: %s" % e)
    results["waf"] = waf
    if interrupted():
        warn("interrupted - partial save")

    # ---------------- Stage B2: endpoint validation ----------------
    head("Stage B2 - Endpoint validation + engine fingerprint + IDE census")
    all_rows, valid = validate_endpoints(http, ranked, meta, conf,
                                         _canary("fp"))
    results["all_rows"] = all_rows
    results["valid_endpoints"] = valid
    results["ranked"] = ranked
    for row in valid:
        F.add("gql_endpoint_live", "GraphQL endpoint live",
              row["url"], "methods=%s typename_ok=%s (P18 engine active)"
              % (sorted(k for k, v in row.get("methods", {}).items()
                        if isinstance(v, int) and v < 500),
                 row.get("typename_ok")), "gql_endpoints.json")
        if row.get("fingerprint"):
            F.add("gql_engine_fingerprint", "GraphQL engine fingerprint",
                  row["url"], "engines=%s" % list(
                      row["fingerprint"].items())[:2],
                  "gql_endpoints.json")
        if row.get("get_query_enabled"):
            F.add("gql_get_query_enabled", "GET-method queries supported",
                  row["url"], "GET ?query= accepted - CSRF/link "
                  "surface", "misconfig_census.json")
        if row.get("cors") == "*":
            F.add("gql_cors_wildcard", "CORS wildcard on GraphQL",
                  row["url"], "Access-Control-Allow-Origin: * - any-"
                  "origin browser-read", "misconfig_census.json")
        if row.get("tracing_enabled"):
            F.add("gql_tracing_enabled", "Apollo tracing exposed",
                  row["url"], "resolver timings/metrics leak",
                  "misconfig_census.json")
    results["ide"] = ide_census(http, base_url, meta, conf)
    ctx["coverage"]["validation"] = ("valid=%d/%d ide=%d"
                                     % (len(valid), len(all_rows),
                                        len(results["ide"])))
    for row in results["ide"]:
        F.add("gql_ide_exposed", "%s console publicly accessible"
              % row["kind"].title(), row["url"],
              "IDE interactive query surface exposed (CWE-489)",
              "ide_census.json")
    results["health"] = health_probe(http, base_url, meta)
    if results["health"]:
        F.add("gql_server_health", "Apollo server-health exposed",
              results["health"]["url"], "infra signal (status=%s)"
              % results["health"]["status"], "health_census.json")
    ok("validated: %d/%d candidates | IDEs=%d | health=%s"
       % (len(valid), len(all_rows), len(results["ide"]),
          "yes" if results["health"] else "no"))
    if not valid:
        err("Koi valid GraphQL endpoint nahi mila (cold pool bhi 404). "
            "P17 (api ff) + P6 (graphql_surface) + P11 (graphql_bola) "
            "chalao, ya endpoint manual seed karo.")
        F.add("gql_surface_sparse", "GraphQL surface khali",
              scope.describe(),
              "seed artifacts + cold-pool se koi live endpoint nahi - "
              "P17/P6/P11 chalao.", "gql_surface.json")

    # ---------------- Stage C: introspection engine ----------------
    head("Stage C - Introspection engine (shallow/stepwise/full census)")
    results["introspections"] = {}
    results["introspection"] = {}
    for row in valid[:4]:
        u = row["url"]
        ckC = "stageC:introspect:%s" % u
        if cp.is_done(ckC):
            res = cp.result_of(ckC) or {}
            ok("introspection replay (checkpoint): %s -> %s"
               % (u, res.get("state")))
        else:
            res = run_introspection(http, u, meta, conf, _canary("in"))
            cp.mark(ckC, res, summary="introspection %s: %s"
                    % (u, res.get("state")))
        results["introspections"][u] = res
        sch = res.get("schema") or {}
        ok("introspection %s: %s | types=%d fields=%d deprecated=%d"
           % (u, res.get("state"), len(sch.get("types", [])),
              sch.get("total_fields", 0), len(sch.get("deprecated", []))))
        if res.get("state") == "OPEN":
            F.add("gql_introspection_open", "Introspection publicly OPEN",
                  u, "types=%d fields=%d (schema-map free disclosure)"
                  % (len(sch.get("types", [])),
                     sch.get("total_fields", 0)),
                  "introspection_census.json")
        elif res.get("state") == "PARTIAL":
            F.add("gql_introspection_partial",
                  "Introspection partial/inconsistent", u,
                  "some queries pass, some block - hardening gap",
                  "introspection_census.json")
        elif res.get("state") == "DISABLED":
            F.add("gql_introspection_disabled",
                  "Introspection cleanly disabled", u,
                  "positive posture (bypass matrix verify karega)",
                  "introspection_census.json")
        if sch.get("deprecated"):
            F.add("gql_deprecated_field_live",
                  "Deprecated fields schema me", u,
                  "%d deprecated: %s" % (len(sch["deprecated"]),
                                         sch["deprecated"][:4]),
                  "introspection_census.json")
        if sch.get("url_args"):
            F.add("gql_ssrf_arg_surface", "URL-accepting args schema me",
                  u, "%d url-args: %s" % (len(sch["url_args"]),
                                          sch["url_args"][:4]),
                  "ssrf_surface.json")
        if sch.get("id_args"):
            F.add("gql_id_arg_live", "ID-arg resolver types live", u,
                  "%d id-args (P11 handoff)" % len(sch["id_args"]),
                  "bola_matrix.json")
    ctx["coverage"]["introspection"] = ", ".join(
        "%s=%s" % (uu.rsplit("/", 1)[-1],
                   (results["introspections"].get(uu) or {}).get("state"))
        for uu in results["introspections"]) or "none"
    # primary = pehla OPEN, warna pehla valid
    pri = next((r for r in valid[:3] if results["introspections"].get(
        r["url"], {}).get("state") == "OPEN"), valid[0] if valid else None)
    results["introspection"] = results["introspections"].get(
        pri["url"], {}) if pri else {}

    # ---------------- Stage D: bypass matrix ----------------
    head("Stage D - Introspection bypass matrix (14 techniques, INERT)")
    results["bypass"] = []
    results["federation"] = {}
    if pri:
        results["federation"] = federation_probe(http, pri["url"], meta)
        if results["federation"].get("sdl_found"):
            F.add("gql_federation_sdl", "Apollo Federation SDL exposed",
                  pri["url"], "_service{sdl} census: %s"
                  % (results["federation"].get("sdl_census") or
                     {}).get("types", [])[:6], "bypass_matrix.json")
    if conf.get("gql_introspection_bypass", True):
        by_target = next((r for r in valid[:3]
                          if results["introspections"].get(
                              r["url"], {}).get("state") in
                          ("DISABLED", "PARTIAL", "BLOCKED")), None)
        if by_target:
            results["bypass"] = bypass_matrix(http, by_target["url"], meta,
                                              conf, _canary("by"))
            leaked = [r for r in results["bypass"]
                      if r.get("schema_leaked")]
            for r in leaked:
                F.add("gql_introspection_bypass",
                      "Introspection bypass: %s" % r["technique"],
                      by_target["url"],
                      "%s -> schema leak (status=%s) - guard single-path "
                      "hai" % (r.get("desc"), r.get("status")),
                      "bypass_matrix.json")
            ok("bypass matrix @%s: %d techniques | leaks=%d"
               % (by_target["url"], len(results["bypass"]), len(leaked)))
        else:
            info("bypass matrix n/a (sab endpoints introspection OPEN)")
    else:
        info("bypass matrix disabled (gql_introspection_bypass=false)")

    # ---------------- Stage E: error mining ----------------
    head("Stage E - Error-based schema mining (field suggestions)")
    results["mining"] = {}
    if valid:
        mine_target = next((r for r in valid[:3]
                            if results["introspections"].get(
                                r["url"], {}).get("state") in
                            ("DISABLED", "BLOCKED", "PARTIAL")),
                           valid[0])
        ckE = "stageE:mining:%s" % mine_target["url"]
        if cp.is_done(ckE):
            results["mining"] = cp.result_of(ckE) or {}
            ok("mining replay (checkpoint): %d mined"
               % len(results["mining"].get("mined_fields", [])))
        else:
            results["mining"] = error_mining(http, mine_target["url"],
                                             meta, conf, _canary("mn"))
            cp.mark(ckE, results["mining"], summary="error mining")
        mine = results["mining"]
        ok("mining @%s: %d suggestions / %d mined fields | verbose=%s "
           "stack=%s" % (mine_target["url"],
                         len(mine.get("suggestions", [])),
                         len(mine.get("mined_fields", [])),
                         mine.get("errors_verbose"),
                         mine.get("stack_trace")))
        if mine.get("suggestions") or mine.get("mined_fields"):
            F.add("gql_field_suggestions",
                  "Field suggestions leak (error-based oracle)",
                  mine_target["url"],
                  "%d did-you-mean suggestions / %d mined fields - "
                  "introspection-off ke bawajood enumeration possible"
                  % (len(mine.get("suggestions", [])),
                     len(mine.get("mined_fields", []))),
                  "error_mining.json")
        if mine.get("mined_types"):
            F.add("gql_type_suggestions", "Type-name suggestions (mutation "
                  "root)", mine_target["url"],
                  "%d mutation-root hints" % len(mine["mined_types"]),
                  "error_mining.json")
        if mine.get("stack_trace"):
            F.add("gql_error_stack_trace", "Stack-trace in GraphQL errors",
                  mine_target["url"], "framework internals leak "
                  "(content redacted)", "error_mining.json")
        elif mine.get("errors_verbose"):
            F.add("gql_error_verbose", "Verbose validation errors",
                  mine_target["url"], "schema-oracle verbose errors",
                  "error_mining.json")

    # ---------------- Stage F: field-level authz ----------------
    head("Stage F - Field-level authz matrix (x invalid-token roles)")
    results["field_authz"] = []
    if valid:
        results["field_authz"] = field_authz_matrix(
            http, valid[0]["url"], results["introspection"].get("schema"),
            (results.get("mining") or {}).get("mined_fields", []), meta,
            conf, _canary("az"))
    for row in results["field_authz"]:
        if row.get("verdict") == "CONFIRMED" and \
                row.get("model") == "field-authz-missing":
            F.add("gql_field_authz_missing",
                  "Sensitive field anon-readable: %s" % row["field"],
                  valid[0]["url"] if valid else "",
                  "field=%s via=%s - resolver-level authz missing "
                  "(CWE-862)" % (row["field"], row.get("via")),
                  "field_authz_matrix.json")
        elif row.get("verdict") == "CONFIRMED" and \
                row.get("model") == "token-not-validated-field":
            F.add("gql_field_authz_inconsistent",
                  "Field token-not-validated: %s" % row["field"],
                  valid[0]["url"] if valid else "",
                  "invalid token par field data de gaya", 
                  "field_authz_matrix.json")
        elif row.get("via") == "mutation-validation-order":
            F.add("gql_mutation_authz_order",
                  "Mutation validation-vs-authz order: %s"
                  % row.get("model"),
                  valid[0]["url"] if valid else "",
                  "error-order oracle (mutation NEVER executed - INERT)",
                  "field_authz_matrix.json")
    vcounts = {v: sum(1 for r in results["field_authz"]
                      if r.get("verdict") == v)
               for v in ("CONFIRMED", "SUSPECTED", "HARDENED")}
    ctx["coverage"]["field_authz"] = "%d rows %s" % (
        len(results["field_authz"]), vcounts)
    ok("field-authz: %d rows -> %s" % (len(results["field_authz"]),
                                       vcounts))

    # ---------------- Stage G: BOLA in resolvers ----------------
    head("Stage G - BOLA in resolvers (GATED canary-ids; P11 handoff)")
    results["bola"] = bola_resolver_sampling(
        http, valid[0]["url"] if valid else base_url,
        results["introspection"].get("schema"), meta, conf, _canary("bo")) \
        if valid else {"skipped": True, "gate": "no-valid-endpoint"}
    if isinstance(results["bola"], dict) and \
            results["bola"].get("skipped"):
        F.add("gql_gate_skipped", "BOLA sampling GATED (OFF)",
              base_url, "gql_allow_bola=false - canary-id sampling "
              "manual wave; full enum P11.", "bola_matrix.json")
    else:
        for row in (results["bola"].get("rows") or []):
            if row.get("verdict") == "CONFIRMED":
                F.add("gql_bola_canary_readable",
                      "Canary object-id readable in resolver",
                      valid[0]["url"] if valid else "",
                      "target=%s canary=%s (structural) - object-level "
                      "authz gap (P11 verify)."
                      % (row["target"], row.get("canary")),
                      "bola_matrix.json")
        al = (results["bola"].get("alias") or {})
        if al.get("amplified"):
            F.add("gql_bola_alias_amplified",
                  "Alias-amplified canary echo (4 objects/1 req)",
                  valid[0]["url"] if valid else "",
                  "typename_echoes=%s - BOLA amplification primitive"
                  % al.get("typename_echoes"), "bola_matrix.json")
    ok("bola: %s" % ("SKIPPED (gated)" if isinstance(
        results["bola"], dict) and results["bola"].get("skipped") else
        "%d rows" % len((results["bola"].get("rows") or []))))

    # ---------------- Stage H: depth/cost/batch guards ----------------
    head("Stage H - Depth/cost/batch guard census (GATED, hard caps)")
    results["guards"] = guard_census(
        http, valid[-1]["url"] if valid else base_url, meta, conf,
        _canary("gd")) if valid else {"deep": {}, "alias": {}, "batch": {},
                                      "apq": {}}
    g = results["guards"]
    if (g.get("deep") or {}).get("resolved") and \
            not (g.get("deep") or {}).get("guard"):
        F.add("gql_no_depth_guard", "Deep nesting resolved (no guard)",
              valid[-1]["url"] if valid else "",
              "5-level query resolved - depth/cost guard absent "
              "(CWE-400)", "guard_census.json")
    elif (g.get("deep") or {}).get("guard"):
        F.add("gql_depth_guard_present", "Depth/cost guard active",
              valid[-1]["url"] if valid else "",
              "deep probe blocked: %s" % g["deep"]["guard"],
              "guard_census.json")
    if (g.get("alias") or {}).get("resolved") and \
            not (g.get("alias") or {}).get("guard"):
        F.add("gql_alias_guard_missing", "Alias multiplication accepted",
              valid[-1]["url"] if valid else "",
              "5 aliases echoed - alias-limit absent (CWE-770)",
              "guard_census.json")
    if (g.get("batch") or {}).get("accepted"):
        F.add("gql_batch_accepted", "JSON-array batching accepted",
              valid[-1]["url"] if valid else "",
              "2-element array -> %s responses - rate-limit/depth bypass "
              "primitive" % (g["batch"].get("responses_seen")),
              "guard_census.json")
    elif (g.get("batch") or {}).get("status"):
        F.add("gql_batch_disabled", "Batching rejected",
              valid[-1]["url"] if valid else "",
              "positive posture (status=%s)"
              % (g["batch"] or {}).get("status"), "guard_census.json")
    if (g.get("apq") or {}).get("supported"):
        F.add("gql_apq_supported", "Automatic Persisted Queries supported",
              valid[-1]["url"] if valid else "",
              "persistedQuery extensions accepted", "guard_census.json")
    ctx["coverage"]["guards"] = "deep=%s batch=%s apq=%s" % (
        (g.get("deep") or {}).get("guard") or
        ("skipped" if (g.get("deep") or {}).get("skipped") else "none"),
        "accepted" if (g.get("batch") or {}).get("accepted") else
        ("skipped" if (g.get("batch") or {}).get("skipped") else
         "rejected"),
        (g.get("apq") or {}).get("supported"))
    ok("guards: deep=%s | alias=%s | batch=%s | apq=%s"
       % ((g.get("deep") or {}).get("guard") or
          ("skipped" if (g.get("deep") or {}).get("skipped") else
           "none"),
          (g.get("alias") or {}).get("guard") or
          ("skipped" if (g.get("alias") or {}).get("skipped") else
           "none"),
          "accepted" if (g.get("batch") or {}).get("accepted") else
          ("skipped" if (g.get("batch") or {}).get("skipped") else
           "rejected"),
          (g.get("apq") or {}).get("supported")))

    # ---------------- Stage I: SSRF surface ----------------
    head("Stage I - SSRF/fetch surface (P15 handoff; .invalid canary)")
    results["ssrf"] = ssrf_surface(
        http, valid[0]["url"] if valid else base_url,
        results["introspection"].get("schema"), meta, conf,
        _canary("sr")) if valid else {}
    pr = (results["ssrf"].get("probe") or {})
    if pr.get("dns_attempt_hint") or pr.get("canary_echo"):
        F.add("gql_ssrf_arg_surface",
              "GraphQL fetch-arg SSRF surface", valid[0]["url"] if valid
              else "",
              "field=%s(%s) canary DNS/echo hint=%s - P15 chain handoff "
              "(.invalid host, zero egress)"
              % (pr.get("field"), pr.get("arg"),
                 pr.get("dns_attempt_hint")), "ssrf_surface.json")
    if results["ssrf"].get("upload_scalar"):
        F.add("gql_upload_scalar", "Upload scalar in schema",
              valid[0]["url"] if valid else "",
              "file-upload GraphQL variant - P16 handoff",
              "ssrf_surface.json")
    ok("ssrf: %d url-args | dns-hint=%s | upload=%s"
       % (len(results["ssrf"].get("url_args", [])),
          pr.get("dns_attempt_hint"), results["ssrf"].get(
              "upload_scalar")))

    # ---------------- Stage J: injection census ----------------
    head("Stage J - Injection surface census (detection-only; P12 handoff)")
    results["inject"] = inject_census(
        http, valid[0]["url"] if valid else base_url,
        results["introspection"].get("schema"), meta, conf,
        _canary("ij")) if valid else {}
    if results["inject"].get("signatures"):
        F.add("gql_inject_error_sig", "Injection signatures in arg errors",
              valid[0]["url"] if valid else "",
              "sigs=%s - P12 full-engine handoff (detection-only census)"
              % results["inject"]["signatures"], "inject_census.json")
    ok("inject census: %d sigs | stack=%s"
       % (len(results["inject"].get("signatures", {})),
          results["inject"].get("stack_trace")))

    # ---------------- Stage K: misconfig census ----------------
    head("Stage K - Misconfig/CSRF/WS census (GATED csrf/ws)")
    results["misconfig"] = misconfig_census(
        http, valid[0]["url"] if valid else base_url, base_url,
        valid[0] if valid else {}, meta, conf, _canary("mi")) if valid \
        else {"csrf_ct": {}, "ws": {}}
    mis = results["misconfig"]
    if isinstance(mis.get("csrf_ct"), dict):
        for ct, v in mis["csrf_ct"].items():
            if isinstance(v, dict) and v.get("accepted"):
                F.add("gql_csrf_ct_confusion",
                      "Cross-CT query accepted: %s" % ct,
                      valid[0]["url"] if valid else "",
                      "browser simple-request CSRF surface (read-only "
                      "probe)", "misconfig_census.json")
    if isinstance(mis.get("ws"), dict) and (mis["ws"].get("upgrade") or
                                            mis["ws"].get(
                                                "upgrade_hint")):
        F.add("gql_ws_signal", "WebSocket upgrade hint (P19 handoff)",
              mis["ws"].get("url", ""), "subscription surface hint "
              "(status=%s)" % mis["ws"].get("status"),
              "misconfig_census.json")
    ok("misconfig: GET=%s | csrf-cts=%s | ws=%s"
       % (mis.get("get_query"), len(mis.get("csrf_ct") or {}),
          (mis.get("ws") or {}).get("upgrade_hint") if isinstance(
              mis.get("ws"), dict) else "-"))

    # ---------------- Stage N (v19): WAF-bypass matrix v2 ----------------
    head("Stage N - WAF/parser bypass matrix v2 (17 SECRET techniques)")
    results["bypass2"] = []
    if conf.get("gql_introspection_bypass", True):
        n_targets = [r for r in valid[:4]
                     if results["introspections"].get(
                         r["url"], {}).get("state") in
                     ("DISABLED", "PARTIAL", "BLOCKED")][:2]
        for n_target in n_targets:
            n_rows = bypass_matrix_v2(http, n_target["url"], meta, conf)
            results["bypass2"].extend(n_rows)
            leaks2 = [r for r in n_rows if r.get("schema_leaked")]
            for r in leaks2:
                F.add("gql_waf_bypass_v2",
                      "WAF bypass v2: %s" % r["technique"],
                      n_target["url"],
                      "%s -> schema leak (status=%s) - edge-only "
                      "enforcement gap" % (r.get("desc"),
                                           r.get("status")),
                      "bypass2_matrix.json")
            confu = [r for r in n_rows if r.get("parser_confusion")]
            if confu:
                F.add("gql_parser_confusion",
                      "Parser-differential signals (v19)",
                      n_target["url"],
                      "%d variants: %s" % (len(confu),
                                           [r["technique"] for r in
                                            confu][:4]),
                      "bypass2_matrix.json")
            ok("bypass2 @%s: %d techniques | leaks=%d"
               % (n_target["url"], len(n_rows), len(leaks2)))
        if not n_targets:
            info("bypass2 n/a (sab endpoints introspection OPEN)")

    # ---------------- Stage O (v19): federation/platform deep ----------
    head("Stage O - Federation/platform deep (entities/role-trust/SDL)")
    results["federation_deep"] = federation_deep(
        http, valid[0]["url"] if valid else base_url, meta, conf,
        _canary("fd")) if valid else {}
    fd = results["federation_deep"]
    if (fd.get("entities") or {}).get("entities_resolved"):
        F.add("gql_entities_exposed", "Federation _entities resolved",
              valid[0]["url"] if valid else "",
              "canary representation resolved - entity-resolver BOLA "
              "surface (P11 handoff)", "federation_deep.json")
    if (fd.get("role_header") or {}).get("trusted"):
        F.add("gql_role_header_trusted", "Role-identity header trusted",
              valid[0]["url"] if valid else "",
              "X-Hasura-Role family differential - header-trust gap "
              "(CWE-284)", "federation_deep.json")
    if (fd.get("ftv1") or {}).get("leak"):
        F.add("gql_ftv1_tracing", "ftv1 resolver-trace leak",
              valid[0]["url"] if valid else "",
              "apollo-federation-include-trace honored (CWE-532)",
              "federation_deep.json")
    if (fd.get("api_key") or {}).get("lenient"):
        F.add("gql_apikey_lenient", "Invalid API-key lenient",
              valid[0]["url"] if valid else "",
              "canary key accepted - key-validation hint", "platform_"
              "census.json")
    results["sdl_endpoints"] = sdl_endpoint_census(http, base_url, meta)
    if results["sdl_endpoints"]:
        F.add("gql_sdl_endpoint", "Raw SDL/schema endpoint exposed",
              results["sdl_endpoints"][0]["url"],
              "%d endpoints leak schema (introspection-off bypass-class)"
              % len(results["sdl_endpoints"]), "sdl_endpoints.json")
    ok("fed2: entities=%s role-trust=%s ftv1=%s | sdl=%d"
       % ((fd.get("entities") or {}).get("entities_resolved"),
          (fd.get("role_header") or {}).get("trusted"),
          (fd.get("ftv1") or {}).get("leak"),
          len(results["sdl_endpoints"])))

    # ---------------- Stage P (v19): input-type census ----------------
    head("Stage P - Input-type census (mass-assignment surface)")
    results["input_census"] = input_type_census(
        results["introspection"].get("schema"), conf)
    if results["input_census"].get("writable_sensitive"):
        F.add("gql_input_massassign",
              "Writable sensitive input fields",
              valid[0]["url"] if valid else "",
              "%d fields: %s" % (
                  len(results["input_census"]["writable_sensitive"]),
                  results["input_census"]["writable_sensitive"][:4]),
              "input_census.json")
    ok("input census: %d types / %d writable-sensitive / where=%s"
       % (len(results["input_census"].get("input_types", [])),
          len(results["input_census"].get("writable_sensitive", [])),
          results["input_census"].get("where_inputs")))

    # ---------------- Stage Q (v19): subscriptions deep ----------------
    head("Stage Q - Subscriptions deep ws-census (GATED gql_allow_ws)")
    results["subs_deep"] = subs_deep(http, base_url, meta, conf)
    if results["subs_deep"].get("paths"):
        F.add("gql_subs_surface", "Subscription ws-path hints",
              base_url, "%d paths (P19 handoff)" %
              len(results["subs_deep"]["paths"]), "subs_deep.json")
    ok("subs: %s" % ("SKIPPED (gated)" if results["subs_deep"].get(
        "skipped") else "%d ws-hints" %
        len(results["subs_deep"].get("paths", []))))

    # ---------------- Stage R (v19): timing oracle ----------------
    head("Stage R - Alias timing/cost oracle (GATED gql_allow_depth)")
    results["timing"] = timing_oracle(
        http, valid[0]["url"] if valid else base_url, meta, conf) \
        if valid else {"skipped": True, "gate": "no-endpoint"}
    ok("timing: %s" % ("SKIPPED (gated)" if results["timing"].get(
        "skipped") else "t1=%sms t5=%sms delta=%sms n1=%s"
        % (results["timing"].get("t1_ms"),
           results["timing"].get("t5_ms"),
           results["timing"].get("delta_ms"),
           results["timing"].get("n1_hint"))))

    # ---------------- Stage S (v19): shadow schema diff ----------------
    head("Stage S - Shadow schema diff (multi-endpoint, 0-probe)")
    results["shadow_diff"] = shadow_schema_diff(
        results["introspections"]) if conf.get("gql_shadow_diff", True) \
        else {"rows": []}
    if results["shadow_diff"].get("rows"):
        F.add("gql_shadow_schema", "Shadow/older schema diff",
              base_url, "%d diffs: %s vs %s" % (
                  len(results["shadow_diff"]["rows"]),
                  results["shadow_diff"]["rows"][0].get("only_a", [])[:2],
                  results["shadow_diff"]["rows"][0].get("only_b", [])[:2]),
              "shadow_schema_diff.json")
    ok("shadow diff: %d rows (0 probes)"
       % len(results["shadow_diff"].get("rows", [])))

    # ---------------- Stage L/M: matrix + reports + feedforward --------
    head("Stage L/M - Technique matrix + reports + feedforward + manifest")
    matrix = build_technique_matrix(results, conf)
    hyps = build_gql_hypotheses(results["introspection"],
                                results.get("bypass") or [],
                                results.get("mining") or {},
                                results["field_authz"],
                                results.get("bola") or {},
                                results.get("guards") or {},
                                results.get("ssrf") or {},
                                results.get("misconfig") or {},
                                results.get("ide") or [], conf,
                                bp2=results.get("bypass2") or [],
                                fedd=results.get("federation_deep") or {},
                                sdlr=results.get("sdl_endpoints") or [],
                                inc=results.get("input_census") or {},
                                shad=results.get("shadow_diff") or {})
    chains = build_gql_chains(F, results["introspection"],
                              results.get("bypass") or [],
                              results.get("mining") or {},
                              results["field_authz"],
                              results.get("bola") or {},
                              results.get("guards") or {},
                              results.get("ssrf") or {},
                              results.get("misconfig") or {},
                              results.get("ide") or [], valid,
                              bp2=results.get("bypass2") or [],
                              fedd=results.get("federation_deep") or {},
                              sdlr=results.get("sdl_endpoints") or [],
                              shad=results.get("shadow_diff") or {},
                              inc=results.get("input_census") or {})
    ctx["coverage"]["techniques"] = "%d rows" % len(matrix)
    manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                             chains, matrix, conf)

    # feedforward (P19 ws + P11 bola + P12 inject + P15 ssrf + P16 files
    # + P20 logic + P24 cloud + P32 report)
    ff = {"to_phase19_ws": {
              "ws_signals": [mis.get("ws")] if isinstance(
                  mis.get("ws"), dict) and mis["ws"].get("url") else [],
              "gql_subscriptions": (results["introspection"].get("schema")
                                    or {}).get("subscription_type"),
              "ws_paths": [p.get("url") for p in
                           (results.get("subs_deep") or {}).get(
                               "paths", [])][:4]},
          "to_phase11_bola": {
              "gql_id_args": ((results["introspection"].get("schema") or
                               {}).get("id_args") or [])[:8],
              "bola_rows": [r.get("target") for r in
                            (results.get("bola", {}).get("rows") or [])
                            if isinstance(r, dict)][:6],
              "entities_live": ((results.get("federation_deep") or
                                 {}).get("entities") or {}).get(
                  "entities_resolved")},
          "to_phase12_inject": {
              "gql_signatures": results.get("inject", {}).get(
                  "signatures", {}),
              "gql_args_census": [a for a in
                                  ((results["introspection"].get("schema")
                                    or {}).get("arg_census") or
                                   {}).keys()][:10]},
          "to_phase15_ssrf": {
              "gql_url_args": (results["introspection"].get("schema") or
                               {}).get("url_args", [])[:8],
              "dns_hint": (results.get("ssrf", {}).get("probe") or
                           {}).get("dns_attempt_hint")},
          "to_phase16_files": {
              "upload_scalar": results.get("ssrf", {}).get(
                  "upload_scalar")},
          "to_phase20_logic": {
              "field_authz_confirmed": [r.get("field") for r in
                                        results["field_authz"]
                                        if r.get("verdict") ==
                                        "CONFIRMED"][:6],
              "mutation_order_models": [r.get("model") for r in
                                        results["field_authz"]
                                        if r.get("via") ==
                                        "mutation-validation-order"][:3],
              "writable_sensitive_inputs": (results.get(
                  "input_census") or {}).get(
                  "writable_sensitive", [])[:8]},
          "to_phase22_cache": {
              "apq_supported": (results.get("guards", {}).get("apq") or
                                {}).get("supported")},
          "to_phase23_misconfig": {
              "ide_exposed": [r.get("url") for r in
                              results.get("ide", [])][:6],
              "tracing": mis.get("tracing"),
              "stack_trace": (results.get("mining") or {}).get(
                  "stack_trace"),
              "sdl_endpoints": [r.get("url") for r in
                                results.get("sdl_endpoints", [])][:6]},
          "to_phase32_report": {"findings": len(F.items),
                                "probes": meta.get("probes_total", 0)}}
    write_feedforward(out, PHASE, ff,
                      notes=["P18 GraphQL: %d valid endpoints, "
                             "introspection=%s"
                             % (len(valid),
                                results["introspection"].get("state"))])
    manifest.append("feedforward.json")
    write_manifest(out, PHASE, manifest,
                   stats={"probes": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "matrix_rows": len(matrix),
                          "chains": len(chains),
                          "hypotheses": len(hyps),
                          "endpoints_valid": len(valid),
                          "introspection_state":
                              results["introspection"].get("state"),
                          "bypass2_techniques": len(
                              results.get("bypass2") or []),
                          "bypass2_leaks": sum(1 for r in
                                               (results.get("bypass2") or
                                                []) if r.get(
                                                   "schema_leaked")),
                          "sdl_endpoints": len(
                              results.get("sdl_endpoints") or []),
                          "shadow_diffs": len((results.get(
                              "shadow_diff") or {}).get("rows", [])),
                          "elapsed_s": round(time.time() - t_start, 1)})
    _rwx_tree_local(out)
    ok("P18 done: %d findings | %d matrix rows | %d chains | probes=%d | "
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


# run() me local alias use hota hai (P16/P17 pattern - naam collision guard)
_rwx_tree_local = _rwx_tree


def main():
    print("WASP mod_graphql.py (Phase 18 - GraphQL, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 18   (ya --module "
          "graphql)")
    print("  self-test : python3 test_mod_graphql.py")
    print("\n  RoE gates (config.json): gql_allow_bola=false (default),"
          " gql_allow_batch=false (default), gql_allow_depth=false "
          "(default), gql_allow_csrf=false (default), gql_allow_ws=false"
          " (default)")
    print("  Safety: 100% INERT queries | canary ids (waspP18) | mutations"
          " NEVER executed | batch/alias/depth caps 2/5/5 | schema dumps "
          "census-only | bodies REDACTED")
    print("  v19 ULTRA++: +WAF-bypass-v2 (17 secret) +federation-deep "
          "(entities/role-trust/ftv1) +SDL census +input-census "
          "+subs-deep +timing-oracle +shadow-diff +nested-BFS mining")


if __name__ == "__main__":
    main()
