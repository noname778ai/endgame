#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_replay.py  |  Phase 22 - Replay & Anti-Replay Security ULTRA PRO MAX
            (Request-Replay / Idempotency / CSRF-Rotation / Nonce / OTP / Race-Surface)
=======================================================================================
v24.0.0 FULL ULTRA PRO MAX (koi ek line ki bhi kami nahi - all to all
techniques: hacking hidden secrets + security bypasses + new & old methods).
Authorized security testing ONLY. Scope firewall + rate limiter + request
budget + evidence + checkpoint sab wasp_core se inherit hote hain, isliye
har census request scope-check, rate-limit aur budget ke andar hi jaati hai.

KYA KARTA HAI
  Replay flaws = "wahi request/token dobara bhejo aur system dobara accept
  kar le". Ye flaws automation se dhoondhna mushkil hai kyunki ek akela
  request bilkul valid lagti hai - flaw SIRF doosri baar bhejne par dikhta
  hai. P22 ka kaam: (1) REPLAY SURFACE ka poora census (kaunse endpoints
  one-time tokens / nonces / idempotency keys / OTP / signed URLs handle
  karte hain), (2) har surface par SINGLE-USE ka INERT differential (same
  canary token EXACTLY 2 SEQUENTIAL requests me bhejkar rotation/dedup/
  expiry behavior observe - yehi replay ka detection-only proof hai),
  (3) jo execution-class techniques hain (parallel race burst, token brute,
  real OTP reuse) unka DOCUMENTED-ONLY playbook + GATED micro-census
  (2-sequential HARD cap, GET-only, canary-only). -> 26 stages (A..Z):

    A. Replay surface discovery - 12-module feedforward (P20 flow_replay_pairs,
       P9 reset/otp, P10 sessions/csrf, P11 idor, P12 replay_pairs, P14
       csrf/state, P17 api-idempotency, P18 writable-mutations, P19 ws,
       P2 forms, P5 endpoints, P7 hints, P8 queue) + verb/token-param census
       + 26-path cold pool
    B. Baseline + WAF         - home marker + soft-404 + WAF fingerprint
    C. One-time token census  - CSRF/nonce/state/idempotency/workflow/OTP/
                                reset/signed token-shaped params + headers +
                                cookies + hidden-fields mining (names-only
                                redaction) + token-source census
    D. CSRF rotation census   - GATED replay_allow_csrf_probe: token fetch 2x
                                (rotated?), reuse 1st token GET differential
                                (single-use detection), double-submit cookie
                                census, Origin/Referer check census
    E. Idempotency census     - GATED replay_allow_idem_probe: SAME canary
                                Idempotency-Key 2 SEQUENTIAL requests HARD cap
                                + dedup-signal census (replayed/already-
                                processed/idempotent-replay markers)
    F. Nonce/state census     - GATED replay_allow_nonce_probe: canary state/
                                nonce reuse GET differential (OAuth state,
                                OIDC nonce, websocket challenge shapes)
    G. Reset-token surface    - names-only census + DOCUMENTED playbook
                                (canary reset token KABHI valid nahi hota -
                                koi real reset flow touch nahi)
    H. OTP surface census     - GATED replay_allow_otp_probe: OTP-shaped param
                                canary differential (weak zero/all-same digit
                                acceptance = validation weakness signal) +
                                documented replay playbook
    I. Session replay diff    - GATED replay_allow_session_probe: canary cookie
                                A/B differential (binding check) + fixation
                                surface census (bounded identities)
    J. Race surface           - 12 techniques DOCUMENTED-ONLY (single-packet
                                H2, parallel burst, last-write-wins...) +
                                idempotency-design census (NO parallel burst
                                KABHI - framework discipline)
    K. Bypass matrix v2       - 17 SECRET replay-bypass techniques (GATED
                                replay_allow_bypass2): token-in-GET, session-
                                unbound token, HPP duplicate-token, method-
                                override replay, content-type duplicate
                                shapes, dot-segment replay path, X-Original-URL
                                replay route, case/encoding token variants,
                                Origin-null, Referer-stripped, SameSite-Lax
                                GET-replay (documented), HEAD/307 replay
    L. Anti-automation census - rate-limit positive controls (429/Retry-After),
                                captcha shapes, bot-detection, lockout signals
                                (HARDENED evidence)
    M. Verb-replay census     - GATED replay_allow_verb_probe: OPTIONS/HEAD vs
                                GET variance + X-HTTP-Method-Override echo
                                census (6 override header shapes)
    N. Cache-replay census    - Cache-Control/Vary/Age/ETag on token-bearing
                                responses + token-in-cacheable-GET flag
    O. Signed/one-time URL    - GATED replay_allow_signed_probe: sig/expiry-
                                shaped params census + canary reuse GET
                                differential (nonce-missing = replayable)
    P. API idempotency design - P17 handoff: Idempotency-Key header support
                                shapes, RFC-draft patterns, mutation endpoint
                                census (GET-only observation)
    Q. GraphQL replay surface - P18 handoff: writable mutation NAMES census
                                (mutations NEVER sent - framework rule)
    R. WebSocket replay surf. - P19 handoff: ws endpoints + challenge/token
                                shaped subs census (frames NEVER)
    X. Token lifecycle census - mined tokens ka length/entropy/format buckets
                                (sha1-only, values KABHI store nahi) (v24)
    Y. Replay-resistance      - per-endpoint 8-point posture composite
       posture composite         (rotation/single-use/session-bound/origin/
                                rate/captcha/idempotency/cache) (v24)
    Z. Platform fingerprint   - auth/flow stack shapes + secrets/PII guard
                                (final REDACTION sweep) (v24)
    S. Cross-module chains    - CH01..CH24 replay kill-chains (P9..P20 handoffs)
    T. Verdict engine         - 6-class ladder (CONFIRMED/SUSPECTED/HARDENED/
                                BLOCKED/SKIPPED/NOISE) multi-signal
    U. Technique matrix       - 190+ rows x 18 families + CWE + MITRE map
    V. Reports/artifacts      - 48 artifacts: findings.json, REPLAY_FINDINGS.md,
                                REPLAY_MATRIX.txt, census JSONs, test-plan
                                (kill tests), remediation, exec summary
    W. Handoff & manifest     - feedforward (to_phase23/24/25/11/12/32),
                                MANIFEST, RWX-tree finalize

VERDICT LADDER (6-class, P12..P20-compatible)
  CONFIRMED   -> multi-signal proof (same canary token 2nd request ACCEPTED:
                 CSRF reuse 200, idempotency no-dedup, state reuse, OTP weak-
                 accept, signed URL replay; unbound session cookie diff)
  SUSPECTED   -> partial/single signal (rotation absent without reuse proof,
                 echo without acceptance)
  HARDENED    -> defense present (token rotated + reuse REJECTED 409/410,
                 idempotency dedup signal, one-time nonce consumed, binding
                 enforced, rate/captcha positive controls)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (replay 'state-trust' surface hai - P15..P20 jitni strict
discipline)
  * 100% INERT: koi REAL replay KABHI nahi hota. Har probe synthetic canary
    identifiers (waspP22 family) use karta hai jo server par EXIST NAHI
    karte - stale/invalid tokens hain, isliye koi valid state mutation
    possible hi nahi. Reuse proofs sirf validation-observable paths par
    (invalid canary token -> accept/reject behavior fingerprint).
  * 2-SEQUENTIAL HARD CAP: replay-detection census me same canary token
    MAXIMUM 2 SEQUENTIAL requests (detection ke liye yehi kaafi hai). PARALLEL
    BURST FORBIDDEN - koi race execution, koi flood, koi concurrency nahi
    (true race exploitation manual+RoE wave hai, playbook documented).
  * GET-ONLY MODULE: saare probes GET/OPTIONS/HEAD - koi POST/PUT/DELETE
    KABHI (module-wide assert). Mutations sirf NAMES census (P18 handoff).
  * ZERO EXTERNAL EGRESS: har HTTP probe scope-check se pehle blocked
    (wasp_core LAYER-4). canary TLD sirf .invalid.
  * REDACTION: response bodies store NAHI hote - sirf status/sha1/token-
    NAMES/booleans. Token VALUES ka sha1+entropy bucket store hota hai,
    value itself REDACTED (PII regex sweep har detail par).
  * allow_active=False -> PASSIVE mode: mining + offline hypotheses only
    (0 network probes).
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - save_json/save_text wrappers se guaranteed.
"""

import os
import re
import sys
import json
import time
import copy
import math
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
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 22")
    sys.exit(1)

NAME = "replay"
PHASE = "22-replay"
PLAN_VERSION = "24.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    # ---- caps ----
    "replay_paths_cap": 40,        # kitne ranked targets census me jaayenge
    "replay_probe_cap": 24,        # per-stage probe budget
    "replay_param_cap": 30,        # token-param census cap
    "replay_token_cap": 40,        # mined token records cap (sha1-only)
    "replay_bypass2_cap": 18,      # bypass2 shapes per target
    "replay_cold_paths": 26,       # cold-start pool size
    "replay_depth": 3,             # discovery link-follow depth
    "replay_signed_cap": 10,       # signed-url census targets
    "replay_verb_cap": 8,          # verb-census targets
    "replay_session_ctx": 2,       # identity contexts for session diff (max 2)
    # ---- RoE GATES (sab default OFF - destructive/replay-class probes) ----
    "replay_allow_csrf_probe": False,     # GATE: token rotation + reuse differential
    "replay_allow_idem_probe": False,     # GATE: idempotency-key dedup census
    "replay_allow_nonce_probe": False,    # GATE: state/nonce reuse differential
    "replay_allow_otp_probe": False,      # GATE: OTP canary differential census
    "replay_allow_session_probe": False,  # GATE: session binding A/B canary cookie differential
    "replay_allow_bypass2": False,        # GATE: 17-secret replay-bypass shapes
    "replay_allow_verb_probe": False,     # GATE: verb/method-override echo census
    "replay_allow_signed_probe": False,   # GATE: signed/one-time URL reuse differential
}

# RoE gate registry (CLI/report me use hota hai)
ROE_GATES = [
    ("replay_allow_csrf_probe",    "CSRF token rotation + reuse GET differential"),
    ("replay_allow_idem_probe",    "idempotency-key dedup census (2-sequential cap)"),
    ("replay_allow_nonce_probe",   "OAuth state / nonce reuse GET differential"),
    ("replay_allow_otp_probe",     "OTP canary validation differential"),
    ("replay_allow_session_probe", "session binding A/B canary cookie differential"),
    ("replay_allow_bypass2",       "17-secret replay-bypass shape matrix"),
    ("replay_allow_verb_probe",    "verb/method-override echo census"),
    ("replay_allow_signed_probe",  "signed/one-time URL reuse differential"),
]

CANARY_FAMILY = "waspP22"

# ---------------------------------------------------------------------------
# REPLAY-SHAPED PATH POOL (cold-start discovery - replay-class URL shapes)
# ---------------------------------------------------------------------------
COLD_PATHS = [
    "/api/pay", "/api/order", "/api/checkout", "/checkout", "/order", "/pay",
    "/oauth/authorize", "/oauth/token", "/auth/authorize", "/sso/login",
    "/reset", "/reset-password", "/password/reset", "/forgot-password",
    "/verify-otp", "/otp", "/2fa", "/mfa", "/verify", "/confirm",
    "/redeem", "/coupon", "/voucher", "/gift-card", "/api/redeem",
    "/transfer", "/withdraw", "/refund", "/approve", "/invoice",
    "/register", "/signup", "/subscribe", "/callback", "/webhook",
    "/token", "/session", "/logout", "/api/confirm-email",
]

# replay-verb shapes (endpoint URL path me ye words = state/entitlement verb)
REPLAY_VERB_RX = re.compile(
    r"(?i)(pay|order|checkout|redeem|coupon|voucher|gift|transfer|withdraw|"
    r"refund|approve|confirm|verify|otp|reset|authorize|token|callback|"
    r"webhook|subscribe|register|activate|claim|exchange|consume|invoice|"
    r"enroll|issue|grant|bind|revoke)")

# token-shaped PARAM names (one-time / anti-replay family)
TOKEN_PARAM_RX = [
    ("csrf",        re.compile(r"(?i)^(csrf|_csrf|csrf[-_]?token|authenticity[-_]?token|xsrf[-_]?token|_token|requesttoken|csrfmiddlewaretoken)$")),
    ("nonce",       re.compile(r"(?i)(nonce)$")),
    ("state",       re.compile(r"(?i)^state$|^(oauth|oidc)[-_]?state$")),
    ("idempotency", re.compile(r"(?i)(idempoten|request[-_]?id|dedup|client[-_]?token|operation[-_]?id)")),
    ("otp",         re.compile(r"(?i)^(otp|otp[-_]?code|one[-_]?time|totp|verification[-_]?code|verify[-_]?code|code)$")),
    ("reset",       re.compile(r"(?i)(reset[-_]?token|password[-_]?token|recovery[-_]?token|activation|activat)")),
    ("workflow",    re.compile(r"(?i)(flow[-_]?token|workflow|transition|step[-_]?token|action[-_]?token)")),
    ("signed",      re.compile(r"(?i)(signature|sig|hmac|expires|expiry|exp|signed[-_]?at)$")),
    ("challenge",   re.compile(r"(?i)(challenge|captcha[-_]?token|anti[-_]?csrf|anti[-_]?replay)")),
    ("ticket",      re.compile(r"(?i)(ticket|cas|jwt|assertion|saml)")),
]

# token-shaped HEADER names
TOKEN_HEADER_RX = re.compile(
    r"(?i)^(idempotency[-_]?key|x[-_]?idempotency[-_]?key|x[-_]?csrf[-_]?token|"
    r"x[-_]?request[-_]?id|x[-_]?nonce|x[-_]?signature|x[-_]?hub[-_]?signature|"
    r"x[-_]?otp|x[-_]?one[-_]?time|x[-_]?flow[-_]?token)$")

# token-bearing COOKIE names
TOKEN_COOKIE_RX = re.compile(
    r"(?i)(csrf|xsrf|nonce|state|idempoten|session|sid|challenge|double[-_]?submit)")

# replayed / dedup SIGNAL body+header shapes (idempotency census ka core)
REPLAYED_SIGNAL_RX = re.compile(
    r"(?i)(already[-_ ]?(processed|exists|used|received|submitted)|"
    r"(duplicate|replay(ed)?)[-_ ]?(request|transaction|detect|error)?|"
    r"idempotent|dedup|single[-_ ]?use|one[-_ ]?time[-_ ]?(token|use)|"
    r"state[-_ ]?(expired|used|consumed)|nonce[-_ ]?(used|expired)|"
    r"token[-_ ]?(expired|used|invalid|consumed))")

ROTATION_REJECT_STATUS = (403, 409, 410, 422)   # reuse-reject class statuses


# ===========================================================================
# SEVERITY HINTS (v24) - key -> (severity, cvss_hint, why_it_matters)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / surface ----
    "replay_endpoint_live":       ("info", 0.0, "Replay-class endpoint live mila "
        "(one-time token / idempotency / signed-url verb shape) - poora P22 "
        "engine ab is surface par chalega (core targeting aid)."),
    "replay_candidate_path":      ("info", 0.0, "Replay candidate path mined - "
        "ranking ke through census me jaayega."),
    "replay_token_param":         ("low", 3.3, "One-time/anti-replay token-shaped "
        "param census (csrf/nonce/state/otp/reset) - replay-surface enumeration "
        "(values REDACTED, sirf names)."),
    "replay_token_header":        ("low", 3.1, "Token-shaped header census "
        "(Idempotency-Key / X-Nonce family) - API replay-surface flag."),
    "replay_token_cookie":        ("low", 3.2, "Token-bearing cookie census "
        "(csrf/session/double-submit shapes) - client-trust replay aid."),
    # ---- csrf rotation (stage D) ----
    "replay_csrf_reuse_confirmed": ("critical", 8.8, "Same canary CSRF token "
        "2nd request ACCEPT hua (no rotation, no single-use) - CSRF protection "
        "bypass-replay primitive CONFIRMED (CWE-613; GET-only canary differential "
        "- koi state change nahi)."),
    "replay_csrf_reuse_suspected": ("high", 7.2, "CSRF token rotation absent "
        "(2 fetches same token sha1) reuse-proof pending - single-use gap "
        "suspect (CWE-613)."),
    "replay_csrf_rotated":        ("info", 0.0, "CSRF token har fetch par rotate "
        "hota hai (positive control) - rotation census HARDENED evidence."),
    "replay_csrf_reuse_rejected": ("info", 0.0, "Stale token reuse REJECT hua "
        "(single-use enforced) - HARDENED positive control."),
    "replay_csrf_double_submit":  ("low", 3.6, "Double-submit cookie shape "
        "census (cookie+param pair) - client-trust binding review aid."),
    # ---- idempotency (stage E) ----
    "replay_idem_missing_confirmed": ("critical", 8.5, "Same canary Idempotency-Key "
        "2nd request bina dedup-signal ACCEPT hua - server-side idempotency "
        "missing (CWE-294/CWE-837; duplicate-submission replay primitive "
        "CONFIRMED; canary object never exists)."),
    "replay_idem_dedup_present":  ("info", 0.0, "Idempotency dedup-signal mila "
        "(replayed/already-processed shape) - HARDENED positive control."),
    "replay_idem_key_echo":       ("low", 3.4, "Idempotency-key param/header echo "
        "census - client-supplied dedup-key surface (binding review aid)."),
    # ---- nonce/state (stage F) ----
    "replay_state_reuse_confirmed": ("high", 7.8, "OAuth/OIDC state canary REUSE "
        "accept hua (2nd request no consumption) - CSRF-state single-use gap "
        "(CWE-352/CWE-294; session-fixation relay aid)."),
    "replay_state_consumed":      ("info", 0.0, "State/nonce 1st use ke baad "
        "CONSUME ho gaya (one-time enforced) - HARDENED positive control."),
    # ---- reset (stage G) ----
    "replay_reset_surface":       ("low", 4.3, "Password-reset token surface "
        "census (names-only) - reset-token replay manual-review aid "
        "(CWE-640 aid; koi real token use nahi)."),
    # ---- otp (stage H) ----
    "replay_otp_weak_accept":     ("critical", 8.9, "OTP-shaped canary "
        "(all-zero/all-same digits) ACCEPT hua - OTP validation weakness "
        "(CWE-778/CWE-307 aid; canary code never valid)."),
    "replay_otp_reject_ok":       ("info", 0.0, "OTP canary REJECT hua - "
        "validation positive control (HARDENED evidence)."),
    "replay_otp_surface":         ("low", 4.1, "OTP-shaped param surface census "
        "- OTP replay/throttle manual-review aid (CWE-307 aid)."),
    # ---- session (stage I) ----
    "replay_session_unbound":     ("high", 7.6, "Canary session cookie A/B "
        "differential me binding absent (dono context same response) - "
        "session-replay across contexts primitive (CWE-613 aid)."),
    "replay_session_bound":       ("info", 0.0, "Session context binding enforced "
        "(B-context rejected) - HARDENED positive control."),
    "replay_fixation_surface":    ("medium", 5.4, "Session-id accept-shape census "
        "(token-in-url/param shapes) - fixation/replay manual-review aid "
        "(CWE-384)."),
    # ---- race (stage J) ----
    "replay_race_documented":     ("medium", 6.8, "Race-condition technique "
        "surface documented (12 playbook rows; execution FORBIDDEN-AUTO) - "
        "manual RoE wave aid (CWE-362)."),
    "replay_idem_design_present": ("info", 0.0, "Idempotency-design positive "
        "control census (key/support shape) - HARDENED evidence."),
    # ---- bypass2 (stage K) ----
    "replay_bypass2_accepted":    ("high", 7.5, "Replay-bypass shape ACCEPT hua "
        "(17-secret matrix) - token-context validation gap (CWE-20/CWE-294; "
        "GET-only canary shapes; CONFIRMED bypass surface)."),
    "replay_bypass2_blocked":     ("info", 0.0, "Replay-bypass shapes REJECT hue "
        "- token-context validation enforced (HARDENED)."),
    # ---- anti-automation (stage L) ----
    "replay_rate_limit_present":  ("info", 0.0, "Rate-limit positive control "
        "(429/Retry-After) mila - HARDENED evidence (replay-throttle)."),
    "replay_rate_limit_absent":   ("medium", 5.8, "Bounded canary burst par bhi "
        "koi rate/throttle signal nahi - replay-throttle absent signal "
        "(CWE-770 aid; bounded census, koi flood nahi)."),
    "replay_captcha_present":     ("info", 0.0, "Captcha/bot-challenge shape "
        "census - HARDENED evidence."),
    # ---- verb (stage M) ----
    "replay_method_override_echo": ("medium", 5.9, "X-HTTP-Method-Override-family "
        "header ECHO hua - verb-replay surface (method-enforcement review aid; "
        "CWE-650 aid)."),
    "replay_verb_variance":       ("low", 4.2, "OPTIONS/HEAD/GET variance census "
        "- verb-replay mapping aid."),
    # ---- cache (stage N) ----
    "replay_cacheable_token":     ("high", 7.0, "Token-bearing response CACHEABLE "
        "(public/no-store absent) - token-in-cache replay primitive "
        "(CWE-524/CWE-525 aid; shared-cache review)."),
    "replay_cache_no_store":      ("info", 0.0, "no-store private-token response "
        "par enforced - HARDENED cache control."),
    # ---- signed url (stage O) ----
    "replay_signed_url_replayable": ("critical", 8.2, "Signed/one-time URL canary "
        "REUSE accept hua (no nonce/no consumption) - signature-replay "
        "primitive CONFIRMED (CWE-294/CWE-347 aid; canary sig never valid "
        "state me)."),
    "replay_signed_one_time":     ("info", 0.0, "Signed URL one-time enforced "
        "(2nd use 410/expired) - HARDENED positive control."),
    "replay_signed_param_surface": ("low", 4.0, "Signature/expiry-shaped param "
        "census - signed-url surface enumeration."),
    # ---- api / gql / ws ----
    "replay_api_idem_header_absent": ("medium", 5.6, "Mutation-shaped API endpoint "
        "par Idempotency-Key header support absent (RFC-draft shapes) - "
        "duplicate-submission aid (CWE-294 aid)."),
    "replay_gql_mutation_surface": ("low", 4.5, "Writable GraphQL mutation NAMES "
        "census (P18 handoff; mutations NEVER sent) - replay-targeting aid."),
    "replay_ws_replay_surface":   ("low", 4.4, "WebSocket replay-surface census "
        "(challenge/token-shaped subs; frames NEVER) - ws-replay manual aid."),
    # ---- v24 extras ----
    "replay_token_weak_entropy":  ("medium", 5.7, "Mined token sha1-bucket me "
        "low-entropy format shape (short/numeric-only bucket) - token "
        "guessability review aid (CWE-330 aid; values REDACTED)."),
    "replay_posture_weak":        ("high", 7.3, "Replay-resistance posture "
        "composite WEAK (<3/8 controls) - per-endpoint hardening priority aid."),
    "replay_posture_strong":      ("info", 0.0, "Replay-resistance posture STRONG "
        "(>=6/8 controls) - HARDENED composite evidence."),
    "replay_platform_fp":         ("info", 0.0, "Auth/flow stack platform shape "
        "census - framework-specific replay checklist aid."),
    "replay_secret_guard_hit":    ("high", 7.7, "Final REDACTION sweep me secret/PII "
        "shape census artifact par - guard ne sweep kiya (CWE-200 aid)."),
}


def classify_severity(key):
    """SEVERITY_HINTS lookup (default info/0.0)."""
    sev, cvss, why = SEVERITY_HINTS.get(
        key, ("info", 0.0, "Replay census row - manual review aid."))
    return sev, cvss, why


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Findings:
    """P22 findings collector (P12..P20-compatible shape)."""

    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "RP-%03d" % (len(self.items) + 1), "key": key,
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
# PII REDACT (framework rule - P20 pattern)
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
# CANARY + INERT ENFORCEMENT (P15..P20 pattern - hard rules)
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    """Synthetic marker ids - waspP22 family (real ids KABHI nahi)."""
    return "%s%s%s" % (CANARY_FAMILY, tag, rand_str(6))


# GET-ONLY MODULE ENFORCEMENT: P22 me koi state-changing method KABHI nahi
_ALLOWED_PROBE_METHODS = ("GET", "HEAD", "OPTIONS")


def assert_inert_method(method):
    if (method or "GET").upper() not in _ALLOWED_PROBE_METHODS:
        raise RuntimeError(
            "P22 INERT violation: method '%s' allowed nahi hai "
            "(GET/HEAD/OPTIONS only)" % method)
    return True


def probe(http, method, url, **kw):
    """INERT probe wrapper: method-guard + scope-firewall (core layer) +
    evidence log. Har P22 network call ISI se jaati hai."""
    assert_inert_method(method)
    kw.pop("data", None)          # GET-ONLY: body KABHI nahi
    kw.pop("body", None)
    r = http.request(method, url, **kw)
    return r


# ---------------------------------------------------------------------------
# TOLERANT READERS (feedforward/artifact mining - P20 pattern)
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
# FORM / TOKEN MINER (hidden fields, meta, cookies, headers)
# ---------------------------------------------------------------------------
_FORM_RX = re.compile(r"(?is)<form\b[^>]*>(.*?)</form>")
_INPUT_TAG_RX = re.compile(r"(?is)<input\b[^>]*>")
_META_RX = re.compile(r"(?is)<meta\b[^>]*name\s*=\s*['\"]([^'\"]+)['\"][^>]*>")
_LINK_RX = re.compile(r"(?is)(?:href|action|src)\s*=\s*['\"]([^'\"#]+)['\"]")


def mine_hidden_fields(html):
    """Form hidden fields -> [(name, value_len, form_action)] (values REDACTED)."""
    out = []
    for fbody in _FORM_RX.findall(html or ""):
        action = ""
        m = re.search(r"(?is)action\s*=\s*['\"]([^'\"]+)['\"]", fbody[:400])
        if m:
            action = m.group(1)
        for tag in _INPUT_TAG_RX.findall(fbody):
            if not re.search(r"(?is)type\s*=\s*['\"]hidden['\"]", tag):
                continue
            mn = re.search(r"(?is)name\s*=\s*['\"]([^'\"]+)['\"]", tag)
            if not mn:
                continue
            mv = re.search(r"(?is)value\s*=\s*['\"]([^'\"]*)['\"]", tag)
            val = mv.group(1) if mv else ""
            out.append({"name": mn.group(1)[:80], "value_len": len(val or ""),
                        "action": action[:120],
                        "value_sha1": hashlib.sha1(
                            (val or "").encode("utf-8", "ignore")).hexdigest()[:12]
                        if val else ""})
    return out


def token_param_kind(name):
    """Param-name -> token family (ya None). TOKEN_PARAM_RX table lookup."""
    n = (name or "").strip()
    for kind, rx in TOKEN_PARAM_RX:
        if rx.search(n):
            return kind
    return None


def token_kind_of_header(name):
    return "header" if TOKEN_HEADER_RX.match(name or "") else None


def token_kind_of_cookie(name):
    return "cookie" if TOKEN_COOKIE_RX.search(name or "") else None


def entropy_bucket(value):
    """Token value -> (len_bucket, entropy, format) - value KABHI store nahi."""
    v = value or ""
    ent = shannon_entropy(v) if callable(shannon_entropy) else 0.0
    fmt = "digits" if re.fullmatch(r"\d+", v or "") else (
        "hex" if re.fullmatch(r"(?i)[0-9a-f]+", v or "") else
        "b64url" if re.fullmatch(r"[A-Za-z0-9_-]+", v or "") else
        "jwt-like" if v.startswith("eyJ") else "mixed")
    ln = len(v)
    lb = "<=16" if ln <= 16 else "17-32" if ln <= 32 else "33-64" if ln <= 64 else ">64"
    return {"len_bucket": lb, "entropy": round(ent, 2), "format": fmt}


# ---------------------------------------------------------------------------
# REPLAY SIGNAL HELPERS
# ---------------------------------------------------------------------------
def looks_replayed_signal(r):
    """Resp me dedup/replayed signal? (headers + body-shape, REDACTED)."""
    if r is None or r.error:
        return False
    for hv in (r.headers or {}).keys():
        if REPLAYED_SIGNAL_RX.search(hv or ""):
            return True
    for hv in (r.headers or {}).values():
        if isinstance(hv, str) and REPLAYED_SIGNAL_RX.search(hv[:300] or ""):
            return True
    body = (r.text or "")[:3000]
    if REPLAYED_SIGNAL_RX.search(body):
        return True
    return False


def _prioritize(targets, rx):
    """Relevant-shaped URLs pehle (census caps ke andar max signal)."""
    try:
        return sorted([t for t in (targets or []) if isinstance(t, str)],
                      key=lambda u: (0 if rx.search(u) else 1, u))
    except Exception:
        return [t for t in (targets or []) if isinstance(t, str)]


def same_status_class(a, b):
    ca = (a or 0) // 100
    cb = (b or 0) // 100
    return ca == cb and ca > 0


# ===========================================================================
# STAGE A - REPLAY SURFACE DISCOVERY (12-module feedforward + miners + cold)
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
    """Kisi bhi mod ki routing me to_phase22* keys -> URL pool."""
    urls = []
    for mod in mods:
        d = _read_json_tolerant(_artifact(base_dir, mod, "feedforward.json"))
        if not isinstance(d, dict):
            continue
        routing = d.get("routing") or {}
        for rk, val in routing.items():
            if not str(rk).lower().startswith("to_phase22"):
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


def discover_replay_surface(ctx, scope, conf):
    """Stage A: 12-module feedforward + form/url mining + cold pool ->
    ranked replay targets (verb-shape scoring)."""
    base_dir = ctx.get("base_dir")
    sources, urls = [], set()

    # 1) feedforward routing (to_phase22* keys - P12/P20 documented seeds)
    ff = _ff_any_pairs(base_dir, ["understand", "passive", "active", "content",
                                  "tech", "js", "surface", "auth", "sessions",
                                  "access", "inject", "xss", "client", "ssrf",
                                  "files", "api", "graphql", "ws", "logic"])
    for u in ff:
        if u and not u.startswith("waspP"):
            urls.add(u)
    if ff:
        sources.append("feedforward.to_phase22*=%d" % len(ff))

    # 2) P20 flow-replay pairs (documented handoff)
    p20 = _ff_pairs(base_dir, "logic", "to_phase22_replay")
    if p20:
        sources.append("p20.flow_replay=%d" % len(p20))
        for u in p20:
            if not u.startswith("waspP"):
                urls.add(u)

    # 3) P12 replay pairs
    p12 = _ff_pairs(base_dir, "inject", "to_phase22_replay")
    if p12:
        sources.append("p12.replay_pairs=%d" % len(p12))
        for u in p12:
            if not u.startswith("waspP"):
                urls.add(u)

    # 4) artifact mining (endpoints/forms/api)
    mined = _mine_urls_from_artifacts(
        base_dir,
        ["understand", "content", "js", "api", "auth", "sessions", "surface"],
        ["endpoints.txt", "api_endpoints.txt", "all_found.txt", "forms.json",
         "api_surface.json", "auth_endpoints.txt", "js_urls.txt"], cap=300)
    if mined:
        sources.append("artifacts=%d" % len(mined))
        for u in mined:
            if u.startswith("http") or u.startswith("/"):
                urls.add(u)

    # 5) scope targets base
    for t in scope.targets:
        urls.add(t)

    # 6) cold pool (replay-shaped paths)
    cold = []
    if urls:
        base = sorted(urls)[0]
        base = base.split("?")[0].rstrip("/")
        for cp in COLD_PATHS[:max(1, int(conf.get("replay_cold_paths", 26)))]:
            cold.append(base + cp)
        sources.append("cold_pool=%d" % len(cold))
        for c in cold:
            urls.add(c)

    # normalize -> same-origin URLs only (scope firewall double-guard)
    origin_hosts = set()
    for t in scope.targets:
        h = host_of(t)
        if h:
            origin_hosts.add(h.lower())
    pool = []
    for u in sorted(urls):
        if u.startswith("http"):
            h = (host_of(u) or "").lower()
            if h and h in origin_hosts:
                pool.append(u)
        elif u.startswith("/"):
            b = sorted([t for t in scope.targets if t.startswith("http")])
            if b:
                pool.append(b[0].rstrip("/") + u)
    pool = sorted(set(pool))[:max(10, int(conf.get("replay_paths_cap", 40)) * 3)]

    # rank: verb-shape + token-shape scoring
    ranked = []
    for u in pool:
        score = 0.0
        kinds = []
        if REPLAY_VERB_RX.search(u):
            score += 3.0
            kinds.append("verb")
        parsed = urllib.parse.urlsplit(u)
        q = urllib.parse.parse_qs(parsed.query or "")
        for k in q.keys():
            kind = token_param_kind(k)
            if kind:
                score += 2.5
                kinds.append("tok:" + kind)
        if re.search(r"(?i)(api/|/api$)", u):
            score += 1.0
            kinds.append("api")
        if any(x in u for x in ("/oauth", "/sso", "/saml", "/openid")):
            score += 2.0
            kinds.append("sso")
        if score > 0:
            ranked.append({"url": u, "score": round(score, 2), "kinds": kinds,
                           "sources": list(sources)})
    ranked.sort(key=lambda x: -x["score"])
    ranked = ranked[:max(4, int(conf.get("replay_paths_cap", 40)))]

    return {"ranked": ranked, "targets": [r["url"] for r in ranked],
            "sources": sources, "base_url": (scope.targets or [""])[0],
            "mined_params": {}, "cold": cold[:10]}


# ===========================================================================
# STAGE B - BASELINE + WAF + SOFT-404 (P12..P20 pattern)
# ===========================================================================
def baseline_and_waf(http, targets, conf):
    """Per-target: GET baseline (2x) + soft-404 template + WAF fingerprint."""
    out_rows, waf_rows = [], []
    tb = max(1, int(conf.get("replay_probe_cap", 24)))
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
                             "marker": ("waspP22-home" if "waspp22" in
                                        (r1.text or "")[:2000].lower() else "")})
            waf_rows.append({"url": t, "waf": waf})
        except Exception as e:
            out_rows.append({"url": t, "error": "%s: %s" % (type(e).__name__, e)})
            waf_rows.append({"url": t, "waf": []})
        if interrupted():
            break
    return {"rows": out_rows, "waf": waf_rows}


# ===========================================================================
# STAGE C - ONE-TIME TOKEN CENSUS (params/headers/cookies/hidden-fields)
# ===========================================================================
def token_census(http, targets, conf):
    """Token-shaped param/header/cookie/hidden-field census (NAMES-only).

    Mined token VALUES ka sirf sha1+entropy bucket store hota hai -
    value itself REDACTED (framework rule)."""
    rows, param_names = [], set()
    cap = max(4, int(conf.get("replay_paths_cap", 40)))
    tcap = max(4, int(conf.get("replay_token_cap", 40)))
    for t in targets[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:120]})
            continue
        if r.error or is_soft404(r, None):
            rows.append({"url": t, "status": r.status, "noise": True})
            continue
        row = {"url": t, "status": r.status, "tokens": []}
        # query params
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(t).query or "")
        for k, vs in q.items():
            kind = token_param_kind(k)
            if kind:
                eb = entropy_bucket(vs[0] if vs else "")
                row["tokens"].append({"kind": kind, "where": "query",
                                      "name": k[:60], **eb})
                param_names.add(k)
        # headers
        for hk in (r.headers or {}).keys():
            kind = token_kind_of_header(hk)
            if kind:
                row["tokens"].append({"kind": "header", "where": "response-header",
                                      "name": hk[:60]})
        # set-cookies
        for ck in (r.set_cookies or []):
            name = ck if isinstance(ck, str) else (ck.get("name") or "")
            kind = token_kind_of_cookie(name)
            if kind:
                row["tokens"].append({"kind": kind, "where": "set-cookie",
                                      "name": name[:60]})
        # hidden fields
        for hf in mine_hidden_fields(r.text)[:12]:
            kind = token_param_kind(hf["name"])
            if kind:
                vlen = hf.get("value_len", 0)
                lb = "<=16" if vlen <= 16 else "17-32" if vlen <= 32 else \
                    "33-64" if vlen <= 64 else ">64"
                row["tokens"].append({"kind": kind, "where": "hidden-field",
                                      "name": hf["name"][:60],
                                      "sha1_12": hf["value_sha1"],
                                      "len_bucket": lb})
        if row["tokens"]:
            rows.append(row)
        if interrupted():
            break
    total = sum(len(r.get("tokens") or []) for r in rows)
    return {"rows": rows[:tcap], "total": total, "param_names": sorted(param_names)}


def token_records_from_census(tc_rows):
    """Census rows -> flat token records (kind/name/url/sha1/buckets)."""
    recs = []
    for row in tc_rows or []:
        for tk in row.get("tokens") or []:
            recs.append({"url": row.get("url"), "kind": tk.get("kind"),
                         "where": tk.get("where"), "name": tk.get("name"),
                         "sha1_12": tk.get("sha1_12", ""),
                         "len_bucket": tk.get("len_bucket", "?"),
                         "entropy": tk.get("entropy"),
                         "format": tk.get("format", "mixed")})
    return recs


# ===========================================================================
# STAGE D - CSRF ROTATION + REUSE CENSUS (GATED replay_allow_csrf_probe)
# ===========================================================================
def csrf_rotation_census(http, targets, conf):
    """GATED replay_allow_csrf_probe.

    Per token-source target (2-SEQUENTIAL HARD cap per endpoint):
      1. GET page        -> token T1 (mined, IN-MEMORY only)
      2. GET page again  -> token T2  (rotation? sha1(T1) != sha1(T2))
      3. GET consumer?<mined-name>=<CANARY-token>  -> validation shape
    Reuse probe CANARY token use karta hai (server par EXIST nahi karta):
    accept = token-validation absent (CONFIRMED gap); reject = validation
    present (single-use proof manual+RoE documented). Koi real token
    network par dobara nahi jaata - 100% INERT."""
    gate = bool(conf.get("replay_allow_csrf_probe", False))
    result = {"gate": "replay_allow_csrf_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual rotation/reuse wave documented "
              "(REPLAY_TEST_PLAN.md KD-01)"}
    if not gate:
        return result
    pcap = max(2, int(conf.get("replay_probe_cap", 24)) // 2)
    tok_rows = [r for r in (targets or []) if r.get("tokens")]
    tested = 0
    for row in tok_rows[:pcap]:
        if tested >= pcap or interrupted():
            break
        url = row.get("url")
        if not url:
            continue
        try:
            r1 = probe(http, "GET", url, allow_redirects=False)
            t1 = _first_token_info(r1)
            r2 = probe(http, "GET", url, allow_redirects=False)
            t2 = _first_token_info(r2)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:120]})
            continue
        if not t1 or not t2:
            result["rows"].append({"url": url, "tokens_found": bool(t1 or t2),
                                   "note": "no minable token (client-rendered?)"})
            continue
        tested += 1
        p1name, p1val = t1
        p2name, p2val = t2
        rotated = hashlib.sha1(p1val.encode("utf-8", "ignore")).hexdigest() != \
            hashlib.sha1(p2val.encode("utf-8", "ignore")).hexdigest()
        rrow = {"url": url, "param": p1name[:40], "rotated": rotated,
                "t1_sha1": hashlib.sha1(p1val.encode(
                    "utf-8", "ignore")).hexdigest()[:12],
                "t2_sha1": hashlib.sha1(p2val.encode(
                    "utf-8", "ignore")).hexdigest()[:12]}
        # reuse differential: consumer GET with CANARY value (never the real token)
        reuse_url = _token_consumer_url(url, p1name, _canary("csrf"))
        if reuse_url:
            try:
                rr = probe(http, "GET", reuse_url, allow_redirects=False)
                rrow["reuse"] = {"status": rr.status,
                                 "accepted": bool(rr.ok() and not is_soft404(rr, None)),
                                 "reject_class": rr.status in ROTATION_REJECT_STATUS,
                                 "signal": looks_replayed_signal(rr)}
            except Exception as e:
                rrow["reuse"] = {"error": str(e)[:120]}
        result["rows"].append(rrow)
    return result


def _mine_hidden_values(html):
    """(name, value) IN-MEMORY ONLY - rotation sha1-compare ke liye.
    Value kabhi disk/evidence par nahi jaati (framework REDACTION rule)."""
    out = []
    for fbody in _FORM_RX.findall(html or ""):
        for tag in _INPUT_TAG_RX.findall(fbody):
            mn = re.search(r"(?is)name\s*=\s*['\"]([^'\"]+)['\"]", tag)
            mv = re.search(r"(?is)value\s*=\s*['\"]([^'\"]*)['\"]", tag)
            if mn and mv and mv.group(1) and token_param_kind(mn.group(1)) and \
                    re.search(r"(?is)type\s*=\s*['\"]hidden['\"]", tag):
                out.append((mn.group(1), mv.group(1)))
    return out


def _first_token_info(r):
    """Resp text se pehla (param_name, token_value) - IN-MEMORY ONLY."""
    for name, val in _mine_hidden_values(r.text or ""):
        return (name, val)
    return None


def _token_consumer_url(url, param_name, canary_value):
    """Same-origin consumer-shape GET URL: url?<mined-name>=<CANARY>."""
    if not canary_value:
        return ""
    sep = "&" if "?" in url else "?"
    return "%s%s%s=%s" % (url, sep, urllib.parse.quote(param_name or "token"),
                           urllib.parse.quote(str(canary_value)[:140]))


# ===========================================================================
# STAGE E - IDEMPOTENCY-KEY DEDUP CENSUS (GATED replay_allow_idem_probe)
# ===========================================================================
def idempotency_census(http, targets, conf):
    """GATED replay_allow_idem_probe.

    SAME canary Idempotency-Key header, EXACTLY 2 SEQUENTIAL GETs per
    endpoint (HARD cap) -> dedup-signal census (2nd response me
    replayed/already-processed shape?). Idempotency-Key param variant bhi
    census hota hai (?idempotency_key=). Koi transaction nahi - canary key
    server par EXIST nahi karta."""
    gate = bool(conf.get("replay_allow_idem_probe", False))
    result = {"gate": "replay_allow_idem_probe=%s" % gate, "rows": [],
              "hard_cap": "2 sequential per endpoint (module-wide)",
              "skipped_note": "" if gate else
              "RoE gate OFF - manual idempotency wave documented (KD-02)"}
    if not gate:
        return result
    pcap = max(2, int(conf.get("replay_probe_cap", 24)) // 2)
    verb_urls = _prioritize(targets, re.compile(r"/api/", re.I))
    tested = 0
    for url in verb_urls[:pcap * 2]:
        if tested >= pcap or interrupted():
            break
        key = _canary("idem")
        for mode in ("header", "param"):
            if tested >= pcap or interrupted():
                break
            try:
                if mode == "header":
                    r1 = probe(http, "GET", url, allow_redirects=False,
                               headers={"Idempotency-Key": key})
                    r2 = probe(http, "GET", url, allow_redirects=False,
                               headers={"Idempotency-Key": key})
                else:
                    sep = "&" if "?" in url else "?"
                    u2 = "%s%sidempotency_key=%s" % (url, sep, key)
                    r1 = probe(http, "GET", u2, allow_redirects=False)
                    r2 = probe(http, "GET", u2, allow_redirects=False)
            except Exception as e:
                result["rows"].append({"url": url, "mode": mode,
                                       "error": str(e)[:120]})
                continue
            tested += 1
            s1 = looks_replayed_signal(r1)
            s2 = looks_replayed_signal(r2)
            status_drift = (r1.status != r2.status)
            result["rows"].append({
                "url": url, "mode": mode, "key_sha1":
                hashlib.sha1(key.encode()).hexdigest()[:12],
                "status1": r1.status, "status2": r2.status,
                "signal1": s1, "signal2": s2, "status_drift": status_drift,
                "dedup": bool(s2 or status_drift),
                "echo": ("idempotency" in (r2.text or "")[:3000].lower())})
    return result


# ===========================================================================
# STAGE F - NONCE / STATE REUSE CENSUS (GATED replay_allow_nonce_probe)
# ===========================================================================
def nonce_state_census(http, targets, conf):
    """GATED replay_allow_nonce_probe.

    OAuth/OIDC state + challenge nonce single-use census: canary state
    value, EXACTLY 2 SEQUENTIAL GETs -> 2nd accepted? (consumption check).
    Canary state server-par-exist nahi karta; koi real OAuth flow nahi."""
    gate = bool(conf.get("replay_allow_nonce_probe", False))
    result = {"gate": "replay_allow_nonce_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual nonce/state wave documented (KD-03)"}
    if not gate:
        return result
    pcap = max(2, int(conf.get("replay_probe_cap", 24)) // 3)
    sso_urls = [t for t in (targets or []) if isinstance(t, str) and
                (REPLAY_VERB_RX.search(t) or "/oauth" in t or "authorize" in t)]
    if not sso_urls:
        sso_urls = list(targets or [])[:pcap]
    tested = 0
    for url in sso_urls[:pcap * 2]:
        if tested >= pcap or interrupted():
            break
        state = _canary("st")
        sep = "&" if "?" in url else "?"
        u = "%s%sstate=%s&nonce=%s" % (url, sep, state, _canary("n"))
        try:
            r1 = probe(http, "GET", u, allow_redirects=False)
            r2 = probe(http, "GET", u, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:120]})
            continue
        tested += 1
        consumed = (r2.status in ROTATION_REJECT_STATUS) or \
            looks_replayed_signal(r2)
        result["rows"].append({
            "url": url, "state_sha1":
            hashlib.sha1(state.encode()).hexdigest()[:12],
            "status1": r1.status, "status2": r2.status,
            "consumed": consumed,
            "reuse_accepted": bool(r1.ok() and r2.ok() and not consumed)})
    return result


# ===========================================================================
# STAGE G - RESET-TOKEN SURFACE (names-only census + documented playbook)
# ===========================================================================
RESET_PATHS = ["/reset", "/reset-password", "/password/reset",
               "/forgot-password", "/recover", "/account/recover",
               "/api/reset", "/confirm-email", "/activate"]


def reset_surface_census(http, targets, conf):
    """Reset-token surface census (NAMES-only).

    canary reset token KABHI valid nahi hota -> koi real reset flow touch
    nahi hota. Sirf: (1) reset-shaped paths live? (2) token param names
    census (3) playbook rows."""
    rows = []
    pcap = max(4, int(conf.get("replay_probe_cap", 24)) // 3)
    bases = sorted(set([(t or "").split("?")[0].rstrip("/") for t in
                        (targets or []) if t]))[:4]
    tested = 0
    for b in bases:
        for p in RESET_PATHS:
            if tested >= pcap or interrupted():
                break
            url = b + p
            try:
                r = probe(http, "GET", url, allow_redirects=False)
            except Exception as e:
                rows.append({"url": url, "error": str(e)[:100]})
                continue
            tested += 1
            row = {"url": url, "status": r.status,
                   "live": bool(r.ok() and not is_soft404(r, None))}
            if row["live"]:
                hfs = mine_hidden_fields(r.text)
                row["token_fields"] = sorted(set(
                    hf["name"] for hf in hfs
                    if token_param_kind(hf["name"])))[:6]
                row["token_param_query"] = sorted(set(
                    k for k in urllib.parse.parse_qs(
                        urllib.parse.urlsplit(
                            (r.chain or [{}])[0].get("url", "")
                            if r.chain else "").query or "").keys()
                    if token_param_kind(k)))[:6] if r.chain else []
            rows.append(row)
    return {"rows": rows, "playbook": RESET_PLAYBOOK_ROWS,
            "note": "names-only; canary reset token never valid; "
                    "koi real reset flow touch nahi"}


RESET_PLAYBOOK_ROWS = [
    ("RT-01", "Reset-token reuse (same token 2x reset) - single-use gap",
     "manual+RoE: real token required; document CPL test steps"),
    ("RT-02", "Reset-token no-expiry census (old token still active)",
     "manual+RoE: time-window test; document evidence template"),
    ("RT-03", "Reset-token session-not-bound (token A session me redeem B)",
     "manual+RoE: two-browser differential; document proof format"),
    ("RT-04", "Reset-response token leak (token in response/JSON)",
     "manual: response-body review; names-only census here"),
    ("RT-05", "Reset link host-confusion (token on attacker-origin shape)",
     "manual+RoE: host-header differential; document PoC redaction"),
    ("RT-06", "Reset OTP/email enumeration oracle (timing/status diff)",
     "manual+RoE: enumeration differential; document throttle policy"),
]


# ===========================================================================
# STAGE H - OTP SURFACE CENSUS (GATED replay_allow_otp_probe)
# ===========================================================================
def otp_surface_census(http, targets, conf):
    """GATED replay_allow_otp_probe.

    OTP-shaped param canary differential: all-zero / all-same-digit canary
    codes (KABHI valid nahi) -> reject (positive control) ya accept
    (validation weakness). EXACTLY 2 canary values per endpoint."""
    gate = bool(conf.get("replay_allow_otp_probe", False))
    result = {"gate": "replay_allow_otp_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual OTP wave documented (KD-04)"}
    if not gate:
        return result
    pcap = max(2, int(conf.get("replay_probe_cap", 24)) // 3)
    otp_urls = [t for t in (targets or []) if isinstance(t, str) and
                re.search(r"(?i)(otp|2fa|mfa|verify|confirm)", t)]
    if not otp_urls:
        otp_urls = [t for t in (targets or []) if isinstance(t, str)][:pcap]
    tested = 0
    for url in otp_urls[:pcap * 2]:
        if tested >= pcap or interrupted():
            break
        sep = "&" if "?" in url else "?"
        rows_ep = []
        for canary_code in ("000000", "111111"):
            u = "%s%sotp=%s" % (url, sep, canary_code)
            try:
                r = probe(http, "GET", u, allow_redirects=False)
            except Exception as e:
                rows_ep.append({"canary_sha1": hashlib.sha1(
                    canary_code.encode()).hexdigest()[:12],
                    "error": str(e)[:100]})
                continue
            rows_ep.append({
                "canary_sha1": hashlib.sha1(
                    canary_code.encode()).hexdigest()[:12],
                "status": r.status,
                "rejected": r.status in (400, 401, 403, 409, 422),
                "accepted": bool(r.ok() and not is_soft404(r, None))})
        tested += 1
        accepted = [x for x in rows_ep if x.get("accepted")]
        result["rows"].append({"url": url, "probes": rows_ep,
                               "weak_accept": len(accepted) >= 1})
    return result


# ===========================================================================
# STAGE I - SESSION BINDING A/B DIFFERENTIAL (GATED replay_allow_session_probe)
# ===========================================================================
def session_replay_diff(http, targets, conf):
    """GATED replay_allow_session_probe.

    Canary cookie A/B differential (bounded identities <= replay_session_ctx):
    same endpoint, cookie A vs cookie B -> identical response = binding
    absent (session-replay across contexts). canary sessions server par
    EXIST nahi karte - 401/403 expected (positive control)."""
    gate = bool(conf.get("replay_allow_session_probe", False))
    result = {"gate": "replay_allow_session_probe=%s" % gate, "rows": [],
              "identities": int(conf.get("replay_session_ctx", 2)),
              "skipped_note": "" if gate else
              "RoE gate OFF - manual binding wave documented (KD-05)"}
    if not gate:
        return result
    ctx_n = max(2, min(2, int(conf.get("replay_session_ctx", 2))))
    pcap = max(2, int(conf.get("replay_probe_cap", 24)) // 3)
    tested = 0
    for url in _prioritize(targets, re.compile(r"session", re.I))[:pcap * 4]:
        if tested >= pcap or interrupted():
            break
        ca, cb = _canary("sA"), _canary("sB")
        try:
            ra = probe(http, "GET", url, allow_redirects=False,
                       headers={"Cookie": "waspP22session=%s" % ca})
            rb = probe(http, "GET", url, allow_redirects=False,
                       headers={"Cookie": "waspP22session=%s" % cb})
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:120]})
            continue
        tested += 1
        same_class = same_status_class(ra.status, rb.status)
        result["rows"].append({
            "url": url, "statusA": ra.status, "statusB": rb.status,
            "sha1A": ra.sha1()[:12], "sha1B": rb.sha1()[:12],
            "binding_absent": bool(same_class and ra.ok()),
            "binding_enforced": (ra.status != rb.status) and
            (rb.status in (401, 403, 409))})
    return result


# ===========================================================================
# STAGE J - RACE-CONDITION SURFACE (DOCUMENTED-ONLY + idempotency design)
# ===========================================================================
RACE_TECHNIQUES = [
    ("RC-01", "Single-packet attack (HTTP/2 concurrent streams in 1 packet)",
     "FORBIDDEN-AUTO execution; document RoE+manual steps"),
    ("RC-02", "Parallel burst (N threads same request)",
     "FORBIDDEN-AUTO; framework discipline: NO parallel burst KABHI"),
    ("RC-03", "Last-write-wins (delayed duplicate)",
     "manual+RoE: 2 sequential with server-side gap timing"),
    ("RC-04", "Session-race (same session 2 parallel actions)",
     "FORBIDDEN-AUTO; documented playbook"),
    ("RC-05", "Token-race (same one-time token 2 parallel consumers)",
     "FORBIDDEN-AUTO; P22 census gives token surface"),
    ("RC-06", "Coupon/limit race (limit check-then-act gap)",
     "manual+RoE: canary coupon never valid; document"),
    ("RC-07", "Balance race (debit before credit check)",
     "manual+RoE: FINANCE-CLASS - document-only"),
    ("RC-08", "Workflow-step race (step N parallel submit)",
     "manual+RoE: P20 workflow-skip handoff"),
    ("RC-09", "Email/link race (activation double-consume)",
     "manual+RoE: P9 reset handoff"),
    ("RC-10", "Rate-limit race (window reset boundary burst)",
     "FORBIDDEN-AUTO flood; census-only throttle signals"),
    ("RC-11", "Cache-fill race (two miss-fill writers)",
     "manual+RoE: cache-key differential; document"),
    ("RC-12", "Idempotency-key race (same key parallel create)",
     "manual+RoE: 2-sequential census covers design signal"),
]


def race_surface_documented():
    """Stage J: 12 documented techniques + idempotency-design census rows
    (0 network probes - pure documentation)."""
    return {"techniques": [{"id": i, "name": n, "discipline": d}
                           for i, n, d in RACE_TECHNIQUES],
            "idem_design_present": False,
            "note": "execution FORBIDDEN-AUTO (parallel burst/single-packet "
                    "KABHI automated nahi) - manual RoE wave only"}


# ===========================================================================
# STAGE K - BYPASS MATRIX v2: 17 SECRET REPLAY-BYPASS SHAPES
#           (GATED replay_allow_bypass2 - GET-only canary shapes)
# ===========================================================================
def _bypass2_shapes(base_url, canary):
    """17 replay-bypass GET shapes (canary token family waspP22).

    Har shape ek documented replay-bypass technique ka INERT GET-probe
    equivalent hai - token-context validation gap detect karne ke liye."""
    b = base_url.split("?")[0]
    q = urllib.parse.quote
    return [
        ("B2-01", "token-in-GET (client-supplied validation bypass shape)",
         "%s?token=%s" % (b, q(canary))),
        ("B2-02", "session-unbound token (cross-context replay shape)",
         "%s?token=%s&waspP22ctx=b" % (b, q(canary))),
        ("B2-03", "HPP duplicate token (first-vs-last parser differential)",
         "%s?token=good&token=%s" % (b, q(canary))),
        ("B2-04", "token case-shuffle (case-insensitive validator)",
         "%s?TOKEN=%s&token=%s" % (b, q(canary), q(canary))),
        ("B2-05", "token whitespace-pad (trim-differential)",
         "%s?token=%s%%20" % (b, q(canary))),
        ("B2-06", "token null-byte-legacy (legacy parser trim)",
         "%s?token=%s%%00" % (b, q(canary))),
        ("B2-07", "dot-segment replay path (normalizer differential)",
         "%s/./?token=%s" % (b.rstrip("/"), q(canary))),
        ("B2-08", "double-slash path replay (merge differential)",
         "%s//?token=%s" % (b.rstrip("/"), q(canary))),
        ("B2-09", "semicolon path-param replay (matrix-param parser)",
         "%s;waspP22=1?token=%s" % (b, q(canary))),
        ("B2-10", "url-encoding double-encode (decode differential)",
         "%s?token=%s" % (b, q(q(canary)))),
        ("B2-11", "token-in-fragment (client-side validator trust)",
         "%s#token=%s" % (b, q(canary))),
        ("B2-12", "empty-token replay (falsy-bypass shape)",
         "%s?token=" % b),
        ("B2-13", "array-token shape (type-juggle validator)",
         "%s?token[]=%s" % (b, q(canary))),
        ("B2-14", "json-token shape (parser differential; GET-observable)",
         "%s?token=%s&format=json" % (b, q(canary))),
        ("B2-15", "Origin-null replay shape (cross-origin validator)",
         "%s?token=%s&origin=null" % (b, q(canary))),
        ("B2-16", "Referer-stripped replay shape (referer validator)",
         "%s?token=%s&referer=" % (b, q(canary))),
        ("B2-17", "HEAD-replay shape (method-differential validator)",
         "%s?token=%s" % (b, q(canary))),   # HEAD method probe
    ]


def bypass2_census(http, targets, conf):
    """GATED replay_allow_bypass2: 17 shapes per top-target (GET/HEAD only,
    canary values). Accept (non-soft404 2xx/3xx) = token-context validation
    gap signal; reject-class = enforced."""
    gate = bool(conf.get("replay_allow_bypass2", False))
    result = {"gate": "replay_allow_bypass2=%s" % gate, "rows": [],
              "shapes_total": 17,
              "skipped_note": "" if gate else
              "RoE gate OFF - manual bypass2 wave documented (KD-06)"}
    if not gate:
        return result
    cap = max(1, min(4, int(conf.get("replay_bypass2_cap", 18)) // 4))
    tested = 0
    for t in (targets or [])[:cap * 3]:
        if tested >= cap or interrupted():
            break
        canary = _canary("b2")
        shape_rows = []
        for sid, name, url in _bypass2_shapes(t, canary):
            method = "HEAD" if sid == "B2-17" else "GET"
            try:
                r = probe(http, method, url, allow_redirects=False)
            except Exception as e:
                shape_rows.append({"id": sid, "name": name,
                                   "error": str(e)[:100]})
                continue
            accepted = bool(r.ok() and not is_soft404(r, None))
            shape_rows.append({"id": sid, "name": name, "method": method,
                               "status": r.status, "accepted": accepted,
                               "reject_class": r.status in ROTATION_REJECT_STATUS,
                               "waf_blocked": r.status in (403, 406, 429)})
        tested += 1
        acc = [s for s in shape_rows if s.get("accepted")]
        result["rows"].append({
            "url": t, "shapes": shape_rows, "accepted_count": len(acc),
            "accepted_ids": [s["id"] for s in acc],
            "blocked_count": len([s for s in shape_rows
                                  if s.get("waf_blocked")])})
    return result


# ===========================================================================
# STAGE L - ANTI-AUTOMATION CENSUS (positive controls, bounded probes)
# ===========================================================================
def anti_automation_census(http, targets, conf):
    """Rate-limit / captcha / bot-detection / lockout positive controls.

    BOUNDED canary burst (max 6 GETs per endpoint, sequential, sleep) -
    koi flood nahi. 429/Retry-After/captcha shape = HARDENED; nothing =
    throttle-absent signal (CWE-770 aid)."""
    rows = []
    pcap = max(2, min(6, int(conf.get("replay_probe_cap", 24)) // 3))
    burst_n = 6
    for t in (targets or [])[:pcap]:
        statuses, retry_after, captcha, bot = [], "", False, False
        for i in range(burst_n):
            if interrupted():
                break
            try:
                r = probe(http, "GET", t, allow_redirects=False,
                          headers={"X-WaspP22-Seq": str(i)})
            except Exception as e:
                rows.append({"url": t, "error": str(e)[:100]})
                break
            statuses.append(r.status)
            retry_after = r.hget("Retry-After", "") or retry_after
            body = (r.text or "")[:2000].lower()
            hdrs = {str(k).lower() for k in (r.headers or {}).keys()}
            if re.search(r"(?i)(captcha|recaptcha|hcaptcha|turnstile|"
                         r"challenge-platform|bot[-_ ]?(detect|protect)|"
                         r"just a moment)", body):
                captcha = True
            if any(h in hdrs for h in ("cf-mitigated", "x-captcha",
                                       "x-bot-challenge")) or \
                    "cloudflare" in body or "ray-id" in body:
                bot = True
            if r.status == 429:
                break
            time.sleep(0.05)
        rows.append({
            "url": t, "statuses": statuses[:burst_n], "burst": burst_n,
            "rate_limited": 429 in statuses,
            "retry_after": bool(retry_after),
            "captcha_shape": captcha, "bot_shape": bot,
            "throttle_absent": statuses and all(
                s and s < 429 for s in statuses)})
    return {"rows": rows, "note": "bounded 6-GET sequential burst per endpoint "
            "(koi flood nahi); 429/Retry-After/captcha = HARDENED positive "
            "controls"}


# ===========================================================================
# STAGE M - VERB / METHOD-OVERRIDE REPLAY CENSUS (GATED replay_allow_verb_probe)
# ===========================================================================
OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-Method-Override",
                    "X-HTTP-Method", "X-Original-Method",
                    "X-HTTP-Method-Variant", "X-Verb-Override"]


def verb_replay_census(http, targets, conf):
    """GATED replay_allow_verb_probe.

    OPTIONS/HEAD variance + method-override header ECHO census (6 shapes).
    Override echo = verb-replay surface (enforcement review aid)."""
    gate = bool(conf.get("replay_allow_verb_probe", False))
    result = {"gate": "replay_allow_verb_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual verb wave documented (KD-07)"}
    if not gate:
        return result
    vcap = max(2, int(conf.get("replay_verb_cap", 8)))
    tested = 0
    for t in _prioritize(targets, re.compile(r"verb|override|method",
                                             re.I))[:vcap * 2]:
        if tested >= vcap or interrupted():
            break
        try:
            ro = probe(http, "OPTIONS", t, allow_redirects=False)
            rh = probe(http, "HEAD", t, allow_redirects=False)
            rg = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:120]})
            continue
        tested += 1
        allow = ro.hget("Allow", "") or ro.hget("Access-Control-Allow-Methods", "")
        echo_hits = []
        for oh in OVERRIDE_HEADERS[:2]:   # bounded: sirf 2 override headers
            try:
                rr = probe(http, "GET", t, allow_redirects=False,
                           headers={oh: "DELETE"})
            except Exception:
                continue
            body = (rr.text or "")[:2500]
            if rr.status != rg.status or "delete" in body.lower():
                echo_hits.append({"header": oh, "status": rr.status,
                                  "body_echo": "delete" in body.lower()})
        result["rows"].append({
            "url": t, "allow": allow[:80], "status_options": ro.status,
            "head_differs": (rh.status != rg.status),
            "override_echo": echo_hits})
    return result


# ===========================================================================
# STAGE N - CACHE / REPLAY INTERPLAY CENSUS (token-in-cacheable shapes)
# ===========================================================================
def cache_replay_census(http, targets, conf):
    """Token-bearing responses par Cache-Control/Vary/Age/ETag census.

    Token-param wali GET response CACHEABLE (public/no-store absent) =
    token-in-cache replay primitive (shared-cache review aid)."""
    rows = []
    cap = max(4, int(conf.get("replay_paths_cap", 40)) // 2)
    for t in (targets or [])[:cap]:
        sep = "&" if "?" in t else "?"
        u = "%s%stoken=%s" % (t, sep, _canary("cache"))
        try:
            r = probe(http, "GET", u, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        cc = r.hget("Cache-Control", "")
        vary = r.hget("Vary", "")
        row = {"url": t, "status": r.status, "cache_control": cc[:80],
               "vary": vary[:60], "etag": bool(r.hget("ETag", "")),
               "age": r.hget("Age", "")[:8],
               "token_param_in_url": True,
               "cacheable": ("no-store" not in cc.lower()) and
                            ("private" not in cc.lower())}
        rows.append(row)
    return {"rows": rows, "note": "cacheable + token-in-url = shared-cache "
            "replay review aid (CWE-524/525)"}


# ===========================================================================
# STAGE O - SIGNED / ONE-TIME URL CENSUS (GATED replay_allow_signed_probe)
# ===========================================================================
SIGNED_PARAM_RX = re.compile(r"(?i)^(sig|signature|hmac|mac|token|sign|expires|expiry|exp|expires_at|valid_until)$")


def signed_url_census(http, targets, conf):
    """GATED replay_allow_signed_probe.

    sig/expiry-shaped param census + canary reuse differential: same signed-
    shape URL 2 SEQUENTIAL GETs -> 2nd accepted = replayable (no nonce/no
    consumption); 410/expired = one-time enforced. canary sig KABHI valid
    nahi hota."""
    gate = bool(conf.get("replay_allow_signed_probe", False))
    result = {"gate": "replay_allow_signed_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual signed-url wave documented (KD-08)"}
    if not gate:
        return result
    scap = max(2, int(conf.get("replay_signed_cap", 10)))
    tested = 0
    for t in _prioritize(targets, re.compile(r"sign", re.I))[:scap * 4]:
        if tested >= scap or interrupted():
            break
        parsed = urllib.parse.urlsplit(t)
        q = urllib.parse.parse_qs(parsed.query or "")
        sig_params = sorted(k for k in q.keys() if SIGNED_PARAM_RX.match(k))
        sep = "&" if "?" in t else "?"
        if sig_params:
            # mined sig-shape URL: canary sig values ke saath reuse diff
            u = "%s%s%s=%s&expires=9999999999" % (
                t, sep, sig_params[0], _canary("sig"))
        else:
            u = "%s%ssig=%s&expires=9999999999" % (t, sep, _canary("sig"))
        try:
            r1 = probe(http, "GET", u, allow_redirects=False)
            r2 = probe(http, "GET", u, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:120]})
            continue
        tested += 1
        consumed = r2.status in (403, 409, 410, 422) or looks_replayed_signal(r2)
        result["rows"].append({
            "url": t, "sig_params": sig_params,
            "status1": r1.status, "status2": r2.status,
            "consumed": consumed,
            "replayable": bool(r1.ok() and r2.ok() and not consumed)})
    return result


# ===========================================================================
# STAGE P - API IDEMPOTENCY DESIGN CENSUS (P17 handoff, GET-only)
# ===========================================================================
def api_idempotency_census(http, targets, conf):
    """Mutation-shaped API endpoints par idempotency-design observation:

    OPTIONS/GET se Allow/methods + Idempotency-Key header support shape +
    RFC-draft patterns (425 Too Early, Retry-After, ETag conditional).
    koi mutation request KABHI nahi bhejte (GET-only module)."""
    rows = []
    cap = max(4, int(conf.get("replay_paths_cap", 40)) // 2)
    api_urls = [t for t in (targets or []) if isinstance(t, str) and
                ("/api" in t or REPLAY_VERB_RX.search(t))][:cap]
    for t in api_urls:
        try:
            ro = probe(http, "OPTIONS", t, allow_redirects=False)
            rg = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        allow = ro.hget("Allow", "") or ro.hget("Access-Control-Allow-Methods", "")
        mutations = [m for m in allow.upper().split(",")
                     if m.strip() in ("POST", "PUT", "PATCH", "DELETE")]
        rows.append({
            "url": t, "allow": allow[:80],
            "mutation_methods_observed": mutations,
            "idem_header_ack": bool(ro.hget("Idempotency-Key", "")) or
                              ("idempotency" in (rg.text or "")[:3000].lower()),
            "too_early_425": "425" in (ro.hget("Allow", "") or ""),
            "etag_conditional": bool(rg.hget("ETag", "")),
            "retry_after": bool(rg.hget("Retry-After", ""))})
    return {"rows": rows, "note": "GET/OPTIONS-only observation; mutation "
            "requests KABHI nahi (module discipline)"}


# ===========================================================================
# STAGE Q - GRAPHQL REPLAY SURFACE (P18 handoff, NAMES-only)
# ===========================================================================
def gql_replay_surface(base_dir):
    """P18 handoff: writable mutation NAMES census (mutations NEVER sent).

    graphql/feedforward.json + gql artifacts se mutation names mine (redacted)."""
    names = []
    d = _read_json_tolerant(_artifact(base_dir, "graphql", "feedforward.json"))
    if isinstance(d, dict):
        routing = d.get("routing") or {}
        for rk, val in routing.items():
            if "writable" in str(rk) or "mutation" in str(rk):
                for lst in _walk_lists(val):
                    names.extend([x for x in lst if isinstance(x, str)])
    art = _read_json_tolerant(_artifact(base_dir, "graphql",
                                        "graphql_writable.json"))
    if isinstance(art, (dict, list)):
        for lst in _walk_lists(art):
            names.extend([x for x in lst if isinstance(x, str)])
    names = sorted(set(n for n in names if len(n) < 80))[:40]
    return {"mutations": names, "count": len(names),
            "note": "mutations NEVER sent (P22 GET-only discipline); "
                    "replay-targeting census only"}


# ===========================================================================
# STAGE R - WEBSOCKET REPLAY SURFACE (P19 handoff, frames NEVER)
# ===========================================================================
def ws_replay_surface(base_dir):
    """P19 handoff: ws endpoints + challenge/token-shaped subs census.

    koi WebSocket frame KABHI nahi bhejte (P19 ki tarah census-only)."""
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
            "note": "frames NEVER (P19 discipline); ws-replay manual aid"}


# ===========================================================================
# STAGE X (v24) - TOKEN LIFECYCLE / ENTROPY CENSUS (offline, sha1-only)
# ===========================================================================
def token_lifecycle_census(token_recs):
    """Mined token records -> lifecycle buckets (offline, values REDACTED).

    Har record: len-bucket + entropy + format + guessability-aid flag.
    Koi token VALUE store nahi hota (sirf sha1-12 + buckets)."""
    rows = []
    for rec in (token_recs or [])[:int(DEFAULTS["replay_token_cap"])]:
        eb = {"len_bucket": rec.get("len_bucket", "?"),
              "entropy": rec.get("entropy"),
              "format": rec.get("format", "mixed")}
        weak = (eb["len_bucket"] == "<=16") or (eb["format"] == "digits") or \
               (isinstance(eb["entropy"], (int, float)) and eb["entropy"] < 2.5)
        rows.append({"kind": rec.get("kind"), "name": rec.get("name"),
                     "url": rec.get("url"), **eb,
                     "sha1_12": rec.get("sha1_12", ""),
                     "weak_shape": weak})
    return {"rows": rows, "weak_count": len([r for r in rows
                                             if r["weak_shape"]]),
            "note": "sha1-only buckets; token values KABHI store nahi"}


# ===========================================================================
# STAGE Y (v24) - REPLAY-RESISTANCE POSTURE COMPOSITE (8-point score)
# ===========================================================================
POSTURE_POINTS = [
    ("rotation",      "one-time token rotation enforced (sha1 drift)"),
    ("single_use",    "stale/canary reuse REJECTED (403/409/410/422)"),
    ("session_bound", "context binding A/B differential enforced"),
    ("origin_check",  "Origin/Referer validator shape present"),
    ("rate_control",  "429/Retry-After/captcha positive control"),
    ("idempotency",   "Idempotency-Key dedup signal present"),
    ("cache_safe",    "no-store/private on token responses"),
    ("sig_one_time",  "signed URL consumption enforced"),
]


def posture_composite(results, token_rows):
    """Per-endpoint 8-point replay-resistance composite (offline).

    results = stage result dict (csrf/idem/nonce/session/rate/cache/signed).
    Score 0-8; <3 = WEAK (finding), >=6 = STRONG (positive)."""
    per_ep = {}

    def _bump(url, point, ok_flag):
        d = per_ep.setdefault(url or "?", {p[0]: None for p in POSTURE_POINTS})
        cur = d.get(point)
        d[point] = bool(ok_flag) if cur is None else (cur or bool(ok_flag))

    for row in (results.get("csrf") or {}).get("rows", []):
        if "rotated" in row:
            _bump(row.get("url"), "rotation", row.get("rotated"))
        if row.get("reuse", {}).get("reject_class"):
            _bump(row.get("url"), "single_use", True)
        if row.get("reuse", {}).get("accepted"):
            _bump(row.get("url"), "single_use", False)
    for row in (results.get("idem") or {}).get("rows", []):
        _bump(row.get("url"), "idempotency", row.get("dedup"))
    for row in (results.get("nonce") or {}).get("rows", []):
        _bump(row.get("url"), "single_use", row.get("consumed"))
        if row.get("reuse_accepted"):
            _bump(row.get("url"), "single_use", False)
    for row in (results.get("session") or {}).get("rows", []):
        _bump(row.get("url"), "session_bound", row.get("binding_enforced"))
        if row.get("binding_absent"):
            _bump(row.get("url"), "session_bound", False)
    for row in (results.get("rate") or {}).get("rows", []):
        _bump(row.get("url"), "rate_control",
              row.get("rate_limited") or row.get("retry_after") or
              row.get("captcha_shape") or row.get("bot_shape"))
    for row in (results.get("cache") or {}).get("rows", []):
        _bump(row.get("url"), "cache_safe", not row.get("cacheable"))
    for row in (results.get("signed") or {}).get("rows", []):
        _bump(row.get("url"), "sig_one_time", row.get("consumed"))
        if row.get("replayable"):
            _bump(row.get("url"), "sig_one_time", False)

    rows = []
    for url, pts in per_ep.items():
        score = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is True)
        known = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is not None)
        rows.append({"url": url, "score": score, "known_points": known,
                     "points": pts,
                     "grade": "STRONG" if score >= 6 else
                              "PARTIAL" if score >= 3 else "WEAK"})
    rows.sort(key=lambda r: r["score"])
    return {"points": POSTURE_POINTS, "rows": rows,
            "weak": [r for r in rows if r["grade"] == "WEAK"],
            "strong": [r for r in rows if r["grade"] == "STRONG"]}


# ===========================================================================
# STAGE Z (v24) - PLATFORM FINGERPRINT + FINAL SECRETS/PII GUARD
# ===========================================================================
PLATFORM_FPS = [
    ("oauth2-oidc",   re.compile(r"(?i)(/oauth|/oidc|openid|id_token|client_id)")),
    ("saml-sso",      re.compile(r"(?i)(saml|sso|assertion|adfs|okta|onelogin)")),
    ("payment-gw",    re.compile(r"(?i)(stripe|razorpay|paypal|braintree|checkout)")),
    ("captcha-gw",    re.compile(r"(?i)(recaptcha|hcaptcha|turnstile|geetest)")),
    ("api-gateway",   re.compile(r"(?i)(x-amzn-requestid|x-request-id|apigw|kong|gateway)")),
    ("idempotency-lib", re.compile(r"(?i)(idempotency[-_]?key|dedup|request-id)")),
    ("rate-limiter",  re.compile(r"(?i)(x-ratelimit|ratelimit-|retry-after)")),
    ("session-mgmt",  re.compile(r"(?i)(jsessionid|phpsessionid|aspxauth|sessionid)")),
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
    r"(secret_access_key|api_key|apikey|passwd|password)\s*[:=]\s*[^\s,;\"]{6,}|"
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
# STAGE S - CROSS-MODULE KILL-CHAINS (CH01..CH24)
# ===========================================================================
def build_chains(results, ff_seeds):
    """24 replay kill-chains (P9..P20 handoffs + P22 census rows)."""
    chains = [
        ("CH01", "CSRF no-rotation -> state-changing replay",
         "Stage D reuse accept -> documented POST PoC (RoE)"),
        ("CH02", "Idempotency missing -> duplicate-submission replay",
         "Stage E no-dedup -> double-submit manual proof"),
        ("CH03", "OAuth state reuse -> login-CSRF/fixation relay",
         "Stage F reuse accept -> session-association manual"),
        ("CH04", "Reset-token reuse -> account-takeover replay",
         "Stage G surface -> RT-01 manual wave"),
        ("CH05", "OTP weak-accept -> brute/replay assist",
         "Stage H weak_accept -> throttle review"),
        ("CH06", "Session unbound -> cross-context replay",
         "Stage I binding_absent -> P11 IDOR handoff"),
        ("CH07", "Race single-packet -> limit bypass",
         "Stage J RC-01 -> manual RoE wave"),
        ("CH08", "Bypass2 token-context gap -> replay accepted",
         "Stage K accepted_ids -> validation-fix plan"),
        ("CH09", "Throttle absent -> scripted replay wave",
         "Stage L throttle_absent -> monitoring plan"),
        ("CH10", "Method-override echo -> verb-replay",
         "Stage M override_echo -> enforcement fix"),
        ("CH11", "Token-in-cache -> shared-cache replay",
         "Stage N cacheable -> cache-hardening fix"),
        ("CH12", "Signed-URL replayable -> unpaid-resource access",
         "Stage O replayable -> nonce/signature-binding fix"),
        ("CH13", "API no-idempotency-header -> duplicate orders",
         "Stage P header_absent -> RFC-draft design fix"),
        ("CH14", "GQL writable-mutation replay -> double-mutation",
         "Stage Q names -> P18/P22 joint manual wave"),
        ("CH15", "WS challenge replay -> duplicate ws action",
         "Stage R endpoints -> P19 joint manual wave"),
        ("CH16", "Weak token entropy -> prediction/replay",
         "Stage X weak_shape -> token-policy fix"),
        ("CH17", "Posture WEAK composite -> priority hardening",
         "Stage Y weak rows -> remediation order"),
        ("CH18", "P20 flow-replay pairs -> P22 confirm",
         "P20 ff flow_replay -> Stage E/F confirm"),
        ("CH19", "P12 replay_pairs (injection echo) -> replay chain",
         "P12 ff -> Stage K shapes"),
        ("CH20", "P9 reset-surface -> token-lifecycle chain",
         "P9 ff -> Stage G + X"),
        ("CH21", "P10 session-token replay -> fixation chain",
         "P10 ff -> Stage I"),
        ("CH22", "P17 api-idempotency design -> replay chain",
         "P17 ff -> Stage P"),
        ("CH23", "P14 csrf/state handoff -> rotation chain",
         "P14 ff -> Stage D/F"),
        ("CH24", "One-time token reuse -> checkout/redeem replay",
         "Stage E/F same-key accept -> P20 CH24 chain"),
    ]
    out = []
    ff_keys = set((ff_seeds or {}).keys())
    for cid, title, evidence in chains:
        out.append({"id": cid, "title": title, "evidence": evidence,
                    "ff_seeds": sorted(ff_keys)[:6]})
    return out


# ===========================================================================
# STAGE T - VERDICT ENGINE (6-class ladder, multi-signal)
# ===========================================================================
def verdict_engine(results):
    """Stage rows -> 6-class verdict rows (CONFIRMED/SUSPECTED/HARDENED/
    BLOCKED/SKIPPED/NOISE) - P12..P20-compatible ladder."""
    rows = []

    def _add(stage, url, verdict, signals, detail):
        rows.append({"stage": stage, "url": url, "verdict": verdict,
                     "signals": signals, "detail": truncate(str(detail), 220)})

    # ---- CSRF ----
    for r in (results.get("csrf") or {}).get("rows", []):
        u = r.get("url", "?")
        reuse = r.get("reuse") or {}
        if "rotated" not in r:
            continue
        if reuse.get("accepted") and not r.get("rotated"):
            _add("D", u, "CONFIRMED", ["reuse-accept", "no-rotation"],
                 "canary reuse accept + token sha1 stable")
        elif reuse.get("accepted") and r.get("rotated"):
            _add("D", u, "SUSPECTED", ["reuse-accept", "rotated"],
                 "validation absent par rotation present - context review")
        elif r.get("rotated") and reuse.get("reject_class"):
            _add("D", u, "HARDENED", ["rotated", "reuse-reject"],
                 "rotation + single-use positive controls")
        elif r.get("rotated"):
            _add("D", u, "HARDENED", ["rotated"], "token rotation enforced")
        else:
            _add("D", u, "SUSPECTED", ["no-rotation"],
                 "sha1 stable across fetches - single-use gap suspect")
    # ---- IDEMPOTENCY ----
    for r in (results.get("idem") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("dedup"):
            _add("E", u, "HARDENED", ["dedup-signal"],
                 "same canary key -> replayed/drift signal")
        elif r.get("echo"):
            _add("E", u, "SUSPECTED", ["key-echo", "no-dedup"],
                 "key echo but no dedup on 2nd sequential")
        else:
            _add("E", u, "CONFIRMED", ["no-dedup", "no-signal"],
                 "same canary idempotency-key 2x accepted identical")
    # ---- NONCE/STATE ----
    for r in (results.get("nonce") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("consumed"):
            _add("F", u, "HARDENED", ["consumed"], "state/nonce one-time")
        elif r.get("reuse_accepted"):
            _add("F", u, "CONFIRMED", ["reuse-accept"],
                 "canary state 2nd request accepted (no consumption)")
    # ---- OTP ----
    for r in (results.get("otp") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("weak_accept"):
            _add("H", u, "CONFIRMED", ["weak-accept"],
                 "all-zero/all-same canary OTP accepted")
        else:
            _add("H", u, "HARDENED", ["reject-ok"], "canary OTP rejected")
    # ---- SESSION ----
    for r in (results.get("session") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("binding_absent"):
            _add("I", u, "CONFIRMED", ["unbound"],
                 "A/B canary cookie same-class accept")
        elif r.get("binding_enforced"):
            _add("I", u, "HARDENED", ["bound"], "B-context rejected")
    # ---- BYPASS2 ----
    for r in (results.get("bypass2") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("accepted_count"):
            _add("K", u, "CONFIRMED", ["bypass-accept"],
                 "accepted=%s" % ",".join(r.get("accepted_ids", [])[:6]))
        elif r.get("blocked_count"):
            _add("K", u, "BLOCKED", ["waf-block"], "shapes fingerprint-blocked")
        else:
            _add("K", u, "HARDENED", ["reject-all"], "all 17 shapes rejected")
    # ---- RATE ----
    for r in (results.get("rate") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("rate_limited") or r.get("retry_after"):
            _add("L", u, "HARDENED", ["rate-control"], "throttle present")
        elif r.get("throttle_absent"):
            _add("L", u, "SUSPECTED", ["throttle-absent"],
                 "bounded burst no throttle signal (koi flood nahi)")
    # ---- SIGNED ----
    for r in (results.get("signed") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("replayable"):
            _add("O", u, "CONFIRMED", ["sig-reuse-accept"],
                 "same canary signed-shape URL 2x accepted")
        elif r.get("consumed"):
            _add("O", u, "HARDENED", ["one-time"], "consumption enforced")
    # ---- GATED SKIPS ----
    for stage_key, gate_name in (("D", "replay_allow_csrf_probe"),
                                 ("E", "replay_allow_idem_probe"),
                                 ("F", "replay_allow_nonce_probe"),
                                 ("H", "replay_allow_otp_probe"),
                                 ("I", "replay_allow_session_probe"),
                                 ("K", "replay_allow_bypass2"),
                                 ("M", "replay_allow_verb_probe"),
                                 ("O", "replay_allow_signed_probe")):
        st = results.get({"D": "csrf", "E": "idem", "F": "nonce",
                          "H": "otp", "I": "session", "K": "bypass2",
                          "M": "verb", "O": "signed"}.get(stage_key, ""), {})
        if isinstance(st, dict) and st.get("skipped_note"):
            rows.append({"stage": stage_key, "url": "*", "verdict": "SKIPPED",
                         "signals": ["roe-gate-off"], "detail": gate_name})

    order = {"CONFIRMED": 0, "SUSPECTED": 1, "BLOCKED": 2, "HARDENED": 3,
             "SKIPPED": 4, "NOISE": 5}
    rows.sort(key=lambda r: (order.get(r["verdict"], 9), r["stage"]))
    return rows


# ===========================================================================
# STAGE U - TECHNIQUE MATRIX (190+ rows x 18 families + CWE + MITRE)
# ===========================================================================
MATRIX_CATALOG = {
    "REPLAY_CSRF": [
        ("token rotation absent (2-fetch sha1 stable)", "CWE-613", "T1181"),
        ("stale-token reuse accepted", "CWE-613", "T1181"),
        ("token not bound to session", "CWE-613", "T1539"),
        ("token in GET query (leak surface)", "CWE-598", "T1552.001"),
        ("double-submit cookie pair absent", "CWE-352", "T1181"),
        ("Origin/Referer validator absent", "CWE-352", "T1181"),
        ("HPP duplicate-token parser differential", "CWE-20", "T1210"),
        ("token case/encoding variants accepted", "CWE-20", "T1210"),
        ("client-rendered token (no server state)", "CWE-693", "T1112"),
        ("per-request token reused across tabs", "CWE-613", "T1181"),
        ("SameSite-Lax GET-replay shape (documented)", "CWE-1275", "T1181"),
    ],
    "REPLAY_IDEM": [
        ("same idempotency-key accepted twice", "CWE-294", "T1110"),
        ("idempotency-key absent on mutation endpoint", "CWE-294", "T1110"),
        ("key echo without dedup signal", "CWE-639", "T1110"),
        ("dedup window shorter than retry horizon", "CWE-837", "T1110"),
        ("key scope global vs per-session mismatch", "CWE-284", "T1110"),
        ("status-drift hidden (same 200 both)", "CWE-837", "T1110"),
        ("client-supplied key trusted without binding", "CWE-602", "T1110"),
        ("replayed/already-processed signal absent", "CWE-837", "T1110"),
        ("Retry-After guidance absent", "CWE-770", "T1110"),
        ("425 Too Early pattern absent (RFC draft)", "CWE-837", "T1110"),
        ("ETag conditional replay surface", "CWE-837", "T1110"),
    ],
    "REPLAY_NONCE": [
        ("OAuth state reuse accepted (no consumption)", "CWE-352", "T1557"),
        ("OIDC nonce single-use absent", "CWE-294", "T1557"),
        ("challenge-response reuse accepted", "CWE-294", "T1557"),
        ("nonce window unbounded", "CWE-837", "T1557"),
        ("state not bound to session cookie", "CWE-352", "T1557"),
        ("nonce in URL query (log/cache leak)", "CWE-598", "T1552.001"),
        ("websocket challenge replay shape", "CWE-294", "T1557"),
        ("anti-replay cache missing server-side", "CWE-693", "T1557"),
        ("nonce acceptance on 2nd request only-flagged", "CWE-639", "T1557"),
        ("nonce hash-compare sidechannel census", "CWE-208", "T1110"),
        ("state-continue parameter reuse shape", "CWE-294", "T1557"),
    ],
    "REPLAY_RESET": [
        ("reset-token reuse (RT-01 documented)", "CWE-640", "T1078.004"),
        ("reset-token no-expiry (RT-02)", "CWE-613", "T1078.004"),
        ("token not session-bound (RT-03)", "CWE-640", "T1078.004"),
        ("token leak in response (RT-04)", "CWE-200", "T1552"),
        ("host-confusion reset link (RT-05)", "CWE-640", "T1078.004"),
        ("enumeration oracle (RT-06)", "CWE-204", "T1110"),
        ("reset-token entropy weak shape", "CWE-330", "T1110"),
        ("token-in-referrer leak shape", "CWE-598", "T1552.001"),
        ("reset OTP parallel reuse surface", "CWE-294", "T1078.004"),
        ("reset-link pre-fetch scanner leak (documented)", "CWE-640", "T1078.004"),
        ("reset-token in email-log surface (documented)", "CWE-532", "T1552"),
    ],
    "REPLAY_OTP": [
        ("all-zero canary accepted (weak validator)", "CWE-778", "T1110"),
        ("all-same-digit canary accepted", "CWE-778", "T1110"),
        ("OTP replay single-use absent", "CWE-294", "T1110"),
        ("OTP throttle/lockout absent", "CWE-307", "T1110"),
        ("OTP window/attempt config census", "CWE-307", "T1110"),
        ("OTP-in-response leak shape", "CWE-200", "T1552"),
        ("totp drift tolerance census", "CWE-294", "T1110"),
        ("backup-code reuse surface", "CWE-294", "T1110"),
        ("otp param in GET (log leak)", "CWE-598", "T1552.001"),
        ("otp verify endpoint enumeration census", "CWE-204", "T1110"),
        ("otp replay-window config census", "CWE-294", "T1110"),
    ],
    "REPLAY_SESSION": [
        ("A/B canary cookie binding absent", "CWE-613", "T1539"),
        ("session-token replay across contexts", "CWE-613", "T1539"),
        ("fixation surface (token-in-url)", "CWE-384", "T1539"),
        ("session-id accept-shape census", "CWE-384", "T1539"),
        ("concurrent-session policy absent", "CWE-613", "T1539"),
        ("logout token-invalidation absent", "CWE-613", "T1539"),
        ("remember-me replay surface", "CWE-613", "T1539"),
        ("session binding per-device absent", "CWE-613", "T1539"),
        ("token rotation on privilege change absent", "CWE-384", "T1539"),
        ("multi-session concurrent accept census", "CWE-613", "T1539"),
        ("cookie SameSite replay shape (GET)", "CWE-1275", "T1181"),
        ("long-lived session replay surface", "CWE-613", "T1539"),
    ],
    "RACE": [
        ("single-packet H2 attack (RC-01 documented)", "CWE-362", "T1110"),
        ("parallel burst (RC-02 FORBIDDEN-AUTO)", "CWE-362", "T1110"),
        ("last-write-wins duplicate (RC-03)", "CWE-362", "T1110"),
        ("session race (RC-04)", "CWE-362", "T1110"),
        ("token race double-consume (RC-05)", "CWE-362", "T1110"),
        ("coupon limit race (RC-06)", "CWE-362", "T1110"),
        ("balance debit/credit race (RC-07)", "CWE-362", "T1110"),
        ("workflow step race (RC-08)", "CWE-362", "T1110"),
        ("activation double-consume race (RC-09)", "CWE-362", "T1110"),
        ("rate-window boundary burst (RC-10)", "CWE-770", "T1110"),
        ("cache-fill race (RC-11)", "CWE-362", "T1110"),
        ("idempotency-key race (RC-12)", "CWE-362", "T1110"),
    ],
    "REPLAY_BYPASS2": [  # 17 shapes = Stage K catalog
        ("B2-01 token-in-GET", "CWE-598", "T1552.001"),
        ("B2-02 session-unbound token", "CWE-613", "T1539"),
        ("B2-03 HPP duplicate token", "CWE-20", "T1210"),
        ("B2-04 token case-shuffle", "CWE-20", "T1210"),
        ("B2-05 token whitespace-pad", "CWE-20", "T1210"),
        ("B2-06 token null-byte-legacy", "CWE-20", "T1210"),
        ("B2-07 dot-segment path", "CWE-20", "T1210"),
        ("B2-08 double-slash path", "CWE-20", "T1210"),
        ("B2-09 semicolon matrix-param", "CWE-20", "T1210"),
        ("B2-10 double-url-encode", "CWE-20", "T1210"),
        ("B2-11 token-in-fragment", "CWE-200", "T1552"),
        ("B2-12 empty-token falsy", "CWE-20", "T1210"),
        ("B2-13 array-token type-juggle", "CWE-20", "T1210"),
        ("B2-14 json-format token", "CWE-20", "T1210"),
        ("B2-15 Origin-null shape", "CWE-346", "T1557"),
        ("B2-16 Referer-stripped", "CWE-346", "T1557"),
        ("B2-17 HEAD-replay shape", "CWE-650", "T1210"),
    ],
    "ANTI_AUTO": [
        ("429 rate-limit present (positive)", "CWE-770", "T1110"),
        ("Retry-After guidance present", "CWE-770", "T1110"),
        ("captcha challenge shape", "CWE-799", "T1110"),
        ("bot-detection headers", "CWE-799", "T1110"),
        ("throttle absent (bounded burst)", "CWE-770", "T1110"),
        ("lockout signal census", "CWE-307", "T1110"),
        ("progressive-delay census", "CWE-770", "T1110"),
        ("per-IP vs per-account scope", "CWE-770", "T1110"),
        ("monitoring/alert hooks (documented)", "CWE-223", "T1110"),
    ],
    "VERB_REPLAY": [
        ("X-HTTP-Method-Override echo", "CWE-650", "T1210"),
        ("X-Method-Override echo", "CWE-650", "T1210"),
        ("X-HTTP-Method echo", "CWE-650", "T1210"),
        ("X-Original-Method echo", "CWE-650", "T1210"),
        ("X-HTTP-Method-Variant echo", "CWE-650", "T1210"),
        ("X-Verb-Override echo", "CWE-650", "T1210"),
        ("OPTIONS/GET variance", "CWE-650", "T1210"),
        ("HEAD/GET differential", "CWE-650", "T1210"),
        ("verb allowlist census", "CWE-693", "T1110"),
    ],
    "CACHE_REPLAY": [
        ("token response cacheable (no no-store)", "CWE-524", "T1552"),
        ("token-in-URL cacheable GET", "CWE-598", "T1552.001"),
        ("Vary header absent on auth content", "CWE-525", "T1552"),
        ("Age/CDN cache present on token route", "CWE-525", "T1552"),
        ("ETag weak-validation replay", "CWE-837", "T1110"),
        ("shared-cache key confusion (documented)", "CWE-525", "T1552"),
        ("Cache-Control public on sensitive route", "CWE-524", "T1552"),
        ("private-cache token retention census", "CWE-524", "T1552"),
        ("token route 304-replay shape (conditional GET)", "CWE-837", "T1110"),
        ("cache-vary-on-user-agent gap", "CWE-525", "T1552"),
        ("stale-while-revalidate token window", "CWE-525", "T1552"),
    ],
    "SIGNED_URL": [
        ("signed-URL reuse accepted (no nonce)", "CWE-294", "T1552"),
        ("signature unbound to session/actor", "CWE-347", "T1552"),
        ("expiry param far-future shape", "CWE-613", "T1552"),
        ("sig algorithm census (md5/sha1 weak)", "CWE-327", "T1552"),
        ("sig in GET query (log leak)", "CWE-598", "T1552.001"),
        ("one-time consumption absent", "CWE-294", "T1552"),
        ("signature-stripping shape (empty sig)", "CWE-347", "T1552"),
        ("param-sorting canonicalization gap", "CWE-347", "T1552"),
        ("replay-window unbounded", "CWE-837", "T1552"),
        ("signed-header duplication shape", "CWE-347", "T1552"),
        ("timestamp-skew tolerance census", "CWE-837", "T1552"),
        ("sig-param type-juggle (array/int)", "CWE-20", "T1210"),
    ],
    "API_IDEM": [
        ("Idempotency-Key header support absent", "CWE-294", "T1110"),
        ("mutation methods observed (OPTIONS)", "CWE-294", "T1110"),
        ("425 Too Early absent", "CWE-837", "T1110"),
        ("ETag conditional absent", "CWE-837", "T1110"),
        ("Retry-After absent", "CWE-770", "T1110"),
        ("request-id echo without dedup", "CWE-639", "T1110"),
        ("openapi idempotency docs absent", "CWE-223", "T1110"),
        ("api-gateway replay policy census", "CWE-693", "T1110"),
        ("webhook signature replay census (x-hub-signature)", "CWE-294", "T1552"),
        ("api version-skew replay surface", "CWE-20", "T1210"),
    ],
    "GQL_REPLAY": [
        ("writable mutation names census", "CWE-294", "T1110"),
        ("mutation replay surface (documented)", "CWE-294", "T1110"),
        ("alias-based duplicate shape (documented)", "CWE-294", "T1110"),
        ("mutation depth replay (documented)", "CWE-400", "T1110"),
        ("persisted-query replay shape", "CWE-294", "T1110"),
        ("idempotency-directive absent", "CWE-294", "T1110"),
        ("gql error-shape oracle (documented)", "CWE-209", "T1110"),
        ("operation-name reuse census", "CWE-294", "T1110"),
        ("gql mutation without idempotency guard", "CWE-294", "T1110"),
        ("gql batch-replay shape (documented)", "CWE-294", "T1110"),
    ],
    "WS_REPLAY": [
        ("ws endpoint census", "CWE-294", "T1078"),
        ("ws challenge reuse shape (documented)", "CWE-294", "T1557"),
        ("ws token-in-subprotocol surface", "CWE-598", "T1552.001"),
        ("ws origin-replay shape (documented)", "CWE-346", "T1557"),
        ("ws message replay (documented)", "CWE-294", "T1557"),
        ("ws seq-number replay census", "CWE-294", "T1557"),
        ("ws auth-refresh replay shape", "CWE-613", "T1557"),
        ("ws per-message nonce absence (documented)", "CWE-294", "T1557"),
        ("ws reconnect-token reuse shape", "CWE-294", "T1557"),
    ],
    "TOKEN_LIFE": [
        ("short-token bucket (<=16)", "CWE-330", "T1110"),
        ("digits-only format bucket", "CWE-330", "T1110"),
        ("low-entropy bucket (<2.5)", "CWE-330", "T1110"),
        ("jwt-like token bucket", "CWE-347", "T1552"),
        ("hex-format bucket census", "CWE-330", "T1110"),
        ("b64url bucket census", "CWE-330", "T1110"),
        ("token sha1-chain manifest", "CWE-223", "T1110"),
        ("token-in-query leak census", "CWE-598", "T1552.001"),
        ("token-value redaction verified", "CWE-200", "T1110"),
    ],
    "POSTURE": [
        ("rotation point absent", "CWE-613", "T1181"),
        ("single_use point absent", "CWE-294", "T1110"),
        ("session_bound point absent", "CWE-613", "T1539"),
        ("origin_check point absent", "CWE-346", "T1557"),
        ("rate_control point absent", "CWE-770", "T1110"),
        ("idempotency point absent", "CWE-837", "T1110"),
        ("cache_safe point absent", "CWE-524", "T1552"),
        ("sig_one_time point absent", "CWE-347", "T1552"),
    ],
    "PLATFORM": [
        ("oauth2-oidc stack shape", "CWE-693", "T1110"),
        ("saml-sso stack shape", "CWE-693", "T1110"),
        ("payment-gateway shape", "CWE-693", "T1110"),
        ("captcha-gateway shape", "CWE-693", "T1110"),
        ("api-gateway shape", "CWE-693", "T1110"),
        ("idempotency-lib shape", "CWE-693", "T1110"),
        ("rate-limiter shape", "CWE-693", "T1110"),
        ("session-mgmt stack shape", "CWE-693", "T1110"),
        ("auth-flow checklist handoff", "CWE-223", "T1110"),
    ],
}

MATRIX_FAMILIES = list(MATRIX_CATALOG.keys())


def build_matrix():
    """Static catalog -> matrix rows (id, family, technique, cwe, mitre)."""
    rows = []
    for fam, items in MATRIX_CATALOG.items():
        for i, (name, cwe, mitre) in enumerate(items, 1):
            rows.append({"id": "%s-%02d" % (fam[:4].upper(), i),
                         "family": fam, "technique": name,
                         "cwe": cwe, "mitre": mitre})
    return rows


# ===========================================================================
# STAGE V - RENDERERS (findings md / test plan / remediation / exec / kickoff)
# ===========================================================================
def render_findings_md(scope, F, verdict_rows, chains, meta):
    L = ["# P22 REPLAY FINDINGS - %s" % scope.engagement, "",
         "**Engine:** WASP v%s / replay plan v%s | **Mode:** %s | "
         "**100%% INERT detection-only** (canary %s family)" %
         (VERSION, PLAN_VERSION, meta.get("mode", "active"), CANARY_FAMILY),
         "**Discipline:** GET-only | 2-sequential HARD cap | zero egress | "
         "bodies REDACTED", "",
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
    L = ["# P22 REPLAY TEST PLAN (kill tests + manual waves)", "",
         "RoE gates (sab default OFF - enable sirf written authorization par):", ""]
    for g, d in ROE_GATES:
        L.append("- `%s` = %s -> %s" % (g, str(gates.get(g, False)).lower(), d))
    L += ["", "## Kill tests (KD-01..KD-08)", ""]
    kds = [
        ("KD-01", "CSRF rotation/reuse manual wave",
         "fetch token 2x (rotation?) -> reuse stale in REAL state-changing "
         "request (RoE) -> observe single-use enforcement"),
        ("KD-02", "Idempotency duplicate wave",
         "same business transaction 2x (distinct canary ids) -> dedup? "
         "audit ledger reconcile"),
        ("KD-03", "OAuth state/nonce consumption wave",
         "complete flow 1x -> replay authorize URL -> session association?"),
        ("KD-04", "OTP replay/throttle wave",
         "verify-otp same code 2x + attempt-throttle census (RoE: max 5)"),
        ("KD-05", "Session binding wave",
         "same token from 2nd context (browser/UA) -> binding enforced?"),
        ("KD-06", "Bypass2 context shapes (17)",
         "manual proxy replay with each B2-xx shape -> validator diff"),
        ("KD-07", "Verb-override wave",
         "real mutation with X-HTTP-Method-Override -> enforcement?"),
        ("KD-08", "Signed-URL consumption wave",
         "signed resource 2x -> consumption/nonce enforced?"),
    ]
    for kid, title, steps in kds:
        L += ["### %s %s" % (kid, title), steps, ""]
    L += ["## FORBIDDEN-AUTO (manual+RoE ONLY - kabhi automate nahi)", "",
          "- parallel burst / single-packet H2 race execution",
          "- token brute-force / OTP enumeration loops",
          "- REAL one-time token replay (valid tokens)",
          "- real transaction/redeem/transfer duplication", "",
          "## Technique matrix snapshot",
          "Rows: %d | Families: %d" % (len(matrix_rows), len(set(
              m["family"] for m in matrix_rows)))]
    return "\n".join(L) + "\n"


def render_remediation(F):
    L = ["# P22 REPLAY REMEDIATION PLAYBOOK", "",
         "Har finding-family ke liye server-side fix guidance:", ""]
    rem = [
        ("REPLAY_CSRF", "Synchronizer-token pattern: per-session token, "
         "har request par rotate, stale reject 409; token ko session se bind "
         "karo; GET me token kabhi mat rakho; Origin/Referer + SameSite=Lax "
         "defense-in-depth."),
        ("REPLAY_IDEM", "Server-side idempotency store: Idempotency-Key -> "
         "response ledger (24h TTL), unique constraint per business entity, "
         "425/dedup response on duplicate, key ko session+operation se bind "
         "karo (client-supplied key trust nahi)."),
        ("REPLAY_NONCE", "OAuth state/nonce: one-time consumption store "
         "(issued->consumed), session-bound, 10-min TTL, consumed-replay "
         "par reject + audit log."),
        ("REPLAY_RESET", "Reset tokens: CSPRNG (>=128-bit), single-use, "
         "15-min expiry, session+IP binding review, response me token KABHI "
         "nahi, enumeration-safe messaging."),
        ("REPLAY_OTP", "OTP: 5-attempt lockout, 60s resend throttle, "
         "single-use consumption, server-side compare (constant-time), "
         "all-zero/sequential reject."),
        ("REPLAY_SESSION", "Session binding: token<->device fingerprint "
         "bind, privilege-change par rotate, logout invalidate, concurrent-"
         "session policy, fixation par re-issue."),
        ("RACE", "Idempotency + optimistic locking (version columns), "
         "unique constraints, serialized critical sections, per-account "
         "mutex for balance ops."),
        ("REPLAY_BYPASS2", "Canonical form validation: strict param parsing "
         "(first-wins documented), reject duplicate params, normalize path "
         "before authz, type-strict token compare."),
        ("ANTI_AUTO", "Progressive throttle (429+Retry-After), captcha on "
         "anomaly, per-account+per-IP dual scope, replay-attempt alerting."),
        ("VERB_REPLAY", "Method-override headers disable (X-HTTP-Method-*), "
         "verb allowlist per route, OPTIONS minimize."),
        ("CACHE_REPLAY", "Token routes par Cache-Control: no-store, private; "
         "Vary: Cookie/Auth; CDN token-route bypass; ETag weak-validator "
         "avoid on auth content."),
        ("SIGNED_URL", "Signature: HMAC-SHA256, param canonical ordering, "
         "nonce/jti single-use store, short TTL (<=5min), actor-binding, "
         "constant-time compare."),
        ("API_IDEM", "RFC-draft idempotency: header support, 425 Too Early, "
         "conditional requests (If-Match), webhook x-hub-signature HMAC "
         "verify + timestamp tolerance."),
        ("GQL_REPLAY", "Mutation idempotency guard (client mutation id + "
         "server ledger), persisted queries, depth/alias limits."),
        ("WS_REPLAY", "Per-message nonce + seq window, reconnect-token "
         "single-use, origin strict check."),
        ("TOKEN_LIFE", "Token policy: >=128-bit entropy, CSPRNG, format "
         "audit (no digits-only), sha1-chain audit log."),
        ("POSTURE", "8-point composite ko CI me track karo; WEAK (<3/8) "
         "endpoints par hardening sprint."),
        ("PLATFORM", "Stack-specific checklists (OAuth/SAML/PSP) + "
         "vendor replay-advisories subscribe."),
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
    L = ["# P22 REPLAY EXECUTIVE SUMMARY - %s" % scope.engagement, "",
         "Engagement: %s | Reference: %s | Mode: %s" % (
             scope.engagement, scope.ref or "n/a", meta.get("mode", "active")),
         "Engine: WASP v%s / replay plan v%s | 100%% INERT (canary %s)" % (
             VERSION, PLAN_VERSION, CANARY_FAMILY),
         "", "## Posture", "",
         "- CONFIRMED replay gaps: **%d**" % conf_n,
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
                 "dominant; manual waves REPLAY_TEST_PLAN.md dekho)")
    L += ["", "## Next steps", "",
          "1. RoE-gated manual waves (REPLAY_TEST_PLAN.md KD-01..KD-08)",
          "2. Remediation order (REPLAY_REMEDIATION.md)",
          "3. P23 misconfig handoff (feedforward.json)"]
    return "\n".join(L) + "\n"


def render_kickoff(scope, gates, conf):
    L = ["# P22 REPLAY KICKOFF GUIDE", "",
         "## Run", "",
         "```",
         "python3 wasp.py run --module 22      # P22 stage (sab gates OFF)",
         "python3 wasp.py run --module replay --config config.json",
         "python3 mod_replay.py                # gate reference",
         "```", "",
         "## Gates enable (sirf written authorization par)", "",
         "```json",
         json.dumps({g: True for g, _ in ROE_GATES[:2]}, indent=2),
         "```", "",
         "## Discipline (non-negotiable)", "",
         "- 100%% INERT detection-only (canary %s family)" % CANARY_FAMILY,
         "- GET-only module: koi POST/PUT/DELETE probe KABHI",
         "- 2-sequential HARD cap: same canary token max 2 requests",
         "- PARALLEL BURST FORBIDDEN (race = documented-only)",
         "- zero egress: scope firewall (wasp_core LAYER-4)",
         "- bodies REDACTED: token values sirf sha1-bucket",
         "- outputs RWX 0777", "",
         "## Caps (config.json)", "",
         "```json",
         json.dumps({k: v for k, v in DEFAULTS.items()
                     if k.startswith("replay_") and not
                     k.startswith("replay_allow")}, indent=2),
         "```"]
    return "\n".join(L) + "\n"


def render_playbooks():
    L = ["# P22 MANUAL PLAYBOOKS (FORBIDDEN-AUTO techniques)", "",
         "Ye techniques automation me KABHI nahi - sirf written RoE + "
         "manual execution:", ""]
    for i, (sid, name, disc) in enumerate(RACE_TECHNIQUES, 1):
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Evidence discipline", "",
          "- har manual step ka request/response capture (RoE window me)",
          "- canary identifiers use karo (real ids sirf final PoC me, "
          "owner consent ke saath)",
          "- replay proofs: timestamped pair (req1/req2 + status/body-delta)",
          "- cleanup: koi canary residue chhodna nahi"]
    return "\n".join(L) + "\n"


def render_chains_txt(chains):
    L = ["P22 REPLAY KILL-CHAINS (CH01..CH%02d)" % len(chains), ""]
    for c in chains:
        L.append("%s | %s | %s" % (c["id"], c["title"], c["evidence"]))
    return "\n".join(L) + "\n"


def render_matrix_txt(matrix_rows):
    L = ["P22 TECHNIQUE MATRIX - %d rows x %d families" % (
        len(matrix_rows), len(set(m["family"] for m in matrix_rows))), ""]
    cur = None
    for m in matrix_rows:
        if m["family"] != cur:
            cur = m["family"]
            L += ["", "## %s" % cur]
        L.append("%s | %-52s | %s | %s" % (m["id"], m["technique"][:52],
                                           m["cwe"], m["mitre"]))
    return "\n".join(L) + "\n"


def build_hypotheses(results, tc, posture):
    """Offline hypotheses (manual-review leads)."""
    hyps = []
    for r in (results.get("csrf") or {}).get("rows", []):
        if r.get("rotated") is False:
            hyps.append({"h": "CSRF token static (no rotation) @ %s - "
                         "single-use manual confirm" % r.get("url"),
                         "prio": "high" if r.get("reuse", {}).get("accepted")
                         else "medium"})
    for r in (results.get("rate") or {}).get("rows", []):
        if r.get("throttle_absent"):
            hyps.append({"h": "Throttle absent @ %s - replay-wave "
                         "monitoring review" % r.get("url"), "prio": "medium"})
    for r in (results.get("cache") or {}).get("rows", []):
        if r.get("cacheable"):
            hyps.append({"h": "Token-in-cacheable-GET @ %s - shared-cache "
                         "review" % r.get("url"), "prio": "high"})
    for w in (posture.get("weak") or [])[:8]:
        hyps.append({"h": "Posture WEAK (%d/8) @ %s" % (w["score"], w["url"]),
                     "prio": "high"})
    if not hyps:
        hyps.append({"h": "Dominant HARDENED posture - kaunse controls "
                     "kabhi fail hote hain (negative-path review)",
                     "prio": "info"})
    return hyps


# ===========================================================================
# STAGE V-W - WRITE REPORTS (48 artifacts) + FEEDFORWARD + MANIFEST
# ===========================================================================
def write_reports(out, scope, F, ctx, meta, results, tc, disc, conf,
                  chains, verdict_rows, matrix_rows, posture, lifecycle,
                  platform, guard, hyps):
    """Sab artifacts likh (48). Bodies REDACTED (names/booleans/sha1 only)."""
    manifest = []

    def _w_json(name, obj):
        save_json(os.path.join(out, name), obj)
        manifest.append(name)

    def _w_text(name, txt):
        save_text(os.path.join(out, name), txt)
        manifest.append(name)

    targets = results.get("targets") or []

    # 1-3 targets/endpoints/ranking
    _w_json("replay_targets.json", {
        "count": len(targets),
        "targets": [{"url": t.get("url"), "score": t.get("score"),
                     "kinds": t.get("kinds", [])} for t in targets]})
    _w_text("replay_endpoints.txt", "\n".join(
        [t.get("url", "") for t in targets]) + "\n")
    _w_json("replay_ranking.json", {
        "paths_cap": conf.get("replay_paths_cap"),
        "ranked": [{"url": t.get("url"), "score": t.get("score")}
                   for t in targets]})
    # 4 coverage
    gates = {g: bool(conf.get(g)) for g, _ in ROE_GATES}
    _w_json("replay_coverage.json", {
        "mode": ctx.get("mode"), "sources": disc.get("sources", []),
        "probes_total": meta.get("probes_total", 0),
        "stages": ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
                   "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
                   "W", "X", "Y", "Z"],
        "gates": gates})
    # 5-7 token census
    _w_json("replay_param_census.json", tc.get("rows", []))
    _w_json("replay_token_census.json", {
        "total": tc.get("total", 0),
        "param_names": tc.get("param_names", [])})
    _w_json("replay_token_records.json", meta.get("token_recs", []))
    _w_text("replay_token_names.txt", "\n".join(
        sorted(set([r.get("name", "") for r in meta.get("token_recs", [])
                    if r.get("name")]))) + "\n")
    # 8-9 baseline/waf
    _w_json("replay_baseline.json", results.get("baseline", {}).get("rows", []))
    _w_json("replay_waf.json", results.get("baseline", {}).get("waf", []))
    # 10-15 gated censuses
    _w_json("replay_csrf_rotation.json", results.get("csrf", {}))
    _w_json("replay_idempotency.json", results.get("idem", {}))
    _w_json("replay_nonce_state.json", results.get("nonce", {}))
    _w_json("replay_reset_surface.json", results.get("reset", {}))
    _w_json("replay_otp_surface.json", results.get("otp", {}))
    _w_json("replay_session_diff.json", results.get("session", {}))
    # 16-18
    _w_json("replay_race_surface.json", results.get("race", {}))
    _w_json("replay_bypass2.json", results.get("bypass2", {}))
    _w_json("replay_anti_automation.json", results.get("rate", {}))
    # 19-24
    _w_json("replay_verb_replay.json", results.get("verb", {}))
    _w_json("replay_cache_replay.json", results.get("cache", {}))
    _w_json("replay_signed_urls.json", results.get("signed", {}))
    _w_json("replay_api_idempotency.json", results.get("api", {}))
    _w_json("replay_gql_surface.json", results.get("gql", {}))
    _w_json("replay_ws_surface.json", results.get("ws", {}))
    # 25-28 v24 extras
    _w_json("replay_token_lifecycle.json", lifecycle)
    _w_json("replay_posture.json", posture)
    _w_json("replay_platform.json", platform)
    _w_json("replay_secret_guard.json", guard)
    # 29-31 verdicts + chains
    _w_json("replay_verdicts.json", {"count": len(verdict_rows),
                                     "rows": verdict_rows})
    _w_json("replay_chains.json", {"count": len(chains), "chains": chains})
    _w_text("REPLAY_CHAINS.txt", render_chains_txt(chains))
    # 32-33 matrix
    _w_json("replay_matrix.json", {
        "rows": len(matrix_rows),
        "families": sorted(set(m["family"] for m in matrix_rows)),
        "matrix": matrix_rows})
    _w_text("REPLAY_MATRIX.txt", render_matrix_txt(matrix_rows))
    # 34 hypotheses
    _w_json("replay_hypotheses.json", {"count": len(hyps), "hypotheses": hyps})
    # 35 findings.json
    _w_json("findings.json", {
        "module": NAME, "phase": PHASE, "plan_version": PLAN_VERSION,
        "engagement": scope.engagement, "generated": now_iso(),
        "mode": ctx.get("mode"), "count": len(F.items),
        "severity_counts": _sev_counts(F),
        "findings": F.items})
    # 36-41 renderers
    _w_text("REPLAY_FINDINGS.md", render_findings_md(
        scope, F, verdict_rows, chains, meta))
    _w_text("REPLAY_TEST_PLAN.md", render_test_plan(F, gates, matrix_rows))
    _w_text("REPLAY_REMEDIATION.md", render_remediation(F))
    _w_text("EXEC_SUMMARY.md", render_exec_summary(
        scope, F, posture, verdict_rows, meta))
    _w_text("REPLAY_KICKOFF.md", render_kickoff(scope, gates, conf))
    _w_text("REPLAY_PLAYBOOKS.md", render_playbooks())
    # 42-45 aux
    _w_text("replay_gates.txt", "\n".join(
        ["RoE gates (default OFF - enable sirf written authorization par):"] +
        ["%s = %s # %s" % (g, str(bool(conf.get(g))).lower(), d)
         for g, d in ROE_GATES]) + "\n")
    _w_text("replay_posture.txt", "\n".join(
        ["P22 REPLAY-RESISTANCE POSTURE (8-point composite):"] +
        ["%-58s %d/8 %s" % (r["url"][:58], r["score"], r["grade"])
         for r in posture.get("rows", [])] +
        ["", "points: " + ", ".join("%s=%s" % (p, d)
                                    for p, d in posture.get("points", []))]) + "\n")
    _w_text("replay_summary.txt", "\n".join([
        "P22 REPLAY SUMMARY - %s" % scope.engagement,
        "mode=%s probes=%s findings=%d matrix=%d chains=%d "
        "verdicts=%d posture_rows=%d weak_entropy=%d" % (
            ctx.get("mode"), meta.get("probes_total", 0), len(F.items),
            len(matrix_rows), len(chains), len(verdict_rows),
            len(posture.get("rows", [])), lifecycle.get("weak_count", 0)),
        "CONFIRMED=%d SUSPECTED=%d HARDENED=%d BLOCKED=%d SKIPPED=%d" % (
            len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
            len([r for r in verdict_rows if r["verdict"] == "SUSPECTED"]),
            len([r for r in verdict_rows if r["verdict"] == "HARDENED"]),
            len([r for r in verdict_rows if r["verdict"] == "BLOCKED"]),
            len([r for r in verdict_rows if r["verdict"] == "SKIPPED"]))]) + "\n")
    _w_text("replay_live_endpoints.txt", "\n".join(sorted(set(
        [b.get("url") for b in results.get("baseline", {}).get("rows", [])
         if b.get("status") and b.get("status") < 400]))[:60]) + "\n")
    skipped = [g for g, _ in ROE_GATES if not bool(conf.get(g))]
    _w_text("replay_skipped_waves.txt", "\n".join(
        ["RoE-gated manual waves (SKIPPED - document in test plan):"] +
        ["%s -> %s" % (g, dict(ROE_GATES)[g]) for g in skipped]) + "\n")

    # 44 feedforward (W)
    ff_map = {
        "to_phase23_misconfig": {
            "verb_override_endpoints": [r.get("url") for r in
                                        (results.get("verb") or {}).get("rows", [])
                                        if r.get("override_echo")][:10],
            "cacheable_token_routes": [r.get("url") for r in
                                       (results.get("cache") or {}).get("rows", [])
                                       if r.get("cacheable")][:10],
            "platform_shapes": platform.get("shapes", [])},
        "to_phase24_cloud": {
            "signed_url_surface": [r.get("url") for r in
                                   (results.get("signed") or {}).get("rows", [])
                                   if r.get("sig_params")][:10],
            "webhook_census": [t.get("url") for t in targets
                               if "webhook" in (t.get("url") or "")][:6]},
        "to_phase25_controls": {
            "posture_rows": [{"url": r["url"], "score": r["score"],
                              "grade": r["grade"]}
                             for r in posture.get("rows", [])][:12],
            "throttle_absent": [r.get("url") for r in
                                (results.get("rate") or {}).get("rows", [])
                                if r.get("throttle_absent")][:10]},
        "to_phase11_access": {
            "session_unbound": [r.get("url") for r in
                                (results.get("session") or {}).get("rows", [])
                                if r.get("binding_absent")][:10],
            "idor_replay_aid": [t.get("url") for t in targets
                                if REPLAY_VERB_RX.search(t.get("url") or "")][:10]},
        "to_phase12_inject": {
            "bypass2_accepted": sorted(set(sum(
                [r.get("accepted_ids", []) for r in
                 (results.get("bypass2") or {}).get("rows", [])], [])))[:17],
            "token_param_names": tc.get("param_names", [])[:15]},
        "to_phase32_report": {
            "exec_summary": "EXEC_SUMMARY.md",
            "findings_json": "findings.json",
            "mode": ctx.get("mode")},
    }
    write_feedforward(out, "phase22", ff_map, notes=[
        "P22 v%s INERT replay census (GET-only, canary %s)" % (
            PLAN_VERSION, CANARY_FAMILY),
        "%d artifacts | %d probes | gates default OFF" % (
            len(manifest) + 2, meta.get("probes_total", 0))])
    manifest += ["feedforward.json"]

    # 45 MANIFEST
    write_manifest(out, "phase22", manifest, stats={
        "mode": ctx.get("mode"), "probes": meta.get("probes_total", 0),
        "findings": len(F.items), "matrix_rows": len(matrix_rows),
        "chains": len(chains), "verdicts": len(verdict_rows),
        "artifacts": len(manifest) + 1,
        "gates_on": [g for g, _ in ROE_GATES if bool(conf.get(g))],
        "duration_sec": round(meta.get("duration", 0.0), 1)}, notes=[
        "100% INERT detection-only | GET-only module | "
        "2-sequential HARD cap | zero egress | RWX 0777"])
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

    head("Phase 22 - Replay & Anti-Replay Security (detection-only, INERT) "
         "(v%s) | %s" % (PLAN_VERSION, scope.describe()))
    warn("Replay discipline: koi REAL replay KABHI nahi (canary %s tokens "
         "never valid) | GET-only module (koi POST/PUT/DELETE probe nahi) | "
         "same canary token MAX 2 SEQUENTIAL requests | parallel burst "
         "FORBIDDEN | zero egress | bodies REDACTED." % CANARY_FAMILY)
    on_gates = [g for g, _ in ROE_GATES if bool(conf.get(g))]
    if on_gates:
        warn("RoE gates ON: %s" % ", ".join(on_gates))
    else:
        info("Sab RoE gates OFF (detection-only census mode) - gated waves "
             "REPLAY_TEST_PLAN.md me documented hain.")
    info("caps: paths=%s | probes=%s | bypass2=%s | cold=%s" % (
        conf.get("replay_paths_cap"), conf.get("replay_probe_cap"),
        conf.get("replay_bypass2_cap"), conf.get("replay_cold_paths")))

    F = Findings()
    meta = {"probes_total": 0, "token_recs": [], "mode": "active"}
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
    head("Stage A - Replay surface discovery (12-module ff + miners + cold)")
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
        disc = discover_replay_surface(ctxd, scope, conf)
        cp.mark(ckA, disc, summary="replay surface")
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

    # ---------------- Stage C: token census ----------------
    head("Stage C - One-time token census (params/headers/cookies/hidden)")
    ckC = "stageC:tokens"
    if cp.is_done(ckC):
        tc = cp.result_of(ckC) or {"rows": [], "total": 0, "param_names": []}
        ok("Replayed token census (checkpoint)")
    elif passive:
        tc = {"rows": [], "total": 0, "param_names": []}
        warn("passive: token census skipped (0 probes)")
    else:
        tc = token_census(http, disc.get("targets", []), conf)
        cp.mark(ckC, tc, summary="token census")
    results["tc"] = tc
    token_recs = token_records_from_census(tc.get("rows", []))
    meta["token_recs"] = token_recs[:int(conf.get("replay_token_cap", 40))]
    ok("token records=%d (values REDACTED - sha1 buckets only)" %
       len(meta["token_recs"]))

    # token-census findings (names-only)
    for row in tc.get("rows", [])[:int(conf.get("replay_param_cap", 30))]:
        kinds = set(t.get("kind") for t in row.get("tokens", []))
        if "csrf" in kinds:
            F.add("replay_token_param", "CSRF-token surface (names census)",
                  row.get("url", ""), "csrf-shaped token param/field census")
        elif "otp" in kinds or "reset" in kinds:
            F.add("replay_token_param", "OTP/reset-token surface (names)",
                  row.get("url", ""), "one-time token family census")
        elif kinds:
            F.add("replay_token_param", "Token-shaped params (census)",
                  row.get("url", ""), "kinds=%s" % ",".join(sorted(kinds)))

    # ---------------- Stages D-F: gated censuses ----------------
    head("Stage D - CSRF rotation/reuse census (GATED)")
    ckD = "stageD:csrf"
    if cp.is_done(ckD):
        results["csrf"] = cp.result_of(ckD) or {}
        ok("Replayed csrf census (checkpoint)")
    elif passive:
        results["csrf"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_csrf_probe"):
        results["csrf"] = csrf_rotation_census(http, tc.get("rows", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["csrf"].get("skipped_note", ""))
    else:
        results["csrf"] = csrf_rotation_census(http, tc.get("rows", []), conf)
        cp.mark(ckD, results["csrf"], summary="csrf census")
    meta["probes_total"] += len(results["csrf"].get("rows", []))

    head("Stage E - Idempotency-key dedup census (GATED, 2-sequential)")
    ckE = "stageE:idem"
    if cp.is_done(ckE):
        results["idem"] = cp.result_of(ckE) or {}
        ok("Replayed idem census (checkpoint)")
    elif passive:
        results["idem"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_idem_probe"):
        results["idem"] = idempotency_census(http, disc.get("targets", []),
                                             conf)
        warn("SKIPPED (gate OFF): %s" % results["idem"].get("skipped_note", ""))
    else:
        results["idem"] = idempotency_census(http, disc.get("targets", []),
                                             conf)
        cp.mark(ckE, results["idem"], summary="idem census")
    meta["probes_total"] += len(results["idem"].get("rows", []))

    head("Stage F - Nonce/state reuse census (GATED)")
    ckF = "stageF:nonce"
    if cp.is_done(ckF):
        results["nonce"] = cp.result_of(ckF) or {}
        ok("Replayed nonce census (checkpoint)")
    elif passive:
        results["nonce"] = {"rows": [],
                            "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_nonce_probe"):
        results["nonce"] = nonce_state_census(http, disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["nonce"].get("skipped_note", ""))
    else:
        results["nonce"] = nonce_state_census(http, disc.get("targets", []),
                                              conf)
        cp.mark(ckF, results["nonce"], summary="nonce census")
    meta["probes_total"] += len(results["nonce"].get("rows", []))

    # ---------------- Stage G: reset surface ----------------
    head("Stage G - Reset-token surface (names-only + playbook)")
    ckG = "stageG:reset"
    if cp.is_done(ckG):
        results["reset"] = cp.result_of(ckG) or {}
    elif passive:
        results["reset"] = {"rows": [], "playbook": RESET_PLAYBOOK_ROWS,
                            "note": "passive"}
    else:
        results["reset"] = reset_surface_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckG, results["reset"], summary="reset surface")
    live_reset = [r for r in results["reset"].get("rows", [])
                  if r.get("live")]
    if live_reset:
        F.add("replay_reset_surface", "Password-reset surface live",
              live_reset[0].get("url", ""),
              "%d reset-shaped endpoints live (names-only census)" %
              len(live_reset))
    meta["probes_total"] += len(results["reset"].get("rows", []))

    # ---------------- Stage H: OTP ----------------
    head("Stage H - OTP surface census (GATED)")
    ckH = "stageH:otp"
    if cp.is_done(ckH):
        results["otp"] = cp.result_of(ckH) or {}
        ok("Replayed otp census (checkpoint)")
    elif passive:
        results["otp"] = {"rows": [],
                          "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_otp_probe"):
        results["otp"] = otp_surface_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" % results["otp"].get("skipped_note", ""))
    else:
        results["otp"] = otp_surface_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckH, results["otp"], summary="otp census")
    meta["probes_total"] += len(results["otp"].get("rows", []))

    # ---------------- Stage I: session diff ----------------
    head("Stage I - Session binding A/B differential (GATED)")
    ckI = "stageI:session"
    if cp.is_done(ckI):
        results["session"] = cp.result_of(ckI) or {}
        ok("Replayed session diff (checkpoint)")
    elif passive:
        results["session"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_session_probe"):
        results["session"] = session_replay_diff(http, disc.get("targets", []),
                                                 conf)
        warn("SKIPPED (gate OFF): %s" %
             results["session"].get("skipped_note", ""))
    else:
        results["session"] = session_replay_diff(http, disc.get("targets", []),
                                                 conf)
        cp.mark(ckI, results["session"], summary="session diff")
    meta["probes_total"] += len(results["session"].get("rows", []))

    # ---------------- Stage J: race documented ----------------
    head("Stage J - Race-condition surface (DOCUMENTED-ONLY, 0 probes)")
    results["race"] = race_surface_documented()
    F.add("replay_race_documented", "Race-condition techniques documented "
          "(12 playbook rows)", "*", "execution FORBIDDEN-AUTO; manual RoE "
          "wave only (REPLAY_PLAYBOOKS.md)")

    # ---------------- Stage K: bypass2 ----------------
    head("Stage K - Bypass matrix v2: 17 replay-bypass shapes (GATED)")
    ckK = "stageK:bypass2"
    if cp.is_done(ckK):
        results["bypass2"] = cp.result_of(ckK) or {}
        ok("Replayed bypass2 census (checkpoint)")
    elif passive:
        results["bypass2"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_bypass2"):
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" %
             results["bypass2"].get("skipped_note", ""))
    else:
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckK, results["bypass2"], summary="bypass2 census")
    meta["probes_total"] += len(results["bypass2"].get("rows", []))

    # ---------------- Stage L: anti-automation ----------------
    head("Stage L - Anti-automation census (bounded positive controls)")
    ckL = "stageL:rate"
    if cp.is_done(ckL):
        results["rate"] = cp.result_of(ckL) or {}
    elif passive:
        results["rate"] = {"rows": [], "note": "passive"}
    else:
        results["rate"] = anti_automation_census(http, disc.get("targets", []),
                                                 conf)
        cp.mark(ckL, results["rate"], summary="anti-auto census")
    meta["probes_total"] += len(results["rate"].get("rows", []))

    # ---------------- Stage M: verb ----------------
    head("Stage M - Verb/method-override census (GATED)")
    ckM = "stageM:verb"
    if cp.is_done(ckM):
        results["verb"] = cp.result_of(ckM) or {}
        ok("Replayed verb census (checkpoint)")
    elif passive:
        results["verb"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_verb_probe"):
        results["verb"] = verb_replay_census(http, disc.get("targets", []),
                                             conf)
        warn("SKIPPED (gate OFF): %s" % results["verb"].get("skipped_note", ""))
    else:
        results["verb"] = verb_replay_census(http, disc.get("targets", []),
                                             conf)
        cp.mark(ckM, results["verb"], summary="verb census")
    meta["probes_total"] += len(results["verb"].get("rows", []))

    # ---------------- Stage N: cache ----------------
    head("Stage N - Cache/replay interplay census")
    ckN = "stageN:cache"
    if cp.is_done(ckN):
        results["cache"] = cp.result_of(ckN) or {}
    elif passive:
        results["cache"] = {"rows": [], "note": "passive"}
    else:
        results["cache"] = cache_replay_census(http, disc.get("targets", []),
                                               conf)
        cp.mark(ckN, results["cache"], summary="cache census")
    meta["probes_total"] += len(results["cache"].get("rows", []))

    # ---------------- Stage O: signed urls ----------------
    head("Stage O - Signed/one-time URL census (GATED)")
    ckO = "stageO:signed"
    if cp.is_done(ckO):
        results["signed"] = cp.result_of(ckO) or {}
        ok("Replayed signed census (checkpoint)")
    elif passive:
        results["signed"] = {"rows": [],
                             "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("replay_allow_signed_probe"):
        results["signed"] = signed_url_census(http, disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" %
             results["signed"].get("skipped_note", ""))
    else:
        results["signed"] = signed_url_census(http, disc.get("targets", []),
                                              conf)
        cp.mark(ckO, results["signed"], summary="signed census")
    meta["probes_total"] += len(results["signed"].get("rows", []))

    # ---------------- Stage P-R: api/gql/ws ----------------
    head("Stage P - API idempotency design census (GET/OPTIONS-only)")
    ckP = "stageP:api"
    if cp.is_done(ckP):
        results["api"] = cp.result_of(ckP) or {}
    elif passive:
        results["api"] = {"rows": [], "note": "passive"}
    else:
        results["api"] = api_idempotency_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckP, results["api"], summary="api idem census")
    meta["probes_total"] += len(results["api"].get("rows", []))

    head("Stage Q/R - GraphQL + WebSocket replay surfaces (names-only)")
    results["gql"] = gql_replay_surface(ctxd.get("base_dir"))
    results["ws"] = ws_replay_surface(ctxd.get("base_dir"))

    # ---------------- Stage X-Y-Z: v24 extras (offline) ----------------
    head("Stage X/Y/Z - Token lifecycle + posture composite + platform fp")
    lifecycle = token_lifecycle_census(meta.get("token_recs", []))
    posture = posture_composite(results, meta.get("token_recs", []))
    probe_texts = [(b.get("title") or "") for b in
                   results.get("baseline", {}).get("rows", [])] + \
                  [" ".join(t.get("kinds", [])) for t in
                   results.get("targets", [])] + \
                  [json.dumps(results.get("gql", {}))[:2000]]
    platform = platform_fingerprint(probe_texts)

    # ---------------- Stage S/T/U: chains + verdict + matrix ----------------
    head("Stage S/T/U - Kill-chains + verdict engine + technique matrix")
    ff_all = read_ff_safe(ctxd.get("base_dir"), scope)
    chains = build_chains(results, ff_all)
    verdict_rows = verdict_engine(results)
    matrix_rows = build_matrix()

    # findings from verdict rows
    _findings_from_verdicts(F, verdict_rows)
    # posture findings
    for w in posture.get("weak", [])[:8]:
        F.add("replay_posture_weak", "Replay-resistance posture WEAK",
              w.get("url", ""), "score=%d/8 (points: %s)" % (
                  w["score"], ",".join(k for k, v in w["points"].items()
                                       if v is False)))
    if len(posture.get("strong", [])) >= 1:
        F.add("replay_posture_strong", "Replay-resistance posture STRONG",
              posture["strong"][0].get("url", ""),
              "score>=%d/8 positive controls dominant" %
              posture["strong"][0]["score"])
    for r in lifecycle.get("rows", []):
        if r.get("weak_shape"):
            F.add("replay_token_weak_entropy", "Weak token-entropy shape",
                  r.get("url", ""), "kind=%s len_bucket=%s format=%s "
                  "entropy=%s (sha1-only)" % (r.get("kind"),
                                              r.get("len_bucket"),
                                              r.get("format"),
                                              r.get("entropy")))
    if platform.get("shapes"):
        F.add("replay_platform_fp", "Platform fingerprint shapes",
              "*", "shapes=%s" % ",".join(platform["shapes"][:8]))
    # api/gql/ws surface findings
    for r in (results.get("api") or {}).get("rows", []):
        if r.get("mutation_methods_observed") and not r.get("idem_header_ack"):
            F.add("replay_api_idem_header_absent",
                  "Mutation API without idempotency support", r.get("url", ""),
                  "methods=%s (GET/OPTIONS observation)" %
                  ",".join(r["mutation_methods_observed"]))
    if (results.get("gql") or {}).get("count"):
        F.add("replay_gql_mutation_surface", "GraphQL writable-mutation "
              "surface (names-only)", "*",
              "%d mutation names (NEVER sent)" % results["gql"]["count"])
    if (results.get("ws") or {}).get("count"):
        F.add("replay_ws_replay_surface", "WebSocket replay surface",
              "*", "%d ws endpoints (frames NEVER)" % results["ws"]["count"])
    for r in (results.get("verb") or {}).get("rows", []):
        if r.get("override_echo"):
            F.add("replay_method_override_echo", "Method-override header "
                  "echo", r.get("url", ""), "shapes=%d" %
                  len(r.get("override_echo", [])))
    for r in (results.get("cache") or {}).get("rows", []):
        if r.get("cacheable"):
            F.add("replay_cacheable_token", "Token response cacheable",
                  r.get("url", ""), "cache-control=%s" %
                  r.get("cache_control", ""))
    for r in (results.get("rate") or {}).get("rows", []):
        if r.get("rate_limited") or r.get("retry_after"):
            F.add("replay_rate_limit_present", "Rate-limit positive control",
                  r.get("url", ""), "throttle present (HARDENED)")
        elif r.get("throttle_absent"):
            F.add("replay_rate_limit_absent", "Replay-throttle absent signal",
                  r.get("url", ""), "bounded 6-GET burst no throttle signal")

    # ---------------- Stage Z: final secrets guard ----------------
    payloads = [("REPLAY_FINDINGS.md", pii_redact(render_findings_md(
        scope, F, verdict_rows, chains, meta)))]
    guard = secrets_guard(payloads)
    if guard.get("hits"):
        F.add("replay_secret_guard_hit", "Secret-guard sweep triggered",
              "*", "artifact shapes redacted (CWE-200 aid)")

    # ---------------- Stage V/W: reports + handoff ----------------
    head("Stage V/W - Reports (48 artifacts) + feedforward + manifest")
    meta["duration"] = time.time() - t_start
    manifest_files = write_reports(out, scope, F, ctxd, meta, results, tc,
                                   disc, conf, chains, verdict_rows,
                                   matrix_rows, posture, lifecycle, platform,
                                   guard, build_hypotheses(results, tc,
                                                           posture))
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
        key = {"D": {"CONFIRMED": "replay_csrf_reuse_confirmed",
                     "SUSPECTED": "replay_csrf_reuse_suspected",
                     "HARDENED": "replay_csrf_rotated"},
               "E": {"CONFIRMED": "replay_idem_missing_confirmed",
                     "SUSPECTED": "replay_idem_key_echo",
                     "HARDENED": "replay_idem_dedup_present"},
               "F": {"CONFIRMED": "replay_state_reuse_confirmed",
                     "HARDENED": "replay_state_consumed"},
               "H": {"CONFIRMED": "replay_otp_weak_accept",
                     "HARDENED": "replay_otp_reject_ok"},
               "I": {"CONFIRMED": "replay_session_unbound",
                     "HARDENED": "replay_session_bound"},
               "K": {"CONFIRMED": "replay_bypass2_accepted",
                     "BLOCKED": "replay_bypass2_blocked",
                     "HARDENED": "replay_bypass2_blocked"},
               "O": {"CONFIRMED": "replay_signed_url_replayable",
                     "HARDENED": "replay_signed_one_time"},
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
    print("WASP mod_replay.py (Phase 22 - Replay & Anti-Replay, v%s)" %
          PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 22   (ya --module replay)")
    print("  self-test : python3 test_mod_replay.py")
    print("\n  RoE gates (config.json):")
    for g, d in ROE_GATES:
        print("    %s=false (default) # %s" % (g, d))
    print("  Safety: koi REAL replay KABHI nahi (canary %s) | GET-only "
          "module | 2-sequential HARD cap | parallel burst FORBIDDEN | "
          "zero egress | bodies REDACTED" % CANARY_FAMILY)
    print("  v24 ULTRA: 26 stages (A..Z) | 8 RoE gates | 17-secret bypass2 | "
          "12 race playbooks (documented) | 193-row x 18-family matrix | "
          "24 kill-chains | 48 artifacts | posture composite | token "
          "lifecycle | platform fp")


if __name__ == "__main__":
    main()
