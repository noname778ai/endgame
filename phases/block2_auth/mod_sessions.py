#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP Module: mod_sessions.py  |  Phase 10 - Session Management & Token Security
===============================================================================
v10.0.0 ULTRA PRO MAX. Authorized security testing ONLY.

Ye Phase 9 (auth) ke baad aata hai: Phase 9 "andar aa sakte hain kya?" poochta
hai, Phase 10 "andar aane ke baad session/token kitna mazboot hai?" poochta hai.

STAGES (v1.0 base, ab ULTRA me bhi intact)
  A  Session surface discovery ..... Phase 9 feedforward + Phase 6 session_model
                                     + Phase 7 JS + cookie/route mining (ranked)
  B  Identity & token capture ...... isolated sessions (own cookie jar), har
                                     identity ka token fingerprint
  C  Cookie security deep-dive ..... flags, __Host-/__Secure- rules, Domain
                                     scope, Path, expiry model, duplicates,
                                     session-tossing, name entropy
  D  Token randomness lab .......... per-position entropy, Hamming distance,
                                     chi-square uniformity, NIST-lite monobit +
                                     runs + serial correlation, birthday bound
  E  Session fixation .............. pre-auth token reuse after login (sirf tab
                                     jab test credentials diye gaye hon)
  F  Session lifecycle ............. logout invalidation, cookie clearing,
                                     idle/absolute timeout inference
  G  Session binding ............... IP / User-Agent / header change par session
                                     accept hota hai ya nahi (hijack resistance)
  H  JWT deep analysis ............. alg/kid/jku/x5u attack surface, claim
                                     hygiene, JWKS key strength, weak-HMAC-secret
                                     crack (bounded list)
  I  JWT tamper matrix ............. alg=none variants, empty signature, claim
                                     escalation, signature strip (gated, GET only)
  J  Token leakage channels ........ URL/query tokens, Referer risk, response-body
                                     tokens, localStorage/sessionStorage hints
  K  Session flow map + reports .... Mermaid lifecycle graph, SESSION_FINDINGS.md,
                                     session_test_plan.md, feedforward + MANIFEST

ULTRA PRO MAX ADDITIONS (v10) - naye + famous session attack techniques
  L  Client-side session lab (0 req) . Flask itsdangerous / Rails Marshal /
                                     Laravel / Play / connect.sid detection,
                                     base64-JSON embedded privilege state,
                                     ASP.NET ViewState surface, unsigned-state
                                     decode surface (offline, pure decode)
  M  Cache deception & mix-up ...... path-suffix variants (<path>.css, /x.css)
                                     with OWN session + X-Cache/CDN/Age signals
                                     + cacheable+Vary-less mix-up surface
  N  Cookie conflict / toss ........ duplicate-name parser probe (own session
                                     values), shadow acceptance detection
  O  Refresh token rotation ........ refresh call -> OLD refresh token reuse
                                     check (single-use rotation verify, bounded)
  P  Concurrent session cap ........ 2 logins same creds (test accounts only) ->
                                     dono sessions valid? (cap detect)
  Q  JWT attack matrix v2 .......... duplicate-claims parse, RS256->HS256
                                     confusion (JWKS pubkey se HMAC craft, DER
                                     encoder pure-python), jwk-header injection
                                     craft, logout-ke-baad JWT reuse probe
  R  Session page hardening (0 req) . clickjacking on token pages, HSTS missing,
                                     referrer-policy weak, cache mix-up surface
                                     (extended capture headers se)
  S  CSRF defense mapping (passive) . P9 forms + SameSite aggregate -> state-
                                     change forms bina CSRF token
  T  WebSocket session surface ..... P7 ws endpoints + cookie model -> auth
                                     model unknown hint (no WS handshake)

v10 BUG FIXES (stock v10.0.0 me mile, yahan fix):
  BUG-1: fixation/concurrent/refresh login POSTs read_only_post=True ke bina
         the -> ULTRA core ka RWX gate ScopeError raise karta -> module crash.
         Fix: saare read-only intent POSTs par read_only_post=True +
         _ensure_read_only_support() shim (purane cores par kwarg drop).
  BUG-2: live filter sirf `if r.get("status")` karti thi -> 404/410/500 bhi
         "live" ban jaate the -> buckets me dead URLs + 404-page false
         positives. Fix: live = status and status < 400.
  BUG-3: Stage I (tamper) ke findings derivation cp.is_done() else-branch ke
         ANDAR thi -> resume par checkpoint replay hota tha par findings
         gayab ho jaate. Fix: derivation replay path par bhi (restructure).
  SAFETY: allow_active=False ab poora honor hota hai (stock me sirf warning
         thi par D/E/F/G/I probes phir bhi chalte the). Passive mode me sirf
         discovery + capture + cookie/JWT offline analysis chalti hai.

STATISTICS (pure python, koi numpy/scipy nahi)
  Shannon entropy (overall + per-position), Hamming distance matrix, chi-square
  goodness-of-fit with regularized incomplete gamma p-value, NIST-lite monobit /
  runs / serial-correlation, birthday-bound entropy estimate.

SAFETY VALVES
  * allow_active=True zaroori hai active stages ke liye.
  * Session fixation / concurrent tests sirf `session_test_credentials` diye
    jaane par - kisi real user ka session nahi.
  * Logout test sirf apne synthetic session par.
  * JWT tamper/matrix probes GET-only, hard-capped, gated by config.
  * Cache deception probe apne session values ke saath, max 3 requests.
  * Refresh rotation test sirf APNE captured refresh token par.
  * Cookie conflict probe apne synthetic session par (koi real user value nahi).
  * Koi destructive action nahi, koi password change nahi, koi data write nahi.
"""

import os
import re
import sys
import json
import math
import time
import hmac
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
                           outdir_for, now_iso, save_json, save_text, load_json, rand_str,
                           shannon_entropy, sha1, sha256, host_of, median, mad, robust_z,
                           truncate, redact, module_ctx, write_feedforward,
                           write_manifest, info, ok, warn, err, head, C, VERSION)
except ImportError:
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    sys.exit(1)

NAME = "sessions"
PHASE = "10-sessions"
PLAN_VERSION = "10.0.0-ultra"

# ---------------------------------------------------------------------------
# TUNABLES (config.json se override; module ke apne defaults bhi hain)
# ---------------------------------------------------------------------------
DEFAULTS = {
    "session_identities": 3,              # isolated sessions for token sampling
    "session_token_samples": 6,           # cookie/token samples for randomness lab
    "session_capture_endpoints": 8,       # max endpoints jahan se token liya jaye
    "session_allow_logout_test": True,    # synthetic session par logout check
    "session_allow_binding_test": True,   # IP/UA change replay
    "session_binding_probes": 3,
    "session_jwt_tamper_max": 3,          # max tamper requests (stage I)
    "session_weak_secret_crack": True,    # bounded HMAC secret dictionary
    "session_weak_secret_max": 40,
    "session_test_credentials": [],       # [{"username": "...", "password": "..."}]
    "session_stats_alpha": 0.05,
    "session_use_phase9_routing": True,
    # ---- ULTRA PRO MAX v10 additions ----
    "session_client_storage_decode": True,  # offline decode lab (0 req)
    "session_allow_cache_probe": True,      # cache deception variants (<=3 req)
    "session_cache_probe_max": 3,
    "session_allow_conflict_probe": True,   # duplicate-cookie parser probe (<=2)
    "session_conflict_probes": 2,
    "session_allow_refresh_test": True,     # refresh rotation reuse check (<=3)
    "session_refresh_max": 3,
    "session_allow_concurrent_test": True,  # 2-login concurrent cap (<=4, creds)
    "session_concurrent_logins": 2,
    "session_allow_jwt_matrix": True,       # confusion/jwk-inject/logout-reuse
    "session_jwt_matrix_max": 3,            # live probes cap (stage Q)
}

# JWT ke liye bounded weak-secret dictionary (sirf detection ke liye)
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "jwt", "changeme", "secretkey",
    "your-256-bit-secret", "supersecret", "test", "key", "jwtsecret", "token",
    "s3cr3t", "qwerty", "letmein", "root", "default", "dev", "development",
    "private", "topsecret", "mysecret", "wasp", "example", "demo", "app",
    "application", "api", "apikey", "auth", "session", "1234567890", "abcdef",
    "0000", "1111", "password123", "P@ssw0rd", "secret123", "hunter2",
]

SESSION_COOKIE_RE = re.compile(
    r"(?i)^(.*(sess|sid|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|_session|"
    r"csrftoken|xsrf|token|auth|jwt|access|refresh|remember|logged|login|user)\.?.*)$")

# Cookie jisme privilege/state ho sakti hai
STATEFUL_COOKIE_RE = re.compile(r"(?i)(sess|sid|token|auth|jwt|remember|logged|role|admin|"
                                r"tenant|user|account|uid|id)")

SENSITIVE_TOKEN_PARAM_RE = re.compile(
    r"(?i)(^|_)(token|access_token|auth|authorization|jwt|apikey|api_key|key|session|"
    r"sid|secret|password|passwd|pwd|signature|sig|code)(_|$)")

LEAK_URL_RE = re.compile(r"(?i)[?&](token|access_token|auth|jwt|api_key|apikey|session|sid)=")

PRIVILEGE_CLAIM_RE = re.compile(
    r"(?i)^(admin|is_?admin|role|roles|scope|scopes|perm|perms|permission|permissions|"
    r"privilege|privileges|group|groups|tier|plan|tenant|tenant_?id|org|org_?id|"
    r"credit|credits|balance|level|acl|is_?staff|is_?superuser|impersonate)$")

WEAK_ALGS = ("none", "None", "NONE", "HS256")

# ULTRA: client-side session storage fingerprints
RAILS_MARSHAL_RE = re.compile(r"^BAh7")          # Rails 3 cookie session (Marshal)
FLASK_LIKE_RE = re.compile(r"^\ eyJ|^\w+\.eyJ")  # handled structurally in decoder
CONNECT_SID_RE = re.compile(r"^s(:|%3A)")        # express connect.sid (server-side)
PLAY_SESSION_NAMES = ("PLAY_SESSION",)
LARAVEL_COOKIE_RE = re.compile(r"^[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+$")

# ULTRA: state-change form fields (CSRF mapping ke liye)
STATE_CHANGE_HINT_RE = re.compile(
    r"(?i)(password|email|profile|settings|delete|remove|create|update|submit|"
    r"transfer|pay|order|role|admin|invite|api[_-]?key)")

SEVERITY_HINTS = {
    "session_token_low_entropy": ("High", "CVSS ~7.5", "Session token predictable -> session prediction/hijack."),
    "session_token_static": ("Critical", "CVSS ~9.1", "Token har session me same -> fixation/hijack."),
    "session_fixation": ("High", "CVSS ~8.1", "Login ke baad session id rotate nahi hoti -> fixation."),
    "session_no_logout_invalidation": ("Medium", "CVSS ~6.5", "Logout ke baad bhi session valid -> shared-device risk."),
    "session_no_idle_timeout": ("Medium", "CVSS ~5.4", "Session expiry nahi -> stolen token hamesha chalega."),
    "session_cookie_flags_missing": ("Medium", "CVSS ~4.3", "Cookie hardening missing -> XSS/sniffing se theft."),
    "session_cookie_prefix_violation": ("Medium", "CVSS ~4.3", "Cookie name prefix rules violate hue."),
    "session_cookie_wide_domain": ("Medium", "CVSS ~5.3", "Cookie parent domain par set -> subdomain takeover risk."),
    "session_cookie_path_wide": ("Low", "CVSS ~3.1", "Cookie path / par set -> scope unnecessarily bada."),
    "session_duplicate_cookies": ("Medium", "CVSS ~5.4", "Duplicate cookie names -> session tossing/fixation."),
    "session_not_bound": ("Medium", "CVSS ~5.9", "Session IP/UA se bound nahi -> token replay aasan."),
    "session_concurrent_unlimited": ("Low", "CVSS ~3.7", "Concurrent session cap nahi -> hijack detect karna mushkil."),
    "jwt_alg_none_accepted": ("Critical", "CVSS ~9.1", "alg=none JWT accept -> complete auth bypass."),
    "jwt_signature_not_verified": ("Critical", "CVSS ~9.1", "Tampered JWT accept -> auth bypass."),
    "jwt_weak_hmac_secret": ("Critical", "CVSS ~9.1", "JWT HMAC secret dictionary me mila -> token forge possible."),
    "jwt_alg_confusion": ("High", "CVSS ~8.1", "RS256/HS256 confusion ke indicators -> key public ho to forge."),
    "jwt_kid_injection": ("High", "CVSS ~8.1", "kid header me traversal/SQLi pattern -> key lookup manipulate."),
    "jwt_jku_x5u_external": ("High", "CVSS ~8.1", "jku/x5u external URL -> attacker apni key host kar sakta hai."),
    "jwt_no_expiry": ("Medium", "CVSS ~6.5", "JWT me exp nahi -> token permanently valid."),
    "jwt_long_expiry": ("Low", "CVSS ~3.7", "JWT expiry bahut lambi -> revocation window bada."),
    "jwt_missing_iss_aud": ("Low", "CVSS ~3.1", "iss/aud validation hints missing -> cross-service token reuse."),
    "jwt_sensitive_claims": ("Medium", "CVSS ~5.3", "JWT payload me privilege claims plaintext."),
    "jwt_pii_in_payload": ("Low", "CVSS ~3.1", "JWT payload me PII (email/phone) plaintext."),
    "jwks_weak_key": ("High", "CVSS ~7.5", "JWKS me chhoti RSA key (<2048) -> factor karna feasible."),
    "jwks_no_kid": ("Low", "CVSS ~3.1", "JWKS keys me kid nahi -> rotation/confusion risk."),
    "token_in_url": ("Medium", "CVSS ~5.3", "Token URL/query me -> logs, Referer, history me leak."),
    "token_in_response_body": ("Low", "CVSS ~3.1", "Token response body me expose -> XSS par readable."),
    "token_localstorage_hint": ("Medium", "CVSS ~5.4", "Token localStorage me (client hint) -> XSS par theft."),
    "token_no_httponly": ("Medium", "CVSS ~4.3", "Token cookie HttpOnly ke bina -> JS se readable."),
    "session_cleartext_transport": ("High", "CVSS ~8.1", "Session HTTP par -> token plaintext me."),
    "session_debug_leak": ("Low", "CVSS ~3.7", "Session endpoint debug/stack info leak karta hai."),
    "session_open_redirect_in_logout": ("Medium", "CVSS ~6.1", "Logout/return URL open redirect -> token leak via Referer."),
    # ---- ULTRA PRO MAX v10 additions ----
    "client_side_session_storage": ("Medium", "CVSS ~5.3",
        "Session state client-side cookie me hai (signed) -> secret key leak par tamper."),
    "client_side_marshal_session": ("High", "CVSS ~7.5",
        "Rails Marshal cookie session -> deserialization surface (secret leak par RCE tak)."),
    "cookie_embedded_privilege_state": ("High", "CVSS ~8.1",
        "Cookie value me plaintext/base64 privilege state hai bina signature ke -> tamper se auth bypass."),
    "unsigned_cookie_state_accepted": ("Critical", "CVSS ~9.1",
        "Tampered unsigned cookie state server ne accept kar liya -> complete session tamper."),
    "viewstate_surface": ("Low", "CVSS ~3.1",
        "ASP.NET ViewState mile -> MAC validation + viewstateUserKey manually verify karo."),
    "cache_deception_surface": ("High", "CVSS ~7.5",
        "Authenticated response path-variant par cache hit -> Web Cache Deception se session data leak."),
    "session_cache_mixup_surface": ("Medium", "CVSS ~5.3",
        "Cacheable session response + Vary: User-Agent nahi -> web-cache mixup/deception surface."),
    "cookie_parser_duplicate_accepted": ("Medium", "CVSS ~5.4",
        "Duplicate cookie name parser ne accept kiya -> cookie tossing pre-condition."),
    "refresh_no_rotation": ("High", "CVSS ~8.1",
        "Refresh token reuse ho raha hai (rotate nahi hota) -> leaked refresh token = permanent ATO."),
    "jwt_alg_confusion_accepted": ("Critical", "CVSS ~9.1",
        "RS256->HS256 confusion token accept -> public key se token forge."),
    "jwt_jwk_injection_accepted": ("Critical", "CVSS ~9.1",
        "Header jwk embedded key accept -> attacker apni key se token sign kar sakta hai."),
    "jwt_logout_reuse": ("Medium", "CVSS ~6.5",
        "Logout ke baad JWT abhi bhi accepted -> JWT revocation missing (stateless token)."),
    "jwt_duplicate_claims": ("Medium", "CVSS ~5.3",
        "JWT payload me duplicate claims -> parser discrepancy surface (konsa claim valid?)."),
    "session_page_clickjacking": ("Low", "CVSS ~3.7",
        "Token/session page par XFO/frame-ancestors nahi -> UI-redress se state change."),
    "session_hsts_missing": ("Low", "CVSS ~3.1",
        "HTTPS session page par HSTS nahi -> SSL-strip se cookie downgrade risk."),
    "session_referrer_leak_surface": ("Low", "CVSS ~3.7",
        "Token page par referrer-policy weak -> token external sites ko leak ho sakta hai."),
    "csrf_defense_weak": ("Medium", "CVSS ~5.4",
        "State-change forms bina CSRF token + SameSite missing -> cross-site state change."),
    "ws_session_model_unknown": ("Info", "-",
        "WebSocket endpoints + cookie auth -> WS par session reuse/model manually verify karo."),
}


def classify_severity(key):
    return SEVERITY_HINTS.get(key, ("Info", "-", ""))


COOKIE_FINDING_TITLES = {
    "session_cookie_flags_missing": "Session cookie hardening flags missing",
    "session_cookie_prefix_violation": "Cookie name prefix (__Host-/__Secure-) rules violated",
    "session_cookie_wide_domain": "Session cookie parent domain par set hai",
    "session_cookie_path_wide": "Session cookie ka Path unnecessarily wide hai",
    "session_no_idle_timeout": "Session cookie ka explicit expiry nahi hai",
}


# ---------------------------------------------------------------------------
# MODULE STATE
# ---------------------------------------------------------------------------
class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "SESS-%03d" % (len(self.items) + 1), "key": key, "title": title,
               "severity": sev, "cvss_hint": cvss, "endpoint": endpoint,
               "detail": detail, "why_it_matters": why,
               "evidence": evidence_ref, "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


# ---------------------------------------------------------------------------
# STATISTICS  (pure python; numpy/scipy ki zaroorat nahi)
# ---------------------------------------------------------------------------
def _gamma_ln(x):
    """Lanczos approximation for ln(Gamma(x))."""
    cof = [76.18009172947146, -86.50532032941677, 24.01409824083091,
           -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5]
    y = x
    tmp = x + 5.5
    tmp -= (x + 0.5) * math.log(tmp)
    ser = 1.000000000190015
    for j in range(6):
        y += 1.0
        ser += cof[j] / y
    return -tmp + math.log(2.5066282746310005 * ser / x)


def _gammainc_lower_series(a, x):
    ap, s, delta = a, 1.0 / a, 1.0 / a
    for _ in range(300):
        ap += 1.0
        delta *= x / ap
        s += delta
        if abs(delta) < abs(s) * 1e-12:
            break
    return s * math.exp(-x + a * math.log(x) - _gamma_ln(a))


def _gammainc_upper_cf(a, x):
    tiny = 1e-300
    b, c, d = x + 1.0 - a, 1.0 / tiny, 1.0 / (x + 1.0 - a)
    h = d
    for i in range(1, 300):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return math.exp(-x + a * math.log(x) - _gamma_ln(a)) * h


def chi2_sf(x, k):
    """P(X > x) for chi-square with k degrees of freedom (survival function)."""
    if k <= 0 or x < 0:
        return 1.0
    a = k / 2.0
    xx = x / 2.0
    if xx < a + 1.0:
        return max(0.0, min(1.0, 1.0 - _gammainc_lower_series(a, xx)))
    return max(0.0, min(1.0, _gammainc_upper_cf(a, xx)))


def normal_sf(z):
    """Two-sided tail probability for standard normal."""
    return math.erfc(abs(z) / math.sqrt(2.0))


def chi_square_uniform(counts):
    """
    Chi-square goodness-of-fit vs uniform. Token ke characters uniform hone
    chahiye - agar nahi, to generator biased/predictable ho sakta hai.
    """
    counts = [c for c in counts if c is not None]
    n = sum(counts)
    k = len(counts)
    if n <= 0 or k < 2:
        return {"chi2": 0.0, "df": 0, "p_value": 1.0, "verdict": "insufficient-data"}
    exp = n / float(k)
    stat = sum((c - exp) ** 2 / exp for c in counts)
    df = k - 1
    p = chi2_sf(stat, df)
    return {"chi2": round(stat, 3), "df": df, "p_value": round(p, 5),
            "n": n, "k": k, "expected_per_bucket": round(exp, 2),
            "verdict": ("biased" if p < 0.01 else "slightly-skewed" if p < 0.05 else "uniform-ish")}


def to_bits(data):
    """Bytes -> bit list (MSB first)."""
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    out = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def monobit_test(bits):
    """NIST SP800-22 monobit: 0 aur 1 ki count barabar honi chahiye."""
    n = len(bits)
    if n < 32:
        return {"n": n, "verdict": "insufficient-data"}
    s = sum(1 for b in bits if b == 1) - sum(1 for b in bits if b == 0)
    s_obs = abs(s) / math.sqrt(n)
    p = math.erfc(s_obs / math.sqrt(2.0))
    return {"n": n, "ones": sum(bits), "zeros": n - sum(bits),
            "s_obs": round(s_obs, 4), "p_value": round(p, 5),
            "verdict": "pass" if p >= 0.01 else "fail"}


def runs_test(bits):
    """NIST SP800-22 runs test: consecutive same-bit runs random hone chahiye."""
    n = len(bits)
    if n < 64:
        return {"n": n, "verdict": "insufficient-data"}
    pi = sum(bits) / float(n)
    if abs(pi - 0.5) > (2.0 / math.sqrt(n)):
        return {"n": n, "pi": round(pi, 4), "verdict": "fail-monobit-precondition"}
    v = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(v - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    p = math.erfc(num / den) if den > 0 else 1.0
    return {"n": n, "runs": v, "pi": round(pi, 4), "p_value": round(p, 5),
            "verdict": "pass" if p >= 0.01 else "fail"}


def serial_correlation(bits):
    """Lag-1 serial correlation coefficient (0 ke qareeb hona chahiye)."""
    n = len(bits)
    if n < 32:
        return {"n": n, "verdict": "insufficient-data"}
    x = [2 * b - 1 for b in bits]
    m = sum(x) / float(n)
    num = sum((x[i] - m) * (x[i + 1] - m) for i in range(n - 1))
    den = sum((xi - m) ** 2 for xi in x)
    rho = num / den if den > 0 else 0.0
    return {"n": n, "rho": round(rho, 5),
            "verdict": "pass" if abs(rho) < 0.05 else "biased" if abs(rho) > 0.15 else "mild"}


def entropy_per_position(samples):
    """Har character position ki entropy (predictable positions pakadne ke liye)."""
    samples = [s for s in samples if s]
    if not samples:
        return []
    L = min(len(s) for s in samples)
    out = []
    for i in range(L):
        col = "".join(s[i] for s in samples)
        out.append(round(shannon_entropy(col), 3))
    return out


def hamming_matrix(samples):
    """Pairwise Hamming distance (normalized). Low distance = collision-prone."""
    samples = [s for s in samples if s]
    if len(samples) < 2:
        return {"pairs": 0, "verdict": "insufficient-data"}
    dists, raw = [], []
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            a, b = samples[i], samples[j]
            m = min(len(a), len(b))
            d = sum(1 for k in range(m) if a[k] != b[k])
            raw.append(d)
            dists.append(d / float(max(1, m)))
    return {"pairs": len(raw), "min_raw": min(raw), "max_raw": max(raw),
            "mean_raw": round(sum(raw) / float(len(raw)), 2),
            "min_normalized": round(min(dists), 4),
            "mean_normalized": round(sum(dists) / float(len(dists)), 4),
            "verdict": ("collision-prone" if min(dists) < 0.15 else
                        "weak-spread" if min(dists) < 0.35 else "good-spread")}


def birthday_entropy_bits(samples):
    """
    Collision-based entropy estimate (birthday bound).
    N samples me koi collision na ho to entropy >= log2(N^2/2) bits ka lower bound.
    Ye "kitne random bits hain" ka practical jawab deta hai.
    """
    uniq = len(set(samples))
    n = len(samples)
    if n < 2:
        return {"n": n, "unique": uniq, "verdict": "insufficient-data"}
    collisions = n - uniq
    if collisions > 0:
        b = math.log(max(1.0, (n * n) / (2.0 * collisions)), 2)
        return {"n": n, "unique": uniq, "collisions": collisions,
                "estimated_bits": round(b, 1),
                "verdict": "collision-observed"}
    upper = math.log(max(1.0, n * n / 2.0), 2)
    return {"n": n, "unique": uniq, "collisions": 0,
            "estimated_bits_lower_bound": round(upper, 1),
            "verdict": "no-collision-in-sample"}


def token_randomness_lab(samples, alpha=0.05):
    """
    Poora randomness lab ek call me: entropy, per-position, Hamming, chi-square,
    monobit, runs, serial correlation, birthday bound.
    """
    samples = [s for s in samples if s]
    out = {"samples": len(samples), "unique": len(set(samples))}
    if not samples:
        out["verdict"] = "no-samples"
        return out
    joined = "".join(samples)
    out["overall_entropy_per_char"] = round(shannon_entropy(joined), 3)
    out["lengths"] = sorted(set(len(s) for s in samples))
    out["entropies"] = [round(shannon_entropy(s), 3) for s in samples]
    out["min_token_entropy"] = min(out["entropies"])
    out["avg_token_entropy"] = round(sum(out["entropies"]) / float(len(out["entropies"])), 3)
    out["bits_per_char_estimate"] = round(out["overall_entropy_per_char"], 2)
    out["per_position_entropy"] = entropy_per_position(samples)
    low = [i for i, e in enumerate(out["per_position_entropy"]) if e < 1.0]
    out["low_entropy_positions"] = low[:15]
    out["hamming"] = hamming_matrix(samples)
    out["birthday"] = birthday_entropy_bits(samples)
    freq = {}
    for ch in joined:
        freq[ch] = freq.get(ch, 0) + 1
    alphabet = [chr(c) for c in range(48, 58)] + [chr(c) for c in range(97, 123)] + \
               [chr(c) for c in range(65, 91)] + ["-", "_"]
    counts = [freq.get(ch, 0) for ch in alphabet]
    out["chi_square"] = chi_square_uniform(counts)
    bits = to_bits(joined)
    out["monobit"] = monobit_test(bits)
    out["runs"] = runs_test(bits)
    out["serial_correlation"] = serial_correlation(bits)
    problems = []
    if out["min_token_entropy"] < 3.0:
        problems.append("low-entropy token")
    if len(low) > 0:
        problems.append("%d predictable position(s)" % len(low))
    if out["hamming"].get("verdict") in ("collision-prone", "weak-spread"):
        problems.append("weak hamming spread")
    if out["chi_square"].get("verdict") == "biased":
        problems.append("biased character distribution")
    if out["runs"].get("verdict") == "fail":
        problems.append("runs-test fail")
    if out["serial_correlation"].get("verdict") == "biased":
        problems.append("serial correlation")
    out["problems"] = problems
    out["weak"] = bool(problems)
    out["verdict"] = ("WEAK: " + ", ".join(problems)) if problems else "looks-random-enough"
    out["note"] = ("Sample chhota hai (%d) - ye statistical indicator hai, proof nahi. "
                   "Bada sample ya source-code review se confirm karo." % len(samples))
    return out


# ---------------------------------------------------------------------------
# COOKIE ANALYSIS
# ---------------------------------------------------------------------------
def parse_set_cookie(raw):
    """Set-Cookie header -> structured dict (flags + scope + attributes)."""
    parts = [p.strip() for p in (raw or "").split(";")]
    if not parts or "=" not in parts[0]:
        return {}
    name, _, value = parts[0].partition("=")
    name = name.strip()
    value = value.strip()
    low = raw.lower()
    c = {"name": name, "value": value, "value_len": len(value),
         "value_fingerprint": sha1(value)[:12],
         "value_entropy": round(shannon_entropy(value), 3),
         "httponly": "httponly" in low, "secure": "secure" in low,
         "samesite": "", "domain": "", "path": "", "max_age": None, "expires": None,
         "priority": "", "partitioned": "partitioned" in low}
    m = re.search(r"samesite\s*=\s*([a-z]+)", low)
    if m:
        c["samesite"] = m.group(1)
    m = re.search(r"domain\s*=\s*([^;]+)", low)
    if m:
        c["domain"] = m.group(1).strip()
    m = re.search(r"path\s*=\s*([^;]+)", low)
    if m:
        c["path"] = m.group(1).strip()
    m = re.search(r"max-age\s*=\s*(-?\d+)", low)
    if m:
        c["max_age"] = int(m.group(1))
    m = re.search(r"expires\s*=\s*([^;]+)", low)
    if m:
        c["expires"] = m.group(1).strip()
    m = re.search(r"priority\s*=\s*([a-z]+)", low)
    if m:
        c["priority"] = m.group(1)
    c["session_cookie"] = c["max_age"] is None and not c["expires"]
    return c


def cookie_findings(c, endpoint, is_https=True):
    """
    Cookie hardening findings + __Host-/__Secure- prefix rule engine.
    Ek cookie se multiple findings nikal sakti hain - isliye list return karti hai.
    """
    out = []
    if not c:
        return out
    name = c.get("name", "")
    sessionish = bool(SESSION_COOKIE_RE.match(name)) or bool(STATEFUL_COOKIE_RE.search(name))
    missing = []
    if sessionish:
        if not c["httponly"]:
            missing.append("HttpOnly")
        if is_https and not c["secure"]:
            missing.append("Secure")
        if not c["samesite"] or c["samesite"] == "none":
            missing.append("SameSite")
    if missing:
        out.append(("session_cookie_flags_missing", endpoint,
                    "cookie '%s' missing: %s" % (name, ", ".join(missing)),
                    {"cookie": name, "missing": missing, "flags": {k: c[k] for k in
                     ("httponly", "secure", "samesite", "partitioned")}}))
    viol = []
    if name.startswith("__Host-"):
        if not c["secure"]:
            viol.append("__Host- bina Secure")
        if c["domain"]:
            viol.append("__Host- par Domain set")
        if c["path"] not in ("", "/"):
            viol.append("__Host- par Path=%s" % c["path"])
    if name.startswith("__Secure-") and not c["secure"]:
        viol.append("__Secure- bina Secure")
    if viol:
        out.append(("session_cookie_prefix_violation", endpoint,
                    "cookie '%s': %s" % (name, "; ".join(viol)),
                    {"cookie": name, "violations": viol}))
    if c["domain"].startswith(".") and sessionish:
        out.append(("session_cookie_wide_domain", endpoint,
                    "cookie '%s' Domain=%s par set (parent domain - subdomain takeover risk)"
                    % (name, c["domain"]), {"cookie": name, "domain": c["domain"]}))
    if sessionish and c["path"] in ("", "/") and not name.startswith("__Host-"):
        out.append(("session_cookie_path_wide", endpoint,
                    "cookie '%s' Path=%s par set" % (name, c["path"] or "/"),
                    {"cookie": name, "path": c["path"] or "/"}))
    if sessionish and c["session_cookie"] and not c["max_age"]:
        out.append(("session_no_idle_timeout", endpoint,
                    "cookie '%s' session-scoped hai (koi Max-Age/Expires nahi) - "
                    "browser band hone tak valid" % name,
                    {"cookie": name}))
    return out


def cookie_analysis(cookies):
    """Cookies list -> summary (duplicates, entropy, expiry model, name hygiene)."""
    out = {"count": len(cookies), "names": [c.get("name") for c in cookies],
           "duplicates": [], "low_entropy": [], "expiry_model": {}, "session_like": []}
    names = [c.get("name", "") for c in cookies]
    out["duplicates"] = sorted({n for n in names if n and names.count(n) > 1})
    for c in cookies:
        if c.get("session_like", True) or STATEFUL_COOKIE_RE.search(c.get("name", "")):
            if c.get("value_len", 0) >= 8 and c.get("value_entropy", 9) < 3.0:
                out["low_entropy"].append({"name": c.get("name"), "len": c.get("value_len"),
                                           "entropy": c.get("value_entropy")})
            out["session_like"].append(c.get("name"))
            out["expiry_model"][c.get("name")] = (
                "session-scoped" if c.get("session_cookie") else
                "max-age=%ss" % c.get("max_age") if c.get("max_age") is not None else
                "expires=%s" % c.get("expires"))
    return out


# ---------------------------------------------------------------------------
# JWT ANALYSIS (deep)
# ---------------------------------------------------------------------------
def b64url_decode(seg):
    try:
        seg = seg or ""
        seg += "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg.encode())
    except Exception:
        return b""


def b64url_decode_json(seg):
    try:
        return json.loads(b64url_decode(seg).decode("utf-8", "ignore"))
    except Exception:
        return None


def b64url_encode(obj_or_bytes):
    raw = obj_or_bytes if isinstance(obj_or_bytes, bytes) else \
        json.dumps(obj_or_bytes, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _pairs_to_detect_duplicates(pairs):
    """object_pairs_hook: duplicate JSON keys ko preserve karta hai."""
    d = {}
    dups = []
    for k, v in pairs:
        if k in d:
            dups.append(k)
        d[k] = v
    return d, dups


def jwt_duplicate_claim_scan(tok):
    """
    ULTRA v10: JWT payload duplicate-claims scan (parser discrepancy surface).
    Kuch JSON parsers LAST value lete hain, kuch FIRST - agar payload me hi
    duplicate keys hain to verifier aur business-logic alag-alag values dekh
    sakte hain (famous parser-confusion technique).
    """
    parts = (tok or "").split(".")
    if len(parts) < 2:
        return {"scanned": False}
    try:
        raw = b64url_decode(parts[1]).decode("utf-8", "ignore")
        pairs = json.loads(raw, object_pairs_hook=lambda p: p)
    except Exception:
        return {"scanned": False}
    if not isinstance(pairs, list):
        return {"scanned": False}
    seen, dups = set(), []
    for k, _v in pairs:
        if k in seen and k not in dups:
            dups.append(k)
        seen.add(k)
    hdr_pairs = None
    try:
        hdr_pairs = json.loads(b64url_decode(parts[0]).decode("utf-8", "ignore"),
                               object_pairs_hook=lambda p: p)
    except Exception:
        hdr_pairs = None
    hdr_dups = []
    if isinstance(hdr_pairs, list):
        hseen = set()
        for k, _v in hdr_pairs:
            if k in hseen and k not in hdr_dups:
                hdr_dups.append(k)
            hseen.add(k)
    return {"scanned": True, "duplicate_payload_claims": dups,
            "duplicate_header_claims": hdr_dups,
            "surface": bool(dups or hdr_dups)}


def _dict_or_none(x):
    """v10 BUG-4 fix: JSON decode ka result dict NAHI ho sakta (int/list/str) -
    downstream .keys()/dict() crash na ho isliye coerce."""
    return x if isinstance(x, dict) else None


def jwt_deep(tok, weak_secrets=None, weak_max=40):
    """
    JWT ko poori tarah todo: header/payload, claims hygiene, alg surface,
    kid/jku/x5u, expiry window, privilege claims, PII, aur (optional) weak
    HMAC secret dictionary check.
    """
    parts = (tok or "").split(".")
    out = {"length": len(tok or ""), "segments": len(parts),
           "entropy": round(shannon_entropy(tok or ""), 3),
           "fingerprint": sha1(tok or "")[:12]}
    hdr = _dict_or_none(b64url_decode_json(parts[0]) if len(parts) > 0 else None)
    pay = _dict_or_none(b64url_decode_json(parts[1]) if len(parts) > 1 else None)
    sig_raw = b64url_decode(parts[2]) if len(parts) > 2 else b""
    out["header"] = hdr
    out["payload"] = pay
    out["alg"] = (hdr or {}).get("alg")
    out["typ"] = (hdr or {}).get("typ")
    out["kid"] = (hdr or {}).get("kid")
    out["jku"] = (hdr or {}).get("jku")
    out["x5u"] = (hdr or {}).get("x5u")
    out["header_keys"] = sorted((hdr or {}).keys())
    out["payload_keys"] = sorted((pay or {}).keys())
    out["signature_bytes"] = len(sig_raw)
    out["unsigned"] = (len(parts) == 3 and parts[2] == "") or len(parts) == 2
    out["decode_ok"] = bool(hdr is not None or pay is not None)

    claims = {}
    if isinstance(pay, dict):
        now = time.time()
        exp = pay.get("exp")
        iat = pay.get("iat")
        nbf = pay.get("nbf")
        claims = {
            "has_exp": exp is not None, "has_iat": iat is not None, "has_nbf": nbf is not None,
            "has_iss": pay.get("iss") is not None, "has_aud": pay.get("aud") is not None,
            "has_jti": pay.get("jti") is not None, "has_sub": pay.get("sub") is not None,
            "iss": pay.get("iss"), "aud": pay.get("aud"), "sub": pay.get("sub"),
            "privilege_claims": [k for k in pay if PRIVILEGE_CLAIM_RE.match(str(k))],
            "pii_claims": [k for k in pay if re.search(
                r"(?i)(email|phone|mobile|address|ssn|dob|name|first_?name|last_?name)", str(k))],
        }
        if exp is not None:
            try:
                claims["exp"] = exp
                claims["expires_in_s"] = int(float(exp) - now)
                claims["expired"] = float(exp) < now
                claims["lifetime_s"] = (int(float(exp) - float(iat))
                                        if iat is not None else None)
            except Exception:
                pass
        if iat is not None:
            try:
                claims["issued_ago_s"] = int(now - float(iat))
            except Exception:
                pass
    out["claims"] = claims
    out["expired"] = bool(claims.get("expired"))

    flags = []
    if out["alg"] in WEAK_ALGS and out["alg"] != "HS256":
        flags.append("alg-none")
    if out["alg"] == "HS256":
        flags.append("hmac-sha256")
    if out["alg"] and str(out["alg"]).startswith("HS") and (hdr or {}).get("jwk"):
        flags.append("hmac-with-embedded-jwk")
    if out["jku"] or out["x5u"]:
        flags.append("external-key-url")
    if out["kid"] and re.search(r"(\.\./|/etc/|\.\.%2f|'|\"|\bor\b|\bunion\b|\bselect\b|\\x00)",
                                str(out["kid"]), re.I):
        flags.append("kid-injection-pattern")
    if not claims.get("has_exp"):
        flags.append("no-expiry")
    if claims.get("has_exp") and not claims.get("has_iat"):
        flags.append("no-iat")
    if not claims.get("has_iss") or not claims.get("has_aud"):
        flags.append("missing-iss-aud")
    if not claims.get("has_jti"):
        flags.append("no-jti-no-revocation-handle")
    if claims.get("privilege_claims"):
        flags.append("privilege-claims-in-payload")
    if claims.get("pii_claims"):
        flags.append("pii-in-payload")
    if out["unsigned"]:
        flags.append("unsigned-token")
    lt = claims.get("lifetime_s")
    if isinstance(lt, (int, float)) and lt > 86400 * 7:
        flags.append("lifetime>7d")
    out["attack_surface_flags"] = flags

    # ULTRA: duplicate-claims scan (0 req)
    try:
        out["duplicate_claims"] = jwt_duplicate_claim_scan(tok)
    except Exception:
        out["duplicate_claims"] = {"scanned": False}

    # --- weak HMAC secret (bounded dictionary) ---
    if weak_secrets is not None and out["alg"] in ("HS256", "HS384", "HS512") and len(parts) == 3:
        algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                "HS512": hashlib.sha512}.get(out["alg"], hashlib.sha256)
        signing_input = ("%s.%s" % (parts[0], parts[1])).encode()
        try:
            expected = b64url_decode(parts[2])
        except Exception:
            expected = b""
        found = None
        tried = 0
        for s in list(weak_secrets)[:int(weak_max)]:
            tried += 1
            mac = hmac.new(s.encode(), signing_input, algo).digest()
            if hmac.compare_digest(mac, expected):
                found = s
                break
        out["weak_secret_check"] = {"tried": tried, "found": found,
                                    "dictionary_size": min(len(weak_secrets), int(weak_max)),
                                    "note": "bounded dictionary - sirf detection, brute-force nahi"}
    return out


def jwks_analysis(doc):
    """JWKS document -> key strength + kid presence analysis (+ pubkey cache)."""
    out = {"keys": 0, "weak_keys": [], "algs": [], "no_kid": 0, "types": []}
    keys = (doc or {}).get("keys") or []
    out["keys"] = len(keys)
    for k in keys:
        if not isinstance(k, dict):
            continue
        kty = k.get("kty")
        alg = k.get("alg")
        kid = k.get("kid")
        out["types"].append(kty)
        out["algs"].append(alg)
        if not kid:
            out["no_kid"] += 1
        if kty == "RSA":
            n = k.get("n") or ""
            try:
                nbytes = len(b64url_decode(n))
                bits = nbytes * 8
            except Exception:
                bits = 0
            if 0 < bits < 2048:
                out["weak_keys"].append({"kid": kid, "kty": kty, "bits_approx": bits,
                                         "why": "RSA key <2048 bit"})
            elif bits >= 2048:
                out.setdefault("strong_keys", []).append({"kid": kid, "bits_approx": bits})
            # ULTRA: confusion craft ke liye first RSA key ka n/e cache karo
            if not out.get("_rsa") and k.get("n") and k.get("e"):
                out["_rsa"] = {"kid": kid, "n": k["n"], "e": k["e"]}
        if kty == "oct":
            kk = k.get("k") or ""
            out["weak_keys"].append({"kid": kid, "kty": "oct",
                                     "bits_approx": len(b64url_decode(kk)) * 8,
                                     "why": "symmetric key JWKS me publicly exposed (jab public hona nahi chahiye)"})
    out["algs"] = sorted(set(a for a in out["algs"] if a))
    out["types"] = sorted(set(t for t in out["types"] if t))
    return out


# ---------------------------------------------------------------------------
# ULTRA STAGE L - CLIENT-SIDE SESSION STORAGE LAB (0 requests, offline decode)
# ---------------------------------------------------------------------------
def _try_base64_decode(value):
    """Cookie value ko base64 (urlsafe + standard) decode karne ki koshish."""
    for cand in (value, value.replace("-", "+").replace("_", "/")):
        try:
            pad = cand + "=" * (-len(cand) % 4)
            if len(pad) % 4:
                continue
            raw = base64.b64decode(pad, validate=False)
            if raw and len(raw) >= 4:
                return raw
        except Exception:
            continue
    return None


def _looks_like_signed_client_session(parts):
    """
    3-segment dot-separated, first segment JSON dict WITHOUT 'alg' ->
    itsdangerous-style signed client session (Flask/Django-signer/Ruby etc).
    JWT me first segment hamesha 'alg' rakhta hai.
    """
    if len(parts) != 3:
        return False
    first = b64url_decode_json(parts[0])
    if isinstance(first, dict) and "alg" not in first:
        return True
    # Flask ka timestamp segment base64 int hota hai (chhota)
    if isinstance(first, dict) and len(parts) == 3 and parts[1] and len(parts[1]) <= 12:
        return True
    return False


def client_session_storage_lab(cookies, captures=None):
    """
    ULTRA Stage L: har stateful cookie value ko decode karke detect karo:
      - signed client-side session (Flask itsdangerous jaisa)
      - Rails Marshal cookie (BAh7...)
      - Laravel encrypted cookie (iv/mac JSON)
      - express connect.sid (server-side, fine)
      - base64-JSON embedded privilege state (unsigned) <- tamper surface
      - PLAY_SESSION / ViewState style
    0 requests - pure offline decoding. Ye famous "cookie tampering" attack ka
    surface map karta hai bina ek bhi request bheje.
    """
    lab = {"decoded": [], "client_side_signed": [], "marshal": [], "laravel_encrypted": [],
           "server_side_ok": [], "embedded_privilege_state": [], "plain_state_values": [],
           "summary": ""}
    captures = captures or {}
    # ASP.NET ViewState (body se, capture me mile ho to)
    viewstate_hits = []
    for u, rec in captures.items():
        body = rec.get("_body_hint") or ""
        if isinstance(body, str) and re.search(r"(?i)name=\"__VIEWSTATE\"|/wEPDw", body):
            viewstate_hits.append(u)
    lab["viewstate_endpoints"] = viewstate_hits

    for c in cookies:
        name = c.get("name", "")
        value = c.get("value", "")
        if not name or not value:
            continue
        rec = {"cookie": name, "len": len(value)}
        if CONNECT_SID_RE.match(value):
            rec["kind"] = "connect-sid (server-side, signature-prefixed)"
            lab["server_side_ok"].append(rec)
            continue
        if name in PLAY_SESSION_NAMES or name.startswith("PLAY_"):
            rec["kind"] = "Play framework session cookie"
            lab["client_side_signed"].append(rec)
            continue
        if RAILS_MARSHAL_RE.match(value):
            rec["kind"] = "Rails cookie session (Marshal base64) - deserialization surface"
            lab["marshal"].append(rec)
            continue
        parts = value.split(".")
        first_json = b64url_decode_json(parts[0]) if parts else None
        # Laravel encrypted cookie: first segment JSON with iv/value/mac/tags
        if isinstance(first_json, dict) and ("iv" in first_json and "mac" in first_json or
                                             "value" in first_json and "tag" in first_json):
            rec["kind"] = "framework-encrypted cookie (iv/mac) - strong-ish"
            lab["laravel_encrypted"].append(rec)
            continue
        # signed client-side session (itsdangerous style)
        if len(parts) >= 3 and _looks_like_signed_client_session(parts) and \
                not isinstance(first_json, dict):
            pass  # non-JSON first segment - niche generic checks
        if _looks_like_signed_client_session(parts):
            rec["kind"] = "signed client-side session (itsdangerous-style, %d segments)" % len(parts)
            rec["payload_preview_keys"] = sorted(
                (first_json or {}).keys())[:10] if isinstance(first_json, dict) else []
            lab["client_side_signed"].append(rec)
            continue
        # base64-JSON embedded state (unsigned) - SABSE BADA tamper surface
        raw = _try_base64_decode(value)
        decoded_obj = None
        if raw:
            try:
                decoded_obj = json.loads(raw.decode("utf-8", "ignore"))
            except Exception:
                decoded_obj = None
        if isinstance(decoded_obj, dict):
            priv_keys = [k for k in decoded_obj if PRIVILEGE_CLAIM_RE.match(str(k))]
            rec["decoded_keys"] = sorted(decoded_obj.keys())[:12]
            rec["privilege_keys"] = priv_keys
            rec["signed"] = bool(re.search(r"[.=][A-Za-z0-9_\-/]{16,}$", value))
            if priv_keys:
                rec["kind"] = "base64-JSON embedded privilege state"
                lab["embedded_privilege_state"].append(rec)
            else:
                rec["kind"] = "base64-JSON embedded session state"
                lab["decoded"].append(rec)
            continue
        # plain state values (role=..., admin=...)
        if re.search(r"(?i)(role|admin|is_admin|priv|level)[:=]", value) and len(value) < 200:
            rec["kind"] = "plain privilege-state value (unsigned)"
            rec["preview"] = truncate(value, 40)
            lab["plain_state_values"].append(rec)
            continue
        lab.setdefault("opaque", []).append(rec)

    hits = (len(lab["client_side_signed"]) + len(lab["marshal"]) +
            len(lab["embedded_privilege_state"]) + len(lab["plain_state_values"]))
    lab["summary"] = ("cookies=%d | client-side-signed=%d | marshal=%d | "
                      "embedded-privilege=%d | viewstate=%d" % (
                          len(cookies), len(lab["client_side_signed"]), len(lab["marshal"]),
                          len(lab["embedded_privilege_state"]), len(viewstate_hits)))
    lab["has_client_side_state"] = hits > 0
    return lab


# ---------------------------------------------------------------------------
# STAGE A - SESSION SURFACE DISCOVERY
# ---------------------------------------------------------------------------
SESSION_WELL_KNOWN = [
    "/", "/login", "/account", "/profile", "/me", "/api/me", "/api/auth/me",
    "/api/auth/session", "/api/v1/me", "/api/user", "/api/v1/user", "/dashboard",
    "/settings", "/security", "/account/sessions", "/security/sessions",
    "/logout", "/signout", "/api/auth/logout", "/api/logout", "/auth/logout",
    "/api/auth/refresh", "/api/auth/token", "/oauth/token", "/api/v1/auth/token",
    "/.well-known/openid-configuration", "/oauth/jwks", "/.well-known/jwks.json",
    "/jwks.json", "/oauth/userinfo", "/userinfo", "/api/auth/whoami", "/whoami",
]

LOGOUT_RE = re.compile(r"(?i)(logout|sign-?out|log-?out|revoke|invalidate|"
                       r"session[s]?/?(delete|destroy|revoke)?|terminate)")
SESSION_PATH_RE = re.compile(r"(?i)(session|token|auth|me$|whoami|profile|account|"
                             r"dashboard|refresh|jwks|userinfo|logout|signout|security)")
REFRESH_PATH_RE = re.compile(r"(?i)(refresh|oauth/token|auth/token|token/refresh)")

NOTABLE_RESP_HEADERS = (
    "x-frame-options", "content-security-policy", "strict-transport-security",
    "referrer-policy", "vary", "x-cache", "cf-cache-status", "age", "via",
    "x-served-by", "x-powered-by", "cross-origin-opener-policy",
    "cross-origin-resource-policy", "x-vercel-cache", "x-drupal-cache",
)


def _authorized_origins(scope):
    origins, seen = [], set()
    for u in scope.seed_urls():
        p = urllib.parse.urlparse(u)
        if p.netloc:
            o = "%s://%s" % (p.scheme, p.netloc)
            if o not in seen:
                seen.add(o)
                origins.append(o)
    for h in (list(getattr(scope, "domains", []) or []) +
              [w.lstrip("*.") for w in (getattr(scope, "wildcards", []) or [])]):
        o = "https://" + h
        if o not in seen:
            seen.add(o)
            origins.append(o)
    return origins


def _phase9_targets(base_dir, eng, scope):
    """Phase 9 feedforward se session/JWT endpoints (routing-aware)."""
    ff = load_json(os.path.join(base_dir, eng, "auth", "feedforward.json"), None) or {}
    route = (ff.get("routing") or {}).get("to_phase10_sessions_jwt") or {}
    eps = route.get("endpoints") or []
    out = []
    for u in eps:
        if u.startswith("http") and scope.check_url(u, raise_on_fail=False):
            out.append({"url": u, "source": "P9-feedforward", "priority": 50})
    return out


def discover_session_surface(base_dir, scope, out, conf=None):
    """
    Session candidates = Phase 9 routing + Phase 6 session_model + Phase 7 JS
    hints + Phase 8 queue + well-known session paths. Priority order preserve.
    """
    conf = conf or {}
    eng = scope.engagement
    ranked, seen = [], set()

    def push(url, source, priority):
        u = (url or "").split("#")[0]
        if not u.startswith("http") or u in seen:
            return
        if not scope.check_url(u, raise_on_fail=False):
            return
        seen.add(u)
        ranked.append({"url": u, "source": source, "priority": priority})

    if conf.get("session_use_phase9_routing", True):
        for r in _phase9_targets(base_dir, eng, scope):
            push(r["url"], r["source"], r["priority"])
        # token/session endpoints ko upar uthao - warna capture cap khatam ho jaata
        # hai aur asli session endpoint (jaise /api/auth/session) skip ho jaata hai.
        for r in list(ranked):
            path = urllib.parse.urlparse(r["url"]).path.lower()
            if re.search(r"(session|token|jwks|refresh|me$|whoami)", path):
                r["priority"] += 30
                r["source"] = r["source"] + "+token-boost"

    # Phase 6 session_model.txt -> cookie names + token storage inference
    sm = os.path.join(base_dir, eng, "tech", "session_model.txt")
    storage_hints = {}
    if os.path.exists(sm):
        try:
            for line in open(sm, errors="ignore"):
                if "->" not in line:
                    continue
                u, rest = line.split("->", 1)
                u = u.strip()
                if not u.startswith("http"):
                    continue
                push(u, "P6-session_model", 45)
                m = re.search(r"storage=([a-z\-]+)", rest)
                if m:
                    storage_hints[u] = m.group(1)
        except Exception:
            pass

    # Phase 7 JS hints
    for fn, src in (("same_origin_endpoints.txt", "P7-js"),
                    ("endpoints.txt", "P7-js"),
                    ("config_hints.txt", "P7-config"),
                    ("interesting_params.txt", "P7-params")):
        p = os.path.join(base_dir, eng, "js", fn)
        if not os.path.exists(p):
            continue
        try:
            for line in open(p, errors="ignore"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("/") or SESSION_PATH_RE.search(line):
                    for o in _authorized_origins(scope)[:1]:
                        push(o.rstrip("/") + (line if line.startswith("/") else "/" + line),
                             src, 30)
                elif line.startswith("http") and SESSION_PATH_RE.search(line):
                    push(line, src, 30)
        except Exception:
            pass

    # Phase 8 priority queue (session/token classes)
    pq = load_json(os.path.join(base_dir, eng, "surface", "priority_queue.json"), None) or {}
    rows = (pq.get("queue") or []) + (pq.get("diverse_queue") or [])
    for r in rows:
        u = r.get("target") or ""
        cls = " ".join(r.get("classes") or [])
        if not u.startswith("http"):
            continue
        if SESSION_PATH_RE.search(urllib.parse.urlparse(u).path) or \
           re.search(r"(Session|Token|Auth|JWT)", cls):
            push(u, "P8-priority", int(r.get("priority") or 20))

    # well-known session paths on every origin
    for o in _authorized_origins(scope)[:4]:
        for p in SESSION_WELL_KNOWN:
            push(o.rstrip("/") + p, "well-known", 10)

    # Fallback: agar abhi tak koi token-ish endpoint nahi mila to token endpoints
    # ko high priority do (warna Phase 10 khaali chalega).
    if not any(re.search(r"(session|token|jwks|me$|whoami)",
                         urllib.parse.urlparse(r["url"]).path, re.I) for r in ranked):
        for o in _authorized_origins(scope)[:2]:
            for p in ("/api/auth/session", "/api/session", "/api/me", "/api/auth/me",
                      "/api/auth/token", "/oauth/token", "/jwks.json",
                      "/.well-known/jwks.json"):
                push(o.rstrip("/") + p, "token-fallback", 60)

    ranked.sort(key=lambda r: -r["priority"])
    return ranked[:int(conf.get("session_capture_endpoints", 8)) * 3]


# ---------------------------------------------------------------------------
# STAGE B - IDENTITY & TOKEN CAPTURE (extended headers, ULTRA)
# ---------------------------------------------------------------------------
def capture_session(http, url, identity_name=None, extra_headers=None, conf=None):
    """Ek isolated identity se endpoint hit karke cookies + tokens capture karo.

    ULTRA v10 extension: notable response headers (hardening + cache signals),
    viewstate flag, light form inventory (CSRF mapping ke liye). Purane
    checkpoint replays me ye fields missing ho sakte hain - consumers .get()
    use karte hain.
    """
    conf = conf or {}
    client = http.identity(identity_name) if identity_name else http
    if extra_headers:
        client.set_default_headers(extra_headers)
    r = client.request("GET", url, allow_redirects=True)
    body = r.text or ""
    low_headers = {}
    for k, v in r.headers.items():
        lk = k.lower()
        if lk in NOTABLE_RESP_HEADERS:
            low_headers[lk] = v
    rec = {"url": url, "status": r.status, "error": r.error, "final_url": r.url,
           "len": len(r.body), "identity": identity_name,
           "set_cookie": [v for k, v in r.headers.items() if k.lower() == "set-cookie"],
           "cookies": client.session_export(),
           "www_authenticate": r.header("WWW-Authenticate"),
           "content_type": r.header("Content-Type"),
           "cache_control": r.header("Cache-Control"),
           "pragma": r.header("Pragma"),
           "vary": r.header("Vary"),
           "scheme": urllib.parse.urlparse(r.url or url).scheme,
           "tokens_in_body": [],
           "tokens_in_headers": [],
           "token_in_url": bool(LEAK_URL_RE.search(url)),
           "localstorage_hints": [],
           "debug_leak": bool(re.search(r"(?i)(traceback|stack trace|werkzeug|django\.core\.exceptions)",
                                        body)),
           # ---- ULTRA extensions ----
           "resp_headers": low_headers,
           "viewstate": bool(re.search(r"(?i)name=\"__VIEWSTATE\"|/wEPDw", body)),
           "forms_post": _scan_post_forms(body)}
    # JWT in body / headers
    for m in re.finditer(r"\b(eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{0,})", body):
        rec["tokens_in_body"].append(m.group(0))
    for k, v in r.headers.items():
        if re.search(r"(?i)(authorization|x-?auth|access-?token|bearer)", k) or \
           re.search(r"(?i)^bearer\s", str(v)):
            rec["tokens_in_headers"].append({"header": k, "value_preview": redact(str(v), 12)})
    # localStorage / sessionStorage hints in inline JS
    for m in re.finditer(r"(?i)(localStorage|sessionStorage)\.(setItem|getItem)\(\s*['\"]([^'\"]{2,60})['\"]", body):
        rec["localstorage_hints"].append({"storage": m.group(1), "op": m.group(2), "key": m.group(3)})
    # generic token-ish cookies
    rec["token_cookies"] = [c for c in rec["cookies"]
                            if STATEFUL_COOKIE_RE.search(c.get("name", ""))]
    return rec


def _scan_post_forms(body):
    """Light form inventory (Stage S CSRF mapping ke liye; 0 extra requests)."""
    forms = []
    try:
        for fm in re.finditer(r"<form\b[^>]*>", body or "", re.I):
            tag = fm.group(0)
            action_m = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", tag, re.I)
            method_m = re.search(r"method\s*=\s*[\"']?post\b", tag, re.I)
            if not method_m:
                continue
            # form ke andar hidden csrf fields dekho (rough: agle </form> tak)
            seg_end = body.find("</form>", fm.end())
            seg = body[fm.end():seg_end if seg_end > 0 else fm.end() + 2000]
            has_csrf = bool(re.search(
                r"(?i)name=[\"']([^\"']*(csrf|xsrf|token|_token|authenticity)[^\"']*)[\"']", seg))
            forms.append({"action": (action_m.group(1) if action_m else ""),
                          "has_csrf": has_csrf,
                          "state_change_hint": bool(STATE_CHANGE_HINT_RE.search(seg[:500]))})
    except Exception:
        pass
    return forms[:8]


def build_identities(http, samples):
    """N isolated identity objects (har ek ka apna cookie jar)."""
    return [http.identity("sess%d" % i) for i in range(max(1, int(samples)))]


# ---------------------------------------------------------------------------
# STAGE C - COOKIE SECURITY DEEP-DIVE
# ---------------------------------------------------------------------------
def cookie_deep_dive(captures):
    """Saare captures ke cookies ko analyse karo (per-endpoint + aggregate)."""
    per_ep, all_cookies = {}, []
    for u, rec in captures.items():
        cookies = [parse_set_cookie(raw) for raw in (rec.get("set_cookie") or [])]
        cookies = [c for c in cookies if c]
        # identity jar se bhi cookies (jo Set-Cookie me nahi dikhti dobara)
        for c in (rec.get("cookies") or []):
            if not any(x.get("name") == c.get("name") for x in cookies):
                cookies.append({"name": c.get("name"), "value": "", "value_len": 0,
                                "value_fingerprint": "", "value_entropy": 0.0,
                                "httponly": False, "secure": bool(c.get("secure")),
                                "samesite": "", "domain": c.get("domain") or "",
                                "path": c.get("path") or "/", "max_age": None,
                                "expires": c.get("expires"), "priority": "",
                                "partitioned": False, "session_cookie": True,
                                "from_jar": True})
        if cookies:
            per_ep[u] = {"cookies": cookies, "summary": cookie_analysis(cookies)}
            all_cookies.extend([dict(c, endpoint=u) for c in cookies])
    agg = cookie_analysis(all_cookies) if all_cookies else {"count": 0}
    # duplicate names ACROSS endpoints (session tossing)
    names = [c.get("name") for c in all_cookies]
    agg["duplicate_names_global"] = sorted({n for n in names if n and names.count(n) > 1})
    return {"per_endpoint": per_ep, "aggregate": agg}


# ---------------------------------------------------------------------------
# SHARED LOGIN HELPER (fixation + concurrent dono use karte hain) - v10
# ---------------------------------------------------------------------------
def _do_login(http, ident, login_url, creds, conf=None):
    """
    Form-aware login ek jagah. BUG-1 FIX: POST read_only_post=True ke saath
    (ULTRA core ka RWX gate bina iske ScopeError raise karta tha -> crash).
    Returns {"ok": bool, "status": int, "page": response-obj | None}
    """
    res = {"ok": False, "status": None}
    pre = ident.request("GET", login_url, allow_redirects=True)
    res["pre_status"] = pre.status
    forms = []
    try:
        from mod_auth import parse_forms, guess_fields
        forms = parse_forms(pre.text, pre.url)
    except Exception:
        forms = []
    form = next((f for f in forms if f.get("has_password")), None)
    user_f = pass_f = None
    action, method = (form["action"], form["method"]) if form else (login_url, "POST")
    if form:
        user_f, pass_f = guess_fields(form["field_names"])
    data = {user_f or "username": creds.get("username", ""),
            pass_f or "password": creds.get("password", "")}
    if form:
        for cf in form.get("csrf_fields", []):
            for fld in form.get("fields", []):
                if fld["name"] == cf and fld.get("value"):
                    data[cf] = fld["value"]
    body = urllib.parse.urlencode(data).encode()
    try:
        post = ident.request(method, action, headers={"Content-Type": "application/x-www-form-urlencoded"},
                             data=body, allow_redirects=False, read_only_post=True)
    except TypeError:
        # purana core: read_only_post kwarg nahi tha
        post = ident.request(method, action, headers={"Content-Type": "application/x-www-form-urlencoded"},
                             data=body, allow_redirects=False)
    res["status"] = post.status
    res["location"] = post.header("Location")
    res["ok"] = bool(post.status and post.status < 500)
    return res


# ---------------------------------------------------------------------------
# STAGE D - TOKEN RANDOMNESS LAB (session-id level)
# ---------------------------------------------------------------------------
def session_token_randomness(http, url, conf, identity_count=None, samples=None):
    """
    N isolated identities se token lo, phir randomness lab chalao.
    Yahan hum SESSION tokens par kaam karte hain (JWT alag stage me).
    """
    n_id = int(identity_count or conf.get("session_identities", 3))
    n_s = int(samples or conf.get("session_token_samples", 6))
    tokens, per_identity = [], []
    for i in range(max(1, n_s)):
        ident = http.identity("rand%d" % i)
        r = ident.request("GET", url, allow_redirects=True)
        if not r.status:
            continue
        jar = ident.session_export()
        stateful = [c for c in jar if STATEFUL_COOKIE_RE.search(c.get("name", ""))]
        vals = [c.get("value") for c in stateful if c.get("value")]
        per_identity.append({"identity": i, "status": r.status,
                             "cookies": [c.get("name") for c in jar],
                             "stateful_values_len": [len(v) for v in vals]})
        tokens.extend(vals)
        # body me token mile to wo bhi
        for m in re.finditer(r"\b(eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{0,})", r.text or ""):
            tokens.append(m.group(0))
    uniq = len(set(tokens))
    lab = token_randomness_lab(tokens, alpha=float(conf.get("session_stats_alpha", 0.05)))
    lab["distinct_identities"] = len(per_identity)
    lab["unique_tokens"] = uniq
    lab["static_token"] = bool(tokens and uniq == 1 and len(tokens) > 1)
    if lab["static_token"]:
        lab["problems"] = list(lab.get("problems", [])) + ["token har session me IDENTICAL"]
        lab["weak"] = True
        lab["verdict"] = "CRITICAL: static session token"
    lab["per_identity"] = per_identity
    return lab


# ---------------------------------------------------------------------------
# STAGE E - SESSION FIXATION
# ---------------------------------------------------------------------------
def session_fixation_test(http, scope, login_url, creds, conf):
    """
    Fixation check: pre-auth session id lo -> login karo -> dekho id rotate hui
    ya nahi. Sirf tab chalta hai jab engagement test credentials de.
    v10: login _do_login() se (read_only_post=True fix ke saath).
    """
    res = {"endpoint": login_url, "ran": False, "rotated": None, "summary": ""}
    if not creds:
        res["summary"] = "skip: session_test_credentials nahi diye gaye"
        return res
    ident = http.identity("fixation")
    pre = ident.request("GET", login_url, allow_redirects=True)
    pre_cookies = {c.get("name"): c.get("value") for c in ident.session_export()}
    pre_stateful = {k: v for k, v in pre_cookies.items() if STATEFUL_COOKIE_RE.search(k or "")}
    if not pre_stateful:
        res["summary"] = "skip: pre-auth session cookie nahi mila"
        res["pre_cookies"] = list(pre_cookies.keys())
        return res
    res["ran"] = True
    res["pre_cookies"] = sorted(pre_stateful.keys())

    login = _do_login(http, ident, login_url, creds, conf)
    res["login_status"] = login.get("status")
    post_cookies = {c.get("name"): c.get("value") for c in ident.session_export()}
    post_stateful = {k: v for k, v in post_cookies.items() if STATEFUL_COOKIE_RE.search(k or "")}
    same = [k for k in pre_stateful if k in post_stateful and pre_stateful[k] == post_stateful[k]]
    res["unchanged_cookies"] = same
    res["rotated"] = not bool(same)
    if same:
        res["summary"] = ("LOGIN ke baad bhi ye session cookies same rahi: %s -> "
                          "session fixation possible" % ", ".join(same))
    else:
        res["summary"] = "session id login par rotate hui (achha)"
    return res


# ---------------------------------------------------------------------------
# STAGE F - SESSION LIFECYCLE (logout / timeout / rotation)
# ---------------------------------------------------------------------------
def logout_invalidation_test(http, scope, logout_url, token_url, check_url, conf):
    """
    Apne synthetic session par: token endpoint se session lo -> protected page
    par authenticated state confirm karo -> logout bhejo -> wahi protected page
    dobara maango. Agar phir bhi 200 aata hai to server-side invalidation nahi.

    check_url token_url se ALAG hona chahiye - warna wahi endpoint naya token
    issue kar dega aur test galat pass ho jayega (v1 ka design flaw).
    """
    res = {"logout_url": logout_url, "token_url": token_url, "check_url": check_url,
           "ran": False, "invalidated": None, "inconclusive": False, "summary": ""}
    if not conf.get("session_allow_logout_test", True):
        res["summary"] = "skip: session_allow_logout_test=false"
        return res
    if not check_url or check_url == token_url:
        res["summary"] = "skip: token endpoint se alag protected endpoint nahi mila"
        return res
    ident = http.identity("logout")
    tok_r = ident.request("GET", token_url, allow_redirects=True)
    token_before = {c.get("name"): c.get("value") for c in ident.session_export()}
    stateful_before = {k: v for k, v in token_before.items() if STATEFUL_COOKIE_RE.search(k or "")}
    res["token_status"] = tok_r.status
    res["token_names"] = sorted(stateful_before.keys())
    if not stateful_before:
        res["summary"] = "skip: token endpoint se koi stateful cookie nahi mili"
        return res
    pre = ident.request("GET", check_url, allow_redirects=True)
    if pre.status in (401, 403):
        res["inconclusive"] = True
        res["pre_status"] = pre.status
        res["summary"] = ("inconclusive: %s ne authenticated state nahi diya (status %s) - "
                          "logout invalidation verify nahi ho sakti bina valid session ke"
                          % (check_url, pre.status))
        return res
    res["ran"] = True
    lo = ident.request("GET", logout_url, allow_redirects=False)
    res["logout_status"] = lo.status
    res["logout_method"] = "GET"
    res["logout_location"] = lo.header("Location")
    res["logout_set_cookie"] = [v for k, v in lo.headers.items() if k.lower() == "set-cookie"]
    # ULTRA: GET-based logout = logout CSRF surface (koi state change nahi karte,
    # sirf observed behavior record hota hai)
    if res["logout_status"] and res["logout_status"] < 400 and not res["inconclusive"]:
        res["get_logout_note"] = ("logout GET request se chalta hai - logout-CSRF surface "
                                  "(attacker page victim ko /logout par bhej sakta hai)")
    # logout ke baad usi jar se protected endpoint
    after = ident.request("GET", check_url, allow_redirects=True)
    res["after_status"] = after.status
    res["after_len"] = len(after.body)
    res["pre_status"] = pre.status
    res["pre_len"] = len(pre.body)
    still = (after.status == pre.status and after.status is not None and after.status < 400
             and abs(len(after.body) - len(pre.body)) <= 64)
    cleared = any(re.search(r"(?i)(max-age\s*=\s*0|expires\s*=\s*thu, 01 jan 1970)", v)
                  for v in res["logout_set_cookie"])
    res["cookie_cleared"] = cleared
    res["invalidated"] = (not still) or cleared
    if not res["invalidated"]:
        res["summary"] = ("logout ke baad bhi same session se %s milta hai aur cookie clear "
                          "nahi hui -> server-side invalidation nahi lag rahi" % after.status)
    else:
        res["summary"] = "logout ne session invalidate/clear kiya (achha)"
    return res


def lifecycle_inference(captures, cookie_deep):
    """Idle/absolute timeout + rotation + concurrent cap ke indicators."""
    out = {"expiry_model": {}, "rotation_indicators": [], "concurrent_cap": "unknown",
           "notes": []}
    for u, rec in (cookie_deep.get("per_endpoint") or {}).items():
        for c in rec.get("cookies", []):
            if not STATEFUL_COOKIE_RE.search(c.get("name", "")):
                continue
            out["expiry_model"].setdefault(c.get("name"), []).append(
                "session-scoped" if c.get("session_cookie")
                else ("max-age=%s" % c.get("max_age") if c.get("max_age") is not None
                      else "expires=%s" % c.get("expires")))
    out["expiry_model"] = {k: sorted(set(v)) for k, v in out["expiry_model"].items()}
    # Cache-Control: no-store missing on session pages = token cache leak risk
    for u, rec in captures.items():
        cc = (rec.get("cache_control") or "").lower()
        if rec.get("token_cookies") and "no-store" not in cc:
            out["rotation_indicators"].append(
                {"endpoint": u, "issue": "session page par Cache-Control: no-store nahi",
                 "cache_control": rec.get("cache_control") or ""})
    if not out["expiry_model"]:
        out["notes"].append("koi stateful cookie nahi mili -> server-side session ya JWT ho sakta hai")
    return out


# ---------------------------------------------------------------------------
# STAGE G - SESSION BINDING (hijack resistance)
# ---------------------------------------------------------------------------
def session_binding_test(http, scope, url, conf):
    """
    Ek session token lo, phir usi token ko alag IP-header / User-Agent ke saath
    replay karo. Agar accept hota hai -> session device/IP se bound nahi.
    """
    res = {"endpoint": url, "ran": False, "bound": None, "probes": [], "summary": ""}
    if not conf.get("session_allow_binding_test", True):
        res["summary"] = "skip: session_allow_binding_test=false"
        return res
    ident = http.identity("binding")
    base = ident.request("GET", url, allow_redirects=True)
    jar = ident.session_export()
    stateful = [c for c in jar if STATEFUL_COOKIE_RE.search(c.get("name", ""))]
    if not stateful:
        res["summary"] = "skip: stateful cookie nahi mili"
        return res
    res["ran"] = True
    cookie_header = "; ".join("%s=%s" % (c.get("name"), c.get("value")) for c in stateful)
    res["baseline_status"] = base.status
    res["baseline_len"] = len(base.body)
    probe_sets = [
        {"label": "same-ua-same-ip", "headers": {}},
        {"label": "different-ua", "headers": {"User-Agent": "WASP-Binding-Probe/1.0"}},
        {"label": "different-xff", "headers": {"X-Forwarded-For": "203.0.113.11"}},
        {"label": "different-ua-and-xff", "headers": {"User-Agent": "curl/8.0",
                                                      "X-Forwarded-For": "198.51.100.7"}},
    ]
    accepted = 0
    for ps in probe_sets[:max(1, int(conf.get("session_binding_probes", 3))) + 1]:
        c = http.identity("bind-" + ps["label"])
        c.set_cookie_header(cookie_header)
        c.set_default_headers(ps["headers"])
        r = c.request("GET", url, allow_redirects=True)
        same = (r.status == base.status and abs(len(r.body) - len(base.body)) <= 64)
        if same:
            accepted += 1
        res["probes"].append({"label": ps["label"], "headers": ps["headers"], "status": r.status,
                              "len": len(r.body), "accepted": bool(same)})
    res["accepted_count"] = accepted
    res["bound"] = (accepted <= 1)
    if accepted >= 2:
        res["summary"] = ("%d/%d alag UA/IP header combos par session accept hua -> "
                          "device/IP binding nahi" % (accepted, len(res["probes"])))
    else:
        res["summary"] = "session sirf original context par chala -> binding lag rahi hai"
    return res


# ---------------------------------------------------------------------------
# STAGE J - TOKEN LEAKAGE CHANNELS
# ---------------------------------------------------------------------------
def token_leakage_analysis(captures, base_dir, eng):
    """
    Token leak ke channels: URL/query, response body, Referer risk, JS storage,
    logs/history, cache. Ye v1 me bilkul nahi tha.
    """
    out = {"url_tokens": [], "body_tokens": [], "header_tokens": [],
           "storage_hints": [], "cache_risks": [], "referer_risks": [],
           "js_storage_from_phase7": [], "summary": ""}
    for u, rec in captures.items():
        if rec.get("token_in_url") or LEAK_URL_RE.search(u):
            out["url_tokens"].append({"endpoint": u, "why": "token query parameter me"})
        for t in rec.get("tokens_in_body") or []:
            out["body_tokens"].append({"endpoint": u, "fingerprint": sha1(t)[:12],
                                       "len": len(t)})
        for h in rec.get("tokens_in_headers") or []:
            out["header_tokens"].append({"endpoint": u, "header": h.get("header")})
        for s in rec.get("localstorage_hints") or []:
            out["storage_hints"].append(dict(s, endpoint=u))
        cc = (rec.get("cache_control") or "").lower()
        if (rec.get("token_cookies") or rec.get("tokens_in_body")) and "no-store" not in cc:
            out["cache_risks"].append({"endpoint": u,
                                       "cache_control": rec.get("cache_control") or "(none)",
                                       "pragma": rec.get("pragma") or "(none)",
                                       "why": "token wale response par Cache-Control: no-store nahi"})
    # Phase 7 ke JS storage hints (agar Phase 7 chala tha)
    for fn in ("dom_analysis.txt", "config_hints.txt", "js_analysis.json"):
        p = os.path.join(base_dir, eng, "js", fn)
        if not os.path.exists(p):
            continue
        try:
            txt = open(p, errors="ignore").read()
        except Exception:
            continue
        for m in re.finditer(r"(?i)(localStorage|sessionStorage)[^\n]{0,80}", txt):
            out["js_storage_from_phase7"].append(m.group(0)[:120])
    out["js_storage_from_phase7"] = sorted(set(out["js_storage_from_phase7"]))[:20]
    # Referer risk: token URL me ho aur page me third-party resource ho
    for ut in out["url_tokens"]:
        out["referer_risks"].append(
            {"endpoint": ut["endpoint"],
             "why": "URL me token hai; us page par koi bhi external resource load hone par "
                    "Referer header ke through token third-party ko ja sakta hai"})
    out["summary"] = ("url_tokens=%d body_tokens=%d header_tokens=%d storage_hints=%d "
                      "cache_risks=%d" % (len(out["url_tokens"]), len(out["body_tokens"]),
                                          len(out["header_tokens"]), len(out["storage_hints"]),
                                          len(out["cache_risks"])))
    return out


# ---------------------------------------------------------------------------
# STAGE H - JWT DEEP ANALYSIS (jwks + weak secret + claim hygiene)
# ---------------------------------------------------------------------------
def _protected_probe(http, url):
    """Baseline GET: 401/403 mila to endpoint 'protected' maana jayega.

    ULTRA v10 FIX: har probe FRESH identity (isolated cookie jar) par hota hai.
    Wajah: agar pehla probe kisi session-issuing endpoint par jaaye to main
    client ki jar me valid session aa jaati hai aur baaki ke 'unauthenticated'
    probes asal me authenticated ho jaate hain -> 401 kabhi nahi milta ->
    tamper/matrix hamesha skip. Isolated jar se har probe clean rehta hai.
    """
    c = http.identity("prot-%s" % rand_str(4))
    r = c.request("GET", url, allow_redirects=False)
    return {"status": r.status, "len": len(r.body),
            "protected": r.status in (401, 403),
            "www_authenticate": r.header("WWW-Authenticate")}


def jwt_deep_analysis(http, scope, tokens, jwks_urls, conf):
    """
    Saare captured JWTs ko deep analyse karo + JWKS key strength + (bounded)
    weak-HMAC-secret dictionary check.
    """
    out = {"tokens": [], "jwks": {}, "weak_secret_hits": [], "summary": ""}
    seen = set()
    for tok, endpoint in tokens:
        if not tok or tok in seen:
            continue
        seen.add(tok)
        info_ = jwt_deep(tok, weak_secrets=(WEAK_JWT_SECRETS if conf.get("session_weak_secret_crack", True)
                                            else None),
                         weak_max=int(conf.get("session_weak_secret_max", 40)))
        info_["endpoint"] = endpoint
        info_["_raw"] = tok          # internal use (reports me redact karke likhte hain)
        out["tokens"].append(info_)
        ws = info_.get("weak_secret_check") or {}
        if ws.get("found"):
            out["weak_secret_hits"].append({"endpoint": endpoint, "secret": ws["found"],
                                            "alg": info_.get("alg")})
    # OIDC discovery docs se asli jwks_uri nikalo (wahan keys hoti hain, doc me nahi)
    resolved = []
    for u in jwks_urls[:4]:
        r = http.request("GET", u, allow_redirects=True)
        if not r.status or r.status >= 400:
            continue
        try:
            doc = json.loads(r.text)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("keys"):
            out["jwks"][u] = jwks_analysis(doc)
            continue
        if isinstance(doc, dict) and doc.get("jwks_uri"):
            resolved.append(doc["jwks_uri"])
    for u in resolved[:2]:
        r = http.request("GET", u, allow_redirects=True)
        if not r.status or r.status >= 400:
            continue
        try:
            doc = json.loads(r.text)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("keys"):
            out["jwks"][u] = jwks_analysis(doc)
            out["jwks_discovered_via"] = u
    alg_list = sorted(set(t.get("alg") for t in out["tokens"] if t.get("alg")))
    out["algs_seen"] = alg_list
    out["summary"] = ("tokens=%d | algs=%s | jwks_docs=%d | weak_secret_hits=%d" % (
        len(out["tokens"]), alg_list, len(out["jwks"]), len(out["weak_secret_hits"])))
    return out


# ---------------------------------------------------------------------------
# STAGE I - JWT TAMPER MATRIX (gated, GET-only, bounded)
# ---------------------------------------------------------------------------
def jwt_tamper_matrix(http, scope, endpoint, token, conf):
    """
    Tamper matrix (sirf tab chalti hai jab baseline 401/403 ho - warna
    'accept' ka matlab hi nahi). Max `session_jwt_tamper_max` requests.
    Variants:
      1) alg=none + empty signature
      2) alg=None (case variant)
      3) signature strip (trailing dot)
      4) claim escalation (admin/role) purani signature ke saath
      5) header kid traversal ke saath (agar kid pehle se ho)
    """
    res = {"endpoint": endpoint, "attempted": False, "variants": [], "bypass": False,
           "bypass_type": None, "summary": "",
           "note": "read-only GET; koi state change nahi"}
    max_r = int(conf.get("session_jwt_tamper_max", 3))
    base = _protected_probe(http, endpoint)
    res["baseline"] = base
    if not base["protected"]:
        res["summary"] = ("baseline %s (401/403 nahi) -> tamper matrix skip; "
                          "protected endpoint pe dobara chalao" % base["status"])
        return res
    parts = (token or "").split(".")
    if len(parts) < 2:
        res["summary"] = "token malformed -> skip"
        return res
    hdr = _dict_or_none(b64url_decode_json(parts[0])) or {}
    pay = _dict_or_none(b64url_decode_json(parts[1])) or {}
    res["attempted"] = True

    variants = []
    h1 = dict(hdr); h1["alg"] = "none"
    variants.append(("alg-none-empty-sig", "%s.%s." % (b64url_encode(h1), parts[1])))
    h2 = dict(hdr); h2["alg"] = "None"
    variants.append(("alg-None-camel", "%s.%s." % (b64url_encode(h2), parts[1])))
    if len(parts) == 3:
        variants.append(("signature-stripped", "%s.%s.%s" % (parts[0], parts[1], "")))
    p3 = dict(pay); p3.update({"admin": True, "role": "admin", "is_admin": True})
    variants.append(("claim-escalation", "%s.%s.%s" % (parts[0], b64url_encode(p3),
                                                       parts[2] if len(parts) > 2 else "")))
    if hdr.get("kid"):
        h4 = dict(hdr); h4["kid"] = "../../../../dev/null"
        variants.append(("kid-traversal", "%s.%s.%s" % (b64url_encode(h4), parts[1],
                                                        parts[2] if len(parts) > 2 else "")))

    for label, tok in variants:
        if len(res["variants"]) >= max_r:
            break
        r = http.request("GET", endpoint, headers={"Authorization": "Bearer " + tok},
                         allow_redirects=False)
        accepted = bool(r.status and r.status < 400)
        res["variants"].append({"variant": label, "status": r.status, "len": len(r.body),
                                "accepted": accepted,
                                "token_len": len(tok)})
        if accepted:
            res["bypass"] = True
            if not res["bypass_type"]:
                res["bypass_type"] = label
    if res["bypass"]:
        res["summary"] = ("%s variant ACCEPT hua (baseline %s tha) -> token verification "
                          "bypass ho sakta hai" % (res["bypass_type"], base["status"]))
    else:
        res["summary"] = ("saare %d tamper variants reject hue -> signature verification "
                          "theek lag rahi hai" % len(res["variants"]))
    return res


# ---------------------------------------------------------------------------
# ULTRA STAGE M - WEB CACHE DECEPTION & MIX-UP (bounded, own session)
# ---------------------------------------------------------------------------
def cache_deception_probe(http, url, conf):
    """
    Famous Web Cache Deception (WCD) technique - apne session ke saath:
      1) baseline: GET <url> (own identity)
      2) variant:  GET <url>.css               (extension spoof)
      3) variant:  GET <url>/wasp-cache.css    (path-append spoof)
    Signals: X-Cache/CF-Cache-Status HIT, Age>0, ya cacheable Cache-Control +
    authenticated body-length ~ baseline. Agar authenticated response cache
    ho gayi to victim ka private data cache me public ho sakta hai.

    NOTE: hum apni hi session use karte hain - kisi victim ke data ko touch
    nahi karte. Ye surface-detection hai, exploitation nahi.
    """
    res = {"endpoint": url, "ran": False, "variants": [], "deception": False,
           "summary": ""}
    max_r = max(0, int(conf.get("session_cache_probe_max", 3)))
    if max_r == 0:
        res["summary"] = "skip: session_cache_probe_max=0"
        return res
    ident = http.identity("wcd")
    base = ident.request("GET", url, allow_redirects=False)
    if not base.status or base.status >= 400:
        res["summary"] = "skip: baseline %s (authenticated endpoint chahiye)" % base.status
        return res
    res["ran"] = True
    res["baseline"] = {"status": base.status, "len": len(base.body),
                       "cache_control": base.header("Cache-Control"),
                       "vary": base.header("Vary")}
    path = urllib.parse.urlsplit(url).path
    sep = "&" if "?" in url else "?"
    variants = []
    if not path.lower().endswith((".css", ".js")):
        variants.append(("extension-suffix", url + ".css"))
        if "/" in path.rstrip("/"):
            variants.append(("path-append", url.rstrip("/") + "/wasp-cache.css"))
    else:
        variants.append(("query-bust", url + sep + "wasp=cachebust"))
    used = 0
    for label, vurl in variants:
        if used >= max_r:
            break
        used += 1
        r = ident.request("GET", vurl, allow_redirects=False)
        h = {k.lower(): v for k, v in r.headers.items()}
        hit_signal = any(sig in (h.get("x-cache", "") + " " + h.get("x-vercel-cache", "")).lower()
                         for sig in ("hit", "stale")) or \
                     "hit" in (h.get("cf-cache-status", "") or "").lower() or \
                     bool(h.get("age") and h.get("age", "0").isdigit() and int(h["age"]) > 0)
        cc = (h.get("cache-control") or "")
        cacheable_cc = bool(re.search(r"(public|max-age\s*=\s*[1-9]|s-maxage)", cc)) and \
            "no-store" not in cc and "private" not in cc
        body_similar = abs(len(r.body) - len(base.body)) <= 64
        deceptive = bool(r.status and r.status < 400 and body_similar and (hit_signal or cacheable_cc))
        res["variants"].append({"variant": label, "url": vurl, "status": r.status,
                                "len": len(r.body), "cache_control": cc,
                                "hit_signal": bool(hit_signal), "cacheable": bool(cacheable_cc),
                                "deceptive": deceptive})
        if deceptive:
            res["deception"] = True
    if res["deception"]:
        res["summary"] = ("authenticated response path-variant par cacheable/cache-hit -> "
                          "Web Cache Deception surface (own session se verify kiya)")
    else:
        res["summary"] = ("cache deception signals nahi mile (%d variants, sirf own session)" % used)
    return res


# ---------------------------------------------------------------------------
# ULTRA STAGE N - COOKIE CONFLICT / TOSS PARSER PROBE (own session, bounded)
# ---------------------------------------------------------------------------
def cookie_conflict_probe(http, url, cookie_name, own_value, conf):
    """
    Famous cookie-tossing pre-condition: parser duplicate cookie names ko kaise
    leta hai? Fresh identity par forced Cookie header me APNI HI value + ek
    shadow value bhejte hain:
        Cookie: <name>=<own_value>; <name>=wasp-shadow-<rand>
    Agar endpoint phir bhi authenticated response de (baseline jaisa) ->
    duplicate accepted (tossing pre-condition). Koi real user value nahi.

    shadow preference detect karne ke liye shadow-first order bhi try hota hai
    (kuch parsers first lete hain, kuch last).
    """
    res = {"endpoint": url, "cookie": cookie_name, "ran": False, "probes": [],
           "duplicate_accepted": False, "summary": ""}
    max_p = max(0, int(conf.get("session_conflict_probes", 2)))
    if not cookie_name or not own_value or max_p == 0:
        res["summary"] = "skip: stateful cookie/own value nahi mili ya probes=0"
        return res
    base_ident = http.identity("conflict-base")
    base_ident.set_cookie_header("%s=%s" % (cookie_name, own_value))
    base = base_ident.request("GET", url, allow_redirects=False)
    if not base.status or base.status >= 400:
        res["summary"] = "skip: own-cookie baseline %s (valid session chahiye)" % base.status
        return res
    res["ran"] = True
    res["baseline"] = {"status": base.status, "len": len(base.body)}
    shadow = "wasp-shadow-%s" % rand_str(6)
    orders = [("own-first", "%s=%s; %s=%s" % (cookie_name, own_value, cookie_name, shadow)),
              ("shadow-first", "%s=%s; %s=%s" % (cookie_name, shadow, cookie_name, own_value))]
    for label, hdr in orders[:max_p]:
        c = http.identity("conflict-" + label)
        c.set_cookie_header(hdr)
        r = c.request("GET", url, allow_redirects=False)
        accepted = bool(r.status and r.status == base.status and
                        abs(len(r.body) - len(base.body)) <= 64)
        res["probes"].append({"order": label, "status": r.status, "len": len(r.body),
                              "accepted": accepted})
        if accepted:
            res["duplicate_accepted"] = True
    if res["duplicate_accepted"]:
        res["summary"] = ("duplicate cookie name accept hua -> parser conflict surface "
                          "(cookie tossing pre-condition; shadow=%s)" % shadow)
    else:
        res["summary"] = "duplicate cookie names reject/normalize hue (achha)"
    return res


# ---------------------------------------------------------------------------
# ULTRA STAGE O - REFRESH TOKEN ROTATION (own token, bounded)
# ---------------------------------------------------------------------------
def refresh_rotation_test(http, refresh_url, refresh_token, conf):
    """
    Famous ATO vector: refresh token rotation. Apne captured refresh token se:
      1) POST refresh -> naya token pair milta hai (normal use)
      2) OLD refresh token dobara POST -> accept hua? to rotation NAHI hota
         (leaked refresh token = permanent account takeover)
    Sirf APNA token; max session_refresh_max requests; read-only intent POST.
    """
    res = {"endpoint": refresh_url, "ran": False, "rotated": None, "summary": ""}
    max_r = max(0, int(conf.get("session_refresh_max", 3)))
    if not refresh_token or not refresh_url or max_r == 0:
        res["summary"] = "skip: refresh token/endpoint nahi mila ya cap=0"
        return res
    ident = http.identity("refresh")
    res["ran"] = True
    new_token = None
    # attempt 1: JSON body
    payload = json.dumps({"refresh_token": refresh_token, "token": refresh_token}).encode()
    used = 0
    first_status = None
    for ctype, body in (("application/json", payload),
                        ("application/x-www-form-urlencoded",
                         urllib.parse.urlencode({"refresh_token": refresh_token}).encode())):
        if used >= max_r:
            break
        used += 1
        r = ident.request("POST", refresh_url, headers={"Content-Type": ctype}, data=body,
                          allow_redirects=False, read_only_post=True)
        first_status = r.status
        if r.status and r.status < 400:
            res["refresh_status"] = r.status
            txt = r.text or ""
            m = re.search(r'"refresh[_-]?token"\s*:\s*"([^"]{8,})"', txt)
            if m:
                new_token = m.group(1)
            res["new_refresh_issued"] = bool(new_token)
            break
    if first_status is None or not (res.get("refresh_status")):
        res["summary"] = "refresh endpoint ne %s diya -> rotation test inconclusive" % first_status
        res["refresh_status"] = first_status
        return res
    # attempt 2: OLD token reuse (rotation ka asli test)
    if used >= max_r:
        res["rotated"] = None
        res["summary"] = "cap khatam -> old-token reuse test skip (rotation unknown)"
        return res
    used += 1
    reuse_body = json.dumps({"refresh_token": refresh_token}).encode()
    r2 = ident.request("POST", refresh_url, headers={"Content-Type": "application/json"},
                       data=reuse_body, allow_redirects=False, read_only_post=True)
    res["reuse_status"] = r2.status
    reused = bool(r2.status and r2.status < 400)
    if reused:
        res["rotated"] = False
        res["summary"] = ("OLD refresh token reuse ACCEPT hua (%s) -> rotation nahi hota; "
                          "leaked refresh token = permanent ATO" % r2.status)
    else:
        res["rotated"] = True
        res["summary"] = "old refresh token reject hua -> single-use rotation lag rahi hai (achha)"
    return res


# ---------------------------------------------------------------------------
# ULTRA STAGE P - CONCURRENT SESSION CAP (test credentials only, bounded)
# ---------------------------------------------------------------------------
def concurrent_session_test(http, scope, login_url, check_url, creds, conf):
    """
    Same test-credentials se N logins (default 2). Dono sessions protected
    endpoint par valid? -> concurrent cap nahi hai. Server agar purana
    session revoke karta hai to ek fail hoga (achha).
    """
    res = {"login_url": login_url, "check_url": check_url, "ran": False,
           "cap": "unknown", "sessions": [], "summary": ""}
    if not creds:
        res["summary"] = "skip: session_test_credentials nahi diye gaye"
        return res
    if not check_url:
        res["summary"] = "skip: protected check endpoint nahi mila"
        return res
    n = max(2, int(conf.get("session_concurrent_logins", 2)))
    if n > 3:
        n = 3  # hard bound
    res["ran"] = True
    valid = 0
    for i in range(n):
        ident = http.identity("conc%d" % i)
        login = _do_login(http, ident, login_url, creds, conf)
        sess = ident.session_export()
        stateful = [c for c in sess if STATEFUL_COOKIE_RE.search(c.get("name", ""))]
        ok_login = bool(stateful)
        status = None
        if ok_login:
            r = ident.request("GET", check_url, allow_redirects=True)
            status = r.status
            is_valid = bool(r.status and r.status < 400)
            valid += 1 if is_valid else 0
            res["sessions"].append({"login": i, "login_status": login.get("status"),
                                    "check_status": status, "valid": is_valid,
                                    "cookies": [c.get("name") for c in stateful]})
        else:
            res["sessions"].append({"login": i, "login_status": login.get("status"),
                                    "check_status": None, "valid": False, "cookies": []})
    if valid >= 2:
        res["cap"] = "none-detected"
        res["summary"] = ("%d/%d concurrent sessions valid rahi -> concurrent session cap "
                          "nahi (hijack detect karna mushkil)" % (valid, n))
    elif valid == 1:
        res["cap"] = "single-session"
        res["summary"] = "sirf 1 session valid raha -> server purana revoke karta hai (achha)"
    else:
        res["cap"] = "inconclusive"
        res["summary"] = "koi login session valid nahi hui -> credentials/endpoints check karo"
    return res


# ---------------------------------------------------------------------------
# ULTRA STAGE Q - JWT ATTACK MATRIX v2 (confusion + jwk-inject + logout-reuse)
# ---------------------------------------------------------------------------
# ---- minimal DER encoder (pure python, RSA public key PEM banane ke liye) ----
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_int(x):
    if x == 0:
        return b"\x02\x01\x00"
    body = b""
    while x:
        body = bytes([x & 0xFF]) + body
        x >>= 8
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + _der_len(len(body)) + body


def _der_seq(payload):
    return b"\x30" + _der_len(len(payload)) + payload


def _der_oid(oid_bytes):
    return b"\x06" + _der_len(len(oid_bytes)) + oid_bytes


def _der_bitstring(payload):
    return b"\x03" + _der_len(len(payload) + 1) + b"\x00" + payload


RSA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])


def rsa_pubkey_pem_from_jwks(n_b64, e_b64):
    """JWKS RSA key -> SubjectPublicKeyInfo PEM (RS256->HS256 confusion craft)."""
    n_int = int.from_bytes(b64url_decode(n_b64), "big")
    e_int = int.from_bytes(b64url_decode(e_b64), "big")
    rsa_pub = _der_seq(_der_int(n_int) + _der_int(e_int))
    spki = _der_seq(_der_seq(_der_oid(RSA_OID) + b"\x05\x00") + _der_bitstring(rsa_pub))
    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def _hs256_token(payload, key_bytes, extra_header=None):
    hdr = {"alg": "HS256", "typ": "JWT"}
    if extra_header:
        hdr.update(extra_header)
    signing_input = "%s.%s" % (b64url_encode(hdr), b64url_encode(payload))
    sig = hmac.new(key_bytes, signing_input.encode(), hashlib.sha256).digest()
    return "%s.%s" % (signing_input, b64url_encode(sig))


def jwt_attack_matrix_v2(http, scope, target, token, conf, logout_res=None, rsa_material=None):
    """
    ULTRA Stage Q (gated, GET-only, bounded):
      offline: duplicate-claims scan
      live (cap session_jwt_matrix_max):
        1) RS256->HS256 confusion - JWKS public key ko HMAC secret bana kar
           sign (payload SAME rakhte hain, sirf exp extend -> sirf verification
           test; koi escalation nahi)
        2) jwk-header injection - apni oct key header me embed karke sign
        3) logout-reuse - logout ke baad original JWT abhi bhi accepted?
    Har live probe se pehle baseline 401/403 zaroori (warna accept ka matlab nahi).
    rsa_material: JWKS se {n, e} public key material (run() se aata hai).
    """
    res = {"target": target, "attempted": False, "offline": {}, "probes": [],
           "bypass": False, "bypass_type": None, "summary": "",
           "note": "read-only GET; payload me privilege escalation NAHI - sirf "
                   "signature-verification behavior test"}
    max_p = max(0, int(conf.get("session_jwt_matrix_max", 3)))
    parts = (token or "").split(".")
    if len(parts) < 3 or max_p == 0:
        res["summary"] = "skip: JWT malformed ya cap=0"
        return res
    pay = _dict_or_none(b64url_decode_json(parts[1])) or {}
    hdr = _dict_or_none(b64url_decode_json(parts[0])) or {}

    # offline: duplicate claims (jwt_deep me bhi hota hai; yahan explicit)
    res["offline"]["duplicate_claims"] = jwt_duplicate_claim_scan(token)

    base = _protected_probe(http, target)
    res["baseline"] = base
    if not base["protected"]:
        res["summary"] = ("baseline %s (401/403 nahi) -> live probes skip" % base["status"])
        res["attempted"] = True
        return res
    res["attempted"] = True
    used = 0

    def probe(label, tok):
        nonlocal used
        used += 1
        r = http.request("GET", target, headers={"Authorization": "Bearer " + tok},
                         allow_redirects=False)
        accepted = bool(r.status and r.status < 400)
        res["probes"].append({"probe": label, "status": r.status, "len": len(r.body),
                              "accepted": accepted})
        if accepted and not res["bypass_type"]:
            res["bypass"] = True
            res["bypass_type"] = label
        return accepted

    # 1) RS256 -> HS256 confusion (sirf tab jab token RS* par sign ho aur JWKS
    #    pubkey available ho)
    rsa = None
    if str(hdr.get("alg", "")).startswith("RS"):
        rsa = rsa_material  # run() se inject hota hai (JWKS public key)
    if rsa and used < max_p:
        try:
            pem = rsa_pubkey_pem_from_jwks(rsa["n"], rsa["e"])
            p2 = dict(pay)
            p2["exp"] = int(time.time()) + 600   # chhota validity, sirf verification test
            p2["iat"] = int(time.time())
            tok2 = _hs256_token(p2, pem.encode())
            probe("rs256-hs256-confusion", tok2)
        except Exception as e:
            res["probes"].append({"probe": "rs256-hs256-confusion", "error": repr(e)[:120]})
    elif str(hdr.get("alg", "")).startswith("RS") and not rsa:
        res["probes"].append({"probe": "rs256-hs256-confusion", "skipped":
                              "JWKS RSA pubkey nahi mili (jwks_urls fetch fail hua hoga)"})

    # 2) jwk-header injection (embedded oct key)
    if used < max_p:
        key_bytes = rand_str(32).encode()
        jwk = {"kty": "oct", "k": b64url_encode(key_bytes)}
        p3 = dict(pay)
        p3["exp"] = int(time.time()) + 600
        p3["iat"] = int(time.time())
        tok3 = _hs256_token(p3, key_bytes, extra_header={"jwk": jwk})
        probe("jwk-header-injection", tok3)

    # 3) logout-reuse (sirf tab jab logout test chala ho)
    if logout_res and logout_res.get("ran") and used < max_p:
        probe("logout-reuse", token)
        lr = res["probes"][-1]
        lr["note"] = ("logout ke baad JWT accepted -> revocation missing "
                      "(stateless token kabhi expire nahi hota jab tak exp na ho)")
    elif not logout_res or not logout_res.get("ran"):
        res["probes"].append({"probe": "logout-reuse", "skipped": "logout test nahi chala"})

    if res["bypass"]:
        res["summary"] = ("%s probe ACCEPT hua (baseline %s) -> JWT verification bypass "
                          "surface CONFIRM" % (res["bypass_type"], base["status"]))
    else:
        accepted_count = sum(1 for p in res["probes"] if p.get("accepted"))
        res["summary"] = ("%d live probes me se %d accept hue; koi bypass nahi" % (
            len([p for p in res["probes"] if "status" in p]), accepted_count))
    return res


# ---------------------------------------------------------------------------
# ULTRA STAGE R - SESSION PAGE HARDENING (passive, 0 requests)
# ---------------------------------------------------------------------------
CDN_CACHE_HEADERS = ("x-cache", "cf-cache-status", "x-vercel-cache", "x-served-by", "via",
                     "x-drupal-cache")


def session_hardening_passive(live):
    """
    Captured response headers se (0 extra requests):
      - clickjacking on token pages (XFO/CSP frame-ancestors missing)
      - HSTS missing (https par)
      - weak referrer-policy on token pages
      - cache mix-up surface (cacheable + Vary: User-Agent missing + CDN hints)
    Purane checkpoint replays me resp_headers missing ho sakta hai -> un endpoints
    ko skip karte hain (false-positive se bachne ke liye).
    """
    out = {"clickjacking": [], "hsts_missing": [], "referrer_weak": [], "mixup": [],
           "analyzed": 0, "summary": ""}
    for u, rec in live.items():
        rh = rec.get("resp_headers")
        if not isinstance(rh, dict):
            continue
        out["analyzed"] += 1
        tokenish = bool(rec.get("token_cookies") or rec.get("tokens_in_body"))
        xfo = (rh.get("x-frame-options") or "").strip()
        csp = (rh.get("content-security-policy") or "")
        if tokenish and not xfo and "frame-ancestors" not in csp.lower():
            out["clickjacking"].append({"endpoint": u})
        hsts = (rh.get("strict-transport-security") or "").strip()
        if (rec.get("scheme") == "https" or u.startswith("https")) and not hsts and tokenish:
            out["hsts_missing"].append({"endpoint": u})
        rp = (rh.get("referrer-policy") or "").strip().lower()
        if tokenish and (not rp or not any(s in rp for s in
                                           ("strict-origin", "no-referrer", "same-origin"))):
            out["referrer_weak"].append({"endpoint": u, "referrer_policy": rp or "(none)"})
        cc = (rec.get("cache_control") or "").lower()
        vary = (rh.get("vary") or "").lower()
        cdn = any(rh.get(h) for h in CDN_CACHE_HEADERS)
        if tokenish and "no-store" not in cc and "user-agent" not in vary and cdn:
            out["mixup"].append({"endpoint": u, "cache_control": cc or "(none)",
                                 "vary": vary or "(none)"})
    out["summary"] = ("analyzed=%d | clickjacking=%d | hsts-missing=%d | referrer-weak=%d | "
                      "mixup=%d" % (out["analyzed"], len(out["clickjacking"]),
                                    len(out["hsts_missing"]), len(out["referrer_weak"]),
                                    len(out["mixup"])))
    return out


# ---------------------------------------------------------------------------
# ULTRA STAGE S - CSRF DEFENSE MAPPING (passive)
# ---------------------------------------------------------------------------
def csrf_defense_mapping(live, cookie_deep, base_dir, eng):
    """
    P10 captures ke forms + P9 auth_surface forms merge karke:
      - state-change POST forms bina CSRF token
      - session cookies SameSite ke bina (CSRF ka doosra half)
    Dono ek saath ho to cross-site state-change ka surface ready hai.
    """
    out = {"forms_without_csrf": [], "forms_total": 0, "samesite_missing_cookies": [],
           "from_phase9": 0, "summary": ""}
    for u, rec in live.items():
        for f in rec.get("forms_post") or []:
            out["forms_total"] += 1
            if not f.get("has_csrf") and f.get("state_change_hint"):
                out["forms_without_csrf"].append({"endpoint": u, "action": f.get("action", "")})
    # P9 auth_surface.json se forms (agar Phase 9 chala tha)
    p9 = load_json(os.path.join(base_dir, eng, "auth", "auth_surface.json"), None) or {}
    for u, pr in (p9.get("probes") or {}).items():
        forms = pr.get("forms") or []
        for f in forms:
            out["forms_total"] += 1
            if not f.get("csrf_present") and (f.get("has_password") or
                                              STATE_CHANGE_HINT_RE.search(
                                                  " ".join(f.get("field_names") or []))):
                out["from_phase9"] += 1
                out["forms_without_csrf"].append({"endpoint": u, "action": f.get("action", ""),
                                                  "source": "P9"})
    for u, rec in (cookie_deep.get("per_endpoint") or {}).items():
        for c in rec.get("cookies", []):
            if STATEFUL_COOKIE_RE.search(c.get("name", "")) and \
                    (not c.get("samesite") or c.get("samesite") == "none"):
                out["samesite_missing_cookies"].append(
                    {"endpoint": u, "cookie": c.get("name")})
    out["samesite_missing_cookies"] = out["samesite_missing_cookies"][:10]
    out["forms_without_csrf"] = out["forms_without_csrf"][:10]
    weak = bool(out["forms_without_csrf"]) and bool(out["samesite_missing_cookies"])
    out["weak"] = weak
    out["summary"] = ("forms=%d | without-csrf=%d (P9: %d) | samesite-missing=%d -> %s" % (
        out["forms_total"], len(out["forms_without_csrf"]), out["from_phase9"],
        len(out["samesite_missing_cookies"]), "CSRF surface WEAK" if weak else "defense theek lag rahi"))
    return out


# ---------------------------------------------------------------------------
# ULTRA STAGE T - WEBSOCKET SESSION SURFACE (passive)
# ---------------------------------------------------------------------------
def ws_session_surface(base_dir, eng, has_token_cookies):
    """P7 websockets.txt -> ws endpoints + session model hint (0 requests)."""
    out = {"ws_endpoints": [], "has_token_cookies": bool(has_token_cookies),
           "hint": "", "summary": ""}
    p = os.path.join(base_dir, eng, "js", "websockets.txt")
    if os.path.exists(p):
        try:
            for line in open(p, errors="ignore"):
                line = line.strip()
                if line.startswith(("ws://", "wss://")):
                    out["ws_endpoints"].append(line)
        except Exception:
            pass
    out["ws_endpoints"] = sorted(set(out["ws_endpoints"]))[:15]
    if out["ws_endpoints"] and has_token_cookies:
        out["hint"] = ("WebSocket connections browser me cookie bhejte hain (SameSite lax "
                       "cross-site WS me apply nahi hota kuch browsers par) - WS auth model "
                       "manually verify karo (origin check + token reuse)")
        out["summary"] = "%d ws endpoint(s) + cookie session -> model verify karna" % len(out["ws_endpoints"])
    elif out["ws_endpoints"]:
        out["summary"] = "%d ws endpoint(s) milte hain par token-cookie nahi" % len(out["ws_endpoints"])
    else:
        out["summary"] = "koi websocket surface nahi (P7 websockets.txt khaali/absent)"
    return out


# ---------------------------------------------------------------------------
# STAGE K - SESSION FLOW MAP (extended with ULTRA stage results)
# ---------------------------------------------------------------------------
def build_session_flow_map(captures, cookie_deep, lifecycle, logout_res, fixation_res,
                           binding_res, jwt_deep_res, leak_res, scope, ultra=None):
    L = ["# Session & Token Flow Map (auto-mapped)", "",
         "Phase 10 me observed session lifecycle. `stateDiagram-v2` ko Mermaid renderer me kholo.", "",
         "```mermaid", "stateDiagram-v2", "    [*] --> Anonymous"]
    ultra = ultra or {}
    # token issue points
    issue_eps = [u for u, r in captures.items() if r.get("set_cookie") or r.get("token_cookies")]
    for i, u in enumerate(issue_eps[:3]):
        L.append("    Anonymous --> TokenIssued : GET %s" % urllib.parse.urlparse(u).path)
    L.append("    TokenIssued --> Authenticated : token accepted")
    if fixation_res.get("ran"):
        if fixation_res.get("rotated"):
            L.append("    Authenticated --> TokenRotated : login (id rotate hui)")
            L.append("    TokenRotated --> Authenticated")
        else:
            L.append("    Authenticated --> FixationRisk : login (id SAME rahi)")
    if binding_res.get("ran"):
        if binding_res.get("bound"):
            L.append("    Authenticated --> BoundContext : device/IP binding")
        else:
            L.append("    Authenticated --> AnyContext : koi device/IP binding nahi")
    if logout_res.get("ran"):
        if logout_res.get("invalidated"):
            L.append("    Authenticated --> TokenDestroyed : logout (invalidated)")
            L.append("    TokenDestroyed --> [*]")
        else:
            L.append("    Authenticated --> TokenStillValid : logout ke baad bhi valid")
    else:
        L.append("    Authenticated --> [*] : logout")
    if jwt_deep_res.get("tokens"):
        L.append("    TokenIssued --> JWTInspected : %d JWT(s) analyse hue" % len(jwt_deep_res["tokens"]))
    # ULTRA flow annotations
    if (ultra.get("jwt_matrix_v2") or {}).get("bypass_type") == "logout-reuse":
        L.append("    TokenDestroyed --> TokenStillValid : JWT logout-reuse (revocation missing)")
    if (ultra.get("refresh") or {}).get("rotated") is False:
        L.append("    TokenIssued --> RefreshForever : old refresh token reuse hota hai")
    if (ultra.get("cache_deception") or {}).get("deception"):
        L.append("    Authenticated --> CachedPublic : auth response cacheable (WCD surface)")
    if (ultra.get("client_lab") or {}).get("has_client_side_state"):
        L.append("    TokenIssued --> ClientSideState : session state cookie me decode hota hai")
    L.append("```")
    L += ["", "## Token issuance inventory", "",
          "| Endpoint | Status | Set-Cookie | Stateful cookies | Token in body | Cache-Control |",
          "|---|---|---|---|---|---|"]
    for u, r in captures.items():
        L.append("| `%s` | %s | %s | %s | %s | %s |" % (
            urllib.parse.urlparse(u).path, r.get("status"),
            len(r.get("set_cookie") or []),
            ",".join(c.get("name", "") for c in (r.get("token_cookies") or [])) or "-",
            len(r.get("tokens_in_body") or []),
            r.get("cache_control") or "-"))
    L += ["", "## Expiry model", "",
          "| Cookie | Model |", "|---|---|"]
    for k, v in (lifecycle.get("expiry_model") or {}).items():
        L.append("| `%s` | %s |" % (k, ", ".join(v)))
    cl = ultra.get("client_lab") or {}
    if cl.get("has_client_side_state"):
        L += ["", "## Client-side session state (ULTRA)", ""]
        for c in (cl.get("client_side_signed") + cl.get("marshal") +
                  cl.get("embedded_privilege_state") + cl.get("plain_state_values"))[:8]:
            L.append("- `%s` -> %s" % (c.get("cookie"), c.get("kind")))
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# HYPOTHESES + KILL TESTS (extended)
# ---------------------------------------------------------------------------
def build_hypotheses(F, rand_lab, cookie_deep, lifecycle, logout_res, fixation_res,
                     binding_res, jwt_deep_res, tamper_res, leak_res, ultra=None):
    H = []
    ultra = ultra or {}

    def add(hid, statement, because, kill, phase):
        H.append({"id": hid, "hypothesis": statement, "because": because,
                  "kill_test": kill, "next_phase": phase})

    if rand_lab.get("static_token"):
        add("H-STATIC",
            "Session token har naye session me same rehta hai",
            "unique=%s / samples=%s" % (rand_lab.get("unique_tokens"), rand_lab.get("samples")),
            "Ek naya session 5 baar lo aur values compare karo; agar ek bhi value badli to REJECT.",
            "10-sessions")
    elif rand_lab.get("weak"):
        add("H-RAND",
            "Session token ka randomness kamzor hai (predictable positions)",
            ", ".join(rand_lab.get("problems") or []),
            "Kam se kam 20 samples lo aur per-position entropy dobara compute karo; "
            "agar saare positions >2.0 bits ho jayein to REJECT.",
            "10-sessions")
    for u, rec in (cookie_deep.get("per_endpoint") or {}).items():
        for c in rec.get("cookies", []):
            if c.get("from_jar"):
                continue
            if not c.get("httponly") and STATEFUL_COOKIE_RE.search(c.get("name", "")):
                add("H-HO-%s" % sha1(u + c.get("name", ""))[:4],
                    "%s ka cookie '%s' HttpOnly ke bina hai" % (u, c.get("name")),
                    "flag response header me nahi mila",
                    "Same endpoint ko dobara hit karo aur Set-Cookie line ka poora text dekho; "
                    "agar flag kabhi bhi present ho to REJECT.",
                    "10-sessions")
    if logout_res.get("ran") and logout_res.get("invalidated") is False:
        add("H-LOGOUT",
            "Logout server-side session invalidate nahi karta",
            logout_res.get("summary", ""),
            "Logout ke baad ek aur protected endpoint (different path) try karo; "
            "agar wahan 401/403 aa jaye to REJECT karo.",
            "10-sessions")
    if fixation_res.get("ran") and fixation_res.get("rotated") is False:
        add("H-FIX",
            "Login ke baad session id rotate nahi hoti (fixation)",
            fixation_res.get("summary", ""),
            "Do baar login karo alag pre-auth cookie ke saath; agar dusri baar rotate ho to REJECT.",
            "10-sessions")
    if binding_res.get("ran") and binding_res.get("bound") is False:
        add("H-BIND",
            "Session device/IP se bound nahi hai (replay aasan)",
            binding_res.get("summary", ""),
            "Original UA/IP se bhi probe bhejo; agar original context bhi reject ho jaye "
            "to binding claim REJECT karo.",
            "10-sessions")
    for t in (jwt_deep_res.get("tokens") or []):
        if t.get("attack_surface_flags"):
            add("H-JWT-%s" % sha1(str(t.get("endpoint")) + str(t.get("fingerprint")))[:4],
                "%s ka JWT surface: %s" % (t.get("endpoint"), ", ".join(t["attack_surface_flags"])),
                "alg=%s exp=%s iss=%s aud=%s" % (t.get("alg"), (t.get("claims") or {}).get("has_exp"),
                                                 (t.get("claims") or {}).get("iss"),
                                                 (t.get("claims") or {}).get("aud")),
                "Token ko protected endpoint par bhejo; agar reject ho to flags exploitable nahi -> REJECT.",
                "10-sessions")
    for h in (jwt_deep_res.get("weak_secret_hits") or []):
        add("H-WEAKSEC-%s" % sha1(str(h.get("endpoint")))[:4],
            "%s ka JWT HMAC secret weak hai (dictionary hit)" % h.get("endpoint"),
            "dictionary secret='%s' signature verify kar raha hai" % h.get("secret"),
            "Is secret se ek naya token sign karke protected endpoint par bhejo; "
            "agar accept na ho to REJECT (false positive dictionary hit).",
            "10-sessions")
    for u, tr in (tamper_res or {}).items():
        if tr.get("bypass"):
            add("H-TAMPER-%s" % sha1(u)[:4],
                "%s tampered JWT accept karta hai (%s)" % (u, tr.get("bypass_type")),
                tr.get("summary", ""),
                "Usi tampered token ko 3 baar bhejo; agar kabhi bhi reject ho (intermittent) "
                "to REJECT karo (cache/warm-up issue ho sakta hai).",
                "10-sessions")
    if leak_res.get("url_tokens"):
        add("H-URLTOK",
            "Token URL/query parameter me travel karta hai",
            "%d endpoint(s) me token URL me mila" % len(leak_res["url_tokens"]),
            "Us URL ko server logs / proxy / browser history me check karo; agar token "
            "har request me badalta ho to risk kam -> REJECT karo.",
            "10-sessions")
    for cr in leak_res.get("cache_risks") or []:
        add("H-CACHE-%s" % sha1(cr.get("endpoint", ""))[:4],
            "%s token wala response cacheable hai" % cr.get("endpoint"),
            cr.get("why", ""),
            "Ek proxy/middlebox ke through same URL dobara maango aur dekho token aata hai ya nahi; "
            "agar fresh token aaye to REJECT karo.",
            "10-sessions")
    # ---- ULTRA hypotheses ----
    cl = ultra.get("client_lab") or {}
    for c in cl.get("embedded_privilege_state")[:3]:
        add("H-EMBED-%s" % sha1(str(c.get("cookie")))[:4],
            "Cookie '%s' me base64-JSON privilege state hai (unsigned)" % c.get("cookie"),
            "decoded_keys=%s privilege_keys=%s" % (c.get("decoded_keys"), c.get("privilege_keys")),
            "Role value ko flip karke (sirf TEST account par) request bhejo; agar server accept "
            "kare to CONFIRM, reject kare to REJECT.",
            "11-idor-bola")
    for c in cl.get("marshal")[:2]:
        add("H-MARSHAL-%s" % sha1(str(c.get("cookie")))[:4],
            "Rails Marshal cookie session use ho rahi hai (%s)" % c.get("cookie"),
            "BAh7 prefix + base64 Marshal structure",
            "Secret-key leak surface check karo (git/secrets phase); agar secret strong hai "
            "to risk sirf tamper tak -> REJECT as critical.",
            "23-secrets")
    if cl.get("viewstate_endpoints"):
        add("H-VIEWSTATE",
            "ASP.NET ViewState surface mila",
            "endpoints: %s" % ", ".join(cl.get("viewstate_endpoints")[:3]),
            "ViewState MAC validation + viewStateUserKey (per-session) check karo; "
            "MAC enabled ho to REJECT.",
            "23-secrets")
    if (ultra.get("cache_deception") or {}).get("deception"):
        cd = ultra["cache_deception"]
        add("H-WCD",
            "Web Cache Deception surface: authenticated response cache ho rahi hai path-variant par",
            json.dumps(cd.get("variants") or [])[:200],
            "Cache key check karo (kya querystring/vary se alag hota hai); agar har variant "
            "fresh compute hota hai to REJECT.",
            "26-cache")
    if (ultra.get("conflict") or {}).get("duplicate_accepted"):
        cf = ultra["conflict"]
        add("H-TOSS",
            "Duplicate cookie names accept hote hain (%s)" % cf.get("cookie"),
            cf.get("summary", ""),
            "Alag-alag parser orders test karo (subdomain tossing ke liye Domain attribute "
            "bhi dekho); agar parser pehli value consistently le to REJECT.",
            "20-logic")
    if (ultra.get("refresh") or {}).get("rotated") is False:
        add("H-REFRESH",
            "Refresh token rotation nahi hota (old reuse)",
            ultra["refresh"].get("summary", ""),
            "Old token ko 3rd baar bhejo; agar ab reject ho (one-time grace) to severity "
            "Medium karo, warna CONFIRM High.",
            "10-sessions")
    if (ultra.get("concurrent") or {}).get("cap") == "none-detected":
        add("H-CONC",
            "Concurrent sessions par koi cap nahi",
            ultra["concurrent"].get("summary", ""),
            "Session management page se purane sessions revoke karne ka UI check karo; "
            "revoke possible hai to risk kam -> REJECT as Low-only.",
            "10-sessions")
    jm = ultra.get("jwt_matrix_v2") or {}
    if jm.get("bypass"):
        add("H-JWTv2-%s" % sha1(str(jm.get("bypass_type")))[:4],
            "JWT matrix v2 bypass: %s" % jm.get("bypass_type"),
            jm.get("summary", ""),
            "Tampered token ko dusre protected endpoint par bhejo; wahan bhi accept ho to "
            "CONFIRM Critical, warna endpoint-specific -> REJECT generic claim.",
            "10-sessions")
    for p in jm.get("probes") or []:
        if p.get("probe") == "logout-reuse" and p.get("accepted"):
            add("H-JWT-LOGOUT",
                "Logout ke baad JWT abhi bhi accepted hai",
                "status=%s (revocation missing)" % p.get("status"),
                "exp ke baad token dobara bhejo (expire hone do); expire ke baad bhi chale to "
                "token cache ho gaya hai - CONFIRM.",
                "10-sessions")
    return H


def write_session_test_plan(out, scope, H, F, coverage, stats_summary):
    L, A = [], None
    A = L.append
    A("# Phase 10 - Session & Token Security Test Plan")
    A("")
    A("**Engagement:** `%s`  " % scope.engagement)
    A("**Generated:** %s  " % now_iso())
    A("**Engine:** WASP v%s / sessions plan v%s (ULTRA PRO MAX)" % (VERSION, PLAN_VERSION))
    A("")
    A("> Har hypothesis ke saath **KILL TEST** diya gaya hai. Kill-test pass ho jaye to")
    A("> hypothesis REJECT karo - ye wahi falsification discipline hai jo exam me marks deti hai.")
    A("")
    A("---")
    A("")
    A("## 1. Findings")
    A("")
    if F.items:
        A("| ID | Severity | Title | Endpoint |")
        A("|---|---|---|---|")
        for f in F.items:
            A("| %s | **%s** | %s | `%s` |" % (f["id"], f["severity"], f["title"],
                                                urllib.parse.urlparse(f["endpoint"]).path or f["endpoint"]))
    else:
        A("_Koi session weakness confirm nahi hui (bounded probes ke saath)._")
    A("")
    A("## 2. Hypotheses + kill-tests")
    A("")
    for h in H:
        A("### %s" % h["id"])
        A("")
        A("- **HYPOTHESIS:** %s" % h["hypothesis"])
        A("- **BECAUSE:** %s" % h["because"])
        A("- **KILL TEST:** %s" % h["kill_test"])
        A("- **NEXT PHASE:** `%s`" % h["next_phase"])
        A("")
    A("## 3. Coverage matrix")
    A("")
    A("| Control | Status |")
    A("|---|---|")
    for k, v in coverage.items():
        A("| %s | %s |" % (k, v))
    A("")
    A("## 4. Statistical method")
    A("")
    A("| Test | Kya batata hai |")
    A("|---|---|")
    A("| Shannon entropy (overall) | token me kitni information hai |")
    A("| Per-position entropy | kaunse character positions predictable hain |")
    A("| Hamming distance (normalized) | tokens me collision/weak spread |")
    A("| Chi-square (uniformity) | character distribution biased hai ya nahi |")
    A("| NIST monobit | 0/1 bits balanced hain ya nahi |")
    A("| NIST runs | consecutive bit-runs random hain ya nahi |")
    A("| Serial correlation (lag-1) | ek bit agle bit ko predict karta hai kya |")
    A("| Birthday-bound entropy | sample se kitne random bits ka lower bound nikalta hai |")
    A("")
    if stats_summary:
        A("```")
        A(json.dumps(stats_summary, indent=2, default=str)[:2200])
        A("```")
    A("")
    A("## 5. Limitations (honesty section)")
    A("")
    A("- Token randomness tests **statistical indicators** hain, cryptographic proof nahi.")
    A("  Chhote sample (n<20) par entropy estimate ki uncertainty zyada hoti hai.")
    A("- Session fixation / logout invalidation / concurrent tests sirf **apne synthetic sessions**")
    A("  aur test credentials par chalte hain; kisi real user ka session touch nahi hota.")
    A("- JWT tamper matrix aur ULTRA live probes sirf GET endpoints par aur hard-capped hain.")
    A("- Weak-HMAC-secret check ek bounded dictionary hai (brute-force nahi).")
    A("- Binding test `X-Forwarded-For` bhejta hai; asli network-level IP binding sirf")
    A("  tab confirm hoti hai jab target us header ko trust kare.")
    A("- Cache deception probe sirf OWN session se surface-detect karta hai; victim data")
    A("  touch nahi hota. Actual cache behavior CDN ke config par depend karta hai.")
    A("- RS256->HS256 confusion craft public-key se hota hai; verification test ke liye")
    A("  payload me koi privilege escalation NAHI hoti (sirf exp extend).")
    A("")
    save_text(os.path.join(out, "session_test_plan.md"), "\n".join(L) + "\n")


# ---------------------------------------------------------------------------
# REPORTS
# ---------------------------------------------------------------------------
def _strip_raw(obj):
    """Internal `_raw`/`_rsa` fields ko report se hata do (evidence hygiene)."""
    if isinstance(obj, dict):
        return {k: _strip_raw(v) for k, v in obj.items()
                if not (str(k).startswith("_raw") or str(k).startswith("_rsa"))}
    if isinstance(obj, list):
        return [_strip_raw(v) for v in obj]
    return obj


def _sev_mix(F):
    mix = {}
    for f in F.items:
        mix[f["severity"]] = mix.get(f["severity"], 0) + 1
    return mix


def write_reports(out, scope, F, ctx):
    save_json(os.path.join(out, "findings.json"),
              {"engagement": scope.engagement, "phase": PHASE, "plan_version": PLAN_VERSION,
               "generated_at": now_iso(), "count": len(F.items), "findings": F.items})

    md = ["# Phase 10 - Session & Token Security Findings", "",
          "- **Engagement:** `%s`" % scope.engagement,
          "- **Generated:** `%s`" % now_iso(),
          "- **Engine:** WASP v%s / sessions plan v%s (ULTRA PRO MAX)" % (VERSION, PLAN_VERSION),
          "- **Endpoints inspected:** `%d`" % ctx.get("capture_count", 0),
          "- **Tokens analysed:** `%d`" % len(ctx.get("jwt_deep", {}).get("tokens") or []),
          "- **Findings:** `%d`" % len(F.items), ""]
    if not F.items:
        md.append("Is bounded, non-destructive run me koi session/token weakness **confirm** "
                  "nahi hui. Ise 'secure' mat samjho - `session_test_plan.md` ke hypotheses "
                  "manually verify karo.")
    else:
        md += ["| ID | Severity | Title | Endpoint |", "|---|---|---|---|"]
        for f in F.items:
            md.append("| %s | **%s** | %s | `%s` |" % (
                f["id"], f["severity"], f["title"],
                urllib.parse.urlparse(f["endpoint"]).path or f["endpoint"]))
        md.append("")
        for f in F.items:
            md += ["## %s - %s" % (f["id"], f["title"]), "",
                   "- **Severity:** %s (%s)" % (f["severity"], f["cvss_hint"]),
                   "- **Endpoint:** `%s`" % f["endpoint"],
                   "- **Detail:** %s" % f["detail"],
                   "- **Why it matters:** %s" % f["why_it_matters"],
                   "- **Evidence:** `%s`" % f["evidence"], ""]
    save_text(os.path.join(out, "SESSION_FINDINGS.md"), "\n".join(md) + "\n")

    write_session_test_plan(out, scope, ctx.get("hypotheses", []), F,
                            ctx.get("coverage", {}), ctx.get("stats_summary", {}))

    routing = {
        "to_phase11_idor": {
            "session_endpoints": sorted(ctx.get("captures", {}).keys())[:40],
            "token_cookies": sorted({c.get("name") for r in ctx.get("captures", {}).values()
                                     for c in (r.get("token_cookies") or [])}),
            "embedded_state_cookies": [c.get("cookie") for c in
                                       (ctx.get("client_lab", {}) or {}).get(
                                           "embedded_privilege_state", [])[:8]],
            "note": "IDOR ke liye do identities ka session chahiye - Phase 10 ne identity "
                    "model + token storage map diya hai"},
        "to_phase12_params": {
            "token_params": ["token", "access_token", "jwt", "api_key", "session", "sid"],
            "candidate_fields": sorted({s.get("key") for r in ctx.get("captures", {}).values()
                                        for s in (r.get("localstorage_hints") or [])})},
        "to_phase13_injection": {"token_endpoints": sorted(ctx.get("captures", {}).keys())[:30]},
        "to_phase14_xss": {
            "storage_hints": ctx.get("leak", {}).get("storage_hints", [])[:20],
            "client_side_session_cookies": [c.get("cookie") for c in
                                            (ctx.get("client_lab", {}) or {}).get(
                                                "client_side_signed", [])[:8]],
            "note": "localStorage me token ho to XSS ka impact Critical ban jata hai; "
                    "client-side session cookie XSS par readable ho to full ATO"},
        "to_phase15_ssrf": {
            "jku_x5u_urls": [t.get("jku") or t.get("x5u") for t in
                             (ctx.get("jwt_deep", {}).get("tokens") or [])
                             if t.get("jku") or t.get("x5u")]},
        "to_phase18_graphql": {"note": "GraphQL auth/session context Phase 7 se dekho"},
        "to_phase20_logic": {
            "logout_endpoints": ctx.get("logout", {}).get("logout_url"),
            "fixation_result": ctx.get("fixation", {}).get("summary"),
            "concurrent_cap": (ctx.get("concurrent", {}) or {}).get("cap"),
            "cookie_toss_surface": (ctx.get("conflict", {}) or {}).get("duplicate_accepted")},
        "to_phase23_secrets": {
            "weak_jwt_secrets": [h.get("secret") for h in
                                 (ctx.get("jwt_deep", {}).get("weak_secret_hits") or [])],
            "marshal_session_cookies": [c.get("cookie") for c in
                                        (ctx.get("client_lab", {}) or {}).get("marshal", [])],
            "note": "JWT secret mile to secrets phase me evidence ke saath record karo"},
        "to_phase26_cache": {
            "cache_deception_surface": (ctx.get("cache_deception", {}) or {}).get("deception", False),
            "wcd_variants": [v.get("url") for v in
                             (ctx.get("cache_deception", {}) or {}).get("variants", [])][:5],
            "cache_mixup_endpoints": [m.get("endpoint") for m in
                                      (ctx.get("hardening", {}) or {}).get("mixup", [])][:5],
            "note": "Phase 10 ne WCD + mixup surfaces de diye; Phase 26 me cache rules deep dive"},
        "to_phase32_report": {"findings": len(F.items), "severity_mix": _sev_mix(F),
                              "test_plan": "session_test_plan.md"},
    }
    ff = write_feedforward(out, PHASE, routing,
                           notes=["Bounded, non-destructive session testing.",
                                  "Session fixation/logout tests sirf synthetic sessions par.",
                                  "JWT tamper matrix GET-only aur hard-capped.",
                                  "Token randomness statistical indicators hain, cryptographic proof nahi.",
                                  "ULTRA: cache deception + refresh rotation + cookie conflict "
                                  "sab OWN session/test-account bounded."])
    files = ["session_endpoints.txt", "session_surface.json", "session_captures.json",
             "cookie_analysis.json", "token_randomness.json", "session_fixation.json",
             "session_lifecycle.json", "session_binding.json", "jwt_analysis.json",
             "jwt_tamper_matrix.json", "token_leakage.json", "session_flow_map.md",
             "SESSION_FINDINGS.md", "session_test_plan.md", "findings.json",
             "client_session_storage.json", "cache_deception.json", "cookie_conflict.json",
             "refresh_rotation.json", "concurrent_sessions.json", "jwt_matrix_v2.json",
             "session_hardening.json", "csrf_mapping.json", "ws_surface.json",
             "feedforward.json", "MANIFEST.json"]
    write_manifest(out, PHASE, files,
                   stats={"endpoints_inspected": ctx.get("capture_count", 0),
                          "tokens_analysed": len(ctx.get("jwt_deep", {}).get("tokens") or []),
                          "findings": len(F.items), "severity_mix": _sev_mix(F),
                          "hypotheses": len(ctx.get("hypotheses", [])),
                          "token_randomness_verdict": (ctx.get("rand_lab") or {}).get("verdict"),
                          "client_side_state": bool((ctx.get("client_lab") or {}).get(
                              "has_client_side_state")),
                          "cache_deception": bool((ctx.get("cache_deception") or {}).get(
                              "deception")),
                          "refresh_rotated": (ctx.get("refresh", {}) or {}).get("rotated")},
                   notes=["deterministic where possible; randomness tests fixed-order pure python",
                          "koi destructive operation nahi; logout/fixation sirf synthetic sessions par",
                          "ULTRA v10: 9 naye stages (L-T) + 4 bug fixes + read_only_post discipline"])
    return ff


# ---------------------------------------------------------------------------
# MAIN RUN
# ---------------------------------------------------------------------------
def _ensure_read_only_support(http):
    """v10 compat: read_only_post kwarg sirf naye ULTRA cores par supported hai.
    Purana wasp_core ho to kwarg drop hota hai (wahan POSTs pehle se allowed hain)
    - module dono cores par error-free chalta hai."""
    try:
        import inspect
        sig = inspect.signature(http.request)
        if "read_only_post" in sig.parameters:
            return http
    except Exception:
        return http
    orig = http.request

    def patched(method, url, **kw):
        kw.pop("read_only_post", None)
        return orig(method, url, **kw)

    http.request = patched
    return http


def run(cfg, scope, base_dir):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_dir, NAME)
    http = _ensure_read_only_support(http)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 10 - Session & Token Security (v%s) | %s" % (PLAN_VERSION, scope.describe()))
    # v10 SAFETY FIX: allow_active ab poora honor hota hai (stock me sirf warning thi)
    ACTIVE = bool(getattr(cfg, "allow_active", True))
    if not ACTIVE:
        warn("allow_active=False -> DISCOVERY + PASSIVE-ONLY mode: randomness/fixation/logout/"
             "binding/tamper/cache/conflict/refresh/concurrent/jwt-matrix sab skip honge.")

    F = Findings()
    ctx = {"captures": {}, "hypotheses": [], "coverage": {}, "stats_summary": {},
           "ultra": {}, "live": {}}
    ultra = ctx["ultra"]

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Session surface discovery")
    key = "stageA:discovery"
    if cp.is_done(key):
        ranked = cp.result_of(key) or []
        ok("Replayed %d candidates (checkpoint)" % len(ranked))
    else:
        ranked = discover_session_surface(base_dir, scope, out, conf)
        cp.mark(key, ranked, summary="session candidates")
    if not ranked:
        err("Koi session candidate nahi mila. Phase 6/7/9 pehle chalao ya scope.json check karo.")
        ctx["coverage"]["session surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx)
        return out
    ok("%d session candidates (priority order me)" % len(ranked))
    save_text(os.path.join(out, "session_endpoints.txt"),
              "\n".join("%-6s %-18s %s" % (r.get("priority"), r.get("source"), r["url"])
                        for r in ranked))
    src_counts = {}
    for r in ranked:
        src_counts[r.get("source")] = src_counts.get(r.get("source"), 0) + 1
    info("sources: %s" % ", ".join("%s=%d" % kv for kv in sorted(src_counts.items())))

    # ---------------- Stage B: capture ----------------
    head("Stage B - Identity & token capture (isolated sessions)")
    cap_eps = ranked[:int(conf.get("session_capture_endpoints", 8))]
    captures = {}
    for i, r in enumerate(cap_eps, 1):
        u = r["url"]
        ck = "capture:" + u
        if cp.is_done(ck):
            captures[u] = cp.result_of(ck) or {}
            continue
        rec = capture_session(http, u, identity_name="cap%d" % i, conf=conf)
        rec["source"] = r.get("source")
        rec["priority"] = r.get("priority")
        captures[u] = rec
        cp.mark(ck, rec, summary="capture")
        if rec.get("status"):
            ok("[%d/%d] %s -> %s cookies=%d body_tokens=%d" % (
                i, len(cap_eps), u, rec["status"], len(rec.get("cookies") or []),
                len(rec.get("tokens_in_body") or [])))
        else:
            warn("[%d/%d] %s -> %s" % (i, len(cap_eps), u, rec.get("error")))
    # v10 BUG-2 FIX: live sirf REAL responses (status < 400). Stock me 404/500 bhi
    # 'live' the -> buckets me dead URLs aage nikal jaate the + 404-page false positives.
    dead = [u for u, r in captures.items() if r.get("status") and r["status"] >= 400]
    live = {u: r for u, r in captures.items() if r.get("status") and r["status"] < 400}
    if dead:
        info("%d dead/error endpoints buckets se hata diye (status>=400)" % len(dead))
    ctx["captures"] = captures
    ctx["live"] = live
    ctx["capture_count"] = len(live)
    save_json(os.path.join(out, "session_surface.json"),
              {"ranked": ranked, "captures": captures})
    save_json(os.path.join(out, "session_captures.json"),
              {"captures": captures,
               "token_bearing": sorted([u for u, r in captures.items()
                                        if r.get("token_cookies") or r.get("tokens_in_body")]),
               "note": "har capture isolated identity (alag cookie jar) se liya gaya"})
    ok("%d/%d endpoints LIVE (status<400)" % (len(live), len(cap_eps)))

    # ---------------- Stage C: cookies ----------------
    head("Stage C - Cookie security deep-dive")
    cookie_deep = cookie_deep_dive(live)
    ctx["cookie_deep"] = cookie_deep
    for u, rec in (cookie_deep.get("per_endpoint") or {}).items():
        is_https = (live.get(u, {}).get("scheme") != "http")
        for c in rec.get("cookies", []):
            for fkey, ep, detail, extra in cookie_findings(c, u, is_https=is_https):
                F.add(fkey, COOKIE_FINDING_TITLES.get(fkey, "Cookie hygiene issue"),
                      ep, detail, evidence_ref="cookie_analysis.json", extra=extra)
    for name in (cookie_deep.get("aggregate") or {}).get("duplicate_names_global", []):
        F.add("session_duplicate_cookies", "Duplicate cookie names multiple endpoints par",
              ", ".join(sorted(cookie_deep.get("per_endpoint", {}).keys())[:3]),
              "cookie '%s' ek se zyada jagah set hui -> session tossing/fixation risk" % name,
              evidence_ref="cookie_analysis.json")
    for le in (cookie_deep.get("aggregate") or {}).get("low_entropy", []):
        F.add("session_token_low_entropy", "Session cookie value low-entropy",
              ", ".join(sorted(cookie_deep.get("per_endpoint", {}).keys())[:2]),
              "cookie '%s' len=%s entropy=%s" % (le.get("name"), le.get("len"), le.get("entropy")),
              evidence_ref="cookie_analysis.json")
    for u, r in live.items():
        if r.get("scheme") == "http" and (r.get("token_cookies") or r.get("set_cookie")):
            F.add("session_cleartext_transport", "Session cookie HTTP par set hui",
                  u, "Cookie plaintext network par jaayegi.", evidence_ref="session_captures.json")
        if r.get("debug_leak"):
            F.add("session_debug_leak", "Session endpoint debug/stack info leak karta hai",
                  u, "Response me debug signature mila.", evidence_ref="session_captures.json")
    save_json(os.path.join(out, "cookie_analysis.json"), cookie_deep)
    ok("cookies analysed: %d endpoint(s), %d finding(s)" % (
        len(cookie_deep.get("per_endpoint") or {}), len(F.items)))

    # common targets (stock jaisa hi selection, ek jagah)
    token_url = None
    for u, r in live.items():
        if r.get("token_cookies"):
            token_url = u
            break
    token_url = token_url or (list(live.keys())[0] if live else None)
    check_url = None
    for u, r in live.items():
        if u == token_url:
            continue
        if r.get("status") in (200, 302, 401, 403) and not LOGOUT_RE.search(
                urllib.parse.urlparse(u).path):
            check_url = u
            break

    # ---------------- Stage D: token randomness lab ----------------
    head("Stage D - Token randomness lab (entropy / Hamming / NIST-lite)")
    rand_lab = {}
    if not ACTIVE:
        info("passive mode -> randomness sampling skip (N isolated requests hoti)")
    elif live:
        target = token_url or list(live.keys())[0]
        ck = "randomness:" + target
        if cp.is_done(ck):
            rand_lab = cp.result_of(ck) or {}
        else:
            rand_lab = session_token_randomness(http, target, conf)
            rand_lab["endpoint"] = target
            cp.mark(ck, rand_lab, summary="randomness lab")
        ctx["rand_lab"] = rand_lab
        ok("samples=%s unique=%s verdict=%s" % (
            rand_lab.get("samples"), rand_lab.get("unique_tokens"), rand_lab.get("verdict")))
    else:
        info("koi live endpoint nahi -> randomness skip")
    # findings derivation resume-safe (checkpoint replay par bhi chalega)
    if rand_lab:
        if rand_lab.get("static_token"):
            F.add("session_token_static", "Session token har session me identical",
                  rand_lab.get("endpoint") or token_url or "-", json.dumps(
                      {k: rand_lab.get(k) for k in ("samples", "unique_tokens", "verdict")},
                      default=str),
                  evidence_ref="token_randomness.json")
        elif rand_lab.get("weak"):
            F.add("session_token_low_entropy", "Session token randomness kamzor",
                  rand_lab.get("endpoint") or token_url or "-",
                  ", ".join(rand_lab.get("problems") or []),
                  evidence_ref="token_randomness.json")
    save_json(os.path.join(out, "token_randomness.json"), rand_lab)

    # ---------------- Stage E: fixation ----------------
    head("Stage E - Session fixation check")
    fixation = {}
    creds_list = conf.get("session_test_credentials") or []
    creds = creds_list[0] if creds_list else None
    login_url = None
    for u in live:
        if re.search(r"(?i)(login|signin|session|token)", urllib.parse.urlparse(u).path):
            login_url = u
            break
    if not ACTIVE:
        fixation = {"ran": False, "summary": "skip: passive mode (allow_active=False)"}
        info(fixation["summary"])
    elif login_url and creds:
        ck = "fixation:" + login_url
        if cp.is_done(ck):
            fixation = cp.result_of(ck) or {}
        else:
            fixation = session_fixation_test(http, scope, login_url, creds, conf)
            cp.mark(ck, fixation, summary="fixation")
    else:
        fixation = {"ran": False,
                    "summary": "skip: test credentials nahi diye (session_test_credentials) "
                               "ya login endpoint nahi mila"}
        info(fixation["summary"])
    # derivation resume-safe
    if fixation.get("rotated") is False:
        F.add("session_fixation", "Session fixation (login par id rotate nahi hui)",
              login_url or "-", fixation.get("summary", ""), evidence_ref="session_fixation.json")
    ctx["fixation"] = fixation
    save_json(os.path.join(out, "session_fixation.json"), fixation)

    # ---------------- Stage F: lifecycle ----------------
    head("Stage F - Session lifecycle (logout / expiry / rotation)")
    lifecycle = lifecycle_inference(live, cookie_deep)
    logout_url = None
    for u in list(live.keys()) + [r["url"] for r in ranked]:
        if LOGOUT_RE.search(urllib.parse.urlparse(u).path):
            logout_url = u
            break
    logout_res = {}
    if not ACTIVE:
        logout_res = {"ran": False, "summary": "skip: passive mode (allow_active=False)"}
        info(logout_res["summary"])
    elif logout_url and token_url and check_url:
        ck = "logout:" + logout_url
        if cp.is_done(ck):
            logout_res = cp.result_of(ck) or {}
        else:
            logout_res = logout_invalidation_test(http, scope, logout_url, token_url,
                                                  check_url, conf)
            cp.mark(ck, logout_res, summary="logout")
    else:
        logout_res = {"ran": False,
                      "summary": "skip: logout endpoint, token endpoint ya alag check page nahi mila"}
        info(logout_res["summary"])
    # derivation resume-safe
    if logout_res.get("ran") and logout_res.get("invalidated") is False:
        F.add("session_no_logout_invalidation",
              "Logout server-side session invalidate nahi karta", logout_url or "-",
              logout_res.get("summary", ""), evidence_ref="session_lifecycle.json")
    ctx["logout"] = logout_res
    ctx["lifecycle"] = lifecycle
    for name, models in (lifecycle.get("expiry_model") or {}).items():
        if any("session-scoped" in m for m in models):
            F.add("session_no_idle_timeout", "Session cookie ka koi explicit expiry nahi",
                  ", ".join(list(live.keys())[:2]) or "-",
                  "cookie '%s' -> %s" % (name, ", ".join(models)),
                  evidence_ref="session_lifecycle.json")
    save_json(os.path.join(out, "session_lifecycle.json"),
              {"lifecycle": lifecycle, "logout": logout_res})

    # ---------------- Stage G: binding ----------------
    head("Stage G - Session binding (hijack resistance)")
    binding = {}
    bind_url = token_url or (list(live.keys())[0] if live else None)
    if not ACTIVE:
        binding = {"ran": False, "summary": "skip: passive mode (allow_active=False)"}
        info(binding["summary"])
    elif bind_url:
        ck = "binding:" + bind_url
        if cp.is_done(ck):
            binding = cp.result_of(ck) or {}
        else:
            binding = session_binding_test(http, scope, bind_url, conf)
            cp.mark(ck, binding, summary="binding")
    else:
        binding = {"ran": False, "summary": "skip: koi live endpoint nahi"}
    # derivation resume-safe
    if binding.get("ran") and binding.get("bound") is False:
        F.add("session_not_bound", "Session device/IP se bound nahi (replay aasan)",
              bind_url or "-", binding.get("summary", ""), evidence_ref="session_binding.json")
    ctx["binding"] = binding
    save_json(os.path.join(out, "session_binding.json"), binding)

    # ---------------- Stage H: JWT deep ----------------
    head("Stage H - JWT deep analysis (+ JWKS + weak-HMAC-secret)")
    tokens = []
    for u, r in live.items():
        for t in (r.get("tokens_in_body") or []):
            tokens.append((t, u))
        for c in (r.get("token_cookies") or []):
            v = c.get("value") or ""
            if v.startswith("eyJ") and v.count(".") >= 2:
                tokens.append((v, u))
    jwks_urls = [u for u in list(live.keys()) +
                 [r["url"] for r in ranked] if re.search(r"(?i)(jwks|openid-configuration)", u)]
    # ULTRA v10 FIX: ranked cap (capture_endpoints*3) JWKS paths kaat deta hai
    # (well-known list me jwks deep hota hai) -> standard JWKS paths explicitly
    # scope-check karke add karo, warna RSA material kabhi nahi milta.
    for _o in _authorized_origins(scope)[:2]:
        for _p in ("/jwks.json", "/.well-known/jwks.json", "/oauth/jwks",
                   "/.well-known/openid-configuration"):
            _u = _o.rstrip("/") + _p
            if _u not in jwks_urls and scope.check_url(_u, raise_on_fail=False):
                jwks_urls.append(_u)
    ck = "jwt:deep"
    if cp.is_done(ck):
        jwt_deep_res = cp.result_of(ck) or {}
    else:
        jwt_deep_res = jwt_deep_analysis(http, scope, tokens, jwks_urls, conf)
        cp.mark(ck, jwt_deep_res, summary="jwt deep")
    ctx["jwt_deep"] = jwt_deep_res
    ok(jwt_deep_res.get("summary", ""))
    # ULTRA: confusion craft ke liye JWKS se RSA material cache karo (public keys)
    _rsa_material = None
    for _u, _j in (jwt_deep_res.get("jwks") or {}).items():
        if isinstance(_j, dict) and _j.get("_rsa"):
            _rsa_material = _j["_rsa"]
            break
    # findings derivation resume-safe (stock me yahan already outside tha)
    for t in jwt_deep_res.get("tokens") or []:
        flags = t.get("attack_surface_flags") or []
        claims = t.get("claims") or {}
        ep = t.get("endpoint")
        if t.get("alg") in ("none", "None", "NONE"):
            F.add("jwt_alg_none_accepted", "JWT alg=none ke saath issue hua", ep,
                  "alg=%s" % t.get("alg"), evidence_ref="jwt_analysis.json")
        if not claims.get("has_exp"):
            F.add("jwt_no_expiry", "JWT me expiry claim nahi", ep,
                  "payload_keys=%s" % ",".join(t.get("payload_keys") or []),
                  evidence_ref="jwt_analysis.json")
        elif isinstance(claims.get("lifetime_s"), (int, float)) and claims["lifetime_s"] > 86400 * 7:
            F.add("jwt_long_expiry", "JWT ki expiry bahut lambi hai", ep,
                  "lifetime=%ss" % claims.get("lifetime_s"), evidence_ref="jwt_analysis.json")
        if t.get("jku") or t.get("x5u"):
            F.add("jwt_jku_x5u_external", "JWT header external key URL (jku/x5u) use karta hai",
                  ep, "jku=%s x5u=%s" % (t.get("jku"), t.get("x5u")),
                  evidence_ref="jwt_analysis.json")
        if t.get("kid") and "kid-injection-pattern" in flags:
            F.add("jwt_kid_injection", "JWT kid header me injection pattern",
                  ep, "kid=%s" % t.get("kid"), evidence_ref="jwt_analysis.json")
        if claims.get("privilege_claims"):
            F.add("jwt_sensitive_claims", "JWT payload me privilege claims plaintext",
                  ep, "claims=%s" % ",".join(claims["privilege_claims"]),
                  evidence_ref="jwt_analysis.json")
        if claims.get("pii_claims"):
            F.add("jwt_pii_in_payload", "JWT payload me PII plaintext",
                  ep, "claims=%s" % ",".join(claims["pii_claims"]),
                  evidence_ref="jwt_analysis.json")
        if not claims.get("has_iss") or not claims.get("has_aud"):
            F.add("jwt_missing_iss_aud", "JWT me iss/aud claim missing",
                  ep, "iss=%s aud=%s" % (claims.get("iss"), claims.get("aud")),
                  evidence_ref="jwt_analysis.json")
        if t.get("alg") and str(t.get("alg")).startswith("RS") and (t.get("header") or {}).get("jwk"):
            F.add("jwt_alg_confusion", "JWT header me embedded JWK (alg confusion surface)",
                  ep, "alg=%s" % t.get("alg"), evidence_ref="jwt_analysis.json")
        # ULTRA: duplicate claims surface
        dc = t.get("duplicate_claims") or {}
        if dc.get("surface"):
            F.add("jwt_duplicate_claims", "JWT me duplicate claims (parser discrepancy surface)",
                  ep, "payload_dups=%s header_dups=%s" % (
                      dc.get("duplicate_payload_claims"), dc.get("duplicate_header_claims")),
                  evidence_ref="jwt_analysis.json")
    for h in jwt_deep_res.get("weak_secret_hits") or []:
        F.add("jwt_weak_hmac_secret", "JWT HMAC secret weak dictionary me mila",
              h.get("endpoint"), "alg=%s secret='%s'" % (h.get("alg"), h.get("secret")),
              evidence_ref="jwt_analysis.json")
    for u, j in (jwt_deep_res.get("jwks") or {}).items():
        for wk in j.get("weak_keys") or []:
            F.add("jwks_weak_key", "JWKS me kamzor/leaked key",
                  u, "kid=%s kty=%s bits~%s (%s)" % (wk.get("kid"), wk.get("kty"),
                                                     wk.get("bits_approx"), wk.get("why")),
                  evidence_ref="jwt_analysis.json")
        if j.get("no_kid"):
            F.add("jwks_no_kid", "JWKS keys me kid nahi", u,
                  "%d key(s) bina kid" % j["no_kid"], evidence_ref="jwt_analysis.json")
    save_json(os.path.join(out, "jwt_analysis.json"), _strip_raw(jwt_deep_res))

    # ---------------- Stage I: tamper matrix ----------------
    head("Stage I - JWT tamper matrix (gated, GET-only, bounded)")
    tamper_res = {}
    prot_cache = {}          # ULTRA: baseline probes cache (Stage Q reuse karega)
    tamper_target = None
    if not ACTIVE:
        info("tamper matrix skip (passive mode)")
    elif conf.get("session_jwt_tamper_max", 3) > 0 and jwt_deep_res.get("tokens"):
        # Tamper target ek PROTECTED endpoint hona chahiye (baseline 401/403).
        # Token jahan se mila wo issue point hai - wahan tamper ka matlab nahi.
        tok = (jwt_deep_res["tokens"][0] or {}).get("_raw") or ""
        if not tok:
            for t, _ep in tokens:
                tok = t
                break
        cand_eps = []
        for u in list(live.keys()) + [r["url"] for r in ranked]:
            if u in cand_eps:
                continue
            cand_eps.append(u)
        for u in cand_eps[:12]:
            if u not in prot_cache:
                prot_cache[u] = _protected_probe(http, u)
            if prot_cache[u].get("protected"):
                tamper_target = u
                break
        if tamper_target and tok:
            ck = "tamper:" + tamper_target
            if cp.is_done(ck):
                tamper_res[tamper_target] = cp.result_of(ck)
            else:
                tr = jwt_tamper_matrix(http, scope, tamper_target, tok, conf)
                tamper_res[tamper_target] = tr
                cp.mark(ck, tr, summary="jwt tamper")
        elif not tamper_target:
            info("tamper matrix skip: koi protected endpoint (401/403) nahi mila")
        else:
            info("tamper matrix skip: koi JWT token nahi mila")
    else:
        info("tamper matrix skip (config off ya JWT nahi mila)")
    # v10 BUG-3 FIX: findings derivation ab replay path par bhi (else ke andar nahi)
    for u, tr in tamper_res.items():
        if tr.get("bypass"):
            if tr.get("bypass_type") in ("alg-none-empty-sig", "alg-None-camel",
                                         "signature-stripped"):
                F.add("jwt_alg_none_accepted", "Tampered/unsigned JWT accept hua",
                      u, tr.get("summary", ""), evidence_ref="jwt_tamper_matrix.json")
            else:
                F.add("jwt_signature_not_verified", "Tampered JWT payload accept hua",
                      u, tr.get("summary", ""), evidence_ref="jwt_tamper_matrix.json")
    ctx["tamper"] = tamper_res
    save_json(os.path.join(out, "jwt_tamper_matrix.json"), tamper_res)

    # ---------------- ULTRA Stage L: client-side session storage lab ----------------
    head("Stage L (ULTRA) - Client-side session storage lab (0 requests)")
    all_stateful_cookies = []
    for u, r in live.items():
        for c in (r.get("cookies") or []):
            if STATEFUL_COOKIE_RE.search(c.get("name", "")) and c.get("value"):
                all_stateful_cookies.append(c)
    client_lab = client_session_storage_lab(all_stateful_cookies, {}) \
        if conf.get("session_client_storage_decode", True) else {"summary": "config off"}
    ultra["client_lab"] = client_lab
    ok(client_lab.get("summary", ""))
    for c in client_lab.get("embedded_privilege_state") or []:
        F.add("cookie_embedded_privilege_state",
              "Cookie me plaintext/base64 privilege state (unsigned)", 
              ", ".join(list(live.keys())[:2]) or "-",
              "cookie '%s' decoded_keys=%s privilege_keys=%s" % (
                  c.get("cookie"), c.get("decoded_keys"), c.get("privilege_keys")),
              evidence_ref="client_session_storage.json")
    for c in client_lab.get("marshal") or []:
        F.add("client_side_marshal_session", "Rails Marshal cookie session (deserialization surface)",
              ", ".join(list(live.keys())[:2]) or "-",
              "cookie '%s' -> %s" % (c.get("cookie"), c.get("kind")),
              evidence_ref="client_session_storage.json")
    for c in client_lab.get("client_side_signed") or []:
        F.add("client_side_session_storage", "Signed client-side session cookie (itsdangerous-style)",
              ", ".join(list(live.keys())[:2]) or "-",
              "cookie '%s' -> %s" % (c.get("cookie"), c.get("kind")),
              evidence_ref="client_session_storage.json")
    if client_lab.get("viewstate_endpoints"):
        F.add("viewstate_surface", "ASP.NET ViewState surface",
              ", ".join(client_lab["viewstate_endpoints"][:2]),
              "ViewState input/body signature mila - MAC validation manually verify karo",
              evidence_ref="client_session_storage.json")
    save_json(os.path.join(out, "client_session_storage.json"), client_lab)

    # ---------------- ULTRA Stage M: cache deception probe ----------------
    head("Stage M (ULTRA) - Web cache deception & mix-up surface (own session)")
    cache_dec = {}
    if not ACTIVE:
        cache_dec = {"ran": False, "summary": "skip: passive mode"}
        info(cache_dec["summary"])
    elif not conf.get("session_allow_cache_probe", True):
        cache_dec = {"ran": False, "summary": "skip: session_allow_cache_probe=false"}
        info(cache_dec["summary"])
    elif token_url:
        ck = "wcd:" + token_url
        if cp.is_done(ck):
            cache_dec = cp.result_of(ck) or {}
        else:
            cache_dec = cache_deception_probe(http, token_url, conf)
            cp.mark(ck, cache_dec, summary="cache deception")
    else:
        cache_dec = {"ran": False, "summary": "skip: koi token endpoint nahi"}
        info(cache_dec["summary"])
    ultra["cache_deception"] = cache_dec
    ok(cache_dec.get("summary", ""))
    if cache_dec.get("deception"):
        F.add("cache_deception_surface", "Web Cache Deception surface (own session se verify)",
              token_url or "-",
              "variants=%s" % json.dumps(cache_dec.get("variants") or [], default=str)[:300],
              evidence_ref="cache_deception.json")
    save_json(os.path.join(out, "cache_deception.json"), cache_dec)

    # ---------------- ULTRA Stage N: cookie conflict / toss ----------------
    head("Stage N (ULTRA) - Cookie conflict / tossing parser probe (own values)")
    conflict = {}
    if not ACTIVE:
        conflict = {"ran": False, "summary": "skip: passive mode"}
        info(conflict["summary"])
    elif not conf.get("session_allow_conflict_probe", True):
        conflict = {"ran": False, "summary": "skip: session_allow_conflict_probe=false"}
        info(conflict["summary"])
    elif token_url:
        conf_cookie = None
        for c in (live.get(token_url, {}).get("cookies") or []):
            if STATEFUL_COOKIE_RE.search(c.get("name", "")) and c.get("value"):
                conf_cookie = c
                break
        if conf_cookie:
            ck = "conflict:%s:%s" % (token_url, conf_cookie["name"])
            if cp.is_done(ck):
                conflict = cp.result_of(ck) or {}
            else:
                conflict = cookie_conflict_probe(http, token_url, conf_cookie["name"],
                                                 conf_cookie["value"], conf)
                cp.mark(ck, conflict, summary="cookie conflict")
        else:
            conflict = {"ran": False, "summary": "skip: stateful cookie value nahi mili"}
            info(conflict["summary"])
    else:
        conflict = {"ran": False, "summary": "skip: koi token endpoint nahi"}
        info(conflict["summary"])
    ultra["conflict"] = conflict
    ok(conflict.get("summary", ""))
    if conflict.get("duplicate_accepted"):
        F.add("cookie_parser_duplicate_accepted",
              "Duplicate cookie name parser ne accept kiya (tossing pre-condition)",
              token_url or "-", conflict.get("summary", ""),
              evidence_ref="cookie_conflict.json")
    save_json(os.path.join(out, "cookie_conflict.json"), conflict)

    # ---------------- ULTRA Stage O: refresh token rotation ----------------
    head("Stage O (ULTRA) - Refresh token rotation check (own token)")
    refresh = {}
    refresh_url = None
    for u in list(live.keys()) + [r["url"] for r in ranked]:
        if REFRESH_PATH_RE.search(urllib.parse.urlparse(u).path):
            refresh_url = u
            break
    if not ACTIVE:
        refresh = {"ran": False, "summary": "skip: passive mode"}
        info(refresh["summary"])
    elif not conf.get("session_allow_refresh_test", True):
        refresh = {"ran": False, "summary": "skip: session_allow_refresh_test=false"}
        info(refresh["summary"])
    elif not refresh_url:
        refresh = {"ran": False, "summary": "skip: refresh endpoint nahi mila"}
        info(refresh["summary"])
    else:
        # refresh token source: cookie named refresh* -> token_url body JSON
        refresh_token = None
        for u, r in live.items():
            for c in (r.get("cookies") or []):
                if re.search(r"(?i)refresh", c.get("name", "")) and c.get("value"):
                    refresh_token = c["value"]
                    break
            if refresh_token:
                break
        if not refresh_token and token_url:
            ck = "refreshcap:" + token_url
            if cp.is_done(ck):
                cap = cp.result_of(ck) or {}
            else:
                cap_ident = http.identity("refreshcap")
                cap_r = cap_ident.request("GET", token_url, allow_redirects=True)
                cap = {"status": cap_r.status, "body": (cap_r.text or "")[:4000]}
                cp.mark(ck, cap, summary="refresh capture")
            m = re.search(r'"refresh[_-]?token"\s*:\s*"([^"]{8,})"', cap.get("body") or "")
            if m:
                refresh_token = m.group(1)
        if refresh_token:
            ck = "refresh:" + refresh_url
            if cp.is_done(ck):
                refresh = cp.result_of(ck) or {}
            else:
                refresh = refresh_rotation_test(http, refresh_url, refresh_token, conf)
                cp.mark(ck, refresh, summary="refresh rotation")
        else:
            refresh = {"ran": False, "summary": "skip: refresh token capture nahi hua "
                                                "(cookie/JSON body me nahi mila)"}
            info(refresh["summary"])
    ultra["refresh"] = refresh
    ok(refresh.get("summary", ""))
    if refresh.get("rotated") is False:
        F.add("refresh_no_rotation", "Refresh token rotate nahi hota (old reuse)",
              refresh_url or "-", refresh.get("summary", ""),
              evidence_ref="refresh_rotation.json")
    save_json(os.path.join(out, "refresh_rotation.json"), refresh)

    # ---------------- ULTRA Stage P: concurrent session cap ----------------
    head("Stage P (ULTRA) - Concurrent session cap (test credentials)")
    concurrent = {}
    if not ACTIVE:
        concurrent = {"ran": False, "summary": "skip: passive mode"}
        info(concurrent["summary"])
    elif not conf.get("session_allow_concurrent_test", True):
        concurrent = {"ran": False, "summary": "skip: session_allow_concurrent_test=false"}
        info(concurrent["summary"])
    elif login_url and creds and check_url:
        ck = "concurrent:%s" % login_url
        if cp.is_done(ck):
            concurrent = cp.result_of(ck) or {}
        else:
            concurrent = concurrent_session_test(http, scope, login_url, check_url, creds, conf)
            cp.mark(ck, concurrent, summary="concurrent cap")
    else:
        concurrent = {"ran": False, "summary": "skip: login/check endpoint ya test credentials "
                                               "nahi (session_test_credentials)"}
        info(concurrent["summary"])
    ultra["concurrent"] = concurrent
    ok(concurrent.get("summary", ""))
    if concurrent.get("cap") == "none-detected":
        F.add("session_concurrent_unlimited",
              "Concurrent session cap nahi (dono sessions valid)",
              check_url or login_url or "-", concurrent.get("summary", ""),
              evidence_ref="concurrent_sessions.json")
    save_json(os.path.join(out, "concurrent_sessions.json"), concurrent)

    # ---------------- ULTRA Stage Q: JWT attack matrix v2 ----------------
    head("Stage Q (ULTRA) - JWT attack matrix v2 (confusion / jwk-inject / logout-reuse)")
    jwt_v2 = {}
    q_target = tamper_target
    if not ACTIVE:
        jwt_v2 = {"attempted": False, "summary": "skip: passive mode"}
        info(jwt_v2["summary"])
    elif not conf.get("session_allow_jwt_matrix", True):
        jwt_v2 = {"attempted": False, "summary": "skip: session_allow_jwt_matrix=false"}
        info(jwt_v2["summary"])
    elif not jwt_deep_res.get("tokens"):
        jwt_v2 = {"attempted": False, "summary": "skip: koi JWT capture nahi hua"}
        info(jwt_v2["summary"])
    else:
        if not q_target:
            cand_eps = list(live.keys()) + [r["url"] for r in ranked]
            for u in cand_eps[:12]:
                if u in prot_cache and prot_cache[u].get("protected"):
                    q_target = u
                    break
                if u not in prot_cache:
                    prot_cache[u] = _protected_probe(http, u)
                    if prot_cache[u].get("protected"):
                        q_target = u
                        break
        if q_target:
            ck = "jwtv2:" + q_target
            if cp.is_done(ck):
                jwt_v2 = cp.result_of(ck) or {}
            else:
                first_tok = (jwt_deep_res["tokens"][0] or {}).get("_raw") or \
                            (tokens[0][0] if tokens else "")
                jwt_v2 = jwt_attack_matrix_v2(http, scope, q_target, first_tok, conf,
                                              logout_res=logout_res,
                                              rsa_material=_rsa_material)
                cp.mark(ck, jwt_v2, summary="jwt matrix v2")
        else:
            jwt_v2 = {"attempted": False, "summary": "skip: koi protected endpoint (401/403) "
                                                     "nahi mila"}
            info(jwt_v2["summary"])
    ultra["jwt_matrix_v2"] = jwt_v2
    ok(jwt_v2.get("summary", "") or "offline-only")
    for p in jwt_v2.get("probes") or []:
        if p.get("accepted"):
            if p.get("probe") == "rs256-hs256-confusion":
                F.add("jwt_alg_confusion_accepted", "RS256->HS256 confusion token ACCEPT hua",
                      q_target or "-", "public key HMAC secret bana kar sign kiya; baseline "
                      "401/403 tha", evidence_ref="jwt_matrix_v2.json")
            elif p.get("probe") == "jwk-header-injection":
                F.add("jwt_jwk_injection_accepted", "Header jwk embedded-key token ACCEPT hua",
                      q_target or "-", "apni oct key header me embed karke sign kiya; baseline "
                      "401/403 tha", evidence_ref="jwt_matrix_v2.json")
            elif p.get("probe") == "logout-reuse":
                F.add("jwt_logout_reuse", "Logout ke baad JWT abhi bhi accepted",
                      q_target or "-", p.get("note") or "revocation missing",
                      evidence_ref="jwt_matrix_v2.json")
    if jwt_v2.get("bypass") and jwt_v2.get("bypass_type") not in (
            "rs256-hs256-confusion", "jwk-header-injection", "logout-reuse"):
        F.add("jwt_signature_not_verified", "JWT matrix v2 bypass (%s)" % jwt_v2.get("bypass_type"),
              q_target or "-", jwt_v2.get("summary", ""), evidence_ref="jwt_matrix_v2.json")
    save_json(os.path.join(out, "jwt_matrix_v2.json"),
              {k: v for k, v in jwt_v2.items() if not str(k).startswith("_")})

    # ---------------- ULTRA Stage R: session page hardening ----------------
    head("Stage R (ULTRA) - Session page hardening (passive, 0 requests)")
    hardening = session_hardening_passive(live)
    ultra["hardening"] = hardening
    ok(hardening.get("summary", ""))
    for hj in hardening.get("clickjacking")[:3]:
        F.add("session_page_clickjacking", "Token page clickjacking-protected nahi",
              hj.get("endpoint"), "X-Frame-Options aur CSP frame-ancestors dono missing",
              evidence_ref="session_hardening.json")
    for hm in hardening.get("hsts_missing")[:2]:
        F.add("session_hsts_missing", "HTTPS session page par HSTS missing",
              hm.get("endpoint"), "Strict-Transport-Security header nahi mila",
              evidence_ref="session_hardening.json")
    for hr in hardening.get("referrer_weak")[:2]:
        F.add("session_referrer_leak_surface", "Token page par weak referrer-policy",
              hr.get("endpoint"), "referrer-policy=%s" % hr.get("referrer_policy"),
              evidence_ref="session_hardening.json")
    for hm2 in hardening.get("mixup")[:2]:
        F.add("session_cache_mixup_surface", "Cacheable session response + Vary: UA missing",
              hm2.get("endpoint"), "Cache-Control=%s Vary=%s + CDN hints" % (
                  hm2.get("cache_control"), hm2.get("vary")),
              evidence_ref="session_hardening.json")
    save_json(os.path.join(out, "session_hardening.json"), hardening)

    # ---------------- ULTRA Stage S: CSRF defense mapping ----------------
    head("Stage S (ULTRA) - CSRF defense mapping (passive)")
    csrf_map = csrf_defense_mapping(live, cookie_deep, base_dir, scope.engagement)
    ultra["csrf_map"] = csrf_map
    ok(csrf_map.get("summary", ""))
    if csrf_map.get("weak"):
        F.add("csrf_defense_weak", "CSRF defense weak (tokenless forms + SameSite missing)",
              ", ".join(sorted(live.keys())[:2]) or "-",
              "forms_without_csrf=%d samesite_missing=%d" % (
                  len(csrf_map.get("forms_without_csrf") or []),
                  len(csrf_map.get("samesite_missing_cookies") or [])),
              evidence_ref="csrf_mapping.json")
    save_json(os.path.join(out, "csrf_mapping.json"), csrf_map)

    # ---------------- ULTRA Stage T: websocket session surface ----------------
    head("Stage T (ULTRA) - WebSocket session surface (passive)")
    has_tok_cookies = bool(token_url)
    ws = ws_session_surface(base_dir, scope.engagement, has_tok_cookies)
    ultra["ws"] = ws
    ok(ws.get("summary", ""))
    if ws.get("hint"):
        F.add("ws_session_model_unknown", "WebSocket session model verify karna",
              ws.get("ws_endpoints", ["-"])[0] if ws.get("ws_endpoints") else "-",
              ws.get("hint"), evidence_ref="ws_surface.json")
    save_json(os.path.join(out, "ws_surface.json"), ws)

    # ---------------- Stage J: leakage ----------------
    head("Stage J - Token leakage channels")
    leak = token_leakage_analysis(live, base_dir, scope.engagement)
    ctx["leak"] = leak
    ultra["leak"] = leak
    ok(leak.get("summary", ""))
    for ut in leak.get("url_tokens") or []:
        F.add("token_in_url", "Token URL/query parameter me travel karta hai",
              ut.get("endpoint"), ut.get("why", ""), evidence_ref="token_leakage.json")
    for bt in leak.get("body_tokens") or []:
        F.add("token_in_response_body", "Token response body me expose hota hai",
              bt.get("endpoint"), "token fingerprint=%s len=%s" % (bt.get("fingerprint"), bt.get("len")),
              evidence_ref="token_leakage.json")
    for sh in leak.get("storage_hints") or []:
        F.add("token_localstorage_hint", "Client JS token storage me rakhta hai",
              sh.get("endpoint"), "%s.%s('%s')" % (sh.get("storage"), sh.get("op"), sh.get("key")),
              evidence_ref="token_leakage.json")
    for cr in leak.get("cache_risks") or []:
        F.add("session_no_idle_timeout", "Token wala response cacheable hai",
              cr.get("endpoint"), "%s (Cache-Control=%s)" % (cr.get("why"), cr.get("cache_control")),
              evidence_ref="token_leakage.json")
    save_json(os.path.join(out, "token_leakage.json"), leak)

    # ---------------- Stage K: flow map + reports ----------------
    head("Stage K - Session flow map, hypotheses & reports")
    sm = build_session_flow_map(live, cookie_deep, lifecycle, logout_res, fixation,
                                binding, jwt_deep_res, leak, scope, ultra)
    save_text(os.path.join(out, "session_flow_map.md"), sm)

    hypotheses = build_hypotheses(F, rand_lab, cookie_deep, lifecycle, logout_res, fixation,
                                  binding, jwt_deep_res, tamper_res, leak, ultra)
    ctx["hypotheses"] = hypotheses
    ctx["stats_summary"] = {
        "token_randomness": {k: rand_lab.get(k) for k in
                             ("samples", "unique_tokens", "verdict", "problems",
                              "overall_entropy_per_char", "min_token_entropy",
                              "per_position_entropy", "low_entropy_positions",
                              "hamming", "chi_square", "monobit", "runs",
                              "serial_correlation", "birthday") if k in rand_lab},
        "ultra_stage_results": {
            "client_side_state": (ultra.get("client_lab") or {}).get("summary"),
            "cache_deception": (ultra.get("cache_deception") or {}).get("summary"),
            "cookie_conflict": (ultra.get("conflict") or {}).get("summary"),
            "refresh_rotation": (ultra.get("refresh") or {}).get("summary"),
            "concurrent_cap": (ultra.get("concurrent") or {}).get("cap"),
            "jwt_matrix_v2": (ultra.get("jwt_matrix_v2") or {}).get("summary"),
            "hardening": (ultra.get("hardening") or {}).get("summary"),
            "csrf_mapping": (ultra.get("csrf_map") or {}).get("summary"),
            "ws_surface": (ultra.get("ws") or {}).get("summary"),
        },
    }

    def mark(cond, yes, no):
        return yes if cond else no
    ctx["coverage"] = {
        "session surface discovery": mark(bool(ranked), "%d endpoints" % len(ranked), "none"),
        "token capture (isolated identities)": mark(bool(live), "%d endpoint(s)" % len(live), "none"),
        "cookie hardening (flags)": mark(bool(cookie_deep.get("per_endpoint")),
                                         "%d endpoint(s)" % len(cookie_deep.get("per_endpoint") or {}),
                                         "cookie nahi mili"),
        "cookie prefix rules (__Host-/__Secure-)": mark(
            bool(cookie_deep.get("per_endpoint")), "check hua", "cookie nahi mili"),
        "duplicate cookie / tossing": mark(
            bool((cookie_deep.get("aggregate") or {}).get("duplicate_names_global")),
            "duplicates mile", "duplicates nahi mile"),
        "token randomness lab": mark(bool(rand_lab), rand_lab.get("verdict", "chala"), "token nahi mila"),
        "session fixation": mark(bool(fixation.get("ran")),
                                 fixation.get("summary", ""), "credentials nahi diye / skip"),
        "logout invalidation": mark(bool(logout_res.get("ran")),
                                    logout_res.get("summary", ""), "logout endpoint nahi mila"),
        "idle/absolute timeout inference": mark(bool(lifecycle.get("expiry_model")),
                                                "%d cookie model(s)" % len(lifecycle.get("expiry_model") or {}),
                                                "cookie nahi mili"),
        "session binding (IP/UA replay)": mark(bool(binding.get("ran")),
                                               binding.get("summary", ""), "skip"),
        "JWT deep analysis": mark(bool(jwt_deep_res.get("tokens")),
                                  "%d token(s)" % len(jwt_deep_res.get("tokens") or []),
                                  "JWT nahi mila"),
        "JWKS key strength": mark(bool(jwt_deep_res.get("jwks")),
                                  "%d doc(s)" % len(jwt_deep_res.get("jwks") or {}), "JWKS nahi mila"),
        "weak HMAC secret (bounded dict)": mark(bool(jwt_deep_res.get("tokens")),
                                                "chala", "JWT nahi mila"),
        "JWT tamper matrix": mark(bool(tamper_res), "chala", "skip"),
        "token leakage channels": mark(bool(ctx.get("leak")), (ctx.get("leak") or {}).get("summary", ""), "none"),
        "cleartext transport": mark(any(r.get("scheme") == "http" and (r.get("set_cookie") or [])
                                        for r in live.values()), "HTTP token mila", "sab HTTPS"),
        # ---- ULTRA coverage ----
        "client-side session storage lab": mark(
            bool((ultra.get("client_lab") or {}).get("summary")),
            (ultra.get("client_lab") or {}).get("summary", ""), "skip"),
        "cache deception probe (own session)": mark(
            bool((ultra.get("cache_deception") or {}).get("ran")),
            (ultra.get("cache_deception") or {}).get("summary", ""), "skip"),
        "cookie conflict / toss probe": mark(
            bool((ultra.get("conflict") or {}).get("ran")),
            (ultra.get("conflict") or {}).get("summary", ""), "skip"),
        "refresh token rotation": mark(
            bool((ultra.get("refresh") or {}).get("ran")),
            (ultra.get("refresh") or {}).get("summary", ""), "skip"),
        "concurrent session cap": mark(
            bool((ultra.get("concurrent") or {}).get("ran")),
            (ultra.get("concurrent") or {}).get("summary", ""), "skip"),
        "JWT attack matrix v2": mark(
            bool((ultra.get("jwt_matrix_v2") or {}).get("attempted")),
            (ultra.get("jwt_matrix_v2") or {}).get("summary", ""), "skip"),
        "session page hardening (passive)": mark(
            bool((ultra.get("hardening") or {}).get("analyzed")),
            "%d page(s) analyzed" % (ultra.get("hardening") or {}).get("analyzed", 0), "no headers"),
        "CSRF defense mapping": mark(
            bool((ultra.get("csrf_map") or {}).get("summary")),
            (ultra.get("csrf_map") or {}).get("summary", ""), "no forms"),
        "websocket session surface": mark(
            bool((ultra.get("ws") or {}).get("summary")),
            (ultra.get("ws") or {}).get("summary", ""), "no ws"),
        "passive-only mode": mark(not ACTIVE, "haan (allow_active=False)", "nahi (full mode)"),
    }
    write_reports(out, scope, F, ctx)

    dt = time.time() - t_start
    head("Phase 10 complete in %.1fs" % dt)
    ok("Findings=%d | hypotheses=%d | endpoints=%d | JWT=%d" % (
        len(F.items), len(hypotheses), len(live), len(jwt_deep_res.get("tokens") or [])))
    info("READ FIRST: SESSION_FINDINGS.md -> session_test_plan.md -> session_flow_map.md")
    return out
