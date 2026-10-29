#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_client.py  |  Phase 14 - Client-Side Attack Surface
                     (CSRF / CORS / Framing / postMessage / OAuth-state / storage chains)
=======================================================================================
v14.0.0 ULTRA ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se inherit
hote hain, isliye har request scope-check, rate-limit aur budget ke andar hi
jaati hai.

KYA KARTA HAI
  Phase 13 poochta tha: "browser DATA ko MARKUP/SCRIPT samajh raha hai?" (XSS).
  Phase 14 poochta hai: "DUSRA WEBSITE (attacker origin) mere users ke browser
  me jo pehle se chal raha hai uske against kya kar sakta hai?" -> yani
  cross-origin trust boundary ki poori family:
    * CSRF      - state-change par token/SameSite/Origin defense ka audit
    * CORS      - Access-Control-* ka origin-validation audit (READ-only probes)
    * Framing   - clickjacking (X-Frame-Options / CSP frame-ancestors)
    * postMessage - cross-document messaging ka origin validation
    * OAuth     - state/PKCE/response_type audit (login-CSRF family)
    * Storage   - localStorage/sessionStorage/cookie token exposure -> ATO chain
  FUNDAMENTAL DISCIPLINE (P12/P13 handoff): blind scanner NAHI. P10 csrf_mapping
  + P9 auth_cors + P7 postmessage/storage/dom + P13 feedforward (to_phase14_client)
  + P2 forms + P4 security_headers = seed list. Wahan targeted, evidence-backed
  probes.

STAGES (A-N)
  A  Client surface discovery ...... P10 csrf_mapping/cookie_analysis/session_
                                     hardening/client_session_storage/ws_surface
                                     + P9 auth_cors/auth_endpoints/auth_redirect
                                     + P7 postmessage/dom_analysis/storage_tokens
                                     /endpoints/websockets + P13 feedforward
                                     (dom_confirmed/ripe_reflections) + P13
                                     csp_analysis/header_reflect + P4 security
                                     headers + P2 forms + P8 priority queue +
                                     P11 idor endpoints + cold-start form
                                     harvest -> evidence-ranked targets
  B  Baseline & calibration ........ per-endpoint 2x GET baseline (status/len/
                                     sha1/timing) + soft-404 baseline + security
                                     header snapshot (XFO/CSP/ACAO/SameSite) ->
                                     hardened-vs-vulnerable pre-map
  C  CSRF token census ............. 30+ token name patterns x 5 sources (form
                                     hidden/meta/cookie/JS-global/header) +
                                     shannon entropy + login-CSRF check +
                                     GET-logout detector + token-in-GET leak
  D  CSRF defense matrix ........... RoE-GATED live replay (csrf_allow_replay,
                                     default OFF; ON hone par bhi SIRF low-risk
                                     fields par apne session se waspP14 canary)
                                     + token-less/blank/garbage 3-probe ladder +
                                     Origin-strip + SameSite audit (None-no-
                                     Secure / missing / __Host- prefix) +
                                     JSON-CSRF (text/plain) analysis + Referer/
                                     Origin validation regex-bypass hypotheses +
                                     PoC HTML generator (inert, manual-submit)
  E  CORS misconfig matrix ......... 12 origin variants (arbitrary .invalid /
                                     null / suffix / concat / case / underscore /
                                     %2e / path / sub / dot-chain / double-suffix
                                     / mixed) - SIRF GET/OPTIONS, reserved TLDs,
                                     ZERO external egress + ACAO/ACAC pair
                                     verdicts + preflight OPTIONS matrix (ACAM/
                                     ACAH/ACSA) + expose-headers + Vary: Origin
                                     (cache chain) + legacy crossdomain.xml /
                                     clientaccesspolicy.xml
  F  Clickjacking & framing ........ XFO missing/invalid/deprecated-ALLOW-FROM +
                                     CSP frame-ancestors missing/'*'/http: +
                                     state-change pages priority + framing PoC
                                     HTML (inert iframe, manual note)
  G  postMessage trust boundary .... addEventListener("message") listeners ka
                                     origin-validation audit (exact-match regex
                                     vs prefix/starts-vs-endsWith bug) + sink-in-
                                     listener (innerHTML/location/eval -> P13
                                     DOM chain) + sender targetOrigin '*' +
                                     sandbox allow-scripts+allow-same-origin
  H  Storage & token exposure ...... localStorage/sessionStorage/cookie tokens
                                     (P7 storage_tokens + P10 client_session_
                                     storage + fresh page JS) -> XSS->ATO chain
                                     narratives (impact sirf likha jaata hai,
                                     execute KABHI nahi) + HttpOnly correlation
                                     + cookie domain-too-broad tossing pre-req
  I  OAuth & advanced techniques ... OAuth authorize links: state missing /
                                     response_type=token (implicit) / PKCE
                                     missing / redirect_uri looseness + 18
                                     technique matrix (double-submit flaw,
                                     referer-regex-bypass, host-header CSRF,
                                     samesite-lax navigations, null-origin CORS,
                                     subdomain-takeover CORS chain, double-frame,
                                     pm-prefix-origin-bypass, ws-no-origin-check,
                                     cookie-tossing, TT/COOP/COEP census...)
  J  Chains & hypotheses ........... CSRF+SameSite+framing ATO chain, CORS+
                                     storage cross-origin ATO, postMessage+DOM
                                     sink one-click chain, OAuth+fixation ->
                                     ranked kill-chains + feedforward (P15/P17/
                                     P18/P19/P20/P23/P26/P32)
  K  Reports ....................... 24+ output files: client_surface.json,
                                     csrf_matrix.json, cors_matrix.json,
                                     framing_matrix.json, postmessage_audit_v14
                                     .json, storage_chains.json, oauth_state_
                                     audit.json, csrf_poc/*.html, framing_poc/
                                     *.html, cors_probe_log.json, technique_
                                     matrix_client.json, CLIENT_FINDINGS.md,
                                     client_test_plan.md, client_chains.txt,
                                     TECHNIQUES_CATALOG_CLIENT.md, cwe_owasp_map
                                     _client.json, findings.json, feedforward
                                     .json, MANIFEST.json

VERDICT ENGINE (P12/P13-compatible multi-signal, false-positive kam)
  CONFIRMED   -> deterministic header/protocol proof (ACAO+ACAC echo, XFO+CSP
                 dono missing, token-less accepted) - reproduce-able
  SUSPECTED   -> partial defense / single signal / passive-only inference
  HARDENED    -> defense PROPERLY present (token validated, XFO DENY, ACAO nahi)
  BLOCKED     -> WAF/probe-level block (finding nahi, fingerprint input)
  NOISE       -> baseline unstable - verdict nahi

SAFETY VALVES
  * allow_active=True zaroori probes ke liye (warna discovery + offline
    hypotheses only - 0 network probes).
  * DETECTION-ONLY hard rule: koi destructive write, koi exfil, koi real
    attack HTML, koi auto-submitting form. PoC files INERT hain (manual
    submit + RoE note ke saath) aur sirf apne lab me khulne ke liye.
  * csrf_allow_replay default False (RoE gate) - ON hone par bhi SIRF low-risk
    fields (bio/about/comment/description...) par apne identity se, canary
    value "waspP14" family, sensitive fields (password/email/role/delete/pay)
    par replay SKIP -> hypothesis-only.
  * CORS probes sirf GET/OPTIONS - Origin values reserved TLDs (.invalid) me
    hi; koi external request kisi real attacker-host ko nahi jaati.
  * Koi WebSocket handshake probe default OFF (client_ws_handshake gate).
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Evidence/details me PII REDACT hota hai (email/phone/JWT masked).
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
"""

import os
import re
import sys
import json
import time
import html
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
                           info, ok, warn, err, head, C, VERSION, now_human,
                           human_size)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 14")
    sys.exit(1)

NAME = "client"
PHASE = "14-client"
PLAN_VERSION = "14.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "client_csrf_form_cap": 60,        # kitne state-change forms census me
    "client_cors_endpoints": 14,       # CORS probe endpoint cap
    "client_cors_origin_cap": 12,      # origin variants cap per endpoint
    "client_frame_pages": 20,          # framing audit page cap
    "client_pm_fetch": 4,              # fresh JS fetch cap (postMessage audit)
    "client_get_crawl": 30,            # cold-start crawl request cap
    "client_replay_budget": 8,         # gated CSRF replay budget (RoE ON par)
    "csrf_allow_replay": False,        # RoE GATE: live token-less replay
    "client_probe_crossdomain": True,  # legacy crossdomain.xml / clientaccesspolicy
    "client_ws_handshake": False,      # RoE GATE: cross-origin WS handshake check
    "client_preflight": True,          # OPTIONS preflight probes
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
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    return _rwx_result(path)


def _rwx_save_text(path, text):
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
# SEVERITY CLASSIFICATION (P12/P13 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- CORS ----
    "cors_credentials_reflected":   ("high", 8.1, "Attacker origin se credentials-"
        "carry karke victim ka data padh sakta hai (cross-origin ATO ka direct "
        "rasta) - ACAO echo + ACAC true deterministic proof hai."),
    "cors_suffix_match_bypass":     ("high", 8.1, "Origin validation prefix/suffix "
        "match karta hai - attacker subdomain (ya takeover-able subdomain) se "
        "credentialed read possible."),
    "cors_null_origin_allowed":     ("high", 7.4, "null origin sandboxed iframe se "
        "credentialed cross-origin read possible hai."),
    "cors_origin_reflection":       ("medium", 6.5, "ACAO kisi bhi origin ko echo "
        "karta hai (ACAC false) - creds ke bina bhi public-data exfil aur "
        "defense-in-depth gap."),
    "cors_wildcard_creds_violation": ("low", 3.7, "ACAO:* + ACAC:true spec-violation "
        "- browsers reject karte hain par config bug ka signal hai."),
    "cors_preflight_dangerous":     ("medium", 6.5, "Preflight arbitrary headers/"
        "methods allow karta hai - cross-origin write surface."),
    "cors_legacy_crossdomain":      ("low", 3.1, "Legacy crossdomain.xml wildcard - "
        "purane Flash/Silverlight clients ke liye full trust."),
    # ---- CSRF ----
    "csrf_no_token_state_change":   ("high", 8.0, "State-change request me CSRF token "
        "hi nahi - attacker-origin form se user ki session me write force ho sakta hai."),
    "csrf_token_not_validated":     ("critical", 9.0, "Token bheja hi nahi to request "
        "ACCEPT ho gayi (live differential proof) - full CSRF."),
    "csrf_reuse_across_sessions":   ("medium", 6.0, "Token per-session fixed pattern - "
        "leak-once-use-forever class."),
    "csrf_token_in_get":            ("medium", 5.4, "Token GET URL me - Referer/log/"
        "history leak -> token compromise chain."),
    "csrf_login":                   ("medium", 5.4, "Login form par token nahi - "
        "login-CSRF se attacker apna session victim par thop sakta hai."),
    "csrf_logout_get":              ("low", 3.1, "GET-based logout - annoying CSRF "
        "(availability), oob state change nahi."),
    "csrf_samesite_none_insecure":  ("medium", 6.0, "SameSite=None bina Secure - "
        "cross-site request me cookie jaati hai (CSRF defense absent)."),
    "csrf_samesite_missing":        ("low", 3.5, "SameSite attribute missing - modern "
        "browsers Lax default lagate hain par purane browsers me CSRF open."),
    "csrf_json_textplain_accept":   ("medium", 6.0, "JSON endpoint text/plain body "
        "parse karta hai (hypothesis) - preflight-free cross-site write."),
    "csrf_origin_validation_weak":  ("medium", 5.8, "Origin/Referer validation prefix/"
        "suffix regex - bypass-friendly (analysis)."),
    # ---- framing ----
    "framing_no_protection":        ("medium", 6.2, "XFO + CSP frame-ancestors dono "
        "missing - clickjacking possible (UI-redress state-change)."),
    "framing_xfo_deprecated":       ("low", 3.3, "X-Frame-Options: ALLOW-FROM deprecated "
        "- modern browsers ignore karte hain (framing effectively open)."),
    "framing_csp_ancestors_weak":   ("low", 3.5, "frame-ancestors wildcard/scheme-source "
        "- partial protection."),
    # ---- postMessage ----
    "pm_no_origin_check":           ("medium", 6.1, "message listener origin validate "
        "nahi karta - koi bhi window sensitive data bhej/hila sakta hai."),
    "pm_prefix_origin_match":       ("medium", 5.8, "Origin check startsWith/endsWith - "
        "attacker-controlled prefix/suffix domain bypass."),
    "pm_sink_in_listener":          ("high", 8.0, "Listener message data ko DOM sink "
        "(innerHTML/location) me daalta hai - one-click DOM XSS chain."),
    "pm_wildcard_target":           ("low", 3.4, "postMessage(targetOrigin '*') - "
        "sensitive data kisi bhi parent/child ko leak."),
    # ---- storage / oauth / ws ----
    "storage_token_in_localstorage": ("medium", 5.9, "Session/JWT token localStorage me "
        "- kisi bhi XSS ka impact full-ATO ban jaata hai (HttpOnly bypass)."),
    "storage_cookie_tossing_prereq": ("low", 3.2, "Cookie domain attribute too broad - "
        "subdomain cookie-tossing pre-req."),
    "oauth_state_missing":          ("high", 7.2, "OAuth authorize par state param nahi "
        "- login-CSRF / authorization-code injection (session fixation family)."),
    "oauth_implicit_flow":          ("medium", 5.6, "response_type=token (implicit) - "
        "token URL-fragment me, history/Referer leak surface."),
    "oauth_pkce_missing":           ("low", 3.6, "PKCE (code_challenge) nahi - code "
        "interception chain (custom-scheme/public client)."),
    "ws_cross_origin_unchecked":    ("medium", 5.9, "WebSocket handshake Origin validate "
        "nahi karta (hypothesis) - cross-site WebSocket hijacking."),
    "defense_census_missing":       ("info", 0.0, "Modern defense headers (COOP/COEP/"
        "CORP/Trusted-Types) absent - defense-in-depth gap."),
    "client_surface_sparse":        ("info", 0.0, "Seed artifacts kam mile - deeper "
        "discovery recommended."),
    "client_replay_skipped_sensitive": ("info", 0.0, "Sensitive field par live replay "
        "RoE ke under skip hua - hypothesis-only verdict."),
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0, "Client-side surface signal."))
    return sev, cvss, why


# ---------------------------------------------------------------------------
# PII REDACT (framework rule)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    return truncate(s, limit)


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "CLI-%03d" % (len(self.items) + 1), "key": key, "title": title,
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


# ===========================================================================
# STAGE A - CLIENT SURFACE DISCOVERY (evidence-first, P10/P9/P7/P13/P4/P2/P8/P11)
# ===========================================================================
# Seed priority (evidence weight):
#   1.0  P10 csrf_mapping.json        (forms_without_csrf / samesite)
#   0.9  P13 feedforward to_phase14   (dom_confirmed / ripe_reflections)
#   0.9  P9 auth_cors.json            (CORS-probed endpoints)
#   0.8  P10 session_hardening.json   (clickjacking pages)
#   0.8  P2 forms.json                (POST forms = state-change census)
#   0.7  P7 postmessage/dom/storage   (client trust boundary)
#   0.6  P9 auth_endpoints / P11 idor (state-change endpoints w/ sessions)
#   0.5  P4 security_headers.txt      (XFO/CSP missing hosts)
#   0.4  P7 endpoints/JS-mined POST   (api surface)
#   0.3  cold-start crawl             (fallback: scope seeds se form harvest)
# ===========================================================================

# state-change keyword families (path/field names) - csrf target scoring
SC_STRONG = re.compile(
    r"(?i)(password|passwd|pwd|email|e-mail|role|admin|delete|remove|destroy|"
    r"transfer|payment|pay|withdraw|deposit|checkout|order|invoice|invite|"
    r"2fa|mfa|otp|totp|toggle|disable|enable|revoke|reset|approve|deny|grant|"
    r"permission|apikey|api_key|api-key|token|logout|signout|deactivate|"
    r"subscribe|unsubscribe|follow|block|ban|unban|verify|confirm|activate|"
    r"settings|preference|profile_update|update_profile|changepass|close_account)")
SC_MEDIUM = re.compile(
    r"(?i)(update|create|add|edit|save|submit|post|import|assign|move|share|"
    r"publish|rename|merge|flag|report|vote|like|comment|upload|attach|bind|"
    r"link|connect|sync|export)")
LOW_RISK_FIELDS = re.compile(
    r"(?i)^(bio|about|comment|description|nickname|display_name|displayname|"
    r"signature|status|message|note|title|tagline|website|url|location|"
    r"interests|motto|summary)$")
SENSITIVE_FIELDS = re.compile(
    r"(?i)(password|passwd|pwd|email|phone|role|admin|balance|amount|price|"
    r"pay|card|ssn|2fa|mfa|otp|secret|token|apikey|api_key|permission|"
    r"old_|new_|current_|confirm_)")

# CSRF token field-name patterns (30+) - framework + vendor naming
CSRF_TOKEN_NAMES = re.compile(
    r"(?i)^(csrf|csrf_token|csrftoken|_csrf|_csrf_token|csrfmiddlewaretoken|"
    r"authenticity_token|__requestverificationtoken|__antiforgerytoken|"
    r"antiforgerytoken|_antiforgery_token|antiforgery|xsrf|xsrf_token|xsrf-"
    r"token|_xsrf|x-xsrf-token|_token|token|_formtoken|formtoken|form_token|"
    r"nonce|_nonce|wp_nonce|_wpnonce|_wp_http_referer|anticsrf|anti-csrf|"
    r"csrfnonce|_csrfnonce|rtoken|requesttoken|request_token|pagestate|"
    r"__viewstate|__eventvalidation|geetest_csrf|yii_csrf|_yii2csrf|"
    r"spring_csrf|_synchronizertoken|org\.apache\.struts\..*token|"
    r"owaspcsrfguard.*|jqcsrf|_jqcsrf|csrf_field|_token_field)$")
CSRF_COOKIE_NAMES = re.compile(
    r"(?i)^(XSRF-TOKEN|XSRF|CSRF-TOKEN|csrftoken|csrf_token|_csrf|_csrfCookie|"
    r"ANTICSRF|ASPXSRF|CAKEPHP|LARAVEL_SESSION.*|XSRF_stub)$")
CSRF_HEADER_NAMES = ("x-csrf-token", "x-xsrf-token", "x-csrf", "x-xsrf",
                     "csrf-token", "x-anticsrf", "x-requested-token")

# API-like URL shapes (CORS targets)
API_LIKE = re.compile(
    r"(?i)(/api/|/api\.|/v[0-9]+/|/rest/|/graphql|\.json($|\?)|/service/|"
    r"/ajax/|/data/|/gateway/|/rpc/|/openapi|/swagger|/internal/|/me($|/)|"
    r"/account($|/)|/user($|/)|/profile($|/)|/settings($|/))")
OAUTH_LIKE = re.compile(
    r"(?i)(oauth|authorize|openid|oidc|connect/token|signin-oidc|/auth\?|"
    r"client_id|response_type|redirect_uri|grant_type|/sso/|/login/oauth)")
WS_LIKE = re.compile(r"(?i)^(wss?://)")
SENSITIVE_PAGE = re.compile(
    r"(?i)(password|email|settings|profile|account|wallet|billing|payment|"
    r"checkout|admin|role|permission|2fa|mfa|security|token|apikey|privacy|"
    r"transfer|invite|member|manage)")

TOKEN_VALUE_HINT = re.compile(r"^[A-Za-z0-9_\-]{16,}={0,2}$")


def _read_json_tolerant(path):
    d = load_json(path, default=None)
    return d


def _mod_dir(base_dir, mod):
    return os.path.join(base_dir, mod)


def _artifact(base_dir, mod, fname):
    """Tolerant artifact reader: missing file -> None (kabhi crash nahi)."""
    p = os.path.join(base_dir, mod, fname)
    if not os.path.isfile(p):
        return None
    if fname.endswith(".json"):
        return _read_json_tolerant(p)
    try:
        with open(p, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def _iter_records(d):
    """JSON artifact -> iterable of dict records (dict{list}/list/dict-of-dicts)."""
    if isinstance(d, list):
        for x in d:
            if isinstance(x, dict):
                yield x
    elif isinstance(d, dict):
        for v in d.values():
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, dict):
                        yield x
            elif isinstance(v, dict):
                yield v


def _url_from_rec(rec, prefer=("url", "endpoint", "action", "target", "href", "page")):
    for k in prefer:
        v = rec.get(k)
        if isinstance(v, str) and v.startswith(("http", "/", "wss://", "ws://")):
            return v
    return ""


def _parse_forms(html_text, base_url):
    """HTML -> form dicts [{action, method, fields:[{name,type,value}], token}].
    Regex-based tolerant parser (bs4 optional nahi hai framework me)."""
    forms = []
    if not html_text:
        return forms
    for fm in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", html_text):
        attrs, inner = fm.group(1), fm.group(2)
        am = re.search(r"action\s*=\s*[\"']?([^\"'>\s]+)", attrs, re.I)
        mm = re.search(r"method\s*=\s*[\"']?([^\"'>\s]+)", attrs, re.I)
        action = urljoin_safe(base_url, am.group(1) if am else base_url)
        method = (mm.group(1) if mm else "GET").upper()
        fields, has_token = [], False
        for im in re.finditer(r"(?is)<input\b([^>]*)/?>", inner):
            ia = im.group(1)
            nm = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", ia, re.I)
            ty = re.search(r"type\s*=\s*[\"']([^\"']+)[\"']", ia, re.I)
            vl = re.search(r"value\s*=\s*[\"']([^\"']*)[\"']", ia, re.I)
            name = nm.group(1) if nm else ""
            ftype = (ty.group(1) if ty else "text").lower()
            if not name:
                continue
            if CSRF_TOKEN_NAMES.match(name) and ftype in ("hidden", "text", ""):
                has_token = True
            fields.append({"name": name, "type": ftype,
                           "value": (vl.group(1) if vl else "")[:120]})
        for sm in re.finditer(r"(?is)<select\b[^>]*name\s*=\s*[\"']([^\"']+)[\"']", inner):
            fields.append({"name": sm.group(1), "type": "select", "value": ""})
        for tm in re.finditer(r"(?is)<textarea\b[^>]*name\s*=\s*[\"']([^\"']+)[\"']", inner):
            fields.append({"name": tm.group(1), "type": "textarea", "value": ""})
        forms.append({"action": action, "method": method, "fields": fields,
                      "has_token": has_token, "source": "html-form"})
    return forms


def urljoin_safe(base, rel):
    try:
        return urllib.parse.urljoin(base, rel or "")
    except Exception:
        return rel or ""


def _state_change_score(method, url, fields):
    """0-10 state-change likelihood: method + path keywords + field names."""
    sc = 0.0
    m = (method or "GET").upper()
    if m in ("POST", "PUT", "PATCH", "DELETE"):
        sc += 4.0
    elif m == "GET" and (SC_STRONG.search(url) or "logout" in url.lower()):
        sc += 3.0
    path_q = url.split("?")[0]
    if SC_STRONG.search(path_q):
        sc += 3.0
    elif SC_MEDIUM.search(path_q):
        sc += 1.5
    fld_names = " ".join((f.get("name") or "") for f in (fields or []))
    if SC_STRONG.search(fld_names):
        sc += 2.0
    elif SC_MEDIUM.search(fld_names):
        sc += 1.0
    if re.search(r"(?i)(id=|/users?/|/accounts?/|/orders?/)", url):
        sc += 0.5
    return min(sc, 10.0)


def _api_like(url):
    return bool(API_LIKE.search(url)) or url.rstrip("/").endswith(".json")


def discover_client_surface(base_dir, scope, conf):
    """Stage A: sab seed artifacts mine karo -> ranked client targets.
    Returns (ranked, meta). Har target: url/kind/method/fields/score/source."""
    base_dir = os.path.join(base_dir, scope.engagement)   # engagement root
    engagement = scope.engagement
    seeds = scope.seed_urls() or []
    base_urls = []
    for s in seeds:
        try:
            sp = urllib.parse.urlsplit(s)
            if sp.scheme and sp.netloc:
                base_urls.append("%s://%s" % (sp.scheme, sp.netloc))
        except Exception:
            continue
    base_url = base_urls[0] if base_urls else ""

    targets = {}          # (kind, url) -> rec
    mined = {"sources": [], "counts": {}}

    def push(kind, url, score, method="GET", fields=None, source="", extra=None):
        if not url or not isinstance(url, str) or len(url) > 600:
            return
        url = url.split("#")[0]
        key = (kind, url)
        rec = {"kind": kind, "url": url, "score": round(score, 2),
               "method": (method or "GET").upper(),
               "fields": fields or [], "source": source}
        if extra:
            rec.update(extra)
        old = targets.get(key)
        if old is None or rec["score"] > old["score"]:
            targets[key] = rec

    # ---------- 1. P10 csrf_mapping.json (highest evidence) ----------
    cm = _artifact(base_dir, "sessions", "csrf_mapping.json")
    if cm is not None:
        mined["sources"].append("sessions/csrf_mapping.json")
        weak = cm.get("weak") if isinstance(cm, dict) else None
        for rec in _iter_records(cm):
            u = _url_from_rec(rec)
            if not u:
                continue
            sc = 9.0 if weak else 8.0
            if rec.get("forms_without_csrf"):
                sc += 0.5
            push("csrf", u, sc, source="P10:csrf_mapping",
                 extra={"hint": rec.get("hint", "")})
        for k in ("forms_without_csrf", "samesite_missing_cookies"):
            v = cm.get(k) if isinstance(cm, dict) else None
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, dict):
                        u = _url_from_rec(x)
                        if u:
                            push("csrf", u, 9.0, source="P10:csrf_mapping.%s" % k)
                    elif isinstance(x, str) and x.startswith("http"):
                        push("csrf", x, 9.0, source="P10:csrf_mapping.%s" % k)
        # samesite cookies -> storage/cookie chain pre-req
        for c in (cm.get("samesite_missing_cookies") or []):
            if isinstance(c, dict) and c.get("name"):
                mined.setdefault("samesite_cookies", []).append(c)

    # ---------- 2. P13 feedforward to_phase14_client ----------
    ff = _artifact(base_dir, "xss", "feedforward.json")
    ff14 = (ff or {}).get("routing", {}).get("to_phase14_client") if isinstance(ff, dict) else None
    if ff14:
        mined["sources"].append("xss/feedforward.json:to_phase14_client")
        for rec in (ff14.get("dom_confirmed") or []):
            if isinstance(rec, dict):
                u = _url_from_rec(rec)
                if u:
                    push("pm", u, 8.8, source="P13:dom_confirmed",
                         extra={"sink": rec.get("sink", "")})
        for rec in (ff14.get("ripe_reflections") or []):
            if isinstance(rec, dict):
                u = _url_from_rec(rec)
                if u:
                    push("csrf", u, 7.5, source="P13:ripe_reflection",
                         extra={"param": rec.get("param", "")})

    # ---------- 3. P9 auth_cors.json ----------
    ac = _artifact(base_dir, "auth", "auth_cors.json")
    if ac is not None:
        mined["sources"].append("auth/auth_cors.json")
        for rec in _iter_records(ac):
            u = _url_from_rec(rec)
            if u and _api_like(u):
                push("cors", u.split("?")[0], 8.5, source="P9:auth_cors",
                     extra={"prior": rec.get("summary", "")[:160]})

    # ---------- 4. P10 session_hardening.json (clickjacking pages) ----------
    sh = _artifact(base_dir, "sessions", "session_hardening.json")
    if sh and isinstance(sh, dict):
        mined["sources"].append("sessions/session_hardening.json")
        for rec in (sh.get("clickjacking") or []):
            if isinstance(rec, dict):
                u = _url_from_rec(rec)
                if u:
                    push("frame", u, 8.6, source="P10:session_hardening")
        for rec in (sh.get("mixup") or []):
            if isinstance(rec, dict):
                u = _url_from_rec(rec)
                if u and _api_like(u):
                    push("cors", u.split("?")[0], 6.5, source="P10:mixup-cacheable")

    # ---------- 5. P2 forms.json (state-change census core) ----------
    forms_art = _artifact(base_dir, "understand", "forms.json")
    if forms_art is not None:
        mined["sources"].append("understand/forms.json")
        for rec in _iter_records(forms_art):
            u = _url_from_rec(rec)
            if not u:
                continue
            method = (rec.get("method") or "POST").upper()
            flds = rec.get("fields") or rec.get("inputs") or []
            if isinstance(flds, list) and flds and isinstance(flds[0], dict):
                fields = [{"name": f.get("name", ""), "type": f.get("type", ""),
                           "value": ""} for f in flds if isinstance(f, dict)]
            else:
                fields = [{"name": str(f), "type": "text", "value": ""}
                          for f in (flds or []) if f]
            sc = _state_change_score(method, u, fields)
            if method in ("POST", "PUT", "PATCH", "DELETE") or sc >= 5.0:
                has_tok = any(CSRF_TOKEN_NAMES.match((f.get("name") or ""))
                              for f in fields)
                push("csrf", u, max(sc, 6.0) + (0.0 if has_tok else 0.4),
                     method=method, fields=fields, source="P2:forms",
                     extra={"has_token_hint": has_tok})

    # ---------- 6. P7 postmessage / dom / storage / endpoints / ws ----------
    pma = _artifact(base_dir, "js", "postmessage_audit.txt")
    if pma:
        mined["sources"].append("js/postmessage_audit.txt")
        for line in pma.splitlines()[:120]:
            m = re.search(r"https?://[^\s\"']+|/(?:[a-z0-9_\-./]+)", line)
            if m:
                push("pm", urljoin_safe(base_url, m.group(0)), 7.2,
                     source="P7:postmessage_audit")
    da = _artifact(base_dir, "js", "dom_analysis.txt")
    if da:
        mined["sources"].append("js/dom_analysis.txt")
        for line in da.splitlines()[:150]:
            if re.search(r"(?i)postmessage|message.*listener|event\.origin", line):
                m = re.search(r"https?://[^\s\"']+|/(?:[a-z0-9_\-./]+)", line)
                if m:
                    push("pm", urljoin_safe(base_url, m.group(0)), 7.6,
                         source="P7:dom_analysis:pm")
    st = _artifact(base_dir, "js", "storage_tokens.txt")
    if st:
        mined["sources"].append("js/storage_tokens.txt")
        for line in st.splitlines()[:60]:
            m = re.search(r"https?://[^\s\"']+|/(?:[a-z0-9_\-./]+)", line)
            if m:
                push("storage", urljoin_safe(base_url, m.group(0)), 7.0,
                     source="P7:storage_tokens")
    je = _artifact(base_dir, "js", "endpoints.txt")
    if je:
        mined["sources"].append("js/endpoints.txt")
        for line in je.splitlines()[:400]:
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            if _api_like(u):
                push("cors", urljoin_safe(base_url, u).split("?")[0], 5.5,
                     source="P7:endpoints:api")
            if OAUTH_LIKE.search(u):
                push("oauth", urljoin_safe(base_url, u), 7.4,
                     source="P7:endpoints:oauth")
    wsx = _artifact(base_dir, "js", "websockets.txt")
    wss = _artifact(base_dir, "sessions", "ws_surface.json")
    if wsx:
        mined["sources"].append("js/websockets.txt")
    for line in (wsx or "").splitlines()[:40]:
        u = line.strip()
        if u.lower().startswith(("ws://", "wss://")):
            push("ws", u, 6.8, source="P7:websockets")
    if wss and isinstance(wss, dict):
        for u in (wss.get("ws_endpoints") or []):
            if isinstance(u, str) and u.lower().startswith(("ws://", "wss://")):
                push("ws", u, 7.0, source="P10:ws_surface")

    # ---------- 7. P9 auth_endpoints.txt (state-change w/ sessions) ----------
    ae = _artifact(base_dir, "auth", "auth_endpoints.txt")
    if ae:
        mined["sources"].append("auth/auth_endpoints.txt")
        for line in ae.splitlines()[:120]:
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            sc = _state_change_score("POST", u, [])
            if sc >= 4.0:
                push("csrf", urljoin_safe(base_url, u), 7.8,
                     source="P9:auth_endpoints")
            if OAUTH_LIKE.search(u):
                push("oauth", urljoin_safe(base_url, u), 7.5,
                     source="P9:auth_endpoints")

    # ---------- 8. P13 csp_analysis (frame-ancestors gaps) ----------
    csp = _artifact(base_dir, "xss", "csp_analysis.json")
    if csp is not None:
        mined["sources"].append("xss/csp_analysis.json")
        for rec in _iter_records(csp):
            gaps = rec.get("gaps") or []
            if any("frame" in str(g).lower() for g in gaps):
                u = _url_from_rec(rec)
                if u:
                    push("frame", u, 8.2, source="P13:csp_frame_gap")

    # ---------- 9. P11 idor_verdicts (state-change endpoints w/ sessions) ----------
    idv = _artifact(base_dir, "access", "idor_verdicts.json")
    if idv is not None:
        mined["sources"].append("access/idor_verdicts.json")
        for rec in _iter_records(idv):
            u = _url_from_rec(rec)
            if u and _state_change_score("POST", u, []) >= 4.0:
                push("csrf", u.split("?")[0], 7.0, source="P11:idor_state_change")

    # ---------- 10. P4 security_headers.txt (XFO/CSP missing) ----------
    sec = _artifact(base_dir, "active", "security_headers.txt")
    if sec:
        mined["sources"].append("active/security_headers.txt")
        block, host_now = [], None
        for line in sec.splitlines():
            if line.strip().startswith(("[", "http")) and "://" in line:
                host_now = line.strip().split()[0].strip("[]")
            if re.search(r"(?i)x-frame-options.*(missing|absent|none)|"
                         r"frame-ancestors.*(missing|absent)", line):
                if host_now:
                    block.append(host_now)
        for h in list(dict.fromkeys(block))[:10]:
            push("frame", urljoin_safe(base_url, "/" if not h.startswith("http") else h),
                 6.0, source="P4:security_headers")

    # ---------- 11. P8 priority_queue (generic client targets) ----------
    pq = _artifact(base_dir, "surface", "priority_queue.json")
    if pq is not None:
        mined["sources"].append("surface/priority_queue.json")
        n = 0
        for rec in _iter_records(pq):
            if n >= 80:
                break
            u = _url_from_rec(rec)
            if not u:
                continue
            n += 1
            if SENSITIVE_PAGE.search(u):
                push("frame", u.split("?")[0], 5.5, source="P8:priority:sensitive")
            if _api_like(u):
                push("cors", u.split("?")[0], 5.0, source="P8:priority:api")

    # ---------- 12. P10 client_session_storage.json ----------
    css = _artifact(base_dir, "sessions", "client_session_storage.json")
    if css is not None:
        mined["sources"].append("sessions/client_session_storage.json")
        for rec in _iter_records(css):
            u = _url_from_rec(rec, prefer=("endpoint", "page", "url"))
            if u:
                push("storage", u, 6.8, source="P10:client_storage")

    mined["counts"] = {"seed_artifacts": len(mined["sources"])}
    return sorted(targets.values(), key=lambda t: -t["score"]), mined, base_url


# ===========================================================================
# COLD-START FORM HARVEST (jab seeds thin hon) - budget-capped GET crawl
# ===========================================================================
def coldstart_harvest(http, scope, conf, cp, base_url, meta):
    """Scope seed URLs -> forms + api/oauth/ws hints (client_get_crawl budget)."""
    out_forms, out_api, out_oauth = [], [], []
    urls = list(scope.seed_urls() or [])
    seen, crawled = set(), 0
    cap = int(conf.get("client_get_crawl", 30))
    q = list(urls)
    extra_links = []
    while q and crawled < cap:
        u = q.pop(0)
        if u in seen:
            continue
        seen.add(u)
        ck = "cold:" + u
        if cp.is_done(ck):
            r_d = cp.result_of(ck) or {}
        else:
            r = http.get(u, allow_redirects=False)
            r_d = {"status": r.status, "text": r.text[:120000],
                   "headers": dict(r.headers)} if r and not r.error else {}
            cp.mark(ck, r_d, summary="cold crawl")
        crawled += 1
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        body = r_d.get("text") or ""
        if not body:
            continue
        for f in _parse_forms(body, u):
            f["source"] = "cold:crawl"
            out_forms.append(f)
        for m in re.finditer(r"(?i)(?:https?://[^\s\"'<>]+|/[a-z0-9_\-./]*)", body[:60000]):
            link = urljoin_safe(u, m.group(0))
            sp = urllib.parse.urlsplit(link)
            if sp.netloc and host_of(link) == host_of(base_url) and \
               link not in seen and len(extra_links) < 40:
                extra_links.append(link)
        for m in re.finditer(r"(?i)(?:\"|')(wss?://[^\"'\s]+)", body[:60000]):
            out_api.append(("ws", m.group(1)))
        q.extend(extra_links[:12])
        extra_links = []
    return out_forms, out_api, crawled


def merge_coldstart(ranked, forms, base_url, cap):
    """Cold forms -> csrf/frame/oauth targets me merge (dedupe)."""
    have_csrf = {t["url"].split("?")[0] for t in ranked if t["kind"] == "csrf"}
    added = 0
    for f in forms[:max(0, int(cap))]:
        action = f.get("action") or ""
        if not action:
            continue
        sc = _state_change_score(f.get("method"), action, f.get("fields"))
        ep = action.split("?")[0]
        if f.get("method") in ("POST", "PUT", "PATCH", "DELETE") and ep not in have_csrf:
            ranked.append({"kind": "csrf", "url": ep, "score": round(min(sc, 9.0), 2),
                           "method": f.get("method"), "fields": f.get("fields") or [],
                           "source": f.get("source", "cold"),
                           "has_token_hint": f.get("has_token", False)})
            have_csrf.add(ep)
            added += 1
    return ranked, added


# ===========================================================================
# STAGE B - BASELINE & CALIBRATION (2x GET + soft-404 + header snapshot)
# ===========================================================================
def baseline_endpoint(http, url, conf, cp, tag="base", meta=None):
    """2x GET baseline: status/len/sha1/timing differential (stability check)."""
    ck = "baseline%s:%s" % (tag, url)
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    r1 = http.get(url, allow_redirects=False)
    r2 = http.get(url, allow_redirects=False)
    if meta is not None:
        meta["probes_total"] = meta.get("probes_total", 0) + 2
    if r1.error or r2.error:
        res = {"ok": False, "error": r1.error or r2.error, "url": url}
        cp.mark(ck, res, summary="baseline err")
        return res
    same_sha = (r1.sha1() == r2.sha1())
    res = {"ok": True, "url": url, "status": r1.status,
           "len": len(r1.body), "sha1": r1.sha1(),
           "stable": same_sha, "elapsed": round((r1.elapsed + r2.elapsed) / 2.0, 4),
           "headers": {k: v for k, v in r1.headers.items()
                       if k.lower() in ("content-type", "cache-control", "vary",
                                        "x-frame-options", "content-security-policy",
                                        "access-control-allow-origin",
                                        "access-control-allow-credentials",
                                        "strict-transport-security", "server")},
           "set_cookies": r1.set_cookies, "title": title_of(r1.text)}
    cp.mark(ck, res, summary="baseline %s" % r1.status)
    return res


FRAME_H = "x-frame-options"
CSP_H = "content-security-policy"
ACAO_H = "access-control-allow-origin"
ACAC_H = "access-control-allow-credentials"


def security_header_snapshot(r):
    """Resp -> normalized client-defense snapshot (XFO/CSP/ACAO/SameSite/COOP)."""
    if r is None or r.error:
        return {}
    xfo = (r.header(FRAME_H) or "").strip()
    csp = (r.header(CSP_H) or "").strip()
    acao = (r.header(ACAO_H) or "").strip()
    acac = (r.header(ACAC_H) or "").strip()
    fa = ""
    for d in csp.split(";"):
        d = d.strip()
        if d.lower().startswith("frame-ancestors"):
            fa = d.split(None, 1)[1] if len(d.split(None, 1)) > 1 else ""
    snap = {"xfo": xfo, "csp": truncate(csp, 300), "frame_ancestors": fa,
            "acao": acao, "acac": acac,
            "coop": (r.header("cross-origin-opener-policy") or "").strip(),
            "coep": (r.header("cross-origin-embedder-policy") or "").strip(),
            "corp": (r.header("cross-origin-resource-policy") or "").strip(),
            "cto": (r.header("x-content-type-options") or "").strip(),
            "set_cookie_raw": r.header("set-cookie", default="")[:400]}
    return snap


def xfo_verdict(xfo):
    """XFO value -> (verdict, note). DENY/SAMEORIGIN = protected."""
    v = (xfo or "").strip()
    if not v:
        return "missing", "header hi nahi"
    lv = v.lower()
    if lv in ("deny", "sameorigin"):
        return "protected", ""
    if lv.startswith("allow-from"):
        return "deprecated", "ALLOW-FROM modern browsers ignore karte hain"
    if "," in v or v.count(" ") > 1:
        return "invalid", "multi/ambiguous value: %s" % truncate(v, 60)
    if lv not in ("deny", "sameorigin"):
        return "invalid", "unknown value: %s" % truncate(v, 60)
    return "protected", ""


def frame_ancestors_verdict(fa):
    """CSP frame-ancestors directive -> (verdict, note)."""
    if not (fa or "").strip():
        return "missing", "directive absent"
    toks = [t.strip().strip("'") for t in fa.split() if t.strip()]
    if toks in (["none"], ["self"]):
        return "protected", ""
    if "*" in toks:
        return "wildcard", "frame-ancestors *"
    if any(t in ("http:", "https:", "data:") for t in toks):
        return "scheme-source", "scheme-source allows any host"
    return "hostlist", "host-list: %s" % truncate(fa, 80)


# ===========================================================================
# STAGE C - CSRF TOKEN CENSUS (passive-heavy, token sources x entropy)
# ===========================================================================
def census_forms_on_page(http, url, conf, cp, meta, budget_left, page_js=None):
    """GET page -> forms w/ token census (page par jitne form mile sab).
    page_js: optional list - (url, js-slice) stash for pm/storage reuse."""
    ck = "census:%s" % url
    if cp.is_done(ck):
        return cp.result_of(ck) or []
    if budget_left() <= 0:
        return []
    r = http.get(url, allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    if r.error or not r.is_html():
        cp.mark(ck, [], summary="census skip")
        return []
    if page_js is not None:
        page_js.append((url, r.text[:80000]))
    forms = _parse_forms(r.text, url)
    snap = security_header_snapshot(r)
    for f in forms:
        f["page"] = url
        f["page_snap"] = snap
        # meta-tag token bhi dekho
        if re.search(r"(?is)<meta[^>]+name\s*=\s*[\"'][^\"']*csrf[^\"']*[\"']", r.text):
            f["meta_token"] = True
        # JS global token
        if re.search(r"(?i)(window\.\w*(?:csrf|xsrf|token)\w*\s*=|"
                     r"axios\.defaults\.headers\.(?:common\.)?['\"]?x-csrf)", r.text):
            f["js_token"] = True
    cp.mark(ck, forms, summary="census %d forms" % len(forms))
    return forms


def csrf_census(http, csrf_targets, conf, cp, meta, page_js=None):
    """Per state-change endpoint: token present? entropy? GET-logout? token-in-GET?"""
    budget = {"n": int(conf.get("client_csrf_form_cap", 60))}
    def budget_left():
        return budget["n"]
    records = []
    for t in csrf_targets:
        if budget_left() <= 0:
            break
        url = t["url"]
        if t.get("fields"):
            # seeded fields (P2/cold) -> fresh GET ki zaroorat nahi
            forms = [{"action": url, "method": t.get("method", "POST"),
                      "fields": t.get("fields") or [],
                      "has_token": t.get("has_token_hint"),
                      "source": t.get("source"), "page": url}]
        else:
            # fresh page census (agar form fields seeded nahi the)
            forms = census_forms_on_page(http, url, conf, cp, meta, budget_left,
                                         page_js=page_js)
        budget["n"] -= 1
        if not forms:
            continue
        for f in forms:
            method = (f.get("method") or "POST").upper()
            sc = _state_change_score(method, f.get("action") or url, f.get("fields"))
            if sc < 4.0 and not SC_STRONG.search(f.get("action") or url):
                continue
            tok_fields = [x for x in (f.get("fields") or [])
                          if CSRF_TOKEN_NAMES.match(x.get("name") or "")]
            tok_vals = [x.get("value") or "" for x in tok_fields]
            tok_ent = max([shannon_entropy(v) for v in tok_vals if v] or [0.0])
            rec = {
                "url": f.get("action") or url, "page": f.get("page", url),
                "method": method, "state_score": round(sc, 1),
                "fields": [(x.get("name"), x.get("type")) for x in (f.get("fields") or [])][:14],
                "sensitive_fields": [x.get("name") for x in (f.get("fields") or [])
                                     if SENSITIVE_FIELDS.search(x.get("name") or "")],
                "low_risk_fields": [x.get("name") for x in (f.get("fields") or [])
                                    if LOW_RISK_FIELDS.match(x.get("name") or "")],
                "token_in_form": bool(tok_fields) or bool(f.get("has_token")),
                "token_names": [x.get("name") for x in tok_fields],
                "token_entropy": round(tok_ent, 2),
                "meta_token": bool(f.get("meta_token")),
                "js_token": bool(f.get("js_token")),
                "token_in_get": bool(re.search(r"(?i)[?&](csrf|_token|token|xsrf)=", url)),
                "source": f.get("source", ""),
                "snap": f.get("page_snap") or {},
            }
            records.append(rec)
    # GET-logout detector (sab targets me logout GET links)
    get_logout = []
    for t in csrf_targets:
        u = t["url"]
        if re.search(r"(?i)(logout|signout|sign-out)", u) and \
           t.get("method", "GET") == "GET":
            get_logout.append(u)
    # login-CSRF (login form bina token)
    login_csrf = [r for r in records
                  if re.search(r"(?i)(login|signin|sign-in)", r["url"])
                  and not r["token_in_form"] and not r["meta_token"] and not r["js_token"]]
    summary = {"census_records": len(records), "no_token": sum(
        1 for r in records if not r["token_in_form"] and not r["meta_token"]
        and not r["js_token"]), "get_logout": len(get_logout),
        "login_csrf": len(login_csrf)}
    return records, get_logout, login_csrf, summary


def samesite_audit(set_cookie_blobs, seeded_cookies):
    """Set-Cookie raw + P10 seeded cookies -> SameSite posture records."""
    recs = []
    for raw in set_cookie_blobs:
        if not raw:
            continue
        m = re.match(r"\s*([^=;\s]+)=([^;]*)", raw)
        if not m:
            continue
        name, val = m.group(1), m.group(2)
        low = raw.lower()
        recs.append({"name": name, "value_len": len(val),
                     "samesite": ("none" if "samesite=none" in low else
                                  "lax" if "samesite=lax" in low else
                                  "strict" if "samesite=strict" in low else ""),
                     "secure": "secure" in low, "httponly": "httponly" in low,
                     "domain": (re.search(r"domain=([^;]+)", raw, re.I).group(1).strip()
                                if re.search(r"domain=([^;]+)", raw, re.I) else ""),
                     "host_prefix": name.startswith("__Host-"),
                     "raw": truncate(raw, 200)})
    for c in (seeded_cookies or []):
        if isinstance(c, dict) and c.get("name") and \
           not any(r["name"] == c["name"] for r in recs):
            recs.append({"name": c["name"], "value_len": len(str(c.get("value", ""))),
                         "samesite": str(c.get("samesite", "") or ""),
                         "secure": bool(c.get("secure")), "httponly": bool(c.get("httponly")),
                         "domain": str(c.get("domain", "") or ""), "host_prefix": False,
                         "raw": "seeded:P10"})
    return recs


# ===========================================================================
# STAGE D - CSRF DEFENSE MATRIX (RoE-gated live replay + SameSite + PoC)
# ===========================================================================
REJECT_SIGNS = re.compile(
    r"(?i)(csrf|xsrf|token.{0,12}(invalid|missing|expired|mismatch|required)|"
    r"forbidden|access denied|unauthorized|bad request|invalid request|"
    r"verification failed|anti.?forgery|authenticity|not allowed|denied|"
    r"origin.{0,12}(invalid|mismatch|not allowed)|referer.{0,12}(invalid|"
    r"missing)|same.?site)")
ACCEPT_SIGNS = re.compile(
    r"(?i)(success|updated|saved|created|posted|changed|done|complete|ok|"
    r"welcome|thanks|thank you|profile|setting)")


def _post_rejection(r):
    """Resp -> (is_rejection, note). Status + body-signature combined."""
    if r is None or r.error:
        return True, "error: %s" % (r.error if r else "none")
    st = r.status or 0
    if st in (400, 401, 403, 405, 406, 412, 422, 428, 429):
        return True, "status %d" % st
    body = r.text[:2500]
    m = REJECT_SIGNS.search(body)
    if m:
        return True, "body-sign: %s" % truncate(m.group(0), 60)
    return False, ""


def _looks_accepted(r):
    if r is None or r.error:
        return False
    st = r.status or 0
    rej, _ = _post_rejection(r)
    if rej:
        return False
    if st in (200, 201, 202, 204, 301, 302, 303, 307, 308):
        return True
    return False


def csrf_replay_probe(http, rec, conf, cp, meta):
    """RoE-GATED live probe (csrf_allow_replay=True par hi call hota hai).
    Ladder (SIRF low-risk fields par, apni identity se, waspP14 canary):
      1. token-LESS POST   -> accepted?
      2. garbage-token POST-> similarly accepted? (double-signal)
    Kabhi password/email/role/finance fields par replay NAHI hota."""
    url = rec["url"]
    low = rec.get("low_risk_fields") or []
    if not low:
        return {"ran": False, "reason": "no-low-risk-field"}
    canary = "waspP14canary%s" % rand_str(6)
    # ---------- build body: low-risk canary + inert fillers, NO token ----------
    def build_body(token_val=None):
        parts = []
        for name, ftype in rec.get("fields", []):
            if CSRF_TOKEN_NAMES.match(name or ""):
                if token_val is not None:
                    parts.append("%s=%s" % (urllib.parse.quote(name),
                                            urllib.parse.quote(token_val)))
                continue  # token-less ladder me token field drop
            if SENSITIVE_FIELDS.search(name or ""):
                continue  # sensitive fields kabhi touch nahi
            if LOW_RISK_FIELDS.match(name or ""):
                parts.append("%s=%s" % (urllib.parse.quote(name),
                                        urllib.parse.quote(canary)))
            else:
                parts.append("%s=wasp14inert" % urllib.parse.quote(name))
        return "&".join(parts)
    ident = http.identity("csrf-replay")
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Origin": "https://wasp-csrf-probe.invalid",
               "Referer": "https://wasp-csrf-probe.invalid/poc",
               "X-Requested-With": "XMLHttpRequest"}
    probes = []
    # probe 1: token-less
    r1 = ident.request("POST", url, headers=headers, data=build_body(None).encode("utf-8"),
                       allow_redirects=False, force_write=True)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    acc1 = _looks_accepted(r1)
    probes.append({"probe": "token-less", "status": r1.status if r1 else None,
                   "accepted": acc1,
                   "rej": _post_rejection(r1)[1],
                   "len": len(r1.body) if r1 else 0})
    # probe 2: garbage token (double-signal)
    r2 = ident.request("POST", url, headers=headers,
                       data=build_body("waspP14invalidtoken").encode("utf-8"),
                       allow_redirects=False, force_write=True)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    acc2 = _looks_accepted(r2)
    probes.append({"probe": "garbage-token", "status": r2.status if r2 else None,
                   "accepted": acc2,
                   "rej": _post_rejection(r2)[1],
                   "len": len(r2.body) if r2 else 0})
    canary_echo = canary in ((r1.text or "")[:8000] if r1 else "")
    if acc1 and acc2:
        verdict = "CONFIRMED"
    elif acc1 or acc2:
        verdict = "SUSPECTED"
    elif _post_rejection(r1)[0] and "status 40" in str(probes[0]["rej"]) + str(probes[1]["rej"]):
        verdict = "BLOCKED"
    else:
        verdict = "HARDENED"
    return {"ran": True, "url": url, "verdict": verdict, "probes": probes,
            "canary": canary, "canary_echoed": canary_echo,
            "note": "RoE: sirf low-risk fields, apni identity, canary=%s" % canary}


def csrf_defense_matrix(http, census_recs, conf, cp, meta, F):
    """Census + (gated) live replay -> defense matrix records."""
    matrix = []
    replay_budget = int(conf.get("client_replay_budget", 8))
    allow_replay = bool(conf.get("csrf_allow_replay", False))
    replayed = 0
    skip_f = 0
    conf_f = 0
    for rec in census_recs:
        m = dict(rec)
        has_tok = rec["token_in_form"] or rec["meta_token"] or rec["js_token"]
        verdict = "SUSPECTED" if not has_tok else "HARDENED"
        reason = ("koi CSRF token source nahi (form/meta/cookie/JS)" if not has_tok
                  else "token source present (form=%s meta=%s js=%s)" % (
                      rec["token_in_form"], rec["meta_token"], rec["js_token"]))
        replay_res = None
        if not has_tok:
            if allow_replay and replayed < replay_budget:
                if rec.get("low_risk_fields"):
                    replay_res = csrf_replay_probe(http, rec, conf, cp, meta)
                    replayed += 1
                    if replay_res.get("ran"):
                        verdict = replay_res["verdict"]
                        reason = "live replay ladder: %s" % json.dumps(
                            replay_res["probes"])[:220]
                    else:
                        reason = "replay skip: %s" % replay_res.get("reason", "")
                else:
                    if skip_f < 2:
                        F.add("client_replay_skipped_sensitive",
                              "Sensitive fields - live replay RoE ke under skip",
                              rec["url"],
                              "fields=%s (sensitive) - sirf hypothesis verdict"
                              % (rec.get("sensitive_fields") or [])[:6],
                              evidence_ref="csrf_matrix.json")
                        skip_f += 1
                    m["replay_skipped"] = "sensitive-fields"
            elif allow_replay and replayed >= replay_budget:
                reason += " (replay budget khatam - census verdict)"
            else:
                # gate OFF - sensitive-skip marker phir bhi (census-level info)
                if not rec.get("low_risk_fields"):
                    m["replay_skipped"] = "sensitive-fields"
        if verdict == "CONFIRMED" and replay_res and replay_res.get("ran") \
           and conf_f < 6:
            F.add("csrf_token_not_validated",
                  "CSRF token validation absent (token-less replay ACCEPT)",
                  rec["url"],
                  "live ladder: %s | RoE: low-risk fields, apni identity"
                  % json.dumps(replay_res.get("probes", []))[:200],
                  evidence_ref="csrf_matrix.json")
            conf_f += 1
        m["verdict"] = verdict
        m["verdict_reason"] = reason
        m["replay"] = replay_res
        matrix.append(m)
    ok("CSRF defense matrix: %d records (replay %s, %d live)"
       % (len(matrix), "ON" if allow_replay else "OFF (RoE)", replayed))
    return matrix


def samesite_verdicts(same_recs, F, meta):
    """SameSite posture -> verdicts + findings."""
    out = []
    for c in same_recs:
        ss, sec = c.get("samesite", ""), bool(c.get("secure"))
        if ss == "none" and not sec:
            v, key = "INSECURE", "csrf_samesite_none_insecure"
        elif ss == "none" and sec:
            v, key = "RISKY", "csrf_samesite_none_insecure"
        elif ss == "":
            v, key = "MISSING", "csrf_samesite_missing"
        elif ss == "lax":
            v, key = "OK-LAX", None
        elif ss == "strict":
            v, key = "STRONG", None
        else:
            v, key = "UNKNOWN", None
        rec = dict(c)
        rec["verdict"] = v
        out.append(rec)
        if key:
            F.add(key, "Cookie %s: SameSite=%s%s" % (
                c["name"], ss or "missing", "" if sec else "+no-Secure"),
                  c.get("domain") or "-", "Set-Cookie: %s" % c.get("raw", ""),
                  evidence_ref="csrf_matrix.json")
    meta["samesite_count"] = len(out)
    return out


def build_csrf_poc(rec, n, outdir):
    """INERT PoC HTML (manual-submit, RoE note) -> csrf_poc/csrf_poc_NN.html."""
    _rwx_dir(outdir)
    action = rec.get("url", "")
    fields = rec.get("fields") or []
    rows = []
    for name, ftype in fields:
        val = ""
        if LOW_RISK_FIELDS.match(name or ""):
            val = "waspP14canary"
        rows.append('<input type="hidden" name="%s" value="%s">' %
                    (html.escape(name or "field"), html.escape(val)))
    doc = """<!DOCTYPE html>
<!-- ===================================================================
WASP P14 CSRF PoC (INERT - koi auto-submit nahi).
RoE: SIRF apne test account / apne lab me SUBMIT karo. Victim ko bhejna
YA kisi real user par fire karna MANA hai (authorized engagement only).
Census: verdict=%s | source=%s | generated=%s
==================================================================== -->
<html><head><title>WASP P14 CSRF PoC #%d</title></head>
<body>
<h3>WASP P14 - CSRF PoC #%d (%s)</h3>
<p>Target: <code>%s</code></p>
<p>Verdict: <b>%s</b> - %s</p>
<form id="poc" method="%s" action="%s" enctype="application/x-www-form-urlencoded">
%s
<input type="submit" value="Manual submit (apne lab me)">
</form>
</body></html>""" % (
        rec.get("verdict", ""), rec.get("source", ""), now_iso(),
        n, n, html.escape(rec.get("method", "POST")),
        html.escape(action), rec.get("verdict", ""),
        html.escape(truncate(rec.get("verdict_reason", ""), 120)),
        html.escape(rec.get("method", "POST").lower() if
                    rec.get("method") != "GET" else "get"),
        html.escape(action, True), "\n".join(rows))
    path = os.path.join(outdir, "csrf_poc_%02d.html" % n)
    _rwx_save_text(path, doc)
    return path


# ===========================================================================
# STAGE E - CORS MISCONFIG MATRIX (12 origin variants - GET/OPTIONS only,
#           reserved TLDs only -> ZERO external egress)
# ===========================================================================
CORS_TLD = "wasp-cors-probe.invalid"     # reserved TLD - kabhi resolve nahi hota


def build_origin_variants(url, cap=12):
    """Target URL -> 12 Origin variants (suffix/concat/case/underscore/...).
    SIRF reserved .invalid TLDs + null - koi real attacker host nahi."""
    try:
        sp = urllib.parse.urlsplit(url)
        host = (sp.netloc or "").split("@")[-1].split(":")[0]
    except Exception:
        host = ""
    if not host:
        return []
    parts = host.split(".")
    reg = ".".join(parts[-2:]) if len(parts) >= 2 else host
    variants = [
        ("arbitrary",       "https://%s" % CORS_TLD),
        ("null-origin",     "null"),
        ("suffix-append",   "https://%s.%s" % (host, CORS_TLD)),
        ("concat-suffix",   "https://%ss.%s" % (host, CORS_TLD)),
        ("case-mix",        "https://%s.%s" % (host.upper(), CORS_TLD)),
        ("underscore",      "https://%s_wasp.%s" % (host, CORS_TLD)),
        ("encoded-dot",     "https://%s%%2e%s" % (host, CORS_TLD)),
        ("regdomain-suffix", "https://%s.%s" % (reg, CORS_TLD)),
        ("dot-chain",       "https://%s.%s" % (host, host)),
        ("double-suffix",   "https://%s.%s.%s" % (host, host, CORS_TLD)),
        ("host-case-evil",  "https://%s.%s" % (CORS_TLD, host)),
        ("sub-own",         "https://www.%s" % host),
    ]
    return [(tag, o) for tag, o in variants[:max(4, min(12, int(cap)))]
            if o != "https://%s" % host]


def cors_probe_endpoint(http, url, conf, cp, meta, base=None):
    """1 endpoint x 12 origins + preflight -> (endpoint_record, probe_log)."""
    ck = "cors:%s" % url
    if cp.is_done(ck):
        return cp.result_of(ck) or ({}, [])
    log = []
    best = {"verdict": "HARDENED", "reflected": False, "acac": False,
            "technique": "", "acao": "", "vary": "", "null_ok": False,
            "suffix_ok": False, "wildcard": False}
    cap = int(conf.get("client_cors_origin_cap", 12))
    for tag, origin in build_origin_variants(url, cap):
        r = http.get(url, headers={"Origin": origin}, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if r is None or r.error:
            log.append({"origin": origin, "tag": tag, "error": str(r.error) if r else "?"})
            continue
        acao = (r.header(ACAO_H) or "").strip()
        acac = (r.header(ACAC_H) or "").strip().lower()
        vary = (r.header("vary") or "").strip()
        ent = {"origin": origin, "tag": tag, "status": r.status, "acao": acao,
               "acac": acac, "vary": vary}
        log.append(ent)
        if not acao:
            continue
        reflected = (acao.strip().lower() == origin.strip().lower())
        if reflected and acac == "true":
            best["reflected"], best["acac"] = True, True
            if origin == "null":
                best["null_ok"] = True
                newtech = "null-origin"
            elif tag in ("suffix-append", "concat-suffix", "regdomain-suffix",
                         "dot-chain", "double-suffix", "host-case-evil"):
                best["suffix_ok"] = True
                newtech = "suffix-match-bypass"
            else:
                newtech = "arbitrary-reflection"
            best["verdict"] = "CONFIRMED"
            if not best.get("technique"):      # first CONFIRMED technique lock
                best["technique"] = newtech
            best["acao"], best["vary"] = acao, vary
        elif reflected and best["verdict"] != "CONFIRMED":
            best["reflected"] = True
            if best["verdict"] not in ("CONFIRMED",):
                best["verdict"] = "SUSPECTED"
                best["technique"] = "origin-reflection-no-creds"
                best["acao"], best["vary"] = acao, vary
        elif acao == "*" and best["verdict"] not in ("CONFIRMED", "SUSPECTED"):
            best["wildcard"] = True
            best["verdict"] = "WILDCARD"
            best["technique"] = "acao-wildcard"
            best["acao"], best["vary"] = acao, vary
        # cache-deception hint (P26 chain): Vary: Origin missing + cacheable
        cc = (r.header("cache-control") or "").lower()
        if "origin" not in vary.lower() and reflected and \
           ("max-age" in cc or "public" in cc or "s-maxage" in cc):
            best["cache_vary_risk"] = True
    # ---------- preflight OPTIONS matrix ----------
    preflight = {}
    if conf.get("client_preflight", True):
        pr = http.request("OPTIONS", url,
                          headers={"Origin": "https://%s" % CORS_TLD,
                                   "Access-Control-Request-Method": "POST",
                                   "Access-Control-Request-Headers": "x-wasp-probe"},
                          allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if pr and not pr.error:
            acam = (pr.header("access-control-allow-methods") or "").strip()
            acah = (pr.header("access-control-allow-headers") or "").strip()
            acac_p = (pr.header(ACAC_H) or "").strip().lower()
            acao_p = (pr.header(ACAO_H) or "").strip()
            preflight = {"status": pr.status, "acam": acam, "acah": truncate(acah, 200),
                         "acac": acac_p, "acao": acao_p,
                         "allow_wildcard_methods": "*" in acam,
                         "dangerous_methods": bool(
                             re.search(r"(?i)\b(put|delete|patch)\b", acam)),
                         "reflected_headers": ("x-wasp-probe" in acah.lower())}
            if preflight["dangerous_methods"] and preflight["reflected_headers"] \
               and (acao_p and acao_p != "*") and acac_p == "true":
                if best["verdict"] != "CONFIRMED":
                    best["verdict"] = "SUSPECTED"
                    best.setdefault("technique", "")
                    best["technique"] = (best["technique"] + "+preflight-write").strip("+")
            best["preflight"] = preflight
    # ---------- Vary/cache note ----------
    if best.get("cache_vary_risk"):
        best["cache_note"] = ("reflected-origin + cacheable + Vary: Origin missing "
                              "-> CORS cache-deception chain (P26)")
    res = (best, log)
    cp.mark(ck, res, summary="cors %s" % best["verdict"])
    return res


def cors_matrix(http, cors_targets, conf, cp, meta, F):
    """All cors targets -> endpoint records + findings + probe log."""
    matrix, all_log = [], []
    cap = int(conf.get("client_cors_endpoints", 14))
    n = 0
    for t in cors_targets:
        if n >= cap:
            break
        url = t["url"]
        n += 1
        best, log = cors_probe_endpoint(http, url, conf, cp, meta)
        all_log.extend([dict(l, url=url) for l in log])
        rec = {"url": url, "source": t.get("source", ""), "verdict": best["verdict"],
               "technique": best.get("technique", ""), "acao": best.get("acao", ""),
               "acac": best.get("acac", False), "reflected": best.get("reflected"),
               "null_ok": best.get("null_ok"), "suffix_ok": best.get("suffix_ok"),
               "wildcard": best.get("wildcard"), "vary": best.get("vary", ""),
               "preflight": {k: v for k, v in (best.get("preflight") or {}).items()}
               if isinstance(best.get("preflight"), dict) else {},
               "cache_vary_risk": best.get("cache_vary_risk", False),
               "cache_note": best.get("cache_note", ""),
               "probe_count": len(log)}
        if best.get("preflight"):
            rec["preflight"] = best["preflight"]
        matrix.append(rec)
        # ---------- findings ----------
        if best["verdict"] == "CONFIRMED":
            if best.get("null_ok"):
                F.add("cors_null_origin_allowed", "CORS: null origin + credentials allowed",
                      url, "Origin: null -> ACAO:null + ACAC:true (sandboxed iframe "
                      "read chain)", evidence_ref="cors_matrix.json")
            elif best.get("suffix_ok"):
                F.add("cors_suffix_match_bypass", "CORS: suffix/prefix origin validation bypass",
                      url, "variant reflected: %s (ACAC true) - attacker-suffix domain "
                      "read possible" % best.get("technique", ""),
                      evidence_ref="cors_matrix.json")
            else:
                F.add("cors_credentials_reflected", "CORS: arbitrary origin reflected "
                      "+ credentials", url, "Origin echo + ACAC:true -> cross-origin "
                      "credentialed read (full ATO rasta)", evidence_ref="cors_matrix.json")
        elif best["verdict"] == "SUSPECTED":
            F.add("cors_origin_reflection", "CORS: origin reflection (no credentials)",
                  url, "ACAO echoes arbitrary origin, ACAC false - defense gap "
                  "(public-data exfil)", evidence_ref="cors_matrix.json")
        elif best["verdict"] == "WILDCARD":
            F.add("cors_wildcard_creds_violation" if best.get("acac") else
                  "cors_origin_reflection",
                  "CORS: ACAO wildcard%s" % (" + ACAC true (spec-violation)"
                                             if best.get("acac") else ""),
                  url, "ACAO:* %s" % ("+ ACAC:true - browsers block par config bug"
                                      if best.get("acac") else "- public data open"),
                  evidence_ref="cors_matrix.json")
        if best.get("cache_vary_risk"):
            F.add("cors_origin_reflection", "CORS + cache: Vary: Origin missing",
                  url, best.get("cache_note", ""), evidence_ref="cors_matrix.json")
        if best.get("preflight", {}).get("dangerous_methods"):
            F.add("cors_preflight_dangerous", "CORS preflight: write-methods + custom "
                  "headers allowed", url, "ACAM=%s ACAH reflects x-wasp-probe + ACAC "
                  "true" % best["preflight"].get("acam", ""),
                  evidence_ref="cors_matrix.json")
    ok("CORS matrix: %d endpoints probed (%d origins total)"
       % (len(matrix), len(all_log)))
    return matrix, all_log


LEGACY_CROSSDOMAIN_ALLOW = re.compile(
    r"(?is)<allow-access-from\s+[^>]*domain\s*=\s*[\"']\*[\"'][^>]*>")
LEGACY_CAP_ALLOW = re.compile(r"(?is)<allow\s*/>|domain\s*=\s*[\"']\*[\"']")


def legacy_crossdomain_audit(http, base_url, conf, cp, meta, F):
    """crossdomain.xml + clientaccesspolicy.xml (legacy Flash/Silverlight trust)."""
    out = []
    if not conf.get("client_probe_crossdomain", True):
        return out
    for path, tag in (("/crossdomain.xml", "flash"),
                      ("/clientaccesspolicy.xml", "silverlight")):
        url = urljoin_safe(base_url, path)
        ck = "xd:%s" % url
        if cp.is_done(ck):
            d = cp.result_of(ck) or {}
        else:
            r = http.get(url, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            body = (r.text or "")[:20000] if (r and not r.error) else ""
            d = {"url": url, "status": r.status if r else None,
                 "body_hint": truncate(body, 600), "present": bool(
                     body and ("<cross-domain-policy" in body or
                               "<access-policy" in body))}
            if d["present"]:
                d["wildcard"] = bool(LEGACY_CROSSDOMAIN_ALLOW.search(body)
                                     or LEGACY_CAP_ALLOW.search(body))
            cp.mark(ck, d, summary="legacy %s" % path)
        if d.get("present"):
            v = "SUSPECTED" if d.get("wildcard") else "HARDENED"
            out.append(dict(d, kind=tag, verdict=v))
            if d.get("wildcard"):
                F.add("cors_legacy_crossdomain",
                      "Legacy %s policy wildcard allow" % tag, url,
                      "domain=\"*\" - purane clients ke liye full cross-origin trust",
                      evidence_ref="cors_matrix.json")
    return out


# ===========================================================================
# STAGE F - CLICKJACKING & FRAMING AUDIT (header-level deterministic)
# ===========================================================================
def framing_audit(http, frame_targets, conf, cp, meta, F, ctx):
    """Per page: XFO + CSP frame-ancestors -> verdicts + PoC artifacts."""
    matrix, pocs = [], []
    cap = int(conf.get("client_frame_pages", 20))
    n = 0
    seen_ep = set()
    for t in frame_targets:
        if n >= cap:
            break
        url = t["url"].split("?")[0]
        if url in seen_ep:
            continue
        seen_ep.add(url)
        base = baseline_endpoint(http, url, conf, cp, tag="frame", meta=meta)
        n += 1
        if not base.get("ok") or (base.get("status") or 500) >= 400:
            continue
        snap = base.get("headers") or {}
        snap_low = {str(k).lower(): v for k, v in snap.items()}
        xfo = snap_low.get("x-frame-options", "") or ""
        csp = snap_low.get("content-security-policy", "") or ""
        xv, xn = xfo_verdict(xfo)
        fa_direct = ""
        for d in csp.split(";"):
            d2 = d.strip()
            if d2.lower().startswith("frame-ancestors"):
                fa_direct = d2.split(None, 1)[1] if len(d2.split(None, 1)) > 1 else ""
        fv, fn = frame_ancestors_verdict(fa_direct)
        if xv in ("missing", "invalid", "deprecated") and fv in ("missing", "wildcard",
                                                                "scheme-source"):
            verdict = "CONFIRMED" if (xv == "missing" and fv == "missing") else "SUSPECTED"
        elif xv == "deprecated" or fv in ("wildcard", "scheme-source"):
            verdict = "SUSPECTED"
        else:
            verdict = "HARDENED"
        sensitive = bool(SENSITIVE_PAGE.search(url))
        rec = {"url": url, "xfo": xfo, "xfo_verdict": xv, "xfo_note": xn,
               "frame_ancestors": fa_direct, "fa_verdict": fv, "fa_note": fn,
               "verdict": verdict, "sensitive_page": sensitive,
               "source": t.get("source", ""), "status": base.get("status")}
        matrix.append(rec)
        if verdict == "CONFIRMED":
            F.add("framing_no_protection",
                  "Clickjacking: page framable (XFO + frame-ancestors dono missing)%s"
                  % (" - SENSITIVE page" if sensitive else ""), url,
                  "X-Frame-Options absent + CSP frame-ancestors absent -> attacker "
                  "UI-redress framing possible", evidence_ref="framing_matrix.json")
            poc = build_frame_poc(rec, len(pocs) + 1,
                                  os.path.join(ctx["out"], "framing_poc"))
            if poc:
                pocs.append(poc)
                rec["poc"] = poc
        elif verdict == "SUSPECTED":
            if xv == "deprecated":
                F.add("framing_xfo_deprecated", "X-Frame-Options: ALLOW-FROM (deprecated)",
                      url, "modern browsers ALLOW-FROM ignore karte hain -> framing "
                      "effectively open", evidence_ref="framing_matrix.json")
            else:
                F.add("framing_csp_ancestors_weak", "CSP frame-ancestors weak",
                      url, "%s (%s)" % (fv, fn), evidence_ref="framing_matrix.json")
    ok("Framing audit: %d pages (%d framable)"
       % (len(matrix), sum(1 for m in matrix if m["verdict"] == "CONFIRMED")))
    return matrix, pocs


def build_frame_poc(rec, n, outdir):
    """INERT framing PoC (iframe + manual note, koi auto-action nahi)."""
    _rwx_dir(outdir)
    doc = """<!DOCTYPE html>
<!-- ===================================================================
WASP P14 Clickjacking PoC (INERT demo - koi auto-submit/action nahi).
RoE: SIRF apne lab me iframe kholo. Real victim par UI-redress demo sirf
authorized engagement ke RoE me allowed ho to.
==================================================================== -->
<html><head><title>WASP P14 Framing PoC #%d</title></head>
<body style="font-family:sans-serif">
<h3>WASP P14 - Clickjacking PoC #%d</h3>
<p>Target: <code>%s</code></p>
<p>Defense: XFO=<b>%s</b> (%s) | frame-ancestors=<b>%s</b> (%s)</p>
<p>Neeche target page iframe me render ho raha hai (agar defense absent):
   attacker apne elements overlay karke user click hijack kar sakta hai.</p>
<iframe src="%s" width="900" height="420" style="border:2px dashed #c33"></iframe>
<p style="color:#a33">NOTE: ye file INERT hai - koi payload/auto-submit nahi.</p>
</body></html>""" % (
        n, n, html.escape(rec.get("url", "")),
        html.escape(rec.get("xfo", "") or "MISSING"),
        html.escape(rec.get("xfo_verdict", "")),
        html.escape(rec.get("frame_ancestors", "") or "MISSING"),
        html.escape(rec.get("fa_verdict", "")),
        html.escape(rec.get("url", ""), True))
    path = os.path.join(outdir, "frame_poc_%02d.html" % n)
    _rwx_save_text(path, doc)
    return path


# ===========================================================================
# STAGE G - POSTMESSAGE TRUST BOUNDARY (origin validation + sink analysis)
# ===========================================================================
PM_LISTENER = re.compile(r"(?i)addEventListener\s*\(\s*[\"']message[\"']")
PM_SINK = re.compile(r"(?i)(innerHTML|outerHTML|document\.write|document\.writeln|"
                     r"insertAdjacentHTML|location\s*(?:=|\.href|\.replace)|"
                     r"\beval\s*\(|new\s+Function\s*\(|\.src\s*=|jQuery\(.+\)\.html)")
PM_ORIGIN_CHECK = re.compile(r"(?i)\.origin\b")
PM_WEAK_MATCH = re.compile(r"(?i)\.origin\s*==[^=]|\.origin\s*!=[^=]|startsWith|"
                           r"endsWith|\.indexOf\(|\.includes\(|search\(|match\(|test\(")
PM_STRICT_MATCH = re.compile(r"(?i)\.origin\s*===\s*[\"']https?:|\.origin\s*!==\s*[\"']|"
                             r"new\s+URL\s*\(|try\s*\{\s*new\s+URL")
PM_SENDER_WILD = re.compile(r"(?i)postMessage\s*\([^;]{0,400}?[\"']\*[\"']")
PM_SANDBOX_COMBO = re.compile(
    r"(?is)<iframe[^>]+sandbox\s*=\s*[\"'][^\"']*(allow-scripts)"
    r"[^\"']*(allow-same-origin)[^\"']*[\"']")
PM_DATA_PARSE = re.compile(r"(?i)(JSON\.parse\s*\(\s*(?:e|event)\.data|"
                           r"(?:e|event)\.data\.(?!postMessage)\w+)")


def pm_analyze_js(js_text, url):
    """JS text -> postMessage risk records (listener/origin/sink/sender)."""
    recs = []
    low = (js_text or "").lower()
    if not js_text or ("message" not in low and "sandbox" not in low
                       and "postmessage" not in low):
        return recs
    for lm in PM_LISTENER.finditer(js_text):
        start = lm.end()
        # handler body approx-slice (1500 chars - regex-only static analysis)
        sl = js_text[start:start + 1500]
        # brace-balance slice (max 1200 chars extra)
        depth, cut = 0, len(sl)
        for i, ch in enumerate(sl):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth <= 0 and i > 0:
                    cut = i + 1
                    break
        body = sl[:cut]
        rec = {"url": url, "kind": "listener", "snippet": truncate(body, 240)}
        has_check = bool(PM_ORIGIN_CHECK.search(body))
        if has_check:
            strict = bool(PM_STRICT_MATCH.search(body))
            weak = bool(PM_WEAK_MATCH.search(body))
            if strict and not weak:
                rec["verdict"] = "HARDENED"
            elif weak:
                rec["verdict"] = "SUSPECTED"
                rec["technique"] = "prefix/loose origin match"
            else:
                rec["verdict"] = "SUSPECTED"
                rec["technique"] = "origin read but no strict compare"
        else:
            rec["verdict"] = "SUSPECTED"
            rec["technique"] = "no origin check"
        if PM_SINK.search(body) and rec["verdict"] != "HARDENED":
            rec["sink"] = True
            rec["verdict"] = "CONFIRMED"
            rec["technique"] = (rec.get("technique", "") + "+dom-sink").strip("+")
        if PM_DATA_PARSE.search(body):
            rec["json_parse"] = True
        recs.append(rec)
    if PM_SENDER_WILD.search(js_text):
        recs.append({"url": url, "kind": "sender-wildcard", "verdict": "SUSPECTED",
                     "technique": "postMessage(targetOrigin '*')",
                     "snippet": truncate(PM_SENDER_WILD.search(js_text).group(0), 200)})
    if PM_SANDBOX_COMBO.search(js_text):
        recs.append({"url": url, "kind": "iframe-sandbox-combo", "verdict": "SUSPECTED",
                     "technique": "sandbox allow-scripts+allow-same-origin (sandbox "
                     "trivially escapes)",
                     "snippet": "iframe sandbox combo"})
    return recs


def postmessage_audit(http, pm_targets, conf, cp, meta, F, extra_pages_js=None):
    """P13 dom_confirmed + P7 hints + fresh capped fetches -> pm records."""
    records = []
    seen = set()
    fetch_cap = int(conf.get("client_pm_fetch", 4))
    fetched = 0
    for t in pm_targets:
        url = t["url"].split("?")[0]
        if url in seen:
            continue
        seen.add(url)
        # (1) seeded DOM records (P13) - 0 requests
        if t.get("sink") or t.get("source", "").startswith("P13"):
            records.append({"url": url, "kind": "seeded-dom", "verdict": "SUSPECTED",
                            "technique": "P13 dom_confirmed seed (listener/chain)",
                            "source": t.get("source", ""),
                            "snippet": t.get("sink", "")})
        # (2) fresh JS analysis (capped)
        if fetched < fetch_cap:
            ck = "pmjs:%s" % url
            if cp.is_done(ck):
                js = (cp.result_of(ck) or {}).get("js", "")
            else:
                r = http.get(url, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                js = r.text[:150000] if (r and not r.error and r.is_html()) else ""
                cp.mark(ck, {"js": js[:40000]}, summary="pm js cap")
            fetched += 1
            if js:
                records.extend(pm_analyze_js(js, url))
    for js, url in (extra_pages_js or []):
        records.extend(pm_analyze_js(js, url))
    # findings (dedupe by url+technique)
    emitted = set()
    for rec in records:
        k = (rec["url"], rec.get("technique", ""), rec["verdict"])
        if k in emitted:
            continue
        emitted.add(k)
        if rec["verdict"] == "CONFIRMED":
            F.add("pm_sink_in_listener", "postMessage listener me DOM sink "
                  "(one-click DOM XSS chain)", rec["url"],
                  "message data -> sink, origin check %s | snippet: %s" % (
                      "weak" if rec.get("technique", "").startswith("no") else "loose",
                      rec.get("snippet", ""))[:300],
                  evidence_ref="postmessage_audit_v14.json")
        elif rec["verdict"] == "SUSPECTED" and rec.get("kind") in ("listener", "seeded-dom"):
            key = "pm_prefix_origin_match" if "prefix" in rec.get("technique", "") \
                else "pm_no_origin_check"
            F.add(key, "postMessage: origin validation %s" % (
                "prefix/loose" if "prefix" in rec.get("technique", "") else "missing"),
                  rec["url"], rec.get("technique", "") + " | " +
                  rec.get("snippet", "")[:200],
                  evidence_ref="postmessage_audit_v14.json")
        elif rec.get("kind") == "sender-wildcard":
            F.add("pm_wildcard_target", "postMessage(targetOrigin '*') sender",
                  rec["url"], "sensitive data kisi bhi window ko leak ho sakta hai",
                  evidence_ref="postmessage_audit_v14.json")
    ok("postMessage audit: %d records (%d listeners)"
       % (len(records), sum(1 for r in records if r.get("kind") in ("listener", "seeded-dom"))))
    return records


# ===========================================================================
# STAGE H - STORAGE & TOKEN EXPOSURE CHAINS (XSS -> ATO narratives)
# ===========================================================================
LS_TOKEN = re.compile(
    r"(?i)localStorage\.setItem\s*\(\s*[\"']([^\"']*(?:token|jwt|auth|session|"
    r"access|refresh|id)[^\"']*)[\"']\s*,\s*([^)]{1,120})")
SS_TOKEN = re.compile(
    r"(?i)sessionStorage\.setItem\s*\(\s*[\"']([^\"']*(?:token|jwt|auth|session|"
    r"access|refresh|id)[^\"']*)[\"']\s*,\s*([^)]{1,120})")
JWT_IN_JS = re.compile(r"(?i)[\"'](eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                       r"\.[A-Za-z0-9_-]{5,})[\"']")


def storage_chain_audit(http, storage_targets, conf, cp, meta, F,
                        extra_pages_js=None, xss_dom_conf=None):
    """localStorage/sessionStorage token exposure -> ATO chain records."""
    records = []
    seen = set()
    fetch_cap = max(2, int(conf.get("client_pm_fetch", 4)))
    fetched = 0
    for t in storage_targets:
        url = t["url"].split("?")[0]
        if url in seen:
            continue
        seen.add(url)
        if fetched >= fetch_cap:
            break
        fetched += 1
        ck = "stjs:%s" % url
        if cp.is_done(ck):
            js = (cp.result_of(ck) or {}).get("js", "")
        else:
            r = http.get(url, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            js = r.text[:150000] if (r and not r.error) else ""
            cp.mark(ck, {"js": js[:40000]}, summary="storage js")
        if not js:
            continue
        for m in LS_TOKEN.finditer(js):
            records.append({"url": url, "store": "localStorage", "key": m.group(1),
                            "value_hint": truncate(m.group(2), 80)})
        for m in SS_TOKEN.finditer(js):
            records.append({"url": url, "store": "sessionStorage", "key": m.group(1),
                            "value_hint": truncate(m.group(2), 80)})
        jm = JWT_IN_JS.search(js)
        if jm and not any(r["url"] == url for r in records):
            records.append({"url": url, "store": "inline-JS", "key": "jwt-like",
                            "value_hint": "eyJ***REDACTED***"})
    for js, url in (extra_pages_js or []):
        for m in LS_TOKEN.finditer(js):
            if not any(r["url"] == url and r["key"] == m.group(1) for r in records):
                records.append({"url": url, "store": "localStorage", "key": m.group(1),
                                "value_hint": truncate(m.group(2), 80)})
    emitted = set()
    for rec in records:
        k = (rec["url"], rec["key"])
        if k in emitted:
            continue
        emitted.add(k)
        chain = " + P13 dom_confirmed (%s) -> full ATO chain" % \
            (xss_dom_conf[0] if xss_dom_conf else "DOM XSS sink") \
            if xss_dom_conf else " (koi XSS confirm ho to ATO chain)"
        F.add("storage_token_in_localstorage",
              "Token %s me exposed: %s" % (rec["store"], rec["key"]),
              rec["url"], "value_hint=%s%s" % (rec["value_hint"], chain),
              evidence_ref="storage_chains.json")
    ok("Storage chains: %d exposure records" % len(records))
    return records


def cookie_tossing_prereq(same_recs, F):
    """Domain-attribute too broad -> cookie-tossing pre-req note."""
    out = 0
    for c in same_recs:
        dom = str(c.get("domain", "") or "")
        if dom.startswith(".") and dom.count(".") >= 2:
            out += 1
            F.add("storage_cookie_tossing_prereq",
                  "Cookie domain too broad (tossing pre-req)", dom,
                  "Domain=%s - koi bhi sibling subdomain cookie toss kar sakta hai"
                  % dom, evidence_ref="csrf_matrix.json")
    return out


# ===========================================================================
# STAGE I - OAUTH STATE AUDIT + WEBSOCKET + ADVANCED TECHNIQUE MATRIX
# ===========================================================================
OAUTH_URL = re.compile(r"(?i)(https?://[^\s\"'<>]*|/[^\s\"'<>]*)"
                       r"(?:oauth|authorize|auth\?|oidc)[^\s\"'<>]*")
OAUTH_STATE = re.compile(r"(?i)[?&]state\s*=\s*[^&\s\"']+")
OAUTH_IMPLICIT = re.compile(r"(?i)[?&]response_type\s*=\s*token(\b|%2[bB])")
OAUTH_PKCE = re.compile(r"(?i)[?&]code_challenge\s*=")
OAUTH_CLIENT = re.compile(r"(?i)[?&]client_id\s*=\s*([^&\s\"']+)")


def oauth_state_audit(http, oauth_targets, conf, cp, meta, F):
    """OAuth authorize URLs: state / response_type / PKCE / redirect_uri audit."""
    records = []
    seen = set()
    cap = 6
    for t in oauth_targets:
        if len(records) >= cap * 3 or len(seen) >= cap:
            break
        url = t["url"]
        ep = url.split("?")[0]
        if ep in seen:
            continue
        seen.add(ep)
        qs = url.split("?")[1] if "?" in url else ""
        has_state = bool(OAUTH_STATE.search(url))
        implicit = bool(OAUTH_IMPLICIT.search(url))
        pkce = bool(OAUTH_PKCE.search(url))
        cid = OAUTH_CLIENT.search(url)
        rec = {"url": url, "state": has_state, "implicit": implicit, "pkce": pkce,
               "client_id": cid.group(1) if cid else "", "source": t.get("source", "")}
        records.append(rec)
        if not has_state:
            F.add("oauth_state_missing", "OAuth authorize par state param missing",
                  url, "authorization-code injection / login-CSRF / session fixation "
                  "chain (CSRF token ka OAuth-roop = state)", evidence_ref="oauth_state_audit.json")
        if implicit:
            F.add("oauth_implicit_flow", "OAuth implicit flow (response_type=token)",
                  url, "access token URL-fragment me - browser history/Referer leak "
                  "surface; PKCE + authorization-code flow recommend",
                  evidence_ref="oauth_state_audit.json")
        if not pkce and not implicit:
            F.add("oauth_pkce_missing", "OAuth par PKCE (code_challenge) missing",
                  url, "public/custom-scheme client me code interception chain",
                  evidence_ref="oauth_state_audit.json")
    # fresh page hunt (agar urls me state dikha hi nahi): cap-2 page GETs
    if len(records) < 2:
        for t in oauth_targets[len(records):]:
            if len(records) >= 4:
                break
            ep = t["url"].split("?")[0]
            if ep in seen:
                continue
            seen.add(ep)
            ck = "oauth:%s" % ep
            if cp.is_done(ck):
                body = (cp.result_of(ck) or {}).get("js", "")
            else:
                r = http.get(ep, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                body = r.text[:80000] if (r and not r.error) else ""
                cp.mark(ck, {"js": body[:30000]}, summary="oauth page")
            for m in OAUTH_URL.finditer(body):
                u = urljoin_safe(ep, m.group(0))
                if OAUTH_STATE.search(u) and not OAUTH_IMPLICIT.search(u):
                    records.append({"url": u, "state": True, "implicit": False,
                                    "pkce": bool(OAUTH_PKCE.search(u)),
                                    "client_id": "", "source": "page-js"})
                    continue
                if u not in [x["url"] for x in records]:
                    records.append({"url": u, "state": bool(OAUTH_STATE.search(u)),
                                    "implicit": bool(OAUTH_IMPLICIT.search(u)),
                                    "pkce": bool(OAUTH_PKCE.search(u)),
                                    "client_id": "", "source": "page-js"})
                    rec = records[-1]
                    if not rec["state"]:
                        F.add("oauth_state_missing", "OAuth authorize par state missing",
                              u, "page-js se mined authorize URL me state absent",
                              evidence_ref="oauth_state_audit.json")
                    if rec["implicit"]:
                        F.add("oauth_implicit_flow", "OAuth implicit flow",
                              u, "response_type=token page-js me",
                              evidence_ref="oauth_state_audit.json")
    ok("OAuth audit: %d authorize URLs (%d state-missing)"
       % (len(records), sum(1 for r in records if not r["state"])))
    return records


def ws_origin_audit(ws_targets, conf, meta, F):
    """WebSocket cross-origin hijack - hypothesis-only (handshake probe gated OFF)."""
    records = []
    for t in ws_targets:
        u = t["url"]
        rec = {"url": u, "source": t.get("source", ""),
               "probe_ran": False,
               "verdict": "SUSPECTED" if not conf.get("client_ws_handshake") else "HYPOTHESIS",
               "note": "cross-site WS hijack check: handshake par Origin header "
                       "naive-allowlist hai ya nahi - manual verify (browser devtools "
                       "ya Burp)".format()}
        records.append(rec)
    emitted = set()
    for rec in records:
        if rec["url"] in emitted:
            continue
        emitted.add(rec["url"])
        F.add("ws_cross_origin_unchecked", "WebSocket: Origin validation unknown "
              "(manual check)", rec["url"], rec["note"],
              evidence_ref="client_surface.json")
    return records


def technique_matrix(census_recs, cors_mx, frame_mx, pm_recs, oauth_recs,
                     same_recs, legacy, storage_recs, ws_count=0):
    """18-technique famous-matrix: status + evidence (analysis-layer)."""
    TM = []

    def t(name, family, status, detail):
        TM.append({"technique": name, "family": family, "status": status,
                   "detail": truncate(detail, 260)})

    # ---------- CSRF family ----------
    if any(r["token_in_get"] for r in census_recs):
        t("csrf-token-in-get-leak", "CSRF", "SUSPECTED",
          "CSRF token GET query me - Referer/Proxy-Log/History leak chain")
    t("csrf-referer-regex-bypass", "CSRF", "HYPOTHESIS",
      "Referer validation regex (startsWith/endsWith/contains) - attacker.example-target.com "
      "jaisa domain bypass kar sakta hai; Origin-header prefer karo")
    t("csrf-host-header-injection", "CSRF", "HYPOTHESIS",
      "Host-header se password-reset/CSRF token poisoning (P12 header-injection "
      "seeds ke saath chain)")
    if any(c.get("json_like") for c in census_recs):
        t("csrf-json-textplain", "CSRF", "HYPOTHESIS",
          "JSON API par text/plain body (form-encoded JSON string) - preflight-free "
          "cross-site write agar server lenient parse kare")
    t("csrf-samesite-lax-navigations", "CSRF", "HYPOTHESIS",
      "SameSite=Lax top-level GET navigations allow karta hai - GET-based state "
      "change (logout/invite links) Lax ke under bhi chal sakta hai")
    if any(c.get("token_names") and c.get("token_in_form") and not c.get("meta_token")
           for c in census_recs):
        t("double-submit-cookie-flaw", "CSRF", "HYPOTHESIS",
          "Token cookie (XSRF-TOKEN) + form-field dono hain - agar server SIRF "
          "equality check kare (bina server-side store) to subdomain-tossing bypass")
    # ---------- CORS family ----------
    if any(m.get("null_ok") for m in cors_mx):
        t("cors-null-origin-sandbox", "CORS", "SUSPECTED",
          "null origin allowed - sandboxed iframe (srcdoc) se credentialed read")
    if any(m.get("suffix_ok") for m in cors_mx):
        t("cors-subdomain-takeover-chain", "CORS", "SUSPECTED",
          "suffix-match bypass + takeover-able subdomain (P4 DNS hints) -> full "
          "credentialed read")
    if any(m.get("cache_vary_risk") for m in cors_mx):
        t("cors-cache-deception", "CORS", "SUSPECTED",
          "reflected ACAO + Vary: Origin missing + cacheable -> CORS cache poisoning "
          "(P26 chain)")
    # ---------- framing family ----------
    if any(m.get("xfo_verdict") == "deprecated" for m in frame_mx):
        t("xfo-allowfrom-deprecated-bypass", "Framing", "SUSPECTED",
          "ALLOW-FROM sirf purane browsers me chalta hai - modern browsers frame kar "
          "sakte hain")
    t("clickjacking-double-frame", "Framing", "HYPOTHESIS",
      "double-frame + inner-frame top-location trick (legacy framebusting bypass) "
      "- XFO absent pages par")
    # ---------- postMessage family ----------
    if any("prefix" in (r.get("technique") or "") for r in pm_recs):
        t("pm-prefix-origin-bypass", "postMessage", "SUSPECTED",
          "startsWith/endsWith origin check - attacker-prefix domain bypass")
    if any(r.get("json_parse") for r in pm_recs):
        t("pm-json-parse-injection", "postMessage", "SUSPECTED",
          "JSON.parse(e.data) bina shape-validation - prototype-pollution gadget "
          "(P13 client_pp chain)")
    # ---------- oauth family ----------
    if any(not r.get("state") for r in oauth_recs):
        t("oauth-login-csrf", "OAuth", "SUSPECTED",
          "state missing -> authorization-code injection -> session fixation/ATO")
    if any(r.get("implicit") for r in oauth_recs):
        t("oauth-implicit-token-leak", "OAuth", "SUSPECTED",
          "implicit flow token fragment - history/Referer/JS-leak surface")
    # ---------- ws / storage ----------
    if ws_count:
        t("ws-cross-origin-hijack", "WebSocket", "HYPOTHESIS",
          "WS handshake Origin allowlist verify karo - missing hai to cross-site "
          "WS hijacking (data read/write victim session me)")
    if any(c.get("domain", "").startswith(".") and c.get("domain", "").count(".") >= 2
           for c in same_recs):
        t("cookie-tossing", "Storage", "SUSPECTED",
          "broad domain cookie - sibling-subdomain tossing -> session fixation input")
    t("defense-census-coop-coep-tt", "Defense", "INFO",
      "COOP/COEP/CORP/Trusted-Types headers ki census - modern cross-origin "
      "isolation absent hai to Spectre/XS-leak surface bhi open")
    return TM


# ===========================================================================
# STAGE J - CHAINS & HYPOTHESES (ranked kill-chains + passive ideas)
# ===========================================================================
def build_client_chains(F, csrf_mx, cors_mx, frame_mx, pm_recs, oauth_recs,
                        storage_recs, same_recs, xss_dom_conf):
    """Cross-signal kill-chains (impact-ranked)."""
    chains = []
    csrf_weak = [r for r in csrf_mx if r["verdict"] in ("CONFIRMED", "SUSPECTED")]
    ss_weak = [c for c in same_recs if c.get("verdict") in ("INSECURE", "RISKY", "MISSING")]
    cors_cred = [m for m in cors_mx if m["verdict"] == "CONFIRMED"]
    frame_conf = [m for m in frame_mx if m["verdict"] == "CONFIRMED" and m.get("sensitive_page")]
    pm_sink = [r for r in pm_recs if r["verdict"] == "CONFIRMED"]
    oauth_bad = [r for r in oauth_recs if not r.get("state")]
    if csrf_weak and ss_weak:
        chains.append({
            "name": "CSRF full-chain (token-less + cookie-samesite weak)",
            "components": ["csrf:%s" % csrf_weak[0]["url"],
                           "cookie:%s" % ss_weak[0].get("name", "?")],
            "impact": "Attacker page se victim-session state-change (email/password/"
                      "role) - SameSite defense bhi absent",
            "steps": "1) PoC HTML apne lab me open; 2) apne test-account par verify; "
                     "3) report me PoC attach; 4) fix: token + SameSite=Lax/Strict + Origin check",
            "severity": "HIGH"})
    if cors_cred and storage_recs:
        chains.append({
            "name": "CORS -> cross-origin ATO chain",
            "components": ["cors:%s" % cors_cred[0]["url"],
                           "storage:%s" % storage_recs[0]["url"]],
            "impact": "Attacker origin victim ke credentials se API read karta hai; "
                      "token storage-exposure ke saath full ATO",
            "steps": "1) evil-origin se fetch(url, {credentials:'include'}) demo "
                     "APNE lab me; 2) response me sensitive data confirm; 3) fix: "
                     "strict origin allowlist + ACAC false",
            "severity": "HIGH"})
    if pm_sink and (xss_dom_conf or storage_recs):
        chains.append({
            "name": "postMessage -> one-click DOM XSS / token chain",
            "components": ["pm:%s" % pm_sink[0]["url"],
                           "xss-dom:%s" % (xss_dom_conf[0] if xss_dom_conf else "-")],
            "impact": "Ek click (attacker window.open/postMessage) se DOM XSS - "
                      "phir token/localStorage exfil (impact-sirf narrative)",
            "steps": "1) apne lab me origin-restricted iframe se message bhejo; "
                     "2) sink trigger verify; 3) fix: origin strict-compare + "
                     "input shape-validation + Trusted Types",
            "severity": "HIGH"})
    if frame_conf and csrf_weak:
        chains.append({
            "name": "Clickjacking -> UI-redress state-change",
            "components": ["frame:%s" % frame_conf[0]["url"],
                           "csrf:%s" % csrf_weak[0]["url"]],
            "impact": "Framable sensitive page + CSRF-weak action = click-hijack "
                      "write (password/role pages par critical)",
            "steps": "1) frame PoC apne browser me kholo; 2) overlay click-path "
                     "sim apne account par; 3) fix: XFO DENY/SAMEORIGIN + "
                     "frame-ancestors 'self'",
            "severity": "MEDIUM-HIGH"})
    if oauth_bad:
        chains.append({
            "name": "OAuth state-missing -> account takeover pre-req",
            "components": ["oauth:%s" % oauth_bad[0]["url"]],
            "impact": "Authorization-code injection -> victim session attacker "
                      "account se bind (login-CSRF/fixation)",
            "steps": "1) authorize URL bina state apne lab me dobara request; "
                     "2) code binding verify; 3) fix: state (session-bound, "
                     "crypto-random) + PKCE",
            "severity": "HIGH"})
    if any(m.get("verdict") == "SUSPECTED" and m.get("wildcard") for m in cors_mx) \
       and any(l.get("wildcard") for l in legacy):
        chains.append({
            "name": "Legacy + modern cross-origin trust mix",
            "components": ["legacy-crossdomain", "cors-wildcard"],
            "impact": "Purane clients (Flash/Silverlight-era) + wildcard ACAO dono "
                      "open - defense-in-depth zero",
            "steps": "1) crossdomain.xml remove/tighten; 2) ACAO explicit allowlist",
            "severity": "LOW-MEDIUM"})
    return chains


def build_client_hypotheses(csrf_mx, cors_mx, census_summary):
    """Passive-layer hypotheses (0-request test ideas for manual wave)."""
    H = []
    if census_summary.get("no_token"):
        H.append("CSRF-1: token-less state-change endpoints par Referer-strip test "
                 "(Burp: Origin/Referer header remove karke) - accepted hai to "
                 "origin-validation bhi absent")
    if any(m.get("reflected") and not m.get("acac") for m in cors_mx):
        H.append("CORS-1: ACAO reflection ACAC-false endpoints par - auth-header "
                 "wale request se non-credentialed sensitive read check (public data "
                 "exfil bhi count)")
    H.append("CSRF-2: login endpoint par login-CSRF (attacker-credentials victim "
             "browser me) - sirf apne do test accounts ke beech")
    H.append("CORS-2: subdomain takeover registry (P4 DNS) se suffix-allowlist "
             "domains ka CNAME check")
    H.append("Framing-1: 404/error pages ka framing differential (XFO kabhi-kabhi "
             "sirf 200 par set hota hai)")
    H.append("PM-1: devtools console se test-origin message bhejo (apne lab page "
             "se) - handler response dekho")
    H.append("OAuth-1: state value reuse/replay (same state 2x) - server validate "
             "karta hai ya nahi")
    H.append("WS-1: cross-origin WS handshake browser-console se (new WebSocket "
             "apne origin se) - connection accepted? read-only messages dekho")
    H.append("Cookie-1: __Host- prefix cookies ka presence - prefixadopted nahi "
             "hai to subdomain-tossing input possible")
    return H


# ===========================================================================
# CWE / OWASP MAPPINGS (P14 client-side family)
# ===========================================================================
CWE_OWASP_MAP_CLIENT = {
    "csrf_no_token_state_change": {"cwe": "CWE-352 (Cross-Site Request Forgery)",
                                   "owasp": "OWASP A01:2021 (Broken Access Control)",
                                   "owasp_attack": "OWASP CSRF Prevention Cheat Sheet"},
    "csrf_token_not_validated": {"cwe": "CWE-352", "owasp": "OWASP A01:2021",
                                 "note": "live differential proof"},
    "csrf_samesite_none_insecure": {"cwe": "CWE-1275 (Sensitive Cookie without "
                                             "'SameSite' Restriction)",
                                    "owasp": "OWASP Session Management"},
    "csrf_samesite_missing": {"cwe": "CWE-1275", "owasp": "OWASP Session Management"},
    "csrf_login": {"cwe": "CWE-352", "owasp": "OWASP A07:2021 (Identification and "
                                           "Authentication Failures)"},
    "csrf_token_in_get": {"cwe": "CWE-598 (Use of GET Request Method With Sensitive "
                                 "Query Strings)", "owasp": "OWASP Session Management"},
    "cors_credentials_reflected": {"cwe": "CWE-942 (Permissive Cross-domain Policy "
                                          "with Untrusted Domains)",
                                   "owasp": "OWASP A05:2021 (Security Misconfiguration)"},
    "cors_suffix_match_bypass": {"cwe": "CWE-346 (Origin Validation Error)",
                                 "owasp": "OWASP A05:2021"},
    "cors_null_origin_allowed": {"cwe": "CWE-346", "owasp": "OWASP A05:2021"},
    "cors_origin_reflection": {"cwe": "CWE-942", "owasp": "OWASP A05:2021"},
    "cors_preflight_dangerous": {"cwe": "CWE-942", "owasp": "OWASP A05:2021"},
    "cors_legacy_crossdomain": {"cwe": "CWE-942", "owasp": "OWASP A05:2021 (legacy)"},
    "framing_no_protection": {"cwe": "CWE-1021 (Improper Restriction of Rendered UI "
                                     "Layers)", "owasp": "OWASP A05:2021"},
    "framing_xfo_deprecated": {"cwe": "CWE-1021", "owasp": "OWASP A05:2021"},
    "pm_no_origin_check": {"cwe": "CWE-346 / CWE-345 (Insufficient Verification of "
                                   "Data Authenticity)", "owasp": "OWASP A08:2021"},
    "pm_sink_in_listener": {"cwe": "CWE-79 (XSS) via CWE-345", "owasp": "OWASP A03:2021"},
    "pm_wildcard_target": {"cwe": "CWE-201 (Information Exposure Through Sent Data)",
                           "owasp": "OWASP A01:2021"},
    "storage_token_in_localstorage": {"cwe": "CWE-922 (Insecure Storage of Sensitive "
                                             "Information)", "owasp": "OWASP A02:2021"},
    "oauth_state_missing": {"cwe": "CWE-352 / CWE-384 (Session Fixation)",
                            "owasp": "OWASP OAuth 2.0 Threat Model"},
    "oauth_implicit_flow": {"cwe": "CWE-522 / OAuth implicit deprecation",
                            "owasp": "OAuth 2.1 draft (implicit removed)"},
    "ws_cross_origin_unchecked": {"cwe": "CWE-346 (CSWSH)", "owasp": "OWASP A05:2021"},
    "storage_cookie_tossing_prereq": {"cwe": "CWE-565 (Reliance on Cookies without "
                                             "Validation)", "owasp": "OWASP Session"},
}


# ===========================================================================
# REPORT BUILDERS (markdown/text)
# ===========================================================================
def _client_findings_md(F, conf, meta):
    L = ["# WASP P14 - Client-Side Findings (CSRF / CORS / Framing / postMessage)",
         "", "- **Module:** mod_client.py v%s" % PLAN_VERSION,
         "- **Generated:** %s" % now_human(),
         "- **Mode:** detection-only | RoE gates: csrf_allow_replay=%s, "
         "ws_handshake=%s" % (bool(conf.get("csrf_allow_replay")),
                              bool(conf.get("client_ws_handshake"))),
         "- **Probes:** %s | **Findings:** %d" % (meta.get("probes_total", 0),
                                                  len(F.items)),
         "",
         "| ID | Sev | Finding | Endpoint | Evidence |",
         "|----|-----|---------|----------|----------|"]
    for f in sorted(F.items, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        L.append("| %s | %s | %s | `%s` | %s |" % (
            f["id"], f["severity"].upper(), f["title"],
            truncate(f["endpoint"], 70), f["evidence"]))
    L += ["", "## Why-it-matters (impact narratives)", ""]
    for f in sorted(F.items, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        L += ["### %s - %s" % (f["id"], f["title"]),
              "- **Endpoint:** `%s`" % f["endpoint"],
              "- **Severity:** %s (CVSS hint %.1f)" % (f["severity"], f["cvss_hint"]),
              "- **Detail:** %s" % f["detail"],
              "- **Impact:** %s" % f["why_it_matters"],
              ""]
    L += ["## Defense census snapshot", "",
          "- XFO/CSP-frame-ancestors: %d pages audited" % meta.get("frame_pages", 0),
          "- CORS endpoints probed: %d (origins: reserved .invalid TLDs only)"
          % meta.get("cors_endpoints", 0),
          "- CSRF census records: %d" % meta.get("census_records", 0),
          "- SameSite cookies audited: %s" % meta.get("samesite_count", 0),
          "",
          "> RoE note: PoC artifacts (csrf_poc/, framing_poc/) INERT hain - manual "
          "submit + sirf apne lab/test-accounts ke liye.", ""]
    return "\n".join(L)


def _client_test_plan_md(hyps, conf, meta):
    L = ["# WASP P14 - Client-Side Manual Test Plan", "",
         "Automation ke baad ye MANUAL wave chalao (har item RoE-checked):", ""]
    for i, h in enumerate(hyps, 1):
        L.append("%d. %s" % (i, h))
    L += ["", "## Priority order (impact-ranked)", "",
          "1. CORS CONFIRMED endpoints - credentialed read demo apne lab me",
          "2. CSRF token-less CONFIRMED - PoC HTML apne test-account par",
          "3. OAuth state-missing - code-injection demo apne do accounts se",
          "4. postMessage sink - origin-restricted message se sink trigger",
          "5. Clickjacking sensitive pages - overlay PoC",
          "6. Storage tokens - XSS-chain impact narrative report me",
          "", "## Evidence checklist", "",
          "- [ ] Har CONFIRMED ka request/response capture (evidence/)",
          "- [ ] PoC file ka screenshot (apne browser, apna session)",
          "- [ ] Impact sentence (kya account/data compromise hota hai)",
          "- [ ] Fix recommendation (token/SameSite/ACAO-allowlist/XFO/origin-check)",
          ""]
    return "\n".join(L)


def _client_chains_text(chains):
    L = ["WASP P14 - CLIENT KILL-CHAINS (impact-ranked)", "=" * 46, ""]
    if not chains:
        L.append("(koi cross-signal chain nahi bani - isolated findings dekho)")
        return "\n".join(L)
    for i, ch in enumerate(chains, 1):
        L += ["CHAIN %d: %s  [%s]" % (i, ch["name"], ch["severity"]),
              "  components : %s" % " + ".join(ch["components"]),
              "  impact     : %s" % ch["impact"],
              "  steps      : %s" % ch["steps"], ""]
    return "\n".join(L)


CATALOG_ROWS = [
    ("CSRF token census (30+ name patterns x 5 sources)", "CSRF",
     "token form/meta/cookie/JS/header me hai ya nahi + entropy", "CWE-352"),
    ("Token-less replay ladder (RoE-gated, low-risk only)", "CSRF",
     "garbage-token double-signal differential", "CWE-352"),
    ("SameSite posture audit (None-no-Secure/missing/__Host-)", "CSRF",
     "cookie-level CSRF defense", "CWE-1275"),
    ("Login-CSRF + GET-logout + token-in-GET", "CSRF",
     "auth-flow CSRF family", "CWE-352"),
    ("JSON-CSRF (text/plain) hypothesis", "CSRF",
     "preflight-free cross-site write", "CWE-352"),
    ("12-origin CORS matrix (suffix/concat/case/null/...)", "CORS",
     "ACAO echo + ACAC pair verdicts", "CWE-942/346"),
    ("Preflight OPTIONS matrix (ACAM/ACAH/ACSA)", "CORS",
     "cross-origin write surface", "CWE-942"),
    ("Vary: Origin + cacheable -> cache-deception", "CORS",
     "P26 cache chain", "CWE-942"),
    ("crossdomain.xml / clientaccesspolicy.xml legacy", "CORS",
     "Flash/Silverlight-era trust", "CWE-942"),
    ("XFO missing/invalid/deprecated + frame-ancestors", "Framing",
     "clickjacking header-proof", "CWE-1021"),
    ("Sensitive-page priority framing", "Framing",
     "password/role/wallet pages first", "CWE-1021"),
    ("postMessage listener origin-audit (strict vs prefix)", "postMessage",
     "CWE-345/346", "CWE-346"),
    ("postMessage sink-in-listener (DOM XSS chain)", "postMessage",
     "one-click client XSS", "CWE-79"),
    ("postMessage wildcard targetOrigin", "postMessage", "data leak", "CWE-201"),
    ("iframe sandbox allow-scripts+allow-same-origin", "postMessage",
     "sandbox escape combo", "CWE-1021"),
    ("localStorage/sessionStorage token exposure", "Storage",
     "XSS->ATO impact multiplier", "CWE-922"),
    ("Cookie domain-broad tossing pre-req", "Storage", "session attacks", "CWE-565"),
    ("OAuth state/implicit/PKCE audit", "OAuth", "login-CSRF/fixation", "CWE-352/384"),
    ("WS cross-origin hijack hypothesis", "WebSocket", "CSWSH", "CWE-346"),
    ("COOP/COEP/CORP/TT defense census", "Defense", "XS-leak/Spectre surface", "-"),
]


def build_catalog_md():
    L = ["# WASP P14 - TECHNIQUES CATALOG (Client-Side, %d rows)" % len(CATALOG_ROWS),
         "", "| # | Technique | Family | Kya deta hai | CWE |", "|---|-----------|--------|"
         "--------------|-----|"]
    for i, (name, fam, what, cwe) in enumerate(CATALOG_ROWS, 1):
        L.append("| %d | %s | %s | %s | %s |" % (i, name, fam, what, cwe))
    L += ["", "## Fix quick-reference", "",
          "- **CSRF:** token (synchronizer) + SameSite=Lax/Strict + Origin/Referer "
          "verify (exact-match) + GET par state-change kabhi nahi",
          "- **CORS:** strict origin allowlist (exact match), ACAC=true sirf "
          "trusted-origins par, wildcard+creds kabhi nahi, Vary: Origin",
          "- **Framing:** X-Frame-Options DENY/SAMEORIGIN + CSP frame-ancestors 'self'",
          "- **postMessage:** strict origin compare (===) + data shape-validation + "
          "sink me sanitization + Trusted Types",
          "- **Storage:** tokens HttpOnly cookies me (bina Path-scope lax), "
          "localStorage me session-token kabhi nahi",
          "- **OAuth:** state (session-bound) + PKCE S256 + authorization-code flow "
          "(implicit deprecated)",
          ""]
    return "\n".join(L)


def write_reports(out, scope, F, ctx, meta, results_by_stage, hypotheses, ranked, conf):
    """Stage K: sab artifacts likho (RWX 0777)."""
    stage_files = {}
    for k, v in (results_by_stage or {}).items():
        if isinstance(v, dict) and v.get("_file") and isinstance(v.get("data"), (dict, list)):
            _rwx_save_json(os.path.join(out, v["_file"]), v["data"])
            stage_files[k] = v["_file"]
    ranked = ranked or []
    # surface + targets
    _rwx_save_json(os.path.join(out, "client_surface.json"),
                   {"module": NAME, "phase": PHASE, "version": PLAN_VERSION,
                    "generated": now_iso(), "targets": ranked,
                    "mined_sources": ctx.get("mined_sources", []),
                    "coverage": ctx.get("coverage", {})})
    _rwx_save_text(os.path.join(out, "client_targets.txt"),
                   "\n".join("[%s] %-9s %s" % (t.get("kind", "?"),
                                               t.get("method", "GET"), t.get("url", ""))
                             for t in ranked))
    # matrices
    for key, fname in (("csrf_matrix", "csrf_matrix.json"),
                       ("cors_matrix", "cors_matrix.json"),
                       ("cors_log", "cors_probe_log.json"),
                       ("framing_matrix", "framing_matrix.json"),
                       ("pm_audit", "postmessage_audit_v14.json"),
                       ("storage", "storage_chains.json"),
                       ("oauth", "oauth_state_audit.json"),
                       ("samesite", "samesite_audit.json"),
                       ("ws", "ws_audit.json"),
                       ("techniques", "technique_matrix_client.json"),
                       ("legacy", "legacy_policies.json")):
        data = (results_by_stage or {}).get(key, {}).get("data")
        if data is not None:
            _rwx_save_json(os.path.join(out, fname), data)
            stage_files[key] = fname
    # poc index
    pocs = ctx.get("pocs") or []
    if pocs:
        _rwx_save_text(os.path.join(out, "poc_index.txt"),
                       "\n".join(str(p) for p in pocs))
        stage_files["pocs"] = "poc_index.txt"
    # docs
    _rwx_save_text(os.path.join(out, "CLIENT_FINDINGS.md"),
                   _client_findings_md(F, conf, meta))
    _rwx_save_text(os.path.join(out, "client_test_plan.md"),
                   _client_test_plan_md(hypotheses or [], conf, meta))
    _rwx_save_text(os.path.join(out, "client_chains.txt"),
                   _client_chains_text(ctx.get("chains") or []))
    _rwx_save_text(os.path.join(out, "TECHNIQUES_CATALOG_CLIENT.md"), build_catalog_md())
    _rwx_save_json(os.path.join(out, "cwe_owasp_map_client.json"), CWE_OWASP_MAP_CLIENT)
    _rwx_save_json(os.path.join(out, "findings.json"),
                   {"module": NAME, "phase": PHASE, "version": PLAN_VERSION,
                    "count": len(F.items), "findings": F.items,
                    "generated": now_iso()})
    # feedforward
    csrf_weak = [r["url"] for r in (results_by_stage.get("csrf_matrix", {})
                                    .get("data") or [])
                 if r.get("verdict") in ("CONFIRMED", "SUSPECTED")][:10]
    cors_conf = [r["url"] for r in (results_by_stage.get("cors_matrix", {})
                                    .get("data") or [])
                 if r.get("verdict") == "CONFIRMED"][:8]
    oauth_bad = [r["url"] for r in (results_by_stage.get("oauth", {}).get("data") or [])
                 if not r.get("state")][:6]
    gql_csrf = [r["url"] for r in (results_by_stage.get("csrf_matrix", {})
                                   .get("data") or [])
                if "graphql" in r["url"].lower()][:4]
    ws_urls = [r["url"] for r in (results_by_stage.get("ws", {}).get("data") or [])][:6]
    cache_risk = [r["url"] for r in (results_by_stage.get("cors_matrix", {})
                                     .get("data") or [])
                  if r.get("cache_vary_risk")][:6]
    state_writes = [r["url"] for r in (results_by_stage.get("csrf_matrix", {})
                                       .get("data") or [])
                    if r.get("verdict") in ("CONFIRMED", "SUSPECTED")][:10]
    write_feedforward(out, PHASE, {
        "to_phase15_ssrf": {"oauth_redirect_uris": oauth_bad,
                            "note": "redirect_uri open-redirect chain P15 me"},
        "to_phase17_api": {"cors_endpoints": [r["url"] for r in
                                              (results_by_stage.get("cors_matrix", {})
                                               .get("data") or [])][:10],
                           "preflight_write_surface": cors_conf},
        "to_phase18_graphql": {"graphql_csrf_targets": gql_csrf,
                               "note": "mutations-via-GET / no-csrf"},
        "to_phase19_ws": {"ws_endpoints": ws_urls},
        "to_phase20_logic": {"state_change_writes": state_writes,
                             "note": "business-logic abuse surface"},
        "to_phase23": {"defense_census": {"coop": meta.get("coop_missing", 0),
                                          "xfo_gaps": meta.get("frame_pages", 0)}},
        "to_phase26_cache": {"vary_origin_missing": cache_risk,
                             "note": "CORS cache-deception chain"},
        "to_phase32_report": {"findings": len(F.items),
                              "by_severity": _sev_counts(F)},
    }, notes=["detection-only run - PoC artifacts INERT (manual-submit)",
              "csrf replay RoE-gated (default OFF); cors origins reserved TLDs",
              "evidence PII-redacted; captures evidence/requests.jsonl me"])
    files = ["client_surface.json", "client_targets.txt", "csrf_matrix.json",
             "cors_matrix.json", "cors_probe_log.json", "framing_matrix.json",
             "postmessage_audit_v14.json", "storage_chains.json",
             "oauth_state_audit.json", "samesite_audit.json", "ws_audit.json",
             "technique_matrix_client.json", "legacy_policies.json",
             "CLIENT_FINDINGS.md", "client_test_plan.md", "client_chains.txt",
             "TECHNIQUES_CATALOG_CLIENT.md", "cwe_owasp_map_client.json",
             "findings.json", "feedforward.json"] + list(stage_files.values())
    files = sorted(set(files))
    write_manifest(out, PHASE, files,
                   stats={"targets": len(ranked), "probes_total": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "csrf_records": meta.get("census_records", 0),
                          "cors_endpoints": meta.get("cors_endpoints", 0),
                          "poc_files": len(pocs)})
    _rwx_tree(out)


def _rwx_tree(root):
    """Output folder ka compact tree (console + RWX enforce sab files par)."""
    try:
        os.chmod(root, 0o777)
    except OSError:
        pass
    lines = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for d in dirnames:
            _rwx_dir(os.path.join(dirpath, d))
        rel = os.path.relpath(dirpath, root)
        indent = "" if rel == "." else "  " * (rel.count(os.sep) + 1)
        if rel != ".":
            lines.append("%s%s/" % ("  " * rel.count(os.sep), os.path.basename(dirpath)))
        for fn in sorted(filenames):
            fp = os.path.join(dirpath, fn)
            _rwx_result(fp)
            lines.append("%s%s (%s)" % (indent, fn, human_size(os.path.getsize(fp))))
    return lines


# ===========================================================================
# MAIN RUN (stages A->K wiring, passive mode, resume-safe)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 14 - Client-Side: CSRF/CORS/framing/postMessage/OAuth "
         "(detection-only) (v%s) | %s" % (PLAN_VERSION, scope.describe()))
    if conf.get("csrf_allow_replay"):
        warn("CSRF LIVE replay ON (csrf_allow_replay=true) - SIRF low-risk fields, "
             "apne sessions, waspP14 canary. RoE khol ke check karo.")
    if conf.get("client_ws_handshake"):
        warn("WS handshake probing flag ON - handshake Origin allowlist manual "
             "verify bhi karo (devtools/Burp).")
    info("caps: forms=%s | cors=%s x %s origins | frame=%s | pm-fetch=%s | "
         "replay-budget=%s%s"
         % (conf.get("client_csrf_form_cap"), conf.get("client_cors_endpoints"),
            conf.get("client_cors_origin_cap"), conf.get("client_frame_pages"),
            conf.get("client_pm_fetch"), conf.get("client_replay_budget"),
            " | REPLAY ROE-GATE OFF" if not conf.get("csrf_allow_replay") else ""))

    F = Findings()
    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "pocs": [], "chains": [], "page_js": [],
           "mined_sources": [], "base_dir": os.path.join(base_out, scope.engagement)}
    results_by_stage = {}

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Client surface discovery (P10/P9/P7/P13-seeded, evidence-ranked)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {}, "")
        ranked, mined, base_url = cached[0], cached[1], cached[2]
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, mined, base_url = discover_client_surface(base_out, scope, conf)
        cp.mark(ckA, [ranked, mined, base_url], summary="client surface")
    ctx["mined_sources"] = mined.get("sources", [])
    ok("seed artifacts: %d sources" % len(ctx["mined_sources"]))
    csrf_targets = [t for t in ranked if t["kind"] == "csrf"]
    cors_targets = [t for t in ranked if t["kind"] == "cors"]
    frame_targets = [t for t in ranked if t["kind"] == "frame"]
    pm_targets = [t for t in ranked if t["kind"] == "pm"]
    oauth_targets = [t for t in ranked if t["kind"] == "oauth"]
    storage_targets = [t for t in ranked if t["kind"] == "storage"]
    ws_targets = [t for t in ranked if t["kind"] == "ws"]

    # cold-start fallback (seeds thin)
    if len(csrf_targets) < 3 and len(cors_targets) < 3 and base_url:
        info("seeds thin - cold-start form harvest (cap %s GETs)"
             % conf.get("client_get_crawl"))
        forms, hints, crawled = coldstart_harvest(http, scope, conf, cp,
                                                  base_url, meta)
        ranked, added = merge_coldstart(ranked, forms, base_url,
                                        int(conf.get("client_csrf_form_cap", 60)))
        csrf_targets = [t for t in ranked if t["kind"] == "csrf"]
        info("cold-start: %d forms, %d naye csrf targets" % (len(forms), added))
        for h in (hints or [])[:8]:
            if h[0] == "ws":
                ws_targets.append({"kind": "ws", "url": h[1], "score": 5.0,
                                   "method": "GET", "fields": [],
                                   "source": "cold:crawl"})
    ctx["coverage"]["surface"] = ("csrf=%d cors=%d frame=%d pm=%d oauth=%d "
                                  "storage=%d ws=%d"
                                  % (len(csrf_targets), len(cors_targets),
                                     len(frame_targets), len(pm_targets),
                                     len(oauth_targets), len(storage_targets),
                                     len(ws_targets)))
    ok("%d client targets total (%s)" % (len(ranked), ctx["coverage"]["surface"]))
    if not ranked:
        err("Koi client-side target nahi mila. P2/P7/P10 pehle chalao (forms/dom/"
            "csrf seeds bante hain) ya scope.json check karo.")
        F.add("client_surface_sparse", "Client surface khali", scope.describe(),
              "seed artifacts nahi mile - P2 (forms) + P7 (dom/pm/storage) + P10 "
              "(csrf_mapping) chalao.", evidence_ref="client_surface.json")
        ctx["coverage"]["surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx, meta, {}, [], [], conf)
        return out

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: seeded census + offline "
             "hypotheses (0 network probes).")
        seeded = [t for t in csrf_targets if t.get("fields")]
        census_recs, get_logout, login_csrf, census_summary = [], [], [], {}
        if seeded:
            census_recs, get_logout, login_csrf, census_summary = csrf_census(
                http, seeded, conf, cp, meta)
        results_by_stage["csrf_matrix"] = {"data": census_recs}
        hyps = build_client_hypotheses([], [], census_summary)
        ctx["coverage"]["passive"] = "%d seeded targets, %d hypotheses" % (
            len(seeded), len(hyps))
        write_reports(out, scope, F, ctx, meta,
                      {"csrf_matrix": {"data": census_recs}}, hyps, ranked, conf)
        write_feedforward(out, PHASE, {"to_phase32_report": {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        write_manifest(out, PHASE, ["client_surface.json", "client_targets.txt",
                                    "csrf_matrix.json", "client_test_plan.md",
                                    "findings.json", "feedforward.json"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree(out)
        return out

    # ---------------- Stage B: baseline & calibration ----------------
    head("Stage B - Baseline & security-header calibration")
    first_url = (ranked[0].get("url") or "") if ranked else ""
    meta["origin"] = "{0.scheme}://{0.netloc}".format(
        urllib.parse.urlsplit(first_url)) if first_url else ""
    try:
        s404 = soft404_baseline(http, meta["origin"] or first_url)
        meta["soft404"] = bool(s404)
        ok("soft-404 baseline: %s" % ("set" if s404 else "flat"))
    except Exception as e:
        meta["soft404"] = None
        warn("soft-404 baseline skip: %s" % e)
    baselines, set_cookies = {}, []
    seen_ep = set()
    for t in ranked[:40]:
        ep = t["url"].split("?")[0]
        if ep in seen_ep or not ep.startswith("http"):
            continue
        seen_ep.add(ep)
        b = baseline_endpoint(http, ep, conf, cp, tag="b", meta=meta)
        if b.get("ok"):
            baselines[ep] = b
            for sc in (b.get("set_cookies") or []):
                if sc and sc not in set_cookies:
                    set_cookies.append(sc)
    ok("baselines: %d endpoints, %d unique Set-Cookie" % (len(baselines),
                                                          len(set_cookies)))

    # ---------------- Stage C: CSRF token census ----------------
    head("Stage C - CSRF token census (30+ patterns x form/meta/cookie/JS/header)")
    census_recs, get_logout, login_csrf, census_summary = csrf_census(
        http, csrf_targets, conf, cp, meta, page_js=ctx["page_js"])
    meta["census_records"] = len(census_recs)
    ok("census: %d records | no-token=%d | login-csrf=%d | get-logout=%d"
       % (len(census_recs), census_summary.get("no_token", 0),
          len(login_csrf), len(get_logout)))
    # census findings (capped)
    n_f = 0
    for rec in census_recs:
        if n_f >= 12:
            break
        has_tok = rec["token_in_form"] or rec["meta_token"] or rec["js_token"]
        if not has_tok:
            F.add("csrf_no_token_state_change",
                  "State-change endpoint par CSRF token nahi (%s)" % rec["method"],
                  rec["url"], "fields=%s | score=%s | source=%s" % (
                      rec["fields"][:6] or "-", rec["state_score"], rec["source"]),
                  evidence_ref="csrf_matrix.json")
            n_f += 1
        if rec.get("token_in_get") and n_f < 12:
            F.add("csrf_token_in_get", "CSRF token GET-URL me (leak surface)",
                  rec["url"], "token query-param me - Referer/log/history leak",
                  evidence_ref="csrf_matrix.json")
            n_f += 1
    for u in get_logout[:3]:
        F.add("csrf_logout_get", "GET-based logout (logout-CSRF possible)", u,
              "GET logout link - top-level navigation se force-logout (annoyance "
              "+ session cleanup attack)", evidence_ref="csrf_matrix.json")
    for rec in login_csrf[:3]:
        F.add("csrf_login", "Login-CSRF (login form token-less)", rec["url"],
              "attacker apne credentials se victim ko login thop sakta hai "
              "(login-CSRF)", evidence_ref="csrf_matrix.json")
    results_by_stage["census"] = {"data": census_summary}

    # ---------------- Stage D: SameSite + defense matrix + PoC ----------------
    head("Stage D - CSRF defense matrix (RoE-gated replay) + SameSite audit + PoC")
    seeded_cookies = mined.get("samesite_cookies", [])
    same_recs = samesite_audit(set_cookies, seeded_cookies)
    same_verdicts = samesite_verdicts(same_recs, F, meta)
    results_by_stage["samesite"] = {"data": same_verdicts}
    cookie_tossing_prereq(same_verdicts, F)
    csrf_mx = csrf_defense_matrix(http, census_recs, conf, cp, meta, F)
    results_by_stage["csrf_matrix"] = {"data": csrf_mx}
    # PoCs (CONFIRMED/SUSPECTED top-6)
    poc_n = 0
    for rec in csrf_mx:
        if poc_n >= 6:
            break
        if rec["verdict"] in ("CONFIRMED", "SUSPECTED"):
            poc = build_csrf_poc(rec, poc_n + 1, os.path.join(out, "csrf_poc"))
            if poc:
                ctx["pocs"].append(poc)
                rec["poc"] = poc
                poc_n += 1
    if poc_n:
        ok("CSRF PoC artifacts: %d (INERT, manual-submit)" % poc_n)

    # ---------------- Stage E: CORS misconfig matrix ----------------
    head("Stage E - CORS misconfig matrix (12 origin variants, GET/OPTIONS only)")
    cors_mx, cors_log = cors_matrix(http, cors_targets, conf, cp, meta, F)
    meta["cors_endpoints"] = len(cors_mx)
    results_by_stage["cors_matrix"] = {"data": cors_mx}
    results_by_stage["cors_log"] = {"data": cors_log}
    legacy = legacy_crossdomain_audit(http, meta["origin"] or first_url, conf,
                                      cp, meta, F)
    results_by_stage["legacy"] = {"data": legacy}

    # ---------------- Stage F: framing audit ----------------
    head("Stage F - Clickjacking & framing audit (XFO / frame-ancestors)")
    frame_mx, frame_pocs = framing_audit(http, frame_targets, conf, cp, meta, F, ctx)
    meta["frame_pages"] = len(frame_mx)
    results_by_stage["framing_matrix"] = {"data": frame_mx}
    ctx["pocs"].extend(frame_pocs)
    # defense census (COOP/COEP/CORP) from baselines
    coop_missing = sum(1 for b in baselines.values()
                       if not (b.get("headers") or {}).get("Cross-Origin-Opener-Policy"))
    if baselines and coop_missing == len(baselines):
        F.add("defense_census_missing", "COOP/COEP/CORP isolation headers absent",
              meta.get("origin", "-"), "%d/%d baseline endpoints par cross-origin "
              "isolation headers nahi (XS-leak/Spectre surface)" % (
                  coop_missing, len(baselines)),
              evidence_ref="framing_matrix.json")

    # ---------------- Stage G: postMessage trust boundary ----------------
    head("Stage G - postMessage trust boundary (origin validation + sinks)")
    dom_seed = [t["url"] for t in pm_targets if t.get("source", "").startswith("P13")]
    xss_dom_conf = dom_seed[:3] or []
    pm_recs = postmessage_audit(http, pm_targets, conf, cp, meta, F,
                                extra_pages_js=ctx["page_js"])
    results_by_stage["pm_audit"] = {"data": pm_recs}

    # ---------------- Stage H: storage & token exposure ----------------
    head("Stage H - Storage & token exposure chains (XSS->ATO narratives)")
    storage_recs = storage_chain_audit(http, storage_targets, conf, cp, meta, F,
                                       extra_pages_js=ctx["page_js"],
                                       xss_dom_conf=xss_dom_conf)
    results_by_stage["storage"] = {"data": storage_recs}

    # ---------------- Stage I: OAuth + WS + technique matrix ----------------
    head("Stage I - OAuth state audit + WebSocket + advanced technique matrix")
    oauth_recs = oauth_state_audit(http, oauth_targets, conf, cp, meta, F)
    results_by_stage["oauth"] = {"data": oauth_recs}
    ws_recs = ws_origin_audit(ws_targets, conf, meta, F)
    results_by_stage["ws"] = {"data": ws_recs}
    tm = technique_matrix(census_recs, cors_mx, frame_mx, pm_recs, oauth_recs,
                          same_verdicts, legacy, storage_recs,
                          ws_count=len(ws_targets))
    results_by_stage["techniques"] = {"data": tm}
    ok("technique matrix: %d rows" % len(tm))

    # ---------------- Stage J: chains & hypotheses ----------------
    head("Stage J - Kill-chains & manual-wave hypotheses")
    chains = build_client_chains(F, csrf_mx, cors_mx, frame_mx, pm_recs,
                                 oauth_recs, storage_recs, same_verdicts,
                                 xss_dom_conf)
    ctx["chains"] = chains
    hyps = build_client_hypotheses(csrf_mx, cors_mx, census_summary)
    for ch in chains:
        ok("CHAIN: %s [%s]" % (ch["name"], ch["severity"]))

    # ---------------- Stage K: reports ----------------
    head("Stage K - Reports (findings / matrices / PoC / catalog / feedforward)")
    ctx["coverage"]["probes"] = meta.get("probes_total", 0)
    write_reports(out, scope, F, ctx, meta, results_by_stage, hyps, ranked, conf)
    dur = time.time() - t_start
    ok("Phase 14 done: %d findings | %d probes | %.1fs | out=%s"
       % (len(F.items), meta.get("probes_total", 0), dur, out))
    return out


# ===========================================================================
# CLI (standalone entry - wasp.py ke through hi chalna recommended)
# ===========================================================================
def main():
    print("WASP mod_client.py (Phase 14 - Client-Side, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 14   (ya --module client)")
    print("  self-test : python3 test_mod_client.py")
    print("\n  RoE gates (config.json): csrf_allow_replay=false (default), "
          "client_ws_handshake=false (default)")
    print("  Detection-only: PoC artifacts INERT hain; koi auto-submit/real "
          "attack nahi.")


if __name__ == "__main__":
    main()
