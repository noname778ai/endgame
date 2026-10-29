#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP Module: mod_auth.py  |  Phase 9 - Authentication Testing (v10.0.0 ULTRA PRO MAX)
============================================================================
Authorized security testing ONLY. Scope firewall + rate limiter + request budget
+ evidence + checkpoint sab wasp_core se inherit hote hain, isliye har request
scope-check, rate-limit aur budget ke andar hi jaati hai.

STAGES
  A  Auth surface discovery .... Phase 8 priority queue + Phase 2 forms +
                                 Phase 7 endpoints + well-known paths (ranked)
  B  Probe & flow mapping ...... read-only GET: forms, CSRF, cookies, JWT,
                                 auth scheme, transport, redirect target
  C  CSRF token binding test ... 2 alag session se token -> session-bound hai
                                 ya static (NEW)
  D  User enumeration .......... DRF-v2 (shape fingerprint) + JSON error-code
                                 oracle (NEW) + robust timing (NEW)
  E  Lockout model ............. per-IP vs per-account vs global classify (NEW)
  F  Bypass matrix v2 .......... interleaved control probe ke saath, sirf tab
                                 jab throttle CONFIRM ho (NEW; v1 me bug tha)
  G  Password reset flow ....... generic-message, host-header injection,
                                 per-position token entropy + Hamming (NEW)
  H  MFA / OTP flow ............ status oracle, JSON oracle, OTP shape from form
                                 attributes, rate-limit, lockout
  I  Registration flow ......... static policy inference (NEW) + optional probe
  J  OAuth / OIDC .............. discovery doc, PKCE support (NEW),
                                 redirect_uri validation, missing state
  K  Session / transport / JWT . cookie prefix rules (NEW), duplicate cookie
                                 names (NEW), cleartext transport (NEW),
                                 JWT v2 + gated tamper probe (NEW)
  L  Auth state machine ........ Mermaid graph + endpoint inventory
  M  Reports ................... AUTH_FINDINGS.md, auth_test_plan.md
                                 (hypotheses + kill-tests + coverage matrix),
                                 findings.json, feedforward + MANIFEST

ULTRA PRO MAX ADDITIONS (v10)
  N  Injection / type oracle ... NoSQL operator ($ne/$gt), JSON type confusion
                                 (null/0/list/true), HPP (double + array),
                                 Content-Type confusion, method-override signal
  O  Reset poisoning v2 ........ per-header variants (X-Forwarded-Host, X-Host,
                                 X-Original-URL, X-Forwarded-Proto) + reset token
                                 HTTP-response disclosure flag
  P  CORS probe ................ Origin echo + credentials on auth endpoints
                                 (attacker-invalid.test origins, bounded)
  Q  Auth page hardening ....... clickjacking (XFO/frame-ancestors), cacheable
                                 auth response, referrer-policy, autocomplete,
                                 SameSite=None-without-Secure (passive, 0 req)
  R  Redirect & reflection ..... open-redirect (wasp-invalid host), reflected
                                 marker context, CRLF header-injection indicator
  S  JWT deep (offline) ........ jku/x5u/x5c/jwk header URLs, duplicate-claim
                                 parser discrepancy, long-lived token, HS256-vs-RS256
                                 confusion candidate (jwks known), token-in-URL
  T  SSO deep .................. SAML metadata surface, NextAuth/Auth.js
                                 providers, OAuth mix-up indicator, PKCE
                                 downgrade surface, redirect_uri path variant
  U  Defense composite score ... per-login brute-force defense score (0-6):
                                 generic-msg + rate-limit + lockout + captcha +
                                 CSRF + MFA -> stuffing readiness verdict

SAFETY FIX (v10): allow_active=False ab poora honor hota hai - Stage D/E/F/G/H/I
aur N/R sab skip hote hain (sirf discovery + passive analysis chalti hai).
v9 me ye sirf warning print karta tha par probes phir bhi chalte the.

STATISTICS (v1 me sirf MAD z-score tha)
  Welch t-test, Mann-Whitney U (tie-corrected), Cliff's delta (effect size),
  bootstrap CI for median difference, per-position token entropy, Hamming
  distance. Sab pure-Python - koi numpy/scipy nahi.

SAFETY VALVES
  * allow_active=True zaroori hai active stages ke liye.
  * Synthetic identifiers reserved TLD `.test` par bante hain (v1 me
    `example.com` fallback tha - wo galat tha).
  * Attempts hard-capped (auth_max_attempts).
  * Lockout sentinel mile to poora module ABORT (koi aur auth request nahi).
  * State-changing probes (duplicate registration) OFF by default.
  * Real users ko reset email bhejne wala probe OFF by default.
  * Token tamper probe sirf GET par, max 2 requests, gated.
  * Injection oracle sirf synthetic identifiers par; sirf ek bounded 'admin'
    operator probe (detection-style, koi session use nahi hota).
  * Open-redirect/CORS probes sirf never-routable `.test` hosts par.
  * Destructive operations kabhi nahi.
"""

import os
import re
import sys
import json
import math
import time
import random
import base64
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
                           shannon_entropy, sha1, host_of, median, mad, robust_z,
                           truncate, redact, module_ctx, write_feedforward,
                           write_manifest, info, ok, warn, err, head, C, VERSION)
except ImportError:
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    sys.exit(1)

NAME = "auth"
PHASE = "9-authentication"
PLAN_VERSION = "10.0.0"

# ---------------------------------------------------------------------------
# TUNABLES  (config.json se override ho sakte hain; module khud default rakhta hai)
# ---------------------------------------------------------------------------
DEFAULTS = {
    # v1 se compatible keys
    "auth_max_attempts": 6,
    "auth_timing_repeats": 3,
    "auth_bypass_probes": 4,
    "auth_reset_token_samples": 5,
    "auth_allow_registration_probe": False,
    "auth_allow_reset_probe": True,
    "auth_allow_heuristic_enum": True,
    # naye knobs (v9)
    "auth_surface_cap": 25,                    # max auth endpoints probed
    "auth_enum_identifiers": 5,                # plausible identifiers per endpoint
    "auth_use_phase8_priority": True,          # Phase 8 queue se targeting
    "auth_allow_reset_plausible_probe": False, # real users ko email na jaye
    "auth_allow_token_tamper_probe": True,     # JWT signature/alg=none (GET only)
    "auth_csrf_token_samples": 2,              # sessions for CSRF binding test
    "auth_stats_bootstrap": 400,               # bootstrap resamples
    "auth_stats_alpha": 0.05,                  # significance level
    "auth_allow_method_matrix": True,          # OPTIONS/HEAD (read-only) probing
    # v10 ULTRA PRO MAX knobs
    "auth_allow_injection_oracle": True,       # NoSQL/type-confusion/HPP/CT probes
    "auth_inject_probes": 10,                  # hard cap injection-oracle requests
    "auth_allow_cors_probe": True,             # Origin echo probe on auth endpoints
    "auth_cors_endpoints": 3,                  # kitne endpoints par CORS probe
    "auth_allow_redirect_probe": True,         # open-redirect + reflection + CRLF
    "auth_redirect_endpoints": 2,              # kitne login/reset endpoints par
    "auth_allow_header_poison": True,          # reset per-header poisoning variants
    "auth_allow_oauth_variants": True,         # redirect_uri path-traversal variant
    "auth_oauth_probes": 4,                    # max authorization-endpoint probes
    "auth_allow_reflection_probe": True,       # benign marker reflection check
}

# Reserved, never-routable TLD -> synthetic identifiers ke liye
SYNTH_DOMAIN = "wasp-invalid.test"

WELL_KNOWN_AUTH = [
    "/login", "/signin", "/sign-in", "/log-in", "/auth/login", "/api/login",
    "/api/auth/login", "/api/v1/auth/login", "/api/v2/auth/login", "/admin/login",
    "/user/login", "/account/login", "/session/new", "/j_security_check",
    "/register", "/signup", "/sign-up", "/auth/register", "/api/register",
    "/api/auth/signup", "/api/v1/register", "/account/create", "/users/new",
    "/forgot", "/forgot-password", "/password/forgot", "/password/reset",
    "/reset", "/reset-password", "/auth/forgot", "/api/auth/forgot",
    "/api/password/reset", "/account/recover", "/users/password/new",
    "/mfa", "/2fa", "/otp", "/verify", "/verify-otp", "/auth/mfa", "/auth/otp",
    "/totp", "/challenge", "/auth/verify",
    "/logout", "/signout", "/auth/logout",
    "/oauth/authorize", "/oauth/token", "/oauth2/authorize", "/connect/authorize",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/saml/login", "/saml2/login", "/saml/metadata", "/saml/metadata.xml",
    "/api/auth/session", "/api/auth/me", "/api/me",
    # v10 ULTRA PRO MAX: modern-stack discovery (NextAuth/Auth.js, JWKS, WordPress)
    "/jwks.json", "/.well-known/jwks.json", "/oauth/jwks.json",
    "/api/auth/providers", "/api/auth/csrf", "/api/auth/providers/auth0",
    "/wp-login.php", "/wp-json/wp/v2/users", "/api/users/me", "/auth/check",
]

AUTH_PATH_RE = re.compile(
    r"(?i)(/|_)(login|log-?in|signin|sign-?in|logout|signout|sign-?out|auth|authenticate|"
    r"authorize|authorization|session|sessions|register|signup|sign-?up|account/create|"
    r"password|passwd|forgot|reset|recover|mfa|2fa|otp|totp|verify|verification|"
    r"challenge|token|jwt|oauth|oidc|saml|sso|credential|apikey|api-?key|"
    r"j_security_check|users/password)")

LOGIN_HINT_RE = re.compile(r"(login|log-?in|signin|sign-?in|authenticate|session|j_security)", re.I)
RESET_HINT_RE = re.compile(r"(forgot|reset|recover|passwd|password)", re.I)
MFA_HINT_RE = re.compile(r"(mfa|2fa|otp|totp|verify|challenge|second[-_]?factor)", re.I)
REGISTER_HINT_RE = re.compile(r"(register|signup|sign-?up|create[-_]?account|account/create|users/new)", re.I)
OAUTH_HINT_RE = re.compile(r"(oauth|oidc|openid|saml|sso|authorize)", re.I)
SESSION_CHECK_RE = re.compile(r"(me$|whoami|session|profile|current[-_]?user|auth/status)", re.I)

# v10 ULTRA PRO MAX constants
REDIRECT_PARAMS = ("next", "return", "returnto", "return_to", "redirect", "redirect_uri",
                   "redirecturl", "redirect_url", "url", "goto", "go", "continue",
                   "continueurl", "target", "dest", "destination", "rurl", "rurl2",
                   "callback", "callbackurl", "forward", "link", "relaystate")
REDIRECT_PARAM_RE = re.compile(
    r"(?i)^(next|return|returnto|return_to|redirect|redirect_uri|redirecturl|redirect_url|"
    r"url|goto|go|continue|continueurl|target|dest|destination|rurl|callback|callbackurl|"
    r"forward|relaystate)$")
WEBAUTHN_RE = re.compile(
    r"(?i)(webauthn|navigator\.credentials|passkey[s]?|fido2?|publickey-credential|"
    r"platformauthenticator|authenticatorselection)")
CAPTCHA_RE = re.compile(r"(?i)(recaptcha|hcaptcha|turnstile|captcha|geetest|funcaptcha)")
NO_STORE_RE = re.compile(r"(?i)(no-store|private|max-age\s*=\s*0)")
CDN_HEADER_RE = re.compile(r"(?i)^(x-cache|x-varnish|x-drupal-cache|x-served-by|x-fastly-request-id|"
                           r"cf-cache-status|x-amz-cf-id|x-vercel-cache|x-proxy-cache|age|via)$")
JWT_URL_RE = re.compile(r"(?i)[?&](token|jwt|access_token|id_token|auth)=")
SAML_RE = re.compile(r"(?i)(samlrequest|samlresponse|samlmetadata|acsurl|entityid)")
NEXTAUTH_PATH_RE = re.compile(r"/api/auth/(providers|csrf|session)$")
WP_USERS_RE = re.compile(r"/wp-json/wp/v2/users?$")
INJECT_MARKERS = {"$ne": None, "$gt": "", "$regex": "^a", "$exists": True}
REFLECT_MARKER = "wasp9xq7"
CRLF_PROBE = "wasp%0d%0aX-Wasp-Probe:1"
INVALID_ORIGIN = "https://attacker-invalid.test"
NULL_ORIGIN = "null"
HARDEN_CDN_HINTS = ("x-cache", "cf-cache-status", "x-vercel-cache", "x-served-by", "via")

PLAUSIBLE_USERS = ["admin", "administrator", "root", "support", "info", "test",
                   "user", "guest", "demo", "operator"]

USERNAME_FIELDS = ["username", "user", "userid", "user_id", "email", "e-mail", "login",
                   "loginid", "account", "identifier", "uname", "phone", "mobile", "msisdn"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pwd", "passphrase", "secret", "pin"]
OTP_FIELDS = ["otp", "code", "token", "pin", "factor", "totp", "otpcode", "verification_code"]
CSRF_FIELDS_RE = re.compile(r"(csrf|xsrf|token|nonce|authenticity|requestverification|_token)", re.I)

FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
FIELD_RE = re.compile(r"<(input|select|textarea)\b[^>]*>", re.I)
ATTR_RE = re.compile(r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{0,})")

LOCKOUT_RE = re.compile(
    r"(?i)(too many (failed )?attempts?|account (has been )?lock|temporarily lock|"
    r"try again (later|in \d)|rate limit|slow down|throttl|blocked|captcha|"
    r"security check|unusual activity|suspicious activity|maximum attempts)")
ENUM_MSG_RE = re.compile(
    r"(?i)(user(n[au]me)? (not found|does not exist|doesn'?t exist|unknown|invalid)|"
    r"no such (user|account)|account (not found|does not exist|doesn'?t exist)|"
    r"email (not found|not registered|does not exist)|incorrect password|wrong password|"
    r"invalid password|password (is )?incorrect|already (taken|registered|exists)|"
    r"email already|username (taken|exists))")
GENERIC_MSG_RE = re.compile(
    r"(?i)(invalid (credentials|username or password|login|email or password)|"
    r"login failed|authentication failed|incorrect (username|email) or password|"
    r"unable to (log ?in|sign ?in)|please (check|try again)|check your (email|inbox)|"
    r"if (the )?(account|email) exists|we (have )?sent|instructions have been sent)")
ERROR_KEY_RE = re.compile(r"(?i)^(error|errors|err|code|errorcode|error_code|detail|details|"
                          r"message|msg|reason|status|type|title|field|fieldname|key|description)$")
DEBUG_LEAK_RE = re.compile(r"(?i)(traceback \(most recent call last\)|stack trace|"
                           r"at [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)|"
                           r"Warning: .* on line \d+|System\.Exception|"
                           r"django\.core\.exceptions|werkzeug\.debug|SQLSTATE\[)")

SEVERITY_HINTS = {
    "no_rate_limit": ("Medium", "CVSS ~5.3", "Credential stuffing aur brute-force ko koi control nahi rokta."),
    "lockout_bypass": ("High", "CVSS ~7.5", "Throttling ko header/identifier mutation se bypass kiya ja sakta hai."),
    "user_enumeration": ("Medium", "CVSS ~5.3", "Valid usernames enumerate ho sakte hain - targeted attacks aasan."),
    "timing_enumeration": ("Low", "CVSS ~3.7", "Response timing account existence leak karti hai."),
    "json_oracle_enumeration": ("Medium", "CVSS ~5.3", "JSON error codes account existence batate hain."),
    "reset_token_weak": ("High", "CVSS ~8.1", "Predictable reset token -> account takeover ka raasta."),
    "reset_host_header_injection": ("High", "CVSS ~7.5", "Host header reset link me reflect hota hai -> token theft."),
    "reset_enumeration": ("Medium", "CVSS ~5.3", "Reset endpoint account existence leak karta hai."),
    "mfa_status_oracle": ("Medium", "CVSS ~5.3", "MFA state status code se leak hota hai."),
    "mfa_no_ratelimit": ("High", "CVSS ~7.5", "OTP verification par rate limit nahi -> OTP brute-force."),
    "mfa_weak_otp_policy": ("Medium", "CVSS ~5.9", "OTP length/format kamzor hai."),
    "registration_enumeration": ("Low", "CVSS ~3.7", "Registration duplicate check account existence leak karta hai."),
    "cookie_flags_missing": ("Medium", "CVSS ~4.3", "Session cookie hardening missing -> session theft."),
    "cookie_prefix_violation": ("Medium", "CVSS ~4.3", "Cookie name prefix (__Host-/__Secure-) ke rules violate hue."),
    "duplicate_cookie_names": ("Medium", "CVSS ~5.4", "Same naam ke multiple cookies -> session fixation/tossing."),
    "preauth_jwt_weak": ("High", "CVSS ~7.5", "Pre-auth JWT me weak alg ya missing expiry."),
    "jwt_alg_none_accepted": ("Critical", "CVSS ~9.1", "alg=none JWT accept hua -> complete auth bypass."),
    "jwt_signature_not_verified": ("Critical", "CVSS ~9.1", "Tampered signature accept hua -> auth bypass."),
    "jwt_sensitive_claims": ("Medium", "CVSS ~5.3", "JWT me privilege claims plaintext me hain."),
    "jwt_kid_injection": ("High", "CVSS ~7.5", "kid/jku header injection ke indicators mile."),
    "cleartext_auth_transport": ("High", "CVSS ~8.1", "Login HTTP par hai -> credentials plaintext me jaate hain."),
    "csrf_token_static": ("Medium", "CVSS ~6.5", "CSRF token session-bound nahi -> cross-session reuse."),
    "csrf_missing": ("Medium", "CVSS ~5.4", "Auth form me CSRF token nahi mila."),
    "weak_auth_scheme": ("Medium", "CVSS ~5.3", "Basic/NTLM jaise weak scheme expose hue."),
    "oauth_redirect_uri_loose": ("High", "CVSS ~7.4", "redirect_uri validation loose -> authorization code theft."),
    "oauth_no_pkce": ("Medium", "CVSS ~5.9", "PKCE support nahi -> public client me code interception."),
    "oauth_implicit_flow": ("Medium", "CVSS ~5.3", "Implicit flow enabled -> token URL fragment me."),
    "oauth_missing_state": ("Medium", "CVSS ~5.3", "Authorization URL me state param nahi -> CSRF."),
    "password_policy_weak": ("Low", "CVSS ~3.1", "Client-side password policy kamzor ya missing."),
    "sensitive_error_disclosure": ("Low", "CVSS ~3.7", "Auth endpoint stack trace/debug info leak karta hai."),
    "registration_open": ("Info", "-", "Registration khula hai - attack surface note karo."),
    # ---- v10 ULTRA PRO MAX findings ----
    "nosql_operator_accepted": ("Critical", "CVSS ~9.1",
                                "NoSQL operator ($ne/$gt) login bypass de sakta hai - auth logic operator query ko value maan rahi hai."),
    "json_type_confusion_signal": ("Medium", "CVSS ~5.9",
                                   "JSON types (null/list/int) par login endpoint ka behaviour badalta hai - type-juggling bypass ka indicator."),
    "hpp_response_diff": ("Low", "CVSS ~3.7",
                          "Parameter pollution se response badalta hai - parser confusion hai, WAF/auth rules dodge ho sakte hain."),
    "content_type_behavior_diff": ("Low", "CVSS ~3.7",
                                   "Form vs JSON body par endpoint alag behave karta hai - validation bypass ka raasta."),
    "cors_cred_reflection": ("High", "CVSS ~7.5",
                             "Arbitrary Origin reflect hota hai credentials ke saath - koi bhi site authenticated data padh sakti hai."),
    "cors_wildcard": ("Medium", "CVSS ~5.4",
                      "Access-Control-Allow-Origin: * auth endpoint par - public data leak (credentials ke saath to Critical)."),
    "auth_clickjacking": ("Low", "CVSS ~3.7",
                          "Login page framing se bacha nahi - login-CSRF/UI-redress possible."),
    "auth_response_cacheable": ("Medium", "CVSS ~4.3",
                                "Auth page cache-control ke bina serve hota hai + CDN hints - shared cache me sensitive data cache ho sakta hai."),
    "password_autocomplete_on": ("Info", "-",
                                 "Password field par autocomplete on hai - shared systems par risk (policy note)."),
    "auth_open_redirect": ("Medium", "CVSS ~6.1",
                           "Login/reset redirect param externally-controlled redirect karta hai - phishing + token leak chain."),
    "auth_reflected_input": ("Medium", "CVSS ~5.4",
                             "Auth page query input ko reflect karta hai - pre-auth XSS candidate (manual confirm karo)."),
    "crlf_injection_auth": ("High", "CVSS ~7.5",
                            "CRLF sequence response headers me inject hua - response splitting / session fixation."),
    "reset_token_disclosure": ("Critical", "CVSS ~9.1",
                               "Password-reset token HTTP response me visible hai - MITM/proxy/logs se ATO."),
    "reset_header_poison_extended": ("High", "CVSS ~7.5",
                                     "X-Original-URL/X-Forwarded-* se reset link poison hua - host-header ATO chain."),
    "jwt_key_injection_headers": ("High", "CVSS ~7.5",
                                  "JWT header me jku/x5u/x5c/jwk URL hai - server attacker-controlled key ya SSRF accept kar sakta hai."),
    "jwt_duplicate_claims": ("Medium", "CVSS ~5.9",
                             "JWT payload me duplicate claims hain - parser discrepancy ke saath privilege confusion possible."),
    "jwt_long_lived": ("Low", "CVSS ~3.7",
                       "Pre-auth token ki validity bahut lambi hai (24h+) - theft window bada."),
    "jwt_hs256_confusion_candidate": ("Medium", "CVSS ~5.9",
                                      "RS256 token + public JWKS endpoint - HS256 key-confusion offline try karo (wasp_config bypass jwt)."),
    "oauth_pkce_downgrade_surface": ("Low", "CVSS ~3.7",
                                     "PKCE optional lag raha hai - public client me downgrade/code-interception ka surface."),
    "oauth_mixup_indicator": ("Medium", "CVSS ~5.9",
                              "Ek se zyada issuer/authorization endpoint mila - mix-up attack ka surface."),
    "saml_surface_detected": ("Info", "-",
                              "SAML endpoints/metdata mile - SAML-specific attacks (wrapper/signature wrapping) manual phase me."),
    "nextauth_surface": ("Info", "-",
                         "NextAuth/Auth.js endpoints mile - provider disclosure + v4 endpoint quirks check karo."),
    "wordpress_users_exposed": ("Medium", "CVSS ~5.3",
                                "WP REST /users endpoint usernames dump karta hai - enumeration + password spraying feed."),
    "webauthn_detected": ("Info", "-",
                          "WebAuthn/passkeys detect hue - downgrade/registration-bypass flows manual check karo."),
    "brute_force_defense_weak": ("Medium", "CVSS ~5.3",
                                 "Login defense composite score kamzor hai - credential stuffing ka easy target."),
    "token_in_url_transport": ("Low", "CVSS ~3.1",
                               "Token query string me jaata hai - Referer/browser history/proxy logs me leak."),
}


def classify_severity(key):
    return SEVERITY_HINTS.get(key, ("Info", "-", ""))


# ---------------------------------------------------------------------------
# MODULE STATE
# ---------------------------------------------------------------------------
class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "AUTH-%03d" % (len(self.items) + 1), "key": key, "title": title,
               "severity": sev, "cvss_hint": cvss, "endpoint": endpoint,
               "detail": detail, "why_it_matters": why,
               "evidence": evidence_ref, "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


# ---------------------------------------------------------------------------
# PURE HELPERS (unit-testable, koi network nahi)
# ---------------------------------------------------------------------------
def attrs_of(tag):
    out = {}
    for m in ATTR_RE.finditer(tag or ""):
        name = m.group(1).lower()
        val = (m.group(2) if m.group(2) is not None
               else (m.group(3) if m.group(3) is not None else (m.group(4) or "")))
        out[name] = val
    return out


def parse_forms(html, base_url=""):
    """HTML se forms + fields nikalo. Pure function."""
    forms, html = [], (html or "")
    for fm in FORM_RE.finditer(html):
        end = html.find(">", fm.start())
        head_tag = html[fm.start():end + 1] if end != -1 else fm.group(0)
        a = attrs_of(head_tag)
        action = urllib.parse.urljoin(base_url, a.get("action") or base_url)
        method = (a.get("method") or "get").upper()
        fields = []
        for im in FIELD_RE.finditer(fm.group(1)):
            ia = attrs_of(im.group(0))
            fname = ia.get("name", "")
            if not fname:
                continue
            fields.append({"name": fname,
                           "type": (ia.get("type") or im.group(1).lower()).lower(),
                           "value": ia.get("value", ""),
                           "maxlength": ia.get("maxlength", ""),
                           "pattern": ia.get("pattern", ""),
                           "autocomplete": ia.get("autocomplete", ""),
                           "required": "required" in im.group(0).lower()})
        forms.append({
            "action": action, "method": method, "enctype": a.get("enctype", ""),
            "field_names": [f["name"] for f in fields],
            "has_password": any(f["type"] == "password" for f in fields),
            "password_count": sum(1 for f in fields if f["type"] == "password"),
            "csrf_fields": [f["name"] for f in fields if CSRF_FIELDS_RE.search(f["name"])],
            "fields": fields,
        })
    return forms


def guess_fields(field_names):
    """Kaunsa field identifier hai aur kaunsa password - guess karo."""
    user_f, pass_f = None, None
    for n in field_names or []:
        ln = n.lower()
        if pass_f is None and any(p in ln for p in PASSWORD_FIELDS):
            pass_f = n
        if user_f is None and any(u in ln for u in USERNAME_FIELDS):
            user_f = n
    return user_f, pass_f


def guess_otp_field(field_names):
    for n in field_names or []:
        if any(o in n.lower() for o in OTP_FIELDS):
            return n
    return (field_names or ["otp"])[0]


def title_of(html):
    m = TITLE_RE.search(html or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def synth_identifier(kind="nonexistent"):
    """Reserved TLD par synthetic identifier - real domain ko chhoota hi nahi."""
    return "wasp-%s-%s@%s" % (kind, rand_str(6), SYNTH_DOMAIN)


# ---------------------------------------------------------------------------
# STATISTICS (pure python; numpy/scipy ki zaroorat nahi)
# ---------------------------------------------------------------------------
def shingle_sim(a, b, k=4):
    """Character-shingle Jaccard. 1.0 = identical."""
    def sh(s):
        s = re.sub(r"\s+", " ", s or "")
        return set(s[i:i + k] for i in range(max(0, len(s) - k + 1)))
    A, B = sh(a), sh(b)
    if not A and not B:
        return 1.0
    if not A or not B:
        return 0.0
    return len(A & B) / float(len(A | B))


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else 0.0


def variance(xs):
    xs = [x for x in xs if x is not None]
    n = len(xs)
    if n < 2:
        return 0.0
    m = mean(xs)
    return sum((x - m) ** 2 for x in xs) / (n - 1)


def welch_t(a, b):
    """Welch t-test -> (t, approx_df). Equal variance assume nahi karta."""
    a = [x for x in a if x is not None]
    b = [x for x in b if x is not None]
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0, 0.0
    va, vb = variance(a), variance(b)
    denom = math.sqrt(va / na + vb / nb)
    if denom <= 0:
        return 0.0, 0.0
    t = (mean(a) - mean(b)) / denom
    num = (va / na + vb / nb) ** 2
    den = (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1)
    df = num / den if den > 0 else 0.0
    return t, df


def mannwhitney_u(a, b):
    """Rank-sum U + normal approximation p-value (tie-corrected)."""
    a = [x for x in a if x is not None]
    b = [x for x in b if x is not None]
    na, nb = len(a), len(b)
    if na == 0 or nb == 0:
        return 0.0, 1.0, 0.0
    pool = [(x, 0) for x in a] + [(x, 1) for x in b]
    pool.sort(key=lambda p: p[0])
    ranks, i, tie_corr = [0.0] * len(pool), 0, 0.0
    while i < len(pool):
        j = i
        while j + 1 < len(pool) and pool[j + 1][0] == pool[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        if j > i:
            tie_corr += (j - i + 1) ** 3 - (j - i + 1)
        i = j + 1
    ra = sum(ranks[k] for k in range(len(pool)) if pool[k][1] == 0)
    ua = ra - na * (na + 1) / 2.0
    ub = na * nb - ua
    u = min(ua, ub)
    mu = na * nb / 2.0
    n = na + nb
    sigma = math.sqrt((na * nb / 12.0) * ((n + 1) - tie_corr / float(n * (n - 1) or 1)))
    if sigma <= 0:
        return u, 1.0, 0.0
    z = (u - mu) / sigma
    p = math.erfc(abs(z) / math.sqrt(2.0))
    return u, min(1.0, p), z


def cliffs_delta(a, b):
    """Effect size: -1..1. |d|>=0.474 = large, >=0.33 medium, >=0.147 small."""
    a = [x for x in a if x is not None]
    b = [x for x in b if x is not None]
    if not a or not b:
        return 0.0
    gt = lt = 0
    for x in a:
        for y in b:
            if x > y:
                gt += 1
            elif x < y:
                lt += 1
    return (gt - lt) / float(len(a) * len(b))


def cliffs_label(d):
    ad = abs(d)
    return "large" if ad >= 0.474 else "medium" if ad >= 0.33 else "small" if ad >= 0.147 else "negligible"


def bootstrap_median_ci(a, b, resamples=400, alpha=0.05, rng=None):
    """Median difference ka bootstrap CI (deterministic seed)."""
    a = [x for x in a if x is not None]
    b = [x for x in b if x is not None]
    if len(a) < 2 or len(b) < 2:
        return None
    rng = rng or random.Random(1337)
    diffs = []
    for _ in range(int(resamples)):
        sa = [a[rng.randrange(len(a))] for _ in range(len(a))]
        sb = [b[rng.randrange(len(b))] for _ in range(len(b))]
        diffs.append(median(sa) - median(sb))
    diffs.sort()
    lo = diffs[int((alpha / 2) * len(diffs))]
    hi = diffs[min(len(diffs) - 1, int((1 - alpha / 2) * len(diffs)))]
    return {"median_diff": round(median(diffs), 6), "ci_low": round(lo, 6),
            "ci_high": round(hi, 6), "excludes_zero": (lo > 0 or hi < 0),
            "resamples": int(resamples)}


def jittered_values(xs, rng=None):
    """Tied values ko halka jitter do -> rank tests ko help karta hai."""
    rng = rng or random.Random(4242)
    return [x + rng.uniform(-1e-6, 1e-6) for x in xs]


def timing_verdict(plausible, bogus, alpha=0.05, resamples=400):
    """
    Ek hi jagah saare timing tests. Ye v1 ke 'sirf MAD z-score' se aage hai:
      * Welch t-test  -> mean shift
      * Mann-Whitney U -> rank shift (outlier-robust)
      * Cliff's delta -> effect size (practical significance)
      * bootstrap CI  -> median difference ka confidence interval
    """
    p = [x for x in plausible if x is not None]
    b = [x for x in bogus if x is not None]
    out = {"n_plausible": len(p), "n_bogus": len(b),
           "median_plausible_ms": round(median(p) * 1000, 1) if p else None,
           "median_bogus_ms": round(median(b) * 1000, 1) if b else None}
    if len(p) < 2 or len(b) < 2:
        out["verdict"] = "insufficient-samples"
        return out
    med_b = median(b)
    m_b = mad(b, med_b)
    z = robust_z(median(p), med_b, m_b) if m_b > 0 else 0.0
    t, df = welch_t(p, b)
    u, pu, uz = mannwhitney_u(jittered_values(p), jittered_values(b))
    d = cliffs_delta(p, b)
    ci = bootstrap_median_ci(p, b, resamples=resamples)
    out.update({"robust_z": round(z, 2), "welch_t": round(t, 3), "welch_df": round(df, 1),
                "mw_u": round(u, 2), "mw_p": round(pu, 5), "mw_z": round(uz, 3),
                "cliffs_delta": round(d, 3), "cliffs_size": cliffs_label(d),
                "median_diff_ms": round((median(p) - med_b) * 1000, 1),
                "bootstrap": ci})
    sig = (pu < alpha) or (abs(z) > 3.5)
    meaningful = abs(d) >= 0.147
    out["timing_anomaly"] = bool(sig and meaningful)
    out["verdict"] = ("TIMING-SIGNAL" if out["timing_anomaly"] else
                      "weak" if sig else "no-signal")
    if sig and not meaningful:
        out["note"] = "statistically detectable but effect size chhota (practical value kam)"
    return out


def token_predictability(tokens):
    """Token samples me entropy, shared prefix, sequence aur Hamming distance."""
    out = {"samples": len(tokens), "unique": len(set(tokens)), "notes": []}
    if not tokens:
        return out
    out["entropies"] = [round(shannon_entropy(t), 3) for t in tokens]
    out["min_entropy"] = min(out["entropies"])
    out["avg_entropy"] = round(mean(out["entropies"]), 3)
    out["lengths"] = sorted(set(len(t) for t in tokens))
    pref = 0
    for i in range(min(len(t) for t in tokens)):
        if len(set(t[i] for t in tokens)) == 1:
            pref += 1
        else:
            break
    out["shared_prefix_len"] = pref
    if pref >= 4:
        out["notes"].append("shared prefix %d chars -> token me predictable hissa" % pref)
    # per-position entropy
    L = min(len(t) for t in tokens)
    pos_ent = []
    for i in range(L):
        col = [t[i] for t in tokens]
        pos_ent.append(round(shannon_entropy("".join(col)), 3))
    out["per_position_entropy"] = pos_ent
    low_pos = [i for i, e in enumerate(pos_ent) if e < 1.0]
    if len(tokens) >= 3 and low_pos:
        out["low_entropy_positions"] = low_pos[:12]
        out["notes"].append("%d position(s) me <1.0 entropy" % len(low_pos))
    # pairwise Hamming distance
    if len(tokens) >= 2:
        base = tokens[0]
        hams = []
        for t in tokens[1:]:
            m = min(len(base), len(t))
            hams.append(sum(1 for i in range(m) if base[i] != t[i]))
        out["hamming_from_first"] = hams
        out["min_hamming"] = min(hams)
        if min(hams) <= 1:
            out["notes"].append("do tokens me sirf %d char ka farq -> high collision" % min(hams))
    # numeric tail sequence
    tails = []
    for t in tokens:
        m = re.search(r"(\d{4,})$", t)
        if m:
            tails.append(int(m.group(1)))
    if len(tails) >= 2:
        diffs = [tails[i + 1] - tails[i] for i in range(len(tails) - 1)]
        if diffs and all(abs(d) <= 1 for d in diffs):
            out["sequential"] = True
            out["notes"].append("numeric tail <=1 increment (sequential token)")
        elif len(set(abs(d) for d in diffs)) == 1 and abs(diffs[0]) < 1000:
            out["notes"].append("numeric tail constant delta %d" % diffs[0])
    if out["min_entropy"] < 3.0:
        out["notes"].append("min entropy <3.0 -> weak token")
    out["weak"] = bool(out.get("sequential") or out["min_entropy"] < 3.0 or pref >= 4
                       or out.get("min_hamming", 99) <= 1)
    return out


def normalize_username_variants(user, domain=SYNTH_DOMAIN):
    """Identifier normalization mutations (rate-limit bypass probes ke liye)."""
    base = user or "waspuser"
    local = base.split("@")[0]
    return {
        "original": base,
        "upper": local.upper(),
        "mixed": local.capitalize(),
        "plus_tag": "%s+%s@%s" % (local, rand_str(4), domain),
        "dot_variant": "%s.%s@%s" % (local, rand_str(3), domain),
        "trailing_space": base + " ",
        "leading_space": " " + base,
        "double_at": local + "@@" + domain,
        "unicode_fullwidth": local + "\uff20" + domain,
    }


def b64url_decode_json(seg):
    try:
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode()).decode("utf-8", "ignore"))
    except Exception:
        return None


def b64url_encode(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt_info(tok):
    parts = (tok or "").split(".")
    hdr = b64url_decode_json(parts[0]) if len(parts) > 0 else None
    pay = b64url_decode_json(parts[1]) if len(parts) > 1 else None
    priv_claims = [k for k in (pay or {}) if re.search(
        r"(?i)(admin|role|roles|scope|scopes|perm|privilege|is_?admin|group|tier|plan|"
        r"credit|balance|tenant|org)", k)]
    return {
        "preview": (tok[:20] + "...") if tok and len(tok) > 20 else tok,
        "length": len(tok or ""),
        "entropy": round(shannon_entropy(tok or ""), 3),
        "alg": (hdr or {}).get("alg"),
        "typ": (hdr or {}).get("typ"),
        "kid": (hdr or {}).get("kid"),
        "jku": (hdr or {}).get("jku"),
        "header_keys": sorted((hdr or {}).keys()),
        "payload_keys": sorted((pay or {}).keys()),
        "privilege_claims": priv_claims,
        "has_exp": bool((pay or {}).get("exp")),
        "has_iat": bool((pay or {}).get("iat")),
        "has_nbf": bool((pay or {}).get("nbf")),
        "iss": (pay or {}).get("iss"),
        "aud": (pay or {}).get("aud"),
        "has_third_segment": len(parts) == 3 and bool(parts[2]),
        "header": hdr,
        "payload": pay,
    }


def find_jwts(text):
    seen, out = set(), []
    for m in JWT_RE.finditer(text or ""):
        t = m.group(0)
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def detect_lockout(status, text, headers):
    """(bool, reason). Ek generic 401 ko lockout nahi maanta."""
    if status in (429, 423):
        return True, "http-%d" % status
    ra = ""
    for k, v in (headers or {}).items():
        if k.lower() == "retry-after":
            ra = v
    if ra:
        return True, "retry-after:%s" % ra
    m = LOCKOUT_RE.search(text or "")
    if m:
        return True, "msg:" + re.sub(r"\s+", " ", m.group(1)).lower()
    return False, ""


def drf_compare(a, b):
    """
    Differential Response Fingerprinting v2.
    v1 me sirf status+title+similarity+len tha. v2 me JSON error-code oracle,
    redirect target, WWW-Authenticate aur debug-leak bhi compare hote hain.
    """
    la, lb = len(a.body), len(b.body)
    sig = {
        "status_a": a.status, "status_b": b.status, "status_same": a.status == b.status,
        "len_a": la, "len_b": lb, "len_delta": abs(la - lb),
        "len_ratio": round(min(la, lb) / float(max(1, max(la, lb))), 4),
        "title_a": title_of(a.text), "title_b": title_of(b.text),
        "title_same": title_of(a.text) == title_of(b.text),
        "body_similarity": round(shingle_sim(a.text, b.text), 4),
        "ct_a": a.header("Content-Type"), "ct_b": b.header("Content-Type"),
        "loc_a": a.header("Location"), "loc_b": b.header("Location"),
        "loc_same": a.header("Location") == b.header("Location"),
        "www_a": a.header("WWW-Authenticate"), "www_b": b.header("WWW-Authenticate"),
    }
    score = 0
    if not sig["status_same"]:
        score += 40
    if not sig["title_same"]:
        score += 15
    if not sig["loc_same"]:
        score += 12
    score += int((1.0 - sig["body_similarity"]) * 100)
    if sig["len_delta"] > 32:
        score += 10
    ja, jb = a.json(None), b.json(None)
    if isinstance(ja, dict) and isinstance(jb, dict):
        ea, eb = _json_error_shape(ja), _json_error_shape(jb)
        sig["json_a"] = ea
        sig["json_b"] = eb
        sig["json_oracle"] = bool(ea and eb and ea != eb)
        if sig["json_oracle"]:
            score += 25
    sig["diff_score"] = max(0, min(score, 100))
    sig["verdict"] = ("DIFFERENT" if sig["diff_score"] >= 30 else
                      "SUSPICIOUS" if sig["diff_score"] >= 12 else "SAME")
    return sig


def _json_error_shape(doc):
    """JSON error response ka 'fingerprint' - enumeration oracle ke liye."""
    out = {}
    def walk(obj, prefix="", depth=0):
        if depth > 3:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if ERROR_KEY_RE.match(str(k)):
                    if isinstance(v, (str, int, bool)) or v is None:
                        out[prefix + str(k).lower()] = str(v)[:60]
                    else:
                        walk(v, prefix + str(k).lower() + ".", depth + 1)
                elif isinstance(v, (dict, list)) and depth < 2:
                    walk(v, prefix + str(k).lower() + ".", depth + 1)
        elif isinstance(obj, list):
            for item in obj[:3]:
                walk(item, prefix, depth + 1)
    walk(doc)
    return out


def analyze_cookie(raw_cookie, is_https=True):
    """Cookie flags + __Host-/__Secure- prefix rules + scope analysis."""
    parts = (raw_cookie or "").split(";")
    head = parts[0]
    name = (head.split("=")[0] or "").strip()
    low = raw_cookie.lower()
    flags = {"httponly": "httponly" in low, "secure": "secure" in low,
             "samesite": "samesite" in low, "samesite_value": "",
             "domain": "", "path": "", "max_age": None, "expires": None}
    m = re.search(r"samesite\s*=\s*([a-z]+)", low)
    if m:
        flags["samesite_value"] = m.group(1)
    m = re.search(r"domain\s*=\s*([^;]+)", low)
    if m:
        flags["domain"] = m.group(1).strip()
    m = re.search(r"path\s*=\s*([^;]+)", low)
    if m:
        flags["path"] = m.group(1).strip()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    if m:
        flags["max_age"] = int(m.group(1))
    sessionish = bool(re.search(r"(sess|sid|jsessionid|phpsessid|asp\.net|token|auth|jwt|"
                                r"remember|logged)", name, re.I))
    missing = []
    if sessionish:
        if not flags["httponly"]:
            missing.append("HttpOnly")
        if is_https and not flags["secure"]:
            missing.append("Secure")
        if not flags["samesite"] or flags["samesite_value"] == "none":
            missing.append("SameSite")
    violations = []
    if name.startswith("__Host-"):
        if not flags["secure"]:
            violations.append("__Host- bina Secure")
        if flags["domain"]:
            violations.append("__Host- par Domain set hai")
        if flags["path"] not in ("", "/"):
            violations.append("__Host- par Path=%s (must be /)" % flags["path"])
    if name.startswith("__Secure-") and not flags["secure"]:
        violations.append("__Secure- bina Secure")
    return {"name": name, "flags": flags, "session_like": sessionish,
            "missing": missing, "prefix_violations": violations,
            "cookie_scope": ("domain-wide" if flags["domain"].startswith(".")
                             else "host-only" if flags["domain"] else "unset")}


def classify_lockout_model(status_series, reasons, identifiers_used):
    """
    Lockout model classify karo: per-IP / per-account / global / none.
    Ye v1 me nahi tha - v1 sirf 'throttled=True' kehta tha.
    """
    if not status_series:
        return "none", "koi attempt nahi hua"
    if not any(r for r in reasons if r):
        return "none", "throttle ka koi signal nahi"
    distinct_idents = len(set(identifiers_used or []))
    distinct_ips = 1
    if distinct_idents > 1:
        return ("global-or-per-IP",
                "%d alag identifiers par bhi throttle aaya -> per-account nahi lag raha" % distinct_idents)
    return ("per-account-or-per-IP", "ek hi identifier par throttle - per-account ya per-IP")


def build_hypotheses(F, enum_report, rl_report, reset_report, mfa_report, reg_report,
                     oauth_report, cookie_report, jwt_report, csrf_report, live,
                     inj_report=None, redir_report=None, hard_report=None, jwt_deep=None,
                     cors_report=None):
    """
    Testable hypotheses + kill-tests. Ye wahi methodology hai jo Phase 8 me thi,
    ab auth findings ke liye.
    """
    H = []

    def add(hid, statement, because, kill, phase):
        H.append({"id": hid, "hypothesis": statement, "because": because,
                  "kill_test": kill, "next_phase": phase})

    for u, r in (enum_report.get("endpoints") or {}).items():
        if r.get("enumeration_likely"):
            add("H-ENUM-%s" % sha1(u)[:4],
                "%s account existence leak karta hai" % u,
                r.get("summary", ""),
                "Ek hi synthetic identifier ko 3 baar bhejo; agar responses bilkul same aa jayein "
                "aur timing overlap kare to hypothesis REJECT karo.",
                "10-sessions")
    for u, r in (rl_report or {}).items():
        if not r.get("throttled"):
            add("H-RL-%s" % sha1(u)[:4],
                "%s par effective rate limiting nahi hai" % u,
                r.get("summary", ""),
                "Dheere-dheere (5s gap) 10 attempts karo; agar lockout/429 aa jaye to REJECT karo.",
                "9-auth")
        if r.get("throttled") and (r.get("bypass_matrix") or {}).get("bypass_likely"):
            add("H-BYP-%s" % sha1(u)[:4],
                "%s ka throttling header/identifier mutation se bypass ho sakta hai" % u,
                (r.get("bypass_matrix") or {}).get("summary", ""),
                "Control probe (bina header, same identifier) bhejo; agar wo bhi pass ho jaye "
                "to bypass claim REJECT karo (throttle hi nahi tha).",
                "9-auth")
    for u, r in (reset_report or {}).items():
        if r.get("host_header_reflected"):
            add("H-HOST-%s" % sha1(u)[:4],
                "Reset link me Host header inject ho sakta hai",
                "Injected host response me reflect hua",
                "Ek aur different injected host try karo; agar wo reflect na ho to REJECT karo.",
                "15-ssrf")
        if (r.get("token") or {}).get("weak"):
            add("H-TOK-%s" % sha1(u)[:4],
                "%s ka reset token predictable hai" % u,
                json.dumps(r.get("token", {}), default=str)[:180],
                "Kam se kam 3 aur token sample lo; agar Hamming distance badh jaye to REJECT karo.",
                "9-auth")
    for u, r in (mfa_report or {}).items():
        if r.get("no_ratelimit"):
            add("H-MFA-%s" % sha1(u)[:4],
                "%s par OTP brute-force possible hai (rate limit nahi)" % u,
                r.get("summary", ""),
                "10 attempts ke baad bhi 200 mile to confirm; agar koi bhi throttle signal aaye to REJECT.",
                "9-auth")
    for u, cookies in (cookie_report or {}).items():
        for c in cookies:
            if c.get("missing"):
                add("H-COOK-%s" % sha1(u + c.get("name", ""))[:4],
                    "%s ka session cookie '%s' hardening missing hai" % (u, c.get("name")),
                    "missing flags: %s" % ", ".join(c["missing"]),
                    "Response header ko dobara check karo; agar flags kabhi bhi present hon to REJECT.",
                    "10-sessions")
    for ji in (jwt_report or []):
        if ji.get("alg") in ("none", "HS256") or not ji.get("has_exp"):
            add("H-JWT-%s" % sha1(str(ji.get("endpoint")) + str(ji.get("alg")))[:4],
                "%s ka pre-auth JWT weak hai" % ji.get("endpoint"),
                "alg=%s has_exp=%s" % (ji.get("alg"), ji.get("has_exp")),
                "Token ko protected endpoint par bhejo; agar reject ho to alg weakness exploitable nahi -> REJECT.",
                "10-sessions")
    for u, r in (csrf_report or {}).items():
        if r.get("static"):
            add("H-CSRF-%s" % sha1(u)[:4],
                "%s ka CSRF token session-bound nahi hai" % u,
                "do alag session me same token mila",
                "Token ke sath ek aur fresh session lo; agar token badal jaye to REJECT karo.",
                "10-sessions")
    for f in F.items:
        if f["key"] in ("jwt_alg_none_accepted", "jwt_signature_not_verified"):
            add("H-JWTTAMPER-%s" % sha1(f["endpoint"])[:4],
                "%s tampered JWT accept karta hai" % f["endpoint"],
                f["detail"],
                "Tampered token ko do baar bhejo; agar dobara reject ho (intermittent) to REJECT karo.",
                "10-sessions")
    # ---- v10 hypotheses ----
    for u, r in (inj_report or {}).items():
        if r.get("nosql_accepted"):
            add("H-NOSQL-%s" % sha1(u)[:4],
                "%s NoSQL operator ($ne/$gt) se bypass hota hai" % u,
                "operator probe par status/shape materially badla",
                "Same probe 2 baar dobara bhejo (synthetic ident par) - agar ab bhi synthetic "
                "reject ho aur sirf 'admin' accept ho to real bypass hai; warna REJECT.",
                "13-injection")
        if r.get("type_confusion"):
            add("H-TC-%s" % sha1(u)[:4],
                "%s me JSON type confusion se auth logic dodge hoti hai" % u,
                "null/0 password types par response differential",
                "Manual client se wahi payloads bhejo; agar app schema-validation reject kare to REJECT.",
                "13-injection")
    for u, r in (redir_report or {}).items():
        if r.get("open_redirect"):
            add("H-REDIR-%s" % sha1(u)[:4],
                "%s ka redirect param externally-controlled hai" % u,
                "wasp-invalid host par 3xx Location mila",
                "Ek aur benign .test host try karo; agar redirect na ho to REJECT.",
                "14-xss")
        if r.get("crlf"):
            add("H-CRLF-%s" % sha1(u)[:4],
                "%s me CRLF injection se headers inject hote hain" % u,
                "X-Wasp-Probe response headers me mila",
                "Dusra CRLF variant try karo; agar header na bane to REJECT (encoding-safe tha).",
                "13-injection")
    for rec in ((jwt_deep or {}).get("key_injection") or []):
        add("H-JWTKEY-%s" % sha1(str(rec.get("endpoint")))[:4],
            "JWT key-injection (jku/x5u/jwk) se key control ho sakti hai",
            "header me attacker-controllable key URL/param",
            "Own jwks host karke (RoE-approved) ek forged token bhejo; reject hua to REJECT.",
            "10-sessions")
    for u, r in (cors_report or {}).items():
        if r.get("reflected") and r.get("credentials"):
            add("H-CORS-%s" % sha1(u)[:4],
                "%s par CORS cred-reflection authenticated data leak karega" % u,
                r.get("summary", ""),
                "Browser-based PoC (RoE-approved origin) se 1 request; agar ACAO na aaye to REJECT.",
                "10-sessions")
    return H


def write_test_plan(out, scope, H, F, coverage, stats_summary):
    L = []
    A = L.append
    A("# Phase 9 - Authentication Test Plan & Findings")
    A("")
    A("**Engagement:** `%s`  " % scope.engagement)
    A("**Generated:** %s  " % now_iso())
    A("**Engine:** WASP v%s / auth plan v%s" % (VERSION, PLAN_VERSION))
    A("")
    A("> Ye plan **bounded, non-destructive** probes par based hai. Har hypothesis ke saath")
    A("> ek KILL TEST diya gaya hai - agar kill-test pass ho jaye to hypothesis REJECT karo.")
    A("")
    A("---")
    A("")
    A("## 1. Findings summary")
    A("")
    if F.items:
        A("| ID | Severity | Title | Endpoint |")
        A("|---|---|---|---|")
        for f in F.items:
            A("| %s | **%s** | %s | `%s` |" % (f["id"], f["severity"], f["title"],
                                                urllib.parse.urlparse(f["endpoint"]).path))
    else:
        A("_Koi finding confirm nahi hui._")
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
    A("## 3. Coverage matrix (tested vs untested)")
    A("")
    A("| Control | Status |")
    A("|---|---|")
    for k, v in coverage.items():
        A("| %s | %s |" % (k, v))
    A("")
    A("## 4. Statistical method (timing analysis)")
    A("")
    A("| Test | Kya batata hai |")
    A("|---|---|")
    A("| Welch t-test | mean response-time shift (unequal variance) |")
    A("| Mann-Whitney U (tie-corrected) | rank shift - outliers se robust |")
    A("| Cliff's delta | effect size - practically bada hai ya nahi |")
    A("| Bootstrap CI | median difference ka confidence interval |")
    A("| Modified z-score (MAD) | v1 ka method, ab supporting evidence ke taur par |")
    A("")
    if stats_summary:
        A("```")
        A(json.dumps(stats_summary, indent=2, default=str)[:1800])
        A("```")
    A("")
    A("## 5. Limitations")
    A("")
    A("- Ye **bounded** testing hai: attempts capped, lockout par abort.")
    A("- `reset_token_weak` sirf tab detect hota hai jab token HTTP response me aaye -")
    A("  email-based reset me token kabhi nahi dikhta, isliye 'no token' = 'weak nahi' NAHI.")
    A("- Timing analysis shared/VPN network par noisy ho sakti hai; effect size dekho, sirf p-value nahi.")
    A("- Ye plan credential guessing nahi karta (koi wordlist attack nahi).")
    A("- Ye kisi bhi real user ko email nahi bhejta (synthetic `.test` identifiers only).")
    A("")
    save_text(os.path.join(out, "auth_test_plan.md"), "\n".join(L) + "\n")


# ---------------------------------------------------------------------------
# STAGE A - AUTH SURFACE DISCOVERY (Phase 8 priority queue aware)
# ---------------------------------------------------------------------------
def _phase8_auth_targets(base_dir, eng, scope):
    """
    Phase 8 ke priority_queue.json se auth-related targets uthao, priority ke
    saath. Isse Phase 9 ka pehla target wahi hota hai jo Phase 8 ne sabse
    zyada scored tha - guess-work nahi.
    """
    pq = load_json(os.path.join(base_dir, eng, "surface", "priority_queue.json"), None)
    rows = []
    if isinstance(pq, dict):
        for r in (pq.get("queue") or []) + (pq.get("diverse_queue") or []):
            url = r.get("target") or ""
            if not url.startswith("http"):
                continue
            cls = " ".join(r.get("classes") or [])
            path = urllib.parse.urlparse(url).path
            if AUTH_PATH_RE.search(path) or "Auth/Credential" in cls or "Access-Control" in cls:
                rows.append({"url": url, "priority": r.get("priority", 0),
                             "classes": r.get("classes") or [], "confidence": r.get("confidence"),
                             "why": (r.get("why") or [])[:2]})
    # dedupe by url, best priority
    best = {}
    for r in rows:
        u = r["url"].split("#")[0]
        if u not in best or r["priority"] > best[u]["priority"]:
            best[u] = r
    out = sorted(best.values(), key=lambda x: -x["priority"])
    return [r for r in out if scope.check_url(r["url"], raise_on_fail=False)]


def discover_auth_surface(base_dir, scope, out, conf=None):
    """
    Auth candidates = (Phase 8 priority targets) + (Phase 2-7 artifact mining)
    + (well-known paths). Priority order preserve hota hai, phir scope filter.
    """
    conf = conf or {}
    eng = scope.engagement
    ranked = []

    # 1) Phase 8 priority queue (sabse bharosemand source)
    if conf.get("auth_use_phase8_priority", True):
        for r in _phase8_auth_targets(base_dir, eng, scope):
            ranked.append(r)

    # 2) Phase 2-7 raw artifact mining (backup, agar Phase 8 na chala ho)
    cands = set()
    for mod in ("understand", "content", "js", "passive", "active", "surface"):
        d = os.path.join(base_dir, eng, mod)
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            if os.sep + "evidence" in root or os.sep + "_state" in root:
                continue
            for fn in files:
                if not fn.endswith((".json", ".txt", ".md")):
                    continue
                fp = os.path.join(root, fn)
                try:
                    txt = open(fp, "r", errors="ignore").read()
                except Exception:
                    continue
                for m in re.finditer(r"https?://[^\s\"'<>,\]]+", txt):
                    u = m.group(0).rstrip(").,;")
                    if AUTH_PATH_RE.search(urllib.parse.urlparse(u).path):
                        cands.add(u.split("#")[0])
                if fn.endswith(".txt"):
                    for line in txt.splitlines():
                        line = line.strip()
                        if line.startswith("/") and AUTH_PATH_RE.search(line):
                            for o in _authorized_origins(scope)[:2]:
                                cands.add(o.rstrip("/") + line)

    # 3) well-known paths (origin-aware -> IP:port targets bhi sahi chalti hain)
    for o in _authorized_origins(scope)[:5]:
        for p in WELL_KNOWN_AUTH:
            cands.add(o.rstrip("/") + p)

    known = {r["url"] for r in ranked}
    for u in sorted(cands):
        if u in known:
            continue
        if scope.check_url(u, raise_on_fail=False):
            ranked.append({"url": u, "priority": 0, "classes": [], "confidence": "low",
                           "why": ["well-known / artifact-mined path"]})

    # 4) seed URL base par bhi login maango (SPA me /login HTML me nahi hota)
    for s in scope.seed_urls():
        for p in ("/login", "/api/auth/login", "/api/login"):
            u = s.rstrip("/") + p
            if scope.check_url(u, raise_on_fail=False) and u not in known:
                ranked.append({"url": u, "priority": 5, "classes": [],
                               "confidence": "low", "why": ["seed-derived login path"]})

    cap = int(conf.get("auth_surface_cap", 25))
    return ranked[:cap]


def _authorized_hosts(scope):
    """Sirf hostname list (domain-based logic ke liye)."""
    hosts = list(getattr(scope, "domains", []) or [])
    hosts += [w.lstrip("*.") for w in (getattr(scope, "wildcards", []) or [])]
    for u in scope.seed_urls():
        h = host_of(u)
        if h:
            hosts.append(h)
    out, seen = [], set()
    for h in hosts:
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _authorized_origins(scope):
    """
    scheme://host:port origins. IP:port targets (jaise http://127.0.0.1:8443) ke
    liye ye zaroori hai - warna well-known path probe port kho kar connection
    refused deti hai (real bug jo mock test me pakda gaya).
    """
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


# ---------------------------------------------------------------------------
# STAGE B - PROBE & FLOW MAPPING
# ---------------------------------------------------------------------------
def probe_endpoint(http, url, conf=None):
    """Read-only GET: forms, CSRF, cookies, JWT, auth scheme, transport, methods.
    v10: + hardening signals (XFO/CSP-frame/cache/referrer/CDN), webauthn marker,
    captcha marker, redirect-param inventory, token-in-URL indicator."""
    conf = conf or {}
    r = http.request("GET", url, allow_redirects=True)
    pu = urllib.parse.urlparse(r.url or url)
    rec = {"url": url, "status": r.status, "error": r.error, "final_url": r.url,
           "len": len(r.body), "content_type": r.header("Content-Type"),
           "server": r.header("Server"), "scheme": pu.scheme,
           "www_authenticate": r.header("WWW-Authenticate"),
           "location": r.header("Location"),
           "set_cookie": [v for k, v in r.headers.items() if k.lower() == "set-cookie"],
           "body_sha1": sha1(r.body) if r.status else None,
           "debug_leak": bool(DEBUG_LEAK_RE.search(r.text or "")),
           "forms": []}
    # ---- v10 hardening capture (passive, response se hi) ----
    headers_lc = {k.lower(): v for k, v in (r.headers.items() if r.headers else [])}
    rec["hardening"] = {
        "x_frame_options": headers_lc.get("x-frame-options"),
        "csp": headers_lc.get("content-security-policy"),
        "frame_ancestors": (re.search(r"frame-ancestors\s+([^;]+)",
                                      headers_lc.get("content-security-policy") or "", re.I)
                            .group(1).strip() if re.search(
                                r"frame-ancestors", headers_lc.get("content-security-policy") or "", re.I)
                            else None),
        "cache_control": headers_lc.get("cache-control"),
        "referrer_policy": headers_lc.get("referrer-policy"),
        "cdn_hints": sorted(k for k in headers_lc if CDN_HEADER_RE.match(k)),
    }
    rec["webauthn"] = bool(WEBAUTHN_RE.search(r.text or ""))
    rec["captcha"] = bool(CAPTCHA_RE.search(r.text or "") or CAPTCHA_RE.search(json.dumps(headers_lc)))
    rec["token_in_url"] = bool(JWT_URL_RE.search(url))
    rec["saml_markers"] = sorted(set(m.group(0).lower() for m in SAML_RE.finditer(r.text or "")))[:6]
    path_only = urllib.parse.urlparse(url).path
    ct_low = (r.header("Content-Type") or "").lower()
    rec["wp_users"] = bool(WP_USERS_RE.search(path_only)) and bool(
        r.status == 200 and "json" in ct_low and len(r.body or b"") > 20)
    rec["nextauth"] = bool(NEXTAUTH_PATH_RE.search(path_only)) and bool(r.status and r.status < 400)
    # redirect params: URL query + form hidden fields
    rp = []
    try:
        for k in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys():
            if REDIRECT_PARAM_RE.match(k):
                rp.append(k)
    except Exception:
        pass
    rec["redirect_params"] = sorted(set(rp))
    if r.status and "html" in (r.header("Content-Type") or "").lower():
        forms = parse_forms(r.text, r.url)
        rec["forms"] = forms
        rec["has_password"] = any(f["has_password"] for f in forms)
        rec["register_form"] = any(
            f["has_password"] and REGISTER_HINT_RE.search(f["action"]) for f in forms)
        rec["csrf_present"] = any(f["csrf_fields"] for f in forms)
        rec["password_policy_hint"] = _password_policy_hint(forms)
        for f in forms:
            for fld in f.get("fields", []):
                if REDIRECT_PARAM_RE.match(fld.get("name") or ""):
                    rec["redirect_params"] = sorted(set((rec["redirect_params"] or []) + [fld["name"]]))
    else:
        rec["forms"] = []
    rec["jwts"] = find_jwts(r.text)[:5]
    if conf.get("auth_allow_method_matrix", True) and r.status:
        rec["methods"] = _method_matrix(http, url)
    return rec


def _password_policy_hint(forms):
    """Form attributes se client-side password policy infer karo."""
    for f in forms or []:
        for fld in f.get("fields", []):
            if fld.get("type") == "password":
                ml = fld.get("maxlength")
                pat = fld.get("pattern") or ""
                ac = fld.get("autocomplete") or ""
                weak = True
                notes = []
                try:
                    if ml and int(ml) < 8:
                        notes.append("maxlength=%s (bahut chhota)" % ml)
                    else:
                        weak = False
                except Exception:
                    weak = False
                if not pat:
                    notes.append("koi pattern attribute nahi (server-side policy confirm karo)")
                if ac.lower() in ("", "on"):
                    notes.append("autocomplete on/unspecified")
                return {"maxlength": ml, "pattern": pat, "autocomplete": ac,
                        "weak_hint": weak, "notes": notes[:4]}
    return {}


def _method_matrix(http, url):
    """OPTIONS + HEAD (read-only) se allowed methods nikaalo."""
    out = {}
    ro = http.request("OPTIONS", url, allow_redirects=False)
    if ro.status:
        out["OPTIONS"] = {"status": ro.status, "allow": ro.header("Allow")}
    rh = http.request("HEAD", url, allow_redirects=False)
    if rh.status:
        out["HEAD"] = {"status": rh.status, "content_type": rh.header("Content-Type")}
    return out


# ---------------------------------------------------------------------------
# STAGE C - CSRF TOKEN BINDING
# ---------------------------------------------------------------------------
def csrf_token_binding(http, scope, url, probe, conf):
    """
    Do INDEPENDENT session se login form lo aur CSRF token compare karo.
    Same token => token session-bound nahi (cross-session reuse possible).
    """
    res = {"endpoint": url, "sessions": [], "static": False, "summary": ""}
    samples = max(2, int(conf.get("auth_csrf_token_samples", 2)))
    tokens, cookies = [], []
    for i in range(samples):
        ident = http.identity("csrf%d" % i)
        r = ident.request("GET", url, allow_redirects=True)
        if not r.status:
            continue
        forms = parse_forms(r.text, r.url)
        csrf = []
        for f in forms:
            for cf in f.get("csrf_fields", []):
                for fld in f.get("fields", []):
                    if fld["name"] == cf and fld.get("value"):
                        csrf.append({"field": cf, "value_len": len(fld["value"]),
                                     "fingerprint": sha1(fld["value"])[:12]})
        ck = [c["name"] for c in ident.session_export()]
        tokens.append(csrf)
        cookies.append(ck)
        res["sessions"].append({"index": i, "status": r.status, "csrf": csrf, "cookies": ck})
    if len(tokens) >= 2 and tokens[0] and tokens[1]:
        fp0 = {t["fingerprint"] for t in tokens[0]}
        fp1 = {t["fingerprint"] for t in tokens[1]}
        if fp0 == fp1:
            res["static"] = True
            res["summary"] = "same CSRF token do alag sessions me -> session-bound nahi"
        else:
            res["summary"] = "CSRF token per-session badal raha hai (bound lag raha hai)"
    else:
        res["summary"] = "CSRF token nahi mila ya sirf ek session sample mila"
    return res


# ---------------------------------------------------------------------------
# STAGE D - USER ENUMERATION v2 (DRF + JSON oracle + robust stats)
# ---------------------------------------------------------------------------
def enum_login_endpoint(http, scope, url, probe, conf):
    """
    Enumeration v2:
      * synthetic baseline (reserved .test TLD)
      * plausible identifiers -> DRF v2 (shape fingerprint + JSON error-code oracle)
      * timing: Welch t + Mann-Whitney U + Cliff's delta + bootstrap CI
      * v1 ka MAD z-score bhi supporting evidence ke taur par
    Bounded + lockout-safe.
    """
    res = {"endpoint": url, "attempts": 0, "locked_out": False, "locked_out_reason": "",
           "enumeration_likely": False, "signals": {}, "identifiers_used": [],
           "stats_method": "welch+mannwhitney+cliffsdelta+bootstrap"}
    cap = int(conf["auth_max_attempts"])
    n_ident = int(conf.get("auth_enum_identifiers", 5))
    repeats = int(conf["auth_timing_repeats"])

    base_r = _send_login(http, probe, synth_identifier("baseline"), "WaspInvalid!" + rand_str(4))
    res["attempts"] += 1
    res["identifiers_used"].append("synthetic-baseline")
    lo, why = detect_lockout(base_r.status, base_r.text, base_r.headers)
    if lo:
        res.update({"locked_out": True, "locked_out_reason": why})
        res["summary"] = "Pehle hi probe par lockout/throttle (%s) - safely abort." % why
        return res

    timing_plausible, timing_bogus = [], []
    worst = None
    json_oracle_hits = []
    for user in PLAUSIBLE_USERS[:n_ident]:
        if res["attempts"] >= cap:
            break
        r = _send_login(http, probe, user, "WaspInvalid!" + rand_str(4))
        res["attempts"] += 1
        res["identifiers_used"].append(user)
        lo, why = detect_lockout(r.status, r.text, r.headers)
        if lo:
            res.update({"locked_out": True, "locked_out_reason": why})
            res["summary"] = "%d attempts ke baad lockout (%s)." % (res["attempts"], why)
            return res
        sig = drf_compare(base_r, r)
        timing_plausible.append(r.elapsed)
        if sig.get("json_oracle"):
            json_oracle_hits.append({"identifier": user, "json_a": sig.get("json_a"),
                                     "json_b": sig.get("json_b")})
        if worst is None or sig["diff_score"] > worst[1]["diff_score"]:
            worst = (user, sig)
        if ENUM_MSG_RE.search(r.text or ""):
            res["signals"].setdefault("message_oracle", []).append(user)
        if GENERIC_MSG_RE.search(r.text or "") and not ENUM_MSG_RE.search(r.text or ""):
            res["signals"].setdefault("generic_message_ok", []).append(user)

    for _ in range(repeats):
        if res["attempts"] >= cap + repeats:
            break
        r = _send_login(http, probe, synth_identifier("bogus"), "WaspInvalid!" + rand_str(4))
        res["attempts"] += 1
        timing_bogus.append(r.elapsed)

    tv = timing_verdict(timing_plausible, timing_bogus,
                        alpha=float(conf.get("auth_stats_alpha", 0.05)),
                        resamples=int(conf.get("auth_stats_bootstrap", 400)))
    res["timing"] = tv
    if json_oracle_hits:
        res["signals"]["json_oracle"] = json_oracle_hits[:3]
    if worst:
        res["signals"]["best_drf"] = {
            "identifier": worst[0], "diff_score": worst[1]["diff_score"],
            "verdict": worst[1]["verdict"], "len_delta": worst[1]["len_delta"],
            "body_similarity": worst[1]["body_similarity"],
            "json_oracle": worst[1].get("json_oracle")}

    enum = (bool(res["signals"].get("message_oracle"))
            or bool(res["signals"].get("json_oracle"))
            or (worst and worst[1]["diff_score"] >= 30)
            or bool(tv.get("timing_anomaly")))
    res["enumeration_likely"] = bool(enum)
    res["enumeration_signals"] = [k for k in ("message_oracle", "json_oracle") if res["signals"].get(k)]
    if worst and worst[1]["diff_score"] >= 30:
        res["enumeration_signals"].append("drf_diff>=30")
    if tv.get("timing_anomaly"):
        res["enumeration_signals"].append("timing_anomaly")
    res["summary"] = ("DRF diff=%s verdict=%s | json_oracle=%s | timing=%s (delta=%.2f p=%.4f) | "
                      "msg_oracle=%s | attempts=%d" % (
                          res["signals"].get("best_drf", {}).get("diff_score"),
                          res["signals"].get("best_drf", {}).get("verdict"),
                          bool(res["signals"].get("json_oracle")),
                          tv.get("verdict"), tv.get("cliffs_delta", 0.0), tv.get("mw_p", 1.0),
                          bool(res["signals"].get("message_oracle")), res["attempts"]))
    return res


def _build_login_request(probe, identifier, password):
    """Parsed form se login request banao (url, method, data, headers)."""
    forms = probe.get("forms") or []
    form = next((f for f in forms if f.get("has_password")), None)
    url = probe.get("final_url") or probe.get("url")
    if form:
        url = form["action"]
        user_f, pass_f = guess_fields(form["field_names"])
        data = {user_f or "username": identifier, pass_f or "password": password}
        for cf in form.get("csrf_fields", []):
            for fld in form.get("fields", []):
                if fld["name"] == cf and fld.get("value"):
                    data[cf] = fld["value"]
        return url, form["method"], data, {"Content-Type": "application/x-www-form-urlencoded"}
    return url, "POST", {"username": identifier, "email": identifier, "password": password}, \
        {"Content-Type": "application/json"}


def _send_login(http, probe, identifier, password, extra_headers=None):
    # v10 FIX: failed login attempts server state mutate nahi karte ->
    # read_only_post=True (mod_tech precedent). Bina iske ULTRA core ka
    # Layer-4 RWX gate ScopeError raise karta tha -> poora module crash (v9 bug).
    url, method, data, headers = _build_login_request(probe, identifier, password)
    h = dict(headers)
    h.update(extra_headers or {})
    if method == "GET":
        q = urllib.parse.urlencode(data)
        return http.request("GET", url + ("&" if "?" in url else "?") + q, headers=h,
                            allow_redirects=False, read_only_post=True)
    body = (json.dumps(data) if "json" in h.get("Content-Type", "")
            else urllib.parse.urlencode(data)).encode()
    return http.request(method, url, headers=h, data=body, allow_redirects=False,
                        read_only_post=True)


# ---------------------------------------------------------------------------
# STAGE E - RATE LIMIT / LOCKOUT MODEL
# ---------------------------------------------------------------------------
def rate_limit_probe(http, scope, url, probe, conf):
    """
    Bounded burst -> throttle engage hota hai ya nahi.
    v9 me lockout MODEL bhi classify hota hai (per-account / per-IP / global).
    """
    res = {"endpoint": url, "attempts": 0, "throttled": False, "locked_out": False,
           "status_series": [], "timing_ms": [], "signals": [], "identifiers_used": [],
           "lockout_model": "none", "lockout_reason": ""}
    cap = int(conf["auth_max_attempts"])
    reasons = []
    for i in range(cap):
        ident = "wasp-rl-%s@%s" % (rand_str(4), SYNTH_DOMAIN) if i % 2 == 0 else "wasp-rl-%s@%s" % (rand_str(4), SYNTH_DOMAIN)
        res["identifiers_used"].append(ident)
        r = _send_login(http, probe, ident, "WaspInvalid!" + rand_str(4))
        res["attempts"] += 1
        res["status_series"].append(r.status)
        res["timing_ms"].append(round(r.elapsed * 1000, 1))
        lo, why = detect_lockout(r.status, r.text, r.headers)
        reasons.append(why)
        if lo:
            res["throttled"] = True
            res["locked_out"] = (r.status in (423, 429)) or ("lock" in why or "too many" in why)
            res["lockout_reason"] = why
            res["signals"].append(why)
            break
    if not res["throttled"] and len(res["timing_ms"]) >= 4:
        first, last = median(res["timing_ms"][:2]), median(res["timing_ms"][-2:])
        if last > max(200.0, first * 3.0):
            res["throttled"] = True
            res["signals"].append("progressive-delay")
    res["lockout_model"], res["lockout_model_note"] = classify_lockout_model(
        res["status_series"], reasons, res["identifiers_used"])
    res["summary"] = ("%d attempts | statuses=%s | throttled=%s | model=%s | signals=%s" % (
        res["attempts"], res["status_series"], res["throttled"], res["lockout_model"],
        res["signals"]))
    return res


# ---------------------------------------------------------------------------
# STAGE F - BYPASS MATRIX v2 (interleaved control probe)
# ---------------------------------------------------------------------------
def rate_limit_bypass_matrix(http, scope, url, probe, conf):
    """
    v1 ka bug: 'not throttled' ko hi bypass maan leta tha, aur control probe
    nahi tha - isliye agar endpoint par throttle hi na ho to bhi 'bypass_likely'
    aa jata tha. v2:
      * pehle ek CONTROL probe (no header, same identifier) bhejo
      * phir mutation probes
      * bypass tab hi claim karo jab mutation pass ho AUR control bhi pass ho
        (matlab throttle kabhi laga hi nahi), ya jab control BLOCK ho aur
        mutation PASS ho (matlab throttle actually bypass hua)
    """
    out = {"probes": [], "bypass_likely": False, "control": {}, "summary": "",
           "bypass_type": None}
    n = int(conf["auth_bypass_probes"])
    domain = SYNTH_DOMAIN
    variants = normalize_username_variants("waspuser", domain)

    # --- control probe ---
    ctrl = _send_login(http, probe, variants["original"], "WaspInvalid!" + rand_str(4))
    ctrl_lo, ctrl_why = detect_lockout(ctrl.status, ctrl.text, ctrl.headers)
    out["control"] = {"status": ctrl.status, "throttled": ctrl_lo, "signal": ctrl_why,
                      "identifier": variants["original"]}

    header_sets = [{"X-Forwarded-For": "127.0.0.%d" % (10 + i)} for i in range(4)]
    header_sets += [{"X-Real-IP": "127.0.0.%d" % (20 + i)} for i in range(2)]
    header_sets += [{"X-Originating-IP": "127.0.0.%d" % (30 + i)} for i in range(2)]
    header_sets += [{"X-Client-IP": "127.0.0.%d" % (40 + i)} for i in range(2)]

    header_pass, ident_pass = 0, 0
    for i in range(min(n, len(header_sets))):
        r = _send_login(http, probe, variants["original"], "WaspInvalid!" + rand_str(4), header_sets[i])
        lo, why = detect_lockout(r.status, r.text, r.headers)
        passed = (not lo) and r.status not in (401, 403)
        if passed:
            header_pass += 1
        out["probes"].append({"type": "header", "headers": header_sets[i], "status": r.status,
                              "throttled": lo, "passed": passed, "signal": why})
    for name in ("upper", "plus_tag", "dot_variant", "trailing_space", "double_at", "unicode_fullwidth"):
        r = _send_login(http, probe, variants[name], "WaspInvalid!" + rand_str(4))
        lo, why = detect_lockout(r.status, r.text, r.headers)
        passed = (not lo) and r.status not in (401, 403)
        if passed:
            ident_pass += 1
        out["probes"].append({"type": "identifier", "variant": name, "status": r.status,
                              "throttled": lo, "passed": passed, "signal": why})

    ctrl_passed = (not ctrl_lo) and ctrl.status not in (401, 403)
    if ctrl_passed:
        # throttle kabhi engage hi nahi hua -> bypass claim nahi kar sakte
        out["bypass_likely"] = False
        out["bypass_type"] = "no-throttle-to-bypass"
        out["summary"] = ("control probe bhi pass hua -> throttling observe nahi hui; "
                          "bypass claim REJECT (header_pass=%d ident_pass=%d)" % (header_pass, ident_pass))
    else:
        # control block hua; agar mutation pass hua to real bypass
        if header_pass or ident_pass:
            out["bypass_likely"] = True
            out["bypass_type"] = ("header-rotation" if header_pass and not ident_pass else
                                  "identifier-normalization" if ident_pass and not header_pass else
                                  "header+identifier")
            out["summary"] = ("control BLOCK hua par %d header / %d identifier probe pass -> "
                              "bypass likely (%s)" % (header_pass, ident_pass, out["bypass_type"]))
        else:
            out["bypass_likely"] = False
            out["bypass_type"] = "throttle-holds"
            out["summary"] = "control aur saare mutation probes block hue -> throttling effective hai"
    return out


# ---------------------------------------------------------------------------
# STAGE G - PASSWORD RESET FLOW
# ---------------------------------------------------------------------------
def reset_flow_analysis(http, scope, url, probe, conf):
    """
    Reset flow analysis (safe):
      1) synthetic identifier -> generic message check (enumeration)
      2) Host header injection check
      3) token sampling + per-position entropy / Hamming (agar token HTTP me aaye)
      4) (opt-in) real-looking identifier probe - default OFF
    """
    res = {"endpoint": url, "probes": [], "token": {}, "host_header_reflected": False,
           "header_variants": [], "token_in_response": False,
           "enumeration_likely": False, "generic_message": None, "summary": ""}
    forms = probe.get("forms") or []
    form = forms[0] if forms else None
    action = form["action"] if form else (probe.get("final_url") or url)
    method = (form["method"] if form else "POST")
    field_names = (form["field_names"] if form else ["email"])

    def build(ident, extra_headers=None):
        d = {}
        uf, _ = guess_fields(field_names)
        d[uf or "email"] = ident
        for cf in (form.get("csrf_fields") if form else []):
            for fld in (form.get("fields") if form else []):
                if fld["name"] == cf and fld.get("value"):
                    d[cf] = fld["value"]
        body = urllib.parse.urlencode(d).encode()
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(extra_headers or {})
        return action, method, body, h

    # 1) synthetic -> generic vs leak (synthetic ident -> koi real state change nahi)
    syn = synth_identifier("reset")
    a, m, b, h = build(syn)
    r1 = http.request(m, a, headers=h, data=b, allow_redirects=False, read_only_post=True)
    gen = bool(GENERIC_MSG_RE.search(r1.text or ""))
    leak = bool(ENUM_MSG_RE.search(r1.text or ""))
    res["generic_message"] = gen
    res["probes"].append({"ident": "synthetic", "status": r1.status, "len": len(r1.body),
                          "generic_message": gen, "leaks": leak,
                          "debug_leak": bool(DEBUG_LEAK_RE.search(r1.text or ""))})
    res["enumeration_likely"] = leak

    # 2) host header injection (v10: konsa header reflect hua wo bhi record hota hai)
    evil = "wasp-inject-%s.attacker-invalid.test" % rand_str(4)
    poison_headers = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server"]
    a2, m2, b2, h2 = build(syn, {h: evil for h in poison_headers})
    r2 = http.request(m2, a2, headers=h2, data=b2, allow_redirects=False, read_only_post=True)
    reflected = evil in (r2.text or "")
    loc = r2.header("Location") or ""
    res["host_header_reflected"] = bool(reflected or (evil in loc))
    res["poison_headers_used"] = list(poison_headers)
    res["probes"].append({"type": "host-header", "injected": evil, "reflected": reflected,
                          "headers": poison_headers, "location": loc[:160], "status": r2.status})

    # 2b) v10 per-header variants (X-Original-URL + X-Forwarded-Proto) - gated
    if conf.get("auth_allow_header_poison", True):
        evil2 = "wasp-orig-%s.attacker-invalid.test" % rand_str(4)
        for variant, hdrs in (("x-original-url", {"X-Original-URL": "https://%s/reset" % evil2}),
                              ("x-forwarded-proto", {"X-Forwarded-Proto": "http"})):
            av, mv, bv, hv = build(syn, hdrs)
            rv = http.request(mv, av, headers=hv, data=bv, allow_redirects=False,
                              read_only_post=True)
            hitv = (evil2 in (rv.text or "")) or (evil2 in (rv.header("Location") or ""))
            protov = variant == "x-forwarded-proto" and "http://" in (rv.text or "")[:4000] \
                and "https://" not in (rv.text or "")[:4000]
            if hitv or protov:
                res["header_variants"].append({"variant": variant, "reflected": bool(hitv),
                                               "proto_downgrade": bool(protov),
                                               "status": rv.status})
            res["probes"].append({"type": "header-variant:%s" % variant, "status": rv.status,
                                  "reflected": bool(hitv)})

    # 3) token sampling
    toks = []
    for i in range(int(conf["auth_reset_token_samples"])):
        a3, m3, b3, h3 = build("wasp-token-%s@%s" % (rand_str(5), SYNTH_DOMAIN))
        r3 = http.request(m3, a3, headers=h3, data=b3, allow_redirects=False,
                          read_only_post=True)
        found = re.findall(r"(?i)(?:token|code|key|reset|otp)[=\"\s:]+([A-Za-z0-9._\-]{12,})", r3.text or "")
        found += re.findall(r"/([A-Za-z0-9._\-]{16,})(?:[\"'/]|$)", r3.text or "")
        if found:
            toks.append(found[0])
    if toks:
        res["token"] = token_predictability(toks)
        res["token_in_response"] = True
    else:
        res["token"] = {"samples": 0,
                        "note": "HTTP response me token nahi aaya (email-based reset me normal hai) - "
                                "isliye 'weak nahi' mat maano, sirf 'detect nahi hua'"}

    # 4) opt-in: plausible identifier probe (default OFF - real users ko email jaa sakta hai)
    # NOTE: ye server-state create kar sakta hai -> Layer-4 write gate ka respect karta hai
    # (allow_write_http=true master switch ke bina yeh block hoga, crash nahi).
    if conf.get("auth_allow_reset_plausible_probe"):
        a4, m4, b4, h4 = build("admin@" + (_authorized_hosts(scope) or ["example.com"])[0])
        try:
            r4 = http.request(m4, a4, headers=h4, data=b4, allow_redirects=False)
            res["plausible_probe"] = {"status": r4.status, "len": len(r4.body),
                                      "leaks": bool(ENUM_MSG_RE.search(r4.text or "")),
                                      "note": "opt-in tha; real mailbox par email jaa sakta hai"}
        except ScopeError:
            res["plausible_probe"] = {"blocked": True,
                                      "note": "READ-ONLY core ne block kiya - "
                                              "allow_write_http=true chahiye (sahi behaviour)"}

    res["summary"] = ("generic_msg=%s | leak=%s | host_header_reflected=%s | variants=%d | "
                      "token_in_response=%s | token=%s" % (
                          gen, leak, res["host_header_reflected"], len(res["header_variants"]),
                          res["token_in_response"], res["token"].get("weak", "n/a")))
    return res


# ---------------------------------------------------------------------------
# STAGE H - MFA / OTP
# ---------------------------------------------------------------------------
def mfa_flow_analysis(http, scope, url, probe, conf):
    """Status oracle + JSON oracle + OTP shape (form attributes) + throttling."""
    res = {"endpoint": url, "status_oracle": False, "no_ratelimit": False,
           "locked_out": False, "otp_shape": {}, "summary": ""}
    forms = probe.get("forms") or []
    form = forms[0] if forms else None
    action = form["action"] if form else (probe.get("final_url") or url)
    field_names = (form.get("field_names") if form else ["otp", "code"])
    otp_field = guess_otp_field(field_names)

    # OTP shape from form attributes (client-side hints - strong signal)
    shape = {"field": otp_field}
    for fld in (form.get("fields") if form else []):
        if fld["name"] == otp_field:
            shape.update({"maxlength": fld.get("maxlength"), "pattern": fld.get("pattern"),
                          "inputmode": fld.get("inputmode", ""), "autocomplete": fld.get("autocomplete")})
    res["otp_shape"] = shape
    lengths = set()
    if shape.get("maxlength"):
        try:
            lengths.add(int(shape["maxlength"]))
        except Exception:
            pass
    if shape.get("pattern"):
        m = re.search(r"\{(\d+)\}", shape["pattern"])
        if m:
            lengths.add(int(m.group(1)))
    if lengths and max(lengths) <= 4:
        res["weak_otp_policy"] = True
        res["otp_shape"]["weak_reason"] = "OTP length %s -> brute-force feasible" % sorted(lengths)

    shapes = ["000000", "123456", "abcdef", "0" * 4, "0000"]
    statuses, errs, json_oracles = [], [], []
    cap = min(5, int(conf["auth_max_attempts"]))
    for s in shapes[:cap]:
        d = {otp_field: s}
        for cf in (form.get("csrf_fields") if form else []):
            for fld in (form.get("fields") if form else []):
                if fld["name"] == cf and fld.get("value"):
                    d[cf] = fld["value"]
        body = urllib.parse.urlencode(d).encode()
        r = http.request((form["method"] if form else "POST"), action,
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         data=body, allow_redirects=False, read_only_post=True)
        statuses.append(r.status)
        lo, why = detect_lockout(r.status, r.text, r.headers)
        if lo:
            res["locked_out"] = True
            res["summary"] = "OTP endpoint throttled after %d probes (%s)" % (len(statuses), why)
            res["status_series"] = statuses
            return res
        j = r.json(None)
        if isinstance(j, dict):
            es = _json_error_shape(j)
            if es:
                json_oracles.append(es)
        m = re.search(r"(expired|invalid|incorrect|wrong|not\s+valid|already\s+used|too\s+many)", r.text or "", re.I)
        if m:
            errs.append(re.sub(r"\s+", " ", m.group(1)).lower())
    res["status_oracle"] = len(set(statuses)) > 1
    res["no_ratelimit"] = len(statuses) >= cap
    res["status_series"] = statuses
    res["error_tokens"] = sorted(set(errs))
    if len(json_oracles) >= 2 and len({json.dumps(x, sort_keys=True) for x in json_oracles}) > 1:
        res["json_oracle"] = True
    res["summary"] = ("statuses=%s | distinct=%d | errors=%s | json_oracle=%s | weak_policy=%s" % (
        statuses, len(set(statuses)), sorted(set(errs)), res.get("json_oracle", False),
        res.get("weak_otp_policy", False)))
    return res


# ---------------------------------------------------------------------------
# STAGE I - REGISTRATION
# ---------------------------------------------------------------------------
def registration_analysis(http, scope, url, probe, conf):
    """Static policy inference always; duplicate probe sirf opt-in par."""
    res = {"endpoint": url, "static": {}, "probe": None, "enumeration_likely": False,
           "summary": ""}
    forms = probe.get("forms") or []
    form = next((f for f in forms if f.get("has_password")), forms[0] if forms else None)
    if not form:
        res["summary"] = "registration form nahi mila (API-only ho sakta hai)"
        return res
    uf, pf = guess_fields(form["field_names"])
    res["static"] = {
        "action": form["action"], "method": form["method"], "enctype": form.get("enctype", ""),
        "identifier_field": uf, "password_field": pf, "csrf_fields": form.get("csrf_fields", []),
        "password_count": form.get("password_count", 0),
        "has_confirm_password": form.get("password_count", 0) > 1,
        "client_side_validation": bool(re.search(
            r"(required|pattern=|minlength|maxlength)", json.dumps(form), re.I)),
        "policy_hint": _password_policy_hint(forms),
    }
    res["open_registration"] = True
    if not conf.get("auth_allow_registration_probe"):
        res["summary"] = "static-only (auth_allow_registration_probe=true karne par duplicate probe hoga)"
        return res
    ident = "wasp-reg-%s@%s" % (rand_str(6), SYNTH_DOMAIN)
    d = {uf or "email": ident, pf or "password": "WaspTest!%s" % rand_str(4)}
    for cf in form.get("csrf_fields", []):
        for fld in form.get("fields", []):
            if fld["name"] == cf and fld.get("value"):
                d[cf] = fld["value"]
    body = urllib.parse.urlencode(d).encode()
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    # registration DUPLICATE probe server-state banata hai -> write-gate respect:
    # allow_write_http=false (default) par gracefully blocked, crash nahi.
    try:
        r1 = http.request(form["method"], form["action"], headers=h, data=body,
                          allow_redirects=False)
        r2 = http.request(form["method"], form["action"], headers=h, data=body,
                          allow_redirects=False)
    except ScopeError:
        res["probe"] = {"blocked": True,
                        "note": "duplicate-registration probe READ-ONLY gate se blocked "
                                "(allow_write_http=true opt-in chahiye - sahi behaviour)"}
        res["summary"] = "static-only (write-gate ne state-changing probe block kiya)"
        return res
    sig = drf_compare(r1, r2)
    res["probe"] = {"first_status": r1.status, "second_status": r2.status, "drf": sig}
    if (ENUM_MSG_RE.search(r2.text or "") and sig["diff_score"] >= 12) or sig.get("json_oracle"):
        res["enumeration_likely"] = True
    res["summary"] = "duplicate reg DRF diff=%s verdict=%s json_oracle=%s" % (
        sig["diff_score"], sig["verdict"], sig.get("json_oracle"))
    return res


# ---------------------------------------------------------------------------
# STAGE J - OAUTH / OIDC
# ---------------------------------------------------------------------------
def oauth_discovery(http, scope, oidc_urls, conf=None):
    """v10: + PKCE-downgrade surface, signing-alg inventory, mix-up indicator,
    redirect_uri path-traversal variant (gated), probe cap (auth_oauth_probes)."""
    conf = conf or {}
    out = {"discovery_urls": list(oidc_urls), "documents": {}, "redirect_uri_loose": False,
           "no_pkce": False, "implicit_flow": False, "missing_state": False,
           "pkce_downgrade_surface": False, "mixup_indicator": False,
           "redirect_path_variant": None, "summary": ""}
    issuers, authz_eps = [], []
    probe_budget = max(1, int(conf.get("auth_oauth_probes", 4)))
    for u in oidc_urls:
        r = http.request("GET", u, allow_redirects=True)
        if not r.status or r.status >= 400:
            continue
        try:
            doc = json.loads(r.text)
        except Exception:
            continue
        keep = ("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                "jwks_uri", "registration_endpoint", "end_session_endpoint",
                "scopes_supported", "response_types_supported",
                "code_challenge_methods_supported", "grant_types_supported",
                "response_modes_supported", "token_endpoint_auth_methods_supported",
                "id_token_signing_alg_values_supported", "claims_supported")
        out["documents"][u] = {k: doc.get(k) for k in keep if k in doc}
        issuer = doc.get("issuer")
        if issuer:
            issuers.append(str(issuer))
        pkce = doc.get("code_challenge_methods_supported") or []
        out["no_pkce"] = not bool(pkce)
        out["pkce_downgrade_surface"] = bool(pkce) and "S256" in [str(x).upper() for x in pkce]
        rt = doc.get("response_types_supported") or []
        out["implicit_flow"] = any(("token" in str(x) or "id_token" in str(x)) and "code" not in str(x)
                                   for x in rt)
        out["id_token_algs"] = [str(x) for x in (doc.get("id_token_signing_alg_values_supported") or [])]
        # redirect_uri validation probe (redirect follow NAHI karte; budget-bound)
        authz = doc.get("authorization_endpoint")
        if authz and len(authz_eps) < probe_budget:
            authz_eps.append(authz)
            evil = "https://wasp-invalid-%s.attacker-invalid.test/cb" % rand_str(4)
            q = urllib.parse.urlencode({"client_id": "wasp-probe", "response_type": "code",
                                        "redirect_uri": evil, "scope": "openid",
                                        "state": rand_str(8), "nonce": rand_str(8)})
            rr = http.request("GET", authz + ("&" if "?" in authz else "?") + q, allow_redirects=False)
            loc = rr.header("Location") or ""
            loose = (evil in loc) or (rr.status in (200, 302) and "error" not in (loc + rr.text).lower())
            out["redirect_uri_probe"] = {"url": authz, "status": rr.status,
                                         "location": loc[:200], "loose": bool(loose)}
            out["redirect_uri_loose"] = bool(loose)
            # state param requirement check
            if len(authz_eps) < probe_budget:
                q2 = urllib.parse.urlencode({"client_id": "wasp-probe", "response_type": "code",
                                             "redirect_uri": evil, "scope": "openid"})
                rr2 = http.request("GET", authz + ("&" if "?" in authz else "?") + q2,
                                   allow_redirects=False)
                loc2 = rr2.header("Location") or ""
                out["missing_state"] = bool(rr2.status in (200, 302) and "state" not in loc2.lower()
                                            and "error" not in (loc2 + rr2.text).lower())
            # v10: path-traversal variant (strict validation ko /../ se test karo) - gated
            if conf.get("auth_allow_oauth_variants", True) and not loose \
                    and len(authz_eps) < probe_budget:
                evil3 = "https://%s.attacker-invalid.test/cb" % rand_str(4)
                trav = doc.get("issuer") or "https://wasp-invalid.test"
                trav_uri = trav.rstrip("/") + "/../../" + evil3.split("//", 1)[1]
                q3 = urllib.parse.urlencode({"client_id": "wasp-probe", "response_type": "code",
                                             "redirect_uri": trav_uri, "scope": "openid",
                                             "state": rand_str(8)})
                rr3 = http.request("GET", authz + ("&" if "?" in authz else "?") + q3,
                                   allow_redirects=False)
                loc3 = rr3.header("Location") or ""
                accepted = ("attacker-invalid.test" in loc3) or \
                           (rr3.status in (200, 302) and "error" not in (loc3 + rr3.text).lower())
                out["redirect_path_variant"] = {"sent": trav_uri, "status": rr3.status,
                                                "location": loc3[:200], "accepted": bool(accepted)}
                if accepted:
                    out["redirect_uri_loose"] = True
    if len(set(issuers)) > 1:
        out["mixup_indicator"] = True
        out["issuers_seen"] = sorted(set(issuers))
    out["summary"] = ("issuer=%s | redirect_uri_loose=%s | no_pkce=%s | implicit=%s | "
                      "missing_state=%s | pkce_downgrade=%s | mixup=%s | docs=%d" % (
                          issuers[0] if issuers else "-", out["redirect_uri_loose"], out["no_pkce"],
                          out["implicit_flow"], out["missing_state"], out["pkce_downgrade_surface"],
                          out["mixup_indicator"], len(out["documents"])))
    return out


def saml_surface(http, scope, live):
    """v10: SAML surface (analysis-only) - SAMLRequest/ACS markers + metadata fetch."""
    out = {"detected": False, "markers": [], "metadata": {}, "summary": ""}
    saml_eps = [u for u, r in live.items()
                if SAML_RE.search(r.get("url") or "") or (r.get("saml_markers") or [])]
    meta_eps = [u for u in live if "saml/metadata" in u]
    if saml_eps:
        out["detected"] = True
        out["endpoints"] = saml_eps[:8]
        out["markers"] = sorted({m for u in saml_eps for m in (live[u].get("saml_markers") or [])})
    for u in meta_eps[:1]:
        r = http.request("GET", u, allow_redirects=True)
        if r.status and r.status < 400:
            eid = re.search(r"entityID=[\"']([^\"']+)", r.text or "")
            out["metadata"][u] = {"status": r.status,
                                  "entity_id": eid.group(1) if eid else None,
                                  "len": len(r.body)}
    if out["detected"] or out["metadata"]:
        out["summary"] = ("SAML surface mila: %d endpoint(s), metadata=%d - signature-wrapping "
                          "/ comment-attacks MANUAL phase me (RoE-gated)." % (
                              len(saml_eps), len(out["metadata"])))
    return out


# ---------------------------------------------------------------------------
# STAGE K - SESSION / TRANSPORT / JWT
# ---------------------------------------------------------------------------
def _is_cleartext(u):
    return urllib.parse.urlparse(u).scheme.lower() == "http"


def _jwt_tamper_probe(http, scope, endpoint, token, conf):
    """
    Gated JWT tamper probe: sirf GET endpoints par, max 2 requests.
    Do classic checks:
      1) alg=none  -> signature strip (ya empty signature)
      2) payload me privilege claim add -> purani signature ke saath
    Agar dono me se koi bhi 2xx/3xx de aur baseline 401/403 tha -> bypass signal.
    """
    res = {"attempted": False, "alg_none": {}, "claim_tamper": {}, "summary": "",
           "note": "destructive nahi; sirf read-only GET par"}
    if not conf.get("auth_allow_token_tamper_probe", True):
        res["summary"] = "disabled by config"
        return res
    parts = (token or "").split(".")
    if len(parts) < 3:
        res["summary"] = "token ke 3 segments nahi hain -> tamper skip"
        return res
    hdr = b64url_decode_json(parts[0]) or {}
    pay = b64url_decode_json(parts[1]) or {}
    base = http.request("GET", endpoint, allow_redirects=False)
    res["baseline_status"] = base.status
    if base.status is None:
        res["summary"] = "baseline GET fail hua -> tamper skip"
        return res
    res["attempted"] = True
    protected = base.status in (401, 403)

    # 1) alg=none
    h1 = dict(hdr)
    h1["alg"] = "none"
    tok1 = "%s.%s." % (b64url_encode(h1), parts[1])
    r1 = http.request("GET", endpoint, headers={"Authorization": "Bearer " + tok1},
                      allow_redirects=False)
    res["alg_none"] = {"status": r1.status,
                       "accepted": bool(r1.status and r1.status < 400 and protected)}
    # 2) claim tamper (admin=true), signature wahi purani
    p2 = dict(pay)
    p2["admin"] = True
    p2["role"] = "admin"
    p2["is_admin"] = True
    tok2 = "%s.%s.%s" % (parts[0], b64url_encode(p2), parts[2])
    r2 = http.request("GET", endpoint, headers={"Authorization": "Bearer " + tok2},
                      allow_redirects=False)
    res["claim_tamper"] = {"status": r2.status,
                           "accepted": bool(r2.status and r2.status < 400 and protected)}
    if res["alg_none"]["accepted"]:
        res["summary"] = "alg=none token ACCEPT hua (baseline %s tha)" % base.status
    elif res["claim_tamper"]["accepted"]:
        res["summary"] = "tampered payload (admin=true) ACCEPT hua - signature verify nahi ho raha"
    else:
        res["summary"] = ("tamper reject hua (baseline=%s, alg_none=%s, claim=%s) -> "
                          "signature verification lag raha hai theek" % (
                              base.status, res["alg_none"]["status"], res["claim_tamper"]["status"]))
    return res


def session_and_token_checks(http, scope, live, conf):
    """Cookies (flags + prefix rules + duplicates), transport, auth schemes, JWT."""
    cookie_report, jwt_report, scheme_report = {}, [], {}
    dup_report = {}
    for u, r in live.items():
        # cookies
        sc = r.get("set_cookie") or []
        if sc:
            cookie_report[u] = [analyze_cookie(raw, is_https=(r.get("scheme") != "http"))
                                for raw in sc]
            names = [c["name"] for c in cookie_report[u]]
            dups = sorted({n for n in names if names.count(n) > 1})
            if dups:
                dup_report[u] = dups
        # auth schemes
        wa = r.get("www_authenticate") or ""
        if wa:
            scheme_report[u] = wa
        # JWT
        for tok in (r.get("jwts") or []):
            ji = jwt_info(tok)
            ji["endpoint"] = u
            jwt_report.append(ji)
    return cookie_report, jwt_report, scheme_report, dup_report


# ---------------------------------------------------------------------------
# v10 STAGE N - INJECTION / TYPE-CONFUSION ORACLE (bounded, detection-style)
# ---------------------------------------------------------------------------
def _login_shape(r):
    """Response ka chhota fingerprint (status + json shape + len band)."""
    j = r.json(None) if hasattr(r, "json") else None
    shape = _json_error_shape(j) if isinstance(j, dict) else None
    return {"status": r.status, "len": len(r.body or b""),
            "json_shape": shape, "location": (r.header("Location") or "")[:120]}


def injection_oracle(http, scope, url, probe, conf):
    """
    Pre-auth injection oracle - SIRF synthetic identifiers:
      1) NoSQL operator (JSON $ne/$gt + form-encoded password[$ne])
      2) ek bounded 'admin' operator probe (detection; koi session use nahi hota)
      3) JSON type confusion (null / 0 / list / true)
      4) HPP (identifier double + array form)
      5) Content-Type confusion (form creds ko JSON bhejna)
      6) X-HTTP-Method-Override signal
    Signal = status ya shape MATERIALLY badla (baseline 401/403 + invalid-msg).
    auth_inject_probes budget se zyada requests KABHI nahi.
    """
    res = {"endpoint": url, "baseline": {}, "probes": [], "budget_used": 0,
           "nosql_accepted": False, "type_confusion": False, "hpp_diff": False,
           "content_type_diff": False, "summary": ""}
    budget = max(0, int(conf.get("auth_inject_probes", 10)))
    state = {"used": 0}

    def fire(label, ident, password=None, data_override=None, json_body=None,
             extra_headers=None, drop_password=False):
        if state["used"] >= budget:
            return None
        state["used"] += 1
        try:
            rurl, method, data, headers = _build_login_request(probe, ident,
                                                               password or ("WaspInvalid!" + rand_str(4)))
            if drop_password:
                data.pop("password", None)
            if data_override:
                data.update(data_override)
            h = dict(headers)
            if json_body is not None:
                h["Content-Type"] = "application/json"
                body = json.dumps(json_body).encode()
            elif any(k.endswith("[]") for k in data):
                body = urllib.parse.urlencode(data, doseq=True).encode()
            else:
                body = urllib.parse.urlencode(data).encode()
            h.update(extra_headers or {})
            r = http.request(method, rurl, headers=h, data=body, allow_redirects=False,
                             read_only_post=True)
            rec = {"label": label, "status": r.status, "shape": _login_shape(r)}
            lo, why = detect_lockout(r.status, r.text, r.headers)
            rec["throttled"] = bool(lo)
            res["probes"].append(rec)
            return r
        except Exception as e:
            res["probes"].append({"label": label, "error": truncate(repr(e), 160)})
            return None

    ident0 = synth_identifier("inj")
    base = fire("baseline", ident0, "WaspInvalid!" + rand_str(4))
    if base is None or base.status is None:
        res["summary"] = "baseline request fail hui -> oracle skip (false-positive se bachna)"
        return res
    res["baseline"] = _login_shape(base)
    base_protected = base.status in (401, 403, 429) or not (200 <= base.status < 300)
    base_invalid = bool(ENUM_MSG_RE.search(base.text or "") or GENERIC_MSG_RE.search(base.text or ""))

    def looks_bypassed(r):
        if r is None:
            return False
        if r.status and 200 <= r.status < 400 and base_protected:
            if r.status in (302, 303) or (r.header("Location") or ""):
                return True
            if not (ENUM_MSG_RE.search(r.text or "") or GENERIC_MSG_RE.search(r.text or "")):
                return True
        return False

    # 1) NoSQL JSON operator ($ne / $gt)
    for op, val in INJECT_MARKERS.items():
        if op not in ("$ne", "$gt"):
            continue
        r = fire("nosql_json:%s" % op, ident0, json_body={
            "username": ident0, "email": ident0, "password": {op: val}})
        if looks_bypassed(r):
            res["nosql_accepted"] = True

    # 1b) NoSQL form-encoded (PHP/Rails style password[$ne]=x)
    r = fire("nosql_form", ident0, data_override={"password[$ne]": "x"}, drop_password=True)
    if looks_bypassed(r):
        res["nosql_accepted"] = True

    # 2) bounded 'admin' operator probe (detection-style; sirf 1 request)
    r = fire("nosql_admin:$ne", "admin", json_body={"username": "admin", "email": "admin",
                                                    "password": {"$ne": "x"}})
    if looks_bypassed(r):
        res["nosql_accepted"] = True

    # 3) JSON type confusion (sirf 2 representative types)
    for label, tv in (("null", None), ("zero", 0)):
        r = fire("typeconf:%s" % label, ident0, json_body={
            "username": ident0, "email": ident0, "password": tv})
        if r is not None and base is not None:
            d = drf_compare(base, r)
            if looks_bypassed(r) or (d.get("diff_score", 0) >= 20 and base_invalid):
                res["type_confusion"] = True

    # 4) HPP - identifier double (form) + array form
    rurl, method, data, headers = _build_login_request(probe, ident0, "WaspInvalid!" + rand_str(4))
    uf = next((k for k in data if k in USERNAME_FIELDS), "username")
    if budget - state["used"] >= 1:
        state["used"] += 1
        try:
            body = "%s=%s&%s=%s&password=x" % (uf, ident0, uf, ident0)
            r = http.request(method, rurl, headers=dict(headers, **{"Content-Type":
                                         "application/x-www-form-urlencoded"}),
                             data=body.encode(), allow_redirects=False, read_only_post=True)
            res["probes"].append({"label": "hpp_double", "status": r.status,
                                  "shape": _login_shape(r)})
            if base is not None:
                d = drf_compare(base, r)
                if d.get("diff_score", 0) >= 20 or looks_bypassed(r):
                    res["hpp_diff"] = True
        except Exception as e:
            res["probes"].append({"label": "hpp_double", "error": truncate(repr(e), 160)})
    if budget - state["used"] >= 1:
        state["used"] += 1
        try:
            body = "%s[]=%s&password=x" % (uf, ident0)
            r = http.request(method, rurl, headers=dict(headers, **{"Content-Type":
                                         "application/x-www-form-urlencoded"}),
                             data=body.encode(), allow_redirects=False, read_only_post=True)
            res["probes"].append({"label": "hpp_array", "status": r.status,
                                  "shape": _login_shape(r)})
            if base is not None:
                d = drf_compare(base, r)
                if d.get("diff_score", 0) >= 20 or looks_bypassed(r):
                    res["hpp_diff"] = True
        except Exception as e:
            res["probes"].append({"label": "hpp_array", "error": truncate(repr(e), 160)})

    # 5) Content-Type confusion (form creds as JSON)
    r = fire("ct_confusion", ident0, data_override={}, json_body={
        "username": ident0, "email": ident0, "password": "WaspInvalid!" + rand_str(4)})
    if r is not None and base is not None:
        d = drf_compare(base, r)
        if d.get("diff_score", 0) >= 20 or (r.status != base.status and base_invalid):
            res["content_type_diff"] = True

    # 6) method override signal (1 request; sirf record, finding nahi)
    fire("method_override", ident0, "WaspInvalid!" + rand_str(4),
         extra_headers={"X-HTTP-Method-Override": "PUT"})

    res["budget_used"] = state["used"]
    res["summary"] = ("budget_used=%d | nosql=%s | typeconf=%s | hpp=%s | ct_diff=%s" % (
        state["used"], res["nosql_accepted"], res["type_confusion"], res["hpp_diff"],
        res["content_type_diff"]))
    return res


# ---------------------------------------------------------------------------
# v10 STAGE P - CORS PROBE (auth endpoints, bounded)
# ---------------------------------------------------------------------------
def cors_probe(http, scope, url, conf=None):
    """Origin echo + credentials check - 2 requests max, invalid .test origins."""
    conf = conf or {}
    res = {"endpoint": url, "origin": INVALID_ORIGIN, "reflected": False, "wildcard": False,
           "credentials": False, "origin_null_reflected": False, "allow_methods": ""}
    r = http.request("GET", url, headers={"Origin": INVALID_ORIGIN}, allow_redirects=False)
    acao = r.header("Access-Control-Allow-Origin") or ""
    acac = (r.header("Access-Control-Allow-Credentials") or "").strip().lower()
    res["reflected"] = (acao.strip() == INVALID_ORIGIN)
    res["wildcard"] = (acao.strip() == "*")
    res["credentials"] = (acac == "true")
    res["allow_methods"] = (r.header("Access-Control-Allow-Methods") or "")[:120]
    if res["reflected"]:
        r2 = http.request("GET", url, headers={"Origin": NULL_ORIGIN}, allow_redirects=False)
        res["origin_null_reflected"] = ((r2.header("Access-Control-Allow-Origin") or "").strip()
                                        in ("null", NULL_ORIGIN))
    res["verdict"] = ("cred-reflection" if res["reflected"] and res["credentials"]
                      else "wildcard" if res["wildcard"]
                      else "reflection-only" if res["reflected"] else "tight")
    res["summary"] = ("acao=%s | credentials=%s | null_reflected=%s -> %s" % (
        acao or "-", res["credentials"], res["origin_null_reflected"], res["verdict"]))
    return res


# ---------------------------------------------------------------------------
# v10 STAGE Q - AUTH PAGE HARDENING (passive, 0 requests)
# ---------------------------------------------------------------------------
def auth_hardening_report(live):
    """Stage B probes ke responses se (0 extra requests):
    clickjacking, cacheable auth response, referrer-policy, autocomplete,
    SameSite=None-without-Secure, webauthn aggregate."""
    out = {"endpoints": {}, "clickjacking": [], "cacheable": [], "samesite_issues": [],
           "autocomplete_on": [], "webauthn_seen": [], "summary": ""}
    for u, r in live.items():
        h = r.get("hardening") or {}
        entry = {"scheme": r.get("scheme"), "status": r.get("status")}
        is_html = "html" in (r.get("content_type") or "").lower()
        if is_html:
            xfo, fa = h.get("x_frame_options"), h.get("frame_ancestors")
            if not xfo and not fa:
                entry["clickjacking"] = True
                out["clickjacking"].append(u)
            cc = h.get("cache_control")
            entry["cache_control"] = cc
            if not (cc and NO_STORE_RE.search(cc)):
                entry["cacheable"] = True
                entry["cdn_hints"] = h.get("cdn_hints") or []
                out["cacheable"].append(u)
            if not h.get("referrer_policy"):
                entry["referrer_policy_missing"] = True
        for raw in (r.get("set_cookie") or []):
            low = raw.lower()
            if "samesite=null" in low and "secure" not in low:
                nm = raw.split("=", 1)[0]
                entry.setdefault("samesite_issue", nm)
                out["samesite_issues"].append({"endpoint": u, "cookie": nm})
        pol = r.get("password_policy_hint") or {}
        if pol.get("autocomplete", "").lower() == "on" or \
                (pol.get("autocomplete") == "" and r.get("has_password")):
            entry["password_autocomplete"] = "on/unspecified"
            out["autocomplete_on"].append(u)
        if r.get("webauthn"):
            out["webauthn_seen"].append(u)
        out["endpoints"][u] = entry
    out["summary"] = ("clickjacking=%d | cacheable=%d | samesite=%d | autocomplete=%d | "
                      "webauthn=%d" % (len(out["clickjacking"]), len(out["cacheable"]),
                                       len(out["samesite_issues"]), len(out["autocomplete_on"]),
                                       len(out["webauthn_seen"])))
    return out


# ---------------------------------------------------------------------------
# v10 STAGE R - OPEN REDIRECT / REFLECTION / CRLF (bounded GET probes)
# ---------------------------------------------------------------------------
def redirect_reflection_probe(http, scope, url, probe, conf):
    """
    Auth endpoints ke redirect params par (GET only, .test hosts):
      1) open redirect - Location attacker-invalid.test par?
      2) reflection    - benign marker page me wapas aaya? context classify
      3) CRLF          - %0d%0a header injection indicator
    """
    res = {"endpoint": url, "params_tested": [], "open_redirect": False, "reflection": [],
           "crlf": False, "summary": ""}
    params = [p for p in (probe.get("redirect_params") or [])][:2]
    if not params:
        res["summary"] = "koi redirect param nahi mila -> skip (0 requests)"
        return res
    evil_host = "wasp-redir-%s.attacker-invalid.test" % rand_str(4)
    base_u = probe.get("final_url") or url
    sep = "&" if "?" in base_u else "?"
    for p in params:
        # 1) open redirect
        val = "https://%s/cb" % evil_host
        r = http.request("GET", "%s%s%s=%s" % (base_u, sep, p, urllib.parse.quote(val, safe="")),
                         allow_redirects=False)
        loc = r.header("Location") or ""
        hit = bool(r.status in (301, 302, 303, 307, 308) and evil_host in loc)
        res["params_tested"].append({"param": p, "probe": "open_redirect", "status": r.status,
                                     "location": loc[:160], "redirected": hit})
        if hit:
            res["open_redirect"] = True
        # 2) reflection (benign marker)
        if conf.get("auth_allow_reflection_probe", True):
            marker = REFLECT_MARKER + rand_str(3)
            r2 = http.request("GET", "%s%s%s=%s" % (base_u, sep, p,
                                                    urllib.parse.quote(marker, safe="")),
                              allow_redirects=True)
            body = r2.text or ""
            if marker in body:
                idx = body.index(marker)
                ctx = body[max(0, idx - 40):idx + 40]
                kind = ("attr" if re.search(r"=\s*[\"'][^\"']*$", ctx) else
                        "js" if re.search(r"(script|var|')\s*$", ctx, re.I) else "html")
                res["reflection"].append({"param": p, "context": kind,
                                          "status": r2.status, "snippet": truncate(ctx, 100)})
        # 3) CRLF header injection
        r3 = http.request("GET", "%s%s%s=%s" % (base_u, sep, p, CRLF_PROBE),
                          allow_redirects=False)
        hdr_names = {k.lower() for k, v in (r3.headers.items() if r3.headers else [])}
        if "x-wasp-probe" in hdr_names:
            res["crlf"] = True
            res["params_tested"].append({"param": p, "probe": "crlf", "status": r3.status,
                                         "injected_header": True})
    res["summary"] = ("params=%s | open_redirect=%s | reflection=%d | crlf=%s" % (
        [p["param"] if isinstance(p, dict) else p for p in params], res["open_redirect"],
        len(res["reflection"]), res["crlf"]))
    return res


# ---------------------------------------------------------------------------
# v10 STAGE S - JWT DEEP ANALYSIS (offline, 0 requests)
# ---------------------------------------------------------------------------
def _dup_json_keys(payload_text):
    """JSON payload me duplicate object keys (parser discrepancy indicator)."""
    dups = []

    def hook(pairs):
        seen = {}
        for k, _v in pairs:
            seen[k] = seen.get(k, 0) + 1
        dups.extend([k for k, c in seen.items() if c > 1])
        return dict(pairs)

    try:
        json.loads(payload_text, object_pairs_hook=hook)
    except Exception:
        return []
    return sorted(set(dups))


def jwt_deep_analysis(jwt_report, live, oauth_report):
    """Pre-auth JWTs par offline deep checks: key-injection headers (jku/x5u/x5c/jwk),
    duplicate claims, exp-iat lifetime, token-in-URL, HS256 confusion candidate."""
    out = {"analyzed": 0, "key_injection": [], "duplicate_claims": [], "long_lived": [],
           "confusion_candidates": [], "token_in_url": [], "notes": []}
    jwks_known = False
    for _u, doc in ((oauth_report or {}).get("documents") or {}).items():
        if doc.get("jwks_uri"):
            jwks_known = True
            out["notes"].append("jwks_uri discovery se mila: %s" % doc.get("jwks_uri"))
    for u, r in live.items():
        if r.get("token_in_url"):
            out["token_in_url"].append(u)
    for ji in jwt_report or []:
        out["analyzed"] += 1
        hdr = ji.get("header") or {}
        pay = ji.get("payload") or {}
        key_urls = [hdr.get(k) for k in ("jku", "x5u") if hdr.get(k)]
        if key_urls or any(k in hdr for k in ("x5c", "jwk")):
            rec = {"endpoint": ji.get("endpoint"), "jku": hdr.get("jku"), "x5u": hdr.get("x5u"),
                   "has_x5c": "x5c" in hdr, "has_jwk": "jwk" in hdr}
            out["key_injection"].append(rec)
            ji["key_injection_headers"] = rec
        # duplicate claims: raw payload segment parse
        tok = None
        for u2, r2 in live.items():
            for t in (r2.get("jwts") or []):
                if jwt_info(t).get("header") == hdr and u2 == ji.get("endpoint"):
                    tok = t
                    break
        if not tok and ji.get("preview"):
            tok = None
        if tok:
            seg = tok.split(".")[1]
            seg += "=" * (-len(seg) % 4)
            try:
                raw = base64.urlsafe_b64decode(seg.encode()).decode("utf-8", "replace")
                dk = _dup_json_keys(raw)
                if dk:
                    ji["duplicate_claims"] = dk
                    out["duplicate_claims"].append({"endpoint": ji.get("endpoint"),
                                                    "claims": dk})
            except Exception:
                pass
        exp, iat = pay.get("exp"), pay.get("iat")
        try:
            if exp and iat and (float(exp) - float(iat)) > 86400:
                ji["lifetime_hours"] = round((float(exp) - float(iat)) / 3600.0, 1)
                out["long_lived"].append({"endpoint": ji.get("endpoint"),
                                          "hours": ji["lifetime_hours"]})
        except Exception:
            pass
        alg = (ji.get("alg") or "").upper()
        if jwks_known and (alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES")):
            out["confusion_candidates"].append({"endpoint": ji.get("endpoint"), "alg": alg})
            ji["hs256_confusion_candidate"] = True
    return out


# ---------------------------------------------------------------------------
# v10 STAGE U - BRUTE-FORCE DEFENSE COMPOSITE SCORE
# ---------------------------------------------------------------------------
def defense_score(login_eps, live, rl_report, enum_report, mfa_report, csrf_report):
    """Per-login-endpoint stuffing-readiness score (0-6). Analysis-only."""
    out = {"endpoints": {}, "weak": [], "strong": [], "summary": ""}
    for u in login_eps:
        pts = []
        enum_res = ((enum_report.get("endpoints") or {}).get(u)) or {}
        rl_res = (rl_report or {}).get(u) or {}
        pts.append(("generic_error", 1 if not enum_res.get("enumeration_likely") else 0))
        pts.append(("rate_limit", 1 if rl_res.get("throttled") else 0))
        pts.append(("lockout_model", 1 if rl_res.get("lockout_model", "none") not in (None, "none") else 0))
        pts.append(("captcha", 1 if (live.get(u, {}) or {}).get("captcha") else 0))
        pts.append(("csrf_token", 1 if (live.get(u, {}) or {}).get("csrf_present") else 0))
        pts.append(("mfa_present", 1 if bool(mfa_report) else 0))
        score = sum(v for _k, v in pts)
        verdict = ("weak" if score <= 2 else "moderate" if score <= 4 else "strong")
        out["endpoints"][u] = {"score": score, "max": 6, "verdict": verdict,
                               "points": dict(pts)}
        if verdict == "weak":
            out["weak"].append(u)
        elif verdict == "strong":
            out["strong"].append(u)
    out["summary"] = ("logins=%d | weak=%d | moderate=%d | strong=%d" % (
        len(login_eps), len(out["weak"]),
        len([e for e, v in out["endpoints"].items() if v["verdict"] == "moderate"]),
        len(out["strong"])))
    return out


# ---------------------------------------------------------------------------
# STAGE L - AUTH STATE MACHINE
# ---------------------------------------------------------------------------
def build_state_machine(live, login_eps, reset_eps, mfa_eps, reg_eps, oidc, oauth_eps=None):
    def p(u):
        return urllib.parse.urlparse(u).path or u
    L = ["# Authentication State Machine (auto-mapped)", "",
         "Phase 9 me observed transitions. `stateDiagram-v2` ko Mermaid renderer me kholo.", "",
         "```mermaid", "stateDiagram-v2", "    [*] --> Anonymous"]
    if reg_eps:
        L.append("    Anonymous --> Registration : GET %s" % p(reg_eps[0]))
        L.append("    Registration --> Credentials : form submit")
    L.append("    Anonymous --> Credentials : GET %s" % (p(login_eps[0]) if login_eps else "/login"))
    L.append("    Credentials --> Authenticated : valid credentials")
    if mfa_eps:
        L.append("    Credentials --> MFA_Challenge : MFA enforced")
        L.append("    MFA_Challenge --> Authenticated : valid OTP")
        L.append("    MFA_Challenge --> MFA_Challenge : invalid OTP")
    if reset_eps:
        L.append("    Credentials --> Password_Reset : GET %s" % p(reset_eps[0]))
        L.append("    Password_Reset --> Credentials : token accepted")
    if oidc:
        L.append("    Anonymous --> SSO_Provider : OIDC discovery")
        L.append("    SSO_Provider --> Authenticated : code exchanged")
    L.append("    Authenticated --> Anonymous : logout")
    L.append("```")
    L += ["", "## Endpoint inventory", "",
          "| Role | Endpoint | Status | Form | CSRF | Transport |",
          "|---|---|---|---|---|---|"]
    for role, eps in (("login", login_eps), ("reset", reset_eps), ("mfa", mfa_eps),
                      ("register", reg_eps)):
        for u in eps:
            r = live.get(u, {})
            L.append("| %s | `%s` | %s | %s | %s | %s |" % (
                role, p(u), r.get("status"),
                "yes" if r.get("has_password") else "-",
                "yes" if r.get("csrf_present") else "-",
                r.get("scheme") or "-"))
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# STAGE M - REPORTS
# ---------------------------------------------------------------------------
def write_reports(out, scope, F, ctx):
    save_json(os.path.join(out, "findings.json"),
              {"engagement": scope.engagement, "phase": PHASE, "plan_version": PLAN_VERSION,
               "generated_at": now_iso(), "count": len(F.items), "findings": F.items})

    md = ["# Phase 9 - Authentication Testing Findings", "",
          "- **Engagement:** `%s`" % scope.engagement,
          "- **Generated:** `%s`" % now_iso(),
          "- **Engine:** WASP v%s / auth plan v%s" % (VERSION, PLAN_VERSION),
          "- **Endpoints probed:** `%d`" % ctx.get("live_count", 0),
          "- **Findings:** `%d`" % len(F.items), ""]
    if not F.items:
        md.append("Is bounded, non-destructive run me koi auth weakness **confirm** nahi hui. "
                  "Isko 'secure' mat samjho - `auth_test_plan.md` ke hypotheses manually test karo.")
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
    # v10: defense composite score section
    defense = ctx.get("defense_score") or {}
    if defense.get("endpoints"):
        md += ["## Brute-force defense composite score (v10)", "",
               "Score 0-6: generic-error + rate-limit + lockout + captcha + CSRF + MFA. "
               "<=2 = weak (stuffing-ready), 3-4 = moderate, >=5 = strong.", "",
               "| Endpoint | Score | Verdict | Points |", "|---|---|---|---|"]
        for u, v in defense["endpoints"].items():
            md.append("| `%s` | %s/6 | **%s** | %s |" % (
                urllib.parse.urlparse(u).path or u, v["score"], v["verdict"],
                ", ".join(k for k, okv in v["points"].items() if okv) or "koi control nahi"))
        md.append("")
    # v10: injection oracle section
    inj = ctx.get("inj_report") or {}
    if inj:
        md += ["## Injection / type-confusion oracle (v10)", ""]
        for u, r in inj.items():
            md.append("- `%s` -> %s" % (urllib.parse.urlparse(u).path or u,
                                        r.get("summary", "")))
        md.append("")
    save_text(os.path.join(out, "AUTH_FINDINGS.md"), "\n".join(md) + "\n")

    coverage = ctx.get("coverage", {})
    write_test_plan(out, scope, ctx.get("hypotheses", []), F, coverage, ctx.get("stats_summary", {}))

    routing = {
        "to_phase10_sessions_jwt": {
            "endpoints": sorted(ctx.get("live", {}).keys())[:50],
            "preauth_jwts": len(ctx.get("jwt_report", [])),
            "cookies_seen": sum(len(v) for v in (ctx.get("cookie_report") or {}).values()),
            "cookie_issues": "cookie_flags.json",
            "jwt_details": "preauth_jwt.json"},
        "to_phase11_idor": {"login_endpoints": list((ctx.get("enum_report") or {}).get("endpoints", {}).keys())},
        "to_phase12_params": {"candidate_fields": sorted(set(
            f["name"] for r in ctx.get("live", {}).values()
            for form in r.get("forms", []) for f in form.get("fields", [])))},
        "to_phase13_injection": {"login_endpoints": list((ctx.get("enum_report") or {}).get("endpoints", {}).keys())},
        "to_phase14_xss": {"login_endpoints": list((ctx.get("enum_report") or {}).get("endpoints", {}).keys()),
                           "reflected_candidates": [
                               {"endpoint": u, "params": [r.get("param") for r in
                                                           (v.get("reflection") or [])]}
                               for u, v in (ctx.get("redir_report") or {}).items()
                               if v.get("reflection")]},
        "to_phase15_ssrf": {"host_header_candidates": [u for u, r in (ctx.get("reset_report") or {}).items()
                                                       if r.get("host_header_reflected")],
                            "jwt_key_injection": (ctx.get("jwt_deep") or {}).get("key_injection", []),
                            "cors": {u: v.get("verdict") for u, v in (ctx.get("cors_report") or {}).items()}},
        "to_phase16_logic": {"reset_endpoints": list((ctx.get("reset_report") or {}).keys()),
                             "mfa_endpoints": list((ctx.get("mfa_report") or {}).keys()),
                             "register_endpoints": list((ctx.get("reg_report") or {}).keys()),
                             "injection_oracle": {u: {"nosql": v.get("nosql_accepted"),
                                                      "typeconf": v.get("type_confusion")}
                                                  for u, v in (ctx.get("inj_report") or {}).items()},
                             "defense_score": (ctx.get("defense_score") or {}).get("endpoints", {})},
        "to_phase18_graphql": {"note": "auth endpoints par GraphQL ho sakta hai - Phase 7/8 dekho"},
        "to_phase23_secrets": {"debug_leaks": [u for u, r in ctx.get("live", {}).items()
                                               if r.get("debug_leak")]},
        "to_phase32_report": {"findings": len(F.items), "severity_mix": _sev_mix(F),
                              "test_plan": "auth_test_plan.md"},
    }
    ff = write_feedforward(out, PHASE, routing,
                           notes=["Bounded, non-destructive auth testing; attempts capped.",
                                  "Synthetic identifiers reserved .test TLD par - koi real mailbox nahi chhua.",
                                  "Har hypothesis ke saath kill-test auth_test_plan.md me hai."])
    files = ["auth_endpoints.txt", "auth_surface.json", "auth_buckets.json", "user_enumeration.json",
             "rate_limit_report.json", "reset_flow_analysis.json", "mfa_analysis.json",
             "registration_analysis.json", "oauth_analysis.json", "saml_surface.json",
             "cookie_flags.json", "preauth_jwt.json", "csrf_binding.json",
             "injection_oracle.json", "auth_http_hardening.json", "auth_cors.json",
             "auth_redirect_xss.json", "auth_state_machine.md",
             "AUTH_FINDINGS.md", "auth_test_plan.md", "findings.json",
             "feedforward.json", "MANIFEST.json"]
    write_manifest(out, PHASE, files,
                   stats={"endpoints_probed": ctx.get("live_count", 0),
                          "findings": len(F.items), "severity_mix": _sev_mix(F),
                          "hypotheses": len(ctx.get("hypotheses", [])),
                          "lockout_abort": bool(ctx.get("aborted")),
                          "injection_budget_used": sum(
                              v.get("budget_used", 0) for v in (ctx.get("inj_report") or {}).values()),
                          "defense_weak": len((ctx.get("defense_score") or {}).get("weak", []))},
                   notes=["deterministic where possible; stats use fixed RNG seed",
                          "v10 ULTRA PRO MAX: injection oracle + CORS + hardening + redirect "
                          "probes bounded by auth_* config knobs"])
    return ff


def _sev_mix(F):
    mix = {}
    for f in F.items:
        mix[f["severity"]] = mix.get(f["severity"], 0) + 1
    return mix


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

    head("Phase 9 - Authentication Testing (v%s) | %s" % (PLAN_VERSION, scope.describe()))
    # v10 SAFETY FIX: allow_active ab poora honor hota hai (v9 me sirf warning thi)
    ACTIVE = bool(getattr(cfg, "allow_active", True))
    if not ACTIVE:
        warn("allow_active=False -> DISCOVERY + PASSIVE-ONLY mode: enum/rate-limit/reset/MFA/"
             "injection/redirect probes sab skip honge (koi login attempt nahi).")

    F = Findings()
    ctx = {"live": {}, "hypotheses": [], "coverage": {}, "stats_summary": {}, "aborted": False}

    # ---------------- Stage A ----------------
    head("Stage A - Auth surface discovery")
    key = "stageA:discovery"
    if cp.is_done(key):
        ranked = cp.result_of(key) or []
        ok("Replayed %d candidates (checkpoint)" % len(ranked))
    else:
        ranked = discover_auth_surface(base_dir, scope, out, conf)
        cp.mark(key, ranked, summary="auth candidates")
    if not ranked:
        err("Koi auth candidate nahi mila. Phase 2-8 pehle chalao, ya scope.json me target add karo.")
        ctx["coverage"]["auth_surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx)
        return out
    ok("%d auth candidate endpoints (priority order me)" % len(ranked))
    save_text(os.path.join(out, "auth_endpoints.txt"),
              "\n".join("%-6s %-8s %s" % (r.get("priority"), r.get("confidence", "-"), r["url"])
                        for r in ranked))
    if ranked and ranked[0].get("priority"):
        info("Phase 8 ka top auth target: %s (priority=%s, classes=%s)" % (
            ranked[0]["url"], ranked[0]["priority"], ",".join(ranked[0].get("classes") or []) or "-"))

    # ---------------- Stage B ----------------
    head("Stage B - Probe & auth-flow mapping (read-only)")
    probes = {}
    for i, r in enumerate(ranked, 1):
        u = r["url"]
        ck = "probe:" + u
        if cp.is_done(ck):
            probes[u] = cp.result_of(ck) or {}
            continue
        rec = probe_endpoint(http, u, conf)
        rec["phase8"] = {"priority": r.get("priority"), "classes": r.get("classes"),
                         "confidence": r.get("confidence"), "why": r.get("why")}
        probes[u] = rec
        cp.mark(ck, rec, summary="probe")
        if rec.get("status"):
            ok("[%d/%d] %s -> %s forms=%d csrf=%s" % (
                i, len(ranked), u, rec["status"], len(rec.get("forms") or []),
                rec.get("csrf_present")))
        else:
            warn("[%d/%d] %s -> %s" % (i, len(ranked), u, rec.get("error")))
        if cp.is_done("__abort__"):
            break
    # v10 FIX: live sirf REAL responses (status < 400). v9 me 404 endpoints bhi
    # 'live' the -> buckets me dead endpoints aage nikal jaate the (login_eps[:3]
    # jaise slices dead URLs par waste) + 404-page false positives (enum/ratelimit).
    dead = [u for u, r in probes.items() if r.get("status") and r["status"] >= 400]
    live = {u: r for u, r in probes.items() if r.get("status") and r["status"] < 400}
    if dead:
        info("%d dead/error endpoints buckets se hata diye (status>=400)" % len(dead))
    ok("%d/%d endpoints LIVE (status<400)" % (len(live), len(ranked)))
    ctx["live"] = live
    ctx["live_count"] = len(live)
    save_json(os.path.join(out, "auth_surface.json"), probes)

    login_eps = [u for u, r in live.items()
                 if r.get("has_password") or LOGIN_HINT_RE.search(urllib.parse.urlparse(u).path)]
    reset_eps = [u for u, r in live.items() if RESET_HINT_RE.search(urllib.parse.urlparse(u).path)]
    mfa_eps = [u for u, r in live.items() if MFA_HINT_RE.search(urllib.parse.urlparse(u).path)]
    reg_eps = [u for u, r in live.items()
               if REGISTER_HINT_RE.search(urllib.parse.urlparse(u).path) or r.get("register_form")]
    oauth_eps = [u for u, r in live.items() if OAUTH_HINT_RE.search(urllib.parse.urlparse(u).path)]
    save_json(os.path.join(out, "auth_buckets.json"),
              {"login": login_eps, "reset": reset_eps, "mfa": mfa_eps,
               "register": reg_eps, "oauth": oauth_eps})
    info("buckets: login=%d reset=%d mfa=%d register=%d oauth=%d" % (
        len(login_eps), len(reset_eps), len(mfa_eps), len(reg_eps), len(oauth_eps)))

    # ---- v10 passive surface findings (0 extra requests) ----
    wp_hit, na_hit, wa_hit = False, False, False
    for u, r in live.items():
        path_u = urllib.parse.urlparse(u).path
        if not wp_hit and r.get("wp_users"):
            F.add("wordpress_users_exposed", "WP REST users endpoint usernames dump karta hai",
                  u, "/wp-json/wp/v2/users 200 + JSON list - enumeration feed.",
                  evidence_ref="auth_surface.json")
            wp_hit = True
        if not na_hit and NEXTAUTH_PATH_RE.search(path_u) and "providers" in path_u:
            F.add("nextauth_surface", "NextAuth/Auth.js provider endpoint exposed", u,
                  "/api/auth/providers reachable - SSO providers disclose hote hain.",
                  evidence_ref="auth_surface.json")
            na_hit = True
        if not wa_hit and r.get("webauthn"):
            F.add("webauthn_detected", "WebAuthn/passkey flows detect hue", u,
                  "Auth page me webauthn/credentials API markers mile.",
                  evidence_ref="auth_surface.json")
            wa_hit = True
        if r.get("token_in_url"):
            F.add("token_in_url_transport", "Auth token URL query me transport hota hai", u,
                  "token/jwt/access_token query param mila - Referer/logs/browser-history leak risk.",
                  evidence_ref="auth_surface.json")

    # transport check (cleartext auth)
    for u in login_eps:
        if _is_cleartext(u):
            F.add("cleartext_auth_transport", "Login endpoint HTTP par hai (cleartext)",
                  u, "Credentials plaintext me network par jaayenge.",
                  evidence_ref="auth_surface.json")

    # debug leak check
    for u, r in live.items():
        if r.get("debug_leak"):
            F.add("sensitive_error_disclosure", "Auth endpoint stack trace / debug info leak karta hai",
                  u, "Response me debug signature mila.", evidence_ref="auth_surface.json")

    # weak scheme check
    for u, r in live.items():
        wa = (r.get("www_authenticate") or "").lower()
        if wa and ("basic" in wa or "ntlm" in wa):
            F.add("weak_auth_scheme", "Weak HTTP auth scheme expose hua",
                  u, "WWW-Authenticate: %s" % r.get("www_authenticate"),
                  evidence_ref="http_auth_schemes.json")

    # ---------------- Stage C: CSRF binding ----------------
    head("Stage C - CSRF token binding test")
    csrf_report = {}
    for u in [x for x in login_eps + reg_eps if (live.get(x, {}).get("csrf_present"))][:3]:
        ck = "csrf:" + u
        if cp.is_done(ck):
            csrf_report[u] = cp.result_of(ck) or {}
            continue
        res = csrf_token_binding(http, scope, u, live[u], conf)
        csrf_report[u] = res
        cp.mark(ck, res, summary="csrf binding")
        if res.get("static"):
            F.add("csrf_token_static", "CSRF token session-bound nahi hai", u,
                  res.get("summary", ""), evidence_ref="csrf_binding.json")
    for u in login_eps + reg_eps:
        r = live.get(u, {})
        if r.get("status") and r.get("forms") and not r.get("csrf_present"):
            if r.get("has_password"):
                F.add("csrf_missing", "Auth form me CSRF token nahi mila", u,
                      "Form mila par koi csrf/xsrf/_token field nahi tha.",
                      evidence_ref="auth_surface.json")
    save_json(os.path.join(out, "csrf_binding.json"), csrf_report)
    ctx["csrf_report"] = csrf_report

    # ---------------- Stage D: enumeration ----------------
    head("Stage D - User enumeration (DRF-v2 + JSON oracle + robust timing)")
    enum_report = {"endpoints": {}, "heuristic_enabled": conf["auth_allow_heuristic_enum"],
                   "stats_method": "welch+mannwhitney+cliffsdelta+bootstrap"}
    if conf["auth_allow_heuristic_enum"] and ACTIVE and not cp.is_done("__abort__"):
        for u in login_eps[:3]:
            ck = "enum:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP enum (done) %s" % u)
            else:
                res = enum_login_endpoint(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="enum")
            # v10 FIX: findings derivation REPLAY par bhi chale (v9 me sirf
            # fresh path par hota tha -> resume par findings gayab ho jaate the)
            enum_report["endpoints"][u] = res
            if res.get("locked_out"):
                warn("Enumeration ke dauraan lockout -> aage ke active stages band")
                cp.mark("__abort__", {"reason": "lockout", "stage": "enum"}, summary="abort")
                ctx["aborted"] = True
                break
            if res.get("enumeration_likely"):
                F.add("user_enumeration", "User enumeration (response differential)",
                      u, res.get("summary", ""), evidence_ref="user_enumeration.json",
                      extra={"signals": res.get("enumeration_signals")})
            if (res.get("timing") or {}).get("timing_anomaly"):
                F.add("timing_enumeration", "Timing-based user enumeration",
                      u, json.dumps(res.get("timing"), default=str)[:300],
                      evidence_ref="user_enumeration.json")
            if (res.get("signals") or {}).get("json_oracle"):
                F.add("json_oracle_enumeration", "JSON error-code oracle se enumeration",
                      u, json.dumps(res["signals"]["json_oracle"], default=str)[:300],
                      evidence_ref="user_enumeration.json")
    elif not conf["auth_allow_heuristic_enum"]:
        info("Heuristic enumeration config se disabled hai.")
    save_json(os.path.join(out, "user_enumeration.json"), enum_report)
    ctx["enum_report"] = enum_report

    # ---------------- Stage N (v10): injection / type-confusion oracle ----------------
    head("Stage N (v10) - Injection / type-confusion oracle (NoSQL, HPP, CT-confusion)")
    inj_report = {}
    if not cp.is_done("__abort__") and ACTIVE and conf.get("auth_allow_injection_oracle", True) \
            and login_eps:
        for u in login_eps[:2]:
            ck = "inj:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP injection oracle (done) %s" % u)
            else:
                res = injection_oracle(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="injection oracle")
            inj_report[u] = res
            if res.get("nosql_accepted"):
                F.add("nosql_operator_accepted", "NoSQL operator login bypass candidate",
                      u, res.get("summary", ""), evidence_ref="injection_oracle.json",
                      extra={"note": "confirm manual me karo - sirf ek bounded probe bheja gaya"})
                warn("NoSQL operator ACCEPT hua %s -> manual confirm karo (Critical candidate)" % u)
            if res.get("type_confusion"):
                F.add("json_type_confusion_signal", "JSON type confusion par behaviour badalta hai",
                      u, res.get("summary", ""), evidence_ref="injection_oracle.json")
            if res.get("hpp_diff"):
                F.add("hpp_response_diff", "Parameter pollution se response differential",
                      u, res.get("summary", ""), evidence_ref="injection_oracle.json")
            if res.get("content_type_diff"):
                F.add("content_type_behavior_diff", "Form vs JSON body par alag behaviour",
                      u, res.get("summary", ""), evidence_ref="injection_oracle.json")
            if cp.is_done("__abort__"):
                break
    elif not ACTIVE:
        info("Injection oracle skip (allow_active=False).")
    save_json(os.path.join(out, "injection_oracle.json"), inj_report)
    ctx["inj_report"] = inj_report

    # ---------------- Stage E/F: rate limit ----------------
    head("Stage E/F - Rate-limit, lockout model & bypass matrix")
    rl_report = {}
    if not cp.is_done("__abort__") and ACTIVE:
        for u in login_eps[:3]:
            ck = "ratelimit:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP rate-limit (done) %s" % u)
            else:
                res = rate_limit_probe(http, scope, u, live[u], conf)
                if res.get("throttled") and int(conf["auth_bypass_probes"]) > 0:
                    res["bypass_matrix"] = rate_limit_bypass_matrix(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="rate-limit")
            # v10 FIX: findings derivation replay par bhi (incl. saved bypass_matrix)
            if (res.get("bypass_matrix") or {}).get("bypass_likely"):
                F.add("lockout_bypass",
                      "Rate-limit/lockout bypassable (%s)" % res["bypass_matrix"].get("bypass_type"),
                      u, res["bypass_matrix"].get("summary", ""),
                      evidence_ref="rate_limit_report.json")
            if not res.get("throttled"):
                F.add("no_rate_limit", "Auth endpoint par effective rate limiting nahi",
                      u, res.get("summary", ""), evidence_ref="rate_limit_report.json")
            rl_report[u] = res
            if res.get("locked_out"):
                warn("Lockout sentinel tripped -> active stages halt")
                cp.mark("__abort__", {"reason": "lockout", "stage": "ratelimit"}, summary="abort")
                ctx["aborted"] = True
                break
    else:
        if ACTIVE:
            warn("Active stages skip (pehle lockout sentinel laga tha).")
        else:
            info("Rate-limit stage skip (passive-only mode).")
    save_json(os.path.join(out, "rate_limit_report.json"), rl_report)
    ctx["rl_report"] = rl_report

    # ---------------- Stage G: reset ----------------
    head("Stage G - Password reset flow analysis")
    reset_report = {}
    if not cp.is_done("__abort__") and conf["auth_allow_reset_probe"] and ACTIVE:
        for u in reset_eps[:4]:
            ck = "reset:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP reset (done) %s" % u)
            else:
                res = reset_flow_analysis(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="reset flow")
            reset_report[u] = res
            if (res.get("token") or {}).get("weak"):
                F.add("reset_token_weak", "Weak / predictable password-reset token", u,
                      json.dumps(res["token"], default=str)[:400], evidence_ref="reset_flow_analysis.json")
            if res.get("host_header_reflected"):
                F.add("reset_host_header_injection", "Host header reset link me inject hota hai", u,
                      "Injected host response body/Location me reflect hua.",
                      evidence_ref="reset_flow_analysis.json")
            if res.get("header_variants"):
                F.add("reset_header_poison_extended",
                      "Reset link alternate header se bhi poison hua (X-Original-URL/Proto)", u,
                      "variants=%s" % json.dumps(res["header_variants"], default=str)[:300],
                      evidence_ref="reset_flow_analysis.json")
            if res.get("token_in_response"):
                F.add("reset_token_disclosure", "Password-reset token HTTP response me disclose hua", u,
                      "Reset POST ke response body me token-shaped value mili.",
                      evidence_ref="reset_flow_analysis.json")
            if res.get("enumeration_likely"):
                F.add("reset_enumeration", "Reset endpoint account existence leak karta hai", u,
                      res.get("summary", ""), evidence_ref="reset_flow_analysis.json")
    elif not conf["auth_allow_reset_probe"]:
        info("Reset probing config se disabled hai.")
    save_json(os.path.join(out, "reset_flow_analysis.json"), reset_report)
    ctx["reset_report"] = reset_report

    # ---------------- Stage H: MFA ----------------
    head("Stage H - MFA / OTP flow analysis")
    mfa_report = {}
    if not cp.is_done("__abort__") and ACTIVE:
        for u in mfa_eps[:4]:
            ck = "mfa:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP mfa (done) %s" % u)
            else:
                res = mfa_flow_analysis(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="mfa flow")
            mfa_report[u] = res
            if res.get("status_oracle") or res.get("json_oracle"):
                F.add("mfa_status_oracle", "MFA verify endpoint state leak karta hai", u,
                      res.get("summary", ""), evidence_ref="mfa_analysis.json")
            if res.get("no_ratelimit"):
                F.add("mfa_no_ratelimit", "OTP verification par rate limit nahi", u,
                      res.get("summary", ""), evidence_ref="mfa_analysis.json")
            if res.get("weak_otp_policy"):
                F.add("mfa_weak_otp_policy", "OTP policy kamzor (chhota length)", u,
                      json.dumps(res.get("otp_shape"), default=str)[:250],
                      evidence_ref="mfa_analysis.json")
            if res.get("locked_out"):
                cp.mark("__abort__", {"reason": "lockout", "stage": "mfa"}, summary="abort")
                ctx["aborted"] = True
                break
    save_json(os.path.join(out, "mfa_analysis.json"), mfa_report)
    ctx["mfa_report"] = mfa_report

    # ---------------- Stage I: registration ----------------
    head("Stage I - Registration flow analysis")
    reg_report = {}
    for u in reg_eps[:3]:
        ck = "reg:" + u
        if cp.is_done(ck):
            res = cp.result_of(ck) or {}
            ok("SKIP register (done) %s" % u)
        else:
            res = registration_analysis(http, scope, u, live[u], conf)
            cp.mark(ck, res, summary="register")
        reg_report[u] = res
        if res.get("enumeration_likely"):
            F.add("registration_enumeration", "Registration account existence leak karta hai", u,
                  res.get("summary", ""), evidence_ref="registration_analysis.json")
        if (res.get("static") or {}).get("policy_hint", {}).get("weak_hint"):
            F.add("password_policy_weak", "Client-side password policy kamzor", u,
                  json.dumps(res["static"]["policy_hint"], default=str)[:250],
                  evidence_ref="registration_analysis.json")
        if res.get("open_registration"):
            F.add("registration_open", "Registration khula hai", u,
                  "Public signup enabled - attack surface note karo.",
                  evidence_ref="registration_analysis.json")
    save_json(os.path.join(out, "registration_analysis.json"), reg_report)
    ctx["reg_report"] = reg_report

    # ---------------- Stage J: OAuth ----------------
    head("Stage J - OAuth / OIDC discovery & redirect_uri validation")
    oauth_report = {}
    saml_report = {}
    oidc = [u for u in live if "openid-configuration" in u or "oauth-authorization-server" in u]
    if oidc:
        ck = "oauth:discovery"
        if cp.is_done(ck):
            oauth_report = cp.result_of(ck) or {}
            ok("SKIP oauth discovery (done)")
        else:
            oauth_report = oauth_discovery(http, scope, oidc, conf)
            cp.mark(ck, oauth_report, summary="oauth discovery")
        if oauth_report.get("redirect_uri_loose"):
            F.add("oauth_redirect_uri_loose", "OAuth redirect_uri validation permissive lag rahi hai",
                  ", ".join(oidc), oauth_report.get("summary", ""), evidence_ref="oauth_analysis.json")
        if oauth_report.get("no_pkce"):
            F.add("oauth_no_pkce", "OIDC provider PKCE support nahi karta", ", ".join(oidc),
                  oauth_report.get("summary", ""), evidence_ref="oauth_analysis.json")
        if oauth_report.get("implicit_flow"):
            F.add("oauth_implicit_flow", "Implicit flow enabled hai", ", ".join(oidc),
                  oauth_report.get("summary", ""), evidence_ref="oauth_analysis.json")
        if oauth_report.get("missing_state"):
            F.add("oauth_missing_state", "Authorization endpoint 'state' ke bina bhi chalta hai",
                  ", ".join(oidc), oauth_report.get("summary", ""), evidence_ref="oauth_analysis.json")
        if oauth_report.get("pkce_downgrade_surface"):
            F.add("oauth_pkce_downgrade_surface", "PKCE optional/downgrade surface", ", ".join(oidc),
                  "S256 supported hai par enforce nahi lagta - public client me downgrade try karo.",
                  evidence_ref="oauth_analysis.json")
        if oauth_report.get("mixup_indicator"):
            F.add("oauth_mixup_indicator", "OAuth mix-up attack indicator (multiple issuers)",
                  ", ".join(oidc), "issuers=%s" % (oauth_report.get("issuers_seen") or []),
                  evidence_ref="oauth_analysis.json")
    else:
        info("OIDC discovery document nahi mila -> Stage J skip.")
    save_json(os.path.join(out, "oauth_analysis.json"), oauth_report)
    ctx["oauth_report"] = oauth_report

    # ---- v10 Stage T: SAML + SSO surface ----
    saml_report = saml_surface(http, scope, live)
    if saml_report.get("detected") or saml_report.get("metadata"):
        F.add("saml_surface_detected", "SAML SSO surface detect hua", ", ".join(oidc or ["-"]),
              saml_report.get("summary", ""), evidence_ref="oauth_analysis.json")
    save_json(os.path.join(out, "saml_surface.json"), saml_report)
    ctx["saml_report"] = saml_report

    # ---------------- Stage K: cookies / JWT / schemes ----------------
    head("Stage K - Session cookies, auth schemes & pre-auth tokens")
    cookie_report, jwt_report, scheme_report, dup_report = session_and_token_checks(
        http, scope, live, conf)
    for u, cookies in cookie_report.items():
        for c in cookies:
            if c.get("missing"):
                F.add("cookie_flags_missing", "Session cookie hardening missing", u,
                      "cookie '%s' missing: %s" % (c.get("name"), ", ".join(c["missing"])),
                      evidence_ref="cookie_flags.json")
            if c.get("prefix_violations"):
                F.add("cookie_prefix_violation", "Cookie name prefix rules violate hue", u,
                      "cookie '%s': %s" % (c.get("name"), "; ".join(c["prefix_violations"])),
                      evidence_ref="cookie_flags.json")
    for u, names in dup_report.items():
        F.add("duplicate_cookie_names", "Duplicate cookie names set hue", u,
              "names=%s (session tossing/fixation risk)" % ",".join(names),
              evidence_ref="cookie_flags.json")
    save_json(os.path.join(out, "cookie_flags.json"), cookie_report)
    if scheme_report:
        save_json(os.path.join(out, "http_auth_schemes.json"), scheme_report)

    tamper_results = {}
    for ji in jwt_report:
        if ji.get("privilege_claims"):
            F.add("jwt_sensitive_claims", "JWT me privilege claims plaintext me hain",
                  ji.get("endpoint"), "claims=%s" % ",".join(ji["privilege_claims"]),
                  evidence_ref="preauth_jwt.json")
        if ji.get("kid") or ji.get("jku"):
            F.add("jwt_kid_injection", "JWT header me kid/jku injection indicator",
                  ji.get("endpoint"), "kid=%s jku=%s" % (ji.get("kid"), ji.get("jku")),
                  evidence_ref="preauth_jwt.json")
        if ji.get("alg") in ("none", "HS256") or not ji.get("has_exp"):
            F.add("preauth_jwt_weak", "Pre-auth JWT weak alg ya missing expiry",
                  ji.get("endpoint"), "alg=%s has_exp=%s" % (ji.get("alg"), ji.get("has_exp")),
                  evidence_ref="preauth_jwt.json")
    # gated tamper probe (sirf GET endpoints, max 2 requests, active-mode only)
    if conf.get("auth_allow_token_tamper_probe", True) and jwt_report and ACTIVE:
        cand = None
        for ji in jwt_report:
            ep = ji.get("endpoint") or ""
            if ep and not _is_cleartext(ep):
                cand = ji
                break
        if cand:
            ck = "jwttamper:" + str(cand.get("endpoint"))
            if cp.is_done(ck):
                tamper_results[cand["endpoint"]] = cp.result_of(ck)
            else:
                tok = ""
                for u, r in live.items():
                    if u == cand["endpoint"] and r.get("jwts"):
                        tok = r["jwts"][0]
                if tok:
                    tr = _jwt_tamper_probe(http, scope, cand["endpoint"], tok, conf)
                    tamper_results[cand["endpoint"]] = tr
                    cp.mark(ck, tr, summary="jwt tamper")
                    if (tr.get("alg_none") or {}).get("accepted"):
                        F.add("jwt_alg_none_accepted", "alg=none JWT accept hua", cand["endpoint"],
                              tr.get("summary", ""), evidence_ref="preauth_jwt.json")
                    elif (tr.get("claim_tamper") or {}).get("accepted"):
                        F.add("jwt_signature_not_verified", "Tampered JWT payload accept hua",
                              cand["endpoint"], tr.get("summary", ""), evidence_ref="preauth_jwt.json")
    # ---- v10 Stage S: JWT deep analysis (offline, 0 requests) ----
    jwt_deep = jwt_deep_analysis(jwt_report, live, oauth_report)
    for rec in jwt_deep.get("key_injection", []):
        F.add("jwt_key_injection_headers", "JWT header me key-injection headers (jku/x5u/x5c/jwk)",
              rec.get("endpoint") or "-",
              "jku=%s x5u=%s x5c=%s jwk=%s - SSRF/attacker-key surface." % (
                  rec.get("jku"), rec.get("x5u"), rec.get("has_x5c"), rec.get("has_jwk")),
              evidence_ref="preauth_jwt.json")
    for rec in jwt_deep.get("duplicate_claims", []):
        F.add("jwt_duplicate_claims", "JWT payload me duplicate claims (parser discrepancy)",
              rec.get("endpoint") or "-", "claims=%s" % ",".join(rec.get("claims") or []),
              evidence_ref="preauth_jwt.json")
    for rec in jwt_deep.get("long_lived", []):
        F.add("jwt_long_lived", "Pre-auth JWT bahut lambi validity ka", rec.get("endpoint") or "-",
              "lifetime_hours=%s (>24h) - theft window bada." % rec.get("hours"),
              evidence_ref="preauth_jwt.json")
    for rec in jwt_deep.get("confusion_candidates", []):
        F.add("jwt_hs256_confusion_candidate", "HS256/RS256 key-confusion candidate",
              rec.get("endpoint") or "-",
              "alg=%s + jwks_uri public - wasp_config.py 'bypass jwt' se offline variants banao." % rec.get("alg"),
              evidence_ref="preauth_jwt.json")
    save_json(os.path.join(out, "preauth_jwt.json"),
              {"tokens": jwt_report, "tamper_probe": tamper_results, "deep": jwt_deep})
    ctx["jwt_deep"] = jwt_deep

    # ---- v10 Stage Q+P: auth-page hardening (passive) + CORS probe ----
    head("Stage P/Q (v10) - CORS probe + auth-page hardening (clickjacking/cache/SameSite)")
    hard_report = auth_hardening_report(live)
    for u in (hard_report.get("clickjacking") or [])[:3]:
        if any(urllib.parse.urlparse(u).path.lower().find(k) >= 0 for k in ("login", "signin", "auth")):
            F.add("auth_clickjacking", "Auth page frame-able hai (XFO/CSP frame-ancestors missing)",
                  u, "login UI-redress/login-CSRF possible.", evidence_ref="auth_http_hardening.json")
            break
    for u in (hard_report.get("cacheable") or [])[:3]:
        F.add("auth_response_cacheable", "Auth response cache-control ke bina", u,
              "cache_control missing/no-store nahi + CDN hints=%s" %
              ((hard_report["endpoints"].get(u) or {}).get("cdn_hints") or []),
              evidence_ref="auth_http_hardening.json")
        break
    for iss in (hard_report.get("samesite_issues") or [])[:3]:
        F.add("cookie_flags_missing", "SameSite=None bina Secure flag ke",
              iss.get("endpoint") or "-", "cookie '%s'" % iss.get("cookie"),
              evidence_ref="auth_http_hardening.json")
    for u in (hard_report.get("autocomplete_on") or [])[:2]:
        F.add("password_autocomplete_on", "Password field autocomplete on/unspecified", u,
              "policy note - shared systems par risk.", evidence_ref="auth_http_hardening.json")
    save_json(os.path.join(out, "auth_http_hardening.json"), hard_report)

    cors_report = {}
    if ACTIVE and conf.get("auth_allow_cors_probe", True):
        for u in list(live)[:max(1, int(conf.get("auth_cors_endpoints", 3)))]:
            res = cors_probe(http, scope, u, conf)
            cors_report[u] = res
            if res.get("reflected") and res.get("credentials"):
                F.add("cors_cred_reflection", "CORS arbitrary Origin reflect + credentials",
                      u, res.get("summary", ""), evidence_ref="auth_cors.json")
            elif res.get("wildcard"):
                F.add("cors_wildcard", "Auth endpoint par Access-Control-Allow-Origin: *",
                      u, res.get("summary", ""), evidence_ref="auth_cors.json")
    else:
        info("CORS probe skip (%s)." % ("passive mode" if not ACTIVE else "config"))
    save_json(os.path.join(out, "auth_cors.json"), cors_report)
    ctx["cors_report"] = cors_report

    # ---- v10 Stage R: open redirect / reflection / CRLF ----
    redir_report = {}
    if ACTIVE and conf.get("auth_allow_redirect_probe", True):
        cand_eps = [x for x in (login_eps + reset_eps) if (live.get(x, {}).get("redirect_params"))]
        for u in cand_eps[:max(1, int(conf.get("auth_redirect_endpoints", 2)))]:
            ck = "redir:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
            else:
                res = redirect_reflection_probe(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="redirect/reflection")
            redir_report[u] = res
            if res.get("open_redirect"):
                F.add("auth_open_redirect", "Auth redirect param open-redirect karta hai",
                      u, res.get("summary", ""), evidence_ref="auth_redirect_xss.json")
            for rfl in res.get("reflection", [])[:2]:
                F.add("auth_reflected_input", "Auth page input reflect karta hai (pre-auth XSS candidate)",
                      u, "param=%s context=%s - manual XSS confirm karo." % (
                          rfl.get("param"), rfl.get("context")),
                      evidence_ref="auth_redirect_xss.json")
            if res.get("crlf"):
                F.add("crlf_injection_auth", "CRLF header-injection indicator auth endpoint par",
                      u, res.get("summary", ""), evidence_ref="auth_redirect_xss.json")
    else:
        info("Redirect/reflection probe skip (%s)." % ("passive mode" if not ACTIVE else "config"))
    save_json(os.path.join(out, "auth_redirect_xss.json"), redir_report)
    ctx["redir_report"] = redir_report

    # ---------------- Stage L/M: state machine + reports ----------------
    head("Stage L/M - Auth state machine, hypotheses & reports")
    sm = build_state_machine(live, login_eps, reset_eps, mfa_eps, reg_eps, oidc)
    save_text(os.path.join(out, "auth_state_machine.md"), sm)

    hypotheses = build_hypotheses(F, enum_report, rl_report, reset_report, mfa_report,
                                  reg_report, oauth_report, cookie_report, jwt_report,
                                  csrf_report, live, inj_report=inj_report,
                                  redir_report=redir_report, hard_report=hard_report,
                                  jwt_deep=jwt_deep, cors_report=cors_report)
    ctx["hypotheses"] = hypotheses
    ctx["cookie_report"] = cookie_report
    ctx["jwt_report"] = jwt_report

    # ---- v10 Stage U: brute-force defense composite score ----
    defense = defense_score(login_eps, live, rl_report, enum_report, mfa_report, csrf_report)
    for u in (defense.get("weak") or [])[:3]:
        F.add("brute_force_defense_weak", "Login brute-force defense composite score WEAK",
              u, "score=%s/6 points=%s - stuffing-ready." % (
                  defense["endpoints"][u]["score"], defense["endpoints"][u]["points"]),
              evidence_ref="AUTH_FINDINGS.md")
    ctx["defense_score"] = defense

    # stats summary (professor-facing: ek jagah saare numbers)
    stats_summary = {}
    for u, r in (enum_report.get("endpoints") or {}).items():
        t = r.get("timing") or {}
        stats_summary[u] = {k: t.get(k) for k in
                            ("median_plausible_ms", "median_bogus_ms", "robust_z", "welch_t",
                             "mw_p", "cliffs_delta", "cliffs_size", "verdict", "bootstrap")
                            if k in t}
    ctx["stats_summary"] = stats_summary

    # coverage matrix (kya test hua, kya nahi)
    def mark(cond, yes, no):
        return yes if cond else no
    ctx["coverage"] = {
        "auth surface discovery": mark(bool(ranked), "%d endpoints" % len(ranked), "none"),
        "form/flow mapping": mark(bool(live), "%d live" % len(live), "none"),
        "CSRF token binding": mark(bool(csrf_report), "%d endpoint(s)" % len(csrf_report),
                                   "koi CSRF-protected form nahi"),
        "user enumeration": mark(bool(enum_report.get("endpoints")),
                                 "%d endpoint(s)" % len(enum_report.get("endpoints") or {}),
                                 "login endpoint nahi mila"),
        "rate-limit / lockout": mark(bool(rl_report), "%d endpoint(s)" % len(rl_report),
                                     "test nahi hua"),
        "lockout model classified": mark(any(v.get("lockout_model") not in (None, "none")
                                             for v in rl_report.values()),
                                         "haan", "throttle observe nahi hui"),
        "bypass matrix": mark(any("bypass_matrix" in v for v in rl_report.values()),
                              "chala", "throttle nahi mila -> skip"),
        "password reset flow": mark(bool(reset_report), "%d endpoint(s)" % len(reset_report),
                                    "reset endpoint nahi mila"),
        "MFA / OTP flow": mark(bool(mfa_report), "%d endpoint(s)" % len(mfa_report),
                               "MFA endpoint nahi mila"),
        "registration flow": mark(bool(reg_report), "%d endpoint(s)" % len(reg_report),
                                  "registration endpoint nahi mila"),
        "OAuth / OIDC": mark(bool(oauth_report), "discovery doc mila", "OIDC nahi mila"),
        "session cookie hardening": mark(bool(cookie_report),
                                         "%d host(s)" % len(cookie_report), "cookie nahi mila"),
        "pre-auth JWT": mark(bool(jwt_report), "%d token(s)" % len(jwt_report),
                             "koi pre-auth JWT nahi mila"),
        "JWT tamper probe": mark(bool(tamper_results),
                                 "chala", "token nahi mila ya disabled"),
        "cleartext transport": mark(any(_is_cleartext(u) for u in login_eps),
                                    "HTTP login mila", "sab HTTPS"),
        # ---- v10 additions ----
        "injection / type oracle": mark(bool(inj_report),
                                        "%d endpoint(s), budget=%s" % (
                                            len(inj_report),
                                            sum(v.get("budget_used", 0) for v in inj_report.values())),
                                        "skip (config/passive)"),
        "NoSQL operator probe": mark(any(v.get("nosql_accepted") for v in inj_report.values()),
                                     "ACCEPT mila (confirm karo)",
                                     "reject/synthetic fail"),
        "CORS probe": mark(bool(cors_report), "%d endpoint(s)" % len(cors_report),
                           "skip (config/passive)"),
        "auth page hardening": mark(bool(hard_report), hard_report.get("summary", ""), "n/a"),
        "open redirect / reflection": mark(bool(redir_report),
                                           "%d endpoint(s)" % len(redir_report),
                                           "redirect params nahi mile ya skip"),
        "JWT deep (offline)": mark(bool(jwt_deep.get("analyzed")),
                                   "%d token(s)" % jwt_deep.get("analyzed", 0),
                                   "koi pre-auth JWT nahi"),
        "SAML surface": mark(bool(saml_report.get("detected") or saml_report.get("metadata")),
                             "mila", "SAML nahi mila"),
        "defense score": mark(bool(defense.get("endpoints")),
                              defense.get("summary", ""), "login endpoints nahi mile"),
        "passive-only mode": mark(not ACTIVE, "haan (allow_active=False)", "nahi (full mode)"),
    }
    write_reports(out, scope, F, ctx)

    dt = time.time() - t_start
    head("Phase 9 complete in %.1fs" % dt)
    ok("Findings=%d | hypotheses=%d | endpoints=%d" % (len(F.items), len(hypotheses), len(live)))
    info("READ FIRST: AUTH_FINDINGS.md -> auth_test_plan.md -> auth_state_machine.md")
    if ctx.get("aborted"):
        warn("Lockout sentinel ne active stages roke - ye SAFE behaviour hai, bug nahi.")
    return out
