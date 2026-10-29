#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 2 - App Understanding & Threat Model  [v3.0.0-ULTRA PRO MAX]
===================================================================================
LOW-noise, authenticated-friendly understanding pass - ab ULTRA intelligence ke saath.

v2 CONTRACT 100% PRESERVED (superset, additive):
  - Har target: HTTP baseline + redirect chain, security header audit (grade+missing),
    tech hints, cookie flags, HTML surface (forms/inputs/links/JS/meta/CSRF),
    JS quick-scan (endpoints + secret patterns), THREAT_MODEL.md
  - Outputs (same names/format): understand.json, endpoints.txt, api_endpoints.txt,
    js_urls.txt, header_flags.txt, interesting.txt, secret_hits.json, forms.json,
    THREAT_MODEL.md, feedforward.json, MANIFEST.json

ULTRA v3 NAYE TECHNIQUES (25):
  1. CSP deep analyzer (unsafe-inline/eval, wildcard *, missing default-src,
     script-src gaps) + csp_weakness.txt
  2. Cookie ULTRA: __Host-/__Secure- prefix validation, session-cookie naming
     (P10 handoff), attribute contradictions, SameSite=None without Secure flag
  3. Form classifier (auth/search/upload/payment/settings) + autocomplete audit
     (password w/o current-password, GET-method password form flag)
  4. Hidden-field inventory -> mass-assignment candidates (P11 handoff)
  5. PII field detector (email/phone/address/ssn/card) -> PII inventory
  6. HTML state-leak extractor (__NEXT_DATA__, __INITIAL_STATE__, nuxt,
     apollo-state) -> endpoints + tokens inside
  7. Comment/leak miner (TODO/FIXME, internal hostnames, emails, stack traces)
  8. JS miner v2: fetch/axios patterns, ws:// wss:// sockets, GraphQL operations,
     source-map (.map) refs, api-prefix paths
  9. ULTRA secret patterns: OpenAI/Anthropic/SendGrid/Twilio/npm/PyPI/Telegram/
     GCP OAuth client, alg:none JWT heuristic, AWS secret context heuristic
  10. Perimeter/WAF detection from artifacts (cf/__cf_bm/akamai/incapsula/...)
      -> waf_edge.txt + P4/P6/P8 handoff
  11. Redirect ULTRA: open-redirect hint (cross-domain hop), scheme downgrade
  12. SRI (subresource integrity) audit on cross-origin scripts
  13. Mixed-content detector (http:// assets on https:// page)
  14. Meta leaks: generator, canonical, robots, well-known hints
  15. Tech MAP++ (SvelteKit/Astro/Remix/Vite/Supabase/Auth0/Sentry/GTM/Stripe/
     Razorpay/hCaptcha/Turnstile...)
  16. Attack-surface score per target (explainable, weighted)
  17. attack_surface.txt (ranked + reasons)
  18. THREAT_MODEL.md v2: STRIDE auto-hypotheses, abuse cases, attack trees,
     PII inventory, API risk table
  19. understand_diff.json (re-run par new/gone/changed)
  20. cookies.txt, forms_classified.txt, csp_report.txt, state_leaks.json,
     mixed_content.txt, sri_audit.txt
  21. Feedforward superset: P3/P4/P5/P6/P7/P8/P9/P10/P11/P12/P22/P23/P32
  22. RWX STANDING RULE: har result file+folder 0777 (core + mod guard dono)
  23. Layer 4 aligned: GET/HEAD-only requests (HttpClient read-only gate)
  24. Budget-aware: understand_js_max (default 60), understands budget kill-switch
  25. Graceful on ORIGINAL v2 core (drop-in, REGISTRY untouched)

SAFETY: read-only recon (GET/HEAD), scope-enforced, secrets REDACTED (4-char),
sirf in-scope JS fetch hota hai. ULTRA core AUR original v2 core dono par chalta hai.
"""
import os, re, json
import urllib.parse as up
from wasp_core import (module_ctx, write_feedforward, write_manifest, ProbeCache,
                       normalize_url, host_of, save_json, save_text, sha1, rand_str,
                       title_of, redact, info, ok, warn, err, head, now_iso)

NAME = "understand"
PHASE = "2-understanding"
ENGINE_VERSION = "3.0.0-ultra"

# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# Ye guard core ke save_json/save_text ke upar wrapper lagata hai - isliye
# IS module ka HAR result file (json/txt/md) + uska folder hamesha rwx hoga,
# ULTRA core ho ya ORIGINAL v2 core (graceful degrade par bhi).
# ===========================================================================
def _rwx_result(path):
    """Result file/folder par rwxrwxrwx (0777) enforce (best-effort, Windows-safe)."""
    try:
        os.chmod(path, 0o777)
    except Exception:
        pass

_core_save_json, _core_save_text = save_json, save_text


def _rwx_save_json(path, obj):
    _core_save_json(path, obj)
    _rwx_result(path)                           # result file -> rwx
    _rwx_result(os.path.dirname(path) or ".")   # result folder -> rwx


def _rwx_save_text(path, text):
    _core_save_text(path, text)
    _rwx_result(path)                           # result file -> rwx
    _rwx_result(os.path.dirname(path) or ".")   # result folder -> rwx


save_json = _rwx_save_json      # module rebind: is mod ke SAARE result writes rwx
save_text = _rwx_save_text

_core_write_manifest = write_manifest


def _rwx_tree(root):
    """FINAL SWEEP (RWX RULE): module ke poore result tree par rwxrwxrwx."""
    try:
        for _dp, _dn, _fn in os.walk(root):
            _rwx_result(_dp)
            for _n in _fn:
                _rwx_result(os.path.join(_dp, _n))
    except Exception:
        pass


def _rwx_write_manifest(out, *a, **k):
    r = _core_write_manifest(out, *a, **k)
    _rwx_tree(out)                  # FINAL SWEEP: jitna likha gaya, sab rwx
    return r


write_manifest = _rwx_write_manifest
# ======================== end RWX STANDING RULE ============================

# ---------------------------------------------------------------------------
# v2 TABLES (100% preserved) + ULTRA superset
# ---------------------------------------------------------------------------
SEC_HEADERS = [  # v2 grade isi 9 par - touch nahi
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]
ULTRA_HEADERS = ["origin-agent-cluster", "x-permitted-cross-domain-policies",
                 "clear-site-data", "report-to", "nel"]  # bonus grade (alag)

SECRET_PATTERNS = [  # v2 preserved + ULTRA rows
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"ASIA[0-9A-Z]{16}", "aws_temp_credential"),
    (r"AIza[0-9A-Za-z_\-]{35}", "google_api_key"),
    (r"ya29\.[0-9A-Za-z_\-]{20,}", "google_oauth_token"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "stripe_secret_live"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "stripe_restricted"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "slack_token"),
    (r"ghp_[0-9A-Za-z]{36}", "github_pat"),
    (r"glpat-[0-9A-Za-z_\-]{20,}", "gitlab_pat"),
    (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}", "jwt"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private_key"),
    (r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", "generic_secret"),
    (r"(?i)[a-z0-9_.-]+\.firebaseio\.com", "firebase_endpoint"),
    (r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"<>]{10,}", "db_uri"),
    # ---- ULTRA additions ----
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "anthropic_api_key"),
    (r"sk-(?:proj-|None)[0-9A-Za-z_\-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ", "openai_api_key"),
    (r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", "sendgrid_key"),
    (r"SK[a-f0-9]{32}", "twilio_api_key"),
    (r"key-[0-9a-zA-Z]{32}", "mailgun_key"),
    (r"npm_[A-Za-z0-9]{36}", "npm_token"),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-=]{40,}", "pypi_token"),
    (r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{32,}", "telegram_bot_token"),
    (r"[0-9]{10,12}-[a-z0-9]{32}\.apps\.googleusercontent\.com", "gcp_oauth_client"),
    (r"ssh-rsa AAAA[0-9A-Za-z+/]{40,}", "ssh_public_key"),
    (r"(?i)alg['\"]?\s*[:=]\s*['\"](?:none|HS256)['\"]", "jwt_weak_alg_hint"),
    (r"(?i)Authorization['\"]?\s*[:=]\s*['\"]Bearer\s+[A-Za-z0-9_\-\.]{20,}", "bearer_in_source"),
    (r"(?i)(?:aws)?_?secret_?_?access_?_?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "aws_secret_context"),
]

TECH_MAP = {  # v2 preserved + ULTRA rows
    "WordPress": ["wp-content", "wp-includes", "/wp-json"],
    "Drupal": ["sites/default", "drupal-settings"],
    "Joomla": ["/components/com_", "joomla"],
    "Magento": ["mage/cookies", "/static/version"],
    "React": ["react-dom", "__react", "data-reactroot"],
    "Angular": ["ng-version", "angular.min", "ng-app"],
    "Vue": ["vue.min", "vue.js", "data-v-"],
    "Next.js": ["__next_data__", "/_next/"],
    "Nuxt": ["__nuxt__", "/_nuxt/"],
    "Svelte": ["svelte-"],
    "jQuery": ["jquery.min", "jquery.js"],
    "Bootstrap": ["bootstrap.min", "bootstrap.css"],
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "Laravel": ["laravel_session", "xsrf-token"],
    "Django": ["csrfmiddlewaretoken"],
    "Rails": ["csrf-token", "_rails_session"],
    "Spring": ["jsessionid"],
    "ASP.NET": ["__viewstate", "asp.net_sessionid"],
    "PHP": ["phpsessid", "x-powered-by: php"],
    "GraphQL": ["graphql"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["microsoft-iis"],
    "Express": ["x-powered-by: express"],
    # ---- ULTRA additions ----
    "SvelteKit": ["__sveltekit", "/_app/immutable"],
    "Astro": ["astro-island", "data-astro"],
    "Remix": ["__remixContext", "remix-run"],
    "Vite": ["/assets/index-", "vite/preload-helper"],
    "Tailwind": ["tailwind", "cdn.tailwindcss.com"],
    "Supabase": ["supabase.co", "supabase"],
    "Auth0": ["auth0.com", "auth0-spa-js"],
    "Firebase Auth": ["firebaseio.com", "firebaseapp.com", "identitytoolkit"],
    "Sentry": ["sentry.io", "ingest.sentry", "@sentry"],
    "Google Tag Manager": ["googletagmanager.com"],
    "Google Analytics": ["google-analytics.com", "gtag("],
    "Matomo": ["matomo.js", "piwik.js"],
    "Hotjar": ["hotjar.com"],
    "Stripe.js": ["js.stripe.com"],
    "Razorpay": ["checkout.razorpay.com"],
    "PayPal": ["paypal.com/sdk"],
    "Plaid": ["plaid.com/link"],
    "hCaptcha": ["hcaptcha.com"],
    "reCAPTCHA": ["recaptcha/api.js", "grecaptcha"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com/turnstile"],
    "Cloudflare Workers": ["workers.dev", "cf-worker"],
    "Keycloak": ["keycloak", "/realms/"],
    "Okta": ["okta.com", "okta-"],
    "WebSockets": ["ws://", "wss://"],
    "SourceMap": [".js.map", "sourceMappingURL"],
}

# ---------------------------------------------------------------------------
# v2 REGEXES (preserved) + ULTRA
# ---------------------------------------------------------------------------
FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
ATTR_RE = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))')
FIELD_RE = re.compile(r"<(input|select|textarea)\b[^>]*>", re.I)
LINK_RE = re.compile(r"""(?i)<a[^>]+href\s*=\s*["']([^"']+)["']""")
SCRIPT_RE = re.compile(r"""(?i)<script[^>]+src\s*=\s*["']([^"']+)["']""")

RE_JS_ENDPOINT = re.compile(r"""["'`](/[A-Za-z0-9_?&=./\-]{2,90})["'`]""")
RE_FETCH = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.open|\.ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'`]([^"'`\s]{2,220})["'`]""", re.I)
RE_WS = re.compile(r"""(?:wss?)://[A-Za-z0-9_.:/\-]{4,120}""", re.I)
RE_GQL_OP = re.compile(r"""(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]{2,50})""")
RE_SMAP = re.compile(r"""sourceMappingURL=([^\s'"]+)""")
RE_STATE_JSON = re.compile(r"""(__NEXT_DATA__|__NUXT__|__INITIAL_STATE__|__INITIAL_PROPS__|__APOLLO_STATE__|__PRELOADED_STATE__|window\.__data)\s*=\s*""")
RE_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_INTERNAL_HOST = re.compile(r"(?i)\b(?:internal|intranet|corp|local|dev|staging|stage|uat|qa|test)[-.][a-z0-9.-]+\.[a-z]{2,}\b")
RE_EXT_SKIP = re.compile(r"(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)$")

PII_HINTS = {
    "email": ("email", r"(?i)^(email|mail|user_?email|email_?address)$"),
    "phone": ("phone", r"(?i)^(phone|mobile|tel|cell|contact_?number|msisdn)$"),
    "address": ("address", r"(?i)(address|street|city|state|zip|postal|country)"),
    "name": ("name", r"(?i)^(first_?name|last_?name|full_?name|fname|lname|name)$"),
    "dob": ("dob", r"(?i)(dob|birth|birthdate|date_of_birth)"),
    "government_id": ("gov-id", r"(?i)(ssn|aadhaar|pan|passport|national_?id|nin)"),
    "payment": ("payment", r"(?i)(card|cvv|cvc|iban|account_?number|routing|upi)"),
    "gender": ("gender", r"(?i)^(gender|sex)$"),
}

FORM_CLASSES = [
    ("auth", r"(?i)(login|signin|sign-in|log[-_]?on|auth)"),
    ("registration", r"(?i)(register|signup|sign-up|create[-_]?account|join)"),
    ("password_reset", r"(?i)(forgot|reset[-_]?password|recover|password[-_]?reset)"),
    ("password_change", r"(?i)(change[-_]?password|changepwd|update[-_]?password)"),
    ("search", r"(?i)(search|query|find)"),
    ("upload", r"(?i)(upload|import|attach)"),
    ("payment", r"(?i)(pay|checkout|billing|order|purchase|cart)"),
    ("profile_settings", r"(?i)(profile|settings|preferences|account[-_]?update)"),
    ("contact", r"(?i)(contact|feedback|enquiry|inquiry)"),
    ("newsletter", r"(?i)(subscribe|newsletter|mailing[-_]?list)"),
    ("mfa", r"(?i)(otp|2fa|mfa|totp|verify[-_]?(?:code|otp)|authenticator)"),
]

# JS-body endpoint endpoint names worth flagging (P5/P11 hints)
JUICY_EP_RE = re.compile(r"(?i)/(admin|api|internal|debug|test|token|auth|user|account|"
                         r"upload|export|download|billing|payment|webhook|oauth|sso|"
                         r"graphql|rest|v\d+(?:/|$)|invite|share|report|settings|role)")

PERIMETER_SIGS = {  # ULTRA: artifact-level edge detection
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm", "cf_chl"],
    "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid"],
    "Akamai": ["x-akamai-transformed", "akamai-grn", "akamai"],
    "Imperva/Incapsula": ["x-iinfo", "visid_incap", "incap_ses"],
    "Sucuri": ["x-sucuri-id", "sucuri_cloudproxy_uuid"],
    "F5 BIG-IP": ["x-wa-info", "x-cnection", "bigipserver"],
    "Fastly": ["x-fastly-request-id", "x-served-by", "fastly"],
    "Azure Front Door": ["x-azure-ref", "x-fd-healthprobe", "arraffinity"],
    "Google Cloud LB": ["x-cloud-trace-context", "x-guploader"],
    "Varnish": ["x-varnish", "x-drupal-cache"],
    "Squid": ["x-squid-error"],
    "Envoy/Istio": ["x-envoy", "istio"],
    "Kong": ["x-kong", "kong-admin"],
    "APISIX": ["x-apisix"],
    "Traefik": ["x-traefik"],
}

CSP_WEAK = [
    ("unsafe-inline", r"(?i)script-src[^;]*'unsafe-inline'"),
    ("unsafe-eval", r"(?i)script-src[^;]*'unsafe-eval'"),
    ("wildcard-star", r"(?i)(?:default-src|script-src)\s+[^;]*\*"),
    ("no-default-src", r"^(?!.*default-src)"),
    ("data:-in-script-src", r"(?i)script-src[^;]*data:"),
    ("http:-in-script-src", r"(?i)script-src[^;]*http:"),
    ("missing-frame-ancestors", r"^(?!.*frame-ancestors)"),
    ("missing-object-src", r"^(?!.*object-src)"),
    ("wide-report-uri", r"(?i)report-uri\s+https?://(?!self)"),
]

DEFAULTS_CFG = {
    "understand_js_max": 60,       # ULTRA: max JS fetches per target (budget)
    "understand_state_leak_max": 4000,  # state JSON parse cap
}

# ---------------------------------------------------------------------------
# v2 HELPERS (100% preserved)
# ---------------------------------------------------------------------------
def attrs_of(tag):
    out = {}
    for m in ATTR_RE.finditer(tag or ""):
        v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else (m.group(4) or ""))
        out[m.group(1).lower()] = v
    return out


def parse_forms(html, base_url):
    forms = []
    for fm in FORM_RE.finditer(html or ""):
        end = html.find(">", fm.start())
        a = attrs_of(html[fm.start():end + 1] if end != -1 else "")
        action = up.urljoin(base_url, a.get("action") or base_url)
        fields = []
        for im in FIELD_RE.finditer(fm.group(1)):
            ia = attrs_of(im.group(0))
            nm = ia.get("name")
            if nm:
                fields.append({"name": nm, "type": (ia.get("type") or im.group(1)).lower(),
                               "value": ia.get("value", ""), "required": "required" in im.group(0).lower()})
        forms.append({
            "action": action, "method": (a.get("method") or "get").upper(),
            "enctype": a.get("enctype", ""),
            "field_names": [f["name"] for f in fields],
            "has_password": any(f["type"] == "password" for f in fields),
            "has_file": any(f["type"] == "file" for f in fields),
            "csrf_fields": [f["name"] for f in fields if re.search(
                r"(csrf|xsrf|token|nonce|authenticity|requestverification)", f["name"], re.I)],
            "fields": fields,
        })
    return forms


def abs_urls(html, base, patterns):
    out = set()
    for rx in patterns:
        for m in rx.finditer(html or ""):
            u = m.group(1).strip()
            if not u or u.startswith(("data:", "javascript:", "mailto:", "#")):
                continue
            if u.startswith("//"):
                out.add("https:" + u)
            else:
                out.add(up.urljoin(base, u))
    return sorted(out)


def grade_headers(missing, total):
    pct = 100.0 * (total - len(missing)) / max(1, total)
    if pct >= 85:
        return "A"
    if pct >= 70:
        return "B"
    if pct >= 50:
        return "C"
    if pct >= 30:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# ULTRA HELPERS (v3)
# ---------------------------------------------------------------------------
def classify_form(f):
    """Form classifier - P9 auth handoff + abuse-case hints."""
    blob = (f.get("action") or "") + " " + " ".join(f.get("field_names") or [])
    classes = [c for c, pat in FORM_CLASSES if re.search(pat, blob)]
    if f.get("has_password") and "auth" not in classes and "registration" not in classes:
        classes.append("password_form")
    if f.get("has_file"):
        classes.append("file_upload")
    return classes or ["generic"]


def form_audit(f, base_host):
    """ULTRA form findings (evidence-only, no request)."""
    notes = []
    act_host = up.urlsplit(f.get("action") or "").hostname or ""
    if f.get("method") == "GET" and f.get("has_password"):
        notes.append("GET-method password form (creds URL/logs me ja sakte hain)")
    if f.get("has_password") and not any(
            (fd.get("autocomplete") or "").lower() in ("current-password", "new-password")
            for fd in f.get("fields", [])):
        notes.append("password field bina current/new-password autocomplete ke")
    for fd in f.get("fields", []):
        if fd["type"] == "password" and (fd.get("maxlength")):
            notes.append("password maxlength=%s (truncation policy leak)" % fd["maxlength"])
    if act_host and act_host != base_host:
        notes.append("cross-origin form action: %s (creds off-site ja sakte hain)" % act_host)
    hidden = [fd["name"] for fd in f.get("fields", []) if fd["type"] == "hidden"]
    return {"notes": notes, "hidden_fields": hidden}


def pii_scan(fields):
    """ULTRA: form fields me PII classes detect karo (inventory only)."""
    found = []
    for fd in fields:
        nm = str(fd.get("name") or "")
        for label, pat in [(l, p) for l, p in PII_HINTS.values()]:
            if re.search(pat, nm):
                found.append({"field": nm, "pii_class": label})
                break
    return found


def csp_analyze(csp):
    """ULTRA: CSP weakness detector."""
    if not csp:
        return {"present": False, "weaknesses": ["csp-missing"]}
    w = [name for name, pat in CSP_WEAK if re.search(pat, csp, re.M)]
    return {"present": True, "weaknesses": sorted(set(w)), "raw_len": len(csp)}


def cookie_ultra(raws):
    """ULTRA cookie deep-audit (v2 flags preserved + prefix/contradiction checks)."""
    out, names = [], set()
    for raw in raws or []:
        name = raw.split("=")[0].strip()
        low = raw.lower()
        missing = [f for f, present in (("HttpOnly", "httponly" in low),
                                        ("Secure", "secure" in low),
                                        ("SameSite", "samesite" in low)) if not present]
        entry = {"raw": raw[:200], "name": name, "missing": missing}
        if name.startswith("__Host-"):
            if "secure" not in low:
                entry["prefix_violation"] = "__Host- needs Secure"
            if "path=/" not in low:
                entry["prefix_violation"] = entry.get("prefix_violation") or "__Host- needs Path=/"
            if "domain=" in low:
                entry["prefix_violation"] = "__Host- must not have Domain"
        elif name.startswith("__Secure-") and "secure" not in low:
            entry["prefix_violation"] = "__Secure- needs Secure"
        if "samesite=none" in low and "secure" not in low:
            entry["prefix_violation"] = entry.get("prefix_violation") or "SameSite=None without Secure"
        if re.search(r"(?i)(sess|session|sid|auth|jwt|token|login)", name):
            entry["session_like"] = True
        out.append(entry)
        names.add(name)
    return out


def perimeter_of_headers(hdrs, cookies):
    """ULTRA: artifact-level edge/perimeter detection (P4/P6/P8 handoff)."""
    blob = json.dumps({k.lower(): str(v).lower() for k, v in (hdrs or {}).items()})
    blob += " " + " ".join(str(c).lower() for c in (cookies or []))
    hits = [w for w, needles in PERIMETER_SIGS.items() if any(n in blob for n in needles)]
    return sorted(set(hits))


def redirect_ultra(chain, final_url):
    """ULTRA: redirect chain me cross-domain hop + scheme downgrade."""
    hints = []
    urls = [(h.get("url") or "") for h in (chain or []) if isinstance(h, dict)]
    urls.append(final_url or "")
    hosts = [up.urlsplit(u).hostname or "" for u in urls if u]
    for i in range(1, len(hosts)):
        if hosts[i] and hosts[i - 1] and hosts[i] != hosts[i - 1]:
            hints.append("cross-domain redirect hop: %s -> %s" % (hosts[i - 1], hosts[i]))
    schemes = [up.urlsplit(u).scheme for u in urls if u]
    if "https" in schemes and "http" in schemes:
        hints.append("scheme change in redirect chain (%s)" % " -> ".join(schemes))
    return hints


def state_leaks(html, cap=4000):
    """ULTRA: inline JSON state extraction (__NEXT_DATA__ etc.)."""
    leaks = []
    for m in RE_STATE_JSON.finditer(html or ""):
        var = m.group(1)
        start = m.end()
        if start >= len(html) or html[start] not in "{[":
            continue
        depth, end = 0, start
        for i in range(start, min(len(html), start + cap * 4)):
            ch = html[i]
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        blob = html[start:end]
        if not blob:
            continue
        eps = sorted(set(p for p in re.findall(r'"/[A-Za-z0-9_\-/]{2,60}"', blob)
                         if not RE_EXT_SKIP.search(p)))[:40]
        toks = [{"type": lb, "sample_redacted": redact(sm.group(0), 4)}
                for pat, lb in SECRET_PATTERNS for sm in list(re.finditer(pat, blob))[:3]]
        leaks.append({"var": var, "bytes": len(blob), "endpoints": eps,
                      "secret_hits": toks})
    return leaks[:6]


def comment_leaks(html):
    """ULTRA: HTML comment miner (TODO/FIXME/emails/internal hosts)."""
    blob = " ".join(m.group(1) for m in RE_COMMENT.finditer(html or ""))[:200000]
    return {
        "emails": sorted(set(RE_EMAIL.findall(blob)))[:20],
        "internal_hosts": sorted(set(RE_INTERNAL_HOST.findall(blob)))[:20],
        "todo_fixme": len(re.findall(r"(?i)\b(?:todo|fixme|hack|xxx)\b", blob)),
        "stack_hint": bool(re.search(r"(?i)(traceback|at .+\.py|Exception in)", blob)),
    }


def sri_audit(html, base_host):
    """ULTRA: cross-origin <script> bina integrity ke -> SRI gaps."""
    gaps = []
    for m in SCRIPT_RE.finditer(html or ""):
        tag = m.group(0)
        src = m.group(1)
        if src.startswith("data:") or src.startswith("/"):
            continue
        host = up.urlsplit(up.urljoin("https://" + (base_host or ""), src)).hostname or ""
        if host and base_host and host != base_host and "integrity=" not in tag.lower():
            gaps.append(src[:160])
    return gaps[:20]


def mixed_content(html, page_https):
    """ULTRA: https page par http:// assets."""
    if not page_https:
        return []
    urls = re.findall(r'''(?:src|href)\s*=\s*["'](http://[^"']{4,180})["']''', html or "", re.I)
    return sorted(set(u for u in urls if not u.startswith("http://www.w3.org")))[:20]


def js_deep(body):
    """ULTRA JS miner: v2 endpoint regex + fetch/axios + ws + graphql + sourcemap."""
    eps = set(RE_JS_ENDPOINT.findall(body or ""))
    for m in RE_FETCH.finditer(body or ""):
        u = m.group(1)
        if u.startswith(("http", "/")) and not RE_EXT_SKIP.search(u):
            eps.add(u if u.startswith("/") else "/" + u.split("/", 3)[-1])
    return {
        "endpoints": sorted(e for e in eps if len(e) < 120),
        "websockets": sorted(set(RE_WS.findall(body or "")))[:12],
        "graphql_ops": sorted(set(RE_GQL_OP.findall(body or "")))[:20],
        "sourcemaps": sorted(set(RE_SMAP.findall(body or "")))[:12],
    }


def surface_score(rec):
    """ULTRA: explainable attack-surface score (0-100)."""
    s, why = 0.0, []
    grade = rec.get("header_grade") or "F"
    s += {"A": 5, "B": 15, "C": 30, "D": 45, "F": 60, "": 60}.get(grade, 60)
    why.append("headers grade=%s (+%.0f)" % (grade or "?", {"A": 5, "B": 15, "C": 30, "D": 45, "F": 60}.get(grade, 60)))
    n = len(rec.get("cookie_flags") or [])
    if n:
        s += min(15, 3 * n)
        why.append("cookie flags missing x%d (+%d)" % (n, min(15, 3 * n)))
    n = len(rec.get("forms") or [])
    if n:
        s += min(10, 2 * n)
        why.append("forms x%d (+%d)" % (n, min(10, 2 * n)))
    n = len(rec.get("upload_forms", []) or [])
    if n:
        s += 10
        why.append("upload forms (+10)")
    n = len(rec.get("secrets") or [])
    if n:
        s += min(15, 5 * n)
        why.append("secret patterns x%d (+%d)" % (n, min(15, 5 * n)))
    n = len(rec.get("csp", {}).get("weaknesses") or [])
    if n:
        s += min(10, 2 * n)
        why.append("csp weaknesses x%d (+%d)" % (n, min(10, 2 * n)))
    if rec.get("mixed_content"):
        s += 8
        why.append("mixed content (+8)")
    if rec.get("state_leaks"):
        s += 7
        why.append("inline state leaks (+7)")
    return round(min(100.0, s), 1), why

# ---------------------------------------------------------------------------
# ANALYZE TARGET - v2 flow preserved + ULTRA fields (superset)
# ---------------------------------------------------------------------------
def analyze_target(cfg, scope, http, cache, cp, seed):
    """Full understanding pass for one base URL. Checkpoint-safe. (v2 contract)"""
    url = normalize_url(seed)
    ck = "target:" + url
    if cp.is_done(ck):
        ok("SKIP (checkpoint) %s" % url)
        return cp.result_of(ck)

    cached = cache.get("GET", url) if cache else None
    if cached:
        ok("SKIP (probe cache) %s" % url)

    r = http.request("GET", url, allow_redirects=True, save="home_%s.html" % re.sub(r"[^A-Za-z0-9._-]", "_", host_of(url)))
    if r.error:
        warn("%s -> %s" % (url, r.error))
        rec = {"seed": url, "error": r.error, "reachable": False}
        cp.mark(ck, rec, summary="unreachable")
        return rec

    final = r.url
    pu = up.urlsplit(final)
    base = "%s://%s" % (pu.scheme, pu.netloc)
    js_max = int(getattr(cfg, "understand_js_max", 60) or 60)

    rec = {"seed": url, "final_url": final, "base": base, "reachable": True,
           "status": r.status, "len": len(r.body),
           "server": r.hget("Server"), "powered": r.hget("X-Powered-By"),
           "generator": r.hget("X-Generator"), "title": title_of(r.text),
           "redirect_chain": r.chain, "tech": [], "missing_headers": [],
           "header_grade": "", "cookies": [], "cookie_flags": [],
           "forms": [], "js": [], "endpoints": [], "secrets": [],
           "flags": [], "interesting_links": []}

    hdr_lines = "\n".join("%s: %s" % (k, v) for k, v in r.headers.items())
    hay = (r.text[:200000] + "\n" + hdr_lines + "\n" + json.dumps(r.headers)).lower()
    for tech, needles in TECH_MAP.items():
        if any(n.lower() in hay for n in needles):
            rec["tech"].append(tech)

    for h in SEC_HEADERS:
        if not r.hget(h):
            rec["missing_headers"].append(h)
    rec["header_grade"] = grade_headers(rec["missing_headers"], len(SEC_HEADERS))
    if not r.hget("content-security-policy"):
        rec["flags"].append("CSP missing")
    if not r.hget("strict-transport-security") and pu.scheme == "https":
        rec["flags"].append("HSTS missing on HTTPS")
    if r.hget("x-powered-by"):
        rec["flags"].append("X-Powered-By discloses stack: %s" % r.hget("x-powered-by"))

    for raw in (r.set_cookies or []):
        name = raw.split("=")[0].strip()
        low = raw.lower()
        missing = [f for f, present in (("HttpOnly", "httponly" in low),
                                        ("Secure", "secure" in low),
                                        ("SameSite", "samesite" in low)) if not present]
        rec["cookies"].append({"raw": raw[:200], "name": name})
        if missing:
            rec["cookie_flags"].append({"cookie": name, "missing": missing})
            rec["flags"].append("Cookie %s missing %s" % (name, ",".join(missing)))

    rec["forms"] = parse_forms(r.text, final)
    js = abs_urls(r.text, base, [SCRIPT_RE])
    rec["js"] = [u for u in js if scope.check_url(u, raise_on_fail=False)][:120]

    links = abs_urls(r.text, base, [LINK_RE])
    for l in links:
        p = up.urlparse(l).path
        if re.search(r"(?i)/(api|admin|account|user|upload|export|download|billing|settings|internal|debug|token|oauth)", p):
            rec["interesting_links"].append(l)

    js_bodies = {}
    for j in rec["js"][:js_max]:
        jr = http.request("GET", j, allow_redirects=True,
                          save="js_%s" % re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(up.urlparse(j).path))[:60])
        if jr.error:
            continue
        body = jr.text
        js_bodies[j] = body or ""
        for em in RE_JS_ENDPOINT.finditer(body):
            p = em.group(1)
            if RE_EXT_SKIP.search(p):
                continue
            rec["endpoints"].append(p)
        for pat, label in SECRET_PATTERNS:
            for sm in re.finditer(pat, body):
                val = sm.group(0)
                rec["secrets"].append({"type": label, "js": j, "len": len(val),
                                       "sample_redacted": redact(val, 4)})

    rec["endpoints"] = sorted(set(rec["endpoints"]))
    rec["js"] = sorted(set(rec["js"]))
    rec["interesting_links"] = sorted(set(rec["interesting_links"]))

    # ------------------------- ULTRA v3 layer -------------------------
    rec["ultra"] = ENGINE_VERSION
    rec["csp"] = csp_analyze(r.hget("content-security-policy"))
    rec["cookies_ultra"] = cookie_ultra(r.set_cookies or [])
    rec["perimeter"] = perimeter_of_headers(r.headers, r.set_cookies or [])
    rec["redirect_hints"] = redirect_ultra(r.chain, final)
    rec["mixed_content"] = mixed_content(r.text, pu.scheme == "https")
    rec["sri_gaps"] = sri_audit(r.text, pu.hostname)
    rec["comment_leaks"] = comment_leaks(r.text)
    rec["state_leaks"] = state_leaks(r.text)
    rec["meta_generator"] = (re.search(r'(?i)<meta[^>]+name\s*=\s*["\']generator["\'][^>]+'
                                       r'content\s*=\s*["\']([^"\']+)', r.text) or [None, ""])[1]
    form_meta = []
    rec["upload_forms"], rec["auth_forms"], rec["pii_fields"] = [], [], []
    for f in rec["forms"]:
        classes = classify_form(f)
        au = form_audit(f, pu.hostname)
        form_meta.append({"action": f["action"], "method": f["method"],
                          "classes": classes, "audit": au})
        if "file_upload" in classes:
            rec["upload_forms"].append(f["action"])
        if "auth" in classes or "registration" in classes or "password_reset" in classes:
            rec["auth_forms"].append({"action": f["action"], "classes": classes})
        for p in pii_scan(f.get("fields", [])):
            rec["pii_fields"].append(dict(p, form=f["action"]))
    rec["forms_meta"] = form_meta
    ws_all, gql_all, smap_all, fetch_eps = set(), set(), set(), set()
    for j, body in js_bodies.items():
        d = js_deep(body)
        fetch_eps.update(d["endpoints"][:60])
        ws_all.update(d["websockets"])
        gql_all.update(d["graphql_ops"])
        smap_all.update(d["sourcemaps"])
    rec["endpoints"] = sorted(set(rec["endpoints"]) | fetch_eps)
    rec["websockets"] = sorted(ws_all)
    rec["graphql_ops"] = sorted(gql_all)
    rec["sourcemaps"] = sorted(smap_all)
    rec["juicy_endpoints"] = sorted(e for e in rec["endpoints"] if JUICY_EP_RE.search(e))
    score, why = surface_score(rec)
    rec["attack_surface_score"] = score
    rec["attack_surface_why"] = why
    if rec["redirect_hints"]:
        rec["flags"].extend(rec["redirect_hints"])
    if rec["csp"]["weaknesses"]:
        rec["flags"].append("CSP weaknesses: %s" % ",".join(rec["csp"]["weaknesses"]))

    if cache:
        cache.put("GET", url, {"status": r.status, "len": len(r.body), "sha1": r.sha1(),
                               "title": rec["title"], "final_url": final})
    cp.mark(ck, rec, summary="understand target")
    ok("%s [%s] grade=%s tech=%s forms=%d js=%d endpoints=%d secrets=%d | ULTRA: score=%.0f csp_w=%d perimeter=%s state_leaks=%d"
       % (host_of(url), r.status, rec["header_grade"], ",".join(rec["tech"]) or "-",
          len(rec["forms"]), len(rec["js"]), len(rec["endpoints"]), len(rec["secrets"]),
          score, len(rec["csp"]["weaknesses"]), ",".join(rec["perimeter"]) or "-",
          len(rec["state_leaks"])))
    if rec["flags"]:
        warn("  flags: %s" % "; ".join(rec["flags"][:5]))
    return rec


# ---------------------------------------------------------------------------
# THREAT MODEL - v2 skeleton preserved + ULTRA auto-hypotheses
# ---------------------------------------------------------------------------
def write_threat_model(out, results, scope):
    L = []
    A = L.append
    A("# Threat Model - %s" % scope.engagement)
    A("_Auto-generated %s by WASP Phase 2 ULTRA v3. Manual sections must be filled._" % now_iso())
    A("")
    A("## Scope snapshot")
    A("- engagement: `%s`" % scope.engagement)
    A("- authorization ref: `%s`" % scope.ref)
    A("- seeds: %s" % ", ".join(scope.seed_urls()) or "-")
    A("- domains: %s" % (", ".join(scope.domains) or "-"))
    A("- wildcards: %s" % (", ".join(scope.wildcards) or "-"))
    A("- excludes: %s" % (", ".join(scope.excludes) or "-"))
    A("- ips: %s" % (", ".join(scope.ips) or "-"))
    A("")
    A("## 1. Application purpose (MANUAL)")
    A("- Business type: ")
    A("- Crown jewels (most valuable data/action): ")
    A("- Regulatory / PII class: ")
    A("")
    A("## 2. Personas & privilege (MANUAL - need 2+ accounts)")
    A("| Role | Unique ability | Cannot do | Test account |")
    A("|---|---|---|---|")
    for role in ("Anonymous", "User A", "User B", "Premium", "Admin/Support", "Tenant A", "Tenant B"):
        A("| %s | | | |" % role)
    A("")
    A("## 3. Sensitive / state-changing actions (checklist)")
    for it in ["login", "logout", "password change", "email change", "MFA enroll/disable",
               "payment/order", "refund", "role change / invite user", "data export/download",
               "file upload", "delete account", "API key generation", "webhook config",
               "tenant/org switch", "impersonation"]:
        A("- [ ] %s" % it)
    A("")
    A("## 4. Observed targets")
    for r in results:
        if not r.get("reachable"):
            A("- %s : UNREACHABLE (%s)" % (r.get("seed"), r.get("error")))
            continue
        A("- **%s** -> `%s` [%s]" % (r["seed"], r["base"], r["status"]))
        A("    - title: %s" % (r["title"] or "-"))
        A("    - server: %s | powered-by: %s" % (r["server"] or "-", r["powered"] or "-"))
        A("    - tech hints: %s" % (", ".join(r["tech"]) or "-"))
        A("    - header grade: **%s** (missing: %s)" % (r["header_grade"], ", ".join(r["missing_headers"]) or "-"))
        A("    - forms: %d | js: %d | endpoints: %d | secrets(pattern): %d"
          % (len(r["forms"]), len(r["js"]), len(r["endpoints"]), len(r["secrets"])))
        if r["cookie_flags"]:
            A("    - cookie hardening: %s" % "; ".join("%s -> %s" % (c["cookie"], ",".join(c["missing"])) for c in r["cookie_flags"]))
        if r["flags"]:
            A("    - flags: %s" % "; ".join(r["flags"]))
        if r.get("attack_surface_score") is not None:
            A("    - ULTRA attack-surface score: **%s**/100 (%s)"
              % (r["attack_surface_score"], "; ".join(r.get("attack_surface_why") or []) or "-"))
        if r.get("perimeter"):
            A("    - perimeter detected: %s (P4/P6/P8 me bypass playbook dekho)" % ", ".join(r["perimeter"]))
    A("")
    A("## 5. Trust boundaries")
    A("Browser (untrusted) -> CDN/WAF -> App/API (trusted) -> DB / queue / object-store / 3rd-party")
    for r in results:
        if r.get("perimeter"):
            A("- %s edge: %s" % (r.get("base"), ", ".join(r["perimeter"])))
    A("")
    A("## 6. STRIDE notes (auto-hypotheses + MANUAL)")
    hyp = {
        "Spoofing": ["auth forms par credential stuffing / MFA bypass", "password-reset flow me account takeover (host-header/email pivot)"],
        "Tampering": ["hidden form fields server par trust hue to mass-assignment", "file upload forms: extension/MIME bypass -> RCE/XSS"],
        "Repudiation": ["state-changing actions par audit log missing", "payment/order flows me non-repudiation gap"],
        "Information Disclosure": ["inline state leaks (__NEXT_DATA__) me sensitive data", "CSP weaknesses -> data exfil paths", "comment/meta leaks (emails, internal hosts)"],
        "Denial of Service": ["export/download endpoints par unbounded query", "upload forms par size/count limits"],
        "Elevation of Privilege": ["role/admin params hidden fields me", "IDOR candidates: endpoints with id/account/doc params"],
    }
    for s in ("Spoofing", "Tampering", "Repudiation", "Information Disclosure",
              "Denial of Service", "Elevation of Privilege"):
        A("- **%s:** " % s)
        for h in hyp.get(s, []):
            A("    - [ ] %s" % h)
    A("")
    A("## 7. Auto-discovered leads")
    eps = sorted(set(e for r in results if r.get("reachable") for e in r["endpoints"]))
    A("- unique JS endpoints: %d" % len(eps))
    A("- secret-pattern hits: %d (VERIFY before any use; samples are redacted)"
      % sum(len(r.get("secrets", [])) for r in results))
    A("- forms with passwords: %d"
      % sum(1 for r in results if r.get("reachable") for f in r["forms"] if f["has_password"]))
    A("- forms with file upload: %d"
      % sum(1 for r in results if r.get("reachable") for f in r["forms"] if f["has_file"]))
    A("- ULTRA: juicy endpoints: %d | graphql ops: %d | websockets: %d"
      % (sum(len(r.get("juicy_endpoints") or []) for r in results),
         sum(len(r.get("graphql_ops") or []) for r in results),
         sum(len(r.get("websockets") or []) for r in results)))
    A("- ULTRA: PII-bearing form fields: %d" % sum(len(r.get("pii_fields") or []) for r in results))
    A("")
    A("## 8. Priority testing list (MANUAL ranking)")
    A("1. ")
    A("2. ")
    A("3. ")
    save_text(os.path.join(out, "THREAT_MODEL.md"), "\n".join(L) + "\n")


# ---------------------------------------------------------------------------
# RUN - v2 flow preserved + ULTRA outputs/diff/feedforward
# ---------------------------------------------------------------------------
def _load_prev(out):
    p = os.path.join(out, "understand.json")
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception:
            return None
    return None


def _diff(prev, results):
    """ULTRA: run-to-run diff (new/gone/changed targets + score moves)."""
    if not prev or not isinstance(prev, dict):
        return None
    old = {t.get("seed"): t for t in (prev.get("targets") or []) if isinstance(t, dict)}
    new = {t.get("seed"): t for t in results if t.get("reachable")}
    d = {"generated_at": now_iso(), "new": [], "gone": [], "changed": []}
    for s, t in new.items():
        if s not in old:
            d["new"].append(s)
        else:
            o = old[s]
            if (o.get("header_grade") != t.get("header_grade")
                    or o.get("title") != t.get("title")
                    or o.get("attack_surface_score") != t.get("attack_surface_score")):
                d["changed"].append({"seed": s,
                                     "grade": [o.get("header_grade"), t.get("header_grade")],
                                     "score": [o.get("attack_surface_score"), t.get("attack_surface_score")]})
    for s in old:
        if s not in new:
            d["gone"].append(s)
    return d if (d["new"] or d["gone"] or d["changed"]) else {"generated_at": now_iso(), "note": "no changes"}


def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    cache = ProbeCache(base_out, scope.engagement) if getattr(cfg, "negative_cache", True) else None
    head("Phase 2 - App Understanding & Threat Model (ULTRA PRO MAX) | %s" % scope.describe())

    seeds = scope.seed_urls()
    if not seeds:
        err("No in-scope seeds (scope.json me targets/domains/ips daalo).")
        return out
    info("Targets: %d" % len(seeds))

    results = []
    for i, s in enumerate(seeds, 1):
        head("[%d/%d] %s" % (i, len(seeds), s))
        results.append(analyze_target(cfg, scope, http, cache, cp, s))

    reachable = [r for r in results if r.get("reachable")]
    endpoints = sorted(set(e for r in reachable for e in r["endpoints"]))
    api_eps = sorted(e for e in endpoints if re.search(
        r"(?i)/(api|v\d+|graphql|rest|internal|admin|auth|token|user|account|billing|webhook)", e))
    js_all = sorted(set(j for r in reachable for j in r["js"]))
    secrets = [dict(s, host=r["base"]) for r in reachable for s in r["secrets"]]
    flags = ["%s: %s" % (r["base"], f) for r in reachable for f in r["flags"]]
    forms = [dict(f, base=r["base"]) for r in reachable for f in r["forms"]]

    # -------- ULTRA aggregates --------
    juicy = sorted(set(e for r in reachable for e in (r.get("juicy_endpoints") or [])))
    pii_all = [dict(p, base=r["base"]) for r in reachable for p in (r.get("pii_fields") or [])]
    auth_forms_all = [dict(a, base=r["base"]) for r in reachable for a in (r.get("auth_forms") or [])]
    session_cookies = sorted({c["name"] for r in reachable for c in (r.get("cookies_ultra") or [])
                              if c.get("session_like")})
    perimeter_all = sorted({p for r in reachable for p in (r.get("perimeter") or [])})
    gql_ops = sorted({o for r in reachable for o in (r.get("graphql_ops") or [])})
    ws_all = sorted({w for r in reachable for w in (r.get("websockets") or [])})
    state_eps = sorted({e for r in reachable for lk in (r.get("state_leaks") or []) for e in lk.get("endpoints", [])})

    save_json(os.path.join(out, "understand.json"),
              {"engine": "wasp-core-ultra", "phase": "2-understanding", "generated_at": now_iso(),
               "engine_version": ENGINE_VERSION,
               "scope": {"engagement": scope.engagement, "seeds": seeds},
               "targets": results})
    save_text(os.path.join(out, "endpoints.txt"), "\n".join(endpoints))
    save_text(os.path.join(out, "api_endpoints.txt"), "\n".join(api_eps))
    save_text(os.path.join(out, "js_urls.txt"), "\n".join(js_all))
    save_text(os.path.join(out, "header_flags.txt"), "\n".join(sorted(set(flags))))
    save_text(os.path.join(out, "interesting.txt"),
              "\n".join(sorted(set(l for r in reachable for l in r["interesting_links"]))))
    save_json(os.path.join(out, "secret_hits.json"), secrets)
    save_json(os.path.join(out, "forms.json"), forms)
    write_threat_model(out, results, scope)

    # -------- ULTRA outputs --------
    save_text(os.path.join(out, "juicy_endpoints.txt"), "\n".join(juicy))
    save_json(os.path.join(out, "pii_inventory.json"), pii_all)
    save_json(os.path.join(out, "auth_forms.json"), auth_forms_all)
    save_text(os.path.join(out, "cookies.txt"),
              "\n".join("%s  missing=[%s]  %s" % (c["name"], ",".join(c["missing"]),
                                                  c.get("prefix_violation") or "")
                        for r in reachable for c in (r.get("cookies_ultra") or [])))
    save_text(os.path.join(out, "session_cookies.txt"), "\n".join(session_cookies))
    save_text(os.path.join(out, "csp_report.txt"),
              "\n".join("%s -> present=%s weaknesses=[%s]" % (r["base"], r["csp"]["present"],
                                                              ",".join(r["csp"]["weaknesses"]))
                        for r in reachable))
    save_text(os.path.join(out, "forms_classified.txt"),
              "\n".join("%s | %s %s | [%s] | %s" % (m["action"], m["method"],
                                                    "pw" if any("password" in c for c in m["classes"]) else "  ",
                                                    ",".join(m["classes"]), "; ".join(m["audit"]["notes"]) or "-")
                        for r in reachable for m in (r.get("forms_meta") or [])))
    save_text(os.path.join(out, "hidden_fields.txt"),
              "\n".join(sorted({h for r in reachable for m in (r.get("forms_meta") or [])
                                for h in m["audit"]["hidden_fields"]})))
    save_text(os.path.join(out, "mixed_content.txt"),
              "\n".join("%s -> %s" % (r["base"], u) for r in reachable for u in (r.get("mixed_content") or [])))
    save_text(os.path.join(out, "sri_audit.txt"),
              "\n".join("%s -> %s" % (r["base"], u) for r in reachable for u in (r.get("sri_gaps") or [])))
    save_text(os.path.join(out, "comment_leaks.txt"),
              "\n".join("%s -> emails=%s internal=%s todo=%d stack=%s"
                        % (r["base"], ",".join((r.get("comment_leaks") or {}).get("emails", [])[:5]),
                           ",".join((r.get("comment_leaks") or {}).get("internal_hosts", [])[:5]),
                           (r.get("comment_leaks") or {}).get("todo_fixme", 0),
                           (r.get("comment_leaks") or {}).get("stack_hint", False))
                        for r in reachable))
    save_json(os.path.join(out, "state_leaks.json"),
              [{"base": r["base"], "leaks": r.get("state_leaks") or []} for r in reachable])
    save_text(os.path.join(out, "waf_edge.txt"),
              "\n".join("%s -> perimeter=[%s]" % (r["base"], ",".join(r.get("perimeter") or []) or "none")
                        for r in reachable))
    save_text(os.path.join(out, "websockets.txt"), "\n".join(ws_all))
    save_text(os.path.join(out, "graphql_ops.txt"), "\n".join(gql_ops))

    ranked = sorted((r for r in reachable if r.get("attack_surface_score") is not None),
                    key=lambda r: -r["attack_surface_score"])
    save_text(os.path.join(out, "attack_surface.txt"),
              "\n".join("%5.1f  %s  ::  %s" % (r["attack_surface_score"], r["base"],
                                               "; ".join(r["attack_surface_why"]))
                        for r in ranked))

    d = _diff(_load_prev(out), results)
    if d:
        save_json(os.path.join(out, "understand_diff.json"), d)

    ff = write_feedforward(out, "2-understanding", {
        "to_phase3_passive": {"domains": scope.root_domains()},
        "to_phase4_active": {"seeds": [r["base"] for r in reachable],
                             "perimeter": perimeter_all},
        "to_phase5_content": {"endpoints": "api_endpoints.txt", "js_seeds": "js_urls.txt",
                              "juicy": "juicy_endpoints.txt"},
        "to_phase6_tech": {"bases": [r["base"] for r in reachable],
                           "tech_hints": sorted({t for r in reachable for t in r["tech"]})},
        "to_phase7_js": {"js_assets": len(js_all), "sourcemaps": "state_leaks.json"},
        "to_phase8_surface": {"attack_surface": "attack_surface.txt",
                              "waf_edge": "waf_edge.txt",
                              "juicy_endpoints": len(juicy)},
        "to_phase9_auth": {"forms": "forms.json", "auth_forms": "auth_forms.json",
                           "auth_endpoints": [e for e in api_eps if re.search(r"(?i)auth|login|token", e)],
                           "mfa_forms": [m["action"] for r in reachable for m in (r.get("forms_meta") or [])
                                         if "mfa" in m["classes"]]},
        "to_phase10_sessions": {"session_cookies": session_cookies,
                                "cookie_flags": "cookies.txt"},
        "to_phase11_idor": {"hidden_fields": "hidden_fields.txt",
                            "idor_param_endpoints": [e for e in juicy if re.search(r"(?i)\bid\b|account|user|doc|invoice|order", e)]},
        "to_phase12_params": {"endpoints": len(endpoints), "params": "endpoints.txt"},
        "to_phase13_injection": {"endpoints": "endpoints.txt"},
        "to_phase15_ssrf_traversal": {"interesting": "interesting.txt"},
        "to_phase17_upload": {"upload_forms": [r["base"] + a for r in reachable for a in (r.get("upload_forms") or [])]},
        "to_phase20_business": {"payment_forms": [m["action"] for r in reachable for m in (r.get("forms_meta") or [])
                                                  if "payment" in m["classes"]]},
        "to_phase22_cache": {"perimeter": perimeter_all},
        "to_phase23_secrets": {"pattern_hits": len(secrets), "state_leaks": "state_leaks.json"},
        "to_phase32_report": {"header_grades": {r["base"]: r["header_grade"] for r in reachable},
                              "attack_surface": {r["base"]: r.get("attack_surface_score") for r in ranked}},
    }, notes=["secret samples are redacted - verify manually before any use",
              "read-only GET/HEAD recon - Layer 4 enforced"])

    write_manifest(out, "2-understanding",
                   ["understand.json", "endpoints.txt", "api_endpoints.txt", "js_urls.txt",
                    "header_flags.txt", "interesting.txt", "secret_hits.json", "forms.json",
                    "THREAT_MODEL.md", "juicy_endpoints.txt", "pii_inventory.json",
                    "auth_forms.json", "cookies.txt", "session_cookies.txt", "csp_report.txt",
                    "forms_classified.txt", "hidden_fields.txt", "mixed_content.txt",
                    "sri_audit.txt", "comment_leaks.txt", "state_leaks.json", "waf_edge.txt",
                    "websockets.txt", "graphql_ops.txt", "attack_surface.txt",
                    "understand_diff.json", "feedforward.json"],
                   stats={"targets": len(seeds), "reachable": len(reachable),
                          "endpoints": len(endpoints), "js": len(js_all), "secrets": len(secrets),
                          "juicy": len(juicy), "pii_fields": len(pii_all),
                          "perimeter": len(perimeter_all),
                          "engine": ENGINE_VERSION})

    head("Phase 2 complete (ULTRA PRO MAX)")
    ok("targets=%d reachable=%d | endpoints=%d api=%d js=%d secrets=%d forms=%d | "
       "juicy=%d pii=%d perimeter=%s"
       % (len(seeds), len(reachable), len(endpoints), len(api_eps), len(js_all),
          len(secrets), len(forms), len(juicy), len(pii_all), ",".join(perimeter_all) or "-"))
    ok("files: understand.json | endpoints.txt | api_endpoints.txt | js_urls.txt | "
       "header_flags.txt | interesting.txt | secret_hits.json | forms.json | THREAT_MODEL.md "
       "| +18 ULTRA outputs")
    return out
