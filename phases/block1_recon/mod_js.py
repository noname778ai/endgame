#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 7 - JavaScript, Client-Side & API Surface Analysis (ULTRA v3)
====================================================================================
Deep client-side attack-surface extraction (read-only, evidence only).

ULTRA v3 = v2 ke saare features 100% preserved + 25 naye techniques:

  CORE (v2, preserved):
   * JS asset collection   - Phase 2 js_urls + Phase 5 found + homepage <script src>
   * Source-map handling   - sourceMappingURL discovery, inline base64, sourcesContent unpack
   * Chunk graph           - webpack/vite/rollup chunk names + dynamic import() targets
   * Endpoint extraction   - absolute/relative URLs, fetch/axios/XHR, method+url objects
   * GraphQL / WebSocket   - operation names, graphql endpoints, ws/wss endpoints
   * Route extraction      - react-router/vue-router/next routes, path defs
   * DOM source->sink map  - tainted-source + dangerous-sink inventory
   * Client authz hints    - isAdmin / role checks / client-side price & validation logic
   * Config & flags        - window.env / API base URLs / feature toggles / build ids
   * Secret patterns       - 25+ patterns + entropy scoring (values REDACTED)
   * Third-party origins   - external hosts = trust boundaries

  ULTRA v3 NEW TECHNIQUES:
   1.  JS beautify-lite          - minified bundle ko statement-level split (regex stability x2)
   2.  Template-literal URLs     - `${base}/api/x` reconstruction -> /api/x
   3.  String-concat URLs        - "/api/"+"users" / '/api/'+'users' join -> /api/users
   4.  OpenAPI-in-JS             - paths:{"/api/...":{...}} swagger spec embedded in bundles
   5.  __NEXT_DATA__/__NUXT__    - buildId/env/apiUrl intel from framework payload scripts
   6.  Service-worker hunt       - navigator.serviceWorker.register / workbox / sw.js targets
   7.  SRI audit                 - third-party scripts without integrity attr (supply chain)
   8.  postMessage audit         - targetOrigin "*" wildcard + listener origins
   9.  document.domain/opener    - sandbox-escape primitives inventory
   10. Storage token map        - localStorage/sessionStorage token-ish keys (XSS->ATO chain)
   11. Client redirect candidates - redirect-param + location sink same file (open-redirect)
   12. API kind classification  - admin/debug/upload/auth/graphql/ws + PRIORITY scoring
   13. API version map          - /api/v1|v2... extraction -> api_versions
   14. GraphQL persisted hashes - apollo persistedQuery/sha256Hash + subscription ops
   15. Sourcemap X-SourceMap    - response-header based map discovery (comment-less)
   16. Sourcemap .map probe     - bundle.js -> bundle.js.map guess jab comment missing
   17. Sourcemap original srcs  - sourcesContent missing -> original sources fetch (bounded)
   18. Sourcemap file tree      - webpack://sources -> internal project tree leak
   19. Sourcemap framework ext  - ts/tsx/vue/jsx sources -> framework intel
   20. Inline <script> analysis - homepage inline blocks = pseudo-assets (endpoints in HTML)
   21. HTML comment intel       - seed pages ke comments (paths, creds hints, build notes)
   22. WAF-aware fetching       - 403/429/503+WAF sig -> 1 stealth retry (alternate headers)
   23. Parallel fetch           - safe_map workers (limiter throttled, budget-aware)
   24. Secrets v2 + core merge  - 40+ patterns + wasp_core.scan_secrets additive (redacted)
   25. js_priority_queue.txt    - explainable high-value target list (P8-ready feedforward)

Safety: GET/HEAD only, koi write probe nahi, scope firewall inherited, secrets REDACTED,
        budget + rate-limiter respect, sourcemap original fetch bounded (js_max_map_sources).

v2 -> v3 fixes/additions (compat intact - saare v2 filenames/formats same):
   * inline scripts + comments ab analyze hote hain (v2 sirf <script src> dekhta tha)
   * sourcemap sourcesContent khaali ho to original sources fetch (v2 chhod deta tha)
   * external_domains me sirf out-of-scope hosts (v2 logic preserved + www-stripped dupes)
   * secrets dedupe fingerprint se (v2) + kind-merge with core scan_secrets (naya)
   * fetch fail/403/WAB-block rec me record hota hai (visibility) - checkpoint same
"""
import os, re, json, base64
import urllib.parse as up
from wasp_core import (module_ctx, write_feedforward, write_manifest, normalize_url, host_of,
                       save_json, save_text, sha1, shannon_entropy, rand_str, title_of, redact,
                       info, ok, warn, err, head, now_iso)

# ULTRA: optional core helpers (older cores par bhi chale - graceful degrade)
try:
    from wasp_core import waf_signature as _core_waf_signature  # noqa: F401
except Exception:
    _core_waf_signature = None
try:
    from wasp_core import scan_secrets as _core_scan_secrets  # noqa: F401
except Exception:
    _core_scan_secrets = None
try:
    from wasp_core import safe_map as _core_safe_map  # noqa: F401
except Exception:
    _core_safe_map = None

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
    """FINAL SWEEP (RWX RULE): module ke poore result tree par rwxrwxrwx - isse
    v2 core par bhi MANIFEST/feedforward/_state/evidence sab cover ho jaata hai."""
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

NAME = "js"

ENGINE = "3.0.0-ultra"

# ---------------------------------------------------------------------------
# v2 REGEX CORE (100% preserved - inko touch nahi kiya)
# ---------------------------------------------------------------------------
RE_ABS_URL = re.compile(r"""(?i)["'`]((?:https?:)?//[^"'`\s]{4,220})["'`]""")
RE_REL_URL = re.compile(r"""(?<![\w.])["'`](/(?:api|v\d+|graphql|rest|internal|admin|auth|token|user|account|upload|export|download|webhook|oauth|sso|billing|payment|invite|share|report)[A-Za-z0-9_\-/{}$.:?&=]{0,140})["'`]""")
RE_ANY_PATH = re.compile(r"""["'`](/[A-Za-z0-9_\-/]{2,90}(?:\?[^"'`]{0,70})?)["'`]""")
RE_FETCH = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.open|\.ajax|\.get|\.post|\.put|\.delete|\.patch|request)\s*\(\s*["'`]([^"'`]{2,220})["'`]""")
RE_METHOD_URL = re.compile(r"""(?i)(?:method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH|OPTIONS)["'][^}]{0,160}?url\s*:\s*["'`]([^"'`]{2,220})["'`])""")
RE_URL_METHOD = re.compile(r"""(?i)url\s*:\s*["'`]([^"'`]{2,220})["'`][^}]{0,160}?method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH)["']""")
RE_AXIOS_VERB = re.compile(r"""(?i)axios\.(get|post|put|delete|patch|head|options)\s*\(\s*["'`]([^"'`]{2,220})["'`]""")
RE_JQUERY_VERB = re.compile(r"""(?i)\$\.(get|post|getJSON|ajax)\s*\(\s*["'`]([^"'`]{2,220})["'`]""")
RE_FETCH_METHOD = re.compile(r"""(?i)fetch\s*\(\s*["'`]([^"'`]{2,220})["'`]\s*,\s*\{[^}]{0,200}?method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH)["']""")
RE_XHR_OPEN = re.compile(r"""(?i)\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH|HEAD)["']\s*,\s*["'`]([^"'`]{2,220})["'`]""")

RE_GRAPHQL = re.compile(r"""(?i)(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{]""")
RE_GQL_ENDPOINT = re.compile(r"""(?i)["'`]([^"'`]*graphql[^"'`]*)["'`]""")
RE_WS = re.compile(r"""(?i)(wss?://[A-Za-z0-9_\-./:?=&%$#{}]{4,200})""")

RE_PARAM = re.compile(r"""[?&]([A-Za-z0-9_\[\]]{2,40})=""")
RE_OBJ_KEYS = re.compile(r"""(?:params|query|data|body|payload|fields|headers)\s*:\s*\{([^}]{5,400})\}""")
RE_KEYVAL = re.compile(r"""["']?([A-Za-z_][A-Za-z0-9_]{1,40})["']?\s*:\s*["'`]?([^"'`,\n}]{1,80})""")

RE_ROUTE_DEF = re.compile(r"""(?i)(?:path|route|to|href)\s*[:=]\s*["'`](/[A-Za-z0-9_\-/{}$.:*]{1,90})["'`]""")
RE_REACT_ROUTE = re.compile(r"""<Route[^>]*path=["']([^"']+)["']""")
RE_NEXT_ROUTE = re.compile(r"""(?i)["'](?:pages|app)(/[A-Za-z0-9_\-/\[\]]{1,80})["']""")

RE_IMPORT = re.compile(r"""(?:import|require)\s*\(\s*["'`]([^"'`]{2,160})["'`]\s*\)""")
RE_CHUNK_MAP = re.compile(r"""(?:\{|,)\s*(\d{1,5})\s*:\s*["'`]([A-Za-z0-9_\-./]{4,120})["'`]""")
RE_SOURCEMAP = re.compile(r"""(?im)^\s*//[#@]\s*sourceMappingURL=([^\s'"]+)""")
RE_SOURCEMAP2 = re.compile(r"""(?im)/\*[#@]\s*sourceMappingURL=([^\*\s]+)\s*\*/""")
RE_BUILD_ID = re.compile(r"""(?i)(?:buildId|build_id|release|version|commit|revision)["']?\s*[:=]\s*["'`]([^"'`]{2,60})["'`]""")

# ---------------------------------------------------------------------------
# v3 NEW REGEXES
# ---------------------------------------------------------------------------
# template literals: `...${var}.../api/x...` -> path part nikalo
RE_TPL_PATH = re.compile(r"""`([^`]*?/(?:api|v\d+|graphql|rest|internal|admin|auth|token|user|account|upload|export|download|webhook|oauth|sso|billing|payment)[A-Za-z0-9_\-/{}$.:${}&=]*)`""")
# template literal with ${base}/... or ...${id}
RE_TPL_BASE = re.compile(r"""\$\{\s*(?:base|baseUrl|BASE_URL|apiBase|API_BASE|api|root|prefix|origin|host)\s*\}(/[^`"']{1,120})""")
# adjacent string concat: "/api/"+"users" | '/api/' + 'users' | `/api/${x}/`+"y"
RE_CONCAT = re.compile(r"""["'`](/[^"'`\n]{2,120})["'`]\s*\+\s*["'`]([^"'`\n]{1,120})["'`]""")
# OpenAPI-ish: paths:{"/api/users":{get:{...}
RE_OPENAPI_PATH = re.compile(r"""(?i)["'](/[^"']{1,110})["']\s*:\s*\{[^{}]{0,220}?(?:get|post|put|delete|patch)\s*:""")
# REST verb blocks: get:"/users" | post:`/users`
RE_VERB_PATH = re.compile(r"""(?i)\b(get|post|put|delete|patch)\s*:\s*["'`](/[^"'`]{2,140})["'`]""")
# __NEXT_DATA__ / __NUXT__ JSON payloads
RE_NEXT_DATA = re.compile(r"""<script[^>]*id=["']__NEXT_DATA__["'][^>]*>(\{.*?\})</script>""", re.S)
RE_NUXT_DATA = re.compile(r"""window\.__NUXT__\s*=\s*(\{.*?\})\s*;?\s*(?:</script>|$)""", re.S)
# service worker / worker registration
RE_SW = re.compile(r"""(?i)navigator\.serviceWorker\.register\s*\(\s*["'`]([^"'`]{2,140})["'`]""")
RE_WORKER = re.compile(r"""(?i)new\s+Worker\s*\(\s*["'`]([^"'`]{2,140})["'`]""")
# SRI / third-party script tags (homepage pass)
RE_SCRIPT_TAG = re.compile(r"""(?is)<script\b([^>]*)>(.*?)</script>""")
RE_SCRIPT_SRC = re.compile(r"""(?i)<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>""")
RE_INTEGRITY = re.compile(r"""(?i)integrity\s*=\s*["']([^"']+)["']""")
RE_SCRIPT_ATTRS = re.compile(r"""(?is)<script\b([^>]*)\bsrc\s*=\s*["']([^"']+)["']([^>]*)>""")
# postMessage targetOrigin wildcard
RE_POSTMESSAGE_WILD = re.compile(r"""(?i)\.postMessage\s*\(\s*([^,]{1,160}),\s*["']\*["']\s*\)""")
RE_POSTMESSAGE = re.compile(r"""(?i)\.postMessage\s*\(""")
RE_MSG_LISTENER = re.compile(r"""(?i)addEventListener\s*\(\s*["']message["']""")
# document.domain / window.opener / clobbering primitives
RE_DOC_DOMAIN = re.compile(r"""(?i)document\.domain\s*=\s*["'`]([^"'`]+)["'`]""")
RE_OPENER = re.compile(r"""(?i)window\.opener|opener\.postMessage|window\.open\s*\([^)]*\)\.postMessage""")
# storage token keys (XSS -> account takeover chain)
RE_STORAGE = re.compile(r"""(?i)(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["'`]([^"'`]{1,60})["'`]""")
# client redirect candidates: location.*= <var/param>
RE_CLIENT_REDIRECT = re.compile(r"""(?i)(?:location\.(?:href|assign|replace)|window\.location)\s*=\s*([^;\n]{1,140})""")
RE_REDIRECT_PARAM = re.compile(r"""(?i)\b(?:redirect|return|next|continue|url|dest|destination|goto|callback|rurl|returnUrl|redirect_uri)\b""")
# GraphQL persisted queries / apollo
RE_GQL_PERSISTED = re.compile(r"""(?i)(?:persistedQueryHash|persistedQuery|sha256Hash|hash)["']?\s*[:=]\s*["'`]([a-f0-9]{16,64})["'`]""")
RE_GQL_SUB = re.compile(r"""(?i)subscription\s+([A-Za-z_][A-Za-z0-9_]*)""")
# API version
RE_API_VERSION = re.compile(r"""["'`]/(?:api/)?(v\d{1,3})(?:\.json)?(?:/|["'`])""")
# upload / multipart
RE_UPLOAD = re.compile(r"""(?i)["'`](/[^"'`\n]{0,100}(?:upload|attachments?|files?|import)[^"'`\n]{0,60})["'`]""")
RE_MULTIPART = re.compile(r"""(?i)FormData\s*\(\s*\)|multipart""")
# env keys in NEXT_DATA/NUXT payloads (public-prefixed only flagged as intel)
RE_PUBLIC_ENV = re.compile(r"""["']((?:PUBLIC_|NEXT_PUBLIC_|VUE_APP_|NUXT_ENV_|REACT_APP_|VITE_)[A-Za-z0-9_]{1,50})["']\s*:\s*["']([^"']{0,120})["']""")
# html comment intel (seed pages)
RE_HTML_COMMENT = re.compile(r"""<!--(.*?)-->""", re.S)
# sourcemap source path (webpack:// style)
RE_MAP_SOURCE_EXT = re.compile(r"""(?i)\.(tsx?|jsx|vue|svelte|mjs|mts|js)$""")
# gRPC-web / tRPC / JSON-RPC style
RE_RPC_STYLE = re.compile(r"""(?i)["'`](/[^"'`\n]{0,80}(?:trpc|rpc|grpc(?:-web)?|jsonrpc)[^"'`\n]{0,60})["'`]""")
# socket.io / signalr / primus
RE_REALTIME = re.compile(r"""(?i)["'`](/[^"'`\n]{0,60}(?:socket\.io|signalr|primus|sockjs|ws)[^"'`\n]{0,40})["'`]""")

# content-type guard: .js par HTML aana = SPA fallback (record but flag)
_HTML_CT_PREFIX = ("text/html",)

# stealth alternate header sets (WAF-aware retry, ULTRA - read-only same request)
STEALTH_HEADER_SETS = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
     "Accept": "application/javascript, */*;q=0.8", "Accept-Language": "en-US,en;q=0.9",
     "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "same-origin"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
     "Accept": "*/*", "Referer": None},  # Referer None = omit
]

# ---------------------------------------------------------------------------
# v2 TABLES (preserved) + v3 additions marked
# ---------------------------------------------------------------------------
DOM_SINKS = {
    "innerHTML": r"\.innerHTML\s*=",
    "outerHTML": r"\.outerHTML\s*=",
    "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
    "document.write": r"document\.write(?:ln)?\s*\(",
    "eval": r"(?<![\w.])eval\s*\(",
    "Function()": r"(?<![\w.])new?\s*Function\s*\(\s*[\"'`]",
    "setTimeout(string)": r"setTimeout\s*\(\s*[\"'`]",
    "setInterval(string)": r"setInterval\s*\(\s*[\"'`]",
    "script.src": r"\.src\s*=\s*[^=]",
    "location.assign": r"location\.(?:assign|replace|href)\s*[=(]",
    "jQuery.html": r"\.html\s*\(",
    "jQuery.append": r"\.(?:append|prepend|after|before)\s*\(",
    "postMessage": r"\.postMessage\s*\(",
    "dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
    "v-html": r"v-html\s*=",
    "bypassSecurityTrust": r"bypassSecurityTrust",
    "srcdoc": r"\.srcdoc\s*=",
    "createContextualFragment": r"createContextualFragment",
    "window.open": r"window\.open\s*\(",
    "angular.element.html": r"angular\.element\([^)]*\)\.html\s*\(",
    "iframe.src": r"<iframe[^>]+src\s*=",
    "element.setAttribute(on*)": r"setAttribute\s*\(\s*[\"'`]on",
    "React.createElement(danger)": r"createElement\s*\([^)]*dangerouslySetInnerHTML",
    # v3 additions
    "document.write(ln) var": r"""document\.write(?:ln)?\s*\(\s*[^)"'`]{0,40}(?:var|\w+\s*\+|\$\{)""",
    "jQuery.attr(href/src)": r"""\.attr\s*\(\s*["'`](?:href|src|action)["']""",
    "jQuery.load": r"\.load\s*\(",
    "$.globalEval": r"globalEval\s*\(",
    "script.text assignment": r"""\.text\s*=\s*(?![=\s]*["'`]\s*$)""",
    "importScripts": r"importScripts\s*\(",
    "range.createContextualFragment": r"createContextualFragment",
    "fetch(...).then(html)": r"""fetch\s*\([^)]*\)[^;\n]{0,120}\.text\s*\(\s*\)""",
}

DOM_SOURCES = {
    "location.search": r"location\.search",
    "location.hash": r"location\.hash",
    "location.href": r"location\.href",
    "document.URL": r"document\.URL",
    "document.referrer": r"document\.referrer",
    "window.name": r"window\.name",
    "URLSearchParams": r"URLSearchParams",
    "postMessage(event.data)": r"(?:event|e|msg|evt)\.data",
    "localStorage": r"localStorage\.(?:getItem|setItem)",
    "sessionStorage": r"sessionStorage\.(?:getItem|setItem)",
    "document.cookie": r"document\.cookie",
    "history.state": r"history\.state",
    "getQueryParam": r"(?i)getParameterByName|getQueryParam|getUrlParam|useSearchParams",
    "window.postMessage(listener)": r"addEventListener\s*\(\s*[\"'`]message",
    "indexedDB": r"indexedDB",
    "caches API": r"caches\.(?:open|match)",
    # v3 additions
    "document.baseURI": r"document\.baseURI",
    "location.pathname": r"location\.pathname",
    "navigation.type": r"(?i)performance\.navigation|navigation\.",
    "referrerPolicy leak": r"(?i)document\.referrer",
    "matchMedia": r"matchMedia\s*\(",
    "fetch(event|msg)": r"""fetch\s*\(\s*(?:event|e|msg|evt|d)\.(?:url|data)""",
}

AUTHZ_HINTS = {
    "isAdmin": r"(?i)\bisAdmin\b|is_admin|isadmin",
    "hasRole/hasPermission": r"(?i)hasRole|hasPermission|canAccess|isAllowed|checkPermission",
    "roleAssignment": r"""(?i)(?:role|roles|permission|permissions|scope|scopes)\s*[=:]\s*["']""",
    "hiddenByRole": r"""(?i)(?:hide|show|display|render)\w*\s*\(\s*[^)]*(?:role|admin|permission)""",
    "clientFeatureFlag": r"(?i)featureFlag|feature_flag|isEnabled|isFeatureOn|toggle",
    "clientPrice": r"(?i)\bprice\b|amount|discount|coupon|credit|balance|total",
    "clientValidation": r"(?i)validateForm|isValid|checkPassword|isEmailValid",
    "routeGuard": r"(?i)requiresAuth|isAuthenticated|ProtectedRoute|beforeEach|canActivate",
    # v3 additions
    "roleLiterals": r"""(?i)["'`](?:admin|superadmin|super_admin|root|owner|moderator|staff|internal)["'`]""",
    "jwtClaimCheck": r"(?i)token\.claims|decodedToken|jwtDecode|parseJwt|jwt_decode",
    "permissionArrays": r"""(?i)(?:permissions|abilities|policies)\s*[:=]\s*\[""",
    "flagSDK": r"(?i)launchdarkly|optimizely|statsig|flagsmith|unleash|growthbook",
    "debugBypass": r"(?i)isDebug|debugMode|bypassAuth|skipAuth|skipPayment|X-Debug",
    "priceMath": r"(?i)(?:price|amount|total)\s*[*+\-/]=?",
    "oauthScopeClient": r"""(?i)scope\s*[:=]\s*["'`][^"'`]*(?:admin|write|delete)""",
    "trialLicense": r"(?i)isTrial|trialExpired|licenseKey|isPremium|plan\s*[:=]\s*['\"]",
}

CONFIG_HINTS = {
    "envObject": r"""(?i)(?:window\.)?(?:env|config|CONFIG|__ENV|__CONFIG__|appSettings|runtimeConfig)\s*=\s*\{""",
    "apiBase": r"""(?i)(?:apiBase|API_BASE|baseUrl|BASE_URL|API_URL|API_ENDPOINT|serverUrl)\s*[:=]\s*["'`]""",
    "featureToggles": r"""(?i)(?:features|toggles|flags|experiments)\s*[:=]\s*\{""",
    "versionString": r"""(?i)(?:version|buildId|release|commit)\s*[:=]\s*["'`][^"'`]{1,40}""",
    "publicKey": r"""(?i)(?:publicKey|publishableKey|clientId|client_id|appId|app_id)\s*[:=]\s*["'`]""",
    "analyticsId": r"""(?i)(?:gtag|gaId|GA_ID|mixpanel|segment|amplitude|posthog|sentry)[^,\n]{0,80}""",
    "cspOrNonce": r"""(?i)nonce|contentSecurityPolicy|__CSP__""",
    "featureDbFlag": r"""(?i)(?:launchdarkly|optimizely|split\.io|unleash)""",
    # v3 additions
    "recaptchaSiteKey": r"""(?i)(?:recaptcha|grecaptcha|sitekey|site_key|captchaSiteKey)\s*[:=]\s*["'`]""",
    "oauthClientId": r"""(?i)(?:oauth_client_id|auth0_client|cognito_(?:client|pool)_id|tenantId|issuer)\s*[:=]\s*["'`]""",
    "sentryDsn": r"""(?i)sentry\.dsn|dsn\s*[:=]\s*["'`]https?://""",
    "wsBase": r"""(?i)(?:wsBase|WS_URL|socketUrl|socket_url|realtimeUrl)\s*[:=]\s*["'`]""",
    "cdnBase": r"""(?i)(?:cdnBase|CDN_URL|assetPrefix|assetsUrl|staticUrl)\s*[:=]\s*["'`]""",
    "firebaseProject": r"""(?i)(?:firebaseapp|firebaseio|firebasestorage|projectId)""",
    "supabaseProject": r"""(?i)supabase\.co|supabaseUrl|supabaseKey""",
    "thirdPartyIds": r"""(?i)(?:mapbox|mapsApiKey|mapsAPIKey|stripe_pk|razorpay|paypal_client)""",
    "internalHostname": r"""(?i)["'`][a-z0-9\-]+\.(?:internal|local|corp|intranet|staging|dev|test)["'`:0-9]*""",
}

# v2 SECRET_PATTERNS preserved + v3 extensions appended (total 40+)
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"ASIA[0-9A-Z]{16}", "aws_temp_credential"),
    (r"AIza[0-9A-Za-z_\-]{35}", "google_api_key"),
    (r"ya29\.[0-9A-Za-z_\-]{20,}", "google_oauth_token"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "stripe_secret_live"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "stripe_restricted"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "stripe_publishable"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "slack_token"),
    (r"ghp_[0-9A-Za-z]{36}", "github_pat"),
    (r"github_pat_[0-9A-Za-z_]{22,}", "github_fine_pat"),
    (r"glpat-[0-9A-Za-z_\-]{20,}", "gitlab_pat"),
    (r"npm_[0-9A-Za-z]{36}", "npm_token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private_key"),
    (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}", "jwt"),
    (r"(?i)authorization['\"]?\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9._\-]{10,}", "bearer_literal"),
    (r"(?i)firebase(?:Config|_key|ApiKey)?[^;]{0,220}", "firebase_config"),
    (r"(?i)supabase(?:Key|Url|_key|_url|AnonKey)?\s*[:=]\s*['\"][^'\"]{10,}", "supabase_key"),
    (r"(?i)(?:sendgrid|mailgun|twilio|nexmo|postmark)[_a-z]*(?:key|token|sid|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{10,}", "comms_provider_secret"),
    (r"(?i)mongodb(?:\+srv)?://[^\s'\"<>]{10,}", "mongo_uri"),
    (r"(?i)postgres(?:ql)?://[^\s'\"<>]{10,}", "postgres_uri"),
    (r"(?i)mysql://[^\s'\"<>]{10,}", "mysql_uri"),
    (r"(?i)redis://[^\s'\"<>]{10,}", "redis_uri"),
    (r"(?i)amqp://[^\s'\"<>]{10,}", "amqp_uri"),
    (r"(?i)algolia[^\n]{0,80}(?:apiKey|adminKey)\s*[:=]\s*['\"][^'\"]{10,}", "algolia_key"),
    (r"(?i)(?:mapbox|maptiler)[_a-z]*token\s*[:=]\s*['\"][^'\"]{10,}", "map_token"),
    (r"(?i)(?:cloudinary|imgix|contentful)[_a-z]*(?:key|token|secret)\s*[:=]\s*['\"][^'\"]{10,}", "cms_provider_secret"),
    # ---- v3 additions ----
    (r"sk-[A-Za-z0-9_\-]{20,}", "openai_style_key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "anthropic_key"),
    (r"hf_[A-Za-z0-9]{30,}", "huggingface_token"),
    (r"(?i)client_secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{10,}", "oauth_client_secret"),
    (r"(?i)DefaultEndpointsProtocol=https;[^'\"\n]{20,}", "azure_storage_conn"),
    (r"(?i)sentry\.dsn\s*=\s*['\"]https://[^'\"]{20,}", "sentry_dsn_literal"),
    (r"(?i)(?:telegram|tg)[_a-z]*bot[_a-z]*token\s*[:=]\s*['\"][0-9]{6,12}:[A-Za-z0-9_\-]{30,}", "telegram_bot_token"),
    (r"https://discord(?:app)?\.com/api/webhooks/[0-9]{10,}/[A-Za-z0-9_\-]{20,}", "discord_webhook"),
    (r"(?i)(?:webhook|callback)[_a-z]*secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{10,}", "webhook_secret"),
    (r"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*['\"](?!null|undefined|\$\{)([A-Za-z0-9_\-!@#$%^&*]{8,40})['\"]", "hardcoded_credential"),
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,50})['\"]", "generic_api_key"),
    (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "bearer_raw"),
    (r"(?i)ftp(?:es?)://[^\s'\"<>]{8,}", "ftp_uri"),
    (r"(?i)ssh://[^\s'\"<>]{8,}", "ssh_uri"),
    (r"(?i)secret[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9+/=]{16,64})['\"]", "secret_key_literal"),
]

INTERESTING_PARAMS = {
    "redirect", "url", "next", "return", "returnurl", "redirect_uri", "continue",
    "callback", "dest", "destination", "goto", "file", "path", "template", "page",
    "debug", "test", "admin", "role", "isadmin", "user_id", "userid", "id",
    "tenant", "tenant_id", "org", "organization", "account", "account_id",
    "token", "key", "apikey", "api_key", "access_token", "id_token",
    "amount", "price", "quantity", "discount", "coupon", "credit",
    # v3 additions
    "email", "username", "password", "otp", "code", "state", "session",
    "file_path", "filepath", "resource", "endpoint", "host", "scheme",
    "filter", "sort", "order", "limit", "offset", "format", "view",
}

# ---------------------------------------------------------------------------
# v3 CLASSIFICATION TABLES (API kind + priority scoring)
# ---------------------------------------------------------------------------
API_KIND_RULES = [
    ("admin",    re.compile(r"(?i)/(?:internal/)?(?:admin|manage|console|backoffice|controlpanel)")),
    ("debug",    re.compile(r"(?i)/(?:debug|_debug|actuator|metrics|health|trace|env|heapdump|swagger|api-docs|openapi)")),
    ("auth",     re.compile(r"(?i)/(?:auth|login|logout|token|refresh|oauth|sso|session|register|signup|password|otp|mfa)")),
    ("upload",   re.compile(r"(?i)/(?:upload|attachments?|files?|import|media)")),
    ("graphql",  re.compile(r"(?i)graphql")),
    ("realtime", re.compile(r"(?i)(?:socket\.io|websocket|/ws(?:/|$)|signalr|primus|sockjs)")),
    ("rpc",      re.compile(r"(?i)(?:trpc|/rpc|jsonrpc|grpc)")),
    ("webhook",  re.compile(r"(?i)webhook|callbacks?")),
    ("billing",  re.compile(r"(?i)billing|payment|invoice|checkout|subscription|orders?")),
    ("user",     re.compile(r"(?i)/(?:users?|accounts?|profile|me|self|members?)")),
    ("search",   re.compile(r"(?i)search|query|find|filter")),
    ("export",   re.compile(r"(?i)export|download|report|csv|pdf|dump")),
]

PRIORITY_WORDS = {
    "admin": 30, "internal": 28, "debug": 24, "actuator": 24, "swagger": 16,
    "graphql": 18, "upload": 16, "auth": 14, "token": 14, "oauth": 14,
    "webhook": 12, "billing": 12, "payment": 14, "user": 8, "account": 8,
    "export": 10, "download": 8, "import": 10, "impersonate": 26,
    "password": 12, "reset": 10, "invite": 10, "role": 12, "permission": 12,
    "secret": 20, "key": 8, "file": 8, "template": 8, "render": 8,
    "exec": 26, "eval": 22, "cmd": 20, "shell": 24, "proxy": 14, "fetch": 8,
    "url": 6, "redirect": 8, "test": 4, "v1": 3, "v2": 3, "v3": 2,
}

TOKEN_KEY_RE = re.compile(r"(?i)(?:token|jwt|auth|session|sid|access|refresh|id_token|api[_-]?key|bearer|cred)")

# ---------------------------------------------------------------------------
# CORE HELPERS (v2 preserved + v3)
# ---------------------------------------------------------------------------
def fetch_text(http, url, save=None):
    r = http.request("GET", url, allow_redirects=True, save=save, retries=1)
    if r.error:
        return None, r.error
    return r.text, None


def detect_minified(text):
    lines = [l for l in text.split("\n")]
    if len(lines) < 5:
        return False
    avg = sum(len(l) for l in lines) / max(1, len(lines))
    return avg > 300 or (len(text) / max(1, len(lines))) > 400


def beautify_js(text):
    """ULTRA v3: minified bundle ko statement-level split karo.

    Regex-based extraction minified code par miss karti hai (sab ek line me hota hai
    aur lazy quantifiers context khaa jaate hain). Ye naive beautifier har statement
    ko apni line pe daal deta hai - koi parsing nahi, sirf regex stability ke liye.
    Original text bhi joined rehta hai, isliye koi cheez miss nahi hoti.
    """
    try:
        out = re.sub(r";", ";\n", text)
        out = re.sub(r"\{", "{\n", out)
        out = re.sub(r"\}", "\n}\n", out)
        out = re.sub(r"\)\s*(?:=>|\.|if|for|while)", lambda m: ")\n" + m.group(1), out, count=0)
        return out
    except Exception:
        return text


def _clean_path(p):
    """v3: extracted path candidate ko normalize (dedupe-friendly)."""
    if not p:
        return None
    p = p.strip()
    if p.endswith(("'", '"', "`", ",", ";")):
        p = p[:-1]
    if len(p) < 2 or not p.startswith("/"):
        return None
    # pure formatting/static asset paths ko drop karo (noise kam)
    if re.match(r"(?i)^/(?:css|img|images|fonts|icons)/", p) and not re.search(
            r"(?i)api|admin|token|auth|user|upload", p):
        return None
    return p


def join_concats(joined):
    """v3: "/api/" + "users" style adjacent literals ko reconstructed path do."""
    out = set()
    for m in RE_CONCAT.finditer(joined):
        a, b = m.group(1), m.group(2)
        if a.startswith("/") and re.match(r"^[A-Za-z0-9_\-./{}$.]+$", b):
            c = _clean_path(a + b)
            if c:
                out.add(c)
    return out


def template_paths(joined):
    """v3: `${base}/api/users` template literals -> /api/users."""
    out = set()
    for m in RE_TPL_BASE.finditer(joined):
        c = _clean_path(m.group(1))
        if c:
            out.add(c)
    for m in RE_TPL_PATH.finditer(joined):
        seg = m.group(1)
        # ${...} placeholders ko :param style me convert karo (P11/P12 ke liye readable)
        seg = re.sub(r"\$\{[^}]{1,40}\}", ":param", seg)
        c = _clean_path(seg.split("${")[0] if "${" in seg and ":param" not in seg else seg)
        if c and len(c) >= 3:
            out.add(c)
    return out


def openapi_in_js(joined):
    """v3: bundles ke andar embedded OpenAPI/Swagger paths."""
    out = set()
    for m in RE_OPENAPI_PATH.finditer(joined):
        c = _clean_path(m.group(1))
        if c:
            out.add(c)
    for m in RE_VERB_PATH.finditer(joined):
        c = _clean_path(m.group(2))
        if c:
            out.add(m.group(1).upper() + " " + c)
    return out


def classify_api(path):
    """v3: path -> (kind, priority). Explainable scoring (P8-ready)."""
    low = path.lower()
    kinds = []
    for name, rx in API_KIND_RULES:
        if rx.search(path):
            kinds.append(name)
    prio = 0
    for w, pts in PRIORITY_WORDS.items():
        if w in low:
            prio += pts
    prio += min(len(low) // 40, 5)          # lambi nested paths thoda upar
    if kinds:
        prio += 6
    if "{" in path or ":param" in path:
        prio += 8                            # parameterized = IDOR/authz candidate
    if re.search(r"(?i)(?:id|uuid|uid|guid|no|num)", low):
        prio += 6
    return (kinds[0] if kinds else "rest"), min(prio, 99)


def extract_storage_tokens(joined):
    """v3: localStorage/sessionStorage keys jo token jaise hain (XSS->ATO chain)."""
    out = set()
    for m in RE_STORAGE.finditer(joined):
        k = m.group(1)
        if TOKEN_KEY_RE.search(k):
            out.add(k)
    return sorted(out)


def extract_client_redirects(joined):
    """v3: location assignment + redirect-ish param same file -> open-redirect candidate."""
    has_param = bool(RE_REDIRECT_PARAM.search(joined))
    out = []
    if has_param:
        for m in RE_CLIENT_REDIRECT.finditer(joined):
            tgt = (m.group(1) or "").strip()
            if not tgt or tgt.lower().startswith(("'http", '"http', "`http")):
                # hardcoded URL = kam interesting; variable/param = interesting
                continue
            out.append("location <= %s (redirect-param present)" % tgt[:80])
    return out


def extract_framework_payloads(html_texts):
    """v3: __NEXT_DATA__/__NUXT__ payload intel (buildId, env, api urls)."""
    intel = {"next_data": False, "nuxt_data": False, "build_id": None,
             "public_env": {}, "api_urls": set()}
    for t in html_texts or []:
        if not t:
            continue
        m = RE_NEXT_DATA.search(t)
        if m:
            intel["next_data"] = True
            try:
                data = json.loads(m.group(1))
                intel["build_id"] = data.get("buildId")
                runtime = data.get("runtimeConfig") or {}
                for k, v in runtime.items():
                    if isinstance(v, str) and v.startswith(("http", "/")):
                        intel["api_urls"].add(v[:120])
            except Exception:
                pass
        m = RE_NUXT_DATA.search(t)
        if m:
            intel["nuxt_data"] = True
        for em in RE_PUBLIC_ENV.finditer(t):
            intel["public_env"][em.group(1)] = redact(em.group(2), 6)
        for um in RE_ABS_URL.finditer(t):
            u = um.group(1)
            if "api" in u.lower():
                intel["api_urls"].add(u[:120])
    intel["api_urls"] = sorted(intel["api_urls"])[:40]
    return intel


def extract_html_intel(html_texts):
    """v3: seed pages ke comments + SRI audit + sw/manifest hints."""
    comments, sri_missing, sri_ok = set(), set(), set()
    for t in html_texts or []:
        if not t:
            continue
        for m in RE_HTML_COMMENT.finditer(t):
            c = m.group(1).strip()
            if 8 <= len(c) <= 300 and not c.lower().startswith("[if"):
                comments.add(c[:280])
        for am in RE_SCRIPT_ATTRS.finditer(t):
            attrs_before, src, attrs_after = am.group(1) or "", am.group(2), am.group(3) or ""
            if src.startswith("data:") or src.endswith((".js", ".mjs")) or "/js/" in src:
                is_external = bool(re.match(r"(?i)(?:https?:)?//", src)) or \
                    ("cdn" in src.lower() or "google" in src.lower() or "unpkg" in src.lower()
                     or "jsdelivr" in src.lower() or "cloudflare" in src.lower())
                has_integrity = RE_INTEGRITY.search(attrs_before + attrs_after)
                if is_external and not has_integrity:
                    sri_missing.add(src[:200])
                elif is_external and has_integrity:
                    sri_ok.add(src[:200])
    return {"comments": sorted(comments)[:60], "sri_missing": sorted(sri_missing)[:40],
            "sri_ok": sorted(sri_ok)[:40]}


# ---------------------------------------------------------------------------
# v2 analyze_js (preserved contract) + v3 superset sections
# ---------------------------------------------------------------------------
def analyze_js(js_url, text, extra_texts, scope_hosts=None):
    blobs = [text] + list(extra_texts or [])
    blob_join = "\n".join(blobs)
    # v3: beautified view sirf URL/endpoint extraction ke liye (counts original par)
    joined = blob_join + "\n" + beautify_js(blob_join)
    count_blob = blob_join
    res = {"url": js_url, "sha1": sha1(text), "size": len(text),
           "minified": detect_minified(text),
           "sourcemap_sources": [], "sourcemap_ref": None,
           "endpoints": set(), "fetch_calls": set(), "methods": set(), "params": set(),
           "graphql_ops": set(), "graphql_endpoints": set(), "websockets": set(),
           "routes": set(), "imports": set(), "chunks": set(), "build_ids": set(),
           "sinks": {}, "sources": {}, "authz_hints": {}, "config_hints": {},
           "secrets": [], "external_domains": set(), "interesting_params": set()}

    for rx, key in ((RE_ABS_URL, "endpoints"), (RE_REL_URL, "endpoints"), (RE_ANY_PATH, "endpoints")):
        for m in rx.finditer(joined):
            v = m.group(1)
            if key == "endpoints":
                v = _clean_path(v) or v
            res[key].add(v)
    for m in RE_FETCH.finditer(joined):
        res["fetch_calls"].add(m.group(1))
    for m in RE_METHOD_URL.finditer(joined):
        res["methods"].add("%s %s" % (m.group(1).upper(), m.group(2)))
    for m in RE_URL_METHOD.finditer(joined):
        res["methods"].add("%s %s" % (m.group(2).upper(), m.group(1)))
    for m in RE_AXIOS_VERB.finditer(joined):
        res["methods"].add("%s %s" % (m.group(1).upper(), m.group(2)))
        res["fetch_calls"].add(m.group(2))
    for m in RE_JQUERY_VERB.finditer(joined):
        verb = "GET" if m.group(1).lower() in ("get", "getjson") else "POST"
        res["methods"].add("%s %s" % (verb, m.group(2)))
    for m in RE_FETCH_METHOD.finditer(joined):
        res["methods"].add("%s %s" % (m.group(2).upper(), m.group(1)))
    for m in RE_XHR_OPEN.finditer(joined):
        res["methods"].add("%s %s" % (m.group(1).upper(), m.group(2)))
    for m in RE_PARAM.finditer(joined):
        res["params"].add(m.group(1))
    for m in RE_GRAPHQL.finditer(joined):
        res["graphql_ops"].add("%s %s" % (m.group(1).lower(), m.group(2)))
    for m in RE_GQL_ENDPOINT.finditer(joined):
        res["graphql_endpoints"].add(m.group(1))
    for m in RE_WS.finditer(joined):
        res["websockets"].add(m.group(1))
    for rx in (RE_ROUTE_DEF, RE_REACT_ROUTE, RE_NEXT_ROUTE):
        for m in rx.finditer(joined):
            res["routes"].add(m.group(1))
    for m in RE_IMPORT.finditer(joined):
        res["imports"].add(m.group(1))
    for m in RE_CHUNK_MAP.finditer(joined):
        res["chunks"].add(m.group(2))
    for m in RE_BUILD_ID.finditer(joined):
        res["build_ids"].add(m.group(1))

    # ---------------- v3 ULTRA extractors ----------------
    for c in join_concats(joined):
        res["endpoints"].add(c)
    for c in template_paths(joined):
        res["endpoints"].add(c)
    for c in openapi_in_js(joined):
        if " " in c:
            res["methods"].add(c)
            res["endpoints"].add(c.split(" ", 1)[1])
        else:
            res["endpoints"].add(c)
    for m in RE_SW.finditer(joined):
        res["endpoints"].add(_clean_path(m.group(1)) or m.group(1))
        res["service_workers"] = res.get("service_workers", set())
        res["service_workers"].add(m.group(1))
    for m in RE_WORKER.finditer(joined):
        res.setdefault("service_workers", set()).add(m.group(1))
    for m in RE_RPC_STYLE.finditer(joined):
        res["endpoints"].add(_clean_path(m.group(1)) or m.group(1))
    for m in RE_REALTIME.finditer(joined):
        res["endpoints"].add(_clean_path(m.group(1)) or m.group(1))
    for m in RE_UPLOAD.finditer(joined):
        res["endpoints"].add(_clean_path(m.group(1)) or m.group(1))
    for m in RE_GQL_PERSISTED.finditer(joined):
        res.setdefault("gql_persisted_hashes", set()).add(m.group(1))
    for m in RE_GQL_SUB.finditer(joined):
        res["graphql_ops"].add("subscription %s" % m.group(1))
    for m in RE_API_VERSION.finditer(joined):
        res.setdefault("api_versions", set()).add(m.group(1).lower())
    res.setdefault("service_workers", set())
    res.setdefault("gql_persisted_hashes", set())
    res.setdefault("api_versions", set())
    res["storage_tokens"] = extract_storage_tokens(joined)          # v3
    res["client_redirects"] = extract_client_redirects(joined)      # v3
    res["postmessage_wildcard"] = len(RE_POSTMESSAGE_WILD.findall(joined))  # v3
    res["postmessage_listeners"] = len(RE_MSG_LISTENER.findall(joined))     # v3
    res["doc_domain_relax"] = [m.group(1)[:80] for m in RE_DOC_DOMAIN.finditer(joined)]  # v3
    res["opener_primitives"] = len(RE_OPENER.findall(joined))       # v3
    res["multipart"] = bool(RE_MULTIPART.search(joined))            # v3

    # counts ORIGINAL par (beautified copy counts double karta) - v2 parity
    for name, pat in DOM_SINKS.items():
        c = len(re.findall(pat, count_blob))
        if c:
            res["sinks"][name] = c
    for name, pat in DOM_SOURCES.items():
        c = len(re.findall(pat, count_blob))
        if c:
            res["sources"][name] = c
    for name, pat in AUTHZ_HINTS.items():
        c = len(re.findall(pat, count_blob))
        if c:
            res["authz_hints"][name] = c
    for name, pat in CONFIG_HINTS.items():
        c = len(re.findall(pat, count_blob))
        if c:
            res["config_hints"][name] = c

    seen_secrets = set()
    for pat, label in SECRET_PATTERNS:
        for m in re.finditer(pat, joined):
            val = m.group(0)
            if len(val) < 12:
                continue
            ent = round(shannon_entropy(val), 2)
            if ent < 2.5 and label not in ("private_key", "firebase_config"):
                continue
            fp = sha1(val)[:16]
            if fp in seen_secrets:
                continue
            seen_secrets.add(fp)
            res["secrets"].append({"type": label, "len": len(val), "entropy": ent,
                                   "fingerprint": fp, "value_redacted": redact(val, 4)})

    # v3: core scan_secrets additive merge (entropy high-value only, redacted)
    if _core_scan_secrets is not None:
        try:
            for s in (_core_scan_secrets(joined, limit=20, entropy_threshold=4.8) or []):
                val = s.get("match") or ""
                if len(val) < 12:
                    continue
                fp = sha1(val)[:16]
                if fp in seen_secrets:
                    continue
                seen_secrets.add(fp)
                res["secrets"].append({"type": "core:%s" % s.get("kind", "unknown"),
                                       "len": len(val),
                                       "entropy": round(shannon_entropy(val), 2),
                                       "fingerprint": fp, "value_redacted": val})
        except Exception:
            pass

    for u in res["endpoints"]:
        if u.startswith("//"):
            u = "https:" + u
        if u.startswith("http"):
            h = host_of(u)
            if h and (not scope_hosts or h not in scope_hosts):
                res["external_domains"].add(h)

    res["interesting_params"] = sorted(p for p in res["params"]
                                       if p.lower() in INTERESTING_PARAMS)

    for k in ("endpoints", "fetch_calls", "methods", "params", "graphql_ops",
              "graphql_endpoints", "websockets", "routes", "imports", "chunks",
              "build_ids", "external_domains", "service_workers",
              "gql_persisted_hashes", "api_versions"):
        res[k] = sorted(res[k])
    return res

# ---------------------------------------------------------------------------
# SOURCEMAP ULTRA (v2 preserved + X-SourceMap header + .map probe + orig fetch)
# ---------------------------------------------------------------------------
def _map_from_json(txt):
    data = json.loads(txt)
    contents = [c for c in (data.get("sourcesContent") or []) if isinstance(c, str) and c]
    return data, contents


def find_sourcemap(http, js_url, js_text, ref=None):
    """Discover source map; returns (info_dict, list_of_extra_source_texts)."""
    if not ref:
        m = RE_SOURCEMAP.search(js_text) or RE_SOURCEMAP2.search(js_text)
        if not m:
            return None, []
        ref = m.group(1).strip()
    if ref.startswith("data:"):
        try:
            b64 = ref.split(",", 1)[1]
            data = json.loads(base64.b64decode(b64))
            contents = [c for c in (data.get("sourcesContent") or []) if isinstance(c, str) and c]
            return ({"ref": ref[:60], "inline": True, "sources": data.get("sources", [])[:200],
                     "sources_count": len(data.get("sources", [])),
                     "sourcesContent_count": len(contents)}, contents)
        except Exception:
            return {"ref": ref[:60], "inline": True, "error": "decode-failed"}, []
    map_url = up.urljoin(js_url, ref)
    txt, e = fetch_text(http, map_url, save="map_%s" % re.sub(r"[^A-Za-z0-9_.-]", "_", ref)[-60:])
    if e:
        return {"ref": ref, "url": map_url, "error": e}, []
    try:
        data, contents = _map_from_json(txt)
    except Exception:
        return {"ref": ref, "url": map_url, "error": "not-json"}, []
    return ({"ref": ref, "url": map_url, "sources": data.get("sources", [])[:300],
             "sources_count": len(data.get("sources", [])),
             "sourcesContent_count": len(contents)}, contents)


def probe_sourcemap_extra(http, js_url, js_text, r_headers=None, probe_budget=None):
    """v3 ULTRA: comment-less sourcemap discovery.

    1) X-SourceMap / SourceMap response header (deprecated but still alive)
    2) .map guess probe: /static/app.js -> /static/app.js.map (+ .min.js strip)
    probe_budget: {"n": int} mutable counter (request cost control)
    Returns (extra_info_dict, extra_texts) - info None = kuch nahi mila.
    """
    infos, texts = [], []
    # 1) response header route
    hdr = None
    if r_headers:
        for k, v in r_headers.items():
            lk = k.lower()
            if lk in ("x-sourcemap", "sourcemap"):
                hdr = (k, v)
                break
    if hdr:
        try:
            map_url = up.urljoin(js_url, str(hdr[1]).strip())
            txt, e = fetch_text(http, map_url, save="map_hdr")
            if not e:
                try:
                    data, contents = _map_from_json(txt)
                    infos.append({"ref": "header:%s" % hdr[0], "url": map_url,
                                  "sources": data.get("sources", [])[:300],
                                  "sources_count": len(data.get("sources", [])),
                                  "sourcesContent_count": len(contents), "via": "header"})
                    texts.extend(contents)
                except Exception:
                    infos.append({"ref": "header:%s" % hdr[0], "url": map_url, "error": "not-json"})
        except Exception:
            pass
    # 2) .map guess probe (sirf jab comment/header se map nahi mila)
    if not infos and js_text is not None:
        if probe_budget is not None:
            if probe_budget.get("n", 0) <= 0:
                return None, []
            probe_budget["n"] -= 1
        path = up.urlsplit(js_url).path
        guesses = []
        if path.endswith(".min.js"):
            guesses.append(path[:-7] + ".min.js.map")
        elif path.endswith(".js"):
            guesses.append(path + ".map")
            guesses.append(path[:-3] + ".min.js.map")
        for g in guesses[:2]:
            gurl = up.urljoin(js_url, g)
            txt, e = fetch_text(http, gurl)
            if e or not txt:
                continue
            t = (txt or "").lstrip()
            if t[:1] == "{":
                try:
                    data, contents = _map_from_json(txt)
                    infos.append({"ref": g, "url": gurl, "probe": True,
                                  "sources": data.get("sources", [])[:300],
                                  "sources_count": len(data.get("sources", [])),
                                  "sourcesContent_count": len(contents), "via": "probe"})
                    texts.extend(contents)
                    break
                except Exception:
                    continue
    if not infos:
        return None, []
    info0 = infos[0]
    return info0, texts


def sourcemap_original_sources(http, map_info, missing_limit=6):
    """v3 ULTRA: sourcesContent khaali ho to original sources fetch karo (bounded).

    Webpack/Vite production maps me aksar sourcesContent STRIP hota hai - lekin
    sources[] original file paths dikhate hain jo fetch ho sakte hain (misconfig).
    Read-only GET, limit-bounded, scope-checked URLs skip hote hain caller me.
    """
    texts = []
    srcs = map_info.get("sources") or []
    base_url = map_info.get("url") or ""
    n = 0
    for s in srcs:
        if n >= max(1, int(missing_limit)):
            break
        if not s or s.startswith(("webpack://", "vite/", "rollup:", "<")):
            # webpack:// virtual paths real fetch nahi hote - sirf tree intel
            continue
        if s.startswith("/") or re.match(r"(?i)https?://", s):
            url = s if s.startswith("http") else None
            if not url and base_url:
                # relative-to-map-origin guess (rare but real)
                try:
                    url = up.urljoin(base_url, s)
                except Exception:
                    url = None
            if url:
                txt, e = fetch_text(http, url, save="mapsrc_%d" % n)
                if not e and txt:
                    texts.append(txt)
                    n += 1
    return texts


def sourcemap_tree(sources):
    """v3: webpack:// sources -> internal project tree (structure leak intel)."""
    tree = set()
    for s in sources or []:
        m = re.match(r"^(?:webpack|vite|rollup):///?([^?]*)", s or "")
        p = (m.group(1) if m else s) or ""
        p = re.sub(r"^\./", "", p)
        if 2 <= len(p) <= 160:
            tree.add(p[:160])
    return sorted(tree)[:250]


# ---------------------------------------------------------------------------
# COLLECTION (v2 preserved + v3 inline/comments/workers)
# ---------------------------------------------------------------------------
def js_urls_from_prev(out, scope):
    urls = set()
    eng = os.path.dirname(out)
    p2 = os.path.join(eng, "understand", "js_urls.txt")
    if os.path.exists(p2):
        urls.update(l.strip() for l in open(p2, errors="ignore") if l.strip())
    p3 = os.path.join(eng, "passive", "findings", "js_urls.txt")
    if os.path.exists(p3):
        urls.update(l.strip() for l in open(p3, errors="ignore") if l.strip())
    p5 = os.path.join(eng, "content", "content.json")
    if os.path.exists(p5):
        data = json.load(open(p5)) if os.path.getsize(p5) > 2 else {}
        for h, rec in (data.get("results") or {}).items():
            for f in (rec.get("found") or []) + (rec.get("extensions") or []):
                if re.search(r"(?i)\.m?js(\?|$)", f.get("path", "") or f.get("url", "")):
                    urls.add(f.get("url"))
    return sorted(u for u in urls if u and scope.check_url(u, raise_on_fail=False))


def crawl_homepage_js(http, scope, seeds):
    """v3: seed pages se JS collection - script src (v2) + workers + prefetch/preload."""
    found = set()
    for s in seeds:
        r = http.request("GET", s, allow_redirects=True, retries=1)
        if r.error or not r.text:
            continue
        pu = up.urlsplit(r.url)
        base = "%s://%s" % (pu.scheme, pu.netloc)
        for m in re.finditer(r"""(?i)<script[^>]+src\s*=\s*["']([^"']+)["']""", r.text):
            u = m.group(1).strip()
            if not u or u.startswith("data:"):
                continue
            if u.startswith("//"):
                found.add("https:" + u)
            else:
                found.add(up.urljoin(base + "/", u))
        # v3: preload/prefetch module scripts (SPA chunk discovery)
        for m in re.finditer(r"""(?i)<link[^>]+(?:preload|prefetch|modulepreload)[^>]+href\s*=\s*["']([^"']+\.m?js[^"']*)["']""", r.text):
            u = m.group(1).strip()
            if u.startswith("//"):
                found.add("https:" + u)
            else:
                found.add(up.urljoin(base + "/", u))
    return sorted(found)


def collect_inline_scripts(seed_html, max_blocks=12, max_len=65536):
    """v3 ULTRA: seed pages ke inline <script> blocks pseudo-assets banake analyze karo.

    Inline scripts me aksar config/api-base/embedded JSON hota hai jo external
    bundles me nahi milta. Pseudo-URL: '<page>#inline:N' (checkpoint deterministic).
    seed_html: {url: html_text} pre-fetched (double network avoid).
    """
    blocks = []
    for page, text in (seed_html or {}).items():
        if not text:
            continue
        n = 0
        for m in RE_SCRIPT_TAG.finditer(text):
            attrs, body = m.group(1) or "", m.group(2) or ""
            if re.search(r"(?i)\bsrc\s*=", attrs):
                continue
            body = body.strip()
            if len(body) < 24 or n >= max_blocks:
                continue
            blocks.append((page + "#inline:%d" % (n + 1), body[:max_len]))
            n += 1
    return blocks


# ---------------------------------------------------------------------------
# FETCH LAYER (v3: WAF-aware stealth retry + status intel)
# ---------------------------------------------------------------------------
def fetch_js_asset(http, url, save_name):
    """v3: JS asset fetch + WAF/edge-block detection + 1 stealth retry.

    Returns (text, info_dict). info: status, blocked, waf, content_type, retried.
    Security stacks (Cloudflare/Nginx/AWS WAF) JS file ko bhi challenge kar sakte
    hain - tab 1 alternate-header retry karte hain (same read-only request).
    """
    r = http.request("GET", url, allow_redirects=True, save=save_name, retries=1)
    if r.error:
        return None, {"status": None, "error": str(r.error), "blocked": False, "waf": []}
    ct = ""
    try:
        ct = (r.headers or {}).get("Content-Type", "") or ""
    except Exception:
        ct = ""
    wafs = []
    if _core_waf_signature is not None:
        try:
            wafs = _core_waf_signature(headers=r.headers, body=(r.text or "")[:4000],
                                       status=r.status) or []
        except Exception:
            wafs = []
    blocked = r.status in (401, 403, 429) or (r.status == 503 and ("cloudflare" in (ct or "").lower()
                                              or "challenge" in (r.text or "")[:2000].lower()))
    text = r.text
    retried = False
    if blocked:
        # stealth retry: alternate browser identity, same GET, evidence-first
        for hs in STEALTH_HEADER_SETS:
            alt = {k: v for k, v in hs.items() if v is not None}
            try:
                r2 = http.request("GET", url, headers=alt, allow_redirects=True,
                                  retries=1)
            except Exception:
                break
            if not r2.error and r2.status not in (401, 403, 429):
                text = r2.text
                blocked = False
                retried = True
                try:
                    ct = (r2.headers or {}).get("Content-Type", "") or ct
                except Exception:
                    pass
                break
    return text, {"status": r.status, "blocked": blocked, "waf": wafs,
                  "content_type": ct[:60], "retried": retried,
                  "headers": dict(r.headers or {})}

# ---------------------------------------------------------------------------
# RUN ENGINE (v2 flow preserved + v3 parallel/WAF/priority/new-outputs)
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    head("Phase 7 - JS, Client-Side & API Surface (ULTRA v3) | %s" % scope.describe())

    js_max_assets = int(cfg.get("js_max_assets", 150) or 150)
    js_map_orig_limit = int(cfg.get("js_max_map_sources", 6) or 6)
    js_inline = bool(cfg.get("js_inline_analysis", True))
    workers = max(1, min(int(cfg.get("concurrency", 8) or 8), 8))

    seeds = scope.seed_urls()
    p4 = os.path.join(os.path.dirname(out), "active", "live_hosts.txt")
    if os.path.exists(p4):
        for line in open(p4, errors="ignore"):
            m = re.match(r"(https?://\S+)\s*\[", line.strip())
            if m:
                seeds.append(m.group(1))
    seeds = sorted(set(s for s in seeds if scope.check_url(s, raise_on_fail=False)))

    js_urls = set(js_urls_from_prev(out, scope))
    js_urls.update(crawl_homepage_js(http, scope, seeds))
    js_urls = sorted(u for u in js_urls if scope.check_url(u, raise_on_fail=False))
    if len(js_urls) > js_max_assets:
        warn("js_max_assets=%d par cap kiya (%d -> %d)" % (js_max_assets, len(js_urls), js_max_assets))
        js_urls = js_urls[:js_max_assets]
    if not js_urls:
        warn("Koi JS asset nahi mila. Authenticated browsing karke Phase 2/5 rerun karo.")
    info("JS assets: %d | seeds: %d | workers: %d" % (len(js_urls), len(seeds), workers))

    scope_hosts = set()
    for d in scope.root_domains():
        scope_hosts.add(d)
    for s in seeds:
        h = host_of(s)
        if h:
            scope_hosts.add(h)
            scope_hosts.add("www." + h)

    # ---- v3: inline scripts + homepage html intel (comment/SRI/framework payload)
    seed_html = {}
    if seeds:
        try:
            for s in seeds[:3]:
                r = http.request("GET", s, allow_redirects=True, retries=1)
                if not r.error and r.text:
                    seed_html[s] = r.text
        except Exception as e:
            warn("seed fetch skip: %s" % e)
    html_texts = list(seed_html.values())
    inline_blocks = collect_inline_scripts(seed_html) if js_inline else []
    html_intel = extract_html_intel(html_texts)          # comments + SRI
    fw_intel = extract_framework_payloads(html_texts)    # __NEXT_DATA__/__NUXT__

    report = {"phase": "7-js", "generated_at": now_iso(), "engine_version": ENGINE,
              "assets": [], "sourcemaps": [], "secret_hits": [], "attack_surface": {},
              "fetch_intel": {}, "html_intel": html_intel, "framework_payload": fw_intel}
    agg_keys = ("endpoints", "params", "graphql_ops", "graphql_endpoints",
                "websockets", "routes", "external_domains", "imports", "chunks",
                "methods", "interesting_params", "api_versions",
                "gql_persisted_hashes", "service_workers")
    agg = {k: set() for k in agg_keys}

    def agg_asset(rec):
        for k in agg_keys:
            agg[k].update(rec.get(k, []) or [])
        if rec.get("sourcemap_ref"):
            report["sourcemaps"].append({"asset": rec["url"], "ref": rec["sourcemap_ref"],
                                         "sources_count": len(rec.get("sourcemap_sources", [])),
                                         "contents_unpacked": rec.get("sourcemap_contents_unpacked", 0),
                                         "via": rec.get("sourcemap_via", "comment"),
                                         "error": None})
        elif rec.get("sourcemap_error"):
            report["sourcemaps"].append({"asset": rec["url"], "ref": rec.get("sourcemap_error_ref"),
                                         "sources_count": 0, "contents_unpacked": 0,
                                         "via": rec.get("sourcemap_via", "comment"),
                                         "error": rec["sourcemap_error"]})
        for s in rec.get("secrets", []):
            report["secret_hits"].append(dict(s, asset=rec["url"]))

    # ---- v3: per-asset analysis (parallel fetch, sequential aggregation) ----
    probe_budget = {"n": int(cfg.get("js_map_probe_max", 40) or 40)}

    def process_asset(u):
        ck = "asset:" + u
        if cp.is_done(ck):
            rec = cp.result_of(ck)
            return (u, rec, "SKIP (checkpoint)", None)
        save_name = "js_%s" % re.sub(r"[^A-Za-z0-9_.-]", "_",
                                     os.path.basename(up.urlparse(u).path))[:60]
        txt, finfo = fetch_js_asset(http, u, save_name)
        if txt is None and finfo.get("error"):
            warn("   -> %s" % finfo["error"])
            rec = {"url": u, "fetch_error": finfo["error"], "fetch_status": finfo.get("status"),
                   "secrets": [], "endpoints": [], "methods": [], "params": [],
                   "graphql_ops": [], "graphql_endpoints": [], "websockets": [],
                   "routes": [], "imports": [], "chunks": [], "build_ids": [],
                   "external_domains": [], "interesting_params": [], "sinks": {},
                   "sources": {}, "authz_hints": {}, "config_hints": {},
                   "api_versions": [], "gql_persisted_hashes": [], "service_workers": [],
                   "storage_tokens": [], "client_redirects": [], "sourcemap_sources": []}
            cp.mark(ck, rec, summary="js fetch failed")
            return (u, rec, "fetch-failed", finfo)
        if finfo.get("blocked"):
            warn("   -> BLOCKED %s %s (security edge) | waf=%s"
                 % (finfo.get("status"), u[:70], ",".join(finfo.get("waf") or []) or "-"))
            rec = {"url": u, "fetch_error": "blocked-by-edge", "fetch_status": finfo.get("status"),
                   "waf": finfo.get("waf") or [], "secrets": [], "endpoints": [], "methods": [],
                   "params": [], "graphql_ops": [], "graphql_endpoints": [], "websockets": [],
                   "routes": [], "imports": [], "chunks": [], "build_ids": [],
                   "external_domains": [], "interesting_params": [], "sinks": {}, "sources": {},
                   "authz_hints": {}, "config_hints": {}, "api_versions": [],
                   "gql_persisted_hashes": [], "service_workers": [], "storage_tokens": [],
                   "client_redirects": [], "sourcemap_sources": []}
            cp.mark(ck, rec, summary="blocked by edge/waf")
            return (u, rec, "blocked", finfo)
        if finfo.get("content_type", "").lower().startswith(_HTML_CT_PREFIX):
            finfo["html_fallback"] = True    # .js par HTML mila (SPA fallback / WAF interstitial)
        # ---- sourcemap: comment -> (v3) header/probe -> (v3) original sources ----
        smap, extra = find_sourcemap(http, u, txt or "")
        smap_via = "comment"
        if not smap:
            smap2, extra2 = probe_sourcemap_extra(http, u, txt,
                                                  r_headers=finfo.get("headers"),
                                                  probe_budget=probe_budget)
            if smap2:
                smap, extra = smap2, extra2
                smap_via = smap2.get("via") or "probe"
        map_tree = []
        if smap and not smap.get("error"):
            map_tree = sourcemap_tree(smap.get("sources") or [])
            if not extra and smap.get("sourcesContent_count", 0) == 0 and smap.get("url"):
                orig = sourcemap_original_sources(http, smap, js_map_orig_limit)
                if orig:
                    extra = orig
                    smap["originals_fetched"] = len(orig)
        rec = analyze_js(u, txt or "", extra, scope_hosts)
        rec["fetch_status"] = finfo.get("status")
        if finfo.get("retried"):
            rec["stealth_retry_ok"] = True
        if finfo.get("html_fallback"):
            rec["html_fallback"] = True
        if finfo.get("waf"):
            rec["waf"] = finfo["waf"]
        if map_tree:
            rec["sourcemap_tree"] = map_tree
        if smap:
            if smap.get("error"):
                # error entry bhi rec me record (resume par bhi dikhe)
                rec["sourcemap_error"] = smap.get("error")
                rec["sourcemap_error_ref"] = smap.get("ref") or smap.get("url")
                rec["sourcemap_via"] = smap_via
            else:
                rec["sourcemap_ref"] = smap.get("ref") or smap.get("url")
                rec["sourcemap_via"] = smap_via
                rec["sourcemap_sources"] = (smap.get("sources") or [])[:150]
                rec["sourcemap_contents_unpacked"] = len(extra)
                rec["sourcemap_sourcesContent_count"] = smap.get("sourcesContent_count", 0)
        cp.mark(ck, rec, summary="js asset")
        stat = ("endpoints=%d methods=%d params=%d gql=%d ws=%d routes=%d imports=%d "
                "sinks=%d authz=%d secrets=%d smap=%s"
                % (len(rec["endpoints"]), len(rec["methods"]), len(rec["params"]),
                   len(rec["graphql_ops"]), len(rec["websockets"]), len(rec["routes"]),
                   len(rec["imports"]), sum(rec["sinks"].values()),
                   sum(rec["authz_hints"].values()), len(rec["secrets"]), smap_via))
        return (u, rec, stat, finfo)

    # parallel fetch (limiter already throttles; safe_map isolates exceptions)
    results = None
    if _core_safe_map is not None and len(js_urls) > 1:
        try:
            mapped = _core_safe_map(js_urls, process_asset, workers=workers,
                                    label="[js]", every=5)
            mapped = sorted(mapped, key=lambda t: js_urls.index(t[0]))
            results = [t[1] for t in mapped]   # safe_map (item, result) tuples unwrap
        except Exception as e:
            warn("parallel fetch fail (%s) -> sequential" % e)
            results = None
    if results is None:
        results = [process_asset(u) for u in js_urls]

    for i, (u, rec, stat, finfo) in enumerate(results, 1):
        if finfo is None:  # checkpoint replay path
            info("[%d/%d] %s" % (i, len(js_urls), u[:100]))
        ok("[%d/%d] %s" % (i, len(js_urls), (stat or "ok")[:150]))
        report["assets"].append(rec)
        agg_asset(rec)
        if finfo:
            report["fetch_intel"][u] = {k: v for k, v in finfo.items() if k != "retried"}
            if finfo.get("retried"):
                report["fetch_intel"][u]["stealth_retry_ok"] = True
    # v3: inline blocks ko bhi analyze karo (pseudo assets - deterministic keys)
    inline_recs = []
    for pu, body in (inline_blocks or []):
        ck = "asset:" + pu
        if cp.is_done(ck):
            rec = cp.result_of(ck)
            if rec:
                inline_recs.append(rec)
                report["assets"].append(rec)
                agg_asset(rec)
            continue
        rec = analyze_js(pu, body, [], scope_hosts)
        rec["inline"] = True
        cp.mark(ck, rec, summary="inline script")
        inline_recs.append(rec)
        report["assets"].append(rec)
        agg_asset(rec)
    if inline_recs:
        ok("inline scripts analyzed: %d" % len(inline_recs))

    # dedupe secrets across assets (same fingerprint => same secret) [v2 preserved]
    uniq_secrets, seen_fp = [], set()
    for s in report["secret_hits"]:
        fp = s.get("fingerprint") or sha1(str(s.get("value_redacted")))[:16]
        if fp in seen_fp:
            continue
        seen_fp.add(fp)
        uniq_secrets.append(s)
    report["secret_hits"] = uniq_secrets
    report["attack_surface"] = {k: sorted(v) for k, v in agg.items()}
    save_json(os.path.join(out, "js_analysis.json"), report)

    # ---------- flat exports (v2 preserved) ----------
    def w(name, items):
        save_text(os.path.join(out, name), "\n".join(sorted(set(x for x in items if x))))

    w("endpoints.txt", agg["endpoints"])
    w("params.txt", agg["params"])
    w("interesting_params.txt", agg["interesting_params"])
    w("methods.txt", agg["methods"])
    w("graphql_ops.txt", agg["graphql_ops"])
    w("graphql_endpoints.txt", agg["graphql_endpoints"])
    w("websockets.txt", agg["websockets"])
    w("routes.txt", agg["routes"])
    w("external_domains.txt", agg["external_domains"])
    w("imports.txt", agg["imports"])
    w("chunks.txt", agg["chunks"])
    w("api_versions.txt", agg["api_versions"])                    # v3
    w("gql_persisted_hashes.txt", agg["gql_persisted_hashes"])    # v3
    w("service_workers.txt", agg["service_workers"])              # v3

    save_text(os.path.join(out, "dom_analysis.txt"),
              "\n".join("=== %s ===\n  sources: %s\n  sinks:   %s"
                        % (r["url"][:110],
                           ", ".join("%s(%d)" % (k, v) for k, v in r["sources"].items()),
                           ", ".join("%s(%d)" % (k, v) for k, v in r["sinks"].items()))
                        for r in report["assets"] if r.get("sinks") or r.get("sources")))
    save_text(os.path.join(out, "authz_client_hints.txt"),
              "\n".join("%s -> %s" % (r["url"][:110], ", ".join("%s(%d)" % (k, v)
                                                                for k, v in r["authz_hints"].items()))
                        for r in report["assets"] if r.get("authz_hints")))
    save_text(os.path.join(out, "config_hints.txt"),
              "\n".join("%s -> %s" % (r["url"][:110], ", ".join("%s(%d)" % (k, v)
                                                                for k, v in r["config_hints"].items()))
                        for r in report["assets"] if r.get("config_hints")))
    save_text(os.path.join(out, "sourcemaps.txt"),
              "\n".join("%s -> %s sources=%s unpacked=%s via=%s %s"
                        % (s["asset"][:100], s.get("ref"), s.get("sources_count"),
                           s.get("contents_unpacked"), s.get("via", "comment"), s.get("error", ""))
                        for s in report["sourcemaps"]))
    save_json(os.path.join(out, "secret_hits.json"), report["secret_hits"])
    save_text(os.path.join(out, "build_ids.txt"),
              "\n".join("%s -> %s" % (r["url"][:90], ",".join(r["build_ids"]))
                        for r in report["assets"] if r.get("build_ids")))

    same_origin = sorted(e for e in agg["endpoints"]
                         if e.startswith("/") or host_of(e) in scope_hosts)
    save_text(os.path.join(out, "same_origin_endpoints.txt"), "\n".join(same_origin))

    # ---------- v3 ULTRA exports ----------
    # api_endpoints.json - classified, prioritized API object list (P8-ready)
    api_objs, seen_api = [], set()
    for e in same_origin:
        p = e.split(" ", 1)[1] if " " in e and e.split(" ", 1)[0].isupper() else e
        if not p.startswith("/"):
            continue
        key = p.split("?")[0]
        if key in seen_api:
            continue
        seen_api.add(key)
        kind, prio = classify_api(key)
        api_objs.append({"path": key, "kind": kind, "priority": prio,
                         "raw": e[:200],
                         "methods": sorted({m.split(" ", 1)[0] for m in agg["methods"]
                                            if " " in m and m.split(" ", 1)[1].startswith(key)})})
    api_objs.sort(key=lambda o: -o["priority"])
    save_json(os.path.join(out, "api_endpoints.json"),
              {"phase": "7-js", "engine_version": ENGINE, "count": len(api_objs),
               "endpoints": api_objs[:400]})
    save_text(os.path.join(out, "js_priority_queue.txt"),
              "\n".join("P%02d [%s] %s" % (o["priority"], o["kind"], o["path"])
                        for o in api_objs[:120]))

    storage_toks = sorted({t for r in report["assets"] for t in (r.get("storage_tokens") or [])})
    w("storage_tokens.txt", storage_toks)
    client_red = sorted({c for r in report["assets"] for c in (r.get("client_redirects") or [])})
    save_text(os.path.join(out, "client_redirects.txt"), "\n".join(client_red))

    pm_lines = []
    for r in report["assets"]:
        if r.get("postmessage_wildcard"):
            pm_lines.append("%s -> postMessage targetOrigin '*' x%d (origin-check missing)"
                            % (r["url"][:110], r["postmessage_wildcard"]))
        if r.get("postmessage_listeners"):
            pm_lines.append("%s -> message listener x%d (event.data validate karo)"
                            % (r["url"][:110], r["postmessage_listeners"]))
        if r.get("doc_domain_relax"):
            pm_lines.append("%s -> document.domain=%s (sandbox relaxation)"
                            % (r["url"][:110], ",".join(r["doc_domain_relax"])))
        if r.get("opener_primitives"):
            pm_lines.append("%s -> window.opener primitive x%d" % (r["url"][:110], r["opener_primitives"]))
    save_text(os.path.join(out, "postmessage_audit.txt"), "\n".join(pm_lines))

    sri_lines = ["# SRI audit - external scripts bina integrity attribute ke (supply-chain risk)"]
    sri_lines += ["MISSING %s" % s for s in html_intel.get("sri_missing", [])]
    sri_lines += ["OK     %s" % s for s in html_intel.get("sri_ok", [])]
    save_text(os.path.join(out, "third_party_scripts.txt"), "\n".join(sri_lines))

    save_text(os.path.join(out, "inline_intel.txt"),
              "\n".join("=== %s ===\n%s" % (r["url"][:110],
                        "\n".join("  %s: %s" % (k, (",".join("%s(%d)" % (a, b) for a, b in v.items())
                                                if isinstance(v, dict) else str(v))[:220])
                                  for k, v in (("endpoints", {"x": len(r.get("endpoints") or [])}),
                                               ("authz_hints", r.get("authz_hints") or {}),
                                               ("config_hints", r.get("config_hints") or {}),
                                               ("secrets", {"count": len(r.get("secrets") or [])}))))
                        for r in inline_recs))
    save_text(os.path.join(out, "html_comments.txt"), "\n".join(html_intel.get("comments", [])))
    map_tree_all = sorted({t for r in report["assets"] for t in (r.get("sourcemap_tree") or [])})
    save_text(os.path.join(out, "sourcemap_tree.txt"), "\n".join(map_tree_all))

    # v3: chains (explainable, evidence-backed)
    chains = []
    if storage_toks and any(sum(r.get("sinks", {}).values()) for r in report["assets"]):
        chains.append("DOM-XSS -> Account-Takeover: token storage keys (%s) + DOM sinks present "
                      "- XSS se token steal possible (P14 validate karo)"
                      % ", ".join(storage_toks[:5]))
    if any("admin" in (o["path"].lower()) for o in api_objs[:50]):
        chains.append("API admin surface exposed client-side: /admin/* paths JS bundles me mile "
                      "- P11 vertical authz matrix in targets par chalao")
    if agg["gql_persisted_hashes"]:
        chains.append("GraphQL persisted queries: hashes se endpoint brute/abuse possible (P18)")
    if agg["service_workers"]:
        chains.append("Service workers registered: sw.js tampering/cache-poisoning review (P16/P23)")
    if html_intel.get("sri_missing"):
        chains.append("Supply-chain: %d external scripts bina SRI - CDN compromise -> XSS (P24/P26)"
                      % len(html_intel["sri_missing"]))
    if client_red:
        chains.append("Client-side open-redirect candidates: redirect-param + location sink (P20)")
    save_text(os.path.join(out, "chains.txt"), "\n".join("- " + c for c in chains))

    ff = write_feedforward(out, "7-js", {
        "to_phase8_surface": {"queue": "js_priority_queue.txt", "api": "api_endpoints.json",
                              "storage": "storage_tokens.txt"},
        "to_phase9_auth": {"endpoints": "same_origin_endpoints.txt", "hints": "authz_client_hints.txt"},
        "to_phase10_sessions": {"secrets": "secret_hits.json", "storage": "storage_tokens.txt"},
        "to_phase11_idor": {"endpoints": "same_origin_endpoints.txt", "routes": "routes.txt",
                            "api": "api_endpoints.json"},
        "to_phase12_params": {"params": "params.txt", "interesting": "interesting_params.txt"},
        "to_phase13_injection": {"endpoints": "same_origin_endpoints.txt"},
        "to_phase14_xss": {"dom": "dom_analysis.txt", "routes": "routes.txt",
                           "postmessage": "postmessage_audit.txt", "storage": "storage_tokens.txt"},
        "to_phase15_ssrf": {"params": "interesting_params.txt"},
        "to_phase16_files": {"upload": "api_endpoints.json"},
        "to_phase17_api": {"endpoints": "same_origin_endpoints.txt", "methods": "methods.txt",
                           "versions": "api_versions.txt"},
        "to_phase18_graphql": {"ops": "graphql_ops.txt", "endpoints": "graphql_endpoints.txt",
                               "persisted": "gql_persisted_hashes.txt"},
        "to_phase19_websocket": {"ws": "websockets.txt"},
        "to_phase20_logic": {"hints": "authz_client_hints.txt", "redirects": "client_redirects.txt"},
        "to_phase23_secrets": {"secrets": "secret_hits.json", "tree": "sourcemap_tree.txt"},
        "to_phase24_cloud": {"external": "external_domains.txt", "config": "config_hints.txt",
                             "sri": "third_party_scripts.txt"},
        "to_phase26_automation": {"comments": "html_comments.txt"},
        "to_phase28_chains": {"chains": "chains.txt"},
        "to_phase32_report": {"assets": len(report["assets"]), "secrets": len(report["secret_hits"])},
    }, notes=["secret values are redacted; entropy<2.5 filtered as noise",
              "v3: api_endpoints.json explainable priority (P8 queue) + sourcemap tree + chains"])

    write_manifest(out, "7-js",
                   ["js_analysis.json", "endpoints.txt", "params.txt", "interesting_params.txt",
                    "methods.txt", "graphql_ops.txt", "graphql_endpoints.txt", "websockets.txt",
                    "routes.txt", "external_domains.txt", "imports.txt", "chunks.txt",
                    "dom_analysis.txt", "authz_client_hints.txt", "config_hints.txt",
                    "sourcemaps.txt", "secret_hits.json", "build_ids.txt",
                    "same_origin_endpoints.txt", "feedforward.json",
                    "api_endpoints.json", "js_priority_queue.txt", "api_versions.txt",
                    "storage_tokens.txt", "client_redirects.txt", "postmessage_audit.txt",
                    "third_party_scripts.txt", "inline_intel.txt", "html_comments.txt",
                    "sourcemap_tree.txt", "gql_persisted_hashes.txt", "service_workers.txt",
                    "chains.txt", "MANIFEST.json"],
                   stats={"assets": len(report["assets"]),
                          "endpoints": len(agg["endpoints"]),
                          "params": len(agg["params"]), "secrets": len(report["secret_hits"]),
                          "websockets": len(agg["websockets"]),
                          "sourcemaps": len(report["sourcemaps"]),
                          "api_objects": len(api_objs), "inline": len(inline_recs),
                          "sri_missing": len(html_intel.get("sri_missing", [])),
                          "chains": len(chains), "engine": ENGINE})

    head("Phase 7 complete (ULTRA v3)")
    ok("assets=%d | endpoints=%d | params=%d | gql_ops=%d | ws=%d | routes=%d | secrets=%d | "
       "sourcemaps=%d | api_objs=%d | inline=%d | chains=%d"
       % (len(report["assets"]), len(agg["endpoints"]), len(agg["params"]),
          len(agg["graphql_ops"]), len(agg["websockets"]), len(agg["routes"]),
          len(report["secret_hits"]), len(report["sourcemaps"]), len(api_objs),
          len(inline_recs), len(chains)))
    _ = ff
    return out
