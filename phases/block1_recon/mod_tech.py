#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP MODULE  |  Phase 6 - Technology & Architecture Identification  (ULTRA v3)
===============================================================================
Read-only, behaviour-based, confidence-scored fingerprinting with
banner-spoof (contradiction) detection. Drop-in replacement for the v2
mod_tech.py - SAME contract (NAME/run/module_ctx/checkpoints), SAME output
filenames + superset JSON schema, so P8 surface / P10 sessions / selftest
kabhi break nahi honge.

Indicators fused per technology (strict source separation - v2 fix retained):
    h  headers       b  body        c  cookies     e  error-page
    d  default-path  j  js-asset    x  xml/feed    r  redirect/Location

ULTRA v3 - v2 ke upar kya naya hai:
  1. Signature DB ~3x (130+ techs): CMS/SSG, frameworks, servers, CDN, WAF,
     LB, hosting, SSO/IdP, client libs, realtime - sab evidence-backed.
  2. Version extraction engine + EOL/staleness rules (PHP 8.1 EOL, jQuery
     <3.5 XSS, Apache 2.4.49/50 CVE-2021-41773/42013, nginx <1.20 ...).
  3. Favicon mmh3 hashing (shodan-style http.favicon.hash pivot).
  4. Behavioural fingerprints: OPTIONS/HEAD/TRACE/Range/ETag-format/
     Alt-Svc(h3)/Date-skew - banner ke bina bhi server detect.
  5. WAF trigger probe (wafw00f-style, 1 request) + block-page signatures
     (Cloudflare/AWS WAF/ModSec/Imperva/Akamai/F5/Sucuri/Barracuda/NetScaler).
  6. Perimeter chain reconstruction: WAF -> CDN -> LB -> origin.
  7. GraphQL surface probe: endpoint + GraphiQL + __typename POST +
     introspection check (read-only, capped) -> P18 ko direct routing.
  8. OpenAPI/Swagger doc discovery + spec parsing (title/version/paths).
  9. SSO/OIDC discovery: /.well-known/opening-configuration + JWKS (alg/kty)
     -> P9/P10 ko routing (HS256 hint = JWT symmetric alert).
 10. Meta probes: robots/humans/security.txt/AASA/assetlinks/cdn-cgi trace.
 11. Architecture inference engine: rendering model (SSR/CSR/SSG/static),
     backend pattern (API-first/MVC/hybrid), realtime layer, BFF detection,
     engagement-level multi-stack (microservices hint).
 12. Security observations (TECH-OBS-###): debug tools exposed, version
     disclosure, directory listing, TRACE enabled, WebDAV, docs exposure ...
     severity + remediation + next-phase feedforward.
 13. Contradiction engine v3: banner-vs-behaviour mismatch, absurd versions,
     Cloudflare-claimed-but-no-cf-ray, PHP+ASP.NET, WP+Drupal ...
 14. v2 BUG FIX: default-path hits v2 me score me contribute hi nahi karte
     the (blob "d" me tech NAME jata tha, SIG patterns PATHS the) - ab dono.
 15. Resume-consistent: har stage checkpointed; reports cached records se
     re-derive hote hain (network ke bina).

Safety: sirf GET/HEAD/OPTIONS/TRACE + read-only GraphQL POST (capped).
Koi destructive probe nahi. Har URL scope-firewall se guzarta hai.
Rate-limit/budget wasp_core enforce karta hai.

Outputs (out dir = <base>/<engagement>/tech/):
    tech_profile.json   full evidence-backed profile per host (superset)
    stack_report.txt    human-readable ranked stack + evidence + versions
    architecture_map.txt  rendering/backend/realtime model per host
    tech_versions.txt   extracted versions + EOL/staleness notes
    favicon_hashes.txt  mmh3 favicon hashes (shodan pivot query included)
    waf_cdn.txt         WAF/CDN/LB detection + trigger results
    perimeter.json      machine-readable perimeter chain per host
    openapi_specs.json  discovered OpenAPI/Swagger specs (parsed)
    graphql_surface.json  endpoints + introspection results
    tech_observations.json / TECH_OBSERVATIONS.md  security observations
    http_behavior.json  OPTIONS/HEAD/TRACE/Range/ETag behaviour per host
    api_style.txt  session_model.txt  contradictions.txt  cache_layer.txt
    error_signatures.txt  stack_summary.txt  feedforward.json  MANIFEST.json
"""
import os, re, json, time
import urllib.parse as up
from wasp_core import (module_ctx, write_feedforward, write_manifest, ProbeCache,
                       soft404_baseline, is_soft404, normalize_url, host_of, sha1,
                       rand_str, title_of, save_json, save_text, info, ok, warn, err,
                       head, now_iso, favicon_hash, interrupted)

NAME = "tech"
MODULE_VERSION = "3.0.0-ultra"

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


def _ro_post(http, method, url, **kw):
    """LAYER 4 compat: pure-read POST (GraphQL introspection jaisa - kuch
    modify nahi karta). ULTRA core par read_only_post=True read-only gate se
    pass hota hai; PURANE v2 core par ye kwarg unsupported hai -> TypeError
    par bina kwarg fallback (v2 me gating core-level nahi thi, module apne
    caps/budgets se hi bounded hai)."""
    try:
        return http.request(method, url, read_only_post=True, **kw)
    except TypeError:
        return http.request(method, url, **kw)

# ---------------------------------------------------------------------------
# CONFIG (config.json me tech_* keys; sab optional - defaults yahin hain)
# ---------------------------------------------------------------------------
CFG_DEFAULTS = {
    "tech_probe_paths": True,     # default-path probing (CMS/framework markers)
    "tech_probe_max": 60,         # max optional path-probes per host (budget)
    "tech_js_fetch": True,        # js assets fetch karke mine karna
    "tech_js_fetch_limit": 6,     # max js assets per host
    "tech_favicon": True,         # favicon.ico mmh3 hash
    "tech_behavior": True,        # OPTIONS/HEAD/TRACE/Range/ETag probes
    "tech_allow_trace": True,     # TRACE method probe (safe, single request)
    "tech_waf_trigger": True,     # wafw00f-style 1-request trigger probe
    "tech_gql_probe": True,       # graphql endpoint + introspection probe
    "tech_gql_post_max": 2,       # max graphql POST probes per host (read-only)
    "tech_sso_probe": True,       # OIDC/SAML discovery probes
    "tech_meta_probe": True,      # robots/humans/security.txt/AASA probes
    "tech_version_extract": True, # version extraction + staleness rules
    "tech_observation_cap": 40,   # max observations (report size bound)
}


def tget(cfg, key):
    return getattr(cfg, key, CFG_DEFAULTS.get(key))


# ---------------------------------------------------------------------------
# SIGNATURE DATABASE (v3 ULTRA - ~130 technologies)
# (pattern, indicator, weight)  indicators: h b c e d j x r
# ---------------------------------------------------------------------------
SIG = {
    # ---- CMS / platforms ----
    "WordPress":   [(r"wp-content|wp-includes|/wp-json", "b", 4), (r"\bwordpress\b", "h", 2), (r"wp-settings|wordpress_", "c", 3), (r"/wp-login\.php", "d", 3), (r"xmlrpc\.php", "d", 1)],
    "Drupal":      [(r"sites/default|drupalSettings|Drupal\.settings", "b", 4), (r"X-Generator:\s*Drupal|X-Drupal", "h", 3), (r"S?SESS[0-9a-f]{8,}", "c", 2), (r"/user/login", "d", 2), (r"/core/misc/drupal", "d", 3)],
    "Joomla":      [(r"/components/com_|joomla", "b", 4), (r"Joomla!", "h", 2), (r"/administrator/", "d", 2), (r"/media/jui|/templates/beez", "b", 3)],
    "Magento":     [(r"Mage\.Cookies|mage/|/static/version", "b", 4), (r"frontend=", "c", 2), (r"X-Magento", "h", 3), (r"/magento_version", "d", 3)],
    "Shopify":     [(r"cdn\.shopify\.com", "b", 4), (r"X-ShopId|X-Shopify", "h", 4), (r"_shopify_|secure_customer_sig", "c", 3)],
    "Ghost":       [(r"ghost-url|content=\"Ghost|ghost-sdk", "b", 4), (r"/ghost/", "d", 2)],
    "Webflow":     [(r"webflow\.(com|io)", "b", 3)],
    "Wix":         [(r"wix\.com|_wixCIDX|wix-static", "b", 3)],
    "Squarespace": [(r"squarespace\.com|static1\.squarespace", "b", 3)],
    "PrestaShop":  [(r"prestashop|/themes/classic", "b", 4), (r"PrestaShop-|ps_", "c", 3)],
    "OpenCart":    [(r"index\.php\?route=", "b", 4), (r"OCSESSID|PHPSESSID.*oc_", "c", 2)],
    "WooCommerce": [(r"woocommerce", "b", 4), (r"wp_woocommerce_session", "c", 4)],
    "Craft CMS":   [(r"cpresources|Craft CMS", "b", 4), (r"CraftSessionId", "c", 4)],
    "Strapi":      [(r"strapi|/strapi", "b", 4), (r"/admin/init", "d", 2)],
    "Sitecore":    [(r"sitecore", "b", 4), (r"\bsc_[A-Z]", "c", 3), (r"X-AspNet-Version.*sc_", "h", 2)],
    "AEM (Adobe)": [(r"/etc\.clientlibs|/libs/granite|cq-action", "b", 4), (r"/libs/granite/core/content/login", "d", 4)],
    "Liferay":     [(r"liferay|Liferay\.Util", "b", 4), (r"GUEST_LANGUAGE_ID|LFR_SESSION", "c", 3), (r"/c/portal/login", "d", 3)],
    "DNN":         [(r"__dnnVariable|dnn\.|DotNetNuke", "b", 4), (r"dnn_IsMobile", "c", 4)],
    "Umbraco":     [(r"umbraco", "b", 4), (r"/umbraco/", "d", 3)],
    "Sitefinity":  [(r"sitefinity", "b", 4), (r"/Sitefinity/", "d", 3)],
    "EPiServer":   [(r"episerver|/episerver", "b", 4)],
    "TYPO3":       [(r"typo3", "b", 4), (r"/typo3/", "d", 3), (r"fe_typo_user", "c", 4)],
    "Silverstripe": [(r"silverstripe", "b", 4)],
    "Concrete5":   [(r"concrete5|ccm-", "b", 4)],
    "Bitrix":      [(r"bitrix", "b", 4), (r"/bitrix/", "d", 3), (r"BITRIX_", "c", 4)],
    "MODX":        [(r"modx", "b", 4)],
    "SharePoint":  [(r"_spPageContextInfo|SharePoint", "b", 4), (r"MicrosoftSharePointTeamServices", "h", 4), (r"FedAuth", "c", 3)],
    "Discourse":   [(r"discourse", "b", 4), (r"_forum_session|_t=", "c", 2)],
    "phpBB":       [(r"phpbb", "b", 4), (r"phpbb3_", "c", 4), (r"/ucp\.php", "d", 3)],
    "vBulletin":   [(r"vbulletin", "b", 4), (r"bb_last", "c", 3)],
    "XenForo":     [(r"xenforo", "b", 4), (r"xf_", "c", 3)],
    "Salesforce":  [(r"salesforce\.com|force\.com|lightning\.force", "b", 3)],
    "ServiceNow":  [(r"service-now\.com|servicenow", "b", 3), (r"glide_session", "c", 3)],
    # ---- SSG / static generators ----
    "Hugo":        [(r"[Gg]enerated by [Hh]ugo", "b", 4), (r"X-Hugo-Deployment", "h", 4)],
    "Jekyll":      [(r"[Gg]enerated by [Jj]ekyll", "b", 4)],
    "Gatsby":      [(r"___gatsby|gatsby-image|page-data\.json", "b", 4)],
    "Astro":       [(r"astro-island|/_astro/", "b", 4)],
    # ---- languages / frameworks ----
    "PHP":         [(r"PHPSESSID", "c", 4), (r"X-Powered-By:\s*PHP", "h", 4), (r"\.php\b", "b", 1), (r"Fatal error|Parse error", "e", 3)],
    "Laravel":     [(r"laravel_session|XSRF-TOKEN", "c", 4), (r"laravel", "b", 2), (r"Whoops|Ignition", "e", 4), (r"/telescope|/horizon", "d", 2), (r"/_ignition", "d", 3)],
    "Symfony":     [(r"symfony", "b", 2), (r"X-Debug-Token", "h", 3), (r"MOODLE|PHPSESSID.*symfony", "c", 0), (r"sf_redirect", "c", 4)],
    "CakePHP":     [(r"CAKEPHP", "c", 3)],
    "CodeIgniter": [(r"ci_session", "c", 3)],
    "Yii":         [(r"YII_CSRF_TOKEN|yii", "c", 3)],
    "Zend":        [(r"X-Powered-By:\s*Zend|zend", "h", 3)],
    "Django":      [(r"csrftoken|csrfmiddlewaretoken", "c", 3), (r"django|Django", "b", 2), (r"DisallowedHost|DEBUG = True", "e", 4), (r"/__debug__/", "d", 3), (r"/admin/login", "d", 1)],
    "Flask":       [(r"Werkzeug|Flask", "e", 4), (r"session=eyJ", "c", 2)],
    "FastAPI":     [(r"FastAPI", "e", 4), (r"fastapi", "j", 3), (r"/docs", "d", 1)],
    "Rails":       [(r"_rails_session|_session_id", "c", 3), (r"csrf-token", "b", 1), (r"ActionController|Rails\.root", "e", 4), (r"/rails/info", "d", 3)],
    "ASP.NET":     [(r"ASP\.NET_SessionId", "c", 3), (r"X-Powered-By:\s*ASP\.NET", "h", 4), (r"X-AspNet-Version", "h", 4), (r"__VIEWSTATE", "b", 4), (r"Server Error in", "e", 3)],
    "ASP.NET Core": [(r"Server:\s*Kestrel", "h", 4), (r".AspNetCore\.", "c", 4), (r"arr\.AspNetCore", "c", 0)],
    "Java/Spring": [(r"JSESSIONID", "c", 3), (r"Whitelabel Error Page|org\.springframework", "e", 4), (r"X-Application-Context", "h", 3), (r"/actuator", "d", 3)],
    "Tomcat":      [(r"Apache-Coyote", "h", 3), (r"\btomcat\b", "h", 2), (r"Apache Tomcat", "e", 3)],
    "Jetty":       [(r"Server:\s*Jetty", "h", 4), (r"Jetty", "e", 3)],
    "WildFly/JBoss": [(r"WildFly|JBoss", "e", 4), (r"X-Powered-By:\s*(JBoss|WildFly)", "h", 4)],
    "WebSphere":   [(r"WebSphere", "e", 4)],
    "WebLogic":    [(r"WebLogic", "e", 4)],
    "Express":     [(r"X-Powered-By:\s*Express", "h", 4), (r"connect\.sid", "c", 3), (r"Cannot (GET|POST) /", "e", 4)],
    "Next.js":     [(r"__NEXT_DATA__|/_next/", "b", 4), (r"x-nextjs", "h", 2), (r"X-Powered-By:\s*Next\.js", "h", 4)],
    "Nuxt":        [(r"__NUXT__|/_nuxt/", "b", 4), (r"X-Powered-By:\s*Nuxt", "h", 3)],
    "SvelteKit":   [(r"/_app/immutable|sveltekit", "b", 4)],
    "Remix":       [(r"__remixContext|remix-run", "b", 4)],
    "Go":          [(r"X-Powered-By:\s*Go|X-Goog", "h", 3), (r"gorilla|gin-gonic", "b", 2)],
    "Python":      [(r"X-Powered-By:\s*Python|WSGIServer|gunicorn|uvicorn", "h", 3)],
    "Tornado":     [(r"Server:\s*Tornado", "h", 4)],
    "uWSGI":       [(r"Server:\s*uWSGI", "h", 4), (r"uwsgi", "h", 2)],
    "Rust":        [(r"axum|actix-web", "h", 3)],
    "Ruby":        [(r"X-Powered-By:\s*Phusion Passenger", "h", 3)],
    "Passenger":   [(r"X-Powered-By:\s*Phusion Passenger", "h", 4)],
    "Puma":        [(r"Server:\s*Puma", "h", 4)],
    "Elixir/Phoenix": [(r"phoenix|X-Request-Id.*phx", "b", 3)],
    "Deno":        [(r"Server:\s*Deno", "h", 4)],
    # ---- servers / proxies ----
    "Nginx":       [(r"Server:\s*nginx", "h", 4), (r"<center>nginx</center>", "e", 4)],
    "Apache":      [(r"Server:\s*Apache", "h", 4), (r"Apache Server at|Apache/\d", "e", 3)],
    "IIS":         [(r"Server:\s*Microsoft-IIS", "h", 4), (r"X-Powered-By:\s*ASP\.NET", "h", 1), (r"HTTP Error \d+\.\d", "e", 2)],
    "Caddy":       [(r"Server:\s*Caddy", "h", 4)],
    "LiteSpeed":   [(r"Server:\s*LiteSpeed", "h", 4)],
    "OpenResty":   [(r"Server:\s*openresty", "h", 4)],
    "Tengine":     [(r"Server:\s*Tengine", "h", 4)],
    "Envoy":       [(r"Server:\s*envoy|x-envoy", "h", 4)],
    "HAProxy":     [(r"Server:\s*HAProxy|x-haproxy", "h", 4)],
    "Varnish":     [(r"X-Varnish|Via:.*varnish", "h", 4)],
    "Traefik":     [(r"Server:\s*Traefik", "h", 4)],
    "Gunicorn":    [(r"Server:\s*gunicorn", "h", 4)],
    "Werkzeug":    [(r"Server:\s*Werkzeug", "h", 4)],
    "Kestrel":     [(r"Server:\s*Kestrel", "h", 4)],
    "lighttpd":    [(r"Server:\s*lighttpd", "h", 4)],
    "Cherokee":    [(r"Server:\s*Cherokee", "h", 4)],
    # ---- CDN / edge ----
    "Cloudflare":  [(r"cf-ray", "h", 4), (r"cf-cache-status", "h", 4), (r"Server:\s*cloudflare", "h", 4), (r"__cf_bm|__cfduid|cf_clearance|__cfruid", "c", 3)],
    "Akamai":      [(r"X-Akamai-Transformed|AkamaiGHost", "h", 4), (r"ak_bmsc|bm_sv|bm_mi|akavpau", "c", 3)],
    "CloudFront":  [(r"X-Amz-Cf-Id|X-Amz-Cf-Pop|Via:.*cloudfront", "h", 4)],
    "Fastly":      [(r"X-Fastly-Request-ID|X-Served-By:.*cache-", "h", 4), (r"Via:.*(varnish|fastly)", "h", 2)],
    "Azure CDN/FD": [(r"X-Azure-Ref|X-MSEdge|X-AzCm", "h", 4)],
    "Google LB":   [(r"Server:\s*Google Frontend|X-Cloud-Trace-Context", "h", 4)],
    "Bunny CDN":   [(r"Server:\s*bunny|X-BunnyCDN|cdn-pullzone", "h", 4)],
    "KeyCDN":      [(r"X-KeyCDN|Server:\s*keycdn-engine", "h", 4)],
    "StackPath":   [(r"stackpath|maxcdn|netdna|Server:\s*NetDNA", "h", 4)],
    "GCore":       [(r"gcore", "h", 3)],
    "CDN77":       [(r"cdn77", "h", 3)],
    # ---- WAF / security ----
    "Sucuri":      [(r"X-Sucuri-ID|Server:\s*Sucuri|Cloudproxy", "h", 4), (r"Access Denied - Sucuri Website Firewall", "e", 4)],
    "Imperva":     [(r"X-Iinfo|X-CDN:\s*Incapsula", "h", 4), (r"visid_incap|incap_ses", "c", 4), (r"Incapsula incident ID|_Incapsula_Resource", "e", 4)],
    "AWS WAF":     [(r"x-amzn-waf-action", "h", 4), (r"awswaf", "c", 4), (r"Blocked by AWS WAF", "e", 4)],
    "ModSecurity": [(r"Mod_Security|ModSecurity|Not Acceptable!|generated by Mod_Security", "e", 4)],
    "F5 BIG-IP":   [(r"TS[0-9a-f]{8,}=|BIGipServer", "c", 4), (r"The requested URL was rejected|BIG-IP|BIGipServer", "e", 3)],
    "Barracuda":   [(r"barracuda_", "c", 4), (r"Barracuda Web", "e", 3)],
    "Citrix NetScaler": [(r"NSC_[A-Za-z0-9]", "c", 4), (r"Via:.*ns-cache|NetScaler", "h", 3)],
    "Wallarm":     [(r"wallarm", "h", 4)],
    "Reblaze":     [(r"rbzid", "c", 4), (r"reblaze", "h", 3)],
    "Aliyun WAF":  [(r"errors\.aliyun\.com|aliyun-waf", "e", 4)],
    "Radware":     [(r"radware", "h", 3)],
    # ---- load balancers ----
    "AWS ALB/ELB": [(r"Server:\s*awselb|AWSALB", "h", 4), (r"AWSALB(TG)?=", "c", 4)],
    "F5 LTM":      [(r"BIGipServer", "c", 4)],
    "DO LB":       [(r"Server:\s*do-lb|x-do-origin", "h", 4)],
    # ---- hosting / cloud storage ----
    "AWS S3":      [(r"Server:\s*AmazonS3|X-Amz-", "h", 4), (r"s3\.amazonaws\.com", "b", 3), (r"<Code>NoSuchBucket</Code>|<Code>AccessDenied</Code>", "e", 3)],
    "GCS":         [(r"storage\.googleapis\.com", "b", 3), (r"X-GUploader|X-Google-Bucket", "h", 4), (r"<Error><Code>NoSuchBucket", "e", 3)],
    "GitHub Pages":[(r"Server:\s*GitHub\.com|X-GitHub-Request-Id", "h", 4)],
    "Vercel":      [(r"Server:\s*Vercel|X-Vercel", "h", 4)],
    "Netlify":     [(r"Server:\s*Netlify|X-NF-Request-ID", "h", 4)],
    "Heroku":      [(r"herokuapp\.com|Via:.*heroku", "h", 3)],
    "Render":      [(r"X-Render-Origin-Server|render\.com", "h", 4)],
    "Fly.io":      [(r"fly-request-id", "h", 4)],
    "Firebase":    [(r"firebaseio\.com|firebaseapp\.com", "b", 3), (r"firebase", "j", 2)],
    "Supabase":    [(r"supabase\.co|supabase", "b", 2)],
    "DO App Platform": [(r"X-DO-App-Origin|x-do-app", "h", 4)],
    "Azure Static Apps": [(r"X-MS-Staticapp|Server:\s*Microsoft-Azure-AppService", "h", 4)],
    # ---- client frameworks / libs ----
    "React":       [(r"react(-dom)?[.\-]|__REACT_DEVTOOLS|data-reactroot|_reactListening", "b", 3), (r"react(-dom)?[.\-]", "j", 3)],
    "Angular":     [(r"ng-version|angular[.\-]min|ng-app|zone\.js", "b", 3)],
    "Vue.js":      [(r"vue[.\-]min|vue\.js|data-v-[0-9a-f]{6,}|__VUE__", "b", 3)],
    "Svelte":      [(r"svelte-[0-9a-z]{6}|svelte\.js", "b", 3)],
    "Ember":       [(r"ember-cli|ember\.js|/assets/vendor.*ember", "b", 4)],
    "Alpine.js":   [(r"alpine\.min\.js|x-cloak|alpine:init", "b", 3)],
    "HTMX":        [(r"htmx\.org|htmx\.min\.js|hx-get", "b", 3)],
    "Livewire":    [(r"wire:id|livewire", "b", 4)],
    "Inertia":     [(r"@inertiajs|data-inertia|inertiajs", "b", 4)],
    "Hotwire/Turbo": [(r"turbo-frames|@hotwired|turbo_stream", "b", 3)],
    "Stimulus":    [(r"stimulus|data-controller", "b", 2)],
    "jQuery":      [(r"jquery[.\-](min\.)?js|jquery/[0-9]|jquery\.core", "b", 3), (r"jquery[.\-]", "j", 3)],
    "Bootstrap":   [(r"bootstrap[.\-](min\.)?(css|js)", "b", 2)],
    "Tailwind":    [(r"tailwind", "b", 2)],
    "Material-UI": [(r"mui-[0-9a-z]|material-ui", "b", 3)],
    "Ant Design":  [(r"ant-design|antd[.\-]|anticon", "b", 3)],
    "Ionic":       [(r"ion-app|ionic[.\-]", "b", 3)],
    "three.js":    [(r"three[.\-]min\.js|THREE\.", "b", 2)],
    "Lodash":      [(r"lodash[.\-]", "b", 2)],
    "axios":       [(r"axios[.\-]|axios\.min", "b", 2), (r"axios", "j", 2)],
    "socket.io":   [(r"socket\.io", "b", 3), (r"io\.socket", "c", 3)],
    # ---- API / protocols ----
    "GraphQL":     [(r"graphql|__schema|GraphiQL|apollo", "b", 3), (r"/graphql", "d", 2), (r"application/graphql", "h", 3)],
    "Hasura":      [(r"hasura", "h", 4), (r"/v1/graphql", "d", 3)],
    "Apollo Server": [(r"Apollo Server|apollo-server", "e", 4), (r"apollo", "b", 1)],
    "gRPC-Web":    [(r"application/grpc-web|x-grpc", "h", 4)],
    "OData":       [(r"odata|\$metadata|@odata\.context", "b", 3)],
    "Swagger UI":  [(r"swagger-ui|Swagger UI", "b", 3), (r"/swagger-ui", "d", 3)],
    "Redoc":       [(r"redoc", "b", 3)],
    # ---- auth / IdP ----
    "Keycloak":    [(r"keycloak", "b", 4), (r"KEYCLOAK_STATE|AUTH_SESSION_ID", "c", 4), (r"/realms/", "d", 3)],
    "Auth0":       [(r"auth0|cdn\.auth0\.com", "b", 4), (r"auth0", "c", 3)],
    "Okta":        [(r"okta|oktacdn", "b", 4), (r"okta", "c", 3)],
    "Cognito":     [(r"cognito", "b", 4)],
    "PingIdentity": [(r"pingfederate|pingidentity", "b", 4)],
    "ForgeRock":   [(r"forgerock|openam", "b", 4)],
    "WSO2":        [(r"wso2", "b", 4)],
    "Shibboleth":  [(r"/Shibboleth\.sso", "d", 4), (r"shibsession", "c", 4)],
    "SimpleSAMLphp": [(r"simplesaml", "d", 4), (r"SimpleSAML", "b", 4)],
    "ADFS":        [(r"/adfs/ls", "d", 4), (r"MSISAuth", "c", 4)],
    # ---- admin / dev tools (exposure = observation) ----
    "phpMyAdmin":  [(r"phpmyadmin|phpMyAdmin", "d", 4), (r"pma_", "c", 3)],
    "Adminer":     [(r"Adminer", "d", 4)],
    "Grafana":     [(r"grafana", "d", 3), (r"grafana_session", "c", 4)],
    "Prometheus":  [(r"# (HELP|TYPE)", "e", 4)],
    "Kibana":      [(r"kibana", "d", 3)],
    "WebDAV":      [(r"^DAV:\s*[12]", "h", 4)],
}

# error-page / default-404 fingerprints (server or framework identity)
ERROR_SIGNATURES = {
    "Spring": r"(?i)Whitelabel Error Page|org\.springframework",
    "Laravel": r"(?i)Whoops|Ignition|laravel",
    "Django": r"(?i)DisallowedHost|You're seeing this error|Using the URLconf",
    "Rails": r"(?i)ActionController|Rails\.root|web-console",
    "ASP.NET": r"(?i)Server Error in|Runtime Error|ASP\.NET is configured",
    "PHP": r"(?i)Fatal error\]:|Warning\]:|Parse error",
    "Node/Express": r"(?i)Cannot GET /|Cannot POST /|at Object\.<anonymous>|node_modules",
    "Tomcat": r"(?i)Apache Tomcat/|HTTP Status 404",
    "Nginx": r"(?i)<center>nginx</center>|nginx/\d",
    "Apache": r"(?i)Apache/\d[\d.]* \((?:Unix|Ubuntu|Debian|Win64|CentOS)\) Server at",
    "IIS": r"(?i)IIS \d\.\d detailed errors|HTTP Error \d+\.\d+",
    "Flask/Werkzeug": r"(?i)Werkzeug Debugger|Traceback \(most recent call last\)",
    "Next.js": r"(?i)__NEXT_DATA__|Application error: a client-side exception",
    "S3": r"(?i)<Code>NoSuchBucket</Code>|<Code>AccessDenied</Code>",
    "Kestrel": r"(?i)Kestrel|HTTP Error 500\.30",
    "WildFly/JBoss": r"(?i)WildFly|JBoss",
    "FastAPI": r"(?i)\bFastAPI\b.*\bdocs\b|{\"detail\":\"Not Found\"}",
    "Vite": r"(?i)vite.*pre-bundling|@vite/client",
}

# ---------------------------------------------------------------------------
# VERSION EXTRACTION + EOL / STALENESS RULES
# ---------------------------------------------------------------------------
VERSION_PATTERNS = {
    "PHP":       [(r"PHP[/ ]v?(\d+\.\d+(?:\.\d+)?)", ("h", "e"))],
    "Nginx":     [(r"nginx/(\d+(?:\.\d+){0,2})", ("h", "e"))],
    "Tengine":   [(r"tengine/(\d+(?:\.\d+){0,2})", ("h", "e"))],
    "Apache":    [(r"Apache/(\d+\.\d+(?:\.\d+)?)", ("h", "e"))],
    "IIS":       [(r"Microsoft-IIS/(\d+\.\d+)", ("h", "e"))],
    "ASP.NET":   [(r"X-AspNet-Version:\s*(\d+\.\d+(?:\.\d+)?)", ("h",)),
                  (r"ASP\.NET Version:(\d+\.\d+(?:\.\d+)?)", ("e",))],
    "LiteSpeed": [(r"LiteSpeed/(\d+(?:\.\d+)*)", ("h", "e"))],
    "OpenResty": [(r"openresty/(\d+(?:\.\d+)*)", ("h", "e"))],
    "Tomcat":    [(r"Apache Tomcat/(\d+(?:\.\d+)*)", ("h", "e"))],
    "WordPress": [(r"WordPress\s+(\d+(?:\.\d+)*)", ("b", "x"))],
    "jQuery":    [(r"jquery[-.]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", ("b", "j")),
                  (r"jquery(?:[-.](?:min|core))?\.js\?ver=([\d.]+)", ("b", "j")),
                  (r"jquery[.\-/]v?(\d+\.\d+(?:\.\d+)?)", ("b", "j"))],
    "Bootstrap": [(r"bootstrap[-.]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:css|js)", ("b", "j"))],
    "Magento":   [(r"Magento/(\d+(?:\.\d+)*)", ("d", "e"))],
    "Shopify":   [(r"shopify", ("b",))],
}

# (tech, op, version_tuple, note) - version_tuple se chhota/badar barabar
STALE_RULES = [
    ("jQuery",  "<",  (3, 5, 0), "jQuery <3.5.0: XSS CVE-2020-11022/11023 (untrusted HTML sinks)"),
    ("jQuery",  "<",  (3, 0, 0), "jQuery 1.x/2.x: multiple known XSS + browser support EOL"),
    ("PHP",     "<",  (8, 1, 0), "PHP <8.1: security support EOL (Dec 2025)"),
    ("PHP",     "<",  (8, 0, 0), "PHP 7.x: EOL - actively unsupported"),
    ("Apache",  "==", (2, 4, 49), "Apache 2.4.49: CVE-2021-41773 path traversal/RCE - CRITICAL"),
    ("Apache",  "==", (2, 4, 50), "Apache 2.4.50: CVE-2021-42013 path traversal/RCE - CRITICAL"),
    ("Nginx",   "<",  (1, 20, 0), "nginx <1.20: purana stable branch - advisory review"),
    ("WordPress", "<", (6, 0, 0), "WordPress 5.x: core support range se bahar - update check"),
    ("Django",  "<",  (3, 2, 0), "Django <3.2: EOL"),
    ("Drupal",  "<",  (9, 0, 0), "Drupal 8: EOL (Nov 2021)"),
    ("IIS",     "<",  (10, 0, 0), "IIS <10: legacy OS platform"),
    ("ASP.NET", "<",  (4, 7, 0), "ASP.NET 4.6.x: older runtime - TLS 1.2 defaults check"),
    ("Tomcat",  "<",  (9, 0, 0), "Tomcat 7.x/8.x: EOL branches (Ghostcat/AJP check)"),
]

# ---------------------------------------------------------------------------
# WAF BLOCK-PAGE + TRIGGER SIGNATURES
# ---------------------------------------------------------------------------
# name -> list of (regex, where) ; where: body|header|cookie
WAF_SIGS = {
    "Cloudflare":  [(r"Attention Required|cf-mitigated|Error 10[0-9]{2}|Access denied.*Cloudflare", "body_or_header"), (r"__cf_bm|cf_clearance|__cfruid", "cookie")],
    "AWS WAF":     [(r"x-amzn-waf-action|awswaf", "header_or_cookie"), (r"Blocked by AWS WAF|Request blocked", "body")],
    "ModSecurity": [(r"Mod_Security|ModSecurity|Not Acceptable!|generated by Mod_Security", "body")],
    "Imperva":     [(r"Incapsula incident ID|_Incapsula_Resource|Request unsuccessful", "body"), (r"visid_incap|incap_ses", "cookie")],
    "Akamai":      [(r"Access Denied.{0,300}Reference #|AkamaiGHost|Support ID.{0,80}Akamai", "body"), (r"ak_bmsc|bm_sv|bm_mi", "cookie")],
    "F5 BIG-IP":   [(r"The requested URL was rejected|BIG-IP|Support ID", "body"), (r"TS[0-9a-f]{8,}|BIGipServerasm", "cookie")],
    "Sucuri":      [(r"Access Denied - Sucuri Website Firewall|Cloudproxy", "body_or_header"), (r"X-Sucuri-ID", "header_or_cookie")],
    "Barracuda":   [(r"barracuda_", "cookie"), (r"Barracuda.{0,200}(blocked|denied|web filter)", "body")],
    "Citrix NetScaler": [(r"NSC_[A-Za-z0-9]", "cookie"), (r"NetScaler|ns-cache", "header_or_cookie")],
    "Wallarm":     [(r"wallarm", "body_or_header")],
    "Reblaze":     [(r"rbzid", "cookie"), (r"reblaze", "body_or_header")],
    "Aliyun WAF":  [(r"errors\.aliyun\.com|aliyun-waf|403 Forbidden.*aliyun", "body")],
    "Radware":     [(r"radware", "body_or_header")],
    "Squarespace WAF": [(r"squarespace\.(waf|block)", "body")],
}

CDN_SIGS = {
    "Cloudflare":  r"cf-ray|cf-cache-status|server:\s*cloudflare|__cf_bm",
    "Akamai":      r"x-akamai-transformed|akamaighost|ak_bmsc",
    "CloudFront":  r"x-amz-cf-id|x-amz-cf-pop|via:.*cloudfront",
    "Fastly":      r"x-served-by:.*cache-|x-fastly-request-id|x-sigsci",
    "Azure CDN/FD": r"x-azure-ref|x-azcm|x-msedge",
    "Google LB":   r"server:\s*google frontend|x-cloud-trace-context",
    "Bunny CDN":   r"server:\s*bunny|x-bunnycdn",
    "KeyCDN":      r"x-keycdn|server:\s*keycdn-engine",
    "StackPath":   r"stackpath|maxcdn|netdna",
    "GCore":       r"gcore",
    "CDN77":       r"cdn77",
}

LB_SIGS = {
    "AWS ALB/ELB": r"server:\s*awselb|awsalb",
    "F5 LTM":      r"bigipserver",
    "Google LB":   r"server:\s*google frontend",
    "HAProxy":     r"server:\s*haproxy|x-haproxy",
    "Envoy":       r"server:\s*envoy|x-envoy",
    "Traefik":     r"server:\s*traefik",
    "nginx proxy": r"server:\s*nginx",
}

# ---------------------------------------------------------------------------
# DEFAULT-PATH PROBE TABLE (ordered: high-value first)
# (path, tech, validator_regex_on_body_or_None)
# validator => body match zaroori; warna catch-all/soft pages false-positive
# ---------------------------------------------------------------------------
DEFAULT_PATHS = [
    ("/wp-login.php", "WordPress", r"wp-|WordPress|log in"),
    ("/wp-json/", "WordPress", r'"namespaces"|"description"'),
    ("/xmlrpc.php", "WordPress", r"XML-RPC server accepts only POST", "405ok"),
    ("/wp-content/uploads/", "WordPress", r"Index of|wp-content"),
    ("/administrator/", "Joomla", r"Joomla|login"),
    ("/user/login", "Drupal", r"Drupal|user login|reset your password"),
    ("/core/misc/drupal.js", "Drupal", r"Drupal|window\."),
    ("/magento_version", "Magento", r"Magento|[\d.]"),
    ("/actuator", "Java/Spring", r'_links|"self"|actuator'),
    ("/actuator/health", "Java/Spring", r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"'),
    ("/metrics", "Prometheus", r"# (HELP|TYPE)"),
    ("/graphql", "GraphQL", None),
    ("/api/graphql", "GraphQL", None),
    ("/graphiql", "GraphQL", r"GraphiQL|graphql"),
    ("/swagger.json", "Swagger UI", r'"(openapi|swagger)"'),
    ("/openapi.json", "Swagger UI", r'"(openapi|swagger)"'),
    ("/docs", "FastAPI", r"fastapi|Swagger UI|swagger-ui"),
    ("/telescope", "Laravel", r"Laravel Telescope"),
    ("/horizon", "Laravel", r"Laravel Horizon"),
    ("/_ignition/health-check", "Laravel", r'"can_query"|healthy'),
    ("/__debug__/", "Django", r"debug_toolbar|djdt"),
    ("/admin/login", "Django", r"django|Log in|site admin"),
    ("/elmah.axd", "ASP.NET", r"ELMAH|Error Log"),
    ("/trace.axd", "ASP.NET", r"Trace.axd|Application Trace"),
    ("/phpinfo.php", "PHP", r"phpinfo\(\)|PHP Version"),
    ("/info.php", "PHP", r"phpinfo\(\)|PHP Version"),
    ("/adminer.php", "Adminer", r"Adminer"),
    ("/phpmyadmin/", "phpMyAdmin", r"phpMyAdmin"),
    ("/server-status", "Apache", r"Apache Server Status|Server uptime"),
    ("/server-info", "Apache", r"Apache Server Information"),
    ("/nginx_status", "Nginx", r"Active connections"),
    ("/stub_status", "Nginx", r"Active connections"),
    ("/_next/static/", "Next.js", r"next|\.js"),
    ("/_nuxt/", "Nuxt", r"nuxt|\.js"),
    ("/rails/info/properties", "Rails", r"Rails|properties"),
    ("/.well-known/security.txt", "security.txt", r"Contact:|Policy:|Preferred-Languages:"),
    ("/security.txt", "security.txt", r"Contact:|Policy:|Preferred-Languages:"),
    ("/api/v3/api-docs", "Java/Spring", r'"(openapi|swagger)"'),
    ("/v3/api-docs", "Java/Spring", r'"(openapi|swagger)"'),
    ("/v2/swagger.json", "Swagger UI", r'"(openapi|swagger)"'),
    ("/swagger-ui.html", "Swagger UI", r"swagger-ui|Swagger UI"),
    ("/swagger-ui/", "Swagger UI", r"swagger-ui"),
    ("/api-docs", "Swagger UI", r'"(openapi|swagger)"|swagger'),
    ("/redoc", "Redoc", r"redoc"),
    ("/admin", "admin-panel", None),
    ("/typo3/", "TYPO3", r"TYPO3"),
    ("/bitrix/", "Bitrix", r"Bitrix"),
    ("/umbraco/", "Umbraco", r"umbraco"),
    ("/Sitefinity/", "Sitefinity", r"Sitefinity"),
    ("/libs/granite/core/content/login.html", "AEM (Adobe)", r"granite|Adobe|AEM"),
    ("/c/portal/login", "Liferay", r"Liferay"),
    ("/simplesaml/module.php/core/loginpage.php", "SimpleSAMLphp", r"SimpleSAML"),
    ("/Shibboleth.sso/Login", "Shibboleth", r"Shibboleth"),
    ("/adfs/ls/", "ADFS", r"ADFS|Sign in"),
    ("/realms/master/.well-known/openid-configuration", "Keycloak", r'"issuer"'),
    ("/status", "PHP", r"php-fpm|active connections"),
]

# (path, tech, validator, "405ok") special rows: 405/403 bhi hit agar body
# validator pass kare (xmlrpc.php jaise endpoints 405 dete hain par zinda hain)

# ---------------------------------------------------------------------------
# META / SSO / GQL / DOC path groups (ULTRA)
# ---------------------------------------------------------------------------
META_PATHS = [
    ("/robots.txt", "robots", r"User-agent:|Disallow:|Sitemap:"),
    ("/humans.txt", "humans", None),
    ("/sitemap.xml", "sitemap", r"<urlset|<sitemapindex"),
    ("/.well-known/security.txt", "securitytxt", r"Contact:|Policy:"),
    ("/.well-known/apple-app-site-association", "aasa", r'"applinks"|appIDs'),
    ("/apple-app-site-association", "aasa", r'"applinks"|appIDs'),
    ("/.well-known/assetlinks.json", "assetlinks", r'"package_name"|get-app-links'),
    ("/cdn-cgi/trace", "cdn_cgi_trace", r"fl=|visit_scheme=|loc="),
]

GQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/graphql/v1",
    "/hasura/v1/graphql", "/appsync", "/gql", "/query", "/api/gql",
    "/graphiql", "/playground", "/altair", "/voyager", "/graphql/console",
]

DOC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/v2/swagger.json",
    "/v3/api-docs", "/api/v3/api-docs", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/api/openapi.json", "/rest/swagger.json",
    "/api/docs", "/documentation", "/docs", "/redoc", "/api/redoc",
    "/api/schema/", "/swagger-ui.html",
]

SSO_PATHS = [
    ("/.well-known/openid-configuration", "oidc"),
    ("/oauth/.well-known/openid-configuration", "oidc"),
    ("/.well-known/jwks.json", "jwks"),
    ("/oauth/jwks", "jwks"),
    ("/saml/metadata", "saml"),
    ("/saml/metadata.xml", "saml"),
    ("/Shibboleth.sso/Metadata", "saml"),
]

# ---------------------------------------------------------------------------
# ARCHITECTURE RULES (rendering model / backend pattern)
# ---------------------------------------------------------------------------
RENDER_RULES = [
    ("Next.js", "SSR/SSG hybrid (React/Next.js)"),
    ("Nuxt", "SSR/SSG hybrid (Vue/Nuxt)"),
    ("SvelteKit", "SSR/SSG hybrid (SvelteKit)"),
    ("Remix", "SSR (React/Remix)"),
    ("Gatsby", "SSG (React/Gatsby)"),
    ("Hugo", "SSG (Hugo)"),
    ("Jekyll", "SSG (Jekyll)"),
    ("Astro", "SSG/islands (Astro)"),
    ("Django", "server-rendered MVC (Django)"),
    ("Laravel", "server-rendered MVC (Laravel)"),
    ("Rails", "server-rendered MVC (Rails)"),
    ("ASP.NET", "server-rendered (ASP.NET)"),
    ("PHP", "server-rendered (PHP)"),
    ("Java/Spring", "server-rendered/hybrid (Java)"),
]

SSO_BACKENDS = {
    "Keycloak", "Auth0", "Okta", "Cognito", "PingIdentity", "ForgeRock",
    "WSO2", "Shibboleth", "SimpleSAMLphp", "ADFS",
}


# ---------------------------------------------------------------------------
# VERSION UTILS
# ---------------------------------------------------------------------------
def ver_tuple(s):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", str(s))[:3])
    except Exception:
        return (0,)


def pad(a, n=3):
    a = tuple(a) + (0,) * (n - len(a)) if len(a) < n else tuple(a[:n])
    return a


def extract_versions(blobs):
    """VERSION_PATTERNS se versions nikalo (source-tagged)."""
    out = {}
    for tech, pats in VERSION_PATTERNS.items():
        for pat, inds in pats:
            for ind in inds:
                src = blobs.get(ind, "")
                if not src:
                    continue
                for m in re.finditer(pat, src, re.I):
                    val = m.group(1).strip(".").rstrip(".min")
                    val = val.replace(".min", "")
                    if not val or val in ("0",):
                        continue
                    rec = out.setdefault(tech, {"value": val, "sources": []})
                    if len(rec["sources"]) < 4 and "%s" % ind not in rec["sources"]:
                        rec["sources"].append("%s" % ind)
                    break
    return out


def version_notes(versions):
    """STALE_RULES lagao -> [{tech, value, note}] (per tech pehla/most-specific rule)."""
    out = []
    for tech, val in (versions or {}).items():
        vt = pad(ver_tuple(val.get("value", "0")))
        for rtech, op, rv, note in STALE_RULES:
            if rtech != tech:
                continue
            rvt = pad(rv)
            hit = (vt < rvt) if op == "<" else (vt == rvt)
            if hit:
                out.append({"tech": tech, "value": val.get("value"), "note": note})
                break  # per tech sirf sabse-specific (sabse naya threshold) rule
    return out


def absurd_version(tech, value):
    """Future/nonsense version => banner spoofing ka strong hint."""
    vt = ver_tuple(str(value))
    if not vt:
        return False
    major = vt[0]
    if tech == "IIS":
        return major > 10
    caps = {"Nginx": 2, "Tengine": 4, "Apache": 3, "PHP": 9, "LiteSpeed": 10,
            "OpenResty": 2, "Tomcat": 12, "Express": 6}
    cap = caps.get(tech)
    return cap is not None and major >= cap


# ---------------------------------------------------------------------------
# CORE FINGERPRINT ENGINE (v2 contract preserved)
# ---------------------------------------------------------------------------
def collect(root, root2, error_body, cookie_names, default_hits, js_blob):
    """Indicator blobs - har indicator strictly apne source se (v2 fix)."""
    headers_raw = "\n".join("%s: %s" % (k, v) for k, v in (root.headers or {}).items())
    return {
        "h": headers_raw,
        "b": (root.text or "")[:200000],
        "c": (root.hget("Set-Cookie") or "") + " " + " ".join(cookie_names or []),
        "e": (error_body or "")[:50000],
        "j": (js_blob or "")[:200000],
        "d": " ".join(default_hits or []),
        "x": (root.text or "")[:5000] if "xml" in (root.hget("Content-Type") or "").lower() else "",
        "r": json.dumps(root.chain or []),
    }


def score_tech(blobs):
    scores, evid = {}, {}
    for tech, sigs in SIG.items():
        for sig in sigs:
            pat, ind, w = sig[0], sig[1], sig[2]
            if w <= 0:
                continue
            src = blobs.get(ind, "")
            if not src:
                continue
            if re.search(pat, src, re.I if ind != "h" else re.I | re.M):
                scores[tech] = scores.get(tech, 0) + w
                evid.setdefault(tech, []).append("%s:%s(+%d)" % (ind, pat[:38], w))
    conf = {}
    for t, s in scores.items():
        conf[t] = "high" if s >= 8 else ("medium" if s >= 4 else "low")
    return scores, evid, conf


def api_style(headers_raw, body, endpoints):
    blob = headers_raw + "\n" + (body or "")[:6000] + "\n" + "\n".join((endpoints or [])[:80])
    hits = {}
    for style, pats in {
        "REST/JSON": [r"Content-Type:\s*application/json", r"/api/v\d", r"application/vnd\.api", r"\.json\b.*api"],
        "GraphQL":   [r"graphql", r"__schema", r"application/graphql", r"graphiql"],
        "SOAP/XML":  [r"Content-Type:\s*(application|text)/xml", r"soap", r"\?wsdl", r"<soap:Envelope"],
        "gRPC-Web":  [r"application/grpc-web", r"grpc-", r"x-grpc"],
        "OData":     [r"odata", r"\$metadata", r"@odata\.context"],
    }.items():
        n = sum(1 for p in pats if re.search(p, blob, re.I))
        if n:
            hits[style] = n
    return hits


def session_model(root, cookie_names):
    ck = root.hget("Set-Cookie") or ""
    low = ck.lower()
    model = {"cookie_names": cookie_names or [], "count": len(cookie_names or []),
             "flags": {}, "stateful_examples": [],
             "jwt_in_cookie": bool(re.search(r"eyJ[A-Za-z0-9_-]{8,}\.", ck)),
             "token_in_body": False}
    if ck:
        model["flags"] = {"httponly": "httponly" in low, "secure": "secure" in low,
                          "samesite": "samesite=" in low}
        m = re.search(r"samesite\s*=\s*(\w+)", low)
        if m:
            model["flags"]["samesite_value"] = m.group(1)
        model["stateful_examples"] = [c for c in (cookie_names or [])
                                      if re.search(r"(?i)sess|sid|jsessionid|phpsessid|csrftoken|xsrf|token|auth", c)]
    model["token_in_body"] = bool(re.search(r"""(?i)"(access_token|id_token|refresh_token)"\s*:""", root.text or ""))
    model["storage_inference"] = ("stateless/JWT-ish" if (model["jwt_in_cookie"] or model["token_in_body"])
                                  else "stateful-cookie" if model["stateful_examples"]
                                  else "unknown")
    return model


# ---------------------------------------------------------------------------
# PERIMETER DETECTORS (WAF / CDN / LB) - headers+cookies+body se
# ---------------------------------------------------------------------------
def _where_check(sig_where, where, rx, blob_body, blob_header, blob_cookie):
    src = {"body": blob_body, "header": blob_header, "cookie": blob_cookie,
           "header_or_cookie": blob_header + " " + blob_cookie,
           "body_or_header": blob_body + " " + blob_header}.get(sig_where, "")
    return bool(re.search(rx, src, re.I))


def detect_waf(resp):
    """Ek response se WAF block/challenge page detect karo."""
    if resp is None or resp.error:
        return []
    body = (resp.text or "")[:40000]
    header = "\n".join("%s: %s" % (k, v) for k, v in (resp.headers or {}).items())
    cookie = (resp.hget("Set-Cookie") or "") + " " + " ".join(resp.set_cookies or [])
    found = []
    for name, sigs in WAF_SIGS.items():
        for sig in sigs:
            rx, where = sig[0], sig[1]
            if _where_check(where, where, rx, body, header, cookie):
                found.append({"waf": name, "evidence": rx[:40], "where": where,
                              "status": resp.status})
                break
    return found


def detect_cdn_lb(resp):
    """CDN + LB hints ek response ke headers/cookies se."""
    if resp is None or resp.error:
        return [], []
    header = "\n".join("%s: %s" % (k, v) for k, v in (resp.headers or {}).items()).lower()
    cookie = ((resp.hget("Set-Cookie") or "") + " " + " ".join(resp.set_cookies or [])).lower()
    blob = header + " " + cookie
    cdns = [c for c, rx in CDN_SIGS.items() if re.search(rx, blob, re.I)]
    lbs = [l for l, rx in LB_SIGS.items() if re.search(rx, blob, re.I)]
    return sorted(set(cdns)), sorted(set(lbs))


# ---------------------------------------------------------------------------
# CONTRADICTION ENGINE v3 (banner spoof / misconfig detection)
# ---------------------------------------------------------------------------
def find_contradictions(scores, headers_raw, server_h, err_hits=None,
                        versions=None, waf_names=None):
    def has(t):
        return scores.get(t, 0) > 0

    out = []
    srv = (server_h or "").lower()
    if "nginx" in srv and has("IIS"):
        out.append("Server banner=Nginx but IIS markers present in body/errors")
    if ("iis" in srv or "microsoft-iis" in srv) and has("Nginx"):
        out.append("Server banner=IIS but Nginx markers present in body/errors")
    if ("iis" in srv or "microsoft-iis" in srv) and (has("PHP") or has("WordPress")):
        out.append("Server banner=IIS but PHP/WordPress markers present (possible reverse proxy ya spoof)")
    if has("WordPress") and has("Drupal"):
        out.append("Both WordPress and Drupal markers present (improbable)")
    if has("WordPress") and has("Joomla"):
        out.append("Both WordPress and Joomla markers present (improbable)")
    if has("Django") and has("PHP"):
        out.append("Django and PHP markers together (improbable on same app)")
    xpb = ""
    for line in (headers_raw or "").splitlines():
        if line.lower().startswith("x-powered-by:"):
            xpb = line.split(":", 1)[1].strip().lower()
    if "php" in xpb and "asp.net" in xpb:
        out.append("X-Powered-By declares PHP and ASP.NET simultaneously")
    if "php" in xpb and has("Java/Spring"):
        out.append("X-Powered-By=PHP but Java/Spring markers present")
    if has("PHP") and has("ASP.NET") and not has("IIS"):
        out.append("PHP and ASP.NET indicators without IIS (improbable on same host)")
    cf_claimed = "server: cloudflare" in (headers_raw or "").lower()
    if cf_claimed and "cf-ray" not in (headers_raw or "").lower():
        out.append("Server: cloudflare claimed but no cf-ray header (spoofed banner ya partial proxy)")
    # absurd versions
    for tech, rec in (versions or {}).items():
        if absurd_version(tech, rec.get("value", "")):
            out.append("Implausible %s version '%s' (banner spoofing/obfuscation hint)" % (tech, rec.get("value")))
    # behavioral mismatch: server claims X, error page says Y
    eh = {e.lower() for e in (err_hits or [])}
    if "nginx" in srv and "apache" in eh:
        out.append("Server banner=Nginx but error page is Apache-style")
    if "apache" in srv and "nginx" in eh:
        out.append("Server banner=Apache but error page is Nginx-style")
    if ("iis" in srv or "microsoft-iis" in srv) and ("nginx" in eh or "apache" in eh):
        which = "nginx" if "nginx" in eh else "Apache"
        out.append("Server banner=IIS but error page matches %s" % which)
    return out


# ---------------------------------------------------------------------------
# PROBE STAGES (scope-checked, budget-capped, soft404-aware)
# ---------------------------------------------------------------------------
def _cnames(resp):
    """Set-Cookie se cookie NAMES (v2 logic, helper me Shift)."""
    names = []
    for sc in (resp.set_cookies or []):
        n = sc.split("=")[0].strip()
        if n:
            names.append(n)
    if not names and resp.hget("Set-Cookie"):
        names = [c.strip().split("=")[0] for c in resp.hget("Set-Cookie").split(",") if "=" in c]
    return names


def _in_scope_url(scope, seed, path):
    url = up.urljoin(seed.rstrip("/") + "/", path.lstrip("/"))
    return (url,) if scope.check_url(url, raise_on_fail=False) else (None,)


def probe_paths(http, seed, base, scope, cap):
    """DEFAULT_PATHS probe - validators + soft404 filter (ULTRA, v2-bug fixed)."""
    hits = {}
    spent = 0
    for row in DEFAULT_PATHS:
        if interrupted() or spent >= cap:
            break
        path, tech, validator = row[0], row[1], row[2]
        allow405 = (len(row) > 3 and row[3] == "405ok")
        url = _in_scope_url(scope, seed, path)[0]
        if not url:
            continue
        spent += 1
        r = http.request("GET", url, allow_redirects=False)
        if r.error or r.status in (400,) or r.status >= 500:
            continue
        if r.status == 404 and not allow405:
            continue
        if is_soft404(r, base):
            continue
        if validator and not re.search(validator, r.text[:8000], re.I):
            continue
        if r.status in (200, 201, 301, 302, 401, 403, 405) or allow405:
            hits[path] = {"tech": tech, "status": r.status, "len": len(r.body),
                          "title": title_of(r.text)[:100]}
    if spent >= cap:
        warn("   path-probe budget (%d) exhausted - baaki paths skip" % cap)
    return hits


def probe_meta(http, seed, base, scope):
    """robots/humans/sitemap/security.txt/AASA/assetlinks/cdn-cgi trace."""
    out = {}
    for path, key, validator in META_PATHS:
        if interrupted():
            break
        url = _in_scope_url(scope, seed, path)[0]
        if not url:
            continue
        r = http.request("GET", url, allow_redirects=False)
        if r.error or r.status in (400, 404, 410) or r.status >= 500:
            continue
        if is_soft404(r, base):
            continue
        if validator and not re.search(validator, r.text[:8000], re.I):
            continue
        rec = {"status": r.status, "len": len(r.body)}
        txt = r.text or ""
        if key == "robots":
            disallow = [m.group(1).strip() for m in re.finditer(r"(?im)^Disallow:\s*(\S+)", txt)]
            sitemaps = [m.group(1).strip() for m in re.finditer(r"(?im)^Sitemap:\s*(\S+)", txt)]
            rec["disallow"] = disallow[:30]
            rec["sitemaps"] = sitemaps[:5]
            rec["admin_paths"] = [d for d in disallow if re.search(r"(?i)admin|manage|panel|secret|backup|staging|api|config", d)][:12]
        elif key == "sitemap":
            urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", txt)
            rec["url_count"] = len(urls)
            rec["sample"] = urls[:5]
        elif key == "securitytxt":
            rec["contacts"] = re.findall(r"(?im)^Contact:\s*(\S+)", txt)[:5]
            rec["policy"] = bool(re.search(r"(?im)^Policy:", txt))
        elif key == "aasa":
            try:
                j = json.loads(txt)
                rec["apps"] = [a.get("appIDs") or a.get("appID") for a in (j.get("applinks") or {}).get("details", [])][:6]
            except Exception:
                rec["apps"] = []
        elif key == "assetlinks":
            try:
                j = json.loads(txt)
                rec["packages"] = [s.get("target", {}).get("package_name")
                                   for s in j if isinstance(s, dict)][:6]
            except Exception:
                rec["packages"] = []
        elif key == "cdn_cgi_trace":
            # PII skip: ip=/uag= store nahi karte
            kv = dict(re.findall(r"(?m)^([a-z]+)=(.*)$", txt))
            rec["trace"] = {k: v for k, v in kv.items()
                            if k in ("loc", "visit_scheme", "http", "tls", "warp", "colo")}
            rec["cloudflare_confirmed"] = True
        out[key] = rec
    return out


def probe_behavior(http, seed, allow_trace=True):
    """OPTIONS/HEAD/TRACE/Range/Alt-Svc/ETag/Date - banner-less server ID."""
    out = {}
    o = http.request("OPTIONS", seed, allow_redirects=False)
    if not o.error:
        out["options"] = {"status": o.status,
                          "allow": o.hget("Allow") or o.hget("Public") or "",
                          "dav": o.hget("DAV") or "",
                          "msauthorvia": o.hget("MS-Author-Via") or ""}
    h = http.request("HEAD", seed, allow_redirects=False)
    if not h.error:
        out["head"] = {"status": h.status, "len_hdr": h.hget("Content-Length") or "",
                       "server": h.hget("Server") or "", "powered": h.hget("X-Powered-By") or ""}
    if allow_trace:
        t = http.request("TRACE", seed, allow_redirects=False)
        if not t.error:
            echoed = bool(re.search(r"(?i)TRACE |User-Agent:|Host:", t.text[:2000]))
            out["trace"] = {"status": t.status, "echo": echoed,
                            "enabled": t.status == 200 and echoed}
    rg = http.request("GET", seed, headers={"Range": "bytes=0-9"}, allow_redirects=False)
    if not rg.error:
        out["range"] = {"status": rg.status, "partial": rg.status == 206,
                        "accept_ranges": rg.hget("Accept-Ranges") or ""}
    return out


def etag_style(etag):
    """ETag format se server guess (Apache inode-size-mtime vs nginx hex)."""
    e = (etag or "").strip().strip('"W/"').strip('"')
    if not e:
        return ""
    if re.fullmatch(r"[0-9a-f]{1,10}-[0-9a-f]{1,14}-[0-9a-f]{1,14}", e, re.I):
        return "Apache-style (inode-size-mtime) ETag"
    if re.fullmatch(r"[0-9a-f]{16,64}", e, re.I):
        return "nginx-style strong hash ETag"
    if len(e) <= 12 and re.fullmatch(r"[0-9a-f\-]+", e, re.I):
        return "short hex ETag (generic)"
    return "opaque/strong ETag"


def probe_favicon(http, seed, base, root_html):
    """favicon.ico (+custom link icon) -> mmh3 hash (shodan pivot)."""
    out = {}
    targets = ["/favicon.ico"]
    m = re.search(r'(?is)<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)["\']', root_html or "")
    if m:
        href = m.group(1)
        if href.startswith("/") and not href.startswith("//"):
            targets.insert(0, href)
    seen = set()
    for path in targets:
        if path in seen:
            continue
        seen.add(path)
        if path.startswith("http"):
            url = path
        else:
            url = up.urljoin(seed.rstrip("/") + "/", path.lstrip("/"))
        r = http.request("GET", url, allow_redirects=False)
        if r.error or r.status != 200 or not r.body or is_soft404(r, base):
            continue
        if len(r.body) < 16 or len(r.body) > 500000:
            continue
        h = favicon_hash(r.body)
        out = {"path": path, "status": r.status, "len": len(r.body), "hash": h,
               "shodan_query": "http.favicon.hash:%d" % h,
               "note": "shodan/fofa/hunter pivot: same favicon = same app/deployment"}
        break
    return out


WAF_TRIGGER_PAYLOAD = "<script>alert(1)</script> ../../etc/passwd ' OR '1'='1"


def probe_waf_trigger(http, seed):
    """wafw00f-style: 1 benign-malicious GET -> block page fingerprint."""
    q = {"wasp_tech_%s" % rand_str(4): WAF_TRIGGER_PAYLOAD}
    url = seed + ("&" if "?" in seed else "?") + up.urlencode(q)
    r = http.request("GET", url, allow_redirects=False)
    if r.error:
        return {"error": r.error}
    wafs = detect_waf(r)
    blocked = bool(wafs) or r.status in (403, 406, 418, 429, 501)
    return {"status": r.status, "len": len(r.body), "title": title_of(r.text)[:100],
            "blocked": blocked, "waf": wafs,
            "note": "single GET trigger - sirf block-page fingerprint, koi payload execute nahi"}


def probe_gql(http, seed, base, scope, post_max=2):
    """GraphQL surface: endpoint scan + read-only __typename + introspection."""
    out = {"endpoints": [], "playgrounds": []}
    posts = 0
    for path in GQL_PATHS:
        if interrupted() or posts >= post_max:
            break
        url = _in_scope_url(scope, seed, path)[0]
        if not url:
            continue
        r = http.request("GET", url, allow_redirects=False)
        if r.error or r.status == 404 or r.status >= 500 or is_soft404(r, base):
            continue
        body = r.text[:6000]
        is_playground = bool(re.search(r"(?i)graphiql|graphql-playground|altair|voyager", body))
        if is_playground:
            out["playgrounds"].append({"path": path, "status": r.status})
            out["endpoints"].append({"path": path, "status": r.status, "kind": "playground"})
            continue
        is_endpoint = bool(re.search(r'(?i)"errors"|"data"|"query"|application/graphql|Cannot query', body)) \
            or (r.is_json() and r.status in (200, 400, 405, 426))
        if not is_endpoint:
            continue
        ep = {"path": path, "status": r.status, "kind": "endpoint"}
        # read-only POST probes (capped)
        if posts < post_max:
            posts += 1
            pr = _ro_post(http, "POST", url, headers={"Content-Type": "application/json"},
                          data=json.dumps({"query": "{ __typename }"}).encode(),
                          allow_redirects=False)  # LAYER 4: pure-read GraphQL query
            if not pr.error:
                ep["post_status"] = pr.status
                try:
                    pj = pr.json() or {}
                    ep["typename_ok"] = bool(pj.get("data", {}).get("__typename"))
                    errs = pj.get("errors") or []
                    ep["error_sample"] = str(errs[0].get("message", ""))[:120] if errs else ""
                except Exception:
                    ep["typename_ok"] = False
            if ep.get("typename_ok") and posts < post_max + 2:
                ir = _ro_post(http, "POST", url, headers={"Content-Type": "application/json"},
                              data=json.dumps({"query": "{ __schema { queryType { name } } }"}).encode(),
                              allow_redirects=False)  # LAYER 4: pure-read introspection
                if not ir.error:
                    try:
                        ij = ir.json() or {}
                        ep["introspection"] = bool((ij.get("data") or {}).get("__schema"))
                    except Exception:
                        ep["introspection"] = False
                    ep["introspection_status"] = ir.status
        out["endpoints"].append(ep)
    return out


def probe_docs(http, seed, base, scope):
    """OpenAPI/Swagger spec discovery + parse (title/version/paths)."""
    out = []
    seen = set()
    for path in DOC_PATHS:
        if interrupted():
            break
        url = _in_scope_url(scope, seed, path)[0]
        if not url or path in seen:
            continue
        seen.add(path)
        r = http.request("GET", url, allow_redirects=False)
        if r.error or r.status in (400, 404, 410) or r.status >= 500 or is_soft404(r, base):
            continue
        body = r.text[:60000]
        spec = None
        if r.is_json():
            j = r.json() or {}
            if isinstance(j, dict) and ("openapi" in j or "swagger" in j):
                info_ = j.get("info") or {}
                spec = {"spec_version": j.get("openapi") or j.get("swagger"),
                        "title": info_.get("title", ""), "version": info_.get("version", ""),
                        "paths_count": len(j.get("paths") or {}),
                        "servers": [s.get("url") for s in (j.get("servers") or []) if isinstance(s, dict)][:4]}
        elif re.search(r"(?i)swagger-ui|redoc|fastapi", body[:4000]) and r.status == 200 \
                and ("html" in (r.hget("Content-Type") or "").lower()):
            spec = {"spec_version": "", "title": "%s (UI page)" % path.strip("/"),
                    "version": "", "paths_count": 0}
        if spec:
            spec.update({"path": path, "status": r.status})
            out.append(spec)
    return out


def probe_sso(http, seed, base, scope):
    """OIDC discovery + JWKS + SAML metadata - auth architecture map."""
    out = {"oidc": None, "jwks": None, "saml": []}
    for path, kind in SSO_PATHS:
        if interrupted():
            break
        url = _in_scope_url(scope, seed, path)[0]
        if not url:
            continue
        r = http.request("GET", url, allow_redirects=False)
        if r.error or r.status in (400, 404, 410) or r.status >= 500 or is_soft404(r, base):
            continue
        body = r.text[:60000]
        if kind == "oidc" and r.is_json():
            j = r.json() or {}
            if isinstance(j, dict) and j.get("issuer"):
                out["oidc"] = {"path": path, "status": r.status,
                               "issuer": j.get("issuer", ""),
                               "grant_types": j.get("grant_types_supported", [])[:8],
                               "scopes": j.get("scopes_supported", [])[:10],
                               "signing_algs": j.get("id_token_signing_alg_values_supported", [])[:8],
                               "jwks_uri": j.get("jwks_uri", "")}
        elif kind == "jwks" and r.is_json():
            j = r.json() or {}
            keys = j.get("keys") or []
            if keys:
                out["jwks"] = {"path": path, "status": r.status,
                               "key_count": len(keys),
                               "ktys": sorted({k.get("kty", "?") for k in keys})[:4],
                               "algs": sorted({k.get("alg", "") for k in keys if k.get("alg")})[:6]}
        elif kind == "saml" and re.search(r"(?i)EntityDescriptor|IDPSSODescriptor|simplesaml|Shibboleth", body):
            out["saml"].append({"path": path, "status": r.status,
                                "entity": (re.search(r'(?i)entityID="([^"]+)"', body) or [None, ""])[1] if re.search(r'(?i)entityID="([^"]+)"', body) else ""})
    # oidc.jwks_uri follow (agar alag path hai)
    if out["oidc"] and out["oidc"].get("jwks_uri") and not out["jwks"]:
        ju = up.urljoin(seed, out["oidc"]["jwks_uri"])
        if scope.check_url(ju, raise_on_fail=False):
            r = http.request("GET", ju, allow_redirects=False)
            if not r.error and r.is_json():
                keys = (r.json() or {}).get("keys") or []
                if keys:
                    out["jwks"] = {"path": out["oidc"]["jwks_uri"], "status": r.status,
                                   "key_count": len(keys),
                                   "ktys": sorted({k.get("kty", "?") for k in keys})[:4],
                                   "algs": sorted({k.get("alg", "") for k in keys if k.get("alg")})[:6]}
    return out


def mine_js(cfg, http, seed, root_html):
    """js assets fetch (P2 js_urls.txt pehle, warna root <script> tags) - blob mine."""
    urls = []
    # understand/js_urls.txt (P2 output) - eng dir = tech/ ka parent
    try:
        eng_dir = os.path.dirname(getattr(cfg, "module_outdir", ".") or ".")
        p2 = os.path.join(eng_dir, "understand", "js_urls.txt")
        if os.path.exists(p2):
            urls = [l.strip() for l in open(p2, errors="ignore") if l.strip()]
    except Exception:
        urls = []
    if not urls:
        for m in re.finditer(r'(?is)<script[^>]+src=["\']([^"\']+)["\']', root_html or ""):
            u = up.urljoin(seed, m.group(1))
            if host_of(u) == host_of(seed):
                urls.append(u)
    urls = [u for u in dict.fromkeys(urls) if host_of(u) == host_of(seed)]
    limit = int(tget(cfg, "tech_js_fetch_limit"))
    blob, fetched = "", []
    for u in urls[:limit]:
        if interrupted():
            break
        r = http.request("GET", u, allow_redirects=True, retries=0)
        if not r.error and r.status == 200:
            blob += r.text[:60000]
            fetched.append(u)
    return blob, fetched


# ---------------------------------------------------------------------------
# OBSERVATIONS (security-relevant tech findings -> P23/P25/P32 feedforward)
# ---------------------------------------------------------------------------
PATH_OBS = {
    "/phpinfo.php": ("HIGH", "phpinfo() page exposed",
                     "phpinfo config paths, env vars, secrets bata deta hai. Hatao ya ACL lagao."),
    "/info.php": ("HIGH", "phpinfo() page exposed (info.php)",
                  "phpinfo config paths, env vars, secrets bata deta hai. Hatao ya ACL lagao."),
    "/adminer.php": ("CRITICAL", "Adminer DB manager exposed",
                    "Adminer se direct DB connect (SSRF/creds brute possible). Turant disable."),
    "/phpmyadmin/": ("HIGH", "phpMyAdmin exposed",
                     "Public phpMyAdmin = credential attacks ka target. IP-allowlist lagao."),
    "/server-status": ("HIGH", "Apache server-status exposed",
                       "Live requests/URLs/vhosts leak. mod_status ko localhost-only karo."),
    "/server-info": ("HIGH", "Apache server-info exposed",
                     "Full module/config info leak. mod_info disable karo."),
    "/nginx_status": ("MEDIUM", "nginx stub_status exposed",
                      "Connection stats leak. allow 127.0.0.1 only."),
    "/stub_status": ("MEDIUM", "nginx stub_status exposed",
                     "Connection stats leak. allow 127.0.0.1 only."),
    "/actuator": ("HIGH", "Spring Boot Actuator root exposed",
                  "/env,/heapdump,/beans jaise endpoints P23 me verify karo (RCE-level impact)."),
    "/actuator/health": ("LOW", "Actuator health publicly readable",
                         "Internal component names/versions leak ho sakte hain."),
    "/metrics": ("MEDIUM", "Prometheus /metrics exposed",
                 "Internal metrics + route/job names leak. Restrict karo."),
    "/telescope": ("HIGH", "Laravel Telescope exposed",
                   "Requests/jobs/exceptions dump - creds PII mil sakte hain. Prod me disable."),
    "/horizon": ("HIGH", "Laravel Horizon exposed",
                 "Queue/jobs dashboard public. Auth lagao."),
    "/_ignition/health-check": ("HIGH", "Laravel Ignition reachable",
                                "Ignition error page = CVE-2021-3129 RCE history. Update + debug off."),
    "/__debug__/": ("HIGH", "Django debug toolbar exposed",
                    "SQL/headers/settings leak. INTERNAL_IPS restrict karo."),
    "/elmah.axd": ("HIGH", "ELMAH error log exposed",
                   "Error logs me creds/PII/paths. remoteAccess disable karo."),
    "/trace.axd": ("HIGH", "ASP.NET trace.axd exposed",
                   "Request/session state leak. trace enabled=false in web.config."),
    "/swagger.json": ("MEDIUM", "OpenAPI/Swagger spec exposed",
                      "Full API surface public. Auth ya obscurity lagao, docs se enum paths."),
    "/openapi.json": ("MEDIUM", "OpenAPI/Swagger spec exposed",
                      "Full API surface public. Auth ya obscurity lagao, docs se enum paths."),
    "/api-docs": ("MEDIUM", "API docs endpoint exposed",
                  "Full API surface public. Auth ya obscurity lagao."),
    "/v2/swagger.json": ("MEDIUM", "Swagger 2.0 spec exposed",
                         "Full API surface public. P17 ko routing."),
    "/v3/api-docs": ("MEDIUM", "OpenAPI 3 spec exposed (springdoc)",
                     "Full API surface public. P17 ko routing."),
    "/api/v3/api-docs": ("MEDIUM", "OpenAPI 3 spec exposed (springdoc)",
                         "Full API surface public. P17 ko routing."),
    "/swagger-ui.html": ("MEDIUM", "Swagger UI exposed",
                         "Interactive API explorer public hai."),
    "/swagger-ui/": ("MEDIUM", "Swagger UI exposed",
                     "Interactive API explorer public hai."),
    "/graphiql": ("MEDIUM", "GraphiQL IDE exposed",
                  "Interactive GraphQL console public. P18 ko routing."),
    "/admin": ("LOW", "Generic /admin path reachable",
               "Status %s - content verify karke P23 me credential checks."),
}

OBS_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _new_obs(state, host, severity, title, detail, evidence, nxt):
    state["n"] += 1
    return {"id": "TECH-OBS-%03d" % state["n"], "host": host, "severity": severity,
            "title": title, "detail": detail, "evidence": evidence[:4], "next": nxt}


def build_observations(final_url, rec_parts, state, cap):
    """rec_parts (assembled host record) se observations banao."""
    obs = []
    def add(*a, **kw):
        if len(obs) < cap:
            obs.append(_new_obs(state, final_url, *a, **kw))

    paths = rec_parts.get("default_paths") or {}
    for path, h in paths.items():
        if path in PATH_OBS and h.get("status") in (200, 201, 301, 302, 401, 403, 405):
            sev, title, detail = PATH_OBS[path]
            add(sev, title, detail,
                ["%s -> status=%s" % (path, h.get("status"))], ["P23"])
    # version disclosures
    versions = rec_parts.get("versions") or {}
    for tech, v in versions.items():
        if "h" in (v.get("sources") or []):
            add("LOW", "%s version disclosed in headers" % tech,
                "Response headers me version leak - attackers ko nunchi vulnerability map milti hai.",
                ["%s=%s" % (tech, v.get("value"))], ["P23"])
    for note in rec_parts.get("version_notes") or []:
        sev = "HIGH" if "CRITICAL" in (note.get("note") or "") else "MEDIUM"
        add(sev, "Outdated/EOL component: %s %s" % (note.get("tech"), note.get("value")),
            note.get("note", ""),
            ["%s=%s" % (note.get("tech"), note.get("value"))], ["P23", "P32"])
    beh = rec_parts.get("behavior") or {}
    if (beh.get("trace") or {}).get("enabled"):
        add("MEDIUM", "HTTP TRACE method enabled",
            "Cross-Site Tracing history + header echo. TRACE disable karo.",
            ["TRACE / -> 200 echo"], ["P23"])
    dav = (beh.get("options") or {}).get("dav") or ""
    if dav:
        add("MEDIUM", "WebDAV enabled (DAV header: %s)" % dav.strip(),
            "PUT/MOVE methods P12/P16 me upload abuse ke liye check karo.",
            ["OPTIONS DAV=%s" % dav.strip()], ["P12", "P16"])
    for path, h in (rec_parts.get("default_paths") or {}).items():
        t = (h.get("title") or "")
        if t.lower().startswith("index of"):
            add("MEDIUM", "Directory listing exposed (%s)" % path,
                "Autoindex public hai - file enum trivial hai. Disable karo.",
                ["%s -> %s" % (path, t[:60])], ["P23"])
    waf = rec_parts.get("waf") or {}
    if waf.get("waf"):
        names = sorted({w["waf"] for w in waf["waf"]})
        add("INFO", "WAF/edge detected: %s" % ", ".join(names),
            "Testing rate/payloads adjust karo; bypass P25 me try honge.",
            ["trigger status=%s" % (waf.get("trigger") or {}).get("status", "-")], ["P25"])
    elif (waf.get("trigger") or {}).get("status") is not None and not waf.get("trigger", {}).get("blocked"):
        add("LOW", "No WAF/filtering on trigger probe",
            "Benign malicious-looking GET par koi block nahi (payload execute nahi hua - sirf fingerprint).",
            ["trigger status=%s" % waf.get("trigger", {}).get("status")], ["P25"])
    cookies_blob = " ".join(rec_parts.get("session_model", {}).get("cookie_names", []))
    if "BIGipServer" in cookies_blob:
        add("MEDIUM", "F5 BIGipServer cookie present",
            "BIGip cookie decode se internal IP/DATAGROUP leak hota hai - P10 me verify.",
            ["cookie: BIGipServer*"], ["P10", "P23"])
    gql = rec_parts.get("graphql") or {}
    if gql.get("playgrounds"):
        add("MEDIUM", "GraphQL IDE/playground exposed",
            "GraphiQL/playground public - schema browsing trivial. P18 me deep test.",
            [str(p.get("path")) for p in gql.get("playgrounds", [])[:3]], ["P18"])
    for ep in gql.get("endpoints") or []:
        if ep.get("introspection"):
            add("INFO", "GraphQL introspection enabled (%s)" % ep.get("path"),
                "Introspection se full schema milega - P18 me attack surface map hoga.",
                ["POST %s -> __schema ok" % ep.get("path")], ["P18"])
    sso = rec_parts.get("sso") or {}
    if sso.get("oidc"):
        add("INFO", "OIDC provider discovered",
            "issuer=%s - P9/P10 me SSO flows test honge." % sso["oidc"].get("issuer", ""),
            [sso["oidc"].get("path", "")], ["P9", "P10"])
        if "HS256" in (sso["oidc"].get("signing_algs") or []):
            add("MEDIUM", "OIDC advertises HS256 token signing",
                "Symmetric JWT alg - weak/client-secret leak par forgery. P10 me tamper test.",
                ["signing_algs: HS256"], ["P10"])
    if not sso.get("jwks") and sso.get("oidc") and sso["oidc"].get("jwks_uri"):
        add("LOW", "OIDC jwks_uri unreachable",
            "JWKS fetch fail - token validation offline ho sakta hai (alg-confusion hint).",
            [sso["oidc"].get("jwks_uri", "")], ["P10"])
    for c in rec_parts.get("contradictions") or []:
        add("MEDIUM", "Banner contradiction/spoof", c, ["evidence: fingerprint set"], ["P23"])
    if (rec_parts.get("meta") or {}).get("robots", {}).get("admin_paths"):
        add("INFO", "robots.txt Disallow me sensitive-looking paths",
            "Hidden paths ka map - P5 content enum + P23 me verify.",
            rec_parts["meta"]["robots"]["admin_paths"][:4], ["P5", "P23"])
    return obs


# ---------------------------------------------------------------------------
# ARCHITECTURE INFERENCE (rendering / backend / realtime / BFF)
# ---------------------------------------------------------------------------
def infer_architecture(blobs, scores, api_hits, sess, sso, gql, hosting, js_blob):
    arch = {"rendering": "unknown", "backend_pattern": "unknown", "realtime": [],
            "static_host": ", ".join(hosting or []), "bff": False, "notes": []}
    body = blobs.get("b", "") or ""
    for tech, label in RENDER_RULES:
        if scores.get(tech, 0) >= 4:
            arch["rendering"] = label
            break
    if arch["rendering"] == "unknown":
        spa_root = bool(re.search(r'<div[^>]+id=["\'](?:root|app|__next|__nuxt)["\']', body, re.I)) \
            and scores.get("jQuery", 0) == 0
        if spa_root:
            arch["rendering"] = "CSR SPA (client-rendered)"
    forms = len(re.findall(r"<form\b", body, re.I))
    api_present = bool(api_hits) or bool((gql or {}).get("endpoints"))
    stateful = bool(sess.get("stateful_examples"))
    if api_present and forms == 0:
        arch["backend_pattern"] = "API-first"
    elif forms >= 1 and stateful and not api_present:
        arch["backend_pattern"] = "traditional MVC (forms + session)"
    elif api_present and forms >= 1:
        arch["backend_pattern"] = "hybrid (SPA + API)"
    if scores.get("Next.js", 0) >= 4 and api_present:
        arch["bff"] = True
        arch["notes"].append("Next.js API routes likely (BFF pattern)")
    if scores.get("socket.io", 0) > 0 or re.search(r"(?i)socket\.io|new WebSocket\(|wss?://", js_blob or ""):
        arch["realtime"].append("websocket/socket.io")
    if sso and (sso.get("oidc") or sso.get("saml")):
        arch["notes"].append("centralized SSO: %s" %
                             ("OIDC" if sso.get("oidc") else "SAML"))
    for tech in SSO_BACKENDS:
        if scores.get(tech, 0) >= 4:
            arch["notes"].append("IdP detected: %s" % tech)
            break
    if hosting:
        arch["notes"].append("hosting/edge: %s" % ", ".join(sorted(hosting)))
    arch["realtime"] = arch["realtime"][:4]
    arch["notes"] = arch["notes"][:8]
    return arch


def perimeter_chain(wafs, cdns, lbs, server_hdr):
    chain = []
    for w in sorted({w["waf"] for w in wafs or []}):
        chain.append("%s (WAF)" % w)
    for c in cdns or []:
        if not any(c in x for x in chain):
            chain.append("%s (CDN)" % c)
    for l in lbs or []:
        if not any(l in x for x in chain):
            chain.append("%s (LB)" % l)
    if server_hdr and not chain:
        chain.append("%s (origin)" % server_hdr)
    elif server_hdr:
        chain.append("%s (origin banner)" % server_hdr)
    return chain[:8]


# ---------------------------------------------------------------------------
# HOST ANALYSIS PIPELINE (har stage checkpointed -> resume consistent)
# ---------------------------------------------------------------------------
class _RootShim(object):
    """Checkpointed root record -> Resp-jaisa interface (collect/detect ke liye)."""

    def __init__(self, d):
        self.status = d.get("status")
        self.url = d.get("url", "")
        self.headers = d.get("headers") or {}
        self.set_cookies = d.get("set_cookies") or []
        self.chain = d.get("chain") or []
        self._text = d.get("text") or ""
        self.error = None

    @property
    def text(self):
        return self._text

    def hget(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == str(name).lower():
                return v
        return default

    def is_json(self):
        return "json" in (self.hget("Content-Type") or "").lower()


def _date_skew(headers):
    d = ""
    for k, v in headers.items():
        if k.lower() == "date":
            d = v
            break
    if not d:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(d)
        return int(dt.timestamp() - time.time())
    except Exception:
        return None


def analyze_host(cfg, scope, http, cache, cp, seed, eng_dir=None):
    seed = normalize_url(seed)
    ck = "host:" + seed
    if cp.is_done(ck):
        ok("SKIP (checkpoint) %s" % seed)
        return cp.result_of(ck)

    if not getattr(cfg, "allow_active", True):
        rec = {"seed": seed, "error": "allow_active=false -> P6 probes skip"}
        cp.mark(ck, rec, summary="inactive")
        warn("%s: allow_active=false - sirf error record" % seed)
        return rec

    # ---- stage 1: root + soft404 baseline + error page ----
    rk = "root:" + seed
    if cp.is_done(rk):
        sroot = cp.result_of(rk) or {}
    else:
        base = soft404_baseline(http, seed, samples=3)
        root = http.request("GET", seed, allow_redirects=True,
                            save="root_%s.html" % re.sub(r"[^A-Za-z0-9._-]", "_", host_of(seed)))
        if root.error:
            warn("%s -> %s" % (seed, root.error))
            rec = {"seed": seed, "error": root.error, "baseline": base or {}}
            cp.mark(rk, {"error": root.error, "baseline": base or {}}, summary="unreachable")
            cp.mark(ck, rec, summary="unreachable")
            return rec
        rnd = "/%s" % rand_str(12)
        er = http.request("GET", up.urljoin(seed.rstrip("/") + "/", rnd.lstrip("/")),
                          allow_redirects=False)
        sroot = {"root": {"status": root.status, "url": root.url,
                          "headers": dict(root.headers), "set_cookies": list(root.set_cookies),
                          "text": (root.text or "")[:120000], "chain": list(root.chain),
                          "title": title_of(root.text), "len": len(root.body)},
                 "baseline": base or {},
                 "error_body": (er.text or "")[:50000] if not er.error else "",
                 "error_status": er.status if not er.error else None}
        cp.mark(rk, sroot, summary="root+baseline+errorpage")

    root_shim = _RootShim(sroot.get("root") or {})
    base = sroot.get("baseline") or {}
    error_body = sroot.get("error_body") or ""
    root_html = root_shim.text or ""
    headers_raw = "\n".join("%s: %s" % (k, v) for k, v in root_shim.headers.items())
    server_h = (root_shim.hget("Server") or "").strip()

    def stage(key, fn):
        k = "%s:%s" % (key, seed)
        if cp.is_done(k):
            return cp.result_of(k)
        res = fn()
        cp.mark(k, res, summary=key)
        return res

    # ---- stage 2: default-path probes ----
    if tget(cfg, "tech_probe_paths"):
        path_hits = stage("paths", lambda: probe_paths(http, seed, base, scope,
                                                       int(tget(cfg, "tech_probe_max"))))
    else:
        path_hits = {}

    # ---- stage 3: meta probes (robots/sitemap/security.txt/AASA) ----
    meta = stage("meta", lambda: probe_meta(http, seed, base, scope)) \
        if tget(cfg, "tech_meta_probe") else {}

    # ---- stage 4: behavioural probes ----
    if tget(cfg, "tech_behavior"):
        behav = stage("behav", lambda: probe_behavior(http, seed,
                                                      allow_trace=bool(tget(cfg, "tech_allow_trace"))))
    else:
        behav = {}

    # ---- stage 5: favicon mmh3 ----
    fav = stage("fav", lambda: probe_favicon(http, seed, base, root_html)) \
        if tget(cfg, "tech_favicon") else {}

    # ---- stage 6: WAF trigger + passive WAF/CDN/LB detection ----
    def _waf_stage():
        trig = probe_waf_trigger(http, seed) if tget(cfg, "tech_waf_trigger") else {}
        wafs = detect_waf(root_shim)
        if trig.get("waf"):
            got = {w["waf"] for w in wafs}
            wafs += [w for w in trig["waf"] if w["waf"] not in got]
        cdn, lb = detect_cdn_lb(root_shim)
        if trig.get("waf"):
            for w in trig["waf"]:
                if w["waf"] not in cdn and w["waf"] in CDN_SIGS:
                    cdn.append(w["waf"])
        return {"trigger": trig, "waf": wafs, "cdn": sorted(set(cdn)), "lb": sorted(set(lb))}
    waf = stage("waf", _waf_stage)  # passive detection + (optional) trigger

    # ---- stage 7: GraphQL surface ----
    gql = stage("gql", lambda: probe_gql(http, seed, base, scope,
                                         post_max=int(tget(cfg, "tech_gql_post_max")))) \
        if tget(cfg, "tech_gql_probe") else {"endpoints": [], "playgrounds": []}

    # ---- stage 8: OpenAPI/Swagger docs ----
    docs = stage("docs", lambda: probe_docs(http, seed, base, scope)) \
        if tget(cfg, "tech_probe_paths") else []

    # ---- stage 9: SSO/OIDC discovery ----
    sso = stage("sso", lambda: probe_sso(http, seed, base, scope)) \
        if tget(cfg, "tech_sso_probe") else {"oidc": None, "jwks": None, "saml": []}

    # ---- stage 10: js mining ----
    def _js_stage():
        blob, fetched = mine_js(cfg, http, seed, root_html)
        return {"blob": blob[:150000], "fetched": fetched}
    js = stage("js", _js_stage) if tget(cfg, "tech_js_fetch") else {"blob": "", "fetched": []}

    # ================= FUSION =================
    cookie_names = _cnames(root_shim)
    default_blob = ["%s @%s" % (h.get("tech"), p) for p, h in path_hits.items()]
    blobs = collect(root_shim, root_shim, error_body, cookie_names, default_blob, js["blob"])
    scores, evid, conf = score_tech(blobs)
    err_hits = sorted({n for n, pat in ERROR_SIGNATURES.items() if re.search(pat, error_body, re.I)})

    versions = extract_versions(blobs) if tget(cfg, "tech_version_extract") else {}
    vnotes = version_notes(versions)

    contradictions = find_contradictions(scores, headers_raw, server_h, err_hits,
                                         versions, waf.get("waf"))

    # endpoints list (P2/P5 files + is module ke discoveries)
    endpoints = []
    for rel in (("understand", "endpoints.txt"), ("content", "api_endpoints.txt")):
        fp = os.path.join(eng_dir or "", *rel)
        try:
            if os.path.exists(fp):
                endpoints += [l.strip() for l in open(fp, errors="ignore") if l.strip()][:400]
        except Exception:
            pass
    endpoints += [d.get("path", "") for d in docs] + \
                 [e.get("path", "") for e in gql.get("endpoints", [])] + list(path_hits.keys())
    style = api_style(headers_raw, root_html, endpoints)
    sess = session_model(root_shim, cookie_names)

    # hosting detection: SaaS/hosting SIG se (scores me hosting entries)
    hosting = [t for t in ("AWS S3", "GCS", "GitHub Pages", "Vercel", "Netlify", "Heroku",
                           "Render", "Fly.io", "Firebase", "Supabase", "Azure Static Apps",
                           "DO App Platform") if scores.get(t, 0) >= 4]
    arch = infer_architecture(blobs, scores, style, sess, sso, gql, hosting, js["blob"])
    perimeter = perimeter_chain(waf.get("waf"), waf.get("cdn"), waf.get("lb"), server_h)

    cache_layer = {k: root_shim.hget(k) for k in
                   ["cf-cache-status", "x-cache", "age", "via", "x-served-by",
                    "x-varnish", "x-fastly-request-id", "x-akamai-transformed",
                    "x-proxy-cache", "x-drupal-cache"]
                   if root_shim.hget(k)}
    security_headers = {h: root_shim.hget(h) for h in
                        ["strict-transport-security", "content-security-policy",
                         "x-frame-options", "x-content-type-options", "referrer-policy",
                         "permissions-policy", "cross-origin-opener-policy"]
                        if root_shim.hget(h)}

    ranked = sorted(({"tech": t, "score": s, "confidence": conf[t],
                      "version": next((v.get("value", "") for k2, v in versions.items()
                                       if k2.lower() == t.lower()), ""),
                      "evidence": evid.get(t, [])[:8]} for t, s in scores.items()),
                    key=lambda x: -x["score"])

    rec = {"seed": seed, "final_url": root_shim.url, "status": root_shim.status,
           "server": server_h, "powered": root_shim.hget("X-Powered-By"),
           "baseline": base, "tech_ranked": ranked,
           "error_signatures": err_hits, "default_paths": path_hits,
           "default_path_hits": [v.get("tech") for v in path_hits.values()],
           "versions": versions, "version_notes": vnotes,
           "api_style": style, "session_model": sess, "contradictions": contradictions,
           "cache_layer": cache_layer, "security_headers": security_headers,
           "behavior": behav, "etag_style": etag_style(root_shim.hget("ETag")),
           "date_skew_sec": _date_skew(root_shim.headers),
           "http3": "h3" in (root_shim.hget("Alt-Svc") or "").lower(),
           "alt_svc": (root_shim.hget("Alt-Svc") or "")[:120],
           "favicon": fav, "waf": waf, "cdn": waf.get("cdn", []), "lb": waf.get("lb", []),
           "perimeter": perimeter, "meta": meta, "graphql": gql, "openapi": docs,
           "sso": sso, "architecture": arch, "hosting": hosting,
           "js_fetched": js.get("fetched", []),
           "module_version": MODULE_VERSION}

    if cache:
        cache.put("GET", seed, {"status": root_shim.status, "len": sroot.get("root", {}).get("len", 0),
                                "sha1": sha1((sroot.get("root") or {}).get("text", "")[:6000]),
                                "title": sroot.get("root", {}).get("title", "")})
    cp.mark(ck, rec, summary="tech host")

    top = ", ".join("%s(%s)" % (t["tech"], t["confidence"]) for t in ranked[:6]) or "-"
    ok("%s [%s] | top: %s" % (host_of(seed), root_shim.status, top))
    ok("   api_style=%s | session=%s | perimeter=%s"
       % (",".join(style.keys()) or "-", sess.get("storage_inference"),
          " -> ".join(perimeter) or "-"))
    if versions:
        ok("   versions: %s" % ", ".join("%s %s" % (k, v.get("value"))
                                         for k, v in sorted(versions.items())))
    if contradictions:
        warn("   CONTRADICTIONS: %s" % "; ".join(contradictions))
    if err_hits:
        warn("   error signatures: %s" % ", ".join(err_hits))
    return rec

# ---------------------------------------------------------------------------
# MAIN ENTRY (v2 contract: run(cfg, scope, base_out))
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    cache = ProbeCache(base_out, scope.engagement) if getattr(cfg, "negative_cache", True) else None
    head("Phase 6 - Technology & Architecture ID (ULTRA v%s) | %s"
         % (MODULE_VERSION.split("-")[0], scope.describe()))

    seeds = []
    p4 = os.path.join(os.path.dirname(out), "active", "live_hosts.txt")
    if os.path.exists(p4):
        for line in open(p4, errors="ignore"):
            m = re.match(r"(https?://\S+)\s*\[", line.strip())
            if m:
                seeds.append(m.group(1))
    if not seeds:
        seeds = scope.seed_urls()
    seeds = [s for s in sorted(set(seeds)) if scope.check_url(s, raise_on_fail=False)]
    if not seeds:
        err("No in-scope targets."); return out
    info("Hosts: %d | probe budget/host: %s" % (len(seeds), tget(cfg, "tech_probe_max")))
    eng_dir = os.path.dirname(out)

    results = []
    for s in seeds:
        if interrupted():
            warn("Interrupt - clean stop (state saved, rerun to resume).")
            break
        results.append(analyze_host(cfg, scope, http, cache, cp, s, eng_dir=eng_dir))
    live = [r for r in results if r.get("status")]

    # ---- observations: cached records se re-derive (resume-consistent) ----
    obs_state = {"n": 0}
    obs_cap = int(tget(cfg, "tech_observation_cap"))
    observations = []
    for r in live:
        observations.extend(build_observations(
            r.get("final_url") or r.get("seed"), r, obs_state,
            max(0, obs_cap - len(observations))))
    observations.sort(key=lambda o: OBS_SEV_ORDER.get(o.get("severity"), 9))
    for i, o in enumerate(observations, 1):
        o["id"] = "TECH-OBS-%03d" % i

    # ---- engagement-level architecture synthesis ----
    renderings = sorted({(r.get("architecture") or {}).get("rendering", "unknown") for r in live})
    backends = sorted({(r.get("architecture") or {}).get("backend_pattern", "unknown") for r in live})
    perimeter_set = sorted({p for r in live for p in (r.get("perimeter") or [])})
    multi_stack = len(renderings) > 1

    # ================= REPORTS =================
    save_json(os.path.join(out, "tech_profile.json"),
              {"phase": "6-tech", "generated_at": now_iso(), "module_version": MODULE_VERSION,
               "hosts": results})

    # stack_report.txt (v2 format superset)
    lines = []
    for r in live:
        lines.append("=== %s (%s) ===" % (r["final_url"], r["status"]))
        lines.append("server=%s | powered=%s" % (r["server"] or "-", r["powered"] or "-"))
        lines.append("baseline: status=%s stable=%s serves200=%s" %
                     (r["baseline"].get("status"), r["baseline"].get("stable_len"),
                      r["baseline"].get("serves_200_on_missing")))
        if r.get("perimeter"):
            lines.append("perimeter: %s" % " -> ".join(r["perimeter"]))
        arch = r.get("architecture") or {}
        lines.append("architecture: %s | %s | realtime=%s" %
                     (arch.get("rendering"), arch.get("backend_pattern"),
                      ",".join(arch.get("realtime") or []) or "-"))
        if r.get("versions"):
            lines.append("versions: %s" % "; ".join("%s %s" % (k, v.get("value"))
                                                    for k, v in sorted(r["versions"].items())))
        for n in r.get("version_notes") or []:
            lines.append("  [EOL/CVE] %s %s: %s" % (n.get("tech"), n.get("value"), n.get("note")))
        for t in r["tech_ranked"][:15]:
            lines.append("  %-16s score=%-3d conf=%-6s %s %s" %
                         (t["tech"], t["score"], t["confidence"],
                          ("v" + t["version"]) if t.get("version") else "",
                          "; ".join(t["evidence"][:3])))
        if r["error_signatures"]:
            lines.append("error_signatures=%s" % ",".join(r["error_signatures"]))
        if r["default_paths"]:
            lines.append("default_path_hits=%s" %
                         ",".join("%s[%s]" % (p, h.get("status")) for p, h in r["default_paths"].items()))
        if r.get("cache_layer"):
            lines.append("cache_layer=%s" % json.dumps(r["cache_layer"]))
        if r["contradictions"]:
            lines.append("CONTRADICTIONS: %s" % "; ".join(r["contradictions"]))
        lines.append("")
    save_text(os.path.join(out, "stack_report.txt"), "\n".join(lines))

    # architecture_map.txt
    am = ["WASP Phase 6 - Architecture Map | module v%s | %s" % (MODULE_VERSION, now_iso()), ""]
    for r in live:
        arch = r.get("architecture") or {}
        sso = r.get("sso") or {}
        am.append("=== %s ===" % r["final_url"])
        am.append("rendering     : %s" % arch.get("rendering"))
        am.append("backend       : %s%s" % (arch.get("backend_pattern"),
                                            " [BFF]" if arch.get("bff") else ""))
        am.append("api_styles    : %s" % ", ".join((r.get("api_style") or {}).keys()) or "-")
        am.append("realtime      : %s" % ", ".join(arch.get("realtime") or []) or "-")
        if sso.get("oidc"):
            am.append("sso/oidc      : issuer=%s algs=%s" %
                      (sso["oidc"].get("issuer", "-"), ",".join(sso["oidc"].get("signing_algs") or []) or "-"))
        if sso.get("saml"):
            am.append("sso/saml      : %s" % ", ".join(s.get("path", "?") for s in sso["saml"]))
        am.append("static_host   : %s" % (arch.get("static_host") or "-"))
        am.append("perimeter     : %s" % " -> ".join(r.get("perimeter") or []) or "-")
        if arch.get("notes"):
            for n in arch["notes"]:
                am.append("note          : %s" % n)
        am.append("")
    am.append("=== ENGAGEMENT SUMMARY ===")
    am.append("hosts=%d | distinct renderings=%d | multi-stack=%s"
              % (len(live), len(renderings), "YES - possible microservices/segregated services"
                 if multi_stack else "no"))
    am.append("perimeter pool: %s" % ", ".join(perimeter_set) or "-")
    save_text(os.path.join(out, "architecture_map.txt"), "\n".join(am))

    # tech_versions.txt
    tv = ["WASP Phase 6 - Versions + EOL/CVE notes | %s" % now_iso(), ""]
    for r in live:
        if not r.get("versions") and not r.get("version_notes"):
            continue
        tv.append("=== %s ===" % r["final_url"])
        for k, v in sorted((r.get("versions") or {}).items()):
            tv.append("  %-12s %-12s sources=%s" % (k, v.get("value"), ",".join(v.get("sources") or [])))
        for n in r.get("version_notes") or []:
            tv.append("  NOTE %-12s %s -> %s" % (n.get("tech"), n.get("value"), n.get("note")))
        tv.append("")
    save_text(os.path.join(out, "tech_versions.txt"), "\n".join(tv))

    # favicon_hashes.txt
    fh = ["WASP Phase 6 - Favicon mmh3 hashes (shodan/fofa pivot) | %s" % now_iso(), ""]
    for r in live:
        f = r.get("favicon") or {}
        if f.get("hash") is not None:
            fh.append("%-10d %s  (%s, %dB) | %s" % (f["hash"], r["final_url"],
                                                     f.get("path", "?"), f.get("len", 0),
                                                     f.get("shodan_query", "")))
    save_text(os.path.join(out, "favicon_hashes.txt"), "\n".join(fh))

    # waf_cdn.txt + perimeter.json
    wc = ["WASP Phase 6 - WAF/CDN/LB detection | %s" % now_iso(), ""]
    for r in live:
        w = r.get("waf") or {}
        wc.append("=== %s ===" % r["final_url"])
        wc.append("waf   : %s" % (", ".join(sorted({x["waf"] for x in w.get("waf", [])})) or "not detected"))
        for x in w.get("waf", [])[:4]:
            wc.append("  evidence: %s (%s, status=%s)" % (x.get("evidence"), x.get("where"), x.get("status")))
        wc.append("cdn   : %s" % ", ".join(r.get("cdn") or []) or "not detected")
        wc.append("lb    : %s" % ", ".join(r.get("lb") or []) or "not detected")
        trig = w.get("trigger") or {}
        if trig:
            wc.append("trigger: status=%s blocked=%s %s" %
                      (trig.get("status"), trig.get("blocked"),
                       "; ".join(x["waf"] for x in trig.get("waf", [])) or ""))
        wc.append("chain : %s" % " -> ".join(r.get("perimeter") or []) or "-")
        wc.append("")
    save_text(os.path.join(out, "waf_cdn.txt"), "\n".join(wc))
    save_json(os.path.join(out, "perimeter.json"),
              {"phase": "6-tech", "generated_at": now_iso(),
               "hosts": [{"host": r["final_url"], "perimeter": r.get("perimeter"),
                          "waf": sorted({x["waf"] for x in (r.get("waf") or {}).get("waf", [])}),
                          "cdn": r.get("cdn"), "lb": r.get("lb")} for r in live]})

    # openapi / graphql / behavior / observations JSON
    save_json(os.path.join(out, "openapi_specs.json"),
              {"phase": "6-tech", "generated_at": now_iso(),
               "hosts": {r["final_url"]: r.get("openapi") or [] for r in live}})
    save_json(os.path.join(out, "graphql_surface.json"),
              {"phase": "6-tech", "generated_at": now_iso(),
               "hosts": {r["final_url"]: r.get("graphql") or {} for r in live}})
    save_json(os.path.join(out, "http_behavior.json"),
              {"phase": "6-tech", "generated_at": now_iso(),
               "hosts": {r["final_url"]: {"behavior": r.get("behavior"),
                                          "etag_style": r.get("etag_style"),
                                          "date_skew_sec": r.get("date_skew_sec"),
                                          "http3": r.get("http3"), "alt_svc": r.get("alt_svc")}
                         for r in live}})
    by_sev = {}
    for o in observations:
        by_sev.setdefault(o["severity"], []).append(o["id"])
    save_json(os.path.join(out, "tech_observations.json"),
              {"phase": "6-tech", "generated_at": now_iso(), "count": len(observations),
               "by_severity": {k: len(v) for k, v in by_sev.items()},
               "observations": observations})

    # TECH_OBSERVATIONS.md
    md = ["# Phase 6 - Technology Security Observations", "",
          "module v%s | %s | hosts=%d" % (MODULE_VERSION, now_iso(), len(live)), ""]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        rows = [o for o in observations if o["severity"] == sev]
        if not rows:
            continue
        md.append("## %s (%d)" % (sev, len(rows)))
        md.append("")
        for o in rows:
            md.append("### %s - %s" % (o["id"], o["title"]))
            md.append("- **host**: %s" % o["host"])
            md.append("- **detail**: %s" % o["detail"])
            if o.get("evidence"):
                md.append("- **evidence**: %s" % "; ".join(str(e) for e in o["evidence"]))
            if o.get("next"):
                md.append("- **next phases**: %s" % ", ".join(o["next"]))
            md.append("")
    save_text(os.path.join(out, "TECH_OBSERVATIONS.md"), "\n".join(md))

    # v2-compatible text reports (EXACT formats - P8/P10 isse parse karte hain)
    save_text(os.path.join(out, "api_style.txt"),
              "\n".join("%s -> %s" % (r["final_url"], ", ".join("%s(%d)" % (k, v) for k, v in r["api_style"].items()) or "-")
                        for r in live))
    save_text(os.path.join(out, "session_model.txt"),
              "\n".join("%s -> storage=%s cookies=%s flags=%s jwt_in_cookie=%s token_in_body=%s"
                        % (r["final_url"], r["session_model"].get("storage_inference"),
                           ",".join(r["session_model"].get("cookie_names", [])) or "-",
                           json.dumps(r["session_model"].get("flags", {})),
                           r["session_model"].get("jwt_in_cookie"),
                           r["session_model"].get("token_in_body")) for r in live))
    save_text(os.path.join(out, "contradictions.txt"),
              "\n".join("%s -> %s" % (r["final_url"], "; ".join(r["contradictions"]))
                        for r in live if r["contradictions"]))
    save_text(os.path.join(out, "cache_layer.txt"),
              "\n".join("%s -> %s" % (r["final_url"], json.dumps(r["cache_layer"]))
                        for r in live if r["cache_layer"]))
    save_text(os.path.join(out, "error_signatures.txt"),
              "\n".join("%s -> %s" % (r["final_url"], ",".join(r["error_signatures"]))
                        for r in live if r["error_signatures"]))
    save_text(os.path.join(out, "stack_summary.txt"),
              "\n".join("%s -> %s" % (r["final_url"], ", ".join(
                  t["tech"] for t in r["tech_ranked"] if t["confidence"] in ("high", "medium")))
                  for r in live))

    ff = write_feedforward(out, "6-tech", {
        "to_phase7_js": {"frameworks": "stack_summary.txt"},
        "to_phase8_surface": {"stack": "tech_profile.json"},
        "to_phase9_auth": {"session": "session_model.txt", "sso": "perimeter.json"},
        "to_phase10_sessions": {"session": "session_model.txt"},
        "to_phase11_access": {"api_style": "api_style.txt", "session": "session_model.txt"},
        "to_phase12_input": {"stack": "stack_report.txt", "versions": "tech_versions.txt"},
        "to_phase13_injection": {"stack": "stack_report.txt"},
        "to_phase14_xss": {"frameworks": "stack_summary.txt"},
        "to_phase17_api": {"api_style": "api_style.txt", "openapi": "openapi_specs.json"},
        "to_phase18_graphql": {"graphql": "graphql_surface.json", "api_style": "api_style.txt"},
        "to_phase19_ws": {"realtime": "architecture_map.txt"},
        "to_phase20_logic": {"stack": "stack_summary.txt"},
        "to_phase22_cache": {"cache_layer": "cache_layer.txt"},
        "to_phase23_misconfig": {"contradictions": "contradictions.txt",
                                 "errors": "error_signatures.txt",
                                 "debug_exposure": "TECH_OBSERVATIONS.md",
                                 "openapi": "openapi_specs.json"},
        "to_phase24_cloud": {"hosting": "stack_summary.txt"},
        "to_phase25_controls": {"perimeter": "waf_cdn.txt"},
        "to_phase32_report": {"hosts": len(live), "observations": len(observations)},
    }, notes=["ULTRA v3: har tech evidence-backed; 'low' = single weak signal",
              "observations cached records se re-derive hote hain (resume-consistent)",
              "versions/EOL notes P23/P32 ko; perimeter P25 ko; graphql P18 ko"])

    files = ["tech_profile.json", "stack_report.txt", "architecture_map.txt",
             "tech_versions.txt", "favicon_hashes.txt", "waf_cdn.txt", "perimeter.json",
             "openapi_specs.json", "graphql_surface.json", "http_behavior.json",
             "tech_observations.json", "TECH_OBSERVATIONS.md",
             "api_style.txt", "session_model.txt", "contradictions.txt", "cache_layer.txt",
             "error_signatures.txt", "stack_summary.txt", "feedforward.json"]
    write_manifest(out, "6-tech", files,
                   stats={"hosts": len(live),
                          "technologies": sum(len(r["tech_ranked"]) for r in live),
                          "contradictions": sum(1 for r in live if r["contradictions"]),
                          "observations": len(observations),
                          "obs_by_severity": {k: len(v) for k, v in by_sev.items()},
                          "api_styles": sum(len(r["api_style"]) for r in live),
                          "waf_hosts": sum(1 for r in live if (r.get("waf") or {}).get("waf")),
                          "graphql_endpoints": sum(len((r.get("graphql") or {}).get("endpoints") or []) for r in live),
                          "openapi_specs": sum(len(r.get("openapi") or []) for r in live),
                          "sso_oidc": sum(1 for r in live if (r.get("sso") or {}).get("oidc"))},
                   notes=ff.get("notes", []))
    cp.mark_complete()

    head("Phase 6 complete")
    ok("hosts=%d | technologies=%d | observations=%d (CRIT/HIGH: %d) | contradictions=%d"
       % (len(live), sum(len(r["tech_ranked"]) for r in live), len(observations),
          len(by_sev.get("CRITICAL", [])) + len(by_sev.get("HIGH", [])),
          sum(1 for r in live if r["contradictions"])))
    ok("reports: tech_profile.json | stack_report.txt | architecture_map.txt | "
       "TECH_OBSERVATIONS.md | waf_cdn.txt | tech_versions.txt")
    return out


if __name__ == "__main__":
    import sys
    print("mod_tech.py v%s - WASP Phase 6: Technology & Architecture ID (ULTRA)" % MODULE_VERSION)
    print("Usage : python3 wasp.py run --module tech")
    print("Self  : python3 test_mod_tech.py   (offline mock-server selftest)")
    sys.exit(0)
