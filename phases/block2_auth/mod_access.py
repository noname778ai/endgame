#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP Module: mod_access.py  |  Phase 11 - Access Control / IDOR / BOLA
==============================================================================
v11.0.0 ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se
inherit hote hain, isliye har request scope-check, rate-limit aur budget ke
andar hi jaati hai.

KYA KARTA HAI
  Phase 9/10 "andar aa sakte hain / session kitni strong hai" poochta hai.
  Phase 11 poochta hai: "andar aakar kaun SA KAUN SA object/kaam allowed hai?"
  -> horizontal privilege (IDOR/BOLA): dusre user ka object padh sakte hain?
  -> vertical privilege: low-priv user admin functions tak pahunch jata hai?
  -> authorization enforcement bypass: 403 ko path/header/method trick se toda?

STAGES
  A  Access surface discovery ...... P10 feedforward (to_phase11_idor) + P8
                                     priority queue (IDOR/BOLA, Access-Control,
                                     Mass-Assignment/AuthZ) + P7/P5 endpoints
                                     + admin path hints (ranked, capped)
  B  Identity & session setup ...... config access_sessions -> isolated
                                     HttpClient.identity() sessions (apna cookie
                                     jar + headers), liveness probe, markers
  C  Template extraction ........... manual Burp raw requests + ID-shaped
                                     endpoints -> template_key (method + masked
                                     path + query keys) se grouping
  D  IDOR/BOLA engine .............. two-account diff: attacker baseline ->
                                     garbage-ID probe -> victim truth -> ID swap
                                     -> multi-signal verdict engine
                                     (CONFIRMED/SUSPECTED/ENUM_HINT/BLOCKED/SAFE)
  E  Vertical role matrix .......... har session x har protected endpoint:
                                     low-priv 200 on admin path -> escalation;
                                     anon 200 -> auth missing (differential proof)
  F  ID intelligence ............... id_type + smart decode (base64 / Mongo
                                     ObjectId timestamp / UUIDv1 leak) + hash-
                                     of-known-value crack + bounded neighbour probe
  G  403 bypass matrix ............. path variants (/..;/, %2e, //, case, .json,
                                     version bump) x header tricks (X-Original-URL,
                                     X-Forwarded-For, CF-Connecting-IP, method
                                     override...) + anon check + double-confirm
  H  GraphQL BOLA .................. endpoint detect, introspection probe,
                                     P7 graphql_ops mining, ID-arg swap with
                                     attacker session, marker verification
  I  Mass assignment (GATED) ....... sirf access_allow_write_probes=true par:
                                     role/state fields inject + echo detection
  J  Method matrix ................. OPTIONS/HEAD (read-only) hamesha;
                                     PUT/DELETE/PATCH sirf gated mode me
  K  Reports ....................... findings.json, access_matrix.json/txt,
                                     idor_verdicts.json, ACCESS_FINDINGS.md,
                                     access_test_plan.md (hypotheses + KILL TEST
                                     + coverage), access_chains.txt, feedforward
                                     + MANIFEST

ULTRA PRO MAX ADDITIONS (v11) - naye + famous access-control attack techniques
  L  GraphQL ULTRA deep ........... introspection-bypass variants (GET?query=,
                                     %0a trick, content-type switch, form-encode)
                                     + field-suggestion error mining (did-you-mean
                                     se hidden fields) + ALIASED multi-ID BOLA
                                     (ek request me N objects - read-only query)
                                     + batching surface detect
  M  Tenant/workspace isolation ... X-Tenant-ID / X-Org-ID / tenant_id / org_id /
                                     workspace_id swap - SIRF apne do test
                                     accounts/workspaces ke beech (cross-tenant
                                     read = Critical finding)
  N  Blind IDOR oracle ............ single-account mode: 404-vs-403-vs-200
                                     existence/authz oracle + response-size delta
                                     + soft-404 filter + timing hint (bounded)
  O  Verb tampering ULTRA ......... HEAD/OPTIONS read-only matrix +
                                     X-HTTP-Method-Override GET->POST (read-only)
                                     + Accept/Content-Type downgrade + action=
                                     param read-name abuse (list/view/export)
  P  Batch/bulk IDOR .............. ids[]/ids=1,2,3 array params (GET) par
                                     single-vs-batch response diff -> over-fetch
                                     detection (array me dusre account ka object?)
  Q  Chained object IDOR .......... confirmed/suspected IDOR + own-object
                                     responses se mined IDs -> second-hop swap on
                                     related templates (order->invoice->payment,
                                     depth 2, bounded)
  R  File/export IDOR ............. file_id/document/download/export/attachment
                                     endpoints par ID-swap + garbage probe +
                                     Content-Disposition attachment-leak sniff
  S  Share-link/invite surface .... share/invite/public/token path mining +
                                     share-token entropy-lite (sequential detect)
                                     + cross-account share READ (apne accounts)
  T  API key/token scope confusion . APNE hi test accounts ke tokens/keys ka
                                     cross-use (key-A par account-B endpoint)
                                     -> scope mismatch + X-API-Key header swap
  U  Search/filter exposure ........ search/filter/q= endpoints GET par APNE
                                     test markers (email/username) se query ->
                                     cross-account leak oracle + limit-max single
                                     probe (pagination over-exposure)
  V  Authz response hygiene (0 req) offline derivation captures se: authz'd
                                     response par Cache-Control missing, object
                                     endpoint par weak CORS/Referrer-Policy,
                                     WWW-Authenticate confusion -> to_phase26
  W  Reports v2 ................... K ka extension: naye ULTRA findings keys,
                                     expanded feedforward (12/13/14/17/18/20/23/
                                     26/32) + CHAIN_HINTS v2 + MANIFEST

v11 FIXES (stock v11.0.0 me mile, yahan fix):
  FIX-1: probe-contamination protection - ULTRA stages (M/S/T) apne probes ke
         liye FRESH identity (http.identity) banate hain, shared jar me cookie
         mutation nahi hota (P10 lesson reuse).
  FIX-2: live-endpoint filter status<400 strictly (404/410/500 "live" nahi).
  FIX-3: passive mode (allow_active=False) ab discovery + manual-request parse
         + offline decode bhi deta hai (pehle sirf discovery-only return tha).
  FIX-4: findings derivation checkpoint replay path par bhi chalti hai
         (resume par findings gayab nahi hote - P10 BUG-3 lesson).
  FIX-5: read-only intent POSTs (GraphQL query/batch) read_only_post=True ke
         saath + _ensure_read_only_support() shim (purane cores par kwarg drop).

VERDICT ENGINE (false-positive kam karne ke liye multi-signal)
  CONFIRMED  -> victim markers mile YA victim-truth similarity >= access_sim_confirm
  SUSPECTED  -> victim-truth similarity >= access_sim_suspect
  ENUM_HINT  -> real ID 200 + garbage ID 404 (existence oracle)
  BLOCKED    -> swap par 401/403 (control behave kar raha hai)
  SAFE       -> swapped response apne own-baseline jaisa (>= access_own_baseline_sim)
                yaani generic/template response - koi object data nahi

SAFETY VALVES
  * allow_active=True zaroori hai probes ke liye (warna discovery-only + offline).
  * Read-only default: IDOR/bypass/matrix sirf GET/HEAD/OPTIONS.
  * Write probes (mass assignment, PUT/DELETE) OFF by default - config gate.
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Evidence/details me PII REDACT hota hai (email/phone/JWT masked).
  * Neighbour probing bounded (access_enum_probes) aur sirf GET.
  * Tenant/scope/share/search probes SIRF apne test accounts/markers ke beech -
    real users ka data KABHI nahi (ULTRA M/S/T/U stages ka hard rule).
  * ULTRA stages har ek apne knob se gated + hard-capped (access_*_probes).
  * GraphQL ULTRA sirf query/read operations - mutation/subscription KABHI nahi.
  * Batch/chained probes GET-preferred; POST sirf read_only_post flag ke saath.
  * File/download probes object-ID swap tak hi - path traversal nahi (P12 ka kaam).
"""

import os
import re
import sys
import json
import time
import uuid
import base64
import hashlib
import difflib
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
                           shannon_entropy, sha1, sha256, md5, host_of, median,
                           truncate, module_ctx, write_feedforward,
                           write_manifest, soft404_baseline, is_soft404, title_of,
                           info, ok, warn, err, head, C, VERSION)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module access")
    print("    Ya 'python3 mod_access.py wizard' chalao sessions config banane ke liye.")
    sys.exit(1)

NAME = "access"
PHASE = "11-access"
PLAN_VERSION = "11.0.0"

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


def _fw_request(cli, method, url, **kw):
    """LAYER 4 compat: WRITE probe request (sirf gated paths se call hota hai -
    upar access_allow_write_probes check ho chuka hota hai). ULTRA core par
    force_write=True read-only gate se pass hota hai; PURANE v2 core par ye
    kwarg unsupported hai -> TypeError par bina kwarg fallback (v2 me gating
    module ke apne flag se hoti hai, core-level gate nahi tha)."""
    try:
        return cli.request(method, url, force_write=True, **kw)
    except TypeError:
        return cli.request(method, url, **kw)

# ---------------------------------------------------------------------------
# TUNABLES (config.json se override; module ke apne defaults bhi hain)
# ---------------------------------------------------------------------------
DEFAULTS = {
    "access_surface_cap": 30,          # max endpoints probed in matrix/engines
    "access_template_cap": 12,         # max templates in IDOR engine
    "access_enum_probes": 6,           # neighbour/decode probe cap (GET only)
    "access_bypass_probes": 40,        # total 403-bypass requests cap
    "access_gql_ops_max": 6,           # graphql candidate type cap
    "access_allow_write_probes": False,  # mass assignment / PUT-DELETE (default OFF)
    "access_allow_neighbour_probe": True,  # +/-ID window probing (GET, bounded)
    "access_sim_confirm": 0.92,        # victim-truth similarity -> CONFIRMED
    "access_sim_suspect": 0.75,        # victim-truth similarity -> SUSPECTED
    "access_own_baseline_sim": 0.985,  # swapped ~ own-baseline -> SAFE
    "access_sessions": [],             # [{name, cookie_header, headers, markers, known_ids, priv}]
    "access_victim_known_ids": [],     # global victim object IDs fallback
    "access_manual_requests": [],      # raw Burp request strings (templates)
    # ---- ULTRA PRO MAX v11 additions ----
    "access_allow_gql_deep": True,     # stage L: introspection-bypass + alias BOLA
    "access_gql_deep_max": 8,          # L: total graphql deep requests cap
    "access_gql_alias_max": 4,         # L: aliases per aliased-BOLA request (<=6 hard)
    "access_allow_tenant_probe": True, # stage M: tenant/workspace swap (own accounts)
    "access_tenant_probes": 4,         # M: tenant swap request cap
    "access_allow_blind_oracle": True, # stage N: single-account 404/403/200 oracle
    "access_blind_probes": 6,          # N: blind oracle request cap
    "access_allow_verb_matrix": True,  # stage O: HEAD/OPTIONS/override read matrix
    "access_verb_probes": 8,           # O: verb matrix request cap
    "access_allow_batch_probe": True,  # stage P: ids[] array over-fetch probe
    "access_batch_probes": 3,          # P: batch probe cap (GET preferred)
    "access_allow_chain_probe": True,  # stage Q: chained object IDOR (depth<=2)
    "access_chain_probes": 6,          # Q: second-hop swap cap
    "access_allow_file_idor": True,    # stage R: file/export/download ID swap
    "access_file_probes": 6,           # R: file IDOR request cap
    "access_allow_share_probe": True,  # stage S: share-link/invite surface
    "access_share_probes": 5,          # S: share token requests cap
    "access_allow_scope_probe": True,  # stage T: own-token/API-key cross-use
    "access_scope_probes": 4,          # T: scope confusion request cap
    "access_allow_search_probe": True, # stage U: search/filter exposure oracle
    "access_search_probes": 4,         # U: search+limit-max request cap
    "access_authz_hygiene": True,      # stage V: offline response hygiene (0 req)
}

# ---------------------------------------------------------------------------
# KNOWLEDGE TABLES
# ---------------------------------------------------------------------------
# Param/path naam jo object identifiers hain (Phase 8 PARAM_HYP se compatible)
ID_PARAM_HINTS = [
    "id", "uid", "user_id", "userid", "account_id", "accountid", "acct", "customer_id",
    "cust_id", "order_id", "orderid", "invoice_id", "doc_id", "document_id", "file_id",
    "item_id", "product_id", "post_id", "msg_id", "message_id", "comment_id", "ticket_id",
    "payment_id", "transaction_id", "txn_id", "booking_id", "profile_id", "emp_id",
    "employee_id", "address_id", "card_id", "project_id", "org_id", "team_id", "group_id",
    "tenant_id", "uuid", "guid", "ref", "reference", "token_id", "session_id", "key_id",
    "record_id", "entry_id", "node_id", "cid", "pid", "aid", "mid", "oid", "rid", "sid",
]

ADMIN_PATH_RE = re.compile(
    r"(?i)(^|/)(admin|administrator|manage|management|manager|console|dashboard|staff|"
    r"root|superuser|operator|backoffice|internal|debug|actuator|controlpanel|"
    r"roles|permissions|audit)(/|$)")

ADMIN_PATH_HINTS = [
    "/admin", "/admin/users", "/admin/panel", "/admin/dashboard", "/administrator",
    "/manage", "/management", "/console", "/controlpanel", "/backoffice", "/staff",
    "/internal/admin", "/internal/admin/roles", "/api/admin", "/api/v1/admin",
    "/api/v1/admin/users", "/api/v1/admin/panel", "/api/v1/admin/roles",
    "/api/v2/admin/users", "/api/users", "/api/v1/users", "/api/v1/roles",
    "/api/v1/permissions", "/api/v1/audit", "/actuator", "/actuator/env",
]

PROTECTED_PATH_HINTS = [
    "/api/me", "/api/auth/me", "/api/v1/me", "/api/v1/profile", "/api/v1/account",
    "/dashboard", "/profile", "/account", "/settings", "/whoami", "/api/whoami",
    "/api/v1/orders", "/api/v1/invoices", "/api/v1/documents", "/api/v1/tickets",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/api/v1/graphql", "/api/v2/graphql", "/gql",
    "/query", "/graphql/v1", "/graphiql", "/api/graph", "/_graphql",
]

# Mass-assignment candidate fields (sirf GATED write mode me use hote hain)
MASS_ASSIGN_KEYS = [
    "role", "roles", "is_admin", "isAdmin", "admin", "is_superuser", "superuser",
    "privilege", "permissions", "perms", "level", "tier", "plan", "group", "groups",
    "status", "active", "verified", "approved", "enabled", "owner", "tenant_id",
    "balance", "credits", "quota", "limit", "price", "discount", "email_verified",
    "account_type", "user_type", "scope", "scopes", "acl",
]

# 403 bypass: path variants (sirf GET, bounded)
BYPASS_PATH_VARIANTS = [
    "{p}/..;/", "{p}/..;/", "{p}%2f..%2f;", "{p}/", "{p}//", "//{p.lstrip('/')}",
    "/./{p.lstrip('/')}", "/{p}/%2e/", "{p.lower()}", "{p.upper() if p.islower() else p.lower()}",
    "{p}%20", "{p}%2e", "{p};%2f", "{p}.json", "{p}?debug=1",
]

BYPASS_HEADER_SETS = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"Referer": "{origin}"},
]

SEVERITY_HINTS = {
    "idor_confirmed": ("Critical", "CVSS ~9.1",
                       "Attacker session dusre user ka object padh raha hai - A01:2021 broken access control."),
    "idor_suspected": ("High", "CVSS ~7.5",
                       "Cross-account response victim-truth se match kar raha hai - manual verify karo."),
    "idor_enumeration_hint": ("Medium", "CVSS ~5.3",
                              "Valid ID 200 / garbage ID 404 -> object existence oracle."),
    "id_sequential_predictable": ("Medium", "CVSS ~5.3",
                                  "IDs sequential/predictable hain -> enumeration aasan."),
    "id_encoding_weak": ("Low", "CVSS ~3.7",
                         "ID plain base64 me decode ho raha hai - obscurity hi control hai."),
    "id_hash_reversible": ("Medium", "CVSS ~5.3",
                           "ID known-value ka hash nikal ke bana hai -> dobara construct ho sakta hai."),
    "uuid_v1_timestamp_leak": ("Low", "CVSS ~3.1",
                               "UUIDv1 me timestamp leak -> generation time + predictability hint."),
    "vertical_escalation_confirmed": ("Critical", "CVSS ~9.1",
                                      "Low-priv session admin function access kar raha hai."),
    "vertical_escalation_suspected": ("High", "CVSS ~8.1",
                                      "Session privilege ke upar ka endpoint 200 de raha hai - verify karo."),
    "anon_access_missing_auth": ("Critical", "CVSS ~9.1",
                                 "Bina kisi session ke protected/admin endpoint 200 de raha hai."),
    "bypass_403_success": ("High", "CVSS ~7.5",
                           "403 path/header trick se bypass hua -> enforcement edge par hai, code me nahi."),
    "auth_missing_403_inconsistent": ("Medium", "CVSS ~5.3",
                                      "Ek session ko 403, dusre ko 200 - inconsistent authorization."),
    "graphql_bola": ("High", "CVSS ~8.1",
                     "GraphQL object-level authz missing - ID arg swap par dusre user ka data."),
    "graphql_introspection_open": ("Low", "CVSS ~3.1",
                                   "Introspection on hai -> poora schema attacker ko visible."),
    "graphql_id_arg_live": ("Medium", "CVSS ~5.3",
                            "GraphQL me ID-arg type live hai - object-level authz manually test karo."),
    "mass_assignment_possible": ("High", "CVSS ~7.5",
                                 "Privilege field echo hua -> role tampering possible."),
    "method_abuse": ("Medium", "CVSS ~5.9",
                     "Restricted method (PUT/DELETE) low-priv session se accept hua."),
    "admin_surface_note": ("Info", "-",
                           "Admin/protected surface mapped - manual testing ke liye."),
    # ---- ULTRA PRO MAX v11 additions ----
    "graphql_introspection_bypass": ("High", "CVSS ~7.5",
                                     "Introspection block ka bypass variant kaam kar gaya - schema attacker ke liye phir bhi readable hai."),
    "graphql_alias_bola": ("Critical", "CVSS ~9.1",
                           "Aliased multi-object query se ek hi request me dusre user ke objects padh liye - mass scraping sasta hai."),
    "graphql_batch_bola": ("High", "CVSS ~8.1",
                           "GraphQL batching/array operations accept hote hain - per-object rate limit bypass hota hai."),
    "graphql_field_suggestion": ("Low", "CVSS ~3.1",
                                 "Validation errors hidden fields suggest karte hain (did-you-mean) - schema discovery aid."),
    "tenant_isolation_missing": ("Critical", "CVSS ~9.1",
                                 "Tenant/workspace identifier swap se doosre tenant ka data - multi-tenant isolation toota hai."),
    "tenant_param_swap_accepted": ("High", "CVSS ~8.1",
                                   "Tenant param/header server ne accept kar liya - manual cross-tenant verify karo."),
    "blind_idor_existence_oracle": ("Medium", "CVSS ~5.3",
                                    "404-vs-200 differential bina auth ke object existence bata raha hai - enumeration ka rasta."),
    "blind_idor_authz_oracle": ("High", "CVSS ~7.5",
                                "Auth/403 response object-specific hai (garbage vs real ID diff) - blind IDOR readable hai."),
    "verb_tampering_bypass": ("Medium", "CVSS ~5.3",
                              "HEAD/OPTIONS/read-action variant protected endpoint par data de raha hai - method-level authz gap."),
    "method_override_bypass": ("Medium", "CVSS ~5.3",
                               "X-HTTP-Method-Override accept hota hai - verb-restricted rules ko override karne ka surface."),
    "batch_overfetch": ("High", "CVSS ~7.5",
                        "Batch/array param se ek request me multiple cross-account objects - over-fetch + rate-limit bypass."),
    "chained_idor_confirmed": ("Critical", "CVSS ~9.1",
                               "IDOR'd response se nikla related object ID doosre endpoint par bhi cross-account padha ja raha hai - chain confirmed."),
    "file_idor_confirmed": ("High", "CVSS ~8.1",
                            "File/export object ID swap par dusre user ka document download ho raha hai."),
    "share_token_weak": ("High", "CVSS ~7.5",
                         "Share/invite token low-entropy/sequential hai - guess karke private access mil sakta hai."),
    "share_cross_account_access": ("High", "CVSS ~7.5",
                                   "Share/invite resource doosre test account se access ho gaya - object-level authz missing."),
    "token_scope_confusion": ("High", "CVSS ~7.5",
                              "Apne hi doosre test account ka token/key doosre account ke endpoints par chal gaya - token-to-resource binding missing."),
    "search_cross_account_leak": ("High", "CVSS ~7.5",
                                  "Search/filter se dusre account ka object/marker response me aa gaya - search me object-level authz missing."),
    "pagination_overexposure": ("Medium", "CVSS ~5.3",
                                "limit/page-size max karke single request me poora dataset aa gaya - result-set controls weak."),
    "authz_cache_hygiene": ("Medium", "CVSS ~5.3",
                            "Authz'd (PII/object) response par cache-control nahi - shared cache me account data capture ka risk."),
}


def classify_severity(key):
    return SEVERITY_HINTS.get(key, ("Info", "-", ""))


CHAIN_HINTS = [
    ("CHAIN-IDOR-ATO", "IDOR + JWT role claim -> Account Takeover",
     "IDOR se victim object -> victim ke PII/session hints -> agar role/permission "
     "object me editable hai to mass-assignment chain ban jata hai",
     "11-access -> 20-logic"),
    ("CHAIN-IDOR-PII", "IDOR + PII exposure -> Data breach (mass scrape)",
     "Ek template confirm -> scripted iteration poori userbase ka data le sakti hai",
     "11-access -> 23-secrets"),
    ("CHAIN-BYPASS-ADMIN", "403 bypass + admin surface -> Full compromise",
     "Edge-filter bypass -> admin endpoints direct reachable -> user management/API keys",
     "11-access -> 17-api"),
    ("CHAIN-GQL-BOLA", "GraphQL BOLA -> Mass data exfiltration",
     "Single GraphQL op me har object ID iterate -> batched queries se scraping sasti",
     "11-access -> 18-graphql"),
    ("CHAIN-MASSASSIGN", "Mass assignment -> Privilege escalation",
     "Signup/profile update me role field inject -> admin ban jao",
     "11-access -> 16-logic"),
    # ---- ULTRA PRO MAX v11 additions ----
    ("CHAIN-TENANT-BREACH", "Tenant swap + BOLA -> Cross-tenant data breach",
     "Tenant header/param isolation toota -> har tenant ka data ek hi account se "
     "iteratable -> multi-tenant SaaS me sabse heavy impact",
     "11-access -> 22-tenant"),
    ("CHAIN-ALIAS-SCRAPE", "GraphQL alias BOLA -> Poora dataset ek request me",
     "Aliases se 100 objects/request -> rate limit circumvent -> full scrape "
     "bina rate-limit trigger kiye",
     "11-access -> 18-graphql"),
    ("CHAIN-FILE-PII", "File IDOR + export surface -> Document breach",
     "file_id/export endpoint cross-account -> invoices/statements/PDF PII "
     "downloadable -> compliance impact",
     "11-access -> 23-secrets"),
    ("CHAIN-SHARE-PERSIST", "Weak share token + no-expiry -> Persistent backdoor",
     "Guessable share token + expiry na hona -> private resource ka permanent "
     "public access",
     "11-access -> 21-share"),
    ("CHAIN-BATCH-CACHE", "Batch overfetch + authz-cache miss -> Cache capture",
     "Batch response me dusre users ka data + Cache-Control nahi -> shared cache "
     "me cross-account data capture ka surface",
     "11-access -> 26-cache"),
]


# ---------------------------------------------------------------------------
# MODULE STATE
# ---------------------------------------------------------------------------
class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "ACC-%03d" % (len(self.items) + 1), "key": key, "title": title,
               "severity": sev, "cvss_hint": cvss, "endpoint": endpoint,
               "detail": pii_redact(detail), "why_it_matters": why,
               "evidence": evidence_ref, "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


# ---------------------------------------------------------------------------
# PURE HELPERS (unit-testable, koi network nahi)
# ---------------------------------------------------------------------------
_PII_EMAIL = re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b")
_PII_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{0,}")
_PII_PHONE = re.compile(r"(?<![\d])\+?\d[\d \-]{8,14}\d(?![\d])")


def pii_redact(s, limit=420):
    """Evidence/detail text se PII mask karo (framework rule: redacted evidence)."""
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    return truncate(s, limit)


_ID_NUMERIC = re.compile(r"^\d{1,19}$")
_ID_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ID_HEX = re.compile(r"^[0-9a-fA-F]{16,64}$")
_ID_B64 = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
_ID_EMAIL = re.compile(r"(?i)^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}$")


def id_type(v):
    """ID ka shape classify karo - decode/predict strategy isi par depend karti hai."""
    v = str(v or "")
    if _ID_EMAIL.match(v):
        return "email"
    if _ID_UUID.match(v):
        try:
            u = uuid.UUID(v)
            if u.version == 1:
                return "uuid1"
            if u.version == 4:
                return "uuid4"
        except Exception:
            pass
        return "uuid"
    if _ID_NUMERIC.match(v):
        try:
            return "snowflake" if int(v) >= 10 ** 14 else "numeric"
        except Exception:
            return "numeric"
    if re.match(r"^[0-9a-fA-F]{24}$", v):
        return "mongo_objectid"
    if _ID_HEX.match(v):
        return "hexhash"
    if _ID_B64.match(v):
        return "b64"
    return "opaque"


def _b64_decode(v):
    for pad in ("", "=", "==", "==="):
        for alpha in (v, v.replace("-", "+").replace("_", "/")):
            try:
                raw = base64.b64decode(alpha + pad, validate=False)
                txt = raw.decode("utf-8", "ignore")
                if txt and sum(1 for ch in txt if 32 <= ord(ch) < 127) / float(len(txt)) > 0.85:
                    return txt
            except Exception:
                continue
    return None


def smart_decode(v):
    """ID se hidden structure nikaalo (b64 content, ObjectId/UUIDv1 timestamps)."""
    t = id_type(v)
    out = {"id": str(v)[:64], "type": t, "leak": None}
    if t == "b64":
        dec = _b64_decode(str(v))
        if dec:
            out["decoded"] = pii_redact(dec, 120)
            out["leak"] = "base64-decodable"
            inner = re.findall(r"\d{2,}", dec)
            if inner:
                out["leak"] = "base64-decodable (numeric hints: %s)" % ",".join(inner[:3])
    elif t == "mongo_objectid":
        try:
            ts = int(str(v)[:8], 16)
            out["leak"] = "mongo-objectid-embeds-unix-ts=%d" % ts
        except Exception:
            pass
    elif t == "uuid1":
        try:
            u = uuid.UUID(str(v))
            out["leak"] = "uuid1-embeds-unix-ts=%d" % int((u.time - 0x01b21dd213814000) / 1e7)
        except Exception:
            pass
    elif t == "numeric":
        n = int(v)
        if n < 100000:
            out["leak"] = "small-numeric-space (<=100k) - enumeration feasible"
    return out


def hash_of_known_value(target_id, known_values):
    """
    hexhash ID 'known value ka digest' hai ya nahi (md5/sha1/sha256).
    known_values: victim emails/ids/naam jo humein already pata hain.
    """
    t = id_type(target_id)
    if t not in ("hexhash", "mongo_objectid"):
        return None
    cands = []
    for kv in known_values or []:
        kv = str(kv)
        cands.append(kv)
        cands.append(kv.lower())
        cands.append(kv.strip().lower())
    for kv in cands:
        for algo in (md5, sha1, sha256):
            try:
                if algo(kv) == target_id.lower():
                    return {"source_value": pii_redact(kv, 40), "algo": algo.__name__}
            except Exception:
                continue
    return None


def collect_ids_from_json(doc, out=None, depth=0):
    """JSON body ke andar ID-shaped values dhoondo (keys ID_PARAM_HINTS ya values ID-shaped)."""
    if out is None:
        out = []
    if depth > 4 or doc is None:
        return out
    if isinstance(doc, dict):
        for k, v in doc.items():
            kl = str(k).lower()
            if isinstance(v, (int,)) and (kl in ID_PARAM_HINTS or kl.endswith(("_id", "id"))):
                out.append(str(v))
            elif isinstance(v, str) and (kl in ID_PARAM_HINTS or kl.endswith(("_id", "id"))
                                         or id_type(v) in ("uuid", "mongo_objectid")):
                if id_type(v) != "opaque":
                    out.append(v)
            elif isinstance(v, (dict, list)):
                collect_ids_from_json(v, out, depth + 1)
    elif isinstance(doc, list):
        for it in doc[:25]:
            collect_ids_from_json(it, out, depth + 1)
    return out


def collect_ids_from_url(url):
    """URL path segments + query values me se IDs nikaalo -> [(value, where)]."""
    out = []
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return out
    for seg in (p.path or "").split("/"):
        if seg and id_type(seg) in ("numeric", "uuid", "uuid1", "uuid4", "mongo_objectid",
                                    "hexhash", "b64", "email"):
            out.append((seg, "path"))
    for k, vals in urllib.parse.parse_qsl(p.query, keep_blank_values=True):
        if vals and (k.lower() in ID_PARAM_HINTS or k.lower().endswith(("_id", "id"))
                     or id_type(vals) in ("numeric", "uuid", "uuid1", "uuid4",
                                          "mongo_objectid", "hexhash")):
            out.append((vals, "query:" + k))
    return out


def template_key(method, url):
    """Template fingerprint: method + {ID}-masked path + query KEYS only."""
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return "%s %s" % (method.upper(), url)
    segs = []
    for seg in p.path.split("/"):
        if seg and id_type(seg) in ("numeric", "uuid", "uuid1", "uuid4", "mongo_objectid",
                                    "hexhash", "b64"):
            segs.append("{ID}")
        else:
            segs.append(seg)
    keys = sorted(k for k, _ in urllib.parse.parse_qsl(p.query, keep_blank_values=True))
    q = ",".join(keys)
    return "%s %s%s" % (method.upper(), "/".join(segs), ("?" + q) if q else "")


def swap_id(url, old, new):
    """URL me sirf standalone path segment / query value replace karo (safe replace)."""
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return url.replace(old, new, 1)
    segs = [new if s == old else s for s in p.path.split("/")]
    path = "/".join(segs)
    query = p.query
    if query:
        parts = []
        for kv in query.split("&"):
            k, _, v = kv.partition("=")
            if v == old:
                v = new
            parts.append("=".join((k, v)) if _ else k)
        query = "&".join(parts)
    return urllib.parse.urlunparse((p.scheme, p.netloc, path, p.params, query, p.fragment))


def body_similarity(a, b):
    """Differential engine ka core: JSON ho to canonical, warna normalized text ratio."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    try:
        ja, jb = json.loads(a), json.loads(b)
        if isinstance(ja, (dict, list)) and isinstance(jb, (dict, list)):
            na = json.dumps(ja, sort_keys=True, separators=(",", ":"), default=str)
            nb = json.dumps(jb, sort_keys=True, separators=(",", ":"), default=str)
            a, b = na, nb
    except Exception:
        pass
    na = re.sub(r"\s+", " ", (a or "")).lower()
    nb = re.sub(r"\s+", " ", (b or "")).lower()
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(None, na[:8000], nb[:8000]).ratio()


def marker_hits(text, markers):
    """Kitne victim/identity markers response me dikh rahe hain."""
    if not text or not markers:
        return []
    low = text.lower()
    return [m for m in markers if str(m).lower() in low]


# ---------------------------------------------------------------------------
# VERDICT ENGINE (multi-signal; false-positive kam karta hai)
# ---------------------------------------------------------------------------
def verdict_engine(text_swap, status_swap, text_own, text_victim, status_garbage,
                   markers_victim, conf):
    """
    Signals: markers, victim-truth similarity, own-baseline similarity,
    garbage-ID oracle. Return {verdict, reason, signals{...}}.
    """
    sig = {"markers": [], "sim_victim": None, "sim_own": None, "status": status_swap,
           "garbage_status": status_garbage}
    vh = marker_hits(text_swap, markers_victim)
    sig["markers"] = vh
    sim_victim = body_similarity(text_swap, text_victim) if text_victim else None
    sim_own = body_similarity(text_swap, text_own) if text_own else None
    sig["sim_victim"] = round(sim_victim, 4) if sim_victim is not None else None
    sig["sim_own"] = round(sim_own, 4) if sim_own is not None else None

    if status_swap in (401, 403):
        return {"verdict": "BLOCKED", "reason": "swap par %d - authorization enforce ho rahi hai"
                % status_swap, "signals": sig}
    if status_swap is None:
        return {"verdict": "UNKNOWN", "reason": "no response", "signals": sig}
    if status_swap in (301, 302, 303, 307, 308):
        return {"verdict": "UNKNOWN", "reason": "redirect on swap - follow karke dekho",
                "signals": sig}
    if vh:
        return {"verdict": "CONFIRMED",
                "reason": "victim markers response me mile: %s" % ", ".join(vh[:3]),
                "signals": sig}
    if sim_victim is not None and sim_victim >= float(conf.get("access_sim_confirm", 0.92)) \
            and sim_own is not None and sim_own < float(conf.get("access_own_baseline_sim", 0.985)):
        return {"verdict": "CONFIRMED",
                "reason": "response victim-truth se %.3f similar hai" % sim_victim,
                "signals": sig}
    if sim_victim is not None and sim_victim >= float(conf.get("access_sim_suspect", 0.75)):
        return {"verdict": "SUSPECTED",
                "reason": "response victim-truth se %.3f similar (threshold ke aas paas)" % sim_victim,
                "signals": sig}
    if sim_own is not None and sim_own >= float(conf.get("access_own_baseline_sim", 0.985)):
        return {"verdict": "SAFE",
                "reason": "swapped response own-baseline jaisa (generic/template response)",
                "signals": sig}
    if status_swap in (200, 201) and status_garbage in (404, 410):
        return {"verdict": "ENUM_HINT",
                "reason": "victim ID par 200, garbage ID par %d -> existence oracle" % status_garbage,
                "signals": sig}
    if status_swap in (200, 201) and sim_victim is None:
        return {"verdict": "SUSPECTED",
                "reason": "victim ID attacker session se 200 - ownership check manually dekho",
                "signals": sig}
    return {"verdict": "UNKNOWN", "reason": "mixed/insufficient signals", "signals": sig}


# ---------------------------------------------------------------------------
# BURP RAW REQUEST PARSER (manual templates import)
# ---------------------------------------------------------------------------
def parse_raw_request(raw, default_origin=""):
    """Burp-style raw request paste -> {method, url, headers, body}."""
    raw = (raw or "").replace("\\r\\n", "\r\n").replace("\\n", "\n")
    lines = raw.splitlines()
    if not lines:
        return None
    try:
        parts = lines[0].split()
        method, target = parts[0].upper(), parts[1]
    except Exception:
        return None
    headers = {}
    for ln in lines[1:]:
        if not ln.strip():
            break
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip()] = v.strip()
    idx = raw.find("\n\n")
    body = raw[idx + 2:].strip() if idx != -1 else ""
    if "\\n" in body:
        body = body.replace("\\n", "")
    host = headers.get("Host") or headers.get("host") or ""
    scheme = "https" if "443" in host else "http"
    if target.startswith("http"):
        url = target
    elif host:
        url = "%s://%s%s" % (scheme, host, target)
    else:
        url = default_origin.rstrip("/") + target if default_origin else target
    headers.pop("Host", None)
    headers.pop("host", None)
    if body and "Content-Length" not in headers and "Content-Length" not in [k.title() for k in headers]:
        headers["Content-Length"] = str(len(body.encode()))
    return {"method": method, "url": url, "headers": headers, "body": body}


# ---------------------------------------------------------------------------
# DISCOVERY SOURCES (P10 feedforward + P8 queue + P7/P5 mining + hints)
# ---------------------------------------------------------------------------
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


def _mine_phase11_feedforward(base_dir, eng, scope):
    """Phase 10 ne to_phase11_idor routing di thi -> session/protected endpoints."""
    ff = load_json(os.path.join(base_dir, eng, "sessions", "feedforward.json"), None) or {}
    route = (ff.get("routing") or {}).get("to_phase11_idor") or {}
    out = []
    for u in (route.get("session_endpoints") or []):
        if u.startswith("http") and scope.check_url(u, raise_on_fail=False):
            out.append({"url": u, "source": "P10-feedforward", "priority": 55})
    return out


def _mine_phase8_queue(base_dir, eng, scope):
    """P8 priority queue: IDOR/BOLA + Access-Control + Mass-Assignment classes."""
    pq = load_json(os.path.join(base_dir, eng, "surface", "priority_queue.json"), None) or {}
    rows = (pq.get("queue") or []) + (pq.get("diverse_queue") or [])
    want = ("IDOR/BOLA", "Access-Control", "Mass-Assignment/AuthZ", "API-Abuse")
    out, best = [], {}
    for r in rows:
        u = r.get("target") or ""
        if not u.startswith("http"):
            continue
        cls = " ".join(r.get("classes") or [])
        path = urllib.parse.urlparse(u).path
        if any(w in cls for w in want) or ID_PARAM_HINTS and \
                any(re.search(r"(?i)(%s)($|[/=])" % re.escape(p), path) for p in
                    ("id", "uid", "user_id", "account", "order", "invoice", "profile")):
            pri = int(r.get("priority") or 20)
            if u not in best or pri > best[u]["priority"]:
                best[u] = {"url": u, "source": "P8-queue", "priority": 30 + pri // 10,
                           "classes": r.get("classes") or []}
    out = sorted(best.values(), key=lambda x: -x["priority"])
    return [r for r in out if scope.check_url(r["url"], raise_on_fail=False)]


def _mine_phase7_js(base_dir, eng, scope):
    """P7 js_analysis.json -> endpoints with ID params + graphql endpoints/ops."""
    data = load_json(os.path.join(base_dir, eng, "js", "js_analysis.json"), None) or {}
    out, gql = [], []
    origins = _authorized_origins(scope)[:2]

    def _res(u):
        if u.startswith("http"):
            return u
        for o in origins:
            if u.startswith("/"):
                return o.rstrip("/") + u
        return (origins[0].rstrip("/") if origins else "") + ("/" + u if not u.startswith("/") else u)

    surface = data.get("attack_surface") or {}
    for a in data.get("assets", []):
        for e in (a.get("graphql_endpoints") or []):
            gu = _res(e)
            if scope.check_url(gu, raise_on_fail=False):
                gql.append(gu)
        for e in (a.get("endpoints") or [])[:200]:
            u = _res(e)
            if not u or _is_noise_path(u):
                continue
            if collect_ids_from_url(u) or ID_PARAM_HINTS and \
                    any(k in u.lower() for k in ("id=", "user", "account", "order", "profile")):
                if scope.check_url(u, raise_on_fail=False):
                    out.append({"url": u, "source": "P7-js", "priority": 35})
    for e in (surface.get("endpoints") or [])[:200]:
        u = _res(e)
        if u and collect_ids_from_url(u) and scope.check_url(u, raise_on_fail=False):
            out.append({"url": u, "source": "P7-js-surface", "priority": 33})
    for op in (surface.get("graphql_ops") or [])[:20]:
        gql.append("op:" + str(op)[:80])
    return out, list(dict.fromkeys(gql))


def _mine_phase5_content(base_dir, eng, scope):
    """P5 content.json -> api endpoints with id params."""
    data = load_json(os.path.join(base_dir, eng, "content", "content.json"), None) or {}
    out = []
    for host, rec in (data.get("results") or {}).items():
        base = rec.get("base_url") or ("https://" + host)
        for f in (rec.get("found", []) + rec.get("extensions", []))[:400]:
            path = f.get("path") or ""
            u = f.get("url") or urllib.parse.urljoin(base, path)
            if not u or _is_noise_path(u):
                continue
            if collect_ids_from_url(u) or ADMIN_PATH_RE.search(path):
                if scope.check_url(u, raise_on_fail=False):
                    out.append({"url": u, "source": "P5-content", "priority": 25})
    return out


def _is_noise_path(url):
    p = urllib.parse.urlparse(url).path or "/"
    if p in ("/", ""):
        return True
    return bool(re.match(r"^/(robots\.txt|sitemap.*\.xml|favicon\.ico|humans\.txt|"
                         r"security\.txt|\.well-known/[^/]*)$", p))


def discover_access_surface(base_dir, scope, conf):
    """Saare sources fuse karo -> ranked access-surface list (dedup + cap)."""
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

    for r in _mine_phase11_feedforward(base_dir, eng, scope):
        push(r["url"], r["source"], r["priority"])
    for r in _mine_phase8_queue(base_dir, eng, scope):
        push(r["url"], r["source"], r["priority"])
    p7_eps, p7_gql = _mine_phase7_js(base_dir, eng, scope)
    for r in p7_eps:
        push(r["url"], r["source"], r["priority"])
    for r in _mine_phase5_content(base_dir, eng, scope):
        push(r["url"], r["source"], r["priority"])

    # well-known hints on first origins (fallback jab pehle phases na chale hon)
    for o in _authorized_origins(scope)[:3]:
        for p in (ADMIN_PATH_HINTS + PROTECTED_PATH_HINTS)[:40]:
            push(o.rstrip("/") + p, "well-known", 10)

    ranked.sort(key=lambda r: -r["priority"])
    cap = int(conf.get("access_surface_cap", 30))
    return ranked[:cap], p7_gql


# ---------------------------------------------------------------------------
# IDENTITY / SESSION SETUP
# ---------------------------------------------------------------------------
def _cookie_str(sc):
    if sc.get("cookie_header"):
        return sc["cookie_header"]
    cookies = sc.get("cookies") or {}
    if isinstance(cookies, dict):
        return "; ".join("%s=%s" % (k, v) for k, v in cookies.items())
    return ""


def build_identities(http, conf):
    """access_sessions -> isolated HttpClient identities (apna jar + headers)."""
    idents, meta = {}, {}
    for i, sc in enumerate(conf.get("access_sessions") or []):
        name = str(sc.get("name") or ("user%d" % i))
        c = http.identity("access:" + name,
                          headers=dict(sc.get("headers") or {}),
                          cookie_header=_cookie_str(sc) or None)
        idents[name] = c
        meta[name] = {"markers": list(sc.get("markers") or []),
                      "known_ids": [str(x) for x in (sc.get("known_ids") or [])],
                      "tenant_ids": [str(x) for x in (sc.get("tenant_ids") or [])],
                      "priv": str(sc.get("priv") or "user"),
                      "headers": dict(sc.get("headers") or {}),
                      "cookie_header": _cookie_str(sc)}
    if "anon" not in idents:
        idents["anon"] = http.identity("access:anon")
        meta["anon"] = {"markers": [], "known_ids": [], "priv": "anon",
                        "headers": {}, "cookie_header": ""}
    return idents, meta


def liveness_probe(http, idents, meta, endpoints, conf):
    """Har identity ko 1-2 endpoint par hit karo -> live hai ya nahi + baseline status map."""
    live, status_map = [], {}
    eps = endpoints[:6]
    for name, client in idents.items():
        hits = 0
        for ep in eps:
            r = client.get(ep["url"], allow_redirects=False)
            if r.status:
                hits += 1
                status_map[(name, ep["url"])] = r.status
        live.append({"name": name, "hits": hits, "markers": meta[name]["markers"],
                     "known_ids": meta[name]["known_ids"], "priv": meta[name]["priv"]})
        if hits:
            ok("session '%s' live (%d/%d endpoints respond hue)"
               % (name, hits, len(eps)))
        else:
            warn("session '%s' -> koi response nahi (cookie/headers check karo)" % name)
    return live, status_map


# ---------------------------------------------------------------------------
# STAGE C - TEMPLATE EXTRACTION
# ---------------------------------------------------------------------------
def extract_templates(http, scope, ranked, conf, idents, meta):
    """
    Templates do jagah se aate hain:
      1. config access_manual_requests (Burp raw paste) -> sabse high priority
      2. surface endpoints jinke path/query me ID-shaped values hain
    Har template ka sample URL attacker session se ek baar verify hota hai.
    """
    templates, seen = [], set()
    origin = (_authorized_origins(scope) or [""])[0]

    # 1) manual raw requests
    for raw in conf.get("access_manual_requests") or []:
        rec = parse_raw_request(raw, default_origin=origin)
        if not rec or not scope.check_url(rec["url"], raise_on_fail=False):
            continue
        tk = template_key(rec["method"], rec["url"])
        if tk in seen:
            continue
        seen.add(tk)
        slots = collect_ids_from_url(rec["url"])
        templates.append({"key": tk, "method": rec["method"], "sample_url": rec["url"],
                          "headers": rec.get("headers") or {}, "body": rec.get("body") or "",
                          "slots": slots, "source": "manual", "priority": 100})

    # 2) auto from surface
    for ep in ranked:
        url = ep["url"]
        if _is_noise_path(url):
            continue
        slots = collect_ids_from_url(url)
        if not slots:
            continue
        tk = template_key("GET", url)
        if tk in seen:
            continue
        seen.add(tk)
        templates.append({"key": tk, "method": "GET", "sample_url": url, "headers": {},
                          "body": "", "slots": slots,
                          "source": ep.get("source", "surface"), "priority": ep.get("priority", 10)})

    templates.sort(key=lambda t: -t["priority"])

    # 3) collection endpoints -> object template expansion (/users -> /users/1)
    COLLECTION_RE = re.compile(r"(?i)/(users?|accounts?|customers?|orders?|invoices?|"
                               r"documents?|docs|employees?|posts?|comments?|tickets?|"
                               r"payments?|transactions?|bookings?|profiles?|cards?|messages?|"
                               r"projects?|teams?)$")
    expanded = 0
    for ep in ranked:
        if expanded >= 8:
            break
        u = ep["url"]
        p = urllib.parse.urlparse(u).path
        if not COLLECTION_RE.search(p.rstrip("/")) or collect_ids_from_url(u):
            continue
        cu = u.rstrip("/") + "/1"
        if not scope.check_url(cu, raise_on_fail=False):
            continue
        tk = template_key("GET", cu)
        if tk in seen:
            continue
        seen.add(tk)
        templates.append({"key": tk, "method": "GET", "sample_url": cu, "headers": {},
                          "body": "", "slots": collect_ids_from_url(cu),
                          "source": "collection-expansion", "priority": 15,
                          "collection": u})
        expanded += 1

    templates.sort(key=lambda t: -t["priority"])
    cap = int(conf.get("access_template_cap", 12))
    templates = templates[:cap]
    for t in templates:
        ok("template: %-60s [%s] ids=%s" % (t["key"][:60], t["source"],
                                            ",".join(s[0][:12] for s in t["slots"][:3])))
    return templates


# ---------------------------------------------------------------------------
# STAGE D - IDOR / BOLA ENGINE (two-account differential)
# ---------------------------------------------------------------------------
def idor_engine(http, scope, F, ctx, conf, templates, idents, meta, cp):
    """Two-account testing: attacker baseline -> garbage probe -> victim truth -> swap."""
    results = {}
    attacker = None
    for name, m in meta.items():
        if m["priv"] not in ("anon",) and idents.get(name):
            attacker = (name, idents[name])
            break
    victim_names = [n for n, m in meta.items() if n != (attacker[0] if attacker else None)
                    and m["priv"] not in ("anon",)]
    anon = idents.get("anon")
    global_known = [str(x) for x in (conf.get("access_victim_known_ids") or [])]

    if not attacker:
        warn("koi authenticated session nahi -> IDOR engine single-account fallback me chalega "
             "(victim truth nahi milega; ENUM_HINT/SUSPECTED tak hi jayega). "
             "2 accounts config me daalo: python3 mod_access.py wizard")
    ok("attacker session: %s | victim candidates: %s"
       % (attacker[0] if attacker else "-", ", ".join(victim_names) or "-"))

    for ti, t in enumerate(templates, 1):
        if not t["slots"]:
            continue
        ck = "idor:%s" % t["key"]
        if cp.is_done(ck):
            cached = cp.result_of(ck) or {}
            results[t["key"]] = cached
            # resume-consistency: cached verdict se bhi findings re-derive karo
            if cached.get("verdict") in ("CONFIRMED", "SUSPECTED", "ENUM_HINT") \
                    or cached.get("cross_read_own_object"):
                _report_verdict(F, t, cached)
            continue
        rec = {"template": t["key"], "method": t["method"], "source": t["source"],
               "verdict": None, "reason": "", "signals": {}, "requests": []}
        a_name, a_cli = attacker if attacker else (list(idents.items())[0])
        old_id, where = t["slots"][0]

        # 1) attacker baseline (own object)
        r_own = a_cli.get(t["sample_url"], allow_redirects=False)
        text_own = (r_own.text or "") if r_own.status == 200 else ""
        own_markers = marker_hits(text_own, meta[a_name]["markers"])
        rec["own_status"] = r_own.status
        if r_own.status is None:
            rec["verdict"], rec["reason"] = "SKIP", "attacker baseline no-response"
            results[t["key"]] = rec
            cp.mark(ck, rec, summary="idor skip")
            continue

        # 2) garbage-ID probe (existence oracle; soft-404 aware - core engine)
        garbage = "99999" + rand_str(4).lower() if id_type(old_id) == "numeric" \
            else ("9" * 20 if id_type(old_id) in ("numeric", "snowflake") else rand_str(24))
        url_g = swap_id(t["sample_url"], old_id, garbage)
        r_g = a_cli.get(url_g, allow_redirects=False)
        origin = "%s://%s" % urllib.parse.urlparse(t["sample_url"])[:2]
        base404 = _get_soft404(ctx, http, origin)
        garbage_missing = r_g.status in (404, 410) or (base404 and is_soft404(r_g, base404))
        garbage_status = 404 if (garbage_missing and r_g.status == 200) else r_g.status
        # own baseline bhi soft-404 ho sakta hai (200-on-missing servers)
        own_is_soft404 = r_own.status == 200 and base404 and is_soft404(r_own, base404)

        # 3) victim truth: victim session apna object dekhe (ya known id use karo)
        text_victim, victim_id, markers_victim = "", None, []
        for vn in victim_names:
            v_cli = idents.get(vn)
            if not v_cli:
                continue
            markers_victim = meta[vn]["markers"]
            v_ids = meta[vn]["known_ids"] or []
            if v_ids and id_type(v_ids[0]) == id_type(old_id):
                victim_id = v_ids[0]
                if victim_id != old_id:
                    url_v = swap_id(t["sample_url"], old_id, victim_id)
                    rv = v_cli.get(url_v, allow_redirects=False)
                    text_victim = (rv.text or "") if rv.status == 200 else ""
            elif not text_victim:
                # victim session se attacker ke object ko dekha -> ownership-check ka symmetric proof
                rv = v_cli.get(t["sample_url"], allow_redirects=False)
                if rv.status == 200 and (text_own and body_similarity(rv.text, text_own) > 0.80):
                    rec["cross_read_own_object"] = {
                        "victim_session": vn, "status": 200,
                        "why": "dusra session bhi attacker ke object ko 200 de raha hai -> "
                               "ownership check missing (symmetric proof)"}
                text_victim = (rv.text or "") if rv.status == 200 else ""
            if victim_id:
                break

        if not victim_id and global_known and id_type(global_known[0]) == id_type(old_id):
            victim_id = global_known[0]
            markers_victim = markers_victim or []

        # 4) swap: attacker session victim ID ke saath
        verdict = {"verdict": "SKIP", "reason": "koi victim ID nahi mili (config known_ids "
                   "ya doosra account chahiye)", "signals": {}}
        if victim_id and victim_id != old_id:
            url_s = swap_id(t["sample_url"], old_id, victim_id)
            # LAYER 4 (RWX RULE): GET swaps read-only hain; non-GET (POST/PUT/PATCH)
            # replay = write probe -> sirf access_allow_write_probes=true par chalega.
            _allow_w = conf.get("access_allow_write_probes", False)
            rs = a_cli.get(url_s, allow_redirects=False) if (t["method"] == "GET" or not _allow_w) else \
                _fw_request(a_cli, t["method"], url_s, headers=dict(t["headers"]),
                            data=(t["body"].encode() if t["body"] else None),
                            allow_redirects=False)  # LAYER 4: gated write replay
            verdict = verdict_engine((rs.text or "") if rs.status == 200 else "",
                                     rs.status, "" if own_is_soft404 else text_own,
                                     text_victim, garbage_status,
                                     markers_victim, conf)
            verdict["swap_url"] = url_s
            rec["requests"].append(pii_redact("%s %s -> %s" % (t["method"], url_s, rs.status), 200))
        elif not victim_id:
            # single-account fallback: garbage vs real existence oracle
            if r_own.status == 200 and garbage_missing and not own_is_soft404:
                verdict = {"verdict": "ENUM_HINT",
                           "reason": "own ID 200 / garbage %d -> existence oracle (victim ID "
                                     "config me daalo to full confirm hoga)" % (r_g.status or 404),
                           "signals": {"own": r_own.status, "garbage": r_g.status}}
            elif r_own.status in (200, 201) and r_g.status in (200, 201) and not garbage_missing:
                verdict = {"verdict": "SUSPECTED",
                           "reason": "garbage ID par bhi 200 -> soft-404 ya generic response, "
                                     "ownership check yahan se confirm nahi hoga",
                           "signals": {"own": r_own.status, "garbage": r_g.status}}

        # auto-collected IDs (bodies se) -> context ke liye (raw, intelligence stage)
        ids_own = collect_ids_from_json(r_own.json(None)) if r_own.status == 200 else []
        if ids_own:
            rec["ids_seen_in_own_response"] = [pii_redact(i, 40) for i in ids_own[:6]]
            ctx.setdefault("collected_ids", set()).update(ids_own[:10])

        rec["verdict"] = verdict["verdict"]
        rec["reason"] = pii_redact(verdict.get("reason", ""), 300)
        rec["signals"] = verdict.get("signals", {})
        rec["garbage_status"] = r_g.status
        if verdict.get("swap_url"):
            rec["swap_url"] = verdict.pop("swap_url")
        results[t["key"]] = rec
        cp.mark(ck, rec, summary="idor %s" % rec["verdict"])
        _report_verdict(F, t, rec)

    ctx["idor_results"] = results
    return results


def _report_verdict(F, template, rec):
    v = rec.get("verdict")
    url = rec.get("swap_url") or template["sample_url"]
    if v == "CONFIRMED":
        F.add("idor_confirmed",
              "IDOR/BOLA confirmed - cross-account object access",
              url, "template=%s | %s | signals=%s" % (
                  template["key"], rec.get("reason", ""),
                  json.dumps(_clean_sig(rec.get("signals", {})), default=str)[:300]),
              evidence_ref="idor_verdicts.json")
        ok("CRITICAL: %s -> %s" % (template["key"], rec.get("reason", "")))
    elif v == "SUSPECTED":
        F.add("idor_suspected", "Possible IDOR/BOLA (response differential match)",
              url, "template=%s | %s" % (template["key"], rec.get("reason", "")),
              evidence_ref="idor_verdicts.json")
        warn("HIGH: %s -> %s" % (template["key"], rec.get("reason", "")))
    elif v == "ENUM_HINT":
        F.add("idor_enumeration_hint", "Object existence oracle (enumeration possible)",
              url, "template=%s | %s" % (template["key"], rec.get("reason", "")),
              evidence_ref="idor_verdicts.json")
        info("MEDIUM: %s -> enumeration hint" % template["key"])
    elif v == "BLOCKED":
        info("blocked (achha): %s -> %s" % (template["key"], rec.get("reason", "")))
    if rec.get("cross_read_own_object"):
        F.add("idor_suspected", "Dusra session attacker ke object ko 200 de raha hai",
              template["sample_url"],
              "ownership check missing (symmetric proof) - %s" % rec["cross_read_own_object"]["victim_session"],
              evidence_ref="idor_verdicts.json")


def _clean_sig(sig):
    out = {}
    for k, v in (sig or {}).items():
        if v not in (None, "", [], {}):
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# STAGE E - VERTICAL ROLE MATRIX
# ---------------------------------------------------------------------------
def role_matrix(http, scope, ctx, conf, ranked, idents, meta):
    """Har session x har protected/admin endpoint -> status matrix (requests only)."""
    eps = [r["url"] for r in ranked if ADMIN_PATH_RE.search(urllib.parse.urlparse(r["url"]).path)]
    eps += [r["url"] for r in ranked if ADMIN_PATH_RE.search(urllib.parse.urlparse(r["url"]).path) is None
            and r.get("source") in ("P10-feedforward", "P8-queue")]
    seen, endpoints = set(), []
    for u in eps:
        if u not in seen:
            seen.add(u)
            endpoints.append(u)
    endpoints = endpoints[:int(conf.get("access_surface_cap", 30))]
    if not endpoints:
        info("role matrix: koi admin/protected endpoint candidate nahi mila")
        ctx["role_matrix"] = {}
        return {}, {}, {}

    matrix, followed, anon_login = {}, {}, {}
    for sname, client in idents.items():
        matrix[sname] = {}
        for u in endpoints:
            r = client.get(u, allow_redirects=False)
            st = r.status
            # engine redirect follow kar chuka ho to status final page ka hai - guard
            redir = _is_redirect_followed(r)
            followed[(sname, u)] = redir
            if sname == "anon" and st == 200:
                anon_login[u] = _looks_like_login(r.text or "")
            matrix[sname][u] = st

    ctx["role_matrix"] = matrix
    return matrix, followed, anon_login


def matrix_findings(F, ctx, meta, matrix, followed, anon_login):
    """Matrix analysis -> findings (fresh data par bhi, cached par bhi chalega)."""
    ctx["role_matrix"] = matrix or {}
    if not matrix:
        return
    findings_counter = 0
    all_eps = sorted({u for eps in matrix.values() for u in eps})
    for u in all_eps:
        sts = {s: matrix[s].get(u) for s in matrix}
        # anon 200 on admin-ish path -> auth missing (redirect-follow + login-page guard)
        anon_st = sts.get("anon")
        if anon_st == 200 and not followed.get(("anon", u)) \
                and not (anon_login or {}).get(u) \
                and ADMIN_PATH_RE.search(urllib.parse.urlparse(u).path):
            F.add("anon_access_missing_auth",
                  "Anonymous session admin endpoint ko 200 de raha hai",
                  u, "bina cookie/header ke 200 - authentication hi missing hai "
                     "(dusre sessions: %s)" % _sts_brief(sts),
                  evidence_ref="access_matrix.json")
            findings_counter += 1
        # differential: kisi ek session 403, koi aur 200 -> inconsistent authorization
        got_2xx = [s for s, st in sts.items() if st and 200 <= st < 300]
        got_403 = [s for s, st in sts.items() if st == 403]
        if got_2xx and got_403:
            low2xx = [s for s in got_2xx if meta.get(s, {}).get("priv") not in ("admin", "superuser")]
            admins = [s for s in matrix if meta.get(s, {}).get("priv") in ("admin", "superuser")]
            if low2xx and "anon" in got_403:
                # authenticated session pass, anon fail -> auth hai, authz verification chahiye
                pass
            elif low2xx and admins and all(matrix[a].get(u) in (401, 403) for a in admins):
                pass  # admins blocked ho to shayad ye admin-only nahi hai
            elif low2xx and len(got_403) >= 1 and "anon" not in got_2xx:
                F.add("auth_missing_403_inconsistent",
                      "Authorization inconsistent - ek session 403, dusra 200",
                      u, "200 wale: %s | 403 wale: %s" % (",".join(got_2xx), ",".join(got_403)),
                      evidence_ref="access_matrix.json")
                findings_counter += 1
        # low-priv session admin path par 200 -> vertical escalation (suspected+)
        for s in got_2xx:
            if s == "anon" or followed.get((s, u)):
                continue
            if meta.get(s, {}).get("priv") in ("admin", "superuser"):
                continue
            if ADMIN_PATH_RE.search(urllib.parse.urlparse(u).path):
                F.add("vertical_escalation_suspected",
                      "Low-priv session admin path par 200",
                      u, "session='%s' (priv=%s) ne 200 liya - role verify karo (admin panel "
                         "content ya sirf generic page?) - %s" % (
                             s, meta.get(s, {}).get("priv"), _sts_brief(sts)),
                      evidence_ref="access_matrix.json")
                findings_counter += 1
                break


def _sts_brief(sts):
    return ", ".join("%s=%s" % (s, st) for s, st in sorted(sts.items()))


# ---------------------------------------------------------------------------
# SHARED: soft-404 baseline (core engine se) + response guards
# ---------------------------------------------------------------------------
def _get_soft404(ctx, http, origin):
    b = (ctx.get("soft404") or {}).get(origin)
    if b is None:
        try:
            b = soft404_baseline(http, origin, samples=2)
        except Exception:
            b = {}
        ctx.setdefault("soft404", {})[origin] = b or {}
    return (ctx.get("soft404") or {}).get(origin) or {}


def _is_redirect_followed(r):
    """Engine allow_redirects=False par bhi follow kar sakta hai - chain se pakdo."""
    return len(getattr(r, "chain", None) or []) > 1


_LOGIN_MARKERS = re.compile(r"(?i)(<form[^>]*(password|passwd)[^>]*>|name=[\"']password|"
                            r"sign[- ]?in|log[- ]?in to|authenticate yourself)")


def _looks_like_login(text):
    return bool(_LOGIN_MARKERS.search((text or "")[:4000]))


# ---------------------------------------------------------------------------
# STAGE F - ID INTELLIGENCE (decode / crack / neighbour probe)
# ---------------------------------------------------------------------------
def id_intelligence(http, scope, ctx, conf, templates, idents, meta, idor_results):
    """smart decode + hash-of-known-value + bounded neighbour probe (GET only)."""
    a_name, a_cli = None, None
    for n, c in idents.items():
        if meta.get(n, {}).get("priv") not in ("anon",):
            a_name, a_cli = n, c
            break
    if not a_cli:
        a_name, a_cli = list(idents.items())[0]
    known = []
    for n, m in meta.items():
        known.extend(m.get("markers") or [])
        known.extend(m.get("known_ids") or [])
    known.extend(str(x) for x in (conf.get("access_victim_known_ids") or []))

    ids, seen = [], set()
    for t in templates:
        for val, where in t["slots"]:
            if val not in seen:
                seen.add(val)
                ids.append((val, t))
    for v in ctx.get("collected_ids") or []:
        if v not in seen:
            seen.add(v)
            ids.append((v, {"key": "(body)", "sample_url": "-"}))

    out = {"ids": [], "sequential": None, "neighbour": None}
    numerics = []
    for val, t in ids[:40]:
        sd = smart_decode(val)
        ht = hash_of_known_value(val, known)
        rec = {"id": val[:48], "type": sd["type"], "template": t["key"],
               "leak": sd.get("leak"), "hash_crack": ht}
        out["ids"].append(rec)
        if sd.get("type") in ("numeric", "snowflake"):
            numerics.append((val, t))

    # sequential pattern (same template slot me >=2 numeric ids)
    by_t = {}
    for val, t in numerics:
        by_t.setdefault(t["key"], []).append(int(val))
    for tk, vals in by_t.items():
        if len(vals) >= 2:
            vals.sort()
            diffs = [b - a for a, b in zip(vals, vals[1:])]
            if diffs and all(0 < d <= 1000 for d in diffs):
                out["sequential"] = {"template": tk, "diffs": diffs[:8]}

    # bounded neighbour probe (attacker session, GET, window +/-)
    if conf.get("access_allow_neighbour_probe", True) and numerics and a_cli:
        # pehle wo template chuno jiska own-baseline 200 tha (403 templates bekaar hain)
        val, t = numerics[0]
        for nv, nt in numerics:
            if (idor_results.get(nt["key"]) or {}).get("own_status") == 200:
                val, t = nv, nt
                break
        n = max(2, int(conf.get("access_enum_probes", 6)))
        base404 = _get_soft404(ctx, http, "%s://%s" % urllib.parse.urlparse(
            t["sample_url"])[:2]) if t.get("sample_url", "-").startswith("http") else {}
        try:
            iv = int(val)
        except Exception:
            iv = None
        if iv is not None and t.get("sample_url", "-").startswith("http"):
            deltas = []
            for d in range(1, n // 2 + 2):
                deltas += [d, -d]
            deltas = deltas[:n]
            readable, tested = 0, 0
            for d in deltas:
                url = swap_id(t["sample_url"], val, str(iv + d))
                r = a_cli.get(url, allow_redirects=False)
                tested += 1
                if r.status == 200 and not _is_redirect_followed(r) \
                        and not (base404 and is_soft404(r, base404)) \
                        and not _looks_like_login(r.text):
                    readable += 1
            out["neighbour"] = {"template": t["key"], "sample_url": t["sample_url"],
                                "tested": tested, "readable": readable, "base_id": val,
                                "window": n // 2 + 1}
            if readable:
                info("ENUM: %d/%d neighbour IDs readable - %s" % (readable, tested, t["key"]))
    ctx["id_intelligence"] = out
    return out


def intel_findings(F, intel):
    """Intel data (fresh ya cached) se findings derive karo - resume-consistent."""
    for rec in (intel or {}).get("ids", []):
        leak = rec.get("leak")
        if leak and "base64" in leak:
            F.add("id_encoding_weak", "ID plain base64 me decode ho raha hai",
                  rec.get("template", "-"),
                  "id=%s (%s)" % (rec.get("id", "")[:24], leak)[:220],
                  evidence_ref="id_intelligence.json")
        elif leak and "ts=" in leak:
            F.add("uuid_v1_timestamp_leak", "ID me embedded timestamp leak hai",
                  rec.get("template", "-"), "%s (%s)" % (rec.get("type"), leak)[:220],
                  evidence_ref="id_intelligence.json")
        elif leak and "small-numeric" in leak:
            F.add("id_sequential_predictable", "ID space chhota hai (enumeration feasible)",
                  rec.get("template", "-"), leak, evidence_ref="id_intelligence.json")
        ht = rec.get("hash_crack")
        if ht:
            F.add("id_hash_reversible", "Hashed ID known-value se reverse hua",
                  rec.get("template", "-"),
                  "id=%s = %s('%s')" % (rec.get("id", "")[:16], ht.get("algo"),
                                        ht.get("source_value")),
                  evidence_ref="id_intelligence.json")
    seq = (intel or {}).get("sequential")
    if seq:
        F.add("id_sequential_predictable", "IDs sequential pattern follow karte hain",
              seq.get("template", "-"), "diffs=%s" % (seq.get("diffs", [])[:8]),
              evidence_ref="id_intelligence.json")
    nb = (intel or {}).get("neighbour")
    if nb and nb.get("readable"):
        F.add("idor_enumeration_hint", "Neighbour IDs readable (mass enumeration feasible)",
              nb.get("sample_url", "-"),
              "%d/%d neighbour IDs attacker session se readable (id=%s, window +/-%s)"
              % (nb.get("readable"), nb.get("tested"), nb.get("base_id"), nb.get("window")),
              evidence_ref="id_intelligence.json")


# ---------------------------------------------------------------------------
# STAGE G - 403 BYPASS MATRIX (path variants x header tricks, GET only)
# ---------------------------------------------------------------------------
def _bypass_hit(r, base_st, base_text, base404):
    if r is None or r.error:
        return False
    if not (r.status and 200 <= r.status < 300):
        return False
    if _is_redirect_followed(r):
        return False
    if base404 and is_soft404(r, base404):
        return False
    txt = r.text or ""
    if not txt.strip():
        return False
    if body_similarity(txt, base_text or "") >= 0.85:
        return False
    return True


def _bypass_finding(F, u, rec):
    F.add("bypass_403_success", "403 authorization bypass confirmed",
          u, "tester=%s | %s | double-confirm=%s | anon_bypass=%s" % (
              rec.get("tester", "-"), rec.get("technique", ""),
              rec.get("confirm_status"), rec.get("anon_also_bypasses")),
          evidence_ref="bypass_403.json")
    err("BYPASS: %s (%s)" % (u, rec.get("technique", "")))


def bypass_403(http, scope, F, ctx, conf, ranked, idents, meta, cp):
    """403 wale endpoints par path/header variants - bounded, double-confirm."""
    budget = int(conf.get("access_bypass_probes", 40))
    matrix = ctx.get("role_matrix") or {}
    cand = {}
    for s, eps in matrix.items():
        if meta.get(s, {}).get("priv") in ("admin", "superuser"):
            continue
        for u, st in (eps or {}).items():
            if st == 403:
                cand[u] = 1
    if not cand:
        for r in ranked:
            if ADMIN_PATH_RE.search(urllib.parse.urlparse(r["url"]).path):
                cand[r["url"]] = 0
    targets = sorted(cand.keys())[:4]
    if not targets:
        info("403 bypass: koi 403/admin target nahi mila")
        ctx["bypass"] = {}
        return {}
    testers = [("anon", idents.get("anon"))] if idents.get("anon") else []
    for n, c in idents.items():
        if n != "anon" and meta.get(n, {}).get("priv") not in ("admin", "superuser"):
            testers.append((n, c))
    tester = testers[-1] if testers else ("anon", idents.get("anon"))
    res, spent = {}, 0
    for u in targets:
        if spent >= budget or not tester[1]:
            break
        ck = "bypass:" + u
        if cp.is_done(ck):
            cached = cp.result_of(ck) or {}
            res[u] = cached
            if cached.get("bypass"):
                _bypass_finding(F, u, cached)
            continue
        pu = urllib.parse.urlparse(u)
        origin = "%s://%s" % (pu.scheme, pu.netloc)
        p, q = pu.path or "/", ("?" + pu.query) if pu.query else ""
        base404 = _get_soft404(ctx, http, origin)
        tb = tester[1].get(u, allow_redirects=False)
        spent += 1
        base_st, base_text = tb.status, (tb.text or "")
        rec = {"target": u, "tester": tester[0], "baseline_status": base_st,
               "attempts": [], "bypass": False}
        tail = p.rstrip("/")
        variants = []
        for v in ("%s/..;/" % tail, "%s/./" % tail, "//%s/" % tail.lstrip("/"),
                  "%s%%2f" % tail, "%s%%3b%%2f" % tail, "%s.json" % tail,
                  "%s%%20" % tail, "%s/" % tail, "%%2e%s" % p,
                  p.replace("/api/v1/", "/api/v2/", 1), p.replace("/api/v2/", "/api/v1/", 1),
                  (p.upper() if p.islower() else p.lower())):
            fu = "%s%s%s" % (origin, v, q)
            if fu != u and fu not in variants:
                variants.append(fu)
        winner = None
        for fu in variants:
            if spent >= budget:
                break
            r = tester[1].get(fu, allow_redirects=False)
            spent += 1
            hit = _bypass_hit(r, base_st, base_text, base404)
            rec["attempts"].append({"type": "path", "req": pii_redact(fu, 160),
                                    "status": r.status, "bypass": bool(hit)})
            if hit:
                winner = {"kind": "path", "url": fu, "headers": {}}
                break
        if not winner:
            for hs in BYPASS_HEADER_SETS:
                if spent >= budget:
                    break
                hh = {k: (str(v).replace("{origin}", origin)) for k, v in hs.items()}
                r = tester[1].get(u, headers=hh, allow_redirects=False)
                spent += 1
                hit = _bypass_hit(r, base_st, base_text, base404)
                rec["attempts"].append({"type": "header", "req": json.dumps(hh),
                                        "status": r.status, "bypass": bool(hit)})
                if hit:
                    winner = {"kind": "header", "url": u, "headers": hh}
                    break
        if winner:
            # double-confirm (fp kam karne ke liye)
            r2 = tester[1].get(winner["url"], headers=dict(winner["headers"]),
                               allow_redirects=False)
            spent += 1
            if _bypass_hit(r2, base_st, base_text, base404):
                rec["bypass"] = True
                rec["technique"] = ("%s variant: %s" % (winner["kind"], winner["url"])
                                    if winner["kind"] == "path"
                                    else "header set: %s" % json.dumps(winner["headers"]))
                rec["confirm_status"] = r2.status
                anon_r = idents["anon"].get(winner["url"], headers=dict(winner["headers"]),
                                            allow_redirects=False) if idents.get("anon") else None
                spent += 1 if anon_r is not None else 0
                rec["anon_also_bypasses"] = bool(
                    anon_r is not None and anon_r.status and 200 <= anon_r.status < 300
                    and not _is_redirect_followed(anon_r))
                _bypass_finding(F, u, rec)
            else:
                rec["bypass"] = False
                rec["note"] = "first hit confirm nahi hua (flaky) - reported nahi"
        res[u] = rec
        cp.mark(ck, rec, summary="bypass %s" % ("HIT" if rec["bypass"] else "no"))
    ctx["bypass"] = res
    ctx["bypass_requests"] = spent
    return res


# ---------------------------------------------------------------------------
# STAGE H - GRAPHQL BOLA
# ---------------------------------------------------------------------------
_GQL_SKIP_TYPES = re.compile(r"(?i)^(__|Query|Mutation|Subscription|PageInfo|Node$|"
                             r".*(Connection|Edge|Payload|Input|Enum|Scalar|Interface|Union).*)$")


def _gql_findings(F, res):
    """GQL result data (fresh ya cached) se findings derive karo."""
    ep = ((res or {}).get("endpoints_live") or ["-"])[0]
    if (res or {}).get("introspection", {}).get("open"):
        F.add("graphql_introspection_open", "GraphQL introspection public hai",
              ep, "schema enumeration possible - internal types/mutations expose",
              evidence_ref="graphql_bola.json")
    b = (res or {}).get("bola")
    if b:
        F.add("graphql_bola", "GraphQL BOLA - ID arg swap par dusre user ka data",
              b.get("endpoint", ep),
              "type=%s id=%s attacker session se victim markers mile: %s"
              % (b.get("type"), b.get("victim_id"), ",".join((b.get("markers") or [])[:2])),
              evidence_ref="graphql_bola.json")
        err("GQL BOLA: %s(id=%s) attacker session se leak hua"
            % (b.get("type"), b.get("victim_id")))
    for ty in (res or {}).get("id_arg_live", []):
        F.add("graphql_id_arg_live", "GraphQL ID-arg type live hai - object authz test karo",
              ep, "type=%s attacker session se data mila (marker check ke liye victim "
              "ID/markers config me daalo)" % ty,
              evidence_ref="graphql_bola.json")


def graphql_bola(http, scope, F, ctx, conf, idents, meta, gql_candidates, cp):
    """GQL endpoint detect -> introspection -> ID-arg types -> victim swap w/ markers."""
    budget = int(conf.get("access_gql_ops_max", 6))
    a_name, a_cli = None, None
    for n, c in idents.items():
        if meta.get(n, {}).get("priv") not in ("anon",):
            a_name, a_cli = n, c
            break
    if not a_cli:
        a_name, a_cli = list(idents.items())[0]
    markers_victim = []
    for n, m in meta.items():
        if n != a_name and m.get("markers"):
            markers_victim = m["markers"]
    victim_ids = []
    for n, m in meta.items():
        if n != a_name:
            victim_ids.extend(m.get("known_ids") or [])
    victim_ids.extend(str(x) for x in (conf.get("access_victim_known_ids") or []))
    victim_id = victim_ids[0] if victim_ids else None

    origins = _authorized_origins(scope)[:2]
    eps = [g for g in (gql_candidates or []) if g.startswith("http")][:4]
    for o in origins:
        for p in GRAPHQL_PATHS:
            u = o.rstrip("/") + p
            if u not in eps and scope.check_url(u, raise_on_fail=False):
                eps.append(u)
    live, spent = [], 0
    for u in eps:
        if spent >= 5 or len(live) >= 2:
            break
        if not scope.check_url(u, raise_on_fail=False):
            continue
        r = _gql_post(a_cli, u, {"query": "{ __typename }"})
        if r is None:
            continue
        spent += 1
        j = r.json(None)
        if r.status == 200 and isinstance(j, dict) and "data" in j \
                and not _is_redirect_followed(r):
            live.append(u)
            ok("GraphQL live: %s" % u)
    res = {"endpoints_live": live, "introspection": None, "types_probed": [],
           "bola": None, "id_arg_live": [], "ops_from_p7": [g for g in (gql_candidates or [])
                                                            if g.startswith("op:")][:10]}
    ck = "stageH:graphql"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {}
        ctx["graphql"] = cached
        _gql_findings(F, cached)
        return cached
    if live:
        u = live[0]
        ri = _gql_post(a_cli, u, {"query": "{ __schema { queryType { name } } }"})
        if ri is None:
            ri = type("R", (), {"status": None, "json": lambda s, d=None: {}})()
        spent += 1
        ji = ri.json(None)
        if ri.status == 200 and isinstance(ji, dict) and (ji.get("data") or {}).get("__schema"):
            res["introspection"] = {"open": True, "query_type": ji["data"]["__schema"]
                                    .get("queryType", {}).get("name")}
            rtypes = _gql_post(a_cli, u, {"query": "{ __schema { types { name kind fields { name } } } }"})
            if rtypes is None:
                rtypes = type("R", (), {"status": None, "json": lambda s, d=None: {}})()
            spent += 1
            types = []
            jt = rtypes.json(None) or {}
            for t in ((jt.get("data") or {}).get("__schema") or {}).get("types") or []:
                nm = t.get("name") or ""
                flds = [f.get("name") for f in (t.get("fields") or [])]
                if t.get("kind") == "OBJECT" and "id" in (flds or []) \
                        and not _GQL_SKIP_TYPES.match(nm):
                    types.append(nm)
            res["types_with_id"] = types[:20]
        else:
            res["introspection"] = {"open": False}
            types = ["user", "account", "order", "invoice", "profile", "customer"]
        probe_types = types[:max(3, int(conf.get("access_gql_ops_max", 6)))]
        for ty in probe_types:
            if spent >= budget + 8:
                break
            vid = victim_id or "1"
            # type name != query field name (User -> user) - variants try karo
            data, errs, rq, fname = None, [], None, ty
            for fname in dict.fromkeys([ty, ty[0].lower() + ty[1:], ty.lower()]):
                q = '{ %s(id: "%s") { id } }' % (fname, vid)
                rq = _gql_post(a_cli, u, {"query": q})
                if rq is None:
                    break
                spent += 1
                jq = rq.json(None) or {}
                data = (jq.get("data") or {}).get(fname)
                errs = jq.get("errors") or []
                if data or not errs:
                    break
            row = {"type": ty, "field": fname, "status": rq.status if rq else None,
                   "live": bool(data), "errors": bool(errs)}
            res["types_probed"].append(row)
            if data and not errs:
                if markers_victim and marker_hits(json.dumps(jq), markers_victim) and victim_id:
                    res["bola"] = {"type": ty, "victim_id": victim_id, "endpoint": u,
                                   "markers": marker_hits(json.dumps(jq), markers_victim)}
                else:
                    res["id_arg_live"].append(ty)
    else:
        info("GraphQL: koi live endpoint nahi mila (candidates=%d)" % len(eps))
    res["requests"] = spent
    _gql_findings(F, res)
    cp.mark(ck, res, summary="graphql")
    ctx["graphql"] = res
    return res


# ---------------------------------------------------------------------------
# STAGE I - MASS ASSIGNMENT (GATED - default OFF)
# ---------------------------------------------------------------------------
def mass_assignment_probe(http, scope, F, ctx, conf, templates, idents, meta):
    if not conf.get("access_allow_write_probes", False):
        info("mass assignment: SKIP (access_allow_write_probes=false - safe default)")
        ctx["mass_assignment"] = {"ran": False, "reason": "gated off (write probes disabled)"}
        return {}
    cands = [t for t in templates if t["method"] in ("POST", "PUT", "PATCH")
             and (t.get("body") or "").strip().startswith("{")]
    if not cands:
        ctx["mass_assignment"] = {"ran": False,
                                  "reason": "koi JSON write template nahi (manual request import karo)"}
        return {}
    a_name, a_cli = None, None
    for n, c in idents.items():
        if meta.get(n, {}).get("priv") not in ("anon",):
            a_name, a_cli = n, c
            break
    if not a_cli:
        ctx["mass_assignment"] = {"ran": False, "reason": "koi authenticated session nahi"}
        return {}
    res = {"ran": True, "probes": []}
    marker_val = "wasp-audit-" + rand_str(6)
    for t in cands[:3]:
        try:
            body = json.loads(t["body"])
            if not isinstance(body, dict):
                continue
        except Exception:
            continue
        injected = []
        for k in MASS_ASSIGN_KEYS:
            if k not in body and len(injected) < 3:
                body[k] = marker_val
                injected.append(k)
        if not injected:
            continue
        r = _fw_request(a_cli, t["method"], t["sample_url"],
                        headers=dict(t["headers"], **{"Content-Type": "application/json"}),
                        data=json.dumps(body).encode(), allow_redirects=False)
        # ^ LAYER 4: gated write probe (mass_assignment_probe entry par check ho chuka)
        echoed = marker_val in (r.text or "")
        row = {"template": t["key"], "injected": injected, "status": r.status,
               "echoed": echoed}
        res["probes"].append(row)
        if echoed:
            F.add("mass_assignment_possible", "Privilege field echo hua (mass assignment)",
                  t["sample_url"],
                  "injected=%s marker-value response me wapas aayi - read-back se persistence "
                  "confirm karo" % ",".join(injected),
                  evidence_ref="mass_assignment.json")
            warn("MASS-ASSIGN echo: %s (%s)" % (t["key"], ",".join(injected)))
        break  # bounded: sirf 1 write probe per run
    ctx["mass_assignment"] = res
    return res


# ---------------------------------------------------------------------------
# STAGE J - METHOD MATRIX (OPTIONS/HEAD always; writes gated)
# ---------------------------------------------------------------------------
def method_matrix(http, scope, F, ctx, conf, ranked, idents, meta):
    a_name, a_cli = None, None
    for n, c in idents.items():
        if meta.get(n, {}).get("priv") not in ("anon",):
            a_name, a_cli = n, c
            break
    if not a_cli:
        ctx["methods"] = {}
        return {}
    eps = []
    for r in ranked:
        p = urllib.parse.urlparse(r["url"]).path
        if ADMIN_PATH_RE.search(p) or r.get("source") in ("P10-feedforward", "P8-queue"):
            eps.append(r["url"])
    eps = list(dict.fromkeys(eps))[:6]
    res = {}
    gated = conf.get("access_allow_write_probes", False)
    for u in eps:
        row = {}
        ro = a_cli.request("OPTIONS", u, allow_redirects=False)
        row["OPTIONS"] = {"status": ro.status, "allow": ro.hget("Allow")}
        rh = a_cli.request("HEAD", u, allow_redirects=False)
        row["HEAD"] = {"status": rh.status}
        if gated:
            for m in ("PUT", "PATCH", "DELETE"):
                rr = _fw_request(a_cli, m, u, headers={"Content-Type": "application/json"},
                                 data=b'{"wasp_audit":true}', allow_redirects=False)
                # ^ LAYER 4: gated write probe (if gated: ke andar)
                row[m] = {"status": rr.status}
                if rr.status in (200, 201, 204):
                    F.add("method_abuse", "Restricted method low-priv session se accept hua",
                          u, "%s -> %d (state change ho sakta hai - manually verify karo)" % (m, rr.status),
                          evidence_ref="method_matrix.json")
        res[u] = row
    ctx["methods"] = res
    return res


# ===========================================================================
# ULTRA PRO MAX v11 - SHARED HELPERS
# ===========================================================================
def _ro_post(cli, url, data=None, headers=None):
    """Read-only intent POST (GraphQL query / form probe). ULTRA core par
    read_only_post=True gate se pass hota hai; purane v2 core par kwarg drop
    (wahan POST gating module-level flag se hoti thi). ScopeError -> None."""
    try:
        try:
            return cli.request("POST", url, data=data, headers=headers,
                               allow_redirects=False, read_only_post=True)
        except TypeError:
            return cli.request("POST", url, data=data, headers=headers,
                               allow_redirects=False)
    except ScopeError:
        return None
    except Exception:
        return None


def _gql_post(cli, url, obj):
    """Read-only intent GraphQL POST (query-only, FIX-5). ULTRA core par
    read_only_post=True gate-pass; purane core par kwarg drop (P10 BUG-1 pattern).
    ScopeError/out-of-scope -> None (probes kabhi crash nahi karte)."""
    try:
        return cli.post_json(url, obj, allow_redirects=False, read_only_post=True)
    except TypeError:
        try:
            return cli.post_json(url, obj, allow_redirects=False)
        except Exception:
            return None
    except Exception:
        return None


def _safe_get(cli, url, headers=None):
    """GET with ScopeError swallow (probes kabhi run ko crash na karein)."""
    try:
        return cli.get(url, headers=headers or {}, allow_redirects=False)
    except ScopeError:
        return None
    except Exception:
        return None


def _fresh_identity(http, meta, name, tag):
    """FIX-1 anti-contamination: config ke ORIGINAL cookie/headers se naya
    isolated identity (shared jar me koi Set-Cookie mutation nahi)."""
    m = meta.get(name) or {}
    return http.identity("access:%s:%s" % (tag, name),
                         headers=dict(m.get("headers") or {}),
                         cookie_header=m.get("cookie_header") or None)


def _hdr_capture(ctx, url, status, headers):
    """Stage V (authz hygiene) ke liye ULTRA stages se header capture (0 extra req)."""
    try:
        if status != 200 or not headers:
            return
        low = (url or "").lower()
        if not any(x in low for x in ("/api/", "/admin", "/account", "/profile",
                                      "/orders", "/invoices", "/documents", "/files",
                                      "/me", "/settings", "/dashboard")):
            return
        h = {k.lower(): str(v) for k, v in dict(headers or {}).items()}
        ctx.setdefault("ultra_header_cache", []).append({
            "url": url, "cache_control": h.get("cache-control", ""),
            "acao": h.get("access-control-allow-origin", ""),
            "acac": h.get("access-control-allow-credentials", ""),
            "referrer_policy": h.get("referrer-policy", ""),
            "pragma": h.get("pragma", ""),
        })
    except Exception:
        pass


def _victim_seed(conf, meta):
    """RoE-safe victim material: SIRF config me diye gaye OWN test accounts ke
    markers/known-ids (koi real-user data, koi fabricated ID nahi)."""
    markers, ids = [], []
    for name, m in (meta or {}).items():
        if m.get("priv") in ("anon",):
            continue
        for mk in m.get("markers") or []:
            if mk and mk not in markers:
                markers.append(str(mk))
        for kid in m.get("known_ids") or []:
            if kid and str(kid) not in ids:
                ids.append(str(kid))
    for kid in conf.get("access_victim_known_ids") or []:
        if str(kid) not in ids:
            ids.append(str(kid))
    return markers, ids


def _attacker_of(meta, idents):
    """Pehla authenticated session (attacker role) - ya None."""
    for name, m in (meta or {}).items():
        if m.get("priv") not in ("anon",) and idents.get(name):
            return name
    return None


def _others_ids(meta, a_name):
    """Doosre authenticated accounts ke known_ids (attacker ke OWN ids exclude).
    RoE-safe: sirf config ke test-account IDs, kabhi fabricated nahi."""
    own = set(str(x) for x in ((meta.get(a_name) or {}).get("known_ids") or []))
    out = []
    for n, m in (meta or {}).items():
        if n == a_name or m.get("priv") in ("anon",):
            continue
        for kid in m.get("known_ids") or []:
            if str(kid) not in own and str(kid) not in out:
                out.append(str(kid))
    return out


# ---------------------------------------------------------------------------
# STAGE L - GRAPHQL ULTRA (introspection bypass / field suggestions /
#           aliased multi-ID BOLA / batching surface)
# ---------------------------------------------------------------------------
def graphql_ultra(http, scope, F, ctx, conf, idents, meta, gql, cp):
    """Stage H ke live endpoints par deep read-only probes. Saare requests
    GET ya read-only POST (query only) - mutation/subscription KABHI nahi."""
    res = {"ran": False, "endpoints": [], "introspection_bypass": [],
           "field_suggestions": {}, "alias_bola": None, "batching": None,
           "requests": 0}
    base_live = list((gql or {}).get("endpoints_live") or [])
    cands = [u for u in dict.fromkeys(base_live + list(gql.get("cands") or []))
             if u][:2]
    if not cands:
        # discovery fallback: gql candidates stage-A se
        for ep in ctx.get("ranked", []) or []:
            if any(p in urllib.parse.urlparse(ep["url"]).path.lower()
                   for p in ("/graphql", "/gql", "/query")):
                cands.append(ep["url"])
            if len(cands) >= 2:
                break
    if not cands:
        res["reason"] = "koi graphql endpoint candidate nahi"
        return res

    a_name = _attacker_of(meta, idents)
    markers, victim_ids = _victim_seed(conf, meta)
    att_cli = (_fresh_identity(http, meta, a_name, "gql")
               if a_name else idents.get("anon"))
    budget = int(conf.get("access_gql_deep_max", 8))
    alias_cap = max(1, min(int(conf.get("access_gql_alias_max", 4)), 6))

    INTRO_Q = '{ __schema { queryType { name } } }'
    # (query_text, note) - newline/tab smuggle + GET/POST/content-type variants
    variants = [
        ("GET", INTRO_Q, "baseline-get"),
        ("GET", '{ __schema \n { queryType { name } } }', "newline-smuggle"),
        ("GET", '{ __schema\t{ queryType { name } } }', "tab-smuggle"),
        ("FORM", INTRO_Q, "form-encoded-post"),
        ("JSON", INTRO_Q, "json-post"),
    ]

    def _looks_schema(txt):
        t = (txt or "").lower()
        return ("__schema" in t and ("querytype" in t or "mutationtype" in t)) \
            or ("types" in t and "name" in t and "fields" in t and "{" in t)

    ep_res = []
    for ep in cands:
        if res["requests"] >= budget or not scope.check_url(ep, raise_on_fail=False):
            continue
        rec = {"endpoint": ep, "plain_blocked": False, "bypass_worked": None,
               "variant": None}
        got_open = False
        for method, q, note in variants:
            if res["requests"] >= budget:
                break
            q_enc = urllib.parse.quote(q, safe=" {}:_")
            if method == "GET":
                r = _safe_get(att_cli, ep + ("&" if "?" in ep else "?")
                              + "query=" + urllib.parse.quote(q, safe=""))
            elif method == "FORM":
                r = _ro_post(att_cli, ep,
                             data=("query=" + urllib.parse.quote(q, safe="")).encode(),
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
            else:
                r = _ro_post(att_cli, ep,
                             data=json.dumps({"query": q}).encode(),
                             headers={"Content-Type": "application/json"})
            res["requests"] += 1
            if r is None or not r.status:
                continue
            _hdr_capture(ctx, ep, r.status, r.headers)
            ok_resp = _looks_schema(r.text)
            if note == "baseline-get":
                if ok_resp:
                    got_open = True        # introspection pehle se open (H me bhi)
                    break
                rec["plain_blocked"] = True
            elif ok_resp:
                rec["bypass_worked"] = note
                break
        if rec["plain_blocked"] and rec["bypass_worked"]:
            res["introspection_bypass"].append(rec)
            F.add("graphql_introspection_bypass",
                  "GraphQL introspection block bypass (%s)" % rec["variant"],
                  ep, "Introspection baseline block tha par '%s' variant ne poora "
                      "schema de diya - block edge par hai, data model leak." % rec["bypass_worked"],
                  evidence_ref="gql_ultra.json")
        # field suggestions (did-you-mean) - 1 probe per endpoint
        if res["requests"] < budget:
            probe = '{ user { usernam } }'
            r = _safe_get(att_cli, ep + ("&" if "?" in ep else "?")
                          + "query=" + urllib.parse.quote(probe, safe=""))
            res["requests"] += 1
            if r is not None and r.status:
                m = re.search(r"(?i)did you mean\s*[\"'`:]+([a-zA-Z_][a-zA-Z0-9_]*)",
                              r.text or "")
                if m:
                    sug = m.group(1)
                    res["field_suggestions"][ep] = sug
                    F.add("graphql_field_suggestion",
                          "GraphQL field suggestion leak (did-you-mean)",
                          ep, "Typo-probe par error ne '%s' suggest kiya - validation "
                              "errors se hidden field discovery possible." % sug,
                          evidence_ref="gql_ultra.json")
        ep_res.append(rec)

    # aliased multi-ID BOLA - SIRF config ke victim IDs (own accounts)
    gql_h = (gql or {})
    type_arg = []
    b = gql_h.get("bola") or {}
    if b.get("type"):
        type_arg.append((b["type"], b.get("arg") or "id"))
    for t in (gql_h.get("id_arg_live") or [])[:2]:
        if isinstance(t, dict) and t.get("type") and t.get("arg"):
            type_arg.append((t["type"], t["arg"]))
        elif isinstance(t, str) and ":" in t:
            ty, _, ag = t.partition(":")
            type_arg.append((ty, ag))
        elif isinstance(t, str) and t.strip():
            type_arg.append((t.strip(), "id"))
    if res["requests"] < budget and victim_ids and type_arg:
        vid = next((v for v in _others_ids(meta, a_name)
                    if str(v) in [str(x) for x in victim_ids]), None)
        if vid is None:
            vid = victim_ids[0]
        ty, ag = type_arg[0]
        alias = " ".join('a%d: %s(%s:"%s"){id}' % (i + 1, ty, ag, vid)
                         for i in range(alias_cap))
        q = "{ %s }" % alias
        ep = cands[0]
        r = _safe_get(att_cli, ep + ("&" if "?" in ep else "?")
                      + "query=" + urllib.parse.quote(q, safe=""))
        res["requests"] += 1
        if r is not None and r.status and r.status < 400:
            _hdr_capture(ctx, ep, r.status, r.headers)
            hits = marker_hits(r.text or "", markers)
            non_null = 0
            try:
                data = json.loads(r.text).get("data") or {}
                non_null = sum(1 for v in data.values() if v is not None)
            except Exception:
                pass
            rec = {"endpoint": ep, "type": ty, "arg": ag, "victim_id": vid,
                   "aliases": alias_cap, "markers": hits[:4], "non_null": non_null,
                   "verdict": "CONFIRMED" if (hits or non_null >= alias_cap - 1)
                              else ("SUSPECTED" if non_null else "UNKNOWN")}
            res["alias_bola"] = rec
            if rec["verdict"] == "CONFIRMED":
                F.add("graphql_alias_bola",
                      "GraphQL aliased multi-object BOLA (%s:%s)" % (ty, ag),
                      ep, "Ek request me %d aliases se victim object '%s' padha "
                          "gaya (markers=%s, non_null=%d) - object-level authz "
                          "missing, mass scraping surface." % (alias_cap, vid,
                          ",".join(hits[:2]) or "n/a", non_null),
                      evidence_ref="gql_ultra.json")
            elif rec["verdict"] == "SUSPECTED":
                F.add("graphql_id_arg_live", "GraphQL alias query victim ID par data "
                      "de raha hai (manual verify)", ep,
                      "alias non_null=%d - ownership check manually confirm karo." % non_null,
                      evidence_ref="gql_ultra.json")
    # batching surface (array-of-queries accept?) - read-only
    if res["requests"] < budget:
        ep = cands[0]
        batch = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]
        r = _ro_post(att_cli, ep, data=json.dumps(batch).encode(),
                     headers={"Content-Type": "application/json"})
        res["requests"] += 1
        if r is not None and r.status and r.status < 400:
            arr = None
            try:
                arr = json.loads(r.text)
            except Exception:
                pass
            if isinstance(arr, list) and len(arr) >= 2:
                res["batching"] = {"endpoint": ep, "accepted": True,
                                   "count": len(arr)}
                F.add("graphql_batch_bola", "GraphQL batching/array accepted", ep,
                      "Array-of-queries response list me aaya (%d items) - per-request "
                      "rate-limit bypass surface (read-only queries se hi)." % len(arr),
                      evidence_ref="gql_ultra.json")

    res["ran"] = True
    res["endpoints"] = cands
    return res


# ---------------------------------------------------------------------------
# STAGE M - TENANT / WORKSPACE ISOLATION (own accounts only)
# ---------------------------------------------------------------------------
TENANT_KEYS = ["tenant_id", "tenantId", "org_id", "orgId", "organization_id",
               "workspace_id", "workspaceId", "team_id", "account_id"]
TENANT_HEADERS = ["X-Tenant-ID", "X-Org-ID", "X-Workspace-ID", "X-Organization-ID"]


def tenant_isolation(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """Tenant param/header swap SIRF apne do test accounts ke known values ke
    beech. Fabricated/guessed tenant IDs = RoE violation, isliye hard-blocked."""
    res = {"ran": False, "reason": "", "targets": [], "swaps": [], "requests": 0}
    if not conf.get("access_allow_tenant_probe", True):
        res["reason"] = "gated off"
        return res
    a_name = _attacker_of(meta, idents)
    other = [n for n in (meta or {})
             if n != a_name and meta[n].get("priv") not in ("anon",)]
    if not a_name or not other:
        res["reason"] = "tenant swap ke liye 2+ test accounts chahiye (config access_sessions)"
        return res
    b_name = other[0]
    markers_a = meta[a_name].get("markers") or []
    markers_b = meta[b_name].get("markers") or []
    # tenant VALUES: sirf dono accounts ke known_ids jo tenant-key naam ke saath
    # aaye hain (template slots 'query:tenant_id' style) ya config tenant_ids
    tenant_vals_a = [v for v in (meta[a_name].get("tenant_ids") or []) if v]
    tenant_vals_b = [v for v in (meta[b_name].get("tenant_ids") or []) if v]
    # fallback: known_ids first value per account (own tenant represent karta hai)
    if not tenant_vals_a:
        ka = (meta[a_name].get("known_ids") or [""])[0]
        tenant_vals_a = [ka] if ka else []
    if not tenant_vals_b:
        kb = (meta[b_name].get("known_ids") or [""])[0]
        tenant_vals_b = [kb] if kb else []
    if not tenant_vals_a or not tenant_vals_b or tenant_vals_a[0] == tenant_vals_b[0]:
        res["reason"] = ("alag tenant/workspace values config me daalo "
                         "(access_sessions[].known_ids / tenant_ids) - swap material nahi")
        return res
    va, vb = tenant_vals_a[0], tenant_vals_b[0]

    budget = int(conf.get("access_tenant_probes", 4))
    # targets: endpoints jinke query me tenant-key hai (top 3), warna protected hints
    t_urls = []
    for r in ranked or []:
        q = urllib.parse.urlparse(r["url"]).query.lower()
        if any(k.lower() in q for k in TENANT_KEYS) and r["url"] not in t_urls:
            t_urls.append(r["url"])
        if len(t_urls) >= 3:
            break
    if not t_urls:
        _o = (_authorized_origins(scope) or [""])[0]
        t_urls = [_o.rstrip("/") + u for u in PROTECTED_PATH_HINTS
                  if u.startswith("/api/")][:2]
    t_urls = [u for u in t_urls if u.startswith("http")
              and scope.check_url(u, raise_on_fail=False)]
    att_cli = _fresh_identity(http, meta, a_name, "tenant")

    for u in t_urls:
        if res["requests"] >= budget or not scope.check_url(u, raise_on_fail=False):
            continue
        # 1) query-param swap (agar param hai)
        swapped_q = None
        p = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        if qs:
            new_q = []
            for k, v in qs:
                if k.lower() in [k.lower() for k in TENANT_KEYS] and v:
                    new_q.append((k, vb))
                    swapped_q = k
                else:
                    new_q.append((k, v))
            if swapped_q:
                su = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params,
                                              urllib.parse.urlencode(new_q), p.fragment))
                r = _safe_get(att_cli, su)
                res["requests"] += 1
                if r is not None and r.status and r.status < 400:
                    _hdr_capture(ctx, su, r.status, r.headers)
                    hits = marker_hits(r.text or "", markers_b)
                    rec = {"endpoint": u, "vector": "query:" + swapped_q,
                           "from": va, "to": vb, "markers_b": hits[:4],
                           "status": r.status}
                    res["swaps"].append(rec)
                    if hits:
                        F.add("tenant_isolation_missing",
                              "Cross-tenant data read (%s swap)" % swapped_q, u,
                              "Session-A ne tenant value B (%s) ke saath B ke markers "
                              "(%s) response me dekhe - tenant isolation missing."
                              % (vb, ",".join(hits[:2])),
                              evidence_ref="tenant_isolation.json")
                    else:
                        F.add("tenant_param_swap_accepted",
                              "Tenant param accepted without validation (%s)" % swapped_q,
                              u, "Tenant value %s->%s accept hui (status %d) - "
                              "cross-tenant read manually verify karo." % (va, vb, r.status),
                              evidence_ref="tenant_isolation.json")
        # 2) header swap (1 endpoint, 1-2 headers)
        if res["requests"] < budget:
            for hname in TENANT_HEADERS[:2]:
                if res["requests"] >= budget:
                    break
                r = _safe_get(att_cli, u, headers={hname: vb})
                res["requests"] += 1
                if r is not None and r.status and r.status < 400:
                    _hdr_capture(ctx, u, r.status, r.headers)
                    hits = marker_hits(r.text or "", markers_b)
                    if hits:
                        res["swaps"].append({"endpoint": u, "vector": "header:" + hname,
                                             "to": vb, "markers_b": hits[:4],
                                             "status": r.status})
                        F.add("tenant_isolation_missing",
                              "Cross-tenant data read (%s header swap)" % hname, u,
                              "Header %s: %s par B ke markers response me - tenant "
                              "isolation header-level par missing." % (hname, vb),
                              evidence_ref="tenant_isolation.json")
                        break
    res["ran"] = True
    res["targets"] = t_urls
    return res


# ---------------------------------------------------------------------------
# STAGE N - BLIND IDOR ORACLE (single-account / anon differential)
# ---------------------------------------------------------------------------
def blind_oracle(http, scope, F, ctx, conf, idents, meta, templates, cp):
    """Jahan 2-account victim-truth nahi mili: anon identity se real-ID vs
    garbage-ID differential -> existence/authz oracle classification."""
    res = {"ran": False, "reason": "", "oracles": [], "requests": 0}
    if not conf.get("access_allow_blind_oracle", True):
        res["reason"] = "gated off"
        return res
    anon = idents.get("anon")
    if anon is None:
        res["reason"] = "anon identity nahi bani"
        return res
    budget = int(conf.get("access_blind_probes", 6))
    for t in (templates or [])[:8]:
        if res["requests"] >= budget:
            break
        if not t["slots"]:
            continue
        old_id, _where = t["slots"][0]
        u_real = t["sample_url"]
        u_garbage = swap_id(u_real, old_id, "wasp9999999")
        if not scope.check_url(u_garbage, raise_on_fail=False):
            continue
        ck = "ultraN:%s" % t["key"]
        cached = cp.result_of(ck) if cp.is_done(ck) else None
        if cached:
            rec = cached
        else:
            r1 = _safe_get(anon, u_real)
            r2 = _safe_get(anon, u_garbage)
            res["requests"] += 2
            if r1 is None or r2 is None or not r1.status or not r2.status:
                continue
            _hdr_capture(ctx, u_real, r1.status, r1.headers)
            sz1, sz2 = len(r1.text or ""), len(r2.text or "")
            # soft-404 note: verdict garbage ko strict 404/410 maangta hai -
            # catch-all-200 case waise hi excluded hai; body-sim authz branch
            # alag se real-vs-garbage similarity check karti hai.
            soft = body_similarity(r2.text or "", r1.text or "") > 0.995
            verdict = "none"
            if r1.status in (200, 201) and r2.status in (404, 410) and not soft:
                verdict = "existence"
            elif r1.status == 403 and r2.status == 403:
                d = abs(sz1 - sz2)
                sim = body_similarity(r1.text or "", r2.text or "")
                if d > 40 and sim < 0.98:
                    verdict = "authz"      # 403 body object-specific hai
            rec = {"template": t["key"], "url": u_real, "status_real": r1.status,
                   "status_garbage": r2.status, "size_real": sz1, "size_garbage": sz2,
                   "soft404_garbage": bool(soft), "verdict": verdict,
                   "ms_real": round(getattr(r1, "elapsed", 0.0) or 0.0, 1),
                   "ms_garbage": round(getattr(r2, "elapsed", 0.0) or 0.0, 1)}
            cp.mark(ck, rec, summary="blind oracle")
        res["oracles"].append(rec)
        if rec["verdict"] == "existence":
            F.add("blind_idor_existence_oracle",
                  "Object existence oracle (anon %d vs garbage %d)"
                  % (rec["status_real"], rec["status_garbage"]), rec["url"],
                  "Real ID anon se %d, garbage ID %d (soft-404 nahi) - object "
                  "existence bina auth bhi readable." % (rec["status_real"],
                  rec["status_garbage"]), evidence_ref="blind_oracle.json")
        elif rec["verdict"] == "authz":
            F.add("blind_idor_authz_oracle",
                  "403 response object-specific hai (blind authz oracle)", rec["url"],
                  "Real vs garbage ID ke 403 bodies alag hain (size %d vs %d) - "
                  "response leak se object existence confirm hota hai."
                  % (rec["size_real"], rec["size_garbage"]),
                  evidence_ref="blind_oracle.json")
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE O - VERB TAMPERING ULTRA (read-only matrix)
# ---------------------------------------------------------------------------
def verb_matrix_ultra(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """HEAD/OPTIONS + method-override + read-action + Accept-downgrade - sab
    read-only, sirf attacker session se, bounded."""
    res = {"ran": False, "reason": "", "targets": [], "hits": [], "requests": 0}
    if not conf.get("access_allow_verb_matrix", True):
        res["reason"] = "gated off"
        return res
    a_name = _attacker_of(meta, idents)
    if not a_name:
        res["reason"] = "authenticated session nahi"
        return res
    att_cli = _fresh_identity(http, meta, a_name, "verb")
    # targets: admin/protected jo role-matrix me 403 hue the + admin hints
    blocked = [u for u in (ctx.get("matrix_403") or [])][:4]
    for h in ADMIN_PATH_HINTS:
        if len(blocked) >= 4:
            break
        for r in ranked or []:
            if r["url"].rstrip("/").endswith(h.rstrip("/")):
                blocked.append(r["url"])
                break
    if not blocked:
        _o = (_authorized_origins(scope) or [""])[0]
        blocked = [_o.rstrip("/") + u for u in PROTECTED_PATH_HINTS
                   if u.startswith("/api/")][:3]
    budget = int(conf.get("access_verb_probes", 8))
    for u in blocked:
        if res["requests"] >= budget or not scope.check_url(u, raise_on_fail=False):
            continue
        # baseline GET (attacker)
        rb = _safe_get(att_cli, u)
        res["requests"] += 1
        base_st = rb.status if rb else None
        if rb:
            _hdr_capture(ctx, u, rb.status, rb.headers)
        if base_st and base_st < 400:
            continue                       # pehle se accessible - verb test ka point nahi
        # 1) HEAD
        if res["requests"] < budget:
            try:
                r = att_cli.request("HEAD", u, allow_redirects=False)
            except Exception:
                r = None
            res["requests"] += 1
            if r is not None and r.status and r.status < 400 \
                    and len(r.text or "") > 0:
                res["hits"].append({"url": u, "vector": "HEAD", "status": r.status,
                                    "note": "HEAD par body/status leak"})
                F.add("verb_tampering_bypass", "HEAD verb par protected response", u,
                      "GET %s tha par HEAD %d (body %d bytes) - method-level "
                      "authz gap." % (base_st, r.status, len(r.text or "")),
                      evidence_ref="verb_matrix.json")
        # 2) OPTIONS allow surface
        if res["requests"] < budget:
            try:
                r = att_cli.request("OPTIONS", u, allow_redirects=False)
            except Exception:
                r = None
            res["requests"] += 1
            if r is not None and r.status and r.status < 400:
                allow = r.header("Allow") or r.header("Access-Control-Allow-Methods")
                if allow:
                    res["hits"].append({"url": u, "vector": "OPTIONS", "status": r.status,
                                        "allow": allow})
        # 3) X-HTTP-Method-Override GET->POST (read-only intent)
        if res["requests"] < budget:
            r = _safe_get(att_cli, u, headers={"X-HTTP-Method-Override": "POST"})
            res["requests"] += 1
            if r is not None and r.status and r.status < 400 and base_st in (401, 403):
                res["hits"].append({"url": u, "vector": "method-override",
                                    "status": r.status})
                F.add("method_override_bypass",
                      "X-HTTP-Method-Override accepted on protected endpoint", u,
                      "GET %s tha par override header ke saath %d - verb rules "
                      "override-se bypass ho sakte hain." % (base_st, r.status),
                      evidence_ref="verb_matrix.json")
        # 4) read-action param abuse
        if res["requests"] < budget:
            r = _safe_get(att_cli, u + ("&" if "?" in u else "?") + "action=list")
            res["requests"] += 1
            if r is not None and r.status and r.status < 400 and base_st in (401, 403):
                res["hits"].append({"url": u, "vector": "action-param",
                                    "status": r.status})
                F.add("verb_tampering_bypass", "action=list param par access mil gaya", u,
                      "GET %s tha par ?action=list %d - action-level authz ke bina "
                      "read path khulta hai." % (base_st, r.status),
                      evidence_ref="verb_matrix.json")
        # 5) Accept downgrade
        if res["requests"] < budget:
            r = _safe_get(att_cli, u, headers={"Accept": "text/plain"})
            res["requests"] += 1
            if r is not None and r.status and r.status < 400 and base_st in (401, 403):
                res["hits"].append({"url": u, "vector": "accept-downgrade",
                                    "status": r.status})
                F.add("verb_tampering_bypass", "Accept downgrade par access", u,
                      "JSON-only endpoint text/plain Accept par %d de gaya (base %s)."
                      % (r.status, base_st), evidence_ref="verb_matrix.json")
        res["targets"].append(u)
    res["ran"] = True
    ctx["verb_matrix"] = res
    return res


# ---------------------------------------------------------------------------
# STAGE P - BATCH / BULK IDOR (array over-fetch, read-only)
# ---------------------------------------------------------------------------
def batch_idor(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """ids[]/ids= style array params: single (own) vs own+victim array response
    diff. Victim IDs sirf config se (own accounts)."""
    res = {"ran": False, "reason": "", "probes": [], "requests": 0}
    if not conf.get("access_allow_batch_probe", True):
        res["reason"] = "gated off"
        return res
    a_name = _attacker_of(meta, idents)
    if not a_name:
        res["reason"] = "authenticated session nahi"
        return res
    markers_v, victim_ids = _victim_seed(conf, meta)
    if not victim_ids:
        res["reason"] = "victim known_ids config me nahi (apne 2nd test account ke IDs daalo)"
        return res
    att_cli = _fresh_identity(http, meta, a_name, "batch")
    budget = int(conf.get("access_batch_probes", 3))
    # batch-capable endpoints: query me ids-like collection param
    BATCH_PARAMS = ["ids", "ids[]", "id_list", "order_ids", "user_ids", "item_ids",
                    "object_ids", "record_ids", "product_ids"]
    targets = []
    for r in ranked or []:
        qk = [k.lower() for k, _ in urllib.parse.parse_qsl(
            urllib.parse.urlparse(r["url"]).query, keep_blank_values=True)]
        if any(k in BATCH_PARAMS for k in qk) and r["url"] not in targets:
            targets.append(r["url"])
        if len(targets) >= budget:
            break
    if not targets:
        # collection-expansion templates se list endpoints
        targets = [r["url"] for r in (ranked or [])
                   if re.search(r"(?i)/(orders|invoices|documents|tickets|messages)$",
                                urllib.parse.urlparse(r["url"]).path)][:budget]
    if not targets:
        res["reason"] = "batch-capable endpoint nahi mila"
        return res
    own_id = (meta[a_name].get("known_ids") or [victim_ids[0]])[0]
    other_ids = _others_ids(meta, a_name) or victim_ids
    for u in targets:
        if res["requests"] >= budget or not scope.check_url(u, raise_on_fail=False):
            continue
        p = urllib.parse.urlparse(u)
        qk = [k for k, _ in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
        key = next((k for k in qk if k.lower() in BATCH_PARAMS), "ids")
        base_u = u if key in qk else u + ("&" if "?" in u else "?") + "ids=" + str(own_id)
        rb = _safe_get(att_cli, base_u)
        res["requests"] += 1
        if rb is None or not rb.status or rb.status >= 400:
            continue
        _hdr_capture(ctx, base_u, rb.status, rb.headers)
        n_base = 0
        try:
            jb = json.loads(rb.text)
            n_base = len(jb) if isinstance(jb, list) else len(jb.get("items")
                                                            or jb.get("data") or [])
        except Exception:
            pass
        mixed = ",".join([str(own_id)] + other_ids[:2])
        mu = u + ("&" if "?" in u else "?") + key + "=" + urllib.parse.quote(mixed, safe=",")
        r = _safe_get(att_cli, mu)
        res["requests"] += 1
        if r is None or not r.status or r.status >= 400:
            continue
        _hdr_capture(ctx, mu, r.status, r.headers)
        hits = marker_hits(r.text or "", markers_v)
        n_mix = 0
        try:
            jm = json.loads(r.text)
            n_mix = len(jm) if isinstance(jm, list) else len(jm.get("items")
                                                             or jm.get("data") or [])
        except Exception:
            pass
        rec = {"endpoint": u, "param": key, "base_items": n_base, "mixed_items": n_mix,
               "markers_victim": hits[:4], "status": r.status,
               "verdict": "CONFIRMED" if (hits or n_mix > n_base) else "UNKNOWN"}
        res["probes"].append(rec)
        if rec["verdict"] == "CONFIRMED":
            F.add("batch_overfetch", "Batch/array param se cross-account over-fetch", u,
                  "%s=%s par %d items aaye (baseline %d), victim markers=%s - ek "
                  "request me multiple accounts ka data (rate-limit bypass bhi)."
                  % (key, mixed[:40], n_mix, n_base, ",".join(hits[:2]) or "n/a"),
                  evidence_ref="batch_idor.json")
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE Q - CHAINED OBJECT IDOR (mined IDs -> second-hop swap, depth 2)
# ---------------------------------------------------------------------------
def chained_idor(http, scope, F, ctx, conf, idents, meta, idor_results, cp):
    """Confirmed/suspected IDOR responses se related object IDs mine karo ->
    doosre templates par swap. Sirf OWN accounts ka data touch hota hai
    (victim IDs bhi config ke hain)."""
    res = {"ran": False, "reason": "", "hops": [], "requests": 0}
    if not conf.get("access_allow_chain_probe", True):
        res["reason"] = "gated off"
        return res
    a_name = _attacker_of(meta, idents)
    if not a_name:
        res["reason"] = "authenticated session nahi"
        return res
    att_cli = _fresh_identity(http, meta, a_name, "chain")
    markers_v, _vids = _victim_seed(conf, meta)
    hot = [(k, v) for k, v in (idor_results or {}).items()
           if v.get("verdict") in ("CONFIRMED", "SUSPECTED")][:3]
    if not hot:
        res["reason"] = "koi confirmed/suspected IDOR nahi -> chain seed nahi"
        return res
    other_templates = []
    ck_ids = "ultraQ:seed_ids"
    mined = cp.result_of(ck_ids) if cp.is_done(ck_ids) else None
    if mined is None:
        mined = []
        for _k, v in hot:
            u = v.get("swap_url") or v.get("url")
            if not u:
                continue
            r = _safe_get(att_cli, u)
            res["requests"] += 1
            if r is None or not r.status or r.status >= 400:
                continue
            _hdr_capture(ctx, u, r.status, r.headers)
            try:
                doc = json.loads(r.text)
                for rid in collect_ids_from_json(doc):
                    if rid not in mined:
                        mined.append(rid)
            except Exception:
                pass
        cp.mark(ck_ids, mined, summary="chain seeds")
    mined = [m for m in (mined or []) if m][:4]
    if not mined:
        res["reason"] = "IDOR responses me related IDs nahi mili"
        return res
    budget = int(conf.get("access_chain_probes", 6))
    for t in ctx.get("templates_all", []) or []:
        if res["requests"] >= budget:
            break
        if t["key"] in dict(hot) or not t["slots"]:
            continue
        for rid in mined:
            if res["requests"] >= budget:
                break
            u2 = swap_id(t["sample_url"], t["slots"][0][0], rid)
            if u2 == t["sample_url"] or not scope.check_url(u2, raise_on_fail=False):
                continue
            r = _safe_get(att_cli, u2)
            res["requests"] += 1
            if r is None or not r.status or r.status >= 400:
                continue
            _hdr_capture(ctx, u2, r.status, r.headers)
            hits = marker_hits(r.text or "", markers_v)
            rec = {"from_template": dict(hot)[next(iter(dict(hot)))].get("template", ""),
                   "seed_id": rid, "hop_url": u2, "status": r.status,
                   "markers": hits[:4],
                   "verdict": "CONFIRMED" if hits else "UNKNOWN"}
            res["hops"].append(rec)
            if hits:
                F.add("chained_idor_confirmed",
                      "Chained object IDOR (seed -> %s)" % t["key"], u2,
                      "IDOR'd response se nikla related ID '%s' doosre endpoint par "
                      "bhi attacker session se padha gaya (markers: %s) - object "
                      "graph par ownership checks missing." % (rid, ",".join(hits[:2])),
                      evidence_ref="chained_idor.json")
                break
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE R - FILE / EXPORT / DOWNLOAD IDOR
# ---------------------------------------------------------------------------
def file_access_idor(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """file_id/document/download/export endpoints par object-ID swap + garbage
    probe + Content-Disposition sniff. Path traversal NAHI (P12 ka kaam)."""
    res = {"ran": False, "reason": "", "targets": [], "hits": [], "requests": 0}
    if not conf.get("access_allow_file_idor", True):
        res["reason"] = "gated off"
        return res
    a_name = _attacker_of(meta, idents)
    if not a_name:
        res["reason"] = "authenticated session nahi"
        return res
    markers_v, victim_ids = _victim_seed(conf, meta)
    att_cli = _fresh_identity(http, meta, a_name, "file")
    budget = int(conf.get("access_file_probes", 6))
    FILE_RE = re.compile(r"(?i)(file_id|doc_id|document_id|download|export|attachment|"
                         r"statement|report_id|/files?/|/documents?/|invoice_id)")
    targets = []
    for r in ranked or []:
        if FILE_RE.search(r["url"]) and r["url"] not in targets:
            targets.append(r["url"])
        if len(targets) >= 4:
            break
    if not targets:
        res["reason"] = "file/export surface nahi mila"
        return res
    own_id = (meta[a_name].get("known_ids") or victim_ids[:1] or ["1"])[0]
    other_ids = _others_ids(meta, a_name)
    for u in targets:
        if res["requests"] >= budget or not scope.check_url(u, raise_on_fail=False):
            continue
        slots = collect_ids_from_url(u)
        if not slots:
            continue
        old_id, _w = slots[0]
        probe_list = []
        if other_ids:
            probe_list.append(("swap", swap_id(u, old_id, other_ids[0])))
        probe_list.append(("garbage", swap_id(u, old_id, "wasp-file-9999999")))
        for tag, u2 in probe_list:
            if res["requests"] >= budget:
                break
            r = _safe_get(att_cli, u2)
            res["requests"] += 1
            if r is None or not r.status:
                continue
            _hdr_capture(ctx, u2, r.status, r.headers)
            cd = r.header("Content-Disposition", "")
            hits = marker_hits(r.text or "", markers_v)
            if tag == "garbage":
                continue                    # garbage sirf baseline/oracle ke liye
            if hits or (cd and "attachment" in cd.lower() and r.status == 200
                        and old_id != (other_ids[0] if other_ids else old_id)):
                rec = {"endpoint": u, "probe": u2, "status": r.status,
                       "content_disposition": cd[:120], "markers": hits[:4],
                       "verdict": "CONFIRMED" if hits else "SUSPECTED"}
                res["hits"].append(rec)
                F.add("file_idor_confirmed" if hits else "blind_idor_existence_oracle",
                      "File/export cross-account access (%s)" % (rec["verdict"]), u2,
                      "File object ID %s par attacker session se %d response%s "
                      "(markers=%s) - document-level authz missing."
                      % (other_ids[0] if other_ids else old_id, r.status,
                         (" CD=%s" % cd[:60]) if cd else "",
                         ",".join(hits[:2]) or "n/a"),
                      evidence_ref="file_idor.json")
        res["targets"].append(u)
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE S - SHARE-LINK / INVITE SURFACE
# ---------------------------------------------------------------------------
def share_surface(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """Share/invite/public-token endpoints: token entropy-lite + cross-account
    READ (sirf apne doosre test account se)."""
    res = {"ran": False, "reason": "", "tokens": [], "cross": None, "requests": 0}
    if not conf.get("access_allow_share_probe", True):
        res["reason"] = "gated off"
        return res
    budget = int(conf.get("access_share_probes", 5))
    SHARE_RE = re.compile(r"(?i)(/share|/invite|/public/|/s/|share_token=|"
                          r"invite_code=|access_token=|public_token=)")
    urls = []
    for r in ranked or []:
        if SHARE_RE.search(r["url"]) and r["url"] not in urls:
            urls.append(r["url"])
        if len(urls) >= 4:
            break
    if not urls:
        res["reason"] = "share/invite surface nahi mila"
        return res
    # token values mine karo observed URLs se
    toks = []
    for u in urls:
        for k, v in urllib.parse.parse_qsl(urllib.parse.urlparse(u).query,
                                           keep_blank_values=True):
            if any(t in k.lower() for t in ("token", "code", "invite")) and v \
                    and len(v) >= 4 and v not in toks:
                toks.append(v)
    for t in (conf.get("access_victim_known_ids") or []):
        if len(str(t)) >= 6 and str(t) not in toks:
            toks.append(str(t))
    toks = toks[:6]
    res["tokens"] = toks
    # entropy-lite + sequential detect
    if len(toks) >= 2:
        ents = [round(shannon_entropy(t), 2) for t in toks]
        same_prefix = len({t[:3] for t in toks}) <= 2
        weak = (min(ents) < 2.8) or (same_prefix and len({t[3:6] for t in toks}) <= 2)
        if weak:
            F.add("share_token_weak", "Share/invite token low-entropy/sequential",
                  urls[0], "Observed tokens: entropy=%s, shared-prefix=%s - tokens "
                  "guessable ho sakte hain (sirf observed values se analysis, "
                  "enumeration nahi)." % (ents[:3], same_prefix),
                  evidence_ref="share_surface.json")
    # cross-account READ: doosra own session share URL kholo
    other = [n for n, m in (meta or {}).items() if m.get("priv") not in ("anon",)]
    if len(other) >= 2 and urls and res["requests"] < budget:
        reader = _fresh_identity(http, meta, other[1], "share")
        r = _safe_get(reader, urls[0])
        res["requests"] += 1
        if r is not None and r.status and r.status < 400:
            _hdr_capture(ctx, urls[0], r.status, r.headers)
            hits = marker_hits(r.text or "", meta[other[0]].get("markers") or [])
            if hits:
                res["cross"] = {"url": urls[0], "reader": other[1],
                                "owner_markers": hits[:4], "status": r.status,
                                "verdict": "CONFIRMED"}
                F.add("share_cross_account_access",
                      "Share resource doosre account se access ho gaya", urls[0],
                      "'%s' ke markers share-URL par '%s' session me dikh gaye - "
                      "share object par ownership/authz check missing."
                      % (other[0], other[1]), evidence_ref="share_surface.json")
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE T - API KEY / TOKEN SCOPE CONFUSION (own accounts only)
# ---------------------------------------------------------------------------
def token_scope_confusion(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """Apne hi do test accounts ke auth materials cross-use: A-cookie + B-header
    (Authorization/X-API-Key) -> identity precedence + scope binding test."""
    res = {"ran": False, "reason": "", "tests": [], "requests": 0}
    if not conf.get("access_allow_scope_probe", True):
        res["reason"] = "gated off"
        return res
    authed = [n for n, m in (meta or {}).items()
              if m.get("priv") not in ("anon",) and m.get("cookie_header")]
    if len(authed) < 2:
        res["reason"] = "2+ accounts (cookie/headers ke saath) chahiye scope test ke liye"
        return res
    budget = int(conf.get("access_scope_probes", 4))
    # protected targets: /me/profile-style (identity echo) top 2 - origin-prefixed
    _o = (_authorized_origins(scope) or [""])[0]
    targets = [_o.rstrip("/") + p for p in PROTECTED_PATH_HINTS
               if any(x in p for x in ("/me", "whoami", "profile", "account"))][:3]
    if not targets:
        targets = [_o.rstrip("/") + p for p in PROTECTED_PATH_HINTS][:2]
    a_name, b_name = authed[0], authed[1]
    for u in targets:
        if res["requests"] >= budget or not scope.check_url(u, raise_on_fail=False):
            continue
        ra = _safe_get(_fresh_identity(http, meta, a_name, "scope"), u)
        res["requests"] += 1
        if ra is None or not ra.status or ra.status >= 400:
            continue
        _hdr_capture(ctx, u, ra.status, ra.headers)
        mk_a = meta[a_name].get("markers") or []
        mk_b = meta[b_name].get("markers") or []
        if not mk_a and not mk_b:
            continue
        # confusion: B-cookie identity + A ki auth headers
        bm = meta[b_name]
        b_cli = _fresh_identity(http, meta, b_name, "scope")
        extra = {}
        for hk in ("Authorization", "X-API-Key", "X-Auth-Token", "Api-Key"):
            if hk in (bm.get("headers") or {}):
                continue
            av = (meta[a_name].get("headers") or {}).get(hk)
            if av:
                extra[hk] = av
        if not extra:
            # A ke headers me kuch auth-material nahi -> cookie-header swap hi test
            ab_mix = http.identity("access:scope:mix:%s" % a_name,
                                   headers=dict(bm.get("headers") or {}),
                                   cookie_header=meta[a_name].get("cookie_header"))
        else:
            ab_mix = http.identity("access:scope:mix:%s" % a_name,
                                   headers={**dict(bm.get("headers") or {}), **extra},
                                   cookie_header=meta[b_name].get("cookie_header"))
        r = _safe_get(ab_mix, u)
        res["requests"] += 1
        if r is None or not r.status or r.status >= 400:
            continue
        _hdr_capture(ctx, u, r.status, r.headers)
        hits_a = marker_hits(r.text or "", mk_a)
        hits_b = marker_hits(r.text or "", mk_b)
        rec = {"endpoint": u, "mixed_identity": "%s-cookie+%s-headers" % (b_name, a_name),
               "markers_a": hits_a[:3], "markers_b": hits_b[:3], "status": r.status}
        res["tests"].append(rec)
        if hits_a and hits_b:
            F.add("token_scope_confusion",
                  "Mixed identity accepted (token precedence inconsistent)", u,
                  "Cookie(%s) + headers(%s) dono ke markers response me - auth "
                  "precedence mixed hai; scope binding endpoints par verify karo."
                  % (b_name, a_name), evidence_ref="token_scope.json")
        elif hits_a:
            F.add("token_scope_confusion",
                  "Header token ne cookie identity override kar diya", u,
                  "B-cookie + A-header par response A ke markers dikhata hai (%s) - "
                  "token-to-identity binding cookie par nahi." % ",".join(hits_a[:2]),
                  evidence_ref="token_scope.json")
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE U - SEARCH / FILTER EXPOSURE + PAGINATION OVER-EXPOSURE
# ---------------------------------------------------------------------------
def search_exposure(http, scope, F, ctx, conf, idents, meta, ranked, cp):
    """Search/filter endpoints par APNE test markers se query -> cross-account
    leak oracle + limit-max single probe (koi enumeration loop nahi)."""
    res = {"ran": False, "reason": "", "probes": [], "pagination": [], "requests": 0}
    if not conf.get("access_allow_search_probe", True):
        res["reason"] = "gated off"
        return res
    a_name = _attacker_of(meta, idents)
    if not a_name:
        res["reason"] = "authenticated session nahi"
        return res
    att_cli = _fresh_identity(http, meta, a_name, "search")
    others = [n for n in (meta or {}) if n != a_name
              and meta[n].get("priv") not in ("anon",)]
    budget = int(conf.get("access_search_probes", 4))
    SEARCH_RE = re.compile(r"(?i)([?&](q|query|search|filter|find|keyword|term)=|"
                           r"/search|/find)")
    s_urls = []
    for r in ranked or []:
        if SEARCH_RE.search(r["url"]) and r["url"] not in s_urls:
            s_urls.append(r["url"])
        if len(s_urls) >= 3:
            break
    if not s_urls:
        res["reason"] = "search/filter endpoint nahi mila"
        return res
    # 1) marker-based leak probe (victim = OWN 2nd account ke markers)
    for u in s_urls:
        if res["requests"] >= budget - 1 or not scope.check_url(u, raise_on_fail=False):
            continue
        p = urllib.parse.urlparse(u)
        existing = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
        qkey = next((k for k, _ in existing if k.lower() in
                     ("q", "query", "search", "keyword", "term", "filter")), None)
        if qkey is None:
            qkey = "q"
            base_pairs = existing + [("q", "wasp-baseline-x")]
        else:
            base_pairs = [(k, ("wasp-baseline-x" if k == qkey else v))
                          for k, v in existing]
        rb = _safe_get(att_cli, urllib.parse.urlunparse(
            (p.scheme, p.netloc, p.path, p.params, urllib.parse.urlencode(base_pairs),
             p.fragment)))
        res["requests"] += 1
        if rb is None or not rb.status or rb.status >= 400:
            continue
        _hdr_capture(ctx, u, rb.status, rb.headers)
        for o in others[:1]:
            mk = meta[o].get("markers") or []
            term = mk[0] if mk else None
            if not term:
                continue
            pairs = [(k, (term if k == qkey else v)) for k, v in existing] \
                if existing else [(qkey, term)]
            r = _safe_get(att_cli, urllib.parse.urlunparse(
                (p.scheme, p.netloc, p.path, p.params, urllib.parse.urlencode(pairs),
                 p.fragment)))
            res["requests"] += 1
            if r is None or not r.status or r.status >= 400:
                continue
            hits = marker_hits(r.text or "", mk)
            if hits:
                res["probes"].append({"endpoint": u, "term": term,
                                      "markers": hits[:4], "status": r.status,
                                      "verdict": "CONFIRMED"})
                F.add("search_cross_account_leak",
                      "Search se dusre account ka data response me", u,
                      "Search term (apne test account '%s' ka marker) se results me "
                      "unki identity/markers aa gaye - search results par object-level "
                      "authz missing." % o, evidence_ref="search_exposure.json")
            break
    # 2) pagination limit-max (single probe per endpoint, max 2)
    list_eps = [r["url"] for r in (ranked or [])
                if re.search(r"(?i)/(orders|invoices|documents|tickets|users|items|"
                             r"messages|payments)($|\?)", r["url"])][:2]
    for u in list_eps:
        if res["requests"] >= budget:
            break
        if not scope.check_url(u, raise_on_fail=False):
            continue
        for pk in ("limit", "page_size", "per_page", "size", "pageSize"):
            if res["requests"] >= budget:
                break
            p0 = urllib.parse.urlparse(u)
            qs0 = [(k, ("9999" if k == pk else v)) for k, v in
                   urllib.parse.parse_qsl(p0.query, keep_blank_values=True)]
            if not any(k == pk for k, _ in qs0):
                qs0.append((pk, "9999"))
            pu = urllib.parse.urlunparse((p0.scheme, p0.netloc, p0.path, p0.params,
                                          urllib.parse.urlencode(qs0), p0.fragment))
            r = _safe_get(att_cli, pu)
            res["requests"] += 1
            if r is None or not r.status or r.status >= 400:
                continue
            _hdr_capture(ctx, u, r.status, r.headers)
            n = 0
            try:
                j = json.loads(r.text)
                n = len(j) if isinstance(j, list) else len(j.get("items")
                                                           or j.get("data") or [])
            except Exception:
                pass
            if n >= 50:
                res["pagination"].append({"endpoint": u, "param": pk, "items": n})
                F.add("pagination_overexposure",
                      "Pagination limit-max par poora dataset (%d items)" % n, u,
                      "%s=9999 par single response me %d items - result-set "
                      "controls weak (mass-scrape friendly)." % (pk, n),
                      evidence_ref="search_exposure.json")
                break
    res["ran"] = True
    return res


# ---------------------------------------------------------------------------
# STAGE V - AUTHZ RESPONSE HYGIENE (0 requests - ULTRA captures se offline)
# ---------------------------------------------------------------------------
def authz_hygiene_offline(F, ctx, cp):
    """ULTRA stages ke captured 200-on-protected headers se offline derivation:
    Cache-Control missing / weak CORS / Referrer-Policy missing."""
    res = {"ran": False, "reason": "", "missing_cache": [], "weak_cors": [],
           "missing_referrer": []}
    caps = (ctx.get("ultra_header_cache") or [])[:80]
    if not conf_hygiene_ok(ctx):
        res["reason"] = "koi ULTRA header capture nahi (active probes nahi chale)"
        return res
    for c in caps:
        cc = (c.get("cache_control") or "").lower()
        if not any(x in cc for x in ("no-store", "private", "no-cache", "max-age=0")):
            res["missing_cache"].append(c["url"])
        acao, acac = c.get("acao") or "", c.get("acac") or ""
        if acao == "*" or (acao and acac.lower() == "true"):
            res["weak_cors"].append({"url": c["url"], "acao": acao, "acac": acac})
        if not (c.get("referrer_policy") or "").strip():
            res["missing_referrer"].append(c["url"])
    dedup = lambda xs: list(dict.fromkeys(xs))
    res["missing_cache"], res["missing_referrer"] = dedup(res["missing_cache"])[:10], \
        dedup(res["missing_referrer"])[:10]
    if res["missing_cache"]:
        F.add("authz_cache_hygiene",
              "Authz'd responses par cache-control missing (%d endpoints)"
              % len(res["missing_cache"]), res["missing_cache"][0],
              "Object/protected 200 responses me Cache-Control: no-store/private "
              "nahi - shared cache capture ka risk (chain: batch-overfetch + cache).",
              evidence_ref="authz_hygiene.json")
    if res["weak_cors"]:
        F.add("authz_cache_hygiene",
              "Object endpoints par permissive CORS", res["weak_cors"][0]["url"],
              "ACAO=%s (ACAC=%s) authz'd response par - cross-origin read surface."
              % (res["weak_cors"][0]["acao"], res["weak_cors"][0]["acac"]),
              evidence_ref="authz_hygiene.json")
    res["ran"] = True
    return res


def conf_hygiene_ok(ctx):
    return bool(ctx.get("ultra_header_cache"))


# ---------------------------------------------------------------------------
# HYPOTHESES + KILL TESTS (Phase 8/9/10 methodology)
# ---------------------------------------------------------------------------
def build_hypotheses(F, ctx):
    H = []

    def add(hid, statement, because, kill, nxt):
        H.append({"id": hid, "hypothesis": statement, "because": because,
                  "kill_test": kill, "next_phase": nxt})

    for key, rec in (ctx.get("idor_results") or {}).items():
        v = rec.get("verdict")
        if v in ("CONFIRMED", "SUSPECTED"):
            add("H-IDOR-%s" % sha1(key)[:4],
                "Template '%s' par object-level ownership check missing hai" % key,
                rec.get("reason", ""),
                "victim ID ko VICTIM session se access karo; agar victim session bhi 403/404 "
                "de to template session-type ke liye protected hai -> REJECT. Aur do garbage IDs "
                "bhejo - dono 200 aaye to soft-404 hai -> REJECT.", "17-api")
        elif v == "ENUM_HINT":
            add("H-ENUM-%s" % sha1(key)[:4],
                "'%s' object existence oracle deta hai" % key,
                rec.get("reason", ""),
                "5 garbage IDs ko 3x bhejo; agar koi bhi 200 de to soft-404 template hai -> REJECT.",
                "17-api")
    for u, rec in (ctx.get("bypass") or {}).items():
        if rec.get("bypass"):
            add("H-BYP-%s" % sha1(u)[:4],
                "%s ka authorization edge par enforce hota hai (bypass possible)" % u,
                rec.get("technique", ""),
                "Bypass request ko 2x aur bhejo + bina-trick control bhejo; agar control bhi 200 "
                "de (baseline hi galat tha) ya result flaky ho -> REJECT.", "17-api")
    for u, row in _matrix_rows(ctx):
        if row.get("anon_200_admin"):
            add("H-ANON-%s" % sha1(u)[:4],
                "%s par authentication hi missing hai" % u,
                "anon session ne 200 liya",
                "Aur 2 baar no-cookie GET bhejo + Set-Cookie/Location dhyan se dekho; agar "
                "login-redirect ya consistent 401/403 mile to REJECT.", "16-logic")
    gq = ctx.get("graphql") or {}
    if gq.get("bola"):
        add("H-GQL-%s" % sha1(str(gq.get("bola")))[:4],
            "GraphQL type '%s' par object authz missing hai" % gq["bola"].get("type"),
            "ID swap par victim markers mile",
            "Usi query ko victim ID ke bina (apni ID) bhejo; agar ownership server-side "
            "filter ho raha ho to data alag hoga -> REJECT.", "18-graphql")
    if (ctx.get("mass_assignment") or {}).get("probes"):
        add("H-MASSASSIGN-01", "Profile/update endpoint privilege fields accept karta hai",
            "marker value echo hui",
            "GET read-back karo; agar value persist nahi hui to sirf echo tha -> severity Info "
            "karo ya REJECT.", "16-logic")
    return H


def _matrix_rows(ctx):
    """role_matrix se anon-200-admin rows nikaalo (hypotheses ke liye)."""
    rows = {}
    m = ctx.get("role_matrix") or {}
    for s, eps in m.items():
        if s != "anon":
            continue
        for u, st in (eps or {}).items():
            if st == 200 and ADMIN_PATH_RE.search(urllib.parse.urlparse(u).path):
                rows[u] = {"anon_200_admin": True}
    return rows.items()


# ---------------------------------------------------------------------------
# REPORTS
# ---------------------------------------------------------------------------
def write_reports(out, scope, F, ctx, hypotheses, conf):
    save_json(os.path.join(out, "findings.json"),
              {"engagement": scope.engagement, "phase": PHASE, "plan_version": PLAN_VERSION,
               "generated_at": now_iso(), "count": len(F.items), "findings": F.items})

    md = ["# Phase 11 - Access Control / IDOR / BOLA Findings", "",
          "- **Engagement:** `%s`" % scope.engagement,
          "- **Generated:** `%s`" % now_iso(),
          "- **Engine:** WASP v%s / access plan v%s" % (VERSION, PLAN_VERSION),
          "- **Findings:** `%d`" % len(F.items), ""]
    if not F.items:
        md.append("Is bounded, read-only run me koi access-control weakness **confirm** nahi "
                  "hui. Ise 'secure' mat samjho - `access_test_plan.md` ke hypotheses manually "
                  "verify karo aur 2-account setup (`python3 mod_access.py wizard`) ke saath "
                  "dobara chalao.")
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
    save_text(os.path.join(out, "ACCESS_FINDINGS.md"), "\n".join(md) + "\n")

    # test plan (hypotheses + kill tests + coverage)
    cov = ctx.get("coverage", {})
    L = ["# Phase 11 - Access Control Test Plan", "",
         "**Engagement:** `%s`  |  **Generated:** `%s`" % (scope.engagement, now_iso()),
         "",
         "> Bounded, read-only-default testing. Har hypothesis ka KILL TEST hai -",
         "> kill-test pass ho jaye to hypothesis REJECT karo (false-positive guard).", ""]
    L += ["## Hypotheses + kill-tests", ""]
    if hypotheses:
        for h in hypotheses:
            L += ["### %s" % h["id"], "",
                  "- **HYPOTHESIS:** %s" % h["hypothesis"],
                  "- **BECAUSE:** %s" % h["because"],
                  "- **KILL TEST:** %s" % h["kill_test"],
                  "- **NEXT PHASE:** `%s`" % h["next_phase"], ""]
    else:
        L += ["_Koi hypothesis nahi bani (koi signal nahi mila)._"]
    L += ["## Coverage matrix", "", "| Control | Status |", "|---|---|"]
    for k, v in cov.items():
        L.append("| %s | %s |" % (k, v))
    L += ["", "## Limitations",
          "- Ye module **read-only default** hai: mass assignment / PUT-DELETE probes sirf "
          "`access_allow_write_probes=true` par chalte hain.",
          "- IDOR full-confirm ke liye **2 accounts** chahiye (access_sessions config) - "
          "single-account mode sirf ENUM_HINT tak jata hai.",
          "- Response-similarity heuristics hain - CONFIRMED bhi manually Burp me verify karo.",
          "- PII evidence me REDACTED store hota hai; raw bodies evidence/raw/ me hain "
          "(save_bodies config par depend).", ""]
    save_text(os.path.join(out, "access_test_plan.md"), "\n".join(L) + "\n")

    # matrix grid
    lines = ["ACCESS MATRIX (session x endpoint)", "=" * 72]
    m = ctx.get("role_matrix") or {}
    eps = sorted({u for eps in m.values() for u in eps})
    if eps:
        header = "%-12s" % "session" + "".join("%-14s" % (urllib.parse.urlparse(u).path[-13:] or "/")
                                               for u in eps[:12])
        lines.append(header)
        for s, eps2 in m.items():
            lines.append("%-12s" % s + "".join("%-14s" % str(eps2.get(u, "-")) for u in eps[:12]))
        lines.append("")
        lines.append("legend: 200/201 readable | 401/403 blocked | 302 redirect | None no-response")
    else:
        lines.append("(matrix nahi bana - sessions ya endpoints nahi mile)")
    save_text(os.path.join(out, "ACCESS_MATRIX.txt"), "\n".join(lines) + "\n")

    # chains
    ch = ["ACCESS-CONTROL CHAINS (hypotheses, proof nahi)", "=" * 72, ""]
    confirmed = [f for f in F.items if f["severity"] in ("Critical", "High")]
    for cid, title, desc, route in CHAIN_HINTS:
        relevant = bool(confirmed) or cid == "CHAIN-MASSASSIGN"
        ch.append("%s - %s [%s]" % (cid, title, "RELEVANT" if relevant else "background"))
        ch.append("  %s" % desc)
        ch.append("  route: %s" % route)
        ch.append("")
    if confirmed:
        ch.append("High/Critical findings jo chains me feed ho sakte hain:")
        for f in confirmed[:10]:
            ch.append("  - %s (%s) %s" % (f["id"], f["severity"], f["title"]))
    save_text(os.path.join(out, "access_chains.txt"), "\n".join(ch) + "\n")


# ---------------------------------------------------------------------------
# MAIN RUN (wasp.py entrypoint)
# ---------------------------------------------------------------------------
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 11 - Access Control / IDOR / BOLA (v%s) | %s" % (PLAN_VERSION, scope.describe()))
    n_sess = len(conf.get("access_sessions") or [])
    if n_sess < 2:
        warn("sirf %d session(s) configured - full 2-account IDOR ke liye doosra account bhi "
             "daalo: python3 mod_access.py wizard" % n_sess)
    if conf.get("access_allow_write_probes"):
        warn("WRITE PROBES ENABLED (access_allow_write_probes=true) - mass-assignment/method "
             "probes state change kar sakte hain. RoE me allowed hona chahiye.")

    F = Findings()
    ctx = {"collected_ids": set(), "coverage": {}}

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Access surface discovery (P10/P8/P7/P5 mining + hints)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], [])
        ranked, gql_cands = cached[0], cached[1]
        ok("Replayed %d candidates (checkpoint)" % len(ranked))
    else:
        ranked, gql_cands = discover_access_surface(base_out, scope, conf)
        cp.mark(ckA, [ranked, gql_cands], summary="access surface")
    if not ranked:
        err("Koi access-surface candidate nahi mila. P2-P10 pehle chalao ya scope.json check karo.")
        ctx["coverage"]["access surface discovery"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx, [], conf)
        return out
    ok("%d access-surface candidates (priority order)" % len(ranked))
    ctx["ranked"] = ranked
    save_text(os.path.join(out, "access_endpoints.txt"),
              "\n".join("%-6s %-18s %s" % (r.get("priority"), r.get("source"), r["url"])
                        for r in ranked))
    src_counts = {}
    for r in ranked:
        src_counts[r.get("source")] = src_counts.get(r.get("source"), 0) + 1
    info("sources: %s" % ", ".join("%s=%d" % kv for kv in sorted(src_counts.items())))

    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: discovery + manual-template parse + "
             "offline ID intel (0 network probes).")
        ctx["coverage"]["access surface discovery"] = "%d endpoints" % len(ranked)
        # FIX-3: manual Burp requests ka OFFLINE parse (koi verification request nahi)
        passive_templates = []
        origin = (_authorized_origins(scope) or [""])[0]
        for raw in conf.get("access_manual_requests") or []:
            rec = parse_raw_request(raw, default_origin=origin)
            if rec and scope.check_url(rec["url"], raise_on_fail=False):
                passive_templates.append(rec)
        save_json(os.path.join(out, "access_templates_passive.json"),
                  {"templates": [{"key": template_key(t["method"], t["url"]),
                                  "method": t["method"], "url": t["url"],
                                  "id_slots": [s[0] for s in (t.get("slots") or [])]}
                                 for t in passive_templates],
                   "note": "allow_active=false - verification ke liye active run chalao "
                           "(python3 wasp.py run --module 11)"})
        # offline ID intel (0 requests): known ids ka type/decode analysis
        intel_off = {"ids": [], "note": "passive offline decode (no network)"}
        for kid in (conf.get("access_victim_known_ids") or [])[:12]:
            intel_off["ids"].append({"id": str(kid), "type": id_type(str(kid)),
                                     "decoded": smart_decode(str(kid))})
        save_json(os.path.join(out, "id_intelligence.json"), intel_off)
        intel_findings(F, intel_off)
        ctx["coverage"]["passive offline intel"] = "%d known ids" % len(intel_off["ids"])
        write_reports(out, scope, F, ctx, [], conf)
        write_feedforward(out, "11-access", {
            "to_phase17_api": {"discovered_endpoints": len(ranked),
                               "manual_templates": len(passive_templates)},
            "to_phase32_report": {"mode": "passive"}},
            notes=["allow_active=false -> passive run (discovery + offline only)"])
        write_manifest(out, "11-access", ["access_endpoints.txt", "findings.json",
                                          "access_templates_passive.json",
                                          "id_intelligence.json",
                                          "access_test_plan.md", "feedforward.json"],
                       stats={"mode": "passive", "candidates": len(ranked),
                              "manual_templates": len(passive_templates),
                              "findings": len(F.items)})
        return out

    # ---------------- Stage B: identities ----------------
    head("Stage B - Identity & session setup")
    idents, meta = build_identities(http, conf)
    live, status_map = liveness_probe(http, idents, meta, ranked, conf)
    ctx["sessions"] = live
    save_json(os.path.join(out, "access_sessions.json"),
              {"sessions": live, "configured": n_sess,
               "note": "markers/known_ids ke sath 2+ accounts = full IDOR proof"})

    # ---------------- Stage C: templates ----------------
    head("Stage C - Template extraction (manual imports + ID-shaped endpoints)")
    ckC = "stageC:templates"
    if cp.is_done(ckC):
        templates = cp.result_of(ckC) or []
    else:
        templates = extract_templates(http, scope, ranked, conf, idents, meta)
        cp.mark(ckC, templates, summary="templates")
    if not templates:
        warn("koi ID-shaped template nahi mila (manual Burp request import karo: "
             "config access_manual_requests ya wizard option 3)")
    ctx["coverage"]["template extraction"] = "%d templates" % len(templates) if templates else "none"
    ctx["templates_all"] = templates

    # ---------------- Stage D: IDOR engine ----------------
    head("Stage D - IDOR/BOLA engine (two-account differential)")
    if templates:
        idor_results = idor_engine(http, scope, F, ctx, conf, templates, idents, meta, cp)
    else:
        idor_results = {}
    save_json(os.path.join(out, "idor_verdicts.json"), idor_results)
    ctx["coverage"]["idor/bola differential"] = ("%d templates tested" % len(idor_results)
                                                 if idor_results else "no templates")

    # ---------------- Stage E: role matrix ----------------
    head("Stage E - Vertical role matrix (sessions x admin endpoints)")
    ckE = "stageE:matrix"
    if cp.is_done(ckE):
        cached = cp.result_of(ckE) or {}
        matrix = cached.get("matrix") or {}
        followed = {(a, b): fl for a, b, fl in (cached.get("followed") or [])}
        anon_login = dict(cached.get("anon_login") or {})
        ok("Replayed role matrix (checkpoint)")
    else:
        matrix, followed, anon_login = role_matrix(http, scope, ctx, conf, ranked,
                                                   idents, meta)
        cp.mark(ckE, {"matrix": matrix,
                      "followed": [[s, u, fl] for (s, u), fl in followed.items()],
                      "anon_login": anon_login}, summary="role matrix")
    matrix_findings(F, ctx, meta, matrix, followed, anon_login)
    # ULTRA stage-O targets: authed sessions ke 401/403 wale protected URLs
    ctx["matrix_403"] = sorted({u for _s, eps in (matrix or {}).items() if _s != "anon"
                                for u, st in (eps or {}).items() if st in (401, 403)})
    save_json(os.path.join(out, "access_matrix.json"),
              {"matrix": matrix, "meta": {k: {kk: vv for kk, vv in v.items()
                                              if kk != "cookie_header"}
                                          for k, v in meta.items()}})
    ctx["coverage"]["vertical role matrix"] = ("%d endpoints x %d sessions"
                                               % (len({u for eps in matrix.values() for u in eps}),
                                                  len(matrix)) if matrix else "no admin endpoints")

    # ---------------- Stage F: id intelligence ----------------
    head("Stage F - ID intelligence (decode / hash-crack / neighbour probe)")
    ckF = "stageF:intel"
    if cp.is_done(ckF):
        intel = cp.result_of(ckF) or {}
        ok("Replayed id intelligence (checkpoint)")
    else:
        intel = id_intelligence(http, scope, ctx, conf, templates, idents, meta,
                                idor_results)
        cp.mark(ckF, intel, summary="id intelligence")
    intel_findings(F, intel)
    save_json(os.path.join(out, "id_intelligence.json"), intel)
    ctx["coverage"]["id intelligence"] = "%d IDs analysed" % len(intel.get("ids", []))

    # ---------------- Stage G: 403 bypass ----------------
    head("Stage G - 403 bypass matrix (path variants x header tricks)")
    bypass = bypass_403(http, scope, F, ctx, conf, ranked, idents, meta, cp)
    save_json(os.path.join(out, "bypass_403.json"), bypass)
    ctx["coverage"]["403 bypass matrix"] = ("%d targets, %d requests"
                                            % (len(bypass), ctx.get("bypass_requests", 0))
                                            if bypass else "no 403 targets")

    # ---------------- Stage H: GraphQL ----------------
    head("Stage H - GraphQL BOLA (introspection + ID-arg swap)")
    gql = graphql_bola(http, scope, F, ctx, conf, idents, meta, gql_cands, cp)
    save_json(os.path.join(out, "graphql_bola.json"), gql)
    ctx["coverage"]["graphql bola"] = ("%d live endpoint(s)" % len(gql.get("endpoints_live", []))
                                       if gql.get("endpoints_live") else "not found")

    # ---------------- Stage I: mass assignment (gated) ----------------
    head("Stage I - Mass assignment probe (gated)")
    ma = mass_assignment_probe(http, scope, F, ctx, conf, templates, idents, meta)
    save_json(os.path.join(out, "mass_assignment.json"), ma)
    ctx["coverage"]["mass assignment"] = ("probed" if ma.get("ran")
                                          else ma.get("reason", "gated off"))

    # ---------------- Stage J: method matrix ----------------
    head("Stage J - Method matrix (OPTIONS/HEAD; writes gated)")
    mm = method_matrix(http, scope, F, ctx, conf, ranked, idents, meta)
    save_json(os.path.join(out, "method_matrix.json"), mm)
    ctx["coverage"]["method matrix"] = "%d endpoints" % len(mm)

    # ULTRA stage result holders (unconditional init - feedforward safe)
    gql_deep, tenant, blind, verb, batch, chained, filex = {}, {}, {}, {}, {}, {}, {}
    share, scopes, searchx, hygiene = {}, {}, {}, {}

    # ---------------- Stage L: GraphQL ULTRA (deep read-only) ----------------
    if conf.get("access_allow_gql_deep", True):
        head("Stage L - GraphQL ULTRA (introspection bypass / alias BOLA / batching)")
        gql_deep = graphql_ultra(http, scope, F, ctx, conf, idents, meta, gql, cp)
        save_json(os.path.join(out, "gql_ultra.json"), gql_deep)
        ctx["coverage"]["graphql ultra"] = (
            "%d endpoints, %d bypass, alias=%s, batch=%s"
            % (len(gql_deep.get("endpoints") or []),
               len(gql_deep.get("introspection_bypass") or []),
               (gql_deep.get("alias_bola") or {}).get("verdict", "-"),
               "yes" if (gql_deep.get("batching") or {}).get("accepted") else "-"))
    else:
        save_json(os.path.join(out, "gql_ultra.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["graphql ultra"] = "gated off"

    # ---------------- Stage M: tenant/workspace isolation ----------------
    if conf.get("access_allow_tenant_probe", True):
        head("Stage M - Tenant/workspace isolation (own accounts only)")
        tenant = tenant_isolation(http, scope, F, ctx, conf, idents, meta, ranked, cp)
        save_json(os.path.join(out, "tenant_isolation.json"), tenant)
        ctx["coverage"]["tenant isolation"] = (
            "%d swaps tested" % len(tenant.get("swaps") or [])) \
            if tenant.get("ran") else (tenant.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "tenant_isolation.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["tenant isolation"] = "gated off"

    # ---------------- Stage N: blind IDOR oracle ----------------
    if conf.get("access_allow_blind_oracle", True):
        head("Stage N - Blind IDOR oracle (real vs garbage differential)")
        blind = blind_oracle(http, scope, F, ctx, conf, idents, meta, templates, cp)
        save_json(os.path.join(out, "blind_oracle.json"), blind)
        ctx["coverage"]["blind oracle"] = (
            "%d oracles" % len(blind.get("oracles") or [])) \
            if blind.get("ran") else (blind.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "blind_oracle.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["blind oracle"] = "gated off"

    # ---------------- Stage O: verb tampering ULTRA ----------------
    if conf.get("access_allow_verb_matrix", True):
        head("Stage O - Verb tampering ULTRA (HEAD/OPTIONS/override, read-only)")
        verb = verb_matrix_ultra(http, scope, F, ctx, conf, idents, meta, ranked, cp)
        save_json(os.path.join(out, "verb_matrix.json"), verb)
        ctx["coverage"]["verb matrix ultra"] = (
            "%d hits on %d targets" % (len(verb.get("hits") or []),
                                       len(verb.get("targets") or []))) \
            if verb.get("ran") else (verb.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "verb_matrix.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["verb matrix ultra"] = "gated off"

    # ---------------- Stage P: batch/bulk IDOR ----------------
    if conf.get("access_allow_batch_probe", True):
        head("Stage P - Batch/bulk IDOR (array over-fetch)")
        batch = batch_idor(http, scope, F, ctx, conf, idents, meta, ranked, cp)
        save_json(os.path.join(out, "batch_idor.json"), batch)
        ctx["coverage"]["batch idor"] = (
            "%d probes" % len(batch.get("probes") or [])) \
            if batch.get("ran") else (batch.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "batch_idor.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["batch idor"] = "gated off"

    # ---------------- Stage Q: chained object IDOR ----------------
    if conf.get("access_allow_chain_probe", True):
        head("Stage Q - Chained object IDOR (mined IDs -> second hop)")
        chained = chained_idor(http, scope, F, ctx, conf, idents, meta,
                               idor_results, cp)
        save_json(os.path.join(out, "chained_idor.json"), chained)
        ctx["coverage"]["chained idor"] = (
            "%d hops" % len(chained.get("hops") or [])) \
            if chained.get("ran") else (chained.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "chained_idor.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["chained idor"] = "gated off"

    # ---------------- Stage R: file/export IDOR ----------------
    if conf.get("access_allow_file_idor", True):
        head("Stage R - File/export/download IDOR")
        filex = file_access_idor(http, scope, F, ctx, conf, idents, meta, ranked, cp)
        save_json(os.path.join(out, "file_idor.json"), filex)
        ctx["coverage"]["file idor"] = (
            "%d hits" % len(filex.get("hits") or [])) \
            if filex.get("ran") else (filex.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "file_idor.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["file idor"] = "gated off"

    # ---------------- Stage S: share-link/invite surface ----------------
    if conf.get("access_allow_share_probe", True):
        head("Stage S - Share-link/invite surface (entropy + cross-read)")
        share = share_surface(http, scope, F, ctx, conf, idents, meta, ranked, cp)
        save_json(os.path.join(out, "share_surface.json"), share)
        ctx["coverage"]["share surface"] = (
            "%d tokens, cross=%s" % (len(share.get("tokens") or []),
                                     (share.get("cross") or {}).get("verdict", "-"))) \
            if share.get("ran") else (share.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "share_surface.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["share surface"] = "gated off"

    # ---------------- Stage T: API key/token scope confusion ----------------
    if conf.get("access_allow_scope_probe", True):
        head("Stage T - Token/API-key scope confusion (own accounts)")
        scopes = token_scope_confusion(http, scope, F, ctx, conf, idents, meta,
                                       ranked, cp)
        save_json(os.path.join(out, "token_scope.json"), scopes)
        ctx["coverage"]["token scope"] = (
            "%d tests" % len(scopes.get("tests") or [])) \
            if scopes.get("ran") else (scopes.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "token_scope.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["token scope"] = "gated off"

    # ---------------- Stage U: search/filter exposure ----------------
    if conf.get("access_allow_search_probe", True):
        head("Stage U - Search/filter exposure + pagination over-exposure")
        searchx = search_exposure(http, scope, F, ctx, conf, idents, meta,
                                  ranked, cp)
        save_json(os.path.join(out, "search_exposure.json"), searchx)
        ctx["coverage"]["search exposure"] = (
            "%d leaks, %d pagination" % (len(searchx.get("probes") or []),
                                         len(searchx.get("pagination") or []))) \
            if searchx.get("ran") else (searchx.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "search_exposure.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["search exposure"] = "gated off"

    # ---------------- Stage V: authz response hygiene (0 requests) ----------------
    if conf.get("access_authz_hygiene", True):
        head("Stage V - Authz response hygiene (offline, ULTRA captures se)")
        hygiene = authz_hygiene_offline(F, ctx, cp)
        save_json(os.path.join(out, "authz_hygiene.json"), hygiene)
        ctx["coverage"]["authz hygiene"] = (
            "%d cache-miss, %d weak-cors" % (len(hygiene.get("missing_cache") or []),
                                             len(hygiene.get("weak_cors") or []))) \
            if hygiene.get("ran") else (hygiene.get("reason") or "skipped")
    else:
        save_json(os.path.join(out, "authz_hygiene.json"), {"ran": False,
                   "reason": "gated off"})
        ctx["coverage"]["authz hygiene"] = "gated off"

    # ---------------- Stage K: reports ----------------
    head("Stage K - Hypotheses, chains & reports")
    hypotheses = build_hypotheses(F, ctx)
    write_reports(out, scope, F, ctx, hypotheses, conf)

    conf_idors = [f for f in F.items if f["key"] == "idor_confirmed"]
    routing = {
        "to_phase12_params": {
            "parameterized_endpoints": [r["url"] for r in ranked if "?" in r["url"]][:30],
            "note": "ID params jo abhi tak sirf GET me dekhe - param tampering phase me useful"},
        "to_phase17_api": {
            "bola_endpoints": [f["endpoint"] for f in F.items
                               if f["key"] in ("idor_confirmed", "idor_suspected")][:20],
            "bypass_endpoints": [f["endpoint"] for f in F.items
                                 if f["key"] == "bypass_403_success"][:10],
            "techniques": ["id-swap", "path-variants", "header-tricks"]},
        "to_phase18_graphql": {
            "live_endpoints": gql.get("endpoints_live", []),
            "bola_types": ([gql.get("bola", {}).get("type")] if gql.get("bola") else []),
            "id_arg_live": gql.get("id_arg_live", []),
            "ops": gql.get("ops_from_p7", []),
            "ultra": {"introspection_bypass": [r.get("endpoint") for r in
                                               (gql_deep.get("introspection_bypass") or [])][:5],
                      "alias_bola": (gql_deep.get("alias_bola") or {}).get("verdict"),
                      "batching": (gql_deep.get("batching") or {}).get("accepted"),
                      "field_suggestions": list((gql_deep.get("field_suggestions") or {}).values())[:5]}},
        "to_phase20_logic": {
            "confirmed_objects": [f["endpoint"] for f in F.items
                                  if f["key"] in ("idor_confirmed",
                                                  "chained_idor_confirmed",
                                                  "tenant_isolation_missing")][:10],
            "note": "IDOR/chained/tenant confirm endpoints = business-logic abuse ke prime targets"},
        "to_phase22_tenant": {
            "tenant_findings": [f["endpoint"] for f in F.items
                                if f["key"].startswith("tenant_")][:10],
            "note": "cross-tenant vectors phase-22 deep tenant abuse ke liye"},
        "to_phase21_share": {
            "share_findings": [f["endpoint"] for f in F.items
                               if f["key"].startswith("share_")][:10],
            "note": "weak share tokens / cross-account share reads"},
        "to_phase26_cache": {
            "authz_cache_missing": (hygiene.get("missing_cache") or [])[:10],
            "weak_cors_on_objects": (hygiene.get("weak_cors") or [])[:5],
            "note": "cache-deception chain ke liye authz'd par cache-control missing"},
        "to_phase23_secrets": {
            "exposed_object_endpoints": [f["endpoint"] for f in F.items
                                         if f["severity"] in ("Critical", "High")][:15],
            "note": "PII/object data expose ho raha hai - secrets/PII classification karo"},
        "to_phase32_report": {
            "findings": len(F.items), "critical": sum(1 for f in F.items
                                                      if f["severity"] == "Critical"),
            "high": sum(1 for f in F.items if f["severity"] == "High")},
    }
    write_feedforward(out, "11-access", routing,
                      notes=["read-only run (write probes %s)"
                             % ("ON" if conf.get("access_allow_write_probes") else "off"),
                             "sessions used: %s" % ",".join(meta.keys())])
    write_manifest(out, "11-access",
                   ["findings.json", "ACCESS_FINDINGS.md", "access_test_plan.md",
                    "ACCESS_MATRIX.txt", "access_chains.txt", "access_endpoints.txt",
                    "access_sessions.json", "idor_verdicts.json", "access_matrix.json",
                    "id_intelligence.json", "bypass_403.json", "graphql_bola.json",
                    "mass_assignment.json", "method_matrix.json",
                    "gql_ultra.json", "tenant_isolation.json", "blind_oracle.json",
                    "verb_matrix.json", "batch_idor.json", "chained_idor.json",
                    "file_idor.json", "share_surface.json", "token_scope.json",
                    "search_exposure.json", "authz_hygiene.json", "feedforward.json"],
                   stats={"findings": len(F.items),
                          "critical": sum(1 for f in F.items if f["severity"] == "Critical"),
                          "high": sum(1 for f in F.items if f["severity"] == "High"),
                          "templates": len(templates), "sessions": len(idents),
                          "requests": getattr(http, "stats", {}).get("sent", 0)})

    dt = time.time() - t_start
    head("Phase 11 complete in %.1fs" % dt)
    ok("Findings=%d (Critical=%d High=%d) | templates=%d | sessions=%d | hypotheses=%d"
       % (len(F.items),
          sum(1 for f in F.items if f["severity"] == "Critical"),
          sum(1 for f in F.items if f["severity"] == "High"),
          len(templates), len(idents), len(hypotheses)))
    info("READ FIRST: ACCESS_FINDINGS.md -> access_test_plan.md -> ACCESS_MATRIX.txt")
    return out


# ---------------------------------------------------------------------------
# STANDALONE WIZARD (config.json me access_* keys banata hai)
# ---------------------------------------------------------------------------
def _wizard():
    if not CORE:
        print("[-] wizard ke liye bhi wasp_core.py chahiye (isi folder me rakho).")
        sys.exit(1)
    head("Phase 11 wizard - access_sessions / manual requests config builder")
    cfg_path = sys.argv[2] if len(sys.argv) > 2 else "config.json"
    data = {}
    if os.path.exists(cfg_path):
        try:
            data = json.load(open(cfg_path)) or {}
        except Exception:
            data = {}
    sessions = list(data.get("access_sessions") or [])
    manuals = list(data.get("access_manual_requests") or [])
    while True:
        print("\n  1) session add        2) sessions dekho/del     3) manual Burp request add")
        print("  4) victim known IDs   5) write-probes toggle    6) save & exit")
        ch = ask("choice").strip()
        if ch == "1":
            name = ask("session name (e.g. attacker/victim)").strip() or "user%d" % len(sessions)
            print("Cookie header paste karo (ek line, e.g. 'sid=abc; theme=dark'):")
            ck = input("> ").strip()
            print("Extra headers (json dict, khali = none), e.g. {\"Authorization\": \"Bearer xyz\"}:")
            try:
                hdrs = json.loads(input("> ").strip() or "{}")
            except Exception:
                hdrs = {}
            print("Markers (comma separated - ye strings is user ke responses me dikhti hain):")
            markers = [m.strip() for m in input("> ").strip().split(",") if m.strip()]
            print("Known object IDs (comma separated, e.g. 1001):")
            kids = [k.strip() for k in input("> ").strip().split(",") if k.strip()]
            priv = ask("priv (user/admin/anon) [user]").strip() or "user"
            sessions = [s for s in sessions if s.get("name") != name]
            sessions.append({"name": name, "cookie_header": ck, "headers": hdrs,
                             "markers": markers, "known_ids": kids, "priv": priv})
            ok("session '%s' added" % name)
        elif ch == "2":
            for i, s in enumerate(sessions):
                print("  [%d] %s priv=%s markers=%s known_ids=%s"
                      % (i, s.get("name"), s.get("priv"), s.get("markers"), s.get("known_ids")))
            d = ask("delete index (khali = kuch nahi)").strip()
            if d.isdigit() and int(d) < len(sessions):
                sessions.pop(int(d))
        elif ch == "3":
            print("Burp raw request paste karo, khatam hone par ek line me sirf END likho:")
            buf = []
            while True:
                try:
                    ln = input()
                except EOFError:
                    break
                if ln.strip() == "END":
                    break
                buf.append(ln)
            if buf:
                manuals.append("\n".join(buf))
                ok("manual request #%d added" % (len(manuals) - 1))
        elif ch == "4":
            print("Global victim object IDs (comma separated):")
            data["access_victim_known_ids"] = [v.strip() for v in input("> ").strip().split(",")
                                               if v.strip()]
        elif ch == "5":
            cur = bool(data.get("access_allow_write_probes", False))
            data["access_allow_write_probes"] = not cur
            print("write probes: %s -> %s" % (cur, not cur))
        elif ch == "6":
            break
    data["access_sessions"] = sessions
    data["access_manual_requests"] = manuals
    data.setdefault("access_surface_cap", DEFAULTS["access_surface_cap"])
    data.setdefault("access_template_cap", DEFAULTS["access_template_cap"])
    data.setdefault("access_bypass_probes", DEFAULTS["access_bypass_probes"])
    tmp = cfg_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, cfg_path)
    ok("saved: %s (sessions=%d, manual_requests=%d)" % (cfg_path, len(sessions), len(manuals)))
    info("ab chalao: python3 wasp.py run --module access")


def ask(prompt):
    try:
        return input("%s> " % prompt)
    except EOFError:
        return ""


if __name__ == "__main__":
    _wizard()
