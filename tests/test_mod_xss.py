#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P13 SELF-TEST SUITE - mod_xss.py v13.0.0-ultra-ultra-pro-max (P13)
=============================================================================
 Mock XSS lab app + full assertion suite:
   - Unit tests (pure helpers: context classifier/surviving-charset/CSP/DOM)
   - Active run end-to-end (stages C..L verdict assertions)
   - Artifact integrity (23 output files, matrix, catalog, feedforward)
   - RWX rule (0777 on every result file)
   - Passive mode (allow_active=False -> 0 probes, hypotheses only)
   - Checkpoint replay (FIX-4: findings re-derivation on resume)
   - RoE gate (stored live probe default OFF)
 Detection-only discipline honored: lab me bhi sab probes inert markers.
=============================================================================
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block3_input")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os
import sys
import json
import shutil
import time
import re
import html as html_mod
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block3_input")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_xss as MX                                      # noqa: E402
import wasp_core as WC                                    # noqa: E402

BASE = os.path.join(HERE, "p13_test_base")
BASE2 = os.path.join(HERE, "p13_test_base_passive")
ENG = "p13lab"
SCOPE_PATH = os.path.join(BASE, "scope.json")
SCOPE_PATH2 = os.path.join(BASE2, "scope.json")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s  -> %s" % (name, detail))
    return cond


# ===========================================================================
# MOCK XSS LAB APP
# - /ref    : q verbatim html-body reflect (NO CSP)          -> CONFIRMED
# - /attr   : name in <input value="...">                    -> attr-dq CONFIRMED
# - /js     : q inside <script>var s='...';</script>         -> js-string CONFIRMED
# - /comment: q inside <!-- ... -->                          -> comment CONFIRMED
# - /textarea: q inside <textarea>...</textarea>              -> rcdata CONFIRMED
# - /urlattr: next in <a href="...">                       -> url-attr scheme CONFIRMED
# - /meta   : u in <meta http-equiv=refresh ... url=...>     -> meta-refresh CONFIRMED
# - /store  : msg verbatim (stored-ripe field name)          -> stored CANDIDATE
# - /strip  : strips < and > chars, reflects rest            -> SUSPECTED
# - /waf    : blocks <svg|onload (single-decode view), backend double-decode
#             reflect verbatim                               -> WAF->bypass CONFIRMED
# - /safe   : html-escapes everything + strong CSP           -> SAFE
# - /noreflect: constant page                                -> SAFE (blind)
# - /hdr    : reflects Referer header verbatim in body       -> header CONFIRMED
# - /dom    : inline script location.hash -> innerHTML       -> DOM SUSPECTED
# ===========================================================================
class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockXSSLab/1.0"

    def log_message(self, *a):      # silence
        pass

    @staticmethod
    def _dec(s, rounds=1):
        v = s or ""
        for _ in range(int(rounds)):
            v = unquote_plus(v)
        return v

    def _raw_val(self, name):
        q = urlsplit(self.path).query
        for part in q.split("&"):
            if "=" in part and part.split("=", 1)[0] == name:
                return part.split("=", 1)[1]
        return ""

    def _respond(self, status, text, headers=None):
        body = text.encode("utf-8", "ignore")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "MockXSSLab/1.0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._route()

    def _route(self):
        sp = urlsplit(self.path)
        path = sp.path

        if path in ("/", ""):
            return self._respond(200, "Mock XSS lab. /ref /attr /js /comment "
                                      "/textarea /urlattr /meta /store /strip "
                                      "/waf /safe /noreflect /hdr /dom")

        if path == "/ref":
            v = self._dec(self._raw_val("q"), 2)
            return self._respond(200, "<html><head><title>Search</title></head>"
                                      "<body><p>Results for: %s</p>"
                                      "<p class=meta>no CSP here on purpose</p>"
                                      "</body></html>" % v)

        if path == "/attr":
            v = self._dec(self._raw_val("name"), 2)
            return self._respond(200, "<html><body><form method=get>"
                                      "<input name=\"name\" value=\"%s\">"
                                      "<button>Go</button></form></body></html>" % v)

        if path == "/js":
            v = self._dec(self._raw_val("q"), 2)
            return self._respond(200, "<html><body><script>"
                                      "var term='%s'; initSearch(term);"
                                      "</script></body></html>" % v)

        if path == "/comment":
            v = self._dec(self._raw_val("q"), 2)
            return self._respond(200, "<html><body><!-- render note: %s -->"
                                      "<p>content</p></body></html>" % v)

        if path == "/textarea":
            v = self._dec(self._raw_val("q"), 2)
            return self._respond(200, "<html><body><textarea>%s</textarea>"
                                      "</body></html>" % v)

        if path == "/urlattr":
            v = self._dec(self._raw_val("next"), 2)
            return self._respond(200, "<html><body>"
                                      "<a href=\"%s\">Continue</a>"
                                      "</body></html>" % v)

        if path == "/meta":
            v = self._dec(self._raw_val("u"), 2)
            return self._respond(200, "<html><head>"
                                      "<meta http-equiv=\"refresh\" "
                                      "content=\"0; url=%s\"></head>"
                                      "<body>redirect page</body></html>" % v)

        if path == "/store":
            v = self._dec(self._raw_val("msg"), 2)
            return self._respond(200, "<html><body><div class=comment>%s</div>"
                                      "</body></html>" % v)

        if path == "/strip":
            v = self._dec(self._raw_val("q"), 2)
            v = v.replace("<", "").replace(">", "")
            return self._respond(200, "<html><body><p>Sanitized: %s</p>"
                                      "</body></html>" % v)

        if path == "/waf":
            waf_view = self._dec(self._raw_val("q"), 1)
            if "<svg" in waf_view or "onload" in waf_view:
                return self._respond(403, "Access Denied. Request blocked by "
                                          "security gateway. Event ID: 9912-xss.")
            v = self._dec(self._raw_val("q"), 2)     # legacy double-decode backend
            return self._respond(200, "<html><body><p>Query: %s</p>"
                                      "</body></html>" % v)

        if path == "/safe":
            v = html_mod.escape(self._dec(self._raw_val("q"), 2), quote=True)
            return self._respond(200, "<html><body><p>Encoded: %s</p>"
                                      "</body></html>" % v,
                                 {"Content-Security-Policy":
                                  "default-src 'self'; script-src 'nonce-abc123'"})

        if path == "/noreflect":
            return self._respond(200, "Results page. Nothing matched your query.")

        if path == "/hdr":
            ref = self.headers.get("Referer", "")
            return self._respond(200, "<html><body><p>Came from: %s</p>"
                                      "<p>audit line</p></body></html>" % ref)

        if path == "/dom":
            return self._respond(200, "<html><body><div id=out></div><script>"
                                      "var frag = location.hash.slice(1);"
                                      "document.getElementById('out').innerHTML = frag;"
                                      "</script></body></html>")

        return self._respond(404, "404 page not found: %s" % path)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True


# ===========================================================================
# ENV BOOTSTRAP
# ===========================================================================
def seed(base, scope_path):
    shutil.rmtree(base, ignore_errors=True)
    eng = os.path.join(base, ENG)
    for sub in ("inject", "surface", "auth", "understand", "js", "tech"):
        os.makedirs(os.path.join(eng, sub), exist_ok=True)
    return eng


def write_scope(scope_path, origin):
    os.makedirs(os.path.dirname(scope_path), exist_ok=True)
    with open(scope_path, "w") as f:
        json.dump({
            "engagement": ENG,
            "authorized": True,
            "authorization_reference": "P13 self-test lab (localhost mock)",
            "targets": [origin],
            "ips": ["127.0.0.1"],
            "notes": "detection-only lab; inert-marker probes only"
        }, f, indent=2)


def seed_p13_files(eng, origin):
    """P12 artifacts (reflection_map + feedforward) + P8/P9/P2 seeds."""
    # P12 reflection_map.json - THE seed (to_phase13_xss)
    refl = {"params": [
        {"url": origin + "/ref?q=term", "param": "q", "context": "html-body",
         "verbatim": True, "payload_probe": "wasp7*7", "status": 200,
         "next_phase": "P13-XSS", "suggested": "<svg/onload=... (P13)"},
        {"url": origin + "/attr?name=bob", "param": "name", "context": "html-attr",
         "verbatim": True, "payload_probe": "wasp7*7", "status": 200,
         "next_phase": "P13-XSS", "suggested": "attr-quote breakout (P13)"},
        {"url": origin + "/js?q=term", "param": "q", "context": "js-string",
         "verbatim": True, "payload_probe": "wasp7*7", "status": 200,
         "next_phase": "P13-XSS", "suggested": "js-string breakout (P13)"},
        {"url": origin + "/safe?q=term", "param": "q", "context": "html-encoded",
         "verbatim": False, "payload_probe": "wasp7*7", "status": 200,
         "next_phase": "P13-encoded-review", "suggested": "entity-encode bypass (P13)"},
    ], "note": "capture-based (0 extra requests)"}
    with open(os.path.join(eng, "inject", "reflection_map.json"), "w") as f:
        json.dump(refl, f, indent=2)
    # P12 feedforward.json -> to_phase13_xss
    with open(os.path.join(eng, "inject", "feedforward.json"), "w") as f:
        json.dump({"phase": "12-inject", "routing": {
            "to_phase13_xss": {"xss_ripe": [
                {"url": origin + "/ref?q=term", "param": "q", "context": "html-body"},
                {"url": origin + "/store?msg=hi", "param": "msg",
                 "context": "html-body"},
                {"url": origin + "/comment?q=term", "param": "q",
                 "context": "html-body"}],
                "note": "verbatim-reflect params"}}, "notes": []}, f, indent=2)
    # P8 queue
    T = [
        ("/ref?q=term", ["reflection-input"], 10.0),
        ("/attr?name=bob", ["reflection-input"], 9.8),
        ("/js?q=term", ["reflection-input"], 9.7),
        ("/comment?q=note", ["reflection-input"], 9.5),
        ("/textarea?q=note", ["reflection-input"], 9.3),
        ("/urlattr?next=/dash", ["redirect-param"], 9.2),
        ("/meta?u=/dash", ["redirect-param"], 9.0),
        ("/store?msg=hi", ["reflection-input", "stored-ripe"], 8.9),
        ("/strip?q=term", ["reflection-input"], 8.8),
        ("/waf?q=term", ["waf-param-input"], 8.6),
        ("/safe?q=term", ["reflection-input"], 8.4),
        ("/noreflect?q=term", ["param-input"], 8.2),
        ("/dom?tpl=1", ["dom-analysis"], 8.0),
        ("/hdr?q=1", ["reflection-input", "header-sink"], 9.9),
    ]
    queue = [{"target": origin + p, "classes": c, "priority": pr} for p, c, pr in T]
    with open(os.path.join(eng, "surface", "priority_queue.json"), "w") as f:
        json.dump({"queue": queue}, f, indent=2)
    # P9 reflections
    with open(os.path.join(eng, "auth", "auth_redirect_xss.json"), "w") as f:
        json.dump({"reflections": [
            {"url": origin + "/ref?q=term", "param": "q",
             "note": "P9 saw reflection"}]}, f, indent=2)
    # P2 forms
    with open(os.path.join(eng, "understand", "forms.json"), "w") as f:
        json.dump({"forms": [
            {"action": origin + "/attr", "method": "GET",
             "fields": [{"name": "name"}, {"name": "email"}]},
            {"action": origin + "/store", "method": "GET",
             "fields": [{"name": "msg"}]}]}, f, indent=2)
    # P7 dom analysis
    with open(os.path.join(eng, "js", "dom_analysis.txt"), "w") as f:
        f.write(origin + "/dom?tpl=1 dom-sink innerHTML\n")


def make_cfg():
    cfg = WC.Cfg(None)
    cfg.rate_limit = 250.0
    cfg.jitter = 0.0
    cfg.retries = 0
    cfg.timeout = 20
    cfg.max_requests = 100000
    cfg.allow_active = True
    cfg.resume = True
    cfg.allow_write_http = False
    # P13 tunables (roomy budgets so mock lab hits every engine)
    cfg.xss_surface_cap = 24
    cfg.xss_param_cap = 40
    cfg.xss_reflect_probes = 48
    cfg.xss_context_probes = 40
    cfg.xss_waf_probes = 80
    cfg.xss_waf_probe_budget = 12
    cfg.xss_dom_fetch = 4
    cfg.xss_header_probes = 70
    cfg.xss_stored_probes = 4
    cfg.xss_technique_probes = 6
    cfg.xss_allow_stored_probe = False     # RoE gate default OFF
    cfg.xss_allow_client_pp = True
    return cfg

# ===========================================================================
# 1) UNIT TESTS (pure helpers - koi network nahi)
# ===========================================================================
def unit_tests():
    print("\n" + "=" * 74)
    print("SECTION 1: UNIT TESTS (pure helpers)")
    print("=" * 74)

    check("unit.set_param.replace",
          MX.set_param("http://x/y?a=1&b=2", "a", "Z") == "http://x/y?a=Z&b=2")
    check("unit.set_param.append",
          MX.set_param("http://x/y", "a", "Z") == "http://x/y?a=Z")
    check("unit.get_param_value",
          MX.get_param_value("http://x/y?a=1&b=2", "b") == "2")
    check("unit.xss_param_hypothesis.stored",
          "stored-candidate" in MX.xss_param_hypothesis("comment"))
    check("unit.xss_param_hypothesis.urlattr",
          "url-attr" in MX.xss_param_hypothesis("next"))
    check("unit.xss_param_hypothesis.default",
          MX.xss_param_hypothesis("zzz_unknown") == ["reflected-ripe"])

    # 16-context classifier
    MK = "waspX13mk01"
    cases = [
        ("<p>hello %s world</p>" % MK, "html-body", True),
        ('<input value="%s">' % MK, "html-attr-dq", True),
        ("<input value='%s'>" % MK, "html-attr-sq", True),
        ("<div data-x=%s>" % MK, "html-attr-uq", True),
        ("<script>var x='%s';</script>" % MK, "js-string", True),
        ("<script>var h=`%s`;</script>" % MK, "js-tmpl", True),
        ("<script>var h = %s ;</script>" % MK, "js-raw", True),
        ("<!-- note: %s -->" % MK, "html-comment", True),
        ("<textarea>%s</textarea>" % MK, "rcdata", True),
        ("<title>page %s</title>" % MK, "rcdata", True),
        ("<noscript>%s</noscript>" % MK, "noscript", True),
        ("<style>.a{x:%s}</style>" % MK, "style-block", True),
        ('<a href="http://x/%s">l</a>' % MK, "url-attr", True),
        ('<meta http-equiv="refresh" content="0; url=%s">' % MK, "meta-refresh", True),
        ("<form><input name=n value=\"%s\"></form>" % MK, "html-attr-dq", True),
        ("<p>plain &#x77;asp</p>", "", False),
        ("nothing here", "", False),
    ]
    n_ok = 0
    for txt, want_ctx, want_ver in cases:
        got, ver = MX.reflection_context_xss(txt, MK)
        if got == want_ctx and ver == want_ver:
            n_ok += 1
        else:
            print("     ctx-mismatch: want=%s got=%s ver=%s | %s"
                  % (want_ctx, got, ver, txt[:48]))
    check("unit.context_classifier.16ctx", n_ok == len(cases),
          "%d/%d" % (n_ok, len(cases)))
    got, ver = MX.reflection_context_xss("<p>%s</p>" % html_mod.escape(MK), MK)
    check("unit.context_classifier.alnum-escape-noop",
          got == "html-body" and ver is True, "%s/%s" % (got, ver))
    MK2 = 'wasp<x>&mk13'
    got2, ver2 = MX.reflection_context_xss(
        "<p>%s</p>" % html_mod.escape(MK2), MK2)
    check("unit.context_classifier.encoded",
          got2 == "html-encoded" and ver2 is False, "%s/%s" % (got2, ver2))

    # surviving-charset (stage J)
    base = "waspCprobe1"
    blob = "".join(base + ch + base for ch in MX.DANGEROUS_CHARS)
    surv = MX.surviving_charset("<div>" + blob + "</div>", base)
    check("unit.surviving.all-verbatim",
          set(surv["verbatim"]) == set(MX.DANGEROUS_CHARS), str(surv))
    ent_blob = "".join(base + html_mod.escape(ch, quote=True) + base
                       for ch in "<>\"'")
    surv2 = MX.surviving_charset("<div>" + ent_blob + "</div>", base)
    check("unit.surviving.entity-encoded",
          set(surv2["encoded"].keys()) == {"<", ">", '"', "'"}, str(surv2))
    ok1, why1 = MX.charset_exploitability(surv, "html-body")
    check("unit.exploitability.body-ok", ok1 and "<" in why1, why1)
    surv3 = {"verbatim": [], "encoded": {}, "missing": MX.DANGEROUS_CHARS}
    ok2, _ = MX.charset_exploitability(surv3, "html-body")
    check("unit.exploitability.body-blocked", ok2 is False)

    # WAF variants: sab callable + string output
    core = MX.TAG_VECTORS[0][0]
    allstr = all(isinstance(xf(core), str) and xf(core)
                 for _l, xf in MX.WAF_BYPASS_VARIANTS)
    check("unit.waf_variants.24-callable",
          allstr and len(MX.WAF_BYPASS_VARIANTS) == 24)
    # koi external host payload me nahi (FIX-7 zero-egress)
    banned = re.compile(r"(?i)https?://(?!(?:wasp-x13\.test|wasp-x13\.invalid))"
                        r"|\.com|\.net|\.org|\.io|\.xyz|\.ru")
    viol = []
    for pv, _l in MX.TAG_VECTORS:
        if banned.search(pv):
            viol.append(pv[:40])
    for _l, xf in MX.WAF_BYPASS_VARIANTS:
        if banned.search(xf(core)):
            viol.append(_l)
    for sch, _l in MX.SCHEME_PROBES:
        pass  # scheme probes self-contained
    check("unit.zero-egress.payloads", not viol, str(viol))

    # ladder coverage: har context >= 1 payload
    missing_ladder = [c for c in MX.CTX_EXPLOIT_KIND if not MX._ladder_payloads(c, "CAN")]
    check("unit.ladder.all-contexts", not missing_ladder, str(missing_ladder))

    # DOM analyzer
    js = ("var h = location.hash.slice(1);"
          "document.getElementById('o').innerHTML = h;"
          "$.extend(true, {}, opts);")
    an = MX.analyze_js_for_dom(js)
    check("unit.dom.source-sink-link",
          "location.hash" in an["sources"] and "innerHTML" in an["sinks"]
          and an["same_script_link"], json.dumps(an)[:160])
    check("unit.dom.pp-gadget", "jquery-deep-extend" in an["pp_gadgets"])
    an2 = MX.analyze_js_for_dom(
        "addEventListener('message', function(e){ el.innerHTML = e.data; });")
    check("unit.dom.listener-no-origin", an2["listener_no_origin"] is True)
    an3 = MX.analyze_js_for_dom(
        "addEventListener('message', function(e){ if (e.origin !== 'https://x') "
        "return; el.innerHTML = e.data; });")
    check("unit.dom.listener-with-origin", an3["listener_no_origin"] is False)

    # CSP parser + gaps
    csp = MX.parse_csp("default-src 'self'; script-src 'unsafe-inline' *.cdn.com")
    gapset = {g for g, _d in MX.csp_gaps(csp)}
    check("unit.csp.parse-gaps",
          {"unsafe-inline", "wildcard-subdomain", "base-uri-missing",
           "frame-ancestors-missing"} <= gapset, str(gapset))
    check("unit.csp.missing", MX.csp_gaps({})[0][0] == "csp-missing")

    # PII redact
    red = MX.pii_redact("mail me at admin@corp-example.com now")
    check("unit.pii_redact.email", "@***" in red and "corp-example.com" not in red)

    # canary uniqueness
    c1, c2 = MX.make_canary("q"), MX.make_canary("q")
    check("unit.canary.unique", c1 != c2 and c1.startswith("waspX13q"))

    # severity classification
    sev, _cv, _why = MX.classify_severity("xss_reflected_confirmed")
    check("unit.severity.reflected", sev == "high")
    sev2, _c2, _w2 = MX.classify_severity("xss_stored_confirmed")
    check("unit.severity.stored", sev2 == "critical")
    sev3, _c3, _w3 = MX.classify_severity("unknown-key-zzz")
    check("unit.severity.default", sev3 == "info")


# ===========================================================================
# 2) ACTIVE END-TO-END RUN
# ===========================================================================
def active_run(httpd, origin):
    print("\n" + "=" * 74)
    print("SECTION 2: ACTIVE RUN (mock lab, detection-only)")
    print("=" * 74)
    eng = seed(BASE, SCOPE_PATH)
    write_scope(SCOPE_PATH, origin)
    seed_p13_files(eng, origin)
    cfg = make_cfg()
    scope = WC.Scope(SCOPE_PATH)
    out = MX.run(cfg, scope, BASE)
    check("active.run.completed", os.path.isdir(out), out)
    return out


# ===========================================================================
# 3) ARTIFACT + VERDICT ASSERTIONS
# ===========================================================================
EXPECTED_FILES = [
    "xss_surface.json", "xss_targets.txt", "csp_map.json",
    "reflection_contexts.json", "reflected_probes.json", "waf_bypass_xss.json",
    "dom_xss.json", "stored_candidates.json", "csp_analysis.json",
    "header_reflect_xss.json", "technique_matrix.json", "encode_matrix.json",
    "framework_notes.json", "xss_matrix.json", "xss_matrix.txt",
    "XSS_FINDINGS.md", "xss_test_plan.md", "xss_chains.txt",
    "TECHNIQUES_CATALOG_XSS.md", "cwe_owasp_map_xss.json", "findings.json",
    "feedforward.json", "MANIFEST.json",
]


def artifact_tests(out):
    print("\n" + "=" * 74)
    print("SECTION 3: ARTIFACT + VERDICT ASSERTIONS")
    print("=" * 74)

    def jload(fname):
        p = os.path.join(out, fname)
        return WC.load_json(p, None) if os.path.exists(p) else None

    missing = [f for f in EXPECTED_FILES if not os.path.exists(os.path.join(out, f))]
    check("artifacts.all-23-present", not missing, str(missing))

    surf = jload("xss_surface.json")
    check("surface.file", isinstance(surf, dict))
    check("surface.targets>=10", isinstance(surf, dict) and
          len(surf.get("targets", [])) >= 10,
          str(len((surf or {}).get("targets", []))))
    tt = os.path.join(out, "xss_targets.txt")
    check("surface.targets_txt", os.path.exists(tt) and
          len([l for l in open(tt) if l.strip()]) >= 10)

    rm = jload("reflection_contexts.json") or {}
    recs = rm.get("records", [])
    by_ep = {}
    for r in recs:
        by_ep[(urlsplit(r["url"]).path, r["param"])] = r

    def verdict_of(path, param):
        r = by_ep.get((path, param))
        return (r or {}).get("verdict", "MISSING")

    def context_of(path, param):
        r = by_ep.get((path, param))
        return (r or {}).get("context", "MISSING")

    check("stageC.ref.html-body.CONFIRMED",
          verdict_of("/ref", "q") == "CONFIRMED" and
          context_of("/ref", "q") == "html-body",
          json.dumps(by_ep.get(("/ref", "q"), {}))[:220])
    check("stageC.attr.attr-dq", context_of("/attr", "name") == "html-attr-dq",
          context_of("/attr", "name"))
    check("stageC.js.js-string", context_of("/js", "q") == "js-string",
          context_of("/js", "q"))
    check("stageC.safe.encoded-echo-SAFE",
          verdict_of("/safe", "q") == "SAFE",
          "%s/%s" % (verdict_of("/safe", "q"), context_of("/safe", "q")))
    check("stageC.noreflect.SAFE", verdict_of("/noreflect", "q") == "SAFE",
          verdict_of("/noreflect", "q"))
    check("stageC.exploit_capable.ref",
          by_ep.get(("/ref", "q"), {}).get("exploit_capable") is True)

    # encode matrix (stage J view)
    em = jload("encode_matrix.json") or {}
    em_ref = [r for r in em.get("rows", [])
              if urlsplit(r.get("url", "")).path == "/ref"]
    check("encode_matrix.ref.row", len(em_ref) == 1 and
          "<" in ((em_ref[0].get("surviving") or {}).get("verbatim") or []),
          json.dumps(em_ref[:1])[:200])

    # stage D verdicts
    rp = jload("reflected_probes.json") or {}
    rp_by = {(urlsplit(r["url"]).path, r["param"]): r for r in rp.get("records", [])}
    check("stageD.ref.CONFIRMED",
          rp_by.get(("/ref", "q"), {}).get("verdict") == "CONFIRMED",
          json.dumps(rp_by.get(("/ref", "q"), {}))[:220])
    check("stageD.js.CONFIRMED",
          rp_by.get(("/js", "q"), {}).get("verdict") == "CONFIRMED",
          json.dumps(rp_by.get(("/js", "q"), {}))[:220])
    check("stageD.attr.CONFIRMED",
          rp_by.get(("/attr", "name"), {}).get("verdict") == "CONFIRMED")
    check("stageD.urlattr.CONFIRMED",
          rp_by.get(("/urlattr", "next"), {}).get("verdict") == "CONFIRMED")
    check("stageD.waf.WAF_BLOCKED",
          rp_by.get(("/waf", "q"), {}).get("verdict") == "WAF_BLOCKED",
          json.dumps(rp_by.get(("/waf", "q"), {}))[:220])
    check("stageD.strip.SUSPECTED",
          rp_by.get(("/strip", "q"), {}).get("verdict") == "SUSPECTED",
          json.dumps(rp_by.get(("/strip", "q"), {}))[:220])
    check("stageD.stats.probes>0", rp.get("stats", {}).get("probes", 0) > 0)

    # stage E bypass
    wb = jload("waf_bypass_xss.json") or {}
    win = [r for r in wb.get("records", [])
           if r.get("verdict") == "CONFIRMED" and r.get("winning_variant")]
    check("stageE.waf.bypass-CONFIRMED", len(win) == 1,
          json.dumps(wb.get("records", []))[:300])
    if win:
        valid = {lbl for lbl, _x in MX.WAF_BYPASS_VARIANTS}
        check("stageE.winning_variant.valid-label",
              win[0].get("winning_variant") in valid,
              str(win[0].get("winning_variant")))

    # stage F DOM
    dx = jload("dom_xss.json") or {}
    dom_hit = [r for r in dx.get("records", [])
               if urlsplit(r.get("url", "")).path == "/dom"
               and r.get("same_script_link")]
    check("stageF.dom.suspected", len(dom_hit) == 1,
          json.dumps(dx.get("records", []))[:260])
    check("stageF.dom.stats", dx.get("stats", {}).get("pages_scanned", 0) > 0)

    # stage G stored (RoE gate OFF)
    st = jload("stored_candidates.json") or {}
    st_hit = [r for r in st.get("records", [])
              if urlsplit(r.get("url", "")).path == "/store"]
    check("stageG.store.CANDIDATE",
          len(st_hit) == 1 and st_hit[0].get("verdict") == "CANDIDATE",
          json.dumps(st.get("records", []))[:220])
    check("stageG.roe-gate.off", st.get("stats", {}).get("live_probe_allowed") is False)

    # stage H CSP
    ca = jload("csp_analysis.json") or {}
    ca_by = {urlsplit(r.get("url", "")).path: r for r in ca.get("records", [])}
    ref_gaps = {g for g, _d in (ca_by.get("/ref", {}).get("gaps") or [])}
    safe_gaps = {g for g, _d in (ca_by.get("/safe", {}).get("gaps") or [])}
    check("stageH.ref.csp-missing", "csp-missing" in ref_gaps, str(ref_gaps))
    check("stageH.safe.weak-only",
          "csp-missing" not in safe_gaps and "base-uri-missing" in safe_gaps,
          str(safe_gaps))

    # stage I header reflect
    hr = jload("header_reflect_xss.json") or {}
    hr_hit = [r for r in hr.get("records", [])
              if r.get("verdict") in ("CONFIRMED", "SUSPECTED")]
    check("stageI.header-reflect.hit", len(hr_hit) >= 1,
          json.dumps(hr.get("records", []))[:220])

    # stage K techniques
    tk = jload("technique_matrix.json") or {}
    tk_names = {r.get("technique") for r in tk.get("records", [])}
    check("stageK.techniques.recorded",
          {"mxss-noscript", "fullwidth-normalization", "json-in-script-embed",
           "utf7-legacy", "dangling-markup", "base-tag-injection",
           "meta-refresh-url"} <= tk_names, str(tk_names))

    # matrix + docs
    mt = jload("xss_matrix.json") or {}
    check("matrix.rows>=10", len(mt.get("rows", [])) >= 10,
          str(len((mt or {}).get("rows", []))))
    mtx = os.path.join(out, "xss_matrix.txt")
    check("matrix.txt", os.path.exists(mtx) and len(open(mtx).read()) > 100)

    fin = jload("findings.json") or {}
    check("findings.count>0", fin.get("count", 0) > 0, str(fin.get("count")))
    keys = {f["key"] for f in fin.get("findings", [])}
    check("findings.xss_reflected_present", "xss_reflected_confirmed" in keys
          or "xss_js_string_breakout" in keys, str(sorted(keys))[:200])
    check("findings.dom_present", "xss_dom_suspected" in keys, str(sorted(keys))[:200])
    check("findings.csp_present",
          "xss_csp_missing" in keys or "xss_csp_weak" in keys)
    check("findings.stored_present", "xss_stored_candidate" in keys)
    for f in fin.get("findings", []):
        if f["severity"] not in ("critical", "high", "medium", "low", "info"):
            check("findings.severity-valid", False, f["severity"])
            break
    else:
        check("findings.severity-valid", True)

    fmd = open(os.path.join(out, "XSS_FINDINGS.md")).read()
    check("docs.findings_md", "Phase 13" in fmd and "detection-only" in fmd)
    tp = open(os.path.join(out, "xss_test_plan.md")).read()
    check("docs.test_plan", "hypotheses" in tp.lower() or "HYPOTHESIS" in tp)
    ch = open(os.path.join(out, "xss_chains.txt")).read()
    check("docs.chains", "Phase 13" in ch)
    cat = open(os.path.join(out, "TECHNIQUES_CATALOG_XSS.md")).read()
    check("docs.catalog", "mXSS" in cat and "WSTG-CLNT" in cat)

    ff = jload("feedforward.json") or {}
    routing = ff.get("routing") or {}
    check("ff.to_phase14_client", "to_phase14_client" in routing, str(list(routing)))
    check("ff.to_phase15_ssrf", "to_phase15_ssrf" in routing)
    check("ff.to_phase20_logic", "to_phase20_logic" in routing)
    check("ff.to_phase26_cache", "to_phase26_cache" in routing)
    check("ff.to_phase32_report", "to_phase32_report" in routing)
    man = jload("MANIFEST.json") or {}
    check("manifest.files>=22", len(man.get("files", [])) >= 22,
          str(len((man or {}).get("files", []))))
    return fin

# ===========================================================================
# 4) RWX RULE (0777 har file par)
# ===========================================================================
def rwx_tests(out):
    print("\n" + "=" * 74)
    print("SECTION 4: RWX RULE (0777)")
    print("=" * 74)
    bad = []
    for root, _dirs, files in os.walk(out):
        for fn in files:
            p = os.path.join(root, fn)
            mode = os.stat(p).st_mode & 0o777
            if mode != 0o777:
                bad.append((fn, oct(mode)))
    check("rwx.all-files-0777", not bad, str(bad[:6]))


# ===========================================================================
# 5) PASSIVE MODE (allow_active=False -> 0 probes)
# ===========================================================================
def passive_run(origin):
    print("\n" + "=" * 74)
    print("SECTION 5: PASSIVE MODE (0 network probes)")
    print("=" * 74)
    eng = seed(BASE2, SCOPE_PATH2)
    write_scope(SCOPE_PATH2, origin)
    seed_p13_files(eng, origin)
    cfg = make_cfg()
    cfg.allow_active = False
    scope = WC.Scope(SCOPE_PATH2)
    out = MX.run(cfg, scope, BASE2)
    check("passive.run.completed", os.path.isdir(out), out)
    rp = WC.load_json(os.path.join(out, "reflected_probes.json"), None)
    check("passive.probes-empty",
          rp is None or not (rp or {}).get("records"),
          json.dumps((rp or {}).get("records", "absent"))[:120])
    ff = WC.load_json(os.path.join(out, "feedforward.json"), {}) or {}
    check("passive.feedforward.mode",
          (ff.get("routing") or {}).get("to_phase32_report", {}).get("mode") == "passive",
          json.dumps(ff.get("routing", {}))[:140])
    surf = WC.load_json(os.path.join(out, "xss_surface.json"), {}) or {}
    check("passive.surface-present", len(surf.get("targets", [])) >= 1)
    tp = os.path.join(out, "xss_test_plan.md")
    check("passive.test-plan-present", os.path.exists(tp))
    rwx_tests(out)


# ===========================================================================
# 6) CHECKPOINT REPLAY (FIX-4: findings re-derivation on resume)
# ===========================================================================
def replay_tests(out_first, origin, httpd):
    print("\n" + "=" * 74)
    print("SECTION 6: CHECKPOINT REPLAY (resume par findings re-derived)")
    print("=" * 74)
    cfg = make_cfg()          # allow_active=True, resume=True
    cfg.resume = True
    scope = WC.Scope(SCOPE_PATH)
    out = MX.run(cfg, scope, BASE)     # same BASE -> stages checkpoint se replay
    fin1 = WC.load_json(os.path.join(out_first, "findings.json"), {}) or {}
    fin2 = WC.load_json(os.path.join(out, "findings.json"), {}) or {}
    check("replay.run.completed", os.path.isdir(out), out)
    check("replay.findings-first-nonempty", fin1.get("count", 0) > 0,
          str(fin1.get("count")))
    check("replay.findings-rederived-nonempty", fin2.get("count", 0) > 0,
          str(fin2.get("count")))
    keys1 = {f["key"] for f in fin1.get("findings", [])}
    keys2 = {f["key"] for f in fin2.get("findings", [])}
    check("replay.finding-keys-stable",
          bool(keys1) and keys1 == keys2,
          "only-first=%s only-second=%s" % (sorted(keys1 - keys2)[:5],
                                            sorted(keys2 - keys1)[:5]))
    rp2 = WC.load_json(os.path.join(out, "reflected_probes.json"), {}) or {}
    check("replay.stage-results-replayed",
          len(rp2.get("records", [])) > 0, str(len(rp2.get("records", []))))
    # re-derivation unit: stage function ko cached results do -> findings wapas
    class FStub:
        items = []

        def add(self, *a, **k):
            self.items.append(a[0])
    cached = {"records": [{"url": origin + "/ref?q=x", "param": "q",
                           "verdict": "CONFIRMED", "context": "html-body",
                           "signals": [{"label": "svg-onload"}]}],
              "stats": {"probes": 3, "budget": 40}}
    fs = FStub()
    MX.reflected_probes_findings(fs, cached)
    check("replay.findings-rederive-unit",
          len(fs.items) == 1 and fs.items[0] == "xss_reflected_confirmed",
          str(fs.items))


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    t0 = time.time()
    print("=" * 74)
    print(" WASP P13 SELF-TEST - mod_xss.py v%s (mock XSS lab)" % MX.PLAN_VERSION)
    print("=" * 74)

    # lab server
    httpd = LabServer(("127.0.0.1", 0), LabHandler)
    port = httpd.server_address[1]
    origin = "http://127.0.0.1:%d" % port
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    print("  lab origin: %s" % origin)

    try:
        unit_tests()
        out = active_run(httpd, origin)
        fin = artifact_tests(out) or {}
        rwx_tests(out)
        passive_run(origin)
        replay_tests(out, origin, httpd)
    finally:
        httpd.shutdown()

    print("\n" + "=" * 74)
    print(" RESULT: %d PASS / %d FAIL  (%.1fs)"
          % (len(PASS), len(FAIL), time.time() - t0))
    print("=" * 74)
    if FAIL:
        print(" Failures:")
        for name, detail in FAIL:
            print("  - %s: %s" % (name, str(detail)[:160]))
        sys.exit(1)
    print(" P13 self-test: SAB PASS. mod_xss.py ready.")
    sys.exit(0)


if __name__ == "__main__":
    main()
