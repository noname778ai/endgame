#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P14 SELF-TEST SUITE - mod_client.py v14.0.0-ultra-ultra-pro-max (P14)
=============================================================================
 Mock client-side lab app + full assertion suite:
   - Unit tests (pure helpers: forms/token-regex/XFO/FA/origins/pm-JS/SameSite)
   - Active run e2e (stages A..K verdict assertions, RoE gate OFF)
   - Gated replay run (csrf_allow_replay=True -> token-less CONFIRMED)
   - Artifact integrity (24 output files, matrices, catalog, feedforward)
   - RWX rule (0777 on every result file)
   - CORS zero-egress check (sirf .invalid/null/own-host origins)
   - Passive mode (allow_active=False -> 0 probes, hypotheses only)
   - Checkpoint replay (FIX-4: findings re-derivation on resume)
 Detection-only discipline honored: lab me bhi PoCs inert hain.
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
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "phases", "block3_input")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_client as MC                                      # noqa: E402
import wasp_core as WC                                       # noqa: E402

BASE = os.path.join(HERE, "p14_test_base")
BASE_GATED = os.path.join(HERE, "p14_test_base_gated")
BASE2 = os.path.join(HERE, "p14_test_base_passive")
ENG = "p14lab"
ENG_G = "p14lab2"
ENG_P = "p14labp"

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
# MOCK CLIENT LAB
# - /form_notoken      POST form (bio field) w/o token, accepts POST  -> replay CONFIRMED
# - /form_token        POST form WITH csrf_token, validates (403 on bad) -> HARDENED
# - /form_sensitive    POST form password field w/o token -> replay SKIPPED
# - /login             login form w/o token -> login-CSRF
# - /logout_get        GET logout link -> logout-CSRF SUSPECTED
# - /api/reflect       echoes arbitrary .invalid origin + ACAC true  -> CORS CONFIRMED
# - /api/suffixbug     reflects origins containing host              -> suffix CONFIRMED
# - /api/null          reflects null origin + ACAC true              -> null CONFIRMED
# - /api/star          ACAO:* (no creds)                             -> WILDCARD
# - /api/cachebug      reflects origin, no ACAC, cacheable no Vary   -> cache risk
# - /api/preflight     OPTIONS permissive (POST/PUT/DELETE + headers)-> preflight DANGEROUS
# - /api/safe          no ACAO                                       -> HARDENED
# - /settings/framable 200, no XFO/CSP (sensitive)                   -> framing CONFIRMED
# - /account/protected XFO DENY + frame-ancestors 'none'             -> HARDENED
# - /account/legacyframe XFO ALLOW-FROM                              -> deprecated SUSPECTED
# - /pm                message listener no origin check + innerHTML  -> pm CONFIRMED
# - /pmweak            listener startsWith origin                    -> prefix SUSPECTED
# - /pmwild            postMessage(..., '*') sender                  -> wildcard
# - /storage           localStorage.setItem('access_token', JWT)     -> storage chain
# - /oauth/authorize?... (no state) + /oauth/authorize2?...response_type=token
# - /crossdomain.xml   allow-access-from domain="*"                  -> legacy SUSPECTED
# ===========================================================================
LAB = {"posts": [], "gets": 0, "options": 0}


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockClientLab/1.0"

    def log_message(self, *a):
        pass

    def _respond(self, status, text, headers=None, cookies=None):
        body = text.encode("utf-8", "ignore")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "MockClientLab/1.0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        for c in (cookies or []):
            self.send_header("Set-Cookie",
                             c if isinstance(c, str) else "%s=%s; %s" % c)
        self.end_headers()
        self.wfile.write(body)

    def _origin(self):
        return self.headers.get("Origin", "") or ""

    def do_GET(self):
        LAB["gets"] += 1
        sp = urlsplit(self.path)
        path, q = sp.path, parse_qs(sp.query)
        org = self._origin()
        ck = [("sid", "s3ssiontok", "Path=/; HttpOnly"),
              ("XSRF-TOKEN", "tok123", "SameSite=None")]

        if path in ("/", ""):
            return self._respond(200, "Mock client lab P14. See index in test file.",
                                 cookies=ck)

        if path == "/form_notoken":
            return self._respond(200, "<html><body><h2>Update bio</h2>"
                                      "<form method=POST action='/form_notoken'>"
                                      "<input name='bio' value='hello'>"
                                      "<button>Save</button></form></body></html>",
                                 cookies=ck)

        if path == "/form_token":
            return self._respond(200, "<html><body><h2>Update bio (protected)</h2>"
                                      "<form method=POST action='/form_token'>"
                                      "<input type=hidden name='csrf_token' "
                                      "value='wasp14tok1234567890'>"
                                      "<input name='bio' value='hello'>"
                                      "<button>Save</button></form></body></html>",
                                 cookies=ck)

        if path == "/form_sensitive":
            return self._respond(200, "<html><body><h2>Change password</h2>"
                                      "<form method=POST action='/form_sensitive'>"
                                      "<input type=password name='password'>"
                                      "<input type=password name='new_password'>"
                                      "<button>Change</button></form></body></html>",
                                 cookies=ck)

        if path == "/login":
            return self._respond(200, "<html><body><h2>Login</h2>"
                                      "<form method=POST action='/login'>"
                                      "<input name='username'><input "
                                      "type=password name='password'>"
                                      "<button>Login</button></form></body></html>",
                                 cookies=ck)

        if path == "/logout_get" and q.get("do", ["0"])[0] == "1":
            return self._respond(200, "logged out. session cleared.")

        if path == "/api/reflect":
            if org == "https://wasp-cors-probe.invalid":
                return self._respond(200, json.dumps({"ok": True, "user": "u1"}),
                                     {"Access-Control-Allow-Origin": org,
                                      "Access-Control-Allow-Credentials": "true",
                                      "Vary": "Origin",
                                      "Content-Type": "application/json"})
            return self._respond(200, json.dumps({"ok": True}),
                                 {"Content-Type": "application/json"})

        if path == "/api/suffixbug":
            if org and "127.0.0.1" in org and \
               org != "https://wasp-cors-probe.invalid" and not org.startswith("null"):
                return self._respond(200, json.dumps({"secret": "v14lab"}),
                                     {"Access-Control-Allow-Origin": org,
                                      "Access-Control-Allow-Credentials": "true",
                                      "Content-Type": "application/json"})
            return self._respond(200, json.dumps({"ok": True}),
                                 {"Content-Type": "application/json"})

        if path == "/api/null":
            if org == "null":
                return self._respond(200, json.dumps({"secret": "nullish"}),
                                     {"Access-Control-Allow-Origin": "null",
                                      "Access-Control-Allow-Credentials": "true",
                                      "Content-Type": "application/json"})
            return self._respond(200, json.dumps({"ok": True}),
                                 {"Content-Type": "application/json"})

        if path == "/api/star":
            return self._respond(200, json.dumps({"public": "data"}),
                                 {"Access-Control-Allow-Origin": "*",
                                  "Content-Type": "application/json"})

        if path == "/api/cachebug":
            h = {"Content-Type": "application/json",
                 "Cache-Control": "public, max-age=300"}
            if org == "https://wasp-cors-probe.invalid":
                h["Access-Control-Allow-Origin"] = org
            return self._respond(200, json.dumps({"c": 1}), h)

        if path == "/api/preflight":
            return self._respond(200, json.dumps({"p": 1}),
                                 {"Content-Type": "application/json"})

        if path == "/api/safe":
            return self._respond(200, json.dumps({"s": 1}),
                                 {"Content-Type": "application/json"})

        if path == "/settings/framable":
            return self._respond(200, "<html><body><h1>Account settings</h1>"
                                      "<form method=POST action='/form_notoken'>"
                                      "<input name='bio'><button>Save</button>"
                                      "</form></body></html>", cookies=ck)

        if path == "/account/protected":
            return self._respond(200, "<html><body><h1>Protected page</h1></body></html>",
                                 {"X-Frame-Options": "DENY",
                                  "Content-Security-Policy":
                                      "frame-ancestors 'none'; default-src 'self'"},
                                 cookies=ck)

        if path == "/account/legacyframe":
            return self._respond(200, "<html><body><h1>Legacy frame page</h1></body>"
                                      "</html>",
                                 {"X-Frame-Options": "ALLOW-FROM https://trusted.example"},
                                 cookies=ck)

        if path == "/pm":
            return self._respond(200, "<html><body><div id=out></div><script>"
                                      "addEventListener('message', function(e){"
                                      "document.getElementById('out').innerHTML "
                                      "= e.data.msg;});"
                                      "</script></body></html>", cookies=ck)

        if path == "/pmweak":
            return self._respond(200, "<html><body><script>"
                                      "addEventListener('message', function(e){"
                                      "if(e.origin.startsWith('https://app'))"
                                      "{handle(e.data);}});"
                                      "</script></body></html>", cookies=ck)

        if path == "/pmwild":
            return self._respond(200, "<html><body><script>"
                                      "var d={tok:'secret123'};"
                                      "parent.postMessage(JSON.stringify(d), '*');"
                                      "</script></body></html>", cookies=ck)

        if path == "/storage":
            return self._respond(200, "<html><body><script>"
                                      "localStorage.setItem('access_token', "
                                      "'eyJhbGciOiJIUzI1NiJ9.eyJ1IjoidjE0In0.sig');"
                                      "</script></body></html>", cookies=ck)

        if path == "/oauth/authorize":
            return self._respond(200, "<html><body><a href='/oauth/authorize?"
                                      "client_id=wasp14&response_type=code&"
                                      "redirect_uri=https://app.example.com/cb'>"
                                      "Authorize</a></body></html>", cookies=ck)

        if path == "/oauth/authorize2":
            return self._respond(200, "<html><body><a href='/oauth/authorize2?"
                                      "client_id=wasp14&response_type=token&"
                                      "redirect_uri=https://app.example.com/cb'>"
                                      "Authorize implicit</a></body></html>", cookies=ck)

        if path == "/crossdomain.xml":
            return self._respond(200, '<?xml version="1.0"?><cross-domain-policy>'
                                      '<allow-access-from domain="*"/>'
                                      "</cross-domain-policy>",
                                 {"Content-Type": "text/xml"})

        return self._respond(404, "404 page not found: %s" % path)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "ignore") if n else ""
        LAB["posts"].append({"path": urlsplit(self.path).path,
                             "origin": self._origin(),
                             "body": body, "ct": self.headers.get("Content-Type", "")})
        sp = urlsplit(self.path)
        path = sp.path

        if path == "/form_notoken":
            return self._respond(200, "<html><body><p>posted: %s</p></body></html>"
                                 % body[:120])
        if path == "/form_token":
            if parse_qs(body).get("csrf_token", [""])[0] == "wasp14tok1234567890":
                return self._respond(200, "<html><body><p>posted ok</p></body></html>")
            return self._respond(403, "CSRF validation failed: token invalid or "
                                      "missing. Request rejected.")
        if path == "/form_sensitive":
            return self._respond(200, "password changed")
        if path == "/login":
            return self._respond(200, "welcome")
        return self._respond(404, "no route")

    def do_OPTIONS(self):
        LAB["options"] += 1
        org = self._origin()
        if urlsplit(self.path).path == "/api/preflight":
            return self._respond(204, "",
                                 {"Access-Control-Allow-Origin": org,
                                  "Access-Control-Allow-Credentials": "true",
                                  "Access-Control-Allow-Methods":
                                      "GET, POST, PUT, DELETE, OPTIONS",
                                  "Access-Control-Allow-Headers":
                                      "Content-Type, X-Auth-Token, X-Wasp-Probe",
                                  "Access-Control-Max-Age": "600"})
        return self._respond(204, "")


class LabServer(ThreadingHTTPServer):
    daemon_threads = True


# ===========================================================================
# ENV BOOTSTRAP
# ===========================================================================
def seed(base, engagement, origin, gated=False):
    shutil.rmtree(base, ignore_errors=True)
    eng = os.path.join(base, engagement)
    for sub in ("sessions", "auth", "understand", "js", "xss", "active",
                "surface", "access"):
        os.makedirs(os.path.join(eng, sub), exist_ok=True)
    with open(os.path.join(base, "scope.json"), "w") as f:
        json.dump({"engagement": engagement, "authorized": True,
                   "authorization_reference": "P14 self-test lab (localhost mock)",
                   "targets": [origin], "ips": ["127.0.0.1"],
                   "notes": "detection-only lab"}, f, indent=2)
    return eng


def seed_p14_files(eng, origin):
    def w(rel, obj):
        p = os.path.join(eng, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            if isinstance(obj, str):
                f.write(obj)
            else:
                json.dump(obj, f, indent=2)
    # P10 csrf_mapping (weak: forms w/o csrf + samesite cookies)
    w("sessions/csrf_mapping.json",
      {"weak": True,
       "forms_without_csrf": [{"url": origin + "/form_notoken", "method": "POST"}],
       "samesite_missing_cookies": [{"name": "sid", "samesite": "", "secure": False,
                                     "httponly": True, "domain": "127.0.0.1"}]})
    # P10 session_hardening (clickjacking page)
    w("sessions/session_hardening.json",
      {"clickjacking": [{"endpoint": origin + "/settings/framable"}],
       "hsts_missing": [], "referrer_weak": [], "mixup": []})
    # P10 ws_surface
    w("sessions/ws_surface.json",
      {"ws_endpoints": ["ws://127.0.0.1/socket-lab"], "hint": "session model unknown"})
    # P2 forms
    w("understand/forms.json",
      {"forms": [
          {"url": origin + "/form_notoken", "method": "POST",
           "fields": [{"name": "bio", "type": "text"}]},
          {"url": origin + "/form_token", "method": "POST",
           "fields": [{"name": "csrf_token", "type": "hidden"},
                      {"name": "bio", "type": "text"}]},
          {"url": origin + "/form_sensitive", "method": "POST",
           "fields": [{"name": "password", "type": "password"},
                      {"name": "new_password", "type": "password"}]},
          {"url": origin + "/login", "method": "POST",
           "fields": [{"name": "username", "type": "text"},
                      {"name": "password", "type": "password"}]},
          {"url": origin + "/form_notoken?_token=leaky1", "method": "POST",
           "fields": [{"name": "bio", "type": "text"}]}]})
    # P9 auth_cors + auth_endpoints
    w("auth/auth_cors.json", {"cors": [{"url": origin + "/api/reflect",
                                        "summary": "ACAO echo + ACAC"}]})
    w("auth/auth_endpoints.txt", origin + "/logout_get?do=1\n")
    # P7 endpoints + pm + storage
    w("js/endpoints.txt", "\n".join([
        origin + "/api/star", origin + "/api/null", origin + "/api/suffixbug",
        origin + "/api/preflight", origin + "/api/safe", origin + "/api/cachebug",
        origin + "/oauth/authorize?client_id=wasp14&response_type=code&"
        "redirect_uri=https://app.example.com/cb",
        origin + "/oauth/authorize2?client_id=wasp14&response_type=token&"
        "redirect_uri=https://app.example.com/cb", ""]) + "\n")
    w("js/postmessage_audit.txt",
      "message listener: %s/pm (no origin check)\n"
      "message listener: %s/pmweak (startsWith)\n"
      "sender wildcard: %s/pmwild\n" % (origin, origin, origin))
    w("js/storage_tokens.txt", "localStorage access_token @ %s/storage\n" % origin)
    # P13 feedforward -> to_phase14_client
    w("xss/feedforward.json", {"phase": "13-xss", "routing": {
        "to_phase14_client": {
            "dom_confirmed": [{"url": origin + "/pm", "sink": "innerHTML",
                               "same_script_link": True}],
            "ripe_reflections": [{"url": origin + "/form_notoken?q=1", "param": "q",
                                  "verbatim": True}],
            "note": "P14 client-side/DOM wave isi seed par"}}, "notes": []})
    # P4 security headers (xfo missing on framable page)
    w("active/security_headers.txt",
      "[%s] \nx-frame-options: missing (no header)\n" % origin)
    # P8 priority queue
    w("surface/priority_queue.json",
      {"queue": [{"url": origin + "/account/protected", "score": 8},
                 {"url": origin + "/account/legacyframe", "score": 7},
                 {"url": origin + "/settings/framable", "score": 7}]})
    # P11 idor verdicts (state-change endpoint)
    w("access/idor_verdicts.json",
      {"records": [{"url": origin + "/form_sensitive?id=1", "verdict": "CONFIRMED"}]})


def make_cfg(engagement, base, gated=False, active=True):
    cfg = WC.Cfg(None)
    cfg.rate_limit = 400.0
    cfg.jitter = 0.0
    cfg.retries = 0
    cfg.timeout = 20
    cfg.max_requests = 200000
    cfg.allow_active = active
    cfg.resume = True
    cfg.allow_write_http = False        # master switch OFF (force_write hi gate)
    cfg.client_csrf_form_cap = 40
    cfg.client_cors_endpoints = 8
    cfg.client_cors_origin_cap = 12
    cfg.client_frame_pages = 12
    cfg.client_pm_fetch = 4
    cfg.client_get_crawl = 12
    cfg.client_replay_budget = 6
    cfg.csrf_allow_replay = gated       # RoE gate
    cfg.client_ws_handshake = False
    cfg.client_probe_crossdomain = True
    cfg.client_preflight = True
    cfg.module_outdir = None
    cfg.checkpoint = None
    return cfg


# ===========================================================================
# UNIT TESTS (pure helpers - 0 network)
# ===========================================================================
def unit_tests(origin):
    print("\n== UNIT: helpers ==")
    # _parse_forms
    html_doc = ("<form method=POST action='/form_token'><input type=hidden "
                "name='csrf_token' value='abc123'><input name='bio'></form>")
    forms = MC._parse_forms(html_doc, origin + "/page")
    check("parse_forms: 1 form", len(forms) == 1, str(len(forms)))
    check("parse_forms: token detected", forms[0]["has_token"] is True)
    check("parse_forms: action joined", forms[0]["action"] == origin + "/form_token",
          forms[0]["action"])
    check("parse_forms: method POST", forms[0]["method"] == "POST")
    # CSRF token regex
    check("token-regex: csrftoken", bool(MC.CSRF_TOKEN_NAMES.match("csrfmiddlewaretoken")))
    check("token-regex: authenticity", bool(MC.CSRF_TOKEN_NAMES.match("authenticity_token")))
    check("token-regex: __RequestVerification",
          bool(MC.CSRF_TOKEN_NAMES.match("__RequestVerificationToken")))
    check("token-regex: _wpnonce", bool(MC.CSRF_TOKEN_NAMES.match("_wpnonce")))
    check("token-regex: NOT username", not MC.CSRF_TOKEN_NAMES.match("username"))
    # state-change score
    check("sc-score: POST password", MC._state_change_score(
        "POST", origin + "/changepass", [{"name": "password", "type": "p"}]) >= 8.0)
    check("sc-score: GET home", MC._state_change_score("GET", origin + "/", []) < 4.0)
    check("sc-score: POST logout", MC._state_change_score(
        "POST", origin + "/logout", []) >= 6.0)
    # xfo verdicts
    check("xfo: missing", MC.xfo_verdict("") == ("missing", "header hi nahi"))
    check("xfo: deny", MC.xfo_verdict("DENY")[0] == "protected")
    check("xfo: sameorigin case", MC.xfo_verdict("sameorigin")[0] == "protected")
    check("xfo: allow-from deprecated", MC.xfo_verdict(
        "ALLOW-FROM https://x.example")[0] == "deprecated")
    check("xfo: garbage invalid", MC.xfo_verdict("allow all")[0] == "invalid")
    # frame-ancestors verdicts
    check("fa: missing", MC.frame_ancestors_verdict("")[0] == "missing")
    check("fa: none", MC.frame_ancestors_verdict("'none'")[0] == "protected")
    check("fa: wildcard", MC.frame_ancestors_verdict("*")[0] == "wildcard")
    check("fa: scheme", MC.frame_ancestors_verdict("https:")[0] == "scheme-source")
    check("fa: hostlist", MC.frame_ancestors_verdict("'self' https://a.example")[0]
          == "hostlist")
    # origin variants
    ov = MC.build_origin_variants(origin + "/api/x", 12)
    check("cors: 12 variants", len(ov) == 12, str(len(ov)))
    tags = [t for t, _ in ov]
    check("cors: null present", "null-origin" in tags)
    check("cors: suffix present", "suffix-append" in tags)
    check("cors: all reserved tld/null/own",
          all(("wasp-cors-probe.invalid" in o) or o == "null"
              or o.endswith("127.0.0.1") or o == "https://www.127.0.0.1"
              for o in [o for _, o in ov]),
          str([o for _, o in ov][:3]))
    # _post_rejection
    class FakeR:
        status = 403
        error = None
        text = "CSRF token invalid"
        body = b"CSRF token invalid"
    check("rejection: 403+sign", MC._post_rejection(FakeR())[0] is True)
    # pm analysis
    js1 = "addEventListener('message', function(e){document.body.innerHTML = e.data;});"
    r1 = MC.pm_analyze_js(js1, origin + "/pm")
    check("pm: sink+no-origin CONFIRMED", any(
        x.get("verdict") == "CONFIRMED" and x.get("sink") for x in r1), str(r1))
    js2 = ("addEventListener('message', function(e){"
           "if(e.origin.startsWith('https://app')){go(e.data);}});")
    r2 = MC.pm_analyze_js(js2, origin + "/pmweak")
    check("pm: prefix SUSPECTED", any(
        x.get("verdict") == "SUSPECTED" and "prefix" in (x.get("technique") or "")
        for x in r2), str(r2))
    js3 = "addEventListener('message', function(e){if(e.origin === 'https://ok.example'){ok(e.data);}});"
    r3 = MC.pm_analyze_js(js3, origin + "/pmstrict")
    check("pm: strict HARDENED", any(x.get("verdict") == "HARDENED" for x in r3), str(r3))
    r4 = MC.pm_analyze_js("parent.postMessage(d, '*');", origin + "/pmwild")
    check("pm: wildcard sender", any(x.get("kind") == "sender-wildcard" for x in r4))
    r5 = MC.pm_analyze_js("<iframe sandbox='allow-scripts allow-same-origin'>",
                          origin + "/sb")
    check("pm: sandbox combo", any(x.get("kind") == "iframe-sandbox-combo" for x in r5))
    # samesite audit
    recs = MC.samesite_audit(["sid=abc; Path=/; HttpOnly",
                              "XSRF-TOKEN=t; SameSite=None",
                              "__Host-c=1; Secure; Path=/"], [])
    check("samesite: 3 cookies", len(recs) == 3, str(len(recs)))
    m = {r["name"]: r for r in recs}
    check("samesite: sid missing", m["sid"]["samesite"] == "")
    check("samesite: xsrf none-nosecure", m["XSRF-TOKEN"]["samesite"] == "none"
          and not m["XSRF-TOKEN"]["secure"])
    check("samesite: host-prefix", m["__Host-c"]["host_prefix"] is True)
    # oauth regex
    check("oauth: state", bool(MC.OAUTH_STATE.search(
        "https://x/cb?state=abc&code=1")))
    check("oauth: implicit", bool(MC.OAUTH_IMPLICIT.search(
        "https://x/authorize?response_type=token")))
    check("oauth: pkce", bool(MC.OAUTH_PKCE.search(
        "https://x/authorize?code_challenge=xyz")))
    # low-risk/sensitive fields
    check("fields: bio low-risk", bool(MC.LOW_RISK_FIELDS.match("bio")))
    check("fields: password sensitive", bool(MC.SENSITIVE_FIELDS.search("new_password")))
    # technique matrix smoke (realistic inputs)
    census_fake = [{"token_in_get": True, "token_names": ["csrf_token"],
                    "token_in_form": True, "meta_token": False}]
    cors_fake = [{"null_ok": True, "suffix_ok": True, "cache_vary_risk": True}]
    frame_fake = [{"xfo_verdict": "deprecated"}]
    pm_fake = [{"technique": "prefix-origin", "json_parse": True}]
    oauth_fake = [{"state": False, "implicit": True}]
    same_fake = [{"domain": ".target.example.com"}]
    tm = MC.technique_matrix(census_fake, cors_fake, frame_fake, pm_fake,
                             oauth_fake, same_fake, [], [], ws_count=1)
    check("tech-matrix: >=15 rows", len(tm) >= 15, str(len(tm)))
    check("tech-matrix: ws row", any(t["technique"] == "ws-cross-origin-hijack"
                                     for t in tm))
    # catalog + cwe map
    cat = MC.build_catalog_md()
    check("catalog: rows present", cat.count("|") > 60)
    check("cwe-map: csrf", "CWE-352" in json.dumps(MC.CWE_OWASP_MAP_CLIENT))
    check("cwe-map: clickjacking", "CWE-1021" in json.dumps(MC.CWE_OWASP_MAP_CLIENT))
    check("pii-redact: jwt", "REDACTED" in MC.pii_redact(
        "tok eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1IjoidjE0In0.sig12345 x"))


# ===========================================================================
# ARTIFACT INTEGRITY
# ===========================================================================
P14_ARTIFACTS = ["client_surface.json", "client_targets.txt", "csrf_matrix.json",
                 "cors_matrix.json", "cors_probe_log.json", "framing_matrix.json",
                 "postmessage_audit_v14.json", "storage_chains.json",
                 "oauth_state_audit.json", "samesite_audit.json", "ws_audit.json",
                 "technique_matrix_client.json", "legacy_policies.json",
                 "CLIENT_FINDINGS.md", "client_test_plan.md", "client_chains.txt",
                 "TECHNIQUES_CATALOG_CLIENT.md", "cwe_owasp_map_client.json",
                 "findings.json", "feedforward.json", "MANIFEST.json"]


def artifact_tests(out, F_count_min=1):
    print("\n== ARTIFACTS ==")
    for a in P14_ARTIFACTS:
        check("artifact: %s" % a, os.path.isfile(os.path.join(out, a)))
    mj = json.load(open(os.path.join(out, "findings.json")))
    check("findings: >=%d" % F_count_min, mj.get("count", 0) >= F_count_min,
          str(mj.get("count")))
    ff = json.load(open(os.path.join(out, "feedforward.json")))
    rt = ff.get("routing", {})
    check("feedforward: to_phase17", "to_phase17_api" in rt)
    check("feedforward: to_phase19", "to_phase19_ws" in rt)
    check("feedforward: to_phase20", "to_phase20_logic" in rt)
    check("feedforward: to_phase26", "to_phase26_cache" in rt)
    check("feedforward: to_phase32", "to_phase32_report" in rt)
    man = json.load(open(os.path.join(out, "MANIFEST.json")))
    check("manifest: >=20 files", len(man.get("files", [])) >= 20,
          str(len(man.get("files", []))))
    # RWX 0777
    bad = []
    for dp, dns, fns in os.walk(out):
        for fn in fns:
            p = os.path.join(dp, fn)
            if (os.stat(p).st_mode & 0o777) != 0o777:
                bad.append(p)
    check("RWX: sab files 0777", not bad, str(bad[:3]))
    # CORS zero-egress: log me sirf reserved/own origins
    log = json.load(open(os.path.join(out, "cors_probe_log.json")))
    bad_origins = [e.get("origin", "") for e in log
                   if e.get("origin") and "wasp-cors-probe.invalid" not in
                   e.get("origin", "") and e.get("origin") != "null"
                   and "127.0.0.1" not in e.get("origin", "")]
    check("cors: zero external egress", not bad_origins, str(bad_origins[:3]))


# ===========================================================================
# E2E ACTIVE RUN (RoE gate OFF)
# ===========================================================================
def e2e_gate_off(origin, out):
    print("\n== E2E (gate OFF) ==")
    cm = json.load(open(os.path.join(out, "csrf_matrix.json")))
    by_url = {r["url"].split("?")[0]: r for r in cm}
    r_nt = by_url.get(origin + "/form_notoken", {})
    check("csrf: /form_notoken SUSPECTED (gate OFF)",
          r_nt.get("verdict") == "SUSPECTED", str(r_nt.get("verdict")))
    check("csrf: /form_notoken no replay", r_nt.get("replay") is None)
    r_tok = by_url.get(origin + "/form_token", {})
    check("csrf: /form_token HARDENED (token present)",
          r_tok.get("verdict") == "HARDENED", str(r_tok.get("verdict")))
    r_sen = by_url.get(origin + "/form_sensitive", {})
    check("csrf: /form_sensitive SUSPECTED", r_sen.get("verdict") == "SUSPECTED",
          str(r_sen.get("verdict")))
    check("csrf: /form_sensitive replay skipped",
          r_sen.get("replay_skipped") == "sensitive-fields")
    # lab par KOI POST nahi gaya (gate OFF)
    check("rogue: 0 POST w/ gate OFF", len(LAB["posts"]) == 0,
          str(LAB["posts"][:2]))
    # SameSite
    ss = json.load(open(os.path.join(out, "samesite_audit.json")))
    m = {r["name"]: r for r in ss}
    check("samesite: sid MISSING verdict", m.get("sid", {}).get("verdict") == "MISSING")
    check("samesite: XSRF INSECURE verdict (None-no-Secure)",
          m.get("XSRF-TOKEN", {}).get("verdict") == "INSECURE")
    # CORS
    cors = json.load(open(os.path.join(out, "cors_matrix.json")))
    cm_by = {r["url"].split("?")[0]: r for r in cors}
    check("cors: /api/reflect CONFIRMED arbitrary",
          cm_by.get(origin + "/api/reflect", {}).get("verdict") == "CONFIRMED"
          and cm_by[origin + "/api/reflect"].get("technique") == "arbitrary-reflection",
          str(cm_by.get(origin + "/api/reflect", {}).get("technique")))
    check("cors: /api/suffixbug CONFIRMED suffix",
          cm_by.get(origin + "/api/suffixbug", {}).get("technique")
          == "suffix-match-bypass",
          str(cm_by.get(origin + "/api/suffixbug", {}).get("technique")))
    check("cors: /api/null CONFIRMED null",
          cm_by.get(origin + "/api/null", {}).get("technique") == "null-origin",
          str(cm_by.get(origin + "/api/null", {}).get("technique")))
    check("cors: /api/star WILDCARD",
          cm_by.get(origin + "/api/star", {}).get("verdict") == "WILDCARD")
    check("cors: /api/cachebug cache risk",
          cm_by.get(origin + "/api/cachebug", {}).get("cache_vary_risk") is True)
    check("cors: /api/preflight dangerous",
          cm_by.get(origin + "/api/preflight", {}).get("preflight", {})
          .get("dangerous_methods") is True)
    check("cors: /api/safe HARDENED",
          cm_by.get(origin + "/api/safe", {}).get("verdict") == "HARDENED")
    # Framing
    fr = json.load(open(os.path.join(out, "framing_matrix.json")))
    fr_by = {r["url"].split("?")[0]: r for r in fr}
    check("framing: /settings/framable CONFIRMED",
          fr_by.get(origin + "/settings/framable", {}).get("verdict") == "CONFIRMED")
    check("framing: sensitive-page flag",
          fr_by.get(origin + "/settings/framable", {}).get("sensitive_page") is True)
    check("framing: /account/protected HARDENED",
          fr_by.get(origin + "/account/protected", {}).get("verdict") == "HARDENED")
    check("framing: /account/legacyframe SUSPECTED",
          fr_by.get(origin + "/account/legacyframe", {}).get("verdict") == "SUSPECTED")
    # postMessage
    pm = json.load(open(os.path.join(out, "postmessage_audit_v14.json")))
    check("pm: /pm sink CONFIRMED", any(
        x.get("verdict") == "CONFIRMED" and x.get("sink") and "/pm" in x.get("url", "")
        for x in pm), str(pm[:2]))
    check("pm: /pmweak prefix", any(
        "prefix" in (x.get("technique") or "") and "/pmweak" in x.get("url", "")
        for x in pm))
    check("pm: /pmwild wildcard", any(
        x.get("kind") == "sender-wildcard" for x in pm))
    # OAuth
    oa = json.load(open(os.path.join(out, "oauth_state_audit.json")))
    o_by = {r["url"].split("?")[0]: r for r in oa}
    check("oauth: authorize state missing",
          o_by.get(origin + "/oauth/authorize", {}).get("state") is False)
    check("oauth: authorize2 implicit",
          o_by.get(origin + "/oauth/authorize2", {}).get("implicit") is True)
    # Storage
    st = json.load(open(os.path.join(out, "storage_chains.json")))
    check("storage: access_token found", any(
        x.get("key") == "access_token" for x in st), str(st[:2]))
    # Legacy
    lg = json.load(open(os.path.join(out, "legacy_policies.json")))
    check("legacy: crossdomain wildcard", any(
        x.get("wildcard") for x in lg), str(lg))
    # WS
    ws = json.load(open(os.path.join(out, "ws_audit.json")))
    check("ws: hypothesis record", len(ws) >= 1 and
          ws[0].get("probe_ran") is False)
    # PoCs (gate OFF: SUSPECTED csrf bhi PoC banata hai; framing CONFIRMED)
    poc_dir = os.path.join(out, "csrf_poc")
    frame_dir = os.path.join(out, "framing_poc")
    check("poc: csrf_poc dir", os.path.isdir(poc_dir)
          and len(os.listdir(poc_dir)) >= 1)
    check("poc: framing_poc dir", os.path.isdir(frame_dir)
          and len(os.listdir(frame_dir)) >= 1)
    # PoC inert (no auto-submit)
    if os.path.isdir(poc_dir):
        sample = open(os.path.join(poc_dir, sorted(os.listdir(poc_dir))[0])).read()
        check("poc: inert (no auto-submit JS)", "submit()" not in sample
              and "RoE" in sample)
    # findings
    fj = json.load(open(os.path.join(out, "findings.json")))
    keys = {f["key"] for f in fj.get("findings", [])}
    expected_keys = {"csrf_no_token_state_change", "csrf_samesite_none_insecure",
                     "csrf_samesite_missing", "cors_credentials_reflected",
                     "cors_suffix_match_bypass", "cors_null_origin_allowed",
                     "cors_origin_reflection", "cors_preflight_dangerous",
                     "framing_no_protection", "framing_xfo_deprecated",
                     "pm_sink_in_listener", "pm_no_origin_check",
                     "oauth_state_missing", "oauth_implicit_flow",
                     "cors_legacy_crossdomain", "csrf_logout_get", "csrf_login",
                     "storage_token_in_localstorage", "csrf_token_in_get",
                     "defense_census_missing"}
    missing = expected_keys - keys
    check("findings: 20 expected keys", not missing, "missing=%s" % sorted(missing))
    sevs = [f["severity"] for f in fj.get("findings", [])]
    check("findings: >=1 high", "high" in sevs, str(set(sevs)))
    # chains
    ch = open(os.path.join(out, "client_chains.txt")).read()
    check("chains: >=1 chain", "CHAIN 1" in ch, ch[:80])
    # technique matrix file
    tm = json.load(open(os.path.join(out, "technique_matrix_client.json")))
    check("tech: >=14 rows", len(tm) >= 14, str(len(tm)))
    # test plan mentions RoE
    plan = open(os.path.join(out, "client_test_plan.md")).read()
    check("plan: manual wave", "MANUAL" in plan.upper() and "RoE" in plan)


# ===========================================================================
# GATED REPLAY RUN (csrf_allow_replay=True)
# ===========================================================================
def e2e_gate_on(origin, out):
    print("\n== E2E (gate ON - RoE replay) ==")
    cm = json.load(open(os.path.join(out, "csrf_matrix.json")))
    by_url = {r["url"].split("?")[0]: r for r in cm}
    r_nt = by_url.get(origin + "/form_notoken", {})
    check("csrf: /form_notoken CONFIRMED (replay)",
          r_nt.get("verdict") == "CONFIRMED", str(r_nt.get("verdict")))
    check("csrf: replay ran w/ probes", (r_nt.get("replay") or {}).get("ran") is True
          and len((r_nt.get("replay") or {}).get("probes", [])) == 2)
    # lab ne POST receive kiya, wasp origin se, no token
    posts = [p for p in LAB["posts"] if p["path"] == "/form_notoken"]
    check("replay: POSTs hit lab", len(posts) >= 2, str(len(posts)))
    check("replay: origin = wasp probe", all(
        "wasp-csrf-probe.invalid" in p["origin"] for p in posts))
    check("replay: no token field", all(
        "csrf_token=" not in p["body"] for p in posts[:2]))
    check("replay: canary present", any(
        "waspP14canary" in p["body"] for p in posts))
    # sensitive form par POST NAHI gaya
    sen_posts = [p for p in LAB["posts"] if p["path"] == "/form_sensitive"]
    check("replay: sensitive SKIP", len(sen_posts) == 0, str(sen_posts))
    # protected form par bhi nahi (token wala)
    tok_posts = [p for p in LAB["posts"] if p["path"] == "/form_token"]
    check("replay: tokened-form untouched", len(tok_posts) == 0, str(tok_posts))
    fj = json.load(open(os.path.join(out, "findings.json")))
    check("findings: csrf_token_not_validated", any(
        f["key"] == "csrf_token_not_validated" for f in fj.get("findings", [])))
    # PoC w/ canary
    poc_dir = os.path.join(out, "csrf_poc")
    sample = open(os.path.join(poc_dir, sorted(os.listdir(poc_dir))[0])).read()
    check("poc: canary embedded", "waspP14canary" in sample)


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    # ---------- lab start ----------
    srv = LabServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    origin = "http://127.0.0.1:%d" % port
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    print("Mock client lab: %s" % origin)

    try:
        # ---------- unit ----------
        unit_tests(origin)

        # ---------- active run (gate OFF) ----------
        print("\n== ACTIVE RUN (gate OFF) ==")
        eng = seed(BASE, ENG, origin)
        seed_p14_files(eng, origin)
        cfg = make_cfg(ENG, BASE, gated=False)
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        out = MC.run(cfg, scope, BASE)
        check("run: outdir bana", os.path.isdir(out), out)
        e2e_gate_off(origin, out)
        artifact_tests(out, F_count_min=10)
        gets_after_run1 = LAB["gets"]

        # ---------- checkpoint replay (same BASE, fresh cfg) ----------
        print("\n== CHECKPOINT REPLAY ==")
        cfg2 = make_cfg(ENG, BASE, gated=False)
        scope2 = WC.Scope(os.path.join(BASE, "scope.json"))
        out2 = MC.run(cfg2, scope2, BASE)
        fj1 = json.load(open(os.path.join(out, "findings.json")))
        fj2 = json.load(open(os.path.join(out2, "findings.json")))
        check("replay: findings stable", fj1["count"] == fj2["count"],
              "%s vs %s" % (fj1["count"], fj2["count"]))
        cm1 = json.load(open(os.path.join(out, "csrf_matrix.json")))
        cm2 = json.load(open(os.path.join(out2, "csrf_matrix.json")))
        v1 = {r["url"]: r["verdict"] for r in cm1}
        v2 = {r["url"]: r["verdict"] for r in cm2}
        check("replay: csrf verdicts stable", v1 == v2)
        check("replay: 0 naye lab GETs (census cached)",
              LAB["gets"] - gets_after_run1 < len(v1) + 6,
              "delta=%d" % (LAB["gets"] - gets_after_run1))

        # ---------- gated replay run ----------
        print("\n== GATED RUN (csrf_allow_replay=True) ==")
        LAB["posts"] = []
        eng_g = seed(BASE_GATED, ENG_G, origin)
        seed_p14_files(eng_g, origin)
        cfg3 = make_cfg(ENG_G, BASE_GATED, gated=True)
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = MC.run(cfg3, scope3, BASE_GATED)
        e2e_gate_on(origin, out3)

        # ---------- passive mode ----------
        print("\n== PASSIVE MODE ==")
        gets_before_passive = LAB["gets"]
        eng_p = seed(BASE2, ENG_P, origin)
        seed_p14_files(eng_p, origin)
        cfg4 = make_cfg(ENG_P, BASE2, active=False)
        scope4 = WC.Scope(os.path.join(BASE2, "scope.json"))
        out4 = MC.run(cfg4, scope4, BASE2)
        check("passive: 0 lab GETs", LAB["gets"] == gets_before_passive,
              "delta=%d" % (LAB["gets"] - gets_before_passive))
        check("passive: test-plan exists",
              os.path.isfile(os.path.join(out4, "client_test_plan.md")))
        man4 = json.load(open(os.path.join(out4, "MANIFEST.json")))
        check("passive: manifest mode", man4.get("stats", {}).get("mode") == "passive")
        ff4 = json.load(open(os.path.join(out4, "feedforward.json")))
        check("passive: feedforward mode", ff4["routing"]
              .get("to_phase32_report", {}).get("mode") == "passive")
        # passive me sensitive-gate bhi respect
        cm4 = json.load(open(os.path.join(out4, "csrf_matrix.json")))
        check("passive: census seeded (no GET)", isinstance(cm4, list))

        # ---------- CLI ----------
        print("\n== CLI ==")
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            MC.main()
        check("cli: banner", "Phase 14" in buf.getvalue())

    finally:
        srv.shutdown()
    print("\n=====================================================")
    print("P14 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, d))
        sys.exit(1)
    print("ALL GREEN ✅")


if __name__ == "__main__":
    main()
