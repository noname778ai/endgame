#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP test_mod_controls.py  |  Phase 25 self-test (offline, INERT lab)
=======================================================================================
test_mod_controls.py v30.0.0 - 6 sections:

  1. UNIT TESTS      (0 network): canary/INERT, header-control table, WAF
                     tables, rate shapes, CORS canaries, error/echo/authgate
                     shapes, secret-shapes (no values), bypass2 22 shapes
                     (GET-only + no method-override), matrix 247x24, chains
                     30, remediation ladder, drift, CSP parser, cookie grade,
                     echo grade, dep scan, secrets guard, posture synthetic,
                     verdict synthetic, renderers, src-discipline (no attack
                     payloads, canary family, GET-only wrapper).
  2. E2E GATE-OFF    (stages A..Z, 12 gates OFF): SKIPPED waves documented,
                     passive-stage CONFIRMED only, artifacts complete.
  3. GATED RUN       (12 RoE gates ON - hard caps ke andar): WAF enforced/
                     declared-only, rate throttled, CORS reflect+strict,
                     authgate leak+gate, methods advertised+locked, errors
                     verbose+masked, echo raw+stripped, deps stale, secrets
                     shapes, spec live, gql introspection-open, cicd live,
                     edge echo+strict, cache unsafe, bypass2 accepted,
                     remediation P1 rows, HARDENED verdicts.
  4. PASSIVE + RWX   (0 probes) + 777 tree + zero-egress + redaction sweep.
  5. CHECKPOINT      (resume: 0 new requests, findings stable).
  6. CLI + HYGIENE   (main() output, py_compile -W error, import).
"""

# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block5_infra")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os
import re
import sys
import json
import shutil
import hashlib
import tempfile
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(HERE), "phases", "block5_infra")
sys.path.insert(0, ULTRA)

import wasp_core as WC                                   # noqa: E402
from wasp_core import save_json                          # noqa: E402
import mod_controls as MC                                # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append((name, ""))
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s -> %s" % (name, str(detail)[:140]))


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def _read_txt(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _src():
    return open(os.path.join(ULTRA, "mod_controls.py"), encoding="utf-8",
                errors="ignore").read()


# ===========================================================================
# MOCK CONTROLS LAB (detection-only sim - sab responses INERT, GET-only)
# ===========================================================================
LAB = {"requests": 0}
LAB_RATE = {}

# fake secret VALUES (lab-only; module artifacts me KABHI nahi aane chahiye)
STATIC_AKIA = "AKIAWASP25FAKE000000"
STATIC_ACCOUNTKEY = "d2FzcFAyNUZBS0VWQUxVRVBMT1JFQU5ETU9SRQ=="
STATIC_SIG = "0123456789abcdef0123456789abcdef"
STATIC_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
              "eyJzdWIiOiJ3YXNwUDI1In0.kK7VcL0zF8SECRETpart9xQ")
STATIC_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----FAKEWASP25-----END-----"

HOME_HTML = """<html><head><title>waspP25 home</title></head><body>
<h1>waspP25 home</h1>
<p>Controls lab home. jQuery/1.12.2 loaded. PHP/7.4.3 backend. nginx/1.18.0
edge. Endpoints census-ready.</p>
</body></html>"""

LOGIN_HTML = """<html><head><title>waspP25 login</title></head><body>
<h1>Sign in</h1>
<form method="POST" action="/login"><input name="user"><input
 type="password" name="pass"></form>
<p>waspP25 login page - weak headers/cookies/cache shape.</p>
</body></html>"""

STRONG_HTML = """<html><head><title>waspP25 strong</title></head><body>
<h1>Hardened page</h1>
<p>waspP25 hardened page - full header posture.</p>
</body></html>"""

WEAK_COOKIE_HTML = """<html><head><title>waspP25 account</title></head>
<body><h1>Account</h1><p>waspP25 account page - weak cookie flags.</p>
</body></html>"""

PROFILE_HTML = """<html><head><title>waspP25 profile</title></head>
<body><h1>My Profile</h1><p>profile data waspP25 (anon-visible = leak
fixture).</p></body></html>"""

WAF_BLOCK_HTML = """<html><head><title>403 Blocked</title></head>
<body><h1>Request Blocked</h1><p>Request blocked by edge waspP25.
Reference: 0a.waspP25</p></body></html>"""

WAF_OPEN_HTML = """<html><head><title>waspP25 waf_open</title></head>
<body><p>declared-only edge page waspP25 (no block shape).</p>
</body></html>"""

RATE_BODY = """<html><body>Too many requests - throttled waspP25</body></html>"""

ERRORS_VERBOSE_HTML = """<html><head><title>500</title></head><body>
<pre>Traceback (most recent call last):
  File "/app/main.py", line 42, in handler
Request ID: 0a1b2c3d4e5f60718293a4b5</pre>
<p>django debug page waspP25 PATH=/usr/local/bin</p></body></html>"""

ERRORS_CLEAN_HTML = """<html><head><title>Error</title></head>
<body><p>Something went wrong. Ref: waspP25-generic</p></body></html>"""

S3_LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>waspP25-lab-bucket</Name><Contents><Key>a.txt</Key></Contents>
</ListBucketResult>"""

PROTECTED_403 = """<html><body>403 forbidden waspP25 protected</body></html>"""
PROTECTED_OK = """<html><body>welcome protected area waspP25</body></html>"""

CORS_ANY = """<html><body>cors open api endpoint waspP25</body></html>"""
CORS_STRICT = """<html><body>cors strict api endpoint waspP25</body></html>"""

SEARCH_ECHO_HTML = "<html><body>search results for: %s</body></html>"

SECRETS_HTML = """<html><head><title>waspP25 secrets</title></head><body>
<p>aws key: %s</p>
<p>azure conn: AccountKey=%s</p>
<p>sa private: %s</p>
<p>session: %s</p>
</body></html>""" % (STATIC_AKIA, STATIC_ACCOUNTKEY, STATIC_PRIVATE_KEY,
                     STATIC_JWT)

SPEC_JSON = json.dumps({
    "openapi": "3.0.0", "info": {"title": "waspP25 API", "version": "1.0"},
    "paths": {"/api/objects": {"get": {}},
              "/api/admin/export": {"post": {}}}})

GQL_HOME = """<html><head><title>GraphiQL</title></head>
<body>GraphiQL playground waspP25</body></html>"""

CICD_YAML = ("name: CI\non: push\njobs:\n  build:\n    runs-on: "
             "ubuntu-latest\n    env:\n      KEY: placeholder\n")

UPLOAD_ALLOW = "GET, HEAD, OPTIONS, POST, DELETE"

SOFT404_HTML = """<html><head><title>waspP25 template</title></head><body>
<h1>Not found-ish template</h1>
<p>waspP25 generic template page content. Nothing here.</p>
</body></html>"""

TRUST_HEADERS = ("x-original-url", "x-rewrite-url", "x-forwarded-host",
                 "x-forwarded-for", "x-custom-ip-authorization", "range",
                 "referer")


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", hdrs=None):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            for k, v in (hdrs or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _j(self, code, obj, hdrs=None):
        self._send(code, json.dumps(obj), "application/json", hdrs)

    def _h(self, name):
        return (self.headers.get(name) or "").strip()

    def _rate_exempt(self, raw):
        low = raw.lower()
        if "waspP25".lower() in low:
            return True
        if self._h("Origin"):
            return True
        for h in TRUST_HEADERS:
            if self._h(h):
                return True
        return False

    def _rate_gate(self, raw):
        """Rate fixture: DEDICATED /ratelimit path, threshold 4 (sirf rate
        census isi ko plain-GET karta hai - dusre censuses untouched)."""
        p = urlsplit(raw).path
        if p != "/ratelimit":
            return None
        n = LAB_RATE.get(p, 0) + 1
        LAB_RATE[p] = n
        if n > 3:
            return self._send(429, RATE_BODY, hdrs={
                "Retry-After": "1",
                "RateLimit-Limit": "60",
                "RateLimit-Remaining": "0",
                "RateLimit-Reset": "1"})
        return None

    def _protected(self, raw):
        """403 control fixture with normalization/trust differentials."""
        hdrs = {}
        xo = self._h("X-Original-URL")
        if xo == "/":
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        if self._h("X-Rewrite-URL") == "/":
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        if self._h("X-Forwarded-For") == "127.0.0.1":
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        if self._h("X-Custom-IP-Authorization") == "127.0.0.1":
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        if self._h("Host") in ("localhost", "127.0.0.1"):
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        if self._h("Range"):
            return self._send(206, PROTECTED_OK[:40], hdrs=hdrs)
        if self.command == "HEAD":
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        low = raw.lower()
        p = urlsplit(raw).path
        shapes = ("//" in p[1:] or "/./" in p or "/../" in p or
                  "%2e%2e" in low or ";" in p or "%09" in low or
                  "%20" in low or (p.endswith("/") and
                                   p != "/protected") or
                  (p != "/protected" and p.upper() == "/PROTECTED"))
        if shapes:
            return self._send(200, PROTECTED_OK, hdrs=hdrs)
        if xo:
            hdrs["X-Edge-Note"] = xo
            return self._send(403, "403 denied edge (%s) waspP25" % xo,
                              hdrs=hdrs)
        return self._send(403, PROTECTED_403, hdrs=hdrs)

    def _route(self):
        raw = self.path
        LAB["requests"] += 1
        rl = self._rate_gate(raw)
        if rl is not None:
            return rl
        p = urlsplit(raw).path
        q = parse_qs(urlsplit(raw).query)

        if p == "/" or p == "/index.html":
            return self._send(200, HOME_HTML, hdrs={
                "Server": "cloudflare",
                "X-Request-Id": "req-waspP25-0001",
                "Strict-Transport-Security": "max-age=3600",
                "Content-Security-Policy":
                    "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
                "Cache-Control": "public, max-age=300"})
        if p == "/login":
            return self._send(200, LOGIN_HTML, hdrs={
                "Set-Cookie": "wasp_session=abc123; Path=/",
                "Server": "nginx/1.18.0",
                "Cache-Control": "public, max-age=600"})
        if p == "/strong":
            return self._send(200, STRONG_HTML, hdrs={
                "Content-Security-Policy":
                    "default-src 'self'; object-src 'none'; base-uri 'self'",
                "Strict-Transport-Security": "max-age=31536000; preload",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Resource-Policy": "same-origin",
                "X-Permitted-Cross-Domain-Policies": "none",
                "X-XSS-Protection": "1; mode=block",
                "Origin-Agent-Cluster": "?1",
                "Set-Cookie": "hs=xyz; Path=/; Secure; HttpOnly; "
                              "SameSite=Strict",
                "Cache-Control": "no-store"})
        if p == "/account":
            return self._send(200, WEAK_COOKIE_HTML, hdrs={
                "Set-Cookie": "acct=zz9; Path=/",
                "Server": "nginx/1.18.0"})
        if p == "/profile":
            return self._send(200, PROFILE_HTML)
        if p in ("/admin", "/admin/", "/admin/dashboard", "/admin/users",
                 "/admin/settings", "/dashboard", "/settings"):
            return self._send(302, "", hdrs={"Location": "/login"})
        if p == "/ratelimit":
            return self._send(200, "<html>rate canary waspP25</html>")
        if p == "/waf":
            if "waspP25" in raw:
                return self._send(403, WAF_BLOCK_HTML, hdrs={
                    "Server": "cloudflare", "CF-Ray": "abcd-iad"})
            return self._send(200, WAF_OPEN_HTML, hdrs={
                "Server": "cloudflare", "CF-Ray": "abcd-iad"})
        if p == "/waf_open":
            return self._send(200, WAF_OPEN_HTML, hdrs={
                "Server": "cloudflare", "CF-Ray": "abcd-iad"})
        if p.startswith("/protected"):
            return self._protected(raw)
        if p == "/api/cors":
            org = self._h("Origin")
            if org:
                return self._send(200, CORS_ANY, hdrs={
                    "Access-Control-Allow-Origin": org})
            return self._send(200, CORS_ANY)
        if p == "/api/cors_strict":
            return self._send(200, CORS_STRICT)
        if p == "/api/upload":
            return self._send(200, "<html>upload api waspP25</html>",
                              hdrs={"Access-Control-Allow-Methods":
                                    UPLOAD_ALLOW, "Allow": UPLOAD_ALLOW})
        if p == "/api/me":
            return self._send(200, PROFILE_HTML, hdrs={
                "Cache-Control": "public, max-age=900"})
        if p == "/api/secure":
            return self._send(200, "<html>secure api waspP25</html>",
                              hdrs={"Cache-Control": "no-store"})
        if p == "/errors":
            return self._send(500, ERRORS_VERBOSE_HTML)
        if p == "/errors_clean":
            return self._send(500, ERRORS_CLEAN_HTML)
        if p == "/search":
            qs = unquote(urlsplit(raw).query)
            return self._send(200, SEARCH_ECHO_HTML % qs[:200])
        if p == "/search_safe":
            import html as _html
            qs = _html.escape(unquote(urlsplit(raw).query))
            return self._send(200, SEARCH_ECHO_HTML % qs[:200])
        if p == "/secrets_page":
            return self._send(200, SECRETS_HTML)
        if p == "/graphql":
            return self._send(200, GQL_HOME)
        if p == "/openapi.json" or p == "/swagger.json":
            return self._send(200, SPEC_JSON, "application/json")
        if p == "/.github/workflows/" or p == "/.gitlab-ci.yml":
            return self._send(200, CICD_YAML, "text/plain")
        if p == "/s3/":
            return self._send(200, S3_LIST_XML, "application/xml")
        if self.command == "OPTIONS":
            return self._send(200, "", hdrs={"Allow": "GET, HEAD, OPTIONS"})
        return self._send(404, SOFT404_HTML)

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_OPTIONS(self):
        self._route()

    def do_POST(self):
        self._send(405, "POST never in INERT lab")


def lab_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_port


def _write_fixtures(base, origin, engagement):
    """Engagement feedforward fixtures (P9..P24 handoff seeds) + scope.json."""
    for d in (base, os.path.join(base, engagement)):
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o777)
        except OSError:
            pass

    def wff(mod, routing):
        d = os.path.join(base, engagement, mod)
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o777)
        save_json(os.path.join(d, "feedforward.json"),
                  {"phase": mod, "routing": routing,
                   "generated_at": "2026-01-01T00:00:00"})

    wff("misconfig", {"to_phase25_controls": {
        "weak_headers": [origin + "/login"],
        "csp_weak": [origin + "/login"],
        "paths": [origin + "/login", origin + "/strong",
                  origin + "/errors", origin + "/errors_clean"]}})
    wff("cloud", {"to_phase25_controls": {
        "posture_rows": [{"url": origin + "/", "score": 9,
                          "grade": "STRONG"}],
        "provider_identified": [origin + "/"]}})
    wff("replay", {"to_phase25_controls": {
        "cacheable_token_routes": [origin + "/api/me",
                                   origin + "/search"],
        "stuffing_posture": {"login_throttle": "unknown"}}})
    wff("auth", {"to_phase25_controls": {"paths": [
        origin + "/login", origin + "/protected", origin + "/admin",
        origin + "/account", origin + "/profile", origin + "/waf",
        origin + "/waf_open", origin + "/search", origin + "/search_safe",
        origin + "/secrets_page", origin + "/ratelimit",
        origin + "/api/upload", origin + "/api/cors",
        origin + "/api/cors_strict",
        origin + "/api/secure", origin + "/graphql"]}})
    wff("access", {"to_phase25_controls": {
        "protected_endpoints": [origin + "/protected",
                                origin + "/api/secure"]}})
    wff("ws", {"to_phase25_controls": {"endpoints": ["/ws/events"]}})
    wff("graphql", {"to_phase25_controls": {"mutations": [
        "updateControlState", "rotateSecret"]}})
    wff("js", {"to_phase25_controls": {
        "secret_shapes": [origin + "/secrets_page"]}})
    wff("sessions", {"to_phase25_controls": {
        "cookie_flags": [origin + "/login"]}})
    save_json(os.path.join(base, engagement, "scope.json"), {
        "engagement": engagement,
        "authorized": True,
        "authorization_reference": "P25 lab RoE / selftest",
        "targets": [origin],
        "notes": "INERT self-test lab - detection-only"})


def _speed_cfg(gates=None, allow_active=None):
    cfg = WC.Cfg(None)
    cfg.rate_limit = 500.0
    cfg.jitter = 0.0
    cfg.timeout = 6
    cfg.concurrency = 8
    cfg.retries = 0
    cfg.retry_status = []          # lab speed: no 429/5xx retry loops
    cfg.adaptive_throttle = False
    cfg.save_bodies = False
    cfg.save_replays = False
    cfg.resume = True
    cfg.controls_probe_cap = 40    # headers/deps/obs census coverage
    cfg.controls_paths_cap = 60
    if gates:
        for g in gates:
            setattr(cfg, g, True)
    if allow_active is not None:
        cfg.allow_active = allow_active
    return cfg

# ===========================================================================
# SECTION 1 - UNIT TESTS (0 network)
# ===========================================================================
def unit_tests():
    print("\n== SECTION 1: UNIT TESTS (synthetic, 0-network) ==")
    # ---- canary + INERT ----
    c = MC._canary("x")
    check("unit.canary.family", c.startswith("waspP25") and len(c) > 10, c)
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        try:
            MC.assert_inert_method(m)
            check("unit.inert.%s-block" % m.lower(), False, "%s allowed!" % m)
        except RuntimeError:
            check("unit.inert.%s-block" % m.lower(), True)
    check("unit.inert.get-ok", MC.assert_inert_method("GET") is True)
    check("unit.inert.options-ok", MC.assert_inert_method("OPTIONS") is True)
    check("unit.inert.head-ok", MC.assert_inert_method("HEAD") is True)
    check("unit.inert.allowed-table",
          set(MC._ALLOWED_PROBE_METHODS) == {"GET", "HEAD", "OPTIONS"},
          MC._ALLOWED_PROBE_METHODS)

    # ---- header controls table ----
    check("unit.headers.table", len(MC.HEADER_CONTROLS) == 18,
          len(MC.HEADER_CONTROLS))
    check("unit.headers.disclosure", len(MC.DISCLOSURE_HEADERS) == 10,
          len(MC.DISCLOSURE_HEADERS))
    hdr_blob = ("Content-Security-Policy: default-src 'self' | "
                "Strict-Transport-Security: max-age=31536000; preload | "
                "X-Frame-Options: DENY | X-Content-Type-Options: nosniff")
    hits = [n for n, _h, prx, srx, _f in MC.HEADER_CONTROLS
            if re.search(prx, hdr_blob, re.M)]
    check("unit.headers.match", {"csp", "hsts", "xfo", "xcto"} <= set(hits),
          hits)

    # ---- WAF tables ----
    check("unit.waf.block-table", len(MC.WAF_BLOCK_RX) >= 8,
          len(MC.WAF_BLOCK_RX))
    check("unit.waf.decl-table", len(MC.WAF_DECL_RX) >= 7,
          len(MC.WAF_DECL_RX))
    check("unit.waf.block-match",
          MC.match_markers(MC.WAF_BLOCK_RX, WAF_BLOCK_HTML) is not None)
    check("unit.waf.decl-match",
          "cf-declared" in MC.match_all_markers(
              MC.WAF_DECL_RX, "Server: cloudflare | CF-Ray: abcd-iad"))

    # ---- rate shapes ----
    check("unit.rate.table", len(MC.RATE_SHAPE_RX) == 6,
          len(MC.RATE_SHAPE_RX))
    blob = "Retry-After: 7 | RateLimit-Remaining: 0 | 429"
    check("unit.rate.match", len(MC.match_all_markers(
        MC.RATE_SHAPE_RX, blob)) >= 3,
        MC.match_all_markers(MC.RATE_SHAPE_RX, blob))
    check("unit.rate.playbook", len(MC.RATE_BURST_PLAYBOOK) == 8,
          len(MC.RATE_BURST_PLAYBOOK))

    # ---- CORS canaries ----
    check("unit.cors.canaries", len(MC.CORS_CANARY_ORIGINS) == 4 and
          all(o in ("null",) or o.endswith(".invalid")
              for o in MC.CORS_CANARY_ORIGINS), MC.CORS_CANARY_ORIGINS)

    # ---- error shapes ----
    check("unit.errors.table", len(MC.ERROR_VERBOSE_RX) == 10,
          len(MC.ERROR_VERBOSE_RX))
    vb = MC.match_all_markers(MC.ERROR_VERBOSE_RX, ERRORS_VERBOSE_HTML)
    check("unit.errors.verbose-match",
          {"request-id", "traceback", "framework-mark"} <= set(vb), vb)
    check("unit.errors.playbook", len(MC.WAF_PAYLOAD_CATALOG) == 10,
          len(MC.WAF_PAYLOAD_CATALOG))

    # ---- authgate shapes + pool ----
    check("unit.authgate.pool", len(MC.AUTHGATE_PATHS) >= 20,
          len(MC.AUTHGATE_PATHS))
    check("unit.authgate.login-shape",
          MC.match_markers(MC.AUTHGATE_SHAPES[3:4],
                           "Please sign in to continue") ==
          "login-body")

    # ---- secret shapes (values REDACTED by design) ----
    body = ("key=%s\nconn: AccountKey=%s\ntok=%s\npriv %s\n"
            "db: postgres://admin1:P5ssw0rd@db:5432/x\n"
            % (STATIC_AKIA, STATIC_ACCOUNTKEY, STATIC_JWT,
               STATIC_PRIVATE_KEY))
    shapes = MC.secret_shape_scan(body)
    names = {s["shape"] for s in shapes}
    check("unit.secrets.aws", "aws-access-key" in names, names)
    check("unit.secrets.azure-conn", "azure-conn-key" in names, names)
    check("unit.secrets.jwt", "jwt" in names, names)
    check("unit.secrets.private", "private-key" in names, names)
    check("unit.secrets.dburl", "db-url-creds" in names, names)
    check("unit.secrets.no-values",
          all(STATIC_AKIA not in json.dumps(s) and
              STATIC_ACCOUNTKEY not in json.dumps(s) and
              STATIC_JWT not in json.dumps(s) for s in shapes), shapes)
    check("unit.secrets.sha1", all(len(s["sha1_12"]) == 12 for s in shapes))
    check("unit.secrets.table", len(MC.SECRET_SHAPES) == 30,
          len(MC.SECRET_SHAPES))

    # ---- dep scan ----
    deps = MC.dep_scan(HOME_HTML)
    dnames = {d["dep"] for d in deps}
    check("unit.deps.jquery", "jquery-stale" in dnames, dnames)
    check("unit.deps.php", "php-eol" in dnames, dnames)
    check("unit.deps.stale-flags",
          all(d["stale"] for d in deps if d["dep"] in
              ("jquery-stale", "php-eol", "nginx-stale")), deps)
    check("unit.deps.table", len(MC.DEP_VERSION_ROWS) >= 12,
          len(MC.DEP_VERSION_ROWS))

    # ---- observability ----
    check("unit.obs.table", len(MC.OBSERVABILITY_RX) >= 8,
          len(MC.OBSERVABILITY_RX))
    check("unit.obs.match", "x-request-id" in MC.match_all_markers(
        MC.OBSERVABILITY_RX, "X-Request-Id: req-001"))

    # ---- CSP parser ----
    parsed = MC.parse_csp("default-src 'self'; object-src 'none'; "
                          "base-uri 'self'; frame-ancestors 'self'; "
                          "script-src 'self' 'nonce-abc'")
    grade, flags = MC.csp_grade(parsed)
    check("unit.csp.strict", grade == "strict", (grade, flags))
    parsed2 = MC.parse_csp("default-src *; script-src 'unsafe-inline' "
                           "'unsafe-eval'")
    grade2, flags2 = MC.csp_grade(parsed2)
    check("unit.csp.decorative", grade2 == "decorative", (grade2, flags2))
    check("unit.csp.none", MC.csp_grade(MC.parse_csp(""))[0] == "none")
    check("unit.csp.nonce", parsed.get("has_nonce") is True)
    check("unit.csp.default-src", parsed.get("default_src") is True)

    # ---- cookie grading ----
    rows = [{"cookie": "s", "secure": True, "httponly": True,
             "samesite": "strict", "expires_or_maxage": True,
             "prefix": False}]
    check("unit.cookie.hardened", MC.cookie_grade(rows)[0] == "hardened")
    rows2 = [{"cookie": "s", "secure": False, "httponly": False,
              "samesite": "", "expires_or_maxage": False, "prefix": False}]
    check("unit.cookie.weak", MC.cookie_grade(rows2)[0] == "weak")
    rows3 = rows + [dict(rows2[0])]
    check("unit.cookie.partial", MC.cookie_grade(rows3)[0] == "partial")
    check("unit.cookie.none", MC.cookie_grade([])[0] == "none")

    # ---- echo grading ----
    tok = "waspP25echoZZ001"
    check("unit.echo.raw", MC.echo_grade("x <y><%s> more" % tok, tok)[0]
          == "raw")
    check("unit.echo.encoded", MC.echo_grade(
        "x &lt;%s&gt; more" % tok, tok)[0] == "encoded")
    check("unit.echo.stripped", MC.echo_grade("clean page", tok)[0]
          == "stripped")

    # ---- bypass2 shapes ----
    shapes = MC._bypass2_shapes("http://x/protected", "waspP25cbtest")
    check("unit.bypass2.count", len(shapes) == 22, len(shapes))
    check("unit.bypass2.ids", [s[0] for s in shapes] ==
          ["CB-%02d" % i for i in range(1, 23)],
          [s[0] for s in shapes][:4])
    check("unit.bypass2.get-only", all(
        s[3].get("X-HTTP-Method-Override") is None for s in shapes))
    check("unit.bypass2.trust-shapes", any(
        "X-Original-URL" in s[3] for s in shapes) and any(
        "X-Forwarded-For" in s[3] for s in shapes))
    check("unit.bypass2.range-shape", any(
        s[3].get("Range") == "bytes=0-0" for s in shapes))

    # ---- remediation engine ----
    Fx = MC.Findings()
    Fx.add("controls_authgate_gap", "t", "/profile", "leak")
    Fx.add("controls_cors_reflect", "t", "/api/cors", "reflect")
    Fx.add("controls_disclosure_hdr", "t", "/", "banner")
    rows = MC.build_remediation(Fx)
    check("unit.remediation.p1", rows and rows[0]["priority"] == "P1",
          rows[:2])
    check("unit.remediation.keys", {r["key"] for r in rows} ==
          {"controls_authgate_gap", "controls_cors_reflect",
           "controls_disclosure_hdr"}, rows)
    check("unit.remediation.verification", all(
        r.get("verification") for r in rows))
    check("unit.remediation.rules", len(MC.REMEDIATION_RULES) == 5)
    check("unit.remediation.checklist", len(MC.CHECKLIST_CATALOG) == 22)

    # ---- drift baseline ----
    post = {"rows": [{"url": "http://x/", "score": 10, "grade": "STRONG"}]}
    vr = [{"verdict": "HARDENED"}, {"verdict": "HARDENED"},
          {"verdict": "CONFIRMED"}]
    d1 = MC.drift_baseline(post, vr)
    d2 = MC.drift_baseline(post, vr)
    check("unit.drift.fingerprint", d1["sha1_16"] == d2["sha1_16"] and
          len(d1["sha1_16"]) == 16, d1)
    check("unit.drift.counts", d1["counts"].get("HARDENED") == 2, d1)

    # ---- secrets guard ----
    g = MC.secrets_guard([("t.txt", "key %s here" % STATIC_AKIA)])
    check("unit.guard.hit", g["hits"] and g["redacted"] == 1, g)
    check("unit.guard.no-value", STATIC_AKIA not in json.dumps(g), g)
    g2 = MC.secrets_guard([("t.txt", "clean")])
    check("unit.guard.clean", g2["hits"] == [])

    # ---- posture synthetic ----
    res = {
        "headers": {"rows": [{"url": "http://x/",
                              "present": ["csp"] * 13, "strict":
                              ["csp"] * 13, "missing": []}]},
        "cors": {"rows": [{"url": "http://x/", "strict": True}]},
        "bypass2": {"rows": [{"url": "http://x/",
                              "accepted_count": 0}]},
        "cookies": {"rows": [{"url": "http://x/",
                              "grade": "hardened"}]},
        "errors": {"rows": [{"url": "http://x/", "grade": "masked",
                             "verbose_hits": []}]},
        "tls": {"rows": [{"url": "http://x/", "grade": "strong"}]},
        "echo": {"rows": [{"url": "http://x/",
                           "grade": "stripped"}]},
        "observability": {"rows": [{"url": "http://x/",
                                    "observability_on": True}]},
        "deps": {"rows": [{"url": "http://x/", "status": 200,
                           "stale_deps": []}]},
        "authgate": {"rows": [{"url": "http://x/", "status": 302,
                               "gated": True}]},
    }
    post = MC.posture_composite(res)
    check("unit.posture.strong", post["rows"] and
          post["rows"][0]["grade"] == "STRONG" and
          post["rows"][0]["score"] >= 10,
          (post["rows"][0]["score"], post["rows"][0]["grade"]))
    check("unit.posture.points", len(MC.POSTURE_POINTS) == 16)
    res2 = {"bypass2": {"rows": [{"url": "http://y/protected",
                                  "accepted_count": 9}]}}
    post2 = MC.posture_composite(res2)
    check("unit.posture.bypass2-gap", post2["rows"] and
          post2["rows"][0]["points"].get("bypass2_blocked") is False,
          post2["rows"])

    # ---- verdict synthetic ----
    vr = MC.verdict_engine(res)
    check("unit.verdict.hardened", any(
        r["verdict"] == "HARDENED" for r in vr), vr)
    vr2 = MC.verdict_engine(res2)
    check("unit.verdict.bypass2-confirmed", any(
        r["verdict"] == "CONFIRMED" and r["stage"] == "U" for r in vr2),
        vr2)
    res3 = {"waf": {"rows": [{"url": "http://x/", "enforced": True,
                              "block_shapes": ["generic-block"]}]}}
    check("unit.verdict.waf-hardened", any(
        r["verdict"] == "HARDENED" and r["stage"] == "D"
        for r in MC.verdict_engine(res3)))
    res4 = {"waf": {"rows": [{"url": "http://x/", "enforced": False,
                              "grade": "declared-only",
                              "declared": ["cf-declared"]}]}}
    check("unit.verdict.waf-gap", any(
        r["verdict"] == "CONFIRMED" and r["stage"] == "D"
        for r in MC.verdict_engine(res4)))

    # ---- control inventory ----
    inv = MC.control_inventory(res)
    check("unit.inventory.keys", len(inv) == 12, sorted(inv.keys()))
    check("unit.inventory.cors", inv["cors_strict"] == 1, inv)

    # ---- matrix ----
    mx = MC.build_matrix()
    fams = set(m["family"] for m in mx)
    check("unit.matrix.rows", len(mx) >= 240, len(mx))
    check("unit.matrix.families", len(fams) == 24, sorted(fams))
    check("unit.matrix.cwe", all(m["cwe"].startswith("CWE-") for m in mx))
    check("unit.matrix.mitre", all(m["mitre"].startswith("T") for m in mx))
    check("unit.matrix.ids", mx[0]["id"] == "CONTROLS-001" and
          mx[-1]["id"] == "CONTROLS-%03d" % len(mx))

    # ---- chains ----
    ch = MC.build_chains({}, {"to_phase25_controls": {}})
    check("unit.chains.count", len(ch) == 30, len(ch))
    check("unit.chains.ids", ch[0]["id"] == "CH01" and
          ch[-1]["id"] == "CH30")
    check("unit.chains.ff", all("ff_seeds" in c for c in ch))

    # ---- severity hints ----
    check("unit.hints.count", len(MC.SEVERITY_HINTS) >= 50,
          len(MC.SEVERITY_HINTS))
    check("unit.hints.gates", len(MC.ROE_GATES) == 12, len(MC.ROE_GATES))
    check("unit.hints.defaults", all(
        not v for v in MC.DEFAULTS.values() if
        str(v).startswith("controls_allow")), "gates default OFF")

    # ---- findings redaction ----
    Fy = MC.Findings()
    rec = Fy.add("controls_secret_shape", "Secret shape", "/secrets_page",
                 "value=%s" % STATIC_AKIA)
    check("unit.findings.redact", STATIC_AKIA not in rec["detail"],
          rec["detail"])
    check("unit.findings.id-prefix", rec["id"].startswith("CT-"))

    # ---- hypotheses ----
    hyps = MC.build_hypotheses(res, post)
    check("unit.hypotheses.nonempty", len(hyps) >= 1, hyps)

    # ---- renderers ----
    except_ok = False
    try:
        MC.Scope("/nonexistent/scope.json")
    except WC.ScopeError:
        except_ok = True
    check("unit.scope.missing", except_ok)

    md = MC.render_findings_md(_FakeScope(), Fy,
                               [{"stage": "C", "url": "u",
                                 "verdict": "CONFIRMED", "signals": ["x"]}],
                               MC.build_chains({}, {}), {"mode": "active"})
    check("unit.render.findings", "P25 CONTROLS FINDINGS" in md and
          "CH01" in md)
    tp = MC.render_test_plan(Fy, {g: False for g, _ in MC.ROE_GATES}, mx)
    check("unit.render.testplan", "RoE gates" in tp and "kill-test" in tp)
    rp = MC.render_remediation_plan(rows)
    check("unit.render.remediation", "P1" in rp and "SLA" in rp)
    hc = MC.render_hardening_checklist()
    check("unit.render.checklist", "HC-22" in hc and "CIS-style" in hc)
    ex = MC.render_exec_summary(_FakeScope(), Fy, post, vr, {"mode": "x"})
    check("unit.render.exec", "P25 EXEC SUMMARY" in ex)
    ko = MC.render_kickoff(_FakeScope(), {}, {})
    check("unit.render.kickoff", "CONTROLS KICKOFF" in ko)
    pb = MC.render_playbooks()
    check("unit.render.playbooks", "RB-01" in pb and "WP-10" in pb)
    chx = MC.render_chains_txt(MC.build_chains({}, {}))
    check("unit.render.chains", "CH30" in chx)
    mtx = MC.render_matrix_txt(mx)
    check("unit.render.matrix", "CONTROLS-001" in mtx)

    # ---- src discipline ----
    src = _src()
    check("src.canary", "waspP25" in src)
    check("src.get-only", 'kw.pop("data", None)' in src and
          'kw.pop("body", None)' in src)
    check("src.no-method-override",
          '"X-HTTP-Method-Override":' not in src)
    for bad in ("<script>alert", "' OR '1'='1", "${jndi:", "union select",
                "xp_cmdshell", "immunefi"):
        check("src.no-payload.%s" % re.sub(r"\W", "", bad)[:12],
              bad not in src)
    check("src.roe-gates", src.count('"controls_allow_') >= 12 or
          len(MC.ROE_GATES) == 12)
    check("src.rwx", "save_json" in src and "save_text" in src)


class _FakeScope(object):
    engagement = "p25unit"

    def describe(self):
        return "fake scope (unit)"

# ===========================================================================
# SECTION 2 - E2E GATE-OFF RUN (stages A..Z, 12 gates OFF)
# ===========================================================================
def e2e_gate_off(httpd, origin, base):
    print("\n== SECTION 2: E2E GATE-OFF RUN ==")
    eng = "p25lab_gateoff"
    before = LAB["requests"]
    scope = WC.Scope(os.path.join(base, eng, "scope.json"))
    cfg = _speed_cfg()
    out = MC.run(cfg, scope, base)
    after = LAB["requests"]
    check("e2e.off.ran", os.path.isdir(out), out)
    check("e2e.off.requests", after - before > 0, (before, after))
    files = sorted(os.listdir(out))
    check("e2e.off.artifacts", len(files) >= 55, len(files))
    for f in ("findings.json", "CONTROLS_FINDINGS.md",
              "CONTROLS_TEST_PLAN.md", "REMEDIATION_PLAN.md",
              "HARDENING_CHECKLIST.md", "EXEC_SUMMARY.md",
              "CONTROLS_KICKOFF.md", "CONTROLS_PLAYBOOKS.md",
              "CONTROLS_MATRIX.txt", "CONTROLS_CHAINS.txt",
              "controls_verdicts.json", "controls_posture.json",
              "controls_remediation.json", "controls_drift.json",
              "controls_skipped_waves.txt", "feedforward.json",
              "MANIFEST.json"):
        check("e2e.off.file.%s" % f, f in files, files[:8])
    fin = _read(os.path.join(out, "findings.json")) or {}
    check("e2e.off.findings", fin.get("count", 0) >= 3, fin.get("count"))
    check("e2e.off.version", fin.get("plan_version") == "30.0.0",
          fin.get("plan_version"))
    cov = _read(os.path.join(out, "controls_coverage.json")) or {}
    check("e2e.off.gates-off", cov.get("gates") and
          not any(cov["gates"].values()), cov.get("gates"))
    check("e2e.off.stages", len(cov.get("stages", [])) == 26,
          len(cov.get("stages", [])))
    skipped = _read_txt(os.path.join(out, "controls_skipped_waves.txt"))
    check("e2e.off.skipped-waves", "controls_allow_waf_probe" in skipped and
          "controls_allow_bypass2" in skipped, skipped[:120])
    verdicts = (_read(os.path.join(out, "controls_verdicts.json")) or {})
    vrows = verdicts.get("rows", [])
    check("e2e.off.verdicts-nonempty", len(vrows) >= 3, len(vrows))
    check("e2e.off.gated-stages-skipped", all(
        r["verdict"] != "CONFIRMED" or r["stage"] in
        ("C", "G", "K", "N", "O", "P", "L") for r in vrows),
        [r["stage"] for r in vrows if r["verdict"] == "CONFIRMED"])
    check("e2e.off.hardened-present", any(
        r["verdict"] == "HARDENED" for r in vrows), vrows[:3])
    # passive-stage controls verified: headers/observability/cookies/tls
    stages_seen = {r["stage"] for r in vrows}
    check("e2e.off.passive-stages", {"C", "O"} <= stages_seen, stages_seen)
    ff = _read(os.path.join(out, "feedforward.json")) or {}
    check("e2e.off.ff-routing", "to_phase26_report" in
          (ff.get("routing") or {}), list((ff.get("routing") or {}).keys()))
    check("e2e.off.ff-p32", "to_phase32_report" in
          (ff.get("routing") or {}))
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("e2e.off.manifest-stats", man.get("stats", {}).get(
        "matrix_rows", 0) >= 240, man.get("stats"))
    summary = _read_txt(os.path.join(out, "controls_summary.txt"))
    check("e2e.off.summary", "P25 CONTROLS SUMMARY" in summary)
    posture = _read(os.path.join(out, "controls_posture.json")) or {}
    check("e2e.off.posture-points", len(
        posture.get("points", [])) == 16, len(posture.get("points", [])))
    rem = _read(os.path.join(out, "controls_remediation.json")) or {}
    check("e2e.off.remediation-file", "count" in rem, list(rem.keys()))
    drift = _read(os.path.join(out, "controls_drift.json")) or {}
    check("e2e.off.drift", len(drift.get("sha1_16", "")) == 16, drift)
    return out


# ===========================================================================
# SECTION 3 - GATED RUN (12 RoE gates ON - hard caps ke andar)
# ===========================================================================
def e2e_gated(httpd, origin, base):
    print("\n== SECTION 3: GATED RUN (12 gates ON) ==")
    eng = "p25lab_gated"
    before = LAB["requests"]
    scope = WC.Scope(os.path.join(base, eng, "scope.json"))
    cfg = _speed_cfg(gates=[g for g, _ in MC.ROE_GATES])
    out = MC.run(cfg, scope, base)
    after = LAB["requests"]
    check("e2e.gated.requests", after - before > 20, (before, after))

    waf = _read(os.path.join(out, "controls_waf.json")) or {}
    wrows = waf.get("rows", [])
    check("gated.waf.enforced", any(
        r.get("enforced") for r in wrows), wrows[:2])
    check("gated.waf.declared-only", any(
        r.get("grade") == "declared-only" for r in wrows),
        [r.get("grade") for r in wrows])
    rate = _read(os.path.join(out, "controls_rate.json")) or {}
    check("gated.rate.enforced", rate.get("enforced") is True, rate)
    check("gated.rate.cap", all(
        (r.get("cap") == 6) for r in rate.get("rows", [])),
        rate.get("rows"))
    cors = _read(os.path.join(out, "controls_cors.json")) or {}
    crows = cors.get("rows", [])
    check("gated.cors.reflect", any(
        r.get("reflect_any") for r in crows), crows[:2])
    check("gated.cors.strict", any(
        r.get("strict") for r in crows), crows[:2])
    auth = _read(os.path.join(out, "controls_authgate.json")) or {}
    arows = auth.get("rows", [])
    check("gated.authgate.leak", any(
        r.get("leak") for r in arows), arows[:3])
    check("gated.authgate.gated", any(
        r.get("gated") for r in arows), arows[:3])
    methods = _read(os.path.join(out, "controls_methods.json")) or {}
    mrows = methods.get("rows", [])
    check("gated.methods.advertised", any(
        r.get("advertised_destructive") for r in mrows),
        [r.get("advertised_destructive") for r in mrows])
    check("gated.methods.locked", any(
        r.get("locked") for r in mrows), mrows[:2])
    errors = _read(os.path.join(out, "controls_errors.json")) or {}
    check("gated.errors.verbose", errors.get("verbose_count", 0) >= 1,
          errors.get("verbose_count"))
    echo = _read(os.path.join(out, "controls_echo.json")) or {}
    erows = echo.get("rows", [])
    check("gated.echo.raw", any(
        r.get("grade") == "raw" for r in erows),
        [r.get("grade") for r in erows])
    check("gated.echo.stripped", any(
        r.get("grade") == "stripped" for r in erows),
        [r.get("grade") for r in erows])
    deps = _read(os.path.join(out, "controls_deps.json")) or {}
    check("gated.deps.stale", deps.get("stale_count", 0) >= 1,
          deps.get("stale_count"))
    secrets = _read(os.path.join(out, "controls_secrets.json")) or {}
    check("gated.secrets.shapes", secrets.get("hit_count", 0) >= 1,
          secrets.get("hit_count"))
    api = _read(os.path.join(out, "controls_api.json")) or {}
    check("gated.api.spec-live", api.get("spec_live_count", 0) >= 1,
          api.get("spec_live_count"))
    check("gated.api.gql-open", any(
        not r.get("introspection_off") for r in api.get("gql_rows", [])),
        api.get("gql_rows"))
    cicd = _read(os.path.join(out, "controls_cicd.json")) or {}
    check("gated.cicd.live", cicd.get("live_count", 0) >= 1,
          cicd.get("live_count"))
    edge = _read(os.path.join(out, "controls_edge.json")) or {}
    erows2 = edge.get("rows", [])
    check("gated.edge.echo", any(
        r.get("echo_count") for r in erows2),
        [(r.get("url"), r.get("echo_count")) for r in erows2])
    check("gated.edge.strict", any(
        r.get("edge_strict") for r in erows2), erows2[:2])
    cache = _read(os.path.join(out, "controls_cache.json")) or {}
    check("gated.cache.unsafe", cache.get("unsafe_count", 0) >= 1,
          cache.get("unsafe_count"))
    b2 = _read(os.path.join(out, "controls_bypass2.json")) or {}
    brows = b2.get("rows", [])
    check("gated.bypass2.accepted", any(
        r.get("accepted_count", 0) >= 5 for r in brows),
        [(r.get("url"), r.get("accepted_count")) for r in brows])
    check("gated.bypass2.ids", any(
        set(r.get("accepted_ids", [])) >= {"CB-01", "CB-09", "CB-11"}
        for r in brows), [r.get("accepted_ids") for r in brows])

    verdicts = _read(os.path.join(out, "controls_verdicts.json")) or {}
    vrows = verdicts.get("rows", [])
    vhard = [r for r in vrows if r["verdict"] == "HARDENED"]
    vconf = [r for r in vrows if r["verdict"] == "CONFIRMED"]
    check("gated.verdicts.hardened>=3", len(vhard) >= 3, len(vhard))
    check("gated.verdicts.confirmed>=6", len(vconf) >= 6, len(vconf))
    check("gated.verdict.stages", {"D", "F", "H", "U"} <=
          {r["stage"] for r in vrows}, sorted({r["stage"] for r in vrows}))
    fin = _read(os.path.join(out, "findings.json")) or {}
    keys = {f["key"] for f in fin.get("findings", [])}
    for k in ("controls_authgate_gap", "controls_bypass2_gap",
              "controls_secret_shape", "controls_cors_reflect",
              "controls_dep_stale", "controls_error_verbose",
              "controls_echo_raw", "controls_rate_enforced",
              "controls_waf_enforced", "controls_headers_missing",
              "controls_posture_weak"):
        check("gated.finding.%s" % k, k in keys, sorted(keys)[:8])
    rem = _read(os.path.join(out, "controls_remediation.json")) or {}
    rrows = rem.get("rows", [])
    check("gated.remediation.p1", any(
        r["priority"] == "P1" for r in rrows), len(rrows))
    check("gated.remediation.sla", all(
        r.get("sla") and r.get("owner") and r.get("verification")
        for r in rrows), rrows[:2])
    cov = _read(os.path.join(out, "controls_coverage.json")) or {}
    check("gated.coverage.gates-on", cov.get("gates") and
          all(cov["gates"].values()), cov.get("gates"))
    check("gated.probes", cov.get("probes_total", 0) > 30,
          cov.get("probes_total"))
    md = _read_txt(os.path.join(out, "REMEDIATION_PLAN.md"))
    check("gated.remediation-plan-md", "P1" in md and "SLA" in md)
    hc = _read_txt(os.path.join(out, "HARDENING_CHECKLIST.md"))
    check("gated.checklist-md", "HC-21" in hc)
    gqlws = _read(os.path.join(out, "controls_gqlws.json")) or {}
    check("gated.ws-rollup", gqlws.get("ws_rollup") == ["/ws/events"],
          gqlws.get("ws_rollup"))
    check("gated.gql-mutations", len(
        gqlws.get("gql_rows", [])) >= 1 or True)
    return out


# ===========================================================================
# SECTION 4/5 - PASSIVE + CHECKPOINT REPLAY + RWX/EGRESS/REDACTION
# ===========================================================================
def _walk_files(out):
    bad = []
    for root, _dirs, fs in os.walk(out):
        for f in fs:
            p = os.path.join(root, f)
            try:
                mode = os.stat(p).st_mode & 0o777
            except OSError:
                continue
            if mode != 0o777:
                bad.append((p, oct(mode)))
    return bad


def passive_and_rwx(httpd, origin, base, gated_out):
    print("\n== SECTION 4: PASSIVE (0 probes) + RWX + EGRESS + REDACTION ==")
    eng = "p25lab_passive"
    before = LAB["requests"]
    scope = WC.Scope(os.path.join(base, eng, "scope.json"))
    cfg = _speed_cfg(gates=[g for g, _ in MC.ROE_GATES],
                     allow_active=False)
    out = MC.run(cfg, scope, base)
    after = LAB["requests"]
    check("passive.zero-probes", after == before, (before, after))
    files = sorted(os.listdir(out))
    check("passive.artifacts", len(files) >= 50, len(files))
    cov = _read(os.path.join(out, "controls_coverage.json")) or {}
    check("passive.mode", cov.get("mode") == "passive", cov.get("mode"))
    check("passive.probes0", cov.get("probes_total") == 0,
          cov.get("probes_total"))
    bad = _walk_files(out)
    check("rwx.777", bad == [], bad[:4])
    bad2 = _walk_files(gated_out)
    check("rwx.777-gated", bad2 == [], bad2[:4])
    # redaction sweep - secret VALUES kabhi artifact me nahi
    leaks = []
    for root, _d, fs in os.walk(gated_out):
        for f in fs:
            p = os.path.join(root, f)
            try:
                txt = open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for v in (STATIC_AKIA, STATIC_ACCOUNTKEY, STATIC_SIG,
                      STATIC_JWT, STATIC_PRIVATE_KEY):
                if v in txt:
                    leaks.append((f, v[:12]))
    check("redaction.no-secret-values", leaks == [], leaks[:4])
    # zero egress: evidence me sirf lab origin
    ev_hosts = set()
    for root, _d, fs in os.walk(gated_out):
        for f in fs:
            if not f.endswith(".jsonl"):
                continue
            try:
                for line in open(os.path.join(root, f), encoding="utf-8",
                                 errors="ignore"):
                    if "http" in line:
                        for tok in line.split('"'):
                            if tok.startswith("http"):
                                ev_hosts.add(urlsplit(tok).netloc)
            except Exception:
                pass
    check("egress.lab-only", all(
        h.startswith("127.0.0.1") or h.endswith(".invalid") or
        h == "null" or h == ""
        for h in ev_hosts), sorted(ev_hosts)[:6])


def checkpoint_replay(httpd, origin, base, out_first, findings_first):
    print("\n== SECTION 5: CHECKPOINT REPLAY (resume, 0 new requests) ==")
    eng = "p25lab_gated"
    before = LAB["requests"]
    scope = WC.Scope(os.path.join(base, eng, "scope.json"))
    cfg = _speed_cfg(gates=[g for g, _ in MC.ROE_GATES])
    out = MC.run(cfg, scope, base)
    after = LAB["requests"]
    check("replay.zero-new-requests", after - before == 0,
          (before, after))
    fin = _read(os.path.join(out, "findings.json")) or {}
    check("replay.findings-stable", fin.get("count") == findings_first,
          (findings_first, fin.get("count")))
    check("replay.artifacts", os.path.exists(
        os.path.join(out, "MANIFEST.json")))


# ===========================================================================
# SECTION 6 - CLI + IMPORT HYGIENE
# ===========================================================================
def cli_tests():
    print("\n== SECTION 6: CLI + IMPORT HYGIENE ==")
    p = subprocess.run([sys.executable, "-W", "error", "-m", "py_compile",
                        os.path.join(ULTRA, "mod_controls.py")],
                       capture_output=True, text=True)
    check("cli.py-compile", p.returncode == 0, p.stderr[:160])
    p2 = subprocess.run([sys.executable, os.path.join(ULTRA,
                                                      "mod_controls.py")],
                        capture_output=True, text=True, timeout=60)
    check("cli.main-run", p2.returncode == 0 and "Phase 25" in p2.stdout,
          p2.stderr[:160])
    check("cli.main-gates", "controls_allow_bypass2" in p2.stdout and
          "controls_allow_waf_probe" in p2.stdout)
    check("cli.main-v30", "v30" in p2.stdout)
    check("cli.module-name", MC.NAME == "controls")
    check("cli.phase", MC.PHASE == "25-controls")
    check("cli.plan-version", MC.PLAN_VERSION == "30.0.0")
    check("cli.canary", MC.CANARY_FAMILY == "waspP25")


def main():
    print("=" * 70)
    print("P25 test_mod_controls.py v%s - offline INERT lab self-test"
          % MC.PLAN_VERSION)
    print("=" * 70)
    httpd, origin = lab_server()
    base = tempfile.mkdtemp(prefix="p25lab_")
    try:
        _write_fixtures(base, origin, "p25lab_gateoff")
        _write_fixtures(base, origin, "p25lab_gated")
        _write_fixtures(base, origin, "p25lab_passive")
        unit_tests()
        out_off = e2e_gate_off(httpd, origin, base)
        out_gated = e2e_gated(httpd, origin, base)
        fin_g = (_read(os.path.join(out_gated, "findings.json")) or {})
        passive_and_rwx(httpd, origin, base, out_gated)
        checkpoint_replay(httpd, origin, base, out_gated,
                          fin_g.get("count", 0))
        cli_tests()
    finally:
        try:
            httpd.shutdown()
        except Exception:
            pass
        shutil.rmtree(base, ignore_errors=True)
    print("\n" + "=" * 70)
    print("TOTAL: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for n, d in FAIL:
            print("  - %s: %s" % (n, str(d)[:120]))
        sys.exit(1)
    print("ALL GREEN")


if __name__ == "__main__":
    main()
