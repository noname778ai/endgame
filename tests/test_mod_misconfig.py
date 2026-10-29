#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P23 SELF-TEST SUITE - mod_misconfig.py v25.0.0 FULL ULTRA PRO MAX (P23)
=============================================================================
 Mock misconfig lab + full assertion suite:
   - Unit tests (canary/INERT guard/markers/cookie-audit/header-posture/
     secret-shapes/log4j-version/bypass2-18/verdict engine/posture composite/
     platform fp/secrets guard/matrix/chains/playbooks/renderers)
   - Active run e2e gate-OFF (stages A..Z) + 13 RoE-gate-skip documentation
   - Gated run (13 RoE gates ON): debug CONFIRMED + artifact CONFIRMED +
     dirlist CONFIRMED + verbose-error CONFIRMED + log4j weak CONFIRMED +
     admin exposed + cors reflect + trust echo + trace echo + spec live +
     sourcemap live + gql introspection + container metrics + bypass2
     accepted (sab hard caps ke andar, GET-only)
   - Artifact integrity (55 outputs, matrix >= 210 rows x 20 families,
     chains == 26) + verdict ladder
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (artifact/secret VALUES KABHI nahi - sirf sha1/shape)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
     (0 new requests, findings stable)
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi REAL exploitation/
 JNDI payload/IMDS probe/credential stuffing NAHI - sab canary waspP23
 family, GET-only module.
=============================================================================
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
import io
import re
import sys
import json
import time
import shutil
import hashlib
import contextlib
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block5_infra")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_misconfig as MC                                    # noqa: E402
import wasp_core as WC                                        # noqa: E402

save_json = WC.save_json

BASE = os.path.join(HERE, "p23_test_base")
BASE_GATED = os.path.join(HERE, "p23_test_base_gated")
BASE2 = os.path.join(HERE, "p23_test_base_passive")
ENG = "p23lab"
ENG_G = "p23lab2"
ENG_P = "p23labp"

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
    return open(os.path.join(ULTRA, "mod_misconfig.py"), encoding="utf-8",
                errors="ignore").read()


# ===========================================================================
# MOCK MISCONFIG LAB (detection-only sim - sab responses INERT, GET-only)
# ===========================================================================
LAB = {"requests": 0}

# fake secret VALUES (lab-only; module artifacts me KABHI nahi aane chahiye)
STATIC_AKIA = "AKIAIOSFODNN7EXAMPLE"
STATIC_DBPASS = "SuperSecret123"
STATIC_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
              "eyJzdWIiOiJ3YXNwUDIzIn0.kK7VcL0zF8SECRETpart9xQ")
STATIC_MAPSRC = "secret-source-token-waspP23-map"

ENV_BODY = ("DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=%s\n"
            "APP_DEBUG=true\n" % STATIC_DBPASS)
GIT_HEAD = "ref: refs/heads/main\n"

HOME_HTML = """<html><head><title>waspP23 home</title></head><body>
<h1>waspP23 home</h1>
<p>Misconfig lab home. Endpoints census-ready.</p>
</body></html>"""

LOGIN_HTML = """<html><head><title>waspP23 login</title></head><body>
<h1>Sign in</h1>
<form method="POST" action="/login"><input name="user"><input
 type="password" name="pass"></form>
<p>waspP23 login page - weak headers/cookies shape.</p>
</body></html>"""

STRONG_HTML = """<html><head><title>waspP23 strong</title></head><body>
<h1>Hardened page</h1>
<p>waspP23 hardened page - full header/cookie posture.</p>
</body></html>"""

DEBUG_VARS_HTML = """<html><body>{"_links":{"self":{"href":"/actuator"}},
"env":{"beans":"..."}}</body></html>"""
CONSOLE_HTML = """<html><head><title>Console</title></head>
<body>Werkzeug Debugger interactive console</body></html>"""
PPROF_HTML = """<html><body>Types of profiles available:
<p><a href="?debug=1">allocs</a> goroutine profile</p></body></html>"""
PHPINFO_HTML = """<html><head><title>phpinfo()</title></head>
<body><h1>PHP Version 7.4.3</h1><p>Configuration File (php.ini) Path</p>
</body></html>"""

TRACEBACK_HTML = """<html><head><title>500</title></head><body>
<pre>Traceback (most recent call last):
  File "/srv/app/handler.py", line 88, in handle
    process(q)
ValueError: invalid literal</pre>
<p>waspP23 verbose error page.</p></body></html>"""
GENERIC_ERR_HTML = """<html><head><title>Error</title></head>
<body><p>Something went wrong. Ref: waspP23-generic</p></body></html>"""

ADMIN_HTML = """<html><head><title>Tomcat Web Application Manager</title>
</head><body><h1>Tomcat Manager App</h1><p>waspP23 admin console.</p>
</body></html>"""

CORS_ANY = """<html><body>cors open endpoint waspP23</body></html>"""
CORS_STRICT = """<html><body>cors strict endpoint waspP23</body></html>"""

SPEC_JSON = json.dumps({
    "openapi": "3.0.0", "info": {"title": "waspP23 API", "version": "1.0"},
    "paths": {"/api/users": {"get": {}},
              "/api/admin/export": {"post": {}},
              "/api/internal/debug": {"get": {}}}})

MAP_JSON = json.dumps({
    "version": 3, "file": "app.js",
    "sources": ["webpack://src/app.js", "webpack://src/secret.js"],
    "sourcesContent": ["// app code " + STATIC_MAPSRC, "// more"],
    "names": []})

GQL_OPEN = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
GQL_LOCKED = json.dumps({"errors": [{"message": "introspection disabled"}]})
GQL_HOME = """<html><head><title>GraphiQL</title></head>
<body>GraphiQL playground waspP23</body></html>"""

METRICS_TXT = ("# HELP go_gc_duration_seconds GC duration.\n"
               "# TYPE go_gc_duration_seconds summary\n"
               "go_gc_duration_seconds_sum 1.2\n")
REGISTRY_JSON = json.dumps({"repositories": ["app/api", "app/web"]})
SERVER_STATUS_HTML = """<html><head><title>Apache Server Status</title>
</head><body>Apache Server Status for localhost - Server uptime: 3 days
</body></html>"""

TRACE_ECHO = "TRACE /trace"      # + query echo (do_TRACE me add hota hai)
PROTECTED_403 = """<html><body>403 forbidden waspP23 protected</body></html>"""
PROTECTED_OK = """<html><body>welcome admin area waspP23</body></html>"""

SOFT404_HTML = """<html><head><title>waspP23 template</title></head><body>
<h1>Not found-ish template</h1>
<p>waspP23 generic template page content. Nothing here.</p>
</body></html>"""

SECRETS_HTML = """<html><head><title>waspP23 secrets page</title></head>
<body>
<p>config: api_key=%s</p>
<p>token: %s</p>
<p>db: postgres://admin:Pa55w0rd@db.internal:5432/prod</p>
<p>host: 10.20.30.40 internal</p>
<p>mail: dev-team@examplecorp.com</p>
</body></html>""" % (STATIC_AKIA, STATIC_JWT)

BACKUP_BYTES = b"PK\x03\x04fakebackupbinarystuff" * 8


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", hdrs=None):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (hdrs or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def _j(self, code, obj, hdrs=None):
        self._send(code, json.dumps(obj), "application/json", hdrs)

    def _q(self):
        return parse_qs(urlsplit(self.path).query)

    def _route(self):
        LAB["requests"] += 1
        p = urlsplit(self.path).path
        q = self._q()

        if p == "/" or p == "/index.html":
            return self._send(200, HOME_HTML)
        # ---- weak headers/cookies page (stage E/M targets) ----
        if p == "/login":
            return self._send(200, LOGIN_HTML, hdrs={
                "Set-Cookie": "wasp_session=abc123; Domain=.lab.invalid; "
                              "Path=/",
                "Server": "nginx/1.18.0", "X-Powered-By": "Express"})
        # ---- strong posture page ----
        if p == "/strong":
            return self._send(200, STRONG_HTML, hdrs={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Set-Cookie": "hs=xyz; Path=/; Secure; HttpOnly; "
                              "SameSite=Strict"})
        # ---- debug family (stage C pool) ----
        if p == "/debug/vars":
            return self._send(200, DEBUG_VARS_HTML)
        if p == "/console":
            return self._send(200, CONSOLE_HTML)
        if p == "/debug/pprof":
            return self._send(200, PPROF_HTML)
        if p == "/phpinfo.php":
            return self._send(200, PHPINFO_HTML)
        # ---- artifacts (stage D pool) ----
        if p == "/.git/HEAD":
            return self._send(200, GIT_HEAD, "text/plain")
        if p == "/.env":
            return self._send(200, ENV_BODY, "text/plain")
        if p == "/backup.zip":
            return self._send(200, BACKUP_BYTES, "application/zip")
        if p == "/files/" or p == "/files":
            return self._send(200, "<html><head><title>Directory listing "
                              "for /files/</title></head><body><h1>Directory "
                              "listing for /files/</h1><hr><a href="
                              "\"../\">Parent Directory</a><a href=\"a.txt\">"
                              "a.txt</a></body></html>")
        # ---- verbose errors (stage G target) ----
        if p == "/errors":
            return self._send(500, TRACEBACK_HTML)
        if p == "/errors_clean":
            return self._send(500, GENERIC_ERR_HTML)
        # ---- log4j version disclosure (stage H) ----
        if p == "/log4j":
            return self._send(200, "<html><body>svc page waspP23</body>"
                              "</html>", hdrs={
                                  "X-Application-Version":
                                  "log4j-core-2.14.1"})
        # ---- admin (stage J pool) ----
        if p == "/admin":
            orig = self.headers.get("X-Original-URL", "")
            body = ADMIN_HTML if not orig else \
                "<html><body>orig-url-echo:%s</body></html>" % orig
            return self._send(200, body)
        if p == "/manager/html":
            return self._send(401, "<html><body>401 unauthorized</body>"
                              "</html>", hdrs={"WWW-Authenticate":
                                               "Basic realm=tm"})
        # ---- protected (bypass2 stage U) ----
        if p == "/protected":
            orig = self.headers.get("X-Original-URL", "")
            if orig == "/":
                return self._send(200, PROTECTED_OK)
            return self._send(403, PROTECTED_403)
        # ---- cors (stage L targets) ----
        if p == "/cors":
            o = self.headers.get("Origin", "")
            return self._send(200, CORS_ANY, hdrs={
                "Access-Control-Allow-Origin": o or "*",
                "Access-Control-Allow-Credentials": "true"})
        if p == "/cors_strict":
            o = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            if o and host and o.endswith(host):
                return self._send(200, CORS_STRICT, hdrs={
                    "Access-Control-Allow-Origin": o})
            return self._send(200, CORS_STRICT)
        # ---- transport (stage P) ----
        if p == "/secure":
            return self._send(301, "", hdrs={
                "Location": "https://127.0.0.1/secure",
                "Strict-Transport-Security": "max-age=31536000"})
        # ---- api spec (stage Q pool) ----
        if p == "/swagger.json":
            return self._send(200, SPEC_JSON, "application/json")
        # ---- sourcemap (stage R pool) ----
        if p == "/app.js.map":
            return self._send(200, MAP_JSON, "application/json")
        # ---- graphql (stage S) ----
        if p == "/graphql":
            query = (q.get("query") or [""])[0]
            if "__schema" in query:
                return self._send(200, GQL_OPEN, "application/json")
            return self._send(200, GQL_HOME)
        if p == "/graphql_locked":
            query = (q.get("query") or [""])[0]
            if "__schema" in query:
                return self._send(200, GQL_LOCKED, "application/json")
            return self._send(403, GENERIC_ERR_HTML)
        # ---- container (stage T pool) ----
        if p == "/metrics":
            return self._send(200, METRICS_TXT, "text/plain")
        if p == "/v2/_catalog":
            return self._send(200, REGISTRY_JSON, "application/json")
        if p == "/server-status":
            return self._send(200, SERVER_STATUS_HTML)
        # ---- secrets page (stage F target) ----
        if p == "/secrets_page":
            return self._send(200, SECRETS_HTML)
        # ---- header trust (stage N target) ----
        if p == "/header_trust":
            xf = self.headers.get("X-Forwarded-Host", "")
            xourl = self.headers.get("X-Original-URL", "")
            body = "trust page waspP23"
            if xf:
                body += " fwd-host:%s" % xf
            if xourl:
                body += " orig:%s" % xourl
            return self._send(200, "<html><body>%s</body></html>" % body)
        # ---- cacheable page ----
        if p == "/cacheable":
            return self._send(200, "<html><body>cache me waspP23</body>"
                              "</html>", hdrs={"Cache-Control":
                                               "public, max-age=300"})
        # ---- catch-all (soft-404 template) ----
        return self._send(200, SOFT404_HTML)

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._send(405, "<html><body>lab is GET-only (INERT sim)</body>"
                   "</html>")

    def do_HEAD(self):
        self._route()

    def do_OPTIONS(self):
        LAB["requests"] += 1
        p = urlsplit(self.path).path
        allow = "GET, POST, PUT, DELETE, OPTIONS"
        if p == "/trace":
            allow = "GET, POST, PUT, DELETE, OPTIONS, TRACE"
        self._send(200, "", hdrs={"Allow": allow,
                                  "Access-Control-Allow-Methods": allow})

    def do_TRACE(self):
        # INERT echo sim: request-line echo (canary-in-URL detectable)
        LAB["requests"] += 1
        self._send(200, "TRACE %s waspP23 echo" % self.path)


@contextlib.contextmanager
def lab_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield "http://127.0.0.1:%d" % port
    finally:
        srv.shutdown()
        srv.server_close()


def _write_fixtures(base, origin, engagement):
    """Engagement feedforward fixtures (P9..P22 handoff seeds) + scope.json."""
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

    wff("auth", {"to_phase23_misconfig": {"paths": [
        origin + "/login", origin + "/strong", origin + "/errors",
        origin + "/errors_clean", origin + "/admin",
        origin + "/admin_hardened", origin + "/protected",
        origin + "/cors", origin + "/cors_strict", origin + "/graphql",
        origin + "/graphql_locked", origin + "/secure",
        origin + "/secrets_page", origin + "/files/",
        origin + "/api/users", origin + "/header_trust",
        origin + "/log4j"]}})
    wff("replay", {"to_phase23_misconfig": {"cacheable_token_routes": [
        origin + "/cacheable"]}})
    wff("inject", {"to_phase23_log4shell": {"hints": [origin + "/log4j"]}})
    wff("graphql", {"to_phase23_gql": {"mutations": [
        "redeemGiftCard", "applyCoupon"]}})
    wff("ws", {"to_phase23_ws": {"endpoints": ["/ws/notifications"]}})
    save_json(os.path.join(base, "scope.json"), {
        "engagement": engagement,
        "authorized": True,
        "authorization_reference": "P23 lab RoE / selftest",
        "targets": [origin],
        "notes": "INERT self-test lab - detection-only"})


def _speed_cfg(gates=None, allow_active=None):
    cfg = WC.Cfg(None)
    cfg.rate_limit = 500.0
    cfg.jitter = 0.0
    cfg.timeout = 6
    cfg.concurrency = 8
    cfg.retries = 0
    cfg.save_bodies = False
    cfg.save_replays = False
    cfg.resume = True
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
    check("unit.canary.family", c.startswith("waspP23") and len(c) > 10, c)
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        try:
            MC.assert_inert_method(m)
            check("unit.inert.%s-block" % m.lower(), False, "%s allowed!" % m)
        except RuntimeError:
            check("unit.inert.%s-block" % m.lower(), True)
    check("unit.inert.get-ok", MC.assert_inert_method("GET") is True)
    check("unit.inert.options-ok", MC.assert_inert_method("OPTIONS") is True)
    check("unit.inert.head-ok", MC.assert_inert_method("HEAD") is True)
    check("unit.inert.trace-gate-flag",
          MC.assert_inert_method("TRACE") == "GATE_REQUIRED")
    check("unit.inert.allowed-table",
          set(MC._ALLOWED_PROBE_METHODS) == {"GET", "HEAD", "OPTIONS",
                                             "TRACE"},
          MC._ALLOWED_PROBE_METHODS)

    # ---- markers ----
    check("unit.marker.autoindex",
          MC.match_markers(MC.AUTOINDEX_RX,
                           "<title>Index of /files/") is not None)
    check("unit.marker.autoindex-none",
          MC.match_markers(MC.AUTOINDEX_RX, "<html>normal</html>") is None)
    check("unit.marker.actuator",
          MC.match_markers(MC.DEBUG_MARKER_RX, '{"_links":{"self":{}}}') ==
          "spring-actuator")
    check("unit.marker.werkzeug",
          MC.match_markers(MC.DEBUG_MARKER_RX, "Werkzeug Debugger console") ==
          "werkzeug-console")
    check("unit.marker.all-stack",
          len(MC.match_all_markers(MC.STACKTRACE_RX,
                                   "Traceback (most recent call last): "
                                   "system.NullReferenceException stack "
                                   "trace:")) >= 2)
    check("unit.marker.table-sizes",
          len(MC.DEBUG_MARKER_RX) == 10 and len(MC.STACKTRACE_RX) == 7 and
          len(MC.PLATFORM_LOGIN_RX) == 16 and len(MC.AUTOINDEX_RX) == 4)

    # ---- cookie audit ----
    wa = MC.cookie_flag_audit("wasp_session=abc123; Domain=.lab.invalid; "
                              "Path=/")
    check("unit.cookie.weak", (not wa["secure"] and not wa["httponly"] and
                               not wa["samesite"] and wa["domain_broad"]),
          wa)
    sa = MC.cookie_flag_audit("hs=xyz; Path=/; Secure; HttpOnly; "
                              "SameSite=Strict")
    check("unit.cookie.strong", sa["secure"] and sa["httponly"] and
          sa["samesite"] and not sa["domain_broad"], sa)
    ha = MC.cookie_flag_audit("__Host-sid=zzz; Secure; HttpOnly; "
                              "SameSite=Lax; Path=/")
    check("unit.cookie.prefix", ha["host_prefix"], ha)

    # ---- header posture ----
    present = {k for k, _ in MC.SECURITY_HEADERS}
    s9, g9 = MC.header_posture_grade(present, set())
    check("unit.headers.strong", s9 == 9 and g9 == "STRONG", (s9, g9))
    s1, g1 = MC.header_posture_grade({"content-security-policy"}, set())
    check("unit.headers.weak", s1 == 1 and g1 == "WEAK", (s1, g1))

    # ---- secret shapes (values REDACTED by design) ----
    body = ("api_key=%s\ntoken=%s\ndb: postgres://user1:P5ssw0rd@db:5432/x\n"
            "host 10.0.0.5\n" % (STATIC_AKIA, STATIC_JWT))
    shapes = MC.secret_shape_scan(body)
    names = {s["shape"] for s in shapes}
    check("unit.secrets.aws", "aws-access-key" in names, names)
    check("unit.secrets.jwt", "jwt" in names, names)
    check("unit.secrets.dburl", "db-url-creds" in names, names)
    check("unit.secrets.internalip", "internal-ip" in names, names)
    check("unit.secrets.no-values",
          all(STATIC_AKIA not in json.dumps(s) and
              STATIC_JWT not in json.dumps(s) for s in shapes), shapes)
    check("unit.secrets.sha1", all(len(s["sha1_12"]) == 12 for s in shapes))
    check("unit.secrets.table", len(MC.SECRET_SHAPE_RX) == 30,
          len(MC.SECRET_SHAPE_RX))

    # ---- log4j version window ----
    rx = MC.LOG4J_VERSION_RX
    m1 = rx.search("log4j-core-2.14.1")
    m_hdr = rx.search("X-Application-Version: log4j-core-2.14.1")
    check("unit.log4j.weak-match", bool(m1) and bool(m_hdr) and
          tuple(int(x) for x in m1.group(2).split(".")) < (2, 17, 1),
          m1 and m1.group(0))
    m2 = rx.search("log4j-core-2.17.1")
    check("unit.log4j.patched", bool(m2) and
          tuple(int(x) for x in m2.group(2).split(".")) >= (2, 17, 1),
          m2 and m2.group(0))

    # ---- bypass2 shapes ----
    shapes = MC._bypass2_shapes("http://x/protected", "waspP23mbabc")
    check("unit.bypass2.count", len(shapes) == 18, len(shapes))
    check("unit.bypass2.ids", [s[0] for s in shapes] ==
          ["MB-%02d" % i for i in range(1, 19)],
          [s[0] for s in shapes][:4])
    check("unit.bypass2.get-only", all(
        s[3].get("X-HTTP-Method") is None for s in shapes))
    check("unit.bypass2.trust-shapes", any(
        "X-Original-URL" in s[3] for s in shapes) and any(
        "X-Forwarded-For" in s[3] for s in shapes))

    # ---- matrix ----
    mx = MC.build_matrix()
    fams = set(m["family"] for m in mx)
    check("unit.matrix.rows", len(mx) >= 210, len(mx))
    check("unit.matrix.families", len(fams) == 20, sorted(fams))
    check("unit.matrix.cwe", all(m["cwe"].startswith("CWE-") for m in mx))
    check("unit.matrix.mitre", all(m["mitre"].startswith("T") for m in mx))
    check("unit.matrix.ids", mx[0]["id"] == "MIS-001" and
          mx[-1]["id"] == "MIS-%03d" % len(mx))

    # ---- chains ----
    ch = MC.build_chains({}, {"to_phase23_misconfig": {}})
    check("unit.chains.count", len(ch) == 26, len(ch))
    check("unit.chains.ids", ch[0]["id"] == "CH01" and
          ch[-1]["id"] == "CH26")
    check("unit.chains.ff", all("ff_seeds" in c for c in ch))

    # ---- playbooks ----
    check("unit.log4shell.playbook", len(MC.LOG4SHELL_PLAYBOOK_ROWS) == 8)
    check("unit.log4shell.forbidden", all(
        any(w in d.lower() for w in (
            "kabhi", "forbidden", "manual", "roe", "census", "review",
            "remediation", "aid", "only"))
        for _, _, d in MC.LOG4SHELL_PLAYBOOK_ROWS))
    check("unit.cloud.playbook", len(MC.CLOUD_PLAYBOOK_ROWS) == 6)
    check("unit.cloud.imds-forbidden", any(
        "FORBIDDEN-AUTO" in d for _, _, d in MC.CLOUD_PLAYBOOK_ROWS))
    check("unit.defaults.matrix", len(MC.DEFAULT_CRED_ROWS) == 14)
    check("unit.race.techniques", len(MC.RACE_TECHNIQUES) == 6 and all(
        "FORBIDDEN-AUTO" in t[2] or "documented aid" in t[2]
        for t in MC.RACE_TECHNIQUES))

    # ---- verdict engine (synthetic) ----
    synth = {
        "debug": {"rows": [{"url": "http://x/console", "live": True,
                            "shape": "werkzeug-console"}]},
        "artifacts": {"rows": [{"url": "http://x/.env", "live": True,
                                "shape": "env-shape"}],
                      "dirlist_rows": [{"url": "http://x/files/",
                                        "live": True, "shape": "listing"}]},
        "headers": {"rows": [{"url": "http://x/", "grade": "WEAK",
                              "score": 1, "missing": ["CSP", "HSTS"]}]},
        "secrets": {"rows": [{"url": "http://x/s",
                              "shapes": [{"shape": "aws-access-key"}]}]},
        "errors": {"rows": [{"url": "http://x/e", "verbose_hits": 2}]},
        "log4shell": {"rows": [{"url": "http://x/l",
                                "kind": "version-disclosure",
                                "weak_version": True,
                                "match": "log4j-core-2.14.1"}]},
        "admin": {"rows": [{"url": "http://x/admin", "live": True,
                            "platform": "tomcat-manager"}]},
        "cors": {"rows": [{"url": "http://x/c", "reflect_attacker": True,
                           "grade": "REFLECT-ANY"}]},
        "cookies": {"rows": [{"url": "http://x/login", "weak_flags": True,
                              "cookies": [{"flags_missing": ["secure"]}]}]},
        "trust": {"rows": [{"url": "http://x/admin", "echo_count": 1,
                            "echoes": [{"header": "X-Original-URL"}]}]},
        "methods": {"rows": [{"url": "http://x/m", "trace_echo": True}]},
        "transport": {"rows": [{"url": "http://x/secure",
                                "transport_strong": True}]},
        "spec": {"rows": [{"url": "http://x/sw", "spec_shape": True,
                           "op_names_count": 3,
                           "sensitive_ops": ["/api/admin"]}]},
        "sourcemap": {"rows": [{"url": "http://x/app.js.map", "live": True,
                                "sources_flag": True}]},
        "gql": {"rows": [{"url": "http://x/gql",
                          "introspection_enabled": True}]},
        "container": {"rows": [{"url": "http://x/metrics", "live": True,
                                "shape": "prometheus-metrics"}]},
        "bypass2": {"rows": [{"url": "http://x/protected",
                              "accepted_count": 1,
                              "accepted_ids": ["MB-11"]}]},
    }
    vd = {(r["stage"], r["verdict"]) for r in MC.verdict_engine(synth)}
    for stg in ("C", "D", "F", "G", "H", "J", "L", "N", "O", "Q", "R", "S",
                "T", "U"):
        check("unit.verdict.%s-confirmed" % stg, (stg, "CONFIRMED") in vd,
              sorted(vd)[:6])
    check("unit.verdict.e-suspected", ("E", "SUSPECTED") in vd)
    check("unit.verdict.m-suspected", ("M", "SUSPECTED") in vd)
    check("unit.verdict.p-hardened", ("P", "HARDENED") in vd)

    # ---- posture composite ----
    post = MC.posture_composite(synth)
    check("unit.posture.points", len(post["points"]) == 12)
    check("unit.posture.rows", len(post["rows"]) >= 6, len(post["rows"]))
    check("unit.posture.weak", len(post["weak"]) >= 1 and
          post["weak"][0]["score"] < 5, post["weak"][:2])
    synth_strong = {
        "headers": {"rows": [{"url": "http://s/", "grade": "STRONG",
                              "score": 9}]},
        "cookies": {"rows": [{"url": "http://s/", "cookies": [{"name": "h"}],
                              "weak_flags": False}]},
        "errors": {"rows": [{"url": "http://s/", "verbose_hits": 0}]},
        "debug": {"rows": [{"url": "http://s/", "live": False,
                            "shape": "", "status": 404}]},
        "admin": {"rows": [{"url": "http://s/", "auth_gate": True}]},
        "artifacts": {"rows": [{"url": "http://s/", "status": 404,
                                "live": False}]},
        "cors": {"rows": [{"url": "http://s/", "strict": True,
                           "reflect_any": False}]},
        "methods": {"rows": [{"url": "http://s/", "trace_echo": False,
                              "broad_methods": []}]},
        "spec": {"rows": [{"url": "http://s/", "status": 404,
                           "spec_shape": False}]},
        "secrets": {"rows": [{"url": "http://s/", "status": 200,
                              "shapes": []}]},
    }
    post2 = MC.posture_composite(synth_strong)
    check("unit.posture.strong", len(post2["strong"]) >= 1 and
          post2["strong"][0]["score"] >= 9, post2["strong"][:1])

    # ---- platform fp + guard ----
    pf = MC.platform_fingerprint(["Werkzeug debugger", "x-amz-request-id",
                                  "kubernetes"])
    check("unit.platform.shapes", "werkzeug-console" not in pf["shapes"] and
          len(pf["shapes"]) >= 2, pf["shapes"])
    guard = MC.secrets_guard([("findings.md",
                               "leak api_key=%s here" % STATIC_AKIA)])
    check("unit.guard.hit", len(guard["hits"]) == 1 and
          "REDACTED" in guard["hits"][0]["shape"], guard)
    check("unit.guard.clean", MC.secrets_guard([("f.md", "nothing here")])[
        "hits"] == [])

    # ---- findings/severity ----
    F = MC.Findings()
    r1 = F.add("misconfig_debug_live", "t", "http://e", "d")
    check("unit.findings.sev", r1["severity"] == "critical" and
          r1["id"] == "MC-001", r1)
    r2 = F.add("misconfig_token_never", "t", "e",
               "mail dev@examplecorp.com pw=hunter2222")
    check("unit.findings.pii", "@***" in r2["detail"] or
          "hunter2222" not in r2["detail"], r2["detail"])
    check("unit.hints.count", len(MC.SEVERITY_HINTS) >= 50,
          len(MC.SEVERITY_HINTS))
    check("unit.hints.shape", all(len(v) == 3 for v in
                                  MC.SEVERITY_HINTS.values()))

    # ---- renderers ----
    mx = MC.build_matrix()
    tp = MC.render_test_plan(F, {g: False for g, _ in MC.ROE_GATES}, mx)
    check("unit.render.testplan", "KD-13" in tp and "FORBIDDEN-AUTO" in tp)
    check("unit.render.matrix-txt",
          "MISCONFIG_BYPASS2" in MC.render_matrix_txt(mx))
    md = MC.render_findings_md(
        type("S", (), {"engagement": "t"})(), F,
        [{"stage": "C", "url": "u", "verdict": "CONFIRMED",
          "signals": ["live"], "detail": "d"}],
        MC.build_chains({}, {}), {"mode": "active"})
    check("unit.render.findings-md", "MC-001" in md and "CH01" in md)
    ex = MC.render_exec_summary(type("S", (), {"engagement": "t",
                                               "ref": "r"})(), F,
                                post, MC.verdict_engine(synth),
                                {"mode": "active"})
    check("unit.render.exec", "CONFIRMED misconfig exposures" in ex)
    rem = MC.render_remediation(F)
    check("unit.render.remediation", "MISCONFIG_DEBUG" in rem and
          "MISCONFIG_BYPASS2" in rem)
    ko = MC.render_kickoff(type("S", (), {"engagement": "t"})(),
                           {g: False for g, _ in MC.ROE_GATES}, MC.DEFAULTS)
    check("unit.render.kickoff", "GET-only module" in ko)
    pb = MC.render_playbooks()
    check("unit.render.playbooks", "L4-01" in pb and "CM-01" in pb and
          "DC-01" in pb and "RA-06" in pb)
    check("unit.render.chains-txt",
          "CH26" in MC.render_chains_txt(MC.build_chains({}, {})))
    hy = MC.build_hypotheses(synth, post)
    check("unit.render.hypotheses", len(hy) >= 2 and hy[0]["prio"] ==
          "critical", hy[:2])

    # ---- gates + source discipline ----
    check("unit.gates.count", len(MC.ROE_GATES) == 13, len(MC.ROE_GATES))
    check("unit.gates.default-off", all(
        not bool(v) for k, v in MC.DEFAULTS.items() if "allow" in k))
    src = _src()
    check("unit.src.no-post-probe",
          not re.search(r'probe\(\s*http\s*,\s*["\'](?:POST|PUT|DELETE|'
                        r'PATCH)["\']', src))
    check("unit.src.get-only-assert", "assert_inert_method" in src and
          "_ALLOWED_PROBE_METHODS" in src)
    check("unit.src.canary-family", src.count("waspP23") >= 6)
    check("unit.src.no-jndi-payload",
          "${jndi" not in src.lower().replace("${jndi:...", ""))
    check("unit.src.no-imds-url", "169.254.169.254" not in src)


# ===========================================================================
# SECTION 2 - E2E GATE-OFF RUN (stages A..Z, 13 gates OFF)
# ===========================================================================
def e2e_gate_off(httpd, origin, base):
    print("\n== SECTION 2: E2E GATE-OFF RUN ==")
    cfg = _speed_cfg()
    out = MC.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    check("e2e.outdir", out and os.path.isdir(out), out)
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("e2e.manifest.phase", man.get("phase") == "phase23",
          man.get("phase"))
    check("e2e.manifest.artifacts", (man.get("stats") or {}).get(
        "artifacts", 0) >= 52, man.get("stats"))
    check("e2e.manifest.matrix", (man.get("stats") or {}).get(
        "matrix_rows", 0) >= 210)
    check("e2e.manifest.chains", (man.get("stats") or {}).get(
        "chains", 0) == 26)
    check("e2e.manifest.mode", (man.get("stats") or {}).get(
        "mode") == "active")
    cov = _read(os.path.join(out, "misconfig_coverage.json")) or {}
    check("e2e.coverage.mode", cov.get("mode") == "active")
    check("e2e.coverage.sources", len(cov.get("sources", [])) >= 3,
          cov.get("sources"))
    check("e2e.coverage.gates-off", all(
        v is False for v in (cov.get("gates") or {}).values()))
    check("e2e.coverage.stages", len(cov.get("stages", [])) == 26)
    fj = _read(os.path.join(out, "findings.json")) or {}
    check("e2e.findings.count", fj.get("count", 0) >= 5, fj.get("count"))
    check("e2e.findings.ids", all(str(f.get("id", "")).startswith("MC-")
                                  for f in fj.get("findings", [])))
    keys = {f.get("key") for f in fj.get("findings", [])}
    check("e2e.findings.default-creds",
          "misconfig_default_creds_documented" in keys, keys)
    check("e2e.findings.headers",
          "misconfig_headers_missing" in keys, keys)
    check("e2e.findings.cookies", "misconfig_cookie_flags" in keys, keys)
    check("e2e.findings.secret-shape", "misconfig_secret_shape" in keys,
          keys)
    check("e2e.findings.posture-weak", "misconfig_posture_weak" in keys,
          keys)
    vv = _read(os.path.join(out, "misconfig_verdicts.json")) or {}
    rows = vv.get("rows", [])
    skips = [r for r in rows if r.get("verdict") == "SKIPPED"]
    check("e2e.verdict.skipped-documented", len(skips) >= 13, len(skips))
    conf_rows = [r for r in rows if r.get("verdict") == "CONFIRMED"]
    check("e2e.verdict.confirmed-only-passive",
          all(r["stage"] == "F" for r in conf_rows) and len(conf_rows) <= 3,
          [(r["stage"], r["url"]) for r in conf_rows])
    for art in ("misconfig_targets.json", "misconfig_debug.json",
                "misconfig_artifacts.json", "misconfig_headers.json",
                "misconfig_secrets.json", "misconfig_errors.json",
                "misconfig_log4shell.json", "misconfig_default_creds.json",
                "misconfig_admin.json", "misconfig_cloud.json",
                "misconfig_cors.json", "misconfig_cookies.json",
                "misconfig_header_trust.json", "misconfig_methods.json",
                "misconfig_transport.json", "misconfig_spec.json",
                "misconfig_sourcemap.json", "misconfig_gql.json",
                "misconfig_container.json", "misconfig_bypass2.json",
                "misconfig_posture.json", "misconfig_platform.json",
                "misconfig_secret_guard.json", "misconfig_chains.json",
                "misconfig_matrix.json", "MISCONFIG_FINDINGS.md",
                "MISCONFIG_TEST_PLAN.md", "MISCONFIG_REMEDIATION.md",
                "EXEC_SUMMARY.md", "MISCONFIG_KICKOFF.md",
                "MISCONFIG_PLAYBOOKS.md", "misconfig_gql_mutations.json",
                "misconfig_ws_endpoints.json", "feedforward.json"):
        check("e2e.artifact.%s" % art,
              os.path.exists(os.path.join(out, art)))
    gqlm = _read(os.path.join(out, "misconfig_gql_mutations.json")) or {}
    check("e2e.gql.names", "redeemGiftCard" in (gqlm.get("mutations") or []),
          gqlm)
    ws = _read(os.path.join(out, "misconfig_ws_endpoints.json")) or {}
    check("e2e.ws.endpoints", ws.get("count", 0) >= 1, ws)
    ff = _read(os.path.join(out, "feedforward.json")) or {}
    rk = set((ff.get("routing") or {}).keys())
    check("e2e.feedforward.keys", {"to_phase24_cloud", "to_phase25_controls",
                                   "to_phase11_access", "to_phase12_inject",
                                   "to_phase9_auth", "to_phase32_report"}
          <= rk, rk)
    gates_txt = _read_txt(os.path.join(out, "misconfig_gates.txt"))
    check("e2e.gates-txt", "misconfig_allow_debug_probe = false" in
          gates_txt)
    pb = _read_txt(os.path.join(out, "MISCONFIG_PLAYBOOKS.md"))
    check("e2e.playbook.jndi-forbidden", "FORBIDDEN-AUTO" in pb)
    check("e2e.probes-bounded", (man.get("stats") or {}).get(
        "probes", 999) <= 400, man.get("stats", {}).get("probes"))
    return out, cfg, man


# ===========================================================================
# SECTION 3 - GATED RUN (13 RoE gates ON - hard caps ke andar)
# ===========================================================================
def e2e_gated(httpd, origin, base):
    print("\n== SECTION 3: GATED RUN (13 gates ON) ==")
    gates = [g for g, _ in MC.ROE_GATES]
    cfg2 = _speed_cfg(gates=gates)
    out = MC.run(cfg2, WC.Scope(os.path.join(base, "scope.json")), base)
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("gated.manifest.gates-on", sorted(
        (man.get("stats") or {}).get("gates_on", [])) == sorted(gates),
        man.get("stats", {}).get("gates_on"))
    vv = _read(os.path.join(out, "misconfig_verdicts.json")) or {}
    rows = vv.get("rows", [])
    conf = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "CONFIRMED"]
    hard = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "HARDENED"]
    check("gated.confirmed-present", len(conf) >= 12, conf[:8])
    check("gated.hardened-present", len(hard) >= 3, hard[:8])
    c_urls = {st: [u for s, u in conf if s == st] for st in
              set(s for s, _ in conf)}
    check("gated.debug-confirmed", any("debug/vars" in u or "console" in u
                                       for u in c_urls.get("C", [])),
          c_urls.get("C"))
    check("gated.artifact-confirmed", any(".env" in u or ".git" in u
                                          for u in c_urls.get("D", [])),
          c_urls.get("D"))
    check("gated.dirlist-confirmed", any("files" in u
                                         for u in c_urls.get("D", [])),
          c_urls.get("D"))
    check("gated.error-confirmed", any("errors" in u
                                       for u in c_urls.get("G", [])),
          c_urls.get("G"))
    check("gated.log4j-confirmed", any("log4j" in u
                                       for u in c_urls.get("H", [])),
          c_urls.get("H"))
    check("gated.admin-confirmed", any("/admin" in u
                                       for u in c_urls.get("J", [])),
          c_urls.get("J"))
    check("gated.cors-confirmed", any("cors" in u
                                      for u in c_urls.get("L", [])),
          c_urls.get("L"))
    check("gated.trace-documented", any(
        r.get("broad_methods") or r.get("trace_documented")
        for r in (_read(os.path.join(out, "misconfig_methods.json")) or {})
        .get("rows", [])))
    check("gated.spec-confirmed", any("swagger" in u
                                      for u in c_urls.get("Q", [])),
          c_urls.get("Q"))
    check("gated.sourcemap-confirmed", any(".map" in u
                                           for u in c_urls.get("R", [])),
          c_urls.get("R"))
    check("gated.gql-confirmed", any("graphql" in u
                                     for u in c_urls.get("S", [])),
          c_urls.get("S"))
    check("gated.container-confirmed", any("metrics" in u
                                           for u in c_urls.get("T", [])),
          c_urls.get("T"))
    check("gated.bypass2-confirmed", any("protected" in u
                                         for u in c_urls.get("U", [])),
          c_urls.get("U"))
    check("gated.trust-confirmed", len(c_urls.get("N", [])) >= 1,
          c_urls.get("N"))
    hard_urls = [u for s, u in hard]
    check("gated.admin-hardened", any("manager/html" in u
                                      for u in hard_urls), hard_urls[:6])
    fj = _read(os.path.join(out, "findings.json")) or {}
    keys = {f.get("key") for f in fj.get("findings", [])}
    for kx in ("misconfig_debug_live", "misconfig_artifact_live",
               "misconfig_verbose_error", "misconfig_log4j_version",
               "misconfig_admin_live", "misconfig_cors_reflect",
               "misconfig_methods_broad", "misconfig_spec_live",
               "misconfig_sourcemap_live", "misconfig_gql_introspect",
               "misconfig_container_live", "misconfig_bypass2_accepted"):
        check("gated.finding.%s" % kx, kx in keys, sorted(keys)[:14])
    b2 = _read(os.path.join(out, "misconfig_bypass2.json")) or {}
    check("gated.bypass2.rows", len(b2.get("rows", [])) >= 1)
    check("gated.bypass2.accepted", any(
        r.get("accepted_count", 0) >= 1 for r in b2.get("rows", [])),
        [r.get("accepted_count") for r in b2.get("rows", [])])
    check("gated.bypass2.shapes-18", all(
        len(r.get("shapes", [])) == 18 for r in b2.get("rows", [])))
    dbg = _read(os.path.join(out, "misconfig_debug.json")) or {}
    check("gated.debug.shapes", any(
        r.get("shape") for r in dbg.get("rows", [])))
    post = _read(os.path.join(out, "misconfig_posture.json")) or {}
    check("gated.posture.rows", len(post.get("rows", [])) >= 3,
          len(post.get("rows", [])))
    return out


# ===========================================================================
# SECTION 4/5 - PASSIVE + CHECKPOINT REPLAY + RWX/EGRESS/REDACTION
# ===========================================================================
def _walk_files(out):
    for root, _dirs, files in os.walk(out):
        for f in files:
            yield os.path.join(root, f)


def passive_and_rwx(httpd, origin, base, gated_out):
    print("\n== SECTION 4: PASSIVE (0 probes) + RWX + EGRESS + REDACTION ==")
    n_before = LAB["requests"]
    cfg4 = _speed_cfg(allow_active=False)
    out2 = MC.run(cfg4, WC.Scope(os.path.join(base, "scope.json")), base)
    check("passive.delta-0", LAB["requests"] - n_before == 0,
          LAB["requests"] - n_before)
    man = _read(os.path.join(out2, "MANIFEST.json")) or {}
    check("passive.manifest-mode", (man.get("stats") or {}).get(
        "mode") == "passive", man.get("stats"))
    check("passive.probes-0", (man.get("stats") or {}).get(
        "probes", 0) == 0, man.get("stats", {}).get("probes"))
    cov = _read(os.path.join(out2, "misconfig_coverage.json")) or {}
    check("passive.coverage", cov.get("mode") == "passive")
    check("passive.manifest-artifacts", (man.get("stats") or {}).get(
        "artifacts", 0) >= 52)

    # RWX on gated run output
    bad = []
    for p in _walk_files(gated_out):
        try:
            mode = os.stat(p).st_mode & 0o777
            if mode != 0o777:
                bad.append((os.path.basename(p), oct(mode)))
        except OSError:
            pass
    check("rwx.all-777", not bad, bad[:6])

    # zero egress
    ev_path = os.path.join(gated_out, "evidence", "requests.jsonl")
    egress, n_rec = [], 0
    if os.path.exists(ev_path):
        for line in open(ev_path, encoding="utf-8", errors="ignore"):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n_rec += 1
            u = str(rec.get("url", ""))
            if "127.0.0.1" not in u:
                egress.append(u)
    check("egress.zero-external", not egress and n_rec > 50,
          (n_rec, egress[:3]))

    # redaction: fake secret/artifact VALUES artifacts me KABHI nahi
    leak = []
    for p in _walk_files(gated_out):
        if p.endswith((".json", ".md", ".txt")):
            txt = _read_txt(p)
            for secret in (STATIC_AKIA, STATIC_DBPASS, STATIC_JWT,
                           STATIC_MAPSRC, "Pa55w0rd"):
                if secret in txt:
                    leak.append((os.path.basename(p), secret[:6]))
    check("redaction.no-secret-values", not leak, leak[:4])


def checkpoint_replay(httpd, origin, base, out_first, findings_first):
    print("\n== SECTION 5: CHECKPOINT REPLAY (resume, 0 new requests) ==")
    n_before = LAB["requests"]
    cfg = _speed_cfg()
    out = MC.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    delta = LAB["requests"] - n_before
    check("replay.same-outdir", out == out_first, "%s vs %s" % (out,
                                                                out_first))
    check("replay.zero-new-requests", delta == 0, "new hits=%d" % delta)
    fj = _read(os.path.join(out, "findings.json")) or {}
    check("replay.findings-stable", fj.get("count") == findings_first,
          "%s vs %s" % (fj.get("count"), findings_first))
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("replay.manifest-valid", (man.get("stats") or {}).get(
        "matrix_rows", 0) >= 210)


# ===========================================================================
# SECTION 6 - CLI + IMPORT HYGIENE
# ===========================================================================
def cli_tests():
    print("\n== SECTION 6: CLI + IMPORT HYGIENE ==")
    p = subprocess.run([sys.executable, "mod_misconfig.py"], cwd=ULTRA,
                       capture_output=True, text=True, timeout=60)
    check("cli.exit-0", p.returncode == 0, p.returncode)
    check("cli.gates-listed", "misconfig_allow_debug_probe" in p.stdout and
          "Phase 23" in p.stdout, p.stdout[:120])
    p2 = subprocess.run([sys.executable, "-W", "error", "-c",
                         "import mod_misconfig"], cwd=ULTRA,
                        capture_output=True, text=True, timeout=60)
    check("cli.import-hygiene", p2.returncode == 0, p2.stderr[:200])
    p3 = subprocess.run([sys.executable, "-m", "py_compile", "-q",
                         os.path.join(ULTRA, "mod_misconfig.py")],
                        capture_output=True, text=True, timeout=60)
    check("cli.py-compile", p3.returncode == 0, p3.stderr[:200])


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    t0 = time.time()
    print("=" * 72)
    print("WASP P23 SELF-TEST - mod_misconfig.py v%s (ULTRA PRO MAX)" %
          MC.PLAN_VERSION)
    print("=" * 72)
    for d in (BASE, BASE_GATED, BASE2):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)

    with lab_server() as origin:
        # fixtures for all 3 bases
        _write_fixtures(BASE, origin, ENG)
        _write_fixtures(BASE_GATED, origin, ENG_G)
        _write_fixtures(BASE2, origin, ENG_P)

        unit_tests()
        out_first, _cfg, man = e2e_gate_off(None, origin, BASE)
        fj = _read(os.path.join(out_first, "findings.json")) or {}
        gated_out = e2e_gated(None, origin, BASE_GATED)
        passive_and_rwx(None, origin, BASE2, gated_out)
        checkpoint_replay(None, origin, BASE, out_first, fj.get("count"))
        cli_tests()

    dt = time.time() - t0
    print("\n" + "=" * 72)
    print("RESULT: %d PASS / %d FAIL  (%.1fs)" % (len(PASS), len(FAIL), dt))
    if FAIL:
        print("FAILURES:")
        for name, d in FAIL:
            print("  - %s: %s" % (name, str(d)[:120]))
        sys.exit(1)
    print("ALL GREEN - P23 v25.0.0 INERT discipline honored (GET-only, "
          "values REDACTED, no JNDI/IMDS/creds, zero egress, RWX 0777)")


if __name__ == "__main__":
    main()
