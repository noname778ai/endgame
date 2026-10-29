#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P24 SELF-TEST SUITE - mod_cloud.py v30.0.0 FULL ULTRA PRO MAX (P24)
=============================================================================
 Mock cloud lab + full assertion suite:
   - Unit tests (canary/INERT guard/provider-markers/storage-shapes/
     takeover-DB/secret-shapes-34/signed-URL-parse/bypass2-20/verdict
     engine/posture composite-14/platform fp/secrets guard/matrix-242/
     chains-28/playbooks/renderers)
   - Active run e2e gate-OFF (stages A..Z) + 12 RoE-gate-skip documentation
   - Gated run (12 RoE gates ON): storage CONFIRMED + bucket-ACL shapes +
     takeover lead + container metrics + registry catalog + serverless
     lambda + cors reflect + dns resolve + provider errors + console +
     cicd artifacts + token/trust + spec + bypass2 accepted (sab hard
     caps ke andar, GET-only)
   - Artifact integrity (54 outputs, matrix >= 230 rows x 22 families,
     chains == 28) + verdict ladder
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (artifact/secret VALUES KABHI nahi - sirf sha1/shape)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
     (0 new requests, findings stable)
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi REAL exploitation/
 IMDS probe/bucket listing/takeover claim/credential stuffing NAHI -
 sab canary waspP24 family, GET-only module.
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

import mod_cloud as MC                                        # noqa: E402
import wasp_core as WC                                        # noqa: E402

save_json = WC.save_json

BASE = os.path.join(HERE, "p24_test_base")
BASE_GATED = os.path.join(HERE, "p24_test_base_gated")
BASE2 = os.path.join(HERE, "p24_test_base_passive")
ENG = "p24lab"
ENG_G = "p24lab2"
ENG_P = "p24labp"

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
    return open(os.path.join(ULTRA, "mod_cloud.py"), encoding="utf-8",
                errors="ignore").read()


# ===========================================================================
# MOCK CLOUD LAB (detection-only sim - sab responses INERT, GET-only)
# ===========================================================================
LAB = {"requests": 0}

# fake secret VALUES (lab-only; module artifacts me KABHI nahi aane chahiye)
STATIC_AKIA = "AKIAIOSFODNN7EXAMPLE"
STATIC_ACCOUNTKEY = "SGVsbG9XYXNwUDI0RkFLRVZBTFVF"
STATIC_SIG = "0123456789abcdef0123456789abcdef"
STATIC_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
              "eyJzdWIiOiJ3YXNwUDI0In0.kK7VcL0zF8SECRETpart9xQ")
STATIC_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"

HOME_HTML = """<html><head><title>waspP24 home</title></head><body>
<h1>waspP24 home</h1>
<p>Cloud lab home. Endpoints census-ready.</p>
</body></html>"""

LOGIN_HTML = """<html><head><title>waspP24 login</title></head><body>
<h1>Sign in</h1>
<form method="POST" action="/login"><input name="user"><input
 type="password" name="pass"></form>
<p>waspP24 login page - weak headers/cookies shape.</p>
</body></html>"""

STRONG_HTML = """<html><head><title>waspP24 strong</title></head><body>
<h1>Hardened page</h1>
<p>waspP24 hardened page - full header posture.</p>
</body></html>"""

S3_LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>waspP24-lab-bucket</Name><Prefix></Prefix><KeyCount>2</KeyCount>
<Contents><Key>a.txt</Key><Size>12</Size></Contents>
<Contents><Key>b.log</Key><Size>44</Size></Contents>
</ListBucketResult>"""

NOSUCHKEY_XML = """<?xml version="1.0"?><Error><Code>NoSuchKey</Code>
<Message>The specified key does not exist.</Message></Error>"""

NOSUCHBUCKET_XML = """<?xml version="1.0"?><Error><Code>NoSuchBucket</Code>
<Message>The specified bucket does not exist.</Message></Error>"""

ACCESSDENIED_XML = """<?xml version="1.0"?><Error><Code>AccessDenied</Code>
<Message>Access Denied</Message></Error>"""

TAKEOVER_HTML = """<html><head><title>waspP24 takeover page</title></head>
<body><p>CDN alias reference: waspP24-lab.azurewebsites.net</p>
<p>legacy host link also mentions herokuapp.com in docs</p>
</body></html>"""

SECRETS_HTML = """<html><head><title>waspP24 secrets page</title></head>
<body>
<p>aws key: %s</p>
<p>azure conn: AccountKey=%s</p>
<p>sas: sig=%s&amp;se=2099-01-01T00:00:00Z</p>
<p>sa private: %s</p>
<p>session: %s</p>
<p>db: postgres://admin:Pa55w0rd@db.internal:5432/prod</p>
</body></html>""" % (STATIC_AKIA, STATIC_ACCOUNTKEY, STATIC_SIG,
                     STATIC_PRIVATE_KEY, STATIC_JWT)

PRESIGNED_HTML = """<html><head><title>waspP24 signed</title></head><body>
<p>download: https://waspP24-lab.s3.us-east-1.amazonaws.com/obj.zip?
X-Amz-Date=20260101T000000Z&amp;X-Amz-Expires=2592000&amp;
X-Amz-Signature=%s&amp;X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20260101/us-east-1/s3/aws4_request</p>
</body></html>""" % STATIC_SIG

METRICS_TXT = ("# HELP go_gc_duration_seconds GC duration.\n"
               "# TYPE go_gc_duration_seconds summary\n"
               "go_gc_duration_seconds_sum 1.2\n")
REGISTRY_JSON = json.dumps({"repositories": ["app/api", "app/web"]})
HEALTHZ_JSON = json.dumps({"status": "ok", "kubernetes": "v1.28"})
ENV_TXT = "PATH=/usr/local/bin\nKUBERNETES_SERVICE_HOST=10.0.0.1\n"
PPROF_HTML = """<html><body>Types of profiles available:
<p><a href="?debug=1">allocs</a> goroutine profile</p></body></html>"""

SERVERLESS_HTML = """<html><body><p>AWS Lambda function
lambda-runtime: python3.11 - invoke via
https://abc123.execute-api.us-east-1.amazonaws.com/prod/</p>
</body></html>"""
FUNCTIONS_HTML = """<html><body>Azure Functions host
https://waspP24-func.azurewebsites.net/api/hello</body></html>"""

CONSOLE_HTML = """<html><head><title>Kubernetes Dashboard</title></head>
<body><h1>Kubernetes Dashboard</h1><p>waspP24 console.</p>
</body></html>"""

CICD_YAML = ("name: CI\non: push\njobs:\n  build:\n    runs-on: "
             "ubuntu-latest\n    env:\n      KEY: placeholder\n")
DOCKERFILE = "FROM node:14-alpine\nCMD [\"node\", \"app.js\"]\n"
KUBE_YAML = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
             "  name: waspP24-app\n")
TFSTATE = json.dumps({"version": 4, "terraform_version": "1.5.0",
                      "modules": [{"path": ["root"]}]})

TRACEBACK_CLOUD = """<html><head><title>500</title></head><body>
<pre>Request ID: 0a1b2c3d4e5f60718293a4b5</pre>
<Error><Code>InternalError</Code></Error>
<p>waspP24 verbose error page.</p></body></html>"""
GENERIC_ERR_HTML = """<html><head><title>Error</title></head>
<body><p>Something went wrong. Ref: waspP24-generic</p></body></html>"""

PROTECTED_403 = """<html><body>403 forbidden waspP24 protected</body></html>"""
PROTECTED_OK = """<html><body>welcome storage area waspP24</body></html>"""

TRUST_HTML_BASE = "trust page waspP24"

SPEC_JSON = json.dumps({
    "openapi": "3.0.0", "info": {"title": "waspP24 cloud API", "version": "1.0"},
    "paths": {"/api/storage/objects": {"get": {}},
              "/api/admin/export": {"post": {}},
              "/api/internal/debug": {"get": {}}}})

GQL_OPEN = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
GQL_LOCKED = json.dumps({"errors": [{"message": "introspection disabled"}]})
GQL_HOME = """<html><head><title>GraphiQL</title></head>
<body>GraphiQL playground waspP24</body></html>"""

TOKEN_PAGE = """<html><head><title>waspP24 share</title></head><body>
<p><a href="/download/f?token=waspP24sharetoken123">share</a>
<a href="/api/key?key=abcdefgh12345678">api</a></p>
</body></html>"""

CORS_ANY = """<html><body>cors open storage endpoint waspP24</body></html>"""
CORS_STRICT = """<html><body>cors strict storage endpoint waspP24</body></html>"""

SOFT404_HTML = """<html><head><title>waspP24 template</title></head><body>
<h1>Not found-ish template</h1>
<p>waspP24 generic template page content. Nothing here.</p>
</body></html>"""


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
        # ---- weak headers/cookies page ----
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
        # ---- provider pages (stage C) ----
        if p == "/aws":
            return self._send(200, "<html><body>waspP24 aws edge</body>"
                              "</html>", hdrs={
                                  "X-Amz-Request-Id": "0A1B2C3D4E5F6G7H",
                                  "X-Amz-Cf-Pop": "IAD54-P2",
                                  "Server": "awselb/2.0"})
        if p == "/azure":
            return self._send(200, "<html><body>azurewebsites host"
                              " waspP24</body></html>", hdrs={
                                  "X-Ms-Request-Id": "abc123-azure",
                                  "X-Powered-By": "ARR/3.0"})
        if p == "/gcp":
            return self._send(200, "<html><body>appengine waspP24"
                              "</body></html>", hdrs={
                                  "X-Goog-Request-Id": "gcp-123",
                                  "Via": "1.1 google"})
        if p == "/cdn":
            return self._send(200, "<html><body>edge waspP24</body></html>",
                              hdrs={"CF-Ray": "abcd-iad", "Age": "12",
                                    "X-Served-By": "cache-iad2147"})
        # ---- storage shapes (stage D/E) ----
        if p == "/s3/" or p == "/s3":
            return self._send(200, S3_LIST_XML, "application/xml", hdrs={
                "X-Amz-Bucket-Region": "us-east-1"})
        if p == "/storage/missing":
            return self._send(404, NOSUCHKEY_XML, "application/xml")
        if p == "/storage/nope":
            return self._send(404, NOSUCHBUCKET_XML, "application/xml")
        if p == "/storage/denied":
            return self._send(403, ACCESSDENIED_XML, "application/xml")
        # ---- takeover page (stage F) ----
        if p == "/takeover":
            return self._send(200, TAKEOVER_HTML)
        # ---- secrets page (stage H) ----
        if p == "/secrets_page":
            return self._send(200, SECRETS_HTML)
        # ---- signed URL (stage I) ----
        if p == "/signed":
            return self._send(200, PRESIGNED_HTML)
        # ---- container (stage J) ----
        if p == "/metrics":
            return self._send(200, METRICS_TXT, "text/plain")
        if p == "/v2/_catalog":
            return self._send(200, REGISTRY_JSON, "application/json")
        if p == "/healthz":
            return self._send(200, HEALTHZ_JSON, "application/json")
        if p == "/env":
            return self._send(200, ENV_TXT, "text/plain")
        if p == "/debug/pprof":
            return self._send(200, PPROF_HTML)
        # ---- serverless (stage K) ----
        if p == "/serverless":
            return self._send(200, SERVERLESS_HTML)
        if p == "/functions":
            return self._send(200, FUNCTIONS_HTML)
        # ---- console (stage Q) ----
        if p == "/console":
            return self._send(200, CONSOLE_HTML)
        # ---- CI/CD artifacts (stage R) ----
        if p == "/.github/workflows/" or p == "/.github/workflows/ci.yml":
            return self._send(200, CICD_YAML, "text/plain")
        if p == "/Dockerfile":
            return self._send(200, DOCKERFILE, "text/plain")
        if p == "/kube.yaml":
            return self._send(200, KUBE_YAML, "text/plain")
        if p == "/terraform.tfstate":
            return self._send(200, TFSTATE, "application/json")
        # ---- protected (bypass2 stage U) ----
        if p == "/protected":
            orig = self.headers.get("X-Original-URL", "")
            if orig == "/":
                return self._send(200, PROTECTED_OK)
            return self._send(403, PROTECTED_403)
        if p == "/s3protected":
            xf = self.headers.get("X-Forwarded-Host", "")
            if xf == "localhost":
                return self._send(200, PROTECTED_OK)
            return self._send(403, PROTECTED_403)
        # ---- cors (stage M targets) ----
        if p == "/storage_cors":
            o = self.headers.get("Origin", "")
            return self._send(200, CORS_ANY, hdrs={
                "Access-Control-Allow-Origin": o or "*",
                "Access-Control-Allow-Credentials": "true"})
        if p == "/storage_cors_strict":
            o = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            if o and host and o.endswith(host):
                return self._send(200, CORS_STRICT, hdrs={
                    "Access-Control-Allow-Origin": o})
            return self._send(200, CORS_STRICT)
        # ---- header trust (stage S target) ----
        if p == "/header_trust":
            xf = self.headers.get("X-Forwarded-Host", "")
            xourl = self.headers.get("X-Original-URL", "")
            body = TRUST_HTML_BASE
            if xf:
                body += " fwd-host:%s" % xf
            if xourl:
                body += " orig:%s" % xourl
            return self._send(200, "<html><body>%s</body></html>" % body)
        # ---- token page (stage S target) ----
        if p == "/token_page":
            return self._send(200, TOKEN_PAGE)
        # ---- api spec (stage T) ----
        if p == "/swagger.json":
            return self._send(200, SPEC_JSON, "application/json")
        # ---- graphql (stage T rollup aid) ----
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
        # ---- cloud errors (stage P) ----
        if p == "/errors":
            return self._send(500, TRACEBACK_CLOUD)
        if p == "/errors_clean":
            return self._send(500, GENERIC_ERR_HTML)
        # ---- cacheable page (stage L) ----
        if p == "/cacheable":
            return self._send(200, "<html><body>cache me waspP24</body>"
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
        self._send(200, "", hdrs={"Allow": "GET, HEAD, OPTIONS",
                                  "Access-Control-Allow-Methods":
                                  "GET, HEAD, OPTIONS"})


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
    """Engagement feedforward fixtures (P9..P23 handoff seeds) + scope.json."""
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

    wff("misconfig", {"to_phase24_cloud": {
        "cloud_header_shapes": ["aws", "s3-shape"],
        "bucket_surface": [origin + "/s3/", origin + "/storage_cors"]}})
    wff("auth", {"to_phase24_cloud": {"paths": [
        origin + "/login", origin + "/strong", origin + "/errors",
        origin + "/errors_clean", origin + "/takeover",
        origin + "/secrets_page", origin + "/signed",
        origin + "/aws", origin + "/azure", origin + "/gcp",
        origin + "/cdn", origin + "/serverless", origin + "/functions",
        origin + "/console", origin + "/token_page",
        origin + "/header_trust", origin + "/protected",
        origin + "/s3protected", origin + "/storage_cors",
        origin + "/storage_cors_strict", origin + "/storage/missing",
        origin + "/storage/nope", origin + "/storage/denied"]}})
    wff("ssrf", {"to_phase24_cloud": {"metadata_cloud": {
        "note": "P15 owns bounded IMDS smoke"}}})
    wff("replay", {"to_phase24_cloud": {"cacheable_token_routes": [
        origin + "/cacheable", origin + "/token_page"]}})
    wff("graphql", {"to_phase24_cloud": {"mutations": [
        "putBucketPolicy", "updateObjectAcl"]}})
    wff("ws", {"to_phase24_cloud": {"endpoints": ["/ws/events"]}})
    wff("js", {"to_phase24_cloud": {"secret_shapes": [origin + "/secrets_page"],
                                    "urls": [origin + "/signed"]}})
    save_json(os.path.join(base, "scope.json"), {
        "engagement": engagement,
        "authorized": True,
        "authorization_reference": "P24 lab RoE / selftest",
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
    check("unit.canary.family", c.startswith("waspP24") and len(c) > 10, c)
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

    # ---- provider markers ----
    hdr = ("X-Amz-Request-Id: x | X-Amz-Cf-Pop: IAD | Server: awselb/2.0")
    check("unit.provider.aws", set(MC.match_all_markers(
        MC.PROVIDER_MARKERS, hdr)) >= {"aws-core", "aws-cloudfront"},
        MC.match_all_markers(MC.PROVIDER_MARKERS, hdr))
    check("unit.provider.azure", "azure-core" in MC.match_all_markers(
        MC.PROVIDER_MARKERS, "x-ms-request-id: 1 | ARRCookie: y"))
    check("unit.provider.gcp", "gcp-core" in MC.match_all_markers(
        MC.PROVIDER_MARKERS, "x-goog-request-id: 1 | via: 1.1 google"))
    check("unit.provider.cf", "cloudflare" in MC.match_all_markers(
        MC.PROVIDER_MARKERS, "cf-ray: abcd-iad | cf-cache-status: HIT"))
    check("unit.provider.table", len(MC.PROVIDER_MARKERS) == 18,
          len(MC.PROVIDER_MARKERS))
    check("unit.cdn.table", len(MC.CDN_HDR_RX) == 6, len(MC.CDN_HDR_RX))
    check("unit.provider-none",
          MC.match_markers(MC.PROVIDER_MARKERS, "plain html") is None)

    # ---- storage shapes ----
    check("unit.storage.listbucket",
          MC.match_markers(MC.STORAGE_SHAPE_RX, S3_LIST_XML) ==
          "listbucket-xml")
    check("unit.storage.nosuchkey",
          MC.match_markers(MC.STORAGE_SHAPE_RX, NOSUCHKEY_XML) ==
          "nosuchkey-xml")
    check("unit.storage.nosuchbucket",
          MC.match_markers(MC.STORAGE_SHAPE_RX, NOSUCHBUCKET_XML) ==
          "nosuchbucket-xml")
    check("unit.storage.accessdenied",
          MC.match_markers(MC.STORAGE_SHAPE_RX, ACCESSDENIED_XML) ==
          "accessdenied-xml")
    check("unit.storage.table", len(MC.STORAGE_SHAPE_RX) == 11,
          len(MC.STORAGE_SHAPE_RX))
    check("unit.storage.paths", len(MC.STORAGE_PATHS) >= 36,
          len(MC.STORAGE_PATHS))

    # ---- takeover DB ----
    check("unit.takeover.rows", len(MC.TAKEOVER_FP_ROWS) == 12,
          len(MC.TAKEOVER_FP_ROWS))
    check("unit.takeover.services", any(
        r[1] == "azure-websites" and r[2] == "azurewebsites.net"
        for r in MC.TAKEOVER_FP_ROWS))
    check("unit.takeover.discipline", all(
        any(w in d.lower() for w in ("manual", "forbidden-auto", "roe",
                                     "review", "confirm"))
        for *_, d in MC.TAKEOVER_FP_ROWS))

    # ---- errors + console + iam tables ----
    check("unit.errors.table", len(MC.CLOUD_ERROR_RX) == 10,
          len(MC.CLOUD_ERROR_RX))
    check("unit.console.table", len(MC.CONSOLE_MARKERS) == 14,
          len(MC.CONSOLE_MARKERS))
    check("unit.console.k8s",
          MC.match_markers(MC.CONSOLE_MARKERS, CONSOLE_HTML) ==
          "k8s-dashboard")
    check("unit.iam.table", len(MC.IAM_SHAPE_RX) == 7, len(MC.IAM_SHAPE_RX))
    m = MC.IAM_SHAPE_RX[0][1].search("arn:aws:iam::123456789012:role/admin")
    check("unit.iam.arn-match", bool(m), m and m.group(0))

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
    check("unit.secrets.table", len(MC.CLOUD_SECRET_RX) == 34,
          len(MC.CLOUD_SECRET_RX))

    # ---- signed URL parse ----
    pu = ("https://b.s3.amazonaws.com/o?X-Amz-Date=20260101T000000Z&"
          "X-Amz-Expires=2592000&X-Amz-Signature=%s" % STATIC_SIG)
    parsed = MC.signed_url_parse(pu)
    pnames = {p["param"] for p in parsed}
    check("unit.signed.amz-expires", "amz-expires" in pnames, pnames)
    check("unit.signed.unbounded", any(
        p.get("ttl_bucket") == "unbounded" for p in parsed), parsed)
    check("unit.signed.sig", "amz-signature" in pnames)
    pu2 = ("https://b.s3.amazonaws.com/o?X-Amz-Expires=600&"
           "X-Amz-Signature=%s" % STATIC_SIG)
    parsed2 = MC.signed_url_parse(pu2)
    check("unit.signed.bounded", any(
        p.get("ttl_bucket") in ("<1h", "1-24h") for p in parsed2), parsed2)
    check("unit.signed.sha1", all(len(p["sha1_12"]) == 12 for p in parsed))

    # ---- bypass2 shapes ----
    shapes = MC._bypass2_shapes("http://x/s3protected", "waspP24cbtest")
    check("unit.bypass2.count", len(shapes) == 20, len(shapes))
    check("unit.bypass2.ids", [s[0] for s in shapes] ==
          ["CB-%02d" % i for i in range(1, 21)],
          [s[0] for s in shapes][:4])
    check("unit.bypass2.get-only", all(
        s[3].get("X-HTTP-Method-Override") is None for s in shapes))
    check("unit.bypass2.trust-shapes", any(
        "X-Original-URL" in s[3] for s in shapes) and any(
        "X-Forwarded-For" in s[3] for s in shapes))
    check("unit.bypass2.range-shape", any(
        s[3].get("Range") == "bytes=0-0" for s in shapes))

    # ---- matrix ----
    mx = MC.build_matrix()
    fams = set(m["family"] for m in mx)
    check("unit.matrix.rows", len(mx) >= 230, len(mx))
    check("unit.matrix.families", len(fams) == 22, sorted(fams))
    check("unit.matrix.cwe", all(m["cwe"].startswith("CWE-") for m in mx))
    check("unit.matrix.mitre", all(m["mitre"].startswith("T") for m in mx))
    check("unit.matrix.ids", mx[0]["id"] == "CLOUD-001" and
          mx[-1]["id"] == "CLOUD-%03d" % len(mx))

    # ---- chains ----
    ch = MC.build_chains({}, {"to_phase24_cloud": {}})
    check("unit.chains.count", len(ch) == 28, len(ch))
    check("unit.chains.ids", ch[0]["id"] == "CH01" and
          ch[-1]["id"] == "CH28")
    check("unit.chains.ff", all("ff_seeds" in c for c in ch))

    # ---- playbooks ----
    check("unit.imds.playbook", len(MC.IMDS_PLAYBOOK_ROWS) == 8)
    check("unit.imds.forbidden", all(
        any(w in d.lower() for w in (
            "kabhi", "forbidden", "manual", "roe", "census", "review",
            "remediation", "aid", "only", "wave"))
        for _, _, d in MC.IMDS_PLAYBOOK_ROWS))
    check("unit.creds.playbook", len(MC.CLOUD_CREDS_PLAYBOOK_ROWS) == 8)
    check("unit.container.playbook", len(MC.CONTAINER_PLAYBOOK_ROWS) == 6)
    check("unit.container.forbidden", any(
        "FORBIDDEN-AUTO" in d for _, _, d in MC.CONTAINER_PLAYBOOK_ROWS))
    check("unit.pools.sizes",
          len(MC.COLD_PATHS) >= 44 and len(MC.ARTIFACT_PATHS) == 24 and
          len(MC.CONTAINER_PATHS) == 16 and len(MC.SERVERLESS_PATHS) == 12
          and len(MC.SPEC_PATHS) == 12)

    # ---- verdict engine (synthetic) ----
    synth = {
        "provider": {"rows": [{"url": "http://x/aws",
                               "provider_shapes": ["aws-core",
                                                   "aws-cloudfront"],
                               "identified": True}]},
        "storage": {"rows": [{"url": "http://x/s3/", "live": True,
                              "shape": "listbucket-xml"}]},
        "bucket": {"rows": [{"url": "http://x/s3/",
                             "visibility_probe": "open",
                             "acl_shapes": ["listbucket-xml"]}]},
        "takeover": {"rows": [{"url": "http://x/takeover",
                               "service_refs": [{"service":
                                                 "azure-websites"}],
                               "lead": True}]},
        "secrets": {"rows": [{"url": "http://x/s",
                              "shapes": [{"shape": "aws-access-key"}]}]},
        "signedurl": {"rows": [{"url": "http://x/signed",
                                "unbounded_ttl": True,
                                "param_count": 3}]},
        "container": {"rows": [{"url": "http://x/metrics", "live": True,
                                "shape": "prometheus-metrics"}]},
        "serverless": {"rows": [{"url": "http://x/serverless", "live": True,
                                 "shape": "lambda-shape"}]},
        "cdn": {"rows": [{"url": "http://x/cacheable", "sensitive": True,
                          "cacheable": True}]},
        "cors": {"rows": [{"url": "http://x/storage_cors",
                           "reflect_attacker": True,
                           "grade": "REFLECT-ANY"}]},
        "iam": {"rows": [{"url": "http://x/i",
                          "iam_shapes": [{"shape": "aws-arn"}]}]},
        "dns": {"rows": [{"host": "x.invalid", "nxdomain": True,
                          "error": "nx"}]},
        "errors": {"rows": [{"url": "http://x/e", "verbose_hits": 2,
                             "shapes": ["aws-requestid"]}]},
        "console": {"rows": [{"url": "http://x/console", "live": True,
                              "platform": "k8s-dashboard"}]},
        "cicd": {"rows": [{"url": "http://x/.github/workflows/ci.yml",
                           "live": True, "shape": "workflow-yaml"}]},
        "tokens": {"rows": [{"url": "http://x/t", "echo_count": 1,
                             "echoes": [{"header": "X-Original-URL"}]}]},
        "spec": {"rows": [{"url": "http://x/sw", "spec_shape": True,
                           "op_names_count": 3,
                           "sensitive_ops": ["/api/admin"]}]},
        "bypass2": {"rows": [{"url": "http://x/protected",
                              "accepted_count": 1,
                              "accepted_ids": ["CB-11"]}]},
    }
    vd = {(r["stage"], r["verdict"]) for r in MC.verdict_engine(synth)}
    for stg in ("C", "D", "E", "H", "I", "J", "K", "M", "P", "Q", "R", "S",
                "T", "U"):
        check("unit.verdict.%s-confirmed" % stg, (stg, "CONFIRMED") in vd,
              sorted(vd)[:6])
    check("unit.verdict.f-suspected", ("F", "SUSPECTED") in vd)
    check("unit.verdict.n-suspected", ("N", "SUSPECTED") in vd)
    check("unit.verdict.o-suspected", ("O", "SUSPECTED") in vd)
    check("unit.verdict.l-suspected", ("L", "SUSPECTED") in vd)
    synth_hard = {
        "cors": {"rows": [{"url": "http://s/c", "strict": True,
                           "reflect_any": False}]},
        "errors": {"rows": [{"url": "http://s/e", "verbose_hits": 0}]},
        "dns": {"rows": [{"host": "s.example", "ips": ["1.2.3.4"]}]},
        "bypass2": {"rows": [{"url": "http://s/p", "accepted_count": 0,
                              "blocked_count": 0}]},
        "tokens": {"rows": [{"url": "http://s/t", "status": 200,
                             "echo_count": 0, "token_params": []}]},
        "spec": {"rows": [{"url": "http://s/sw", "status": 404,
                           "spec_shape": False}]},
        "cdn": {"rows": [{"url": "http://s/c", "sensitive": True,
                          "cacheable": False, "cache_safe": True}]},
    }
    vd2 = {(r["stage"], r["verdict"]) for r in MC.verdict_engine(synth_hard)}
    check("unit.verdict.m-hardened", ("M", "HARDENED") in vd2)
    check("unit.verdict.p-hardened", ("P", "HARDENED") in vd2)
    check("unit.verdict.o-hardened", ("O", "HARDENED") in vd2)
    check("unit.verdict.u-hardened", ("U", "HARDENED") in vd2)
    check("unit.verdict.s-hardened", ("S", "HARDENED") in vd2)
    check("unit.verdict.t-hardened", ("T", "HARDENED") in vd2)

    # ---- posture composite (14-point) ----
    post = MC.posture_composite(synth)
    check("unit.posture.points", len(post["points"]) == 14)
    check("unit.posture.rows", len(post["rows"]) >= 6, len(post["rows"]))
    check("unit.posture.weak", len(post["weak"]) >= 1 and
          post["weak"][0]["score"] < 5, post["weak"][:2])
    synth_strong = {
        "provider": {"rows": [{"url": "http://s/", "provider_shapes": [],
                               "identified": False}]},
        "storage": {"rows": [{"url": "http://s/", "status": 404,
                              "live": False, "shape": ""}]},
        "bucket": {"rows": [{"url": "http://s/", "visibility_probe":
                             "denied"}]},
        "takeover": {"rows": [{"url": "http://s/", "service_refs": [],
                               "lead": False}]},
        "secrets": {"rows": [{"url": "http://s/", "status": 200,
                              "shapes": []}]},
        "signedurl": {"rows": [{"url": "http://s/", "status": 200,
                                "unbounded_ttl": False,
                                "param_count": 0}]},
        "container": {"rows": [{"url": "http://s/", "status": 404,
                                "live": False, "shape": ""}]},
        "serverless": {"rows": [{"url": "http://s/", "status": 404,
                                 "live": False, "shape": ""}]},
        "cdn": {"rows": [{"url": "http://s/", "sensitive": False,
                          "cacheable": False, "cache_safe": True}]},
        "cors": {"rows": [{"url": "http://s/", "strict": True,
                           "reflect_any": False}]},
        "dns": {"rows": [{"host": "s.example", "ips": ["1.2.3.4"]}]},
        "errors": {"rows": [{"url": "http://s/", "verbose_hits": 0}]},
        "cicd": {"rows": [{"url": "http://s/", "status": 404,
                           "live": False}]},
        "bypass2": {"rows": [{"url": "http://s/", "accepted_count": 0}]},
    }
    post2 = MC.posture_composite(synth_strong)
    check("unit.posture.strong", len(post2["strong"]) >= 1 and
          post2["strong"][0]["score"] >= 9, post2["strong"][:1])

    # ---- platform fp + guard ----
    pf = MC.platform_fingerprint(["x-amz-request-id", "cf-ray",
                                  "kubernetes", "lambda-runtime"])
    check("unit.platform.shapes", len(pf["shapes"]) >= 3, pf["shapes"])
    guard = MC.secrets_guard([("findings.md",
                               "leak api_key=%s here" % STATIC_AKIA)])
    check("unit.guard.hit", len(guard["hits"]) == 1 and
          "REDACTED" in guard["hits"][0]["shape"], guard)
    check("unit.guard.clean", MC.secrets_guard([("f.md",
                                                 "nothing here")])[
        "hits"] == [])

    # ---- findings/severity ----
    F = MC.Findings()
    r1 = F.add("cloud_secret_shape", "t", "http://e", "d")
    check("unit.findings.sev", r1["severity"] == "critical" and
          r1["id"] == "CL-001", r1)
    r2 = F.add("cloud_token_param", "t", "e",
               "mail dev@examplecorp.com token=hunter2222")
    check("unit.findings.pii", "@***" in r2["detail"] or
          "hunter2222" not in r2["detail"], r2["detail"])
    check("unit.hints.count", len(MC.SEVERITY_HINTS) >= 48,
          len(MC.SEVERITY_HINTS))
    check("unit.hints.shape", all(len(v) == 3 for v in
                                  MC.SEVERITY_HINTS.values()))

    # ---- renderers ----
    mx = MC.build_matrix()
    tp = MC.render_test_plan(F, {g: False for g, _ in MC.ROE_GATES}, mx)
    check("unit.render.testplan", "KD-13" in tp and "FORBIDDEN-AUTO" in tp)
    check("unit.render.matrix-txt",
          "CLOUD_BYPASS2" in MC.render_matrix_txt(mx))
    md = MC.render_findings_md(
        type("S", (), {"engagement": "t"})(), F,
        [{"stage": "C", "url": "u", "verdict": "CONFIRMED",
          "signals": ["live"], "detail": "d"}],
        MC.build_chains({}, {}), {"mode": "active"})
    check("unit.render.findings-md", "CL-001" in md and "CH01" in md)
    ex = MC.render_exec_summary(type("S", (), {"engagement": "t",
                                               "ref": "r"})(), F,
                                post, MC.verdict_engine(synth),
                                {"mode": "active"})
    check("unit.render.exec", "CONFIRMED cloud exposures" in ex)
    rem = MC.render_remediation(F)
    check("unit.render.remediation", "CLOUD_STORAGE" in rem and
          "CLOUD_BYPASS2" in rem)
    ko = MC.render_kickoff(type("S", (), {"engagement": "t"})(),
                           {g: False for g, _ in MC.ROE_GATES}, MC.DEFAULTS)
    check("unit.render.kickoff", "GET-only module" in ko)
    pb = MC.render_playbooks()
    check("unit.render.playbooks", "IM-01" in pb and "CC-01" in pb and
          "KP-01" in pb and "TO-01" in pb)
    check("unit.render.chains-txt",
          "CH28" in MC.render_chains_txt(MC.build_chains({}, {})))
    hy = MC.build_hypotheses(synth, post)
    check("unit.render.hypotheses", len(hy) >= 3, len(hy))

    # ---- gates + source discipline ----
    check("unit.gates.count", len(MC.ROE_GATES) == 12, len(MC.ROE_GATES))
    check("unit.gates.default-off", all(
        not bool(v) for k, v in MC.DEFAULTS.items() if "allow" in k))
    src = _src()
    check("unit.src.no-post-probe",
          not re.search(r'probe\(\s*http\s*,\s*["\'](?:POST|PUT|DELETE|'
                        r'PATCH)["\']', src))
    check("unit.src.get-only-assert", "assert_inert_method" in src and
          "_ALLOWED_PROBE_METHODS" in src)
    check("unit.src.canary-family", src.count("waspP24") >= 6)
    check("unit.src.no-imds-url", "169.254.169.254" not in src)
    check("unit.src.no-listobjects", "ListObjects" not in src)
    check("unit.src.scope-guard", "host_of" in src and "CLOUD_PATH_RX"
          in src)

# ===========================================================================
# SECTION 2 - E2E GATE-OFF RUN (stages A..Z, 12 gates OFF)
# ===========================================================================
def e2e_gate_off(httpd, origin, base):
    print("\n== SECTION 2: E2E GATE-OFF RUN ==")
    cfg = _speed_cfg()
    out = MC.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    check("e2e.outdir", out and os.path.isdir(out), out)
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("e2e.manifest.phase", man.get("phase") == "phase24",
          man.get("phase"))
    check("e2e.manifest.artifacts", (man.get("stats") or {}).get(
        "artifacts", 0) >= 52, man.get("stats"))
    check("e2e.manifest.matrix", (man.get("stats") or {}).get(
        "matrix_rows", 0) >= 230)
    check("e2e.manifest.chains", (man.get("stats") or {}).get(
        "chains", 0) == 28)
    check("e2e.manifest.mode", (man.get("stats") or {}).get(
        "mode") == "active")
    cov = _read(os.path.join(out, "cloud_coverage.json")) or {}
    check("e2e.coverage.mode", cov.get("mode") == "active")
    check("e2e.coverage.sources", len(cov.get("sources", [])) >= 3,
          cov.get("sources"))
    check("e2e.coverage.gates-off", all(
        v is False for v in (cov.get("gates") or {}).values()))
    check("e2e.coverage.stages", len(cov.get("stages", [])) == 26)
    fj = _read(os.path.join(out, "findings.json")) or {}
    check("e2e.findings.count", fj.get("count", 0) >= 5, fj.get("count"))
    check("e2e.findings.ids", all(str(f.get("id", "")).startswith("CL-")
                                  for f in fj.get("findings", [])))
    keys = {f.get("key") for f in fj.get("findings", [])}
    check("e2e.findings.imds-documented",
          "cloud_imds_documented" in keys, keys)
    check("e2e.findings.creds-documented",
          "cloud_creds_documented" in keys, keys)
    check("e2e.findings.secret-shape", "cloud_secret_shape" in keys, keys)
    check("e2e.findings.signedurl", "cloud_signedurl_unbounded" in keys,
          keys)
    check("e2e.findings.provider", "cloud_provider_identified" in keys,
          keys)
    check("e2e.findings.posture-weak", "cloud_posture_weak" in keys, keys)
    vv = _read(os.path.join(out, "cloud_verdicts.json")) or {}
    rows = vv.get("rows", [])
    skips = [r for r in rows if r.get("verdict") == "SKIPPED"]
    check("e2e.verdict.skipped-documented", len(skips) >= 12, len(skips))
    conf_rows = [r for r in rows if r.get("verdict") == "CONFIRMED"]
    check("e2e.verdict.confirmed-only-passive-stages",
          all(r["stage"] in ("C", "H", "I") for r in conf_rows) and
          len(conf_rows) <= 6,
          [(r["stage"], r["url"]) for r in conf_rows])
    for art in ("cloud_targets.json", "cloud_provider.json",
                "cloud_storage.json", "cloud_bucket.json",
                "cloud_takeover.json", "cloud_imds.json",
                "cloud_secrets.json", "cloud_signedurl.json",
                "cloud_container.json", "cloud_serverless.json",
                "cloud_cdn.json", "cloud_cors.json", "cloud_dns.json",
                "cloud_iam.json", "cloud_errors.json", "cloud_console.json",
                "cloud_cicd.json", "cloud_apitoken.json", "cloud_spec.json",
                "cloud_gqlws.json", "cloud_bypass2.json",
                "cloud_posture.json", "cloud_platform.json",
                "cloud_secret_guard.json", "cloud_chains.json",
                "cloud_matrix.json", "CLOUD_FINDINGS.md",
                "CLOUD_TEST_PLAN.md", "CLOUD_REMEDIATION.md",
                "EXEC_SUMMARY.md", "CLOUD_KICKOFF.md",
                "CLOUD_PLAYBOOKS.md", "feedforward.json"):
        check("e2e.artifact.%s" % art,
              os.path.exists(os.path.join(out, art)))
    gqlws = _read(os.path.join(out, "cloud_gqlws.json")) or {}
    gql = (gqlws.get("gql_mutations") or {})
    check("e2e.gql.names", "putBucketPolicy" in (gql.get("mutations") or []),
          gql)
    ws = (gqlws.get("ws_endpoints") or {})
    check("e2e.ws.endpoints", ws.get("count", 0) >= 1, ws)
    ff = _read(os.path.join(out, "feedforward.json")) or {}
    rk = set((ff.get("routing") or {}).keys())
    check("e2e.feedforward.keys", {"to_phase25_controls", "to_phase15_ssrf",
                                   "to_phase11_access", "to_phase12_inject",
                                   "to_phase9_auth", "to_phase32_report"}
          <= rk, rk)
    gates_txt = _read_txt(os.path.join(out, "cloud_gates.txt"))
    check("e2e.gates-txt", "cloud_allow_bucket_probe = false" in gates_txt)
    pb = _read_txt(os.path.join(out, "CLOUD_PLAYBOOKS.md"))
    check("e2e.playbook.forbidden", "FORBIDDEN-AUTO" in pb)
    check("e2e.probes-bounded", (man.get("stats") or {}).get(
        "probes", 999) <= 450, man.get("stats", {}).get("probes"))
    stg_txt = _read_txt(os.path.join(out, "cloud_summary.txt"))
    check("e2e.summary-txt", "P24 CLOUD SUMMARY" in stg_txt)
    return out, cfg, man


# ===========================================================================
# SECTION 3 - GATED RUN (12 RoE gates ON - hard caps ke andar)
# ===========================================================================
def e2e_gated(httpd, origin, base):
    print("\n== SECTION 3: GATED RUN (12 gates ON) ==")
    gates = [g for g, _ in MC.ROE_GATES]
    cfg2 = _speed_cfg(gates=gates)
    out = MC.run(cfg2, WC.Scope(os.path.join(base, "scope.json")), base)
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("gated.manifest.gates-on", sorted(
        (man.get("stats") or {}).get("gates_on", [])) == sorted(gates),
        man.get("stats", {}).get("gates_on"))
    vv = _read(os.path.join(out, "cloud_verdicts.json")) or {}
    rows = vv.get("rows", [])
    conf = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "CONFIRMED"]
    hard = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "HARDENED"]
    susp = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "SUSPECTED"]
    check("gated.confirmed-present", len(conf) >= 12, conf[:8])
    check("gated.hardened-present", len(hard) >= 3, hard[:8])
    c_urls = {st: [u for s, u in conf if s == st] for st in
              set(s for s, _ in conf)}
    s_urls = {st: [u for s, u in susp if s == st] for st in
              set(s for s, _ in susp)}
    check("gated.provider-confirmed", len(c_urls.get("C", [])) >= 1,
          c_urls.get("C"))
    check("gated.storage-confirmed", any("/s3" in u
                                         for u in c_urls.get("D", [])),
          c_urls.get("D"))
    check("gated.bucket-confirmed", any("/s3" in u or "storage" in u
                                        for u in c_urls.get("E", [])),
          c_urls.get("E"))
    check("gated.takeover-suspected", any("takeover" in u
                                          for u in s_urls.get("F", [])),
          s_urls.get("F"))
    check("gated.container-confirmed", any("metrics" in u
                                           for u in c_urls.get("J", [])),
          c_urls.get("J"))
    check("gated.serverless-confirmed", any(
        "serverless" in u or "functions" in u
        for u in c_urls.get("K", [])),
          c_urls.get("K"))
    check("gated.cors-confirmed", any("storage_cors" in u
                                      for u in c_urls.get("M", [])),
          c_urls.get("M"))
    check("gated.errors-confirmed", any("errors" in u
                                        for u in c_urls.get("P", [])),
          c_urls.get("P"))
    check("gated.console-confirmed", any("console" in u
                                         for u in c_urls.get("Q", [])),
          c_urls.get("Q"))
    check("gated.cicd-confirmed", any(".github" in u or "Dockerfile" in u
                                      for u in c_urls.get("R", [])),
          c_urls.get("R"))
    check("gated.trust-confirmed", any("header_trust" in u
                                       for u in c_urls.get("S", [])),
          c_urls.get("S"))
    check("gated.spec-confirmed", any("swagger" in u
                                      for u in c_urls.get("T", [])),
          c_urls.get("T"))
    check("gated.bypass2-confirmed", any("protected" in u
                                         for u in c_urls.get("U", [])),
          c_urls.get("U"))
    check("gated.dns-rows", any(
        r.get("host") for r in (_read(os.path.join(out, "cloud_dns.json"))
                                or {}).get("rows", [])))
    fj = _read(os.path.join(out, "findings.json")) or {}
    keys = {f.get("key") for f in fj.get("findings", [])}
    for kx in ("cloud_provider_identified", "cloud_storage_shape",
               "cloud_bucket_acl_shape", "cloud_takeover_lead",
               "cloud_container_live", "cloud_serverless_live",
               "cloud_cors_reflect", "cloud_verbose_error",
               "cloud_console_live", "cloud_cicd_live",
               "cloud_trust_echo", "cloud_spec_live",
               "cloud_bypass2_accepted"):
        check("gated.finding.%s" % kx, kx in keys, sorted(keys)[:14])
    b2 = _read(os.path.join(out, "cloud_bypass2.json")) or {}
    check("gated.bypass2.rows", len(b2.get("rows", [])) >= 1)
    check("gated.bypass2.accepted", any(
        r.get("accepted_count", 0) >= 1 for r in b2.get("rows", [])),
        [r.get("accepted_count") for r in b2.get("rows", [])])
    check("gated.bypass2.shapes-20", all(
        len(r.get("shapes", [])) == 20 for r in b2.get("rows", [])))
    stg = _read(os.path.join(out, "cloud_storage.json")) or {}
    check("gated.storage.shapes", any(
        r.get("shape") for r in stg.get("rows", [])))
    bkt = _read(os.path.join(out, "cloud_bucket.json")) or {}
    check("gated.bucket.visibility", any(
        r.get("visibility_probe") for r in bkt.get("rows", [])))
    post = _read(os.path.join(out, "cloud_posture.json")) or {}
    check("gated.posture.rows", len(post.get("rows", [])) >= 3,
          len(post.get("rows", [])))
    check("gated.posture.points-14", len(post.get("points", [])) == 14)
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
    cov = _read(os.path.join(out2, "cloud_coverage.json")) or {}
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
            for secret in (STATIC_AKIA, STATIC_ACCOUNTKEY, STATIC_SIG,
                           STATIC_JWT, STATIC_PRIVATE_KEY, "Pa55w0rd"):
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
        "matrix_rows", 0) >= 230)


# ===========================================================================
# SECTION 6 - CLI + IMPORT HYGIENE
# ===========================================================================
def cli_tests():
    print("\n== SECTION 6: CLI + IMPORT HYGIENE ==")
    p = subprocess.run([sys.executable, "mod_cloud.py"], cwd=ULTRA,
                       capture_output=True, text=True, timeout=60)
    check("cli.exit-0", p.returncode == 0, p.returncode)
    check("cli.gates-listed", "cloud_allow_bucket_probe" in p.stdout and
          "Phase 24" in p.stdout, p.stdout[:120])
    p2 = subprocess.run([sys.executable, "-W", "error", "-c",
                         "import mod_cloud"], cwd=ULTRA,
                        capture_output=True, text=True, timeout=60)
    check("cli.import-hygiene", p2.returncode == 0, p2.stderr[:200])
    p3 = subprocess.run([sys.executable, "-m", "py_compile", "-q",
                         os.path.join(ULTRA, "mod_cloud.py")],
                        capture_output=True, text=True, timeout=60)
    check("cli.py-compile", p3.returncode == 0, p3.stderr[:200])


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    t0 = time.time()
    print("=" * 72)
    print("WASP P24 SELF-TEST - mod_cloud.py v%s (ULTRA PRO MAX)" %
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
    print("ALL GREEN - P24 v30.0.0 INERT discipline honored (GET-only, "
          "values REDACTED, no IMDS/bucket-enum/takeover-claim/creds, "
          "zero egress, RWX 0777)")


if __name__ == "__main__":
    main()
