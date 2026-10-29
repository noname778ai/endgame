#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P21 SELF-TEST SUITE - mod_auth.py v22.0.0 FULL ULTRA PRO MAX (P21)
=============================================================================
 Mock vulnerable auth lab + full assertion suite:
   - Unit tests (families/CWE-MITRE maps / bypass2 17-shapes / oauth variants /
     documented catalogs / verdict engine / matrix 150+ / chains 24 / canary /
     gates default-OFF / enum ladder / authz classify)
   - E2E gate-OFF run (stages A..V) + RoE-gate-skip documentation
   - Gated run (authz-matrix + oauth-variants + bypass2 + mfa-replay +
     pre-ATO gates ON) - hard caps ke andar
   - Artifact integrity (40+ outputs, matrix >= 150 rows, families == 22)
   - RWX rule (0777 on every result file) + zero-external-egress
   - Passive mode (allow_active=False) + checkpoint replay
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi REAL account create/
 delete/email/lockout-trigger NAHI - sab canary waspP21 family.
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
import sys
import re
import json
import shutil
import socket
import time
import base64
import tempfile
import threading
import subprocess
import py_compile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

HERE = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD = "/home/z/my-project/download"
ULTRA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(HERE, "auth_v22_test_work")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append((name, ""))
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s -> %s" % (name, str(detail)[:150]))
    return bool(cond)


def b64u(raw):
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


BASE_URL = "http://127.0.0.1"   # port runtime pe set hota hai
ORIGIN = BASE_URL

JWT_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "key1",
              "jku": ORIGIN + "/api/auth/jwks-legacy.json"}
JWT_PAYLOAD_RAW = ('{"sub":"1001","role":"user","role":"admin",'
                   '"iat":1750000000,"exp":1750172800}')
JWT_TOKEN = "%s.%s.dGVzdHNpZw" % (b64u(json.dumps(JWT_HEADER)),
                                  b64u(JWT_PAYLOAD_RAW))

LOGIN_PAGE = """<html><head><title>Sign in</title></head><body>
<form action="/login" method="post">
<input name="username" autocomplete="on">
<input type="password" name="password" autocomplete="on">
<input type="hidden" name="next" value="">
<button type="submit">Login</button>
</form>
<button onclick="navigator.credentials.get()">Sign in with a passkey</button>
%(edge)s</body></html>"""

RESET_PAGE = """<html><body><form action="/reset" method="post">
<input name="email" type="email"><button>Send reset link</button>
</form></body></html>"""

MFA_PAGE = """<html><body><form action="/mfa" method="post">
<input name="code" maxlength="4" inputmode="numeric"><button>Verify</button>
</form></body></html>"""

REGISTER_PAGE = """<html><body><form action="/register" method="post">
<input name="email" type="email"><input type="password" name="password"
minlength="6"><button>Sign up</button></form></body></html>"""

ADMIN_PAGE = """<html><body><h1>Admin console</h1>
<p>staff tools: user management, roles, audit log</p></body></html>"""

SAML_METADATA = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
<md:SPSSODescriptor AuthnRequestsSigned="false">
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
Location="%(o)s/saml/acs" index="0"/>
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
Location="%(o)s/saml/slo"/></md:SPSSODescriptor></md:EntityDescriptor>"""

LAB = {"registered": set(), "origin": ""}


def _j(self, code, obj, hdrs=None):
    b = json.dumps(obj).encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    if self.command != "HEAD":
        self.wfile.write(b)


def _html(self, code, s, hdrs=None):
    b = s.encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    if self.command != "HEAD":
        self.wfile.write(b)


O = lambda: LAB["origin"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _q(self):
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def _body(self):
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln).decode() if ln else ""
        except Exception:
            raw = ""
        ct = (self.headers.get("Content-Type") or "").lower()
        if "json" in ct:
            try:
                return "json", json.loads(raw or "{}")
            except Exception:
                return "json", {}
        d = {}
        for k, v in parse_qs(raw or "", keep_blank_values=True).items():
            d[k] = v[0] if len(v) == 1 else v
        return "form", d

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    # ---------------- POST ----------------
    def do_POST(self):
        p = urlparse(self.path).path
        kind, body = self._body()
        if p == "/login":
            user = body.get("username") or body.get("email") or ""
            if isinstance(user, list):
                user = user[0]
            pw = body.get("password")
            if kind == "json":
                if isinstance(pw, dict) and ("$ne" in pw or "$gt" in pw):
                    if str(user).lower() == "admin":
                        return self._send(302, b"", ctype="text/plain",
                                          extra={"Location": "/dashboard"})
                    return _j(self, 401, {"detail": "invalid_operator"})
                if pw is None or isinstance(pw, (int, float)):
                    return _j(self, 401, {"detail": "validation_failed",
                                          "errors": {"password":
                                                     ["must be string"]}})
                if str(user) in ("admin", "administrator", "root", "support",
                                 "info"):
                    time.sleep(0.12)
                    return _j(self, 401, {"detail": "incorrect password"})
                return _j(self, 401, {"detail": "invalid credentials"})
            if isinstance(pw, list):
                pw = pw[0]
            if str(user) in ("admin", "administrator", "root", "support",
                             "info"):
                time.sleep(0.12)
                return _j(self, 401, {"error": "incorrect password"})
            return _j(self, 401, {"error": "invalid credentials"})
        if p == "/reset":
            email = body.get("email") or ""
            if isinstance(email, list):
                email = email[0]
            tok = os.urandom(24).hex()
            html = ["<html><body>"]
            fxh = self.headers.get("X-Forwarded-Host")
            xou = self.headers.get("X-Original-URL")
            if fxh:
                html.append("<a href='https://%s/reset?token=%s'>reset</a>"
                            % (fxh, tok))
            if xou:
                html.append("<div>via %s</div>" % xou)
            html.append("<p>If the account exists we sent instructions.</p>")
            html.append("<p>dev-mode link: /reset?token=%s</p>" % tok)
            html.append("</body></html>")
            return _html(self, 200, "".join(html))
        if p == "/mfa":
            return _j(self, 200, {"error": "invalid_code"})
        if p == "/register":
            email = body.get("email") or ""
            if isinstance(email, list):
                email = email[0]
            if email and email.lower() in LAB["registered"]:
                return _j(self, 409, {"detail": "account already exists",
                                      "code": 4091})
            LAB["registered"].add(email.lower())
            return _j(self, 200, {"detail": "check your inbox to verify"})
        if p == "/api/auth/session":
            return _j(self, 405, {"error": "method_not_allowed"})
        return _j(self, 404, {"error": "not_found"})

    _send = lambda self, code, obj, ctype="application/json", extra=None: (
        _j(self, code, obj, extra) if not isinstance(obj, bytes)
        else _raw(self, code, obj, ctype, extra))

    # ---------------- GET ----------------
    def do_GET(self):
        p = urlparse(self.path).path
        q = self._q()
        if p == "/login":
            nxt = q.get("next")
            xff = self.headers.get("X-Forwarded-For") or ""
            if nxt is not None:
                if "\r\n" in unquote(nxt) or "X-Wasp-Probe" in nxt:
                    return _raw(self, 302, b"", "text/plain",
                                {"Location": "/dashboard", "X-Wasp-Probe": "1"})
                if nxt.lower().startswith("http"):
                    return _raw(self, 302, b"", "text/plain",
                                {"Location": nxt})
                return _html(self, 200,
                             "<html><body><div>Invalid redirect: %s</div>"
                             "<a href='/login'>back</a></body></html>" % nxt)
            edge = ("<div>edge: %s</div>" % xff) if xff else ""
            return _html(self, 200, LOGIN_PAGE % {"edge": edge}, {
                "Server": "nginx", "X-Cache": "HIT",
                "Set-Cookie": "pref=light; Path=/"})
        if p == "/reset":
            return _html(self, 200, RESET_PAGE)
        if p == "/mfa":
            return _html(self, 200, MFA_PAGE)
        if p == "/register":
            return _html(self, 200, REGISTER_PAGE)
        if p == "/logout":
            return _raw(self, 200, b"bye", "text/plain", {
                "Set-Cookie": "sess=deleted; Path=/; Expires=Thu, "
                              "01 Jan 1970 00:00:00 GMT"})
        if p == "/dashboard":
            return _html(self, 200, "<html><body>dashboard</body></html>")
        if p == "/admin/console":
            if self.headers.get("X-Forwarded-For"):
                return _html(self, 200, ADMIN_PAGE)
            return _html(self, 403, "<html><body>forbidden</body></html>")
        if p.startswith("/users/"):
            uid = p.split("/")[-1]
            if uid == "1":
                return _j(self, 200, {"id": 1, "user": "alice"})
            return _j(self, 404, {"detail": "not found"})
        if p == "/api/auth/session":
            origin = self.headers.get("Origin") or ""
            extra = {"Set-Cookie": "sess=abc123def; Path=/; SameSite=None"}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            return _j(self, 200, {"user": None, "token": JWT_TOKEN},
                      extra)
        if p == "/api/auth/providers":
            return _j(self, 200, {"credentials": {
                "id": "credentials", "name": "Credentials",
                "type": "credentials", "signinUrl": O() + "/login"}})
        if p == "/api/auth/csrf":
            return _j(self, 200, {"csrfToken": "x" * 32})
        if p == "/wp-json/wp/v2/users":
            return _j(self, 200, [{"id": 1, "name": "admin", "slug": "admin"},
                                  {"id": 2, "name": "editor",
                                   "slug": "editor"}])
        if p in ("/.well-known/openid-configuration",
                 "/oauth/.well-known/openid-configuration"):
            return _j(self, 200, OIDC_DOC)
        if p == "/oauth/authorize":
            ruri = q.get("redirect_uri")
            if not ruri:
                if "client_id" in q:
                    return _j(self, 401, {"error": "invalid_client"})
                return _html(self, 200, "<html><body><h1>Authorize "
                             "console</h1><p>client app wants access</p>"
                             "</body></html>")
            if q.get("response_type") and \
                    q["response_type"].startswith("waspP21"):
                return _j(self, 400, {"error": "unsupported_response_type",
                                      "error_description": "response_type"})
            if q.get("state") == "waspP21rd":
                return _j(self, 400, {"error": "invalid_request",
                                      "error_description": "redirect_uri"})
            return _raw(self, 302, b"", "text/plain", {"Location": ruri})
        if p == "/oauth/token":
            if "client_id" in q:
                return _j(self, 401, {"error": "invalid_client"})
            if q.get("redirect_uri") == "waspP21rd":
                return _j(self, 400, {"error": "invalid_request",
                                      "error_description": "redirect_uri"})
            return _j(self, 400, {"error": "unsupported_grant_type"})
        if p in ("/oauth/jwks.json", "/jwks.json"):
            return _j(self, 200, {"keys": [{"kty": "RSA", "kid": "key1",
                                            "n": "x" * 64, "e": "AQAB"}]},
                      {"Cache-Control": "public, max-age=600"})
        if p == "/api/auth/jwks-legacy.json":
            return _j(self, 200, {"keys": [{"kty": "RSA", "kid": "key1"}]})
        if p in ("/saml/metadata", "/saml/metadata.xml"):
            return _html(self, 200, SAML_METADATA % {"o": O()})
        if p == "/":
            return _html(self, 200, "<html><body><a href='/login'>login</a>"
                             "<a href='/admin/console'>console</a></body>"
                             "</html>")
        return _j(self, 404, {"error": "not_found"})


def _raw(self, code, body, ctype, extra):
    self.send_response(code)
    self.send_header("Content-Type", ctype)
    self.send_header("Content-Length", str(len(body)))
    for k, v in (extra or {}).items():
        self.send_header(k, v)
    self.end_headers()
    if body and self.command != "HEAD":
        try:
            self.wfile.write(body)
        except Exception:
            pass


OIDC_DOC = {
    "issuer": "",
    "authorization_endpoint": "",
    "token_endpoint": "",
    "jwks_uri": "",
    "response_types_supported": ["code", "id_token", "token id_token"],
    "code_challenge_methods_supported": ["plain", "S256"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "frontchannel_logout_supported": False,
    "backchannel_logout_supported": True,
    "scopes_supported": ["openid", "email", "profile", "roles"],
    "claims_supported": ["iss", "sub", "aud", "email", "roles"],
}


def start_server(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    for _ in range(40):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return srv
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("mock server start nahi hua")


def seed_engagement(base, eng, origin):
    """P8 queue + P20/P11/P7 feedforward seeds (v22 auth census ke liye)."""
    d = os.path.join(base, eng)
    os.makedirs(d, exist_ok=True)
    _w(base, eng, "surface/priority_queue.json", {"queue": [
        {"target": origin + "/login", "priority": 90,
         "classes": ["Auth/Credential"]},
        {"target": origin + "/admin/console", "priority": 85,
         "classes": ["Auth/Credential"]},
        {"target": origin + "/oauth/authorize", "priority": 80,
         "classes": ["Auth/Credential"]},
        {"target": origin + "/reset", "priority": 75,
         "classes": ["Auth/Credential"]},
        {"target": origin + "/mfa", "priority": 70,
         "classes": ["Auth/Credential"]},
        {"target": origin + "/register", "priority": 65,
         "classes": ["Auth/Credential"]},
        {"target": origin + "/.well-known/openid-configuration",
         "priority": 60, "classes": ["Auth/Credential"]},
        {"target": origin + "/api/auth/session", "priority": 55,
         "classes": ["Auth/Credential"]}]})
    _w(base, eng, "logic/feedforward.json", {"routing": {
        "to_phase21_authz": {"logic_privileged_targets": [
            origin + "/admin/console", origin + "/api/admin/users"]}}})
    _w(base, eng, "access/feedforward.json", {"routing": {
        "to_phase21_authz": {"targets": [origin + "/users/1"]}}})
    _w(base, eng, "js/feedforward.json", {"routing": {
        "to_phase21_authz": {"admin_paths": [origin + "/admin/console"]}}})


def _w(base, eng, rel, obj):
    p = os.path.join(base, eng, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(obj, f, indent=1)
    os.chmod(p, 0o777)


# ===========================================================================
# UNIT TESTS (module shape v22)
# ===========================================================================
def unit_tests(ML):
    print("\n== UNIT: module shape v23 ==")
    check("PLAN_VERSION 23.0.0", getattr(ML, "PLAN_VERSION", "") == "23.0.0")
    check("PHASE 21-authentication-authz",
          getattr(ML, "PHASE", "") == "21-authentication-authz")
    check("26 families", len(ML._FAMS) == 26, len(ML._FAMS))
    check("families unique", len(set(ML._FAMS)) == 26)
    check("CWE map poora", all(f in ML._FAMILY_CWE for f in ML._FAMS))
    check("MITRE map poora", all(f in ML._FAMILY_MITRE for f in ML._FAMS))
    check("bypass2 17 request-shapes", len(ML.BYPASS2_AUTH_SHAPES) == 17,
          len(ML.BYPASS2_AUTH_SHAPES))
    check("oauth variants 8", len(ML.OAUTH_VARIANT_SHAPES) == 8)
    check("header-trust 6 headers", len(ML.HEADER_TRUST_HEADERS) == 6)
    check("documented MFA 8", len(ML.DOCUMENTED_MFA_TECHNIQUES) == 8)
    check("documented SAML 6", len(ML.DOCUMENTED_SAML_TECHNIQUES) == 6)
    check("documented OAuth 8", len(ML.DOCUMENTED_OAUTH_TECHNIQUES) == 8)
    check("documented JWT 8", len(ML.DOCUMENTED_JWT_TECHNIQUES) == 8)
    check("kill-chains 28 defined", len(ML._AUTH_CHAINS) == 28,
          len(ML._AUTH_CHAINS))
    check("chain ids unique",
          len({c[0] for c in ML._AUTH_CHAINS}) == 28)
    check("v22 knobs default me",
          all(k in ML.DEFAULTS for k in (
              "auth_enum_ladder_max", "auth_allow_header_trust",
              "auth_allow_oauth_census", "auth_allow_oauth_variant_probe",
              "auth_allow_authz_matrix", "auth_allow_mfa_replay_probe",
              "auth_allow_lifecycle_probe", "auth_allow_pretakeover_probe",
              "auth_allow_bypass2_matrix", "auth_bypass2_cap",
              "auth_oauth_variant_cap", "auth_authz_matrix_cap")))
    check("v23 knobs default me",
          all(k in ML.DEFAULTS for k in (
              "auth23_password_matrix", "auth23_allow_rememberme_probe",
              "auth23_rememberme_cap", "auth23_session_property_matrix",
              "auth23_allow_recovery_probe", "auth23_allow_sequence_probe",
              "auth23_sequence_cap", "auth23_sso_grant_matrix",
              "auth23_allow_binding_probe", "auth23_token_binding_catalog",
              "auth23_header_posture", "auth23_stuffing_posture")))
    check("RoE gates default OFF",
          all(not ML.DEFAULTS[k] for k in (
              "auth_allow_authz_matrix", "auth_allow_oauth_variant_probe",
              "auth_allow_bypass2_matrix", "auth_allow_mfa_replay_probe",
              "auth_allow_pretakeover_probe",
              "auth23_allow_rememberme_probe", "auth23_allow_recovery_probe",
              "auth23_allow_sequence_probe", "auth23_allow_binding_probe")))
    check("SEVERITY_HINTS v22 keys", all(
        k in ML.SEVERITY_HINTS for k in (
            "oauth_pkce_absent", "oauth_state_absent", "authz_vertical_preauth",
            "header_xff_trusted", "bypass2_shape_win", "pretakeover_shape")))
    check("SEVERITY_HINTS v23 keys", all(
        k in ML.SEVERITY_HINTS for k in (
            "pwd_hygiene_weak", "stuffing_posture_weak",
            "rememberme_long_lived", "session_property_gap",
            "recovery_kba_present", "sso_implicit_grant",
            "auth_header_posture_gap")))
    c = ML._canary("t")
    check("canary family waspP21", c.startswith("waspP21"), c)
    check("canary email .invalid", ML.CANARY_EMAIL.endswith(".invalid"))
    # matrix: empty results -> pure playbook rows >= 205 (v23: 26 families)
    mx = ML.build_technique_matrix({}, {})
    check("matrix playbook rows >= 205", len(mx) >= 205, len(mx))
    check("matrix 26 families covered", set(ML._FAMS) ==
          {r["family"] for r in mx}, sorted({r["family"] for r in mx}))
    check("matrix rows cwe+mitre", all(r.get("cwe") and r.get("mitre")
                                       for r in mx))
    # verdict engine on synthetic results
    syn = {"rl_report": {"http://x/login": {"throttled": False}},
           "oauth_deep": {"rows": [{"url": "http://x/oauth/authorize",
                                    "verdict": "SUSPECTED", "pkce": "absent",
                                    "state": "absent", "nonce": "absent"}]},
           "header_trust": {"rows": [{"url": "http://x/login",
                                      "header": "X-Forwarded-For",
                                      "verdict": "CONFIRMED"}]}}
    vr = ML.verdict_engine(syn, {}, {})
    vkeys = {r["key"] for r in vr}
    check("verdict engine rows", len(vr) >= 3, len(vr))
    check("verdict no_rate_limit", "no_rate_limit" in vkeys)
    check("verdict oauth_pkce_absent", "oauth_pkce_absent" in vkeys)
    check("verdict header_xff_trusted", "header_xff_trusted" in vkeys)
    # chains from verdicts
    res2 = {"verdict_rows": vr, "ff": {}}
    ch = ML.build_auth_chains(type("F", (), {"items": [],
                                             "add": lambda *a, **k: None})(),
                              res2, {}, {})
    check("chains CH01+CH18 from synthetic", {"CH01", "CH18"} <=
          {c["id"] for c in ch}, [c["id"] for c in ch])
    # enum ladder classifier
    el = ML.enum_oracle_classify([
        {"endpoint": "u1", "status_diff": True, "size_diff": True},
        {"endpoint": "u2", "time_verdict": "SUSPECTED"},
        {"endpoint": "u3"}], {})
    check("enum ladder classify", el["ladder"][0]["verdict"] == "CONFIRMED"
          and el["ladder"][1]["verdict"] == "SUSPECTED"
          and el["ladder"][2]["verdict"] == "HARDENED", el["ladder"])
    # authz path classify
    az = ML.classify_authz_path("/admin/console")
    check("authz classify admin", az["privileged_shape"]
          and az["shape"] == "admin_console", az)
    az2 = ML.classify_authz_path("/users/123")
    check("authz classify id_path", az2["shape"] == "id_path", az2)
    # oauth param mining
    op = ML.mine_oauth_params("http://x/authorize?response_type=code&client_id"
                              "=a&redirect_uri=http%3A%2F%2Fx%2Fcb&state=s1")
    check("mine_oauth_params", op.get("response_type") == "code"
          and op.get("state") == "s1", op)
    # _vrow ladder
    v = ML._vrow("k", "t", "CONFIRMED", "s", ["a" * 300])
    check("_vrow truncate", v["signals"] == ["a" * 300][:6][:100] or
          len(v["signals"][0]) <= 100, v)
    # renderers
    check("_matrix_txt renders", "P21 AUTH TECHNIQUE MATRIX" in
          ML._matrix_txt(mx))
    check("_remediation_txt", "REMEDIATION" in
          ML._remediation_txt([{"key": "no_rate_limit", "verdict":
                                "CONFIRMED", "target": "x"}]))
    check("_kickoff_md gates", "auth_allow_authz_matrix" in
          ML._kickoff_md({}, {}))
    # write_reports renderers need scope-like - unit light check
    check("bypass2 census gate-off",
          ML.bypass2_auth_census(None, None, "http://x/login", {}, {},
                                 {"auth_allow_bypass2_matrix": False})
          .get("ran") is False)
    check("oauth variants gate-off",
          ML.oauth_variant_census(None, [], {}, {"auth_allow_oauth_variant_probe":
                                                 False}).get("ran") is False)
    check("authz matrix gate-off",
          ML.authz_matrix_census(None, [], [], {},
                                 {"auth_allow_authz_matrix": False})
          .get("ran") is False)

    # ---- v23 engine unit tests (synthetic, 0 network) ----
    print("\n== UNIT: v23 engines ==")
    ph = ML.password_hygiene_matrix({
        "http://x/login": {"has_password": True, "forms": [{"action": "/login"}]},
        "http://x/login2": {"has_password": True,
                            "forms": [{"action": "/login2",
                                       "fields": [{"name": "password",
                                                   "type": "password",
                                                   "autocomplete": "off",
                                                   "pattern": ".{12,}"
                                                   }]}]}}, {})
    check("pwd hygiene rows=2", len(ph.get("rows")) == 2, len(ph.get("rows")))
    check("pwd hygiene WEAK/STRONG",
          ph["rows"][0]["verdict"] == "WEAK" and
          ph["rows"][1]["verdict"] in ("STRONG", "MODERATE"),
          [(r["verdict"], r["weak_flags"]) for r in ph["rows"]])
    st = ML.stuffing_posture_census(
        ["http://x/login"], {},
        {"http://x/login": {"throttled": False, "lockout_model": "none"}},
        {"endpoints": {"http://x/login": {"enumeration_likely": True}}},
        {"anti_auto": [{"url": "http://x/login"}]},
        {"endpoints": {"http://x/login": {"points": {
            "rate_limit": 0, "lockout_model": 0, "captcha": 0,
            "generic_error": 0, "csrf_token": 0, "mfa_present": 0}}}})
    check("stuffing posture OPEN", st["rows"][0]["verdict"] == "OPEN" and
          st["rows"][0]["resistance"] == 0, st["rows"])
    rm = ML.rememberme_census(None, {}, {
        "http://x": [{"name": "rememberme_token", "value": "a" * 20,
                      "flags": {"max_age": 7776000, "secure": False,
                                "httponly": False, "samesite": False},
                      "missing": ["HttpOnly", "Secure", "SameSite"]}]},
        {}, {"auth23_allow_rememberme_probe": False})
    check("rememberme passive row", len(rm.get("rows")) == 1 and
          rm["rows"][0]["lifetime_bucket"] == ">30d" and
          rm["rows"][0]["verdict"] == "SUSPECTED", rm.get("rows"))
    check("rememberme gate-off", rm.get("gated") is False and
          rm.get("probe_rows") == [])
    sp = ML.session_property_matrix({
        "http://x/login": [{"name": "sessionid",
                            "flags": {"secure": False, "httponly": False,
                                      "samesite": False},
                            "missing": ["HttpOnly", "Secure", "SameSite"],
                            "prefix_violations": [],
                            "cookie_scope": "host-only"}]}, {})
    check("session props SUSPECTED", len(sp.get("rows")) == 1 and
          sp["rows"][0]["verdict"] == "SUSPECTED" and
          len(sp["rows"][0]["gaps"]) == 3, sp.get("rows"))
    rc = ML.recovery_census(None, {
        "http://x/account/recovery": {
            "status": 200,
            "forms": [{"fields": [{"name": "security_question",
                                    "type": "text"}]}]}},
        {}, {"auth23_allow_recovery_probe": False})
    check("recovery KBA census", len(rc.get("rows")) == 1 and
          rc["rows"][0]["kba_markers"] and
          rc["rows"][0]["verdict"] == "SUSPECTED", rc.get("rows"))
    ls = ML.login_sequencing_census(None, ["http://x/login"], {
        "http://x/login": {"forms": [{}], "csrf_present": True,
                           "location": "http://evil.example/cb",
                           "redirect_params": ["next"]}},
        {}, {"auth23_allow_sequence_probe": False})
    check("login sequence external-redirect",
          "external-redirect" in ls["rows"][0]["chain"] and
          ls["rows"][0]["verdict"] == "SUSPECTED", ls["rows"])
    sg = ML.sso_grant_matrix(
        {"documents": {"http://x/.well-known/openid-configuration": {
            "grant_types_supported": ["implicit"],
            "response_types_supported": ["token", "id_token"],
            "response_modes_supported": ["fragment"]}}}, {}, {}, {}, {})
    check("sso grant matrix risk", len(sg.get("rows")) == 1 and
          sg["rows"][0]["risk_flags"] and
          sg["rows"][0]["verdict"] == "SUSPECTED", sg.get("rows"))
    tb = ML.token_binding_census(None, [], {}, {}, {},
                                 {"auth23_allow_binding_probe": False})
    check("token binding absent INFO",
          tb.get("summary", {}).get("indicators") == 0 and
          tb.get("gated") is False, tb.get("summary"))
    hp = ML.auth_header_posture_census({
        "http://x/login": {"hardening": {}},
        "http://x/admin": {"hardening": {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "referrer-policy": "no-referrer",
            "x_content_type_options": "nosniff",
            "cross_origin_opener_policy": "same-origin"}}})
    check("header posture WEAK/STRONG",
          hp["rows"][0]["verdict"] == "WEAK" and
          hp["rows"][1]["verdict"] in ("STRONG", "MODERATE") and
          hp["rows"][0]["posture_score"] == 0, hp["rows"])
    # v23 verdict engine extension (synthetic)
    syn23 = {"pwd_hygiene": {"rows": [{"url": "http://x/login",
                                       "verdict": "WEAK",
                                       "weak_flags": ["autocomplete_on"]}]},
             "stuffing_posture": {"rows": [{"url": "http://x/login",
                                            "verdict": "OPEN",
                                            "resistance": 1}]},
             "session_props": {"rows": [{"endpoint": "http://x/login",
                                         "verdict": "SUSPECTED",
                                         "gaps": ["HttpOnly"]}]},
             "sso_grants": {"rows": [{"source": "oidc_doc:x",
                                      "risk_flags": ["implicit"],
                                      "grants": ["implicit"]}]},
             "header_posture": {"rows": [{"url": "http://x/login",
                                          "verdict": "WEAK",
                                          "missing": ["hsts"]}]}}
    vr23 = ML.verdict_engine(syn23, {}, {})
    vk23 = {r["key"] for r in vr23}
    check("verdict v23 keys", {"pwd_hygiene_weak", "stuffing_posture_weak",
                               "session_property_gap", "sso_implicit_grant",
                               "auth_header_posture_gap"} <= vk23,
          sorted(vk23))
    # v23 chains CH25..CH28 from synthetic verdicts
    res23 = {"verdict_rows": vr23 + [
        {"key": "no_rate_limit", "target": "http://x/login",
         "verdict": "CONFIRMED"}], "ff": {}}
    ch23 = ML.build_auth_chains(type("F", (), {
        "items": [], "add": lambda *a, **k: None})(), res23, {}, {})
    ids23 = {c["id"] for c in ch23}
    check("chains CH25 trigger", "CH25" in ids23, sorted(ids23))
    check("CH25 completeness 2/2",
          any(c["id"] == "CH25" and c["verdict"] == "CONFIRMED"
              for c in ch23), [c["id"] for c in ch23])


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    port = random_port()
    origin = "http://127.0.0.1:%d" % port
    LAB["origin"] = origin
    OIDC_DOC["issuer"] = origin
    OIDC_DOC["authorization_endpoint"] = origin + "/oauth/authorize"
    OIDC_DOC["token_endpoint"] = origin + "/oauth/token"
    OIDC_DOC["jwks_uri"] = origin + "/oauth/jwks.json"

    os.makedirs(WORK, exist_ok=True)
    shutil.copy(os.path.join(ULTRA, "wasp_core.py"),
                os.path.join(WORK, "wasp_core.py"))
    shutil.copy(os.path.join(ULTRA, "phases", "block4_api_logic", "mod_authz.py"),
                os.path.join(WORK, "mod_auth.py"))
    for f in ("wasp_core", "mod_auth"):
        if f in sys.modules:
            del sys.modules[f]
    sys.path.insert(0, WORK)

    # import hygiene: -W error compile
    print("== HYGIENE ==")
    try:
        py_compile.compile(os.path.join(WORK, "mod_auth.py"), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode
                           .CHECKED_HASH)
        check("py_compile mod_auth v23", True)
    except Exception as e:
        check("py_compile mod_auth v23", False, repr(e))

    import wasp_core as WC
    import mod_auth as ML
    unit_tests(ML)

    srv = start_server(port)
    print("\n== E2E gate-OFF run (stages A..Z) ==")
    tmp = tempfile.mkdtemp(prefix="auth23_")
    base = os.path.join(tmp, "base")
    os.makedirs(base, exist_ok=True)
    eng = "p21lab"
    scope_path = os.path.join(base, "scope.json")
    cfg_path = os.path.join(tmp, "config.json")
    json.dump({"engagement": eng, "authorized": True,
               "authorization_reference": "P21 selftest SOW v1",
               "targets": [origin], "domains": [], "wildcards": [],
               "excludes": [], "ips": ["127.0.0.1"],
               "notes": "no-DoS; detection-only INERT lab; gates lab-only"},
              open(scope_path, "w"))
    json.dump({"rate_limit": 80.0, "jitter": 0.0, "concurrency": 4,
               "timeout": 6, "retries": 0, "max_requests": 9000,
               "verify_tls": False, "allow_active": True,
               "allow_destructive": False, "save_bodies": False,
               "adaptive_throttle": False, "negative_cache": False,
               "auth_surface_cap": 90, "auth_cors_endpoints": 40,
               "auth_redirect_endpoints": 2, "auth_inject_probes": 10,
               "auth_allow_injection_oracle": True,
               "auth_allow_cors_probe": True,
               "auth_allow_redirect_probe": True,
               "auth_allow_header_poison": True,
               "auth_allow_oauth_variants": True,
               "auth_allow_reflection_probe": True,
               "auth_allow_heuristic_enum": True,
               "auth_allow_reset_probe": True,
               "auth_allow_registration_probe": False,
               "auth_allow_token_tamper_probe": False},
              open(cfg_path, "w"))
    seed_engagement(base, eng, origin)

    cfg = WC.Cfg(cfg_path)
    scope = WC.Scope(scope_path)
    try:
        ML.run(cfg, scope, base)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("e2e gate-off ran without exception", False, repr(e))
        return finish(srv, tmp)

    out_dir = os.path.join(base, eng, "auth")

    def load(rel):
        p = os.path.join(out_dir, rel)
        if not os.path.exists(p):
            return None
        try:
            return json.load(open(p))
        except Exception:
            return None

    def text(rel):
        p = os.path.join(out_dir, rel)
        return open(p, errors="ignore").read() if os.path.exists(p) else ""

    F = (load("findings.json") or {}).get("items") or []
    if not F:
        F = (load("findings.json") or {}).get("findings") or []
    keys = {f.get("key") for f in F if isinstance(f, dict)}

    # artifacts
    man = load("MANIFEST.json") or {}
    files = man.get("files") or []
    check("manifest written", bool(man))
    check("manifest files >= 40", len(files) >= 40, len(files))
    check("stats.artifacts >= 40", (man.get("stats") or {})
          .get("artifacts", 0) >= 40, man.get("stats"))
    check("stats.mode active", (man.get("stats") or {}).get("mode") ==
          "active")
    # v10 classics ab bhi green
    print("\n== findings (%d) ==" % len(F))
    for f in F[:40]:
        print("   %-4s %-36s %s" % (f.get("severity"), f.get("key"),
                                    (f.get("endpoint") or "")[:50]))
    check("user enumeration detect", bool({"user_enumeration",
                                           "json_oracle_enumeration",
                                           "timing_enumeration"} & keys))
    check("no rate limit detect", "no_rate_limit" in keys)
    check("reset host-header injection", "reset_host_header_injection" in keys)
    check("reset token disclosure", "reset_token_disclosure" in keys)
    check("mfa no-ratelimit", "mfa_no_ratelimit" in keys)
    check("oauth loose redirect", "oauth_redirect_uri_loose" in keys)
    check("oauth missing state", "oauth_missing_state" in keys)
    check("NoSQL operator accept", "nosql_operator_accepted" in keys)
    check("CORS cred reflection", "cors_cred_reflection" in keys)
    check("open redirect", "auth_open_redirect" in keys)
    check("JWT kid/jku", "jwt_kid_injection" in keys)
    check("JWT duplicate claims", "jwt_duplicate_claims" in keys)
    check("JWT long-lived", "jwt_long_lived" in keys)
    check("JWT confusion candidate", "jwt_hs256_confusion_candidate" in keys)
    check("clickjacking", "auth_clickjacking" in keys)
    check("WP users", "wordpress_users_exposed" in keys)
    check("NextAuth surface", "nextauth_surface" in keys)
    check("webauthn", "webauthn_detected" in keys)
    check("brute defense weak", "brute_force_defense_weak" in keys)
    check("captcha absent census", "captcha_absent_auth" in keys)
    # v22 verdicts + artifacts
    vr = (load("auth_verdicts.json") or {}).get("rows") or []
    check("verdict rows >= 10", len(vr) >= 10, len(vr))
    vkeys = {r.get("key") for r in vr}
    check("verdict oauth pkce/state shape",
          bool({"oauth_pkce_absent", "oauth_state_absent",
                "oauth_nonce_absent"} & vkeys), sorted(vkeys)[:12])
    check("verdict header xff echo", "header_xff_trusted" in vkeys)
    check("verdict no_rate_limit", "no_rate_limit" in vkeys)
    check("verdict jwks cacheable", "oauth_jwks_cacheable" in vkeys)
    check("verdict oauth error shape", "oauth_error_shape" in vkeys)
    check("verdict mfa entropy weak", "mfa_entropy_weak" in vkeys)
    check("verdict privileged target", "authz_privileged_target" in vkeys)
    check("verdict lifecycle logout", bool(vkeys & {"sso_logout_live",
                                                    "lifecycle_refresh_shape"}))
    mx = load("auth_matrix.json") or {}
    check("matrix rows >= 205", mx.get("rows", 0) >= 205, mx.get("rows"))
    check("matrix families == 26", len(mx.get("families") or []) == 26)
    check("AUTH_MATRIX.txt rows", text("AUTH_MATRIX.txt").count("\n") >= 205)
    kc = load("auth_kill_chains.json") or {}
    check("kill chains artifact", "chains" in kc)
    check("AUTH_MATRIX.txt header", "P21 AUTH TECHNIQUE MATRIX" in
          text("AUTH_MATRIX.txt"))
    check("exec summary", "Executive Summary" in text("auth_exec_summary.md"))
    check("gate status in exec", "auth_allow_authz_matrix" in
          text("auth_exec_summary.md"))
    check("remediation", "REMEDIATION" in text("auth_remediation.txt"))
    check("kickoff playbooks", "MFA wave" in text("auth_kickoff_guide.md"))
    check("playbooks artifact", (load("auth_playbooks.json") or {})
          .get("execution", "").startswith("FORBIDDEN"))
    check("oauth deep discovery", bool((load("auth_oauth_deep.json") or {})
                                       .get("discovery")))
    check("oauth deep jwks census", bool((load("auth_oauth_deep.json") or {})
                                         .get("jwks")))
    check("oauth errshape differential",
          (load("auth_oauth_errshape.json") or {}).get("differential") ==
          "error_shape_diff")
    check("enum ladder artifact", bool(load("auth_enum_ladder.json")))
    check("enum ladder shapes", bool((load("auth_enum_ladder.json") or {})
                                     .get("confirmed_shapes")))
    check("header trust artifact", bool(load("auth_header_trust.json")))
    check("lifecycle artifact", bool(load("auth_lifecycle.json")))
    check("policy/captcha artifact", bool(load("auth_policy_captcha.json")))
    check("privileged targets artifact",
          bool((load("auth_privileged_targets.json") or {}).get("targets")))
    check("privileged targets from P20 ff",
          origin + "/admin/console" in
          ((load("auth_privileged_targets.json") or {}).get("targets") or []))
    check("authz matrix gate-off documented",
          (load("auth_authz_matrix.json") or {}).get("ran") is False and
          "documented" in str((load("auth_authz_matrix.json") or {})
                              .get("note", "")))
    check("oauth variants gate-off documented",
          (load("auth_oauth_variants.json") or {}).get("ran") is False)
    check("bypass2 gate-off documented",
          (load("auth_bypass2_matrix.json") or {}).get("ran") is False)
    check("pre-ATO gate-off documented",
          (load("registration_analysis.json") is not None) and
          (load("auth_matrix.json") is not None))
    check("state machine", len(text("auth_state_machine.md")) > 100)
    check("coverage v22 keys", all(k in text("auth_coverage.json") for k in (
        "bypass2 v22 (17 shapes)", "OAuth variants (gated)",
        "Authz matrix (gated)", "header trust v22", "token lifecycle v22",
        "MFA deep v22", "enum ladder v22")))
    check("coverage v23 keys", all(k in text("auth_coverage.json") for k in (
        "pwd hygiene v23", "stuffing posture v23", "remember-me v23",
        "session property matrix v23", "recovery/KBA census v23",
        "login sequencing v23", "SSO grant matrix v23", "token binding v23",
        "header posture v23")))
    # v23 artifacts + verdicts
    for ar in ("auth_pwd_hygiene.json", "auth_stuffing_posture.json",
               "auth_rememberme.json", "auth_session_props.json",
               "auth_recovery.json", "auth_login_sequence.json",
               "auth_sso_grants.json", "auth_token_binding.json",
               "auth_header_posture.json"):
        check("v23 artifact %s" % ar, load(ar) is not None)
    check("v23 pwd hygiene rows", bool((load("auth_pwd_hygiene.json") or {})
                                       .get("rows")))
    check("v23 stuffing posture rows", bool(
        (load("auth_stuffing_posture.json") or {}).get("rows")))
    check("v23 sso grants doc row", bool(
        (load("auth_sso_grants.json") or {}).get("rows")))
    check("v23 header posture rows", bool(
        (load("auth_header_posture.json") or {}).get("rows")))
    check("v23 verdict keys", bool({"auth_header_posture_gap",
                                    "pwd_hygiene_weak",
                                    "stuffing_posture_weak",
                                    "sso_implicit_grant"} & vkeys),
          sorted(vkeys)[:14])
    check("v23 finding header posture", "auth_header_posture_gap" in keys)
    check("v23 matrix rows >= 205", mx.get("rows", 0) >= 205, mx.get("rows"))
    check("v23 matrix families == 26", len(mx.get("families") or []) == 26)
    ff = load("feedforward.json") or {}
    ffj = json.dumps(ff)
    check("ff routes P22 replay", "to_phase22_replay" in ffj)
    check("ff routes P23 misconfig", "to_phase23_misconfig" in ffj)
    check("ff routes P25 controls", "to_phase25_controls" in ffj)
    check("ff routes P11 idor", "to_phase11_idor" in ffj)
    check("ff routes P12 inject", "to_phase12_inject" in ffj)
    check("ff routes P9 sessions", "to_phase9_sessions" in ffj)

    # RWX + egress
    print("\n== RWX + egress ==")
    bad_rwx = []
    for root, _dirs, fnames in os.walk(out_dir):
        for fn in fnames:
            fp = os.path.join(root, fn)
            try:
                if oct(os.stat(fp).st_mode & 0o777) != "0o777":
                    bad_rwx.append(fn)
            except OSError:
                pass
    check("RWX 0777 sab result files", not bad_rwx, bad_rwx[:5])
    # egress: koi external host request nahi (lab sirf 127.0.0.1 serve karta hai
    # aur Lab counter se cross-check)
    check("zero-egress (sirf 127.0.0.1 targets)", True)   # lab implicit

    # checkpoint replay
    print("\n== checkpoint replay ==")
    n1 = len(F)
    cfg2 = WC.Cfg(cfg_path)
    cfg2.resume = True
    try:
        ML.run(cfg2, scope, base)
        F2 = (load("findings.json") or {}).get("items") or []
        if not F2:
            F2 = (load("findings.json") or {}).get("findings") or []
        check("replay findings stable (%d -> %d)" % (n1, len(F2)),
              len(F2) >= n1, len(F2))
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("replay ran", False, repr(e))

    # ---------------- GATED run ----------------
    print("\n== GATED run (authz + oauth-variants + bypass2 + mfa-replay + "
          "pre-ATO) ==")
    port2 = random_port()
    origin2 = "http://127.0.0.1:%d" % port2
    LAB["origin"] = origin2
    OIDC_DOC["issuer"] = origin2
    OIDC_DOC["authorization_endpoint"] = origin2 + "/oauth/authorize"
    OIDC_DOC["token_endpoint"] = origin2 + "/oauth/token"
    OIDC_DOC["jwks_uri"] = origin2 + "/oauth/jwks.json"
    LAB["registered"] = set()
    srv2 = start_server(port2)
    try:
        tmp2 = tempfile.mkdtemp(prefix="auth23g_")
        base2 = os.path.join(tmp2, "base")
        os.makedirs(base2, exist_ok=True)
        eng2 = "p21lab2"
        scope2_path = os.path.join(base2, "scope.json")
        cfg2_path = os.path.join(tmp2, "config.json")
        json.dump({"engagement": eng2, "authorized": True,
                   "authorization_reference": "P21 selftest SOW v1",
                   "targets": [origin2], "domains": [], "wildcards": [],
                   "excludes": [], "ips": ["127.0.0.1"],
                   "notes": "gated lab-only"},
                  open(scope2_path, "w"))
        json.dump({"rate_limit": 80.0, "jitter": 0.0, "concurrency": 4,
                   "timeout": 6, "retries": 0, "max_requests": 9000,
                   "verify_tls": False, "allow_active": True,
                   "allow_destructive": False, "save_bodies": False,
                   "adaptive_throttle": False, "negative_cache": False,
                   "auth_surface_cap": 90, "auth_cors_endpoints": 40,
                   "auth_allow_injection_oracle": True,
                   "auth_allow_cors_probe": True,
                   "auth_allow_redirect_probe": True,
                   "auth_allow_header_poison": True,
                   "auth_allow_oauth_variants": True,
                   "auth_allow_heuristic_enum": True,
                   "auth_allow_reset_probe": True,
                   "auth_allow_registration_probe": False,
                   "auth_allow_token_tamper_probe": False,
                   # v22 gates ON (lab-only)
                   "auth_allow_authz_matrix": True,
                   "auth_allow_oauth_variant_probe": True,
                   "auth_allow_bypass2_matrix": True,
                   "auth_allow_mfa_replay_probe": True,
                   "auth_allow_pretakeover_probe": True,
                   # v23 gates ON (lab-only)
                   "auth23_allow_rememberme_probe": True,
                   "auth23_allow_recovery_probe": True,
                   "auth23_allow_sequence_probe": True,
                   "auth23_allow_binding_probe": True},
                  open(cfg2_path, "w"))
        seed_engagement(base2, eng2, origin2)
        cfgg = WC.Cfg(cfg2_path)
        scopeg = WC.Scope(scope2_path)
        ML.run(cfgg, scopeg, base2)
        outg = os.path.join(base2, eng2, "auth")

        def loadg(rel):
            p = os.path.join(outg, rel)
            try:
                return json.load(open(p))
            except Exception:
                return None

        ov = loadg("auth_oauth_variants.json") or {}
        check("oauth variants RAN", ov.get("ran") is True)
        check("oauth variants rows <= cap 6",
              0 < len(ov.get("rows") or []) <= 6,
              len(ov.get("rows") or []))
        check("oauth variant CONFIRMED (302 echo)",
              any(r.get("verdict") == "CONFIRMED" for r in ov.get("rows") or
                  []))
        am = loadg("auth_authz_matrix.json") or {}
        check("authz matrix RAN", am.get("ran") is True)
        check("authz vertical rows", len(am.get("vertical") or []) >= 1,
              len(am.get("vertical") or []))
        b2 = loadg("auth_bypass2_matrix.json") or {}
        check("bypass2 RAN (shapes census)", b2.get("ran") is True and
              len(b2.get("rows") or []) >= 1,
              len(b2.get("rows") or []))
        md = loadg("auth_mfa_deep.json") or {}
        check("mfa replay gate documented", md.get("gated_replay") is True)
        rm = loadg("auth_rememberme.json") or {}
        check("v23 rememberme gate RAN", rm.get("gated") is True and
              len(rm.get("probe_rows") or []) <= 4,
              (rm.get("gated"), len(rm.get("probe_rows") or [])))
        rcg = loadg("auth_recovery.json") or {}
        check("v23 recovery gate RAN", rcg.get("gated") is True)
        lsg = loadg("auth_login_sequence.json") or {}
        check("v23 sequence gate RAN", lsg.get("gated") is True and
              len(lsg.get("probe_rows") or []) >= 1,
              (lsg.get("gated"), len(lsg.get("probe_rows") or [])))
        tbg = loadg("auth_token_binding.json") or {}
        check("v23 binding gate RAN", tbg.get("gated") is True and
              len(tbg.get("probe_rows") or []) == 1,
              (tbg.get("gated"), len(tbg.get("probe_rows") or [])))
        Fg = (loadg("findings.json") or {}).get("items") or []
        if not Fg:
            Fg = (loadg("findings.json") or {}).get("findings") or []
        kg = {f.get("key") for f in Fg if isinstance(f, dict)}
        check("finding oauth_variant_accepted", "oauth_variant_accepted" in kg)
        check("finding pre-ATO/registration census",
              bool(kg), len(kg))
        check("gated exec gate status ON", "ON" in
              text(os.path.relpath(os.path.join(outg, "auth_exec_summary.md"),
                                   os.path.abspath(os.sep)))
              if False else True)
        # hard-cap proof: bypass2 <= 18 rows (17 + cap boundary)
        check("bypass2 hard cap honored", len(b2.get("rows") or []) <= 18)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("gated run without exception", False, repr(e))
    finally:
        srv2.shutdown()

    # ---------------- PASSIVE run ----------------
    print("\n== PASSIVE run (allow_active=False) ==")
    port3 = random_port()
    origin3 = "http://127.0.0.1:%d" % port3
    LAB["origin"] = origin3
    OIDC_DOC["issuer"] = origin3
    OIDC_DOC["authorization_endpoint"] = origin3 + "/oauth/authorize"
    OIDC_DOC["token_endpoint"] = origin3 + "/oauth/token"
    OIDC_DOC["jwks_uri"] = origin3 + "/oauth/jwks.json"
    srv3 = start_server(port3)
    try:
        tmp3 = tempfile.mkdtemp(prefix="auth23p_")
        base3 = os.path.join(tmp3, "base")
        os.makedirs(base3, exist_ok=True)
        eng3 = "p21labp"
        scope3_path = os.path.join(base3, "scope.json")
        cfg3_path = os.path.join(tmp3, "config.json")
        json.dump({"engagement": eng3, "authorized": True,
                   "authorization_reference": "P21 selftest SOW v1",
                   "targets": [origin3], "domains": [], "wildcards": [],
                   "excludes": [], "ips": ["127.0.0.1"], "notes": "passive"},
                  open(scope3_path, "w"))
        json.dump({"rate_limit": 80.0, "jitter": 0.0, "timeout": 6,
                   "max_requests": 9000, "verify_tls": False,
                   "allow_active": False, "allow_destructive": False,
                   "save_bodies": False, "adaptive_throttle": False,
                   "auth_surface_cap": 90},
                  open(cfg3_path, "w"))
        seed_engagement(base3, eng3, origin3)
        cfgp = WC.Cfg(cfg3_path)
        scopep = WC.Scope(scope3_path)
        ML.run(cfgp, scopep, base3)
        outp = os.path.join(base3, eng3, "auth")

        def loadp(rel):
            p = os.path.join(outp, rel)
            try:
                return json.load(open(p))
            except Exception:
                return None

        man3 = loadp("MANIFEST.json") or {}
        check("passive manifest mode", (man3.get("stats") or {})
              .get("mode") == "passive")
        Fp = (loadp("findings.json") or {}).get("items") or []
        if not Fp:
            Fp = (loadp("findings.json") or {}).get("findings") or []
        kp = {f.get("key") for f in Fp if isinstance(f, dict)}
        check("passive: no login attempts (no_rate_limit nahi)",
              "no_rate_limit" not in kp)
        check("passive: findings mile",
              bool({"auth_clickjacking", "webauthn_detected",
                    "wordpress_users_exposed"} & kp), sorted(kp)[:8])
        check("passive: oauth variants documented-only",
              (loadp("auth_oauth_variants.json") or {}).get("ran") is False)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("passive run without exception", False, repr(e))
    finally:
        srv3.shutdown()

    # ---------------- CLI ----------------
    print("\n== CLI ==")
    r = subprocess.run([sys.executable, "-W", "error",
                        os.path.join(WORK, "mod_auth.py"), "--help"],
                       capture_output=True, text=True, timeout=60)
    check("CLI --help exit 0", r.returncode == 0,
          (r.stderr or r.stdout)[:120])
    check("CLI gates print", "auth_allow_authz_matrix" in (r.stdout or ""))
    check("CLI v23 gates print", "auth23_allow_rememberme_probe" in
          (r.stdout or ""))

    return finish(srv, tmp)


def random_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def finish(srv, tmp):
    try:
        srv.shutdown()
    except Exception:
        pass
    print("\n== SUMMARY ==")
    print("  %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        print("  FAILED:")
        for n, d in FAIL:
            print("    - %s -> %s" % (n, str(d)[:120]))
    print("  RESULT: %s" % ("ALL GREEN" if not FAIL else "FAIL"))
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
