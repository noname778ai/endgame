#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 9 offline test harness - mock vulnerable AUTH server ke against
mod_auth.run() (v10 ULTRA PRO MAX) ko chalata hai aur verified assertions
check karta hai. (koi internet nahi chahiye - sirf 127.0.0.1)

Mock server me ye vulnerabilities deliberately hain:
  - user enumeration (JSON error-code + message oracle + timing)
  - NoSQL operator login bypass ($ne on 'admin')
  - JSON type confusion (null password -> different error shape)
  - open redirect (?next=), reflected marker, CRLF header injection
  - password reset: host-header reflect + X-Original-URL + token in response
  - MFA: 4-digit OTP, no rate limit
  - OAuth/OIDC: loose redirect_uri, implicit flow, no state, PKCE S256
  - CORS: origin reflection + credentials on /api/auth/session
  - pre-auth JWT: RS256 + kid + jku + duplicate 'role' claim + 48h lifetime
  - clickjacking (no XFO), cacheable login (no Cache-Control) + CDN header
  - SameSite=None without Secure, password autocomplete=on
  - WordPress users API + NextAuth providers + passkey (webauthn) marker
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block2_auth")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, shutil, socket, time, threading, tempfile, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "auth_test")
UPLOAD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOWNLOAD = "/home/z/my-project/download"
ULTRA_CORE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wasp_core.py")
sys.path.insert(0, WORK)

PORT = 8923
BASE = "http://127.0.0.1:%d" % PORT
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-56s %s" % ("[PASS]" if cond else "[FAIL]", name, detail))
    return bool(cond)


# ---------------------------------------------------------------------------
# helpers: raw JWT with duplicate claims (dict literal se nahi ban sakta)
# ---------------------------------------------------------------------------
def b64u(raw):
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


JWT_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "key1",
              "jku": BASE + "/api/auth/jwks-legacy.json"}
JWT_PAYLOAD_RAW = ('{"sub":"1001","role":"user","role":"admin",'
                   '"iat":1750000000,"exp":1750172800}')
JWT_TOKEN = "%s.%s.dGVzdHNpZw" % (b64u(json.dumps(JWT_HEADER)), b64u(JWT_PAYLOAD_RAW))

LOGIN_PAGE = """<html><head><title>Sign in</title></head><body>
<form action="/login" method="post">
<input name="username" autocomplete="on">
<input type="password" name="password" autocomplete="on">
<input type="hidden" name="next" value="">
<button type="submit">Login</button>
</form>
<button onclick="navigator.credentials.get()">Sign in with a passkey</button>
</body></html>"""

RESET_PAGE = """<html><body><form action="/reset" method="post">
<input name="email" type="email"><button>Send reset link</button></form></body></html>"""

MFA_PAGE = """<html><body><form action="/mfa" method="post">
<input name="code" maxlength="4" inputmode="numeric"><button>Verify</button></form></body></html>"""

OIDC_DOC = {
    "issuer": BASE,
    "authorization_endpoint": BASE + "/oauth/authorize",
    "token_endpoint": BASE + "/oauth/token",
    "jwks_uri": BASE + "/oauth/jwks.json",
    "response_types_supported": ["code", "id_token", "token id_token"],
    "code_challenge_methods_supported": ["plain", "S256"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


# ---------------------------------------------------------------------------
# MOCK VULNERABLE AUTH SERVER
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj=b"", ctype="application/json", extra=None):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
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

    def _html(self, code, html, extra=None):
        return self._send(code, html.encode(), "text/html; charset=utf-8", extra)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

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

    def do_POST(self):
        p = urlparse(self.path).path
        kind, body = self._body()
        if p == "/login":
            user = body.get("username") or body.get("email") or ""
            if isinstance(user, list):
                user = user[0]
            pw = body.get("password")
            # JSON vs form -> alag error shape (CT-confusion signal, realistic DRF)
            if kind == "json":
                # NoSQL operator bypass: sirf 'admin' par operator accept hota hai
                if isinstance(pw, dict) and ("$ne" in pw or "$gt" in pw):
                    if str(user).lower() == "admin":
                        return self._send(302, b"", ctype="text/plain",
                                          extra={"Location": "/dashboard"})
                    return self._send(401, {"detail": "invalid_operator"})
                # type confusion: null/0 password -> validation error shape
                if pw is None or isinstance(pw, (int, float)):
                    return self._send(401, {"detail": "validation_failed",
                                            "errors": {"password": ["must be string"]}})
                # plausible user? timing + message oracle JSON-side
                if str(user) in ("admin", "administrator", "root", "support", "info"):
                    time.sleep(0.12)
                    return self._send(401, {"detail": "incorrect password"})
                return self._send(401, {"detail": "invalid credentials"})
            # form-encoded path
            if isinstance(pw, list):
                pw = pw[0]
            if str(user) in ("admin", "administrator", "root", "support", "info"):
                time.sleep(0.12)
                return self._send(401, {"error": "incorrect password"})
            return self._send(401, {"error": "invalid credentials"})
        if p == "/reset":
            email = body.get("email") or ""
            if isinstance(email, list):
                email = email[0]
            tok = os.urandom(24).hex()
            html = ["<html><body>"]
            fxh = self.headers.get("X-Forwarded-Host")
            xou = self.headers.get("X-Original-URL")
            if fxh:
                html.append("<a href='https://%s/reset?token=%s'>reset</a>" % (fxh, tok))
            if xou:
                html.append("<div>via %s</div>" % xou)
            html.append("<p>If the account exists we sent instructions.</p>")
            html.append("<p>dev-mode link: /reset?token=%s</p>" % tok)
            html.append("</body></html>")
            return self._html(200, "".join(html))
        if p == "/mfa":
            return self._send(200, {"error": "invalid_code"})
        if p == "/api/auth/session":
            return self._send(405, {"error": "method_not_allowed"})
        return self._send(404, {"error": "not_found"})

    def do_GET(self):
        p = urlparse(self.path).path
        q = self._q()
        if p == "/login":
            nxt = q.get("next")
            if nxt is not None:
                if "\r\n" in unquote(nxt) or "X-Wasp-Probe" in nxt:
                    return self._send(302, b"", ctype="text/plain",
                                      extra={"Location": "/dashboard",
                                             "X-Wasp-Probe": "1"})
                if nxt.lower().startswith("http"):
                    return self._send(302, b"", ctype="text/plain",
                                      extra={"Location": nxt})
                return self._html(200, "<html><body><div>Invalid redirect: %s</div>"
                                  "<a href='/login'>back</a></body></html>" % nxt)
            err = q.get("error")
            if err is not None:
                return self._html(200, "<html><body><div class='msg'>Error: %s</div>"
                                  "%s</body></html>" % (err, LOGIN_PAGE))
            return self._html(200, LOGIN_PAGE, extra={
                "Server": "nginx", "X-Cache": "HIT",
                "Set-Cookie": "pref=light; Path=/"})
        if p == "/reset":
            return self._html(200, RESET_PAGE)
        if p == "/mfa":
            return self._html(200, MFA_PAGE)
        if p == "/dashboard":
            return self._html(200, "<html><body>dashboard</body></html>")
        if p == "/api/auth/session":
            origin = self.headers.get("Origin") or ""
            extra = {"Set-Cookie": "sess=abc123def; Path=/; SameSite=None"}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            return self._send(200, {"user": None, "token": JWT_TOKEN}, extra=extra)
        if p == "/api/auth/providers":
            return self._send(200, {"credentials": {"id": "credentials", "name": "Credentials",
                                                    "type": "credentials", "signinUrl": BASE + "/login"}})
        if p == "/api/auth/csrf":
            return self._send(200, {"csrfToken": "x" * 32})
        if p == "/wp-json/wp/v2/users":
            return self._send(200, [{"id": 1, "name": "admin", "slug": "admin"},
                                    {"id": 2, "name": "editor", "slug": "editor"}])
        if p in ("/.well-known/openid-configuration", "/oauth/.well-known/openid-configuration"):
            return self._send(200, OIDC_DOC)
        if p == "/oauth/authorize":
            ruri = q.get("redirect_uri")
            if not ruri:
                return self._send(400, {"error": "invalid_request"})
            return self._send(302, b"", ctype="text/plain", extra={"Location": ruri})
        if p in ("/oauth/jwks.json", "/jwks.json"):
            return self._send(200, {"keys": [{"kty": "RSA", "kid": "key1",
                                              "n": "x" * 64, "e": "AQAB"}]})
        if p == "/api/auth/jwks-legacy.json":
            return self._send(200, {"keys": [{"kty": "RSA", "kid": "key1"}]})
        if p == "/":
            return self._html(200, "<html><body><a href='/login'>login</a></body></html>")
        return self._send(404, {"error": "not_found"})


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    for _ in range(40):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
            return srv
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("mock server start nahi hua")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    os.makedirs(WORK, exist_ok=True)
    # LATEST ULTRA core use karo (read_only_post support wala)
    shutil.copy(ULTRA_CORE, os.path.join(WORK, "wasp_core.py"))
    shutil.copy(os.path.join(_WASP_ROOT, "phases", "block2_auth", "mod_auth.py"), os.path.join(WORK, "mod_auth.py"))
    for f in ("wasp_core", "mod_auth"):
        if f in sys.modules:
            del sys.modules[f]

    tmp = tempfile.mkdtemp(prefix="auth10_")
    scope_path = os.path.join(tmp, "scope.json")
    cfg_path = os.path.join(tmp, "config.json")
    out_base = os.path.join(tmp, "out")

    json.dump({"engagement": "auth10-test", "authorized": True,
               "authorization_reference": "SELFTEST (local mock)",
               "targets": [BASE], "domains": [], "wildcards": [],
               "excludes": [], "ips": ["127.0.0.1"],
               "notes": "offline selftest only"}, open(scope_path, "w"))
    json.dump({"rate_limit": 40.0, "jitter": 0.0, "concurrency": 4, "timeout": 6,
               "retries": 0, "max_requests": 6000, "verify_tls": False,
               "allow_active": True, "allow_destructive": False, "save_bodies": False,
               "adaptive_throttle": False, "negative_cache": False,
               # v10 auth knobs (config plumbing ka test bhi)
               "auth_surface_cap": 90, "auth_cors_endpoints": 40,
               "auth_redirect_endpoints": 2, "auth_inject_probes": 10,
               "auth_allow_injection_oracle": True, "auth_allow_cors_probe": True,
               "auth_allow_redirect_probe": True, "auth_allow_header_poison": True,
               "auth_allow_oauth_variants": True, "auth_allow_reflection_probe": True,
               "auth_allow_heuristic_enum": True, "auth_allow_reset_probe": True,
               "auth_allow_registration_probe": False},
              open(cfg_path, "w"))

    srv = start_server()
    print("  mock target: %s" % BASE)

    from wasp_core import Cfg, Scope
    import mod_auth

    cfg = Cfg(cfg_path)
    sc = Scope(scope_path)
    try:
        mod_auth.run(cfg, sc, out_base)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("module ran without exception", False, repr(e))
        return finish(srv, tmp)

    eng = os.path.join(out_base, "auth10-test", "auth")

    def load(rel):
        p = os.path.join(eng, rel)
        return json.load(open(p)) if os.path.exists(p) else None

    def text(rel):
        p = os.path.join(eng, rel)
        return open(p, errors="ignore").read() if os.path.exists(p) else ""

    F = (load("findings.json") or {}).get("findings") or []
    keys = {f["key"] for f in F}

    print("\n== findings (%d) ==" % len(F))
    for f in F:
        print("   %-4s %-34s %s" % (f["severity"], f["key"], (f["endpoint"] or "")[:58]))

    # --- core pipeline ---
    check("findings.json written", load("findings.json") is not None)
    check("AUTH_FINDINGS.md written (>200 chars)", len(text("AUTH_FINDINGS.md")) > 200)
    check("auth_test_plan.md has KILL TEST", "KILL TEST" in text("auth_test_plan.md"))
    check("auth_state_machine.md written", len(text("auth_state_machine.md")) > 100)
    check("MANIFEST.json written", load("MANIFEST.json") is not None)
    check("feedforward.json written", load("feedforward.json") is not None)

    # --- v9 stock paths ab bhi kaam kar rahe hain ---
    check("user enumeration detect hua (json+msg oracle)",
          "user_enumeration" in keys or "json_oracle_enumeration" in keys)
    check("no rate limit detect hua", "no_rate_limit" in keys)
    check("reset host-header injection detect hua",
          "reset_host_header_injection" in keys)
    check("mfa no-ratelimit detect hua", "mfa_no_ratelimit" in keys)
    check("oauth loose redirect_uri detect hua", "oauth_redirect_uri_loose" in keys)
    check("oauth implicit flow detect hua", "oauth_implicit_flow" in keys)
    check("oauth missing state detect hua", "oauth_missing_state" in keys)
    check("cookie flags missing detect hua", "cookie_flags_missing" in keys)
    check("cleartext transport detect hua (http target)", "cleartext_auth_transport" in keys)
    check("JWT sensitive claims plaintext me", "jwt_sensitive_claims" in keys)
    check("JWT kid/jku indicator", "jwt_kid_injection" in keys)

    # --- v10 ULTRA PRO MAX findings ---
    check("NoSQL operator bypass detect hua (CRITICAL)",
          "nosql_operator_accepted" in keys)
    check("reset token disclosure detect hua (CRITICAL)",
          "reset_token_disclosure" in keys)
    check("reset header poison extended (X-Original-URL)",
          "reset_header_poison_extended" in keys)
    check("JSON type confusion signal", "json_type_confusion_signal" in keys)
    check("CORS cred-reflection detect hua", "cors_cred_reflection" in keys)
    check("open redirect detect hua", "auth_open_redirect" in keys)
    check("reflected input detect hua", "auth_reflected_input" in keys)
    check("CRLF injection indicator", "crlf_injection_auth" in keys)
    check("clickjacking detect hua", "auth_clickjacking" in keys)
    check("auth response cacheable", "auth_response_cacheable" in keys)
    check("password autocomplete on", "password_autocomplete_on" in keys)
    check("JWT key-injection headers (jku)", "jwt_key_injection_headers" in keys)
    check("JWT duplicate claims", "jwt_duplicate_claims" in keys)
    check("JWT long-lived (48h)", "jwt_long_lived" in keys)
    check("JWT HS256 confusion candidate", "jwt_hs256_confusion_candidate" in keys)
    check("PKCE downgrade surface", "oauth_pkce_downgrade_surface" in keys)
    check("WordPress users exposed", "wordpress_users_exposed" in keys)
    check("NextAuth surface detect hua", "nextauth_surface" in keys)
    check("WebAuthn/passkey detect hua", "webauthn_detected" in keys)
    check("brute-force defense WEAK score", "brute_force_defense_weak" in keys)

    # --- v10 naye output files ---
    check("injection_oracle.json written", load("injection_oracle.json") is not None)
    check("auth_http_hardening.json written", load("auth_http_hardening.json") is not None)
    check("auth_cors.json written", load("auth_cors.json") is not None)
    check("auth_redirect_xss.json written", load("auth_redirect_xss.json") is not None)
    check("saml_surface.json written", load("saml_surface.json") is not None)
    check("preauth_jwt.json has deep block",
          isinstance((load("preauth_jwt.json") or {}).get("deep"), dict))

    # --- defense score content ---
    d = load("feedforward.json") or {}
    check("feedforward routes to_phase15_ssrf with cors/jwt-key",
          "to_phase15_ssrf" in json.dumps(d))
    check("AUTH_FINDINGS.md me defense score table",
          "Brute-force defense composite score" in text("AUTH_FINDINGS.md"))

    # --- resume / checkpoint ---
    print("\n== resume / checkpoint ==")
    n1 = len(F)
    cfg2 = Cfg(cfg_path)
    cfg2.resume = True
    mod_auth.run(cfg2, sc, out_base)
    F2 = (load("findings.json") or {}).get("findings") or []
    check("resume: findings stable (%d -> %d)" % (n1, len(F2)), len(F2) == n1,
          "lost=%s" % sorted({f["key"] for f in F} - {f["key"] for f in F2}))

    # --- passive-only mode (allow_active=False) ---
    print("\n== passive-only mode ==")
    tmp2 = tempfile.mkdtemp(prefix="auth10p_")
    cfg3 = Cfg(cfg_path)
    cfg3.allow_active = False
    cfg3.checkpoint = None
    cfg3.module_outdir = None
    try:
        mod_auth.run(cfg3, sc, tmp2)
        eng2 = os.path.join(tmp2, "auth10-test", "auth")
        F3 = (json.load(open(os.path.join(eng2, "findings.json"))) or {}).get("findings") or []
        k3 = {f["key"] for f in F3}
        check("passive mode: module ran, findings mile",
              os.path.exists(os.path.join(eng2, "findings.json")))
        check("passive mode: koi enum/login attempt nahi (no_rate_limit nahi)",
              "no_rate_limit" not in k3)
        check("passive mode: passive findings (clickjacking/webauthn) mile",
              bool({"auth_clickjacking", "webauthn_detected"} & k3))
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("passive mode ran without exception", False, repr(e))

    return finish(srv, tmp)


def finish(srv, tmp):
    srv.shutdown()
    print("\n== SUMMARY ==")
    passed = sum(1 for _, okk, _ in RESULTS if okk)
    failed = [n for n, okk, _ in RESULTS if not okk]
    print("  %d/%d checks passed" % (passed, len(RESULTS)))
    if failed:
        print("  FAILED: %s" % ", ".join(failed))
    print("  RESULT: %s" % ("AUTH PASS" if not failed else "AUTH FAIL"))
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
