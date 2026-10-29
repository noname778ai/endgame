#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 10 offline test harness - mock vulnerable SESSION server ke against
mod_sessions.run() (v10 ULTRA PRO MAX) ko chalata hai aur verified assertions
check karta hai. (koi internet nahi chahiye - sirf 127.0.0.1)

Mock server me ye vulnerabilities deliberately hain:
  - predictable low-entropy session ids (sess-00001 style counter)
  - session fixation (login par id rotate nahi hoti)
  - logout invalidation missing (cookie clear nahi hoti)
  - cookie flags missing (HttpOnly/SameSite nahi)
  - JWT: HS256 weak secret ('secret') + duplicate role claims raw token
  - JWT verifier deliberately vulnerable: alg=none accept + RS256->HS256
    confusion fallback (pubkey-as-HMAC-key) + jwk-header embedded key accept
  - JWKS: chhoti (512-bit) RSA key
  - client-side session cookies: itsdangerous-style signed + unsigned base64
    JSON privilege state (role/uid)
  - Web Cache Deception: /api/auth/session.css cacheable + HIT signal
  - duplicate cookie names accepted (tossing pre-condition)
  - refresh token rotation missing (old refresh token reuse hota hai)
  - concurrent session cap missing (2 logins dono valid)
  - clickjacking (token page par XFO/CSP nahi)
  - login form bina CSRF token
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block2_auth")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, shutil, base64, hmac, hashlib, threading, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "sess_test")
UPLOAD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOWNLOAD = "/home/z/my-project/download"
ULTRA_CORE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wasp_core.py")
sys.path.insert(0, WORK)

PORT = 8931
BASE = "http://127.0.0.1:%d" % PORT
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-56s %s" % ("[PASS]" if cond else "[FAIL]", name, detail))
    return bool(cond)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def b64u(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(seg):
    try:
        seg += "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg)
    except Exception:
        return b""


# hardcoded 512-bit RSA "modulus" (sirf mock - real key nahi chahiye)
N_BYTES = bytes([0xC7] * 64)
N_B64 = b64u(N_BYTES)
E_B64 = "AQAB"

JWT_HDR_RS = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
JWT_PAY_RS = '{"sub":"1001","role":"user","iat":1750000000,"exp":1893456000}'
RS_TOKEN = "%s.%s.%s" % (b64u(json.dumps(JWT_HDR_RS)), b64u(JWT_PAY_RS), b64u(b"fakesig"))

# HS256 weak-secret token with DUPLICATE role claims (raw string)
HS_SIGNING = "%s.%s" % (b64u('{"alg":"HS256","typ":"JWT"}'),
                        b64u('{"sub":"1001","role":"user","role":"admin",'
                             '"iat":1750000000,"exp":1893456000}'))
HS_TOKEN = "%s.%s" % (HS_SIGNING, b64u(hmac.new(b"secret", HS_SIGNING.encode(),
                                                hashlib.sha256).digest()))

# client-side session cookies
FLASK_LIKE = "%s.%s.%s" % (b64u('{"user_id":"1001","flask_sess":true}'),
                           b64u("1750000000"), b64u(b"a" * 16))
STATE_COOKIE = b64u('{"role":"user","uid":"1001","username":"victim"}')

CREDS = {"username": "victim", "password": "pass123"}

# ULTRA core se PEM builder (confusion verify dono side same hona chahiye)
sys.path.insert(0, WORK)


def _pem_pubkey():
    import mod_sessions
    return mod_sessions.rsa_pubkey_pem_from_jwks(N_B64, E_B64).encode()


PEM_CACHE = {"pem": None}


def verify_vulnerable_jwt(tok):
    """Mock JWT verifier - jaan-boojh kar 3 tarike se vulnerable:
    alg=none accept, RS256->HS256 confusion (pubkey HMAC fallback),
    jwk-header embedded key accept."""
    parts = (tok or "").split(".")
    if len(parts) < 2:
        return False
    try:
        hdr = json.loads(b64d(parts[0]).decode("utf-8", "ignore"))
    except Exception:
        return False
    if not isinstance(hdr, dict):
        return False
    alg = str(hdr.get("alg", ""))
    sig = b64d(parts[2]) if len(parts) > 2 else b""
    signing_input = ("%s.%s" % (parts[0], parts[1])).encode()
    if alg in ("none", "None", "NONE") and (len(parts) == 2 or sig == b""):
        return True                                   # vuln-1: alg=none
    if alg.startswith("HS"):
        keys = [b"secret"]
        if PEM_CACHE["pem"]:
            keys.append(PEM_CACHE["pem"])             # vuln-2: confusion fallback
        jwk = hdr.get("jwk")
        if isinstance(jwk, dict) and jwk.get("k"):
            keys.append(b64d(jwk["k"]))               # vuln-3: jwk header injection
        return any(hmac.new(k, signing_input, hashlib.sha256).digest() == sig
                   for k in keys)
    if alg.startswith("RS"):
        return True                                   # mock: RS256 trusted
    return False


# ---------------------------------------------------------------------------
# MOCK VULNERABLE SESSION SERVER
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

    def _cookies(self):
        out = {}
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                out.setdefault(k.strip(), v.strip())   # FIRST occurrence wins
        return out

    def _session_body(self):
        return {"user": "victim", "uid": 1001, "jwt": RS_TOKEN,
                "legacy_jwt": HS_TOKEN, "refresh_token": "rt-opaque-9988"}

    def _serve_session(self, cache=False):
        sid = "sess-%05d" % STATE["counter"]
        STATE["counter"] += 1
        STATE["valid"][sid] = "victim"
        body = json.dumps(self._session_body()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # teen cookies: sessionid (server-side), app_session (itsdangerous),
        # user_state (unsigned base64 JSON privilege state)
        for ck in ("sessionid=%s; Path=/" % sid,
                   "app_session=%s; Path=/" % FLASK_LIKE,
                   "user_state=%s; Path=/" % STATE_COOKIE):
            self.send_header("Set-Cookie", ck)
        if cache:
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("X-Cache", "HIT")
        # token page par koi XFO/CSP nahi (clickjacking)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        path = self.path.split("?")[0]
        cookies = self._cookies()
        sid = cookies.get("sessionid")
        authed = bool(sid and STATE["valid"].get(sid))
        bearer = (self.headers.get("Authorization") or "")
        bearer_tok = bearer[7:] if bearer.startswith("Bearer ") else ""
        bearer_ok = bool(bearer_tok and verify_vulnerable_jwt(bearer_tok))

        # cache deception variants (path suffix strip)
        if path.endswith(".css") or path.endswith("/wasp-cache.css"):
            base_path = path[:-4] if path.endswith(".css") else \
                path[: -len("/wasp-cache.css")]
            if base_path == "/api/auth/session":
                self._serve_session(cache=True)
                return
            self._send(404, {"error": "not found"})
            return
        if path in ("/api/auth/session", "/api/auth/session/"):
            self._serve_session()
            return
        if path == "/api/me":
            if authed or bearer_ok:
                self._send(200, {"user": "victim", "secret_docs": True,
                                 "notes": "private data yahan hai"})
            else:
                self._send(401, {"error": "unauthorized"},
                           extra={"WWW-Authenticate": "Bearer"})
            return
        if path == "/logout":
            # vuln: cookie clear NAHI hoti, invalidation NAHI hoti
            self._send(200, {"message": "logged out"})
            return
        if path == "/jwks.json" or path == "/oauth/jwks" or \
                path == "/.well-known/jwks.json":
            self._send(200, {"keys": [{"kty": "RSA", "kid": "k1",
                                       "n": N_B64, "e": E_B64}]})
            return
        if path == "/login":
            html = ("<html><body><form action='/api/auth/session' method='post'>"
                    "<input name='username'><input type='password' name='password'>"
                    "<button>Login</button></form></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            try:
                self.wfile.write(html)
            except Exception:
                pass
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        cookies = self._cookies()
        sid = cookies.get("sessionid")
        data = {}
        try:
            if "json" in ctype:
                data = json.loads(raw.decode("utf-8", "ignore") or "{}")
            else:
                from urllib.parse import parse_qs
                data = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "ignore")).items()}
        except Exception:
            data = {}

        if path == "/api/auth/session":
            # vuln fixation: sid rotate NAHI hoti (already-valid sid reuse)
            if data.get("username") == CREDS["username"] and \
                    data.get("password") == CREDS["password"]:
                if not sid:
                    sid = "sess-%05d" % STATE["counter"]
                    STATE["counter"] += 1
                STATE["valid"][sid] = "victim"
                body = json.dumps({"ok": True}).encode()
                self.send_response(302)
                self.send_header("Location", "/api/me")
                self.send_header("Set-Cookie", "sessionid=%s; Path=/" % sid)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass
            else:
                self._send(401, {"error": "invalid credentials",
                                 "message": "bad login"})
            return
        if path == "/api/auth/refresh":
            # vuln: OLD refresh token hamesha accept (rotation missing)
            rt = data.get("refresh_token") or ""
            if rt:
                STATE["counter"] += 1
                self._send(200, {"access_token": "at-%05d" % STATE["counter"],
                                 "refresh_token": "rt-opaque-%05d" % STATE["counter"]})
            else:
                self._send(400, {"error": "refresh_token required"})
            return
        self._send(404, {"error": "not found"})


STATE = {"counter": 1, "valid": {}}


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def finish(srv, tmp):
    try:
        srv.shutdown()
    except Exception:
        pass
    fails = [r for r in RESULTS if not r[1]]
    print("\n  ===== SESSIONS SELFTEST: %d/%d PASS =====" % (
        len(RESULTS) - len(fails), len(RESULTS)))
    if fails:
        print("  FAILED:")
        for name, _ok, det in fails:
            print("    - %s %s" % (name, det))
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if fails else 0)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    os.makedirs(WORK, exist_ok=True)
    shutil.copy(ULTRA_CORE, os.path.join(WORK, "wasp_core.py"))
    shutil.copy(os.path.join(_WASP_ROOT, "phases", "block2_auth", "mod_sessions.py"), os.path.join(WORK, "mod_sessions.py"))
    shutil.copy(os.path.join(_WASP_ROOT, "phases", "block2_auth", "mod_auth.py"), os.path.join(WORK, "mod_auth.py"))
    for f in ("wasp_core", "mod_sessions", "mod_auth"):
        if f in sys.modules:
            del sys.modules[f]

    tmp = tempfile.mkdtemp(prefix="sess10_")
    scope_path = os.path.join(tmp, "scope.json")
    cfg_path = os.path.join(tmp, "config.json")
    out_base = os.path.join(tmp, "out")

    json.dump({"engagement": "sess10-test", "authorized": True,
               "authorization_reference": "SELFTEST (local mock)",
               "targets": [BASE], "domains": [], "wildcards": [],
               "excludes": [], "ips": ["127.0.0.1"],
               "notes": "offline selftest only"}, open(scope_path, "w"))
    json.dump({"rate_limit": 40.0, "jitter": 0.0, "concurrency": 4, "timeout": 6,
               "retries": 0, "max_requests": 6000, "verify_tls": False,
               "allow_active": True, "allow_destructive": False, "save_bodies": False,
               "adaptive_throttle": False, "negative_cache": False,
               # v10 sessions knobs (config plumbing ka test bhi)
               "session_identities": 3, "session_token_samples": 6,
               "session_capture_endpoints": 8, "session_jwt_tamper_max": 3,
               "session_weak_secret_crack": True, "session_weak_secret_max": 40,
               "session_test_credentials": [CREDS],
               "session_allow_cache_probe": True, "session_cache_probe_max": 3,
               "session_allow_conflict_probe": True, "session_conflict_probes": 2,
               "session_allow_refresh_test": True, "session_refresh_max": 3,
               "session_allow_concurrent_test": True, "session_concurrent_logins": 2,
               "session_allow_jwt_matrix": True, "session_jwt_matrix_max": 3,
               "session_client_storage_decode": True},
              open(cfg_path, "w"))

    # P9 feedforward seed (deterministic discovery)
    eng_dir = os.path.join(out_base, "sess10-test", "auth")
    os.makedirs(eng_dir, exist_ok=True)
    json.dump({"routing": {"to_phase10_sessions_jwt": {"endpoints": [
        BASE + "/api/auth/session", BASE + "/api/me", BASE + "/api/auth/refresh",
        BASE + "/logout", BASE + "/login"]}}},
        open(os.path.join(eng_dir, "feedforward.json"), "w"))

    srv = start_server()
    print("  mock target: %s" % BASE)

    from wasp_core import Cfg, Scope
    import mod_sessions
    PEM_CACHE["pem"] = _pem_pubkey()

    cfg = Cfg(cfg_path)
    sc = Scope(scope_path)
    try:
        mod_sessions.run(cfg, sc, out_base)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("module ran without exception", False, repr(e))
        return finish(srv, tmp)

    eng = os.path.join(out_base, "sess10-test", "sessions")

    def load(rel):
        p = os.path.join(eng, rel)
        return json.load(open(p)) if os.path.exists(p) else None

    def text(rel):
        p = os.path.join(eng, rel)
        return open(p, errors="ignore").read() if os.path.exists(p) else ""

    F = (load("findings.json") or {}).get("findings") or []
    keys = {f["key"] for f in F}

    def has(key):
        return key in keys

    print("\n== FRESH RUN assertions ==")
    check("findings generated", len(F) >= 15, "count=%d" % len(F))
    check("cookie flags missing pakda", has("session_cookie_flags_missing"))
    check("low-entropy session id pakda", has("session_token_low_entropy"))
    check("session fixation pakda", has("session_fixation"))
    check("logout invalidation missing pakda", has("session_no_logout_invalidation"))
    check("session binding missing pakda", has("session_not_bound"))
    check("JWT weak HMAC secret pakda", has("jwt_weak_hmac_secret"))
    check("tamper: alg=none accept pakda", has("jwt_alg_none_accepted"))
    check("JWT duplicate claims pakda", has("jwt_duplicate_claims"))
    check("JWKS weak key pakda", has("jwks_weak_key"))
    check("client-side signed session pakda", has("client_side_session_storage"))
    check("embedded privilege state pakda", has("cookie_embedded_privilege_state"))
    check("cache deception surface pakda", has("cache_deception_surface"))
    check("cookie duplicate accepted pakda", has("cookie_parser_duplicate_accepted"))
    check("refresh no-rotation pakda", has("refresh_no_rotation"))
    check("concurrent unlimited pakda", has("session_concurrent_unlimited"))
    check("RS256->HS256 confusion ACCEPT pakda", has("jwt_alg_confusion_accepted"))
    check("jwk-header injection ACCEPT pakda", has("jwt_jwk_injection_accepted"))
    check("logout-reuse pakda", has("jwt_logout_reuse"))
    check("clickjacking on token page pakda", has("session_page_clickjacking"))
    check("CSRF weak mapping pakda", has("csrf_defense_weak"))

    cd = load("cache_deception.json") or {}
    check("cache_deception.json deception=true", cd.get("deception") is True,
          str(cd.get("summary"))[:60])
    rr = load("refresh_rotation.json") or {}
    check("refresh_rotation.json rotated=false", rr.get("rotated") is False,
          str(rr.get("summary"))[:60])
    cc = load("concurrent_sessions.json") or {}
    check("concurrent cap=none-detected", cc.get("cap") == "none-detected",
          str(cc.get("summary"))[:60])
    jv = load("jwt_matrix_v2.json") or {}
    check("jwt_matrix_v2 bypass=true", jv.get("bypass") is True,
          "type=%s" % jv.get("bypass_type"))
    cl = load("client_session_storage.json") or {}
    check("client lab has_client_side_state", cl.get("has_client_side_state") is True,
          str(cl.get("summary"))[:60])
    check("SESSION_FINDINGS.md exist", len(text("SESSION_FINDINGS.md")) > 500)
    check("session_test_plan.md me ULTRA hypotheses",
          "H-REFRESH" in text("session_test_plan.md") and
          "H-WCD" in text("session_test_plan.md"))
    check("session_flow_map.md mermaid", "stateDiagram-v2" in text("session_flow_map.md"))
    ff = load("feedforward.json") or {}
    routing = ff.get("routing") or {}
    check("feedforward P11 + P26 routes",
          "to_phase11_idor" in routing and "to_phase26_cache" in routing,
          ",".join(sorted(routing.keys()))[:80])
    manifest = load("MANIFEST.json") or {}
    mfiles = json.dumps(manifest)
    check("MANIFEST me ULTRA files",
          all(f in mfiles for f in ("client_session_storage.json", "cache_deception.json",
                                    "refresh_rotation.json", "jwt_matrix_v2.json")))

    # ---------------- resume run (checkpoint replay) ----------------
    print("\n== RESUME RUN assertions ==")
    cfg2 = Cfg(cfg_path)
    try:
        mod_sessions.run(cfg2, sc, out_base)
        check("resume ran without exception", True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("resume ran without exception", False, repr(e))
    F2 = (load("findings.json") or {}).get("findings") or []
    check("resume findings stable (BUG-3 fix)",
          len(F2) == len(F) and {f["key"] for f in F2} == keys,
          "fresh=%d resume=%d" % (len(F), len(F2)))

    # ---------------- passive-only run ----------------
    print("\n== PASSIVE MODE assertions ==")
    tmp2 = tempfile.mkdtemp(prefix="sess10p_")
    cfg3 = Cfg(cfg_path)
    cfg3.allow_active = False
    try:
        mod_sessions.run(cfg3, sc, tmp2)
        check("passive ran without exception", True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("passive ran without exception", False, repr(e))
    eng2 = os.path.join(tmp2, "sess10-test", "sessions")
    fp2 = os.path.join(eng2, "findings.json")
    F3 = (json.load(open(fp2)).get("findings") if os.path.exists(fp2) else []) or []
    keys3 = {f["key"] for f in F3}
    check("passive me fixation NAHI (safety fix)",
          "session_fixation" not in keys3 and "session_concurrent_unlimited" not in keys3)
    check("passive me client lab chala (0-req stage)",
          "client_side_session_storage" in keys3 or "cookie_embedded_privilege_state" in keys3)
    check("passive findings < fresh", len(F3) < len(F),
          "passive=%d fresh=%d" % (len(F3), len(F)))
    return finish(srv, tmp)


if __name__ == "__main__":
    main()
