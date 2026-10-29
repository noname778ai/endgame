#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P22 SELF-TEST SUITE - mod_replay.py v24.0.0 FULL ULTRA PRO MAX (P22)
=============================================================================
 Mock replay lab + full assertion suite:
   - Unit tests (canary/INERT guard / token-kind regexes / form miner /
     entropy buckets / replayed-signal / bypass2-17 / verdict engine /
     posture composite / platform fp / secrets guard / matrix / chains /
     race playbooks / reset playbook / renderers)
   - Active run e2e gate-OFF (stages A..Z) + RoE-gate-skip documentation
   - Gated run (8 RoE gates ON): csrf-reuse CONFIRMED + idem CONFIRMED +
     state-reuse CONFIRMED + otp weak-accept + session unbound + bypass2 +
     verb-override + signed-URL replayable (sab hard caps ke andar)
   - Artifact integrity (48 outputs, matrix >= 190 rows x 18 families,
     chains == 24) + verdict ladder
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (token VALUES artifacts me KABHI nahi - sirf sha1)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
     (0 new requests, findings stable)
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi REAL replay/race/
 brute NAHI - sab canary waspP22 family, GET-only module.
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
import time
import shutil
import hashlib
import contextlib
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block4_api_logic")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_replay as MR                                            # noqa: E402
import wasp_core as WC                                             # noqa: E402

save_json = WC.save_json

BASE = os.path.join(HERE, "p22_test_base")
BASE_GATED = os.path.join(HERE, "p22_test_base_gated")
BASE2 = os.path.join(HERE, "p22_test_base_passive")
ENG = "p22lab"
ENG_G = "p22lab2"
ENG_P = "p22labp"

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
    return open(os.path.join(ULTRA, "mod_replay.py"), encoding="utf-8",
                errors="ignore").read()


# ===========================================================================
# MOCK REPLAY LAB (detection-only sim - sab responses INERT, GET-only)
# ===========================================================================
LAB = {"requests": 0, "tok_n": 100, "idem_seen": {}, "state_seen": {},
       "sig_seen": {}}

STATIC_TOK = "tok0001122334455"          # vuln form ka static token
STATIC_RTOK = "rtok0001122334455"

FORM_HTML = """<html><head><title>WASP confirm form</title></head><body>
<h1>Confirm action</h1>
<form method="POST" action="/confirm/form/submit">
  <input type="hidden" name="csrf_token" value="%(tok)s">
  <input type="text" name="note">
  <button type="submit">Confirm</button>
</form>
<p>Single-use token flow page of the waspP22 lab.</p>
</body></html>"""

FORM_VULN_HTML = """<html><head><title>WASP confirm form vuln</title></head><body>
<h1>Confirm action (vuln)</h1>
<form method="POST" action="/confirm/form_vuln/submit">
  <input type="hidden" name="csrf_token" value="%(tok)s">
  <input type="text" name="note">
  <button type="submit">Confirm</button>
</form>
<p>Static-token flow page of the waspP22 lab.</p>
</body></html>"""

RESET_HTML = """<html><head><title>WASP reset</title></head><body>
<h1>Reset password</h1>
<form method="POST" action="/reset/do">
  <input type="hidden" name="reset_token" value="%(tok)s">
  <input type="email" name="email">
  <button type="submit">Reset</button>
</form>
<p>Reset flow page of the waspP22 lab.</p>
</body></html>"""

HOME_HTML = """<html><head><title>waspP22 home</title></head><body>
<h1>waspP22 home</h1>
<p>Replay lab home. Endpoints census-ready.</p>
</body></html>"""

SOFT404_HTML = """<html><head><title>waspP22 template</title></head><body>
<h1>Not found-ish template</h1>
<p>waspP22 generic template page content. Nothing here.</p>
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
        # ---- csrf pair ----
        if p == "/confirm/form":
            tok = (q.get("csrf_token") or q.get("token") or [""])[0]
            if tok and not tok.startswith("tok"):
                # canary/stale token param on page -> validator reject shape
                return self._send(409, "<html><body>csrf rejected</body></html>")
            LAB["tok_n"] += 1
            return self._send(200, FORM_HTML % {"tok": "tok%012d" % LAB["tok_n"]})
        if p == "/confirm/form/submit":
            tok = (q.get("csrf_token") or q.get("token") or [""])[0]
            cur = "tok%012d" % LAB["tok_n"]
            prev = "tok%012d" % (LAB["tok_n"] - 1)
            if tok in (cur, prev):
                return self._send(200, "<html><body>OK confirmed</body></html>")
            return self._send(409, "<html><body>csrf rejected</body></html>")
        if p == "/confirm/form_vuln":
            return self._send(200, FORM_VULN_HTML % {"tok": STATIC_TOK})
        if p == "/confirm/form_vuln/submit":
            tok = (q.get("csrf_token") or q.get("token") or [""])[0]
            if tok:
                return self._send(200, "<html><body>OK confirmed</body></html>")
            return self._send(400, "<html><body>missing token</body></html>")
        # ---- idempotency pair ----
        if p == "/api/pay_idem":
            key = (self.headers.get("Idempotency-Key") or
                   (q.get("idempotency_key") or [""])[0])
            if not key:
                return self._j(400, {"error": "idempotency_key required"})
            if key in LAB["idem_seen"]:
                return self._j(200, {"status": "already_processed",
                                     "idempotency_key": key},
                               {"X-Idempotent-Replay": "true"})
            LAB["idem_seen"][key] = True
            return self._j(200, {"status": "ok", "idempotency_key": key})
        if p == "/api/pay_noidem":
            return self._j(200, {"status": "ok"})
        # ---- oauth state pair ----
        if p == "/oauth/authorize":
            st = (q.get("state") or [""])[0]
            if st in LAB["state_seen"]:
                return self._j(400, {"error": "state_used"})
            LAB["state_seen"][st] = True
            return self._send(302, "", hdrs={"Location": "/cb?code=x1"})
        if p == "/oauth/authorize_vuln":
            return self._send(302, "", hdrs={"Location": "/cb?code=x2"})
        if p == "/cb":
            return self._send(200, "<html><body>callback ok</body></html>")
        # ---- reset ----
        if p == "/reset":
            return self._send(200, RESET_HTML % {"tok": STATIC_RTOK})
        # ---- otp pair ----
        if p == "/verify/otp":
            return self._j(400, {"error": "invalid_otp"})
        if p == "/verify/otp_vuln":
            code = (q.get("otp") or q.get("code") or [""])[0]
            if code and len(set(code)) <= 1:
                return self._j(200, {"status": "verified"})
            return self._j(400, {"error": "invalid_otp"})
        # ---- session pair ----
        if p == "/token/session":
            if "waspp22session" in self.headers.get("Cookie", "").lower():
                return self._j(403, {"error": "binding mismatch"})
            return self._j(401, {"error": "no session"})
        if p == "/token/session_vuln":
            return self._j(200, {"status": "in", "ctx": "any"})
        # ---- verb / override ----
        if p == "/approve/verb":
            ov = self.headers.get("X-HTTP-Method-Override")
            if ov:
                return self._send(200, "<html><body>override=%s</body></html>"
                                  % ov.lower())
            return self._send(200, "<html><body>verb endpoint plain</body></html>")
        # ---- cache pair ----
        if p == "/redeem/cached":
            return self._send(200, "<html><body>cached token page</body></html>",
                              hdrs={"Cache-Control": "public, max-age=300"})
        if p == "/redeem/nocache":
            return self._send(200, "<html><body>private page</body></html>",
                              hdrs={"Cache-Control": "no-store, private"})
        # ---- signed pair ----
        if p == "/verify/signed":
            sig = (q.get("sig") or [""])[0]
            return self._j(200, {"status": "valid", "sig": sig[:6] + "***"})
        if p == "/verify/signed_ot":
            sig = (q.get("sig") or [""])[0]
            if sig in LAB["sig_seen"]:
                return self._j(410, {"error": "gone_one_time"})
            LAB["sig_seen"][sig] = True
            return self._j(200, {"status": "valid_once"})
        # ---- gql/ws info ----
        if p == "/graphql":
            return self._send(405, "<html><body>method not allowed</body></html>",
                              hdrs={"Allow": "POST"})
        if p == "/ws-info":
            return self._j(200, {"endpoints": ["/ws/notifications"]})
        # ---- catch-all (soft-404 template) ----
        return self._send(200, SOFT404_HTML)

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._send(405, "<html><body>lab is GET-only (INERT sim)</body></html>")

    def do_HEAD(self):
        self._route()

    def do_OPTIONS(self):
        LAB["requests"] += 1
        self._send(200, "", hdrs={
            "Allow": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"})


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
    """Engagement feedforward fixtures (P9..P20 handoff seeds) + scope.json."""
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

    wff("logic", {"to_phase22_replay": {"replay_pairs": [
        origin + "/api/pay", origin + "/checkout", "waspP20canary"]}})
    wff("inject", {"to_phase22_replay": {"replay_pairs": [
        origin + "/verify-otp"]}})
    wff("auth", {"to_phase22_authflow": {"paths": [
        origin + "/confirm/form", origin + "/confirm/form_vuln",
        origin + "/oauth/authorize", origin + "/oauth/authorize_vuln",
        origin + "/verify/otp", origin + "/verify/otp_vuln",
        origin + "/token/session", origin + "/token/session_vuln",
        origin + "/verify/signed", origin + "/verify/signed_ot",
        origin + "/approve/verb", origin + "/redeem/cached",
        origin + "/api/pay_idem", origin + "/api/pay_noidem"]}})
    wff("sessions", {"to_phase22_tokens": {"names": [
        "csrf_token", "wasp_session"]}})
    wff("graphql", {"to_phase22_writable": {"mutations": [
        "redeemGiftCard", "applyCoupon"]}})
    wff("ws", {"to_phase22_ws": {"endpoints": ["/ws/notifications"]}})
    save_json(os.path.join(base, "scope.json"), {
        "engagement": engagement,
        "authorized": True,
        "authorization_reference": "P22 lab RoE / selftest",
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
    # canary family + INERT guard
    c = MR._canary("x")
    check("unit.canary.family", c.startswith("waspP22") and len(c) > 10, c)
    try:
        MR.assert_inert_method("POST")
        check("unit.inert.post-block", False, "POST allowed!")
    except RuntimeError:
        check("unit.inert.post-block", True)
    try:
        MR.assert_inert_method("DELETE")
        check("unit.inert.delete-block", False, "DELETE allowed!")
    except RuntimeError:
        check("unit.inert.delete-block", True)
    check("unit.inert.get-ok", MR.assert_inert_method("GET") is True)
    check("unit.inert.options-ok", MR.assert_inert_method("OPTIONS") is True)
    check("unit.inert.head-ok", MR.assert_inert_method("HEAD") is True)
    check("unit.inert.probe-drops-body",
          MR.probe(type("H", (), {"request": lambda s, m, u, **k:
                                  "nodata"})(), "GET", "http://x/",
                   data="should-drop") == "nodata")

    # token kind regexes
    check("unit.kind.csrf", MR.token_param_kind("csrf_token") == "csrf")
    check("unit.kind.authenticity", MR.token_param_kind(
        "authenticity_token") == "csrf")
    check("unit.kind.state", MR.token_param_kind("state") == "state")
    check("unit.kind.otp", MR.token_param_kind("otp_code") == "otp")
    check("unit.kind.reset", MR.token_param_kind("reset_token") == "reset")
    check("unit.kind.idem", MR.token_param_kind("idempotency_key") ==
          "idempotency")
    check("unit.kind.none", MR.token_param_kind(" innocuous ") is None)
    check("unit.kind.header", MR.token_kind_of_header("Idempotency-Key") ==
          "header")
    check("unit.kind.cookie", MR.token_kind_of_cookie("csrftoken") == "cookie")

    # form miner
    hfs = MR.mine_hidden_fields(FORM_HTML % {"tok": STATIC_TOK})
    check("unit.miner.hidden", len(hfs) == 1 and hfs[0]["name"] ==
          "csrf_token", hfs)
    check("unit.miner.sha1", hfs and hfs[0]["value_sha1"] ==
          hashlib.sha1(STATIC_TOK.encode()).hexdigest()[:12])

    # entropy buckets
    eb = MR.entropy_bucket("123456")
    check("unit.entropy.digits", eb["format"] == "digits" and
          eb["len_bucket"] == "<=16", eb)
    eb2 = MR.entropy_bucket("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    check("unit.entropy.hex", eb2["format"] == "hex" and
          eb2["len_bucket"] == "17-32", eb2)

    # replayed signal
    r_sig = WC.Resp("http://x/", 200, {"X-Idempotent-Replay": "true"},
                    b'{"status": "already_processed"}')
    r_clean = WC.Resp("http://x/", 200, {"Content-Type": "text/html"},
                      b"<html>fine page</html>")
    check("unit.signal.hit", MR.looks_replayed_signal(r_sig) is True)
    check("unit.signal.clean", MR.looks_replayed_signal(r_clean) is False)

    # bypass2 shapes
    shapes = MR._bypass2_shapes("http://x/api/pay", "waspP22c1")
    check("unit.bypass2.count", len(shapes) == 17, len(shapes))
    check("unit.bypass2.ids", [s[0] for s in shapes][-1] == "B2-17")
    check("unit.bypass2.get-only",
          all(u.startswith("http://x/api/pay") for _, _, u in shapes))

    # matrix
    mx = MR.build_matrix()
    fams = set(m["family"] for m in mx)
    check("unit.matrix.rows", len(mx) >= 190, len(mx))
    check("unit.matrix.families", len(fams) == 18, sorted(fams))
    check("unit.matrix.cwe", all(m["cwe"].startswith("CWE-") for m in mx))
    check("unit.matrix.mitre", all(m["mitre"].startswith("T") for m in mx))

    # chains + race + reset playbook
    ch = MR.build_chains({}, {"logic": 1})
    check("unit.chains.count", len(ch) == 24, len(ch))
    check("unit.chains.ids", ch[0]["id"] == "CH01" and ch[-1]["id"] == "CH24")
    race = MR.race_surface_documented()
    check("unit.race.techniques", len(race["techniques"]) == 12)
    check("unit.race.forbidden-auto", all("FORBIDDEN-AUTO" in t["discipline"]
                                          or "manual" in t["discipline"]
                                          for t in race["techniques"]))
    check("unit.reset.playbook", len(MR.RESET_PLAYBOOK_ROWS) == 6)

    # verdict engine (synthetic)
    vr = MR.verdict_engine({
        "csrf": {"rows": [{"url": "u1", "rotated": False,
                           "reuse": {"accepted": True}}]},
        "idem": {"rows": [{"url": "u2", "dedup": False, "echo": False}]},
        "nonce": {"rows": [{"url": "u3", "consumed": True}]},
        "otp": {"rows": [{"url": "u4", "weak_accept": True}]},
        "session": {"rows": [{"url": "u5", "binding_absent": True}]},
        "bypass2": {"rows": [{"url": "u6", "accepted_count": 3,
                              "accepted_ids": ["B2-01"]}]},
        "rate": {"rows": [{"url": "u7", "rate_limited": True}]},
        "signed": {"rows": [{"url": "u8", "replayable": True}]},
        "verb": {"skipped_note": "gate off"},
    })
    vd = {(r["stage"], r["verdict"]) for r in vr}
    check("unit.verdict.csrf-confirmed", ("D", "CONFIRMED") in vd, vd)
    check("unit.verdict.idem-confirmed", ("E", "CONFIRMED") in vd)
    check("unit.verdict.nonce-hardened", ("F", "HARDENED") in vd)
    check("unit.verdict.otp-confirmed", ("H", "CONFIRMED") in vd)
    check("unit.verdict.session-confirmed", ("I", "CONFIRMED") in vd)
    check("unit.verdict.bypass2-confirmed", ("K", "CONFIRMED") in vd)
    check("unit.verdict.rate-hardened", ("L", "HARDENED") in vd)
    check("unit.verdict.signed-confirmed", ("O", "CONFIRMED") in vd)
    check("unit.verdict.skipped-row", ("M", "SKIPPED") in vd)

    # posture composite
    post = MR.posture_composite({
        "csrf": {"rows": [{"url": "p1", "rotated": True,
                           "reuse": {"reject_class": True}}]},
        "idem": {"rows": [{"url": "p1", "dedup": True}]},
        "rate": {"rows": [{"url": "p1", "rate_limited": True}]},
        "cache": {"rows": [{"url": "p1", "cacheable": False}]},
    }, [])
    check("unit.posture.score", post["rows"] and post["rows"][0]["score"] >= 4,
          post["rows"])
    check("unit.posture.points", len(post["points"]) == 8)
    post2 = MR.posture_composite({
        "cache": {"rows": [{"url": "p2", "cacheable": True}]}}, [])
    check("unit.posture.weak", post2["rows"] and
          post2["rows"][0]["grade"] == "WEAK", post2["rows"])

    # platform + secrets guard
    pf = MR.platform_fingerprint(["/oauth/authorize id_token shape",
                                  "x-ratelimit header seen"])
    check("unit.platform.shapes", "oauth2-oidc" in pf["shapes"] and
          "rate-limiter" in pf["shapes"], pf)
    guard = MR.secrets_guard([("a.txt", "password=SuperSecret9 value"),
                              ("b.txt", "clean content")])
    check("unit.guard.hit", len(guard["hits"]) == 1 and
          "REDACTED" in guard["hits"][0]["shape"], guard)

    # token lifecycle
    lc = MR.token_lifecycle_census([
        {"kind": "csrf", "name": "csrf_token", "url": "u",
         "len_bucket": "<=16", "entropy": None, "format": "b64url"}])
    check("unit.lifecycle.weak", lc["weak_count"] == 1 and
          lc["rows"][0]["weak_shape"] is True, lc)

    # findings collector
    F = MR.Findings()
    r1 = F.add("replay_csrf_reuse_confirmed", "t", "e", "d")
    check("unit.findings.sev", r1["severity"] == "critical" and
          r1["id"] == "RP-001", r1)
    check("unit.findings.pii", F.add("replay_token_param", "t", "e",
                                     "mail a@b.com here")["detail"].find(
                                         "***@***") >= 0)

    # severity hints sanity
    check("unit.hints.count", len(MR.SEVERITY_HINTS) >= 40,
          len(MR.SEVERITY_HINTS))
    check("unit.hints.shape", all(len(v) == 3 for v in
                                  MR.SEVERITY_HINTS.values()))

    # renderers
    gates = {g: False for g, _ in MR.ROE_GATES}
    tp = MR.render_test_plan(F, gates, mx)
    check("unit.render.testplan", "KD-08" in tp and "FORBIDDEN-AUTO" in tp)
    check("unit.render.matrix-txt", "REPLAY_BYPASS2" in MR.render_matrix_txt(mx))
    sc = WC.Scope(os.path.join(HERE, "p22_test_base", "scope.json")) \
        if os.path.exists(os.path.join(HERE, "p22_test_base", "scope.json")) \
        else None
    fake_scope = type("S", (), {"engagement": "x", "ref": "r", "notes": ""})()
    md = MR.render_findings_md(fake_scope, F, vr, ch, {"mode": "active"})
    check("unit.render.findings-md", "RP-001" in md and "CH01" in md)
    ex = MR.render_exec_summary(fake_scope, F, post, vr, {"mode": "active"})
    check("unit.render.exec", "CONFIRMED replay gaps" in ex)
    rem = MR.render_remediation(F)
    check("unit.render.remediation", "REPLAY_CSRF" in rem and
          "Synchronizer-token" in rem)
    ko = MR.render_kickoff(fake_scope, gates, {})
    check("unit.render.kickoff", "GET-only module" in ko)
    pb = MR.render_playbooks()
    check("unit.render.playbooks", "RC-01" in pb and "RC-12" in pb)
    check("unit.render.chains-txt", "CH24" in MR.render_chains_txt(ch))
    hy = MR.build_hypotheses({"csrf": {"rows": [{"url": "u", "rotated": False}]},
                              "rate": {"rows": []}, "cache": {"rows": []}},
                             [], post)
    check("unit.render.hypotheses", len(hy) >= 1 and hy[0]["prio"] in
          ("high", "medium", "info"))

    # gates registry
    check("unit.gates.count", len(MR.ROE_GATES) == 8)
    check("unit.gates.default-off", all(
        not MR.DEFAULTS[g] for g, _ in MR.ROE_GATES))

    # source hygiene: GET-only module (koi POST probe call nahi)
    src = _src()
    check("unit.src.no-post-probe",
          not re.search(r'probe\(http,\s*["\'](?:POST|PUT|DELETE|PATCH)', src))
    check("unit.src.get-only-assert", "assert_inert_method" in src)
    check("unit.src.canary-family", src.count("waspP22") >= 6)


# ===========================================================================
# SECTION 2 - E2E GATE-OFF RUN (stages A..Z, sab INERT GET probes)
# ===========================================================================
def e2e_gate_off(httpd, origin, base):
    print("\n== SECTION 2: E2E GATE-OFF RUN ==")
    cfg = _speed_cfg()
    out = MR.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    check("e2e.outdir", out and os.path.isdir(out), out)
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("e2e.manifest.phase", man.get("phase") == "phase22", man.get("phase"))
    check("e2e.manifest.artifacts", (man.get("stats") or {}).get(
        "artifacts", 0) >= 46, man.get("stats"))
    check("e2e.manifest.matrix", (man.get("stats") or {}).get(
        "matrix_rows", 0) >= 190)
    check("e2e.manifest.chains", (man.get("stats") or {}).get(
        "chains", 0) == 24)
    check("e2e.manifest.mode", (man.get("stats") or {}).get(
        "mode") == "active")
    cov = _read(os.path.join(out, "replay_coverage.json")) or {}
    check("e2e.coverage.mode", cov.get("mode") == "active")
    check("e2e.coverage.sources", len(cov.get("sources", [])) >= 3,
          cov.get("sources"))
    check("e2e.coverage.gates-off", all(
        v is False for v in (cov.get("gates") or {}).values()))
    check("e2e.coverage.stages", len(cov.get("stages", [])) == 26)
    fj = _read(os.path.join(out, "findings.json")) or {}
    check("e2e.findings.count", fj.get("count", 0) >= 5, fj.get("count"))
    check("e2e.findings.ids", all(str(f.get("id", "")).startswith("RP-")
                                  for f in fj.get("findings", [])))
    keys = {f.get("key") for f in fj.get("findings", [])}
    check("e2e.findings.race", "replay_race_documented" in keys, keys)
    check("e2e.findings.reset", "replay_reset_surface" in keys, keys)
    check("e2e.findings.weak-entropy", "replay_token_weak_entropy" in keys,
          keys)
    vv = _read(os.path.join(out, "replay_verdicts.json")) or {}
    skips = [r for r in vv.get("rows", []) if r.get("verdict") == "SKIPPED"]
    check("e2e.verdict.skipped-documented", len(skips) >= 8, len(skips))
    check("e2e.verdict.no-confirmed",
          len([r for r in vv.get("rows", [])
               if r.get("verdict") == "CONFIRMED"]) == 0,
          "gate-off par CONFIRMED nahi hona chahiye")
    for art in ("replay_targets.json", "replay_token_census.json",
                "replay_csrf_rotation.json", "replay_idempotency.json",
                "replay_nonce_state.json", "replay_reset_surface.json",
                "replay_otp_surface.json", "replay_session_diff.json",
                "replay_race_surface.json", "replay_bypass2.json",
                "replay_anti_automation.json", "replay_verb_replay.json",
                "replay_cache_replay.json", "replay_signed_urls.json",
                "replay_api_idempotency.json", "replay_gql_surface.json",
                "replay_ws_surface.json", "replay_token_lifecycle.json",
                "replay_posture.json", "replay_platform.json",
                "replay_secret_guard.json", "replay_chains.json",
                "replay_matrix.json", "REPLAY_FINDINGS.md",
                "REPLAY_TEST_PLAN.md", "REPLAY_REMEDIATION.md",
                "EXEC_SUMMARY.md", "REPLAY_KICKOFF.md",
                "REPLAY_PLAYBOOKS.md", "feedforward.json"):
        check("e2e.artifact.%s" % art, os.path.exists(os.path.join(out, art)))
    gql = _read(os.path.join(out, "replay_gql_surface.json")) or {}
    check("e2e.gql.names", "redeemGiftCard" in (gql.get("mutations") or []),
          gql)
    ws = _read(os.path.join(out, "replay_ws_surface.json")) or {}
    check("e2e.ws.endpoints", ws.get("count", 0) >= 1, ws)
    ff = _read(os.path.join(out, "feedforward.json")) or {}
    rk = set((ff.get("routing") or {}).keys())
    check("e2e.feedforward.keys", {"to_phase23_misconfig",
                                   "to_phase24_cloud", "to_phase25_controls",
                                   "to_phase11_access", "to_phase12_inject",
                                   "to_phase32_report"} <= rk, rk)
    gates_txt = _read_txt(os.path.join(out, "replay_gates.txt"))
    check("e2e.gates-txt", "replay_allow_csrf_probe = false" in gates_txt)
    check("e2e.probes-bounded", (man.get("stats") or {}).get(
        "probes", 999) <= 400, man.get("stats", {}).get("probes"))
    return out, cfg, man


# ===========================================================================
# SECTION 3 - GATED RUN (8 RoE gates ON - hard caps ke andar)
# ===========================================================================
def e2e_gated(httpd, origin, base):
    print("\n== SECTION 3: GATED RUN (8 gates ON) ==")
    gates = [g for g, _ in MR.ROE_GATES]
    cfg2 = _speed_cfg(gates=gates)
    out = MR.run(cfg2, WC.Scope(os.path.join(base, "scope.json")), base)
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("gated.manifest.gates-on", sorted(
        (man.get("stats") or {}).get("gates_on", [])) == sorted(gates),
        man.get("stats", {}).get("gates_on"))
    vv = _read(os.path.join(out, "replay_verdicts.json")) or {}
    rows = vv.get("rows", [])
    conf = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "CONFIRMED"]
    hard = [(r["stage"], r["url"]) for r in rows if r["verdict"] == "HARDENED"]
    check("gated.confirmed-present", len(conf) >= 5, conf[:8])
    check("gated.hardened-present", len(hard) >= 3, hard[:8])
    d_urls = [u for s, u in conf if s == "D"]
    check("gated.csrf-reuse-confirmed", any("form_vuln" in u for u in d_urls),
          d_urls)
    e_urls = [u for s, u in conf if s == "E"]
    check("gated.idem-confirmed", any("pay_noidem" in u for u in e_urls),
          e_urls)
    f_urls = [u for s, u in conf if s == "F"]
    check("gated.state-confirmed", any("authorize_vuln" in u for u in f_urls),
          f_urls)
    h_urls = [u for s, u in conf if s == "H"]
    check("gated.otp-weak-confirmed", any("otp_vuln" in u for u in h_urls),
          h_urls)
    i_urls = [u for s, u in conf if s == "I"]
    check("gated.session-unbound", any("session_vuln" in u for u in i_urls),
          i_urls)
    o_urls = [u for s, u in conf if s == "O"]
    check("gated.signed-replayable", any("signed" in u and
                                         "signed_ot" not in u
                                         for u in o_urls), o_urls)
    hard_urls = [u for s, u in hard]
    d_hard = [u for s2, u in hard if s2 == "D"]
    check("gated.csrf-rotated-hardened", any(
        u.rstrip("/").endswith("/confirm/form") for u in d_hard), d_hard)
    check("gated.idem-dedup-hardened", any("pay_idem" in u for s2, u in hard
                                           if s2 == "E"),
          [u for s2, u in hard if s2 == "E"])
    check("gated.state-consumed-hardened", any(
        u.endswith("/oauth/authorize") or ("authorize" in u and
                                           "vuln" not in u)
        for s2, u in hard if s2 == "F"),
        [u for s2, u in hard if s2 == "F"])
    fj = _read(os.path.join(out, "findings.json")) or {}
    keys = {f.get("key") for f in fj.get("findings", [])}
    for kx in ("replay_csrf_reuse_confirmed", "replay_idem_missing_confirmed",
               "replay_state_reuse_confirmed", "replay_otp_weak_accept",
               "replay_session_unbound", "replay_signed_url_replayable",
               "replay_method_override_echo", "replay_bypass2_accepted"):
        check("gated.finding.%s" % kx, kx in keys, sorted(keys)[:12])
    b2 = _read(os.path.join(out, "replay_bypass2.json")) or {}
    check("gated.bypass2.rows", len(b2.get("rows", [])) >= 1)
    check("gated.bypass2.accepted", any(
        r.get("accepted_count", 0) >= 1 for r in b2.get("rows", [])),
        [r.get("accepted_count") for r in b2.get("rows", [])])
    check("gated.bypass2.shapes-17", all(
        len(r.get("shapes", [])) == 17 for r in b2.get("rows", [])))
    idem = _read(os.path.join(out, "replay_idempotency.json")) or {}
    check("gated.idem.hard-cap-2seq", all(
        r.get("mode") in ("header", "param") for r in
        idem.get("rows", [])))
    post = _read(os.path.join(out, "replay_posture.json")) or {}
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
    out2 = MR.run(cfg4, WC.Scope(os.path.join(base, "scope.json")), base)
    check("passive.delta-0", LAB["requests"] - n_before == 0,
          LAB["requests"] - n_before)
    man = _read(os.path.join(out2, "MANIFEST.json")) or {}
    check("passive.manifest-mode", (man.get("stats") or {}).get(
        "mode") == "passive", man.get("stats"))
    check("passive.probes-0", (man.get("stats") or {}).get(
        "probes", 0) == 0, man.get("stats", {}).get("probes"))
    cov = _read(os.path.join(out2, "replay_coverage.json")) or {}
    check("passive.coverage", cov.get("mode") == "passive")
    check("passive.manifest-artifacts", (man.get("stats") or {}).get(
        "artifacts", 0) >= 46)

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

    # redaction: real token values artifacts me KABHI nahi
    leak = []
    for p in _walk_files(gated_out):
        if p.endswith((".json", ".md", ".txt")):
            txt = _read_txt(p)
            if STATIC_TOK in txt or STATIC_RTOK in txt:
                leak.append(os.path.basename(p))
    check("redaction.no-token-values", not leak, leak)
    # rotating tokens tok%012d bhi nahi hone chahiye (sirf sha1 buckets)
    rot = []
    for p in _walk_files(gated_out):
        if p.endswith((".json", ".md", ".txt")):
            txt = _read_txt(p)
            m = re.search(r"tok\d{12}", txt)
            if m:
                rot.append((os.path.basename(p), m.group(0)))
    check("redaction.no-rotating-tokens", not rot, rot[:4])


def checkpoint_replay(httpd, origin, base, out_first, findings_first):
    print("\n== SECTION 5: CHECKPOINT REPLAY (resume, 0 new requests) ==")
    n_before = LAB["requests"]
    cfg = _speed_cfg()
    out = MR.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    delta = LAB["requests"] - n_before
    check("replay.same-outdir", out == out_first, "%s vs %s" % (out, out_first))
    check("replay.zero-new-requests", delta == 0, "new hits=%d" % delta)
    fj = _read(os.path.join(out, "findings.json")) or {}
    check("replay.findings-stable", fj.get("count") == findings_first,
          "%s vs %s" % (fj.get("count"), findings_first))
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    check("replay.manifest-valid", (man.get("stats") or {}).get(
        "matrix_rows", 0) >= 190)


# ===========================================================================
# SECTION 6 - CLI + IMPORT HYGIENE
# ===========================================================================
def cli_tests():
    print("\n== SECTION 6: CLI + IMPORT HYGIENE ==")
    p = subprocess.run([sys.executable, "mod_replay.py"], cwd=ULTRA,
                       capture_output=True, text=True, timeout=60)
    check("cli.exit-0", p.returncode == 0, p.returncode)
    check("cli.gates-listed", "replay_allow_csrf_probe" in p.stdout and
          "Phase 22" in p.stdout, p.stdout[:120])
    p2 = subprocess.run([sys.executable, "-W", "error", "-c",
                         "import mod_replay"], cwd=ULTRA,
                        capture_output=True, text=True, timeout=60)
    check("cli.import-hygiene", p2.returncode == 0, p2.stderr[:200])
    p3 = subprocess.run([sys.executable, "-m", "py_compile", "-q",
                         os.path.join(ULTRA, "mod_replay.py")],
                        capture_output=True, text=True, timeout=60)
    check("cli.py-compile", p3.returncode == 0, p3.stderr[:200])


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    t0 = time.time()
    print("=" * 72)
    print("WASP P22 SELF-TEST - mod_replay.py v%s (ULTRA PRO MAX)" %
          MR.PLAN_VERSION)
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
    print("ALL GREEN - P22 v24.0.0 INERT discipline honored (GET-only, "
          "2-seq cap, canary %s)" % MR.CANARY_FAMILY)


if __name__ == "__main__":
    main()
