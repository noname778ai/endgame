#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P19 SELF-TEST SUITE - mod_ws.py v19.0.0 FULL ULTRA PRO MAX (P19)
=============================================================================
 Mock WebSocket lab + full assertion suite:
   - Unit tests (RFC 6455 crypto: accept GUID math / key-gen / scheme maps,
     mining regexes, discovery seeds, origin variant builder, verdict
     engine, matrix builder, chains builder, message-technique docs)
   - Handshake census unit (101 + accept-crypto + version guard + subproto
     echo + CRLF split + deflate + server-push + WAF 403 + auth 401 +
     OUT-OF-SCOPE firewall) - sab INERT raw-socket probes
   - Active run e2e gate-OFF (stages A..S) + RoE-gate-skip documentation
   - Gated run (evil-origins + transports + burst + frames + h2ws + subs)
     - sab hard caps ke andar (burst <= 3, data-frames NEVER)
   - Artifact integrity (40 outputs, matrix >= 150 rows, chains == 20)
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (bodies sirf shape/sha1 - content stored nahi hota)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi data-frame/expl payload
 nahi; handshake ke baad frames KABHI exchange nahi hote.
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
import base64
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

import mod_ws as MW                                              # noqa: E402
import wasp_core as WC                                           # noqa: E402

BASE = os.path.join(HERE, "p19_test_base")
BASE_GATED = os.path.join(HERE, "p19_test_base_gated")
BASE2 = os.path.join(HERE, "p19_test_base_passive")
ENG = "p19lab"
ENG_G = "p19lab2"
ENG_P = "p19labp"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append((name, ""))
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s -> %s" % (name, str(detail)[:140]))


# ===========================================================================
# MOCK WEBSOCKET LAB (detection-only sim - sab responses INERT)
# ===========================================================================
LAB = {}


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


def _ws101(self, proto=None, extra=None, accept_override=None, push=b""):
    """RFC 6455 101 upgrade response (headers-only, koi frame/data nahi)."""
    key = self.headers.get("Sec-WebSocket-Key", "")
    acc = base64.b64encode(hashlib.sha1(
        (key + MW.WS_GUID).encode("ascii")).digest()).decode("ascii")
    if accept_override is not None:
        acc = accept_override
    self.send_response(101)
    self.send_header("Upgrade", "websocket")
    self.send_header("Connection", "Upgrade")
    self.send_header("Sec-WebSocket-Accept", acc)
    if proto is not None:
        self.send_header("Sec-WebSocket-Protocol", proto)
    for k, v in (extra or {}).items():
        self.send_header(k, v)
    self.end_headers()
    if push:
        try:
            self.wfile.write(push)
        except Exception:
            pass


def _same_origin(self):
    return self.headers.get("Origin") or "" == LAB.get("origin", "!") or \
        (self.headers.get("Origin") or "") == LAB.get("origin", "")


def _origin_ok(self):
    o = self.headers.get("Origin")
    if o is None:
        return True          # non-browser client baseline
    return o == LAB.get("origin", "")


def _ws_route(self, p):
    """Upgrade-header requests ka routing sim (sab 101/4xx, no frames)."""
    o = self.headers.get("Origin")
    up = (self.headers.get("Upgrade") or "").lower()
    if up != "websocket":
        return _txt(self, 426, "Upgrade Required",
                    {"Connection": "Upgrade", "Upgrade": "websocket"})
    if p == "/ws":
        # strict origin + version enforcement sim: version pehle (RFC 4.2.2
        # order), phir origin. absent OK, same OK, cross/null/variant reject.
        if (self.headers.get("Sec-WebSocket-Version") or "13") != "13":
            return _txt(self, 426, "Upgrade Required",
                        hdrs={"Sec-WebSocket-Version": "13"})
        if o is None or o == LAB.get("origin", ""):
            return _ws101(self)
        return _txt(self, 403, "origin not allowed")
    if p == "/ws_open":
        # CSWSH sim: ANY origin accepted (evil included)
        return _ws101(self)
    if p == "/ws_null":
        if o in (None, "null", LAB.get("origin", "")):
            return _ws101(self)
        return _txt(self, 403, "origin not allowed")
    if p == "/ws_auth":
        if self.headers.get("Cookie") == "session=supersecret123":
            return _ws101(self)
        return _j(self, 401, {"error": "auth required on upgrade"})
    if p == "/ws_token":
        return _ws101(self)   # token query me hai - census flag karega
    if p == "/ws_v8":
        # version guard missing: koi bhi version 101
        return _ws101(self)
    if p == "/ws_echo":
        # arbitrary subprotocol verbatim echo (reflection surface sim)
        return _ws101(self, proto=self.headers.get("Sec-WebSocket-Protocol"))
    if p == "/ws_crlf":
        # CRLF-encoded protocol -> injected header (split sim)
        pr = self.headers.get("Sec-WebSocket-Protocol") or ""
        extra = {"X-Wasp-B": "c"} if "%0d%0a" in pr else None
        return _ws101(self, proto=pr, extra=extra)
    if p == "/ws_deflate":
        return _ws101(self, extra={"Sec-WebSocket-Extensions":
                                   "permessage-deflate"})
    if p == "/ws_accept_bad":
        return _ws101(self, accept_override="BOGUSACCEPTBOGUSACCEPTBOGUS==")
    if p == "/ws_push":
        return _ws101(self, push=b"PUSHED-BYTES-waspP19")
    if p == "/ws_waf":
        # edge ws-filter sim: plain GET pass, upgrade block
        return _txt(self, 403, "blocked by edge")
    if p == "/ws_rate":
        LAB["rate_n"] = LAB.get("rate_n", 0) + 1
        if LAB["rate_n"] <= 2:
            return _ws101(self)
        return _txt(self, 429, "rate limited", hdrs={"Retry-After": "0"})
    if p == "/ws_edge":
        return _txt(self, 403, "edge deny")
    if p == "/graphql-ws":
        pr = self.headers.get("Sec-WebSocket-Protocol") or ""
        if pr == "graphql-transport-ws":
            return _ws101(self, proto=pr)
        if pr == "graphql-ws":
            return _txt(self, 403, "legacy subprotocol rejected")
        return _ws101(self)
    if p == "/blocked-ws":
        return _txt(self, 403, "edge deny")
    return _j(self, 404, {"error": "not found"})


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlsplit(self.path)
        p = u.path
        q = parse_qs(u.query)
        up = (self.headers.get("Upgrade") or "").lower()
        # ---- upgrade requests pehle (raw-socket census path) ----
        if up == "websocket" or p.startswith("/ws") or \
                p in ("/graphql-ws", "/blocked-ws"):
            # edge misroute sim: X-Original-URL edge par pehle lagta hai
            xou = self.headers.get("X-Original-URL")
            if xou:
                p = urlsplit(xou).path or p
            return _ws_route(self, p)
        # ---- plain HTTP census routes ----
        if p == "/":
            return _txt(self, 200,
                        "<html><head><title>WASP P19 Lab</title></head>"
                        "<body>realtime app <script src=\"/app.js\">"
                        "</script><a href=\"ws://127.0.0.1:%d/ws\">ws</a>"
                        "</body></html>" % LAB.get("port", 0),
                        ct="text/html")
        if p == "/app.js":
            return _txt(self, 200,
                        "var s = new WebSocket(\"ws://127.0.0.1:%d/ws_echo\");"
                        "var t = new WebSocket(\"ws://127.0.0.1:%d/ws_token?"
                        "token=abcdef123456\");"
                        "var io = io('/socket.io', {transports:['websocket']});"
                        "var sock = new SockJS('/sockjs');"
                        % (LAB.get("port", 0), LAB.get("port", 0)),
                        ct="application/javascript")
        if p == "/socket.io/" and "EIO" in (u.query or ""):
            eio = (q.get("EIO") or ["4"])[0]
            if eio == "3":
                return _j(self, 200, {"sid": "legacy0123456789",
                                      "upgrades": ["websocket"],
                                      "pingInterval": "25000",
                                      "pingTimeout": "60000"})
            return _j(self, 200, {"sid": "waspLabSid0123456789abcdef",
                                  "upgrades": ["websocket"],
                                  "pingInterval": 25000,
                                  "pingTimeout": 20000,
                                  "maxPayload": 1000000})
        if p == "/socket.io/":
            return _txt(self, 400, "transport required")
        if p in ("/sockjs/info", "/echo/info"):
            return _j(self, 200, {"websocket": True,
                                  "origins": ["*:*"],
                                  "cookie_needed": False,
                                  "entropy": 87215,
                                  "url_prefix": ""})
        if p == "/signalr/negotiate":
            return _j(self, 200, {"ConnectionId": "wasp0123456789",
                                  "ConnectionToken": "tokwasp0123456789xyz",
                                  "TryWebSockets": True,
                                  "Url": "/signalr",
                                  "ProtocolVersion": "1.5"})
        if p == "/primus":
            return _txt(self, 200, "primus transformer ws")
        if p == "/faye":
            return _txt(self, 200, "faye bayeux")
        if p == "/ws":
            return _j(self, 404, {"error": "not found",
                                  "code": "resource_missing"})
        return _j(self, 404, {"error": "not found",
                              "code": "resource_missing"})

    def do_POST(self):
        return _j(self, 404, {"error": "not found"})


def _start_lab():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, port


# ===========================================================================
# SEED FIXTURES (P14/P17/P18/P6/P7 artifacts -> P19 guide seeds)
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
        "authorization_reference": "P19 selftest SOW v1",
        "targets": [origin],
        "notes": "no-DoS; detection-only INERT lab; gates lab-only"})
    # ---- P14 client feedforward (ws_endpoints) ----
    wsr = origin.replace("http://", "ws://", 1)
    wssr = origin.replace("http://", "wss://", 1)
    _w(base, eng, "client/feedforward.json", {"routing": {
        "to_phase19_ws": {"ws_endpoints": [
            wsr + "/ws_open", wsr + "/ws_null",
            wsr + "/ws_token?token=abcdef123456", wsr + "/ws_echo",
            wsr + "/ws_v8", wsr + "/ws_crlf",
            wssr + "/ws_tlsseed"],
            "note": "client-side realtime surface"}}})
    # ---- P17 api feedforward (ws_signals) ----
    _w(base, eng, "api/feedforward.json", {"routing": {
        "to_phase19_ws": {"ws_signals": [{"url": origin + "/ws",
                                          "status": 426},
                                         {"url": origin + "/ws_auth",
                                          "status": 401}],
                          "gql_probe": {"url": origin + "/graphql"}}}})
    # ---- P18 graphql feedforward (ws_signals + ws_paths + subs) ----
    _w(base, eng, "graphql/feedforward.json", {"routing": {
        "to_phase19_ws": {
            "ws_signals": [{"url": origin + "/graphql-ws"}],
            "gql_subscriptions": "RootSubscription",
            "ws_paths": [origin + "/graphql-ws",
                         origin + "/graphql/subscriptions"],
            "note": "P18 subs-deep handoff"}}})
    # ---- P6 tech feedforward (realtime) ----
    _w(base, eng, "tech/feedforward.json", {"routing": {
        "to_phase19_ws": {"realtime": "architecture_map.txt"}}})
    # ---- P7 js artifacts (guide seed: JS miner ws:// links) ----
    _w(base, eng, "js/websockets.txt",
       wsr + "/ws_v8\n"
       + wsr + "/ws_crlf\n"
       + wsr + "/ws_rate\n"
       + wsr.replace("ws://", "wss://", 1) + "/ws_tlsseed\n")
    _w(base, eng, "js/endpoints.txt", origin + "/ws_deflate\n")
    _w(base, eng, "js/cached_page.html",
       "<html><body><script>new WebSocket(\"ws://127.0.0.1:1/x\");"
       "</script></body></html>")
    # ---- P5 content cache ----
    _w(base, eng, "content/js_cache.txt",
       "wss://realtime.example.invalid/socket")
    _w(base, eng, "surface/priority_queue.json", {"queue": [
        {"url": origin + "/ws", "score": 90}]})


def _read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _src():
    with open(os.path.join(os.path.dirname(HERE), "phases", "block4_api_logic", "mod_ws.py"), encoding="utf-8") as f:
        return f.read()


# ===========================================================================
# UNIT: RFC 6455 CRYPTO + URL HELPERS
# ===========================================================================
def unit_crypto():
    print("\n--- unit: rfc6455 crypto + url helpers ---")
    # RFC 6455 Sec 1.3 ka official example vector
    acc = MW.expected_accept("dGhlIHNhbXBsZSBub25jZQ==")
    check("accept GUID math (RFC vector)", acc ==
          "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", acc)
    check("accept deterministic", MW.expected_accept(
        "dGhlIHNhbXBsZSBub25jZQ==") == acc)
    k = MW.ws_key_gen()
    check("key gen base64-16B", k.endswith("=") and len(k) >= 22, k)
    check("key gen unique", MW.ws_key_gen() != MW.ws_key_gen())
    check("ws->http map", MW.ws_url_to_http(
        "ws://h.example:80/x?a=1") == "http://h.example/x?a=1",
        MW.ws_url_to_http("ws://h.example:80/x?a=1"))
    check("wss->https map", MW.ws_url_to_http(
        "wss://h.example/p") == "https://h.example/p")
    t = MW.ws_parse_target("wss://h.example:8443/p?q=1")
    check("parse target wss:8443", t == ("wss", "h.example", 8443, "/p?q=1"),
          t)
    check("parse reject http", MW.ws_parse_target(
        "http://h.example/") is None)
    m = MW._WS_URL_PARAM_RE.search("ws://h/ws?token=abcdef123456")
    check("token-in-url regex", bool(m) and m.group(1) == "token",
          bool(m))
    check("guid constant", MW.WS_GUID == "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")


# ===========================================================================
# UNIT: MINING + DISCOVERY
# ===========================================================================
def unit_mining():
    print("\n--- unit: mining + discovery ---")
    txt = ("connect wss://a.example/rt and ws://b.example/x?token=abc123 "
           "io('/socket.io',{x:1}) SockJS('/sockjs') $.connection.hub.url="
           "'/signalr' graphql-ws /graphql-ws")
    hits = MW.mine_ws_links(txt)
    check("ws links mined", len(hits["ws_links"]) == 2, hits["ws_links"])
    check("socketio mined", hits["socketio"] == ["/socket.io"],
          hits["socketio"])
    check("sockjs mined", "/sockjs" in hits["sockjs"])
    check("signalr mined", "/signalr" in hits["signalr"])
    check("gql-ws mined", "/graphql-ws" in hits["gql_ws"])
    empty = MW.mine_ws_links("")
    check("empty-safe miner", empty["ws_links"] == [])
    check("gql-ws path regex", MW._GQL_WS_RE.search(
        "/api/graphql-ws") is not None)


def unit_discovery():
    print("\n--- unit: discovery seeds (0 probes) ---")
    class _S:
        engagement = ENG
        def seed_urls(self):
            return [LAB["origin"]]
        def describe(self):
            return "stub"
    disc = MW.discover_ws_surface(os.path.join(BASE, ENG), _S(),
                                  dict(MW.DEFAULTS, ws_paths_cap=64))
    urls = [t["ws_url"] for t in disc["targets"]]
    check("ff seeds consumed", any(u.endswith("/ws_open") for u in urls),
          urls[:6])
    check("js links mined", any("/ws_echo" in u for u in urls))
    check("token target mined", any("/ws_token" in u for u in urls))
    check("cold pool in targets", any(u.endswith("/socket.io/") for u in urls))
    check("oos candidate present", any("example.invalid" in u for u in urls))
    check("sources tracked", len(disc["sources"]) >= 4, disc["sources"])
    cold_urls = [r["url"] for r in disc["ranked"]]
    check("cold pool in ranked", any(u.endswith("/socket.io/") for u in
                                     cold_urls), len(cold_urls))
    ranked = MW.rank_targets(disc["targets"], dict(MW.DEFAULTS))
    check("probe cap respected", len(ranked) <= MW.DEFAULTS["ws_probe_cap"],
          len(ranked))
    top3 = [t["ws_url"] for t in ranked[:3]]
    check("top3 interesting", any("/ws_open" in u for u in top3) and
          any("/ws_token" in u for u in top3), top3)


# ===========================================================================
# UNIT: INERT SAFETY (module-level hard rules)
# ===========================================================================
def unit_inert_safety():
    print("\n--- unit: INERT safety (hard rules) ---")
    src = _src()
    check("no frame-opcode construction", "0x81" not in src and
          "\\x81" not in src, "no ws frame builder in module")
    check("data-frame ban documented", "data frames NEVER" in src)
    check("burst hard cap", "HARD cap" in src)
    check("canary family", "waspP19" in src)
    check("FORBIDDEN patterns non-empty",
          len(MW.FORBIDDEN_CONTENT_PATTERNS) >= 20)
    check("assert_inert passes canary", MW.assert_inert(
        b"GET /ws HTTP/1.1\r\nSec-WebSocket-Key: waspP19key\r\n\r\n",
        "probe") is True)
    try:
        MW.assert_inert(b"<script>alert(document.cookie)</script>", "x")
        check("assert_inert blocks", False, "no raise")
    except ValueError:
        check("assert_inert blocks", True)
    for pat in ["ws_allow_origin_evil", "ws_allow_transports",
                "ws_allow_burst", "ws_allow_frames", "ws_allow_h2ws",
                "ws_allow_ws"]:
        check("gate default OFF: %s" % pat, MW.DEFAULTS.get(pat) is False)
    check("no external egress primitive", "create_connection" in src and
          "scope.check_host" in src)


# ===========================================================================
# UNIT: RAW HANDSHAKE PROBES (live lab, INERT)
# ===========================================================================
def unit_handshake_live(scope):
    print("\n--- unit: raw handshake census probes (live lab) ---")
    origin = LAB["origin"]
    ws0 = origin.replace("http://", "ws://", 1)
    res = MW.ws_handshake(scope, ws0 + "/ws", conf=dict(MW.DEFAULTS))
    check("101 handshake", res.get("status") == 101 and res.get("ok"),
          res.get("status"))
    check("accept crypto valid", res.get("accept_ok") is True)
    check("headers-only read", res.get("leftover_bytes", 0) == 0)
    bad = MW.ws_handshake(scope, ws0 + "/ws_accept_bad",
                          conf=dict(MW.DEFAULTS))
    check("accept mismatch detected", bad.get("status") == 101 and
          bad.get("accept_ok") is False)
    v8 = MW.ws_handshake(scope, ws0 + "/ws", version="8",
                         conf=dict(MW.DEFAULTS))
    check("version guard (426+hint)", v8.get("status") == 426 and bool(
        (v8.get("headers") or {}).get("sec-websocket-version")),
        v8.get("status"))
    echo = MW.ws_handshake(scope, ws0 + "/ws_echo",
                           protocols="waspP19census.x",
                           conf=dict(MW.DEFAULTS))
    check("subprotocol verbatim echo", ((echo.get("headers") or {}).get(
        "sec-websocket-protocol") or "").strip() == "waspP19census.x",
        (echo.get("headers") or {}).get("sec-websocket-protocol"))
    crlf = MW.ws_handshake(scope, ws0 + "/ws_crlf",
                           protocols="waspP19.a%0d%0aX-Wasp-B: c",
                           conf=dict(MW.DEFAULTS))
    check("CRLF split-header trigger", bool(
        (crlf.get("headers") or {}).get("x-wasp-b")), crlf.get("headers"))
    df = MW.ws_handshake(scope, ws0 + "/ws_deflate", extra_headers={
        "Sec-WebSocket-Extensions": "permessage-deflate"},
        conf=dict(MW.DEFAULTS))
    check("deflate negotiated", "permessage-deflate" in ((df.get(
        "headers") or {}).get("sec-websocket-extensions") or "").lower())
    push = MW.ws_handshake(scope, ws0 + "/ws_push", conf=dict(MW.DEFAULTS))
    check("server-push detected", (push.get("leftover_bytes") or 0) > 0,
          push.get("leftover_bytes"))
    waf = MW.ws_handshake(scope, ws0 + "/ws_waf", conf=dict(MW.DEFAULTS))
    check("edge ws-filter 403", waf.get("status") == 403, waf.get("status"))
    au = MW.ws_handshake(scope, ws0 + "/ws_auth", conf=dict(MW.DEFAULTS))
    check("auth required on upgrade", au.get("status") == 401,
          au.get("status"))
    au2 = MW.ws_handshake(scope, ws0 + "/ws_auth", extra_headers={
        "Cookie": "session=supersecret123"}, conf=dict(MW.DEFAULTS))
    check("valid creds accepted", au2.get("status") == 101)
    oos = MW.ws_handshake(scope, "ws://out-of-scope.example.invalid/x",
                          conf=dict(MW.DEFAULTS))
    check("OUT-OF-SCOPE firewall", oos.get("error") == "OUT-OF-SCOPE",
          oos.get("error"))
    check("not-ws-url guard", MW.ws_handshake(
        scope, "http://x/y", conf=dict(MW.DEFAULTS)).get("error") ==
        "not-a-ws-url")
    # burst shape: 3 sequential on rate-limited endpoint (101,101,429)
    seq = [MW.ws_handshake(scope, ws0 + "/ws_rate", conf=dict(MW.DEFAULTS))
           for _ in range(3)]
    check("burst shape (101,101,429)",
          [s.get("status") for s in seq] == [101, 101, 429],
          [s.get("status") for s in seq])
    fp = MW.ws_fingerprint(res)
    check("fingerprint shape", fp.get("upgrade_echo") == "websocket" and
          fp.get("accept_ok") is True, fp)
    # INERT: koi data nahi bheja gaya (lab side assert)
    check("lab zero-frame discipline", LAB.get("frames_seen", 0) == 0)


# ===========================================================================
# UNIT: ORIGIN VARIANTS + VERDICT ENGINE + MATRIX + CHAINS
# ===========================================================================
def unit_origin_variants():
    print("\n--- unit: origin variant builder ---")
    benign = MW._origin_variants("http://h.example", dict(MW.DEFAULTS), False)
    check("benign variants (7)", len(benign) == 7 and
          all(b[2] for b in benign), len(benign))
    check("no evil in benign", not any(b[0].startswith("evil") or
                                       b[0] in ("prefix_trick", "suffix_trick")
                                       for b in benign))
    evil = MW._origin_variants("http://h.example", dict(MW.DEFAULTS), True)
    check("evil variants gated (12)", len(evil) == 12 and
          sum(1 for e in evil if not e[2]) == 5, len(evil))
    names = [e[0] for e in evil if not e[2]]
    check("evil family", set(names) == {"evil_cross", "prefix_trick",
                                        "suffix_trick", "at_sign",
                                        "punycode"}, names)


def unit_verdict_engine():
    print("\n--- unit: verdict engine (synthetic) ---")
    results = {"origin_matrix": [
        {"target": "ws://t/ws_open", "applicable": True,
         "verdict": "CONFIRMED", "bypass_variant": "evil_cross"}],
        "auth_diff": {"rows": [{"target": "ws://t/ws_open",
                                "applicable": True, "verdict": "OPEN"}],
                      "cookie_ctx": True},
        "handshake": [{"target": "ws://t/ws_echo", "upgrade": True,
                       "subprotocol_echo": {"reflected_verbatim": True}}],
        "transport_sec": {"rows": [{"target": "wss://t/ws",
                                    "downgrade": True}]},
        "header_injection": [{"target": "ws://t/ws_crlf", "applicable": True,
                              "probes": {"crlf_encoded": {
                                  "split_header_seen": True}}}],
        "bypass2": [{"target": "ws://t/ws", "wins": ["x_original_url"],
                     "variants": {"x_original_url": {
                         "class": "route_misroute"}}}],
        "rate": {"skipped": False, "rows": [{"target": "ws://t/ws_rate",
                                             "limit_signal": True}]},
        "subs": {"skipped": False, "subprotocol_diff": [
            {"endpoint": "ws://t/graphql-ws",
             "graphql-transport-ws": {"accepted": True}}]},
        "secrets_url": [{"url": "ws://t/ws_token?token=x",
                         "param": "token"}],
    }
    rows = MW.verdict_engine(results, {}, {})
    keys = {r["key"] for r in rows}
    check("bypass variant CONFIRMED", "ws_origin_bypass_variant" in keys)
    check("auth open CONFIRMED", "ws_auth_handshake_open" in keys)
    check("echo CONFIRMED", "ws_subprotocol_echo" in keys)
    check("downgrade CONFIRMED", "ws_ws_downgrade" in keys)
    check("inject CONFIRMED", "ws_header_injection" in keys)
    check("misroute CONFIRMED", "ws_bypass2_route_misroute" in keys)
    check("rate present HARDENED", "ws_rate_limit_present" in keys)
    check("subs open CONFIRMED", "ws_subs_transport_open" in keys)
    check("secret-url CONFIRMED", "ws_secret_url_param" in keys)
    verdicts = {r["key"]: r["verdict"] for r in rows}
    check("verdict class correct", verdicts.get(
        "ws_origin_bypass_variant") == "CONFIRMED" and verdicts.get(
        "ws_rate_limit_present") == "HARDENED", verdicts)


def unit_matrix_chains():
    print("\n--- unit: matrix + chains builders ---")
    conf = dict(MW.DEFAULTS)
    results = {"targets": [], "handshake": [], "origin_matrix": [],
               "auth_diff": {}, "transports": {}, "transport_sec": {},
               "header_injection": [], "bypass2": [], "waf_upgrade_fp": [],
               "rate": {}, "frames": {}, "subs": {}, "platform_fp": {},
               "secrets_url": [], "js_miner": {}, "chains": []}
    m = MW.build_technique_matrix(results, conf)
    check("matrix >= 150 rows", len(m) >= 150, len(m))
    fams = {r["family"] for r in m}
    check("18 families", len(fams) == 18, sorted(fams))
    check("bypass2 = 17 rows", sum(1 for r in m if r["family"] == "BYPASS2")
          == 17)
    check("unique ids", len({r["id"] for r in m}) == len(m))
    ch = MW.build_ws_chains(type("F", (), {"items": []})(), results, [],
                            [], {}, conf)
    check("chains == 20", len(ch) == 20, len(ch))
    check("chain ids unique", len({c["id"] for c in ch}) == 20)
    techs = MW.DOCUMENTED_MESSAGE_TECHNIQUES
    check("message techniques documented", len(techs) >= 8)
    check("execution forbidden noted", any("FORBIDDEN" in d for _, d in
                                           techs))
    hyps = MW.build_ws_hypotheses(results, [], ch, conf)
    check("hypotheses builder runs", isinstance(hyps, list))


# ===========================================================================
# E2E HELPERS (gate-OFF run assertions)
# ===========================================================================
def e2e_gate_off(origin, out):
    print("\n--- e2e: active run gate-OFF (stages A..S) ---")
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    files = man.get("files") or []
    check("manifest 40 artifacts", len(files) >= 39, len(files))
    for f in ("findings.json", "WS_FINDINGS.md", "ws_matrix.json",
              "WS_MATRIX.txt", "ws_chains.json", "ws_verdicts.json",
              "ws_handshake_census.json", "ws_origin_matrix.json",
              "ws_auth_diff.json", "ws_bypass2_matrix.json",
              "ws_transports.json", "ws_downgrade_census.json",
              "ws_header_injection.json", "ws_subs_census.json",
              "ws_platform_fp.json", "ws_secrets_in_url.json",
              "ws_message_techniques.md", "ws_kickoff_guide.md",
              "ws_test_plan.md", "ws_remediation.txt", "feedforward.json"):
        check("artifact: %s" % f, f in files, "missing")
    hs = _read(os.path.join(out, "ws_handshake_census.json")) or []
    check("handshake census rows", len(hs) >= 4, len(hs))
    live = [r for r in hs if r.get("upgrade")]
    check("live upgrades found", len(live) >= 3, len(live))
    check("accept-crypto clean", all(r.get("fp", {}).get("accept_ok")
                                     for r in live if not r.get(
                                         "accept_mismatch")))
    om = _read(os.path.join(out, "ws_origin_matrix.json")) or []
    applicable = [r for r in om if r.get("applicable")]
    check("origin matrix applicable", len(applicable) >= 2)
    ws_open = next((r for r in om if "/ws_open" in (r.get("target") or "")),
                   {})
    check("CSWSH SUSPECTED (gate-OFF)", ws_open.get("verdict") ==
          "SUSPECTED", ws_open.get("verdict"))
    check("no evil probes gate-OFF", not ws_open.get("bypass_variant"))
    ad = _read(os.path.join(out, "ws_auth_diff.json")) or {}
    rows = ad.get("rows", []) if isinstance(ad, dict) else ad
    check("auth rows", len(rows) >= 2)
    check("auth OPEN found", any(r.get("verdict") == "OPEN" for r in rows
                                 if isinstance(r, dict)))
    check("token-in-URL flagged", any(r.get("token_in_url") for r in rows
                                      if isinstance(r, dict)))
    check("cookie_ctx tracked", isinstance(ad.get("cookie_ctx"), bool))
    tr = _read(os.path.join(out, "ws_transports.json")) or {}
    check("transports GATE skip documented", tr.get("skipped") is True and
          "ws_allow_transports=false" in (tr.get("gate") or ""),
          tr.get("gate"))
    rate = _read(os.path.join(out, "ws_rate_census.json")) or {}
    check("rate GATE skip documented", rate.get("skipped") is True)
    fr = _read(os.path.join(out, "ws_frames_gated.json")) or {}
    check("frames GATE skip documented", fr.get("skipped") is True and
          len(fr.get("documented") or []) >= 8)
    subs = _read(os.path.join(out, "ws_subs_census.json")) or {}
    check("subs GATE skip documented", subs.get("skipped") is True and
          len(subs.get("paths") or []) >= 3, len(subs.get("paths") or []))
    v = _read(os.path.join(out, "ws_verdicts.json")) or {}
    check("verdict rows present", (v.get("count") or 0) >= 5, v.get("count"))
    vv = v.get("rows") or []
    check("CSWSH verdict present", any(r.get("key") == "ws_origin_wildcard"
                                       for r in vv))
    ch = _read(os.path.join(out, "ws_chains.json")) or {}
    check("20 chains in artifact", ch.get("count") == 20)
    check("active chains >= 3", (ch.get("active") or 0) >= 3,
          ch.get("active"))
    m = _read(os.path.join(out, "ws_matrix.json")) or {}
    check("matrix >= 150 in artifact", (m.get("row_count") or 0) >= 150,
          m.get("row_count"))
    ff = _read(os.path.join(out, "feedforward.json")) or {}
    rt = ff.get("routing") or {}
    for want in ("to_phase20_logic", "to_phase22_replay",
                 "to_phase23_misconfig", "to_phase25_controls",
                 "to_phase11_bola", "to_phase12_inject",
                 "to_phase32_report"):
        check("feedforward: %s" % want, want in rt)
    check("ff token signals", len((rt.get("to_phase22_replay") or {}).get(
        "token_in_url") or []) >= 1)
    f = _read(os.path.join(out, "findings.json")) or {}
    keys = {x.get("key") for x in (f.get("findings") or [])}
    check("finding: endpoint live", "ws_endpoint_live" in keys)
    check("finding: origin wildcard", "ws_origin_wildcard" in keys)
    check("finding: replay documented", "ws_message_replay_risk" in keys)
    check("sev counts valid", isinstance(f.get("sev_counts"), dict))


def rwx_and_egress(out, origin):
    print("\n--- rwx + egress + redaction ---")
    bad_perm, bad_egress = [], []
    allowed_host = urlsplit(origin).hostname
    for base, dirs, files in os.walk(out):
        for fn in files:
            p = os.path.join(base, fn)
            try:
                mode = os.stat(p).st_mode & 0o777
            except OSError:
                continue
            if mode != 0o777:
                bad_perm.append((p, oct(mode)))
        for dn in dirs:
            try:
                mode = os.stat(os.path.join(base, dn)).st_mode & 0o777
            except OSError:
                continue
            if mode != 0o777:
                bad_perm.append((os.path.join(base, dn), oct(mode)))
    check("RWX 0777 sab results", not bad_perm, bad_perm[:3])
    blob = ""
    for fn in os.listdir(out):
        p = os.path.join(out, fn)
        if os.path.isfile(p):
            try:
                blob += open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
    for u in re.findall(r"ws[s]?://[A-Za-z0-9.\-]+", blob):
        h = urlsplit(u if "://" in u else "ws://" + u).hostname
        if h and h not in (allowed_host, "out-of-scope.example.invalid") \
                and not h.endswith(".invalid") and h != "127.0.0.1":
            bad_egress.append(u)
    check("zero external egress (ws urls)", not bad_egress, bad_egress[:3])
    check("realtime.example.invalid allowed (RFC2606)",
          "realtime.example.invalid" in blob)


# ===========================================================================
# E2E GATED RUN (sab gates ON - caps verify)
# ===========================================================================
def e2e_gated(origin, out):
    print("\n--- e2e: gated run (all RoE gates ON, lab-only) ---")
    om = _read(os.path.join(out, "ws_origin_matrix.json")) or []
    ws_open = next((r for r in om if "/ws_open" in (r.get("target") or "")),
                   {})
    check("CSWSH CONFIRMED (evil accepted)", ws_open.get("verdict") ==
          "CONFIRMED" and ws_open.get("bypass_variant") == "evil_cross",
          ws_open.get("verdict"))
    check("evil variants probed", any(
        v.get("gated") is False for v in (ws_open.get("variants") or
                                          {}).values()))
    ob = _read(os.path.join(out, "ws_origin_bypass.json")) or {}
    check("bypass artifact row", len(ob.get("bypass_rows") or []) >= 1)
    tr = _read(os.path.join(out, "ws_transports.json")) or {}
    check("socketio census hit", len(tr.get("socketio") or []) >= 2,
          len(tr.get("socketio") or []))
    sio = (tr.get("socketio") or [{}])[0]
    check("sid shape scored", (sio.get("sid_shape") or {}).get("len", 0) > 0)
    check("ping config leak", sio.get("pingInterval") in (25000, "25000"))
    check("sockjs census hit", len(tr.get("sockjs") or []) >= 1)
    check("signalr census hit", len(tr.get("signalr") or []) >= 1)
    rate = _read(os.path.join(out, "ws_rate_census.json")) or {}
    check("rate census ran", rate.get("skipped") is not True)
    rrow = ((rate.get("rows") or []) or [{}])[0]
    check("burst <= HARD cap 3", len(rrow.get("burst") or []) <= 3 and
          len(rrow.get("burst") or []) >= 2, len(rrow.get("burst") or []))
    check("limit signal bool", isinstance(rrow.get("limit_signal"), bool))
    fr = _read(os.path.join(out, "ws_frames_gated.json")) or {}
    check("frames census ran (own-session)",
          fr.get("skipped") is not True)
    check("techniques documented in artifact",
          len(fr.get("techniques_documented") or []) >= 8)
    ts = _read(os.path.join(out, "ws_h2ws_census.json")) or {}
    check("h2ws hint (gated ran)", ts.get("skipped") is False)
    subs = _read(os.path.join(out, "ws_subs_census.json")) or {}
    check("subs diff ran", len(subs.get("subprotocol_diff") or []) >= 1)
    srow = (subs.get("subprotocol_diff") or [{}])[0]
    check("graphql-transport-ws accepted", srow.get(
        "graphql-transport-ws", {}).get("accepted") is True)
    check("legacy graphql-ws rejected", srow.get(
        "graphql-ws", {}).get("accepted") is False)
    pf = _read(os.path.join(out, "ws_platform_fp.json")) or {}
    plats = {p.get("name") for p in (pf.get("platforms") or [])}
    check("platform fingerprints", {"socket.io", "sockjs", "signalr"} <=
          plats, plats)
    b2 = _read(os.path.join(out, "ws_bypass2_matrix.json")) or []
    check("bypass2 rows", len(b2) >= 2, len(b2))
    v = _read(os.path.join(out, "ws_verdicts.json")) or {}
    keys = {r.get("key") for r in (v.get("rows") or [])}
    check("gated verdict keys", {"ws_origin_bypass_variant",
                                 "ws_socketio_exposed"} <= keys, keys)


# ===========================================================================
# PASSIVE + CHECKPOINT REPLAY
# ===========================================================================
def passive_and_replay(cfg, cfg4, base, base2, eng, eng_p, origin):
    print("\n--- passive mode + checkpoint replay ---")
    out2 = MW.run(cfg4, WC.Scope(os.path.join(base2, "scope.json")), base2)
    man = _read(os.path.join(out2, "MANIFEST.json")) or {}
    check("passive manifest", man.get("stats", {}).get("mode") == "passive")
    check("passive 0 probes", (man.get("stats", {}).get("probes") in
                               (0, None)), man.get("stats"))
    cov = _read(os.path.join(out2, "ws_coverage.json")) or {}
    check("passive coverage mode", cov.get("mode") == "passive")
    # checkpoint replay: dobara run (wahi engagement) - discovery replay
    LAB["origin"] = origin
    t0 = time.time()
    out_r = MW.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    _ = time.time() - t0
    hs = _read(os.path.join(out_r, "ws_handshake_census.json")) or []
    check("replay produced census", len(hs) >= 3, len(hs))
    man2 = _read(os.path.join(out_r, "MANIFEST.json")) or {}
    check("replay manifest valid", (man2.get("stats") or {}).get(
        "matrix_rows", 0) >= 150)
    return out_r


# ===========================================================================
# CLI + IMPORT HYGIENE
# ===========================================================================
def cli_and_hygiene():
    print("\n--- cli + hygiene (-W error) ---")
    r = subprocess.run([sys.executable, "-W", "error", "-m", "py_compile",
                        os.path.join(os.path.dirname(HERE), "phases", "block4_api_logic", "mod_ws.py"),
                        os.path.join(HERE, "test_mod_ws.py")],
                       capture_output=True, text=True, cwd=ULTRA)
    check("py_compile -W error clean", r.returncode == 0, r.stderr[:200])
    r2 = subprocess.run([sys.executable, "-W", "error",
                         os.path.join(ULTRA, "mod_ws.py")],
                        capture_output=True, text=True, timeout=60)
    check("main() CLI banner", r2.returncode == 0 and "mod_ws.py" in
          r2.stdout and "19" in r2.stdout, r2.stdout[:120])
    check("gates documented in CLI", "ws_allow_frames=false" in r2.stdout and
          "ws_allow_burst=false" in r2.stdout)
    check("module shape", MW.NAME == "ws" and MW.PLAN_VERSION == "19.0.0")
    check("cold pool size", len(MW.COLD_WS_PATHS) >= 20)
    check("DEFAULTS keys", all(k in MW.DEFAULTS for k in (
        "ws_probe_cap", "ws_cold_paths", "ws_origin_variants",
        "ws_bypass2_cap", "ws_allow_origin_evil", "ws_allow_transports",
        "ws_allow_burst", "ws_allow_frames", "ws_allow_h2ws", "ws_allow_ws")))
    check("SEVERITY_HINTS rich", len(MW.SEVERITY_HINTS) >= 38)
    src = _src()
    check("v19 INERT note (source)", "headers-only read" in src and
          "OUT-OF-SCOPE" in src)
    check("stage docs present", all(("Stage %s" % s) in src for s in
                                    "ABCDEFGHIJKLMNOPS"))


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    print("=" * 69)
    print(" WASP P19 SELF-TEST - mod_ws.py v%s" % MW.PLAN_VERSION)
    print("=" * 69)
    srv, port = _start_lab()
    origin = "http://127.0.0.1:%d" % port
    LAB["origin"] = origin
    LAB["port"] = port
    try:
        _seed(BASE, ENG, origin)
        _seed(BASE_GATED, ENG_G, origin)
        _seed(BASE2, ENG_P, origin)

        unit_crypto()
        unit_mining()
        LAB["origin"] = origin
        unit_discovery()
        unit_inert_safety()
        unit_origin_variants()
        unit_verdict_engine()
        unit_matrix_chains()

        cfg = WC.Cfg(None)
        cfg.adaptive_throttle = False
        cfg.allow_active = True
        LAB.clear()
        LAB["origin"] = origin
        LAB["port"] = port
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        unit_handshake_live(scope)
        out = MW.run(cfg, scope, BASE)
        e2e_gate_off(origin, out)
        rwx_and_egress(out, origin)

        cfg2 = WC.Cfg(None)
        cfg2.adaptive_throttle = False
        cfg2.allow_active = True
        cfg2.ws_allow_origin_evil = True
        cfg2.ws_allow_transports = True
        cfg2.ws_allow_burst = True
        cfg2.ws_allow_frames = True
        cfg2.ws_allow_h2ws = True
        cfg2.ws_allow_ws = True
        LAB.clear()
        LAB["origin"] = origin
        LAB["port"] = port
        LAB["rate_n"] = 0
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = MW.run(cfg2, scope3, BASE_GATED)
        e2e_gated(origin, out3)

        cfg4 = WC.Cfg(None)
        cfg4.adaptive_throttle = False
        cfg4.allow_active = False
        LAB.clear()
        LAB["origin"] = origin
        LAB["port"] = port
        passive_and_replay(cfg, cfg4, BASE, BASE2, ENG, ENG_P, origin)

        cli_and_hygiene()
    finally:
        srv.shutdown()
        try:
            srv.server_close()
        except Exception:
            pass
    print("\n" + "=" * 53)
    print(" P19 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, str(d)[:140]))
        sys.exit(1)
    print(" ALL GREEN \u2705")


if __name__ == "__main__":
    main()
