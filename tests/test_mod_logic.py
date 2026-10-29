#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P20 SELF-TEST SUITE - mod_logic.py v20.0.0 FULL ULTRA PRO MAX (P20)
=============================================================================
 Mock commerce lab + full assertion suite:
   - Unit tests (logic shape regexes / form miner / canary / INERT guard /
     value-matrix / bypass2 variants / verdict engine / matrix / chains /
     hypotheses / playbooks)
   - Param census unit (live lab: client-trust price + CSRF census + state
     shapes) - sab INERT GET probes
   - Active run e2e gate-OFF (stages A..T) + RoE-gate-skip documentation
   - Gated run (price + race + workflow + echo + coupon + role gates ON) -
     hard caps ke andar (race 2-sequential, coupon 30 probes)
   - Artifact integrity (40 outputs, matrix >= 150 rows, chains == 20)
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (bodies sirf shape/sha1/booleans - content stored nahi)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi REAL transaction/
 redeem/transfer/parallel-burst NAHI - sab canary waspP20 family.
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

import mod_logic as ML                                            # noqa: E402
import wasp_core as WC                                            # noqa: E402

BASE = os.path.join(HERE, "p20_test_base")
BASE_GATED = os.path.join(HERE, "p20_test_base_gated")
BASE2 = os.path.join(HERE, "p20_test_base_passive")
ENG = "p20lab"
ENG_G = "p20lab2"
ENG_P = "p20labp"

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
    return open(os.path.join(os.path.dirname(HERE), "phases", "block4_api_logic", "mod_logic.py"), encoding="utf-8",
                errors="ignore").read()




# ===========================================================================
# MOCK COMMERCE LAB (detection-only sim - sab responses INERT)
# ===========================================================================
LAB = {"requests": 0}


def _j(self, code, obj, hdrs=None):
    b = json.dumps(obj).encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    self.wfile.write(b)


def _html(self, code, s, hdrs=None):
    b = s.encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    self.wfile.write(b)


CHECKOUT_HTML = """<html><head><title>Checkout - shop</title></head><body>
<h1>Checkout</h1>
<div class="echo">ref: %(ref)s</div>
<form method="POST" action="/api/order">
  <input type="hidden" name="sku" value="SKU-8811">
  <input type="hidden" name="qty" value="1">
  <input type="hidden" name="total" value="199.00">
  <input type="hidden" name="currency" value="INR">
  <input type="text" name="card_name">
  <button type="submit">Place shop request</button>
</form>
<p>Shipping address step 2 of the shop flow.</p>
</body></html>"""

ORDER_HTML = """<html><head><title>Shop order</title></head><body>
<h1>Shop order console</h1>
<form method="POST" action="/order/open">
  <input type="hidden" name="csrf_token" value="tok0001122334455">
  <input type="hidden" name="amount" value="aW90b3RhbDE5OTA0MzIyMw.sig0987654321abcd">
  <input type="hidden" name="order_id" value="ord_7712">
</form>
<p>Review status panel. Staff tools: refund-approve console listed here.
Confirm your order details before submit.</p>
</body></html>"""

CART_HTML = """<html><head><title>Cart</title></head><body>
<h1>Cart</h1>
<form method="POST" action="/cart/add">
  <input type="hidden" name="test_sku" value="TEST-ITEM-01">
  <input type="hidden" name="flow_state" value="st190.transition.v1.state-blob-000111222333">
  <input type="hidden" name="qty" value="1">
</form>
</body></html>"""

STEP_HTML = """<html><head><title>Step %(n)s</title></head><body>
<h1>Checkout step %(n)s</h1>
<p>Step %(n)s content: enter details for this stage of the shop flow.
This page is reachable at step %(n)s.</p>
</body></html>"""

HOME_HTML = """<html><head><title>Shop home</title></head><body>
<h1>Shop</h1>
<p>wocommerce-style storefront (powered by woocommerce class stack).</p>
<a href="/checkout">checkout</a> <a href="/order">order</a>
<a href="/cart">cart</a> <a href="/api/redeem">redeem</a>
<a href="/api/coupon">coupon</a> <a href="/api/transfer">transfer</a>
</body></html>"""


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _qs(self):
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True)

    def _echo_vals(self):
        q = self._qs()
        return " ".join("%s=%s" % (k, v[0][:60])
                        for k, v in sorted(q.items()) if k != "_")

    def do_GET(self):
        LAB["requests"] = LAB.get("requests", 0) + 1
        u = urlsplit(self.path)
        p = u.path
        q = self._qs()
        orig = self.headers.get("X-Original-URL", "")
        # edge sim: dot-segment + semicolon literal-block (403/404)
        if "/./" in p:
            return _j(self, 403, {"detail": "edge block"})
        if ";" in p:
            return _j(self, 404, {"detail": "no route"})
        # edge misroute sim: X-Original-URL on /checkout -> serve step 3
        if orig and p == "/checkout":
            return _html(self, 200, STEP_HTML % {"n": 3})
        if p == "/":
            return _html(self, 200, HOME_HTML)
        if p == "/checkout":
            return _html(self, 200, CHECKOUT_HTML % {"ref": self._echo_vals()})
        if p.startswith("/checkout/step/"):
            try:
                n = int(p.rsplit("/", 1)[1])
            except Exception:
                n = 1
            return _html(self, 200, STEP_HTML % {"n": max(1, min(9, n))})
        if p == "/checkout/success":
            return _html(self, 200, STEP_HTML % {"n": 5})
        if p.startswith("/checkout/") and \
                p.split("/")[2] in ("cart", "address", "shipping", "payment",
                                    "review", "confirm", "complete"):
            st = p.split("/")[2]
            return _html(self, 200, "<html><body><h1>Checkout %s</h1>"
                         "<p>Stage %s page of the shop flow, rich content "
                         "block for census. This page contains enough body "
                         "text to be counted as nontrivial content by the "
                         "census engine and it renders the %s stage "
                         "properly for the user.</p></body></html>"
                         % (st, st, st))
        if p == "/order":
            return _html(self, 200, ORDER_HTML,
                         hdrs={"X-RateLimit-Limit": "60",
                               "X-RateLimit-Remaining": "59"})
        if p == "/order/open":
            return _j(self, 200, {"accepted": True, "state": "open-shape",
                                  "received": self._echo_vals()})
        if p == "/api/order":
            return _j(self, 422, {"error": "validation",
                                  "detail": "order shape rejected"})
        if p == "/api/redeem":
            idem = self.headers.get("Idempotency-Key", "")
            hdrs = {"X-RateLimit-Limit": "10",
                    "X-RateLimit-Remaining": "9"}
            if idem:
                hdrs["X-Idempotency-Key"] = "echo-" + idem[:24]
            return _j(self, 400, {"error": "invalid_code"}, hdrs=hdrs)
        if p == "/redeem/open":
            return _j(self, 200, {"accepted": True, "state": "open-shape",
                                  "received": self._echo_vals()})
        if p == "/api/coupon":
            return _j(self, 400, {"error": "invalid_code"},
                      hdrs={"X-RateLimit-Limit": "10",
                            "X-RateLimit-Remaining": "9"})
        if p == "/coupon/apply_open":
            return _j(self, 200, {"applied": True, "discount_pct": 100,
                                  "state": "open-shape"})
        if p == "/api/credits":
            return _j(self, 200, {"ok": True,
                                  "points": (q.get("points") or ["0"])[0],
                                  "state": "open-shape"})
        if p == "/api/transfer":
            return _j(self, 200, {"ok": True, "queued": False})
        if p == "/api/pay":
            idem = self.headers.get("Idempotency-Key", "")
            return _j(self, 200, {"ok": True},
                      hdrs={"X-Idempotency-Key": "echo-" + idem[:24]})
        if p == "/api/admin":
            if "role" in q or "is_admin" in q:
                return _j(self, 200, {"role": (q.get("role") or
                                               q.get("is_admin") or [""])[0],
                                      "granted": "canary-echo"})
            return _j(self, 403, {"error": "forbidden"})
        if p == "/profile":
            return _html(self, 200,
                         "<html><body><h1>Profile</h1><div>%s</div>"
                         "</body></html>" % self._echo_vals())
        if p == "/cart":
            return _html(self, 200, CART_HTML)
        if p == "/cart/add":
            return _j(self, 200, {"ok": True})
        if p == "/logout":
            return _j(self, 200, {"ok": True})
        return _j(self, 404, {"error": "not found"})

    def do_POST(self):
        LAB["requests"] = LAB.get("requests", 0) + 1
        ln = int(self.headers.get("Content-Length") or 0)
        if ln:
            self.rfile.read(min(ln, 4096))
        return _j(self, 404, {"error": "not found"})


def _start_lab():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, port




# ===========================================================================
# SEED FIXTURES (13-module feedforward -> P20 guide seeds)
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
        "authorization_reference": "P20 selftest SOW v1",
        "targets": [origin],
        "notes": "no-DoS; detection-only INERT lab; gates lab-only"})
    # ---- P2 understand (payment forms + forms.json) ----
    _w(base, eng, "understand/feedforward.json", {"routing": {
        "to_phase20_business": {"payment_forms": [origin + "/checkout"],
                                "note": "payment-classes forms"}}})
    _w(base, eng, "understand/forms.json", [
        {"action": origin + "/checkout", "method": "POST",
         "classes": ["payment"]},
        {"action": origin + "/cart", "method": "POST"}])
    # ---- P5 content (endpoints) ----
    _w(base, eng, "content/api_endpoints.txt", "\n".join([
        origin + "/api/redeem", origin + "/api/coupon",
        origin + "/api/credits", origin + "/coupon/apply_open",
        origin + "/order/open", origin + "/redeem/open",
        origin + "/checkout?step=2"]) + "\n")
    _w(base, eng, "content/all_found.txt", "\n".join([
        origin + "/order", origin + "/checkout"]) + "\n")
    # ---- P8 surface (priority queue) ----
    _w(base, eng, "surface/priority_queue.json", {"queue": [
        {"url": origin + "/checkout", "score": 90},
        {"url": origin + "/order", "score": 85}]})
    # ---- P7 js (authz hints + redirects artifacts) ----
    _w(base, eng, "js/feedforward.json", {"routing": {
        "to_phase20_logic": {"hints": "authz_client_hints.txt",
                             "redirects": "client_redirects.txt"}}})
    _w(base, eng, "js/authz_client_hints.txt", "\n".join([
        origin + "/profile?field=role", origin + "/profile"]) + "\n")
    _w(base, eng, "js/client_redirects.txt", origin + "/checkout\n")
    # ---- P10 sessions ----
    _w(base, eng, "sessions/feedforward.json", {"routing": {
        "to_phase20_logic": {"logout_endpoints": origin + "/logout",
                             "concurrent_cap": 3,
                             "cookie_toss_surface": False}}})
    # ---- P11 access (confirmed IDOR objects) ----
    _w(base, eng, "access/feedforward.json", {"routing": {
        "to_phase20_logic": {"confirmed_objects": [origin + "/order",
                                                   origin + "/api/transfer"],
                             "note": "idor = business-logic abuse targets"}}})
    # ---- P12 inject ----
    _w(base, eng, "inject/feedforward.json", {"routing": {
        "to_phase20_logic": {"sqli_confirmed": [origin + "/api/coupon"],
                             "deser_hints": []}}})
    # ---- P14 client ----
    _w(base, eng, "client/feedforward.json", {"routing": {
        "to_phase20_logic": {"state_change_writes": [origin + "/order"],
                             "note": "state-changing client writes"}}})
    # ---- P16 files ----
    _w(base, eng, "files/feedforward.json", {"routing": {
        "to_phase20_logic": {"size_unlimited": [origin + "/cart"],
                             "overwrite_endpoints": []}}})
    # ---- P17 api (mass assignment ops) ----
    _w(base, eng, "api/feedforward.json", {"routing": {
        "to_phase20_logic": {"mass_assign_ops": [origin + "/api/admin"]}}})
    # ---- P18 graphql (field authz + writable sensitive) ----
    _w(base, eng, "graphql/feedforward.json", {"routing": {
        "to_phase20_logic": {"field_authz_confirmed": [origin + "/profile"],
                             "mutation_order_models": [origin + "/profile"],
                             "writable_sensitive_inputs": [origin + "/profile",
                                                           origin + "/api/admin"]}}})
    # ---- P19 ws (open channels + message techniques) ----
    _w(base, eng, "ws/feedforward.json", {"routing": {
        "to_phase20_logic": {"ws_auth_open": True,
                             "message_techniques": ["message_injection",
                                                    "replay",
                                                    "sid_hijack"],
                             "subs_channels": [origin + "/checkout"]}}})




# ===========================================================================
# UNIT TESTS - shapes / miner / canary / INERT
# ===========================================================================
def unit_shapes():
    print("\n--- unit: logic shape regexes ---")
    c = ML.classify_logic_path("http://x.example.invalid/api/redeem")
    check("verb: redeem", c["verb"] == "redeem", c)
    c = ML.classify_logic_path("http://x.example.invalid/checkout/step/2")
    check("verb: checkout + workflow_url", c["verb"] == "checkout" and
          c["has_workflow_url"], c)
    c = ML.classify_logic_path("http://x.example.invalid/coupon/apply")
    check("verb: coupon/apply", c["verb"] in ("coupon", "apply"), c)
    check("price shape on /order/price", ML.classify_logic_path(
        "http://x.example.invalid/order/price")["has_price_shape"])
    check("state shape on /order/status", ML.classify_logic_path(
        "http://x.example.invalid/order/status")["has_state_shape"])
    check("non-verb path score 1", ML.classify_logic_path(
        "http://x.example.invalid/about")["verb"] is None)
    rows = ML.param_census_from_url("http://x.invalid/a?price=1&step=2"
                                    "&role=x&code=y&qty=3&other=1")
    cls = {r["param"]: r["class"] for r in rows}
    check("param class price", cls.get("price") == "price", cls)
    check("param class state", cls.get("step") == "state", cls)
    check("param class role", cls.get("role") == "role", cls)
    check("param class coupon", cls.get("code") == "coupon", cls)
    check("param class qty", cls.get("qty") == "qty", cls)


def unit_miner():
    print("\n--- unit: form/param miner ---")
    html = ('<form method="POST" action="/api/order">'
            '<input type="hidden" name="total" value="199.00">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '<input type="hidden" name="state" value="'
            'bbbbbbbbbbbbbbbbbbbbbb.ccccdddddeee">'
            '<input type="hidden" name="role" value="x">'
            '<input type="hidden" name="coupon_code" value="">'
            '<input type="hidden" name="qty" value="1"></form>')
    ml = ML.mine_logic_params(html)
    check("form mined", len(ml["forms"]) == 1 and
          ml["forms"][0]["method"] == "POST", ml["forms"])
    names = [h["name"] for h in ml["hidden"]]
    check("hidden: total", "total" in names, names)
    check("price field: total", any(h["name"] == "total"
                                    for h in ml["price_fields"]))
    check("state field: state", any(h["name"] == "state"
                                    for h in ml["state_fields"]))
    check("role field: role", any(h["name"] == "role"
                                  for h in ml["role_fields"]))
    check("coupon field", any(h["name"] == "coupon_code"
                              for h in ml["coupon_fields"]))
    check("qty field", any(h["name"] == "qty"
                           for h in ml["qty_fields"]))
    check("signed shape detect", any(
        h.get("signed_amount") for h in ml["hidden"]))
    ml2 = ML.mine_logic_params("<input type='hidden' name='total' "
                               "value='waspP20abc123'>")
    check("canary value flag", ml2["hidden"] and
          ml2["hidden"][0]["value_canary"] is True, ml2["hidden"])


def unit_canary_inert():
    print("\n--- unit: canary + INERT enforcement ---")
    cv = ML._canary("t")
    check("canary family", cv.startswith("waspP20") and len(cv) > 12, cv)
    check("canary unique", ML._canary("t") != ML._canary("t"))
    try:
        ML.assert_inert("<script>alert(document.cookie)</script>", "x")
        check("assert_inert raises", False)
    except ValueError:
        check("assert_inert raises", True)
    check("assert_inert ok canary", ML.assert_inert(
        "sku=waspP20abc price=-1", "x"))
    try:
        ML.assert_logic_inert({"price": "199.00", "sku": "real-sku"}, "x")
        check("assert_logic_inert raises real amount", False)
    except ValueError:
        check("assert_logic_inert raises real amount", True)
    check("logic_inert ok negative", ML.assert_logic_inert(
        {"price": "-1", "qty": "-2"}, "x"))
    check("logic_inert ok zero", ML.assert_logic_inert({"price": "0"}, "x"))
    check("logic_inert ok canary-shaped", ML.assert_logic_inert(
        {"price": "waspP20canary"}, "x"))
    check("logic_inert ok non-amount", ML.assert_logic_inert(
        {"color": "red"}, "x"))
    check("filesig shape", ML.filesig("abc")["len"] == 3 and
          len(ML.filesig("abc")["sha1"]) == 16)
    check("pii redact email", "***@***" in ML.pii_redact(
        "mail a@b.com here"))
    check("pii redact creds", "REDACTED" in ML.pii_redact(
        "password: supersecret99"))


def unit_values_bypass():
    print("\n--- unit: value matrix + bypass2 + documented sets ---")
    vm = ML.price_value_matrix({})
    check("value matrix 8", len(vm) == 8, len(vm))
    check("value labels", [lbl for lbl, _ in vm][:2] ==
          ["negative", "zero"])
    check("value matrix cap", len(ML.price_value_matrix(
        {"logic_value_cap": 4})) == 4)
    b2 = ML.bypass2_variants("waspP20")
    check("bypass2 17 techniques", len(b2) == 17, len(b2))
    classes = {cls for _, _, cls in b2}
    check("bypass2 classes", classes == {"param_smuggle", "type_confusion",
                                         "numeric_edge", "normalization",
                                         "route_misroute"}, classes)
    check("race techniques 10", len(ML.DOCUMENTED_RACE_TECHNIQUES) == 10)
    check("playbooks 12", len(ML.DOCUMENTED_BUSINESS_PLAYBOOKS) == 12)
    check("race exec forbidden note", any("FORBIDDEN" in str(x) or
                                          "manual" in str(x).lower()
                                          for _, x in
                                          ML.DOCUMENTED_RACE_TECHNIQUES))
    check("workflow stages", len(ML.WORKFLOW_STAGES) >= 6)
    check("hidden canary params 15", len(ML.HIDDEN_CANARY_PARAMS) == 15)
    check("cold pool 26+", len(ML.COLD_LOGIC_PATHS) >= 26)


def unit_ff_reader():
    print("\n--- unit: feedforward reader + discovery (fixture) ---")
    ff = ML._ff_from_engagement(os.path.join(BASE, ENG))
    mods = [k for k in ("understand", "api", "access", "graphql", "ws",
                        "files", "client", "sessions", "inject", "js")
            if k in ff]
    check("ff reads 10 modules", len(mods) >= 10, mods)
    disc = ML.discover_logic_surface(os.path.join(BASE, ENG), None,
                                     dict(ML.DEFAULTS))
    check("discovery targets", len(disc["targets"]) >= 10,
          len(disc["targets"]))
    urls = [t["url"] for t in disc["targets"]]
    check("target: checkout", any(u.endswith("/checkout") for u in urls),
          urls[:5])
    check("target: order/open", any("/order/open" in u for u in urls))
    check("target: coupon/apply_open", any("coupon/apply_open" in u
                                           for u in urls))
    check("target: profile", any("/profile" in u for u in urls))
    srcs = disc["sources"]
    check("sources: ff multi", sum(1 for s in srcs if s.startswith("ff:"))
          >= 6, srcs)
    check("sources: P5", any("P5:" in s for s in srcs))
    check("sources: P8", any("P8" in s for s in srcs))
    check("sources: forms", any("forms" in s for s in srcs))
    ranked = ML.rank_targets(disc["targets"], {"logic_probe_cap": 12})
    check("rank cap 12", len(ranked) == 12, len(ranked))
    check("rank sorted", all(ranked[i]["score"] >= ranked[i + 1]["score"]
                             for i in range(len(ranked) - 1)))



# ===========================================================================
# UNIT TESTS - verdict engine / matrix / chains / hypotheses / source
# ===========================================================================
def unit_verdict_engine():
    print("\n--- unit: verdict engine (synthetic census) ---")
    results = {
        "param_census": [{"target": "http://x.invalid/checkout",
                          "client_trust_price": True,
                          "price_fields": ["total"], "signed_amount": False},
                         {"target": "http://x.invalid/order",
                          "client_trust_price": False,
                          "price_fields": ["amount"],
                          "signed_amount": True}],
        "hidden_param": {"rows": [{"target": "http://x.invalid/profile",
                                   "echoed": [{"param": "role",
                                               "status": 200},
                                              {"param": "debug",
                                               "status": 200}]}]},
        "role_diff": {"rows": [{"target": "http://x.invalid/api/admin",
                                "verdict": "CONFIRMED",
                                "canary_reflected": True}]},
        "price_tamper": {"rows": [{"target": "http://x.invalid/order/open",
                                   "verdict": "CONFIRMED",
                                   "variants": {"negative": {
                                       "verdict": "CONFIRMED"},
                                       "zero": {"verdict": "CONFIRMED"}}}]},
        "value_oracle": {"rows": [{"target": "http://x.invalid/api/credits",
                                   "variants": {"negative": {
                                       "verdict": "SUSPECTED"}}}]},
        "workflow": {"rows": [{"target": "http://x.invalid/checkout",
                               "verdict": "CONFIRMED",
                               "later_accessible": ["2", "3"],
                               "steps": {"2": {"nontrivial": True}}}]},
        "state_param": {"rows": [{"target": "http://x.invalid/checkout",
                                  "variants": {"step=99": {
                                      "reflected": True}}}]},
        "idempotency": {"rows": [{"target": "http://x.invalid/redeem/open",
                                  "idempotency_signal": False,
                                  "same_response_shape": True},
                                 {"target": "http://x.invalid/api/redeem",
                                  "idempotency_signal": True}]},
        "coupon": {"rows": [{"target": "http://x.invalid/coupon/apply_open",
                             "verdict": "CONFIRMED", "case_edge": False},
                            {"target": "http://x.invalid/api/coupon",
                             "verdict": "HARDENED", "case_edge": True}]},
        "bypass2": {"rows": [{"target": "http://x.invalid/checkout",
                              "variants": {"orig_url_header": {
                                  "nontrivial": True,
                                  "class": "route_misroute"}}}]},
        "authz_diff": [{"target": "http://x.invalid/order",
                        "privileged_shape_preauth": True,
                        "reauth_signal": False, "anon_status": 200}],
        "anti_auto": [{"target": "http://x.invalid/checkout",
                       "verdict": "ABSENT"}],
        "platform_fp": {"platforms": [{"name": "woocommerce"}]},
        "state_leak": {"rows": [{"target": "http://x.invalid/cart",
                                 "flags": ["state_blob_field"]}]},
        "chains": [{"tag": "idor_price", "active": True,
                    "overlap_target": "http://x.invalid/order",
                    "source": "P20-composite"},
                   {"tag": "upload", "active": True,
                    "overlap_target": "http://x.invalid/cart",
                    "source": "files:overwrite_endpoints"}],
        "waf": {},
    }
    rows = ML.verdict_engine(results, {}, {})
    keys = {r["key"] for r in rows}
    for want in ("logic_client_trust_price", "logic_role_param_echo",
                 "logic_negative_accepted", "logic_value_oracle",
                 "logic_workflow_skip", "logic_workflow_state_client",
                 "logic_idempotency_absent", "logic_idempotency_present",
                 "logic_dedup_absent", "logic_coupon_accepted_any",
                 "logic_coupon_case_edge", "logic_bypass2_route_misroute",
                 "logic_privilege_preauth", "logic_no_reauth",
                 "logic_no_csrf_state_change", "logic_platform_fp",
                 "logic_state_leak", "logic_chain_idor_price",
                 "logic_chain_upload_invoice", "logic_race_surface",
                 "logic_signed_amount"):
        check("verdict key: %s" % want, want in keys, sorted(keys)[:8])
    neg = [r for r in rows if r["key"] == "logic_negative_accepted"]
    check("negative CONFIRMED", neg and neg[0]["verdict"] == "CONFIRMED")


def unit_matrix_chains():
    print("\n--- unit: matrix / chains / hypotheses ---")
    matrix = ML.build_technique_matrix({}, {})
    check("matrix >= 150 rows", len(matrix) >= 150, len(matrix))
    fams = {r["family"] for r in matrix}
    check("matrix 18 families", fams == set(ML._FAMS), fams)
    check("matrix rows have cwe", all(r.get("cwe") for r in matrix[:20]))
    check("matrix rows have mitre", all(r.get("mitre")
                                        for r in matrix[:20]))
    b2rows = [r for r in matrix if r["family"] == "BYPASS2"]
    check("matrix bypass2 17", len(b2rows) == 17, len(b2rows))
    chains = ML.build_logic_chains(ML.Findings(), {}, [], [], {}, {})
    check("chains == 20", len(chains) == 20, len(chains))
    check("chains manual wave", all(c.get("manual_wave_required")
                                    for c in chains))
    hyps = ML.build_logic_hypotheses({}, [], [], {})
    check("hypotheses fallback", len(hyps) >= 1 and
          hyps[0]["priority"] == "P3", hyps)
    src = _src()
    check("source: stage letters", all(("Stage %s" % s) in src for s in
                                       "ABCDEFGHIJKLMNOPQRST"))
    check("source: safety notes", "REAL transaction" in src and
          "FORBIDDEN" in src)
    check("source: gates documented", all(g in src for g in (
        "logic_allow_price_probe", "logic_allow_race_probe",
        "logic_allow_workflow_probe", "logic_allow_param_echo",
        "logic_allow_coupon_probe", "logic_allow_role_probe")))
    check("severity hints rich", len(ML.SEVERITY_HINTS) >= 44)
    check("module shape", ML.NAME == "logic" and
          ML.PLAN_VERSION == "20.0.0")
    check("DEFAULTS keys", all(k in ML.DEFAULTS for k in (
        "logic_probe_cap", "logic_cold_paths", "logic_param_cap",
        "logic_value_cap", "logic_bypass2_cap",
        "logic_allow_price_probe", "logic_allow_race_probe",
        "logic_allow_workflow_probe", "logic_allow_param_echo",
        "logic_allow_coupon_probe", "logic_allow_role_probe")))



# ===========================================================================
# E2E GATE-OFF RUN (gates OFF - census-only behavior)
# ===========================================================================
def e2e_gate_off(origin, out):
    print("\n--- e2e: gate-OFF run (stages A..T) ---")
    man = _read(os.path.join(out, "MANIFEST.json")) or {}
    stats = man.get("stats", {})
    check("manifest phase", man.get("phase") == "20-logic", man.get("phase"))
    check("manifest matrix rows", stats.get("matrix_rows", 0) >= 150,
          stats)
    check("manifest chains 20", stats.get("chains") == 20,
          stats.get("chains"))
    check("manifest targets >= 10", stats.get("targets", 0) >= 10,
          stats.get("targets"))
    check("manifest verdicts", stats.get("verdicts", 0) >= 5)
    check("documented race 10", stats.get("documented_race") == 10)
    tg = _read(os.path.join(out, "logic_targets.json")) or {}
    check("targets artifact", tg.get("count", 0) >= 10)
    verbs = [t.get("verb") for t in (tg.get("targets") or [])]
    check("verb census in targets", any(verbs), verbs[:6])
    pc = _read(os.path.join(out, "logic_param_census.json")) or []
    check("param census rows", len(pc) >= 8, len(pc))
    ct = _read(os.path.join(out, "logic_client_trust.json")) or {}
    ctr = ct.get("rows") or []
    check("client-trust row (checkout)", any(
        r.get("client_trust_price") and "/checkout" in (r.get("target") or "")
        for r in ctr), len(ctr))
    cov = _read(os.path.join(out, "logic_coverage.json")) or {}
    gates = cov.get("gates") or {}
    check("gates all OFF", gates and not any(gates.values()), gates)
    check("coverage mode active", cov.get("mode") == "active")
    hp = _read(os.path.join(out, "logic_hidden_param.json")) or {}
    check("hidden-param GATED skip", hp.get("skipped") is True and
          len(hp.get("techniques_documented") or []) >= 12)
    pt = _read(os.path.join(out, "logic_price_tamper.json")) or {}
    check("price GATED skip", pt.get("skipped") is True and
          len(pt.get("techniques_documented") or []) >= 16)
    wf = _read(os.path.join(out, "logic_workflow.json")) or {}
    check("workflow GATED skip + flow map", wf.get("skipped") is True and
          len(wf.get("flow_map") or []) >= 1)
    rt = _read(os.path.join(out, "logic_race_techniques.json")) or {}
    check("race techniques artifact", rt.get("count") == 10 and
          rt.get("execution") == "FORBIDDEN (manual+RoE wave only)")
    check("race parallelism NONE", rt.get("parallelism") ==
          "NONE (sequential census only, cap 2)")
    idm = _read(os.path.join(out, "logic_idempotency.json")) or {}
    check("idempotency GATED skip", idm.get("skipped") is True)
    cp = _read(os.path.join(out, "logic_coupon.json")) or {}
    check("coupon GATED skip", cp.get("skipped") is True)
    b2 = _read(os.path.join(out, "logic_bypass2_matrix.json")) or {}
    check("bypass2 GATED documented", b2.get("skipped") is True and
          len(b2.get("techniques_documented") or []) == 17)
    az = _read(os.path.join(out, "logic_authz_diff.json")) or []
    check("authz diff rows (not gated)", len(az) >= 6, len(az))
    check("authz privileged on /order", any(
        r.get("privileged_shape_preauth") and "/order" in
        (r.get("target") or "") and "/order/open" not in r.get("target", "")
        for r in az))
    aa = _read(os.path.join(out, "logic_anti_auto.json")) or []
    check("anti-auto rows", len(aa) >= 6)
    check("anti-auto: checkout ABSENT / order HARDENED", any(
        r.get("verdict") == "ABSENT" and "/checkout" in
        (r.get("target") or "") for r in aa) and any(
        r.get("verdict") == "HARDENED" and r.get("target", "").rstrip("/")
        .endswith("/order") for r in aa), [(r.get("target"),
                                            r.get("verdict"))
                                           for r in aa][:4])
    pf = _read(os.path.join(out, "logic_platform_fp.json")) or {}
    plats = {p.get("name") for p in (pf.get("platforms") or [])}
    check("platform fingerprint", "woocommerce" in plats, plats)
    sl = _read(os.path.join(out, "logic_state_leak.json")) or {}
    check("state leak: cart flags", any(
        "state_blob_field" in (r.get("flags") or []) and
        "/cart" in (r.get("target") or "")
        for r in (sl.get("rows") or [])))
    ch = _read(os.path.join(out, "logic_chains_crossref.json")) or []
    tags = {c.get("tag") for c in ch}
    check("chain tags (idor_price active)", "idor_price" in tags and any(
        c.get("tag") == "idor_price" and c.get("active") for c in ch), tags)
    check("chain massassign active", any(
        c.get("tag") == "massassign" and c.get("active") for c in ch), tags)
    v = _read(os.path.join(out, "logic_verdicts.json")) or {}
    vkeys = {r.get("key") for r in (v.get("rows") or [])}
    for want in ("logic_client_trust_price", "logic_privilege_preauth",
                 "logic_no_reauth", "logic_race_surface",
                 "logic_chain_idor_price", "logic_anti_auto_present"):
        check("verdict: %s" % want, want in vkeys,
              sorted(vkeys)[:8])
    f = _read(os.path.join(out, "findings.json")) or {}
    fkeys = {x.get("key") for x in (f.get("findings") or [])}
    for want in ("logic_client_trust_price", "logic_no_csrf_state_change",
                 "logic_signed_amount", "logic_privilege_preauth",
                 "logic_no_reauth", "logic_race_surface",
                 "logic_platform_fp", "logic_chain_idor_price",
                 "logic_endpoint_live", "logic_verb_census"):
        check("finding: %s" % want, want in fkeys, sorted(fkeys)[:10])
    check("sev counts valid", isinstance(f.get("sev_counts"), dict) and
          f.get("sev_counts"), f.get("sev_counts"))
    mtxt = _read_txt(os.path.join(out, "LOGIC_MATRIX.txt"))
    check("matrix txt rows", "150" in mtxt.split("\n")[0] or
          len(mtxt.splitlines()) > 150)
    check("playbooks artifact", "discount-stacking" in
          _read_txt(os.path.join(out, "logic_playbooks.md")))
    check("kill chains txt", _read_txt(
        os.path.join(out, "logic_kill_chains.txt")).count("[CH") == 20)
    ffj = _read(os.path.join(out, "feedforward.json")) or {}
    rt2 = ffj.get("routing") or {}
    for want in ("to_phase21_authz", "to_phase22_replay",
                 "to_phase23_misconfig", "to_phase25_controls",
                 "to_phase11_bola", "to_phase12_inject",
                 "to_phase32_report"):
        check("feedforward: %s" % want, want in rt2)
    check("ff race primitives", len((rt2.get("to_phase22_replay") or {}).get(
        "race_primitives") or []) == 10)
    check("ff bola order surface", len((rt2.get("to_phase11_bola") or
                                        {}).get("order_surface") or []) >= 3)


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
    for u in re.findall(r"https?://[A-Za-z0-9.\-]+", blob):
        h = urlsplit(u if "://" in u else "http://" + u).hostname
        if h and h not in (allowed_host,) and \
                not h.endswith(".invalid") and h != "127.0.0.1":
            bad_egress.append(u)
    check("zero external egress (urls)", not bad_egress, bad_egress[:3])
    check("forbidden patterns absent", not re.search(
        r"(?i)(4111\s?1111|sk_live|pk_live|drop\s+table)", blob))



# ===========================================================================
# E2E GATED RUN (sab gates ON - caps verify)
# ===========================================================================
def e2e_gated(origin, out):
    print("\n--- e2e: gated run (all RoE gates ON, lab-only) ---")
    hp = _read(os.path.join(out, "logic_hidden_param.json")) or {}
    check("hidden-param ran", hp.get("skipped") is not True)
    rows = hp.get("rows") or []
    prows = [r for r in rows if "/profile" in (r.get("target") or "")]
    check("profile echo >= 5", prows and
          len(prows[0].get("echoed") or []) >= 5,
          (prows or [{}])[0].get("echoed"))
    rd = _read(os.path.join(out, "logic_role_diff.json")) or {}
    rrows = rd.get("rows") or []
    check("role diff ran", len(rrows) >= 6, len(rrows))
    check("role CONFIRMED (profile)", any(
        r.get("verdict") == "CONFIRMED" and "/profile" in
        (r.get("target") or "") for r in rrows),
        [(r.get("target"), r.get("verdict")) for r in rrows][:4])
    pt = _read(os.path.join(out, "logic_price_tamper.json")) or {}
    prows2 = pt.get("rows") or []
    orow = next((r for r in prows2 if "/order/open" in
                 (r.get("target") or "")), {})
    check("price CONFIRMED on /order/open",
          orow.get("verdict") == "CONFIRMED", orow.get("verdict"))
    check("negative variant accepted", (orow.get("variants") or {}).get(
        "negative", {}).get("verdict") == "CONFIRMED")
    check("huge variant accepted", (orow.get("variants") or {}).get(
        "huge", {}).get("verdict") == "CONFIRMED")
    check("canary-object flag", orow.get("canary_object") is True)
    vo = _read(os.path.join(out, "logic_value_oracle.json")) or {}
    check("value oracle SUSPECTED (credits)", any(
        any(v.get("verdict") == "SUSPECTED"
            for v in (r.get("variants") or {}).values())
        and "/api/credits" in (r.get("target") or "")
        for r in (vo.get("rows") or [])))
    wf = _read(os.path.join(out, "logic_workflow.json")) or {}
    wrows = wf.get("rows") or []
    check("workflow ran", len(wrows) >= 1)
    check("workflow skip CONFIRMED", any(
        r.get("verdict") == "CONFIRMED" and
        (r.get("later_accessible") or []) for r in wrows),
        [(r.get("target"), r.get("verdict")) for r in wrows])
    sp = _read(os.path.join(out, "logic_state_param.json")) or {}
    check("state-param reflected", any(
        any(v.get("reflected") for v in (r.get("variants") or {}).values())
        for r in (sp.get("rows") or [])))
    idm = _read(os.path.join(out, "logic_idempotency.json")) or {}
    irows = idm.get("rows") or []
    check("idempotency ran", len(irows) >= 5, len(irows))
    check("race HARD cap 2 sequential", all(
        r.get("requests", 0) <= 2 and r.get("sequential") is True
        for r in irows))
    check("idem present (api/redeem)", any(
        r.get("idempotency_signal") and "/api/redeem" in
        (r.get("target") or "") for r in irows))
    check("idem absent (redeem/open)", any(
        not r.get("idempotency_signal") and "/redeem/open" in
        (r.get("target") or "") for r in irows))
    cp = _read(os.path.join(out, "logic_coupon.json")) or {}
    crows = cp.get("rows") or []
    check("coupon ran", len(crows) >= 5, len(crows))
    check("coupon CONFIRMED (apply_open)", any(
        r.get("verdict") == "CONFIRMED" and "apply_open" in
        (r.get("target") or "") for r in crows),
        [(r.get("target"), r.get("verdict")) for r in crows][:5])
    check("coupon limit headers (api/coupon)", any(
        r.get("limit_headers") and "/api/coupon" in
        (r.get("target") or "") for r in crows))
    b2 = _read(os.path.join(out, "logic_bypass2_matrix.json")) or {}
    brows = b2.get("rows") or []
    check("bypass2 ran", len(brows) >= 3, len(brows))
    ckrow = next((r for r in brows if (r.get("target") or "").endswith(
        "/checkout")), {})
    check("orig-url misroute win (checkout)", (ckrow.get("variants") or
                                               {}).get("orig_url_header",
                                                       {}).get("nontrivial")
          is True, (ckrow.get("variants") or {}).get("orig_url_header"))
    check("dot-segment blocked (edge sim)", (ckrow.get("variants") or
                                             {}).get("dot_segment_step",
                                                     {}).get("nontrivial")
          is not True)
    check("hpp variant probed", "hpp_price" in (ckrow.get("variants") or {}))
    az = _read(os.path.join(out, "logic_authz_diff.json")) or []
    check("cookie differential rows", any(
        r.get("cookie_diff_class") in ("DIFFERENTIAL", "SAME")
        for r in az))
    v = _read(os.path.join(out, "logic_verdicts.json")) or {}
    vkeys = {r.get("key") for r in (v.get("rows") or [])}
    for want in ("logic_negative_accepted", "logic_role_param_echo",
                 "logic_param_echo", "logic_workflow_skip",
                 "logic_workflow_state_client", "logic_idempotency_absent",
                 "logic_dedup_absent", "logic_idempotency_present",
                 "logic_coupon_accepted_any", "logic_limit_absent",
                 "logic_bypass2_route_misroute", "logic_value_oracle",
                 "logic_price_probe_suspected", "logic_massassign_crossref",
                 "logic_state_leak", "logic_test_sku"):
        check("gated verdict: %s" % want, want in vkeys,
              sorted(vkeys)[:12])
    f = _read(os.path.join(out, "findings.json")) or {}
    fkeys = {x.get("key") for x in (f.get("findings") or [])}
    crit = {x.get("key") for x in (f.get("findings") or [])
            if x.get("severity") == "critical"}
    for want in ("logic_negative_accepted", "logic_coupon_accepted_any",
                 "logic_role_param_echo", "logic_workflow_skip",
                 "logic_bypass2_route_misroute", "logic_test_sku",
                 "logic_limit_absent", "logic_dedup_absent"):
        check("gated finding: %s" % want, want in fkeys,
              sorted(fkeys)[:12])
    check("critical findings present", {"logic_negative_accepted",
                                        "logic_coupon_accepted_any",
                                        "logic_workflow_skip"} <= crit,
          crit)
    cov = _read(os.path.join(out, "logic_coverage.json")) or {}
    gates = cov.get("gates") or {}
    check("gates all ON", gates and all(gates.values()), gates)
    check("hypotheses active", (_read(os.path.join(
        out, "logic_hypotheses.json")) or {}).get("count", 0) >= 3)
    tp = _read_txt(os.path.join(out, "logic_test_plan.md"))
    check("test plan kill-tests", "kill-tests" in tp and
          "logic_negative_accepted" in tp)
    rem = _read_txt(os.path.join(out, "logic_remediation.txt"))
    check("remediation rows", "logic_negative_accepted" in rem and
          "logic_workflow_skip" in rem)


# ===========================================================================
# PASSIVE + CHECKPOINT REPLAY
# ===========================================================================
def passive_and_replay(cfg, cfg4, base, base2, eng, eng_p, origin):
    print("\n--- passive mode + checkpoint replay ---")
    out2 = ML.run(cfg4, WC.Scope(os.path.join(base2, "scope.json")), base2)
    man = _read(os.path.join(out2, "MANIFEST.json")) or {}
    check("passive manifest", man.get("stats", {}).get("mode") == "passive")
    check("passive 0 probes", (man.get("stats", {}).get("probes") in
                               (0, None)), man.get("stats"))
    cov = _read(os.path.join(out2, "logic_coverage.json")) or {}
    check("passive coverage mode", cov.get("mode") == "passive")
    # checkpoint replay: dobara run (wahi engagement) - discovery replay
    LAB["origin"] = origin
    out_r = ML.run(cfg, WC.Scope(os.path.join(base, "scope.json")), base)
    hs = _read(os.path.join(out_r, "logic_param_census.json")) or []
    check("replay produced census", len(hs) >= 8, len(hs))
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
                        os.path.join(os.path.dirname(HERE), "phases", "block4_api_logic", "mod_logic.py"),
                        os.path.join(HERE, "test_mod_logic.py")],
                       capture_output=True, text=True, cwd=ULTRA)
    check("py_compile -W error clean", r.returncode == 0, r.stderr[:200])
    r2 = subprocess.run([sys.executable, "-W", "error",
                         os.path.join(ULTRA, "mod_logic.py")],
                        capture_output=True, text=True, timeout=60)
    check("main() CLI banner", r2.returncode == 0 and "mod_logic.py" in
          r2.stdout and "20" in r2.stdout, r2.stdout[:120])
    check("gates documented in CLI", "logic_allow_price_probe=false" in
          r2.stdout and "logic_allow_race_probe=false" in r2.stdout)
    check("module shape", ML.NAME == "logic" and
          ML.PLAN_VERSION == "20.0.0")
    check("cold pool size", len(ML.COLD_LOGIC_PATHS) >= 26)
    check("FF seed sources 10", len(ML.FF_SEED_SOURCES) == 10)


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    print("=" * 69)
    print(" WASP P20 SELF-TEST - mod_logic.py v%s" % ML.PLAN_VERSION)
    print("=" * 69)
    srv, port = _start_lab()
    origin = "http://127.0.0.1:%d" % port
    LAB["origin"] = origin
    LAB["port"] = port
    try:
        _seed(BASE, ENG, origin)
        _seed(BASE_GATED, ENG_G, origin)
        _seed(BASE2, ENG_P, origin)

        unit_shapes()
        unit_miner()
        unit_canary_inert()
        unit_values_bypass()
        LAB["origin"] = origin
        unit_ff_reader()
        unit_verdict_engine()
        unit_matrix_chains()

        cfg = WC.Cfg(None)
        cfg.adaptive_throttle = False
        cfg.allow_active = True
        cfg.rate_limit = 120
        cfg.logic_probe_cap = 12
        LAB.clear()
        LAB["origin"] = origin
        LAB["port"] = port
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        out = ML.run(cfg, scope, BASE)
        e2e_gate_off(origin, out)
        rwx_and_egress(out, origin)

        cfg2 = WC.Cfg(None)
        cfg2.adaptive_throttle = False
        cfg2.allow_active = True
        cfg2.rate_limit = 120
        cfg2.logic_probe_cap = 12
        cfg2.logic_allow_price_probe = True
        cfg2.logic_allow_race_probe = True
        cfg2.logic_allow_workflow_probe = True
        cfg2.logic_allow_param_echo = True
        cfg2.logic_allow_coupon_probe = True
        cfg2.logic_allow_role_probe = True
        cfg2.test_cookie = "session=waspP20canary-cookie"
        LAB.clear()
        LAB["origin"] = origin
        LAB["port"] = port
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = ML.run(cfg2, scope3, BASE_GATED)
        e2e_gated(origin, out3)

        cfg4 = WC.Cfg(None)
        cfg4.adaptive_throttle = False
        cfg4.allow_active = False
        cfg4.logic_probe_cap = 12
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
    print(" P20 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, str(d)[:140]))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

