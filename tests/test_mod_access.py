#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 11 offline test harness - mock vulnerable ACCESS-CONTROL server ke against
mod_access.run() (v11 ULTRA PRO MAX) ko chalata hai aur verified assertions
check karta hai. (koi internet nahi chahiye - sirf 127.0.0.1)

Mock server me ye vulnerabilities deliberately hain:
  - orders/invoices/files par ownership check missing (classic BOLA, both ways)
  - garbage ID par 404 -> existence oracle; anon 403 object-specific (blind authz oracle)
  - /admin/users path-403 but X-Original-URL header se edge bypass
  - X-HTTP-Method-Override + ?action=list + Accept-downgrade se verb bypass
  - /graphql: introspection GET-blocked but newline-smuggle GET works;
    did-you-mean field suggestions; aliased multi-ID BOLA; batching accepted
  - tenant_id / X-Tenant-ID swap se cross-tenant read (T1 vs T2)
  - /api/v1/orders/batch?ids=1,2,3 over-fetch (cross-account items)
  - order response me related invoice_id -> chained IDOR (invoice cross-read)
  - /api/v1/files/<id> attachment cross-user download
  - /s/share-0001 sequential tokens + cross-account share read
  - X-API-Key + cookie mixed identity accepted (scope confusion)
  - search?q=<email> se dusre account ka object; limit=9999 over-exposure
  - authz'd responses par Cache-Control missing (stage V derivation)
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block2_auth")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, shutil, threading, tempfile, re, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "acc_test")
DOWNLOAD = "/home/z/my-project/download"
ULTRA_CORE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wasp_core.py")
sys.path.insert(0, WORK)

PORT = 8932
BASE = "http://127.0.0.1:%d" % PORT
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-58s %s" % ("[PASS]" if cond else "[FAIL]", name, detail))
    return bool(cond)


# ---------------------------------------------------------------------------
# MOCK DATA
# ---------------------------------------------------------------------------
USERS = {"A-token": "userA@example.test", "B-token": "userB@example.test"}
KEYS = {"key-A": "userA@example.test", "key-B": "userB@example.test"}
ORDERS = {"1001": "userA@example.test", "1002": "userA@example.test",
          "1003": "userA@example.test", "2001": "userB@example.test",
          "2002": "userB@example.test", "2003": "userB@example.test"}
INVOICES = {"5001": "userB@example.test", "5002": "userA@example.test"}
FILES = {"9000": "userA@example.test", "2001": "userB@example.test",
         "1001": "userB@example.test"}
TENANTS = {"T1": "userA@example.test", "T2": "userB@example.test"}
SCHEMA_JSON = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
BLOCKED = {"errors": [{"message": "introspection disabled"}]}
SUGGEST = {"errors": [{"message": "Cannot query field `usernam` on type `User`. "
                                  "Did you mean `username`?"}]}


def _cookie_user(h):
    c = h.get("Cookie", "") or ""
    m = re.search(r"sess=([A-Za-z0-9\-]+)", c)
    return USERS.get(m.group(1)) if m else None


def _api_user(h):
    return KEYS.get(h.get("X-API-Key", "") or "")


def _order_obj(oid):
    return {"id": oid, "owner": ORDERS.get(oid), "item": "widget-" + str(oid),
            "total": 199, "invoice_id": "5001" if oid == "2001" else None}


def _deny_rich(oid):
    return {"error": "denied", "object": str(oid),
            "detail": "access to order %s denied for anonymous principal" % oid,
            "policy": "order-owner-only", "ref": "den-%s" % oid}


def _deny_min():
    return {"error": "denied", "ref": "den-999"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, extra=None):
        body = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    # ---------------- GET router ----------------
    def do_GET(self):
        h = self.headers
        u = self.path
        p, _, q = u.partition("?")
        qs = {}
        for kv in q.split("&"):
            if "=" in kv:
                k, _, v = kv.partition("=")
                try:
                    qs[k] = urllib.parse.unquote(v)
                except Exception:
                    qs[k] = v
        p = p.rstrip("/") or "/"
        user = _cookie_user(h.__dict__ if isinstance(h, dict) else dict(h.items()))

        if p == "/admin/users":
            if h.get("X-Original-URL"):
                return self._send(200, {"users": [
                    {"username": "userA@example.test", "role": "user"},
                    {"username": "userB@example.test", "role": "user"}]})
            if h.get("X-HTTP-Method-Override"):
                return self._send(200, {"users": [
                    {"username": "userA@example.test", "role": "user"}]})
            if qs.get("action") == "list":
                return self._send(200, {"users": [
                    {"username": "userA@example.test", "role": "user"}]})
            if (h.get("Accept", "") or "") == "text/plain":
                return self._send(200, {"users": [
                    {"username": "userA@example.test", "role": "user"}]})
            return self._send(403, _deny_min())

        if p in ("/api/v1/me", "/api/me", "/api/auth/me", "/whoami", "/api/whoami"):
            cu = _cookie_user(dict(h.items()))
            ku = _api_user(dict(h.items()))
            if not cu and not ku:
                return self._send(401, {"error": "no identity"})
            return self._send(200, {"user": cu, "api_key_owner": ku,
                                    "tenant": "T1" if cu == "userA@example.test" else "T2"})

        if p == "/api/v1/orders/batch":
            ids = [x for x in (qs.get("ids", "").split(",")) if x]
            items = [_order_obj(i) for i in ids if i in ORDERS]
            if user is None:
                return self._send(403, _deny_min())
            return self._send(200, {"items": items})

        m = re.match(r"^/api/v1/orders/([A-Za-z0-9\-]+)$", p)
        if m:
            oid = m.group(1)
            if user is None:
                rich = oid in ORDERS
                return self._send(403, _deny_rich(oid) if rich else _deny_min())
            if oid not in ORDERS:
                return self._send(404, {"error": "not found"})
            return self._send(200, _order_obj(oid))

        if p == "/api/v1/orders":
            if user is None:
                return self._send(403, _deny_min())
            try:
                lim = int(qs.get("limit", "10"))
            except Exception:
                lim = 10
            if lim >= 9999:
                items = []
                for i in range(120):
                    oid = "100%d" % (i % 3 + 1) if i % 2 == 0 else "200%d" % (i % 3 + 1)
                    items.append(_order_obj(oid))
                return self._send(200, {"items": items, "total": 120})
            items = [_order_obj("1001"), _order_obj("1002")]
            return self._send(200, {"items": items, "total": 2})

        m = re.match(r"^/api/v1/invoices/([A-Za-z0-9\-]+)$", p)
        if m:
            iid = m.group(1)
            if user is None:
                rich = iid in INVOICES
                return self._send(403, _deny_rich(iid) if rich else _deny_min())
            if iid not in INVOICES:
                return self._send(404, {"error": "not found"})
            return self._send(200, {"id": iid, "owner": INVOICES[iid],
                                    "amount": 499})

        m = re.match(r"^/api/v1/files/([A-Za-z0-9\-]+)$", p)
        if m:
            fid = m.group(1)
            if user is None:
                return self._send(403, _deny_min())
            if fid not in FILES:
                return self._send(404, {"error": "not found"})
            return self._send(200, {"file": fid, "owner": FILES[fid],
                                    "content": "CONFIDENTIAL doc for %s" % FILES[fid]},
                              extra={"Content-Disposition":
                                     "attachment; filename=\"doc-%s.pdf\"" % fid})

        if p == "/api/v1/reports":
            if user is None:
                return self._send(403, _deny_min())
            tid = (qs.get("tenant_id") or h.get("X-Tenant-ID")
                   or h.get("X-Org-ID") or "")
            if tid not in TENANTS:
                return self._send(403, _deny_min())
            return self._send(200, {"report": "quarterly", "tenant": tid,
                                    "owner": TENANTS[tid]})

        if p == "/api/v1/search":
            if user is None:
                return self._send(403, _deny_min())
            term = qs.get("q", "")
            if "userB@example.test" in term:
                return self._send(200, {"results": [_order_obj("2001")]})
            if "userA@example.test" in term:
                return self._send(200, {"results": [_order_obj("1001")]})
            return self._send(200, {"results": []})

        if p.startswith("/s/"):
            tok = p[len("/s/"):]
            if tok == "share-0001":
                return self._send(200, {"shared_doc": "quarterly-report",
                                        "owner": "userA@example.test"})
            return self._send(404, {"error": "not found"})

        if p == "/graphql":
            qry = qs.get("query", "")
            return self._send(*gql_handle(qry))

        return self._send(404, {"error": "not found"})

    # ---------------- POST router ----------------
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b""
        if self.path.rstrip("/") == "/graphql":
            try:
                doc = json.loads(raw.decode())
            except Exception:
                return self._send(400, {"errors": [{"message": "bad json"}]})
            if isinstance(doc, list):
                return self._send(200, [{"data": {"__typename": "Query"}}
                                        for _ in doc[:5]])
            qry = str((doc or {}).get("query", ""))
            return self._send(*gql_handle(qry, post=True))
        if self.path.rstrip("/") == "/login":
            return self._send(200, {"ok": True},
                              extra={"Set-Cookie": "sess=A-token; Path=/"})
        return self._send(404, {"error": "not found"})

    # ---------------- HEAD/OPTIONS ----------------
    def do_HEAD(self):
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()


def gql_handle(qry, post=False):
    """Mock GraphQL engine - (code, obj) return."""
    if "__typename" in qry and "__schema" not in qry:
        return 200, {"data": {"__typename": "Query"}}
    if "__schema" in qry:
        if not post and ("\n" in qry or "\t" in qry):
            return 200, SCHEMA_JSON          # newline-smuggle GET bypass
        return 400, BLOCKED                  # plain GET + POST blocked
    if "usernam" in qry:
        return 400, SUGGEST
    aliases = re.findall(r"([A-Za-z0-9_]+):\s*order\(id:\s*\"([A-Za-z0-9\-]+)\"\)", qry)
    if len(aliases) >= 2:
        data = {}
        for name, oid in aliases:
            data[name] = _order_obj(oid) if oid in ORDERS else None
        return 200, {"data": data}
    m = re.search(r"(\w+)\(id:\s*\"([A-Za-z0-9\-]+)\"\)", qry)
    if m:
        fld, oid = m.group(1), m.group(2)
        if fld == "order":
            return 200, {"data": {"order": _order_obj(oid) if oid in ORDERS else None}}
        return 200, {"data": {fld: None}}
    return 200, {"data": {"__typename": "Query"}}


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
    print("\n  ===== ACCESS SELFTEST: %d/%d PASS =====" % (
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
SEED_ENDPOINTS = [
    BASE + "/api/v1/orders/1001",
    BASE + "/api/v1/orders/2001",
    BASE + "/api/v1/invoices/5002",
    BASE + "/api/v1/orders/batch?ids=1001",
    BASE + "/api/v1/files/9000",
    BASE + "/api/v1/search?q=baseline",
    BASE + "/api/v1/orders?limit=50",
    BASE + "/s/share-0001",
    BASE + "/admin/users",
    BASE + "/api/v1/reports?tenant_id=T1",
]

SESSIONS = [
    {"name": "accA", "cookie_header": "sess=A-token", "priv": "user",
     "markers": ["userA@example.test"], "known_ids": ["1001"],
     "tenant_ids": ["T1"], "headers": {"X-API-Key": "key-A"}},
    {"name": "accB", "cookie_header": "sess=B-token", "priv": "user",
     "markers": ["userB@example.test"], "known_ids": ["2001"],
     "tenant_ids": ["T2"], "headers": {"X-API-Key": "key-B"}},
]

EXPECTED_FILES = ["findings.json", "ACCESS_FINDINGS.md", "access_test_plan.md",
                  "access_endpoints.txt", "access_sessions.json", "idor_verdicts.json",
                  "access_matrix.json", "id_intelligence.json", "bypass_403.json",
                  "graphql_bola.json", "mass_assignment.json", "method_matrix.json",
                  "gql_ultra.json", "tenant_isolation.json", "blind_oracle.json",
                  "verb_matrix.json", "batch_idor.json", "chained_idor.json",
                  "file_idor.json", "share_surface.json", "token_scope.json",
                  "search_exposure.json", "authz_hygiene.json", "feedforward.json"]

EXPECTED_KEYS = ["idor_confirmed", "bypass_403_success", "graphql_bola",
                 "graphql_introspection_bypass", "graphql_field_suggestion",
                 "graphql_alias_bola", "graphql_batch_bola",
                 "tenant_isolation_missing", "blind_idor_authz_oracle",
                 "method_override_bypass", "verb_tampering_bypass",
                 "batch_overfetch", "chained_idor_confirmed", "file_idor_confirmed",
                 "share_token_weak", "share_cross_account_access",
                 "token_scope_confusion", "search_cross_account_leak",
                 "pagination_overexposure", "authz_cache_hygiene"]


def make_cfg(tmp, allow_active=True):
    cfg_path = os.path.join(tmp, "config.json")
    scope_path = os.path.join(tmp, "scope.json")
    json.dump({"engagement": "acc11-test", "authorized": True,
               "authorization_reference": "SELFTEST (local mock)",
               "targets": [BASE], "domains": [], "wildcards": [],
               "excludes": [], "ips": ["127.0.0.1"],
               "notes": "offline selftest only"}, open(scope_path, "w"))
    conf = {"rate_limit": 40.0, "jitter": 0.0, "concurrency": 4, "timeout": 6,
            "retries": 0, "max_requests": 6000, "verify_tls": False,
            "allow_active": allow_active, "allow_destructive": False,
            "save_bodies": False, "adaptive_throttle": False,
            "negative_cache": False,
            # stock knobs
            "access_surface_cap": 30, "access_template_cap": 12,
            "access_enum_probes": 6, "access_bypass_probes": 40,
            "access_gql_ops_max": 6, "access_allow_write_probes": False,
            "access_allow_neighbour_probe": True,
            "access_sessions": SESSIONS,
            "access_victim_known_ids": ["share-0001", "share-0002"],
            # ULTRA knobs (config plumbing ka test bhi)
            "access_allow_gql_deep": True, "access_gql_deep_max": 8,
            "access_gql_alias_max": 4,
            "access_allow_tenant_probe": True, "access_tenant_probes": 4,
            "access_allow_blind_oracle": True, "access_blind_probes": 6,
            "access_allow_verb_matrix": True, "access_verb_probes": 8,
            "access_allow_batch_probe": True, "access_batch_probes": 3,
            "access_allow_chain_probe": True, "access_chain_probes": 6,
            "access_allow_file_idor": True, "access_file_probes": 6,
            "access_allow_share_probe": True, "access_share_probes": 5,
            "access_allow_scope_probe": True, "access_scope_probes": 4,
            "access_allow_search_probe": True, "access_search_probes": 4,
            "access_authz_hygiene": True}
    json.dump(conf, open(cfg_path, "w"))
    return cfg_path, scope_path


def seed_feedforward(out_base):
    eng = os.path.join(out_base, "acc11-test")
    os.makedirs(os.path.join(eng, "sessions"), exist_ok=True)
    os.makedirs(os.path.join(eng, "js"), exist_ok=True)
    os.makedirs(os.path.join(eng, "surface"), exist_ok=True)
    json.dump({"routing": {"to_phase11_idor": {"session_endpoints": SEED_ENDPOINTS}}},
              open(os.path.join(eng, "sessions", "feedforward.json"), "w"))
    json.dump({"assets": [{"graphql_endpoints": [BASE + "/graphql"],
                           "endpoints": ["/api/v1/invoices/5002"]}],
               "attack_surface": {"graphql_ops": ["order(id:$id)"],
                                  "endpoints": []}},
              open(os.path.join(eng, "js", "js_analysis.json"), "w"))
    json.dump({"queue": [{"target": BASE + "/api/v1/orders/2001",
                          "classes": ["IDOR/BOLA"], "priority": 42}]},
              open(os.path.join(eng, "surface", "priority_queue.json"), "w"))


def load_eng(out_base):
    eng = os.path.join(out_base, "acc11-test", "access")

    def load(rel):
        p = os.path.join(eng, rel)
        try:
            return json.load(open(p)) if os.path.exists(p) else None
        except Exception:
            return None

    def text(rel):
        p = os.path.join(eng, rel)
        return open(p, errors="ignore").read() if os.path.exists(p) else ""
    return eng, load, text


def run_module(tmp, cfg_path, scope_path, out_base):
    from wasp_core import Cfg, Scope
    import mod_access
    cfg = Cfg(cfg_path)
    sc = Scope(scope_path)
    mod_access.run(cfg, sc, out_base)


def main():
    os.makedirs(WORK, exist_ok=True)
    shutil.copy(ULTRA_CORE, os.path.join(WORK, "wasp_core.py"))
    shutil.copy(os.path.join(_WASP_ROOT, "phases", "block2_auth", "mod_access.py"),
                os.path.join(WORK, "mod_access.py"))
    for f in ("wasp_core", "mod_access"):
        if f in sys.modules:
            del sys.modules[f]

    tmp = tempfile.mkdtemp(prefix="acc11_")
    out_base = os.path.join(tmp, "out")
    cfg_path, scope_path = make_cfg(tmp, allow_active=True)
    seed_feedforward(out_base)

    srv = start_server()
    print("  mock target: %s" % BASE)
    try:
        run_module(tmp, cfg_path, scope_path, out_base)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("module ran without exception", False, repr(e))
        return finish(srv, tmp)
    check("module ran without exception", True)

    eng, load, text = load_eng(out_base)
    F = (load("findings.json") or {}).get("findings") or []
    keys = {f["key"] for f in F}

    print("\n== FRESH RUN assertions ==")
    for k in EXPECTED_KEYS:
        check("finding: %s" % k, k in keys)
    check("mass_assignment GATED off", "mass_assignment_possible" not in keys)
    miss = [f for f in EXPECTED_FILES
            if not os.path.exists(os.path.join(eng, f))]
    check("output files (%d/%d)" % (len(EXPECTED_FILES) - len(miss),
                                    len(EXPECTED_FILES)), not miss,
          "missing: %s" % (miss or "none"))
    idv = load("idor_verdicts.json") or {}
    conf_verdicts = [k for k, v in (idv or {}).items()
                     if isinstance(v, dict) and v.get("verdict") == "CONFIRMED"]
    check("idor verdict CONFIRMED present", bool(conf_verdicts),
          str(conf_verdicts[:2]))
    ff = (load("feedforward.json") or {}).get("routing") or {}
    check("feedforward to_phase26_cache", "to_phase26_cache" in ff)
    check("feedforward to_phase22_tenant", "to_phase22_tenant" in ff)
    check("feedforward to_phase21_share", "to_phase21_share" in ff)
    g18 = (ff.get("to_phase18_graphql") or {}).get("ultra") or {}
    check("feedforward gql ultra block", g18.get("alias_bola") == "CONFIRMED"
          and g18.get("batching") is True,
          "alias=%s batch=%s" % (g18.get("alias_bola"), g18.get("batching")))
    gx = load("gql_ultra.json") or {}
    check("gql_ultra: alias victim id B ka hai",
          (gx.get("alias_bola") or {}).get("victim_id") == "2001",
          str((gx.get("alias_bola") or {}).get("victim_id")))
    bl = load("blind_oracle.json") or {}
    check("blind oracle authz verdict", any(o.get("verdict") == "authz"
                                            for o in bl.get("oracles") or []))
    # RWX standing rule - result files 0o777
    bad_perm = []
    for f in EXPECTED_FILES[:8]:
        p = os.path.join(eng, f)
        if os.path.exists(p):
            mode = os.stat(p).st_mode & 0o777
            if mode != 0o777:
                bad_perm.append("%s=%o" % (f, mode))
    check("RWX 0777 on result files", not bad_perm, str(bad_perm))
    md = text("ACCESS_FINDINGS.md")
    check("ACCESS_FINDINGS.md non-trivial", len(md) > 500, "%d chars" % len(md))

    # ---------------- RESUME RUN (checkpoint replay + findings stable) ----------------
    print("\n== RESUME RUN assertions ==")
    f1 = len(F)
    try:
        run_module(tmp, cfg_path, scope_path, out_base)
        check("resume ran without exception", True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("resume ran without exception", False, repr(e))
        return finish(srv, tmp)
    F2 = (load("findings.json") or {}).get("findings") or []
    keys2 = {f["key"] for f in F2}
    check("resume: findings stable (FIX-4)", len(F2) >= f1,
          "%d -> %d" % (f1, len(F2)))
    check("resume: ULTRA keys still present",
          all(k in keys2 for k in EXPECTED_KEYS))

    # ---------------- PASSIVE MODE (allow_active=False) ----------------
    print("\n== PASSIVE MODE assertions ==")
    tmp2 = tempfile.mkdtemp(prefix="acc11p_")
    out_base2 = os.path.join(tmp2, "out")
    cfg2, scope2 = make_cfg(tmp2, allow_active=False)
    seed_feedforward(out_base2)
    try:
        run_module(tmp2, cfg2, scope2, out_base2)
        check("passive ran without exception", True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("passive ran without exception", False, repr(e))
        return finish(srv, tmp)
    eng2 = os.path.join(out_base2, "acc11-test", "access")
    ptv = os.path.join(eng2, "access_templates_passive.json")
    check("passive: templates parsed offline (FIX-3)", os.path.exists(ptv))
    fp2 = os.path.join(eng2, "findings.json")
    if os.path.exists(fp2):
        Fp = (json.load(open(fp2)) or {}).get("findings") or []
        active_leaks = [f for f in Fp if f["key"] in
                        ("idor_confirmed", "bypass_403_success",
                         "tenant_isolation_missing", "search_cross_account_leak")]
        check("passive: koi active probe finding nahi", not active_leaks,
              str([f["key"] for f in active_leaks]))
    else:
        check("passive: findings.json generated", False)
    shutil.rmtree(tmp2, ignore_errors=True)

    return finish(srv, tmp)


if __name__ == "__main__":
    main()
