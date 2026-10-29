#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P12 SELF-TEST SUITE - mod_inject.py v13.0.0-ultra-ultra-pro-max (P12)
=============================================================================
 Mock vulnerable lab app + full assertion suite:
   - Unit tests (pure helpers: matchers/param-utils/pair-diff/timing)
   - Active run end-to-end (all stages C..W verdict assertions)
   - Artifact integrity (31 output files, matrix, catalog, feedforward, manifest)
   - RWX rule (0777 on every result file)
   - Passive mode (allow_active=False -> 0 probes, hypotheses only)
   - Checkpoint replay (FIX-4: findings re-derivation on resume)
   - Log4Shell gated mini-run (default OFF -> explicit ON run, loopback-only)
 Detection-only discipline honored: no destructive payloads anywhere.
=============================================================================
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block3_input")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os
import sys
import json
import shutil
import time
import threading
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote_plus, parse_qsl

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block3_input")
sys.path.insert(0, ULTRA)      # pehle ULTRA, phir HERE -> HERE wins (fresh module)
sys.path.insert(0, HERE)

import mod_inject as MI                                   # noqa: E402
import wasp_core as WC                                    # noqa: E402

BASE = os.path.join(HERE, "p12_test_base")
BASE2 = os.path.join(HERE, "p12_test_base_passive")
BASE3 = os.path.join(HERE, "p12_test_base_l4s")
ENG = "p12lab"
SCOPE_PATH = os.path.join(BASE, "scope.json")
SCOPE_PATH2 = os.path.join(BASE2, "scope.json")
SCOPE_PATH3 = os.path.join(BASE3, "scope.json")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s  -> %s" % (name, detail))
    return cond


# ===========================================================================
# MOCK VULNERABLE LAB APP
# - WAF simulation on /protected: single-pass decode view (blocks), backend
#   recursive-decode view (legacy app) -> double-url-encode bypass works.
# - Every endpoint returns CONSTANT bodies (baseline stability) except the
#   vuln triggers, so paired-diff/timing oracles stay clean.
# ===========================================================================
class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockLab/1.0"

    def log_message(self, *a):      # silence
        pass

    # ---- decode helpers -------------------------------------------------
    @staticmethod
    def _dec(s, rounds=1):
        v = s or ""
        for _ in range(int(rounds)):
            v = v.replace("%c0%af", "%2f").replace("%C0%AF", "%2f")
            v = unquote_plus(v)
        return v

    def _raw_pairs(self):
        q = urlsplit(self.path).query
        out = []
        for part in q.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                out.append((k, v))
            elif part:
                out.append((part, ""))
        return out

    def _raw_val(self, name):
        for k, v in self._raw_pairs():
            if k == name:
                return v
        return ""

    def _raw_qs(self):
        return urlsplit(self.path).query

    def _respond(self, status, text, headers=None):
        body = text.encode("utf-8", "ignore")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "MockLab/1.0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        if getattr(self, "_body_cache", None) is not None:
            return self._body_cache
        try:
            cl = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            cl = 0
        raw = self.rfile.read(cl) if cl else b""
        self._body_cache = raw.decode("utf-8", "ignore") if cl else ""
        return self._body_cache

    # ---- HTTP methods ----------------------------------------------------
    def do_GET(self):
        self.server.hits.append(("GET", self.path, ""))
        self._route()

    def do_POST(self):
        self.server.hits.append(("POST", self.path, self._body()[:400]))
        self._route()

    # ---- router ----------------------------------------------------------
    def _route(self):
        sp = urlsplit(self.path)
        path = sp.path
        rq = sp.query

        if path == "/" or path == "":
            return self._respond(200, "Mock injection lab. Endpoints: /item "
                                      "/product /slow /api/users /page /ping "
                                      "/download /go /vote /protected /search /graphql "
                                      "/hdr /pp /xml /log /export /el")

        if path == "/item":
            vb = self._dec(self._raw_val("id"), 2)
            if "$ne" in self._dec(rq, 1):
                return self._respond(200, '{"error":"MongoServerError: '
                                          'unknown operator $ne"}')
            if "'" in vb or '"' in vb:
                return self._respond(500, "You have an error in your SQL syntax; "
                                          "check the manual that corresponds to your "
                                          "MariaDB server version for the right syntax")
            if vb.startswith("[") or vb.startswith("{"):
                return self._respond(500, "Cannot deserialize value of type "
                                          "java.lang.String from Array value")
            return self._respond(200, "Item details page. Inventory system v2.")

        if path == "/hdr":
            xff = self.headers.get("X-Forwarded-For", "")
            if "'" in xff:
                return self._respond(500, "You have an error in your SQL syntax; "
                                          "check the manual that corresponds to your "
                                          "PostgreSQL server version for the right syntax")
            return self._respond(200, "Audit trail: request from %s logged "
                                      "for compliance." % (xff or "internal"))

        if path == "/pp":
            raw = self._raw_qs()
            mk = None
            for key in ("__proto__%5BwaspPP%5D=", "__proto__[waspPP]="):
                if key in raw:
                    mk = self._dec(raw.split(key, 1)[1].split("&")[0], 1)
                    break
            if mk is None and self.command == "POST":
                try:
                    mk = (json.loads(self._body() or "{}").get("__proto__")
                          or {}).get("waspPP")
                except Exception:
                    mk = None
            if mk:
                return self._respond(200, json.dumps({"ok": True, "user": "guest",
                                                      "waspPP": mk, "isAdmin": False}))
            return self._respond(200, '{"ok":true,"user":"guest"}')

        if path == "/xml":
            if self.command == "POST":
                body = self._body()
                m = re.search(r'<!ENTITY waspE "([^"]+)">', body or "")
                if m and "&waspE;" in body:
                    return self._respond(200, "<root><q>%s</q></root>" % m.group(1),
                                         {"Content-Type": "application/xml"})
                if "DOCTYPE" in (body or ""):
                    return self._respond(200, "<root><q>&amp;waspE;</q></root>",
                                         {"Content-Type": "application/xml"})
                return self._respond(200, "<root><q>ok</q></root>",
                                     {"Content-Type": "application/xml"})
            return self._respond(200, "XML service ready. POST documents here.")

        if path == "/log":
            msg = self._dec(self._raw_val("msg"), 2)
            ua = self.headers.get("User-Agent", "")
            if "jndi" in msg.lower() or "jndi" in ua.lower():
                return self._respond(500, "log4j:ERROR Could not find server. "
                                          "Invalid LDAP URL: connection refused")
            return self._respond(200, "Logged event: %s" % msg)

        if path == "/export":
            col = self._dec(self._raw_val("col"), 1)
            return self._respond(200, 'id,name,%s\n1,wasp-user,%s\n' % (col, col),
                                 {"Content-Type": "text/csv"})

        if path == "/el":
            tpl = self._dec(self._raw_val("tpl"), 2)
            if tpl.endswith("${7*7}") or tpl == "${7*7}":
                return self._respond(200, "Computed: 49 for template engine.")
            return self._respond(200, "Template page. Literal: %s" % tpl)

        if path == "/product":
            vb = self._dec(self._raw_val("cat"), 2)
            if "AND 1=2" in vb:
                return self._respond(200, "No items found in this category. "
                                          "Try another filter today.")
            return self._respond(200, "Product catalog page. Featured items "
                                      "listed below with prices.")

        if path == "/slow":
            vb = self._dec(self._raw_val("q"), 2)
            if "SLEEP(" in vb or "pg_sleep" in vb.lower() or \
                    "WAITFOR" in vb.upper() or "DBMS_PIPE" in vb.upper():
                time.sleep(3.05)
            return self._respond(200, "Search results page. Nothing matched "
                                      "your filters here.")

        if path == "/api/users":
            dec1 = self._dec(rq, 1)
            body = self._body()
            if "$ne" in dec1 or "$gt" in dec1 or "$regex" in dec1 \
                    or "$where" in dec1 or (self.command == "POST" and "$ne" in body):
                return self._respond(200, '{"error":"MongoServerError: '
                                          'unknown operator $ne"}')
            return self._respond(200, '{"users":["alice","bob"],"count":2}')

        if path == "/page":
            vb = self._dec(self._raw_val("tpl"), 2)
            if "7*7" in vb:
                return self._respond(200, "Rendered output: 49 done.")
            return self._respond(200, "Home page. Welcome to the portal.")

        if path == "/ping":
            vb = self._dec(self._raw_val("host"), 2)
            for trig in (";id", "|id", "$(id)", "`id`", "&&id", "; id", "\nid",
                         ";/usr/bin/id", ";id;", "\tid"):
                if trig in vb:
                    return self._respond(200, "uid=33(www-data) gid=33(www-data) "
                                              "groups=33(www-data)")
            return self._respond(200, "PING utility endpoint. Provide a host.")

        if path == "/download":
            vb = self._dec(self._raw_val("file"), 2)
            if "etc/passwd" in vb:
                return self._respond(200, "root:x:0:0:0:0:root:/root:/bin/bash\n"
                                          "daemon:/usr/sbin:/usr/sbin/nologin\n")
            if "win.ini" in vb:
                return self._respond(200, "[fonts]\n[extensions]\n")
            return self._respond(200, "Downloads portal. Choose a file to fetch.")

        if path == "/go":
            vb = self._dec(self._raw_val("next"), 2)
            if "example.com" in vb:
                return self._respond(302, "Redirecting to example.com destination "
                                          "now.", {"Location": vb})
            hdrs = {}
            if "wasp-probe:" in vb.lower():
                hdrs["WASP-Probe"] = "wasp12"
            if "set-cookie: wasp12" in vb.lower():
                hdrs["Set-Cookie"] = "wasp12=probe"
            return self._respond(200, "User dashboard. Session active.", hdrs)

        if path == "/vote":
            pids = [self._dec(v, 2) for k, v in self._raw_pairs() if k == "pid"]
            return self._respond(200, "Vote count: %s" % (pids[-1] if pids else "0"))

        if path == "/protected":
            vw = self._dec(self._raw_val("p"), 1)      # WAF single-pass view
            if "'" in vw or re.search(r"(?i)union|select", vw):
                return self._respond(403, "Access Denied. Request blocked by "
                                          "security gateway. Event ID: 4212-3381.")
            vb = self._dec(self._raw_val("p"), 3)      # legacy recursive backend
            if "'" in vb:
                return self._respond(500, "You have an error in your SQL syntax; "
                                          "check the manual that corresponds to your "
                                          "MySQL server version for the right syntax")
            return self._respond(200, "Protected admin area. Console ready.")

        if path == "/search":
            return self._respond(200, "Search results listing. 0 documents matched.")

        if path == "/graphql":
            try:
                data = json.loads(self._body() or "{}")
            except Exception:
                data = {}
            q = str(data.get("query", ""))
            if "__typename" in q:
                return self._respond(200, '{"data":{"__typename":"Query"}}',
                                     {"Content-Type": "application/json"})
            if "1-" in q:
                return self._respond(200, '{"errors":[{"message":"Cannot query '
                                          "field 'usr' on type 'Query'. Did you mean "
                                          "'user'?\"}]}",
                                     {"Content-Type": "application/json"})
            return self._respond(200, '{"errors":[{"message":"Cannot query field '
                                      '\'zzz\' on type \'Query\'."}]}',
                                 {"Content-Type": "application/json"})

        return self._respond(404, "404 page not found: %s" % path)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.hits = []


# ===========================================================================
# ENV BOOTSTRAP
# ===========================================================================
def seed(base, scope_path, with_gql=True):
    shutil.rmtree(base, ignore_errors=True)
    eng = os.path.join(base, ENG)
    os.makedirs(os.path.join(eng, "surface"), exist_ok=True)
    os.makedirs(os.path.join(eng, "js"), exist_ok=True)
    os.makedirs(os.path.join(eng, "auth"), exist_ok=True)
    return eng


def write_scope(scope_path, origin):
    os.makedirs(os.path.dirname(scope_path), exist_ok=True)
    with open(scope_path, "w") as f:
        json.dump({
            "engagement": ENG,
            "authorized": True,
            "authorization_reference": "P12 self-test lab (localhost mock)",
            "targets": [origin],
            "ips": ["127.0.0.1"],
            "notes": "detection-only lab; no destructive testing"
        }, f, indent=2)


def seed_queue(eng, origin, with_gql=True):
    T = [
        ("/item?id=1", ["sql-injection"], 10.0),
        ("/slow?q=1", ["param-input"], 9.9),
        ("/product?cat=2", ["sql-injection"], 9.8),
        ("/hdr?id=1", ["sql-injection"], 9.7),
        ("/download?file=report.pdf", ["path-traversal-param"], 9.5),
        ("/api/users?name=bob", ["nosql-input"], 9.4),
        ("/page?tpl=home", ["template-injection"], 9.2),
        ("/el?tpl=home", ["template-injection"], 9.1),
        ("/ping?host=127.0.0.1", ["command-injection"], 9.0),
        ("/xml?doc=1", ["xml-input"], 8.8),
        ("/pp?name=guest", ["param-input"], 8.7),
        ("/log?msg=hello", ["param-input"], 8.65),
        ("/export?col=name", ["param-input"], 8.55),
        ("/vote?pid=10", ["param-pollution"], 8.4),
        ("/protected?p=1", ["waf-param-input"], 8.2),
        ("/search?q=test", ["reflection-input"], 8.0),
        ("/go?next=/dashboard", ["open-redirect"], 8.6),
    ]
    queue = [{"target": origin + p, "classes": c, "priority": pr} for p, c, pr in T]
    with open(os.path.join(eng, "surface", "priority_queue.json"), "w") as f:
        json.dump({"queue": queue}, f, indent=2)
    with open(os.path.join(eng, "auth", "injection_oracle.json"), "w") as f:
        json.dump({"endpoints": [
            {"url": origin + "/item?id=1", "param": "id", "note": "P9 oracle"}
        ]}, f, indent=2)
    if with_gql:
        with open(os.path.join(eng, "js", "graphql_ops.txt"), "w") as f:
            f.write(origin + "/graphql { __typename }\n")


def make_cfg():
    cfg = WC.Cfg(None)
    cfg.rate_limit = 250.0
    cfg.jitter = 0.0
    cfg.retries = 0
    cfg.timeout = 20
    cfg.max_requests = 100000
    cfg.allow_active = True
    cfg.resume = True
    cfg.allow_write_http = False
    # P12 tunables (roomy budgets so mock lab hits every engine)
    cfg.inject_error_probes = 48
    cfg.inject_boolean_probes = 24
    cfg.inject_time_probes = 4
    cfg.inject_nosql_probes = 12
    cfg.inject_ssti_probes = 20
    cfg.inject_cmdi_probes = 12
    cfg.inject_traversal_probes = 48
    cfg.inject_redirect_probes = 16
    cfg.inject_crlf_probes = 10
    cfg.inject_hpp_probes = 30
    cfg.inject_waf_probes = 10
    cfg.inject_waf_probe_budget = 24
    cfg.inject_gql_probes = 6
    cfg.inject_deser_probes = 6
    # v13 stage budgets (roomy so mock lab hits every new engine)
    cfg.inject_header_probes = 10
    cfg.inject_proto_probes = 6
    cfg.inject_xxe_probes = 4
    cfg.inject_el_probes = 6
    cfg.inject_log4shell_probes = 6
    cfg.inject_csv_probes = 5
    return cfg


# ===========================================================================
# 1) UNIT TESTS (pure helpers - koi network nahi)
# ===========================================================================
def unit_tests():
    print("\n" + "=" * 74)
    print("SECTION 1: UNIT TESTS (pure helpers)")
    print("=" * 74)

    check("unit.set_param.replace",
          MI.set_param("http://x/y?a=1&b=2", "a", "Z") == "http://x/y?a=Z&b=2")
    check("unit.set_param.append",
          MI.set_param("http://x/y", "a", "Z") == "http://x/y?a=Z")
    check("unit.get_param_value",
          MI.get_param_value("http://x/y?a=1&b=2", "b") == "2")
    check("unit.dup_param",
          MI.dup_param("http://x/y?a=1", "a", "ZZ") == "http://x/y?a=1&a=ZZ")
    check("unit.param_family.redirect", "redirect" in MI.param_family("next"))
    check("unit.param_family.file", "file" in MI.param_family("file"))
    check("unit.param_family.unknown-default", "sqli" in MI.param_family("zzz_unknown"))
    fam, snip = MI.match_sql_error("You have an error in your SQL syntax; "
                                   "check the manual ... MySQL server version")
    check("unit.sql_error.mysql", fam == "mysql" and bool(snip), str(fam))
    check("unit.nosql_error", MI.match_nosql_error("MongoServerError: bad")[0] is True)
    check("unit.cmdi_fp", MI.match_cmdi("uid=33(www-data) gid=33")[0] is True)
    tag, _ = MI.match_traversal_marker("root:x:0:0:0:0:root:/root:/bin/bash")
    check("unit.traversal_marker", tag == "unix-passwd", str(tag))
    tag, _ = MI.match_deser("Cannot deserialize value of type X")
    check("unit.deser_fp", tag == "generic-deserialize", str(tag))
    check("unit.timing_hit.true", MI.timing_hit(3.1, 0.01, 2.5) is True)
    check("unit.timing_hit.false", MI.timing_hit(1.0, 0.0, 2.5) is False)
    red = MI.pii_redact("contact admin@corp-example.com now")
    check("unit.pii_redact.email", "@***" in red and "corp-example.com" not in red)
    ctx_name, verbatim = MI.reflection_context("<p>hello WASPXYZMARK world</p>",
                                               "WASPXYZMARK")
    check("unit.reflection_context", ctx_name == "html-body" and verbatim,
          "%s/%s" % (ctx_name, verbatim))
    u = MI._nosql_get_url("http://x/y?a=1", "a", "$ne", "x")
    check("unit.nosql_get_url", ("%24ne" in u or "$ne" in u) and "a=1" not in u,
          u)

    # pair_diff with stub Resps
    class Stub:
        def __init__(self, status, body):
            self.status, self.body, self.error = status, body.encode(), None
        @property
        def text(self):
            return self.body.decode()
    base = {"status": 200, "len": len("catalog"), "text_sample": "catalog"}
    check("unit.pair_diff.confirmed",
          MI.pair_diff(Stub(200, "catalog"), Stub(200, "no items"), base)[0] == "CONFIRMED")
    check("unit.pair_diff.safe",
          MI.pair_diff(Stub(200, "catalog"), Stub(200, "catalog"), base)[0] == "SAFE")


# ===========================================================================
# 2) ACTIVE END-TO-END RUN
# ===========================================================================
def active_run(httpd, origin):
    print("\n" + "=" * 74)
    print("SECTION 2: ACTIVE RUN (mock lab, detection-only)")
    print("=" * 74)
    eng = seed(BASE, SCOPE_PATH)
    write_scope(SCOPE_PATH, origin)
    seed_queue(eng, origin)
    cfg = make_cfg()
    scope = WC.Scope(SCOPE_PATH)
    out = MI.run(cfg, scope, BASE)
    check("active.run.completed", os.path.isdir(out), out)
    return out


def artifact_tests(out):
    print("\n" + "=" * 74)
    print("SECTION 3: ARTIFACT + VERDICT ASSERTIONS")
    print("=" * 74)

    def jload(fname):
        p = os.path.join(out, fname)
        return WC.load_json(p, None) if os.path.exists(p) else None

    surf = jload("inject_surface.json")
    check("surface.file", isinstance(surf, dict))
    check("surface.targets>=8", isinstance(surf, dict) and
          len(surf.get("targets", [])) >= 8,
          str(len((surf or {}).get("targets", []))))
    tt = os.path.join(out, "inject_targets.txt")
    check("surface.targets_txt", os.path.exists(tt) and
          len([l for l in open(tt) if l.strip()]) >= 8)

    es = jload("error_sqli.json") or {}
    hit = [r for r in es.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/item" in r.get("url", "") and r.get("db") == "mysql"]
    check("error_sqli.item.CONFIRMED", len(hit) == 1,
          json.dumps(es.get("records", []))[:200])
    check("error_sqli.stats.probes", es.get("stats", {}).get("probes", 0) > 0)

    bs = jload("boolean_sqli.json") or {}
    hit = [r for r in bs.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/product" in r.get("url", "")]
    check("boolean_sqli.product.CONFIRMED", len(hit) == 1,
          json.dumps(bs.get("records", []))[:200])

    ts = jload("time_sqli.json") or {}
    hit = [r for r in ts.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/slow" in r.get("url", "")]
    check("time_sqli.slow.CONFIRMED", len(hit) == 1,
          json.dumps(ts.get("records", []))[:200])

    ns = jload("nosql_injection.json") or {}
    hit = [r for r in ns.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/api/users" in r.get("url", "")]
    check("nosql.users.CONFIRMED", len(hit) == 1,
          json.dumps(ns.get("records", []))[:200])
    check("nosql.login_probe.off", ns.get("stats", {}).get("login_probe") is False)

    ss = jload("ssti_scan.json") or {}
    hit = [r for r in ss.get("records", []) if r.get("verdict") == "CONFIRMED"
           and any(s.get("rendered") == "49" for s in r.get("signals", []))
           and "/page" in r.get("url", "")]
    check("ssti.page.CONFIRMED-49", len(hit) == 1,
          json.dumps(ss.get("records", []))[:200])

    cs = jload("cmdi_scan.json") or {}
    hit = [r for r in cs.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/ping" in r.get("url", "")
           and "uid=" in json.dumps(r.get("signals", []))]
    check("cmdi.ping.CONFIRMED", len(hit) == 1,
          json.dumps(cs.get("records", []))[:200])

    tv = jload("traversal_scan.json") or {}
    hit = [r for r in tv.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/download" in r.get("url", "")
           and r.get("winning_variant") == "unix-basic"]
    check("traversal.download.CONFIRMED", len(hit) == 1,
          json.dumps(tv.get("records", []))[:200])

    rd = jload("redirect_scan.json") or {}
    hit = [r for r in rd.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/go" in r.get("url", "")]
    ok302 = bool(hit) and any(s.get("status") == 302 and
                              "example.com" in str(s.get("location", ""))
                              for s in hit[0].get("signals", []))
    check("redirect.go.CONFIRMED-302", len(hit) == 1 and ok302,
          json.dumps(rd.get("records", []))[:220])
    check("redirect.canary.recorded", rd.get("stats", {}).get("canary") == "example.com")

    cr = jload("crlf_scan.json") or {}
    hit = [r for r in cr.get("records", []) if r.get("verdict") == "CONFIRMED"
           and any(s.get("style") == "header" for s in r.get("signals", []))]
    check("crlf.go.CONFIRMED-header", len(hit) == 1,
          json.dumps(cr.get("records", []))[:200])

    hp = jload("hpp_scan.json") or {}
    hit = [r for r in hp.get("records", []) if "/vote" in r.get("url", "")]
    check("hpp.vote.SUSPECTED-lastwins",
          len(hit) == 1 and hit[0]["signals"][0].get("style") == "last-wins",
          json.dumps(hp.get("records", []))[:200])

    wm = jload("waf_map.json") or []
    hit = [w for w in wm if "/protected" in w.get("url", "") and w.get("waf")]
    check("waf_map.protected.fingerprinted", len(hit) == 1, json.dumps(wm)[:220])

    wb = jload("waf_bypass.json") or {}
    hit = [r for r in wb.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/protected" in r.get("url", "")
           and r.get("winning") == "double-url-encode"]
    check("waf_bypass.protected.CONFIRMED", len(hit) >= 1,
          json.dumps(wb.get("records", []))[:240])
    check("waf_bypass.blocked_inputs", wb.get("stats", {}).get("blocked_inputs", 0) >= 1)

    gq = jload("gql_inject.json") or {}
    hit = [r for r in gq.get("records", []) if "/graphql" in r.get("url", "")]
    live = any(s.get("liveness") for r in hit for s in r.get("signals", []))
    check("gql.record+liveness", len(hit) >= 1 and live,
          json.dumps(gq.get("records", []))[:220])

    ds = jload("deser_scan.json") or {}
    hit = [r for r in ds.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/item" in r.get("url", "")]
    check("deser.item.CONFIRMED", len(hit) == 1,
          json.dumps(ds.get("records", []))[:200])

    # ---- v13 stages (S-W) ----
    hs = jload("header_inject.json") or {}
    hit = [r for r in hs.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/hdr" in r.get("url", "")]
    check("hdr.sqli.CONFIRMED", len(hit) == 1,
          json.dumps(hs.get("records", []))[:240])

    pp = jload("proto_pollution.json") or {}
    hit = [r for r in pp.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/pp" in r.get("url", "")]
    check("proto.pp.CONFIRMED", len(hit) == 1,
          json.dumps(pp.get("records", []))[:240])

    xe = jload("xxe_canary.json") or {}
    hit = [r for r in xe.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/xml" in r.get("url", "")]
    check("xxe.xml.CONFIRMED", len(hit) == 1,
          json.dumps(xe.get("records", []))[:240])

    el = jload("el_log4shell.json") or {}
    hit = [r for r in el.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/el" in r.get("url", "")
           and any(s.get("kind") == "el" for s in r.get("signals", []))]
    check("el.refine.CONFIRMED", len(hit) == 1,
          json.dumps(el.get("records", []))[:240])
    check("el.log4shell.default-off",
          el.get("stats", {}).get("log4shell_enabled") is False
          and el.get("stats", {}).get("log4shell_probes", 0) == 0,
          json.dumps(el.get("stats", {}))[:160])

    cv = jload("csv_inject.json") or {}
    hit = [r for r in cv.get("records", []) if r.get("verdict") == "CONFIRMED"
           and "/export" in r.get("url", "")]
    check("csv.export.CONFIRMED", len(hit) == 1,
          json.dumps(cv.get("records", []))[:240])

    cat = os.path.join(out, "TECHNIQUES_CATALOG.md")
    check("catalog.exists+content", os.path.exists(cat)
          and "CWE-89" in open(cat).read() and "Log4Shell" in open(cat).read())
    cm = jload("cwe_owasp_map.json") or {}
    check("cwemap.keys", cm.get("sqli_error", {}).get("cwe") == "CWE-89"
          and cm.get("prototype_pollution", {}).get("cwe") == "CWE-1321")

    rm = jload("reflection_map.json") or {}
    params = [p.get("param") for p in rm.get("params", [])]
    verbatim = [p for p in rm.get("params", []) if p.get("verbatim")]
    check("reflection.map>=1", len(rm.get("params", [])) >= 1, str(params))
    check("reflection.verbatim-next", any(p == "next" for p in params)
          and len(verbatim) >= 1, str(params))

    mx = jload("injection_matrix.json") or {}
    rows = mx.get("rows", [])
    conf_rows = [r for r in rows if "CONFIRM" in json.dumps(r.get("verdicts", {}))]
    check("matrix.rows>=8", len(rows) >= 8, str(len(rows)))
    check("matrix.has-CONFIRMED", len(conf_rows) >= 5, str(len(conf_rows)))
    mtxt = os.path.join(out, "injection_matrix.txt")
    check("matrix.txt.exists", os.path.exists(mtxt) and os.path.getsize(mtxt) > 100)

    hy = jload("injection_hypotheses.json") or {}
    check("hypotheses>=5", hy.get("count", 0) >= 5, str(hy.get("count")))

    for doc in ("INJECTION_FINDINGS.md", "injection_test_plan.md",
                "injection_chains.txt"):
        p = os.path.join(out, doc)
        check("doc.%s" % doc, os.path.exists(p) and os.path.getsize(p) > 200)
    fmd = open(os.path.join(out, "INJECTION_FINDINGS.md")).read()
    check("findings_md.table+sev", "INJ-001" in fmd and "critical" in fmd.lower()
          and "Phase 12" in fmd)

    fd = jload("findings.json") or {}
    keys = set(f.get("key") for f in fd.get("findings", []))
    need = {"sqli_error", "sqli_boolean", "sqli_time", "nosql_injection",
            "ssti_detected", "cmdi_detected", "path_traversal_confirmed",
            "open_redirect_confirmed", "crlf_header_injection", "hpp_anomaly",
            "waf_detected", "sqli_waf_bypassable", "deser_hint",
            "gql_error_disclosure",
            "sqli_header", "prototype_pollution", "xxe_entity_processing",
            "el_injection", "csv_formula_injection"}
    missing = need - keys
    check("findings.keys>=19", not missing, "missing=%s have=%s"
          % (sorted(missing), sorted(keys)))
    check("findings.count>=20", fd.get("count", 0) >= 20, str(fd.get("count")))

    ff = jload("feedforward.json") or {}
    mp = ff.get("routing", {})
    check("feedforward.phase13-xss", len((mp.get("to_phase13_xss") or {})
                                         .get("xss_ripe", [])) >= 1)
    check("feedforward.phase14-redirect", len((mp.get("to_phase14_redirect") or {})
                                              .get("confirmed", [])) >= 1)
    check("feedforward.phase15-ssrf", "to_phase15_ssrf" in mp)
    check("feedforward.phase16-files", "to_phase16_files" in mp)
    check("feedforward.phase18-graphql", "to_phase18_graphql" in mp)
    check("feedforward.phase32-report", "to_phase32_report" in mp)

    mf = jload("MANIFEST.json") or {}
    check("manifest.files>=20", len(mf.get("files", [])) >= 20,
          str(len(mf.get("files", []))))
    ck = os.path.join(out, "_state", "checkpoint_inject.json")
    check("checkpoint.persisted", os.path.exists(ck))

    # ---- RWX standing rule: HAR file 0777 ----
    bad = []
    for r, _d, fs in os.walk(out):
        for fn in fs:
            p = os.path.join(r, fn)
            if (os.stat(p).st_mode & 0o777) != 0o777:
                bad.append(os.path.relpath(p, out))
    check("rwx.all-files-0777", not bad, "non-rwx=%s" % bad[:6])


# ===========================================================================
# 3) PASSIVE MODE (allow_active=False -> 0 network probes)
# ===========================================================================
def passive_run(httpd, origin):
    print("\n" + "=" * 74)
    print("SECTION 4: PASSIVE MODE (0 probes)")
    print("=" * 74)
    eng = seed(BASE2, SCOPE_PATH2)
    write_scope(SCOPE_PATH2, origin)
    seed_queue(eng, origin, with_gql=False)
    cfg = make_cfg()
    cfg.allow_active = False
    scope = WC.Scope(SCOPE_PATH2)
    hits_before = len(httpd.hits)
    out = MI.run(cfg, scope, BASE2)
    new_hits = len(httpd.hits) - hits_before
    check("passive.run.completed", os.path.isdir(out), out)
    check("passive.zero-probes", new_hits <= 1, "hits=%d" % new_hits)
    es_p = WC.load_json(os.path.join(out, "error_sqli.json"), None)
    check("passive.stage-files-empty", isinstance(es_p, dict) and
          es_p.get("records") == [], str(es_p))
    hy = WC.load_json(os.path.join(out, "injection_hypotheses.json"), None)
    check("passive.hypotheses>=5", isinstance(hy, dict) and
          hy.get("count", 0) >= 5, str(hy))
    surf = WC.load_json(os.path.join(out, "inject_surface.json"), None)
    check("passive.surface-present", isinstance(surf, dict) and
          len(surf.get("targets", [])) >= 8)
    bad = [fn for r, _d, fs in os.walk(out) for fn in fs
           if (os.stat(os.path.join(r, fn)).st_mode & 0o777) != 0o777]
    check("passive.rwx-0777", not bad, str(bad[:4]))
    return out


# ===========================================================================
# 4) CHECKPOINT REPLAY (FIX-4: findings re-derivation, 0 new requests)
# ===========================================================================
def replay_run(httpd, origin, out_first, findings_first):
    print("\n" + "=" * 74)
    print("SECTION 5: CHECKPOINT REPLAY (resume, FIX-4)")
    print("=" * 74)
    cfg = make_cfg()
    scope = WC.Scope(SCOPE_PATH)
    hits_before = len(httpd.hits)
    out = MI.run(cfg, scope, BASE)
    delta = len(httpd.hits) - hits_before
    check("replay.same-outdir", out == out_first, "%s vs %s" % (out, out_first))
    check("replay.zero-new-requests", delta == 0, "new hits=%d" % delta)
    fd = WC.load_json(os.path.join(out, "findings.json"), None)
    check("replay.findings-rederived", isinstance(fd, dict) and
          fd.get("count") == findings_first and findings_first >= 15,
          "replay=%s first=%s" % (fd.get("count"), findings_first))
    es = WC.load_json(os.path.join(out, "error_sqli.json"), None)
    hit = [r for r in (es or {}).get("records", []) if r.get("verdict") == "CONFIRMED"]
    check("replay.stage-C-cached-CONFIRMED", len(hit) >= 1)


# ===========================================================================
# 5) LOG4SHELL GATED MINI-RUN (inject_allow_log4shell=False default -> explicit ON)
# ===========================================================================
def log4shell_run(httpd, origin):
    print("\n" + "=" * 74)
    print("SECTION 6: LOG4SHELL GATED RUN (RoE-gated, loopback-only)")
    print("=" * 74)
    eng = seed(BASE3, SCOPE_PATH3)
    write_scope(SCOPE_PATH3, origin)
    seed_queue(eng, origin, with_gql=False)
    cfg = make_cfg()
    cfg.inject_allow_log4shell = True
    cfg.inject_log4shell_probes = 6
    scope = WC.Scope(SCOPE_PATH3)
    out = MI.run(cfg, scope, BASE3)
    el = WC.load_json(os.path.join(out, "el_log4shell.json"), None) or {}
    hit = [r for r in el.get("records", []) if r.get("verdict") == "CONFIRMED"
           and any(s.get("kind") == "log4shell" for s in r.get("signals", []))]
    check("log4shell.gated-run.CONFIRMED", len(hit) >= 1,
          json.dumps(el.get("records", []))[:240])
    check("log4shell.loopback-only-payloads",
          all("127.0.0.1" in s.get("payload", "")
              for r in hit for s in r.get("signals", [])),
          json.dumps([s.get("payload") for r in hit
                      for s in r.get("signals", [])])[:200])
    check("log4shell.stats-enabled", el.get("stats", {}).get("log4shell_enabled")
          is True and el.get("stats", {}).get("log4shell_probes", 0) >= 1)
    fd = WC.load_json(os.path.join(out, "findings.json"), None) or {}
    keys = set(f.get("key") for f in fd.get("findings", []))
    check("log4shell.finding-present", "log4shell_indicator" in keys,
          str(sorted(keys))[:300])
    bad = [fn for r, _d, fs in os.walk(out) for fn in fs
           if (os.stat(os.path.join(r, fn)).st_mode & 0o777) != 0o777]
    check("log4shell.rwx-0777", not bad, str(bad[:4]))


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    t0 = time.time()
    shutil.rmtree(BASE, ignore_errors=True)
    shutil.rmtree(BASE2, ignore_errors=True)
    shutil.rmtree(BASE3, ignore_errors=True)

    unit_tests()

    httpd = LabServer(("127.0.0.1", 0), LabHandler)
    port = httpd.server_address[1]
    origin = "http://127.0.0.1:%d" % port
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    print("\n[mock lab] %s  (endpoints: item/product/slow/api-users/page/ping/"
          "download/go/vote/protected/search/graphql)" % origin)

    try:
        out = active_run(httpd, origin)
        findings_count = 0
        if os.path.isdir(out):
            artifact_tests(out)
            fd = WC.load_json(os.path.join(out, "findings.json"), None)
            findings_count = (fd or {}).get("count", 0)
        passive_run(httpd, origin)
        if os.path.isdir(out):
            replay_run(httpd, origin, out, findings_count)
        log4shell_run(httpd, origin)
    finally:
        httpd.shutdown()

    print("\n" + "=" * 74)
    print("RESULT: %d PASS / %d FAIL  (%.1fs)"
          % (len(PASS), len(FAIL), time.time() - t0))
    print("=" * 74)
    if FAIL:
        print("Failures:")
        for n, d in FAIL:
            print("  - %s: %s" % (n, d[:300]))
        sys.exit(1)
    print("ALL TESTS PASSED - mod_inject.py v13.0.0-ultra-ultra-pro-max is "
          "delivery-ready.")
    sys.exit(0)


if __name__ == "__main__":
    main()
