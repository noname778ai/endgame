#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TEST MOD_CONTENT (ULTRA v3) - offline harness, koi internet nahi chahiye
==========================================================================
Official wasp_selftest.py P5 assertions cover karta hai; YE harness ULTRA
v3 ke NAYE techniques ko deeply verify karta hai:

  Mock Host A (port 8801) - rich vulnerable target:
    * 403 /admin with X-Original-URL bypass      -> bypass engine CONFIRMED
    * /backups/ dir-listing (children recursion) -> child .sql discovered
    * /.DS_Store binary (2 filenames)            -> hidden child probed
    * /.env (AWS key + password)                 -> env intel + secret sniff
    * /.git/HEAD + /.git/config                  -> branch + remote redacted
    * /swagger.json                              -> openapi endpoint map
    * nested sitemap (index -> child)            -> /portal/dashboard found
    * /wp-json/wp/v2/users                       -> user_enum finding
    * /login (password form)                     -> auth-wall flagged
    * /api + /api/v2                             -> version probe hit
    * /static/app.js + .map                      -> sourcemap + js hints
  Mock Host B (port 8802) - dead target          -> graceful baseline-fail
  Budget run (max_requests=40)                   -> graceful budget_stop
  Partial resume (composite key delete)          -> stages cached, no re-probe

Usage:  python3 test_mod_content.py
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block1_recon")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, re, sys, json, time, struct, tempfile, importlib, threading, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

PORT_A, PORT_B = 8801, 8802
BASE_A = "http://127.0.0.1:%d" % PORT_A
RESULTS = []
HITS = {"n": 0}

ADMIN_BODY = ("<!doctype html><html><head><title>Admin Panel</title></head>"
              "<body><h1>ADMIN DASHBOARD</h1><p>user management console</p>"
              "<a href='/admin/users'>users</a></body></html>")


def _html(title, body):
    return ("<!doctype html><html><head><title>%s</title></head><body>%s</body></html>"
            % (title, body)).encode()


def ds_store_blob(names):
    blob = b""
    for nm in names:
        raw = nm.encode("utf-16-be")
        blob += b"\x00\x00\x00\x01" + struct.pack(">H", len(nm)) + raw
        blob += b"\x00\x00\x00\x02" + b"\x00" * 16
    return blob


class HandlerA(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except Exception:
                pass

    def do_OPTIONS(self):
        self._send(200, b"", headers={"Allow": "GET, HEAD, OPTIONS, POST"})

    def do_HEAD(self):
        self._route()

    def do_GET(self):
        self._route()

    def _route(self):
        HITS["n"] += 1
        p = self.path.split("?")[0]
        # 403 bypass: /admin 403 normally, but X-Original-URL trick works
        if p == "/admin":
            xou = self.headers.get("X-Original-URL") or ""
            if xou:
                self._send(200, ADMIN_BODY)
            else:
                self._send(403, b"forbidden", "text/plain")
            return
        if p == "/admin/users":
            self._send(403, b"forbidden", "text/plain")
            return
        if p in ("/backups", "/hidden-vault"):
            self._send(301, b"", headers={"Location": p + "/"})
            return
        R = {
            "/": (200, _html("UltraTest Home",
                             "<h1>Home</h1><script src='/static/app.js'></script>"
                             "<a href='/admin'>admin</a>"), "text/html; charset=utf-8"),
            "/login": (200, _html("Login", "<form><input type='password' name='pw'>"
                                  "<input name='user'></form>"), "text/html; charset=utf-8",
                       {"Set-Cookie": "preauth=1; Path=/"}),
            "/robots.txt": (200, "User-agent: *\nDisallow: /hidden-vault/\n"
                                 "Sitemap: %s/sitemap.xml\n" % BASE_A, "text/plain"),
            "/sitemap.xml": (200, "<?xml version='1.0'?><sitemapindex><sitemap><loc>"
                             + BASE_A + "/sitemap-pages.xml</loc></sitemap></sitemapindex>",
                             "application/xml"),
            "/sitemap-pages.xml": (200, "<?xml version='1.0'?><urlset><url><loc>"
                                   + BASE_A + "/portal/dashboard?ref=news</loc></url>"
                                   "<url><loc>" + BASE_A + "/static/app.js.map</loc></url></urlset>",
                                   "application/xml"),
            "/portal/dashboard": (200, _html("Dashboard", "<p>internal dashboard</p>"
                                  "<script src='/static/app.js'></script>"),
                                  "text/html; charset=utf-8"),
            "/.env": (200, "APP_KEY=base64:AAAAKEY\nDB_PASSWORD=hunter2secret\n"
                      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "text/plain"),
            "/.git/HEAD": (200, "ref: refs/heads/main\n", "text/plain"),
            "/.git/config": (200, '[remote "origin"]\n\turl = git@github.com:corp/web.git\n',
                             "text/plain"),
            "/.DS_Store": (200, ds_store_blob(["secret_notes.txt", "admin_dump.sql"]),
                           "application/octet-stream"),
            "/secret_notes.txt": (200, "notes: rotate admin password flow v2", "text/plain"),
            "/admin_dump.sql": (200, "INSERT INTO users VALUES (1,'admin');", "application/sql"),
            "/backups/": (200, _html("Index of /backups/",
                          "<a href='../'>Parent Directory</a>"
                          "<a href='db-2025-01-01.sql'>db-2025-01-01.sql</a>"
                          "<a href='site-old.tar.gz'>site-old.tar.gz</a>"),
                          "text/html; charset=utf-8"),
            "/backups/db-2025-01-01.sql": (200, "-- dump\nCREATE TABLE u;", "application/sql"),
            "/backups/site-old.tar.gz": (200, "BINARYTARGZ", "application/gzip"),
            "/swagger.json": (200, json.dumps({"openapi": "3.0.0", "paths": {
                "/api/v1/users": {"get": {}}, "/api/v1/orders": {"post": {}},
                "/api/internal/audit": {"get": {}}}}), "application/json"),
            "/api": (200, json.dumps({"version": "v1", "docs": "/swagger.json"}),
                     "application/json"),
            "/api/v2": (200, json.dumps({"version": "v2"}), "application/json"),
            "/api/v1/users": (200, json.dumps([{"id": 1, "email": "a@x.com"}]),
                              "application/json"),
            "/wp-json/wp/v2/users": (200, json.dumps(
                [{"id": 1, "slug": "admin", "name": "Admin"},
                 {"id": 2, "slug": "editor", "name": "Ed"}]), "application/json"),
            "/wp-content/debug.log": (200, "[01-Jan-2026] PHP Notice: x", "text/plain"),
            "/health": (200, json.dumps({"status": "ok"}), "application/json"),
            "/static/app.js": (200, "const api='/api/v1';", "application/javascript"),
            "/static/app.js.map": (200, json.dumps({"version": 3, "sources": ["a.js"],
                                                    "sourcesContent": ["x"]}),
                                   "application/json"),
            "/hidden-vault/": (200, _html("Index of /hidden-vault/",
                              "<a href='../'>Parent Directory</a>"
                              "<a href='flag.txt'>flag.txt</a>"),
                              "text/html; charset=utf-8"),
            "/hidden-vault/flag.txt": (200, "FLAG-VAULT", "text/plain"),
        }
        if p in R:
            code, body, ctype = R[p][0], R[p][1], R[p][2]
            hdrs = R[p][3] if len(R[p]) > 3 else {}
            if p == "/":
                hdrs = dict(hdrs, **{"Set-Cookie": "sid=abc123; Path=/"})
            self._send(code, body, ctype, hdrs)
            return
        # soft-404 catch-all: fixed 200 body
        self._send(200, _html("Not Found", "Page not found - soft404 template"))


def start_a():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT_A), HandlerA)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-56s %s" % ("[PASS]" if cond else "[FAIL]", name, str(detail)[:70]))
    return bool(cond)


def make_env(tmp, targets, extra_cfg=None, fresh=True):
    from wasp_core import Cfg, Scope, Checkpoint, outdir_for
    scope_path = os.path.join(tmp, "scope.json")
    cfg_path = os.path.join(tmp, "config.json")
    json.dump({"engagement": "t5", "authorized": True,
               "authorization_reference": "OFFLINE SELFTEST",
               "targets": targets, "domains": [], "wildcards": [],
               "excludes": [], "ips": ["127.0.0.1"],
               "notes": "offline"}, open(scope_path, "w"))
    cfgd = {"rate_limit": 500, "concurrency": 12, "timeout": 4, "retries": 0,
            "max_requests": 30000, "verify_tls": False, "jitter": 0.0,
            "save_bodies": False, "adaptive_throttle": False, "negative_cache": False}
    cfgd.update(extra_cfg or {})
    json.dump(cfgd, open(cfg_path, "w"))
    cfg = Cfg(cfg_path)
    sc = Scope(scope_path)
    return cfg, sc


def run_content(cfg, sc, tmp):
    mod = importlib.import_module("mod_content")
    from wasp_core import outdir_for, Checkpoint
    mout = outdir_for(os.path.join(tmp, "out"), sc.engagement, "content")
    cp = Checkpoint(mout, "content", fresh=True)
    cfg.checkpoint = cp
    cfg.module_outdir = mout
    cfg.resume = False
    mod.run(cfg, sc, os.path.join(tmp, "out"))
    cp.mark_complete()
    return mout


def load(tmp, rel):
    p = os.path.join(tmp, "out", "t5", rel)
    return json.load(open(p)) if os.path.exists(p) else None


def text_of(mout, name):
    p = os.path.join(mout, name)
    return open(p, errors="ignore").read() if os.path.exists(p) else ""


# ---------------------------------------------------------------------------
def main():
    tmp = tempfile.mkdtemp(prefix="t5_ultra_")
    print("  temp: %s" % tmp)
    srv = start_a()
    print("  mock A: %s  (dead B: %s)\n" % (BASE_A, "http://127.0.0.1:%d" % PORT_B))

    # ================= RUN 1: rich host A =================
    print("== RUN 1: rich host (bypass/dirlisting/dsstore/nested/authwall) ==")
    cfg, sc = make_env(tmp, [BASE_A])
    t0 = time.time()
    mout = run_content(cfg, sc, tmp)
    dt = time.time() - t0
    check("R1 module ran (%.1fs, %d mock hits)" % (dt, HITS["n"]), True)

    c = load(tmp, "content/content.json")
    check("content.json written", c is not None)
    rec = (list(c["results"].values()) or [{}])[0] if c else {}

    found_paths = {f["path"] for f in rec.get("found", [])}
    ext_paths = {f["path"] for f in rec.get("extensions", [])}
    arts = {a["path"]: a for a in rec.get("artifacts", [])}

    # --- 403 bypass engine ---
    bp = {b["path"]: b for b in rec.get("bypass_403", [])}
    check("403 bypass engine ran on /admin", "/admin" in bp, sorted(bp))
    check("403 bypass CONFIRMED for /admin (X-Original-URL)",
          bp.get("/admin", {}).get("verdict") == "CONFIRMED",
          bp.get("/admin", {}).get("verdict"))
    check("bypass win recorded with kind",
          (bp.get("/admin", {}).get("win") or {}).get("kind") in ("headers", "path_variant"),
          bp.get("/admin", {}).get("win"))
    check("bypass_403.txt has CONFIRMED line",
          "CONFIRMED" in text_of(mout, "bypass_403.txt"))

    # --- dir redirects + dirlisting + child recursion ---
    check("/backups 301 captured in dirs",
          any(d["path"] == "/backups" for d in rec.get("dirs", [])),
          rec.get("dirs"))
    check("dirlisting detected on /backups(/)",
          any(d["path"].rstrip("/") == "/backups" for d in rec.get("dirlistings", [])),
          rec.get("dirlistings"))
    check("dirlisting CHILD auto-discovered (db-2025-01-01.sql)",
          "/backups/db-2025-01-01.sql" in found_paths, sorted(found_paths)[:14])
    check("dirlisting flagged on found entry",
          any(f.get("dirlisting") for f in rec.get("found", [])
              if f["path"].rstrip("/") == "/backups"),
          [f["path"] for f in rec.get("found", []) if f.get("dirlisting")])
    check("dirlistings.txt written", "/backups" in text_of(mout, "dirlistings.txt"))

    # --- .DS_Store binary parse + hidden children ---
    check("/.DS_Store artifact found", "/.DS_Store" in arts)
    check(".DS_Store names extracted (2)",
          len((arts.get("/.DS_Store", {}).get("intel") or {})
              .get("ds_store_names", [])) == 2,
          (arts.get("/.DS_Store", {}).get("intel") or {}).get("ds_store_names"))
    check("DS_Store child probed (secret_notes.txt)",
          "/secret_notes.txt" in arts, sorted(arts))
    check("DS_Store child probed (admin_dump.sql)", "/admin_dump.sql" in arts)

    # --- .git + .env intel ---
    check("/.git/HEAD branch=main parsed",
          (arts.get("/.git/HEAD", {}).get("intel") or {}).get("git_branch") == "main",
          (arts.get("/.git/HEAD", {}).get("intel") or {}))
    check("/.git/config remote REDACTED",
          (arts.get("/.git/config", {}).get("intel") or {}).get("git_remotes") and
          "*" in str((arts.get("/.git/config", {}).get("intel") or {}).get("git_remotes")),
          (arts.get("/.git/config", {}).get("intel") or {}).get("git_remotes"))
    check("/.env critical + keys inventory",
          arts.get("/.env", {}).get("severity_hint") == "critical" and
          "DB_PASSWORD" in ((arts.get("/.env", {}).get("intel") or {})
                            .get("env", {}).get("keys", [])),
          arts.get("/.env", {}).get("note"))
    check("env values REDACTED in samples",
          all("*" in s.get("value_redacted", "") for s in
              ((arts.get("/.env", {}).get("intel") or {})
               .get("env", {}).get("samples_redacted", []))))

    # --- secret sniffing ---
    check("AWS key sniffed (redacted)",
          any(s["type"] == "aws_access_key" for s in
              arts.get("/.env", {}).get("secrets_sniffed", [])),
          [s["type"] for s in arts.get("/.env", {}).get("secrets_sniffed", [])])
    check("secrets_content.txt redacted sample", "AKIA" in text_of(mout, "secrets_content.txt")
          and "****" in text_of(mout, "secrets_content.txt"))
    check("no RAW secret in JSON (hunter2 absent)",
          "hunter2secret" not in json.dumps(c))

    # --- openapi + api versions ---
    op = (arts.get("/swagger.json", {}).get("intel") or {}).get("openapi", {})
    check("openapi parsed (3 paths)", op.get("n_paths") == 3, op)
    check("api_endpoints_expanded includes spec+found",
          "/api/internal/audit" in rec.get("api_endpoints_expanded", []) and
          "/api" in rec.get("api_endpoints_expanded", []),
          rec.get("api_endpoints_expanded", [])[:6])
    check("version probe: /api/v2 reachable (wordlist or probe)",
          "/api/v2" in found_paths or
          any(v["path"] == "/api/v2" for v in rec.get("api_versions", [])),
          [v["path"] for v in rec.get("api_versions", [])])
    check("api_versions mechanism ran (list)",
          isinstance(rec.get("api_versions"), list))
    check("api_endpoints.txt written", "/api/internal/audit"
          in text_of(mout, "api_endpoints.txt"))

    # --- nested sitemap + params ---
    sm = rec.get("metadata", {}).get("/sitemap.xml", {})
    check("nested sitemap crawled",
          any(u.endswith("/sitemap-pages.xml") for u in (sm.get("nested_sitemaps") or []))
          and bool(sm.get("nested_urls")), sm.get("nested_sitemaps"))
    check("sitemap child path discovered (/portal/dashboard)",
          "/portal/dashboard" in found_paths)
    check("query param harvested (ref)", "ref" in rec.get("params", []),
          rec.get("params"))
    check("params_all.txt written", "ref" in text_of(mout, "params_all.txt"))

    # --- CMS pack + user enum ---
    check("wp-json user enum flagged",
          arts.get("/wp-json/wp/v2/users", {}).get("user_enum") is True)
    check("wp debug.log artifact (cms)", "/wp-content/debug.log" in arts)
    check("user-enum finding exists",
          any("user" in f["title"].lower() or "wp-json" in f["title"]
              for f in rec.get("findings", [])),
          [f["title"] for f in rec.get("findings", [])][:6])

    # --- authwall ---
    check("/login flagged auth-wall",
          any(a["path"] == "/login" for a in rec.get("authwalls", [])) and
          any(f.get("auth_wall") for f in rec.get("found", []) if f["path"] == "/login"),
          rec.get("authwalls"))

    # --- sourcemaps + js hints + cookies ---
    check("sourcemap detected", any(u.endswith(".js.map") for u in rec.get("sourcemaps", [])),
          rec.get("sourcemaps"))
    check("js hints from <script src>",
          any(u.endswith("/static/app.js") for u in rec.get("js_urls", [])),
          rec.get("js_urls", [])[:3])
    check("js_hints.txt written", "app.js" in text_of(mout, "js_hints.txt"))
    check("cookie names captured (sid/preauth)",
          "sid" in rec.get("cookies_seen", []) or "preauth" in rec.get("cookies_seen", []),
          rec.get("cookies_seen"))

    # --- robots hint word probed (via redirect + dirlisting chain) ---
    check("robots Disallow path probed (hidden-vault/flag.txt)",
          "/hidden-vault/flag.txt" in found_paths,
          [p for p in found_paths if "hidden" in p])

    # --- findings / chains / priority ---
    check("findings >= 6 with ids", len(rec.get("findings", [])) >= 6 and
          all(f.get("id", "").startswith("P5-") for f in rec.get("findings", [])),
          len(rec.get("findings", [])))
    check("findings have remediation + chain_hint",
          all(f.get("remediation") and f.get("chain_hint")
              for f in rec.get("findings", [])))
    check("chains built (git/env/api/bypass)", len(rec.get("chains", [])) >= 3,
          [c0.get("chain", "")[:40] for c0 in rec.get("chains", [])])
    check("priority top has score+reasons",
          rec.get("priority") and rec["priority"][0]["score"] > 40 and
          rec["priority"][0].get("reasons"), rec.get("priority", [{}])[0].get("path"))
    check("priority.txt written", text_of(mout, "priority.txt").count("\n") >= 5)
    check("chains.txt written", "high" in text_of(mout, "chains.txt"))
    check("P5_FINDINGS.txt written", "P5-" in text_of(mout, "P5_FINDINGS.txt"))
    check("advertised destructive methods captured (POST not in list)",
          isinstance(rec.get("methods"), dict) and
          any(v.get("OPTIONS", {}).get("allow") for v in rec.get("methods", {}).values()))
    check("techniques list in JSON (22)", len(c.get("techniques", [])) == 22)
    check("no soft404 noise in found", all(not f.get("soft404") for f in rec.get("found", [])))
    check("all ULTRA exports exist", all(os.path.exists(os.path.join(
        mout, n)) for n in ["priority.txt", "bypass_403.txt", "params_all.txt",
                            "js_hints.txt", "sourcemaps.txt", "dirlistings.txt",
                            "secrets_content.txt", "chains.txt", "P5_FINDINGS.txt"]))

    # ================= RUN 1b: partial resume (composite delete) =================
    print("\n== RUN 1b: partial resume (sub-stage cache) ==")
    from wasp_core import Checkpoint, outdir_for
    hits_before = HITS["n"]
    cp2 = Checkpoint(mout, "content")
    keys_before = set(cp2.done.keys())
    ck_name = "host:127.0.0.1"
    composite = cp2.done.pop(ck_name, None)
    cp2._save()
    cfg.resume = True
    mod = importlib.import_module("mod_content")
    cfg.module_outdir = mout
    cfg.checkpoint = Checkpoint(mout, "content")
    mod.run(cfg, sc, os.path.join(tmp, "out"))
    added = HITS["n"] - hits_before
    cp3 = Checkpoint(mout, "content")
    check("partial resume: stages cached (only composite re-marked)",
          set(cp3.done.keys()) == keys_before, sorted(cp3.done.keys()))
    check("partial resume: no stage re-probe (<20 reqs, got %d)" % added, added < 20, added)
    check("partial resume: artifacts identical", len((cp3.result_of(ck_name) or {})
          .get("artifacts", [])) == len(rec.get("artifacts", [])))

    # ================= RUN 2: dead host graceful =================
    print("\n== RUN 2: dead host (baseline-fail) ==")
    tmp2 = tempfile.mkdtemp(prefix="t5_dead_")
    cfg2, sc2 = make_env(tmp2, ["http://127.0.0.1:%d" % PORT_B])
    run_content(cfg2, sc2, tmp2)
    c2 = load(tmp2, "content/content.json")
    r2 = (list(c2["results"].values()) or [{}])[0] if c2 else {}
    check("dead host: error recorded, no crash", r2.get("error") == "baseline-failed",
          r2.get("error"))
    check("dead host: composite checkpoint marked (resume-safe)",
          "host:127.0.0.1" in Checkpoint(outdir_for(os.path.join(tmp2, "out"), "t5",
                                                   "content"), "content").done)

    # ================= RUN 3: budget graceful stop =================
    print("\n== RUN 3: budget kill-switch (max_requests=45) ==")
    tmp3 = tempfile.mkdtemp(prefix="t5_budget_")
    cfg3, sc3 = make_env(tmp3, [BASE_A], extra_cfg={"max_requests": 45})
    run_content(cfg3, sc3, tmp3)
    c3 = load(tmp3, "content/content.json")
    r3 = (list(c3["results"].values()) or [{}])[0] if c3 else {}
    check("budget stop flagged", r3.get("budget_stop") is True, r3.get("budget_stop"))
    check("budget stop: no crash, partial results kept", c3 is not None and
          "results" in c3)

    srv.shutdown()
    print("\n" + "=" * 76)
    npass = sum(1 for _, okk, _ in RESULTS if okk)
    print("RESULT: %d/%d checks passed" % (npass, len(RESULTS)))
    if npass != len(RESULTS):
        print("FAILED:")
        for name, okk, d in RESULTS:
            if not okk:
                print("   - %s  %s" % (name, d))
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(tmp2, ignore_errors=True)
    shutil.rmtree(tmp3, ignore_errors=True)
    return 0 if npass == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
