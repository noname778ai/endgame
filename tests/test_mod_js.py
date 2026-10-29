#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_mod_js.py - Phase 7 ULTRA v3 offline harness (koi external network nahi).

Mock host A (rich, vulnerable-by-design SPA):
  * /static/app.js        - axios/fetch/XHR verbs, wss, graphql GetUser+subscription,
                            template literals, concat URLs, openapi-ish paths, isAdmin,
                            localStorage tokens, postMessage '*', document.domain,
                            sk_live/pk_live/AKIA secrets, __NEXT_DATA__ inline,
                            sourceMappingURL=/static/app.js.map
  * /static/app.js.map    - sourcesContent (hidden /internal/admin endpoints)
  * /static/chunk.min.js  - NO sourcemap comment, X-SourceMap header route -> map
  * /static/chunk.min.js.map - map bina sourcesContent (original source fetch path)
  * /src/roles.js         - "original source" jo map se fetch hota hai
  * /static/vendor.js     - 403 protected (WAF sim) + stealth retry header accept karta hai
  * /api/v1/users, /api/v1/users/123, /admin, /graphql, /upload, /socket.io - probe paths
Mock host B: dead (connection refused)

Checks: 40+ assertions covering v2 parity (selftest P7 items) + v3 features,
resume consistency, blocked-asset handling, priority queue, feedforward superset.
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block1_recon")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, time, socket, threading, tempfile, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PORT = 4771
BASE = "http://127.0.0.1:%d" % PORT

APP_JS = r"""
/*! app build 2026.10 */
const API_BASE = "https://api.example.com";
window.__CONFIG__ = { apiBase: "/api/v2", featureToggles: {newCheckout: true} };
const base = "/api";
axios.defaults.baseURL = base;
axios.get('/api/v1/users').then(r => r.data);
axios.post(`${base}/v1/login`, {user, pass});
fetch('/api/v1/users?page=2&limit=10');
fetch(`${base}/v2/orders/${orderId}`, {method: 'POST'});
const url = "/api/" + "v1/export";
$.get('/api/v1/me');
const x = new XMLHttpRequest(); x.open('PUT', '/api/v1/users/123', true);
const ws = new WebSocket('wss://rt.example.com/socket.io/?EIO=4');
const gq = `query GetUser($id: ID!) { user(id: $id) { ok } }`;
const gm = `mutation UpdateUser($role: String) { ok }`;
const gs = `subscription OnEvent($id: ID) { ping }`;
const gqlUrl = "/graphql";
const persisted = { sha256Hash: "a3f1c2b4d5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2" };
const routes = [{path: '/dashboard'}, {path: '/admin/users'}, {path: '/user/:id'}];
document.querySelector('#x').innerHTML = location.search;
const t = document.getElementById('out'); t.innerHTML = '<b>hi</b>';
localStorage.setItem('accessToken', tok); localStorage.getItem('refreshToken');
sessionStorage.getItem('session_id');
window.postMessage({cmd: 'grant'}, '*');
addEventListener('message', (event) => { eval(event.data); });
document.domain = 'example.com';
const sw = navigator.serviceWorker.register('/sw.js');
const upload = fetch('/api/v1/upload', {method: 'POST'});
const hook = new Worker('/workers/telemetry.js');
const semver = {version: '3.2.1', buildId: 'b-777'};
const opts = {method: 'DELETE', url: '/api/v1/sessions/999'};
const key1 = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
const key2 = 'pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
const awsKey = 'AKIAIOSFODNN7EXAMPLE';
const paths = {'/api/v1/health': {get: {}}, '/api/v1/users': {post: {}}};
if (user.isAdmin || user.hasPermission('admin Panel')) { showSecret() }
const trpc = '/api/trpc/users.list';
const grpcw = '/grpc/web/UsersService';
//# sourceMappingURL=/static/app.js.map
"""

SOURCEMAP = json.dumps({
    "version": 3,
    "sources": ["webpack:///src/index.js", "webpack:///src/admin/roles.js", "/src/config.js"],
    "sourcesContent": [
        "import {api} from './api'; api.get('/internal/admin/roles'); // hidden endpoint",
        "export const roles = ['admin','user']; // adminOnly endpoint /internal/admin/grant",
        None,  # sourcesContent missing for /src/config.js -> original fetch path
    ],
})

CHUNK_MAP = json.dumps({
    "version": 3,
    "sources": ["webpack:///src/chunk-a.js", "/src/config.js"],
    "sourcesContent": [],
})

ROLES_JS = ("export const grants = ['/api/v2/admin/grant-all']; // secret route\n"
            "const debugToken = 'debug-9f8e7d6c5b4a';\n")

VENDOR_JS = "/* vendor bundle */ fetch('/api/v1/tracking'); console.log('vendor');"

HOME_HTML = """<!doctype html><html><head><title>Mock SPA</title>
<script src="/static/app.js"></script>
<script src="/static/vendor.js"></script>
<link rel="modulepreload" href="/static/chunk.min.js">
<script src="https://cdn.example.com/analytics.js"></script>
<script src="https://cdn.example.com/secure.js" integrity="sha384-abc"></script>
<script id="__NEXT_DATA__" type="application/json">{"buildId": "build-42", "runtimeConfig": {"apiUrl": "/api/v2"}}</script>
<script>
  const REACT_APP_FLAG = "beta-on"; var NEXT_PUBLIC_KEY = "pub-abcdef123456";
</script>
<script>
  const inlineApi = '/api/v1/inline-check';
  if (window.inlineAdmin) { console.log('isAdmin inline logic'); }
</script>
<!-- build: 2026-10-01 deploy pipeline internal -->
<!-- TODO: remove staging backdoor /debug/entry -->
</head><body><div id="app"></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            if v is not None:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        ua = (self.headers.get("User-Agent") or "")
        if p == "/":
            self._send(200, HOME_HTML)
        elif p == "/static/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif p == "/static/app.js.map":
            self._send(200, SOURCEMAP, "application/json")
        elif p == "/static/chunk.min.js":
            # comment-less bundle; map via X-SourceMap header (v3 route)
            self._send(200, "/* minified */ fetch('/api/v1/chunkdata');", "application/javascript",
                       {"X-SourceMap": "/static/chunk.min.js.map"})
        elif p == "/static/chunk.min.js.map":
            self._send(200, CHUNK_MAP, "application/json")
        elif p == "/src/config.js":
            self._send(200, "export const cfg = {api: '/api/v3/orig-source'};", "application/javascript")
        elif p == "/static/vendor.js":
            # WAF sim: pehli request (default python UA) ko 403, stealth UA ko 200
            if "Firefox/124" in ua or "Safari/605" in ua:
                self._send(200, VENDOR_JS, "application/javascript")
            else:
                self._send(403, "<html><body>Access denied by Cloudflare</body></html>",
                           "text/html", {"Server": "cloudflare", "CF-Ray": "aaa-bbb"})
        elif p == "/sw.js":
            self._send(200, "self.addEventListener('fetch', e=>{});", "application/javascript")
        elif p == "/api/v1/users":
            self._send(200, json.dumps([{"id": 1}]), "application/json")
        else:
            self._send(404, "nope", "text/plain")


ROUTES_B = None  # host B = dead port


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
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-56s %s" % ("[PASS]" if cond else "[FAIL]", name, detail))
    return bool(cond)


def save_json_local(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


def main():
    srv = start_server()
    from wasp_core import Cfg, Scope
    import importlib
    mod_js = importlib.import_module("mod_js")

    work = tempfile.mkdtemp(prefix="p7_ultra_")
    base_out = os.path.join(work, "engines")
    try:
        cfg = Cfg(None)
        cfg.rate_limit = 50.0
        cfg.timeout = 8
        cfg.retries = 1
        cfg.concurrency = 4
        cfg.max_requests = 20000
        scope_path = os.path.join(work, "scope.json")
        save_json_local(scope_path, {
            "engagement": "p7test", "authorized": True,
            "authorization_reference": "local offline harness",
            "targets": [BASE + "/"],
            "ips": ["127.0.0.1"],
            "notes": "offline selftest - no external network",
        })
        scope = Scope(scope_path)
        # host B dead seed add karke multi-host path bhi cover karo
        print("== Phase 7 ULTRA v3 - fresh run ==")
        t0 = time.time()
        mod_js.run(cfg, scope, base_out)
        fresh_dt = time.time() - t0
        out = os.path.join(base_out, "p7test", "js")
        load = lambda p: (json.load(open(os.path.join(out, p))) if os.path.exists(
            os.path.join(out, p)) and os.path.getsize(os.path.join(out, p)) > 2 else None)
        text = lambda p: (open(os.path.join(out, p), errors="ignore").read()
                          if os.path.exists(os.path.join(out, p)) else "")

        j = load("js_analysis.json")
        check("js_analysis.json written", j is not None)
        if not j:
            return 1
        surf = j.get("attack_surface", {})

        # ---- v2 parity (official selftest P7 items) ----
        check("endpoints >= 4", len(surf.get("endpoints", [])) >= 4,
              str(surf.get("endpoints", [])[:6]))
        check("methods POST extract (axios.post)",
              any("POST" in m for m in surf.get("methods", [])),
              str(surf.get("methods", [])[:4]))
        check("websocket wss:// extract",
              any("wss://" in w for w in surf.get("websockets", [])),
              str(surf.get("websockets", [])[:2]))
        check("graphql ops GetUser",
              any("GetUser" in o for o in surf.get("graphql_ops", [])),
              str(surf.get("graphql_ops", [])[:4]))
        check("dom_analysis innerHTML+location.search",
              "innerHTML" in text("dom_analysis.txt") and
              "location.search" in text("dom_analysis.txt"))
        check("authz hints isAdmin", "isAdmin" in text("authz_client_hints.txt"))
        check("sourcemap unpacked (comment route)",
              len(j.get("sourcemaps", [])) >= 1 and
              any((s or {}).get("contents_unpacked", 0) >= 1 for s in j.get("sourcemaps", [])),
              str(j.get("sourcemaps"))[:160])
        fps = [s.get("fingerprint") for s in j.get("secret_hits", [])]
        check("secrets deduped", len(set(fps)) == len(fps), "secrets=%d" % len(fps))
        check("own host NOT in external_domains",
              "127.0.0.1" not in surf.get("external_domains", []),
              str(surf.get("external_domains")))
        check("api.example.com captured", "api.example.com" in surf.get("external_domains", []))

        # ---- v2 artifacts exist ----
        for f in ("endpoints.txt", "params.txt", "interesting_params.txt", "methods.txt",
                  "graphql_ops.txt", "graphql_endpoints.txt", "websockets.txt", "routes.txt",
                  "external_domains.txt", "imports.txt", "chunks.txt", "dom_analysis.txt",
                  "authz_client_hints.txt", "config_hints.txt", "sourcemaps.txt",
                  "secret_hits.json", "build_ids.txt", "same_origin_endpoints.txt",
                  "feedforward.json", "MANIFEST.json"):
            check("v2 artifact: " + f, os.path.exists(os.path.join(out, f)))

        # ---- v3 ULTRA features ----
        check("v3: sourcemap via X-SourceMap header",
              any(s.get("via") == "header" for s in j.get("sourcemaps", [])),
              str([(s.get("asset", "")[-24:], s.get("via")) for s in j.get("sourcemaps", [])]))
        check("v3: sourcemap original-source fetch (no sourcesContent)",
              any(s.get("asset", "").endswith("chunk.min.js") and
                  s.get("contents_unpacked", 0) >= 1 for s in j.get("sourcemaps", [])),
              str(j.get("sourcemaps"))[:200])
        check("v3: /api/v3/orig-source (from fetched original)",
              any("orig-source" in e for e in surf.get("endpoints", [])))
        check("v3: hidden internal endpoints via map sources",
              any("/internal/admin/roles" in e or "/internal/admin/grant" in e
                  for e in surf.get("endpoints", [])),
              str([e for e in surf.get("endpoints", []) if "internal" in e]))
        check("v3: template literal path (`${base}/v1/login`)",
              any("/v1/login" in e for e in surf.get("endpoints", [])),
              str([e for e in surf.get("endpoints", []) if "login" in e]))
        check("v3: concat URL (/api/ + v1/export)",
              any("export" in e for e in surf.get("endpoints", [])))
        check("v3: api_versions (v1/v2)",
              {"v1", "v2"} <= set(surf.get("api_versions", [])),
              str(surf.get("api_versions")))
        check("v3: service workers (/sw.js)",
              any("sw.js" in w for w in surf.get("service_workers", [])),
              str(surf.get("service_workers")))
        check("v3: persisted query hash",
              len(surf.get("gql_persisted_hashes", [])) >= 1,
              str(surf.get("gql_persisted_hashes"))[:80])
        check("v3: storage tokens (accessToken/refreshToken)",
              {"accessToken", "refreshToken"} <= set(text("storage_tokens.txt").split()),
              text("storage_tokens.txt")[:80])
        check("v3: postMessage wildcard audit",
              "postMessage targetOrigin '*'" in text("postmessage_audit.txt"),
              text("postmessage_audit.txt")[:120])
        check("v3: document.domain relaxation",
              "document.domain=example.com" in text("postmessage_audit.txt"))
        check("v3: SRI missing (cdn analytics)",
              any("MISSING" in l and "analytics.js" in l
                  for l in text("third_party_scripts.txt").splitlines()),
              text("third_party_scripts.txt")[:140])
        check("v3: SRI ok (secure.js)",
              any(l.startswith("OK") and "secure.js" in l
                  for l in text("third_party_scripts.txt").splitlines()))
        check("v3: inline script analyzed (inline-check endpoint)",
              any("inline-check" in e for e in surf.get("endpoints", [])),
              str([e for e in surf.get("endpoints", []) if "inline" in e]))
        check("v3: html comments intel",
              "staging backdoor" in text("html_comments.txt"),
              text("html_comments.txt")[:100])
        check("v3: NEXT_DATA buildId + runtimeConfig",
              (j.get("framework_payload") or {}).get("next_data") is True and
              (j.get("framework_payload") or {}).get("build_id") == "build-42",
              str(j.get("framework_payload"))[:140])
        check("v3: WAF-blocked asset recorded + stealth retry ok",
              any(r.get("stealth_retry_ok") and "vendor" in r.get("url", "")
                  for r in j.get("assets", [])),
              str([(r.get("url", "")[-22:], r.get("fetch_status")) for r in j.get("assets", [])]))
        check("v3: fetch_intel has waf/edge info",
              any("cloudflare" in str(v.get("waf", [])).lower() or v.get("status") == 403
                  for v in (j.get("fetch_intel") or {}).values()))
        api = load("api_endpoints.json")
        check("v3: api_endpoints.json classified",
              api and api.get("count", 0) >= 5 and
              any(o.get("kind") == "admin" for o in api.get("endpoints", [])),
              "count=%s kinds=%s" % (api and api.get("count"),
                                     sorted({o.get("kind") for o in (api or {}).get("endpoints", [])})))
        check("v3: priority queue top = admin/debug high-score",
              api and api["endpoints"][0]["priority"] >= api["endpoints"][-1]["priority"] and
              ("admin" in api["endpoints"][0]["path"] or "internal" in api["endpoints"][0]["path"]),
              str(api["endpoints"][0]))
        check("v3: js_priority_queue.txt explainable",
              "P" in text("js_priority_queue.txt") and "[" in text("js_priority_queue.txt"))
        check("v3: sourcemap_tree.txt (webpack tree)",
              "src/admin/roles.js" in text("sourcemap_tree.txt"),
              text("sourcemap_tree.txt")[:100])
        check("v3: chains.txt non-empty",
              len(text("chains.txt").splitlines()) >= 2,
              text("chains.txt")[:160])
        check("v3: gql subscriptions op",
              any("OnEvent" in o for o in surf.get("graphql_ops", [])))
        check("v3: upload endpoint detected",
              any("upload" in e for e in surf.get("endpoints", [])))
        check("v3: rpc endpoints (trpc/grpc)",
              any("trpc" in e or "grpc" in e for e in surf.get("endpoints", [])))
        ff = load("feedforward.json")
        v2_keys = {"to_phase9_auth", "to_phase10_sessions", "to_phase11_idor", "to_phase12_params",
                   "to_phase13_injection", "to_phase14_xss", "to_phase15_ssrf", "to_phase17_api",
                   "to_phase18_graphql", "to_phase19_websocket", "to_phase20_logic",
                   "to_phase23_secrets", "to_phase24_cloud", "to_phase32_report"}
        check("feedforward: all v2 keys preserved",
              v2_keys <= set((ff or {}).get("routing", {}).keys()))
        check("feedforward: v3 to_phase8_surface added",
              "to_phase8_surface" in (ff or {}).get("routing", {}))
        check("secrets still REDACTED",
              all("*" in (s.get("value_redacted") or "") or len(s.get("value_redacted", "")) < 4
                  for s in j.get("secret_hits", [])),
              str([s.get("type") for s in j.get("secret_hits", [])]))
        check("no raw secret in ANY output",
              "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in json.dumps(j))
        check("MANIFEST stats engine=v3",
              (load("MANIFEST.json") or {}).get("stats", {}).get("engine") == mod_js.ENGINE)

        # ---- resume consistency ----
        print("== resume / checkpoint ==")
        cp_path = os.path.join(out, "_state", "checkpoint_js.json")
        check("checkpoint file exists", os.path.exists(cp_path))
        t1 = time.time()
        mod_js.run(cfg, scope, base_out)
        resume_dt = time.time() - t1
        j2 = load("js_analysis.json")
        fps2 = {s.get("fingerprint") for s in (j2 or {}).get("secret_hits", [])}
        check("resume: same secret set", fps2 == set(fps), "%d vs %d" % (len(fps), len(fps2)))
        check("resume: endpoint set stable",
              j2.get("attack_surface", {}).get("endpoints") == surf.get("endpoints"))
        check("resume: no duplicate sourcemap entries",
              len(j2.get("sourcemaps", [])) == len(j.get("sourcemaps", [])),
              "%d vs %d" % (len(j.get("sourcemaps", [])), len(j2.get("sourcemaps", []))))
        check("resume fast (<2s, skip log)", resume_dt < 2.0, "%.2fs (fresh %.2fs)" % (resume_dt, fresh_dt))
        print("  fresh=%.2fs resume=%.2fs" % (fresh_dt, resume_dt))

        passed = sum(1 for _, c, _ in RESULTS if c)
        print("\n== RESULT: %d/%d PASS ==" % (passed, len(RESULTS)))
        return 0 if passed == len(RESULTS) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
