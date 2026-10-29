#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 6 ULTRA offline selftest - 3 mock hosts ke against mod_tech.run() chalata
hai aur verified assertions check karta hai (koi internet nahi - sirf 127.0.0.1).

  Host A (:8931)  WordPress 6.4.2 + PHP 8.2.12 + nginx 1.24 + Cloudflare WAF
                  TRACE enabled + uploads dir listing + openapi.json + robots secrets
  Host B (:8932)  Next.js + Express + AWS ALB + AWS WAF + GraphQL(introspection)
                  OIDC (RS256+HS256) + JWKS + socket.io + HTTP/3 + custom favicon
  Host C (:8933)  SPOOFED IIS banner (asli PHP/WordPress peeche) -> contradiction
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block1_recon")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, shutil, socket, time, threading, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "tech_test")
UPLOAD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOWNLOAD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORK)

PORT_A, PORT_B, PORT_C = 8931, 8932, 8933
BASE_A = "http://127.0.0.1:%d" % PORT_A
BASE_B = "http://127.0.0.1:%d" % PORT_B
BASE_C = "http://127.0.0.1:%d" % PORT_C
RESULTS = []

NGINX_404 = ("<html><head><title>404 Not Found</title></head>"
             "<body><center>nginx/1.24.0</center><hr><center>nginx</center></body></html>")
EXPRESS_404 = "Cannot GET /\nExpress route not found (stable error page)"
IIS_404 = ("<html><head><title>404 - Not Found</title></head>"
           "<body><h1>HTTP Error 404.0 - Not Found</h1></body></html>")

FAV_A = b"\x89PNG\r\n\x1a\nmockfaviconAdata!!"
FAV_B = b"\x00\x00\x01\x00mockfaviconBbytes!!"


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-56s %s" % ("[PASS]" if cond else "[FAIL]", name, detail))
    return bool(cond)


def _hdrs(pairs):
    return list(pairs or [])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        b = body if isinstance(body, bytes) else body.encode("utf-8", "ignore")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if b and self.command != "HEAD":
            try:
                self.wfile.write(b)
            except Exception:
                pass

    # ---------------- methods ----------------
    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        if self.client_port() == PORT_A:
            return self._send(200, "", "text/plain", _hdrs([("Allow", "GET, POST, OPTIONS, TRACE")]))
        return self._send(200, "", "text/plain", _hdrs([("Allow", "GET, HEAD, OPTIONS")]))

    def do_TRACE(self):
        if self.client_port() == PORT_A:
            echo = "TRACE / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: wasp-tech-probe\r\n\r\n"
            return self._send(200, echo, "message/http")
        return self._send(405, "TRACE disabled", "text/plain")

    def do_POST(self):
        port = self.client_port()
        ln = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(ln).decode())
        except Exception:
            payload = {}
        if port == PORT_B and self.path.split("?")[0] == "/graphql":
            q = str(payload.get("query") or "")
            if "__schema" in q:
                return self._send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}),
                                  "application/json")
            if "__typename" in q:
                return self._send(200, json.dumps({"data": {"__typename": "Query"}}), "application/json")
            return self._send(400, json.dumps({"errors": [{"message": "Cannot query field"}]}),
                              "application/json")
        return self._send(405, "method not allowed", "text/plain")

    def client_port(self):
        return self.server.server_address[1]

    # ---------------- GET ----------------
    def do_GET(self):
        port = self.client_port()
        p, _, query = self.path.partition("?")

        # WAF trigger -> block pages
        if "wasp_tech_" in query:
            if port == PORT_A:
                return self._send(403, "<html><head><title>Attention Required! | Cloudflare</title>"
                                  "</head><body>Access denied | Error 1020 Ray ID: 8a1b2c</body></html>",
                                  "text/html", _hdrs([("cf-mitigated", "challenge"),
                                                      ("Server", "cloudflare")]))
            if port == PORT_B:
                return self._send(403, '{"message":"Blocked by AWS WAF"}', "application/json",
                                  _hdrs([("x-amzn-waf-action", "blocked")]))
            return self._send(404, IIS_404)

        if port == PORT_A:
            return self._host_a(p)
        if port == PORT_B:
            return self._host_b(p)
        return self._host_c(p)

    def _host_a(self, p):
        common = _hdrs([("Server", "nginx/1.24.0"), ("X-Powered-By", "PHP/8.2.12"),
                        ("cf-ray", "8a1b2c3d4e5f6071-BOM"), ("cf-cache-status", "HIT")])
        if p == "/":
            html = ('<html><head><meta name="generator" content="WordPress 6.4.2">'
                    '<title>My WP Site</title>'
                    '<link rel="icon" href="/favicon.ico">'
                    '<link rel="stylesheet" href="/wp-content/themes/t/style.css?ver=6.4.2">'
                    '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.0"></script>'
                    '</head><body><h1>Home</h1>'
                    '<form action="/" method="get"><input name="s"></form>'
                    '<a href="/wp-json/">rest</a></body></html>')
            return self._send(200, html, "text/html; charset=utf-8",
                              common + _hdrs([("Set-Cookie", "PHPSESSID=abc123def; HttpOnly"),
                                              ("Set-Cookie", "__cf_bm=cfdummy; Path=/")]))
        if p == "/wp-login.php":
            return self._send(200, "<html><body><form action='/wp-login.php' method='post'>"
                              "<input name='log'><input type='password' name='pwd'></form>"
                              "<p>WordPress login</p></body></html>", "text/html", common)
        if p == "/wp-json/":
            return self._send(200, json.dumps({"name": "WASP Test", "description": "test site",
                                               "namespaces": ["oembed/1.0"]}), "application/json", common)
        if p == "/phpinfo.php":
            return self._send(200, "<html><body><h1>PHP Version 8.2.12</h1>"
                              "<pre>phpinfo() output - Configuration File etc.</pre></body></html>",
                              "text/html", common)
        if p == "/xmlrpc.php":
            return self._send(405, "XML-RPC server accepts only POST requests.", "text/plain", common)
        if p == "/wp-content/uploads/":
            return self._send(200, "<html><head><title>Index of /wp-content/uploads/</title></head>"
                              "<body><h1>Index of /wp-content/uploads/</h1></body></html>",
                              "text/html", common)
        if p == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /wp-admin/\n"
                              "Disallow: /secret-admin-panel\nSitemap: %s/sitemap.xml\n"
                              % BASE_A, "text/plain", common)
        if p == "/sitemap.xml":
            return self._send(200, "<urlset><url><loc>%s/a</loc></url>"
                              "<url><loc>%s/b</loc></url></urlset>" % (BASE_A, BASE_A),
                              "application/xml", common)
        if p == "/favicon.ico":
            return self._send(200, FAV_A, "image/x-icon", common)
        if p == "/openapi.json":
            return self._send(200, json.dumps({"openapi": "3.0.2",
                                               "info": {"title": "WASP Test API", "version": "1.2.3"},
                                               "paths": {"/x": {"get": {}}, "/y": {"post": {}}}}),
                              "application/json", common)
        if p == "/admin":
            return self._send(200, "<html><body><h1>admin dashboard</h1></body></html>",
                              "text/html", common)
        return self._send(404, NGINX_404, "text/html", common)

    def _host_b(self, p):
        common = _hdrs([("Server", "awselb/2.0"), ("X-Powered-By", "Next.js"),
                        ("Alt-Svc", 'h3=":443"; ma=2592000'),
                        ("ETag", '"a1b2c3d4e5f60718293a4b5c"')])
        if p == "/":
            html = ('<html><head><title>SPA App</title><link rel="icon" href="/icons/app.ico">'
                    '<script id="__NEXT_DATA__" type="application/json">'
                    '{"buildId":"bld_123","props":{}}</script>'
                    '<script src="/_next/static/chunks/main-a1b2c3.js"></script>'
                    '<script src="/socket.io/socket.io.js"></script>'
                    '</head><body><div id="__next"></div></body></html>')
            return self._send(200, html, "text/html; charset=utf-8",
                              common + _hdrs([("Set-Cookie", "__Host-next-auth.csrf-token=abc|def; Secure; HttpOnly"),
                                              ("Set-Cookie", "AWSALB=zzzz==; Path=/")]))
        if p == "/_next/static/":
            return self._send(200, "next static chunks dir", "text/plain", common)
        if p == "/icons/app.ico":
            return self._send(200, FAV_B, "image/x-icon", common)
        if p == "/graphql":
            return self._send(400, json.dumps({"errors": [{"message": "Must provide query string."}]}),
                              "application/json", common)
        if p == "/graphiql":
            return self._send(200, "<html><head><title>GraphiQL</title></head>"
                              "<body><div id='graphiql'>graphql-playground loading</div></body></html>",
                              "text/html", common)
        if p == "/socket.io/":
            return self._send(200, json.dumps({"code": 0, "message": "ok"}), "application/json", common)
        if p == "/.well-known/openid-configuration":
            return self._send(200, json.dumps({"issuer": "https://auth.wasp.test",
                                    "grant_types_supported": ["authorization_code", "refresh_token"],
                                    "scopes_supported": ["openid", "profile", "email"],
                                    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
                                    "jwks_uri": "/.well-known/jwks.json"}), "application/json", common)
        if p == "/.well-known/jwks.json":
            return self._send(200, json.dumps({"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k1"},
                                             {"kty": "EC", "alg": "ES256", "kid": "k2"}]}),
                              "application/json", common)
        if p == "/api/health":
            return self._send(200, json.dumps({"ok": True}), "application/json", common)
        return self._send(404, EXPRESS_404, "text/html", common)

    def _host_c(self, p):
        common = _hdrs([("Server", "Microsoft-IIS/10.0")])
        if p == "/":
            html = ('<html><head><meta name="generator" content="WordPress 6.3.1">'
                    '<title>Site</title></head><body>'
                    '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
                    '</body></html>')
            return self._send(200, html, "text/html; charset=utf-8",
                              common + _hdrs([("Set-Cookie", "PHPSESSID=zzz; Path=/")]))
        return self._send(404, IIS_404, "text/html", common)


def start_server(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(40):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return srv
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("mock server %d start nahi hua" % port)


# ---------------------------------------------------------------------------
def main():
    os.makedirs(WORK, exist_ok=True)
    for f in ("wasp_core.py",):
        shutil.copy(os.path.join(UPLOAD, f), os.path.join(WORK, f))
    shutil.copy(os.path.join(DOWNLOAD, "phases", "block1_recon", "mod_tech.py"), os.path.join(WORK, "mod_tech.py"))
    for m in ("wasp_core", "mod_tech"):
        if m in sys.modules:
            del sys.modules[m]

    tmp = tempfile.mkdtemp(prefix="tech6_")
    scope_path = os.path.join(tmp, "scope.json")
    cfg_path = os.path.join(tmp, "config.json")
    out_base = os.path.join(tmp, "out")

    json.dump({"engagement": "tech6-test", "authorized": True,
               "authorization_reference": "SELFTEST (local mock)",
               "targets": [BASE_A, BASE_B, BASE_C], "domains": [], "wildcards": [],
               "excludes": [], "ips": ["127.0.0.1"],
               "notes": "offline selftest only"}, open(scope_path, "w"))
    json.dump({"rate_limit": 200.0, "jitter": 0.0, "concurrency": 4, "timeout": 5,
               "retries": 0, "max_requests": 30000, "verify_tls": False,
               "allow_active": True, "allow_destructive": False, "save_bodies": False,
               "allow_write_http": True,
               "adaptive_throttle": False, "negative_cache": False,
               "tech_probe_max": 60, "tech_gql_post_max": 2},
              open(cfg_path, "w"))

    srvs = [start_server(PORT_A), start_server(PORT_B), start_server(PORT_C)]
    print("  mock targets: %s | %s | %s" % (BASE_A, BASE_B, BASE_C))

    from wasp_core import Cfg, Scope, favicon_hash
    import mod_tech

    cfg = Cfg(cfg_path)
    sc = Scope(scope_path)
    try:
        mod_tech.run(cfg, sc, out_base)
    except Exception as e:
        import traceback
        traceback.print_exc()
        check("module ran without exception", False, repr(e))
        return finish(srvs, tmp)

    eng = os.path.join(out_base, "tech6-test", "tech")

    def load(rel):
        pth = os.path.join(eng, rel)
        return json.load(open(pth)) if os.path.exists(pth) else None

    def text(rel):
        pth = os.path.join(eng, rel)
        return open(pth, errors="ignore").read() if os.path.exists(pth) else ""

    prof = load("tech_profile.json")

    def host_of(u):
        return (u or "").split("//")[-1].split("/")[0]

    hosts = {}
    if prof:
        for h in prof.get("hosts", []):
            hosts[host_of(h.get("final_url") or h.get("seed"))] = h
    HA, HB, HC = hosts.get("127.0.0.1:%d" % PORT_A, {}), hosts.get("127.0.0.1:%d" % PORT_B, {}), hosts.get("127.0.0.1:%d" % PORT_C, {})

    def tech(h, name):
        for t in (h.get("tech_ranked") or []):
            if t["tech"] == name:
                return t
        return {}

    print("\n== files ==")
    check("tech_profile.json written", prof is not None)
    check("stack_report.txt written (>300 chars)", len(text("stack_report.txt")) > 300)
    check("architecture_map.txt + ENGAGEMENT SUMMARY",
          "ENGAGEMENT SUMMARY" in text("architecture_map.txt"))
    check("multi-stack hint (3 alag-alag hosts)", "multi-stack=YES" in text("architecture_map.txt"))
    check("tech_versions.txt me Nginx+PHP versions",
          "Nginx" in text("tech_versions.txt") and "PHP" in text("tech_versions.txt"))
    check("favicon_hashes.txt + shodan pivot",
          "http.favicon.hash:" in text("favicon_hashes.txt"))
    check("waf_cdn.txt me Cloudflare + AWS WAF",
          "Cloudflare" in text("waf_cdn.txt") and "AWS WAF" in text("waf_cdn.txt"))
    check("perimeter.json written", load("perimeter.json") is not None)
    check("openapi_specs.json parsed (title/version/paths)",
          any(s.get("title") == "WASP Test API" and s.get("paths_count") == 2
              for specs in (load("openapi_specs.json") or {}).get("hosts", {}).values()
              for s in specs))
    check("graphql_surface.json: typename + introspection",
          any(ep.get("typename_ok") and ep.get("introspection")
              for g in (load("graphql_surface.json") or {}).get("hosts", {}).values()
              for ep in g.get("endpoints", [])))
    obs = (load("tech_observations.json") or {}).get("observations") or []
    obs_titles = " | ".join(o["title"] for o in obs)
    check("tech_observations.json (>=8 obs)", len(obs) >= 8, "count=%d" % len(obs))
    check("TECH_OBSERVATIONS.md HIGH section", "## HIGH" in text("TECH_OBSERVATIONS.md"))
    beh = (load("http_behavior.json") or {}).get("hosts", {})
    trace_on = any((h.get("behavior") or {}).get("trace", {}).get("enabled")
                   for h in beh.values() if isinstance(h, dict))
    check("http_behavior.json: TRACE enabled captured", trace_on)
    ff = text("feedforward.json")
    check("feedforward: P17/P18/P23/P25 routing",
          all(k in ff for k in ("to_phase17_api", "to_phase18_graphql",
                                "to_phase23_misconfig", "to_phase25_controls")))
    check("MANIFEST.json written", load("MANIFEST.json") is not None)
    check("session_model.txt v2-exact format", "-> storage=" in text("session_model.txt"))
    check("api_style.txt: GraphQL (host B)", "GraphQL" in text("api_style.txt"))

    print("\n== host A (WordPress/PHP/nginx/CF) ==")
    check("WordPress HIGH + version 6.4.2",
          tech(HA, "WordPress").get("confidence") == "high"
          and tech(HA, "WordPress").get("version") == "6.4.2",
          str(tech(HA, "WordPress")))
    check("PHP HIGH + version 8.2.12",
          tech(HA, "PHP").get("confidence") == "high" and tech(HA, "PHP").get("version") == "8.2.12")
    check("Nginx HIGH + version 1.24.0",
          tech(HA, "Nginx").get("confidence") == "high" and tech(HA, "Nginx").get("version") == "1.24.0")
    check("jQuery version 3.7.0 extracted", tech(HA, "jQuery").get("version") == "3.7.0")
    check("Cloudflare detected (CDN+WAF)",
          tech(HA, "Cloudflare").get("score", 0) >= 8 and "Cloudflare" in (HA.get("cdn") or []))
    check("WAF trigger blocked (Cloudflare page)",
          ((HA.get("waf") or {}).get("trigger") or {}).get("blocked") is True)
    check("TRACE enabled observation",
          any("TRACE" in o["title"] for o in obs))
    check("directory listing observation (uploads)",
          any("Directory listing" in o["title"] for o in obs))
    check("openapi exposure observation",
          any("OpenAPI" in o["title"] or "swagger" in o["title"].lower() for o in obs))
    check("robots admin_paths captured",
          "/secret-admin-panel" in (((HA.get("meta") or {}).get("robots") or {}).get("admin_paths") or []))
    check("favicon hash = wasp_core favicon_hash",
          (HA.get("favicon") or {}).get("hash") == favicon_hash(FAV_A))
    check("arch A: server-rendered MVC (PHP)",
          ((HA.get("architecture") or {}).get("rendering") == "server-rendered (PHP)"))
    check("arch A: backend=traditional MVC",
          "traditional" in ((HA.get("architecture") or {}).get("backend_pattern") or ""))

    print("\n== host B (Next/Express/AWS/OIDC) ==")
    check("Next.js HIGH", tech(HB, "Next.js").get("confidence") == "high")
    check("Express detected (error page)", tech(HB, "Express").get("score", 0) >= 4)
    check("AWS WAF detected", "AWS WAF" in [w["waf"] for w in (HB.get("waf") or {}).get("waf", [])])
    check("AWS ALB/ELB (LB) detected", "AWS ALB/ELB" in (HB.get("lb") or []))
    check("OIDC issuer captured",
          ((HB.get("sso") or {}).get("oidc") or {}).get("issuer") == "https://auth.wasp.test")
    check("OIDC HS256 -> MEDIUM observation",
          any("HS256" in o["title"] for o in obs))
    check("JWKS parsed (2 keys, RSA+EC)",
          ((HB.get("sso") or {}).get("jwks") or {}).get("key_count") == 2)
    check("HTTP/3 (Alt-Svc) detected", HB.get("http3") is True)
    check("realtime (socket.io) hint", (HB.get("architecture") or {}).get("realtime"))
    check("arch B: SSR hybrid + BFF",
          "Next" in (HB.get("architecture") or {}).get("rendering", "")
          and (HB.get("architecture") or {}).get("bff") is True)
    check("arch B: API-first backend",
          (HB.get("architecture") or {}).get("backend_pattern") == "API-first")
    check("perimeter chain B: WAF -> LB -> origin",
          (HB.get("perimeter") or [""])[0].startswith("AWS WAF")
          and "AWS ALB/ELB (LB)" in (HB.get("perimeter") or []))
    check("custom favicon (/icons/app.ico) hashed",
          (HB.get("favicon") or {}).get("path") == "/icons/app.ico")

    print("\n== host C (IIS spoof) ==")
    check("contradiction: IIS banner vs PHP/WP markers",
          any("IIS" in c for c in (HC.get("contradictions") or [])),
          "; ".join(HC.get("contradictions") or []))
    check("C: WordPress 6.3.1 version extracted",
          tech(HC, "WordPress").get("version") == "6.3.1")

    # ---- resume consistency ----
    print("\n== resume / checkpoint ==")
    def sig(h):
        return sorted((t["tech"], t["score"]) for t in (h.get("tech_ranked") or []))
    fresh_sigs = {k: sig(v) for k, v in hosts.items()}
    t0 = time.time()
    cfg2 = Cfg(cfg_path)
    cfg2.resume = True
    mod_tech.run(cfg2, sc, out_base)
    dt = time.time() - t0
    prof2 = load("tech_profile.json")
    hosts2 = {}
    for h in (prof2 or {}).get("hosts", []):
        hosts2[host_of(h.get("final_url") or h.get("seed"))] = h
    sigs2 = {k: sig(v) for k, v in hosts2.items()}
    check("resume: tech_ranked sets identical", fresh_sigs == sigs2,
          "fresh=%s resume=%s" % (len(fresh_sigs), len(sigs2)))
    check("resume fast (<8s, stages skip)", dt < 8.0, "%.2fs" % dt)

    return finish(srvs, tmp)


def finish(srvs, tmp):
    for s in srvs:
        s.shutdown()
        s.server_close()
    passed = sum(1 for _, okk, _ in RESULTS if okk)
    total = len(RESULTS)
    print("\n" + "=" * 78)
    print("PHASE-6 ULTRA SELFTEST RESULT: %d/%d checks passed" % (passed, total))
    if passed != total:
        print("FAILED:")
        for n, okk, d in RESULTS:
            if not okk:
                print("   - %s  %s" % (n, d))
    print("artifacts: %s" % tmp)
    print("=" * 78)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
