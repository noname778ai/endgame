#!/usr/bin/env python3
"""Phase 2 ULTRA offline harness - fake HTTP, no network. Deterministic."""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block1_recon")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, shutil, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wasp_core as wc
import mod_understand as MU

P = F = 0


def check(name, cond, extra=""):
    global P, F
    if cond:
        P += 1
        print("  [PASS] %s" % name)
    else:
        F += 1
        print("  [FAIL] %s %s" % (name, extra))


HOME = """<html><head><title>TestApp - Portal</title>
<meta name="generator" content="WordPress 6.4">
<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline' *; ">
<script src="/app.js"></script>
<script src="https://cdn.thirdparty.test/lib.js"></script>
<script src="http://insecure.example.com/track.js"></script>
<!-- TODO: remove staging admin link staging.internal.example-corp.test -->
<div data-reactroot></div>
<script>__NEXT_DATA__ = {"props":{"apiBase":"/api/v2","endpoint":"/api/v2/users"},"secret":"AKIAABCDEFGHIJKLMNOP"};</script>
</head><body>
<form action="/login" method="post"><input name="user"><input name="email"><input type="password" name="pass"><input type="hidden" name="role" value="user"><input type="hidden" name="csrf" value="x"></form>
<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="doc"></form>
<form action="/search" method="get"><input name="q"></form>
<a href="/admin/dashboard">Admin</a><a href="/api/v2/orders">API</a>
<img src="http://insecure.example.com/pix.gif">
<link rel="stylesheet" href="/wp-content/themes/main/style.css">
</body></html>"""

JS_BODY = """
fetch("/api/v2/profile");
axios.post("/api/v2/graphql", {query: "query GetOrders { orders { id } }"});
const ws = new WebSocket("wss://realtime.example.com/socket");
//# sourceMappingURL=app.js.map
const cfg = {apiKey: "AIzaSyA1234567890123456789012345678901234"};
if (user.role === "admin") { location = "/internal/debug"; }
"""


class Resp:
    def __init__(self, url, status=200, text="", headers=None, set_cookies=None, chain=None):
        self.url = url
        self.status = status
        self._text = text
        self.headers = headers or {}
        self.set_cookies = set_cookies or []
        self.body = text.encode()
        self.chain = chain or []
        self.error = None

    def hget(self, k):
        for kk, vv in self.headers.items():
            if kk.lower() == k.lower():
                return vv
        return None

    def sha1(self):
        import hashlib
        return hashlib.sha1(self.body).hexdigest()

    @property
    def text(self):
        return self._text


class FakeHttp:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append(method.upper())
        if url.endswith("/app.js"):
            return Resp(url, text=JS_BODY, headers={"Server": "nginx"})
        return Resp(url, text=HOME,
                    headers={"Server": "nginx", "X-Powered-By": "PHP/8.1",
                             "Content-Security-Policy": "script-src 'unsafe-inline' *;"},
                    set_cookies=["sid=abc123; Path=/", "__Host-prem=1; Path=/app"],
                    chain=[{"url": "https://app.example.com/"}])


def main():
    work = tempfile.mkdtemp(prefix="p2_test_")
    scope_path = os.path.join(work, "scope.json")
    with open(scope_path, "w") as f:
        json.dump({"engagement": "p2t", "authorized": True, "authorization_reference": "harness",
                   "targets": ["https://app.example.com/"], "domains": ["example.com"]}, f)
    scope = wc.Scope(scope_path)
    cfg = wc.Cfg(None)
    cfg.understand_js_max = 10

    print("== A) unit helpers ==")
    check("v2 funcs intact", all(callable(getattr(MU, n, None)) for n in
                                 ("parse_forms", "abs_urls", "grade_headers", "attrs_of")))
    check("rwx banner", "RWX STANDING RULE" in open(MU.__file__).read())
    forms = MU.parse_forms(HOME, "https://app.example.com/")
    check("forms parsed", len(forms) == 3)
    check("form classify auth", "auth" in MU.classify_form(forms[0]))
    check("form classify upload", "file_upload" in MU.classify_form(forms[1]))
    audit = MU.form_audit(forms[0], "app.example.com")
    check("hidden fields", set(audit["hidden_fields"]) == {"role", "csrf"})
    check("csp weak", set(MU.csp_analyze("script-src 'unsafe-inline' *;")["weaknesses"])
          >= {"unsafe-inline", "wildcard-star"})
    check("csp missing", MU.csp_analyze(None)["weaknesses"] == ["csp-missing"])
    cu = MU.cookie_ultra(["sid=abc123; Path=/", "__Host-prem=1; Path=/app"])
    check("cookie missing flags", cu[0]["missing"] == ["HttpOnly", "Secure", "SameSite"])
    check("__Host- violation", "prefix_violation" in cu[1])
    check("session-like cookie", cu[0].get("session_like") is True)
    check("perimeter none on clean", MU.perimeter_of_headers({"Server": "nginx"}, []) == [])
    check("perimeter cf-ray", MU.perimeter_of_headers({"Cf-Ray": "x"}, []) == ["Cloudflare"])
    check("redirect hint", MU.redirect_ultra([{"url": "https://a.test/"}], "https://b.test/"))
    leaks = MU.state_leaks(HOME)
    check("state leak found", leaks and leaks[0]["var"] == "__NEXT_DATA__")
    check("state leak secrets", any(t["type"] == "aws_access_key_id"
                                    for t in leaks[0]["secret_hits"]))
    cl = MU.comment_leaks(HOME)
    check("comment todo", cl["todo_fixme"] >= 1)
    check("comment internal host", any("internal" in h for h in cl["internal_hosts"]))
    check("sri gap", MU.sri_audit(HOME, "app.example.com"))
    check("mixed content", MU.mixed_content(HOME, True))
    d = MU.js_deep(JS_BODY)
    check("js fetch endpoints", "/api/v2/profile" in d["endpoints"])
    check("js websocket", any("wss://" in w for w in d["websockets"]))
    check("js graphql op", "GetOrders" in d["graphql_ops"])
    check("js sourcemap", d["sourcemaps"] == ["app.js.map"])

    print("== B) analyze_target full ==")
    http = FakeHttp()
    out = os.path.join(work, "out")
    os.makedirs(out, exist_ok=True)
    cp = wc.Checkpoint(out, "understand", fresh=True)
    rec = MU.analyze_target(cfg, scope, http, None, cp, "https://app.example.com/")
    check("reachable", rec["reachable"])
    check("tech detect", "WordPress" in rec["tech"] and "React" in rec["tech"])
    check("header grade F", rec["header_grade"] == "F")
    check("secrets found", any(s["type"] == "google_api_key" for s in rec["secrets"]))
    check("auth form captured", len(rec["auth_forms"]) >= 1)
    check("upload form captured", rec["upload_forms"])
    check("pii detected", any(p["pii_class"] == "email" for p in rec["pii_fields"]))
    check("perimeter in rec", isinstance(rec["perimeter"], list))
    check("score in range", 0 <= rec["attack_surface_score"] <= 100)
    check("GET-only requests", all(m in ("GET", "HEAD", "OPTIONS") for m in http.calls))

    print("== C) run() full outputs ==")
    saved_ctx = MU.module_ctx

    def fake_ctx(c, s, base_out, name):
        o = os.path.join(work, "eng", name)
        os.makedirs(o, exist_ok=True)
        return o, None, FakeHttp(), wc.Checkpoint(o, name, fresh=True)

    MU.module_ctx = fake_ctx
    MU.write_manifest = lambda *a, **k: None
    try:
        MU.run(cfg, scope, work)
    finally:
        MU.module_ctx = saved_ctx
    eng = os.path.join(work, "eng", "understand")
    need = ["understand.json", "endpoints.txt", "api_endpoints.txt", "js_urls.txt",
            "header_flags.txt", "interesting.txt", "secret_hits.json", "forms.json",
            "THREAT_MODEL.md", "juicy_endpoints.txt", "pii_inventory.json",
            "auth_forms.json", "cookies.txt", "session_cookies.txt", "csp_report.txt",
            "forms_classified.txt", "hidden_fields.txt", "mixed_content.txt",
            "sri_audit.txt", "comment_leaks.txt", "state_leaks.json", "waf_edge.txt",
            "websockets.txt", "graphql_ops.txt", "attack_surface.txt", "feedforward.json"]
    missing = [n for n in need if not os.path.exists(os.path.join(eng, n))]
    check("all %d outputs present" % len(need), not missing, str(missing))
    tm = open(os.path.join(eng, "THREAT_MODEL.md")).read()
    check("TM v2 sections", "## 6. STRIDE" in tm and "## 8. Priority" in tm)
    check("TM ultra lines", "attack-surface score" in tm and "Spoofing" in tm)
    bad = []
    for dp, dn, fn in os.walk(eng):
        for n in dn + fn:
            import stat as st
            if st.S_IMODE(os.stat(os.path.join(dp, n)).st_mode) != 0o777:
                bad.append(n)
    check("RWX: all outputs 777", not bad, str(bad[:4]))
    d2 = json.load(open(os.path.join(eng, "understand.json")))
    check("engine version stamped", d2.get("engine_version") == MU.ENGINE_VERSION)

    print("==" * 14)
    print("PHASE 2 ULTRA HARNESS: %d PASS / %d FAIL" % (P, F))
    return 0 if not F else 1


if __name__ == "__main__":
    sys.exit(main())
