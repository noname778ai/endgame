#!/usr/bin/env python3
"""Phase 4 ULTRA offline harness - fake HTTP + patched sockets/TLS. No network."""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block1_recon")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, socket, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wasp_core as wc
import mod_active as MA

P = F = 0


def check(name, cond, extra=""):
    global P, F
    if cond:
        P += 1
        print("  [PASS] %s" % name)
    else:
        F += 1
        print("  [FAIL] %s %s" % (name, extra))


HOME = """<html><head><title>Edge Test</title></head><body>
<link href="/wp-content/themes/s.css">v1.2.3 build</body></html>"""


class Resp:
    def __init__(self, url, status=200, text=HOME, headers=None, set_cookies=None):
        self.url, self.status, self._text = url, status, text
        self.headers = headers or {}
        self.set_cookies = set_cookies or []
        self.body = text.encode()
        self.chain = []
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
    """Behavior keyed by URL pattern. GET-only asserted by harness."""
    def __init__(self, waf_block=True):
        self.calls = []
        self.waf_block = waf_block

    def request(self, method, url, headers=None, **kw):
        self.calls.append(method.upper())
        m = headers or {}
        host_hdr = (m.get("Host") or "").lower()
        if "waspprobe" in url and self.waf_block:
            return Resp(url, 403, "blocked by edge", headers={"Server": "CloudFront"})
        if host_hdr and host_hdr not in ("app.example.com",) and host_hdr.endswith("example.com"):
            return Resp(url, 200, "<html><title>VHOST %s</title></html>" % host_hdr)
        if "favicon" in url:
            return Resp(url, 200, "\x89PNG tiny")
        if "/_ping" in url:
            return Resp(url, 200, "OK", headers={"Server": "Docker/24.0"})
        _p = url.split("://", 1)[-1].split("/", 1)
        _path = _p[1] if len(_p) > 1 else ""
        if len(_path) > 10 and "." not in _path and "waspprobe" not in url:
            # random error path (soft404 baseline + error fingerprint)
            return Resp(url, 404, "<center>nginx</center> version 1.2.3 internal 10.0.0.5",
                        headers={"Server": "nginx"})
        return Resp(url, 200, HOME,
                    headers={"Server": "nginx", "Cf-Ray": "abc", "X-Cache": "MISS",
                             "X-Origin-Hint": "origin-1"},
                    set_cookies=["sid=xyz; Path=/"])


def main():
    work = tempfile.mkdtemp(prefix="p4_test_")
    sp = os.path.join(work, "scope.json")
    with open(sp, "w") as f:
        json.dump({"engagement": "p4t", "authorized": True, "authorization_reference": "h",
                   "targets": ["https://app.example.com/"], "domains": ["example.com"]}, f)
    scope = wc.Scope(sp)
    cfg = wc.Cfg(None)
    cfg.allow_active = True

    print("== A) unit tables/funcs ==")
    check("v2 funcs intact", all(callable(getattr(MA, n, None)) for n in
                                 ("http_probe", "header_grade", "edge_fingerprint",
                                  "tls_inspect", "error_fingerprint", "vhost_discovery",
                                  "port_scan", "nmap_scan", "run")))
    check("rwx banner", "RWX STANDING RULE" in open(MA.__file__).read())
    check("SAFE_PORTS ULTRA", all(p in MA.SAFE_PORTS for p in (6443, 2379, 9092, 8123)))
    check("WAF_SIG ULTRA", all(w in MA.WAF_SIG for w in ("AWS WAF", "DDoS-Guard", "Gcore")))
    check("VHOST_NAMES ULTRA", len(MA.VHOST_NAMES) >= 120 and "origin" in MA.VHOST_NAMES)
    check("bypass playbook db", "Cloudflare" in MA.WAF_BYPASS_PLAYBOOK and
          "nginx" in MA.WAF_BYPASS_PLAYBOOK and len(MA.WAF_BYPASS_PLAYBOOK["generic"]) >= 5)
    check("ERROR_LEAKS", MA.ERROR_LEAKS and "stack_trace" in MA.ERROR_LEAKS)
    check("SERVICE_HTTP_FP", any(p == 2375 for p, _, _, _ in MA.SERVICE_HTTP_FP))

    http = FakeHttp()
    probe = {"seed": "https://app.example.com/", "url": "https://app.example.com/",
             "scheme": "https", "host": "app.example.com", "port": 443}
    r = MA.http_probe(cfg, scope, http, "https://app.example.com/")
    check("http_probe ok", r.get("status") == 200 and "cloudflare" in r.get("tech", []))
    check("cookie_names captured", r.get("cookie_names") == ["sid"])
    e = MA.edge_fingerprint(cfg, scope, http, probe)
    check("edge waf hit", "Cloudflare" in e["waf_hits"])
    check("origin_hints captured", e["origin_hints"])
    check("cache headers", "x-cache" in e["cdn_headers"])
    ef = MA.error_fingerprint(http, probe)
    check("error template nginx", "nginx" in ef["template_hits"])
    check("error leaks", "internal_host" in ef.get("leak_hits", []) and
          "version_disclose" in ef.get("leak_hits", []))
    waf = MA.waf_behavioral_probe(cfg, http, probe, max_probes=5)
    check("waf behavioral high", waf["waf_confidence"] == "high" and
          waf["blocked_count"] == len(waf["probes"]))

    # tls_deep with patched tls_inspect
    saved_ti = MA.tls_inspect
    MA.tls_inspect = lambda h, p=443, timeout=8: {
        "host": h, "port": p, "tls_version": "TLSv1.3", "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "issuer": "R3", "not_after": "Jun 01 12:00:00 2027 GMT",
        "sans": ["app.example.com", "other.test"], "hostname_mismatch": False,
        "self_signed": False}
    try:
        t = MA.tls_deep("app.example.com", 443, timeout=1)
    finally:
        MA.tls_inspect = saved_ti
    check("tls expiry computed", isinstance(t.get("expires_in_days"), int))
    check("tls san cross-domain", "other.test" in t.get("san_cross_domain", []))
    check("tls weak cipher none", t.get("weak_cipher_hint") == [])

    # service fingerprint (docker ping)
    svc = MA.service_http_fingerprint(cfg, scope, http, "app.example.com", {2375, 9999})
    check("svc fp docker", any(g.get("identified") and g["product"] == "docker-api"
                               for g in svc))

    print("== B) run() full ==")
    saved = (MA.module_ctx, MA.socket.gethostbyname, MA._socket_probe)
    outdir = os.path.join(work, "eng", "active")
    fh = FakeHttp()

    def fake_ctx(c, s, b, n):
        os.makedirs(outdir, exist_ok=True)
        return outdir, None, fh, wc.Checkpoint(outdir, n, fresh=True)

    def fake_gh(h):
        return "127.0.0.1"

    def fake_probe(host, port, timeout=4):
        if port in (80, 2375):
            return {"host": host, "port": port, "state": "open", "banner": "",
                    "service": "", "product": "", "version": ""}
        return None

    MA.module_ctx = fake_ctx
    MA.socket.gethostbyname = fake_gh
    MA._socket_probe = fake_probe
    MA.nmap_scan = lambda h, **kw: None
    MA.write_manifest = lambda *a, **k: None
    saved_ti2 = MA.tls_inspect
    MA.tls_inspect = lambda h, p=443, timeout=8: {
        "host": h, "port": p, "tls_version": "TLSv1.3", "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "issuer": "R3", "not_after": "Jun 01 12:00:00 2027 GMT", "sans": ["app.example.com"],
        "hostname_mismatch": False, "self_signed": False}
    try:
        MA.run(cfg, scope, work)
    finally:
        MA.module_ctx, MA.socket.gethostbyname, MA._socket_probe = saved
        MA.tls_inspect = saved_ti2

    need = ["active.json", "live_hosts.txt", "open_ports.txt", "waf_cdn.txt", "vhosts.txt",
            "tls_report.txt", "favicon_hashes.txt", "error_templates.txt",
            "security_headers.txt", "waf_matrix.json", "bypass_playbook.txt",
            "origin_playbook.txt", "tls_deep.txt", "service_fingerprints.txt",
            "session_cookies.txt", "waf_behavioral.txt", "error_leaks.txt",
            "recon_summary.md", "feedforward.json"]
    missing = [n for n in need if not os.path.exists(os.path.join(outdir, n))]
    check("all %d outputs present" % len(need), not missing, str(missing))
    aj = json.load(open(os.path.join(outdir, "active.json")))
    check("engine stamped", aj.get("engine_version") == MA.ENGINE_VERSION)
    check("vhosts found", len(aj["vhosts"]) >= 1 and
          any(v["vhost"].startswith("dev") for v in aj["vhosts"]))
    check("ports 2375 open", any(p["port"] == 2375 for p in aj["ports"]))
    check("waf behavioral in report", aj.get("waf_behavioral") and
          aj["waf_behavioral"][0]["waf_confidence"] == "high")
    check("svc identified in report", any(g.get("identified") for g in aj.get("service_fp") or []))
    bp = open(os.path.join(outdir, "bypass_playbook.txt")).read()
    check("playbook tailored", "Cloudflare" in bp and "X-Original-URL" in bp)
    rs = open(os.path.join(outdir, "recon_summary.md")).read()
    check("summary exec", "live hosts:" in rs and "Next-phase prep" in rs)
    check("GET-only HTTP", all(m in ("GET", "HEAD", "OPTIONS") for m in fh.calls))
    import stat as st
    bad = []
    for dp, dn, fn in os.walk(outdir):
        for n in dn + fn:
            if st.S_IMODE(os.stat(os.path.join(dp, n)).st_mode) != 0o777:
                bad.append(n)
    check("RWX: all outputs 777", not bad, str(bad[:4]))

    print("==" * 14)
    print("PHASE 4 ULTRA HARNESS: %d PASS / %d FAIL" % (P, F))
    return 0 if not F else 1


if __name__ == "__main__":
    sys.exit(main())
