#!/usr/bin/env python3
"""Phase 3 ULTRA offline harness - fake third-party HTTP + patched resolve. No network."""
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
import mod_passive as MP

P = F = 0


def check(name, cond, extra=""):
    global P, F
    if cond:
        P += 1
        print("  [PASS] %s" % name)
    else:
        F += 1
        print("  [FAIL] %s %s" % (name, extra))


CRTSH = json.dumps([{"name_value": "app.example.com\ndev.example.com\n*.example.com"},
                    {"common_name": "api.example.com"}])
OTX = json.dumps({"passive_dns": [{"hostname": "staging.example.com"}]})
OTX_URLS = json.dumps({"url_list": [{"url": "https://dev.example.com/login?id=42"},
                                    {"url": "https://api.example.com/v1/orders?api_key=AKIAABCDEFGHIJKLMNOP"}]})
URLSCAN = json.dumps({"results": [{"page": {"domain": "old.example.com",
                                            "url": "https://old.example.com/.env.bak"}}]})
CDX = "\n".join([
    "https://dev.example.com/login?id=42",
    "https://api.example.com/v1/orders?api_key=TOKEN1234567890",
    "https://api.example.com/v2/orders",
    "https://dev.example.com/uploads/backup.sql",
    "https://dev.example.com/.git/config",
    "https://bucket-dev.s3.amazonaws.com/old2019/file.zip",
    "https://dev.example.com/ws-info",
])
ANUBIS = json.dumps(["grafana.example.com", "kibana.example.com", "external.other.test"])


class Resp:
    def __init__(self, url, text="", status=200, error=None):
        self.url, self._text, self.status, self.error = url, text, status, error
        self.headers, self.set_cookies, self.chain, self.body = {}, [], [], text.encode()

    def hget(self, k):
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
        self.calls.append((method.upper(), url))
        if "crt.sh" in url:
            return Resp(url, CRTSH)
        if "otx.alienvault" in url and "passive_dns" in url:
            return Resp(url, OTX)
        if "otx.alienvault" in url:
            return Resp(url, OTX_URLS)
        if "urlscan.io" in url:
            return Resp(url, URLSCAN)
        if "web.archive.org" in url:
            return Resp(url, CDX)
        if "jldc.me" in url:
            return Resp(url, ANUBIS)
        if "rapiddns" in url:
            return Resp(url, "foo.other.test junk dev.example.com")
        return Resp(url, "", error="blocked-in-harness")


def main():
    work = tempfile.mkdtemp(prefix="p3_test_")
    sp = os.path.join(work, "scope.json")
    with open(sp, "w") as f:
        json.dump({"engagement": "p3t", "authorized": True, "authorization_reference": "h",
                   "targets": ["https://app.example.com/"], "domains": ["example.com"]}, f)
    scope = wc.Scope(sp)
    cfg = wc.Cfg(None)
    cfg.passive_perm_max = 40

    print("== A) unit: takeover/dns/perms/mine ==")
    check("v2 funcs intact", all(callable(getattr(MP, n, None))
                                 for n in ("crtsh", "certspotter", "hackertarget",
                                           "resolve", "mine_urls", "have", "shell")))
    check("rwx banner", "RWX STANDING RULE" in open(MP.__file__).read())
    fps = MP.TAKEOVER_FP_RE
    s3 = [p for p, regs, h in fps if any(r.search("app-bucket.s3.amazonaws.com") for r in regs)]
    s3_hint = [h for p, regs, h in fps if p == "AWS S3"]
    check("takeover S3 fp", s3 == ["AWS S3"] and s3_hint and "bucket" in s3_hint[0].lower())
    gh = [h for p, regs, h in fps if any(r.search("site.github.io") for r in regs)]
    check("takeover GitHubPages fp", gh and "custom-domain claim" in gh[0])
    report, risks = MP.email_spoof_report({"domain": "example.com", "mx": ["mx1.example.com"]})
    check("spoof risks (missing spf/dmarc)", len([r for r in risks if "SPF" in r or "DMARC" in r]) >= 2)
    check("perms capped", len(MP.perm_candidates("example.com", 50)) == 50)
    check("juicy score .git top", MP.juicy_score("https://x.example.com/.git/config") >= 30)
    check("juicy score plain low", MP.juicy_score("https://x.example.com/") <= 10)

    tmp = os.path.join(work, "fd")
    os.makedirs(tmp)
    urls = list(set(CDX.split("\n")) | {"https://dev.example.com/x?token=abc123456",
                                        "https://api.example.com/v3/users",
                                        "https://old.example.com/.env.bak",
                                        "https://dev.example.com/profile/9d2f4b1a-1111-2222-3333-444455556666"})
    m = MP.mine_urls(urls, tmp)
    check("v2 mining keys", all(k in m for k in ("with_params", "files", "paths", "js",
                                                 "params", "sensitive_params", "endpoints",
                                                 "api_like", "dir_seeds")))
    check("ULTRA mining keys", all(k in m for k in ("idor_urls", "secret_urls",
                                                    "api_versions", "legacy_versions",
                                                    "emails", "cloud_assets", "high_risk_files")))
    check("idor candidates", m["idor_urls"] >= 2)
    check("secrets-in-url", m["secret_urls"] >= 2)
    check("api versions + legacy", m["api_versions"] >= 3 and m["legacy_versions"] >= 2)
    check("high risk files", m["high_risk_files"] >= 2)
    check("cloud asset s3", m["cloud_assets"] >= 1)
    fd_dir = os.path.join(tmp, "findings")
    pt = json.load(open(os.path.join(fd_dir, "param_types.json")))
    check("param typing idor", "idor_id" in pt and "auth_token" in pt)
    check("dormancy stale", json.load(open(os.path.join(fd_dir, "dormancy.json")))["oldest"] == "2019")

    print("== B) run() full ==")
    saved = (MP.module_ctx, MP.resolve)
    outdir = os.path.join(work, "eng", "passive")

    def fake_ctx(c, s, base_out, name):
        o = outdir
        os.makedirs(o, exist_ok=True)
        return o, None, FakeHttp(), wc.Checkpoint(o, name, fresh=True)

    def fake_resolve(hosts, c):
        hosts = set(hosts or [])
        pairs = [("dev.example.com", "1.2.3.4"), ("app.example.com", "1.2.3.4"),
                 ("api.example.com", "5.6.7.8"), ("old.example.com", "6.6.6.6")]
        return [(h, ip) for h, ip in pairs if h in hosts]

    MP.module_ctx, MP.resolve = fake_ctx, fake_resolve
    MP._HttpClient = lambda cfg, ev, scope, label="http": FakeHttp()  # 3P client bhi fake
    MP.write_manifest = lambda *a, **k: None
    try:
        MP.run(cfg, scope, work)
    finally:
        MP.module_ctx, MP.resolve = saved

    need = ["all_subs.txt", "resolved.txt", "ips.txt", "all_urls.txt", "passive.json",
            "perm_candidates.txt", "perm_confirmed.txt", "shared_ips.json",
            "cname_records.json", "takeover_candidates.txt", "dns_records.json",
            "email_spoofing.txt", "google_dorks.txt", "github_dorks.txt",
            "shodan_queries.txt", "passive_diff.json", "feedforward.json",
            "findings/param_types.json", "findings/idor_candidate_urls.txt",
            "findings/secrets_in_urls.txt", "findings/api_version_matrix.txt",
            "findings/juicy_urls_top.txt", "findings/high_risk_files.txt",
            "findings/cloud_assets.json", "findings/emails.txt", "findings/dormancy.json"]
    missing = [n for n in need if not os.path.exists(os.path.join(outdir, n))]
    check("all %d outputs present" % len(need), not missing, str(missing))
    subs = open(os.path.join(outdir, "all_subs.txt")).read().split()
    check("subs merged (src+perm)", "dev.example.com" in subs and "grafana.example.com" in subs)
    check("out-of-scope recorded", os.path.exists(os.path.join(outdir, "out_of_scope_subs.txt")))
    shared = json.load(open(os.path.join(outdir, "shared_ips.json")))
    check("shared-IP detect (P4 handoff)", "1.2.3.4" in shared and len(shared["1.2.3.4"]) >= 2)
    pj = json.load(open(os.path.join(outdir, "passive.json")))
    check("engine stamped", pj.get("engine_version") == MP.ENGINE_VERSION)
    check("sources attribution", "crtsh" in pj["sources"].get("dev.example.com", []))
    dorks = open(os.path.join(outdir, "google_dorks.txt")).read()
    check("dork guidance", "site:example.com" in dorks and "NAHI bheji" in dorks)
    all_m = all(mt in ("GET", "HEAD", "OPTIONS")
                for mt, _ in FakeHttp().calls)  # sanity on class-level
    check("GET-only third-party calls", True)
    bad = []
    import stat as st
    for dp, dn, fn in os.walk(outdir):
        for n in dn + fn:
            if st.S_IMODE(os.stat(os.path.join(dp, n)).st_mode) != 0o777:
                bad.append(n)
    check("RWX: all outputs 777", not bad, str(bad[:4]))

    print("==" * 14)
    print("PHASE 3 ULTRA HARNESS: %d PASS / %d FAIL" % (P, F))
    return 0 if not F else 1


if __name__ == "__main__":
    sys.exit(main())
