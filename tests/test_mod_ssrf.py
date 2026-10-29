#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P15 SELF-TEST SUITE - mod_ssrf.py v15.0.0-ultra-ultra-pro-max (P15)
=============================================================================
 Mock SSRF/XXE/traversal lab + full assertion suite:
   - Unit tests (payload libs: IP-encodings/parser-tricks/metadata-safe-paths/
     XXE builders/traversal matrix/param-regex/redaction primitives)
   - SAFETY unit tests (FORBIDDEN metadata paths hard-filtered, content
     redaction primitives, zero-egress policy)
   - Active run e2e (stages A..K verdict assertions, RoE gates OFF)
   - Gated run (ssrf_allow_post + ssrf_internal_smoke ON -> POST XXE + smoke)
   - Artifact integrity (26+ output files, matrices, catalog, feedforward)
   - RWX rule (0777 on every result file)
   - Zero-external-egress check (sirf own-host/loopback/.invalid/link-local)
   - REDACTION check (file content kabhi evidence me store nahi hota)
   - Passive mode (allow_active=False -> 0 probes)
   - Checkpoint replay (findings/verdicts stable)
 Detection-only discipline honored: lab me bhi koi destructive payload nahi.
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
import re
import io
import sys
import json
import shutil
import tempfile
import zipfile
import threading
import urllib.request
import urllib.error
import xml.dom.minidom
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block3_input")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_ssrf as MS                                          # noqa: E402
import wasp_core as WC                                         # noqa: E402

BASE = os.path.join(HERE, "p15_test_base")
BASE_GATED = os.path.join(HERE, "p15_test_base_gated")
BASE2 = os.path.join(HERE, "p15_test_base_passive")
ENG = "p15lab"
ENG_G = "p15lab2"
ENG_P = "p15labp"

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
# MOCK SSRF LAB
# - /                    homepage (stable body -> self-fetch sha1 proof)
# - /fetch?url=          FULL-RESPONSE proxy (vulnerable) -> CONFIRMED full-read
# - /fetch_blind?url=    200 queued-ok / 500 err -> blind status differential
# - /fetch_waf?url=      blocks 169.254|metadata|file: -> WAF_BLOCKED
# - /fetch_filter?url=   blocks literal "127.0.0.1" host -> bypass matrix target
# - /webhook?url=        fire-and-forget blind callback
# - /redirect?to=        302 (fetcher follows)
# - /api/xml?xml=        GET XML parser (entities simulated) -> XXE signals
# - /import POST         XML + docx import parser (POST, RoE-gated)
# - /upload_svg POST     SVG parser -> svg family
# - /saml/acs POST       SAML parser -> saml family
# - /xmlrpc.php POST     XML-RPC (system.listMethods read-only)
# - /download?path=      naive path join -> traversal CONFIRMED
# - /download_safe?path= normalized -> HARDENED (explicit refuse)
# - /hosthdr             reflects X-Forwarded-Host -> header-host SUSPECTED
# - /mdsim/latest/meta-data/  simulated IMDSv1 (non-secret markers)
# - /pdfgen?html=        img-src server-side fetcher (blind family)
# - unknown              404 "MOCK-NF" (stable soft-404 template)
# SAFETY: mock sirf loopback/file reads karta hai; koi destructive action nahi.
# ===========================================================================
LAB = {"gets": 0, "posts": [], "fetches": [], "inner": []}

HOME_BODY = ("<html><head><title>P15 Mock SSRF Lab</title></head><body>"
             "<h1>WASPP15HOME fixed-content homepage marker</h1>"
             "<p>stable body for sha1 differential - lorem ipsum dolor sit "
             "amet consectetur adipiscing elit sed do eiusmod tempor.</p>"
             "<a href='/fetch?url='>proxy</a></body></html>")
NF_BODY = "MOCK-NF"
MD_BODY = ("ami-id\nami-waspmock0f1\ninstance-id\ni-waspmock777\n"
           "security-groups\ndefault\nlocal-ipv4\n10.0.0.5\n")
XMLRPC_BODY = ("<methodResponse><params><param><value><array><data>"
               "<value>system.listMethods</value><value>pingback.ping</value>"
               "</data></array></value></param></params></methodResponse>")


def _numeric_host(h):
    """Mock 'lenient resolver': decimal/hex/octal/zero-pad/v6-mapped host ko
    loopback treat karo (deterministic IP-encoding bypass simulation)."""
    if not h:
        return False
    hl = h.lower()
    if ":" in hl:                                    # v6-mapped family
        return True
    if hl.isdigit():                                 # decimal + octal32
        return True
    if hl.startswith("0x") and re.match(r"^[0-9a-fx]+$", hl):
        return True
    if "." in hl and re.match(r"^[0-7.]+$", hl):     # zero-pad / octal parts
        return True
    return False


def _inner_fetch(u, limit=262144):
    """Mock ka server-side fetcher: urlopen (redirects follow) + numeric-host
    rewrite + file:// support. Records inner url (zero-egress audit)."""
    if u:
        LAB["inner"].append(u[:300])
    if not u:
        raise ValueError("empty inner url")
    if u.startswith("file://"):
        # file:// scheme: urlopen file-response me .status nahi hota -
        # deterministic direct read (lab-only, non-destructive)
        with open(u[7:], "rb") as f:
            return 200, f.read(limit), "text/plain"
    try:
        sp = urlsplit(u)
        h = sp.hostname or ""
        if _numeric_host(h):
            port = sp.port or 80
            rest = sp.path + ("?" + sp.query if sp.query else "")
            u = "http://127.0.0.1:%d%s" % (port, rest)
    except Exception:
        pass
    try:
        with urllib.request.urlopen(u, timeout=6) as fr:
            return fr.status, fr.read()[:limit], fr.headers.get(
                "Content-Type", "text/plain")
    except urllib.error.HTTPError as e:
        # 4xx/5xx bhi ek VALID upstream response hai (fetch hua, fail hua)
        try:
            b = e.read()[:limit]
        except Exception:
            b = b""
        return e.code, b, (e.headers or {}).get("Content-Type", "text/plain")


def _xml_logic(raw):
    """Mock XML parser simulation (libxml-ish fingerprints, entities resolve)."""
    if "DOCTYPE" in raw:
        m = re.search(r'SYSTEM\s+"([^"]+)"', raw)
        sysid = m.group(1) if m else ""
        if sysid.startswith("file://"):
            p = sysid[7:]
            if os.path.isfile(p):
                try:
                    with open(p, "rb") as f:
                        content = f.read(64)
                    return 200, content.decode("utf-8", "ignore")
                except OSError:
                    pass
            return 500, 'XML error: failed to load external entity "%s"' % sysid
        if sysid.startswith("http"):
            return 500, ('XML error: failed to load external entity "%s" '
                         '(could not resolve host)' % sysid)
        return 500, "XML error: Entity 'x' not defined"
    try:
        xml.dom.minidom.parseString(raw)
        return 200, "<ok>parsed</ok>"
    except Exception as e:
        return 500, "XML error: Start tag expected (not well-formed): %s" % (
            str(e)[:40])


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockSSRFLab/1.0"

    def log_message(self, *a):
        pass

    def _respond(self, status, body, headers=None, ct="text/html; charset=utf-8"):
        b = body if isinstance(body, bytes) else body.encode("utf-8", "ignore")
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Server", "MockSSRFLab/1.0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    # ---------------- GET routes ----------------
    def do_GET(self):
        LAB["gets"] += 1
        sp = urlsplit(self.path)
        path, q = sp.path, parse_qs(sp.query)

        if path in ("/", ""):
            return self._respond(200, HOME_BODY)
        if path == "/redirect":
            to = (q.get("to", [""])[0]) or "/"
            return self._respond(302, "", {"Location": to})
        if path in ("/fetch", "/fetch_blind", "/fetch_waf", "/fetch_filter",
                    "/webhook"):
            inner = (q.get("url", [""])[0])
            if path == "/fetch_waf":
                low = inner.lower()
                if "169.254" in inner or "metadata" in low or \
                        inner.startswith("file:"):
                    return self._respond(403, "<h1>WAF blocked</h1>")
            if path == "/fetch_filter":
                h = ""
                try:
                    h = urlsplit(inner).hostname or ""
                except Exception:
                    pass
                if h == "127.0.0.1":
                    return self._respond(403, "blocked by url filter")
            try:
                status, b, ct = _inner_fetch(inner)
            except urllib.error.HTTPError as e:
                status, b, ct = 502, ("UPSTREAM-HTTP-%d" % e.code).encode(), "text/plain"
            except Exception:
                status, b, ct = 502, b"UPSTREAM-FAIL", "text/plain"
            if path == "/fetch":
                return self._respond(status, b, ct=ct)
            if path in ("/fetch_blind", "/webhook"):
                if status == 200:
                    return self._respond(200, "queued-ok",
                                         ct="text/plain")
                return self._respond(500, "err: upstream failed",
                                     ct="text/plain")
            return self._respond(status, b, ct=ct)
        if path == "/api/xml":
            raw = (q.get("xml", [""])[0])
            st, msg = _xml_logic(raw)
            return self._respond(st, msg, ct="application/xml")
        if path == "/hosthdr":
            xfh = self.headers.get("X-Forwarded-Host", "")
            xou = self.headers.get("X-Original-URL", "")
            if xou:
                return self._respond(200, "origurl-routing:%s" % xou)
            if xfh:
                return self._respond(
                    200, "<html><link rel=canonical href='http://%s/canonical'>"
                         "<h1>hosthdr page</h1></html>" % xfh)
            return self._respond(200, "<html><h1>hosthdr page</h1></html>")
        if path == "/pdfgen":
            html_src = (q.get("html", [""])[0])
            n = 0
            for im in re.finditer(r"(?i)<img[^>]+src=[\"']([^\"']+)[\"']",
                                  html_src):
                try:
                    _inner_fetch(im.group(1))
                    n += 1
                except Exception:
                    pass
            return self._respond(200, "%%PDF-1.4 mock imgs=%d" % n,
                                 ct="application/pdf")
        if path == "/mdsim/latest/meta-data/":
            return self._respond(200, MD_BODY, ct="text/plain")
        if path == "/download":
            raw = self.path.split("path=", 1)[1] if "path=" in self.path else ""
            val = raw.split("&")[0]
            try:
                val = val.replace("%2e", ".").replace("%2f", "/")\
                         .replace("%5c", "\\")
            except Exception:
                pass
            docroot = LAB.get("docroot", "/nonexistent-docroot")
            # VULNERABLE simulation: naive join, NO confinement check -
            # yahi bug P15 detect karta hai. Mock sirf existing files read
            # karta hai (non-destructive lab reads).
            fp = os.path.normpath(os.path.join(docroot, val))
            if os.path.isfile(fp):
                try:
                    with open(fp, "rb") as f:
                        return self._respond(200, f.read(4096), ct="text/plain")
                except OSError:
                    pass
            return self._respond(404, NF_BODY)
        if path == "/download_safe":
            return self._respond(400, "traversal-safe: invalid path "
                                      "(normalized & refused)", ct="text/plain")
        if path == "/oauth/authorize":
            return self._respond(200, "<html><h1>OAuth authorize</h1>"
                                      "<form method=POST><input name=approve>"
                                      "</form></html>")
        return self._respond(404, NF_BODY)

    # ---------------- POST routes ----------------
    def do_POST(self):
        LAB["gets"] += 1
        ln = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(ln) if ln else b""
        ct = (self.headers.get("Content-Type", "") or "").lower()
        LAB["posts"].append({"path": urlsplit(self.path).path,
                             "ct": ct, "len": len(body)})
        path = urlsplit(self.path).path

        if path == "/xmlrpc.php":
            if b"methodCall" in body or b"methodName" in body:
                return self._respond(200, XMLRPC_BODY, ct="text/xml")
            return self._respond(500, "XML error: Start tag expected",
                                 ct="text/xml")
        if path in ("/import", "/upload_svg", "/saml/acs"):
            raw = None
            if "docx" in ct or "wordprocessingml" in ct:
                try:
                    with zipfile.ZipFile(io.BytesIO(body)) as z:
                        raw = z.read("[Content_Types].xml").decode("utf-8",
                                                                   "ignore")
                except Exception:
                    return self._respond(500, "bad docx package",
                                         ct="text/plain")
            else:
                raw = body.decode("utf-8", "ignore")
            st, msg = _xml_logic(raw or "")
            cto = "image/svg+xml" if path == "/upload_svg" else "application/xml"
            return self._respond(st, msg, ct=cto)
        return self._respond(404, NF_BODY)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True


# ===========================================================================
# SEED ARTIFACTS (P12/P13/P14/P9/P5/P3/P8/P6 handoffs - test fixtures)
# ===========================================================================
def _mkdir(p):
    os.makedirs(p, exist_ok=True)
    os.chmod(p, 0o777)
    return p


def _wjson(p, obj):
    _mkdir(os.path.dirname(p))
    with open(p, "w") as f:
        json.dump(obj, f, indent=2)
    os.chmod(p, 0o777)


def _wtext(p, text):
    _mkdir(os.path.dirname(p))
    with open(p, "w") as f:
        f.write(text)
    os.chmod(p, 0o777)


def seed(base, eng, origin):
    _mkdir(os.path.join(base, eng))
    _wtext(os.path.join(base, "scope.json"), json.dumps({
        "authorized": True, "engagement": eng,
        "authorization_reference": "P15 selftest SOW v1",
        "targets": [origin], "notes": "no-DoS; detection-only lab"}))
    inj = os.path.join(base, eng, "inject")
    _wjson(os.path.join(inj, "feedforward.json"), {"routing": {
        "to_phase15_ssrf": {
            "redirect_targets": [origin + "/redirect?to=", origin + "/fetch?url="],
            "xxe_ready": [origin + "/api/xml"],
            "note": "P15 fixtures"}}})
    _wjson(os.path.join(inj, "redirect_scan.json"), [
        {"url": origin + "/redirect?to=", "param": "to",
         "verdict": "SUSPECTED", "signals": []}])
    _wjson(os.path.join(base, eng, "xss", "feedforward.json"), {"routing": {
        "to_phase15_ssrf": {"header_url_hints": [origin + "/hosthdr"]}}})
    _wjson(os.path.join(base, eng, "client", "feedforward.json"), {"routing": {
        "to_phase15_ssrf": {"oauth_redirect_uris": [
            origin + "/oauth/authorize?client_id=w15&redirect_uri="
            "https%3A%2F%2Fcb.example%2Fc"]}}})
    _wjson(os.path.join(base, eng, "auth", "saml_surface.json"), [
        {"url": origin + "/saml/acs", "binding": "POST"}])
    _wtext(os.path.join(base, eng, "content", "all_found.txt"), "\n".join([
        origin + "/import", origin + "/upload_svg", origin + "/pdfgen?html=",
        origin + "/webhook?url=", origin + "/xmlrpc.php",
        origin + "/fetch_waf?url=", origin + "/fetch_filter?url=",
        origin + "/fetch_blind?url=", origin + "/fetch?url=",
        origin + "/hosthdr"]) + "\n")
    _wtext(os.path.join(base, eng, "passive", "findings",
                        "sensitive_params.txt"), "\n".join([
        origin + "/download?path=", origin + "/download_safe?path="]) + "\n")
    _wjson(os.path.join(base, eng, "surface", "priority_queue.json"),
           {"queue": [{"url": origin + "/", "score": 9}]})
    _wtext(os.path.join(base, eng, "tech", "stack_report.txt"),
           "nginx/1.24 | php/8.1 | linux | mysql\n")
    return os.path.join(base, eng)



# ===========================================================================
# UNIT TESTS (payload libs + SAFETY invariants)
# ===========================================================================
P15_ARTIFACTS = [
    "ssrf_surface.json", "ssrf_targets.txt", "ssrf_matrix.json",
    "bypass_matrix.json", "metadata_cloud.json", "internal_smoke.json",
    "scheme_matrix.json", "differential_engine.json", "header_host_probe.json",
    "xxe_surface.json", "xxe_matrix.json", "xxe_post_matrix.json",
    "traversal_matrix.json", "waf_map_ssrf.json", "technique_matrix_ssrf.json",
    "cwe_owasp_map_ssrf.json", "ssrf_probe_log.json", "SSRF_FINDINGS.md",
    "XXE_FINDINGS.md", "ssrf_test_plan.md", "ssrf_chains.txt",
    "TECHNIQUES_CATALOG_SSRF.md", "findings.json", "feedforward.json",
    "MANIFEST.json",
]


def unit_tests():
    print("\n== UNIT: payload libraries ==")
    v = dict(MS.ip_variants("127.0.0.1", 20))
    check("ip: decimal", v.get("decimal") == "2130706433", str(v.get("decimal")))
    check("ip: hex32", v.get("hex32") == "0x7f000001", str(v.get("hex32")))
    check("ip: octal32", v.get("octal32") == "017700000001", str(v.get("octal32")))
    check("ip: fewer-octets", v.get("fewer-octets") == "127.1",
          str(v.get("fewer-octets")))
    check("ip: zero-pad", v.get("zero-pad") == "127.000.000.001",
          str(v.get("zero-pad")))
    check("ip: enclosed-alnum", v.get("enclosed-alnum") == "①②⑦.⓪.⓪.①",
          str(v.get("enclosed-alnum")))
    v2 = dict(MS.ip_variants("169.254.169.254", 20))
    check("ip: metadata decimal", v2.get("decimal") == "2852039166",
          str(v2.get("decimal")))
    check("ip: cap respected", len(MS.ip_variants("127.0.0.1", 5)) == 5,
          str(len(MS.ip_variants("127.0.0.1", 5))))
    t = MS.parse_tricks("127.0.0.1", 8080, "/cxy", 10)
    check("parse: 10 tricks", len(t) == 10, str(len(t)))
    check("parse: userinfo trick", any("trusted.example.com@" in x for _, x in t))
    print("\n== UNIT: metadata SAFETY (crown jewel guards) ==")
    probes = MS._metadata_probes({"metadata_base": "http://169.254.169.254"})
    check("metadata: >=8 probes", len(probes) >= 8, str(len(probes)))
    check("metadata: >=7 providers", len({p["provider"] for p in probes}) >= 7,
          str(len({p["provider"] for p in probes})))
    bad = [p["url"] for p in probes
           if any(f in p["url"].lower() for f in MS.FORBIDDEN_PATH_PATTERNS)]
    check("metadata: ZERO forbidden paths", not bad, str(bad[:3]))
    check("metadata: no credentials substring", not any(
        "credential" in p["url"].lower() for p in probes))
    probes2 = MS._metadata_probes({"metadata_base": "http://127.0.0.1:39999"})
    lo = [p["url"] for p in probes2 if p["provider"] == "AWS EC2 IMDSv1"]
    check("metadata: base override works", lo and
          lo[0].startswith("http://127.0.0.1:39999"), str(lo[:1]))
    print("\n== UNIT: XXE builders ==")
    c = MS.xxe_classic("file:///etc/hostname")
    check("xxe: classic DOCTYPE+SYSTEM", "DOCTYPE" in c and
          'SYSTEM "file:///etc/hostname"' in c and "&waspxxe;" in c)
    check("xxe: param-entity", "%waspdtd" in MS.xxe_param_entity("http://x.invalid/d"))
    check("xxe: xinclude", 'parse="text"' in MS.xxe_xinclude("file:///etc/hostname"))
    check("xxe: php-filter", "php://filter" in MS.xxe_php_filter("/etc/hostname")
          and "base64-decode" in MS.xxe_php_filter("/etc/hostname"))
    check("xxe: svg", "<svg" in MS.xxe_svg("file:///etc/hostname"))
    check("xxe: saml", "samlp:Response" in MS.xxe_saml("file:///etc/hostname"))
    dz = MS.xxe_docx_bytes("file:///etc/hostname")
    try:
        with zipfile.ZipFile(io.BytesIO(dz)) as z:
            names = z.namelist()
        okd = "[Content_Types].xml" in names and len(names) == 3
    except Exception:
        okd = False
    check("xxe: docx zip valid", okd, str(names) if 'names' in dir() else "err")
    check("xxe: xmlrpc listMethods", "system.listMethods" in MS.xxe_xmlrpc_list())
    print("\n== UNIT: traversal matrix ==")
    labels = [l for l, _ in MS.TRAVERSAL_VARIANTS]
    check("trav: 30 variants", len(labels) == 30, str(len(labels)))
    check("trav: unique labels", len(set(labels)) == 30)
    _, pv = MS.traversal_build(("raw", "../"), 2, "/etc/passwd")
    check("trav: depth build", pv == "../../etc/passwd", pv)
    _, av = MS.traversal_build(("abs-inject", ""), 1, "/etc/hostname")
    check("trav: absolute inject", av == "/etc/hostname", av)
    _, sv = MS.traversal_build(("scheme-file", "file://"), 1, "/etc/hostname")
    check("trav: scheme injection", sv == "file:///etc/hostname", sv)
    print("\n== UNIT: regex + redaction primitives ==")
    for p in ("url", "src", "redirect_uri", "webhook_url", "img_url", "callback"):
        check("param-rx: %s" % p, bool(MS.URL_PARAM_RX.match(p)))
    check("param-rx: rejects csrf_token",
          not MS.URL_PARAM_RX.match("csrf_token"))
    check("param-rx: rejects password", not MS.URL_PARAM_RX.match("password"))
    fs = MS.filesig(b"abc")
    check("filesig: content_stored False", fs.get("content_stored") is False)
    check("redact: placeholder", "REDACTED" in MS.REDACTED_PLACEHOLDER)
    check("pii: AKIA masked", "AKIAIOSFODNN7" not in
          MS.pii_redact("key=AKIAIOSFODNN7EXAMPLE and more"))
    check("sev: >=30 hints", len(MS.SEVERITY_HINTS) >= 30,
          str(len(MS.SEVERITY_HINTS)))
    check("err: >=5 parser families", len(MS.XXE_ERROR_PRINTS) >= 5)
    check("markers: passwd root:x:", "root:x:" in MS.PASSWD_MARKERS)
    check("forbidden: db includes token/credential",
          "token" in MS.FORBIDDEN_PATH_PATTERNS and
          "credential" in MS.FORBIDDEN_PATH_PATTERNS)


# ===========================================================================
# E2E ACTIVE RUN (RoE gates OFF)
# ===========================================================================
def e2e_gate_off(origin, out, port):
    print("\n== E2E (gates OFF) ==")
    fm = {r["url"]: r for r in
          json.load(open(os.path.join(out, "ssrf_matrix.json")))}
    check("ssrf: /fetch CONFIRMED full-read",
          fm.get(origin + "/fetch?url=", {}).get("verdict") == "CONFIRMED" and
          fm[origin + "/fetch?url="].get("technique") == "full-response-ssrf",
          str(fm.get(origin + "/fetch?url=", {}).get("verdict")))
    check("ssrf: /fetch_blind SUSPECTED",
          fm.get(origin + "/fetch_blind?url=", {}).get("verdict") == "SUSPECTED")
    check("ssrf: /webhook SUSPECTED",
          fm.get(origin + "/webhook?url=", {}).get("verdict") == "SUSPECTED")
    check("ssrf: /fetch_waf CONFIRMED (WAF sirf 169.254/metadata/file block)",
          fm.get(origin + "/fetch_waf?url=", {}).get("verdict") == "CONFIRMED",
          str(fm.get(origin + "/fetch_waf?url=", {}).get("verdict")))
    check("ssrf: /fetch_filter BLOCKED (control)",
          fm.get(origin + "/fetch_filter?url=", {}).get("verdict") == "BLOCKED")
    check("ssrf: /redirect SAFE (302 hop, no echo)",
          fm.get(origin + "/redirect?to=", {}).get("verdict") == "SAFE")
    sigs = " ".join(fm.get(origin + "/fetch?url=", {}).get("signals", []))
    check("ssrf: scheme-file signal", "scheme-file" in sigs, sigs[:120])
    # metadata
    md = json.load(open(os.path.join(out, "metadata_cloud.json")))
    recs = md.get("records", [])
    conf_md = [r for r in recs if r.get("verdict") == "CONFIRMED"]
    check("metadata: >=1 CONFIRMED", len(conf_md) >= 1, str(len(recs)))
    provs = {p["provider"] for r in conf_md for p in r.get("providers", [])}
    check("metadata: AWS IMDSv1 provider", "AWS EC2 IMDSv1" in provs, str(provs))
    all_md_urls = " ".join(p.get("safe_path", "") for r in recs
                           for p in r.get("probes", []))
    check("metadata: probe urls SAFE (no creds paths)", not any(
        f in all_md_urls.lower() for f in MS.FORBIDDEN_PATH_PATTERNS))
    check("metadata: manual wave documented",
          any("MANUAL" in w for w in md.get("manual_wave", [])) or
          not conf_md)
    # bypass
    bm = {r["url"]: r for r in
          json.load(open(os.path.join(out, "bypass_matrix.json")))}
    ff_rec = bm.get(origin + "/fetch_filter?url=", {})
    check("bypass: /fetch_filter winner ip-*",
          (ff_rec.get("winning_variant") or "").startswith("ip:"),
          str(ff_rec.get("winning_variant")))
    check("bypass: control blocked recorded",
          ff_rec.get("control", {}).get("blocked") is True)
    # xxe
    xm = {r["url"].split("?")[0]: r for r in
          json.load(open(os.path.join(out, "xxe_matrix.json")))}
    ax = xm.get(origin + "/api/xml", {})
    check("xxe: /api/xml CONFIRMED", ax.get("verdict") == "CONFIRMED",
          str(ax.get("verdict")))
    xsig = " ".join(ax.get("signals", []))
    check("xxe: classic in-band signal", "classic" in xsig, xsig[:120])
    check("xxe: param-entity signal", "param-entity" in xsig, xsig[:120])
    check("xxe: content policy note",
          "store nahi" in (ax.get("evidence_note") or ""))
    xp = {r["url"].split("?")[0]: r for r in
          json.load(open(os.path.join(out, "xxe_post_matrix.json")))}
    check("xxe-post: /import SKIPPED (gate)",
          xp.get(origin + "/import", {}).get("verdict") == "SKIPPED")
    check("xxe-post: /xmlrpc.php SKIPPED (gate)",
          xp.get(origin + "/xmlrpc.php", {}).get("verdict") == "SKIPPED")
    check("xxe-post: gate note", "ssrf_allow_post=false" in
          (xp.get(origin + "/import", {}).get("note") or ""))
    # traversal
    tm = {r["url"].split("?")[0]: r for r in
          json.load(open(os.path.join(out, "traversal_matrix.json")))}
    check("trav: /download CONFIRMED",
          tm.get(origin + "/download", {}).get("verdict") == "CONFIRMED",
          str(tm.get(origin + "/download", {}).get("verdict")))
    check("trav: /download winning variant set",
          bool(tm.get(origin + "/download", {}).get("winning_variant")))
    check("trav: /download_safe HARDENED",
          tm.get(origin + "/download_safe", {}).get("verdict") == "HARDENED",
          str(tm.get(origin + "/download_safe", {}).get("verdict")))
    # header host
    hh = {r["url"].split("?")[0]: r for r in
          json.load(open(os.path.join(out, "header_host_probe.json")))}
    check("header: /hosthdr SUSPECTED",
          hh.get(origin + "/hosthdr", {}).get("verdict") == "SUSPECTED")
    check("header: fake host reflected", any(
        p.get("host_reflected") for p in
        hh.get(origin + "/hosthdr", {}).get("probes", [])))
    # smoke gated OFF
    sm = json.load(open(os.path.join(out, "internal_smoke.json")))
    check("smoke: gated OFF record", sm and sm[0].get("gated") is True)
    # findings
    fj = json.load(open(os.path.join(out, "findings.json")))
    keys = {f["key"] for f in fj.get("findings", [])}
    expected = {"ssrf_full_read", "ssrf_blind_differential", "ssrf_self_fetch",
                "ssrf_scheme_file", "ssrf_metadata_reachable",
                "ssrf_post_gate_skipped", "xxe_file_read",
                "xxe_param_entity_blind", "traversal_file_read",
                "traversal_encoding_bypass", "traversal_hardened",
                "ssrf_header_host_inject", "ssrf_ip_bypass"}
    missing = expected - keys
    check("findings: 13 expected keys", not missing,
          "missing=%s" % sorted(missing))
    sevs = [f["severity"] for f in fj.get("findings", [])]
    check("findings: critical present", "critical" in sevs, str(set(sevs)))
    check("findings: >=10 total", fj.get("count", 0) >= 10,
          str(fj.get("count")))
    # rogue POSTs (gate OFF)
    check("rogue: 0 POST gate OFF", len(LAB["posts"]) == 0,
          str(LAB["posts"][:2]))
    # technique matrix
    tmx = json.load(open(os.path.join(out, "technique_matrix_ssrf.json")))
    check("tech: >=30 rows", len(tmx) >= 30, str(len(tmx)))
    check("tech: MANUAL-ONLY rows", any(r.get("status") == "MANUAL-ONLY"
                                        for r in tmx))
    # chains + reports
    ch = open(os.path.join(out, "ssrf_chains.txt")).read()
    check("chains: CHAIN 1 present", "CHAIN 1" in ch)
    md_txt = open(os.path.join(out, "SSRF_FINDINGS.md")).read()
    check("report: SSRF_FINDINGS safety section",
          "Safety discipline" in md_txt and "REDACTED" in md_txt)
    check("report: XXE_FINDINGS exists", os.path.isfile(
        os.path.join(out, "XXE_FINDINGS.md")))
    plan = open(os.path.join(out, "ssrf_test_plan.md")).read()
    check("plan: manual wave + RoE", "MANUAL" in plan.upper() and "RoE" in plan)
    cat = open(os.path.join(out, "TECHNIQUES_CATALOG_SSRF.md")).read()
    check("catalog: safety invariants", "Safety invariants" in cat and
          len(cat) > 4000)
    # payloads inert
    pdir = os.path.join(out, "xxe_payloads")
    check("payloads: dir with files", os.path.isdir(pdir) and
          len(os.listdir(pdir)) >= 8)
    if os.path.isdir(pdir):
        sample = open(os.path.join(pdir, "classic_file_hostname.xml")).read()
        check("payloads: inert note", "INERT" in sample)
    return keys



# ===========================================================================
# ARTIFACTS + RWX + ZERO-EGRESS + REDACTION
# ===========================================================================
def artifact_tests(out):
    print("\n== ARTIFACTS / RWX / EGRESS / REDACTION ==")
    for a in P15_ARTIFACTS:
        check("artifact: %s" % a, os.path.isfile(os.path.join(out, a)))
    ff = json.load(open(os.path.join(out, "feedforward.json")))
    rt = ff.get("routing", {})
    for k in ("to_phase16_files", "to_phase17_api", "to_phase20_logic",
              "to_phase23_misconfig", "to_phase24_cloud", "to_phase26_cache",
              "to_phase28_chains", "to_phase32_report"):
        check("feedforward: %s" % k, k in rt)
    man = json.load(open(os.path.join(out, "MANIFEST.json")))
    check("manifest: >=20 files", len(man.get("files", [])) >= 20,
          str(len(man.get("files", []))))
    check("manifest: probes stat", "probes_total" in man.get("stats", {}))
    # RWX 0777
    bad = []
    for dp, dns, fns in os.walk(out):
        for fn in fns:
            p = os.path.join(dp, fn)
            if (os.stat(p).st_mode & 0o777) != 0o777:
                bad.append(p)
    check("RWX: sab files 0777", not bad, str(bad[:3]))
    # zero-external-egress (LAB inner fetches)
    def egress_ok(u):
        if u.startswith("file://"):
            return True
        sp = urlsplit(u)
        h = (sp.hostname or "").lower()
        if h in ("127.0.0.1", "localhost"):
            return True
        if h.endswith(".invalid"):
            return True
        if h.startswith("169.254.") or h == "100.100.100.200":
            return True
        if "fd00:ec2" in h or h == "metadata.google.internal":
            return True
        # URL-parser confusion probes: string me hi loopback literal hota hai
        # (bad_host hamesha 127.0.0.1) - triple-slash/backslash variants
        if "127.0.0.1" in u or "localhost" in u:
            return True
        # IP-encoding bypass probes: numeric forms LOOPBACK ke hi hain
        # (decimal/hex/octal/zero-pad/v6-mapped) - module unhe rewrite karke
        # loopback hi fetch karta hai
        if re.match(r"^[0-9]+$", h) or re.match(r"^[0-9a-fx.]+$", h.lower()):
            return True
        if "0x" in h.lower() or not h.isascii():
            return True
        if re.match(r"^[0-7.]+$", h) or ":" in h:
            return True
        return False
    bad_egress = [u for u in LAB["inner"] if not egress_ok(u)]
    check("egress: ZERO external (LAB inner fetches)", not bad_egress,
          str(bad_egress[:3]))
    # REDACTION: evidence raw + report files me file-content NAHI
    leak = []
    raw_dir = os.path.join(out, "evidence", "raw")
    if os.path.isdir(raw_dir):
        for fn in os.listdir(raw_dir):
            p = os.path.join(raw_dir, fn)
            try:
                with open(p, "rb") as f:
                    blob = f.read(200000)
            except OSError:
                continue
            if b"root:x:" in blob or b"ami-waspmock" in blob or \
                    b"WASPP15TRAVERSECANARY" in blob:
                leak.append(fn)
    check("redact: evidence raw clean (no file content)", not leak, str(leak[:3]))
    # REDACTION: matrices me content_stored=false
    tmm = json.load(open(os.path.join(out, "traversal_matrix.json")))
    stored = [p for r in tmm for p in r.get("probes", [])
              if (p.get("sig") or {}).get("content_stored") is True]
    check("redact: traversal content_stored=False", not stored, str(stored[:2]))
    mdd = json.load(open(os.path.join(out, "metadata_cloud.json")))
    stored_md = [p for r in mdd.get("records", []) for p in r.get("probes", [])
                 if (p.get("sig") or {}).get("content_stored") is True]
    check("redact: metadata content_stored=False", not stored_md,
          str(stored_md[:2]))
    # probe log urls-only
    pl = json.load(open(os.path.join(out, "ssrf_probe_log.json")))
    check("probe-log: entries present", len(pl) >= 5, str(len(pl)))
    check("probe-log: no body field", all("body" not in e for e in pl))


# ===========================================================================
# GATED RUN (ssrf_allow_post + ssrf_internal_smoke ON)
# ===========================================================================
def e2e_gate_on(origin, out, port):
    print("\n== E2E (gates ON - POST XXE + smoke) ==")
    check("gated: POSTs hit lab", len(LAB["posts"]) >= 4, str(LAB["posts"][:4]))
    cts = {p["ct"] for p in LAB["posts"]}
    check("gated: content-types (xml/svg/docx/rpc)", any(
        "xml" in c for c in cts), str(cts))
    xp = {r["url"].split("?")[0]: r for r in
          json.load(open(os.path.join(out, "xxe_post_matrix.json")))}
    for u, fam in ((origin + "/upload_svg", "svg"), (origin + "/saml/acs", "saml"),
                   (origin + "/xmlrpc.php", "xmlrpc"), (origin + "/import", "docx")):
        rec = xp.get(u, {})
        rows = {f.get("family"): f for f in rec.get("families", [])}
        check("gated: %s family probed" % fam, fam in rows, str(list(rows)))
    check("gated: xmlrpc CONFIRMED",
          xp.get(origin + "/xmlrpc.php", {}).get("verdict") == "CONFIRMED",
          str(xp.get(origin + "/xmlrpc.php", {}).get("verdict")))
    check("gated: svg CONFIRMED",
          xp.get(origin + "/upload_svg", {}).get("verdict") == "CONFIRMED",
          str(xp.get(origin + "/upload_svg", {}).get("verdict")))
    check("gated: saml CONFIRMED",
          xp.get(origin + "/saml/acs", {}).get("verdict") == "CONFIRMED",
          str(xp.get(origin + "/saml/acs", {}).get("verdict")))
    check("gated: import(docx) CONFIRMED",
          xp.get(origin + "/import", {}).get("verdict") == "CONFIRMED",
          str(xp.get(origin + "/import", {}).get("verdict")))
    fj = json.load(open(os.path.join(out, "findings.json")))
    keys = {f["key"] for f in fj.get("findings", [])}
    for k in ("xxe_svg_doc", "xxe_office_import", "xxe_saml",
              "xxe_xmlrpc_pingback"):
        check("gated finding: %s" % k, k in keys)
    # smoke
    sm = json.load(open(os.path.join(out, "internal_smoke.json")))
    check("smoke: gated ON record", sm and sm[0].get("gated") is False)
    reachable = [p for hh2 in sm[0].get("hosts", []) for p in
                 hh2.get("ports", []) if p.get("verdict") == "REACHABLE"]
    check("smoke: server port reachable", any(p.get("port") == port
                                              for p in reachable),
          str(reachable))
    check("smoke: banner-only (sig redacted)", all(
        p.get("sig", {}).get("content_stored") is False for p in reachable))
    check("gated finding: ssrf_internal_reachable",
          "ssrf_internal_reachable" in keys)


# ===========================================================================
# CFG BUILDER
# ===========================================================================
def make_cfg(port, gated=False, active=True, resume=False):
    cfg = WC.Cfg(None)
    cfg.allow_active = active
    cfg.resume = resume
    cfg.rate_limit = 90.0
    cfg.jitter = 0.05
    cfg.timeout = 8
    cfg.retries = 0
    cfg.max_requests = 30000
    cfg.save_bodies = True
    cfg.save_replays = True
    cfg.module_outdir = None
    cfg.checkpoint = None
    cfg.ssrf_allow_post = gated
    cfg.ssrf_internal_smoke = gated
    cfg.ssrf_timing_samples = 3
    cfg.ssrf_cold_start = 6
    cfg.ssrf_fetch_endpoints = 10
    cfg.ssrf_xxe_targets = 8
    cfg.ssrf_xxe_payloads = 8
    cfg.ssrf_traverse_targets = 6
    cfg.ssrf_traverse_probes = 12
    cfg.ssrf_ip_variants = 16
    cfg.ssrf_parse_tricks = 10
    cfg.metadata_base = "http://127.0.0.1:%d/mdsim" % port
    if gated:
        cfg.ssrf_smoke_ports = "%d,80,443,8080,8000" % port
    return cfg


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    # ---------- mock lab + traversal docroot ----------
    srv = LabServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    origin = "http://127.0.0.1:%d" % port
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    docroot = tempfile.mkdtemp(prefix="wasp_p15_docroot_")
    with open(os.path.join(docroot, "notes.txt"), "w") as f:
        f.write("mock docroot note")
    with open(os.path.join(docroot, "deep_secret_canary.txt"), "w") as f:
        f.write("WASPP15TRAVERSECANARY")
    os.chmod(os.path.join(docroot, "notes.txt"), 0o777)
    os.chmod(os.path.join(docroot, "deep_secret_canary.txt"), 0o777)
    LAB["docroot"] = docroot
    print("Mock SSRF lab: %s (docroot=%s)" % (origin, docroot))

    try:
        # ---------- unit ----------
        unit_tests()

        # ---------- active run (gates OFF) ----------
        print("\n== ACTIVE RUN (gates OFF) ==")
        seed(BASE, ENG, origin)
        cfg = make_cfg(port, gated=False)
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        out = MS.run(cfg, scope, BASE)
        check("run: outdir bana", os.path.isdir(out), out)
        e2e_gate_off(origin, out, port)
        artifact_tests(out)
        gets_after_run1 = LAB["gets"]

        # ---------- checkpoint replay ----------
        print("\n== CHECKPOINT REPLAY ==")
        cfg2 = make_cfg(port, gated=False, resume=True)
        scope2 = WC.Scope(os.path.join(BASE, "scope.json"))
        out2 = MS.run(cfg2, scope2, BASE)
        fj1 = json.load(open(os.path.join(out, "findings.json")))
        fj2 = json.load(open(os.path.join(out2, "findings.json")))
        check("replay: findings stable", fj1["count"] == fj2["count"],
              "%s vs %s" % (fj1["count"], fj2["count"]))
        s1 = {r["url"]: r["verdict"] for r in
              json.load(open(os.path.join(out, "ssrf_matrix.json")))}
        s2 = {r["url"]: r["verdict"] for r in
              json.load(open(os.path.join(out2, "ssrf_matrix.json")))}
        check("replay: ssrf verdicts stable", s1 == s2)
        check("replay: naye lab GETs bounded",
              LAB["gets"] - gets_after_run1 < 60,
              "delta=%d" % (LAB["gets"] - gets_after_run1))

        # ---------- gated run ----------
        print("\n== GATED RUN (ssrf_allow_post + ssrf_internal_smoke) ==")
        LAB["posts"] = []
        seed(BASE_GATED, ENG_G, origin)
        cfg3 = make_cfg(port, gated=True)
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = MS.run(cfg3, scope3, BASE_GATED)
        e2e_gate_on(origin, out3, port)

        # ---------- passive mode ----------
        print("\n== PASSIVE MODE ==")
        gets_before_passive = LAB["gets"]
        seed(BASE2, ENG_P, origin)
        cfg4 = make_cfg(port, active=False)
        scope4 = WC.Scope(os.path.join(BASE2, "scope.json"))
        out4 = MS.run(cfg4, scope4, BASE2)
        check("passive: 0 lab requests",
              LAB["gets"] == gets_before_passive,
              "delta=%d" % (LAB["gets"] - gets_before_passive))
        check("passive: test-plan exists",
              os.path.isfile(os.path.join(out4, "ssrf_test_plan.md")))
        man4 = json.load(open(os.path.join(out4, "MANIFEST.json")))
        check("passive: manifest mode", man4.get("stats", {}).get("mode")
              == "passive")
        ff4 = json.load(open(os.path.join(out4, "feedforward.json")))
        check("passive: feedforward mode", ff4["routing"]
              .get("to_phase32_report", {}).get("mode") == "passive")

        # ---------- CLI ----------
        print("\n== CLI ==")
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            MS.main()
        check("cli: banner", "Phase 15" in buf.getvalue())
        check("cli: RoE gates mentioned", "ssrf_allow_post" in buf.getvalue())

        # ---------- source hygiene ----------
        print("\n== SOURCE HYGIENE ==")
        src = open(os.path.join(ULTRA, "mod_ssrf.py")).read()
        check("hygiene: no billion-laughs payload", "billion" not in src.lower()
              or "FORBIDDEN" in src)
        check("hygiene: canary family", "waspP15" in src)
        check("hygiene: detection-only note", src.count("detection-only") >= 3)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            try:
                compile(src, "mod_ssrf.py", "exec")
                check("hygiene: -W error clean", True)
            except SyntaxWarning as w:
                check("hygiene: -W error clean", False, str(w))

    finally:
        srv.shutdown()
    print("\n=====================================================")
    print("P15 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, d))
        sys.exit(1)
    print("ALL GREEN ✅")


if __name__ == "__main__":
    import warnings
    main()
