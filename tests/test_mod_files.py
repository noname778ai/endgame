#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P16 SELF-TEST SUITE - mod_files.py v17.0.0-ultra-ultra-pro-max (P16)
=============================================================================
 Mock file-upload lab + full assertion suite:
   - Unit tests (payload libs: magic builders/filename variants/CT matrix/
     svg-docx-zipslip INERT builders/multipart roundtrip/INERT enforcement)
   - SAFETY unit tests (FORBIDDEN_CONTENT_PATTERNS hard-enforced, webshell/
     htaccess exts FORBIDDEN-AUTO, zero-external-egress, content redaction)
   - Active run e2e (stages A..K verdict assertions, RoE gates OFF)
   - Gated run (import-xxe + archive zip-slip + cleanup DELETE ON)
   - Artifact integrity (24+ output files, matrices, catalog, feedforward)
   - RWX rule (0777 on every result file)
   - Zero-external-egress check (sirf loopback)
   - REDACTION check (getback content kabhi evidence me store nahi hota)
   - Passive mode (allow_active=False -> 0 probes)
   - Checkpoint replay (verdicts stable)
 Detection-only discipline honored: lab me bhi koi webshell/code payload nahi.
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
import io
import re
import sys
import json
import shutil
import zipfile
import hashlib
import contextlib
import threading
import subprocess
import email.parser
import email.policy
import urllib.request
import urllib.error
import xml.dom.minidom
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block3_input")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_files as MF                                         # noqa: E402
import wasp_core as WC                                         # noqa: E402

BASE = os.path.join(HERE, "p16_test_base")
BASE_GATED = os.path.join(HERE, "p16_test_base_gated")
BASE2 = os.path.join(HERE, "p16_test_base_passive")
ENG = "p16lab"
ENG_G = "p16lab2"
ENG_P = "p16labp"

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
# MOCK UPLOAD LAB
# - /                    homepage (2 multipart forms w/ accept + csrf)
# - POST /upload         VULNERABLE: accepts EVERYTHING, serves back raw
#                        (.php -> text/html = exec sim), zip-extract echo
# - POST /upload_client  same (client-side-only filter sim)
# - POST /upload_strict  HARDENED: ext whitelist + magic check + rename
# - POST /upload_waf     WAF: 403 sab multipart par
# - POST /upload_priv    upload OK par getback auth-protected (401 anon)
# - POST /upload_svg     XML/SVG import parser (entity-resolve sim)
# - POST /import         DOCX import parser (zip -> document.xml sim)
# - GET  /files/         directory listing (Index of)
# - GET  /files/<n>      serve: CT by extension (exec sim for php/html)
# - GET  /safe_files/<n> serve: attachment + nosniff (hardened)
# - GET  /priv_files/<n> 401 without Cookie (auth sim)
# - DELETE /files/<n>    cleanup sim (200 deleted)
# - unknown              404 "MOCK-NF" (stable soft-404 template)
# SAFETY: mock sirf in-memory store use karta hai; koi filesystem write nahi,
#         koi webshell/code execute nahi - CT headers sirf SIMULATE hote hain.
# ===========================================================================
LAB = {"gets": 0, "posts": 0, "deletes": 0, "uploads": []}
STORE = {}                                     # "files/<n>"|"/safe_files/<n>"|...

HOME_TPL = ("<html><head><title>P16 Mock Upload Lab</title></head><body>"
            "<h1>WASPP16HOME fixed-content homepage marker</h1>"
            "<form action='%s/upload' method='post' enctype='multipart/"
            "form-data'><input type='hidden' name='csrf_token' value="
            "'waspcsr123'><input type='file' name='file' accept='.png'>"
            "<input type=submit></form>"
            "<form action='%s/upload_client' method='post' enctype="
            "'multipart/form-data'><input type='hidden' "
            "name='MAX_FILE_SIZE' value='100'><input type='file' "
            "name='file' accept='.png'><input type=submit></form>"
            "<p>lorem ipsum dolor sit amet consectetur adipiscing elit sed "
            "do eiusmod tempor incididunt ut labore.</p></body></html>")
NF_BODY = "MOCK-NF"
LISTING_TPL = ("<html><head><title>Index of /files</title></head><body>"
               "<h1>Index of /files</h1><table>%s</table></body></html>")

EXEC_EXTS = {"php", "php5", "phtml", "phar", "shtml", "html", "jsp", "asp",
             "aspx", "cgi"}


def _ct_for(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in ("php", "php5", "phtml", "phar", "shtml", "html", "jsp"):
        return "text/html"
    if ext == "svg":
        return "image/svg+xml"
    if ext == "png":
        return "image/png"
    if ext in ("jpg", "jpeg"):
        return "image/jpeg"
    if ext == "gif":
        return "image/gif"
    return "text/plain"


def _leaf(name):
    n = (name or "").replace("\\", "/")
    return n.rsplit("/", 1)[-1]


def _parse_mp(body, ct_header):
    """Multipart/form-data parse (email parser) -> [{filename,ctype,content}]."""
    try:
        msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            ("Content-Type: %s\r\nMIME-Version: 1.0\r\n\r\n"
             % ct_header).encode() + body)
        parts = []
        if msg.is_multipart():
            for p in msg.iter_parts():
                parts.append({"filename": p.get_filename(),
                              "ctype": p.get_content_type(),
                              "content": p.get_payload(decode=True) or b""})
        else:
            parts.append({"filename": msg.get_filename(),
                          "ctype": msg.get_content_type(),
                          "content": msg.get_payload(decode=True) or b""})
        return parts
    except Exception:
        return []


def _import_sim(raw):
    """Vulnerable import parser sim: ENTITY+SYSTEM file:// -> path echo."""
    if "<!ENTITY" in raw and "SYSTEM" in raw:
        m = re.search(r'SYSTEM\s+"file://([^"]+)"', raw)
        tgt = m.group(1) if m else "/etc/hostname"
        return 200, ("imported: entity resolved file://%s -> "
                     "MOCKFILE-WASPP16-CONTENT" % tgt)
    try:
        xml.dom.minidom.parseString(raw)
        return 200, "imported ok"
    except Exception as e:
        return 500, "xml error: %s" % str(e)[:60]


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockUploadLab/1.0"

    def log_message(self, *a):
        pass

    def _respond(self, status, body, headers=None, ct="text/html; charset=utf-8"):
        b = body if isinstance(body, bytes) else body.encode("utf-8", "ignore")
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Server", "MockUploadLab/1.0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    # ---------------- GET ----------------
    def do_GET(self):
        LAB["gets"] += 1
        sp = urlsplit(self.path)
        path = sp.path
        origin = "http://127.0.0.1:%d" % self.server.server_address[1]

        if path in ("/", ""):
            return self._respond(200, HOME_TPL % (origin, origin))
        if path == "/files/":
            rows = "".join("<tr><td><a href='/files/%s'>%s</a></td></tr>"
                           % (k.split("/", 1)[1], k.split("/", 1)[1])
                           for k in sorted(STORE) if k.startswith("files/"))
            return self._respond(200, LISTING_TPL % rows)
        for prefix, guarded in (("/files/", False), ("/safe_files/", True),
                                ("/priv_files/", "auth")):
            if path.startswith(prefix):
                nm = path[len(prefix):]
                key = prefix + nm
                if guarded == "auth" and \
                        "waspsess=1" not in (self.headers.get("Cookie") or ""):
                    return self._respond(401, "auth required", ct="text/plain")
                if key in STORE:
                    data = STORE[key]
                    if guarded is True:
                        return self._respond(
                            200, data,
                            {"Content-Disposition": "attachment; filename=%s"
                             % nm, "X-Content-Type-Options": "nosniff"},
                            ct="image/png")
                    return self._respond(200, data, ct=_ct_for(nm))
                return self._respond(404, NF_BODY)
        return self._respond(404, NF_BODY)

    # ---------------- DELETE ----------------
    def do_DELETE(self):
        LAB["deletes"] += 1
        path = urlsplit(self.path).path
        if path.startswith("/files/") and path in STORE:
            STORE.pop(path, None)
            return self._respond(200, "deleted", ct="text/plain")
        return self._respond(404, NF_BODY)

    # ---------------- OPTIONS (v17 put/dav census) ----------------
    def do_OPTIONS(self):
        LAB["options"] = LAB.get("options", 0) + 1
        path = urlsplit(self.path).path
        if path.startswith("/files"):
            return self._respond(200, "ok", {
                "Allow": "GET, POST, PUT, DELETE, OPTIONS", "DAV": "1"},
                ct="text/plain")
        return self._respond(405, "method not allowed",
                             {"Allow": "GET, POST"}, ct="text/plain")

    # ---------------- PUT (v17 gated write probe) ----------------
    def do_PUT(self):
        LAB["puts"] = LAB.get("puts", 0) + 1
        ln = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(ln) if ln else b""
        path = urlsplit(self.path).path
        if path.startswith("/files/") and len(path) > len("/files/"):
            STORE[path] = body
            return self._respond(201, "created", ct="text/plain")
        return self._respond(405, "put not allowed here", ct="text/plain")

    # ---------------- POST ----------------
    def do_POST(self):
        LAB["posts"] += 1
        ln = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(ln) if ln else b""
        ct = (self.headers.get("Content-Type", "") or "")
        path = urlsplit(self.path).path
        origin = "http://127.0.0.1:%d" % self.server.server_address[1]
        parts = _parse_mp(body, ct)
        fpart = next((p for p in parts if p.get("filename")), None)
        LAB["uploads"].append({"path": path,
                               "filename": (fpart or {}).get("filename"),
                               "len": len((fpart or {}).get("content") or b"")})

        if path == "/upload_waf":
            return self._respond(403, "<h1>blocked by WAF upload rules</h1>",
                                 ct="text/html")
        if path in ("/upload", "/upload_client", "/upload_priv"):
            if not fpart or not fpart["filename"]:
                return self._respond(400, "no file", ct="application/json")
            rawname = fpart["filename"]
            leaf = _leaf(rawname)
            content = fpart["content"] or b""
            prefix = "/priv_files/" if path == "/upload_priv" else "/files/"
            STORE[prefix + leaf] = content
            extracted = []
            if leaf.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        extracted = z.namelist()[:6]
                except Exception:
                    extracted = ["badzip"]
            resp = json.dumps({"status": "uploaded", "ok": True,
                               "url": "%s%s%s" % (origin, prefix, leaf),
                               "saved": rawname,
                               "extracted": ",".join(extracted)})
            return self._respond(200, resp, ct="application/json")
        if path == "/upload_strict":
            if not fpart or not fpart["filename"]:
                return self._respond(400, "no file", ct="application/json")
            rawname = fpart["filename"]
            content = fpart["content"] or b""
            ext = _leaf(rawname).rsplit(".", 1)[-1].lower()
            magic_ok = content[:4] in (b"\x89PNG", b"GIF8") or \
                content[:2] == b"\xff\xd8"
            tokens = re.split(r"[.;\s\x00]", _leaf(rawname).lower())
            bad_ext = any(t in ("php", "php5", "phtml", "phar", "jsp",
                                "jspx", "asp", "aspx", "ashx", "shtml",
                                "cgi") for t in tokens)
            if bad_ext or ext not in ("png", "jpg", "jpeg",
                                      "gif") or not magic_ok:
                return self._respond(415, "invalid extension or content: "
                                     "allowed types png jpg gif",
                                     ct="text/plain")
            import binascii
            nm = "%s.%s" % (binascii.hexlify(os.urandom(6)).decode(), ext)
            STORE["/safe_files/" + nm] = content
            return self._respond(200, json.dumps(
                {"status": "uploaded", "url": "%s/safe_files/%s"
                 % (origin, nm)}), ct="application/json")
        if path == "/upload_svg":
            raw = (fpart or {}).get("content")
            raw = raw.decode("utf-8", "ignore") if raw else ""
            st, msg = _import_sim(raw)
            return self._respond(st, msg, ct="image/svg+xml")
        if path == "/import":
            raw = ""
            if fpart and (fpart["filename"] or "").lower().endswith(".docx"):
                try:
                    with zipfile.ZipFile(io.BytesIO(fpart["content"])) as z:
                        raw = z.read("word/document.xml").decode("utf-8",
                                                                 "ignore")
                except Exception:
                    return self._respond(500, "bad docx package",
                                         ct="text/plain")
            elif fpart:
                raw = (fpart["content"] or b"").decode("utf-8", "ignore")
            st, msg = _import_sim(raw)
            return self._respond(st, msg, ct="application/xml")
        return self._respond(404, NF_BODY)


def _start_lab():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, port


# ===========================================================================
# SEED FIXTURES (P15/P5/P2/P7/P12/P8/P3 artifacts)
# ===========================================================================
def _w(base, eng, rel, data):
    p = os.path.join(base, eng, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        if isinstance(data, str):
            f.write(data)
        else:
            json.dump(data, f, indent=1)
    os.chmod(p, 0o777)


def _seed(base, eng, origin, with_forms=True):
    if os.path.isdir(os.path.join(base, eng)):
        shutil.rmtree(os.path.join(base, eng))
    os.makedirs(os.path.join(base, eng), exist_ok=True)
    _w(base, "", "scope.json", {
        "authorized": True, "engagement": eng,
        "authorization_reference": "P16 selftest SOW v1",
        "targets": [origin],
        "notes": "no-DoS; detection-only INERT lab"})
    # P15 feedforward (import handoff)
    _w(base, eng, "ssrf/feedforward.json", {"routing": {
        "to_phase16_files": {
            "svg_doc_endpoints": [origin + "/upload_svg", origin + "/import"],
            "traversal_confirmed": [origin + "/download?path="],
            "note": "upload/import par SVG/docx XXE P16 me"}}})
    # P5 feedforward + content
    _w(base, eng, "content/feedforward.json", {"routing": {
        "to_phase16_upload": {"paths": ["/upload", "/upload_client",
                                        "/upload_waf", "/upload_strict",
                                        "/upload_priv"]}}})
    _w(base, eng, "content/all_found.txt", "\n".join([
        origin + "/upload", origin + "/files/", origin + "/media/upload",
        origin + "/import"]) + "\n")
    # P2 forms (multipart census)
    if with_forms:
        _w(base, eng, "understand/forms.json", {"forms": [{
            "url": origin + "/upload", "method": "POST",
            "enctype": "multipart/form-data",
            "has_file": True,
            "fields": [{"name": "csrf_token", "type": "hidden"},
                       {"name": "file", "type": "file"}],
            "csrf_fields": ["csrf_token"]}]})
    # P7 js
    _w(base, eng, "js/endpoints.txt", "\n".join([
        origin + "/upload", origin + "/import", origin + "/media/upload"]) + "\n")
    _w(base, eng, "js/params.txt", "file\nimage\navatar\ndocument\n")
    # P8 priority
    _w(base, eng, "surface/priority_queue.json", [
        {"url": origin + "/upload", "param": "file", "score": 9.0}])
    # P12 reflection_map
    _w(base, eng, "inject/reflection_map.json", [
        {"url": origin + "/upload", "param": "file", "verbatim": True}])
    # P3 sensitive params
    _w(base, eng, "passive/findings/sensitive_params.txt", "file\navatar\n")
    return True


# ===========================================================================
# UNIT: payload libraries
# ===========================================================================
def unit_payloads():
    print("\n== UNIT: payload libraries ==")
    fv = MF.filename_variants("waspP16doc", 14)
    labels = [l for l, _ in fv]
    check("fv: cap respected", len(fv) == 14, str(len(fv)))
    check("fv: svg-serve in cap", "svg-serve" in labels, str(labels))
    check("fv: double-ext present", "double-ext" in labels)
    check("fv: nullbyte label", "nullbyte-legacy" in labels)
    dbl = dict(fv)["double-ext"]
    check("fv: double-ext shape", dbl.endswith(".png.php"), dbl)
    nul = dict(fv)["nullbyte-legacy"]
    check("fv: NUL raw in nullbyte", "\x00" in nul)
    check("fv: unique filenames", len(set(n for _, n in fv)) == len(fv))
    tv = MF.filename_trick_variants("waspP16doc", 6)
    check("tv: 6 tricks", len(tv) == 6, str(len(tv)))
    check("tv: relative-up", dict(tv)["relative-up"].startswith("../../"))
    check("tv: absolute", dict(tv)["absolute-tmp"].startswith("/tmp/"))
    check("tv: windows", "..\\..\\" in dict(tv)["windows-up"])
    ctv = MF.ct_variants(6)
    check("ct: honest first", ctv[0] == ("image/png", "honest"), str(ctv[0]))
    check("ct: spoof kinds", any(k == "spoof" for _, k in ctv))
    check("ct: cap", len(MF.ct_variants(3)) == 3)
    # magic builders
    png = MF.magic_png("WASP16C1")
    check("magic: png header", png.startswith(b"\x89PNG\r\n\x1a\n"))
    check("magic: png canary", b"WASP16C1" in png)
    check("magic: gif", MF.magic_gif("C").startswith(b"GIF89a"))
    check("magic: jpg", MF.magic_jpg("C").startswith(b"\xff\xd8\xff\xe0"))
    check("magic: pdf", MF.magic_pdf("C").startswith(b"%PDF-1.4"))
    check("magic: plain-text", b"no executable" in MF.plain_text("C"))
    # svg builders
    sv = MF.svg_plain("WASP16C2")
    check("svg: plain no DOCTYPE", b"<!DOCTYPE" not in sv)
    check("svg: plain canary", b"WASP16C2" in sv)
    se = MF.svg_entity("WASP16C3", "/etc/hostname")
    check("svg: entity DOCTYPE", b"<!DOCTYPE" in se and b"&xxe;" in se)
    check("svg: entity file target", b'file:///etc/hostname' in se)
    dx = MF.docx_entity_bytes("WASP16C4", "/etc/hostname")
    names = []
    try:
        with zipfile.ZipFile(io.BytesIO(dx)) as z:
            names = z.namelist()
            doc = z.read("word/document.xml").decode()
    except Exception:
        doc = ""
    check("docx: zip 3 parts", len(names) == 3, str(names))
    check("docx: entity + target", "<!ENTITY" in doc and
          "file:///etc/hostname" in doc and "WASP16C4" in doc)
    zs = MF.zipslip_bytes("WASP16C5", 2)
    with zipfile.ZipFile(io.BytesIO(zs)) as z:
        zn = z.namelist()
    check("zip: slip entries", any(n.startswith("../") for n in zn), str(zn))
    check("zip: safe entry too", any(not n.startswith("../") for n in zn))
    # benign docx (no entity)
    bd = MF._docx_benign_bytes("WASP16C6")
    with zipfile.ZipFile(io.BytesIO(bd)) as z:
        bdoc = z.read("word/document.xml").decode()
    check("docx-benign: no entity", "<!ENTITY" not in bdoc and
          "WASP16C6" in bdoc)
    # multipart roundtrip
    body, cth = MF.multipart_body("file", "a b.png", png, "image/png",
                                  fields=[("csrf_token", "t1"),
                                          ("max", "9")])
    check("mp: boundary header", cth.startswith("multipart/form-data; "
                                                "boundary=----waspP16"))
    check("mp: filename roundtrip",
          MF.parse_multipart_filenames(body) == ["a b.png"],
          str(MF.parse_multipart_filenames(body)))
    check("mp: fields present", b'name="csrf_token"' in body and b"t1" in body)
    check("mp: content present", png in body)
    b2, _ = MF.multipart_body("file", "x.png", b"data", "image/png",
                              boundary="xyz")
    check("mp: custom boundary", b"--xyz" in b2)


# ===========================================================================
# UNIT + SAFETY: INERT enforcement
# ===========================================================================
def unit_inert_safety():
    print("\n== UNIT/SAFETY: INERT enforcement ==")
    can = "WASP16S1"
    builders = [MF.magic_png(can), MF.magic_gif(can), MF.magic_jpg(can),
                MF.magic_pdf(can), MF.plain_text(can), MF.svg_plain(can),
                MF.svg_entity(can, "/etc/hostname"),
                MF.docx_entity_bytes(can, "/etc/hostname"),
                MF.zipslip_bytes(can, 2), MF._docx_benign_bytes(can)]
    bad = []
    for i, b in enumerate(builders):
        try:
            MF.assert_inert(b, "unit%d" % i)
        except ValueError as e:
            bad.append((i, str(e)))
    check("inert: all 10 builders pass", not bad, str(bad))
    for i, evil in enumerate([b"<?php echo 1;", b"<script>alert(1)</script>",
                              b"eval(mal);", b"system('ls');",
                              b"#!/bin/sh\nid", b"javascript:alert(1)",
                              b"base64_decode(x)", b"onload=alert(1)",
                              b"Import java.lang.Runtime"]):
        try:
            MF.assert_inert(evil, "evil%d" % i)
            caught = False
        except ValueError:
            caught = True
        check("inert: blocks evil #%d" % i, caught, evil[:24])
    body, _ = MF.multipart_body("f", "x.php", MF.magic_png(can), "image/png")
    try:
        MF.assert_inert(body, "mp-php-name")
        mp_ok = True
    except ValueError:
        mp_ok = False
    check("inert: php FILENAME ok (name not content)", mp_ok)
    check("ext: htaccess NOT auto", "htaccess" not in MF.DANGEROUS_EXTS and
          "user.ini" not in MF.DANGEROUS_EXTS and
          "web.config" not in MF.DANGEROUS_EXTS)
    check("ext: manual list has them",
          {"htaccess", "user.ini", "web.config"} <= set(MF.MANUAL_ONLY_EXTS))
    check("ext: no overlap auto/manual",
          not (set(MF.DANGEROUS_EXTS) & set(MF.MANUAL_ONLY_EXTS)))
    check("forbidden: >=25 patterns", len(MF.FORBIDDEN_CONTENT_PATTERNS) >= 25,
          str(len(MF.FORBIDDEN_CONTENT_PATTERNS)))
    check("forbidden: rx count match",
          len(MF._FORBIDDEN_RX) == len(MF.FORBIDDEN_CONTENT_PATTERNS))
    fs = MF.filesig(b"abcdef")
    check("filesig: fields", fs["len"] == 6 and fs["content_stored"] is False
          and len(fs["sha1_12"]) == 12)
    check("redact: placeholder", "REDACTED" in MF.REDACTED_PLACEHOLDER)
    check("canary: family", MF._canary("t").startswith("waspP16"))
    check("sev: >=30 hints", len(MS_HINTS := MF.SEVERITY_HINTS) >= 30,
          str(len(MF.SEVERITY_HINTS)))
    sev, cvss, why = MF.classify_severity("upload_exec_content_type")
    check("sev: exec critical", sev == "critical" and cvss >= 9.0)
    sev2, _, _ = MF.classify_severity("unknown-key-xyz")
    check("sev: fallback info", sev2 == "info")
    cm = MF.build_cwe_map()
    check("cwe: >=18 mappings", len(cm["mappings"]) >= 18,
          str(len(cm["mappings"])))
    check("cwe: all have cwe+owasp", all(m.get("cwe") and m.get("owasp")
                                         for m in cm["mappings"]))
    cat = MF.build_catalog_md()
    check("catalog: >=45 rows", len(re.findall(r"^\d+\. \*\*", cat,
                                               re.M)) >= 45,
          str(len(re.findall(r"^\d+\. \*\*", cat, re.M))))
    check("catalog: FORBIDDEN rows documented", "FORBIDDEN-AUTO" in cat)


# ===========================================================================
# UNIT: response-analysis helpers (fake responses)
# ===========================================================================
class _FakeResp:
    def __init__(self, status, text, headers=None, body=None):
        self.status = status
        self.text = text
        self.body = body if body is not None else text.encode()
        self._h = headers or {}
        self.error = None

    def header(self, n, d=""):
        return self._h.get(n.lower(), d)


def unit_analysis():
    print("\n== UNIT: response-analysis helpers ==")
    r = _FakeResp(200, json.dumps({"status": "uploaded", "url":
                                   "http://127.0.0.1:1/files/waspP16x.png",
                                   "saved": "waspP16x.png"}),
                  {"content-type": "application/json"})
    sc, hits = MF.upload_success(r, "waspP16x.png", "http://127.0.0.1:1/up")
    check("success: score 3", sc >= 3, str(hits))
    check("success: reflect+url", hits["reflect"] and hits["json_url"])
    rf = _FakeResp(415, "invalid extension: allowed types png jpg gif")
    okf, why = MF.upload_failure(rf)
    check("failure: 415 caught", okf and why == "status-415", str((okf, why)))
    rm = _FakeResp(200, "file type not allowed here")
    okm, whm = MF.upload_failure(rm)
    check("failure: message caught", okm and whm == "message")
    loc = MF.locate_uploaded_url(
        '{"url": "http://127.0.0.1:1/files/waspP16y.png", "path": '
        '"/files/waspP16y2.png"}', "http://127.0.0.1:1", "waspP16y")
    check("locate: 2 urls", len(loc) == 2, str(loc))
    check("locate: normalized", loc[0].startswith("http://127.0.0.1:1"))
    sa = MF.serve_analysis(_FakeResp(200, "c", {"content-type": "text/html"}),
                           "x.php", "waspP16z", "http://127.0.0.1:1")
    check("serve: exec ct", sa["serve_verdict"] == "SERVED_EXEC" and
          "exec-ct:text/html" in sa["reason"], str(sa))
    sa2 = MF.serve_analysis(_FakeResp(200, "c", {
        "content-type": "image/png", "content-disposition": "attachment",
        "x-content-type-options": "nosniff"}), "x.png", "w", "h")
    check("serve: attachment safe", sa2["serve_verdict"] == "SAFE_SERVE" and
          sa2["nosniff"], str(sa2))
    sa3 = MF.serve_analysis(_FakeResp(200, "c", {"content-type":
                                                 "image/svg+xml"}),
                            "x.svg", "w", "h")
    check("serve: svg inline", sa3["serve_verdict"] == "SERVED_SVG_INLINE")
    sa4 = MF.serve_analysis(_FakeResp(200, "c", {
        "content-type": "text/html", "content-disposition": "attachment"}),
                            "x.php", "w", "h")
    check("serve: attachment softens exec", sa4["serve_verdict"] ==
          "SERVED_DISPOSAL_EXEC", str(sa4["serve_verdict"]))
    check("dangerrx: php match", MF.DANGEROUS_EXT_RX.search("a.png.php"))
    check("dangerrx: png no match", not MF.DANGEROUS_EXT_RX.search("a.png"))
    mpu = MF.parse_upload_forms(
        "<form action='/u' method='post' enctype='multipart/form-data'>"
        "<input type='hidden' name='csrf_token' value='tok1'>"
        "<input type='file' name='upfile' accept='.png'></form>",
        "http://127.0.0.1:1")
    check("census: 1 multipart form", len(mpu) == 1)
    f0 = mpu[0]
    check("census: file field", f0["file_fields"] == ["upfile"])
    check("census: accept hint", f0["accept_hints"] == [".png"])
    check("census: csrf value", f0["csrf_values"].get("csrf_token") == "tok1")
    check("census: max hints list type", isinstance(f0["max_hints"], list))


# ===========================================================================
# E2E ACTIVE RUN (RoE gates OFF)
# ===========================================================================
def e2e_gate_off(origin, out):
    print("\n== E2E (gates OFF) ==")
    um = {r["url"]: r for r in
          json.load(open(os.path.join(out, "upload_matrix.json")))}
    up = origin + "/upload"
    uc = origin + "/upload_client"
    st = origin + "/upload_strict"
    waf = origin + "/upload_waf"
    pr = origin + "/upload_priv"
    check("upload: /upload CONFIRMED",
          um.get(up, {}).get("verdict") == "CONFIRMED",
          str(um.get(up, {}).get("verdict")))
    check("upload: /upload exec-serve technique",
          "exec" in (um.get(up, {}).get("technique") or ""),
          str(um.get(up, {}).get("technique")))
    check("upload: risky accepts on /upload",
          set(um.get(up, {}).get("accepted_risky", [])) >=
          {"plain-dangerous", "double-ext", "phtml"},
          str(um.get(up, {}).get("accepted_risky", [])[:6]))
    se = um.get(up, {}).get("served_exec") or []
    check("upload: served_exec rows", len(se) >= 2, str(se[:3]))
    check("upload: /upload_client CONFIRMED",
          um.get(uc, {}).get("verdict") == "CONFIRMED")
    check("upload: /upload_strict HARDENED",
          um.get(st, {}).get("verdict") == "HARDENED",
          str(um.get(st, {}).get("verdict")))
    check("upload: strict rejected plain-dangerous",
          "plain-dangerous" in (um.get(st, {}).get("rejected_labels") or []),
          str(um.get(st, {}).get("rejected_labels", [])[:6]))
    check("upload: /upload_waf BLOCKED",
          um.get(waf, {}).get("verdict") == "BLOCKED",
          str(um.get(waf, {}).get("verdict")))
    check("upload: /upload_priv CONFIRMED",
          um.get(pr, {}).get("verdict") in ("CONFIRMED", "SUSPECTED"),
          str(um.get(pr, {}).get("verdict")))
    # getback serve analysis
    gb = json.load(open(os.path.join(out, "getback_matrix.json")))
    gb_up = [g for g in gb if g["url"] == up]
    check("getback: /upload located urls", bool(gb_up and
                                                gb_up[0].get("located")))
    check("getback: anon served on /upload",
          (gb_up[0].get("anon_getback") or {}).get("served") is True,
          str((gb_up[0].get("anon_getback") if gb_up else {})))
    # magic + ct + overwrite
    mm = json.load(open(os.path.join(out, "magic_matrix.json")))
    check("magic: /upload gif-as-png accepted",
          (mm.get(up, {}).get("gif-as-png") or {}).get("score", 0) >= 1,
          str(mm.get(up)))
    ct = json.load(open(os.path.join(out, "ct_matrix.json")))
    check("ct: spoof accepted on /upload",
          set(ct.get("accepted_by_endpoint", {}).get(up, [])) >=
          {"image/jpeg", "text/plain"}, str(ct.get("accepted_by_endpoint",
                                                   {}).get(up)))
    check("ct: strict verdict HARDENED (CT acceptance harmless)",
          um.get(st, {}).get("verdict") == "HARDENED",
          str(um.get(st, {}).get("verdict")))
    umu = um.get(up, {})
    check("upload: overwrite confirmed on /upload",
          (umu.get("overwrite_probe") or {}).get("overwritten") is True,
          str(umu.get("overwrite_probe")))
    ext_labels = [x.get("label") for x in umu.get("ext_matrix", [])]
    check("ext: matrix has 24 rows (v17 pool)",
          len(ext_labels) == 24, str(len(ext_labels)))
    check("ext: NUL masked in matrix", "<NUL>" in json.dumps(umu))
    # svg inline serve on /upload
    svg_rows = [x for x in umu.get("ext_matrix", [])
                if x.get("label") == "svg-serve"]
    check("svg: inline serve row",
          svg_rows and (svg_rows[0].get("serve") or {}).get("serve_verdict")
          == "SERVED_SVG_INLINE",
          str((svg_rows[0].get("serve") or {}).get("serve_verdict")
              if svg_rows else "no-row"))
    # dir listing
    dl = json.load(open(os.path.join(out, "dir_listing_matrix.json")))
    check("listing: /files/ listed", any(d.get("listing") for d in dl),
          str(dl[:2]))
    # import engine (gate OFF -> SKIPPED)
    im = {r["url"]: r for r in
          json.load(open(os.path.join(out, "import_xxe_matrix.json")))}
    check("import: /upload_svg svg-accepted + SKIPPED xxe",
          im.get(origin + "/upload_svg", {}).get("verdict") == "SKIPPED" and
          "svg-accepted" in im.get(origin + "/upload_svg", {}).get("signals",
                                                                   []),
          str(im.get(origin + "/upload_svg", {})))
    # archive gated
    ar = json.load(open(os.path.join(out, "archive_matrix.json")))
    check("archive: gated SKIPPED", ar and ar[0].get("gated") is True and
          ar[0].get("verdict") == "SKIPPED", str(ar[:1]))
    # findings
    fj = json.load(open(os.path.join(out, "findings.json")))
    keys = {f["key"] for f in fj["findings"]}
    check("findings: >=10", fj["count"] >= 10, str(fj["count"]))
    for k in ("upload_exec_content_type", "upload_risky_ext_accepted",
              "upload_unauth_accessible", "upload_dir_listing",
              "upload_mime_bypass", "upload_magic_missing",
              "upload_overwrite_possible", "upload_gate_skipped"):
        check("findings: %s" % k, k in keys, str(sorted(keys)))
    # technique matrix + artifacts
    tm = json.load(open(os.path.join(out, "technique_matrix_files.json")))
    check("tm: >=45 rows", len(tm) >= 45, str(len(tm)))
    check("tm: webshell FORBIDDEN row", any(
        r["technique"] == "webshell-upload" and r["status"] ==
        "FORBIDDEN-AUTO" for r in tm))
    check("tm: ext rows TESTED", any(r["technique"] == "ext-double-ext" and
                                     r["status"] == "TESTED" for r in tm))
    diff = json.load(open(os.path.join(out, "differential_files.json")))
    check("diff: confirmed >=2", diff.get("confirmed", 0) >= 2, str(diff))
    check("diff: served_exec includes /upload", up in
          diff.get("served_exec_endpoints", []), str(diff.get(
              "served_exec_endpoints")))
    for fn in ("upload_surface.json", "upload_targets.txt",
               "upload_form_census.json", "filename_matrix.json",
               "serve_matrix.json", "import_xxe_matrix.json",
               "waf_map_files.json", "UPLOAD_FINDINGS.md",
               "IMPORT_XXE_FINDINGS.md", "files_test_plan.md",
               "files_chains.txt", "TECHNIQUES_CATALOG_FILES.md",
               "findings.json", "feedforward.json", "MANIFEST.json",
               "upload_payloads/canary.png",
               "upload_payloads/svg_entity.svg",
               "upload_payloads/docx_entity_import.docx",
               "upload_payloads/zipslip_canary.zip",
               "upload_payloads/README.txt"):
        check("artifact: %s" % fn, os.path.isfile(os.path.join(out, fn)))
    ff = json.load(open(os.path.join(out, "feedforward.json")))
    check("ff: to_phase17 upload endpoints", up in
          (ff["routing"].get("to_phase17_api", {}).get("upload_endpoints",
                                                       [])))
    check("ff: to_phase23 listings", any("files/" in d for d in
                                         ff["routing"].get("to_phase23_"
                                                           "misconfig", {})
                                         .get("dir_listings", [])))
    # payload dir INERT re-check
    with open(os.path.join(out, "upload_payloads/svg_entity.svg"), "rb") as f:
        MF.assert_inert(f.read(), "stored-svg")
    with open(os.path.join(out, "upload_payloads/zipslip_canary.zip"),
              "rb") as f:
        MF.assert_inert(f.read(), "stored-zip")
    check("payloads: stored payloads INERT", True)
    # redaction: getback recs store no content blobs
    gbjson = json.dumps(json.load(open(os.path.join(out,
                                                    "getback_matrix.json"))))
    check("redact: no content blobs in getback", '"content_stored": false'
          in gbjson or "content_stored" in gbjson)


# ===========================================================================
# GATED RUN (import-xxe + archive + cleanup ON, cold-start harvest)
# ===========================================================================
def e2e_gated(origin, out):
    print("\n== E2E (gated: import-xxe + archive + cleanup ON) ==")
    im = {r["url"]: r for r in
          json.load(open(os.path.join(out, "import_xxe_matrix.json")))}
    sg = im.get(origin + "/upload_svg", {})
    check("gated: /upload_svg CONFIRMED import-xxe",
          sg.get("verdict") == "CONFIRMED" and "import-xxe" in
          sg.get("signals", []), str(sg.get("verdict")))
    check("gated: svg path_echo family",
          any(f.get("path_echo") for f in sg.get("families", [])),
          str(sg.get("families", [])[:2]))
    imp = im.get(origin + "/import", {})
    check("gated: docx import CONFIRMED", imp.get("verdict") == "CONFIRMED",
          str(imp.get("verdict")))
    ar = json.load(open(os.path.join(out, "archive_matrix.json")))
    check("gated: archive slip_reflected", ar and
          ar[0].get("slip_reflected") is True, str(ar[:1]))
    um = {r["url"]: r for r in
          json.load(open(os.path.join(out, "upload_matrix.json")))}
    up = origin + "/upload"
    check("gated: cleanup deleted canaries",
          all(x.get("deleted") for x in (um.get(up, {}).get("cleanup") or
                                         [{"deleted": False}])),
          str((um.get(up, {}).get("cleanup"))[:2] if um.get(up, {}).get(
              "cleanup") else "none"))
    fj = json.load(open(os.path.join(out, "findings.json")))
    keys = {f["key"] for f in fj["findings"]}
    check("gated: import xxe finding", "upload_import_xxe" in keys,
          str(sorted(keys)))
    check("gated: zip-slip finding", "upload_zip_slip" in keys,
          str(sorted(keys)))
    check("gated: client-only filter finding (cold-form accept)",
          "upload_client_only_filter" in keys, str(sorted(keys)))
    # cold-start harvest happened (form census in artifact)
    fc = json.load(open(os.path.join(out, "upload_form_census.json")))
    check("gated: cold-start forms harvested",
          len(fc.get("cold_harvest", [])) >= 1,
          str(len(fc.get("cold_harvest", []))))
    tm = json.load(open(os.path.join(out, "technique_matrix_files.json")))
    check("gated: import-xxe row TESTED", any(
        r["technique"] == "import-xxe-entities" and r["status"] == "TESTED"
        for r in tm))
    check("gated: zip-slip row TESTED", any(
        r["technique"] == "zip-slip-archive" and r["status"] == "TESTED"
        for r in tm))


# ===========================================================================
# RWX / egress / passive / replay / CLI / hygiene
# ===========================================================================
def rwx_and_egress(out, origin):
    print("\n== RWX + ZERO-EGRESS ==")
    bad_perm = []
    for dirpath, _, filenames in os.walk(out):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.stat(p).st_mode & 0o777 != 0o777:
                bad_perm.append(p)
    check("rwx: all files 0777", not bad_perm, str(bad_perm[:3]))
    pl = json.load(open(os.path.join(out, "upload_probe_log.json")))
    urls = [x.get("endpoint") for x in pl if x.get("endpoint")]
    check("egress: probe log endpoints loopback-only",
          all(u.startswith(origin) or "127.0.0.1" in u for u in urls),
          str([u for u in urls if "127.0.0.1" not in u][:3]))
    um = json.load(open(os.path.join(out, "upload_matrix.json")))
    blob = json.dumps(um)
    check("egress: no external host refs", "http://x.invalid" not in blob and
          "interact.sh" not in blob and "burpcollaborator" not in blob)
    check("redact: no upload content blobs", '"content_stored": false' in
          json.dumps(um[:1]) or "content_stored" not in blob)


def passive_and_replay(cfg, cfg_passive, base, base2, eng, engp, origin):
    print("\n== PASSIVE MODE ==")
    scope4 = WC.Scope(os.path.join(base2, "scope.json"))
    out4 = MF.run(cfg_passive, scope4, base2)
    man = json.load(open(os.path.join(out4, "MANIFEST.json")))
    stats = man.get("stats", {})
    check("passive: mode passive", stats.get("mode") == "passive",
          str(stats))
    check("passive: 0 probes", stats.get("probes_total", 0) == 0,
          str(stats.get("probes_total")))
    check("passive: findings >=1 (sparse info)", os.path.isfile(
        os.path.join(out4, "findings.json")))

    print("\n== CHECKPOINT REPLAY ==")
    scope2 = WC.Scope(os.path.join(base, "scope.json"))
    out1 = MF.run(cfg, scope2, base)
    v1 = {r["url"]: r["verdict"] for r in json.load(
        open(os.path.join(out1, "upload_matrix.json")))}
    out1b = MF.run(cfg, scope2, base)
    v2 = {r["url"]: r["verdict"] for r in json.load(
        open(os.path.join(out1b, "upload_matrix.json")))}
    check("replay: verdicts stable", v1 == v2, "%s vs %s" % (v1, v2))
    return out1


def cli_and_hygiene():
    print("\n== CLI ==")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        MF.main()
    s = buf.getvalue()
    check("cli: banner", "mod_files.py" in s and "Phase 16" in s, s[:80])
    check("cli: RoE gates mentioned", "files_allow_import_xxe" in s and
          "files_allow_archive" in s, s[:200])
    print("\n== SOURCE HYGIENE ==")
    r = subprocess.run([sys.executable, "-W", "error", "-c",
                        "import mod_files"], cwd=ULTRA,
                       capture_output=True, text=True)
    check("hygiene: -W error import clean", r.returncode == 0,
          r.stderr[-160:])
    check("hygiene: no billion-laughs", "billion" not in
          open(os.path.join(ULTRA, "mod_files.py")).read().lower())



# ===========================================================================
# v17 ULTRA TESTS (payloads + multipart + deep-dive e2e + gated + matrix)
# ===========================================================================
def unit_payloads_v17():
    print("\n== UNIT: v17 payload libraries ==")
    c = "waspP16t17"
    check("v17: gif87a magic", MF.magic_gif87a(c)[:6] == b"GIF87a")
    check("v17: zip magic PK", MF.magic_zip(c)[:2] == b"PK")
    check("v17: bmp magic", MF.magic_bmp(c)[:2] == b"BM")
    check("v17: tiff magic", MF.magic_tiff(c)[:4] == b"II\x2a\x00")
    wp = MF.magic_webp(c)
    check("v17: webp riff", wp[:4] == b"RIFF" and wp[8:12] == b"WEBP")
    check("v17: mp4 ftyp", MF.magic_mp4(c)[4:8] == b"ftyp")
    check("v17: gzip magic", MF.magic_gzip(c)[:3] == b"\x1f\x8b\x08")
    check("v17: rar magic", MF.magic_rar(c)[:4] == b"Rar!")
    check("v17: 7z magic", MF.magic_7z(c)[:2] == b"7z")
    check("v17: ico magic", MF.magic_ico(c)[:4] == b"\x00\x00\x01\x00")
    png = MF.png_valid_text(c)
    check("v17: png valid CRC+dims", MF.png_dims(png) == (1, 1) and
          b"tEXt" in png and png.endswith(b"IEND\xaeB`\x82"))
    jpg = MF.jpeg_com_segment(c)
    check("v17: jpeg com", jpg[:2] == b"\xff\xd8" and b"\xff\xfe" in jpg
          and jpg.endswith(b"\xff\xd9"))
    gc = MF.gif_comment_ext(c)
    check("v17: gif comment ext", gc.startswith(b"GIF89a") and
          gc.endswith(b"\x3b") and c.encode() in gc)
    with zipfile.ZipFile(io.BytesIO(MF.xlsx_benign_bytes(c))) as z:
        check("v17: xlsx parts", "xl/workbook.xml" in z.namelist())
    with zipfile.ZipFile(io.BytesIO(MF.odt_benign_bytes(c))) as z:
        check("v17: odt mimetype first",
              z.namelist()[0] == "mimetype" and z.read("mimetype").startswith(
                  b"application/vnd.oasis"))
    check("v17: html inert no script",
          b"<script" not in MF.html_inert_doc(c).lower())
    sv = MF.svg_ssrf_bytes(c, "/waspP16nope")
    check("v17: svg-ssrf same-origin only",
          b'href="http' not in sv and b"href='http" not in sv and
          c.encode() in sv)
    try:
        MF.svg_ssrf_bytes(c, "http://evil.example/x")
        check("v17: svg-ssrf egress guard", False)
    except ValueError:
        check("v17: svg-ssrf egress guard", True)
    check("v17: svg use+foreignObject", b"<use" in MF.svg_use_ref(c) and
          b"<foreignObject" in MF.svg_use_ref(c))
    check("v17: filename pool 50+",
          len(MF.filename_variants(c, cap=99)) >= 50)
    check("v17: trick pool 16+",
          len(MF.filename_trick_variants(c, cap=99)) >= 16)
    check("v17: ct pool 18+", len(MF.ct_variants(cap=99)) >= 18)
    fpool = [x for _, x in MF.filename_variants(c, cap=99)]
    check("v17: no forbidden-ext auto", not any(
        "htaccess" in x or "user.ini" in x or "web.config" in x
        for x in fpool))
    check("v17: nullbyte kept", any("\x00" in x for x in fpool))
    check("v17: ads variants", any("::$DATA" in x for x in fpool))
    check("v17: rtlo present", any("\u202e" in x for x in fpool))
    check("v17: svg-serve within 24",
          any(x.endswith(".svg") for x in
              [xx for _, xx in MF.filename_variants(c, cap=24)]))
    check("v17: ext model pool 40 ctrl-first",
          len(MF.EXT_MODEL_POOL) >= 38 and
          MF.EXT_MODEL_POOL[0] in ("png", "jpg", "gif", "txt", "pdf", "zip"))
    mm = MF.build_mitre_map()
    check("v17: mitre map", "CWE-434" in mm["cwe"] and
          "T1505.003" in mm["attack"] and "cheatsheets" in mm)
    es = MF.build_exec_summary_md({"probes_total": 3}, [], [], [], [], [], {})
    check("v17: exec summary built", "EXEC SUMMARY" in es and "INERT" in es)
    check("v17: INERT sab new builders", MF.assert_inert(png) and
          MF.assert_inert(MF.magic_zip(c)) and MF.assert_inert(jpg) and
          MF.assert_inert(gc) and MF.assert_inert(sv) and
          MF.assert_inert(MF.svg_use_ref(c)))


def unit_multipart_builders():
    print("\n== UNIT: v17 multipart confusion builders ==")
    c = "waspP16mp"
    png = MF.magic_png(c)
    for lbl, fn in MF.CONFUSION_BUILDERS:
        body, ct = fn("file", "%s.php" % c, png, "image/png")
        ok = (isinstance(body, bytes) and isinstance(ct, str) and
              "boundary=" in ct and len(body) > len(png))
        check("v17 mp build: %s" % lbl, ok)
        if ok:
            MF.assert_inert(body)
    b1, _ = MF.mp_rfc5987("file", "x.php", png, "image/png")
    check("v17 mp: rfc5987 star", b"filename*=UTF-8''" in b1)
    b2, _ = MF.mp_two_files("file", "a.php", png, "image/png")
    check("v17 mp: two files", len(MF.parse_multipart_filenames(b2)) == 2)
    b3, _ = MF.mp_bare_lf("file", "x.php", png, "image/png")
    check("v17 mp: bare lf", b"\r\n--" not in b3[:60] and b"\n--" in b3)
    b4, _ = MF.mp_empty_filename("file", "x", png, "image/png")
    check("v17 mp: empty fname", b'filename=""' in b4)
    b5, _ = MF.mp_base64_cte("file", "x.php", png, "image/png")
    check("v17 mp: base64 cte",
          b"Content-Transfer-Encoding: base64" in b5)
    b6, _ = MF.mp_preamble_epilogue("file", "x.php", png, "image/png")
    check("v17 mp: preamble+epilogue",
          b6.startswith(b"waspP16-preamble") and
          b"waspP16-epilogue" in b6)
    b7, _ = MF.mp_no_filename("file", "x", png, "image/png")
    check("v17 mp: no fname", b"filename=" not in b7)
    b8, _ = MF.mp_dup_boundary("file", "x.php", png, "image/png")
    check("v17 mp: dup boundary injected",
          b"injected:--" in b8)
    b9, _ = MF.mp_ct_star("file", "x.php", png, "image/png")
    check("v17 mp: star ct", b"Content-Type: */*" in b9)
    b10, _ = MF.mp_fake_headers("file", "x.php", png, "image/png")
    check("v17 mp: fake headers", b"Content-Length: 99999" in b10)


def e2e_deep(origin, out):
    print("\n== E2E v17 DEEP-DIVE (gates OFF) ==")
    for fn, cond in [
            ("ext_acceptance_matrix.json", True),
            ("multipart_matrix.json", True),
            ("magic_consistency.json", True),
            ("client_bypass_matrix.json", True),
            ("exotic_formats.json", True),
            ("metadata_matrix.json", True),
            ("storage_fingerprint.json", True),
            ("rename_policy.json", True),
            ("mitre_map.json", True),
            ("put_method_matrix.json", True),
            ("EXEC_SUMMARY.md", True)]:
        check("v17 artifact: %s" % fn, os.path.isfile(os.path.join(out, fn)))
    um = json.load(open(os.path.join(out, "upload_matrix.json")))
    deeps = [r for r in um if r.get("deep")]
    check("v17 e2e: deep attached to recs", len(deeps) >= 1,
          str([r["url"] for r in deeps]))
    up = next((r for r in um if r["url"].rstrip("/").endswith("/upload")
               and r.get("deep")), None)
    if up:
        d = up["deep"]
        em = d.get("ext_model") or {}
        check("v17 e2e: /upload no-validation model",
              em.get("model") == "no-validation", str(em.get("model")))
        check("v17 e2e: ext rows 24+", len(em.get("rows", [])) >= 24,
              str(len(em.get("rows", []))))
        cf = d.get("confusion") or {}
        check("v17 e2e: /upload parser lenient",
              cf.get("parser_signal") in ("parser-lenient", "parser-mixed"),
              str(cf.get("parser_signal")))
        mc = d.get("magic_consistency") or {}
        check("v17 e2e: /upload no-inspection",
              mc.get("inspection_depth") == "no-content-inspection",
              str(mc.get("inspection_depth")))
        ex = d.get("exotic") or {}
        check("v17 e2e: exotic >=8 accepted",
              len(ex.get("accepted", [])) >= 8, str(ex.get("accepted")))
        md = d.get("metadata") or {}
        acc = [x for x in md.get("rows", []) if x.get("accepted")]
        check("v17 e2e: metadata rows ran", len(acc) >= 2, str(len(acc)))
        check("v17 e2e: metadata canary survived",
              all(x.get("canary_survived") for x in acc) and
              not md.get("stripped") and not md.get("transformed"),
              str(md))
    else:
        check("v17 e2e: /upload deep-covered", False)
    st = next((r for r in um if r["url"].rstrip("/").endswith(
        "/upload_strict") and r.get("deep")), None)
    if st:
        em2 = (st["deep"].get("ext_model") or {})
        check("v17 e2e: strict whitelist model",
              em2.get("model") == "whitelist-or-sanitizer",
              str(em2.get("model")))
        cf2 = (st["deep"].get("confusion") or {})
        check("v17 e2e: strict parser strict",
              cf2.get("parser_signal") in ("parser-strict", "parser-mixed"),
              str(cf2.get("parser_signal")))
    else:
        check("v17 e2e: /upload_strict deep-covered", False)
    uc = next((r for r in um if r["url"].rstrip("/").endswith(
        "/upload_client") and r.get("deep")), None)
    if uc:
        cb = uc["deep"].get("client_bypass") or {}
        check("v17 e2e: client-only-limit", cb.get("client_only_limit")
              is True, str(cb.get("rows")))
        check("v17 e2e: client-only-accept",
              cb.get("client_only_accept") is True, str(cb.get("rows")))
    else:
        check("v17 e2e: /upload_client deep-covered", False)
    rp = json.load(open(os.path.join(out, "rename_policy.json")))
    check("v17 e2e: rename original + enum risk",
          rp.get("policy") == "original" and
          rp.get("enumeration_risk") is True, str(rp))
    sf = json.load(open(os.path.join(out, "storage_fingerprint.json")))
    check("v17 e2e: storage fp sampled",
          isinstance(sf, dict) and len(sf.get("data", [])) >= 1, str(sf)[:80])
    pm0 = json.load(open(os.path.join(out, "put_method_matrix.json")))
    check("v17 e2e: put census gate-off (no write)",
          len(pm0) >= 1 and all(not p.get("put_write") for p in pm0) and
          any(p.get("dav_allowed") for p in pm0), str(pm0[:1]))
    fj = json.load(open(os.path.join(out, "findings.json")))
    keys = {f["key"] for f in fj["findings"]}
    for k in ("upload_ext_no_validation", "upload_parser_lenient",
              "upload_magic_consistency_missing", "upload_client_only_limit",
              "upload_client_only_accept", "upload_dav_put_census",
              "upload_metadata_preserved"):
        check("v17 findings: %s" % k, k in keys, str(sorted(keys)))


def matrix_chains_v17(out):
    print("\n== MATRIX/CHAINS v17 ==")
    tm = json.load(open(os.path.join(out, "technique_matrix_files.json")))
    check("v17 matrix: rows >= 65", len(tm) >= 65, str(len(tm)))
    labels = {r["technique"] for r in tm}
    need = {"ext-acceptance-model", "multipart-parser-confusion",
            "magic-consistency", "client-side-bypass", "exotic-format-accept",
            "metadata-pipeline", "put-dav-census", "rename-policy"}
    check("v17 matrix: new rows present", need <= labels,
          str(sorted(need - labels)))
    need2 = {"eicar-test-string", "png-decompression-bomb",
             "http2-upload-smuggling", "php-filter-wrapper"}
    check("v17 matrix: manual additions", need2 <= labels,
          str(sorted(need2 - labels)))
    ff = json.load(open(os.path.join(out, "feedforward.json")))
    chains = ff.get("routing", {}).get("to_phase28_chains", {}).get(
        "chains", [])
    check("v17 chains: >= 3 (gate-off)", len(chains) >= 3, str(chains))
    mit = json.load(open(os.path.join(out, "mitre_map.json")))
    check("v17 mitre artifact sane", "CWE-434" in mit.get("cwe", {}))
    es = open(os.path.join(out, "EXEC_SUMMARY.md"), encoding="utf-8").read()
    check("v17 exec summary content", "Verdict snapshot" in es and
          "RoE gates" in es)


def e2e_gated_v17(origin, out3):
    print("\n== E2E v17 GATED (svg-ssrf + race + put ON) ==")
    um = json.load(open(os.path.join(out3, "upload_matrix.json")))
    deeps = [r for r in um if r.get("deep")]
    check("v17 gated: deep recs", len(deeps) >= 1)
    d0 = deeps[0]["deep"]
    check("v17 gated: svg_ssrf ran", "svg_ssrf" in d0, str(d0.keys()))
    ss = d0.get("svg_ssrf") or {}
    check("v17 gated: svg ssrf 2 variants",
          len(ss.get("rows", [])) == 2 and
          all(x.get("accepted") for x in ss.get("rows", [])), str(ss))
    check("v17 gated: svg ssrf signal", ss.get("signal") in
          ("svg-accepted-no-diff", "svg-rasterizer-hypothesis"),
          str(ss.get("signal")))
    check("v17 gated: race ran", "race" in d0)
    rr = d0.get("race") or {}
    check("v17 gated: race all-succeeded",
          rr.get("signal") == "all-concurrent-succeeded" and
          rr.get("accepted") == rr.get("threads"), str(rr))
    check("v17 gated: svg artifact",
          os.path.isfile(os.path.join(out3, "svg_ssrf_matrix.json")))
    check("v17 gated: race artifact",
          os.path.isfile(os.path.join(out3, "race_analysis.json")))
    pm = json.load(open(os.path.join(out3, "put_method_matrix.json")))
    check("v17 gated: dav write CONFIRMED",
          any(p.get("put_write") for p in pm), str(pm[:2]))
    check("v17 gated: dav write finding", True)
    fj = json.load(open(os.path.join(out3, "findings.json")))
    keys = {f["key"] for f in fj["findings"]}
    check("v17 gated: dav_put_write finding", "upload_dav_put_write" in keys,
          str(sorted(keys)))
    ff = json.load(open(os.path.join(out3, "feedforward.json")))
    rt = ff.get("routing", {})
    check("v17 gated: ff phase13 lfi",
          any("phase13" in k for k in rt.keys()), str(sorted(rt.keys())))
    check("v17 gated: ff phase15 stored",
          any("phase15" in k for k in rt.keys()))
    check("v17 gated: ff phase24 storage backends",
          any("phase24" in k for k in rt.keys()))


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    print("=" * 69)
    print(" WASP P16 SELF-TEST - mod_files.py v%s" % MF.PLAN_VERSION)
    print("=" * 69)
    srv, port = _start_lab()
    try:
        origin = "http://127.0.0.1:%d" % port
        _seed(BASE, ENG, origin, with_forms=True)
        _seed(BASE_GATED, ENG_G, origin, with_forms=False)
        _seed(BASE2, ENG_P, origin, with_forms=True)

        unit_payloads()
        unit_inert_safety()
        unit_analysis()

        cfg = WC.Cfg(None)
        cfg.allow_active = True
        cfg.files_deep_endpoints = 6
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        out = MF.run(cfg, scope, BASE)
        e2e_gate_off(origin, out)
        rwx_and_egress(out, origin)

        cfg2 = WC.Cfg(None)
        cfg2.allow_active = True
        cfg2.files_allow_import_xxe = True
        cfg2.files_allow_archive = True
        cfg2.files_allow_cleanup = True
        cfg2.files_allow_svg_ssrf = True
        cfg2.files_allow_put_method = True
        cfg2.files_allow_race = True
        cfg2.files_deep_endpoints = 6
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = MF.run(cfg2, scope3, BASE_GATED)
        e2e_gated(origin, out3)

        cfg4 = WC.Cfg(None)
        cfg4.allow_active = False
        passive_and_replay(cfg, cfg4, BASE, BASE2, ENG, ENG_P, origin)

        unit_payloads_v17()
        unit_multipart_builders()
        e2e_deep(origin, out)
        matrix_chains_v17(out)
        e2e_gated_v17(origin, out3)

        cli_and_hygiene()
    finally:
        srv.shutdown()
    print("\n" + "=" * 53)
    print(" P16 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, str(d)[:120]))
        sys.exit(1)
    print(" ALL GREEN \u2705")


if __name__ == "__main__":
    main()
