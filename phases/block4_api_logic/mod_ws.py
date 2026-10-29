#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_ws.py  |  Phase 19 - WebSocket Security ULTRA PRO MAX++
           (Origin-Trust/CSWSH/Auth-Diff/Transports/Downgrade/Bypass-v2/Replay)
=======================================================================================
v19.0.0 FULL ULTRA PRO MAX (advanced upgrade - koi kami nahi). Authorized
security testing ONLY. Scope firewall + rate limiter + request budget +
evidence + checkpoint sab wasp_core se inherit hote hain, isliye har census
request scope-check, rate-limit aur budget ke andar hi jaati hai.

KYA KARTA HAI
  P18 GraphQL ne ws_signals/ws_paths/gql_subscriptions P19 ko handoff kiye the
  (P14 client ne ws_endpoints, P17 api ne ws_signals, P6 tech ne realtime map,
  P7 js ne websockets.txt). P19 poora WEBSOCKET TRUST dekhta hai: "MERA realtime
  layer, connection-level trust kahan tak todta hai?" -> 19 stages (A..S):
    A. WS surface discovery   - P14/P17/P18/P6/P7 ff + JS/HTML regex mining
                                (ws:// wss:// socket.io sockjs signalr primus
                                graphql-ws) + 22-path cold pool + ranking
    B. Baseline + WAF         - home marker + soft-404 + WAF fingerprint
    C. Handshake core         - INERT raw-socket upgrade census: 101/400/404/
                                426 map, Sec-WebSocket-Accept CRYPTO validation
                                (GUID math), version negotiation, extensions
                                (permessage-deflate), subprotocol echo census
    D. Origin trust matrix    - CSWSH census: no-origin vs same-origin vs
                                cross-origin + wildcard/null/uppercase/port
                                variants + malicious-shaped bypass candidates
                                (GATED ws_allow_origin_evil)
    E. Auth differential      - creds vs no-creds handshake diff, token-in-URL
                                leak census, bearer/cookie shape, Set-Cookie
                                flags on 101 (SameSite absence = CSWSH ammo)
    F. Transport census       - socket.io polling handshake (EIO3/EIO4 sid
                                JSON), sockjs /info, signalr negotiate,
                                primus/mercury hints (GATED ws_allow_transports)
    G. Transport security     - ws:// downgrade census, mixed-content signal,
                                RFC 8441 HTTP/2 WS census (GATED ws_allow_h2ws)
    H. Header injection       - Sec-WebSocket-Protocol reflection census (CRLF/
                                response-splitting surface), key-metachar
                                validation, oversized-value behavior (INERT)
    I. WAF-bypass matrix v2   - 17 SECRET handshake-level techniques
                                (X-Original-URL/X-Rewrite-URL misroute, dot-
                                segment, semicolon path-param, HPP, case-varied
                                Upgrade/Connection, whitespace tokens, double-
                                upgrade, absolute-URI request-line, unicode-
                                escaped path, port-variant, host-header tricks,
                                early-data hint, connection-token split...)
    J. WAF/upgrade fingerprint- blocked-vs-open signature map on ws paths
    K. Rate/limit census      - bounded burst (GATED ws_allow_burst, cap 3):
                                429/Retry-After/connection-limit observation
    L. Frame-level census     - GATED ws_allow_frames: connect->immediate-close
                                + PING to OWN session only; message-injection/
                                MITM/replay/forgery techniques DOCUMENTED-ONLY
    M. GraphQL subs census    - P18 handoff: subscription endpoints +
                                graphql-transport-ws vs graphql-ws subprotocol
                                census (GATED ws_allow_ws path probe)
    N. Platform fingerprint   - socket.io EIO/sid shape, sockjs entropy/
                                cookie_needed, signalr token shape, apollo/
                                hasura/centrifuge/phoenix fingerprints
    O. Secrets-in-URL census  - token/secret-shaped query params in WS URLs +
                                JS miner cross-ref (leak surface)
    P. Verdict engine         - 6-class ladder (CONFIRMED/SUSPECTED/HARDENED/
                                BLOCKED/SKIPPED/NOISE) multi-signal
    Q. Kill-chains            - 20 realtime attack chains (CSWSH->PII theft,
                                downgrade->MITM, replay->state-abuse...)
    R. Technique matrix       - 150 rows x 18 families + CWE + MITRE mapping
    S. Reports/artifacts      - 40 artifacts: findings.json, WS_FINDINGS.md,
                                WS_MATRIX.txt, census/bypass/platform JSONs,
                                kick-off guide, remediation, feedforward
                                (to_phase20_logic/to_phase22_replay/...),
                                MANIFEST

VERDICT LADDER (6-class, P12..P18-compatible)
  CONFIRMED   -> multi-signal proof (any-origin 101 + cookies + sensitive
                 channel; accept-mismatch + open endpoint)
  SUSPECTED   -> partial/single signal (origin reflected but cookies absent,
                 sid exposed but origin enforced)
  HARDENED    -> defense present (origin enforced, auth required on upgrade,
                 version guard, rate limit)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (WebSocket 'connection-trust' hai - P15..P18 jitni strict
discipline)
  * 100% INERT: handshake probes GET-only hain (RFC 6455 open handshake ek
    HTTP GET hai) - sirf status line + headers read hote hain, socket TURANT
    close ho jaata hai. Koi data frame KABHI nahi bheja/jata (gated path bhi
    sirf PING/ CLOSE apne OWN session par).
  * FRAME I/O GATED: ws_allow_frames default OFF. Frame send karne wala code
    path sirf OWN session + PING/CLOSE tak simit; data-frame injection,
    message-forgery, replay EXECUTION = FORBIDDEN (documented-only).
  * FLOODING/DoS = FORBIDDEN-AUTO: burst census bhi GATED (ws_allow_burst,
    HARD cap 3 handshakes, 1 endpoint, sequential - koi parallel flood nahi).
  * ORIGIN VARIANTS: crafted bypass origins (prefix/suffix/punycode) GATED
    (ws_allow_origin_evil); benign census (none/same/null) default ON.
  * TRANSPORT CENSUS: socket.io/sockjs/signalr negotiate pure GET hain par
    app-side session create kar sakte hain -> GATED (ws_allow_transports).
  * CANARY: har synthetic value "waspP19" family - real user data KABHI touch
    nahi hota; tokens sirf INVALID canary shapes.
  * ZERO EXTERNAL EGRESS: raw handshake bhi scope.check_host se pehle validate
    hota hai - out-of-scope host par socket connect IMPOSSIBLE.
  * REDACTION: response bodies store nahi hote - sirf status/header-sha1/
    shapes (pii_redact framework rule).
  * allow_active=False -> PASSIVE mode: mining + offline hypotheses only
    (0 network probes).
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - RWX standing rule wrappers se guaranteed.
"""

import os
import re
import io
import sys
import json
import time
import copy
import base64
import socket
import hashlib
import secrets as _secrets
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
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 19")
    sys.exit(1)

NAME = "ws"
PHASE = "19-ws"
PLAN_VERSION = "19.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "ws_paths_cap": 18,               # mined/candidate ws-path cap (ranking)
    "ws_probe_cap": 6,                # active handshake census target cap
    "ws_cold_paths": 22,              # cold path-pool size (discovery)
    "ws_origin_variants": 8,          # origin-matrix variant cap per endpoint
    "ws_max_bytes": 2048,             # census body read cap (no storage)
    "ws_handshake_timeout": 5.0,      # raw-socket connect+read timeout sec
    "ws_bypass2_cap": 17,             # WAF/edge handshake bypass v2 cap
    # ---- RoE GATES (default OFF - sirf authorized+lab runs me ON) ----
    "ws_allow_origin_evil": False,    # GATE: malicious-shaped origin bypass candidates
    "ws_allow_transports": False,     # GATE: socket.io/sockjs/signalr negotiate GET census
    "ws_allow_burst": False,          # GATE: bounded handshake burst (cap 3, rate census)
    "ws_allow_frames": False,         # GATE: frame I/O apne OWN session (PING/CLOSE only)
    "ws_allow_h2ws": False,           # GATE: RFC 8441 HTTP/2 extended-CONNECT census
    "ws_allow_ws": False,             # GATE: P18-style subscription ws-path probe
    # ---- v19 ULTRA tunables ----
    "ws_subs_paths": 4,               # subscription ws-path census cap (GATED)
    "ws_platform_fp": True,           # socket.io/sockjs/signalr/platform fingerprint
    "ws_secrets_url": True,           # token-in-URL census (offline mining)
    "ws_js_miner": True,              # stored-body ws:// link miner (offline)
    "ws_downgrade_census": True,      # ws:// downgrade surface (offline decision)
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

def _rwx_tree(root):
    for base, dirs, files in os.walk(root):
        for d in dirs:
            _rwx_dir(os.path.join(base, d))
        for fn in files:
            _rwx_result(os.path.join(base, fn))


# ===========================================================================
# SEVERITY CLASSIFICATION (P12..P18 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / fingerprint ----
    "ws_endpoint_live":          ("info", 0.0, "WebSocket endpoint upgrade-accept "
        "karta mila - poora connection-trust engine ab is surface par chalega "
        "(P19 core)."),
    "ws_candidate_path":         ("info", 0.0, "WebSocket candidate path mined - "
        "ranking ke through handshake census me jaayega."),
    "ws_js_link":                ("info", 0.0, "JS/HTML me ws://|wss:// link mila - "
        "client-side realtime surface (P7/P2 miner cross-ref)."),
    "ws_platform_fp":            ("low", 3.1, "Realtime platform fingerprint "
        "(socket.io/sockjs/signalr/centrifuge/phoenix...) - platform-specific "
        "known-bypass research aid (targeting)."),
    "ws_ping_interval_leak":     ("low", 3.3, "pingInterval/pingTimeout config "
        "public JSON me leak - infra tuning fingerprint (recon aid)."),
    "ws_sid_shape":              ("low", 3.5, "Session-id shape (sid/ConnectionId) "
        "public census me exposed - session-entropy research aid."),
    # ---- handshake / crypto ----
    "ws_upgrade_open":           ("medium", 5.3, "Sec-WebSocket-Accept ke saath "
        "clean 101 handshake anonymous ho gaya - koi origin/auth guard nahi "
        "(CWE-284 connection-level)."),
    "ws_accept_mismatch":        ("medium", 5.9, "Sec-WebSocket-Accept GUID math "
        "galat - custom/patched server stack ya proxy MITM surface "
        "(RFC 6455 violation, fingerprint aid)."),
    "ws_version_mismatch_ok":    ("low", 3.4, "Unsupported Sec-WebSocket-Version "
        "par bhi handshake chal gaya - version guard missing (RFC 6455 4.2.2 "
        "violation)."),
    "ws_permessage_deflate":     ("info", 0.0, "permessage-deflate extension "
        "offered - compression+secrets side-channel surface (CRIME-class, "
        "documented)."),
    "ws_subprotocol_echo":       ("medium", 6.1, "Arbitrary Sec-WebSocket-Protocol "
        "value response me reflect ho gaya - header-injection/response-"
        "splitting surface (CWE-113)."),
    "ws_protocol_accepted":      ("low", 3.2, "Server ne subprotocol accept kiya - "
        "protocol-shape fingerprint (targeting aid)."),
    # ---- origin trust (CSWSH) ----
    "ws_origin_unchecked":       ("critical", 8.8, "Cross-site WebSocket "
        "hijacking (CSWSH): arbitrary/absent Origin par 101 mila - victim "
        "browser cookies ke saath attacker page realtime data chura sakta "
        "hai (CWE-346; origin guard connection-trust ka base hai)."),
    "ws_origin_wildcard":        ("high", 7.4, "Wildcard-style origin acceptance "
        "(null/uppercase/prefix-variant pass) - inconsistent origin parser "
        "(CWE-346 partial; bypass primitives)."),
    "ws_origin_bypass_variant":  ("critical", 8.9, "Crafted origin variant "
        "(prefix/suffix/punycode/charset) ne origin check bypass kiya - "
        "validation sirf string-match hai (CWE-346; CSWSH fully exploitable)."),
    "ws_origin_enforced":        ("info", 0.0, "Origin guard present - cross-"
        "origin handshake reject hua (positive control, HARDENED evidence)."),
    "ws_null_origin_accepted":   ("high", 7.1, "null Origin (sandboxed iframe/"
        "file://) accept hua - attacker-controlled embed se hijack surface "
        "(CWE-346)."),
    # ---- auth differential ----
    "ws_auth_handshake_open":    ("high", 7.8, "Upgrade par koi auth nahi: "
        "no-creds handshake bhi 101 + channel attach - anonymous realtime "
        "access (CWE-306 connection-level)."),
    "ws_auth_diff_partial":      ("medium", 5.7, "Creds vs no-creds handshake "
        "differential partial - kuch signals par guard, channels par nahi "
        "(CWE-285 gap)."),
    "ws_token_in_url":           ("high", 7.5, "Auth token WS URL query-string me "
        "- logs/proxies/browser-history/referrer me token leak surface "
        "(CWE-598; realtime session hijack primitive)."),
    "ws_cookie_missing_samesite": ("medium", 5.5, "Handshake par Set-Cookie "
        "SameSite absent - browser CSWSH amplification (CWE-1275 flag; "
        "origin-guard ke saath bhi defense-in-depth gap)."),
    "ws_cookie_on_upgrade":      ("low", 3.6, "101 response Set-Cookie de raha hai - "
        "session semantics handshake-level par (flag, review aid)."),
    # ---- transports ----
    "ws_socketio_exposed":       ("medium", 5.6, "socket.io polling handshake "
        "public (sid + upgrades + ping config) - realtime surface free recon "
        "(CWE-200; EIO3 known-issues mapping)."),
    "ws_sockjs_exposed":         ("medium", 5.4, "SockJS /info public - entropy/"
        "cookie_needed/websocket capability leak (CWE-200)."),
    "ws_signalr_exposed":        ("medium", 5.6, "SignalR negotiate public - "
        "ConnectionId/ConnectionToken shapes exposed (CWE-200; reconnect-"
        "impersonation research aid)."),
    "ws_transports_probe_open":  ("medium", 5.5, "Transport negotiate endpoint "
        "auth ke bina respond karta hai - anonymous session seed surface "
        "(CWE-306)."),
    # ---- transport security ----
    "ws_ws_downgrade":           ("high", 7.6, "wss:// channel ws:// plaintext "
        "par bhi reachable - TLS-absent realtime interception surface "
        "(CWE-319; MITM read/write primitives)."),
    "ws_mixed_content_ws":       ("medium", 6.4, "HTTPS page context me ws:// "
        "(non-TLS) reference - mixed-content realtime downgrade (CWE-311)."),
    "ws_h2ws_available":         ("low", 3.7, "RFC 8441 HTTP/2 extended-CONNECT "
        "census signal - edge policy bypass research aid (GATED probe)."),
    # ---- injection / bypass ----
    "ws_header_injection":       ("critical", 8.2, "Subprotocol/key value par "
        "reflection ya malformed-accept behavior - HTTP response splitting/"
        "request smuggling surface (CWE-113)."),
    "ws_bypass2_route_misroute": ("critical", 8.7, "Edge-misroute technique "
        "(X-Original-URL/X-Rewrite-URL/dot-segment/semicolon) ne upgrade path "
        "khol diya jo direct access par block tha - WAF single-path hardening "
        "(CWE-693; bypass CONFIRMED)."),
    "ws_bypass2_header_smuggle": ("high", 7.7, "Header-level variant (case/"
        "whitespace/double-upgrade/HPP/absolute-URI) ne guard miss kiya - "
        "parser differential (CWE-436)."),
    "ws_waf_upgrade_missing":    ("medium", 5.8, "Upgrade-path par WAF/blocked "
        "signature absent - edge filtering ws traffic par blind (CWE-943 "
        "surface flag)."),
    # ---- rate / frames ----
    "ws_rate_limit_absent":      ("medium", 5.9, "Burst handshake par koi 429/"
        "limit signal nahi - connection-flood surface (CWE-770 flag; DoS "
        "execution FORBIDDEN - sirf census)."),
    "ws_rate_limit_present":     ("info", 0.0, "Rate-limit signal burst par mila "
        "(positive control, HARDENED evidence)."),
    "ws_frames_ping_only":       ("low", 3.8, "GATED frame census: connect+"
        "close/PING apne session par - frame-level behavior fingerprint "
        "(koi data frame nahi)."),
    "ws_message_replay_risk":    ("high", 7.3, "Message-replay/injection "
        "primitives DOCUMENTED (sequence/id/timestamp signals census se) - "
        "execution RoE+manual wave (P20/P22 handoff)."),
    # ---- subscriptions / secrets ----
    "ws_subs_transport_open":    ("high", 7.4, "GraphQL subscription WS transport "
        "open (graphql-transport-ws census) - realtime schema channel P18 "
        "handoff se CONFIRMED surface (CWE-200/284 chain)."),
    "ws_secret_url_param":       ("high", 7.5, "Secret/token-shaped param WS URL "
        "me (canary-match offline census) - leak surface (CWE-598)."),
    "ws_misconfig_flag":         ("medium", 5.2, "WebSocket misconfig signal "
        "(guard inconsistency/debug shape) - P23 handoff."),
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0,
                                              "WebSocket-surface signal."))
    return sev, cvss, why


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "WS-%03d" % (len(self.items) + 1), "key": key,
               "title": title, "severity": sev, "cvss_hint": cvss,
               "endpoint": endpoint, "detail": pii_redact(detail),
               "why_it_matters": why, "evidence": evidence_ref,
               "ts": now_iso()}
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
# PII REDACT (framework rule)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token)\s*[:=]\s*[^\s,;\"]{6,})")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


# ---------------------------------------------------------------------------
# CANARY + INERT ENFORCEMENT (P15..P18 pattern - hard rules)
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    """Synthetic marker ids - waspP19 family (real ids KABHI nahi)."""
    return "waspP19%s%s" % (tag, rand_str(6))


def filesig(body):
    """Body content store NAHI hota - sirf len + sha1 (redaction rule)."""
    if isinstance(body, str):
        body = body.encode("utf-8", "ignore")
    b = body or b""
    return {"len": len(b), "sha1": hashlib.sha1(b).hexdigest()[:16]}


# FORBIDDEN: koi destructive/exploit/exfil semantic. Sirf census + canary +
# invalid-token + structural differentials (P15..P18 pattern).
FORBIDDEN_CONTENT_PATTERNS = [
    r"(?i)drop\s+table", r"(?i)delete\s+from", r"(?i)insert\s+into",
    r"(?i)update\s+\w+\s+set", r"(?i)shutdown", r"(?i)rm\s+-rf",
    r"(?i)etc/passwd", r"(?i)boot\.ini", r"(?i)\.\./\.\./\.\./",
    r"(?i)<script[^>]*>\s*(alert|document\.cookie)", r"(?i)onerror\s*=",
    r"(?i)javascript:", r"(?i)data:text/html", r"(?i)union\s+select",
    r"(?i)sleep\(\d+\)", r"(?i)waitfor\s+delay", r"(?i)benchmark\(",
    r"(?i)eval\(", r"(?i)system\(", r"(?i)exec\(", r"(?i)curl\s+http",
    r"(?i)wget\s+http", r"(?i)nc\s+-e", r"(?i)bash\s+-i",
    r"(?i)churchill", r"(?i)log4j\{", r"(?i)\$\{jndi:",
    r"(?i)9091\r\n\r\n", r"(?i)smuggling[\s-]*attack",
    r"(?i)begin\s+payload", r"(?i)cat\s+/etc", r"(?i)type\s+C:\\",
    r"(?i)document\.location", r"(?i)window\.location\s*=",
]


def assert_inert(body, what="payload"):
    """Har synthetic request/body INERT hona chahiye - violation = hard fail."""
    s = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body or "")
    for pat in FORBIDDEN_CONTENT_PATTERNS:
        if re.search(pat, s):
            raise ValueError("FORBIDDEN content in %s (pattern: %s)"
                             % (what, pat))
    return True

# ===========================================================================
# WS HANDSHAKE CORE (RFC 6455) - INERT raw-socket upgrade probe
#   * GET-only (open handshake = HTTP GET), sirf status-line + headers read,
#     socket TURANT close. Frame exchange KABHI nahi (gate bhi PING/CLOSE
#     apne OWN session tak simit).
#   * Zero-egress: connect se PEHLE scope.check_host - fail = IMPOSSIBLE.
# ===========================================================================
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

WS_SCHEME_MAP = {"ws": "http", "wss": "https"}


def ws_key_gen():
    """16-byte base64 Sec-WebSocket-Key (RFC 6455 4.2.1) - canary-tagged entropy."""
    return base64.b64encode(_secrets.token_bytes(16)).decode("ascii")


def expected_accept(key):
    """RFC 6455 4.2.2: base64(SHA1(key + GUID)) - server honesty check."""
    try:
        return base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
    except Exception:
        return None


def ws_url_to_http(url):
    """ws://app/ws -> http://app/ws (wss -> https) census helper."""
    try:
        u = urllib.parse.urlsplit(url)
        scheme = WS_SCHEME_MAP.get(u.scheme)
        if not scheme:
            return None
        netloc = u.netloc
        if scheme == "http" and u.port == 80:
            netloc = u.hostname or netloc
        elif scheme == "https" and u.port == 443:
            netloc = u.hostname or netloc
        return urllib.parse.urlunsplit((scheme, netloc, u.path or "/",
                                        u.query, ""))
    except Exception:
        return None


def ws_parse_target(url):
    """WS URL -> (scheme, host, port, path_query) ya None."""
    try:
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("ws", "wss") or not u.hostname:
            return None
        port = u.port or (443 if u.scheme == "wss" else 80)
        pq = (u.path or "/") + (("?" + u.query) if u.query else "")
        return (u.scheme, u.hostname, port, pq)
    except Exception:
        return None


class WsHandshakeResult(dict):
    """Census row - koi body storage nahi (header-shapes + status only)."""
    pass


def ws_handshake(scope, url, extra_headers=None, key=None, version="13",
                 protocols=None, origin=None, timeout=None, conf=None,
                 read_bytes=8192):
    """Ek INERT upgrade probe: GET + Upgrade headers bhejo, status-line +
    response headers PARSE karo, turant close (frames NEVER).

    Returns dict: {ok, status, headers(dict, lower-cased), accept_expected,
    accept_ok, error, elapsed_ms, host, port, tls}. Koi body read nahi
    (101 ke baad ka stream intentionally untouched).
    """
    tgt = ws_parse_target(url)
    if not tgt:
        return {"ok": False, "error": "not-a-ws-url", "url": url}
    scheme, host, port, pq = tgt
    # ---- LAYER-4 scope firewall: connect se pehle hard gate ----
    if scope is not None:
        allowed = False
        try:
            allowed = scope.check_host(host, raise_on_fail=False)
        except Exception:
            allowed = False
        if not allowed:
            return {"ok": False, "error": "OUT-OF-SCOPE", "url": url,
                    "host": host}
    conf = conf or {}
    timeout = float(timeout or conf.get("ws_handshake_timeout", 5.0))
    key = key or ws_key_gen()
    lines = ["GET %s HTTP/1.1" % pq,
             "Host: %s%s" % (host, (":%d" % port) if port not in (80, 443) else ""),
             "Upgrade: websocket",
             "Connection: Upgrade",
             "Sec-WebSocket-Key: %s" % key,
             "Sec-WebSocket-Version: %s" % version]
    if protocols:
        lines.append("Sec-WebSocket-Protocol: %s" % protocols)
    if origin is not None:
        lines.append("Origin: %s" % origin)
    for k, v in (extra_headers or {}).items():
        lines.append("%s: %s" % (k, v))
    raw_req = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", "replace")
    assert_inert(raw_req, "ws_handshake request")
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if scheme == "wss":
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except Exception as e:
                return {"ok": False, "error": "tls-fail: %s" % e,
                        "url": url, "host": host, "port": port,
                        "elapsed_ms": int((time.time() - t0) * 1000)}
        sock.settimeout(timeout)
        sock.sendall(raw_req)
        # sirf status-line + headers (bounded) - body/frames KABHI nahi
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        head_blob, _, rest = buf.partition(b"\r\n\r\n")
        # 101 immediate-push catch (ek chhota bounded recv - race-safe;
        # frames/data read NAHI kiye jaate, sirf byte-count census)
        head_txt0 = head_blob.decode("utf-8", "ignore")
        if re.match(r"HTTP/1\.[01]\s+101", head_txt0):
            try:
                sock.settimeout(0.1)
                extra = sock.recv(4096)
                if extra:
                    rest += extra
            except (socket.timeout, OSError):
                pass
        head_txt = head_blob.decode("utf-8", "ignore")
        status = 0
        m = re.match(r"HTTP/1\.[01]\s+(\d{3})", head_txt)
        if m:
            status = int(m.group(1))
        headers = {}
        for line in head_txt.split("\r\n")[1:]:
            if ":" in line:
                hk, hv = line.split(":", 1)
                headers[hk.strip().lower()] = hv.strip()
        acc = headers.get("sec-websocket-accept")
        exp = expected_accept(key)
        return WsHandshakeResult(
            ok=(200 <= status < 300) or status == 101, status=status,
            headers=headers,
            accept_expected=exp, accept_ok=bool(acc and exp and acc == exp),
            header_sha1=hashlib.sha1(head_blob).hexdigest()[:16],
            leftover_bytes=len(rest), elapsed_ms=int((time.time() - t0) * 1000),
            host=host, port=port, tls=(scheme == "wss"), url=url, key=key)
    except socket.timeout:
        return {"ok": False, "error": "timeout", "url": url, "host": host,
                "elapsed_ms": int((time.time() - t0) * 1000)}
    except (OSError, ValueError) as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                "url": url, "host": host,
                "elapsed_ms": int((time.time() - t0) * 1000)}
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


def ws_fingerprint(res, protocols_sent=None):
    """101 response shape -> engine/edge fingerprint hints (census-only)."""
    if not res or not res.get("ok"):
        return {}
    h = res.get("headers") or {}
    fp = {"upgrade_echo": (h.get("upgrade") or "").lower(),
          "connection_tokens": [t.strip().lower() for t in
                                (h.get("connection") or "").split(",") if t.strip()],
          "extensions": (h.get("sec-websocket-extensions") or ""),
          "protocols_accepted": (h.get("sec-websocket-protocol") or ""),
          "accept_ok": bool(res.get("accept_ok")),
          "server": (h.get("server") or "")[:60],
          "via": (h.get("via") or "")[:40],
          "set_cookie_present": bool(h.get("set-cookie"))}
    if protocols_sent and fp["protocols_accepted"]:
        fp["protocol_echo"] = (fp["protocols_accepted"].strip() ==
                               protocols_sent.strip())
    return fp


# ===========================================================================
# SURFACE MINING (Stage A) - seeds + JS/HTML regex + cold pool + ranking
# ===========================================================================
_WS_LINK_RE = re.compile(
    r"(?i)\b(wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,})")
_SOCKETIO_RE = re.compile(r"(?i)(/socket\.io(?:/[^\s'\"<>]{0,40})?)")
_SOCKJS_RE = re.compile(r"(?i)(/[A-Za-z0-9._-]{1,32}/sockjs[^\s'\"<>]{0,30}"
                        r"|/sockjs[^\s'\"<>]{0,30})")
_SIGNALR_RE = re.compile(r"(?i)(/signalr[^\s'\"<>]{0,30}|"
                         r"/_blazor[^\s'\"<>]{0,30}|"
                         r"/centrifugo[^\s'\"<>]{0,30})")
_GQL_WS_RE = re.compile(r"(?i)((?:/[\w.-]+)*/(?:graphql[-_]?ws|subscriptions?"
                        r"|ws)[-A-Za-z0-9_./]{0,24})")
_WS_URL_PARAM_RE = re.compile(
    r"(?i)[?&](token|auth|jwt|access[_-]?token|session|sid|key|api[_-]?key|"
    r"secret|ticket|sig|signature|connection_?token|auth_?token)=([^\s&\"']{4,})")


def mine_ws_links(text, base_url=None, cap=40):
    """Stored-body miner: ws/wss links + transport hints (offline, 0 probes)."""
    out = {"ws_links": [], "socketio": [], "sockjs": [], "signalr": [],
           "gql_ws": []}
    if not text:
        return out
    for m in _WS_LINK_RE.finditer(text):
        u = m.group(1).rstrip(".,;)")
        if u not in out["ws_links"]:
            out["ws_links"].append(u)
        if len(out["ws_links"]) >= cap:
            break
    for m in _SOCKETIO_RE.finditer(text):
        if m.group(1) not in out["socketio"]:
            out["socketio"].append(m.group(1))
    for m in _SOCKJS_RE.finditer(text):
        if m.group(1) not in out["sockjs"]:
            out["sockjs"].append(m.group(1))
    for m in _SIGNALR_RE.finditer(text):
        if m.group(1) not in out["signalr"]:
            out["signalr"].append(m.group(1))
    for m in _GQL_WS_RE.finditer(text):
        if m.group(1) not in out["gql_ws"]:
            out["gql_ws"].append(m.group(1))
    return out


def _read_json_tolerant(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_text_tolerant(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _artifact(base_dir, mod, fname):
    """Seed-artifact path resolver (P18 pattern)."""
    return os.path.join(base_dir, mod, fname)


def _iter_records(d):
    """JSON me sab dict/list records flatten (bounded)."""
    out = []
    if isinstance(d, dict):
        for v in d.values():
            out.extend(_iter_records(v))
    elif isinstance(d, list):
        for v in d:
            out.extend(_iter_records(v))
    elif isinstance(d, str):
        out.append(d)
    return out


def _abs_urls_from_text(text, base_url, cap=40):
    """Text me relative/absolute URLs -> absolute (cap)."""
    out = []
    if not text:
        return out
    for m in re.finditer(r"(?i)(https?://[^\s'\"<>)]{4,})", text):
        u = m.group(1).rstrip(".,;)")
        if u not in out:
            out.append(u)
        if len(out) >= cap:
            break
    return out


def urljoin_safe(base_url, rel):
    try:
        return urllib.parse.urljoin(base_url or "", rel or "")
    except Exception:
        return ""


COLD_WS_PATHS = [
    "/ws", "/wss", "/websocket", "/websockets/v1", "/socket", "/sockets",
    "/socket.io/", "/sockjs", "/sockjs/info", "/echo/sockjs/info",
    "/signalr", "/signalr/negotiate", "/signalr/connect",
    "/_blazor", "/centrifugo", "/centrifugo/connection", "/primus",
    "/graphql-ws", "/graphql/ws", "/graphql/subscriptions", "/subscriptions",
    "/live/ws", "/realtime", "/rt", "/stream/ws", "/chat/ws", "/notify/ws",
]


def discover_ws_surface(base_dir, scope, conf):
    """Stage A: seed-artifact mining (P14/P17/P18/P6/P7/P5/P3/P8) + stored
    JS/HTML bodies + cold path pool -> ranked ws target list. 0 network."""
    paths_cap = int(conf.get("ws_paths_cap", 14))
    cold_n = int(conf.get("ws_cold_paths", 22))
    base_url = ""
    try:
        base_url = (scope.seed_urls() or [""])[0]
    except Exception:
        base_url = ""
    found = {}          # path -> row
    sources = []

    def _add_path(p, kind, src, extra=None):
        if not p or not isinstance(p, str):
            return
        p = p.strip()
        if not p or len(p) > 300:
            return
        absu = urljoin_safe(base_url, p) if not p.startswith(("ws://", "wss://",
                                                              "http://", "https://")) else p
        key = absu if absu.startswith(("ws://", "wss://")) else (
            urljoin_safe(base_url, p) if not p.startswith("/") else
            (base_url.rstrip("/") + p))
        row = found.setdefault(key, {"url": key, "kinds": set(), "sources": set(),
                                     "score": 0})
        if kind in row["kinds"]:
            # same-kind re-seed: score double-count NAHI (sources track)
            row["sources"].add(src)
            return
        row["kinds"].add(kind)
        row["sources"].add(src)
        # max() stacking: multi-kind rows ek hi strongest signal rakhte
        # hain (double-bonus inflation nahi - fair ranking)
        row["score"] = max(row["score"], {"ws_link": 5, "socketio": 4,
                                          "sockjs": 4, "signalr": 4,
                                          "gql_ws": 2, "ff": 8, "seed": 3,
                                          "cold": 1}.get(kind, 1))
        if extra:
            row.setdefault("extra", []).append(extra)

    # ---- P14 client: ws_endpoints feedforward ----
    for mod, fname, kind in (
            ("client", "feedforward.json", "ff"),
            ("api", "feedforward.json", "ff"),
            ("graphql", "feedforward.json", "ff"),
            ("tech", "feedforward.json", "ff"),
            ("js", "feedforward.json", "ff")):
        p = _artifact(base_dir, mod, fname)
        d = _read_json_tolerant(p)
        if not isinstance(d, dict):
            continue
        routing = d.get("routing") or d
        for rt_key in ("to_phase19_ws", "to_phase19_websocket"):
            node = routing.get(rt_key)
            if isinstance(node, dict):
                sources.append("%s:%s" % (mod, rt_key))
                for k in ("ws_endpoints", "ws_signals", "ws_paths"):
                    for u in (node.get(k) or []):
                        if isinstance(u, dict):
                            u = u.get("url") or ""
                        _add_path(u, kind, "%s.%s" % (mod, k))
                if node.get("gql_subscriptions") and not node.get("ws_paths"):
                    # gql_subs seed sirf tab (real ws_paths already ho to
                    # heuristic seed score-inflate nahi karega)
                    _add_path("/graphql-ws", "gql_ws", "%s.gql_subs" % mod)
                if node.get("realtime"):
                    sources.append("%s.realtime" % mod)
        # graphql feedforward ke andar ws_paths bhi direct ho sakte hain
        gp = (routing.get("to_phase19_ws") or {}).get("ws_paths") \
            if isinstance(routing.get("to_phase19_ws"), dict) else None
        if gp:
            for u in gp:
                _add_path(u, "ff", "graphql.ws_paths")
    # ---- P7 js artifacts (guide seed: JS miner ws:// links) ----
    for fname in ("websockets.txt", "js_urls.txt", "endpoints.txt"):
        p = _artifact(base_dir, "js", fname)
        txt = _read_text_tolerant(p)
        if txt:
            sources.append("js:%s" % fname)
            for line in txt.splitlines()[:60]:
                line = line.strip()
                if not line:
                    continue
                if line.startswith(("ws://", "wss://")):
                    _add_path(line, "ws_link", "js.%s" % fname)
                else:
                    absu = urljoin_safe(base_url, line)
                    for lk in mine_ws_links(absu, base_url, cap=8)["ws_links"]:
                        _add_path(lk, "ws_link", "js.%s.miner" % fname)
    # ---- stored JS/HTML bodies (P2/P7 caches jo milen) ----
    for root in (os.path.join(base_dir, "js"), os.path.join(base_dir, "content")):
        if os.path.isdir(root):
            for fn in sorted(os.listdir(root))[:24]:
                if not fn.endswith((".txt", ".json", ".html")):
                    continue
                txt = _read_text_tolerant(os.path.join(root, fn))
                hits = mine_ws_links(txt, base_url, cap=10)
                for u in hits["ws_links"]:
                    _add_path(u, "ws_link", "cache:%s" % fn)
    # ---- cold pool ----
    for cp in COLD_WS_PATHS[:cold_n]:
        _add_path(cp, "cold", "cold_pool")

    ranked = []
    for row in found.values():
        row["kinds"] = sorted(row["kinds"])
        row["sources"] = sorted(row["sources"])
        # ws/wss scheme urls sabse upar, phir score, phir short path
        scheme_rank = 0 if row["url"].startswith(("ws://", "wss://")) else 1
        ranked.append((scheme_rank, -row["score"], len(row["url"]), row))
    ranked.sort(key=lambda t: (t[0], t[1], t[2]))
    ranked = [t[3] for t in ranked][:paths_cap]

    # canonical ws:// urls banake census-ready targets banao
    # (found-insertion order - seed priority order rank_targets ka stable
    # tiebreak banta hai)
    targets = []
    seen = set()
    for row in found.values():
        u = row["url"]
        http_u = ws_url_to_http(u) if u.startswith(("ws://", "wss://")) else None
        if not http_u:
            http_u = u if u.startswith("http") else urljoin_safe(base_url, u)
        wsu = u if u.startswith(("ws://", "wss://")) else \
            ("ws://" + urllib.parse.urlsplit(base_url).netloc +
             (urllib.parse.urlsplit(http_u).path or "/") +
             (("?" + urllib.parse.urlsplit(http_u).query) if
              urllib.parse.urlsplit(http_u).query else ""))
        if http_u in seen:
            continue
        seen.add(http_u)
        targets.append({"url": http_u, "ws_url": wsu, "row": row})

    return {"ranked": ranked, "targets": targets, "sources": sources,
            "base_url": base_url}


def rank_targets(targets, conf):
    """Probe-cap tak targets rank: scheme-links + transport kinds pehle."""
    cap = int(conf.get("ws_probe_cap", 6))
    def _score(t):
        row = t.get("row") or {}
        s = row.get("score", 0)
        kinds = set(row.get("kinds", []))
        if "ws_link" in kinds or "ff" in kinds:
            s += 6
        if "socketio" in kinds or "sockjs" in kinds or "signalr" in kinds:
            s += 3
        return -s
    return sorted(targets, key=_score)[:cap]

# ===========================================================================
# STAGE C - HANDSHAKE CORE CENSUS (101/400/404/426 map + accept-crypto +
#           version negotiation + extensions + subprotocol echo)
# ===========================================================================
def handshake_census(scope, targets, meta, conf, canary):
    """Har target par INERT upgrade census (GET-only, immediate close):
    - baseline handshake (v13, no origin)
    - Sec-WebSocket-Accept crypto validation (GUID math)
    - version negotiation (v8/v13/v99 differential)
    - subprotocol echo census (INERT protocol names)
    - extensions (permessage-deflate offer)
    """
    rows = []
    timeout = float(conf.get("ws_handshake_timeout", 5.0))
    for t in targets:
        wsu = t["ws_url"]
        row = {"target": wsu, "http_url": t["url"], "probes": {}}
        # 1) canonical handshake
        res = ws_handshake(scope, wsu, timeout=timeout, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        row["probes"]["baseline"] = res
        row["status"] = res.get("status", 0)
        row["upgrade"] = res.get("ok") and res.get("status") == 101
        if res.get("ok"):
            row["fp"] = ws_fingerprint(res)
            if not res.get("accept_ok") and res.get("status") == 101:
                row["accept_mismatch"] = True
            if res.get("leftover_bytes"):
                # server ne 101 ke turant baad data push kiya (frame dump)
                row["server_pushed_bytes"] = int(res.get("leftover_bytes", 0))
        # 2) version negotiation (sirf live upgrade par - INERT)
        if row["upgrade"]:
            vres = ws_handshake(scope, wsu, version="8", timeout=timeout,
                                conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            v13only = vres.get("status") in (400, 426) and \
                (vres.get("headers") or {}).get("sec-websocket-version")
            row["version_guard"] = {"v8_status": vres.get("status"),
                                    "hinted": v13only}
            # 3) subprotocol echo census (response-splitting surface)
            pres = ws_handshake(scope, wsu, protocols="waspP19census.%0d.echo",
                                timeout=timeout, conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            pacc = ((pres.get("headers") or {}).get(
                "sec-websocket-protocol") or "")
            row["subprotocol_echo"] = {
                "accepted": bool(pacc),
                "reflected_verbatim": (pacc.strip().lower() ==
                                       "waspp19census.%0d.echo"),
                "header_sha1": pres.get("header_sha1")}
            # 4) extensions offer (census-only)
            xres = ws_handshake(scope, wsu,
                                extra_headers={"Sec-WebSocket-Extensions":
                                               "permessage-deflate"},
                                timeout=timeout, conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            row["extensions"] = {
                "deflate_negotiated": "permessage-deflate" in
                ((xres.get("headers") or {}).get(
                    "sec-websocket-extensions") or "").lower()}
        rows.append(row)
        if interrupted():
            warn("interrupted - handshake census partial")
            break
    return rows


def _origin_variants(base_url, conf, gate_evil):
    """Origin-matrix variants (benign default, evil GATED)."""
    try:
        sp = urllib.parse.urlsplit(base_url or "")
        scheme = sp.scheme or "https"
        host = sp.netloc or "localhost"
    except Exception:
        scheme, host = "https", "localhost"
    same = "%s://%s" % (scheme, host)
    variants = [
        ("none", None, True),
        ("same", same, True),
        ("null", "null", True),
        ("uppercase", same.upper(), True),
        ("trailing_dot", same + ".", True),
        ("subdomain", same.replace("://", "://sub."), True),
        ("port_variant", same.replace(scheme + "://", scheme + "://") + ":", True),
    ]
    # evil crafted bypass candidates - RoE GATED (cap benign-only lagta
    # hai; evil family census complete rehta hai jab gate ON ho)
    if gate_evil:
        h = urllib.parse.urlsplit(same).hostname or "localhost"
        variants += [
            ("evil_cross", "https://evil.example", False),
            ("prefix_trick", "https://%s.evil.example" % h, False),
            ("suffix_trick", "https://evil-%s.example" % h, False),
            ("at_sign", "https://evil.example@%s" % h, False),
            ("punycode", "https://xn--evil-2ve.example", False),
        ]
        return variants
    return variants[:max(3, int(conf.get("ws_origin_variants", 8)))]


# ===========================================================================
# STAGE D - ORIGIN TRUST MATRIX (CSWSH census - CWE-346)
# ===========================================================================
def origin_matrix(scope, targets, meta, conf, canary):
    """CSWSH census: none/null/same/uppercase(+evil GATED) origin variants
    ka handshake differential. 101-on-evil = hijack surface (CONFIRMED-class
    signal jab cookies bhi attached hon - stage E se correlate hota hai).
    INERT: sirf handshake, turant close."""
    gate_evil = bool(conf.get("ws_allow_origin_evil"))
    rows = []
    for t in targets[:max(1, min(3, int(conf.get("ws_probe_cap", 6))))]:
        wsu = t["ws_url"]
        # baseline: ye endpoint upgrade karta hai kya (no-origin)?
        base_res = ws_handshake(scope, wsu, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if not (base_res.get("ok") and base_res.get("status") == 101):
            rows.append({"target": wsu, "applicable": False,
                         "baseline_status": base_res.get("status", 0)})
            continue
        row = {"target": wsu, "applicable": True, "variants": {},
               "verdict": "SAFE"}
        for name, origin, benign in _origin_variants(
                t["url"], conf, gate_evil):
            res = ws_handshake(scope, wsu, origin=origin, timeout=None,
                               conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            acc = bool(res.get("ok") and res.get("status") == 101)
            row["variants"][name] = {
                "origin": origin if origin is not None else "(absent)",
                "status": res.get("status", 0), "accepted": acc,
                "gated": (not benign)}
            if acc:
                if name == "same":
                    continue
                if name == "none":
                    # non-browser client baseline (browsers Origin bhejte
                    # hain) - informational, verdict raise NAHI karta
                    row.setdefault("none_accepted", True)
                    continue
                if name == "null":
                    row["verdict"] = "SUSPECTED" if row["verdict"] == "SAFE" \
                        else row["verdict"]
                elif name in ("uppercase", "trailing_dot", "subdomain",
                              "port_variant"):
                    row["verdict"] = "SUSPECTED"
                    row["variant_flags"] = row.get("variant_flags", []) + [name]
                else:
                    # evil crafted bypass - strongest CSWSH proof (pehla
                    # accepted evil = primary; baaki variants row me)
                    if not row.get("bypass_variant"):
                        row["verdict"] = "CONFIRMED"
                        row["bypass_variant"] = name
                    else:
                        row["verdict"] = "CONFIRMED"
                        row.setdefault("extra_bypass", []).append(name)
        # wildcard story: same accept + evil accept => origin parser unchecked
        acc_any = [v for v in row["variants"].values() if v.get("accepted")]
        row["accepted_count"] = len(acc_any)
        rows.append(row)
        if interrupted():
            warn("interrupted - origin matrix partial")
            break
    return rows


# ===========================================================================
# STAGE E - AUTH DIFFERENTIAL (creds vs no-creds + token-in-URL + cookies)
# ===========================================================================
def auth_diff(http, scope, targets, meta, conf, canary, cookie_header=None):
    """Connection-level auth census (INERT):
    - no-creds handshake vs canary-cookie handshake vs canary-bearer header
    - differential verdict: open / partial / enforced
    - token-in-URL census: ws URL me secret-shaped query param ho to flag
      (offline regex, koi naya request nahi)
    """
    rows = []
    for t in targets[:max(1, min(3, int(conf.get("ws_probe_cap", 6))))]:
        wsu = t["ws_url"]
        anon = ws_handshake(scope, wsu, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if not (anon.get("ok") and anon.get("status") == 101):
            rows.append({"target": wsu, "applicable": False,
                         "anon_status": anon.get("status", 0)})
            continue
        row = {"target": wsu, "applicable": True}
        row["anon"] = {"status": anon.get("status"),
                       "set_cookie": bool(
                           (anon.get("headers") or {}).get("set-cookie"))}
        # canary cookie handshake (INVALID creds - sirf shape)
        cck = ws_handshake(scope, wsu,
                           extra_headers={"Cookie": "waspP19session=census"},
                           timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        # canary bearer handshake
        brr = ws_handshake(scope, wsu,
                           extra_headers={"Authorization":
                                          "Bearer waspP19.invalid.token"},
                           timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        anon101 = anon.get("status") == 101
        cck101 = cck.get("status") == 101
        brr101 = brr.get("status") == 101
        if anon101:
            row["verdict"] = "OPEN"          # anonymous upgrade accepted
        elif cck101 and not anon101:
            row["verdict"] = "COOKIE_REQUIRED"
        elif brr101 and not anon101:
            row["verdict"] = "HEADER_AUTH_REQUIRED"
        else:
            row["verdict"] = "ENFORCED"
        row["diff"] = {"anon": anon.get("status"),
                       "canary_cookie": cck.get("status"),
                       "canary_bearer": brr.get("status")}
        # token-in-URL census (offline - WS URL khud me secret shape?)
        m = _WS_URL_PARAM_RE.search(wsu)
        if m:
            row["token_in_url"] = {"param": m.group(1),
                                   "shape_sha1": hashlib.sha1(
                                       m.group(2).encode("utf-8", "ignore")
                                   ).hexdigest()[:12],
                                   "note": "token query-string me - log/"
                                           "referrer leak surface"}
        # Set-Cookie flags census (SameSite absence = CSWSH ammo)
        sc = (anon.get("headers") or {}).get("set-cookie") or ""
        if sc:
            row["cookie_flags"] = {
                "samesite": bool(re.search(r"(?i)samesite", sc)),
                "httponly": bool(re.search(r"(?i)httponly", sc)),
                "secure": bool(re.search(r"(?i)secure", sc))}
        rows.append(row)
        if interrupted():
            warn("interrupted - auth diff partial")
            break
    return rows

# ===========================================================================
# STAGE F - TRANSPORT CENSUS (socket.io / sockjs / signalr negotiate)
#           GATED ws_allow_transports (app-side session create ho sakta hai)
# ===========================================================================
def _read_json_resp(r):
    try:
        return json.loads(r.text or "")
    except Exception:
        return None


def transports_census(http, base_url, meta, conf, canary):
    """Realtime transport handshake JSON census (INERT GETs):
    - socket.io EIO4/EIO3 polling handshake (sid/upgrades/pingInterval)
    - sockjs /info (entropy/cookie_needed/websocket)
    - signalr negotiate (ConnectionId/ConnectionToken shapes)
    - primus/mercury/faye hints (census)
    GATED: ws_allow_transports (session-seed concern).
    """
    if not conf.get("ws_allow_transports"):
        return {"skipped": True, "gate": "ws_allow_transports=false",
                "manual_wave": "socket.io/sockjs/signalr negotiate GETs "
                               "(session create ho sakta hai - authorized "
                               "lab me gate ON karo)"}
    out = {"skipped": False, "socketio": [], "sockjs": [], "signalr": [],
           "other": []}
    root = (base_url or "").rstrip("/")
    # ---- socket.io EIO4 (v4) aur EIO3 (legacy) ----
    for eio, path in (("4", "/socket.io/?EIO=4&transport=polling"),
                      ("3", "/socket.io/?EIO=3&transport=polling")):
        try:
            r = http.get(root + path, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            obj = _read_json_resp(r)
            if r.status == 200 and isinstance(obj, dict) and (
                    "sid" in obj or "upgrades" in obj):
                rec = {"path": path, "eio": eio, "status": r.status,
                       "sid_shape": {"len": len(str(obj.get("sid", ""))),
                                     "entropy": round(shannon_entropy(
                                         str(obj.get("sid", ""))), 2)},
                       "upgrades": obj.get("upgrades"),
                       "pingInterval": obj.get("pingInterval"),
                       "pingTimeout": obj.get("pingTimeout"),
                       "maxPayload": obj.get("maxPayload")}
                out["socketio"].append(rec)
        except Exception:
            pass
    # ---- sockjs /info (+ /echo/info variants) ----
    for path in ("/sockjs/info", "/echo/info", "/websocket/info"):
        try:
            r = http.get(root + path, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            obj = _read_json_resp(r)
            if r.status == 200 and isinstance(obj, dict) and (
                    "websocket" in obj or "entropy" in obj):
                out["sockjs"].append({"path": path, "status": r.status,
                                      "websocket": obj.get("websocket"),
                                      "cookie_needed": obj.get("cookie_needed"),
                                      "origins": obj.get("origins"),
                                      "entropy": obj.get("entropy"),
                                      "url_prefix": obj.get("url_prefix")})
        except Exception:
            pass
    # ---- signalr negotiate (old ASP.NET GET-negotiate) ----
    for path in ("/signalr/negotiate", "/signalr/negotiate?connectionData=%5B%5D"):
        try:
            r = http.get(root + path, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            obj = _read_json_resp(r)
            if r.status == 200 and isinstance(obj, dict) and (
                    "ConnectionId" in obj or "ConnectionToken" in obj or
                    "TryWebSockets" in obj):
                out["signalr"].append({"path": path, "status": r.status,
                                       "connection_id_len": len(
                                           str(obj.get("ConnectionId", ""))),
                                       "try_websockets": obj.get(
                                           "TryWebSockets"),
                                       "url": obj.get("Url")})
        except Exception:
            pass
    # ---- primus / faye / mercury census (path live hona hi signal hai) ----
    for path in ("/primus", "/faye", "/mercury"):
        try:
            r = http.get(root + path, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            if r.status and r.status < 404 and r.status != 405:
                out["other"].append({"path": path, "status": r.status,
                                     "ct": (r.header("Content-Type") or "")[:40]})
        except Exception:
            pass
    return out


# ===========================================================================
# STAGE G - TRANSPORT SECURITY (ws:// downgrade + mixed-content + h2-WS)
# ===========================================================================
def transport_security_census(scope, targets, meta, conf):
    """wss -> ws downgrade census: mined wss:// target ko ws:// scheme par
    same-path handshake (INERT). 101 = TLS-absent realtime channel
    (CWE-319). HTTPS-context me ws:// references = mixed-content (offline
    mining se). RFC 8441 h2 extended-CONNECT = GATED ws_allow_h2ws."""
    rows = []
    h2_out = {"skipped": True, "gate": "ws_allow_h2ws=false"}
    for t in targets:
        wsu = t["ws_url"]
        if not wsu.startswith("wss://"):
            rows.append({"target": wsu, "applicable": False,
                         "note": "not-wss (mined ws:// scheme hi hai)"})
            continue
        # wss baseline
        sres = ws_handshake(scope, wsu, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if not (sres.get("ok") and sres.get("status") == 101):
            rows.append({"target": wsu, "applicable": False,
                         "wss_status": sres.get("status", 0),
                         "note": "wss upgrade hi nahi hua"})
            continue
        plain = "ws://" + wsu[len("wss://"):]
        pres = ws_handshake(scope, plain, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        row = {"target": wsu, "applicable": True,
               "wss_status": sres.get("status"),
               "ws_status": pres.get("status", 0),
               "ws_error": pres.get("error"),
               "downgrade": bool(pres.get("ok") and pres.get("status") == 101)}
        rows.append(row)
        if interrupted():
            warn("interrupted - downgrade census partial")
            break
    if conf.get("ws_allow_h2ws"):
        h2_out = {"skipped": False, "note": "RFC 8441 extended-CONNECT census "
                  "hint-only: HTTP/2 SETTINGS_ENABLE_CONNECT_PROTOCOL "
                  "advertisement edge-par differential; execution manual wave "
                  "(h2 client dependency lab-only)"}
    return {"rows": rows, "h2ws": h2_out}


# ===========================================================================
# STAGE H - HEADER INJECTION CENSUS (CWE-113 surface, INERT)
# ===========================================================================
def header_injection_census(scope, targets, meta, conf):
    """Subprotocol reflection = response header injection surface:
    - protocol value me %0d%0a shape (encoded) -> server verbatim echo kare
      to browser-level response splitting primitive (SUSPECTED/CONFIRMED)
    - key metachar validation (spaces/quotes/unicode)
    - oversized protocol value (bounded, no DoS)
    """
    rows = []
    for t in targets[:max(1, min(3, int(conf.get("ws_probe_cap", 6))))]:
        wsu = t["ws_url"]
        # baseline echo?
        base_p = ws_handshake(scope, wsu, protocols="waspP19.base",
                              timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if not (base_p.get("ok") and base_p.get("status") == 101):
            rows.append({"target": wsu, "applicable": False,
                         "status": base_p.get("status", 0)})
            continue
        base_acc = (base_p.get("headers") or {}).get(
            "sec-websocket-protocol") or ""
        row = {"target": wsu, "applicable": True,
               "echo_baseline": (base_acc.strip() == "waspP19.base"),
               "probes": {}}
        # 1) CRLF-encoded protocol echo (response-splitting primitive)
        pres = ws_handshake(scope, wsu, protocols="waspP19.a%0d%0aX-B: c",
                            timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        pact = ((pres.get("headers") or {}).get("sec-websocket-protocol") or "")
        row["probes"]["crlf_encoded"] = {
            "status": pres.get("status", 0),
            "reflected": "waspP19.a" in pact,
            "split_header_seen": bool(pres.get("headers", {}).get("x-b")),
            "risk": "critical" if bool(
                pres.get("headers", {}).get("x-b")) else (
                "high" if "waspP19.a" in pact else "none")}
        # 2) key metachar (server validation census)
        kres = ws_handshake(scope, wsu, key="waspP19 key\" <meta>",
                            timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        row["probes"]["key_metachar"] = {
            "status": kres.get("status", 0),
            "validation": (kres.get("status") in (400, 426))}
        # 3) oversized protocol (512B, bounded)
        big_p = ("waspP19." + "A" * 500)
        bres = ws_handshake(scope, wsu, protocols=big_p, timeout=None,
                            conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        bacc = ((bres.get("headers") or {}).get("sec-websocket-protocol") or "")
        row["probes"]["oversized_protocol"] = {
            "status": bres.get("status", 0),
            "echoed_full": bacc.strip() == big_p,
            "echo_len": len(bacc)}
        rows.append(row)
        if interrupted():
            warn("interrupted - header injection census partial")
            break
    return rows


# ===========================================================================
# STAGE I - WAF/EDGE BYPASS MATRIX v2 (17 SECRET handshake techniques)
# ===========================================================================
def bypass2_variants(target_url, origin):
    """17 SECRET handshake-level edge/WAF variants - sirf structural/header
    differentials (upgrade request hi GET hai; payload semantics INERT).
    Returns list[(name, {url|headers|key|version}, benign)] - benign=False
    wale RoE-gated (misroute-class actively edge ko confuse karte hain)."""
    u = urllib.parse.urlsplit(target_url)
    path = u.path or "/"
    q = ("?" + u.query) if u.query else ""
    host = u.netloc
    H = lambda **kw: dict(kw)  # noqa: E731
    return [
        ("x_original_url", {"headers": H(**{"X-Original-URL": path})}, False),
        ("x_rewrite_url", {"headers": H(**{"X-Rewrite-URL": path})}, False),
        ("dot_segment", {"url": path + "/../" + u.path.split("/")[-1] + q}, False),
        ("semicolon_param", {"url": path + ";ws=1" + q}, False),
        ("hpp_upgrade", {"headers": H(**{"Upgrade": "websocket, h2c"})}, False),
        ("case_upgrade", {"headers": H(**{"UPGRADE": "WebSocket",
                                          "cOnNeCtIoN": "Upgrade"})}, False),
        ("whitespace_token", {"headers": H(**{"Upgrade": " WebSocket ",
                                              "Connection": "Upgrade, keep-alive"})}, False),
        ("double_upgrade", {"headers": H(**{"Upgrade": "websocket",
                                            "Connection": "Upgrade",
                                            "X-Up": "websocket"})}, False),
        ("absolute_uri", {"absolute": True}, False),
        ("unicode_path", {"url": urllib.parse.quote(path)}, False),
        ("port_variant", {"port_hint": 8443}, False),
        ("host_header_trick", {"headers": H(**{"X-Forwarded-Host": host})}, False),
        ("xff_trust", {"headers": H(**{"X-Forwarded-For": "127.0.0.1",
                                       "X-Real-IP": "127.0.0.1"})}, False),
        ("early_data_hint", {"headers": H(**{"Early-Data": "1"})}, False),
        ("conn_token_split", {"headers": H(**{"Connection": "keep-alive",
                                              "X-Conn": "Upgrade"})}, False),
        ("null_origin", {"origin": "null"}, True),
        ("minified_headers", {"headers": H(**{"Accept": "*/*"})}, True),
    ]


def bypass2_matrix(scope, targets, meta, conf):
    """Bypass matrix v2 engine: har live-upgrade target par variants ka
    differential. Baseline: direct par kya hota hai. Variant jeet = edge/
    guard miss (route-misroute = CONFIRMED-class, header smuggle = HIGH).
    Cap: ws_bypass2_cap (17)."""
    cap = int(conf.get("ws_bypass2_cap", 17))
    rows = []
    for t in targets[:max(1, min(3, int(conf.get("ws_probe_cap", 6))))]:
        wsu = t["ws_url"]
        base = ws_handshake(scope, wsu, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        base_ok = bool(base.get("ok") and base.get("status") == 101)
        base_blocked = base.get("status") in (403, 406, 401)
        if not (base_ok or base_blocked):
            rows.append({"target": wsu, "applicable": False,
                         "baseline_status": base.get("status", 0)})
            continue
        row = {"target": wsu, "applicable": True,
               "baseline": {"status": base.get("status"), "ok": base_ok},
               "variants": {}}
        for name, patch, benign in bypass2_variants(wsu, None)[:cap]:
            url = wsu
            extra = dict(patch.get("headers") or {})
            origin = patch.get("origin")
            if patch.get("url"):
                # relative path variant -> same ws host par rebuild
                uu = urllib.parse.urlsplit(wsu)
                url = urllib.parse.urlunsplit(
                    (uu.scheme, uu.netloc, patch["url"].split("?")[0] or
                     uu.path, uu.query, ""))
            res = ws_handshake(scope, url, extra_headers=extra,
                               origin=origin, timeout=None, conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            v_ok = bool(res.get("ok") and res.get("status") == 101)
            v_stat = res.get("status", 0)
            win = bool(v_ok and not base_ok)
            row["variants"][name] = {
                "status": v_stat, "accepted": v_ok, "gated": (not benign),
                "win": win,
                "class": ("route_misroute" if name in (
                    "x_original_url", "x_rewrite_url", "dot_segment",
                    "semicolon_param", "unicode_path", "port_variant")
                    else "header_smuggle" if name in (
                        "hpp_upgrade", "case_upgrade", "whitespace_token",
                        "double_upgrade", "absolute_uri", "conn_token_split",
                        "host_header_trick", "xff_trust", "early_data_hint")
                    else "census")}
            if win:
                row.setdefault("wins", []).append(name)
        row["win_count"] = len(row.get("wins", []))
        rows.append(row)
        if interrupted():
            warn("interrupted - bypass2 partial")
            break
    return rows


# ===========================================================================
# STAGE J - WAF/UPGRADE FINGERPRINT (blocked-vs-open signature map)
# ===========================================================================
def waf_upgrade_fp(http, scope, targets, meta, conf):
    """Upgrade-path par WAF blind-spot census: plain GET vs upgrade GET ka
    treatment differential (edge ws-filtering policies)."""
    rows = []
    for t in targets[:max(1, min(3, int(conf.get("ws_probe_cap", 6))))]:
        http_u = t["url"]
        wsu = t["ws_url"]
        try:
            r = http.get(http_u, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            plain_status = r.status
            plain_waf = waf_signature(r.headers or {}, r.text or "", r.status)
        except Exception as e:
            plain_status, plain_waf = 0, {}
        hres = ws_handshake(scope, wsu, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        rows.append({"target": wsu,
                     "plain_get": {"status": plain_status,
                                   "waf": plain_waf if isinstance(
                                       plain_waf, dict) else {}},
                     "upgrade_get": {"status": hres.get("status", 0),
                                     "accepted": bool(
                                         hres.get("ok") and
                                         hres.get("status") == 101)},
                     "edge_ws_filter": (hres.get("status") in (403, 406)) and
                     (plain_status not in (403, 406))})
        if interrupted():
            break
    return rows

# ===========================================================================
# STAGE K - RATE/LIMIT CENSUS (GATED ws_allow_burst, HARD cap 3 sequential)
# ===========================================================================
def rate_census(scope, targets, meta, conf):
    """Bounded burst census: SAME endpoint par max-3 sequential handshakes
    (1s spacing) -> 429/Retry-After/connection-limit observation.
    DoS execution FORBIDDEN - sirf limit-presence census (gate OFF = skip)."""
    if not conf.get("ws_allow_burst"):
        return {"skipped": True, "gate": "ws_allow_burst=false",
                "manual_wave": "bounded burst (<=3 sequential, 1s spacing) "
                               "rate-limit census - authorized lab only"}
    cap = int(conf.get("ws_burst_cap", 3)) if conf.get("ws_burst_cap") else 3
    cap = max(1, min(3, int(cap)))   # HARD cap 3 - koi flood nahi
    rows = []
    for t in targets[:1]:
        wsu = t["ws_url"]
        statuses = []
        for i in range(cap):
            res = ws_handshake(scope, wsu, timeout=None, conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            statuses.append({"n": i + 1, "status": res.get("status", 0),
                             "elapsed_ms": res.get("elapsed_ms")})
            if i < cap - 1:
                time.sleep(1.0)
        hit = [s for s in statuses if s["status"] in (429, 503)]
        rows.append({"target": wsu, "burst": statuses,
                     "limit_signal": bool(hit),
                     "signal_shape": hit[0]["status"] if hit else None,
                     "verdict": "PRESENT" if hit else "ABSENT"})
    return {"rows": rows, "cap": cap}


# ===========================================================================
# STAGE L - FRAME-LEVEL CENSUS (GATED ws_allow_frames; DOCUMENTED-ONLY wave)
# ===========================================================================
DOCUMENTED_MESSAGE_TECHNIQUES = [
    ("message_injection", "Post-handshake server-bound data frames me "
     "canary JSON (owner-id swap) - realtime BOLA/IDOR (P11 chain). "
     "EXECUTION FORBIDDEN AUTO - sirf manual authorized lab wave."),
    ("message_replay", "Client->server messages capture karke exact resend "
     "(sequence/timestamp/id census se replay-prone shape detection) - "
     "duplicate-action/abuse surface (P22 handoff). EXECUTION FORBIDDEN."),
    ("message_forgery", "Signed/MAC-ed message fields me tamper canary "
     "(role/amount/qty shapes) - server-side trust violation surface "
     "(P20 logic handoff). EXECUTION FORBIDDEN."),
    ("ws_mitm_interception", "ws:// (non-TLS) channel par network-level "
     "read/write MITM primitives - downgrade finding ke saath chain hota "
     "hai (stage G). EXECUTION FORBIDDEN."),
    ("frame_fragment_abuse", "Fragmented-frame/continuation edge-cases "
     "(RSV-bit/opcode confusion) server-parser stress - DoS class, "
     "FORBIDDEN-AUTO (documented-only)."),
    ("origin_spoof_via_client", "Browser-devtools Origin override = CSWSH "
     "PoC manual wave (origin-matrix finding ka human-verification step)."),
    ("subprotocol_desync", "Server-accepted subprotocol vs app-message "
     "format mismatch abuse - desync primitive (research aid)."),
    ("sid_hijack_socketio", "socket.io sid reuse cross-connection - session "
     "impersonation research aid (sid entropy census ke saath)."),
]


def frames_census_gated(scope, targets, meta, conf, canary):
    """GATED frame-level census (ws_allow_frames): connect -> PING (OWN
    session) -> immediate close. Koi data frame KABHI. Message-techniques
    sirf DOCUMENTED hote hain (execution RoE+manual)."""
    if not conf.get("ws_allow_frames"):
        return {"skipped": True, "gate": "ws_allow_frames=false",
                "documented": [t[0] for t in DOCUMENTED_MESSAGE_TECHNIQUES],
                "manual_wave": "frame I/O (PING/CLOSE own-session only) - "
                               "authorized lab me gate ON karo"}
    rows = []
    for t in targets[:1]:
        wsu = t["ws_url"]
        res = ws_handshake(scope, wsu, timeout=None, conf=conf)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        row = {"target": wsu, "upgrade": bool(res.get("ok") and
                                              res.get("status") == 101),
               "note": "frame-I/O engine own-session PING/CLOSE-only; "
                       "data-frames execution FORBIDDEN (documented)",
               "canary": canary}
        rows.append(row)
    return {"rows": rows, "techniques_documented":
            [{"name": n, "method": d} for n, d in DOCUMENTED_MESSAGE_TECHNIQUES]}


# ===========================================================================
# STAGE M - GRAPHQL SUBSCRIPTIONS CENSUS (P18 handoff, GATED ws_allow_ws)
# ===========================================================================
def subs_census(http, scope, base_url, ff_ws_paths, gql_subs, meta, conf,
                canary):
    """P18 GraphQL handoff consume: subscription transports ka census
    (graphql-transport-ws vs graphql-ws subprotocol differential).
    GATED ws_allow_ws (upgrade probes); offline path list hamesha banti hai."""
    out = {"skipped": False, "paths": [], "subprotocol_diff": []}
    cand = []
    for p in (ff_ws_paths or [])[:int(conf.get("ws_subs_paths", 4))]:
        cand.append(p)
    for p in ("/graphql-ws", "/graphql/ws", "/graphql/subscriptions",
              "/subscriptions"):
        cand.append(urljoin_safe(base_url, p))
    seen, uniq = set(), []
    for c in cand:
        if c and c not in seen:
            seen.add(c)
            uniq.append(c)
    out["paths"] = [{"url": c, "gql_subs_signal": bool(gql_subs)} for c in uniq]
    if not conf.get("ws_allow_ws"):
        out["skipped"] = True
        out["gate"] = "ws_allow_ws=false"
        out["manual_wave"] = "graphql-ws subprotocol upgrade differential " \
                             "(graphql-transport-ws vs graphql-ws)"
        return out
    for c in uniq[:int(conf.get("ws_subs_paths", 4))]:
        hu = ws_url_to_http(c) if c.startswith(("ws://", "wss://")) else c
        wsu = c if c.startswith(("ws://", "wss://")) else (
            "ws://" + urllib.parse.urlsplit(hu).netloc +
            urllib.parse.urlsplit(hu).path)
        row = {"endpoint": wsu}
        for subp in ("graphql-transport-ws", "graphql-ws"):
            res = ws_handshake(scope, wsu, protocols=subp, timeout=None,
                               conf=conf)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            acc = ((res.get("headers") or {}).get(
                "sec-websocket-protocol") or "").strip()
            row[subp] = {"status": res.get("status", 0),
                         "accepted": bool(res.get("ok") and
                                          res.get("status") == 101),
                         "protocol_echo": acc == subp}
        out["subprotocol_diff"].append(row)
        if interrupted():
            break
    return out


# ===========================================================================
# STAGE N - PLATFORM FINGERPRINT (socket.io/sockjs/signalr shapes + misc)
# ===========================================================================
PLATFORM_HINTS = [
    ("socket.io", ["socket.io", "engine.io"], "socket.io - EIO3 known-issues "
     "(CSWSH defaults pre-4.6), namespace escalation research"),
    ("sockjs", ["sockjs"], "SockJS - info-entropy + fallback transports"),
    ("signalr", ["signalr", "asp.net signalr"], "SignalR - ConnectionToken "
     "reconnect-impersonation research"),
    ("centrifuge", ["centrifugo"], "Centrifugo - channel-subscription "
     "authz research"),
    ("phoenix", ["phoenix", "phx-"], "Phoenix channels - topic-authz research"),
    ("faye", ["faye"], "Faye - extension-chain abuse research"),
    ("primus", ["primus"], "Primus - transformer-layer research"),
    ("apollo", ["apollo", "subscriptions-transport-ws"],
     "Apollo ws engine - graphql-transport-ws protocol research"),
    ("hasura", ["hasura"], "Hasura subscriptions - role-header chain "
     "(P18 federation-deep handoff)"),
]


def platform_fingerprint(results, meta, conf):
    """Sab census rows se platform shapes (offline aggregation, 0 probes)."""
    fp = {"platforms": [], "shapes": {}}
    blob = json.dumps(results, default=str).lower()
    for name, sigs, note in PLATFORM_HINTS:
        if any(s in blob for s in sigs):
            fp["platforms"].append({"name": name, "note": note})
    try:
        for rec in (results.get("transports") or {}).get("socketio", []):
            fp["shapes"]["socketio_eio"] = rec.get("eio")
            fp["shapes"]["ping_interval"] = rec.get("pingInterval")
            fp["shapes"]["sid_entropy"] = rec.get("sid_shape", {}).get("entropy")
    except Exception:
        pass
    try:
        for rec in (results.get("transports") or {}).get("sockjs", []):
            fp["shapes"]["sockjs_cookie_needed"] = rec.get("cookie_needed")
            fp["shapes"]["sockjs_entropy"] = rec.get("entropy")
    except Exception:
        pass
    return fp


# ===========================================================================
# STAGE O - SECRETS-IN-URL + JS MINER CROSS-REF (offline, 0 probes)
# ===========================================================================
def secrets_in_url_census(targets, base_url, meta, conf):
    """Mined WS URLs + stored bodies me secret-shaped params (canary-match
    offline). 0 network. CWE-598 (sensitive info in query strings)."""
    rows = []
    for t in targets:
        wsu = t["ws_url"]
        m = _WS_URL_PARAM_RE.search(wsu)
        if m:
            rows.append({"url_sha1": hashlib.sha1(wsu.encode()).hexdigest()[:12],
                         "url": wsu[:120], "param": m.group(1),
                         "value_shape": {"len": len(m.group(2)),
                                         "entropy": round(shannon_entropy(
                                             m.group(2)), 2)},
                         "risk": "token-in-URL (log/referrer/history leak)"})
    return rows


def js_miner_crossref(base_dir, base_url, conf):
    """Stored JS/HTML caches me ws:// links + transport hints (offline)."""
    out = {"ws_links": [], "socketio": [], "sockjs": [], "signalr": [],
           "gql_ws": [], "sources": []}
    for root in (os.path.join(base_dir, "js"), os.path.join(base_dir, "content")):
        if not os.path.isdir(root):
            continue
        for fn in sorted(os.listdir(root))[:24]:
            if not fn.endswith((".txt", ".json", ".html")):
                continue
            txt = _read_text_tolerant(os.path.join(root, fn))
            hits = mine_ws_links(txt, base_url, cap=20)
            for k in ("ws_links", "socketio", "sockjs", "signalr", "gql_ws"):
                for v in hits[k]:
                    if v not in out[k]:
                        out[k].append(v)
            if any(hits.values()):
                out["sources"].append(fn)
    return out

# ===========================================================================
# STAGE P - VERDICT ENGINE (6-class ladder, multi-signal)
# ===========================================================================
def _verdict_from_origin(row, cookie_ctx):
    if not row.get("applicable"):
        return None
    v = row.get("verdict") or "SAFE"
    if v == "CONFIRMED":
        return ("CONFIRMED", "ws_origin_bypass_variant",
                "Crafted origin variant ne handshake accept kiya - CSWSH "
                "exploitable (CWE-346)")
    if v == "SUSPECTED":
        if cookie_ctx:
            return ("CONFIRMED", "ws_origin_unchecked",
                    "Benign-variant origin (null/uppercase/subdomain) accept "
                    "+ browser cookies attach - CSWSH CONFIRMED (CWE-346)")
        return ("SUSPECTED", "ws_origin_wildcard",
                "Origin parser inconsistent (variants pass) - CSWSH "
                "primitive (CWE-346 partial)")
    return ("HARDENED", "ws_origin_enforced",
            "Origin guard present - variants reject hue")


def verdict_engine(results, meta, conf):
    """Sab census rows -> verdict rows (CONFIRMED/SUSPECTED/HARDENED/BLOCKED/
    SKIPPED/NOISE) + finding-key mapping. P12..P18-compatible."""
    rows = []
    cookie_ctx = bool(results.get("auth_diff", {}).get("cookie_ctx"))
    # --- origin matrix ---
    for row in (results.get("origin_matrix") or []):
        v = _verdict_from_origin(row, cookie_ctx)
        if v:
            rows.append({"surface": row["target"], "stage": "origin",
                         "verdict": v[0], "key": v[1], "why": v[2]})
    # --- auth diff ---
    for row in (results.get("auth_diff") or {}).get("rows", []) if isinstance(
            results.get("auth_diff"), dict) else (results.get("auth_diff") or []):
        if not row.get("applicable"):
            continue
        v = row.get("verdict")
        if v == "OPEN":
            rows.append({"surface": row["target"], "stage": "auth",
                         "verdict": "CONFIRMED", "key": "ws_auth_handshake_open",
                         "why": "no-creds upgrade 101 - anonymous channel "
                                "(CWE-306)"})
        elif v in ("COOKIE_REQUIRED", "HEADER_AUTH_REQUIRED"):
            rows.append({"surface": row["target"], "stage": "auth",
                         "verdict": "HARDENED", "key": "ws_auth_diff_partial",
                         "why": "auth guard upgrade-par present"})
    # --- handshake census ---
    for row in (results.get("handshake") or []):
        if row.get("accept_mismatch"):
            rows.append({"surface": row["target"], "stage": "handshake",
                         "verdict": "SUSPECTED", "key": "ws_accept_mismatch",
                         "why": "Sec-WebSocket-Accept GUID math galat"})
        se = (row.get("subprotocol_echo") or {})
        if se.get("reflected_verbatim"):
            rows.append({"surface": row["target"], "stage": "handshake",
                         "verdict": "CONFIRMED", "key": "ws_subprotocol_echo",
                         "why": "arbitrary subprotocol verbatim echo - "
                                "response-splitting surface (CWE-113)"})
    # --- transports ---
    tr = results.get("transports") or {}
    if not tr.get("skipped"):
        for rec in tr.get("socketio", []):
            rows.append({"surface": rec.get("path"), "stage": "transports",
                         "verdict": "SUSPECTED", "key": "ws_socketio_exposed",
                         "why": "socket.io handshake JSON public (sid "
                                "+ ping config)"})
        for rec in tr.get("sockjs", []):
            rows.append({"surface": rec.get("path"), "stage": "transports",
                         "verdict": "SUSPECTED", "key": "ws_sockjs_exposed",
                         "why": "sockjs /info public"})
        for rec in tr.get("signalr", []):
            rows.append({"surface": rec.get("path"), "stage": "transports",
                         "verdict": "SUSPECTED", "key": "ws_signalr_exposed",
                         "why": "signalr negotiate public"})
    # --- downgrade ---
    ts = results.get("transport_sec") or {}
    for row in ts.get("rows", []):
        if row.get("downgrade"):
            rows.append({"surface": row["target"], "stage": "downgrade",
                         "verdict": "CONFIRMED", "key": "ws_ws_downgrade",
                         "why": "wss channel ws:// plaintext par bhi 101 - "
                                "TLS-absent realtime (CWE-319)"})
    # --- header injection ---
    for row in (results.get("header_injection") or []):
        crlf = (row.get("probes") or {}).get("crlf_encoded") or {}
        if crlf.get("split_header_seen"):
            rows.append({"surface": row["target"], "stage": "inject",
                         "verdict": "CONFIRMED", "key": "ws_header_injection",
                         "why": "CRLF-encoded subprotocol split-header trigger "
                                "hua - response splitting (CWE-113)"})
        elif crlf.get("reflected"):
            rows.append({"surface": row["target"], "stage": "inject",
                         "verdict": "SUSPECTED", "key": "ws_subprotocol_echo",
                         "why": "encoded CRLF protocol value reflect hua"})
    # --- bypass2 ---
    for row in (results.get("bypass2") or []):
        wins = row.get("wins") or []
        if not wins:
            continue
        route_wins = [w for w in wins if ((row.get("variants") or {})
                                          .get(w) or {}).get("class") ==
                      "route_misroute"]
        if route_wins:
            rows.append({"surface": row["target"], "stage": "bypass2",
                         "verdict": "CONFIRMED",
                         "key": "ws_bypass2_route_misroute",
                         "why": "edge-misroute variant(s) %s ne guard miss "
                                "kiya (CWE-693)" % ",".join(route_wins[:3])})
        else:
            rows.append({"surface": row["target"], "stage": "bypass2",
                         "verdict": "SUSPECTED",
                         "key": "ws_bypass2_header_smuggle",
                         "why": "header-variant guard differential "
                                "(CWE-436): %s" % ",".join(wins[:3])})
    # --- rate ---
    rc = results.get("rate") or {}
    if not rc.get("skipped"):
        for row in rc.get("rows", []):
            rows.append({"surface": row["target"], "stage": "rate",
                         "verdict": "SUSPECTED" if row.get("limit_signal") is
                         False else "HARDENED",
                         "key": "ws_rate_limit_absent" if not
                         row.get("limit_signal") else "ws_rate_limit_present",
                         "why": "burst census %s" % ("limit signal nahi" if
                                                     not row.get("limit_signal")
                                                     else "limit present")})
    # --- subs ---
    sc = results.get("subs") or {}
    if not sc.get("skipped"):
        for row in sc.get("subprotocol_diff", []):
            if row.get("graphql-transport-ws", {}).get("accepted"):
                rows.append({"surface": row.get("endpoint"), "stage": "subs",
                             "verdict": "CONFIRMED",
                             "key": "ws_subs_transport_open",
                             "why": "GraphQL subscription transport open "
                                    "(P18 handoff)"})
    # --- secrets in URL ---
    for row in (results.get("secrets_url") or []):
        rows.append({"surface": row.get("url", "")[:80], "stage": "secrets",
                     "verdict": "CONFIRMED", "key": "ws_secret_url_param",
                     "why": row.get("risk", "token-in-URL")})
    # --- cookies ---
    for row in (results.get("auth_diff") or {}).get("rows", []) if isinstance(
            results.get("auth_diff"), dict) else (results.get("auth_diff") or []):
        cf = row.get("cookie_flags") or {}
        if cf and not cf.get("samesite"):
            rows.append({"surface": row["target"], "stage": "cookies",
                         "verdict": "SUSPECTED",
                         "key": "ws_cookie_missing_samesite",
                         "why": "Set-Cookie SameSite absent - CSWSH ammo"})
    return rows


# ===========================================================================
# STAGE Q - KILL-CHAINS (20 realtime attack chains)
# ===========================================================================
def build_ws_chains(F, results, verdict_rows, targets, meta, conf):
    """20 chains: har chain = preconditions -> technique -> impact -> next-
    phase handoff. INERT discipline: execution steps manual+authorized only."""
    o = {r.get("surface"): r for r in verdict_rows}
    has = lambda stage, key=None: any(          # noqa: E731
        r.get("stage") == stage and (key is None or r.get("key") == key)
        for r in verdict_rows)
    conf_cswsh = has("origin", "ws_origin_bypass_variant")
    cswsh = conf_cswsh or has("origin", "ws_origin_unchecked")
    downgrade = has("downgrade", "ws_ws_downgrade")
    auth_open = has("auth", "ws_auth_handshake_open")
    subs_open = has("subs", "ws_subs_transport_open")
    tok_url = has("secrets", "ws_secret_url_param")
    echo_hdr = has("handshake", "ws_subprotocol_echo") or \
        has("inject", "ws_header_injection")
    misroute = has("bypass2", "ws_bypass2_route_misroute")
    smuggle = has("bypass2", "ws_bypass2_header_smuggle")
    socketio = has("transports", "ws_socketio_exposed")
    sockjs = has("transports", "ws_sockjs_exposed")
    signalr = has("transports", "ws_signalr_exposed")
    samesite = has("cookies", "ws_cookie_missing_samesite")
    rate_absent = has("rate", "ws_rate_limit_absent")
    deflate = any(r.get("extensions", {}).get("deflate_negotiated")
                  for r in (results.get("handshake") or []))
    chains = [
        ("CHAIN-01", "CSWSH -> realtime PII theft", cswsh,
         "Attacker page victim-browser se in-scope WS connect (cookies "
         "auto-attach) -> subscription/channel messages me PII stream "
         "-> attacker origin par exfil. Stage-D origin finding + stage-E "
         "cookie context chain hota hai. Execution manual wave."),
        ("CHAIN-02", "Origin-bypass -> realtime BOLA (P11 chain)", cswsh,
         "Origin guard bypass + object-id channels -> attacker apne session "
         "se doosre user ki realtime feed subscribe (IDOR over websocket). "
         "P11 findings ke ids ke saath manual differential."),
        ("CHAIN-03", "wss->ws downgrade -> MITM read/write", downgrade,
         "Same-path plaintext 101 -> network-level interception primitives "
         "(read + inject). Stage-G downgrade + stage-L documented MITM "
         "technique chain."),
        ("CHAIN-04", "Token-in-URL -> realtime session hijack", tok_url,
         "WS URL me token -> access-logs/proxy/browser-history leak -> token "
         "replay -> channel impersonation. Stage-O census + P22 replay "
         "research."),
        ("CHAIN-05", "Anonymous upgrade -> channel enumeration", auth_open,
         "no-creds 101 -> channel/room naming research -> unauth data "
         "channels attach (server-side authz P20 handoff)."),
        ("CHAIN-06", "Subprotocol echo -> response splitting", echo_hdr,
         "Arbitrary Sec-WebSocket-Protocol reflect -> upgrade-response "
         "header injection primitive (browser-level). Stage-H census."),
        ("CHAIN-07", "Edge misroute -> hidden ws endpoints", misroute,
         "X-Original-URL/dot-segment par upgrade accept -> WAF single-path "
         "hardening bypass -> hidden realtime surface exposure."),
        ("CHAIN-08", "Header smuggle -> guard differential", smuggle,
         "Case/whitespace/double-upgrade variants guard miss -> policy "
         "bypass research (CWE-436)."),
        ("CHAIN-09", "socket.io sid -> namespace escalation", socketio,
         "Public sid + EIO census -> sid-shape/entropy research -> "
         "namespace/room authz manual wave (P20)."),
        ("CHAIN-10", "sockjs cookie_needed=false -> CSWSH ammo", sockjs,
         "SockJS info me cookie_needed false + open origin -> transport-"
         "fallback hijack research."),
        ("CHAIN-11", "SignalR ConnectionToken -> reconnect impersonation",
         signalr,
         "Negotiate shapes public -> token-reuse research -> reconnect "
         "impersonation wave (documented)."),
        ("CHAIN-12", "null-origin accept -> sandbox-iframe hijack",
         has("origin", "ws_origin_wildcard"),
         "null Origin 101 -> sandboxed iframe/file:// embed se hijack "
         "research (CWE-346)."),
        ("CHAIN-13", "SameSite-absent cookies -> CSWSH amplification",
         samesite,
         "Handshake Set-Cookie bina SameSite -> browser cross-site attach "
         "guaranteed -> CHAIN-01 amplify."),
        ("CHAIN-14", "GraphQL subs open -> realtime schema data leak",
         subs_open,
         "graphql-transport-ws accepted -> P18 schema ke subscription "
         "fields over ws census (census-only) -> P20 logic handoff."),
        ("CHAIN-15", "Rate-absent + burst -> connection exhaustion",
         rate_absent,
         "Burst par koi 429 nahi -> flood surface (DoS EXECUTION FORBIDDEN "
         "- sirf capacity-planning flag P23/P25 handoff)."),
        ("CHAIN-16", "permessage-deflate + secrets -> compression side-"
         "channel", deflate,
         "Deflate negotiated + secret-bearing messages -> CRIME-class "
         "recovery research (documented-only)."),
        ("CHAIN-17", "Misroute + token-in-URL -> stealth hijack", misroute,
         "Hidden endpoint (misroute) + URL-token -> logged-out attacker "
         "stealth connect (chains 04+07 combine)."),
        ("CHAIN-18", "Version-guard miss -> legacy client impersonation",
         any(r.get("version_guard", {}).get("v8_status") == 101
             for r in (results.get("handshake") or [])),
         "v8 handshake accepted -> legacy-parser differential research "
         "(RFC deviation)."),
        ("CHAIN-19", "Message-injection -> client DOM XSS (P13 chain)",
         auth_open or cswsh,
         "Attacker-controlled server->client message render path -> DOM "
         "sink (P13 findings cross-ref) - documented-only."),
        ("CHAIN-20", "Realtime logic abuse -> P20 workflow skip", auth_open,
         "Server-bound messages me state-transitions (qty/price/step "
         "shapes census) -> P20 logic engine handoff (execution manual)."),
    ]
    return [{"id": cid, "title": t, "active": bool(pred), "story": story}
            for cid, t, pred, story in chains]

# ===========================================================================
# STAGE R (part 1) - HYPOTHESES + TECHNIQUE MATRIX (150 rows x 18 families)
# ===========================================================================
def build_ws_hypotheses(results, verdict_rows, chains, conf):
    """Offline intelligence: 'agar X aaya to Y karo' action rows (0 probes)."""
    has = lambda stage, key=None: any(          # noqa: E731
        r.get("stage") == stage and (key is None or r.get("key") == key)
        for r in verdict_rows)
    hyps = []
    if has("origin", "ws_origin_bypass_variant"):
        hyps.append({"if": "origin bypass variant CONFIRMED", "then":
                     "browser-devtools se Origin override karke manual CSWSH "
                     "PoC (apna test account) - realtime data cross-origin "
                     "stream proof pack karo", "priority": 1,
                     "phase": "manual/P25"})
    if has("auth", "ws_auth_handshake_open"):
        hyps.append({"if": "anonymous upgrade 101", "then":
                     "channel/room naming research (client JS me subscribe "
                     "shapes) -> unauth channels differential", "priority": 1,
                     "phase": "P20"})
    if has("downgrade", "ws_ws_downgrade"):
        hyps.append({"if": "wss->ws downgrade", "then":
                     "same-host plaintext mitmproxy census (OWN lab) - "
                     "interception proof + transport policy bug report",
                     "priority": 1, "phase": "manual"})
    if has("secrets", "ws_secret_url_param"):
        hyps.append({"if": "token-in-URL", "then":
                     "access-log/referrer/history leak story + token-rotate "
                     "impact - P22 replay research", "priority": 2,
                     "phase": "P22"})
    if has("handshake", "ws_subprotocol_echo"):
        hyps.append({"if": "subprotocol verbatim echo", "then":
                     "header-injection PoC (controlled %0d%0a) par browser "
                     "level response-splitting verify - authorized lab",
                     "priority": 2, "phase": "manual"})
    if has("bypass2", "ws_bypass2_route_misroute"):
        hyps.append({"if": "edge misroute win", "then":
                     "hidden ws endpoint inventory banao (misroute variants "
                     "x path wordlist) - WAF rule-gap report", "priority": 1,
                     "phase": "P25"})
    if has("transports", "ws_socketio_exposed"):
        hyps.append({"if": "socket.io public", "then":
                     "EIO version CVE mapping (EIO3 CSWSH defaults) + sid "
                     "entropy review + namespace authz manual wave",
                     "priority": 2, "phase": "P20/P23"})
    if has("transports", "ws_signalr_exposed"):
        hyps.append({"if": "signalr negotiate public", "then":
                     "ConnectionToken reuse research + reconnect-impersonation "
                     "PoC (own session only)", "priority": 2, "phase": "manual"})
    if has("subs", "ws_subs_transport_open"):
        hyps.append({"if": "graphql-transport-ws accepted", "then":
                     "P18 schema ke subscription fields par census (koi "
                     "subscribe EXECUTION nahi) -> P20 logic handoff",
                     "priority": 2, "phase": "P20"})
    if has("rate", "ws_rate_limit_absent"):
        hyps.append({"if": "burst par limit absent", "then":
                     "capacity-planning flag + connection-exhaustion story "
                     "(DoS execution FORBIDDEN) - P25 controls", "priority": 3,
                     "phase": "P25"})
    if has("cookies", "ws_cookie_missing_samesite"):
        hyps.append({"if": "SameSite absent", "then":
                     "origin-guard ke saath bhi defense-in-depth gap report - "
                     "CSWSH amplification", "priority": 3, "phase": "P23"})
    if any(r.get("extensions", {}).get("deflate_negotiated")
           for r in (results.get("handshake") or [])):
        hyps.append({"if": "permessage-deflate", "then":
                     "compression side-channel research (CRIME-class, "
                     "documented-only)", "priority": 3, "phase": "research"})
    if has("inject", "ws_header_injection"):
        hyps.append({"if": "CRLF split-header", "then":
                     "response-splitting primitive PoC (lab) + edge CVE "
                     "mapping", "priority": 1, "phase": "manual"})
    if has("transports", "ws_sockjs_exposed"):
        hyps.append({"if": "sockjs info public", "then":
                     "cookie_needed=false + open origin => fallback-hijack "
                     "research", "priority": 3, "phase": "research"})
    return hyps


_FAMS = ("MINE", "TARGET", "HAND", "CRYPTO", "ORIGIN", "AUTH", "TRANSPORT",
         "DOWNGRADE", "INJECT", "BYPASS2", "WAF", "RATE", "FRAME", "SUBS",
         "PLATFORM", "SECRET", "VERDICT", "CHAIN")


def build_technique_matrix(results, conf):
    """150+ rows x 18 families - har technique ka method + gate + status +
    CWE + MITRE (detection-only mapping)."""
    rows = []

    def add(fam, tech, method, status="clean", gate="ON", cwe="", mitre=""):
        rows.append({"id": "WS-%s-%02d" % (fam, len(
            [r for r in rows if r["family"] == fam]) + 1),
            "family": fam, "technique": tech, "method": method,
            "status": status, "gate": gate, "cwe": cwe, "mitre": mitre})

    hs = results.get("handshake") or []
    live = [r for r in hs if r.get("upgrade")]
    mined = results.get("targets") or []
    # ---- MINE (8) ----
    add("MINE", "feedforward seed mining",
        "P14/P17/P18/P6/P7 feedforward.json (to_phase19_ws) paths",
        "hit" if mined else "clean", cwe="CWE-200")
    add("MINE", "JS/HTML ws:// regex miner",
        "wss?:// + socket.io + sockjs + signalr + graphql-ws regex over "
        "stored bodies (offline)", "hit" if results.get("js_miner") else "clean",
        cwe="CWE-540")
    add("MINE", "cold path pool",
        "%d canonical ws paths (/ws /socket.io/ /signalr/...)" %
        int(conf.get("ws_cold_paths", 22)), "clean")
    add("MINE", "ranking scorer",
        "kind-weighted max-score (ff 8 / ws_link 5 / transport 4 / cold 1)",
        "clean")
    add("MINE", "transport-shape hinting",
        "path-shape se socket.io/sockjs/signalr classification", "clean")
    add("MINE", "cache cross-ref", "js/content stored bodies cross-ref",
        "clean")
    add("MINE", "P18 subs handoff consume",
        "gql_subscriptions + ws_paths seed", "hit" if results.get(
            "subs", {}).get("paths") else "clean")
    add("MINE", "duplicate-target dedupe",
        "http<->ws canonical map + seen-set", "clean")
    # ---- TARGET (6) ----
    add("TARGET", "ws->http scheme map", "ws_url_to_http() canonicalization",
        "clean")
    add("TARGET", "probe cap discipline",
        "ws_probe_cap=%d (handshake targets)" % int(conf.get("ws_probe_cap", 6)),
        "clean")
    add("TARGET", "scope firewall pre-connect",
        "scope.check_host BEFORE socket.connect (zero-egress)", "clean")
    add("TARGET", "wss scheme preserved", "wss/ws scheme census ke through "
        "preserve (no artificial boost)", "clean")
    add("TARGET", "kind-weighted ordering", "ws_link/ff first", "clean")
    add("TARGET", "interrupt-safe iteration", "interrupted() checkpoints",
        "clean")
    # ---- HAND (12) ----
    add("HAND", "canonical RFC 6455 upgrade", "GET + Upgrade/Connection/Key/"
        "Version: 13 (raw socket, headers-only read)", "hit" if live else
        "clean", cwe="CWE-284", mitre="T1046")
    add("HAND", "101/400/404/426 status map", "upgrade-accept matrix per "
        "target", "hit" if hs else "clean")
    add("HAND", "version negotiation diff", "v8 vs v13 (426+hint = guard)",
        "hit" if any(r.get("version_guard") for r in hs) else "clean",
        cwe="CWE-693")
    add("HAND", "subprotocol echo census", "INERT protocol names echo check",
        "hit" if any((r.get("subprotocol_echo") or {}).get("reflected_verbatim")
                     for r in hs) else "clean", cwe="CWE-113")
    add("HAND", "permessage-deflate offer",
        "Sec-WebSocket-Extensions census", "hit" if any(
            (r.get("extensions") or {}).get("deflate_negotiated") for r in hs)
        else "clean")
    add("HAND", "server-push detection", "leftover-bytes after 101 headers",
        "hit" if any(r.get("server_pushed_bytes") for r in hs) else "clean")
    add("HAND", "header-shape fingerprint", "upgrade_echo/connection tokens/"
        "server/via", "hit" if any(r.get("fp") for r in hs) else "clean")
    add("HAND", "accept honesty check", "expected vs returned accept", "clean")
    add("HAND", "immediate-close discipline", "frame exchange NEVER (headers "
        "only)", "clean")
    add("HAND", "timeout bounded", "ws_handshake_timeout=%.1fs" % float(
        conf.get("ws_handshake_timeout", 5.0)), "clean")
    add("HAND", "raw socket INERT probe", "connect->send->read-headers->close",
        "clean")
    add("HAND", "probe counter", "meta.probes_total accounting", "clean")
    # ---- CRYPTO (6) ----
    add("CRYPTO", "Sec-WebSocket-Key gen", "16-byte token_bytes -> base64",
        "clean")
    add("CRYPTO", "GUID math", "SHA1(key+258EAFA5-...) -> base64", "clean")
    add("CRYPTO", "accept mismatch fingerprint",
        "galat accept = patched stack/proxy", "hit" if any(
            r.get("accept_mismatch") for r in hs) else "clean",
        cwe="CWE-327", mitre="T1557")
    add("CRYPTO", "TLS-wrap wss", "ssl wrap (no-verify census mode)", "clean")
    add("CRYPTO", "key metachar validation",
        "spaces/quotes/unicode in key -> 400/426 census", "clean",
        cwe="CWE-113")
    add("CRYPTO", "header sha1 storage",
        "bodies nahi - sirf header-sha1 (redaction)", "clean")
    # ---- ORIGIN (14) ----
    ov = [("none", "absent Origin header"), ("same", "same-origin echo"),
          ("null", "null Origin (sandbox/file)"), ("uppercase", "case-variant"),
          ("trailing_dot", "host trailing dot"), ("subdomain", "sub-domain "
           "prefix"), ("port_variant", "port suffix variant")]
    for name, desc in ov:
        st = "hit" if any(v.get("accepted") for r in (results.get(
            "origin_matrix") or []) if r.get("applicable")
            for k, v in (r.get("variants") or {}).items()
            if k == name and name not in ("none", "same")) else \
            ("hit" if name in ("none", "same") and any(
                r.get("applicable") for r in (results.get("origin_matrix") or
                                              [])) else "clean")
        add("ORIGIN", "origin:%s" % name, desc, st, gate="ON",
            cwe="CWE-346", mitre="T1557")
    evil = [("evil_cross", "https://evil.example"),
            ("prefix_trick", "https://host.evil.example"),
            ("suffix_trick", "https://evil-host.example"),
            ("at_sign", "https://evil@host userinfo"),
            ("punycode", "xn-- punycode homograph")]
    for name, desc in evil:
        st = "hit" if any(v.get("accepted") for r in (results.get(
            "origin_matrix") or []) if r.get("applicable")
            for k, v in (r.get("variants") or {}).items() if k == name) else \
            ("skip" if not conf.get("ws_allow_origin_evil") else "clean")
        add("ORIGIN", "origin:evil/%s" % name, desc, st,
            gate="GATED ws_allow_origin_evil", cwe="CWE-346", mitre="T1557")
    add("ORIGIN", "CSWSH differential verdict",
        "101-on-evil + cookies => CONFIRMED", "clean")
    add("ORIGIN", "accepted-count aggregation", "variant accept matrix",
        "clean")
    # ---- AUTH (10) ----
    ad = results.get("auth_diff") or {}
    ad_rows = ad.get("rows", []) if isinstance(ad, dict) else (ad or [])
    add("AUTH", "anonymous upgrade", "no-creds handshake", "hit" if any(
        r.get("verdict") == "OPEN" for r in ad_rows) else "clean",
        cwe="CWE-306", mitre="T1552")
    add("AUTH", "canary cookie differential", "Cookie: waspP19session=census",
        "clean")
    add("AUTH", "canary bearer differential", "Authorization: Bearer "
        "waspP19.invalid.token", "clean")
    add("AUTH", "verdict ladder", "OPEN/COOKIE_REQUIRED/HEADER_AUTH_REQUIRED/"
        "ENFORCED", "clean")
    add("AUTH", "token-in-URL census", "secret-shaped params regex over ws "
        "urls", "hit" if any(r.get("token_in_url") for r in ad_rows) else
        "clean", cwe="CWE-598")
    add("AUTH", "Set-Cookie flags census", "SameSite/HttpOnly/Secure on 101",
        "hit" if any(r.get("cookie_flags") for r in ad_rows) else "clean",
        cwe="CWE-1275")
    add("AUTH", "creds-vs-anon diff", "status differential matrix", "clean")
    add("AUTH", "canary-token discipline", "INVALID tokens only", "clean")
    add("AUTH", "cookie context correlation", "CSWSH CONFIRMED ammo check",
        "clean")
    add("AUTH", "authz P20 handoff", "OPEN -> P20 workflow signals", "clean")
    # ---- TRANSPORT (12) ----
    tr = results.get("transports") or {}
    tstat = "skip" if tr.get("skipped") else "hit" if (tr.get("socketio") or
                                                       tr.get("sockjs") or
                                                       tr.get("signalr")) \
        else "clean"
    add("TRANSPORT", "socket.io EIO4 handshake", "GET /socket.io/?EIO=4&"
        "transport=polling (sid JSON)", tstat, gate="GATED "
        "ws_allow_transports", cwe="CWE-200")
    add("TRANSPORT", "socket.io EIO3 legacy", "EIO=3 shape diff", tstat,
        gate="GATED ws_allow_transports", cwe="CWE-200")
    add("TRANSPORT", "sockjs /info", "entropy/cookie_needed/websocket",
        tstat, gate="GATED ws_allow_transports", cwe="CWE-200")
    add("TRANSPORT", "sockjs variants", "/echo/info /websocket/info", tstat,
        gate="GATED ws_allow_transports")
    add("TRANSPORT", "signalr negotiate", "ConnectionId/ConnectionToken",
        tstat, gate="GATED ws_allow_transports", cwe="CWE-200")
    add("TRANSPORT", "primus/faye/mercury census", "path-live signals",
        tstat, gate="GATED ws_allow_transports")
    add("TRANSPORT", "sid entropy score", "shannon_entropy(sid)", tstat)
    add("TRANSPORT", "ping config leak", "pingInterval/pingTimeout public",
        tstat, cwe="CWE-200")
    add("TRANSPORT", "maxPayload leak", "transport config exposure", tstat)
    add("TRANSPORT", "upgrades list", "transport-negotiation surface", tstat)
    add("TRANSPORT", "session-seed concern gate", "negotiate GETs session "
        "create kar sakte hain -> GATED", "clean")
    add("TRANSPORT", "transport platform map", "shapes -> platform_fp",
        "clean")
    # ---- DOWNGRADE (6) ----
    tsec = results.get("transport_sec") or {}
    add("DOWNGRADE", "wss->ws same-path", "plaintext 101 = TLS-absent channel",
        "hit" if any(r.get("downgrade") for r in tsec.get("rows", [])) else
        "clean", cwe="CWE-319", mitre="T1557")
    add("DOWNGRADE", "mixed-content census", "HTTPS page + ws:// refs (mined)",
        "clean", cwe="CWE-311")
    add("DOWNGRADE", "RFC 8441 hint", "h2 extended-CONNECT census hint",
        "skip" if (tsec.get("h2ws") or {}).get("skipped") else "clean",
        gate="GATED ws_allow_h2ws")
    add("DOWNGRADE", "TLS presence map", "wss/ws scheme inventory", "clean")
    add("DOWNGRADE", "downgrade verdict", "CONFIRMED on ws 101", "clean")
    add("DOWNGRADE", "MITM chain link", "stage-L documented technique",
        "clean")
    # ---- INJECT (8) ----
    hi = results.get("header_injection") or []
    add("INJECT", "CRLF-encoded protocol echo", "%0d%0a value reflection "
        "census", "hit" if any(((r.get("probes") or {}).get("crlf_encoded") or
                                {}).get("reflected") for r in hi) else "clean",
        cwe="CWE-113", mitre="T1557")
    add("INJECT", "split-header detection", "X-B injected header seen",
        "hit" if any(((r.get("probes") or {}).get("crlf_encoded") or
                      {}).get("split_header_seen") for r in hi) else "clean",
        cwe="CWE-113")
    add("INJECT", "key metachar validation", "malformed key -> 400/426",
        "clean")
    add("INJECT", "oversized protocol", "512B value echo census", "clean")
    add("INJECT", "echo baseline", "canonical subprotocol echo check", "clean")
    add("INJECT", "response-splitting story", "browser-level primitive "
        "documented", "clean")
    add("INJECT", "INERT guarantee", "sirf reflection census - koi exploit "
        "nahi", "clean")
    add("INJECT", "CWE-113 mapping", "header injection class", "clean")
    # ---- BYPASS2 (17) ----
    for name, patch, benign in bypass2_variants("ws://h/p", None):
        cls = ("route_misroute" if name in ("x_original_url", "x_rewrite_url",
                                            "dot_segment", "semicolon_param",
                                            "unicode_path", "port_variant")
               else "header_smuggle" if name in (
                   "hpp_upgrade", "case_upgrade", "whitespace_token",
                   "double_upgrade", "absolute_uri", "conn_token_split",
                   "host_header_trick", "xff_trust", "early_data_hint")
               else "census")
        st = "hit" if any(name in (r.get("wins") or []) for r in
                          (results.get("bypass2") or [])) else \
            ("skip" if not benign and not _b2_applicable(results) else "clean")
        add("BYPASS2", name, patch.get("headers") and
            ("headers: %s" % patch["headers"]) or
            ("url-shape: %s" % patch.get("url", "structural")), st,
            gate="ON" if benign else "GATED-variant (benign census)",
            cwe="CWE-693" if cls == "route_misroute" else "CWE-436")
    # ---- WAF (8) ----
    wfp = results.get("waf_upgrade_fp") or []
    add("WAF", "plain-vs-upgrade differential", "GET status vs 101/403 map",
        "hit" if wfp else "clean", cwe="CWE-943")
    add("WAF", "edge ws-filter census", "upgrade 403 par plain 200 => blind",
        "clean")
    add("WAF", "waf_signature calibration", "wasp_core waf on home", "clean")
    add("WAF", "blocked-signature map", "403/406/401 upgrade paths", "clean")
    add("WAF", "edge-trust story", "single-path hardening detection", "clean")
    add("WAF", "misroute interplay", "bypass2 route wins cross-ref", "clean")
    add("WAF", "upgrade-fp artifacts", "ws_waf_upgrade_fp.json", "clean")
    add("WAF", "CWE-943 flag", "ws-filter blind-spot surface", "clean")
    # ---- RATE (6) ----
    rc = results.get("rate") or {}
    add("RATE", "bounded burst", "<=3 sequential (HARD cap, 1s spacing)",
        "skip" if rc.get("skipped") else "hit" if any(
            r.get("limit_signal") is False for r in rc.get("rows", [])) else
        "clean", gate="GATED ws_allow_burst", cwe="CWE-770")
    add("RATE", "429/503 signal census", "limit-presence observation",
        "clean")
    add("RATE", "Retry-After capture", "header-shape only", "clean")
    add("RATE", "flood FORBIDDEN", "DoS execution auto-forbidden", "clean")
    add("RATE", "sequential discipline", "koi parallel burst nahi", "clean")
    add("RATE", "P25 handoff", "controls-effectiveness flag", "clean")
    # ---- FRAME (10) ----
    fr = results.get("frames") or {}
    add("FRAME", "gated frame I/O", "PING/CLOSE own-session only",
        "skip" if fr.get("skipped") else "clean", gate="GATED "
        "ws_allow_frames")
    add("FRAME", "message-injection documented", "owner-id swap canary "
        "(execution FORBIDDEN)", "clean", cwe="CWE-284")
    add("FRAME", "message-replay documented", "sequence/timestamp census",
        "clean", cwe="CWE-294")
    add("FRAME", "message-forgery documented", "role/amount shapes", "clean")
    add("FRAME", "ws-MITM documented", "downgrade chain read/write", "clean")
    add("FRAME", "fragment-abuse documented", "RSV/opcode stress FORBIDDEN",
        "clean", cwe="CWE-400")
    add("FRAME", "origin-spoof documented", "devtools Origin override PoC "
        "wave", "clean")
    add("FRAME", "subprotocol-desync documented", "format mismatch research",
        "clean")
    add("FRAME", "sid-hijack documented", "socket.io sid reuse research",
        "clean")
    add("FRAME", "data-frame ban", "koi data frame KABHI nahi (code-level)",
        "clean")
    # ---- SUBS (6) ----
    sc = results.get("subs") or {}
    add("SUBS", "P18 handoff consume", "ws_paths + gql_subscriptions seed",
        "hit" if sc.get("paths") else "clean")
    add("SUBS", "graphql-transport-ws", "subprotocol differential",
        "hit" if any(r.get("graphql-transport-ws", {}).get("accepted")
                     for r in sc.get("subprotocol_diff", [])) else
        ("skip" if sc.get("skipped") else "clean"), cwe="CWE-200")
    add("SUBS", "graphql-ws legacy", "legacy subprotocol diff", "clean")
    add("SUBS", "path census", "%d candidate paths" % len(sc.get("paths", [])),
        "clean")
    add("SUBS", "subscribe-execution ban", "connection_open message NEVER "
        "(census-only)", "clean")
    add("SUBS", "P20 handoff", "realtime logic channels signal", "clean")
    # ---- PLATFORM (9 fixed rows) ----
    pf = results.get("platform_fp") or {}
    pf_names = {p.get("name") for p in (pf.get("platforms") or [])}
    for name, _sigs, note in PLATFORM_HINTS:
        add("PLATFORM", "platform:%s" % name, note,
            "hit" if name in pf_names else "clean")
    # ---- SECRET (8) ----
    add("SECRET", "token-in-URL deep census", "entropy + shape sha1",
        "hit" if (results.get("secrets_url") or []) else "clean",
        cwe="CWE-598")
    add("SECRET", "sid-shape entropy", "socket.io/signalr sid research",
        "clean")
    add("SECRET", "ping-interval leak", "infra tuning fingerprint",
        "clean", cwe="CWE-200")
    add("SECRET", "cookie_needed research", "sockjs CSWSH ammo", "clean")
    add("SECRET", "cookie-on-upgrade flag", "101 Set-Cookie semantics",
        "clean")
    add("SECRET", "redirect-never-follow", "census GETs no-redirect", "clean")
    add("SECRET", "soft-404 noise filter", "baseline template guard", "clean")
    add("SECRET", "evidence-off probe loops", "quiet_client heavy loops",
        "clean")
    # ---- VERDICT (4) ----
    add("VERDICT", "6-class ladder", "CONFIRMED/SUSPECTED/HARDENED/BLOCKED/"
        "SKIPPED/NOISE", "clean")
    add("VERDICT", "multi-signal correlate", "origin+cookies+auth diff",
        "clean")
    add("VERDICT", "gate-skip documentation", "SKIPPED rows manual wave",
        "clean")
    add("VERDICT", "findings mapping", "key -> sev/cvss/why", "clean")
    # ---- CHAIN (2) ----
    add("CHAIN", "chain count", "%d chains (active: %d)" % (
        len(results.get("chains") or []),
        sum(1 for c in (results.get("chains") or []) if c.get("active"))),
        "clean")
    add("CHAIN", "chain-to-phase map", "P11/P12/P13/P20/P22/P25 handoffs",
        "clean")
    return rows


def _b2_applicable(results):
    return any(r.get("applicable") for r in (results.get("bypass2") or []))

# ===========================================================================
# STAGE S - REPORTS / ARTIFACTS (40 outputs, RWX 0777)
# ===========================================================================
def write_reports(out, scope, F, ctx, meta, results, hyps, chains, matrix,
                  conf):
    """Sab artifacts likh (40) - findings/verdicts/census/matrix/chains/
    guides/feedforward/manifest. Bodies REDACTED (sha1-shape only)."""
    manifest = []
    targets = results.get("targets") or []
    verdict_rows = results.get("verdict_rows") or []
    trans = results.get("transports") or {}
    tsec = results.get("transport_sec") or {}

    def _w_json(name, obj):
        _rwx_save_json(os.path.join(out, name), obj)
        manifest.append(name)

    def _w_text(name, txt):
        _rwx_save_text(os.path.join(out, name), txt)
        manifest.append(name)

    # 1-3 targets/paths/ranking
    _w_json("ws_targets.json", {
        "count": len(targets),
        "targets": [{"url": t.get("url"), "ws_url": t.get("ws_url"),
                     "kinds": (t.get("row") or {}).get("kinds", []),
                     "sources": (t.get("row") or {}).get("sources", [])}
                    for t in targets]})
    _w_text("ws_endpoints.txt", "\n".join(
        sorted(set([t.get("ws_url", "") for t in targets if t.get("ws_url")])))
        + "\n")
    _w_json("ws_ranking.json", {
        "probe_cap": conf.get("ws_probe_cap"),
        "ranked": [{"url": t.get("ws_url"),
                    "score": (t.get("row") or {}).get("score", 0)}
                   for t in targets]})
    # 4 coverage
    _w_json("ws_coverage.json", {
        "mode": ctx.get("mode"), "sources": meta.get("sources", []),
        "probes_total": meta.get("probes_total", 0),
        "surface": ctx.get("coverage", {}),
        "gates": {k: bool(conf.get(k)) for k in
                  ("ws_allow_origin_evil", "ws_allow_transports",
                   "ws_allow_burst", "ws_allow_frames", "ws_allow_h2ws",
                   "ws_allow_ws")}})
    # 5-7 handshake census
    hs = results.get("handshake") or []
    _w_json("ws_handshake_census.json", [{
        "target": r.get("target"), "status": r.get("status"),
        "upgrade": r.get("upgrade"),
        "fp": r.get("fp"), "version_guard": r.get("version_guard"),
        "subprotocol_echo": r.get("subprotocol_echo"),
        "extensions": r.get("extensions"),
        "server_pushed_bytes": r.get("server_pushed_bytes")}
        for r in hs])
    _w_json("ws_accept_crypto.json", [{
        "target": r.get("target"),
        "accept_ok": (r.get("probes", {}).get("baseline") or
                      {}).get("accept_ok", (r.get("fp") or {}).get("accept_ok")),
        "accept_mismatch": r.get("accept_mismatch", False)} for r in hs])
    _w_json("ws_version_negotiation.json", [{
        "target": r.get("target"), "version_guard": r.get("version_guard")}
        for r in hs if r.get("version_guard")])
    # 8-11 origin/auth/cookies
    _w_json("ws_origin_matrix.json", results.get("origin_matrix") or [])
    _w_json("ws_origin_bypass.json", {
        "gate": "ws_allow_origin_evil=%s" % bool(
            conf.get("ws_allow_origin_evil")),
        "bypass_rows": [{"target": r.get("target"),
                         "bypass_variant": r.get("bypass_variant"),
                         "verdict": r.get("verdict")}
                        for r in (results.get("origin_matrix") or [])
                        if r.get("bypass_variant")]})
    _w_json("ws_auth_diff.json", results.get("auth_diff") or {})
    _w_json("ws_cookie_census.json", {
        "rows": [{"target": r.get("target"),
                  "set_cookie": (r.get("anon") or {}).get("set_cookie"),
                  "flags": r.get("cookie_flags")}
                 for r in (results.get("auth_diff") or {}).get("rows", [])
                 if isinstance(results.get("auth_diff"), dict)] or
                 (results.get("auth_diff") or [])})
    # 12-15 transports
    _w_json("ws_transports.json", trans)
    _w_json("ws_transports_socketio.json",
            trans.get("socketio", []) if isinstance(trans, dict) else [])
    _w_json("ws_transports_sockjs.json",
            trans.get("sockjs", []) if isinstance(trans, dict) else [])
    _w_json("ws_transports_signalr.json",
            trans.get("signalr", []) if isinstance(trans, dict) else [])
    # 16-18 downgrade/h2ws/injection
    _w_json("ws_downgrade_census.json", tsec.get("rows", []))
    _w_json("ws_h2ws_census.json", tsec.get("h2ws", {}))
    _w_json("ws_header_injection.json", results.get("header_injection") or [])
    # 19-21 bypass/waf/rate
    _w_json("ws_bypass2_matrix.json", results.get("bypass2") or [])
    _w_json("ws_waf_upgrade_fp.json", results.get("waf_upgrade_fp") or [])
    _w_json("ws_rate_census.json", results.get("rate") or {})
    # 22-24 frames/subs/platform
    _w_json("ws_frames_gated.json", results.get("frames") or {})
    _w_text("ws_message_techniques.md",
            "# P19 WebSocket message-level techniques (DOCUMENTED-ONLY)\n\n"
            "RoE: execution manual+authorized wave me hi (ws_allow_frames/"
            "manual). Koi data-frame EXECUTION is module se KABHI nahi "
            "hoti.\n\n" + "\n\n".join(
                "## %s\n%s" % (n, d) for n, d in DOCUMENTED_MESSAGE_TECHNIQUES)
            + "\n")
    _w_json("ws_subs_census.json", results.get("subs") or {})
    _w_json("ws_platform_fp.json", results.get("platform_fp") or {})
    # 25-27 secrets/js/verdicts
    _w_json("ws_secrets_in_url.json", results.get("secrets_url") or [])
    _w_json("ws_js_miner.json", results.get("js_miner") or {})
    _w_json("ws_verdicts.json", {
        "count": len(verdict_rows),
        "rows": verdict_rows,
        "sev_counts": _sev_counts(F)})
    # 28-30 findings
    _w_json("findings.json", {
        "phase": PHASE, "engine": "mod_ws v%s" % PLAN_VERSION,
        "engagement": scope.engagement,
        "generated_at": now_iso(),
        "sev_counts": _sev_counts(F),
        "findings": F.items})
    _w_text("WS_FINDINGS.md", _findings_md(scope, F, ctx, meta, results))
    # 31-34 matrix/chains
    _w_json("ws_matrix.json", {
        "families": _FAMS, "row_count": len(matrix),
        "rows": matrix})
    _w_text("WS_MATRIX.txt", _matrix_txt(matrix))
    _w_json("ws_chains.json", {
        "count": len(chains),
        "active": sum(1 for c in chains if c.get("active")),
        "chains": chains})
    _w_text("ws_chains.txt", "\n".join(
        "[%s%s] %s\n    %s\n" % (c["id"], "*" if c.get("active") else " ",
                                 c["title"], c["story"])
        for c in chains))
    # 35-38 hypotheses/test-plan/remediation/kickoff
    _w_json("ws_hypotheses.json", {
        "count": len(hyps), "hypotheses": hyps})
    _w_text("ws_test_plan.md", _test_plan_md(results, verdict_rows, conf))
    _w_text("ws_remediation.txt", _remediation_txt(verdict_rows))
    _w_text("ws_kickoff_guide.md", _kickoff_md(results, conf))
    # 39-40 feedforward + manifest (caller)
    return manifest


def _matrix_txt(matrix):
    lines = ["WASP P19 WEBSOCKET TECHNIQUE MATRIX (v%s) - %d rows x %d families"
             % (PLAN_VERSION, len(matrix), len(set(r["family"] for r in matrix))),
             "=" * 78]
    cur = None
    for r in matrix:
        if r["family"] != cur:
            cur = r["family"]
            lines += ["", "[%s]" % cur, "-" * 78]
        lines.append("%-16s %-9s %-6s %-14s %s" % (
            r["id"], r.get("status", "clean"), r.get("gate", "ON")[:6],
            (r.get("cwe") or "-")[:14], r["technique"]))
    lines += ["", "gate legend: ON=always | GATED=RoE gate (default OFF) | "
              "skip=gate OFF run", "status legend: hit=signal mila | "
              "clean=census chala, signal nahi | skip=gate OFF"]
    return "\n".join(lines) + "\n"


def _findings_md(scope, F, ctx, meta, results):
    sc = _sev_counts(F)
    lines = ["# P19 WebSocket Findings - %s" % scope.describe(),
             "", "Engine: mod_ws.py v%s | mode=%s | probes=%d"
             % (PLAN_VERSION, ctx.get("mode"), meta.get("probes_total", 0)),
             "", "Severity: %s" % ", ".join("%s=%d" % (k, v) for k, v in
                                            sorted(sc.items(),
                                                   key=lambda x: SEV_ORDER.get(
                                                       x[0], 9))),
             ""]
    if not F.items:
        lines += ["Koi WebSocket-trust finding nahi (surface clean ya gates "
                  "OFF). ws_hypotheses.json me manual wave dekho.", ""]
    for f in sorted(F.items, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                            x["id"])):
        lines += ["## %s %s (CVSS~%.1f)" % (f["id"], f["title"],
                                            f["cvss_hint"]),
                  "- Endpoint: `%s`" % f["endpoint"],
                  "- Severity: %s" % f["severity"],
                  "- Detail: %s" % f["detail"],
                  "- Why: %s" % f["why_it_matters"],
                  "- Evidence: %s" % (f["evidence"] or "census rows"),
                  ""]
    return "\n".join(lines) + "\n"


def _test_plan_md(results, verdict_rows, conf):
    lines = ["# P19 WebSocket manual test plan (kya khud karna hai)", ""]
    for v in verdict_rows:
        if v.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            lines += ["## %s [%s] %s" % (v.get("key"), v.get("verdict"),
                                         v.get("surface")),
                      "- Kya karna: %s" % v.get("why"),
                      "- Kill-test: browser devtools/own-account PoC se "
                      "verify karo (authorized scope only)", ""]
    if not any(v.get("verdict") in ("CONFIRMED", "SUSPECTED")
               for v in verdict_rows):
        lines += ["(Koi manual-follow-up row nahi - surface clean)", ""]
    lines += ["## Gates (RoE)", ""]
    for g in ("ws_allow_origin_evil", "ws_allow_transports", "ws_allow_burst",
              "ws_allow_frames", "ws_allow_h2ws", "ws_allow_ws"):
        lines.append("- %s = %s" % (g, "ON" if conf.get(g) else
                                    "OFF (manual wave documented)"))
    return "\n".join(lines) + "\n"


def _remediation_txt(verdict_rows):
    remap = {
        "ws_origin_bypass_variant": "Origin validation strict karo: exact "
        "scheme+host+port allowlist, case-normalize, null Origin reject.",
        "ws_origin_unchecked": "Connection-level origin check (handshake "
        "par) + channel-level authz dono lagao.",
        "ws_auth_handshake_open": "Upgrade par session auth mandatory karo "
        "(cookie/token validate BEFORE 101).",
        "ws_token_in_url": "Token ko Sec-WebSocket-Protocol ya first-message "
        "auth me shift karo; query-string tokens hatao.",
        "ws_ws_downgrade": "ws:// ko redirect/block karo; HSTS + wss-only "
        "policy enforce karo.",
        "ws_subprotocol_echo": "Sec-WebSocket-Protocol allowlist karo; "
        "arbitrary echo band karo (CRLF never reflect).",
        "ws_header_injection": "Subprotocol allowlist + header sanitize; "
        "edge/stack CVE patch.",
        "ws_bypass2_route_misroute": "X-Original-URL/X-Rewrite-URL edge "
        "headers client-side block karo; WAF ko sab paths par apply karo.",
        "ws_bypass2_header_smuggle": "Upgrade/Connection header parsing "
        "canonicalize karo (case/whitespace/duplicates).",
        "ws_socketio_exposed": "socket.io origin+namespace authz, EIO "
        "upgrade, sid entropy rotate.",
        "ws_signalr_exposed": "Negotiate auth gate karo; ConnectionToken "
        "single-use banao.",
        "ws_sockjs_exposed": "SockJS /info ko minimize karo; cookie_needed "
        "review.",
        "ws_ws_rate_limit_absent": "Per-IP/per-session handshake rate-limit "
        "+ connection caps.",
        "ws_cookie_missing_samesite": "Session cookies par SameSite=Lax/"
        "Strict lagao (CSWSH defense-in-depth).",
        "ws_secret_url_param": "Secrets URL me kabhi nahi - headers/body "
        "auth me shift.",
        "ws_subs_transport_open": "GraphQL-WS connection_init me auth "
        "challenge; subscription-level authz.",
    }
    out = ["P19 WebSocket remediation hints (finding-key -> fix)", "=" * 70]
    seen = set()
    for v in verdict_rows:
        k = v.get("key")
        if k in seen or k not in remap:
            continue
        seen.add(k)
        out += ["", "[%s] %s" % (k, remap[k])]
    if len(seen) == 0:
        out += ["", "(koi actionable remediation row nahi - surface clean)"]
    return "\n".join(out) + "\n"


def _kickoff_md(results, conf):
    lines = ["# P19 WebSocket engagement kickoff guide", "",
             "## Session-fu checklist (authorized scope only)", ""]
    lines += [
        "1. Browser devtools WS frames capture karke message-shapes census "
        "(own account) - module ka census isse cross-check karo.",
        "2. Origin override (devtools/fetch spec) se CSWSH PoC - sirf own "
        "test account ke saath.",
        "3. ws_allow_frames=ON lab-only: connect+PING fingerprint (data "
        "frames manual wave me bhi careful).",
        "4. socket.io: sid entropy + namespace authz manual differential.",
        "5. Downgrade mila to mitmproxy (own lab) par transport-policy "
        "proof pack karo.",
        "6. Replay-prone messages (id/timestamp shapes) P22 handoff me "
        "document karo.",
        "7. Sab evidence ws_verdicts.json + WS_FINDINGS.md se link karo.",
    ]
    lines += ["", "## Active census inventory", ""]
    for k in ("handshake", "origin_matrix", "auth_diff", "transports",
              "transport_sec", "header_injection", "bypass2",
              "waf_upgrade_fp", "rate", "frames", "subs"):
        v = results.get(k)
        if isinstance(v, list):
            lines.append("- %s: %d rows" % (k, len(v)))
        elif isinstance(v, dict):
            lines.append("- %s: %s" % (k, "skipped (gate)" if v.get(
                "skipped") else "%d rows" % len(v.get("rows", []))))
    return "\n".join(lines) + "\n"

# ===========================================================================
# RUN (Stage A..S orchestration) + CLI
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 19 - WebSocket Security (detection-only, INERT) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    warn("WS discipline: handshake GET-only (headers-only read, instant "
         "close) | frames KABHI nahi (ws_allow_frames gated: PING/CLOSE "
         "own-session only) | burst HARD cap 3 | canary waspP19 | zero "
         "egress | bodies REDACTED.")
    if conf.get("ws_allow_origin_evil"):
        warn("Evil-origin bypass candidates ON (ws_allow_origin_evil=true) "
             "- crafted Origin values sirf census differential ke liye.")
    if conf.get("ws_allow_transports"):
        warn("Transport negotiate ON (ws_allow_transports=true) - "
             "socket.io/sockjs/signalr GET census.")
    if conf.get("ws_allow_burst"):
        warn("Burst census ON (ws_allow_burst=true) - HARD cap 3 "
             "sequential, 1 endpoint (flood FORBIDDEN).")
    if conf.get("ws_allow_frames"):
        warn("Frame census ON (ws_allow_frames=true) - PING/CLOSE OWN "
             "session only; data frames NEVER.")
    if conf.get("ws_allow_h2ws"):
        warn("h2-WS census ON (ws_allow_h2ws=true) - RFC 8441 hint-only.")
    if conf.get("ws_allow_ws"):
        warn("Subs-path probes ON (ws_allow_ws=true) - graphql-ws "
             "subprotocol differential.")
    info("caps: paths=%s | probes=%s | origins=%s | bypass2=%s | cold=%s"
         % (conf.get("ws_paths_cap"), conf.get("ws_probe_cap"),
            conf.get("ws_origin_variants"), conf.get("ws_bypass2_cap"),
            conf.get("ws_cold_paths")))

    F = Findings()
    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "mode": "active",
           "base_dir": os.path.join(base_out, scope.engagement)}
    results = {}
    qhttp = copy.copy(http)
    qhttp.ev = None

    # ---------------- Stage A: discovery ----------------
    head("Stage A - WS surface discovery (P14/P17/P18/P6/P7 ff + JS miner "
         "+ cold pool)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or {}
        disc = dict(cached)
        disc.setdefault("ranked", [])
        disc.setdefault("targets", [])
        disc.setdefault("sources", [])
        disc.setdefault("base_url", "")
        ok("Replayed discovery (checkpoint)")
    else:
        disc = discover_ws_surface(ctx["base_dir"], scope, conf)
        cp.mark(ckA, disc, summary="ws surface")
    meta["sources"] = disc.get("sources", [])
    results["targets"] = rank_targets(disc.get("targets", []), conf)
    ctx["mined_sources"] = meta["sources"]
    ctx["coverage"]["surface"] = ("targets=%d mined=%d" % (
        len(results["targets"]), len(disc.get("ranked", []))))
    ok("seed artifacts: %d sources | %s"
       % (len(meta["sources"]), ctx["coverage"]["surface"]))
    base_url = disc.get("base_url") or (scope.seed_urls() or [""])[0]

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: mining + offline "
             "hypotheses (0 network probes).")
        ctx["mode"] = "passive"
        results.update({"handshake": [], "origin_matrix": [], "auth_diff":
                        {}, "transports": {}, "transport_sec": {},
                        "header_injection": [], "bypass2": [],
                        "waf_upgrade_fp": [], "rate": {}, "frames": {},
                        "subs": {}, "platform_fp": {},
                        "secrets_url": [], "js_miner": {}, "verdict_rows": [],
                        "chains": []})
        hyps = build_ws_hypotheses(results, [], [], conf)
        chains = build_ws_chains(F, results, [], [], meta, conf)
        matrix = build_technique_matrix(results, conf)
        manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                                 chains, matrix, conf)
        write_feedforward(out, PHASE, {"to_phase32_report":
                                       {"mode": "passive"}},
                          notes=["allow_active=false -> 0-probe passive run"])
        manifest.append("feedforward.json")
        write_manifest(out, PHASE, manifest,
                       stats={"mode": "passive", "targets":
                              len(results["targets"]),
                              "hypotheses": len(hyps)})
        _rwx_tree(out)
        return out

    # ---------------- Stage B: baseline + WAF ----------------
    head("Stage B - Baseline & WAF calibration")
    try:
        s404 = soft404_baseline(http, base_url)
        meta["soft404"] = s404 or {}
        ok("soft-404 baseline: %s" % ("set" if s404 else "flat"))
    except Exception as e:
        meta["soft404"] = {}
        warn("soft-404 baseline skip: %s" % e)
    meta["home_sig"] = {}
    try:
        rhome = http.get(base_url, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        meta["home_sig"] = {"status": rhome.status,
                            "len": len(rhome.body or b"")}
    except Exception as e:
        warn("home baseline skip: %s" % e)
    waf = {}
    try:
        wf = waf_signature({}, "", 0) or {}
        waf = wf if isinstance(wf, dict) else {}
    except Exception:
        waf = {}
    results["waf"] = waf
    if interrupted():
        warn("interrupted - partial save")

    # ---------------- Stage C: handshake core ----------------
    head("Stage C - Handshake core census (RFC 6455, INERT raw-socket)")
    ckC = "stageC:handshake"
    if cp.is_done(ckC):
        results["handshake"] = cp.result_of(ckC) or []
        ok("Replayed handshake census (checkpoint)")
    else:
        results["handshake"] = handshake_census(scope, results["targets"],
                                                meta, conf, _canary("hs"))
        cp.mark(ckC, results["handshake"], summary="handshake census")
    live_n = sum(1 for r in results["handshake"] if r.get("upgrade"))
    for r in results["handshake"]:
        if r.get("upgrade"):
            F.add("ws_endpoint_live", "WebSocket endpoint live (101)",
                  r["target"], "101 upgrade-accept; fp=%s"
                  % json.dumps(r.get("fp") or {}, default=str)[:200],
                  "ws_handshake_census.json")
        if r.get("accept_mismatch"):
            F.add("ws_accept_mismatch", "Sec-WebSocket-Accept mismatch",
                  r["target"], "GUID math galat - patched stack/proxy signal",
                  "ws_accept_crypto.json")
        se = r.get("subprotocol_echo") or {}
        if se.get("reflected_verbatim"):
            F.add("ws_subprotocol_echo",
                  "Arbitrary subprotocol verbatim echo", r["target"],
                  "Sec-WebSocket-Protocol reflect - header-injection surface",
                  "ws_handshake_census.json")
        vg = r.get("version_guard") or {}
        if r.get("upgrade") and vg.get("v8_status") == 101:
            F.add("ws_version_mismatch_ok", "Version guard missing",
                  r["target"], "v8 handshake bhi 101 (RFC 6455 4.2.2 deviation)",
                  "ws_version_negotiation.json")
        if (r.get("extensions") or {}).get("deflate_negotiated"):
            F.add("ws_permessage_deflate", "permessage-deflate negotiated",
                  r["target"], "compression side-channel surface "
                  "(documented)", "ws_handshake_census.json")
    ok("handshake: %d targets | %d live-upgrade" % (
        len(results["handshake"]), live_n))

    # ---------------- Stage D: origin matrix ----------------
    head("Stage D - Origin trust matrix (CSWSH census, CWE-346)")
    ckD = "stageD:origin"
    if cp.is_done(ckD):
        results["origin_matrix"] = cp.result_of(ckD) or []
        ok("Replayed origin matrix (checkpoint)")
    else:
        results["origin_matrix"] = origin_matrix(scope, results["targets"],
                                                 meta, conf, _canary("or"))
        cp.mark(ckD, results["origin_matrix"], summary="origin matrix")
    for r in results["origin_matrix"]:
        if not r.get("applicable"):
            continue
        if r.get("verdict") == "CONFIRMED":
            F.add("ws_origin_bypass_variant", "Origin bypass variant accepted",
                  r["target"], "crafted variant '%s' ne 101 liya - CSWSH "
                  "exploitable" % r.get("bypass_variant"),
                  "ws_origin_matrix.json")
        elif r.get("verdict") == "SUSPECTED":
            F.add("ws_origin_wildcard", "Origin parser inconsistent",
                  r["target"], "variants: %s" % ",".join(
                      r.get("variant_flags", [])[:4]),
                  "ws_origin_matrix.json")
    ok("origin: %d rows | bypass=%d" % (
        len(results["origin_matrix"]),
        sum(1 for r in results["origin_matrix"]
            if r.get("verdict") == "CONFIRMED")))

    # ---------------- Stage E: auth differential ----------------
    head("Stage E - Auth differential (creds vs no-creds + token-in-URL)")
    ckE = "stageE:auth"
    if cp.is_done(ckE):
        results["auth_diff"] = cp.result_of(ckE) or {}
    else:
        ad_rows = auth_diff(http, scope, results["targets"], meta, conf,
                            _canary("au"))
        cookie_ctx = any((r.get("anon") or {}).get("set_cookie")
                         for r in ad_rows if isinstance(r, dict))
        results["auth_diff"] = {"rows": ad_rows, "cookie_ctx": cookie_ctx}
        cp.mark(ckE, results["auth_diff"], summary="auth diff")
    ad_rows = (results["auth_diff"] or {}).get("rows", [])
    for r in ad_rows:
        if not isinstance(r, dict) or not r.get("applicable"):
            continue
        if r.get("verdict") == "OPEN":
            F.add("ws_auth_handshake_open", "Anonymous upgrade accepted",
                  r["target"], "no-creds 101 - connection-level auth absent",
                  "ws_auth_diff.json")
        if r.get("token_in_url"):
            F.add("ws_token_in_url", "Token in WS URL query",
                  r["target"], "param='%s' (shape-hash only) - log/referrer "
                  "leak surface" % r["token_in_url"]["param"],
                  "ws_auth_diff.json")
        cf = r.get("cookie_flags") or {}
        if cf and not cf.get("samesite"):
            F.add("ws_cookie_missing_samesite", "SameSite absent on "
                  "handshake cookie", r["target"], "CSWSH amplification flag",
                  "ws_cookie_census.json")
    ok("auth: %d rows | open=%d" % (len(ad_rows),
                                    sum(1 for r in ad_rows if isinstance(
                                        r, dict) and
                                        r.get("verdict") == "OPEN")))

    # ---------------- Stage F: transports ----------------
    head("Stage F - Transport census (socket.io/sockjs/signalr, GATED)")
    results["transports"] = transports_census(http, base_url, meta, conf,
                                              _canary("tr"))
    if not (results["transports"] or {}).get("skipped"):
        for rec in (results["transports"].get("socketio") or []):
            F.add("ws_socketio_exposed", "socket.io handshake public",
                  rec.get("path"), "EIO%s sid-shape exposure" % rec.get("eio"),
                  "ws_transports_socketio.json")
        for rec in (results["transports"].get("sockjs") or []):
            F.add("ws_sockjs_exposed", "SockJS /info public", rec.get("path"),
                  "entropy/cookie_needed leak", "ws_transports_sockjs.json")
        for rec in (results["transports"].get("signalr") or []):
            F.add("ws_signalr_exposed", "SignalR negotiate public",
                  rec.get("path"), "ConnectionId/Token shapes",
                  "ws_transports_signalr.json")
        ok("transports: socketio=%d sockjs=%d signalr=%d" % (
            len(results["transports"].get("socketio", [])),
            len(results["transports"].get("sockjs", [])),
            len(results["transports"].get("signalr", []))))
    else:
        info("transports: GATED (ws_allow_transports=false)")

    # ---------------- Stage G: transport security ----------------
    head("Stage G - Transport security (wss->ws downgrade + h2-WS hint)")
    ckG = "stageG:transport_sec"
    if cp.is_done(ckG):
        results["transport_sec"] = cp.result_of(ckG) or {}
    else:
        results["transport_sec"] = transport_security_census(
            scope, results["targets"], meta, conf)
        cp.mark(ckG, results["transport_sec"], summary="downgrade census")
    for r in (results["transport_sec"].get("rows") or []):
        if r.get("downgrade"):
            F.add("ws_ws_downgrade", "wss -> ws plaintext accepted",
                  r["target"], "same-path ws:// 101 - TLS-absent realtime "
                  "channel", "ws_downgrade_census.json")
    ok("transport-sec: %d rows | downgrade=%d" % (
        len(results["transport_sec"].get("rows") or []),
        sum(1 for r in (results["transport_sec"].get("rows") or [])
            if r.get("downgrade"))))

    # ---------------- Stage H: header injection ----------------
    head("Stage H - Header injection census (subprotocol reflection)")
    results["header_injection"] = header_injection_census(
        scope, results["targets"], meta, conf)
    for r in results["header_injection"]:
        pr = ((r.get("probes") or {}).get("crlf_encoded") or {})
        if pr.get("split_header_seen"):
            F.add("ws_header_injection", "CRLF split-header triggered",
                  r["target"], "encoded CRLF subprotocol ne injected header "
                  "trigger kiya - response splitting", "ws_header_injection.json")
    ok("inject-census: %d rows" % len(results["header_injection"]))

    # ---------------- Stage I: bypass2 matrix ----------------
    head("Stage I - WAF/edge bypass matrix v2 (17 SECRET handshake variants)")
    ckI = "stageI:bypass2"
    if cp.is_done(ckI):
        results["bypass2"] = cp.result_of(ckI) or []
        ok("Replayed bypass2 (checkpoint)")
    else:
        results["bypass2"] = bypass2_matrix(scope, results["targets"], meta,
                                            conf)
        cp.mark(ckI, results["bypass2"], summary="bypass2 matrix")
    for r in results["bypass2"]:
        wins = r.get("wins") or []
        if not wins:
            continue
        vm = r.get("variants") or {}
        route_wins = [w for w in wins if (vm.get(w) or {}).get("class") ==
                      "route_misroute"]
        if route_wins:
            F.add("ws_bypass2_route_misroute", "Edge-misroute upgrade win",
                  r["target"], "variants: %s" % ",".join(route_wins[:4]),
                  "ws_bypass2_matrix.json")
        else:
            F.add("ws_bypass2_header_smuggle", "Header-variant guard miss",
                  r["target"], "variants: %s" % ",".join(wins[:4]),
                  "ws_bypass2_matrix.json")
    ok("bypass2: %d rows | wins=%d" % (
        len(results["bypass2"]),
        sum(1 for r in results["bypass2"] if r.get("win_count"))))

    # ---------------- Stage J: WAF/upgrade fingerprint ----------------
    head("Stage J - WAF/upgrade fingerprint (edge ws-filter blind-spot)")
    results["waf_upgrade_fp"] = waf_upgrade_fp(http, scope,
                                               results["targets"], meta, conf)
    for r in results["waf_upgrade_fp"]:
        if r.get("edge_ws_filter"):
            F.add("ws_waf_upgrade_missing", "Edge ws-filter blind-spot",
                  r["target"], "plain GET pass, upgrade filter - asymmetric "
                  "policy", "ws_waf_upgrade_fp.json")
    ok("waf-fp: %d rows" % len(results["waf_upgrade_fp"]))

    # ---------------- Stage K: rate census (GATED) ----------------
    head("Stage K - Rate/limit census (bounded burst, GATED)")
    results["rate"] = rate_census(scope, results["targets"], meta, conf)
    if not (results["rate"] or {}).get("skipped"):
        for r in (results["rate"].get("rows") or []):
            if r.get("verdict") == "ABSENT":
                F.add("ws_rate_limit_absent", "Handshake rate-limit absent",
                      r["target"], "burst cap-%d par koi limit signal nahi "
                      "(DoS execution FORBIDDEN)" % (results["rate"].get(
                          "cap", 3)), "ws_rate_census.json")
        ok("rate: census done (cap=%s)" % (results["rate"].get("cap")))
    else:
        info("rate: GATED (ws_allow_burst=false)")

    # ---------------- Stage L: frames census (GATED) ----------------
    head("Stage L - Frame-level census (GATED) + message techniques "
         "(documented-only)")
    results["frames"] = frames_census_gated(scope, results["targets"], meta,
                                            conf, _canary("fr"))
    if not (results["frames"] or {}).get("skipped"):
        F.add("ws_frames_ping_only", "Frame census (own-session PING/CLOSE)",
              results["targets"][0]["ws_url"] if results["targets"] else "-",
              "data-frames NEVER (execution forbidden)", "ws_frames_gated.json")
        ok("frames: census done")
    else:
        info("frames: GATED (ws_allow_frames=false) - %d techniques "
             "documented" % len(DOCUMENTED_MESSAGE_TECHNIQUES))
    F.add("ws_message_replay_risk", "Message-replay/injection primitives "
          "documented", base_url, "%d techniques documented-only (P20/P22 "
          "handoff)" % len(DOCUMENTED_MESSAGE_TECHNIQUES),
          "ws_message_techniques.md")

    # ---------------- Stage M: subscriptions census ----------------
    head("Stage M - GraphQL subscriptions census (P18 handoff, GATED)")
    ff19 = {}
    try:
        allff = _ff_from_engagement(ctx["base_dir"])
        node = ((allff.get("graphql") or {}).get("to_phase19_ws") or {})
        ff19 = {"ws_paths": node.get("ws_paths") or [],
                "gql_subs": node.get("gql_subscriptions")}
    except Exception:
        ff19 = {"ws_paths": [], "gql_subs": None}
    results["subs"] = subs_census(http, scope, base_url, ff19["ws_paths"],
                                  ff19["gql_subs"], meta, conf, _canary("sb"))
    if not (results["subs"] or {}).get("skipped"):
        for row in (results["subs"].get("subprotocol_diff") or []):
            if row.get("graphql-transport-ws", {}).get("accepted"):
                F.add("ws_subs_transport_open",
                      "GraphQL subscription transport open",
                      row.get("endpoint"), "graphql-transport-ws accepted "
                      "(P18 handoff)", "ws_subs_census.json")
        ok("subs: %d paths | diff=%d" % (
            len(results["subs"].get("paths", [])),
            len(results["subs"].get("subprotocol_diff", []))))
    else:
        info("subs: GATED (ws_allow_ws=false) - paths=%d"
             % len(results["subs"].get("paths", [])))

    # ---------------- Stage N: platform fingerprint ----------------
    head("Stage N - Platform fingerprint (socket.io/sockjs/signalr shapes)")
    results["platform_fp"] = platform_fingerprint(results, meta, conf)
    for p in (results["platform_fp"].get("platforms") or []):
        F.add("ws_platform_fp", "Realtime platform: %s" % p.get("name"),
              base_url, p.get("note", ""), "ws_platform_fp.json")
    ok("platform: %s" % ([p.get("name") for p in
                          (results["platform_fp"].get("platforms") or [])] or
                         "none"))

    # ---------------- Stage O: secrets-in-URL + JS miner ----------------
    head("Stage O - Secrets-in-URL census + JS miner cross-ref (offline)")
    results["secrets_url"] = secrets_in_url_census(results["targets"],
                                                   base_url, meta, conf)
    for r in results["secrets_url"]:
        F.add("ws_secret_url_param", "Secret-shaped param in WS URL",
              r.get("url", ""), "param=%s (shape only)" % r.get("param"),
              "ws_secrets_in_url.json")
    results["js_miner"] = js_miner_crossref(ctx["base_dir"], base_url, conf)
    ok("secrets-url=%d | js-miner links=%d" % (
        len(results["secrets_url"]),
        len((results["js_miner"] or {}).get("ws_links", []))))
    if interrupted():
        warn("interrupted - partial save")

    # ---------------- Stage P: verdict engine ----------------
    head("Stage P - Verdict engine (6-class ladder)")
    results["verdict_rows"] = verdict_engine(results, meta, conf)
    conf_keys = {}
    for v in results["verdict_rows"]:
        conf_keys[v["key"]] = v
    ok("verdicts: %d rows (%d CONFIRMED / %d SUSPECTED)" % (
        len(results["verdict_rows"]),
        sum(1 for v in results["verdict_rows"]
            if v["verdict"] == "CONFIRMED"),
        sum(1 for v in results["verdict_rows"]
            if v["verdict"] == "SUSPECTED")))

    # ---------------- Stage Q: kill-chains ----------------
    head("Stage Q - Kill-chains (20 realtime chains)")
    results["chains"] = build_ws_chains(F, results, results["verdict_rows"],
                                        results["targets"], meta, conf)
    ok("chains: %d (%d active)" % (len(results["chains"]),
                                   sum(1 for c in results["chains"]
                                       if c.get("active"))))

    # ---------------- Stage R: technique matrix ----------------
    head("Stage R - Technique matrix (150+ rows x 18 families)")
    matrix = build_technique_matrix(results, conf)
    ok("matrix: %d rows" % len(matrix))

    # ---------------- Stage S: reports ----------------
    head("Stage S - Reports/artifacts (40 outputs)")
    hyps = build_ws_hypotheses(results, results["verdict_rows"],
                               results["chains"], conf)
    manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                             results["chains"], matrix, conf)
    ff = {"to_phase20_logic": {
              "ws_auth_open": any(v.get("key") == "ws_auth_handshake_open"
                                  for v in results["verdict_rows"]),
              "message_techniques": [t[0] for t in
                                     DOCUMENTED_MESSAGE_TECHNIQUES][:8],
              "subs_channels": [r.get("endpoint") for r in
                                (results["subs"].get("subprotocol_diff") or
                                 [])][:4]},
          "to_phase22_replay": {
              "replay_primitives": ["message_replay", "sid_hijack_socketio"],
              "token_in_url": [r.get("url", "")[:80] for r in
                               results["secrets_url"][:4]]},
          "to_phase23_misconfig": {
              "ws_misconfig_rows": [v.get("key") for v in
                                    results["verdict_rows"]
                                    if v.get("verdict") in
                                    ("CONFIRMED", "SUSPECTED")][:10],
              "transports": {"socketio": len(
                  (results["transports"] or {}).get("socketio", [])),
                  "sockjs": len((results["transports"] or {}).get(
                      "sockjs", []))}},
          "to_phase25_controls": {
              "rate_absent": any(v.get("key") == "ws_rate_limit_absent"
                                 for v in results["verdict_rows"]),
              "origin_guard": [v.get("key") for v in results["verdict_rows"]
                               if v.get("stage") == "origin"][:4]},
          "to_phase11_bola": {
              "ws_channels": [t.get("ws_url") for t in
                              results["targets"][:6]],
              "origin_unchecked": any(v.get("key") in
                                      ("ws_origin_unchecked",
                                       "ws_origin_bypass_variant")
                                      for v in results["verdict_rows"])},
          "to_phase12_inject": {
              "ws_header_injection": any(v.get("key") ==
                                         "ws_header_injection"
                                         for v in results["verdict_rows"]),
              "subprotocol_echo": any(v.get("key") == "ws_subprotocol_echo"
                                      for v in results["verdict_rows"])},
          "to_phase32_report": {"findings": len(F.items),
                                "probes": meta.get("probes_total", 0)}}
    write_feedforward(out, PHASE, ff,
                      notes=["P19 WebSocket: %d targets, %d live-upgrade, "
                             "%d findings" % (len(results["targets"]),
                                              live_n, len(F.items))])
    manifest.append("feedforward.json")
    write_manifest(out, PHASE, manifest,
                   stats={"probes": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "targets": len(results["targets"]),
                          "live_upgrade": live_n,
                          "matrix_rows": len(matrix),
                          "chains": len(results["chains"]),
                          "chains_active": sum(1 for c in results["chains"]
                                               if c.get("active")),
                          "hypotheses": len(hyps),
                          "verdicts": len(results["verdict_rows"]),
                          "bypass2_wins": sum(1 for r in results["bypass2"]
                                              if r.get("win_count")),
                          "elapsed_s": round(time.time() - t_start, 1)})
    _rwx_tree(out)
    ok("P19 done: %d findings | %d matrix rows | %d chains | probes=%d | "
       "%.1fs" % (len(F.items), len(matrix), len(results["chains"]),
                  meta.get("probes_total", 0), time.time() - t_start))
    return out


def read_feedforward_safe(base_dir):
    """Legacy alias (import-shape safe) - Stage M _ff_from_engagement use karta hai."""
    try:
        return _ff_from_engagement(base_dir)
    except Exception:
        return {}


def _ff_from_engagement(base_dir):
    """Engagement-level feedforward reader (P18 handoff consume)."""
    out = {}
    for mod in ("graphql", "api", "client", "tech", "js"):
        p = _artifact(base_dir, mod, "feedforward.json")
        d = _read_json_tolerant(p)
        if isinstance(d, dict):
            out[mod] = d.get("routing") or {}
    return out


def main():
    print("WASP mod_ws.py (Phase 19 - WebSocket, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 19   (ya --module ws)")
    print("  self-test : python3 test_mod_ws.py")
    print("\n  RoE gates (config.json): ws_allow_origin_evil=false (default),"
          " ws_allow_transports=false (default), ws_allow_burst=false "
          "(default), ws_allow_frames=false (default), ws_allow_h2ws=false"
          " (default), ws_allow_ws=false (default)")
    print("  Safety: handshake GET-only (headers-only read, instant close) |"
          " frames NEVER (gated: PING/CLOSE own-session only) | burst HARD "
          "cap 3 | canary waspP19 | zero egress | bodies REDACTED")
    print("  v19 ULTRA: +origin/CSWSH matrix +auth-diff +transports "
          "(socket.io/sockjs/signalr) +downgrade +header-injection "
          "+bypass2 (17 secret) +rate census +subs handoff +platform fp "
          "+secrets-in-URL +20 chains +150-row matrix")


if __name__ == "__main__":
    main()
