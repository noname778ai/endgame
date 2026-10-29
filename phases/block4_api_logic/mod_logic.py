#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_logic.py  |  Phase 20 - Business Logic Security ULTRA PRO MAX
           (Price-Tamper/Workflow-Skip/Race-Surface/Coupon-Oracle/Negative-Edge)
=======================================================================================
v20.0.0 FULL ULTRA PRO MAX (koi ek line ki bhi kami nahi - all to all
techniques: hacking hidden secrets + security bypasses + new & old methods).
Authorized security testing ONLY. Scope firewall + rate limiter + request
budget + evidence + checkpoint sab wasp_core se inherit hote hain, isliye
har census request scope-check, rate-limit aur budget ke andar hi jaati hai.

KYA KARTA HAI
  Business logic flaws automation se NAHI pakde jaate - isliye P20 ka kaam
  hai: (1) LOGIC SURFACE ka poora census (kaunse endpoints paisa/state/
  entitlement handle karte hain), (2) har surface par VALIDATION-ORDER ka
  INERT differential (canary values se sirf validation behavior observe),
  (3) jo execution-class techniques hain (real race, real redeem) unka
  DOCUMENTED-ONLY playbook + GATED micro-census (2-request hard cap,
  sequential, canary-only). "MERA app ka business trust kahan tak todta
  hai?" -> 20 stages (A..T):

    A. Logic surface discovery - 13-module feedforward (P2 payment_forms,
       P5 endpoints, P7 hints, P8 queue, P10 logout, P11 idor, P12 deser,
       P14 state-writes, P16 uploads, P17 mass-assign, P18 writable,
       P19 ws-open) + verb/price/state param census + 26-path cold pool
    B. Baseline + WAF         - home marker + soft-404 + WAF fingerprint
    C. Param/state census     - GET forms/hidden-fields/state-params/
                                price-params mining (names-only redaction)
    D. Hidden-param matrix    - canary param echo census (mass-assignment
                                surface; GATED logic_allow_param_echo)
    E. Price/qty tamper       - canary value-matrix validation differential
                                (negative/zero/decimal/huge/type-juggle;
                                GATED logic_allow_price_probe; kabhi real
                                transaction NAHI - canary ids never exist)
    F. Workflow/state-machine - multi-step flow map + step-skip differential
                                (direct-step GET census; GATED
                                logic_allow_workflow_probe; depth cap 4)
    G. Race-condition surface - 10 techniques DOCUMENTED-ONLY + GATED
                                idempotency census (logic_allow_race_probe;
                                2 sequential canary requests HARD cap; NO
                                parallel burst KABHI)
    H. Coupon/redeem oracle   - canary code validation shapes + case/whitespace
                                variants census (GATED logic_allow_coupon_probe)
    I. Numeric edge oracle    - points/credits/bid-shaped fields par structured
                                canary values (validation-error observation)
    J. Bypass matrix v2       - 17 SECRET logic-bypass techniques (HPP price,
                                JSON type-confusion, duplicate-keys, array-
                                params, plus/hex/unicode numerics, negative-
                                zero, null-price, dot-segment step normalize,
                                X-Original-URL step route...)
    K. Authz-context diff     - anon vs canary-cookie differential + re-auth
                                census + CSRF-token census (client trust)
    L. Cross-module chains    - IDOR->price, mass-assign->role, upload->
                                invoice-forgery, ws-open->bid-abuse, deser->
                                logic (P11/P12/P14/P16/P17/P18/P19 handoffs)
    M. Anti-automation census - CSRF/idempotency/signing/confirmation/rate
                                positive-controls (HARDENED evidence)
    N. Platform fingerprint   - commerce/subscription/payment stack shapes
                                (census-only, zero PAN data)
    O. State/secret leaks     - client-trusted totals, state blobs, test SKUs,
                                debug-priced items, coupon-list leaks
    P. Verdict engine         - 6-class ladder (CONFIRMED/SUSPECTED/HARDENED/
                                BLOCKED/SKIPPED/NOISE) multi-signal
    Q. Kill-chains            - 20 business-logic attack chains
    R. Technique matrix       - 150+ rows x 18 families + CWE + MITRE map
    S. Reports/artifacts      - 40+ artifacts: findings.json, LOGIC_FINDINGS.md,
                                LOGIC_MATRIX.txt, census JSONs, test-plan,
                                remediation, kickoff guide
    T. Handoff & manifest     - feedforward (to_phase21/22/23/25/11/12/32),
                                MANIFEST, RWX-tree finalize

VERDICT LADDER (6-class, P12..P19-compatible)
  CONFIRMED   -> multi-signal proof (canary value accepted by validation on
                 live endpoint; role-param echoed into privileged context;
                 later workflow step 200 without prior step)
  SUSPECTED   -> partial/single signal (echo without privilege context,
                 client-trust shape without server confirmation)
  HARDENED    -> defense present (server-side validation rejects canary,
                 CSRF/idempotency/re-auth present, step guard enforced)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (business logic 'state-trust' hai - P15..P19 jitni strict
discipline)
  * 100% INERT: koi REAL transaction/redeem/transfer/withdraw KABHI nahi
    hota. Har probe synthetic canary identifiers (waspP20 family) use karta
    hai jo server par EXIST NAHI karte - isliye koi state change possible
    hi nahi. Value probes sirf validation-observable paths par jaate hain
    (invalid canary object -> validation error -> behavior fingerprint).
  * RACE EXECUTION FORBIDDEN: koi parallel burst, koi concurrent flood nahi.
    Race techniques sirf DOCUMENTED (playbook). Gated census bhi 2
    SEQUENTIAL canary requests se zyada kabhi nahi (idempotency-key +
    dedup-signal census) - true race exploitation manual+RoE wave hai.
  * ZERO EXTERNAL EGRESS: har HTTP probe scope-check se pehle blocked
    (wasp_core LAYER-4). canary TLD sirf .invalid.
  * REDACTION: response bodies store NAHI hote - sirf status/sha1/param-
    names/booleans. Values canary-marked, PII regex redaction har detail par.
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
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 20")
    sys.exit(1)

NAME = "logic"
PHASE = "20-logic"
PLAN_VERSION = "20.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    "logic_paths_cap": 18,            # mined/candidate logic-path cap (ranking)
    "logic_probe_cap": 8,             # active census target cap
    "logic_cold_paths": 26,           # cold path-pool size (discovery)
    "logic_param_cap": 12,            # hidden-param canary matrix width
    "logic_value_cap": 8,             # price/edge value-matrix cap per endpoint
    "logic_workflow_depth": 4,        # step-chain depth census cap
    "logic_bypass2_cap": 17,          # SECRET bypass-v2 technique cap
    # ---- RoE GATES (default OFF - sirf authorized+lab runs me ON) ----
    "logic_allow_price_probe": False,   # GATE: canary price/value validation differential
    "logic_allow_race_probe": False,    # GATE: 2-request sequential idempotency census
    "logic_allow_workflow_probe": False,# GATE: step-skip GET differential census
    "logic_allow_param_echo": False,    # GATE: canary hidden-param echo census
    "logic_allow_coupon_probe": False,  # GATE: canary coupon validation oracle
    "logic_allow_role_probe": False,    # GATE: role/privilege param differential
    # ---- v20 ULTRA tunables ----
    "logic_platform_fp": True,        # commerce/payment fingerprint (census)
    "logic_secrets_state": True,      # client-trust/state-leak census (offline)
    "logic_forms_mine": True,         # stored form bodies miner (offline)
    "logic_chain_build": True,        # cross-module logic chains
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
# SEVERITY CLASSIFICATION (P12..P19 pattern - key -> sev/cvss/why)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / surface ----
    "logic_endpoint_live":        ("info", 0.0, "Business-logic endpoint live "
        "mila (state/paisa/entitlement verb shape) - poora logic engine ab "
        "is surface par chalega (P20 core)."),
    "logic_candidate_path":       ("info", 0.0, "Logic candidate path mined - "
        "ranking ke through census me jaayega."),
    "logic_verb_census":          ("low", 3.1, "Commerce/state verb-shape "
        "(order|redeem|transfer|withdraw...) census - business-flow map "
        "(targeting aid)."),
    "logic_state_param":          ("low", 3.4, "State/workflow-shaped param "
        "(step|stage|phase|status) census - state-machine surface flag."),
    "logic_price_param":          ("low", 3.5, "Price/amount-shaped param "
        "census - tamper-surface enumeration (values canary-only)."),
    # ---- client trust / price ----
    "logic_client_trust_price":   ("high", 7.9, "Total/price client-side form "
        "me hai (hidden/computed field) - server-side recalculation absent "
        "signal (CWE-602; classic price-tamper primitive)."),
    "logic_price_probe_confirmed": ("critical", 9.1, "Canary price/value "
        "validation se ACCEPT hua (negative/zero/decimal variant) - "
        "server-side amount validation missing (CWE-20; koi real charge "
        "nahi - canary object never exists; CONFIRMED tamper surface)."),
    "logic_price_probe_suspected": ("high", 7.4, "Price validation differential "
        "partial - kuch variants reject, kuch echo - inconsistent amount "
        "parsing (CWE-20 suspect)."),
    "logic_currency_confusion":   ("high", 7.5, "Currency-shaped param multiple "
        "formats accept (minor-unit vs major-unit shapes) - rounding/truncation "
        "surface (CWE-20; documented aid)."),
    "logic_rounding_edge":        ("medium", 6.2, "Decimal/truncation edge "
        "signal canary values par - rounding-policy review aid."),
    # ---- workflow / state machine ----
    "logic_workflow_skip":        ("critical", 8.6, "Later workflow step bina "
        "prior completion direct-access ho gaya (GET census) - server-side "
        "step-validation missing (CWE-840; checkout/auth flow bypass)."),
    "logic_workflow_state_client": ("high", 7.8, "Step/state param "
        "client-controlled echo - state machine client-trust (CWE-602)."),
    "logic_workflow_map":         ("info", 0.0, "Multi-step flow map ban gaya "
        "(cart->address->payment->confirm shapes) - manual wave guide."),
    "logic_referer_trust":        ("medium", 6.0, "Referer-dependent step-gate "
        "signal (direct GET par bhi step content) - gate client-side hai "
        "(CWE-602 suspect)."),
    # ---- hidden params / mass assignment ----
    "logic_param_echo":           ("high", 7.2, "Canary hidden param server ne "
        "echo/accept kiya - mass-assignment surface (CWE-915; P17/P18 handoff "
        "cross-ref)."),
    "logic_role_param_echo":      ("critical", 8.5, "Role/privilege-shaped "
        "param (role|is_admin|premium) echo hua - privilege-assignment "
        "surface (CWE-915 high-impact variant)."),
    "logic_massassign_crossref":  ("high", 7.3, "P17/P18 handoff mass-assign/"
        "writable-sensitive targets logic surface se overlap - chained "
        "escalation candidate."),
    # ---- race / idempotency ----
    "logic_race_surface":         ("high", 7.6, "Race-condition primitives "
        "DOCUMENTED (double-redeem/TOCTOU/parallel-withdraw...) - execution "
        "RoE+manual wave (koi concurrent request KABHI nahi)."),
    "logic_idempotency_absent":   ("high", 7.3, "State-changing op par "
        "idempotency-key signal absent - double-submit/race hardening gap "
        "(CWE-841 flag)."),
    "logic_idempotency_present":  ("info", 0.0, "Idempotency-key accept/echo "
        "signal (positive control, HARDENED evidence)."),
    "logic_dedup_absent":         ("medium", 5.9, "2 sequential canary requests "
        "par identical accept-shape - dedup signal absent (census; execution "
        "FORBIDDEN)."),
    # ---- coupon / redeem / limits ----
    "logic_coupon_oracle":        ("medium", 5.8, "Coupon validation differential "
        "observable (canary codes) - brute/enumeration surface flag (koi brute "
        "EXECUTION nahi)."),
    "logic_coupon_accepted_any":  ("critical", 8.8, "Canary coupon code (kabhi "
        "issue nahi hua) ACCEPT hua - discount validation missing (CWE-20; "
        "CONFIRMED)."),
    "logic_coupon_case_edge":     ("medium", 5.6, "Case/whitespace variant "
        "differential signal coupon validation par - normalization gap "
        "(CWE-178 suspect)."),
    "logic_limit_absent":         ("medium", 5.9, "Redeem/attempt limit signal "
        "absent (census) - enumeration/flood surface flag (DoS execution "
        "FORBIDDEN)."),
    "logic_test_sku":             ("low", 3.9, "Test/sandbox-shaped SKU/item "
        "exposed (test|demo|sandbox|0.00 shapes) - environment bleed flag."),
    # ---- negative / edge values ----
    "logic_negative_accepted":    ("critical", 8.9, "Negative-amount canary "
        "validation pass - reverse-payment surface (CWE-20 CONFIRMED shape)."),
    "logic_zero_accepted":        ("critical", 8.7, "Zero-amount canary "
        "validation pass - free-checkout surface (CWE-20 CONFIRMED shape)."),
    "logic_huge_accepted":        ("high", 7.7, "Oversized-amount canary "
        "validation pass (10^9-shape) - overflow/credit surface (CWE-190 "
        "flag; canary-only)."),
    "logic_type_juggle":          ("high", 7.4, "String-in-numeric canary "
        "accept - type-confusion validation gap (CWE-843)."),
    "logic_value_oracle":         ("medium", 5.7, "Numeric edge-oracle "
        "differential census (points/credits/bid shapes) - validation-order "
        "fingerprint."),
    # ---- authz context / anti-automation ----
    "logic_no_csrf_state_change": ("high", 7.9, "State-changing form par CSRF "
        "token absent (form census) - CSRF-amplified logic abuse (CWE-352)."),
    "logic_no_reauth":            ("medium", 6.5, "Sensitive action "
        "(transfer/withdraw/password) par re-auth census absent - session-"
        "hijack amplified impact (CWE-640 flag)."),
    "logic_privilege_preauth":    ("high", 7.7, "Privileged-shaped action "
        "anon-context GET par reachable content de gaya - authz gap "
        "(CWE-862 suspect; canary census)."),
    "logic_anti_auto_present":    ("info", 0.0, "Anti-automation positive "
        "control (signing/confirmation/limit) - HARDENED evidence."),
    # ---- platform / leaks ----
    "logic_platform_fp":          ("low", 3.3, "Commerce/payment platform "
        "fingerprint (census-only) - platform-specific known-bypass research "
        "aid (targeting)."),
    "logic_state_leak":           ("medium", 5.9, "State blob / unsigned "
        "workflow state client me leaked (shape census) - tamper surface "
        "(CWE-345 flag)."),
    "logic_coupon_list_leak":     ("medium", 5.5, "Coupon/campaign listing "
        "shape public census - promo-abuse recon aid."),
    "logic_signed_amount":        ("low", 3.8, "Signed-amount shape (HMAC/JWT-"
        "shaped total field) - tamper-resistance signal (review aid)."),
    # ---- chains / bypass2 ----
    "logic_chain_idor_price":     ("critical", 9.0, "P11 CONFIRMED IDOR object "
        "x price-param overlap - order-manipulation chain (P11 handoff)."),
    "logic_chain_massassign_role": ("critical", 8.9, "Mass-assign/role-echo x "
        "logic surface overlap - privilege-escalation chain."),
    "logic_chain_ws_bid":         ("high", 7.8, "P19 ws-auth-open x realtime "
        "bid/trade surface - live-state manipulation chain candidate."),
    "logic_chain_upload_invoice": ("high", 7.4, "P16 upload x invoice/receipt "
        "surface - document-forgery chain candidate."),
    "logic_bypass2_param_smuggle": ("high", 7.7, "Param-level variant (HPP/"
        "duplicate-key/array/type-confusion) ne validation miss kiya - parser "
        "differential (CWE-436/915)."),
    "logic_bypass2_route_misroute": ("critical", 8.7, "Edge-misroute technique "
        "(X-Original-URL/dot-segment/semicolon) ne workflow step khol diya jo "
        "direct access par block tha (CWE-693; CONFIRMED bypass)."),
    "logic_waf_logic_blind":      ("medium", 5.8, "WAF/edge logic-paths par "
        "filter asymmetry - business-logic traffic blind-spot (CWE-943 flag)."),
    "logic_misconfig_flag":       ("medium", 5.2, "Logic misconfig signal "
        "(debug shape/env bleed) - P23 handoff."),
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_severity(key):
    sev, cvss, why = SEVERITY_HINTS.get(key, ("info", 0.0,
                                              "Business-logic surface signal."))
    return sev, cvss, why


class Findings:
    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "LG-%03d" % (len(self.items) + 1), "key": key,
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
_PII_PAN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_PAN.sub("***PAN***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


# ---------------------------------------------------------------------------
# CANARY + INERT ENFORCEMENT (P15..P19 pattern - hard rules)
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    """Synthetic marker ids - waspP20 family (real ids KABHI nahi)."""
    return "waspP20%s%s" % (tag, rand_str(6))


def filesig(body):
    """Body content store NAHI hota - sirf len + sha1 (redaction rule)."""
    if isinstance(body, str):
        body = body.encode("utf-8", "ignore")
    b = body or b""
    return {"len": len(b), "sha1": hashlib.sha1(b).hexdigest()[:16]}


# FORBIDDEN: koi destructive/exploit/exfil semantic. Sirf census + canary +
# invalid-token + structural differentials (P15..P19 pattern). Logic-extra:
# koi real PAN, koi real transaction verb+id combo, koi bulk-write loop.
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
    r"(?i)4111\s?1111\s?1111\s?1111", r"(?i)5500\s?0000\s?0000\s?0004",
    r"(?i)razorpay_live|sk_live|pk_live", r"(?i)confirm[-_]?payment[-_]?now",
    r"(?i)execute[-_]?order[-_]?66", r"(?i)bulk[-_]?redeem",
]


def assert_inert(body, what="payload"):
    """Har synthetic request/body INERT hona chahiye - violation = hard fail."""
    s = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body or "")
    for pat in FORBIDDEN_CONTENT_PATTERNS:
        if re.search(pat, s):
            raise ValueError("FORBIDDEN content in %s (pattern: %s)"
                             % (what, pat))
    return True


def assert_logic_inert(params, what="params"):
    """Logic-extra INERT: koi REAL amount>0 real-object par nahi ja sakta -
    har probe ya canary-object par hai (kisi value me waspP20 marker) ya
    canary/invalid value par. Canary-object context me koi real state
    change possible hi nahi (object server par exist nahi karta)."""
    joined = " ".join(str(v) for v in (params or {}).values())
    if "waspP20" in joined:
        return True  # canary-object context (objects never exist)
    for k, v in (params or {}).items():
        kl = str(k).lower()
        if any(t in kl for t in ("price", "amount", "total", "qty", "quantity")):
            sv = str(v)
            try:
                fv = float(sv.replace(",", ""))
            except (ValueError, TypeError):
                continue
            if fv > 0 and "waspP20" not in str(v):
                raise ValueError("FORBIDDEN real-shaped amount in %s (%s=%s) - "
                                 "sirf canary/negative/zero values allowed"
                                 % (what, k, v))
    return True


# ===========================================================================
# LOGIC SHAPE REGEXES (verb/price/state/coupon census - offline mining)
# ===========================================================================
LOGIC_VERB_RE = re.compile(
    r"(?i)^/?(?:[a-z0-9_-]+/){0,3}"
    r"(order|orders|purchase|checkout|cart|carts|pay|payment|payments|"
    r"billing|invoice|invoices|receipt|receipts|redeem|redemption|"
    r"coupon|coupons|voucher|vouchers|promo|promotion|promotions|discount|"
    r"discounts|gift[-_]?card|giftcards|refund|refunds|transfer|transfers|"
    r"withdraw|withdrawal|withdrawals|deposit|deposits|balance|balances|"
    r"wallet|wallets|credit|credits|subscription|subscriptions|plan|plans|"
    r"bid|bids|auction|vote|votes|apply|invite|unlock|activate|points|"
    r"loyalty|reward|rewards|cashback|topup|recharge|payout|payouts|"
    r"mint|swap|stake|claim|airdrop)(?:/[a-z0-9_{}:.-]+){0,3}/?$")

PRICE_PARAM_RE = re.compile(
    r"(?i)^(price|amount|amt|total|subtotal|grand[-_]?total|unit[-_]?price|"
    r"cost|fee|charge|discount|discount[-_]?amount|tax|taxes|vat|gst|"
    r"shipping[-_]?cost|handling|tip|balance|credits|points|amount[-_]?due|"
    r"payable|value|bid[-_]?amount|qty[-_]?price|currency[-_]?amount)$")

PRICEISH_PARAM_RE = re.compile(
    r"(?i)(price|amount|total|cost|fee|discount|tax|balance|credits|points|"
    r"payable|charge|value|due)")

STATE_PARAM_RE = re.compile(
    r"(?i)^(step|stage|phase|state|status|workflow|action|next|prev|"
    r"back|forward|redirect|return|return[-_]?url|confirm|confirmed|"
    r"complete|completed|done|current|process|flow|wizard)$")

STATEISH_PARAM_RE = re.compile(
    r"(?i)(step|stage|phase|state|status|workflow|confirm|complete|done|"
    r"process|flow|wizard|action)")

ROLE_PARAM_RE = re.compile(
    r"(?i)^(role|user[-_]?role|is[-_]?admin|admin|isadmin|is[-_]?staff|"
    r"staff|super[-_]?user|superuser|privilege|priv|level|tier|grade|"
    r"premium|vip|verified|is[-_]?pro|pro|internal|debug|test|impersonate|"
    r"act[-_]?as|user[-_]?id|uid|account[-_]?type|plan[-_]?type)$")

COUPON_PARAM_RE = re.compile(
    r"(?i)^(coupon|coupon[-_]?code|voucher|voucher[-_]?code|promo|"
    r"promo[-_]?code|promotional[-_]?code|discount[-_]?code|code|"
    r"gift[-_]?code|referral[-_]?code|ref|referral|invite[-_]?code|"
    r"activation[-_]?code|redeem[-_]?code)$")

QTY_PARAM_RE = re.compile(
    r"(?i)^(qty|quantity|quantities|count|units|items[-_]?count|"
    r"quantity[-_]?requested|volume|multiplicity|seats|licenses)$")

HIDDEN_FIELD_RE = re.compile(
    r"""<input[^>]*type\s*=\s*["']?hidden["']?[^>]*>""", re.I)
INPUT_NAME_RE = re.compile(r"""name\s*=\s*["']([^"']{1,80})["']""", re.I)
INPUT_VALUE_RE = re.compile(r"""value\s*=\s*["']([^"']{0,200})["']""", re.I)
FORM_ACTION_RE = re.compile(r"""<form[^>]*action\s*=\s*["']([^"']{1,200})["']""", re.I)
FORM_METHOD_RE = re.compile(r"""<form[^>]*method\s*=\s*["']?([a-z]{3,6})["']?""", re.I)
PRICE_IN_FORM_RE = re.compile(
    r"""(?i)<input[^>]*name\s*=\s*["']([^"']*(?:price|amount|total|fee|discount)[^"']*)["'][^>]*>""")

WORKFLOW_STEP_URL_RE = re.compile(
    r"(?i)(/step[-_]?(\d{1,2})|step=(\d{1,2})|/checkout(?:/[a-z0-9_-]+){0,4}"
    r"|/flow/[a-z0-9_-]+|/(?:cart|address|shipping|payment|billing|review|"
    r"confirm|complete|done|finish|success)(?:/|$|[?&]))")

TESTISH_RE = re.compile(
    r"(?i)(test|demo|sandbox|sample|dummy|fake|stage|qa|uat|dev)")




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
    """Seed-artifact path resolver (P18/P19 pattern)."""
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


def path_only(url):
    try:
        u = urllib.parse.urlsplit(url or "")
        return u.path or "/"
    except Exception:
        return "/"


def _ff_from_engagement(base_dir):
    """Engagement-level feedforward reader - 13 P20 feeder modules."""
    out = {}
    for mod in ("understand", "passive", "active", "content", "tech", "js",
                "surface", "auth", "sessions", "access", "inject", "xss",
                "client", "ssrf", "files", "api", "graphql", "ws"):
        p = _artifact(base_dir, mod, "feedforward.json")
        d = _read_json_tolerant(p)
        if isinstance(d, dict):
            out[mod] = d.get("routing") or {}
    return out


def read_feedforward_safe(base_dir):
    """Legacy alias (import-shape safe)."""
    try:
        return _ff_from_engagement(base_dir)
    except Exception:
        return {}


def _deep_get(d, *keys):
    """Nested dict/list safe-get (keys chain)."""
    cur = d
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, list) and isinstance(k, int) and 0 <= k < len(cur):
            cur = cur[k]
        else:
            return None
        if cur is None:
            return None
    return cur


def classify_logic_path(path):
    """Path -> verb/price/state/coupon shape classification (census row)."""
    p = path_only(path)
    row = {"path": p, "verb": None, "has_price_shape": False,
           "has_state_shape": False, "has_coupon_shape": False,
           "has_workflow_url": False}
    m = LOGIC_VERB_RE.match(p)
    if m:
        row["verb"] = m.group(1).lower()
        row["score"] = 6
    else:
        row["score"] = 1
    if PRICEISH_PARAM_RE.search(p):
        row["has_price_shape"] = True
        row["score"] += 3
    if STATEISH_PARAM_RE.search(p):
        row["has_state_shape"] = True
        row["score"] += 2
    if COUPON_PARAM_RE.search(p):
        row["has_coupon_shape"] = True
        row["score"] += 3
    if WORKFLOW_STEP_URL_RE.search(p):
        row["has_workflow_url"] = True
        row["score"] += 3
    return row


def mine_logic_params(html):
    """Stored-form miner: forms/hidden fields/param names (VALUES sirf shape,
    store nahi hote). Returns dict - 0 network, redaction-safe."""
    out = {"forms": [], "hidden": [], "price_fields": [], "state_fields": [],
           "role_fields": [], "coupon_fields": [], "qty_fields": []}
    if not html:
        return out
    for m in FORM_ACTION_RE.finditer(html):
        act = m.group(1)
        seg = html[m.start():m.start() + 3000]
        mm = FORM_METHOD_RE.search(seg)
        out["forms"].append({"action": act[:180],
                             "method": (mm.group(1).upper() if mm else "GET")})
        if len(out["forms"]) >= 12:
            break
    for hm in HIDDEN_FIELD_RE.finditer(html):
        seg = hm.group(0)
        nm = INPUT_NAME_RE.search(seg)
        vm = INPUT_VALUE_RE.search(seg)
        if not nm:
            continue
        name = nm.group(1)
        val = (vm.group(1) if vm else "")
        row = {"name": name, "value_len": len(val),
               "value_canary": "waspP20" in val,
               "value_shape": ("numeric" if re.match(r"^-?\d+(\.\d+)?$", val)
                               else ("signed" if len(val) > 40 else "text")),
               "signed_amount": bool(re.match(
                   r"^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}", val))}
        out["hidden"].append(row)
        if PRICEISH_PARAM_RE.search(name):
            out["price_fields"].append(row)
        if STATEISH_PARAM_RE.search(name):
            out["state_fields"].append(row)
        if ROLE_PARAM_RE.match(name):
            out["role_fields"].append(row)
        if COUPON_PARAM_RE.match(name):
            out["coupon_fields"].append(row)
        if QTY_PARAM_RE.match(name):
            out["qty_fields"].append(row)
        if len(out["hidden"]) >= 24:
            break
    for pm in PRICE_IN_FORM_RE.finditer(html):
        out["price_fields"].append({"name": pm.group(1), "in_form": True})
        if len(out["price_fields"]) >= 12:
            break
    return out


def param_census_from_url(url):
    """URL query params -> shape census (values kabhi store nahi)."""
    try:
        q = urllib.parse.urlsplit(url).query
    except Exception:
        return []
    rows = []
    for k in urllib.parse.parse_qs(q, keep_blank_values=True).keys():
        rows.append({"param": k[:80],
                     "class": ("price" if PRICE_PARAM_RE.match(k) else
                               "state" if STATE_PARAM_RE.match(k) else
                               "role" if ROLE_PARAM_RE.match(k) else
                               "coupon" if COUPON_PARAM_RE.match(k) else
                               "qty" if QTY_PARAM_RE.match(k) else "other")})
    return rows



# ===========================================================================
# COLD PATH POOL (discovery - logic-shaped, bounded)
# ===========================================================================
COLD_LOGIC_PATHS = [
    "/order", "/orders", "/order/history", "/order/confirm",
    "/purchase", "/checkout", "/checkout/step/1", "/checkout/step/2",
    "/checkout/step/3", "/checkout/review", "/checkout/confirm",
    "/cart", "/cart/add", "/cart/update", "/payment", "/payment/method",
    "/billing", "/invoice", "/invoices", "/redeem", "/redeem/code",
    "/coupon", "/coupon/apply", "/voucher", "/gift-card", "/giftcard",
    "/refund", "/refund/request", "/transfer", "/transfer/funds",
    "/withdraw", "/withdrawal", "/deposit", "/balance", "/wallet",
    "/credits", "/subscription", "/subscription/cancel", "/plan",
    "/bid", "/vote", "/points", "/loyalty", "/reward", "/rewards",
    "/cashback", "/topup", "/recharge", "/payout", "/api/order",
    "/api/orders", "/api/checkout", "/api/cart", "/api/payment",
    "/api/redeem", "/api/coupon", "/api/refund", "/api/transfer",
    "/api/withdraw", "/api/subscription", "/api/credits", "/api/points",
    "/api/vote", "/api/bid", "/checkout/success", "/order/complete",
]

FF_SEED_SOURCES = [
    # (mod, routing-key, field-extractor)
    ("understand", "to_phase20_business",
     lambda n: [x for x in (n.get("payment_forms") or [])][:8]),
    ("api", "to_phase20_logic",
     lambda n: [x for x in (n.get("mass_assign_ops") or [])][:8]),
    ("sessions", "to_phase20_logic",
     lambda n: [str(x) for x in (n.get("logout_endpoints"),
                                 n.get("fixation_result"),
                                 n.get("concurrent_cap"),
                                 n.get("cookie_toss_surface")) if x][:6]),
    ("access", "to_phase20_logic",
     lambda n: [x for x in (n.get("confirmed_objects") or [])][:10]),
    ("inject", "to_phase20_logic",
     lambda n: [x for x in (n.get("sqli_confirmed") or [])
                + (n.get("deser_hints") or [])][:8]),
    ("client", "to_phase20_logic",
     lambda n: [x for x in (n.get("state_change_writes") or [])][:8]),
    ("files", "to_phase20_logic",
     lambda n: [x for x in (n.get("size_unlimited") or [])
                + (n.get("overwrite_endpoints") or [])][:8]),
    ("graphql", "to_phase20_logic",
     lambda n: [x for x in (n.get("field_authz_confirmed") or [])
                + (n.get("mutation_order_models") or [])
                + (n.get("writable_sensitive_inputs") or [])][:12]),
    ("ws", "to_phase20_logic",
     lambda n: [str(x) for x in (n.get("message_techniques") or [])
                + (n.get("subs_channels") or [])][:8]),
    ("js", "to_phase20_logic",
     lambda n: [str(x) for x in (n.get("hints"), n.get("redirects")) if x][:4]),
]


def discover_logic_surface(base_dir, scope, conf):
    """Stage A: 13-module feedforward seeds + P5 content endpoints +
    P8 surface queue + stored-form mining + cold pool -> ranked targets.
    0 network (sirf stored artifacts)."""
    paths_cap = int(conf.get("logic_paths_cap", 18))
    cold_n = int(conf.get("logic_cold_paths", 26))
    base_url = ""
    try:
        base_url = (scope.seed_urls() or [""])[0]
    except Exception:
        base_url = ""
    found = {}          # url -> row
    sources = []

    def _add_path(p, kind, src, score_hint=0):
        if not p or not isinstance(p, str):
            return False
        p = p.strip()
        if not p or len(p) > 300 or p.lower().startswith(("javascript:", "data:",
                                                          "mailto:", "tel:")):
            return False
        if p.startswith(("http://", "https://")):
            try:
                if scope is not None and not scope.check_url(
                        p, raise_on_fail=False):
                    return False
            except Exception:
                return False
        key = urljoin_safe(base_url, p) if not p.startswith("http") else p
        if not key or not key.startswith("http"):
            return False
        row = found.setdefault(key, {"url": key, "kinds": [], "sources": [],
                                     "score": 0, "verb": None,
                                     "has_price_shape": False,
                                     "has_state_shape": False,
                                     "has_coupon_shape": False,
                                     "has_workflow_url": False})
        if kind not in row["kinds"]:
            row["kinds"].append(kind)
        row["score"] += (1 + score_hint)
        if src not in row["sources"]:
            row["sources"].append(src)
            return True
        return False

    # ---- 13-module feedforward seeds ----
    ff = _ff_from_engagement(base_dir)
    for mod, key, extractor in FF_SEED_SOURCES:
        node = (ff.get(mod) or {}).get(key)
        if not isinstance(node, dict):
            continue
        hit = False
        for item in extractor(node):
            if isinstance(item, dict):
                u = item.get("action") or item.get("url") or item.get(
                    "endpoint") or item.get("field") or ""
                hit = _add_path(u, "ff_%s" % mod, mod,
                                2 if isinstance(u, str) and
                                (PRICEISH_PARAM_RE.search(u) or
                                 LOGIC_VERB_RE.match(path_only(u))) else
                                0) or hit
            elif isinstance(item, str):
                hit = _add_path(item, "ff_%s" % mod, mod, 1) or hit
        if hit:
            sources.append("ff:%s" % mod)

    # ---- P5 content endpoints (artifact file) ----
    for fname in ("api_endpoints.txt", "all_found.txt", "endpoints.txt"):
        txt = _read_text_tolerant(_artifact(base_dir, "content", fname))
        hit = False
        for line in txt.splitlines()[:400]:
            u = line.strip().split(" ")[0]
            if u.startswith("http") and (LOGIC_VERB_RE.match(path_only(u)) or
                                         PRICEISH_PARAM_RE.search(u)):
                hit = _add_path(u, "content_endpoint", "P5:%s" % fname,
                                2) or hit
        if hit:
            sources.append("P5:%s" % fname)

    # ---- P8 surface priority queue ----
    pq = _read_json_tolerant(_artifact(base_dir, "surface",
                                       "priority_queue.json"))
    if isinstance(pq, (list, dict)):
        rows = pq if isinstance(pq, list) else (pq.get("queue") or
                                                pq.get("items") or [])
        hit = False
        for r in rows[:120]:
            u = (r.get("url") or r.get("path") or "") if isinstance(r, dict) \
                else str(r)
            if u:
                hit = _add_path(u, "surface_queue", "P8:priority_queue",
                                2) or hit
        if hit:
            sources.append("P8:priority_queue")

    # ---- P7 js hints (authz_client_hints / client_redirects) ----
    for fname in ("authz_client_hints.txt", "client_redirects.txt"):
        txt = _read_text_tolerant(_artifact(base_dir, "js", fname))
        hit = False
        for line in txt.splitlines()[:200]:
            u = line.strip().split(" ")[0]
            if u.startswith(("http", "/")):
                hit = _add_path(u, "js_hint", "P7:%s" % fname, 1) or hit
        if hit:
            sources.append("P7:%s" % fname)

    # ---- P2 understand forms.json (stored form mining) ----
    forms = _read_json_tolerant(_artifact(base_dir, "understand",
                                          "forms.json"))
    if isinstance(forms, (list, dict)):
        rows = forms if isinstance(forms, list) else (forms.get("forms") or [])
        hit = False
        for r in rows[:80]:
            if not isinstance(r, dict):
                continue
            u = r.get("action") or ""
            if u:
                hit = _add_path(u, "p2_form", "P2:forms.json", 3) or hit
        if hit:
            sources.append("P2:forms.json")

    # ---- stored JS/HTML bodies miner (offline; P7 assets) ----
    mined_params = {}
    for dname in ("js", "content", "understand"):
        dpath = _artifact(base_dir, dname, "")
        try:
            if not os.path.isdir(dpath):
                continue
            for fn in sorted(os.listdir(dpath))[:60]:
                if not fn.endswith((".txt", ".json", ".html")):
                    continue
                body = _read_text_tolerant(os.path.join(dpath, fn))
                if not body or "<form" not in body and "input" not in body:
                    continue
                ml = mine_logic_params(body)
                if ml.get("hidden") or ml.get("forms"):
                    mined_params["%s/%s" % (dname, fn)] = {
                        k: v[:6] for k, v in ml.items()}
        except Exception:
            continue
    if mined_params:
        sources.append("stored-forms:%d" % len(mined_params))

    # ---- cold pool ----
    for p in COLD_LOGIC_PATHS[:cold_n]:
        _add_path(p, "cold", "cold_pool", 0)
    if not sources:
        sources.append("cold_pool")

    # ---- classify + cap ----
    ranked = []
    for url, row in found.items():
        cls = classify_logic_path(row["url"])
        row.update({k: cls[k] for k in ("verb", "has_price_shape",
                                        "has_state_shape",
                                        "has_coupon_shape",
                                        "has_workflow_url")})
        if cls["verb"]:
            row["score"] += 4
        ranked.append((row["score"], url, row))
    ranked.sort(key=lambda t: (-t[0], t[1]))
    return {"base_url": base_url, "sources": sources,
            "mined_params": mined_params,
            "ranked": [{"url": u, "score": s, "row": r}
                       for s, u, r in ranked[:paths_cap * 3]],
            "targets": [{"url": u, "score": s, "row": r}
                        for s, u, r in ranked[:paths_cap]]}


def rank_targets(targets, conf):
    """Probe-cap ranking (score desc, stable by url)."""
    cap = int(conf.get("logic_probe_cap", 8))
    ranked = sorted(targets, key=lambda t: (-t.get("score", 0),
                                            t.get("url", "")))[:cap]
    return ranked



# ===========================================================================
# STAGE C - PARAM/STATE CENSUS (GET forms/hidden/price/state shapes)
# ===========================================================================
def param_census(http, targets, meta, conf):
    """Har target par 1 GET census: form/hidden/price/state/role/coupon
    param-shapes. Bodies REDACTED (names-only). Client-trust price signal
    yahin pakda jaata hai (CWE-602 shape)."""
    rows = []
    for t in targets:
        url = t.get("url") or ""
        if not url or meta.get("probes_total", 0) >= int(
                conf.get("logic_probe_cap", 8)) * 6:
            break
        try:
            r = http.get(url, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
        except Exception:
            continue
        if r is None or not getattr(r, "status", 0):
            continue
        body = ""
        try:
            body = (r.body or b"").decode("utf-8", "ignore")
        except Exception:
            body = ""
        if is_soft404(r, meta.get("soft404") or {}):
            rows.append({"target": url, "status": r.status, "soft404": True})
            continue
        ml = mine_logic_params(body)
        uparams = param_census_from_url(url)
        price_hidden = [h for h in ml.get("price_fields", [])]
        client_trust = bool(price_hidden) and any(
            h.get("value_shape") == "numeric" or h.get("in_form")
            for h in price_hidden)
        signed_amount = any(h.get("signed_amount")
                            for h in ml.get("hidden", []))
        csrf_like = any(re.search(r"(?i)(csrf|_token|authenticity|xsrf)",
                                  h.get("name", ""))
                        for h in ml.get("hidden", []))
        rows.append({
            "target": url, "status": r.status, "sig": filesig(r.body),
            "forms": ml.get("forms", [])[:6],
            "hidden_count": len(ml.get("hidden", [])),
            "hidden_sample": [h.get("name") for h in
                              ml.get("hidden", [])[:10]],
            "price_fields": [h.get("name") for h in price_hidden[:6]],
            "state_fields": [h.get("name") for h in
                             ml.get("state_fields", [])[:6]],
            "role_fields": [h.get("name") for h in
                            ml.get("role_fields", [])[:6]],
            "coupon_fields": [h.get("name") for h in
                              ml.get("coupon_fields", [])[:6]],
            "qty_fields": [h.get("name") for h in
                           ml.get("qty_fields", [])[:4]],
            "url_params": uparams[:10],
            "client_trust_price": client_trust,
            "signed_amount": signed_amount,
            "csrf_in_form": csrf_like,
            "workflow_url": bool(WORKFLOW_STEP_URL_RE.search(url)),
        })
    return rows


def client_trust_findings(rows, F):
    """Stage C -> findings bridge (client-trust price/state)."""
    n = 0
    for r in rows:
        if not isinstance(r, dict) or r.get("soft404"):
            continue
        if r.get("client_trust_price"):
            F.add("logic_client_trust_price", "Client-side price/total field",
                  r["target"], "price fields in form: %s - server-side "
                  "recalculation verify karo" % ",".join(
                      r.get("price_fields", [])[:4]),
                  "logic_param_census.json")
            n += 1
        if r.get("signed_amount"):
            F.add("logic_signed_amount", "Signed-amount shape in form",
                  r["target"], "long dotted token-shaped value in hidden "
                  "amount field - tamper-resistance signal", "logic_param_census.json")
        if not r.get("csrf_in_form") and (r.get("forms") and
                                          any(f.get("method") == "POST"
                                              for f in r.get("forms", []))):
            F.add("logic_no_csrf_state_change", "POST form without CSRF token",
                  r["target"], "form census: POST action without csrf/token "
                  "hidden field", "logic_param_census.json")
            n += 1
    return n



# ===========================================================================
# STAGE D - HIDDEN-PARAM ECHO MATRIX (GATED logic_allow_param_echo)
# ===========================================================================
HIDDEN_CANARY_PARAMS = [
    "admin", "is_admin", "role", "user_role", "debug", "internal",
    "premium", "vip", "verified", "balance", "credits", "price",
    "discount", "tier", "act_as",
]


def hidden_param_matrix(http, targets, meta, conf, canary):
    """Canary param echo census (mass-assignment surface). Sirf GET query
    canary (echo-observation). Values = waspP20 canary (kabhi real shape
    nahi). GATED: OFF -> documented-only."""
    gate = bool(conf.get("logic_allow_param_echo", False))
    result = {"gate": "logic_allow_param_echo=%s" % gate, "rows": [],
              "probes": 0 if not gate else 0}
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "%s (canary echo GET; mass-assignment surface)" % p
            for p in HIDDEN_CANARY_PARAMS[:int(conf.get("logic_param_cap", 12))]]
        return result
    cap_p = int(conf.get("logic_param_cap", 12))
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        if not url:
            continue
        row = {"target": url, "echoed": [], "reflected": [], "gated": False}
        for pname in HIDDEN_CANARY_PARAMS[:cap_p]:
            val = _canary("pm")
            q = "?%s=%s" % (urllib.parse.quote(pname),
                            urllib.parse.quote(val))
            try:
                r = http.get(url + q, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                result["probes"] += 1
            except Exception:
                continue
            if r is None or not getattr(r, "status", 0):
                continue
            body = ""
            try:
                body = (r.body or b"").decode("utf-8", "ignore")
            except Exception:
                body = ""
            if val in body:
                row["echoed"].append({"param": pname, "status": r.status,
                                      "sig": filesig(r.body)})
            elif is_soft404(r, meta.get("soft404") or {}):
                row["soft404"] = True
                break
        result["rows"].append(row)
    return result


def role_param_diff(http, targets, meta, conf, canary):
    """Role/privilege param differential (GATED logic_allow_role_probe):
    baseline GET vs canary-role GET - status/content-differential census.
    GATED OFF -> documented-only."""
    gate = bool(conf.get("logic_allow_role_probe", False))
    result = {"gate": "logic_allow_role_probe=%s" % gate, "rows": []}
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "role-param differential (baseline vs canary role echo; "
            "privilege-assignment census)"]
        return result
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        if not url:
            continue
        row = {"target": url}
        try:
            rb = http.get(url, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            val = _canary("rl")
            q = "?role=%s&is_admin=%s" % (urllib.parse.quote(val),
                                          urllib.parse.quote(val))
            rr = http.get(url + q, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
        except Exception:
            continue
        if rb is None or rr is None:
            continue
        sb, sr = filesig(rb.body), filesig(rr.body)
        body = ""
        try:
            body = (rr.body or b"").decode("utf-8", "ignore")
        except Exception:
            body = ""
        row.update({"baseline_status": rb.status, "role_status": rr.status,
                    "sig_diff": sb["sha1"] != sr["sha1"],
                    "canary_reflected": val in body})
        if val in body:
            row["verdict"] = "CONFIRMED"
        elif rr.status != rb.status:
            row["verdict"] = "SUSPECTED"
        else:
            row["verdict"] = "HARDENED"
        result["rows"].append(row)
    return result


# ===========================================================================
# STAGE E - PRICE/QTY TAMPER CENSUS (GATED logic_allow_price_probe)
#   canary value-matrix validation differential. Canary object-ids KABHI
#   exist nahi karte -> koi real transaction possible hi nahi.
# ===========================================================================
VALUE_MATRIX = [
    ("negative",       "-1"),
    ("zero",           "0"),
    ("decimal_micro",  "0.0042"),
    ("negative_qty",   "-2"),
    ("huge",           "1000000000"),
    ("overflow_ish",   "999999999999999"),
    ("string_in_num",  "waspP20"),
    ("negative_zero",  "-0"),
]


def price_value_matrix(conf):
    cap = int(conf.get("logic_value_cap", 8))
    return VALUE_MATRIX[:max(2, min(cap, len(VALUE_MATRIX)))]


def _build_canary_obj_params(t, canary):
    """Target-shape se canary object params (sku/item/order id)."""
    p = path_only(t.get("url") or "")
    if "api/" in p:
        return {"sku": canary, "order_id": canary, "item_id": canary}
    return {"item": canary, "sku": canary}


def price_tamper_census(http, targets, meta, conf, canary):
    """GATED price/value canary differential. Har probe: canary object id +
    canary/negative/zero value -> sirf VALIDATION behavior observe. CONFIRMED
    sirf tab jab validation success-shape canary object par de (jo possible
    hi nahi hona chahiye -> validation-order gap)."""
    gate = bool(conf.get("logic_allow_price_probe", False))
    result = {"gate": "logic_allow_price_probe=%s" % gate, "rows": []}
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "%s tamper (canary value-matrix validation differential)" % lbl
            for lbl, _ in VALUE_MATRIX]
        result["techniques_documented"] += [
            "currency-minor/major-unit confusion census",
            "rounding/truncation differential (documented)",
            "free-item swap shapes (documented)",
            "discount stacking playbook (documented)",
            "refund > purchase shapes (documented)",
            "transfer-to-self shapes (documented)",
            "subscription-trial reset shapes (documented)",
            "gift-card enumeration surface census (no brute execution)"]
        return result
    vmat = price_value_matrix(conf)
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        cls = t.get("row") or {}
        if not (cls.get("has_price_shape") or cls.get("verb") or
                cls.get("has_coupon_shape")):
            continue
        cobj = _build_canary_obj_params(t, canary)
        row = {"target": url, "variants": {}, "canary_object": True}
        for lbl, val in vmat:
            params = dict(cobj)
            params["price"] = val
            params["amount"] = val
            params["qty"] = ("1" if not lbl.startswith("negative_qty")
                             else val)
            assert_logic_inert(params, "price probe %s" % lbl)
            qs = urllib.parse.urlencode(params)
            try:
                r = http.get(url + "?" + qs, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
            except Exception:
                continue
            if r is None:
                continue
            body = ""
            try:
                body = (r.body or b"").decode("utf-8", "ignore")
            except Exception:
                body = ""
            status = getattr(r, "status", 0) or 0
            valid_err = bool(re.search(
                r"(?i)(invalid|validation|error|reject|bad[_ ]?request|"
                r"unprocessable|not[_ ]?found)", body)) or status in (400, 402,
                                                                      404, 422)
            # transaction-shape (CONFIRMED ke liye zaroori): server ne canary
            # object ko accept-shape me reflect kiya (accepted/created/applied)
            tx_shape = bool(re.search(
                r"(?i)(accepted|created|applied|processed|completed|"
                r"successful)", body)) and (canary in body)
            success_shape = (200 <= status < 300) and not valid_err and tx_shape
            row["variants"][lbl] = {
                "value_shape": lbl, "status": status,
                "validation_error": valid_err, "sig": filesig(r.body),
                "verdict": ("CONFIRMED" if success_shape else
                            "HARDENED" if valid_err else "SUSPECTED")}
        verdicts = [v.get("verdict") for v in row["variants"].values()]
        if "CONFIRMED" in verdicts:
            row["verdict"] = "CONFIRMED"
        elif "SUSPECTED" in verdicts:
            row["verdict"] = "SUSPECTED"
        else:
            row["verdict"] = "HARDENED"
        result["rows"].append(row)
    return result


def value_oracle_census(http, targets, meta, conf, canary):
    """Stage I: numeric edge oracle (points/credits/bid-shaped fields par
    canary values; GATED logic_allow_price_probe)."""
    gate = bool(conf.get("logic_allow_price_probe", False))
    result = {"gate": "logic_allow_price_probe=%s" % gate, "rows": []}
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "points edge oracle (canary)", "credits edge oracle (canary)",
            "bid edge oracle (canary)", "vote edge oracle (canary)",
            "loyalty multiplay shapes (documented)",
            "cashback self-referral shapes (documented)"]
        return result
    numeric_fields = ["points", "credits", "bid", "vote", "amount"]
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        cls = t.get("row") or {}
        if not (cls.get("has_price_shape") or cls.get("verb")):
            continue
        row = {"target": url, "variants": {}}
        for lbl, val in VALUE_MATRIX[:4]:
            params = {f: val for f in numeric_fields}
            params["ref"] = canary
            assert_logic_inert({"points": val}, "value oracle")
            qs = urllib.parse.urlencode(params)
            try:
                r = http.get(url + "?" + qs, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
            except Exception:
                continue
            if r is None:
                continue
            body = ""
            try:
                body = (r.body or b"").decode("utf-8", "ignore")
            except Exception:
                body = ""
            status = getattr(r, "status", 0) or 0
            valid_err = bool(re.search(r"(?i)(invalid|error|reject)", body)) \
                or status >= 400
            row["variants"][lbl] = {
                "status": status, "validation_error": valid_err,
                "verdict": ("SUSPECTED" if not valid_err and
                            200 <= status < 300 else "HARDENED")}
        result["rows"].append(row)
    return result



# ===========================================================================
# STAGE F - WORKFLOW / STATE-MACHINE CENSUS (GATED logic_allow_workflow_probe)
# ===========================================================================
WORKFLOW_STEP_SHAPES = [
    ("url_segment", "/checkout/step/{n}"),
    ("query_param", "?step={n}"),
    ("flow_paths",  "/checkout/{stage}"),
]
WORKFLOW_STAGES = ["cart", "address", "shipping", "payment", "review",
                   "confirm", "complete"]


def _workflow_step_urls(base_url, shape, n):
    """Step-N candidate urls (shape x n)."""
    out = []
    base = (base_url or "").rstrip("/")
    if shape == "url_segment":
        out = [base + "/checkout/step/%d" % n, base + "/order/step/%d" % n]
    elif shape == "query_param":
        out = [base + "/checkout?step=%d" % n, base + "/order?step=%d" % n]
    elif shape == "flow_paths":
        if n <= len(WORKFLOW_STAGES):
            st = WORKFLOW_STAGES[n - 1]
            out = [base + "/checkout/" + st, base + "/" + st]
    return out


def workflow_census(http, targets, meta, conf, base_url, canary):
    """GATED step-skip differential: LATER step direct GET (bina prior
    completion). Sirf GET census; koi state change nahi. CONFIRMED jab
    later-step 200 non-trivial content de."""
    gate = bool(conf.get("logic_allow_workflow_probe", False))
    result = {"gate": "logic_allow_workflow_probe=%s" % gate, "rows": [],
              "flow_map": []}
    depth = max(2, int(conf.get("logic_workflow_depth", 4)))
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "step-skip direct access (later step w/o prior)",
            "state-param tamper census (canary step ids)",
            "referer-forge step gate census (documented)",
            "workflow-token replay shapes (documented)",
            "back-button resubmission shapes (documented)",
            "order-confirmation direct access (documented)",
            "guest->member flow merge abuse (documented)",
            "signup-activation skip shapes (documented)"]
        # flow map offline (targets se)
        for t in targets:
            u = t.get("url") or ""
            if WORKFLOW_STEP_URL_RE.search(u):
                result["flow_map"].append({"url": u,
                                           "shape": "mined"})
        return result
    seen = set()
    for t in targets[:4]:
        u0 = t.get("url") or ""
        if not u0:
            continue
        p = path_only(u0)
        m = WORKFLOW_STEP_URL_RE.search(p)
        if not m:
            continue
        shape = "url_segment" if "/step" in p else (
            "query_param" if re.search(r"(?i)step=\d", u0) else "flow_paths")
        row = {"target": u0, "shape": shape, "steps": {}}
        for n in range(1, depth + 1):
            for cand in _workflow_step_urls(base_url, shape, n):
                if cand in seen:
                    continue
                seen.add(cand)
                try:
                    r = http.get(cand, allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                except Exception:
                    continue
                if r is None:
                    continue
                body = ""
                try:
                    body = (r.body or b"").decode("utf-8", "ignore")
                except Exception:
                    body = ""
                status = getattr(r, "status", 0) or 0
                nontrivial = (200 <= status < 300 and
                              not is_soft404(r, meta.get("soft404") or {})
                              and len(body) > 120)
                cand_row = {"url": cand[:120], "status": status,
                            "sig": filesig(r.body), "nontrivial": nontrivial}
                prev = row["steps"].get(str(n))
                # best-candidate keep (multiple shapes per step; nontrivial
                # candidate ko overwrite NAHI karte)
                if not (prev and prev.get("nontrivial")):
                    row["steps"][str(n)] = cand_row
        # skip signal: step-3/4 accessible while step-1 also open
        s = row.get("steps", {})
        first = s.get("1", {}).get("status")
        later_ok = [k for k, v in s.items()
                    if int(k) > 1 and v.get("nontrivial")]
        row["skip_signal"] = bool(later_ok)
        row["later_accessible"] = later_ok
        row["verdict"] = ("CONFIRMED" if later_ok else
                          "HARDENED" if first else "NOISE")
        result["rows"].append(row)
    return result


def state_param_census(http, targets, meta, conf, canary):
    """State-param canary differential (workflow ke saath, gate-shared):
    step/state param canary values -> echo/accept shapes."""
    gate = bool(conf.get("logic_allow_workflow_probe", False))
    result = {"gate": "logic_allow_workflow_probe=%s" % gate, "rows": []}
    if not gate:
        result["skipped"] = True
        return result
    for t in targets[:4]:
        url = t.get("url") or ""
        if not url:
            continue
        row = {"target": url, "variants": {}}
        for sp in ("step", "stage", "state", "phase"):
            for val in ("99", "0", "confirm", "complete"):
                val2 = val if not val.isdigit() else val
                q = "?%s=%s&ref=%s" % (sp, urllib.parse.quote(val2),
                                       urllib.parse.quote(canary))
                try:
                    r = http.get(url + q, allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                except Exception:
                    continue
                if r is None:
                    continue
                body = ""
                try:
                    body = (r.body or b"").decode("utf-8", "ignore")
                except Exception:
                    body = ""
                status = getattr(r, "status", 0) or 0
                row["variants"]["%s=%s" % (sp, val)] = {
                    "status": status, "reflected": canary in body,
                    "sig": filesig(r.body)}
        result["rows"].append(row)
    return result


# ===========================================================================
# STAGE G - RACE-CONDITION SURFACE (DOCUMENTED-ONLY + GATED idempotency)
#   RACE EXECUTION FORBIDDEN. Gated census = 2 SEQUENTIAL canary requests.
# ===========================================================================
DOCUMENTED_RACE_TECHNIQUES = [
    ("double-redeem", "Same gift-card/coupon code 2 parallel redeem "
     "requests - balance check aur debit ke beech TOCTOU window. PoC: "
     "manual, 2 tabs, SAME canary code (RoE)."),
    ("parallel-withdraw", "Withdraw endpoint par parallel requests - "
     "balance read common, debit per-request (overdraw). Manual wave."),
    ("toctou-balance", "Read-modify-write cycle race (credits/points) - "
     "single-user two-device sync abuse. Manual wave."),
    ("single-packet-attack", "HTTP/2 single-packet race (N requests ek "
     "packet me) - last-byte sync technique. Manual wave, RoE-gated."),
    ("last-byte-sync", "Connection-level partial-write hold, phir release "
     "- server threads ko synchronized karna. Manual+RoE."),
    ("response-queue-abuse", "Proxy response-queue desync se race window "
     "widen (request-smuggling adjacent). Documented-only."),
    ("session-racing", "Ek session ki limits do parallel sessions me "
     "split - concurrent-session cap bypass (P10 handoff)."),
    ("cart-merge-race", "Guest-cart merge race: merge ke waqt price "
     "recalculation miss (CWE-367). Manual wave."),
    ("coupon-multiuse", "Single-use coupon parallel apply - usage counter "
     "increment race. Manual wave."),
    ("limit-reset-race", "Rate-limit window boundary race (reset ke exact "
     "par burst). Census-only; koi burst KABHI nahi."),
]

# 12 BUSINESS-LOGIC PLAYBOOKS (documented-only; execution manual+RoE wave)
DOCUMENTED_BUSINESS_PLAYBOOKS = [
    ("discount-stacking", "Multiple discount codes stack > 100% - apply-"
     "order audit + single-code policy. Manual wave: own-account stack "
     "attempt, evidence pack."),
    ("refund-beyond-purchase", "Refund amount > paid amount (partial-refund "
     "replay) - refund ledger reconciliation check."),
    ("transfer-to-self", "A->A transfer shapes: fee-bypass / limit-reset "
     "via self-transfer - per-pair limit audit."),
    ("rounding-drift", "Per-item rounding accumulate vs total rounding - "
     "1 paisa/cen systematic drift harvest (CWE-1339)."),
    ("trial-reset", "Subscription trial re-enroll via email-variant/"
     "identity-rotate - identity-linking audit."),
    ("proration-abuse", "Plan down/up-grade proration edges - credit "
     "mint shapes (chargebee/recurly class)."),
    ("gift-card-derivation", "Sequential/predictable gift-card code-space "
     "census (NO brute) - entropy audit."),
    ("loyalty-multiplay", "Points earn x spend loop: earn-rate on "
     "discounted spend - business-rule review."),
    ("cashback-self-referral", "Self-referral chain on cashback - graph "
     "audit (same-device/same-payment shapes)."),
    ("cart-timing", "Price change between cart-add and checkout - server "
     "recompute-at-checkout check (CWE-367 adjacent)."),
    ("quantity-tier-edge", "Tiered pricing boundary (x999 vs x1000) - "
     "tier threshold validation."),
    ("invoice-edit-after-finalize", "Invoice mutation post-finalize - "
     "immutable-ledger check (P16 overwrite cross-ref)."),
]


def idempotency_census(http, targets, meta, conf, canary):
    """GATED logic_allow_race_probe: 2 SEQUENTIAL canary validation GETs
    per target - idempotency-key header signal + dedup differential.
    HARD CAP 2 requests/target, NO parallelism, small sleep between."""
    gate = bool(conf.get("logic_allow_race_probe", False))
    result = {"gate": "logic_allow_race_probe=%s" % gate, "rows": [],
              "hard_cap_per_target": 2, "parallelism": "NONE (sequential)"}
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "%s (documented-only; execution manual+RoE)" % n
            for n, _ in DOCUMENTED_RACE_TECHNIQUES]
        return result
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        cls = t.get("row") or {}
        if not cls.get("verb"):
            continue
        row = {"target": url, "sequential": True, "requests": 0}
        ikey = "waspP20-idem-" + rand_str(6)
        try:
            r1 = http.get(url + "?ref=%s" % urllib.parse.quote(canary),
                          allow_redirects=False,
                          headers={"Idempotency-Key": ikey})
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            row["requests"] += 1
            time.sleep(0.15)
            r2 = http.get(url + "?ref=%s" % urllib.parse.quote(canary),
                          allow_redirects=False,
                          headers={"Idempotency-Key": ikey})
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            row["requests"] += 1
        except Exception:
            result["rows"].append(row)
            continue
        if r1 is None or r2 is None:
            result["rows"].append(row)
            continue
        s1, s2 = filesig(r1.body), filesig(r2.body)
        hdrs1 = getattr(r1, "headers", {}) or {}
        hdrs2 = getattr(r2, "headers", {}) or {}
        idem_echo = any(re.search(r"(?i)idempot", str(k))
                        for k in (list(hdrs1.keys()) + list(hdrs2.keys())))
        row.update({
            "req1_status": getattr(r1, "status", 0),
            "req2_status": getattr(r2, "status", 0),
            "idempotency_signal": idem_echo,
            "same_response_shape": s1["sha1"] == s2["sha1"]})
        row["verdict"] = ("HARDENED" if idem_echo else "SUSPECTED")
        result["rows"].append(row)
    return result



# ===========================================================================
# STAGE H - COUPON/REDEEM VALIDATION ORACLE (GATED logic_allow_coupon_probe)
# ===========================================================================
COUPON_VARIANTS = [
    ("plain",        "%s"),
    ("lowercase",    "%s_lw"),
    ("padded",       " %s "),
]


def coupon_census(http, targets, meta, conf, canary):
    """GATED canary coupon oracle: invalid canary codes -> validation-error
    shapes + case/pad variant differential. Koi brute/loop KABHI nahi
    (3 variants x top-N, hard cap)."""
    gate = bool(conf.get("logic_allow_coupon_probe", False))
    result = {"gate": "logic_allow_coupon_probe=%s" % gate, "rows": []}
    if not gate:
        result["skipped"] = True
        result["techniques_documented"] = [
            "canary coupon validation oracle",
            "case-insensitivity differential (CWE-178 census)",
            "whitespace-padded code differential",
            "discount-application-order shapes (documented)",
            "stacked-discount playbook (documented)",
            "expired-coupon reapply shapes (documented)",
            "referral-self-abuse shapes (documented)",
            "coupon-listing leak census (offline)"]
        return result
    n_probes = 0
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        cls = t.get("row") or {}
        if not (cls.get("has_coupon_shape") or cls.get("verb")):
            continue
        row = {"target": url, "variants": {}}
        base_code = _canary("cp")
        for lbl, fmt in COUPON_VARIANTS:
            code = fmt % base_code
            q = "?code=%s&coupon=%s&ref=%s" % (
                urllib.parse.quote(code), urllib.parse.quote(code),
                urllib.parse.quote(canary))
            try:
                r = http.get(url + q, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
                n_probes += 1
            except Exception:
                continue
            if r is None:
                continue
            body = ""
            try:
                body = (r.body or b"").decode("utf-8", "ignore")
            except Exception:
                body = ""
            status = getattr(r, "status", 0) or 0
            invalid_shape = bool(re.search(
                r"(?i)(invalid|not[_ ]?found|expired|error|no such|"
                r"unknown code)", body)) or status >= 400
            accepted = (200 <= status < 300) and not invalid_shape
            row["variants"][lbl] = {
                "status": status, "invalid_shape": invalid_shape,
                "sig": filesig(r.body),
                "verdict": ("CONFIRMED" if accepted else "HARDENED")}
            row["limit_headers"] = sorted(
                k for k in (getattr(r, "headers", {}) or {}).keys()
                if re.search(r"(?i)(rate|limit|retry)", str(k)))[:4]
            if n_probes >= 30:
                break
        verdicts = [v.get("verdict") for v in row["variants"].values()]
        row["verdict"] = ("CONFIRMED" if "CONFIRMED" in verdicts else
                          "SUSPECTED" if len(set(verdicts)) > 1 else
                          "HARDENED")
        row["case_edge"] = len(set(
            (v.get("sig") or {}).get("sha1")
            for v in row["variants"].values())) > 1
        result["rows"].append(row)
        if n_probes >= 30:
            break
    return result


# ===========================================================================
# STAGE J - BYPASS MATRIX v2 (17 SECRET logic techniques - canary census)
# ===========================================================================
def bypass2_variants(canary):
    """17 SECRET param/value-level logic-bypass builders. Sirf canary/negative/
    zero shapes - assert_logic_inert enforced har final param-set par."""
    c = canary
    return [
        ("hpp_price",              {"price": ["0", "-1"]}, "param_smuggle"),
        ("dup_json_key",           {"__dup__": True}, "param_smuggle"),
        ("json_type_confusion",    {"price": '"' + c + '"'}, "type_confusion"),
        ("array_param",            {"qty[]": "-1"}, "param_smuggle"),
        ("nested_object_price",    {"item": {"price": "0"}}, "type_confusion"),
        ("null_price",             {"price": "null"}, "type_confusion"),
        ("plus_prefix",            {"price": "+0"}, "numeric_edge"),
        ("hex_shaped",             {"price": "0x0"}, "numeric_edge"),
        ("exp_shaped",             {"price": "0e0"}, "numeric_edge"),
        ("unicode_minus",          {"price": "\u22120"}, "numeric_edge"),
        ("whitespace_val",         {"price": " 0 "}, "normalization"),
        ("negative_zero",          {"price": "-0"}, "numeric_edge"),
        ("param_alias",            {"amt": "-1", "amount": "-1"}, "param_smuggle"),
        ("case_varied_param",      {"Price": "0", "PRICE": "0"}, "normalization"),
        ("dot_segment_step",       {"__url__": "/checkout/./step/3"}, "route_misroute"),
        ("semicolon_step",         {"__url__": "/checkout/step/2;bypass=1"}, "route_misroute"),
        ("orig_url_header",        {"__hdr__": ("X-Original-URL",
                                                "/checkout/step/3")}, "route_misroute"),
    ]


def bypass2_matrix(http, scope, targets, meta, conf, base_url, canary):
    """17 SECRET techniques census. Route-class variants sirf GATED
    logic_allow_workflow_probe par wire par jaate hain; param-class GATED
    logic_allow_price_probe + logic_allow_param_echo. OFF -> documented."""
    gate_p = bool(conf.get("logic_allow_price_probe", False))
    gate_e = bool(conf.get("logic_allow_param_echo", False))
    gate_w = bool(conf.get("logic_allow_workflow_probe", False))
    result = {"gates": {"price": gate_p, "echo": gate_e, "workflow": gate_w},
              "rows": []}
    if not (gate_p and gate_e):
        result["skipped"] = True
        result["techniques_documented"] = [
            "%s (%s)" % (n, cls) for n, _, cls in bypass2_variants(canary)]
        return result
    cap = int(conf.get("logic_bypass2_cap", 17))
    variants = bypass2_variants(canary)[:cap]
    for t in targets[:3]:
        url = t.get("url") or ""
        if not url:
            continue
        row = {"target": url, "variants": {}}
        for name, params, klass in variants:
            if klass == "route_misroute" and not gate_w:
                row["variants"][name] = {"gated": True, "class": klass}
                continue
            if "__dup__" in params:
                # TRUE duplicate-key JSON body (dict literal collapse nahi)
                body = ('{"sku": "%s", "price": 0, "price": -1}'
                        % canary).encode()
                assert_inert(body, "bypass2 dup_json_key")
                try:
                    r = http.post(url, data=body,
                                  headers={"Content-Type": "application/json"},
                                  allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                except Exception:
                    continue
                status = getattr(r, "status", 0) or 0
                row["variants"][name] = {"status": status,
                                         "class": klass,
                                         "sig": filesig(r.body)}
                continue
            if "__url__" in params:
                # RAW concat (urljoin dot-segments normalize kar deta hai -
                # misroute census ko RAW path chahiye)
                u = (base_url or "").rstrip("/") + params["__url__"]
                try:
                    if scope is not None:
                        scope.check_url(u, raise_on_fail=True)
                    r = http.get(u, allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                except Exception:
                    row["variants"][name] = {"gated": True, "class": klass,
                                             "error": "scope/req"}
                    continue
                status = getattr(r, "status", 0) or 0
                body = ""
                try:
                    body = (r.body or b"").decode("utf-8", "ignore")
                except Exception:
                    body = ""
                row["variants"][name] = {
                    "status": status, "class": klass,
                    "nontrivial": (200 <= status < 300 and
                                   not is_soft404(
                                       r, meta.get("soft404") or {}) and
                                   len(body) > 120)}
                continue
            if "__hdr__" in params:
                hk, hv = params["__hdr__"]
                u = url + "?ref=" + urllib.parse.quote(canary)
                try:
                    rb = http.get(u, allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                    r = http.get(u, headers={hk: hv},
                                 allow_redirects=False)
                    meta["probes_total"] = meta.get("probes_total", 0) + 1
                except Exception:
                    continue
                status = getattr(r, "status", 0) or 0
                body = ""
                try:
                    body = (r.body or b"").decode("utf-8", "ignore")
                except Exception:
                    body = ""
                nontrivial = (200 <= status < 300 and
                              not is_soft404(
                                  r, meta.get("soft404") or {}) and
                              len(body) > 120)
                # win sirf tab jab header-differential ho (baseline same
                # response de to wo misroute nahi, baseline hi hai)
                diff = (getattr(rb, "status", 0) != status or
                        filesig(rb.body)["sha1"] !=
                        filesig(r.body)["sha1"])
                row["variants"][name] = {
                    "status": status, "class": klass,
                    "nontrivial": bool(nontrivial and diff)}
                continue
            # param-class variants
            clean = {k: v for k, v in params.items() if not k.startswith("__")}
            clean["sku"] = canary
            assert_logic_inert(clean, "bypass2 %s" % name)
            qs = urllib.parse.urlencode(clean, doseq=True)
            try:
                r = http.get(url + "?" + qs, allow_redirects=False)
                meta["probes_total"] = meta.get("probes_total", 0) + 1
            except Exception:
                continue
            status = getattr(r, "status", 0) or 0
            body = ""
            try:
                body = (r.body or b"").decode("utf-8", "ignore")
            except Exception:
                body = ""
            valid_err = bool(re.search(r"(?i)(invalid|error|reject)", body)) \
                or status >= 400
            row["variants"][name] = {
                "status": status, "class": klass,
                "validation_error": valid_err,
                "verdict": ("SUSPECTED" if not valid_err and
                            200 <= status < 300 else "HARDENED")}
        result["rows"].append(row)
    return result



# ===========================================================================
# STAGE K - AUTHZ-CONTEXT DIFFERENTIAL (anon vs canary-cookie) + re-auth
# ===========================================================================
def authz_context_diff(http, targets, meta, conf, canary, cookie_header=None):
    """Anon GET vs canary-cookie GET differential on logic targets +
    re-auth census (password-confirm shapes in HTML). Client-cookie canary
    hai (real session kabhi use nahi)."""
    rows = []
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        if not url:
            continue
        row = {"target": url}
        try:
            ra = http.get(url, allow_redirects=False)
            meta["probes_total"] = meta.get("probes_total", 0) + 1
            rc = None
            if cookie_header:
                rc = http.get(url, allow_redirects=False,
                              headers={"Cookie": cookie_header})
                meta["probes_total"] = meta.get("probes_total", 0) + 1
        except Exception:
            continue
        if ra is None:
            continue
        body = ""
        try:
            body = (ra.body or b"").decode("utf-8", "ignore")
        except Exception:
            body = ""
        status = getattr(ra, "status", 0) or 0
        reauth = bool(re.search(
            r"(?i)(re-?authenticate|confirm[-_ ]?password|password[-_ ]?"
            r"confirm|enter[-_ ]?your[-_ ]?password|otp|2fa|verify[-_ ]?"
            r"identity)", body))
        privileged_shape = bool(re.search(
            r"(?i)(admin|refund[-_ ]?approve|override|approve[-_ ]?"
            r"refund|adjust[-_ ]?balance|role[-_ ]?assign|internal)",
            body))
        row.update({
            "anon_status": status,
            "reauth_signal": reauth,
            "privileged_shape_preauth": privileged_shape and
                                        200 <= status < 300,
            "sig": filesig(ra.body)})
        if rc is not None:
            s_a, s_c = filesig(ra.body), filesig(rc.body)
            row["cookie_status"] = getattr(rc, "status", 0)
            row["cookie_sig_diff"] = s_a["sha1"] != s_c["sha1"]
            row["cookie_diff_class"] = (
                "DIFFERENTIAL" if row["cookie_sig_diff"] or
                row["cookie_status"] != status else "SAME")
        else:
            row["cookie_diff_class"] = "SKIPPED"
        if privileged_shape and 200 <= status < 300:
            row["verdict"] = "SUSPECTED"
        elif status in (401, 403) or (200 <= status < 300 and reauth):
            row["verdict"] = "HARDENED"
        else:
            row["verdict"] = "NOISE"
        rows.append(row)
    return rows


# ===========================================================================
# STAGE M - ANTI-AUTOMATION POSITIVE-CONTROL CENSUS
# ===========================================================================
def anti_auto_census(http, targets, meta, conf, pc_rows=None):
    """CSRF/idempotency/signing/confirmation/limit positive controls per
    target (1 GET each; pc_rows = Stage C rows cross-ref)."""
    rows = []
    pc_map = {}
    for r in (pc_rows or []):
        if isinstance(r, dict) and r.get("target"):
            pc_map[r["target"]] = r
    for t in targets[:int(conf.get("logic_probe_cap", 8))]:
        url = t.get("url") or ""
        if not url:
            continue
        row = {"target": url}
        pc = pc_map.get(url) or {}
        row["csrf_in_form"] = pc.get("csrf_in_form")
        row["signed_amount"] = pc.get("signed_amount")
        try:
            r = http.get(url, allow_redirects=False,
                         headers={"Origin": "https://waspP20.invalid"})
            meta["probes_total"] = meta.get("probes_total", 0) + 1
        except Exception:
            rows.append(row)
            continue
        if r is not None:
            hdrs = getattr(r, "headers", {}) or {}
            row["sec_fetch_block"] = (getattr(r, "status", 0) in (403, 401))
            row["limit_headers"] = sorted(
                k for k in hdrs.keys()
                if re.search(r"(?i)(rate|limit|retry)", str(k)))[:4]
            body = ""
            try:
                body = (r.body or b"").decode("utf-8", "ignore")
            except Exception:
                body = ""
            row["confirmation_shape"] = bool(re.search(
                r"(?i)(confirm|review your|are you sure|verify)", body))
        signals = [row.get("csrf_in_form"), row.get("signed_amount"),
                   row.get("sec_fetch_block"), row.get("confirmation_shape"),
                   bool(row.get("limit_headers"))]
        row["controls_present"] = sum(1 for s in signals if s)
        row["verdict"] = ("HARDENED" if row["controls_present"] >= 2 else
                          "SUSPECTED" if row["controls_present"] == 1 else
                          "ABSENT")
        rows.append(row)
    return rows



# ===========================================================================
# STAGE L - CROSS-MODULE LOGIC CHAINS (handoff x surface overlap)
# ===========================================================================
CHAIN_FEEDS = [
    ("access", "to_phase20_logic", "confirmed_objects", "idor"),
    ("api", "to_phase20_logic", "mass_assign_ops", "massassign"),
    ("graphql", "to_phase20_logic", "writable_sensitive_inputs", "writable"),
    ("graphql", "to_phase20_logic", "field_authz_confirmed", "gql_authz"),
    ("inject", "to_phase20_logic", "deser_hints", "deser"),
    ("client", "to_phase20_logic", "state_change_writes", "state_write"),
    ("files", "to_phase20_logic", "overwrite_endpoints", "upload"),
    ("ws", "to_phase20_logic", "subs_channels", "ws_channel"),
    ("sessions", "to_phase20_logic", "logout_endpoints", "logout"),
]


def chain_logic(base_dir, targets, conf):
    """Cross-module overlap census (0 probes): handoff objects x logic
    surface -> chain rows."""
    chains = []
    ff = _ff_from_engagement(base_dir)
    target_paths = {path_only(t.get("url") or ""): t.get("url")
                    for t in targets}
    price_targets = [u for t in targets
                     for u in [t.get("url")]
                     if (t.get("row") or {}).get("has_price_shape")]
    verb_targets = [u for t in targets
                    for u in [t.get("url")]
                    if (t.get("row") or {}).get("verb")]
    for mod, key, field, tag in CHAIN_FEEDS:
        node = (ff.get(mod) or {}).get(key) or {}
        items = node.get(field) or []
        if not items:
            continue
        for item in items[:6]:
            s = str(item)[:120]
            hit = None
            for p, u in target_paths.items():
                frag = s.split("/")[-1][:24] if s else ""
                if frag and frag.lower() in p.lower():
                    hit = u
                    break
            chains.append({"tag": tag, "source": "%s:%s" % (mod, field),
                           "object_shape": s, "overlap_target": hit,
                           "active": bool(hit)})
    # price x idor special chain
    if price_targets:
        chains.append({"tag": "idor_price", "source": "P20-composite",
                       "object_shape": "price-surface x P11 idor objects",
                       "overlap_target": price_targets[0],
                       "active": True})
    if price_targets and verb_targets:
        chains.append({"tag": "workflow_price", "source": "P20-composite",
                       "object_shape": "workflow x price surface",
                       "overlap_target": verb_targets[0],
                       "active": True})
    return chains


# ===========================================================================
# STAGE N - PLATFORM FINGERPRINT (commerce/payment/subscription stacks)
# ===========================================================================
PLATFORM_SIGNATURES = [
    ("shopify",       r"(?i)(shopify|x-shopify|cdn\.shopify)"),
    ("woocommerce",   r"(?i)(woocommerce|wc-|wp-content/plugins/woocommerce)"),
    ("magento",       r"(?i)(magento|mage-|Magento_Version)"),
    ("bigcommerce",   r"(?i)(bigcommerce|stencil-)"),
    ("prestashop",    r"(?i)(prestashop|prestashop_)"),
    ("snipcart",      r"(?i)(snipcart)"),
    ("stripe",        r"(?i)(stripe\.com|js\.stripe|pk_(?:test|live)_)"),
    ("paypal",        r"(?i)(paypal(?:objects)?\.com|business\.sandbox\.paypal)"),
    ("razorpay",      r"(?i)(razorpay\.com|checkout\.razorpay)"),
    ("recurly",       r"(?i)(recurly)"),
    ("chargify",      r"(?i)(chargify)"),
    ("chargebee",     r"(?i)(chargebee)"),
    ("saleor",        r"(?i)(saleor|graphene-saleor)"),
    ("medusa",        r"(?i)(medusa[-_ ]?(js|commerce)?)"),
    ("spree",         r"(?i)(spree[-_ ]?(commerce|commerce))"),
]


def platform_fingerprint(http, base_url, meta, conf, results):
    """Commerce/payment platform shapes (1 home GET + census cross-ref).
    Census-only; zero PAN/credential data."""
    out = {"platforms": []}
    blob = ""
    home_body = (results.get("home_body") or "")
    blob += home_body
    for r in (results.get("param_census") or []):
        if isinstance(r, dict) and r.get("sig"):
            blob += "sig:%s " % r["sig"].get("sha1", "")
    try:
        r = http.get(base_url or "", allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        if r is not None:
            hdrs = getattr(r, "headers", {}) or {}
            blob += json.dumps({k: str(v)[:80] for k, v in
                                sorted(hdrs.items())[:20]}) + " "
            try:
                blob += (r.body or b"").decode("utf-8", "ignore")[:4000]
            except Exception:
                pass
    except Exception:
        pass
    if not conf.get("logic_platform_fp", True):
        out["skipped"] = True
        return out
    seen = set()
    for name, pat in PLATFORM_SIGNATURES:
        m = re.search(pat, blob)
        if m and name not in seen:
            seen.add(name)
            out["platforms"].append({"name": name,
                                     "note": "platform shape census "
                                             "(research aid)"})
    return out


# ===========================================================================
# STAGE O - STATE/SECRET LEAK CENSUS (client-trust + test SKUs, offline)
# ===========================================================================
def state_leak_census(results, conf):
    """Offline census: client-trusted totals, unsigned state blobs,
    test/sandbox SKUs, coupon-listing shapes (param_census rows se)."""
    out = {"rows": []}
    if not conf.get("logic_secrets_state", True):
        out["skipped"] = True
        return out
    for r in (results.get("param_census") or []):
        if not isinstance(r, dict) or r.get("soft404"):
            continue
        row = {"target": r.get("target")}
        flags = []
        if r.get("client_trust_price"):
            flags.append("client_trust_price")
        if r.get("signed_amount"):
            flags.append("signed_amount_present")
        hidden = r.get("hidden_sample") or []
        if any(re.search(r"(?i)(state|session[-_]?state|flow[-_]?state)",
                         h or "") for h in hidden):
            flags.append("state_blob_field")
        if any(TESTISH_RE.search(h or "") for h in
               (r.get("price_fields") or []) + hidden):
            flags.append("testish_field")
        if r.get("coupon_fields"):
            flags.append("coupon_form_present")
        row["flags"] = flags
        if flags:
            out["rows"].append(row)
    return out



# ===========================================================================
# STAGE P - VERDICT ENGINE (6-class ladder, multi-signal)
# ===========================================================================
def _vrow(key, target, verdict, stage, signals, note=""):
    return {"key": key, "target": target, "verdict": verdict,
            "stage": stage, "signals": signals[:6], "note": note[:200]}


def verdict_engine(results, meta, conf):
    """Sab stages ke signals -> 6-class verdict rows (P12..P19 pattern)."""
    rows = []

    # ---- client-trust price (Stage C) ----
    for r in (results.get("param_census") or []):
        if not isinstance(r, dict) or r.get("soft404"):
            continue
        if r.get("client_trust_price"):
            rows.append(_vrow("logic_client_trust_price", r["target"],
                              "SUSPECTED", "param_census",
                              ["price_field_in_form", "client_trust"],
                              "server-side recalculation verify karo"))
        elif r.get("price_fields") or r.get("url_price_param"):
            if r.get("signed_amount"):
                rows.append(_vrow("logic_signed_amount", r["target"],
                                  "HARDENED", "param_census",
                                  ["signed_amount_shape"]))
            else:
                rows.append(_vrow("logic_price_param", r["target"],
                                  "NOISE", "param_census",
                                  ["price_param_shape"]))

    # ---- hidden-param echo (Stage D) ----
    hpm = results.get("hidden_param") or {}
    for r in (hpm.get("rows") or []):
        if r.get("echoed"):
            role_hits = [e for e in r["echoed"]
                         if ROLE_PARAM_RE.match(e.get("param", ""))]
            non_role = [e for e in r["echoed"]
                        if not ROLE_PARAM_RE.match(e.get("param", ""))]
            if role_hits:
                rows.append(_vrow("logic_role_param_echo", r["target"],
                                  "CONFIRMED", "hidden_param",
                                  ["canary_echo:%s" % e["param"]
                                   for e in role_hits]))
            if non_role:
                rows.append(_vrow("logic_param_echo", r["target"],
                                  "CONFIRMED", "hidden_param",
                                  ["canary_echo:%s" % e["param"]
                                   for e in non_role[:4]]))

    # ---- role diff (Stage D/K) ----
    for r in (results.get("role_diff") or {}).get("rows", []):
        if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
            rows.append(_vrow("logic_role_param_echo", r["target"],
                              r["verdict"], "role_diff",
                              ["canary_reflected", "status_diff"]))

    # ---- price tamper (Stage E) ----
    for r in (results.get("price_tamper") or {}).get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            bad = [k for k, v in (r.get("variants") or {}).items()
                   if v.get("verdict") == "CONFIRMED"]
            key = ("logic_negative_accepted"
                   if "negative" in bad or "negative_qty" in bad else
                   "logic_zero_accepted" if "zero" in bad or
                   "negative_zero" in bad else
                   "logic_huge_accepted" if "huge" in bad or
                   "overflow_ish" in bad else
                   "logic_type_juggle" if "string_in_num" in bad else
                   "logic_price_probe_confirmed")
            rows.append(_vrow(key, r["target"], "CONFIRMED", "price_tamper",
                              ["accepted:%s" % b for b in bad[:4]]))
        elif r.get("verdict") == "SUSPECTED":
            rows.append(_vrow("logic_price_probe_suspected", r["target"],
                              "SUSPECTED", "price_tamper",
                              ["mixed_validation"]))

    # ---- value oracle (Stage I) ----
    for r in (results.get("value_oracle") or {}).get("rows", []):
        sus = [k for k, v in (r.get("variants") or {}).items()
               if v.get("verdict") == "SUSPECTED"]
        if sus:
            rows.append(_vrow("logic_value_oracle", r["target"],
                              "SUSPECTED", "value_oracle",
                              ["accepted:%s" % s for s in sus[:4]]))

    # ---- workflow (Stage F) ----
    for r in (results.get("workflow") or {}).get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            rows.append(_vrow("logic_workflow_skip", r["target"],
                              "CONFIRMED", "workflow",
                              ["later_accessible:%s" % ",".join(
                                  r.get("later_accessible", [])[:3])]))
        for v in (r.get("steps") or {}).values():
            if v.get("nontrivial"):
                rows.append(_vrow("logic_workflow_map", r["target"],
                                  "HARDENED", "workflow", ["step_map"]))
                break
    for r in (results.get("state_param") or {}).get("rows", []):
        acc = [k for k, v in (r.get("variants") or {}).items()
               if v.get("reflected")]
        if acc:
            rows.append(_vrow("logic_workflow_state_client", r["target"],
                              "SUSPECTED", "state_param",
                              ["reflected:%s" % a for a in acc[:4]]))

    # ---- race surface (Stage G) ----
    for r in (results.get("idempotency") or {}).get("rows", []):
        if not r.get("idempotency_signal"):
            rows.append(_vrow("logic_idempotency_absent", r["target"],
                              "SUSPECTED", "idempotency",
                              ["no_idem_header", "same_shape" if
                               r.get("same_response_shape") else "shape_diff"]))
            if r.get("same_response_shape"):
                rows.append(_vrow("logic_dedup_absent", r["target"],
                                  "SUSPECTED", "idempotency",
                                  ["identical_accept_shape"]))
        else:
            rows.append(_vrow("logic_idempotency_present", r["target"],
                              "HARDENED", "idempotency", ["idem_signal"]))
    if not (results.get("idempotency") or {}).get("skipped") or \
            (results.get("idempotency") or {}).get("techniques_documented"):
        rows.append(_vrow("logic_race_surface", "-",
                          "SKIPPED" if (results.get("idempotency") or {})
                          .get("skipped") else "SUSPECTED", "race",
                          ["%d documented techniques"
                           % len(DOCUMENTED_RACE_TECHNIQUES)]))

    # ---- coupon (Stage H) ----
    for r in (results.get("coupon") or {}).get("rows", []):
        if r.get("verdict") == "CONFIRMED":
            rows.append(_vrow("logic_coupon_accepted_any", r["target"],
                              "CONFIRMED", "coupon", ["canary_accepted"]))
        else:
            if r.get("case_edge"):
                rows.append(_vrow("logic_coupon_case_edge", r["target"],
                                  "SUSPECTED", "coupon", ["variant_diff"]))
            rows.append(_vrow("logic_coupon_oracle", r["target"],
                              "HARDENED", "coupon", ["oracle_diff"]))
        if not r.get("limit_headers"):
            rows.append(_vrow("logic_limit_absent", r["target"],
                              "SUSPECTED", "coupon",
                              ["no_rate_limit_headers"]))

    # ---- bypass2 (Stage J) ----
    b2 = results.get("bypass2") or {}
    for r in (b2.get("rows") or []):
        wins_route = [k for k, v in (r.get("variants") or {}).items()
                      if v.get("nontrivial") and
                      v.get("class") == "route_misroute"]
        wins_param = [k for k, v in (r.get("variants") or {}).items()
                      if v.get("verdict") == "SUSPECTED"]
        if wins_route:
            rows.append(_vrow("logic_bypass2_route_misroute", r["target"],
                              "CONFIRMED", "bypass2",
                              ["win:%s" % w for w in wins_route[:4]]))
        if wins_param:
            rows.append(_vrow("logic_bypass2_param_smuggle", r["target"],
                              "SUSPECTED", "bypass2",
                              ["win:%s" % w for w in wins_param[:4]]))

    # ---- authz context (Stage K) ----
    for r in (results.get("authz_diff") or []):
        if r.get("privileged_shape_preauth"):
            rows.append(_vrow("logic_privilege_preauth", r["target"],
                              "SUSPECTED", "authz_diff",
                              ["privileged_shape_preauth"]))
        if r.get("reauth_signal") is False and \
                r.get("anon_status") and 200 <= r.get("anon_status", 0) < 300:
            rows.append(_vrow("logic_no_reauth", r["target"],
                              "SUSPECTED", "authz_diff", ["no_reauth"]))

    # ---- anti-auto (Stage M) ----
    for r in (results.get("anti_auto") or []):
        if r.get("verdict") == "ABSENT":
            rows.append(_vrow("logic_no_csrf_state_change", r["target"],
                              "SUSPECTED", "anti_auto", ["no_controls"]))
        elif r.get("verdict") == "HARDENED":
            rows.append(_vrow("logic_anti_auto_present", r["target"],
                              "HARDENED", "anti_auto",
                              ["controls:%d" % r.get("controls_present", 0)]))

    # ---- platform/leaks (Stage N/O) ----
    for p in (results.get("platform_fp") or {}).get("platforms", []):
        rows.append(_vrow("logic_platform_fp", "-", "NOISE", "platform",
                          [p.get("name", "")]))
    for r in (results.get("state_leak") or {}).get("rows", []):
        fl = r.get("flags") or []
        if "state_blob_field" in fl:
            rows.append(_vrow("logic_state_leak", r.get("target", "-"),
                              "SUSPECTED", "state_leak", fl[:4]))
        if "testish_field" in fl:
            rows.append(_vrow("logic_test_sku", r.get("target", "-"),
                              "SUSPECTED", "state_leak", fl[:4]))
        elif "client_trust_price" in fl:
            pass  # already covered by client_trust row

    # ---- chains (Stage L) ----
    for c in (results.get("chains") or []):
        if not c.get("active"):
            continue
        key = ("logic_chain_idor_price" if c.get("tag") == "idor_price"
               else "logic_chain_massassign_role" if c.get("tag") in
               ("massassign", "writable", "gql_authz")
               else "logic_chain_ws_bid" if c.get("tag") == "ws_channel"
               else "logic_chain_upload_invoice" if c.get("tag") == "upload"
               else None)
        if key:
            rows.append(_vrow(key, c.get("overlap_target") or "-",
                              "CONFIRMED" if c.get("overlap_target")
                              else "SUSPECTED", "chains",
                              ["src:%s" % c.get("source")]))
        if c.get("tag") in ("massassign", "writable") and c.get("active"):
            rows.append(_vrow("logic_massassign_crossref",
                              c.get("overlap_target") or "-",
                              "SUSPECTED", "chains",
                              ["src:%s" % c.get("source")]))

    # ---- waf blind (Stage B) ----
    if (results.get("waf") or {}).get("family"):
        rows.append(_vrow("logic_waf_logic_blind", "-",
                          "NOISE", "baseline",
                          ["waf:%s" % (results["waf"].get("family"))]))

    # dedupe by (key, target)
    seen = set()
    out = []
    for r in rows:
        k = (r["key"], r["target"])
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out



# ===========================================================================
# STAGE Q - KILL-CHAINS (20 business-logic attack chains)
# ===========================================================================
def build_logic_chains(F, results, verdict_rows, targets, meta, conf):
    """20 chains - sirf census-driven 'active' flag; execution manual+RoE."""
    vkeys = {(v.get("key"), v.get("target")) for v in verdict_rows}
    def _v(key, target=None):
        return any(k == key and (target is None or t == target)
                   for k, t in vkeys)
    price_targets = [t.get("url") for t in targets
                     if (t.get("row") or {}).get("has_price_shape")]
    verb_targets = [t.get("url") for t in targets
                    if (t.get("row") or {}).get("verb")]
    coupon_targets = [t.get("url") for t in targets
                      if (t.get("row") or {}).get("has_coupon_shape")]
    wf_targets = [t.get("url") for t in targets
                  if (t.get("row") or {}).get("has_workflow_url")]
    chains = [
        ("CH01", "Client-trust price tamper -> free/underpriced order",
         "Hidden price field client me hai -> tamper karke server bina "
         "recalculation ke amount accept karta hai (agar Stage E CONFIRMED).",
         bool(price_targets and _v("logic_client_trust_price"))),
        ("CH02", "Negative-amount acceptance -> reverse-payment / credit mint",
         "Negative canary validation pass -> refund/credit flow reverse "
         "shape (CONFIRMED par manual RoE wave).",
         bool(_v("logic_negative_accepted"))),
        ("CH03", "Zero-amount acceptance -> free checkout",
         "Zero canary pass -> total=0 order shape (CONFIRMED par manual).",
         bool(_v("logic_zero_accepted"))),
        ("CH04", "Workflow step-skip -> payment bypass",
         "Later step direct access -> bina payment completion order state "
         "aage badh jaata hai (CONFIRMED par manual).",
         bool(_v("logic_workflow_skip"))),
        ("CH05", "Race double-redeem -> unlimited gift-card drain",
         "Idempotency/dedup absent + redeem endpoint -> parallel redeem "
         "race (DOCUMENTED; execution manual+RoE).",
         bool(verb_targets and _v("logic_idempotency_absent"))),
        ("CH06", "Canary-coupon accepted -> discount validation gap",
         "Kabhi-issue-na-hua code accept -> koi bhi code forge surface.",
         bool(_v("logic_coupon_accepted_any"))),
        ("CH07", "Role-param echo -> privilege escalation via mass-assign",
         "role/is_admin echo + P17/P18 writable handoff -> registration/"
         "profile update se privilege grant shape.",
         bool(_v("logic_role_param_echo"))),
        ("CH08", "IDOR order-id x price params -> order manipulation",
         "P11 CONFIRMED idor objects order/receipt surface par -> kisi "
         "doosre user ke order me price/qty tamper chain.",
         bool(_v("logic_chain_idor_price"))),
        ("CH09", "Type-juggle price -> string/JSON confusion bypass",
         "String-in-numeric accept -> validation type-checks absent.",
         bool(_v("logic_type_juggle"))),
        ("CH10", "HPP price -> parser differential discount",
         "price=0&price=-1 shape me koi variant accept -> param parser "
         "inconsistency (Stage J).",
         bool(_v("logic_bypass2_param_smuggle"))),
        ("CH11", "Edge-misroute -> blocked workflow step access",
         "X-Original-URL/dot-segment se WAF-blocked step khula (Stage J "
         "route_misroute CONFIRMED).",
         bool(_v("logic_bypass2_route_misroute"))),
        ("CH12", "WS auth-open x realtime bid -> live auction manipulation",
         "P19 ws_auth_open + bid/auction surface -> bid spoof chain "
         "(P19 handoff cross-ref).",
         bool(_v("logic_chain_ws_bid"))),
        ("CH13", "Upload overwrite x invoice surface -> receipt forgery",
         "P16 overwrite endpoints + invoice/receipt verbs -> document "
         "replace chain.",
         bool(_v("logic_chain_upload_invoice"))),
        ("CH14", "No-reauth x transfer endpoints -> session-hijack amplified",
         "Sensitive transfer/withdraw par re-auth absent -> stolen-cookie "
         "se direct money movement shape.",
         bool(verb_targets and _v("logic_no_reauth"))),
        ("CH15", "No-CSRF x state-change -> CSRF-amplified purchase/redeem",
         "POST forms without CSRF token -> cross-site forced purchase "
         "shape.",
         bool(verb_targets and _v("logic_no_csrf_state_change"))),
        ("CH16", "Coupon case/whitespace edge -> normalization bypass",
         "Variant differential -> code-normalization gap (CWE-178).",
         bool(_v("logic_coupon_case_edge"))),
        ("CH17", "State-param client-trust -> step/status spoof",
         "State param echo -> client-controlled state machine.",
         bool(_v("logic_workflow_state_client"))),
        ("CH18", "Huge-amount acceptance -> overflow/credit inflation",
         "10^9-shape accepted -> numeric bounds missing (CWE-190 flag).",
         bool(_v("logic_huge_accepted"))),
        ("CH19", "Trial-reset shapes -> subscription abuse (documented)",
         "Subscription surface + documented trial-reset playbook -> "
         "manual wave.",
         bool(verb_targets and any("subscription" in (u or "")
                                   for u in verb_targets))),
        ("CH20", "Test-SKU/sandbox bleed -> env-pivot recon",
         "Test/demo/sandbox-shaped SKUs public -> staging logic endpoints "
         "recon aid.",
         bool(_v("logic_misconfig_flag"))),
    ]
    out = []
    for cid, title, story, active in chains:
        out.append({"id": cid, "title": title, "story": story,
                    "active": bool(active),
                    "manual_wave_required": True})
    return out



# ===========================================================================
# STAGE R - TECHNIQUE MATRIX (150+ rows x 18 families)
# ===========================================================================
_FAMS = ["PRICE", "QTY", "WORKFLOW", "RACE", "COUPON", "NEGATIVE",
         "BYPASS2", "HIDPARAM", "ROLE", "VALIDATION", "ANTI-AUTO",
         "PLATFORM", "CHAIN", "STATE", "CURRENCY", "TRIAL", "ROUNDING",
         "TRUST"]

_FAMILY_CWE = {
    "PRICE": ["CWE-20", "CWE-602", "CWE-840"], "QTY": ["CWE-20", "CWE-190"],
    "WORKFLOW": ["CWE-840", "CWE-284", "CWE-602"],
    "RACE": ["CWE-362", "CWE-367", "CWE-841"],
    "COUPON": ["CWE-20", "CWE-178", "CWE-645"],
    "NEGATIVE": ["CWE-20", "CWE-190"],
    "BYPASS2": ["CWE-436", "CWE-693", "CWE-915"],
    "HIDPARAM": ["CWE-915"], "ROLE": ["CWE-915", "CWE-284", "CWE-862"],
    "VALIDATION": ["CWE-20", "CWE-843"],
    "ANTI-AUTO": ["CWE-352", "CWE-799"], "PLATFORM": ["CWE-200"],
    "CHAIN": ["CWE-693", "CWE-284"], "STATE": ["CWE-345", "CWE-602"],
    "CURRENCY": ["CWE-20", "CWE-687"], "TRIAL": ["CWE-840", "CWE-645"],
    "ROUNDING": ["CWE-190", "CWE-1339"], "TRUST": ["CWE-602", "CWE-345"],
}
_FAMILY_MITRE = {
    "PRICE": ["T1565", "T1499"], "QTY": ["T1565"], "WORKFLOW": ["T1068"],
    "RACE": ["T1499"], "COUPON": ["T1565"], "NEGATIVE": ["T1565"],
    "BYPASS2": ["T1027", "T1068"], "HIDPARAM": ["T1068"],
    "ROLE": ["T1068", "T1548"], "VALIDATION": ["T1565"],
    "ANTI-AUTO": ["T1114"], "PLATFORM": ["T1592"], "CHAIN": ["T1068"],
    "STATE": ["T1565"], "CURRENCY": ["T1565"], "TRIAL": ["T1078"],
    "ROUNDING": ["T1565"], "TRUST": ["T1557"],
}


def _mrow(fam, tech, det, sig, gated=False, cwe=None, mitre=None):
    return {"family": fam, "technique": tech, "detail": det,
            "signal": sig, "gated": bool(gated),
            "cwe": cwe or _FAMILY_CWE.get(fam, ["CWE-693"]),
            "mitre": mitre or _FAMILY_MITRE.get(fam, ["T1068"])}


def build_technique_matrix(results, conf):
    """150+ rows: static playbook + live census-driven signals."""
    price_rows = results.get("price_tamper") or {}
    wf_rows = results.get("workflow") or {}
    idem_rows = results.get("idempotency") or {}
    coupon_rows = results.get("coupon") or {}
    b2_rows = results.get("bypass2") or {}
    hpm_rows = results.get("hidden_param") or {}
    rows = []
    # ---- PRICE (12) ----
    price_play = [
        ("hidden-total tamper", "client form total edit"),
        ("unit-price swap", "line-item price replace"),
        ("price-param injection", "server trust query price"),
        ("stale-price replay", "old cached price submit"),
        ("currency switch", "minor/major unit confusion"),
        ("decimal expansion", "0.0042 shape rounding abuse"),
        ("discount-past-zero", "discount > total"),
        ("shipping-zero", "shipping fee nulling"),
        ("tax-omission", "tax field drop"),
        ("fee-flip", "handling to negative"),
        ("bundle-split", "bundle price decomp"),
        ("price-collision", "same-sku multi-price"),
        ("loyalty-points swap", "points-as-currency price swap"),
    ]
    for tech, det in price_play:
        sig = "live" if price_rows.get("rows") else "playbook"
        rows.append(_mrow("PRICE", tech, det, sig,
                          gated=not bool(price_rows.get("rows"))))
    # ---- QTY (8) ----
    for tech, det in [
        ("negative-qty cart", "-1 items -> credit"),
        ("zero-qty order", "0 items price calc"),
        ("qty-max int", "huge quantity bounds"),
        ("float-qty", "0.5 unit edge"),
        ("qty[] array", "array param multi-value"),
        ("qty-type-flip", "string quantity"),
        ("cart-merge dup", "merge double-count"),
        ("stock-reserve race", "reserve/release TOCTOU (documented)")]:
        rows.append(_mrow("QTY", tech, det,
                          "live" if price_rows.get("rows") else "playbook",
                          gated=not bool(price_rows.get("rows"))))
    # ---- WORKFLOW (10) ----
    for tech, det in [
        ("step-skip direct GET", "later step w/o prior"),
        ("state-param tamper", "client state spoof"),
        ("referer-forge gate", "referer-dependent steps"),
        ("back-button resubmit", "state regression"),
        ("confirm-page direct", "final step open"),
        ("order-edit post-confirm", "mutation after freeze"),
        ("guest->member merge", "cart flow confusion"),
        ("activation-skip", "signup flow bypass"),
        ("multi-tab flow fork", "parallel flow states"),
        ("token-less step auth", "flow token absent")]:
        rows.append(_mrow("WORKFLOW", tech, det,
                          "live" if wf_rows.get("rows") else "playbook",
                          gated=not bool(wf_rows.get("rows"))))
    # ---- RACE (10, documented) ----
    for name, _ in DOCUMENTED_RACE_TECHNIQUES:
        rows.append(_mrow("RACE", name, "documented-only technique",
                          "live" if idem_rows.get("rows") else "playbook",
                          gated=True))
    # ---- COUPON (10) ----
    for tech, det in [
        ("canary oracle", "invalid code differential"),
        ("case variants", "upper/lower normalization"),
        ("whitespace padding", "pad-normalization gap"),
        ("expired reapply", "validity window edge"),
        ("stacking", "multi-coupon apply"),
        ("self-referral", "referral loop"),
        ("brute surface census", "code-space shape (no brute)"),
        ("transfer codes", "code reuse cross-account"),
        ("min-order edge", "threshold rounding"),
        ("listing leak", "campaign enumeration")]:
        rows.append(_mrow("COUPON", tech, det,
                          "live" if coupon_rows.get("rows") else "playbook",
                          gated=not bool(coupon_rows.get("rows"))))
    # ---- NEGATIVE (8) ----
    for lbl, val in VALUE_MATRIX:
        rows.append(_mrow("NEGATIVE", "value-%s" % lbl,
                          "canary value %s differential" % val,
                          "live" if price_rows.get("rows") else "playbook",
                          gated=not bool(price_rows.get("rows"))))
    # ---- BYPASS2 (17 secret) ----
    for name, _p, cls in bypass2_variants("waspP20"):
        wins = []
        for r in (b2_rows.get("rows") or []):
            v = (r.get("variants") or {}).get(name) or {}
            if v.get("nontrivial") or v.get("verdict") == "SUSPECTED":
                wins.append(r.get("target", ""))
        rows.append(_mrow("BYPASS2", name, "%s census" % cls,
                          "win" if wins else
                          ("live" if b2_rows.get("rows") else "playbook"),
                          gated=not bool(b2_rows.get("rows"))))
    # ---- HIDPARAM (12) ----
    for pname in HIDDEN_CANARY_PARAMS[:12]:
        echoed = any(pname in [e.get("param") for e in
                               (r.get("echoed") or [])]
                     for r in (hpm_rows.get("rows") or []))
        rows.append(_mrow("HIDPARAM", "canary-%s" % pname,
                          "hidden param echo census",
                          "echo" if echoed else "census",
                          gated=not bool(hpm_rows.get("rows"))))
    # ---- ROLE (8) ----
    for tech, det in [
        ("role-param echo", "role=canary reflected"),
        ("is_admin flip", "boolean privilege param"),
        ("act-as header", "impersonation header"),
        ("tier-downgrade", "plan param tamper"),
        ("verified-flag", "self-verification param"),
        ("role-in-url", "privilege in query"),
        ("role-in-json", "body privilege mass-assign"),
        ("role-inherit", "nested object privilege")]:
        rows.append(_mrow("ROLE", tech, det, "census", gated=True))
    # ---- VALIDATION (8) ----
    for tech, det in [
        ("type-juggle", "string-in-numeric"),
        ("null-injection", "null price field"),
        ("unicode-minus", "U+2212 normalization"),
        ("hex/exp numeric", "0x0/0e0 shapes"),
        ("plus-prefix", "+0 leading sign"),
        ("whitespace-trim", "pad normalization"),
        ("negative-zero", "-0 edge"),
        ("validation-order", "authz-vs-validate order")]:
        rows.append(_mrow("VALIDATION", tech, det, "census"))
    # ---- ANTI-AUTO (6) ----
    aa = results.get("anti_auto") or []
    for tech, det in [
        ("csrf census", "token presence forms"),
        ("idempotency census", "key header signal"),
        ("request-signing", "sig header shape"),
        ("confirmation-step", "review/re-verify shape"),
        ("rate-limit headers", "limit census"),
        ("sec-fetch gate", "fetch-metadata enforcement")]:
        rows.append(_mrow("ANTI-AUTO", tech, det,
                          "live" if aa else "census"))
    # ---- PLATFORM (6 playbook base + live extras) ----
    plat_seen = set()
    for p in (results.get("platform_fp") or {}).get("platforms", []) or []:
        plat_seen.add(p.get("name", ""))
        rows.append(_mrow("PLATFORM", "fp-%s" % p.get("name"),
                          p.get("note", ""), "live"))
    for n in ("shopify", "woocommerce", "stripe", "paypal", "razorpay",
              "chargebee"):
        if n in plat_seen:
            continue
        rows.append(_mrow("PLATFORM", "playbook-%s" % n,
                          "platform playbook (not detected)", "playbook"))
    # ---- CHAIN (8) ----
    for tech, det in [
        ("idor x price", "P11 objects + price surface"),
        ("massassign x role", "P17 ops + role params"),
        ("writable x pricing", "P18 inputs + price"),
        ("upload x invoice", "P16 + receipt verbs"),
        ("ws-open x bid", "P19 + auction verbs"),
        ("deser x logic", "P12 + state flows"),
        ("session x concurrent", "P10 + limits"),
        ("sqli x coupon", "P12 + code fields")]:
        act = any(c.get("active") for c in (results.get("chains") or [])
                  if tech.split(" x ")[0].replace("idor", "idor") in
                  str(c.get("tag", "")))
        rows.append(_mrow("CHAIN", tech, det,
                          "active" if act else "census"))
    # ---- STATE (6) ----
    for tech, det in [
        ("state-blob leak", "unsigned state in client"),
        ("signed-amount shape", "tamper-resistance census"),
        ("test-sku bleed", "sandbox items public"),
        ("debug-price census", "test values"),
        ("coupon-list leak", "campaign shapes"),
        ("flow-state persist", "server-side state check")]:
        rows.append(_mrow("STATE", tech, det, "census"))
    # ---- CURRENCY (5) ----
    for tech, det in [
        ("minor/major unit", "cents vs units"),
        ("multi-currency flip", "currency param switch"),
        ("crypto-roundtrip", "token precision"),
        ("fx-rate staleness", "cached rate abuse"),
        ("symbol normalization", "currency-code edge")]:
        rows.append(_mrow("CURRENCY", tech, det, "playbook"))
    # ---- TRIAL (5) ----
    for tech, det in [
        ("trial-reset shapes", "re-enroll edge"),
        ("plan-downgrade refund", "proration abuse"),
        ("trial-to-paid skip", "activation skip"),
        ("multi-trial identities", "email variants"),
        ("cancel-refund overlap", "cancel window edge")]:
        rows.append(_mrow("TRIAL", tech, det, "playbook"))
    # ---- ROUNDING (4) ----
    for tech, det in [
        ("micro-decimal", "0.0042 truncation"),
        ("half-cent", "banker rounding edge"),
        ("percent-float", "discount precision"),
        ("cumulative-round", "per-item rounding drift")]:
        rows.append(_mrow("ROUNDING", tech, det, "playbook"))
    # ---- TRUST (6) ----
    for tech, det in [
        ("client-total trust", "server trusts form total"),
        ("client-status trust", "server trusts status param"),
        ("client-identity trust", "server trusts user param"),
        ("client-price-sign trust", "unsigned price fields"),
        ("client-step trust", "server trusts step param"),
        ("server-recompute absent", "no recalculation signal")]:
        rows.append(_mrow("TRUST", tech, det, "census"))
    return rows



# ===========================================================================
# STAGE S - REPORTS/ARTIFACTS (40+ outputs)
# ===========================================================================
def _matrix_txt(matrix):
    lines = ["WASP P20 BUSINESS LOGIC TECHNIQUE MATRIX (v%s) - %d rows x %d families"
             % (PLAN_VERSION, len(matrix), len(_FAMS)),
             "=" * 70, ""]
    fam_now = None
    for r in matrix:
        if r["family"] != fam_now:
            fam_now = r["family"]
            lines += ["", "[%s]  (CWE: %s | MITRE: %s)" % (
                fam_now, ",".join(r.get("cwe", [])),
                ",".join(r.get("mitre", []))), "-" * 60]
        lines.append("  %-28s [%s%s] %s" % (
            r["technique"][:28], "GATED " if r.get("gated") else "",
            r["signal"], r["detail"][:60]))
    return "\n".join(lines) + "\n"


def _findings_md(scope, F, ctx, meta, results):
    L = ["# P20 Business Logic FINDINGS (v%s)" % PLAN_VERSION, "",
         "- engagement: `%s`" % scope.engagement,
         "- generated: %s" % now_human(),
         "- probes: %d (all INERT canary)" % meta.get("probes_total", 0),
         "- mode: %s" % ctx.get("mode"), "",
         "| ID | Sev | CVSS | Finding | Endpoint |", "|----|-----|------|---------|----------|"]
    for f in F.items:
        L.append("| %s | %s | %.1f | %s | `%s` |" % (
            f["id"], f["severity"].upper(), f["cvss_hint"],
            f["title"].replace("|", "/"), (f["endpoint"] or "-")[:60]))
    L += ["", "## Why it matters (mapping)", ""]
    for f in F.items:
        if f["severity"] in ("critical", "high"):
            L += ["### %s - %s" % (f["id"], f["title"]),
                  "- endpoint: `%s`" % f["endpoint"],
                  "- detail: %s" % f["detail"],
                  "- impact: %s" % f["why_it_matters"], ""]
    return "\n".join(L) + "\n"


def _test_plan_md(results, verdict_rows, conf):
    conf_keys = [(v["key"], v["target"]) for v in verdict_rows
                 if v["verdict"] in ("CONFIRMED", "SUSPECTED")]
    L = ["# P20 Business Logic manual test plan (kill-tests)", "",
         "> Execution-class probes RoE-gated hain. Sab manual steps sirf",
         "> OWN test accounts + canary ids par karo.", ""]
    if not conf_keys:
        L += ["(koi CONFIRMED/SUSPECTED row nahi - surface clean; playbook",
              "  sections LOGIC_MATRIX.txt me hain)", ""]
    for i, (key, tgt) in enumerate(conf_keys[:24], 1):
        L += ["%d. [%s] %s" % (i, key, tgt)]
        if key in ("logic_client_trust_price", "logic_price_probe_confirmed",
                   "logic_negative_accepted", "logic_zero_accepted",
                   "logic_huge_accepted", "logic_type_juggle"):
            L += ["   - apne test order me total/price ko tamper karo (devtools)",
                  "   - server-side recalculation confirm karo (order detail)",
                  "   - PoC request/response evidence pack karo"]
        elif key in ("logic_workflow_skip", "logic_workflow_state_client"):
            L += ["   - step-1 skip karke direct later step GET karo (own acct)",
                  "   - state param values tamper karke flow behavior dekho",
                  "   - payment completion ke bina order-state check karo"]
        elif key in ("logic_idempotency_absent", "logic_race_surface"):
            L += ["   - same canary code 2 requests (manual, sequential pehle)",
                  "   - server-side dedup/idempotency confirm karo",
                  "   - race PoC sirf RoE allow ho to (lab-first)"]
        elif key.startswith("logic_coupon"):
            L += ["   - canary code variants (case/pad) manually try karo",
                  "   - discount application order verify karo",
                  "   - brute/loop KABHI nahi - sirf shape analysis"]
        elif key.startswith("logic_role") or key.startswith("logic_param"):
            L += ["   - canary param ko profile/register POST me daalo",
                  "   - server response me privilege change verify karo",
                  "   - mass-assignment fix (allowlist) recommend karo"]
        else:
            L += ["   - LOGIC_MATRIX.txt me is family ka playbook follow karo"]
        L.append("")
    return "\n".join(L) + "\n"


def _remediation_txt(verdict_rows):
    remap = {
        "logic_client_trust_price": "Total/price SERVER-SIDE recalculate "
        "karo; client fields kabhi trust nahi (allowlist + recompute).",
        "logic_price_probe_confirmed": "Amount validation server-side "
        "karo: type+range+sign+recalculation, canonical currency units.",
        "logic_negative_accepted": "Negative/zero amounts reject (explicit "
        "sign checks) + refund/credit alag audited flow.",
        "logic_zero_accepted": "Zero-total orders block karo (ya explicit "
        "free-item allowlist) + server-side total recompute.",
        "logic_huge_accepted": "Numeric bounds (min/max) + overflow-safe "
        "integer types lagao.",
        "logic_type_juggle": "Strict type validation (schema/DTO) - "
        "string-in-numeric reject.",
        "logic_workflow_skip": "Har step par server-side state validation "
        "(state machine token + prior-completion check).",
        "logic_workflow_state_client": "Workflow state server-side session "
        "me rakho; client params sirf render ke liye.",
        "logic_idempotency_absent": "Idempotency-Key enforce karo "
        "state-changing ops par + per-object dedup (unique constraints).",
        "logic_coupon_accepted_any": "Coupon validation: existence+validity+"
        "single-use; koi bhi unknown code reject.",
        "logic_coupon_case_edge": "Coupon codes canonicalize (case/pad) "
        "before validation.",
        "logic_role_param_echo": "Mass-assignment protection: param "
        "allowlist; role/privilege fields server-side only.",
        "logic_param_echo": "Mass-assignment protection: DTO allowlist "
        "per endpoint.",
        "logic_no_csrf_state_change": "State-changing endpoints par CSRF "
        "tokens / SameSite+Origin checks enforce karo.",
        "logic_no_reauth": "Sensitive actions (transfer/withdraw/password) "
        "par step-up authentication lagao.",
        "logic_privilege_preauth": "Privileged actions par authz guard "
        "(server-side) - pre-auth shapes expose nahi karo.",
        "logic_bypass2_route_misroute": "X-Original-URL/X-Rewrite-URL "
        "client-side block; WAF ko sab paths par canonical apply.",
        "logic_bypass2_param_smuggle": "Param parsing canonicalize (HPP/"
        "dup-key/array policies) + WAF-app parity.",
        "logic_state_leak": "State blobs sign+encrypt karo (ya server-side "
        "session me shift).",
        "logic_chain_idor_price": "Object-level authz (P11 fixes) + price "
        "audit log har order mutation par.",
        "logic_test_sku": "Test/sandbox SKUs production se hatao "
        "(env separation).",
        "logic_limit_absent": "Redeem/attempt rate-limits + per-account "
        "caps lagao.",
    }
    out = ["P20 Business Logic remediation hints (finding-key -> fix)",
           "=" * 70]
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
    lines = ["# P20 Business Logic engagement kickoff guide", "",
             "## Manual wave checklist (authorized scope only)", ""]
    lines += [
        "1. P2 forms + P8 queue kholo - logic verbs wale endpoints pehle "
        "test karo (order/redeem/transfer surface).",
        "2. Own test account banao - kisi REAL object/id par kabhi probe "
        "nahi (canary discipline).",
        "3. Devtools me hidden price/total fields dekho - client-trust "
        "findings se match karo.",
        "4. Workflow steps manually walk karo (cart->payment->confirm) - "
        "step-skip findings verify karo.",
        "5. Coupon: sirf canary/invalid codes manual - brute FORBIDDEN.",
        "6. Race techniques DOCUMENTED-ONLY hain - PoC sirf RoE+lab me.",
        "7. P11 idor endpoints x order surface cross-check (chain CH08).",
        "8. Sab evidence logic_verdicts.json + LOGIC_FINDINGS.md se link "
        "karo.",
    ]
    lines += ["", "## Active census inventory", ""]
    for k in ("param_census", "hidden_param", "role_diff", "price_tamper",
              "workflow", "state_param", "idempotency", "coupon",
              "value_oracle", "bypass2", "authz_diff", "anti_auto",
              "platform_fp", "state_leak", "chains"):
        v = results.get(k)
        if isinstance(v, list):
            lines.append("- %s: %d rows" % (k, len(v)))
        elif isinstance(v, dict):
            lines.append("- %s: %s" % (k, "skipped (gate)" if v.get(
                "skipped") else "%d rows" % len(v.get("rows", []))))
    return "\n".join(lines) + "\n"


def write_reports(out, scope, F, ctx, meta, results, hyps, chains, matrix,
                  conf):
    """Sab artifacts likh (40+). Bodies REDACTED (names/booleans only)."""
    manifest = []
    targets = results.get("targets") or []
    verdict_rows = results.get("verdict_rows") or []

    def _w_json(name, obj):
        _rwx_save_json(os.path.join(out, name), obj)
        manifest.append(name)

    def _w_text(name, txt):
        _rwx_save_text(os.path.join(out, name), txt)
        manifest.append(name)

    # 1-3 targets/paths/ranking
    _w_json("logic_targets.json", {
        "count": len(targets),
        "targets": [{"url": t.get("url"), "score": t.get("score"),
                     "verb": (t.get("row") or {}).get("verb"),
                     "kinds": (t.get("row") or {}).get("kinds", []),
                     "sources": (t.get("row") or {}).get("sources", [])}
                    for t in targets]})
    _w_text("logic_endpoints.txt", "\n".join(
        sorted(set([t.get("url", "") for t in targets]))) + "\n")
    _w_json("logic_ranking.json", {
        "probe_cap": conf.get("logic_probe_cap"),
        "ranked": [{"url": t.get("url"), "score": t.get("score")}
                   for t in targets]})
    # 4 coverage
    _w_json("logic_coverage.json", {
        "mode": ctx.get("mode"), "sources": meta.get("sources", []),
        "probes_total": meta.get("probes_total", 0),
        "surface": ctx.get("coverage", {}),
        "gates": {k: bool(conf.get(k)) for k in
                  ("logic_allow_price_probe", "logic_allow_race_probe",
                   "logic_allow_workflow_probe", "logic_allow_param_echo",
                   "logic_allow_coupon_probe", "logic_allow_role_probe")}})
    # 5-8 param census + client trust
    _w_json("logic_param_census.json", results.get("param_census") or [])
    _w_json("logic_client_trust.json", {
        "rows": [{"target": r.get("target"),
                  "client_trust_price": r.get("client_trust_price"),
                  "price_fields": r.get("price_fields"),
                  "signed_amount": r.get("signed_amount"),
                  "csrf_in_form": r.get("csrf_in_form")}
                 for r in (results.get("param_census") or [])
                 if isinstance(r, dict) and not r.get("soft404")]})
    _w_json("logic_mined_forms.json", results.get("mined_params") or {})
    # 9-11 hidden params + role
    _w_json("logic_hidden_param.json", results.get("hidden_param") or {})
    _w_json("logic_role_diff.json", results.get("role_diff") or {})
    # 12-14 price tamper + value oracle
    _w_json("logic_price_tamper.json", results.get("price_tamper") or {})
    _w_json("logic_value_oracle.json", results.get("value_oracle") or {})
    _w_json("logic_value_matrix.json", {
        "matrix": [{"label": lbl, "value_shape": val}
                   for lbl, val in price_value_matrix(conf)]})
    # 15-17 workflow + state
    _w_json("logic_workflow.json", results.get("workflow") or {})
    _w_json("logic_state_param.json", results.get("state_param") or {})
    _w_text("logic_workflow_map.txt", "\n".join(
        "[%s] %s -> later=%s verdict=%s" % (
            r.get("target", "-"), r.get("shape", "-"),
            ",".join(r.get("later_accessible", []) or []),
            r.get("verdict", "-"))
        for r in (results.get("workflow") or {}).get("rows", [])) + "\n")
    # 18-19 race + idempotency
    _w_json("logic_race_techniques.json", {
        "count": len(DOCUMENTED_RACE_TECHNIQUES),
        "execution": "FORBIDDEN (manual+RoE wave only)",
        "parallelism": "NONE (sequential census only, cap 2)",
        "techniques": [{"name": n, "playbook": d}
                       for n, d in DOCUMENTED_RACE_TECHNIQUES]})
    _w_text("logic_playbooks.md",
            "# P20 business-logic playbooks (DOCUMENTED-ONLY)\n\n"
            "Execution manual+authorized wave me hi (RoE). Koi real "
            "transaction/redeem/transfer is module se KABHI nahi hoti.\n\n"
            + "\n\n".join("## %s\n%s" % (n, d) for n, d in
                          DOCUMENTED_BUSINESS_PLAYBOOKS) + "\n")
    _w_json("logic_idempotency.json", results.get("idempotency") or {})
    # 20-21 coupon + oracle
    _w_json("logic_coupon.json", results.get("coupon") or {})
    # 22 bypass2
    _w_json("logic_bypass2_matrix.json", results.get("bypass2") or {})
    # 23-25 authz + anti-auto + platform
    _w_json("logic_authz_diff.json", results.get("authz_diff") or [])
    _w_json("logic_anti_auto.json", results.get("anti_auto") or [])
    _w_json("logic_platform_fp.json", results.get("platform_fp") or {})
    # 26-27 state leaks + chains
    _w_json("logic_state_leak.json", results.get("state_leak") or {})
    _w_json("logic_chains_crossref.json",
            results.get("chains_crossref") or results.get("chains") or [])
    # 28-30 verdicts + findings
    _w_json("logic_verdicts.json", {
        "count": len(verdict_rows), "rows": verdict_rows,
        "sev_counts": _sev_counts(F)})
    _w_json("findings.json", {
        "phase": PHASE, "engine": "mod_logic v%s" % PLAN_VERSION,
        "engagement": scope.engagement,
        "generated_at": now_iso(),
        "sev_counts": _sev_counts(F),
        "findings": F.items})
    _w_text("LOGIC_FINDINGS.md", _findings_md(scope, F, ctx, meta, results))
    # 31-34 matrix/chains
    _w_json("logic_matrix.json", {
        "families": _FAMS, "row_count": len(matrix), "rows": matrix})
    _w_text("LOGIC_MATRIX.txt", _matrix_txt(matrix))
    _w_json("logic_kill_chains.json", {
        "count": len(chains),
        "active": sum(1 for c in chains if c.get("active")),
        "chains": chains})
    _w_text("logic_kill_chains.txt", "\n".join(
        "[%s%s] %s\n    %s\n" % (c["id"], "*" if c.get("active") else " ",
                                 c["title"], c["story"])
        for c in chains))
    # 35-39 hypotheses/test-plan/remediation/kickoff
    _w_json("logic_hypotheses.json", {
        "count": len(hyps), "hypotheses": hyps})
    _w_text("logic_test_plan.md", _test_plan_md(results, verdict_rows, conf))
    _w_text("logic_remediation.txt", _remediation_txt(verdict_rows))
    _w_text("logic_kickoff_guide.md", _kickoff_md(results, conf))
    # 40 feedforward + manifest (caller)
    return manifest



def build_logic_hypotheses(results, verdict_rows, chains, conf):
    """Offline hypotheses (P19 pattern): census-shapes -> manual-wave leads."""
    hyps = []
    def _h(title, basis, wave, priority="P2"):
        hyps.append({"title": title, "basis": basis[:160],
                     "manual_wave": wave, "priority": priority})

    pt = [r for r in (results.get("param_census") or [])
          if isinstance(r, dict) and r.get("client_trust_price")]
    if pt:
        _h("Client-trust total tamper PoC (own order)",
           "hidden price fields: %s" % ",".join(
               (pt[0].get("price_fields") or [])[:3]),
           "devtools tamper + server recalc check")
    wf = [r for r in (results.get("workflow") or {}).get("rows", [])
          if r.get("skip_signal")]
    if wf:
        _h("Workflow step-skip PoC (bina payment completion)",
           "later steps open: %s" % ",".join(
               wf[0].get("later_accessible", [])[:3]),
           "step walk + order-state audit")
    idem = [r for r in (results.get("idempotency") or {}).get("rows", [])
            if not r.get("idempotency_signal")]
    if idem:
        _h("Double-submit / race PoC planning (RoE-gated)",
           "idempotency absent on %s" % idem[0].get("target", "-"),
           "sequential PoC first; parallel sirf lab")
    cp = [r for r in (results.get("coupon") or {}).get("rows", [])
          if r.get("verdict") == "CONFIRMED"]
    if cp:
        _h("Coupon validation gap PoC (canary code accept)",
           cp[0].get("target", "-"), "single canary code manual")
    b2w = [r for r in (results.get("bypass2") or {}).get("rows", [])
           if any(v.get("nontrivial") or v.get("verdict") == "SUSPECTED"
                  for v in (r.get("variants") or {}).values())]
    if b2w:
        _h("Bypass2 param/parser differential PoC",
           "wins: %s" % ",".join(list(
               (b2w[0].get("variants") or {}).keys())[:3]),
           "manual differential + WAF log check")
    rl = [r for r in ((results.get("role_diff") or {}).get("rows") or
                      (results.get("hidden_param") or {}).get("rows", []))
          if (r.get("verdict") == "CONFIRMED" or r.get("echoed"))]
    if rl:
        _h("Role-param mass-assign PoC (own profile)",
           "echo rows: %d" % len(rl),
           "profile update + privilege audit")
    ch_act = [c for c in (chains or []) if c.get("active")]
    for c in ch_act[:4]:
        _h("Chain: %s" % c.get("title", "-"),
           "%s x %s" % (c.get("source"), c.get("overlap_target")),
           "chain-specific manual wave")
    if not hyps:
        _h("Baseline logic hygiene review", "no active signals",
           "LOGIC_MATRIX.txt playbook walkthrough", "P3")
    return hyps


# ===========================================================================
# RUN (Stage A..T orchestration) + CLI
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 20 - Business Logic Security (detection-only, INERT) (v%s) | %s"
         % (PLAN_VERSION, scope.describe()))
    warn("Logic discipline: koi REAL transaction/redeem/transfer KABHI nahi "
         "(canary waspP20 objects never exist) | race execution FORBIDDEN "
         "(gated census bhi 2 sequential canary GETs max) | zero egress | "
         "bodies REDACTED (names/booleans/sha1).")
    if conf.get("logic_allow_price_probe"):
        warn("Price/value canary probes ON (logic_allow_price_probe=true) "
             "- sirf validation-observable differential.")
    if conf.get("logic_allow_race_probe"):
        warn("Race census ON (logic_allow_race_probe=true) - 2 SEQUENTIAL "
             "canary requests HARD cap; NO parallel KABHI.")
    if conf.get("logic_allow_workflow_probe"):
        warn("Workflow step-skip census ON (logic_allow_workflow_probe=true)"
             " - GET-only differential.")
    if conf.get("logic_allow_param_echo"):
        warn("Hidden-param canary echo ON (logic_allow_param_echo=true).")
    if conf.get("logic_allow_coupon_probe"):
        warn("Coupon canary oracle ON (logic_allow_coupon_probe=true) - "
             "koi brute/loop nahi (hard cap 30 probes).")
    if conf.get("logic_allow_role_probe"):
        warn("Role-param differential ON (logic_allow_role_probe=true).")
    info("caps: paths=%s | probes=%s | params=%s | values=%s | workflow=%s | "
         "bypass2=%s | cold=%s"
         % (conf.get("logic_paths_cap"), conf.get("logic_probe_cap"),
            conf.get("logic_param_cap"), conf.get("logic_value_cap"),
            conf.get("logic_workflow_depth"), conf.get("logic_bypass2_cap"),
            conf.get("logic_cold_paths")))

    F = Findings()
    meta = {"probes_total": 0}
    ctx = {"out": out, "coverage": {}, "mode": "active",
           "base_dir": os.path.join(base_out, scope.engagement)}
    results = {}

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Logic surface discovery (13-module ff + P2/P5/P7/P8 "
         "+ form miner + cold pool)")
    ckA = "stageA:discovery"
    if cp.is_done(ckA):
        cached = cp.result_of(ckA) or {}
        disc = dict(cached)
        disc.setdefault("ranked", [])
        disc.setdefault("targets", [])
        disc.setdefault("sources", [])
        disc.setdefault("base_url", "")
        disc.setdefault("mined_params", {})
        ok("Replayed discovery (checkpoint)")
    else:
        disc = discover_logic_surface(ctx["base_dir"], scope, conf)
        cp.mark(ckA, disc, summary="logic surface")
    meta["sources"] = disc.get("sources", [])
    results["targets"] = rank_targets(disc.get("targets", []), conf)
    results["targets_all"] = disc.get("targets", [])[
        :int(conf.get("logic_paths_cap", 18))]
    results["ranked_all"] = disc.get("ranked", [])
    results["mined_params"] = disc.get("mined_params") or {}
    ctx["mined_sources"] = meta["sources"]
    ctx["coverage"]["surface"] = ("targets=%d ranked=%d" % (
        len(results["targets"]), len(disc.get("ranked", []))))
    ok("seed artifacts: %d sources | %s"
       % (len(meta["sources"]), ctx["coverage"]["surface"]))
    base_url = disc.get("base_url") or (scope.seed_urls() or [""])[0]

    # ---------------- PASSIVE MODE ----------------
    if not getattr(cfg, "allow_active", True):
        warn("allow_active=False -> PASSIVE mode: mining + offline "
             "hypotheses (0 network probes).")
        ctx["mode"] = "passive"
        results.update({"param_census": [], "hidden_param": {}, "role_diff":
                        {}, "price_tamper": {}, "value_oracle": {},
                        "workflow": {}, "state_param": {}, "idempotency": {},
                        "coupon": {}, "bypass2": {}, "authz_diff": [],
                        "anti_auto": [], "platform_fp": {}, "state_leak": {},
                        "chains": [], "verdict_rows": []})
        chains = build_logic_chains(F, results, [], results["targets"],
                                    meta, conf)
        results["chains"] = chains
        hyps = build_logic_hypotheses(results, [], chains, conf)
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
    results["home_body"] = ""
    try:
        rhome = http.get(base_url, allow_redirects=False)
        meta["probes_total"] = meta.get("probes_total", 0) + 1
        meta["home_sig"] = {"status": rhome.status,
                            "len": len(rhome.body or b"")}
        try:
            results["home_body"] = (rhome.body or b"").decode(
                "utf-8", "ignore")[:4000]
        except Exception:
            results["home_body"] = ""
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

    # ---------------- Stage C: param/state census ----------------
    head("Stage C - Param/state census (forms/hidden/price/state shapes)")
    ckC = "stageC:param_census"
    if cp.is_done(ckC):
        results["param_census"] = cp.result_of(ckC) or []
        ok("Replayed param census (checkpoint)")
    else:
        results["param_census"] = param_census(http, results["targets"],
                                               meta, conf)
        cp.mark(ckC, results["param_census"], summary="param census")
    n_ct = client_trust_findings(results["param_census"], F)
    live_n = sum(1 for r in results["param_census"]
                 if isinstance(r, dict) and not r.get("soft404"))
    verb_any = False
    for r in results["param_census"]:
        if isinstance(r, dict) and not r.get("soft404") and \
                (r.get("verb") or (t_row(r) or {}).get("verb")):
            F.add("logic_endpoint_live", "Logic endpoint live", r["target"],
                  "verb/state shape census", "logic_param_census.json")
            verb_any = True
            break
    if verb_any:
        F.add("logic_verb_census", "Commerce verb-shape census",
              base_url, "order/redeem/transfer-shaped endpoints ranked "
              "(business-flow map)", "logic_targets.json")
    ok("param census: %d targets | %d client-trust rows" % (
        len(results["param_census"]), n_ct))

    # ---------------- Stage D: hidden-param + role ----------------
    head("Stage D - Hidden-param canary matrix + role differential (GATED)")
    results["hidden_param"] = hidden_param_matrix(http, results["targets"],
                                                  meta, conf, _canary("hp"))
    if not (results["hidden_param"] or {}).get("skipped"):
        for r in (results["hidden_param"].get("rows") or []):
            for e in (r.get("echoed") or []):
                if ROLE_PARAM_RE.match(e.get("param", "")):
                    F.add("logic_role_param_echo",
                          "Role-param canary echo", r["target"],
                          "param=%s reflected (canary)" % e.get("param"),
                          "logic_hidden_param.json")
                else:
                    F.add("logic_param_echo", "Canary param echo",
                          r["target"], "param=%s reflected" % e.get("param"),
                          "logic_hidden_param.json")
        ok("hidden-param: %d rows | probes=%d" % (
            len((results["hidden_param"]).get("rows", [])),
            (results["hidden_param"]).get("probes", 0)))
    else:
        info("hidden-param: GATED (logic_allow_param_echo=false) - %d "
             "techniques documented" %
             len((results["hidden_param"]).get("techniques_documented", [])))
    results["role_diff"] = role_param_diff(http, results["targets"], meta,
                                           conf, _canary("rp"))
    if not (results["role_diff"] or {}).get("skipped"):
        for r in (results["role_diff"].get("rows") or []):
            if r.get("verdict") in ("CONFIRMED", "SUSPECTED"):
                F.add("logic_role_param_echo", "Role differential signal",
                      r["target"], "verdict=%s" % r.get("verdict"),
                      "logic_role_diff.json")

    if interrupted():
        warn("interrupted - partial save")

    # ---------------- Stage E: price tamper ----------------
    head("Stage E - Price/qty tamper census (GATED canary value-matrix)")
    ckE = "stageE:price"
    if cp.is_done(ckE):
        results["price_tamper"] = cp.result_of(ckE) or {}
        ok("Replayed price census (checkpoint)")
    else:
        results["price_tamper"] = price_tamper_census(
            http, results["targets"], meta, conf, _canary("pr"))
        cp.mark(ckE, results["price_tamper"], summary="price tamper")
    for r in (results["price_tamper"].get("rows") or []):
        if r.get("verdict") == "CONFIRMED":
            bad = [k for k, v in (r.get("variants") or {}).items()
                   if v.get("verdict") == "CONFIRMED"]
            key = ("logic_negative_accepted"
                   if any(b.startswith("negative") for b in bad) else
                   "logic_zero_accepted" if any(b in ("zero", "negative_zero")
                                                for b in bad) else
                   "logic_huge_accepted" if any(b in ("huge", "overflow_ish")
                                                for b in bad) else
                   "logic_type_juggle" if "string_in_num" in bad else
                   "logic_price_probe_confirmed")
            F.add(key, "Canary value validation gap", r["target"],
                  "accepted variants: %s (canary object - koi real tx nahi)"
                  % ",".join(bad[:4]), "logic_price_tamper.json")
        elif r.get("verdict") == "SUSPECTED":
            F.add("logic_price_probe_suspected", "Price validation partial",
                  r["target"], "mixed variant verdicts",
                  "logic_price_tamper.json")
    ok("price: %d rows" % len((results["price_tamper"]).get("rows", [])))

    # ---------------- Stage I: numeric edge oracle ----------------
    head("Stage I - Numeric edge oracle (points/credits/bid canary shapes)")
    results["value_oracle"] = value_oracle_census(
        http, results["targets"], meta, conf, _canary("vo"))
    for r in (results["value_oracle"].get("rows") or []):
        sus = [k for k, v in (r.get("variants") or {}).items()
               if v.get("verdict") == "SUSPECTED"]
        if sus:
            F.add("logic_value_oracle", "Numeric edge differential",
                  r["target"], "accepted shapes: %s" % ",".join(sus[:4]),
                  "logic_value_oracle.json")
    ok("oracle: %d rows" % len((results["value_oracle"]).get("rows", [])))

    # ---------------- Stage F: workflow census ----------------
    head("Stage F - Workflow/state-machine census (GATED)")
    ckF = "stageF:workflow"
    if cp.is_done(ckF):
        results["workflow"] = cp.result_of(ckF) or {}
        results["state_param"] = cp.result_of(ckF + ":sp") or {}
        ok("Replayed workflow census (checkpoint)")
    else:
        results["workflow"] = workflow_census(http, results["targets"], meta,
                                              conf, base_url, _canary("wf"))
        results["state_param"] = state_param_census(http, results["targets"],
                                                    meta, conf, _canary("sp"))
        cp.mark(ckF, results["workflow"], summary="workflow census")
        cp.mark(ckF + ":sp", results["state_param"], summary="state param")
    for r in (results["workflow"].get("rows") or []):
        if r.get("verdict") == "CONFIRMED":
            F.add("logic_workflow_skip", "Workflow step-skip signal",
                  r["target"], "later steps open bina prior completion: %s"
                  % ",".join(r.get("later_accessible", [])[:3]),
                  "logic_workflow.json")
    for r in (results["state_param"].get("rows") or []):
        acc = [k for k, v in (r.get("variants") or {}).items()
               if v.get("reflected")]
        if acc:
            F.add("logic_workflow_state_client", "State param reflected",
                  r["target"], "variants: %s" % ",".join(acc[:4]),
                  "logic_state_param.json")
    ok("workflow: %d rows | skip=%d" % (
        len((results["workflow"]).get("rows", [])),
        sum(1 for r in (results["workflow"]).get("rows", [])
            if r.get("skip_signal"))))

    # ---------------- Stage G: race surface (GATED) ----------------
    head("Stage G - Race-condition surface (10 documented + GATED "
         "idempotency census, 2-seq cap)")
    results["idempotency"] = idempotency_census(http, results["targets"],
                                                meta, conf, _canary("rc"))
    if not (results["idempotency"] or {}).get("skipped"):
        for r in (results["idempotency"].get("rows") or []):
            if not r.get("idempotency_signal"):
                F.add("logic_idempotency_absent",
                      "Idempotency signal absent", r["target"],
                      "2-sequential canary census (execution FORBIDDEN)",
                      "logic_idempotency.json")
                if r.get("same_response_shape"):
                    F.add("logic_dedup_absent", "Dedup signal absent",
                          r["target"], "identical accept-shape dono canary "
                          "requests par (census; execution FORBIDDEN)",
                          "logic_idempotency.json")
            else:
                F.add("logic_idempotency_present",
                      "Idempotency signal present", r["target"],
                      "positive control", "logic_idempotency.json")
        ok("idempotency: %d rows" % len(
            (results["idempotency"]).get("rows", [])))
    else:
        info("race: GATED (logic_allow_race_probe=false) - %d techniques "
             "documented" % len(DOCUMENTED_RACE_TECHNIQUES))
    F.add("logic_race_surface", "Race-condition primitives documented",
          base_url, "%d techniques DOCUMENTED-ONLY (execution manual+RoE; "
          "koi parallel request is module se KABHI nahi jaata)"
          % len(DOCUMENTED_RACE_TECHNIQUES), "logic_race_techniques.json")

    if interrupted():
        warn("interrupted - partial save")

    # ---------------- Stage H: coupon oracle ----------------
    head("Stage H - Coupon/redeem validation oracle (GATED)")
    results["coupon"] = coupon_census(http, results["targets"], meta, conf,
                                      _canary("cp"))
    if not (results["coupon"] or {}).get("skipped"):
        for r in (results["coupon"].get("rows") or []):
            if r.get("verdict") == "CONFIRMED":
                F.add("logic_coupon_accepted_any",
                      "Canary coupon accepted", r["target"],
                      "invalid canary code validation pass",
                      "logic_coupon.json")
            elif r.get("case_edge"):
                F.add("logic_coupon_case_edge", "Coupon variant edge",
                      r["target"], "case/pad differential",
                      "logic_coupon.json")
            if not r.get("limit_headers"):
                F.add("logic_limit_absent", "Redeem/attempt limit absent",
                      r["target"], "no rate/limit headers on coupon/redeem "
                      "census (DoS execution FORBIDDEN)",
                      "logic_coupon.json")
        ok("coupon: %d rows" % len((results["coupon"]).get("rows", [])))
    else:
        info("coupon: GATED (logic_allow_coupon_probe=false)")

    # ---------------- Stage J: bypass2 matrix ----------------
    head("Stage J - Bypass matrix v2 (17 SECRET logic techniques)")
    ckJ = "stageJ:bypass2"
    if cp.is_done(ckJ):
        results["bypass2"] = cp.result_of(ckJ) or []
        ok("Replayed bypass2 (checkpoint)")
    else:
        results["bypass2"] = bypass2_matrix(http, scope, results["targets"],
                                            meta, conf, base_url,
                                            _canary("b2"))
        cp.mark(ckJ, results["bypass2"], summary="bypass2 matrix")
    b2 = results["bypass2"] if isinstance(results["bypass2"], dict) \
        else {"rows": results["bypass2"]}
    for r in (b2.get("rows") or []):
        wins_route = [k for k, v in (r.get("variants") or {}).items()
                      if v.get("nontrivial") and
                      v.get("class") == "route_misroute"]
        wins_param = [k for k, v in (r.get("variants") or {}).items()
                      if v.get("verdict") == "SUSPECTED"]
        if wins_route:
            F.add("logic_bypass2_route_misroute", "Edge-misroute step win",
                  r["target"], "variants: %s" % ",".join(wins_route[:4]),
                  "logic_bypass2_matrix.json")
        elif wins_param:
            F.add("logic_bypass2_param_smuggle", "Param-smuggle win",
                  r["target"], "variants: %s" % ",".join(wins_param[:4]),
                  "logic_bypass2_matrix.json")
    ok("bypass2: %d rows" % len(b2.get("rows", [])))

    # ---------------- Stage K: authz context diff ----------------
    head("Stage K - Authz-context differential (anon vs canary-cookie) "
         "+ re-auth census")
    cookie_hdr = None
    try:
        cookie_hdr = getattr(cfg, "test_cookie", None) or None
    except Exception:
        cookie_hdr = None
    results["authz_diff"] = authz_context_diff(http, results["targets"],
                                               meta, conf, _canary("az"),
                                               cookie_header=cookie_hdr)
    for r in (results["authz_diff"] or []):
        if r.get("privileged_shape_preauth"):
            F.add("logic_privilege_preauth", "Privileged shape pre-auth",
                  r["target"], "admin/approve shapes anon 200 me",
                  "logic_authz_diff.json")
        if r.get("reauth_signal") is False and \
                200 <= (r.get("anon_status") or 0) < 300:
            F.add("logic_no_reauth", "Re-auth census absent", r["target"],
                  "sensitive action par re-auth shape nahi",
                  "logic_authz_diff.json")
    ok("authz-diff: %d rows" % len(results["authz_diff"] or []))

    # ---------------- Stage L: chains ----------------
    head("Stage L - Cross-module logic chains (13 handoff cross-ref)")
    if conf.get("logic_chain_build", True):
        results["chains"] = chain_logic(ctx["base_dir"],
                                        results.get("ranked_all") or
                                        results.get("targets_all") or
                                        results["targets"],
                                        conf)
        for c in (results["chains"] or []):
            if not c.get("active"):
                continue
            key = ("logic_chain_idor_price" if c.get("tag") == "idor_price"
                   else "logic_chain_massassign_role" if c.get("tag") in
                   ("massassign", "writable", "gql_authz")
                   else "logic_chain_ws_bid" if c.get("tag") == "ws_channel"
                   else "logic_chain_upload_invoice" if c.get("tag") ==
                   "upload" else None)
            if key:
                F.add(key, "Logic chain active", c.get("overlap_target") or
                      "-", "src=%s obj=%s" % (c.get("source"),
                                              c.get("object_shape")),
                      "logic_chains_crossref.json")
            if c.get("tag") in ("massassign", "writable"):
                F.add("logic_massassign_crossref",
                      "Mass-assign x logic overlap", c.get("overlap_target")
                      or "-", "P17/P18 handoff objects logic surface par "
                      "overlap", "logic_chains_crossref.json")
        ok("chains: %d (%d active)" % (len(results["chains"] or []),
                                       sum(1 for c in
                                           (results["chains"] or [])
                                           if c.get("active"))))
    else:
        results["chains"] = []
        results["chains_crossref"] = []
        info("chains: OFF (logic_chain_build=false)")
    results["chains_crossref"] = results.get("chains") or []

    # ---------------- Stage M: anti-auto census ----------------
    head("Stage M - Anti-automation positive-control census")
    results["anti_auto"] = anti_auto_census(http, results["targets"], meta,
                                            conf,
                                            pc_rows=results["param_census"])
    for r in (results["anti_auto"] or []):
        if r.get("verdict") == "ABSENT":
            F.add("logic_no_csrf_state_change", "No anti-automation controls",
                  r["target"], "csrf/confirm/limit signals absent",
                  "logic_anti_auto.json")
        elif r.get("verdict") == "HARDENED":
            F.add("logic_anti_auto_present", "Anti-automation controls",
                  r["target"], "controls=%d" % r.get("controls_present", 0),
                  "logic_anti_auto.json")
    ok("anti-auto: %d rows" % len(results["anti_auto"] or []))

    # ---------------- Stage N: platform fingerprint ----------------
    head("Stage N - Commerce platform fingerprint (census-only)")
    results["platform_fp"] = platform_fingerprint(http, base_url, meta,
                                                  conf, results)
    for p in (results["platform_fp"].get("platforms") or []):
        F.add("logic_platform_fp", "Commerce platform: %s" % p.get("name"),
              base_url, p.get("note", ""), "logic_platform_fp.json")
    ok("platform: %s" % ([p.get("name") for p in
                          (results["platform_fp"].get("platforms") or [])]
                         or "none"))

    # ---------------- Stage O: state/secret leaks ----------------
    head("Stage O - State/secret leak census (offline)")
    results["state_leak"] = state_leak_census(results, conf)
    for r in (results["state_leak"].get("rows") or []):
        if "state_blob_field" in (r.get("flags") or []):
            F.add("logic_state_leak", "State blob in client", r["target"],
                  "flags: %s" % ",".join(r.get("flags", [])[:4]),
                  "logic_state_leak.json")
        if "testish_field" in (r.get("flags") or []):
            F.add("logic_test_sku", "Test/sandbox-shaped field exposed",
                  r["target"], "flags: %s" % ",".join(
                      r.get("flags", [])[:4]), "logic_state_leak.json")
    ok("state-leak: %d rows" % len((results["state_leak"]).get("rows", [])))

    if interrupted():
        warn("interrupted - partial save")

    # ---------------- Stage P: verdict engine ----------------
    head("Stage P - Verdict engine (6-class ladder)")
    results["verdict_rows"] = verdict_engine(results, meta, conf)
    ok("verdicts: %d rows (%d CONFIRMED / %d SUSPECTED)" % (
        len(results["verdict_rows"]),
        sum(1 for v in results["verdict_rows"]
            if v["verdict"] == "CONFIRMED"),
        sum(1 for v in results["verdict_rows"]
            if v["verdict"] == "SUSPECTED")))

    # ---------------- Stage Q: kill-chains ----------------
    head("Stage Q - Kill-chains (20 business-logic chains)")
    results["chains_final"] = build_logic_chains(F, results,
                                                 results["verdict_rows"],
                                                 results["targets"], meta,
                                                 conf)
    ok("chains: %d (%d active)" % (len(results["chains_final"]),
                                   sum(1 for c in results["chains_final"]
                                       if c.get("active"))))

    # ---------------- Stage R: technique matrix ----------------
    head("Stage R - Technique matrix (150+ rows x 18 families)")
    matrix = build_technique_matrix(results, conf)
    ok("matrix: %d rows" % len(matrix))

    # ---------------- Stage S: reports ----------------
    head("Stage S - Reports/artifacts (40+ outputs)")
    hyps = build_logic_hypotheses(results, results["verdict_rows"],
                                  results["chains_final"], conf)
    results["chains"] = results["chains_final"]
    manifest = write_reports(out, scope, F, ctx, meta, results, hyps,
                             results["chains_final"], matrix, conf)

    # ---------------- Stage T: feedforward + manifest ----------------
    head("Stage T - Feedforward handoff (P21/P22/P23/P25/P11/P12/P32) + "
         "manifest")
    ff = {"to_phase21_authz": {
              "logic_privileged_targets": [v.get("target") for v in
                                           results["verdict_rows"]
                                           if v.get("key") in
                                           ("logic_privilege_preauth",
                                            "logic_role_param_echo")][:6]},
          "to_phase22_replay": {
              "race_primitives": [n for n, _ in DOCUMENTED_RACE_TECHNIQUES][:10],
              "idempotency_gaps": [r.get("target") for r in
                                   (results["idempotency"].get("rows") or [])
                                   if not r.get("idempotency_signal")][:6]},
          "to_phase23_misconfig": {
              "test_sku_flags": [r.get("target") for r in
                                 (results["state_leak"].get("rows") or [])
                                 if "testish_field" in
                                 (r.get("flags") or [])][:6],
              "platform": [p.get("name") for p in
                           (results["platform_fp"].get("platforms") or [])]},
          "to_phase25_controls": {
              "anti_auto_gaps": [r.get("target") for r in
                                 (results["anti_auto"] or [])
                                 if r.get("verdict") == "ABSENT"][:6],
              "waf_blind": bool(results.get("waf"))},
          "to_phase11_bola": {
              "order_surface": [t.get("url") for t in results["targets"]
                                if (t.get("row") or {}).get("verb")][:6],
              "price_targets": [t.get("url") for t in results["targets"]
                                if (t.get("row") or {}).get(
                                    "has_price_shape")][:6]},
          "to_phase12_inject": {
              "coupon_fields": [t.get("url") for t in results["targets"]
                                if (t.get("row") or {}).get(
                                    "has_coupon_shape")][:4]},
          "to_phase32_report": {"findings": len(F.items),
                                "probes": meta.get("probes_total", 0)}}
    write_feedforward(out, PHASE, ff,
                      notes=["P20 Business Logic: %d targets, %d findings, "
                             "%d documented race techniques"
                             % (len(results["targets"]), len(F.items),
                                len(DOCUMENTED_RACE_TECHNIQUES))])
    manifest.append("feedforward.json")
    write_manifest(out, PHASE, manifest,
                   stats={"probes": meta.get("probes_total", 0),
                          "findings": len(F.items),
                          "targets": len(results["targets"]),
                          "matrix_rows": len(matrix),
                          "chains": len(results["chains_final"]),
                          "chains_active": sum(1 for c in
                                               results["chains_final"]
                                               if c.get("active")),
                          "hypotheses": len(hyps),
                          "verdicts": len(results["verdict_rows"]),
                          "documented_race": len(DOCUMENTED_RACE_TECHNIQUES),
                          "elapsed_s": round(time.time() - t_start, 1)})
    _rwx_tree(out)
    ok("P20 done: %d findings | %d matrix rows | %d chains | probes=%d | "
       "%.1fs" % (len(F.items), len(matrix), len(results["chains_final"]),
                  meta.get("probes_total", 0), time.time() - t_start))
    return out


def t_row(r):
    """param_census row se verb shape (compat helper)."""
    if not isinstance(r, dict):
        return None
    u = r.get("target") or ""
    cls = classify_logic_path(u)
    return cls if cls.get("verb") else None


def main():
    print("WASP mod_logic.py (Phase 20 - Business Logic, v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 20   (ya --module logic)")
    print("  self-test : python3 test_mod_logic.py")
    print("\n  RoE gates (config.json): logic_allow_price_probe=false "
          "(default), logic_allow_race_probe=false (default), "
          "logic_allow_workflow_probe=false (default), "
          "logic_allow_param_echo=false (default), "
          "logic_allow_coupon_probe=false (default), "
          "logic_allow_role_probe=false (default)")
    print("  Safety: koi REAL transaction KABHI nahi (canary waspP20) | "
          "race execution FORBIDDEN (2-sequential canary cap) | zero "
          "egress | bodies REDACTED")
    print("  v20 ULTRA: +price-tamper census +workflow-skip +race surface "
          "(10 documented) +coupon oracle +negative/edge values +bypass2 "
          "(17 secret) +role-diff +anti-auto +platform-fp +chains +20 "
          "kill-chains +150-row matrix")


if __name__ == "__main__":
    main()

