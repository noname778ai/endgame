#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP LICENSE GATE v2.0 (tier-based)
================================================================================
Token-based licensing (Open-Core: Free First, Paid Later).

KAISE KAAM KARTA HAI
--------------------
1. Token resolve order :  --token flag  >  WASP_TOKEN env var  >  cached token
                          (~/.wasp/token_cache.json)  >  interactive prompt
2. Offline demo token (public - sirf FREE tier):
     WASP-FREE-2025-DEMO   -> FREE tier (P2-P8 recon block)
3. Owner-issued tokens : ~/.wasp/extra_tokens.json file me manually entry jodo
     (public code me PRO tokens KABHI nahi hote):
       {"WASP-PRO-XXXX-YYYY": {"tier": "PRO", "expires": "2026-12-31"}}
4. Server mode: WASP_API_URL env var set karo -> verify_via_api()
     POST <WASP_API_URL>  {"token": "..."}  ->  {"valid": true, "tier": "...",
     "expires": "...", "user": "..."}  (5s timeout, fail = offline fallback)
5. Gate sirf TESTING commands par lagta hai (run/runall). Diagnostics FREE:
     list | doctor | verify | status | selftest | findings | report | chain
6. Non-interactive shells (CI/piped) me token na ho to CLEAR error + exit,
   prompt hang NAHI hota (sys.stdin.isatty() check).

TIER POLICY (v2.0 - open-core)
-------------------------------
  FREE : P2-P8 recon block (7 modules) - public demo token se
  PRO  : P2-P32 poora toolkit (P9+ sirf yahan unlock hote hain)
         - P9-P11  auth/sessions/access
         - P12-P16 injection/xss/ssrf/files/client
         - P17-P22 api/graphql/ws/logic/authz/replay
         - P23-P26 misconfig/cloud/controls/scanval
         - P27-P32 evidence/chaining/cvss/remediation/retest/reporting

AUDIT
-----
Har successful gate ek append-only line likhta hai:
  <out-base>/<engagement>/license_audit.jsonl
================================================================================
"""
import os
import sys
import re
import json
import time
import random
import hashlib
import hmac as _hmac
import urllib.request

LICENSE_VERSION = "2.1"
TOKEN_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".wasp")
TOKEN_CACHE_PATH = os.path.join(TOKEN_CACHE_DIR, "token_cache.json")
EXTRA_TOKENS_PATH = os.path.join(TOKEN_CACHE_DIR, "extra_tokens.json")

# FREE tier limit: sirf P2-P8 (block1_recon) chalta hai FREE token se.
# P9 se aage ke modules PRO tier maangte hain.
FREE_TIER_MAX_PHASE = 8

# ---------------------------------------------------------------------------
# SIGNED TOKEN SYSTEM (offline PRO tokens - customer ke machine pe verify hota hai)
#   Format : WASP-<TIER>-<YYYY-MM-DD>-<tag>-<hmac16>
#   Example: WASP-PRO-2026-12-31-rahul7-a3f9c2b81d4e5f60
#   Owner token banata hai:  python3 wasp_license.py issue PRO 2026-12-31 rahul7
#   Customer sirf export WASP_TOKEN=<token> karta hai - bas.
#
#   SECURITY NOTE: ye secret SHIPPED CODE me hai (private-repo period ke liye
#   theek). PUBLIC LAUNCH se pehle signing server-side karni hogi
#   (WASP_API_URL), warna code padhne wala tokens forge kar sakta hai.
# ---------------------------------------------------------------------------
TOKEN_SIGNING_SECRET = "wasp~sign~7f3a9c1e5b2d84a690cf4e13d7b8a259"

_SIGNED_TOKEN_RE = re.compile(
    r"^WASP-([A-Z]+)-(\d{4}-\d{2}-\d{2})-([a-z0-9]{4,16})-([0-9a-f]{16})$")


def _sign(payload):
    return _hmac.new(TOKEN_SIGNING_SECRET.encode("utf-8"),
                     payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def make_token(tier="PRO", expires="2026-12-31", tag=None):
    """Naya signed token banao. tag = customer ka short naam (unique/revoke).
    Return (token, tag)."""
    tier = str(tier).strip().upper()
    exp = str(expires).strip()
    if not tag:
        tag = "".join(random.choice("abcdefghjkmnpqrstuvwxyz23456789")
                      for _ in range(6))
    tag = str(tag).strip().lower().replace(" ", "")[:16] or "cust1"
    tok = "WASP-%s-%s-%s-%s" % (tier, exp, tag, _sign("WASP|%s|%s|%s" % (tier, exp, tag)))
    return tok, tag


def _verify_signed(token):
    """Signed token check (sig + expiry). dict | None."""
    m = _SIGNED_TOKEN_RE.match(token or "")
    if not m:
        return None
    tier, exp, tag, sig = m.groups()
    if _sign("WASP|%s|%s|%s" % (tier, exp, tag)) != sig:
        return None
    if _expired(exp):
        return None
    return {"tier": tier, "expires": exp, "user": tag, "source": "offline-signed"}

# ---------------------------------------------------------------------------
# OFFLINE DEMO TOKEN (public - sirf FREE tier advertise hota hai)
# NOTE: koi bhi PRO token public code me KABHI nahi rakhna (leak ho jayega).
#       Owner apne paid tokens ~/.wasp/extra_tokens.json me daalta hai
#       (wo file gitignored hai) ya server verify (WASP_API_URL) use karta hai.
# ---------------------------------------------------------------------------
DEMO_TOKENS = {
    "WASP-FREE-2025-DEMO": {"tier": "FREE", "expires": "2027-12-31"},
    # TEST-ONLY PRO token (private-repo testing ke liye).
    # PUBLIC LAUNCH SE PEHLE: is line ko HATA DO - warna koi bhi code padh ke
    # PRO le lega. Public launch par PRO verify sirf WASP_API_URL se hoga.
    "WASP-PRO-2025-DEMO":  {"tier": "PRO",  "expires": "2027-12-31"},
}

TIERS = {
    "FREE": {"name": "Free", "features": "P2-P8 recon block (7 modules), community support"},
    "PRO":  {"name": "Pro",  "features": "poora toolkit P2-P32 (P9+ unlock) + (future) "
                                          "no report watermark + priority updates + API verify"},
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _now_ymd():
    return time.strftime("%Y-%m-%d", time.gmtime())


def _expired(expires):
    try:
        return str(_now_ymd()) > str(expires)
    except Exception:
        return False


def _load_extra_tokens():
    """Owner-issued tokens (~/.wasp/extra_tokens.json) - gitignored file.
    Owner paid customer tokens yahan manually add karta hai; ye public repo
    me KABHI nahi jaate. Format:
        {"WASP-PRO-XXXX-YYYY": {"tier": "PRO", "expires": "2026-12-31"}}
    """
    try:
        if os.path.exists(EXTRA_TOKENS_PATH):
            with open(EXTRA_TOKENS_PATH) as f:
                d = json.load(f)
            if isinstance(d, dict):
                return {str(k): v for k, v in d.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def tier_allows_phase(tier, phase_num):
    """FREE tier sirf P2-P8 chala sakta hai; PRO sab kuch. Fail-safe:
    unknown/garbage tier -> FREE limit lagti hai (fail-closed)."""
    try:
        p = int(str(phase_num).strip().upper().lstrip("P"))
    except Exception:
        return True  # bina phase-number wale (future) modules - block nahi karte
    t = str(tier or "FREE").strip().upper()
    if t in ("PRO", "TEAM", "UNLIMITED", "LIFETIME"):
        return True
    return p <= FREE_TIER_MAX_PHASE


def verify_via_api(token, api_url=None):
    """Future server-side verify. dict|None (None = server unavailable/skip)."""
    url = api_url or os.environ.get("WASP_API_URL") or ""
    if not url:
        return None
    try:
        req = urllib.request.Request(
            url, data=json.dumps({"token": token}).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "User-Agent": "WASP-LicenseGate/%s" % LICENSE_VERSION},
            method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read().decode("utf-8", "ignore"))
            if isinstance(d, dict) and d.get("valid"):
                return {"tier": str(d.get("tier", "FREE")).upper(),
                        "expires": str(d.get("expires", "2099-12-31")),
                        "user": d.get("user"), "source": "api"}
    except Exception:
        return None
    return None


def verify_token(token):
    """Token -> license dict | None (invalid/expired).
    Lookup order: demo tokens > owner extra_tokens.json > signed token > server."""
    token = (token or "").strip()
    if not token:
        return None
    d = DEMO_TOKENS.get(token) or _load_extra_tokens().get(token)
    if d:
        if _expired(d.get("expires")):
            return None
        return {"tier": d["tier"], "expires": d["expires"],
                "user": d.get("tag", "demo"), "source": "offline"}
    signed = _verify_signed(token)
    if signed:
        return signed
    api = verify_via_api(token)
    if api:
        if _expired(api.get("expires")):
            return None
        return api
    return None


def load_cached_token():
    try:
        if os.path.exists(TOKEN_CACHE_PATH):
            d = json.load(open(TOKEN_CACHE_PATH))
            tok = str(d.get("token", "")).strip()
            if tok and not _expired(d.get("expires", "1970-01-01")):
                return tok
    except Exception:
        pass
    return None


def save_cached_token(token, lic):
    try:
        os.makedirs(TOKEN_CACHE_DIR, exist_ok=True)
        with open(TOKEN_CACHE_PATH, "w") as f:
            json.dump({"token": token, "tier": lic.get("tier"),
                       "expires": lic.get("expires"),
                       "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                 time.gmtime())}, f, indent=2)
        os.chmod(TOKEN_CACHE_PATH, 0o600)
        return True
    except Exception:
        return False


def resolve_token(cli_token=None, interactive=None):
    """--token > env WASP_TOKEN > cache > prompt (sirf TTY par)."""
    if cli_token and cli_token.strip():
        return cli_token.strip()
    env = (os.environ.get("WASP_TOKEN") or "").strip()
    if env:
        return env
    cached = load_cached_token()
    if cached:
        return cached
    if interactive is None:
        interactive = sys.stdin.isatty()
    if interactive:
        try:
            t = input("License token (WASP-FREE-2025-DEMO = free tier): ").strip()
            return t or None
        except (EOFError, KeyboardInterrupt):
            return None
    return None


# ---------------------------------------------------------------------------
# the gate - wasp.py main() isi ko call karta hai (run/runall ke liye)
# ---------------------------------------------------------------------------
def gate_license(token=None, stream=sys.stderr):
    """Pass -> prints OK. Fail -> clear error + sys.exit(2)."""
    tok = resolve_token(cli_token=token)
    if not tok:
        stream.write(
            "\n[x] WASP LICENSE REQUIRED (command: run/runall)\n"
            "    Token do - kisi ek tareeke se:\n"
            "      1) --token WASP-FREE-2025-DEMO\n"
            "      2) export WASP_TOKEN=WASP-FREE-2025-DEMO\n"
            "    FREE tier = P2-P8 recon block. P9+ modules PRO tier me hain.\n"
            "    Token ek baar daalne par cache ho jaata hai.\n"
            "    Detail: README.md -> License System.\n\n")
        sys.exit(2)
    lic = verify_token(tok)
    if not lic:
        stream.write(
            "\n[x] INVALID / EXPIRED TOKEN: %s...\n"
            "    Free demo token: WASP-FREE-2025-DEMO  (README.md -> License)\n"
            "    Agar ye tumhara paid token hai to WASP_API_URL server check karo.\n\n"
            % (tok[:12] + "..."))
        sys.exit(2)
    # success -> cache + audit line
    if load_cached_token() != tok:
        save_cached_token(tok, lic)
    tier = TIERS.get(lic["tier"], TIERS["FREE"])
    try:
        from wasp_core import ok
        ok("license: %s tier (%s) | expires %s | source %s"
           % (lic["tier"], tier["features"], lic.get("expires"), lic.get("source")))
    except Exception:
        stream.write("[i] license: %s tier | expires %s\n"
                     % (lic["tier"], lic.get("expires")))
    audit_license(lic, tok)
    return lic


def audit_license(lic, tok):
    """Append-only audit line (engagement folder me, agar available ho)."""
    try:
        base = os.path.abspath(os.path.expanduser(
            os.environ.get("WASP_OUT") or "~/wasp_out"))
        # engagement name scope.json se (agar padh sako)
        eng = "unnamed"
        try:
            from wasp_core import load_json
            for cand in (os.path.join(os.getcwd(), "scope.json"),
                         os.path.join(os.path.dirname(os.path.abspath(
                             sys.argv[0])), "scope.json")):
                d = load_json(cand, None)
                if isinstance(d, dict) and d.get("engagement"):
                    eng = str(d.get("engagement"))[:64]
                    break
        except Exception:
            pass
        d = os.path.join(base, eng)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "license_audit.jsonl"), "a") as f:
            f.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": "license_ok", "tier": lic.get("tier"),
                "expires": lic.get("expires"), "source": lic.get("source"),
                "token_sha1_12": __import__("hashlib").sha1(
                    tok.encode("utf-8", "ignore")).hexdigest()[:12],
                "cmd": " ".join(sys.argv[1:6])}) + "\n")
    except Exception:
        pass  # audit kabhi run nahi rokti


def self_test():
    """python3 wasp_license.py  -> offline sanity check."""
    print("WASP license gate v%s" % LICENSE_VERSION)
    print("  demo tokens : %s" % ", ".join(sorted(DEMO_TOKENS)))
    print("  free token  : %s" % ("OK" if verify_token("WASP-FREE-2025-DEMO") else "FAIL"))
    print("  pro token   : %s" % ("OK" if verify_token("WASP-PRO-2025-DEMO") else "FAIL"))
    print("  bad token   : %s" % ("OK (rejected)" if not verify_token("FAKE-123") else "FAIL"))
    print("  empty       : %s" % ("OK (rejected)" if not verify_token("") else "FAIL"))
    tok, _tag = make_token("PRO", "2099-12-31", "selftest")
    good = verify_token(tok)
    tampered = tok[:-4] + ("0000" if tok[-4:] != "0000" else "1111")
    print("  signed tok  : %s" % ("OK" if good and good.get("tier") == "PRO" else "FAIL"))
    print("  tampered    : %s" % ("OK (rejected)" if not verify_token(tampered) else "FAIL"))
    tier_ok = (tier_allows_phase("FREE", 2) and tier_allows_phase("FREE", 8)
               and not tier_allows_phase("FREE", 9) and not tier_allows_phase("FREE", 32)
               and tier_allows_phase("PRO", 9) and tier_allows_phase("PRO", 2)
               and not tier_allows_phase("GARBAGE", 9))
    print("  tier gate   : %s" % ("OK (FREE=P2-P8, PRO=all)" if tier_ok else "FAIL"))
    print("  extra tokens: %s (%d owner-issued)" % (EXTRA_TOKENS_PATH, len(_load_extra_tokens())))
    print("  cache path  : %s" % TOKEN_CACHE_PATH)
    return 0


def _issue_cli(argv):
    """python3 wasp_license.py issue PRO 2026-12-31 [customer-tag]"""
    tier = (argv[1] if len(argv) > 1 else "PRO").strip().upper()
    exp = (argv[2] if len(argv) > 2 else "2026-12-31").strip()
    tok, tag = make_token(tier, exp, argv[3] if len(argv) > 3 else None)
    try:
        os.makedirs(TOKEN_CACHE_DIR, exist_ok=True)
        led = _load_extra_tokens()
        led[tok] = {"tier": tier, "expires": exp, "tag": tag, "issued": _now_ymd()}
        with open(EXTRA_TOKENS_PATH, "w") as f:
            json.dump(led, f, indent=2)
        os.chmod(EXTRA_TOKENS_PATH, 0o600)
    except Exception:
        pass
    print("=" * 64)
    print("  NAYA TOKEN ISSUE HO GAYA")
    print("=" * 64)
    print("  TOKEN  : %s" % tok)
    print("  tier   : %s | expires: %s | customer-tag: %s" % (tier, exp, tag))
    print("  ledger : %s" % EXTRA_TOKENS_PATH)
    print("-" * 64)
    print("  Customer ko ye TOKEN bhejo (WhatsApp/email). Customer sirf:")
    print("     export WASP_TOKEN=%s" % tok)
    print("  karega - uske machine pe poora toolkit (P2-P32) unlock.")
    print("  Koi code change / file customer pe nahi chahiye.")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "issue":
        sys.exit(_issue_cli(sys.argv[1:]))
    sys.exit(self_test())
