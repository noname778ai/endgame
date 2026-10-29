#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP LICENSE GATE v1.0
================================================================================
Token-based licensing (Free First, Paid Later model).

KAISE KAAM KARTA HAI
--------------------
1. Token resolve order :  --token flag  >  WASP_TOKEN env var  >  cached token
                          (~/.wasp/token_cache.json)  >  interactive prompt
2. Offline demo tokens (FREE tier - abhi sabke liye):
     WASP-FREE-2025-DEMO   -> FREE tier
     WASP-PRO-2025-DEMO    -> PRO tier
3. Server mode (future): WASP_API_URL env var set karo -> verify_via_api()
     POST <WASP_API_URL>  {"token": "..."}  ->  {"valid": true, "tier": "...",
     "expires": "...", "user": "..."}  (5s timeout, fail = offline fallback)
4. Gate sirf TESTING commands par lagta hai (run/runall). Diagnostics FREE:
     list | doctor | verify | status | selftest | findings | report | chain
5. Non-interactive shells (CI/piped) me token na ho to CLEAR error + exit,
   prompt hang NAHI hota (sys.stdin.isatty() check).

TIER POLICY (abhi - Free First)
-------------------------------
  FREE : poora toolkit (P2-P32), community support
  PRO  : future - report branding removal, priority updates, API verify
(Dono tiers ka behaviour abhi same hai; tier sirf license_state me record hota hai.)

AUDIT
-----
Har successful gate ek append-only line likhta hai:
  <out-base>/<engagement>/license_audit.jsonl
================================================================================
"""
import os
import sys
import json
import time
import urllib.request

LICENSE_VERSION = "1.0"
TOKEN_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".wasp")
TOKEN_CACHE_PATH = os.path.join(TOKEN_CACHE_DIR, "token_cache.json")

# ---------------------------------------------------------------------------
# OFFLINE DEMO TOKENS (public - Free tier. Baad me server-side verify hoga)
# ---------------------------------------------------------------------------
DEMO_TOKENS = {
    "WASP-FREE-2025-DEMO": {"tier": "FREE", "expires": "2027-12-31"},
    "WASP-PRO-2025-DEMO":  {"tier": "PRO",  "expires": "2027-12-31"},
}

TIERS = {
    "FREE": {"name": "Free", "features": "full toolkit (P2-P32), community support"},
    "PRO":  {"name": "Pro",  "features": "full toolkit + (future) no report "
                                          "watermark + priority updates + API verify"},
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
    """Token -> license dict | None (invalid/expired)."""
    token = (token or "").strip()
    if not token:
        return None
    d = DEMO_TOKENS.get(token)
    if d:
        if _expired(d.get("expires")):
            return None
        return {"tier": d["tier"], "expires": d["expires"],
                "user": "demo", "source": "offline"}
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
            "    FREE tier = poora toolkit. Token ek baar daalne par cache ho jaata hai.\n"
            "    Detail: README.md -> License section.\n\n")
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
    print("  cache path  : %s" % TOKEN_CACHE_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(self_test())
