#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_wasp_config.py - WASP ULTRA CONFIG ENGINE + MEGA CONFIG harness
=====================================================================
Offline (0 network requests). Run: python3 test_wasp_config.py

Layers:
  A. mega wasp_config.json parse + contract coverage (115/115)
  B. STOCK compatibility: wasp_core.Cfg mega config seedha load kare
     (bina engine ke) - har phase ke keys resolve hon (getattr + cfg.get)
  C. UltraConfig engine: phase views, posture, make_cfg injection
  D. Security model: force-false, double opt-in, read-only tamper raise
  E. Profiles: 5 ULTRA profiles apply + re-validate
  F. Bypass kits: 403/jwt/cors/encode/ratelimit OFFLINE + RWX save
  G. CLI subprocess: selftest/validate/show/explain/profile/upgrade/diff
  H. doctor: temp pack me scope+mods ke saath green + --fix RWX repair
  I. wasp.py tune compatibility (stock CLI mega config ke saath)
"""

import os
import sys
import json
import shutil
import glob
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _find_core_dir():
    """wasp_core.py kahan hai - pack root ya wasp_ultra/ subfolder."""
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for c in (_root, HERE, os.path.join(HERE, "wasp_ultra")):
        if os.path.exists(os.path.join(c, "wasp_core.py")):
            return os.path.abspath(c)
    return HERE


CORE_DIR = _find_core_dir()
if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)

import wasp_config as W                                    # noqa: E402

PASSED = []
FAILED = []


def chk(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print("  [+] %s %s" % (name, detail and ("(%s)" % detail) or ""))
    else:
        FAILED.append(name)
        print("  [x] %s %s" % (name, detail and ("(%s)" % detail) or ""))


def section(m):
    print("\n== %s ==" % m)


CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "wasp_config.json")
PY = sys.executable


def run_cli(*argv, cwd=HERE):
    _cfg = os.path.join(os.path.dirname(HERE), "wasp_config.py")
    r = subprocess.run([PY, _cfg] + list(argv),
                       capture_output=True, text=True, cwd=cwd, timeout=120)
    return r


# ---------------------------------------------------------------------------
# A. mega config parse + coverage
# ---------------------------------------------------------------------------
section("A. MEGA CONFIG - parse + contract coverage")
try:
    mega = W.load_json(CFG_PATH)
    chk("wasp_config.json parses", True, "%d top keys" % len(mega))
except Exception as e:
    chk("wasp_config.json parses", False, str(e))
    mega = {}
flat = W.flatten(dict(mega, __path__=None))
missing = [k for k in W.CONTRACT if k not in flat]
chk("contract coverage 115/115", not missing, "missing=%s" % missing[:5])
E, Wn = W.validate(flat)
chk("validation 0 errors", not E, "; ".join(E[:3]))
chk("security_model block present", isinstance(mega.get("security_model"), dict))
chk("layer4 methods fixed",
    tuple(mega.get("security_model", {}).get("read_only_methods") or []) == W.LAYER4_METHODS)
chk("profiles block: 5 ULTRA", set(mega.get("profiles", {}).keys()) >= set(W.PROFILES_ULTRA))
chk("bypass_kit block rich", isinstance(mega.get("bypass_kit"), dict)
    and len(mega["bypass_kit"].get("path_variants", [])) >= 10)
chk("pipeline_order 8 phases", mega.get("pipeline_order") == ["understand", "passive", "active",
                                                              "content", "tech", "js", "surface", "access"])
chk("per-phase enabled keys", all(flat.get("%s_enabled" % m) is True for m in W.PHASE_KEYS))
chk("write gates default OFF",
    flat.get("allow_write_http") is False and flat.get("access_allow_write_probes") is False
    and flat.get("allow_destructive") is False)

# ---------------------------------------------------------------------------
# B. STOCK compatibility - Cfg mega config seedha kha jaata hai (engine ke bina)
# ---------------------------------------------------------------------------
section("B. STOCK wasp_core.Cfg compatibility (bina engine)")
try:
    import wasp_core
    cfg = wasp_core.Cfg(CFG_PATH)
    stock_ok = True
except Exception as e:
    stock_ok = False
    chk("Cfg loads mega config", False, str(e))
if stock_ok:
    chk("Cfg loads mega config", True)
    probes = {
        "core": {"rate_limit": 4.0, "jitter": 0.35, "concurrency": 8, "timeout": 12,
                 "max_requests": 20000, "allow_write_http": False},
        "P2 understand": {"understand_js_max": 60},
        "P3 passive": {"passive_perm_max": 600, "passive_resolve_max": 3000},
        "P4 active": {"active_vhost_max": 48, "active_waf_probe_max": 12, "active_svc_max": 40},
        "P5 content": {"content_max_depth": 2, "content_total_cap": 4000,
                       "content_global_cap": 12000, "content_cms_packs": True},
        "P6 tech": {"tech_probe_max": 60, "tech_gql_probe": True, "tech_observation_cap": 40},
        "P7 js": {"js_max_assets": 150, "js_map_probe_max": 40, "js_inline_analysis": True},
        "P8 surface": {"surface_min_priority": 22.0, "surface_top": 60,
                       "surface_budget_minutes": 90.0},
        "P11 access": {"access_surface_cap": 30, "access_bypass_probes": 40,
                       "access_sim_confirm": 0.92, "access_allow_write_probes": False},
    }
    for phase, keys in probes.items():
        bad = [(k, v, getattr(cfg, k, "<absent>")) for k, v in keys.items()
               if getattr(cfg, k, "<absent>") != v]
        chk("%s keys resolve" % phase, not bad, "bad=%s" % bad[:2])
    # mods ke actual access patterns simulate karo
    sim = [
        int(cfg.get("js_max_assets", 150) or 150),                       # mod_js style
        float(getattr(cfg, "surface_min_priority", 22.0)),                # mod_surface style
        int(getattr(cfg, "understand_js_max", 60) or 60),                 # mod_understand style
        int(getattr(cfg, "passive_perm_max", 600) or 600),                # mod_passive style
        int(getattr(cfg, "active_vhost_max", 48) or 48),                  # mod_active style
        float(cfg.get("access_sim_confirm", 0.92)),                       # mod_access style
    ]
    chk("module access-patterns simulate", sim == [150, 22.0, 60, 600, 48, 0.92])

# ---------------------------------------------------------------------------
# C. UltraConfig engine
# ---------------------------------------------------------------------------
def _try_bad_phase(uc):
    try:
        uc.phase("nahi_hai")
        return False
    except ValueError:
        return True


section("C. UltraConfig engine (views + make_cfg)")
uc = W.UltraConfig(CFG_PATH)
chk("UltraConfig loads", uc.flat.get("rate_limit") == 4.0)
pv = uc.phase("tech")
chk("phase('tech') 15 keys", len(pv) == 15 and pv["tech_probe_max"] == 60)
chk("phase invalid raise", _try_bad_phase(uc))
chk("posture read-only", uc.posture["read_only"] == ["GET", "HEAD", "OPTIONS"]
    and uc.posture["allow_write_http"] is False)
cfg2 = uc.make_cfg(core_dir=CORE_DIR)
chk("make_cfg injects into real Cfg", getattr(cfg2, "tech_probe_max") == 60
    and getattr(cfg2, "access_sim_confirm") == 0.92
    and getattr(cfg2, "bypass_max_probes") == 60)


# ---------------------------------------------------------------------------
# D. Security model enforcement
# ---------------------------------------------------------------------------
section("D. SECURITY MODEL enforcement")
t = json.loads(json.dumps(mega))
t["allow_write_http"] = True
chk("write without confirm -> force false",
    W.flatten(dict(t, __path__=None)).get("allow_write_http") is False)
t2 = json.loads(json.dumps(mega))
t2["allow_write_http"] = True
t2["security_model"]["i_confirm_write_http"] = True
rf2 = W.flatten(dict(t2, __path__=None))
chk("write with confirm -> pass", rf2.get("allow_write_http") is True)
chk("confirm pass par validate warns", any("CONFIRMED" in w for w in W.validate(rf2)[1]))
try:
    W.flatten(dict(mega, security_model={"read_only_methods": ["GET", "POST"]}, __path__=None))
    chk("read_only_methods tamper raise", False)
except ValueError:
    chk("read_only_methods tamper raise", True)
t3 = json.loads(json.dumps(mega))
t3["results_rwx"] = False
chk("results_rwx=false = error", any("results_rwx" in e for e in W.validate(W.flatten(
    dict(t3, __path__=None)))[0]))

# ---------------------------------------------------------------------------
# E. Profiles
# ---------------------------------------------------------------------------
section("E. ULTRA PROFILES (5)")
for pname, expect in (("ghost", (0.8, 1, False)), ("stealth", (1.2, 2, None)),
                      ("balanced", (4.0, 8, None)), ("redteam", (8.0, 12, True)),
                      ("audit", (2.0, None, False))):
    tp = json.loads(json.dumps(mega))
    ch = W.apply_profile(tp, pname)
    okp = ch is not None and tp.get("profile") == pname and tp.get("rate_limit") == expect[0]
    if expect[1] is not None:
        okp = okp and tp.get("concurrency") == expect[1]
    if expect[2] is not None:
        okp = okp and tp.get("bypass_enabled") is expect[2]
    chk("profile %s apply" % pname, okp)
    e2, _ = W.validate(W.flatten(dict(tp, __path__=None)))
    chk("profile %s re-validates clean" % pname, not e2, "; ".join(e2[:2]))
chk("invalid profile rejected", W.apply_profile(dict(mega), "turbo") is None)

# ---------------------------------------------------------------------------
# F. Bypass kits (OFFLINE)
# ---------------------------------------------------------------------------
section("F. BYPASS KITS (0 requests)")
rows = W.kit_403(W.UltraConfig(CFG_PATH), "https://t.example.com/admin")
chk("kit_403 >=30 variants", len(rows) >= 30, "%d rows" % len(rows))
chk("kit_403 families", {r["family"] for r in rows} >= {"path", "header", "verb", "suffix"})
chk("kit_403 full URLs", all(str(r["url"]).startswith("https://t.example.com/") for r in rows
                             if r["family"] == "path"))
tok = "%s.%s.%s" % (W._b64u({"alg": "HS256", "typ": "JWT"}),
                    W._b64u({"sub": "1", "role": "user", "exp": 1600000000}), "sig")
jk = W.kit_jwt(W.UltraConfig(CFG_PATH), tok)
kinds = " ".join(a["attack"] for a in jk.get("attacks", []))
chk("kit_jwt alg:none + kid + claim-swap + exp",
    "alg:none" in kinds and "kid-injection" in kinds and "claim-swap" in kinds
    and "exp+10y" in kinds, "%d attacks" % len(jk.get("attacks", [])))
chk("kit_jwt token parse ho raha", jk["header"].get("alg") == "HS256")
ck = W.kit_cors(W.UltraConfig(CFG_PATH), "target.example")
chk("kit_cors origins templated", any("target.example.evil" in r["origin_header"] for r in ck))
enc = W.kit_encode(W.UltraConfig(CFG_PATH), "<svg onload=alert(1)>")
chk("kit_encode 6 layers + roundtrip", len(enc) == 6
    and enc["url"] == "%3Csvg%20onload%3Dalert%281%29%3E")
chk("kit_ratelimit playbook", len(W.kit_ratelimit(W.UltraConfig(CFG_PATH))) >= 6)
# RWX save
td = tempfile.mkdtemp(prefix="cfgtest_kit_")
kpath = os.path.join(td, "kit.json")
W.save_json_rwx(kpath, {"rows": rows})
chk("kit save is 0777", oct(os.stat(kpath).st_mode & 0o777) == "0o777")
shutil.rmtree(td, ignore_errors=True)

# ---------------------------------------------------------------------------
# G. CLI subprocess
# ---------------------------------------------------------------------------
section("G. CLI subprocess")
r = run_cli("selftest")
chk("CLI selftest exit 0", r.returncode == 0, r.stdout.strip().splitlines()[-1]
    if r.stdout else r.stderr[:80])
r = run_cli("validate", CFG_PATH)
chk("CLI validate PASS", r.returncode == 0)
r = run_cli("show", CFG_PATH)
chk("CLI show renders phases", r.returncode == 0 and "P11 access" in r.stdout
    and "pipeline order" in r.stdout)
r = run_cli("explain", "bypass_max_probes")
chk("CLI explain key", r.returncode == 0 and "budget" in r.stdout)
r = run_cli("explain")
chk("CLI explain full", r.returncode == 0 and "P11 access" in r.stdout)
r = run_cli("--config", CFG_PATH, "bypass", "403", "https://demo.example.com/admin")
chk("CLI bypass 403 table", r.returncode == 0 and "path" in r.stdout and "header" in r.stdout,
    (r.stderr or r.stdout).strip().splitlines()[-1][:70] if r.returncode else "")
r = run_cli("--config", CFG_PATH, "bypass", "jwt", tok)
chk("CLI bypass jwt", r.returncode == 0 and "alg:none" in r.stdout,
    (r.stderr or r.stdout).strip().splitlines()[-1][:70] if r.returncode else "")
r = run_cli("--config", CFG_PATH, "bypass", "encode", "<svg onload=alert(1)>")
chk("CLI bypass encode", r.returncode == 0 and "double_url" in r.stdout,
    (r.stderr or r.stdout).strip().splitlines()[-1][:70] if r.returncode else "")

# profile CLI on temp copy
tdir = tempfile.mkdtemp(prefix="cfgtest_prof_")
tcfg = os.path.join(tdir, "config.json")
shutil.copy2(CFG_PATH, tcfg)
r = run_cli("profile", "ghost", tcfg)
d2 = W.load_json(tcfg)
chk("CLI profile ghost writes flat", r.returncode == 0 and d2.get("rate_limit") == 0.8
    and d2.get("bypass_enabled") is False)
chk("CLI profile backup bana", len(glob.glob(tcfg + ".bak-*")) == 1)
chk("profile ke baad bhi 0777", oct(os.stat(tcfg).st_mode & 0o777) == "0o777")
# upgrade on PURANA v2-style config
old = {"rate_limit": 2.5, "timeout": 9, "tech_probe_max": 33, "access_sessions": [
    {"name": "victim", "cookie_header": "sid=A"}]}
ocfg = os.path.join(tdir, "old_config.json")
W.save_json_rwx(ocfg, old)
r = run_cli("upgrade", ocfg)
d3 = W.load_json(ocfg)
chk("CLI upgrade adds contract keys", r.returncode == 0
    and d3.get("tech_probe_max") == 33                      # user value untouched
    and d3.get("rate_limit") == 2.5
    and d3.get("js_max_assets") == 150                      # naya key default se
    and len(d3.get("access_sessions")) == 1)
# diff
r = run_cli("diff", CFG_PATH, ocfg)
chk("CLI diff detects changes", r.returncode == 0 and "rate_limit" in r.stdout)
shutil.rmtree(tdir, ignore_errors=True)

# ---------------------------------------------------------------------------
# H. DOCTOR in temp pack (scope + core + mods)
# ---------------------------------------------------------------------------
section("H. DOCTOR (temp pack)")
tpack = tempfile.mkdtemp(prefix="cfgtest_pack_")
_ROOT2 = os.path.dirname(HERE)
_core_src = os.path.join(_ROOT2, "wasp_core.py")
if not os.path.exists(_core_src):
    _core_src = os.path.join(HERE, "wasp_ultra", "wasp_core.py")
_phases = {"mod_understand.py": "block1_recon", "mod_passive.py": "block1_recon",
           "mod_active.py": "block1_recon", "mod_content.py": "block1_recon",
           "mod_tech.py": "block1_recon", "mod_js.py": "block1_recon",
           "mod_surface.py": "block1_recon", "mod_access.py": "block2_auth"}
for fn in ("wasp_config.json", "mod_understand.py", "mod_passive.py",
           "mod_active.py", "mod_content.py", "mod_tech.py", "mod_js.py",
           "mod_surface.py", "mod_access.py"):
    src = os.path.join(HERE, fn)
    if not os.path.exists(src):
        if fn in _phases:
            src = os.path.join(_ROOT2, "phases", _phases[fn], fn)
        elif fn == "wasp_config.json":
            src = os.path.join(_ROOT2, fn)
    if os.path.exists(src):
        os.symlink(src, os.path.join(tpack, fn))
if os.path.exists(_core_src):
    os.symlink(_core_src, os.path.join(tpack, "wasp_core.py"))
W.save_json_rwx(os.path.join(tpack, "scope.json"), {
    "authorized": True, "authorization_reference": "SOW-2026-044 (signed)",
    "targets": ["https://testphp.vulnweb.com"], "excludes": [], "engagement": "cfgtest"})
# ek non-777 result file daalo -> --fix repair test
res_dir = os.path.join(tpack, "engines", "cfgtest", "surface")
os.makedirs(res_dir, exist_ok=True)
with open(os.path.join(res_dir, "surface.json"), "w") as f:
    json.dump({"ok": 1}, f)
os.chmod(os.path.join(res_dir, "surface.json"), 0o644)
os.chmod(res_dir, 0o755)
r = run_cli("doctor", os.path.join(tpack, "wasp_config.json"), cwd=tpack)
chk("doctor catch non-777 + green on rest",
    "non-777 (engines)" in r.stdout and "scope.json" in r.stdout and r.returncode == 1)
r = run_cli("doctor", os.path.join(tpack, "wasp_config.json"), "--fix", cwd=tpack)
chk("doctor --fix repairs RWX", oct(os.stat(os.path.join(res_dir, "surface.json")).st_mode
                                    & 0o777) == "0o777")
chk("doctor SAB GREEN after fix", "SAB GREEN" in r.stdout, "rc=%d" % r.returncode)
shutil.rmtree(tpack, ignore_errors=True)

# ---------------------------------------------------------------------------
# I. STOCK wasp.py tune compatibility
# ---------------------------------------------------------------------------
section("I. STOCK wasp.py tune (mega config ke saath)")
wp = None
for cand in (os.path.join(os.path.dirname(HERE), "wasp.py"),
             os.path.join(HERE, "wasp.py"),
             os.path.join(HERE, "wasp_ultra", "wasp.py")):
    if os.path.exists(cand):
        wp = cand
        break
if wp:
    tdir2 = tempfile.mkdtemp(prefix="cfgtest_tune_")
    tcfg2 = os.path.join(tdir2, "config.json")
    shutil.copy2(CFG_PATH, tcfg2)
    r = subprocess.run([PY, wp, "tune", "--profile", "stealth", "--config", tcfg2],
                       capture_output=True, text=True, cwd=tdir2, timeout=120)
    d4 = W.load_json(tcfg2)
    chk("wasp.py tune mega config par chala", r.returncode == 0 and d4.get("rate_limit") == 1.2)
    chk("tune ne nested blocks preserve kiye",
        isinstance(d4.get("security_model"), dict) and isinstance(d4.get("profiles"), dict))
    uc4 = W.UltraConfig(tcfg2)
    chk("engine tuned config par bhi clean", not uc4.errors
        and uc4.flat.get("rate_limit") == 1.2)
    shutil.rmtree(tdir2, ignore_errors=True)
else:
    chk("wasp.py tune (wasp.py not present, skipped)", True)

# ---------------------------------------------------------------------------
print("\n" + "=" * 64)
print("  RESULT: %d PASS / %d FAIL" % (len(PASSED), len(FAILED)))
print("=" * 64)
if FAILED:
    print("  failed:")
    for f in FAILED:
        print("    - %s" % f)
sys.exit(1 if FAILED else 0)
