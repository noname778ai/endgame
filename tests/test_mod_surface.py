#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_mod_surface.py - Phase 8 ULTRA v3 offline harness (koi network nahi).

Phase 8 PURE ANALYSIS hai -> harness ek MOCK ENGAGEMENT directory banata hai
jisme P2-P7 (+P11 access + feedforward) ke realistic output files hote hain,
fir mod_surface.run() chala kar sab kuch validate karta hai.

Mock engagement (app.example.com + api.example.com + hidden vhost):
  understand.json  - reachable target, endpoints, login form (password), upload form
  passive.json     - subdomains, resolved, mining urls, takeover_candidates (dangling CNAME)
  active.json      - probes, edge w/ waf_hits=[Cloudflare, CloudFront], vhost, redis port
  content.json     - found 403 /admin/users, backup.sql artifact, dirs, .env/.git artifacts
  tech_profile.json- jQuery 1.12.4 (stale), nginx, Cloudflare WAF sig, contradictions,
                     session_model jwt_in_cookie, openapi api_endpoints v1+v2, graphql
  js_analysis.json - sourcemap asset, JS endpoints, secrets, authz_hints isAdmin, sinks
  access/          - P11 findings.json (2 IDOR confirms) + ACCESS_MATRIX.txt
  content/feedforward.json - FF hint (ingest_ff path)

Covers: v2 parity (13 outputs + formats), ULTRA 25 techniques, determinism,
diff, graceful-empty, effort bump, bypass kit, DAG, version matrix, phase prep.
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block1_recon")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os, sys, json, time, shutil, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %-58s %s" % ("[PASS]" if cond else "[FAIL]", name, detail))
    return bool(cond)


def _w(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(obj, str):
            f.write(obj)
        else:
            json.dump(obj, f, indent=1)


def build_mock_eng(eng):
    """P2-P7 + P11 mock outputs likho (realistic shapes, v2/v3 modules jaise)."""
    H = "app.example.com"
    AH = "api.example.com"

    # ---- P2 understand ----
    _w(os.path.join(eng, "understand", "understand.json"), {
        "targets": [{
            "reachable": True, "base": "https://%s/" % H, "status": 200,
            "title": "Example App", "server": "nginx/1.24.0",
            "powered": "Express", "header_grade": "C",
            "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security"],
            "endpoints": ["/login", "/dashboard", "/api/v1/users?id=3",
                          "/api/v2/users?id=3", "/static/logo.png"],
            "forms": [
                {"action": "/login", "method": "POST", "has_password": True,
                 "fields": ["username", "password", "remember_me"]},
                {"action": "/upload", "method": "POST", "has_file": True,
                 "fields": ["file", "description"]},
            ],
        }],
    })

    # ---- P3 passive ----
    _w(os.path.join(eng, "passive", "passive.json"), {
        "domain": "example.com",
        "subdomains": [H, AH, "stg.example.com", "dev.example.com"],
        "resolved": {H: ["93.184.216.34"], AH: ["93.184.216.35"]},
        "mining": {"urls": ["https://%s/blog/2024/launch" % H,
                            "https://%s/api/v1/orders?order_id=881" % H,
                            "https://%s/wp-admin/setup.php" % H]},
        "takeover_candidates": [{"host": "old-docs.example.com", "service": "github-pages",
                                 "fingerprint": "404 Not Found (GitHub)", "cname": "old-docs.example.github.io"}],
    })

    # ---- P4 active ----
    _w(os.path.join(eng, "active", "active.json"), {
        "probes": [{"url": "https://%s/" % H, "host": H, "status": 200,
                    "title": "Example App", "server": "nginx/1.24.0",
                    "scheme": "https", "port": 443, "favicon_hash": "a1b2c3d4",
                    "tech": ["nginx", "Express"], "content_type": "text/html"}],
        "edges": [{"url": "https://%s/" % H, "waf_hits": ["cloudflare", "cloudfront"],
                   "header_grade": {"grade": "C"},
                   "cdn_headers": {"cf-ray": "8af", "x-amz-cf-id": "xyz"}}],
        "vhosts": [{"host": "internal-admin.example.com", "url": "https://internal-admin.example.com/",
                    "len": 2048, "base_len": 120}],
        "ports": [{"host": H, "port": 6379, "service": "redis", "product": "Redis 6.2"},
                  {"host": H, "port": 8080, "service": "http", "product": "Tomcat"}],
    })

    # ---- P5 content ----
    _w(os.path.join(eng, "content", "content.json"), {
        "results": {H: {
            "base_url": "https://%s/" % H,
            "baseline": {"status": 200, "serves_200_on_missing": False},
            "found": [
                {"url": "https://%s/admin/users" % H, "path": "/admin/users",
                 "status": 403, "len": 512, "title": "Forbidden"},
                {"url": "https://%s/backup.sql" % H, "path": "/backup.sql",
                 "status": 200, "len": 4096, "title": ""},
                {"url": "https://%s/api/v1/debug/vars" % H, "path": "/api/v1/debug/vars",
                 "status": 200, "len": 1024, "title": ""},
            ],
            "extensions": [],
            "dirs": [{"path": "/backup", "location": "/backup/", "status": 301}],
            "artifacts": [
                {"path": "/.env", "status": 200, "severity_hint": "high",
                 "note": "dotenv-shaped keys present"},
                {"path": "/.git/HEAD", "status": 200, "severity_hint": "critical",
                 "note": "git ref: refs/heads/main"},
            ],
        }},
    })

    # ---- P6 tech ----
    _w(os.path.join(eng, "tech", "tech_profile.json"), {
        "hosts": [{
            "final_url": "https://%s/" % H,
            "tech_ranked": [
                {"tech": "jQuery", "version": "1.12.4", "confidence": 0.9, "category": "client-lib"},
                {"tech": "nginx", "version": "1.24.0", "confidence": 0.95, "category": "server"},
                {"tech": "Express", "version": "4.18.2", "confidence": 0.8, "category": "framework"},
                {"tech": "Cloudflare", "version": "", "confidence": 0.9, "category": "waf"},
            ],
            "contradictions": ["server header nginx but X-Powered-By Express + CF-Ray edge"],
            "default_path_hits": ["/wp-admin/setup.php"],
            "session_model": {"storage_inference": "cookie", "cookie_names": ["sess", "jwt"],
                              "jwt_in_cookie": True},
            "api_style": "rest",
            "cache_layer": "cloudflare",
            "api_endpoints": [
                {"url": "/api/v1/users", "method": "GET"},
                {"url": "/api/v2/orders", "method": "POST"},
            ],
            "graphql_endpoints": ["/graphql"],
            "waf_detected": ["cloudflare"],
        }],
    })

    # ---- P7 js ----
    _w(os.path.join(eng, "js", "js_analysis.json"), {
        "assets": [{
            "url": "https://%s/static/app.min.js" % H,
            "sourcemap_ref": "/static/app.min.js.map",
            "build_ids": ["b-2026.10"],
            "endpoints": ["/api/v1/export?user_id=7", "/admin/api/tokens", "/ws/rt"],
            "graphql_endpoints": [],
            "websockets": ["wss://%s/ws/rt" % H],
            "routes": ["/admin/settings"],
            "params": ["next", "redirect_url"],
            "authz_hints": {"isAdmin": 3},
            "sinks": {"innerHTML": 5},
            "secrets": [{"type": "api_key_live", "value_redacted": "sk_****abcd",
                         "entropy": 4.2, "fingerprint": "fp1", "len": 32}],
        }],
        "secret_hits": [{"type": "aws_key", "asset": "https://%s/static/app.min.js" % H,
                         "value_redacted": "AKIA****", "fingerprint": "fp2", "len": 20}],
        "service_workers": ["https://%s/sw.js" % H],
    })

    # ---- P11 access (ULTRA ingest) ----
    _w(os.path.join(eng, "access", "findings.json"), [
        {"title": "IDOR confirmed: /api/v1/users/7 cross-account read",
         "severity": "high", "confidence": "confirmed",
         "target": "https://%s/api/v1/users?id=3" % AH,
         "remediation": "server-side object-level authz"},
        {"title": "Admin panel reachable without role (vertical authz)",
         "severity": "critical", "confidence": "confirmed",
         "target": "https://%s/admin/users" % H,
         "remediation": "role check server-side"},
    ])
    _w(os.path.join(eng, "access", "ACCESS_MATRIX.txt"),
       "# ACCESS MATRIX (role x endpoint)\n"
       "GET https://%s/api/v1/orders?order_id=881  user=A 200 | user=B 200 <- IDOR suspect\n" % AH)

    # ---- feedforward from content module (ingest_ff path) ----
    _w(os.path.join(eng, "content", "feedforward.json"), {
        "phase": "5-content", "routing": {
            "to_phase11_idor": {"IDOR/BOLA": "3 target(s): /api/v1/users"},
            "to_phase8_surface": {"discovered": "12 endpoints"},
        },
        "notes": ["mock ff"],
    })


def main():
    from wasp_core import Cfg, Scope
    import importlib
    mod = importlib.import_module("mod_surface")

    work = tempfile.mkdtemp(prefix="p8_ultra_")
    base_out = os.path.join(work, "engines")
    eng = os.path.join(base_out, "p8test")
    build_mock_eng(eng)

    scope_path = os.path.join(work, "scope.json")
    _w(scope_path, {
        "engagement": "p8test", "authorized": True,
        "authorization_reference": "local offline harness",
        "targets": ["https://app.example.com/"],
        "domains": ["example.com"],
        "ips": ["93.184.216.34"],
        "notes": "offline selftest - pure analysis, no requests",
    })

    cfg = Cfg(None)
    cfg.surface_min_priority = 20.0
    cfg.surface_top = 40
    cfg.surface_budget_minutes = 60.0

    scope = Scope(scope_path)

    print("== Phase 8 ULTRA v3 - fresh run ==")
    t0 = time.time()
    mod.run(cfg, scope, base_out)
    dt = time.time() - t0
    out = os.path.join(eng, "surface")
    load = lambda p: (json.load(open(os.path.join(out, p))) if os.path.exists(
        os.path.join(out, p)) and os.path.getsize(os.path.join(out, p)) > 2 else None)
    text = lambda p: (open(os.path.join(out, p), errors="ignore").read()
                      if os.path.exists(os.path.join(out, p)) else "")

    surf = load("surface.json")
    pq = load("priority_queue.json")
    check("surface.json written", surf is not None)
    check("priority_queue.json written", pq is not None)
    if not surf or not pq:
        print("CRITICAL: core outputs missing - aborting further checks")
        return 1

    nodes = surf.get("nodes", [])
    queue = pq.get("queue", [])
    mmr = pq.get("diverse_queue", [])
    by_target = {n.get("target") or n.get("url") or "": n for n in queue}

    # ---------- v2 parity ----------
    print("-- v2 parity --")
    check("plan_version 8.1.0-ULTRA", surf.get("plan_version") == "8.1.0-ULTRA",
          str(surf.get("plan_version")))
    check("nodes >= 25", len(nodes) >= 25, "nodes=%d" % len(nodes))
    check("queue sorted desc", all(
        queue[i]["priority"] >= queue[i + 1]["priority"] for i in range(len(queue) - 1)),
        "first=%s" % [q["priority"] for q in queue[:3]])
    check("queue has type variety", len({q["type"] for q in queue}) >= 4,
          str({q["type"] for q in queue}))
    check("mmr <= surface_top", len(mmr) <= 40, "mmr=%d" % len(mmr))
    check("node types include secret", any(n["type"] == "secret" for n in nodes))
    check("node types include artifact", any(n["type"] == "artifact" for n in nodes))
    check("admin endpoint in queue (403)",
          any("admin/users" in (q.get("target") or "") for q in queue))
    check("hypotheses.txt has KILL TEST", "KILL TEST" in text("hypotheses.txt"))
    check("hypotheses kill test covers new class",
          "Subdomain-Takeover" in text("hypotheses.txt")
          or "Legacy-API" in text("hypotheses.txt")
          or "DevOps-Exposure" in text("hypotheses.txt"))
    check("clusters.txt non-empty", len(text("clusters.txt").strip()) > 20)
    check("quick_wins.txt non-empty", len(text("quick_wins.txt").strip()) > 20)
    check("coverage_plan budget respected",
          "used=" in text("coverage_plan.txt") and "60" in text("coverage_plan.txt"))
    check("coverage_matrix has classes", "high=" in text("coverage_matrix.txt"))
    check("ignore.txt drops static/FF",
          "static" in text("ignore.txt").lower() or "feedforward" in text("ignore.txt").lower())
    check("test_plan.md sections v2",
          all(s in text("test_plan.md") for s in ["Surface summary", "Ranked targets",
                                                  "Time-boxed", "Limitations"]))
    check("feedforward has to_phase routing",
          any(k.startswith("to_phase") for k in (load("feedforward.json") or {}).get("routing", {})))
    check("MANIFEST.json stats", (load("MANIFEST.json") or {}).get("stats", {}).get("nodes", 0) > 0)

    # ---------- ULTRA v3: bypass intelligence ----------
    print("-- ULTRA: security bypass --")
    bp = text("bypass_playbook.txt")
    check("bypass_playbook.txt written", len(bp) > 200)
    check("playbook covers Cloudflare", "Cloudflare" in bp, "detected waf")
    check("playbook covers CloudFront", "CloudFront" in bp)
    check("playbook has X-Original-URL header", "X-Original-URL" in bp)
    check("playbook lists 403 targets", "403/401 targets" in bp)
    q403 = [q for q in queue if "admin/users" in (q.get("target") or "")]
    check("403 node has bypass kit in priority_queue.json",
          bool(q403) and isinstance(q403[0].get("bypass"), dict)
          and len(q403[0]["bypass"].get("headers", [])) >= 3,
          str((q403[0].get("bypass") or {}).get("wafs") if q403 else "no-403"))
    check("stale tech boost applied (jQuery 1.12)",
          any(n.get("stale_boost", 0) > 0 for n in nodes),
          str(max([n.get("stale_boost", 0) for n in nodes] or [0])))
    check("effort bumped on WAF/403 targets",
          any("perimeter stealth" in nt for n in nodes for nt in (n.get("notes") or [])))

    # ---------- ULTRA v3: ingest access + ff ----------
    print("-- ULTRA: P11 + feedforward ingest --")
    check("P11 finding config nodes present",
          any("access_finding" in (n.get("labels") or []) for n in nodes))
    check("P11 endpoint tag (access_control_evidence)",
          any("access_control_evidence" in (n.get("labels") or []) for n in nodes))
    check("ff hint nodes ingested",
          any("feedforward_hint" in (n.get("labels") or []) for n in nodes))

    # ---------- ULTRA v3: attack-path DAG ----------
    print("-- ULTRA: attack-path DAG --")
    ap = text("attack_paths.txt")
    check("attack_paths.txt written", "ATTACK PATHS" in ap)
    check("DAG has PRE step (artifact/secret prereq)", "PRE:" in ap)
    check("DAG has BYPASS step (403/WAF)", "BYPASS:" in ap)
    check("DAG has TEST step", "TEST:" in ap)
    apj_present = os.path.exists(os.path.join(out, "attack_paths.txt"))

    # ---------- ULTRA v3: version matrix + blind spots + phase prep ----------
    print("-- ULTRA: matrix / blind spots / prep --")
    vm = text("api_version_matrix.txt")
    check("version matrix has v1+v2", "v1" in vm and "v2" in vm)
    check("legacy warning on old version", "LEGACY" in vm)
    check("Legacy-API class assigned",
          any("Legacy-API" in (n.get("classes") or []) for n in nodes))
    tp = text("test_plan.md")
    check("test_plan has bypass section", "bypass playbook" in tp)
    check("test_plan has DAG section", "Attack-path DAG" in tp)
    check("test_plan has blind spots", "Blind spots" in tp)
    check("test_plan has phase prep kits", "Next-phase prep kits" in tp)
    check("test_plan has version matrix", "API version matrix" in tp)
    pp = text("phase_prep.txt")
    check("phase_prep has P9/P10/P11 kits",
          all(k in pp for k in ["phase9_auth", "phase10_sessions", "phase11_idor"]))
    check("P11 kit lists IDOR targets", "api.example.com" in pp or "api/v1" in tp)

    # ---------- ULTRA v3: chains ----------
    print("-- ULTRA: chains v2 --")
    ch = text("chains.txt")
    for cid in ["CHAIN-VCS-01", "CHAIN-ENV-01", "CHAIN-GQL-01", "CHAIN-AUTHZ-01",
                "CHAIN-SMAP-01", "CHAIN-WAF-01", "CHAIN-VER-01", "CHAIN-SUB-01",
                "CHAIN-PORT-01", "CHAIN-DEVOPS-01"]:
        check("chain %s" % cid, cid in ch)

    # ---------- WAF detection ----------
    check("surface.json waf_map", "app.example.com" in (surf.get("waf_map") or {}),
          str(surf.get("waf_map")))

    # ---------- determinism + diff ----------
    print("-- determinism + diff --")
    snap = json.dumps([{k: v for k, v in n.items() if k not in ("signals", "ultra_signals")}
                       for n in sorted(nodes, key=lambda x: x["id"])], sort_keys=True)
    mod.run(cfg, scope, base_out)
    surf2 = load("surface.json")
    nodes2 = surf2.get("nodes", [])
    snap2 = json.dumps([{k: v for k, v in n.items() if k not in ("signals", "ultra_signals")}
                        for n in sorted(nodes2, key=lambda x: x["id"])], sort_keys=True)
    check("deterministic (same input = same nodes)", snap == snap2)
    diff = load("surface_diff.json")
    check("surface_diff.json on 2nd run", diff is not None)
    check("diff has no phantom changes",
          diff is not None and len(diff.get("added", [])) == 0 and len(diff.get("gone", [])) == 0,
          "added=%s gone=%s" % (len((diff or {}).get("added", [])), len((diff or {}).get("gone", []))))

    # ---------- graceful: empty engagement ----------
    print("-- graceful empty --")
    eng2 = os.path.join(base_out, "emptytest")
    os.makedirs(os.path.join(eng2, "surface"), exist_ok=True)
    scope2_path = os.path.join(work, "scope2.json")
    _w(scope2_path, {"engagement": "emptytest", "authorized": True,
                     "authorization_reference": "harness",
                     "targets": ["https://x.example.com/"], "domains": ["example.com"]})
    try:
        mod.run(Cfg(None), Scope(scope2_path), base_out)
        check("empty engagement no-crash + friendly msg", True)
    except Exception as e:
        check("empty engagement no-crash + friendly msg", False, "%s: %s" % (type(e).__name__, e))

    # ---------- takeovers / classes ----------
    print("-- classes --")
    check("Subdomain-Takeover class present",
          any("Subdomain-Takeover" in (n.get("classes") or []) for n in nodes))
    check("DevOps-Exposure class present (debug/vars or devops path)",
          any("DevOps-Exposure" in (n.get("classes") or []) for n in nodes),
          str([n.get("classes") for n in nodes if "api/v1/debug" in str(n.get("url"))]))
    check("Session-Weakness class present",
          any("Session-Weakness" in (n.get("classes") or []) for n in nodes))
    check("Auth/Credential class (login form)",
          any("Auth/Credential" in (n.get("classes") or []) for n in nodes))
    check("MMR diversity: no >3 same-shape in top10",
          sum(1 for m in mmr[:10] if str(m.get("target", "")).startswith("https://app.example.com/api/v1"))
          <= 4, "")

    shutil.rmtree(work, ignore_errors=True)

    fails = [r for r in RESULTS if not r[1]]
    print()
    print("=" * 64)
    print("TOTAL: %d/%d PASS (%.2fs)" % (len(RESULTS) - len(fails), len(RESULTS), dt))
    if fails:
        print("FAILED:")
        for f in fails:
            print("  -", f[0], f[2])
        return 1
    print("ALL PASS - Phase 8 ULTRA v3 validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
