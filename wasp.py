#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP v2.1.0-ULTRA - Web Assessment Script Pack (main CLI)
=========================================================
Authorized security testing ONLY. scope.json -> authorized=true hone par hi chalta hai.

Commands
--------
  python3 wasp.py list                              # module registry (ULTRA table)
  python3 wasp.py verify                            # pre-flight (scope, deps, network)
  python3 wasp.py run    --module content           # resumable run
  python3 wasp.py run    --module content --fresh   # zero se shuru
  python3 wasp.py run    --module 5 --profile stealth   # phase-number alias + stealth preset
  python3 wasp.py runall                            # poora pipeline (order me, skip-done)
  python3 wasp.py status                            # kya-kya ho chuka hai (--json bhi)
  python3 wasp.py reset  --module content           # checkpoint delete (--all/--cache/--hard)
  python3 wasp.py selftest                          # offline self-test (mock server)
  python3 wasp.py doctor                            # environment + checkpoint integrity
  python3 wasp.py findings [--min-sev high]         # cross-module findings rollup (NEW)
  python3 wasp.py report                            # poora REPORT.md engagement ka (NEW)
  python3 wasp.py chain                             # phase feedforward chain map (NEW)
  python3 wasp.py wizard                            # scope.json + config.json builder (NEW)
  python3 wasp.py tune --profile stealth            # config.json preset likho (NEW)
  python3 wasp.py cache stats|clear                 # cross-module probe cache (NEW)
  python3 wasp.py evidence [--tail 20]              # evidence requests summary (NEW)

Global flags
------------
  --scope PATH   scope.json          (default ./scope.json)
  --config PATH  config.json         (default ./config.json)
  --out DIR      output base         (default ~/wasp_out, env WASP_OUT)
  --profile NAME stealth|normal|fast|audit   (engine preset, env WASP_PROFILE)
  --rate F --jitter F --concurrency N --timeout N --max-requests N --proxy URL
  --yes          non-interactive (confirmations skip)
  --json         machine-readable output (status/findings)
"""
import os, sys, re, json, ast, time, argparse, importlib, importlib.util, traceback, shutil, socket

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from wasp_core import (Cfg, Scope, ScopeError, Evidence, outdir_for, Checkpoint,
                       checkpoint_status, checkpoint_healthy, install_signal_handlers,
                       interrupted, interrupt_info, ProbeCache, SessionStore,
                       apply_profile, aggregate_findings, write_findings_report,
                       read_feedforward, human_size, human_dur, now_human,
                       info, ok, warn, err, head, dim, table, banner, C, VERSION)

APP_VERSION = "2.4.0"  # tier gating: FREE=P2-P8 recon, PRO=P9-P32 + owner-issued tokens

# ---------------------------------------------------------------------------
# MODULE REGISTRY  (name -> file, description, phase, requires_active)
# ---------------------------------------------------------------------------
REGISTRY = {
    "understand": ("mod_understand", "P2  Application understanding + threat model", "2", False),
    "passive":    ("mod_passive",    "P3  Passive recon (CT/archives/DNS, multi-source)", "3", False),
    "active":     ("mod_active",     "P4  Active recon: probe, edge, vhost, ports, TLS", "4", True),
    "content":    ("mod_content",    "P5  Content/endpoint enum + VCS/backup/API artifacts", "5", True),
    "tech":       ("mod_tech",       "P6  Technology & architecture ID (confidence-scored)", "6", True),
    "js":         ("mod_js",         "P7  JS / client-side / API surface + sourcemaps", "7", True),
    "surface":    ("mod_surface",    "P8  Attack surface map + priority queue (analysis only)", "8", False),
    "auth":       ("mod_auth",       "P9  Authentication testing (bounded, non-destructive)", "9", True),
    "sessions":   ("mod_sessions",   "P10 Session & token security (cookies/JWT/lifecycle)", "10", True),
    "access":     ("mod_access",     "P11 Access Control / IDOR / BOLA (ULTRA PRO MAX)", "11", True),
    "inject":     ("mod_inject",     "P12 Injection ULTRA PRO MAX: SQLi/NoSQL/SSTI/CMDI/traversal/redirect/header/PP/XXE/EL/Log4Shell/CSV (detection-only v13)", "12", True),
    "xss":        ("mod_xss",        "P13 XSS ULTRA PRO MAX: reflected/DOM/stored/mXSS/WAF-bypass/CSP-audit (detection-only, inert markers)", "13", True),
    "client":     ("mod_client",     "P14 Client-Side ULTRA PRO MAX: CSRF/CORS/framing/postMessage/OAuth-state/storage-chains (detection-only, inert PoC)", "14", True),
    "ssrf":       ("mod_ssrf",       "P15 SSRF/XXE/Traversal ULTRA PRO MAX: URL-fetch/cloud-IMDS/internal-smoke/XXE-XInclude-SAML/traversal-matrix (detection-only, redacted)", "15", True),
    "files":      ("mod_files",      "P16 File Upload ULTRA PRO MAX: extension/MIME/magic bypass/filename-traversal/serve-back/SVG-docx-import-XXE/zip-slip (INERT, detection-only)", "16", True),
    "api":        ("mod_api",        "P17 REST API ULTRA PRO MAX: openapi/swagger-spec/auth-matrix/version-skew/rate-limits/mass-assignment/BOLA-canary/error-leak/method-override (INERT, detection-only)", "17", True),
    "graphql":    ("mod_graphql",    "P18 GraphQL ULTRA PRO MAX: introspection-census/bypass-matrix-14/error-mining/field-authz/BOLA-resolvers/depth-cost-batch-guards/SSRF-surface/misconfig (INERT, detection-only, mutations-never)", "18", True),
    "ws":         ("mod_ws",         "P19 WebSocket ULTRA PRO MAX: origin-trust/CSWSH/auth-diff/transports/downgrade/replay (detection-only)", "19", True),
    "logic":      ("mod_logic",      "P20 Business Logic ULTRA PRO MAX: price-tamper/workflow-skip/race-surface/coupon-oracle/negative-edge (detection-only)", "20", True),
    "authz":      ("mod_authz",      "P21 AuthZ/OAuth/OIDC/MFA/SAML ULTRA PRO MAX: grant-matrix/token-binding/SSO/recovery/remember-me (detection-only)", "21", True),
    "replay":     ("mod_replay",     "P22 Replay & Anti-Replay ULTRA PRO MAX: request-replay/idempotency/CSRF-rotation/nonce/OTP/race (detection-only)", "22", True),
    "misconfig":  ("mod_misconfig",  "P23 Misconfig & Secrets ULTRA PRO MAX: debug/console/headers/errors/secrets/default-creds/admin-panels (detection-only)", "23", True),
    "cloud":      ("mod_cloud",      "P24 Cloud & Container ULTRA PRO MAX: buckets/takeover/IMDS/signed-URL/K8s/serverless/CDN/IAM (detection-only)", "24", True),
    "controls":   ("mod_controls",   "P25 Security Controls Validation & Remediation: controls-inv/WAF/rate/CORS/cookie/authgate/TLS/CSP (inert)", "25", True),
    "scanval":    ("mod_scanval",    "P26 Automation & Scanner Validation: FP-filter/manual-verify workflow (STUB - apna script daalo)", "26", False),
    "evidence":   ("mod_evidence",   "P27 Safe Validation & Evidence: non-destructive PoC/PII-redact/evidence-pack (STUB - apna script daalo)", "27", False),
    "chaining":   ("mod_chaining",   "P28 Vulnerability Chaining: finding->kill-chain composer (STUB - apna script daalo)", "28", False),
    "cvss":       ("mod_cvss",       "P29 Impact Assessment & CVSS 3.1: base-score + business impact (STUB - apna script daalo)", "29", False),
    "remediation":("mod_remediation", "P30 Remediation Engineering: exact code-level fixes (STUB - apna script daalo)", "30", False),
    "retest":     ("mod_retest",     "P31 Retesting & Regression: fix-verify + bypass-vectors (STUB - apna script daalo)", "31", False),
    "reporting":  ("mod_reporting",  "P32 Professional Reporting: exec-summary + REPORT.md (STUB - apna script daalo)", "32", False),
}

RUN_ORDER = ["understand", "passive", "active", "content", "tech", "js", "surface",
             "auth", "sessions", "access", "inject", "xss", "client", "ssrf",
             "files", "api", "graphql", "ws", "logic", "authz", "replay",
             "misconfig", "cloud", "controls", "scanval",
             "evidence", "chaining", "cvss", "remediation", "retest", "reporting"]

PHASE_ALIAS = {"2": "understand", "3": "passive", "4": "active", "5": "content",
               "6": "tech", "7": "js", "8": "surface", "9": "auth", "10": "sessions",
               "11": "access", "12": "inject", "13": "xss", "14": "client",
               "15": "ssrf", "16": "files", "17": "api", "18": "graphql",
               "19": "ws", "20": "logic", "21": "authz", "22": "replay",
               "23": "misconfig", "24": "cloud", "25": "controls",
               "26": "scanval", "27": "evidence", "28": "chaining",
               "29": "cvss", "30": "remediation", "31": "retest",
               "32": "reporting"}

# ---------------------------------------------------------------------------
# 6-BLOCK ORGANIZATION (33-phase framework ke blocks)
# run: python3 wasp.py run --block 2   |   runall: python3 wasp.py runall --block 3
# ---------------------------------------------------------------------------
BLOCK_DIRS = {"1": "block1_recon", "2": "block2_auth", "3": "block3_input",
              "4": "block4_api_logic", "5": "block5_infra", "6": "block6_report"}

BLOCKS = {
    "1": ("Block 1 :: Reconnaissance (P2-P8)",
          ["understand", "passive", "active", "content", "tech", "js", "surface"]),
    "2": ("Block 2 :: Auth, Session & Access (P9-P11) [HIGHEST BOUNTY]",
          ["auth", "sessions", "access"]),
    "3": ("Block 3 :: Input & Server-Side Injections (P12-P16)",
          ["inject", "xss", "client", "ssrf", "files"]),
    "4": ("Block 4 :: Modern Protocols & Business Logic (P17-P22)",
          ["api", "graphql", "ws", "logic", "authz", "replay"]),
    "5": ("Block 5 :: Misconfig, Cloud, Controls & Scan-Validation (P23-P26)",
          ["misconfig", "cloud", "controls", "scanval"]),
    "6": ("Block 6 :: Validation, Chaining & Reporting (P27-P32)",
          ["evidence", "chaining", "cvss", "remediation", "retest", "reporting"]),
}

# module name -> phases/<block>/<file>.py (naye layout ke file paths)
MODULE_PATHS = {}
for _bn, (_bt, _bmods) in BLOCKS.items():
    for _mn in _bmods:
        if _mn in REGISTRY:
            MODULE_PATHS[_mn] = os.path.join("phases", BLOCK_DIRS[_bn],
                                             REGISTRY[_mn][0] + ".py")


def mod_path(name):
    """Module .py ka resolved path. phases/<block>/ pehle, root drop-in fallback.
    Dono jagah missing ho to None."""
    cands = []
    rel = MODULE_PATHS.get(name)
    if rel:
        cands.append(os.path.join(HERE, rel))
    cands.append(os.path.join(HERE, REGISTRY[name][0] + ".py"))
    for p in cands:
        if os.path.exists(p):
            return p
    return None

# default feedforward chain (README section 6) - chain command ka baseline
CHAIN_TXT = {
    "understand": ["endpoints.txt", "api_endpoints.txt", "js_urls.txt", "forms.json",
                   "secret_hits.json", "header_flags.txt", "THREAT_MODEL.md"],
    "passive":    ["all_subs.txt", "resolved.txt", "ips.txt", "all_urls.txt",
                   "findings/{urls_with_params,interesting_files,interesting_paths,js_urls,"
                   "param_names,sensitive_params,endpoints,api_like,dir_seeds}.txt"],
    "active":     ["live_hosts.txt", "open_ports.txt", "waf_cdn.txt", "vhosts.txt",
                   "tls_report.txt", "favicon_hashes.txt", "error_templates.txt",
                   "security_headers.txt"],
    "content":    ["all_found.txt", "all_dirs.txt", "interesting.txt", "artifacts_high.txt",
                   "api_endpoints.txt", "found_<host>.txt", "dirs_<host>.txt"],
    "tech":       ["stack_report.txt", "api_style.txt", "session_model.txt",
                   "contradictions.txt", "cache_layer.txt", "error_signatures.txt"],
    "js":         ["endpoints.txt", "params.txt", "methods.txt", "graphql_ops.txt",
                   "websockets.txt", "routes.txt", "dom_analysis.txt",
                   "authz_client_hints.txt", "config_hints.txt", "sourcemaps.txt",
                   "secret_hits.json", "external_domains.txt"],
    "auth":       ["auth_endpoints.txt", "user_enumeration.json", "rate_limit_report.json",
                   "reset_flow_analysis.json", "mfa_analysis.json", "AUTH_FINDINGS.md",
                   "injection_oracle.json", "auth_http_hardening.json", "auth_cors.json",
                   "auth_redirect_xss.json", "saml_surface.json", "preauth_jwt.json"],
    "sessions":   ["session_endpoints.txt", "session_surface.json", "session_captures.json",
                   "cookie_analysis.json", "token_randomness.json", "session_fixation.json",
                   "session_lifecycle.json", "session_binding.json", "jwt_analysis.json",
                   "jwt_tamper_matrix.json", "token_leakage.json", "session_flow_map.md",
                   "SESSION_FINDINGS.md", "session_test_plan.md", "findings.json",
                   "client_session_storage.json", "cache_deception.json",
                   "cookie_conflict.json", "refresh_rotation.json",
                   "concurrent_sessions.json", "jwt_matrix_v2.json",
                   "session_hardening.json", "csrf_mapping.json", "ws_surface.json"],
    "access":     ["access_endpoints.txt", "access_sessions.json", "idor_verdicts.json",
                   "access_matrix.json", "id_intelligence.json", "bypass_403.json",
                   "graphql_bola.json", "mass_assignment.json", "method_matrix.json",
                   "gql_ultra.json", "tenant_isolation.json", "blind_oracle.json",
                   "verb_matrix.json", "batch_idor.json", "chained_idor.json",
                   "file_idor.json", "share_surface.json", "token_scope.json",
                   "search_exposure.json", "authz_hygiene.json",
                   "ACCESS_FINDINGS.md", "access_test_plan.md", "findings.json"],
    "inject":     ["inject_surface.json", "inject_targets.txt", "waf_map.json",
                   "error_sqli.json", "boolean_sqli.json", "time_sqli.json",
                   "nosql_injection.json", "ssti_scan.json", "cmdi_scan.json",
                   "traversal_scan.json", "redirect_scan.json", "crlf_scan.json",
                   "hpp_scan.json", "waf_bypass.json", "gql_inject.json",
                   "deser_scan.json", "injection_matrix.json", "injection_matrix.txt",
                   "reflection_map.json", "injection_hypotheses.json",
                   "INJECTION_FINDINGS.md", "injection_test_plan.md",
                   "injection_chains.txt", "findings.json", "feedforward.json"],
    "xss":        ["xss_surface.json", "xss_targets.txt", "csp_map.json",
                   "reflection_contexts.json", "reflected_probes.json",
                   "waf_bypass_xss.json", "dom_xss.json", "stored_candidates.json",
                   "csp_analysis.json", "header_reflect_xss.json",
                   "technique_matrix.json", "encode_matrix.json",
                   "framework_notes.json", "xss_matrix.json", "xss_matrix.txt",
                   "XSS_FINDINGS.md", "xss_test_plan.md", "xss_chains.txt",
                   "TECHNIQUES_CATALOG_XSS.md", "cwe_owasp_map_xss.json",
                   "findings.json", "feedforward.json"],
    "client":     ["client_surface.json", "client_targets.txt", "csrf_matrix.json",
                   "cors_matrix.json", "cors_probe_log.json", "framing_matrix.json",
                   "postmessage_audit_v14.json", "storage_chains.json",
                   "oauth_state_audit.json", "samesite_audit.json", "ws_audit.json",
                   "technique_matrix_client.json", "legacy_policies.json",
                   "CLIENT_FINDINGS.md", "client_test_plan.md", "client_chains.txt",
                   "TECHNIQUES_CATALOG_CLIENT.md", "cwe_owasp_map_client.json",
                   "findings.json", "feedforward.json"],
    "ssrf":       ["ssrf_surface.json", "ssrf_targets.txt", "ssrf_matrix.json",
                   "bypass_matrix.json", "metadata_cloud.json",
                   "internal_smoke.json", "scheme_matrix.json",
                   "differential_engine.json", "header_host_probe.json",
                   "xxe_surface.json", "xxe_matrix.json", "xxe_post_matrix.json",
                   "traversal_matrix.json", "waf_map_ssrf.json",
                   "technique_matrix_ssrf.json", "cwe_owasp_map_ssrf.json",
                   "ssrf_probe_log.json", "SSRF_FINDINGS.md", "XXE_FINDINGS.md",
                   "ssrf_test_plan.md", "ssrf_chains.txt",
                   "TECHNIQUES_CATALOG_SSRF.md", "findings.json",
                   "feedforward.json"],
    "files":      ["upload_surface.json", "upload_targets.txt",
                   "upload_form_census.json", "upload_matrix.json",
                   "filename_matrix.json", "ct_matrix.json",
                   "magic_matrix.json", "getback_matrix.json",
                   "serve_matrix.json", "import_xxe_matrix.json",
                   "archive_matrix.json", "dir_listing_matrix.json",
                   "waf_map_files.json", "differential_files.json",
                   "technique_matrix_files.json", "cwe_owasp_map_files.json",
                   "upload_probe_log.json", "UPLOAD_FINDINGS.md",
                   "IMPORT_XXE_FINDINGS.md", "files_test_plan.md",
                   "files_chains.txt", "TECHNIQUES_CATALOG_FILES.md",
                   "EXEC_SUMMARY.md", "ext_acceptance_matrix.json",
                   "multipart_matrix.json", "magic_consistency.json",
                   "client_bypass_matrix.json", "exotic_formats.json",
                   "svg_ssrf_matrix.json", "race_analysis.json",
                   "metadata_matrix.json", "put_method_matrix.json",
                   "storage_fingerprint.json", "rename_policy.json",
                   "mitre_map.json", "findings.json", "feedforward.json"],
    "api":        ["api_surface.json", "api_targets.txt",
                   "openapi_spec_census.json", "version_matrix.json",
                   "auth_matrix.json", "mass_assign_matrix.json",
                   "rate_limit_matrix.json", "bola_matrix.json",
                   "method_matrix.json", "error_leak_matrix.json",
                   "ws_gql_fingerprint.json", "param_census.json",
                   "waf_map_api.json", "differential_api.json",
                   "technique_matrix_api.json", "cwe_map_api.json",
                   "mitre_map_api.json", "api_probe_log.json",
                   "api_chains.txt", "api_test_plan.md",
                   "API_FINDINGS.md", "TECHNIQUES_CATALOG_API.md",
                   "EXEC_SUMMARY.md", "findings.json", "feedforward.json"],
    "graphql":    ["gql_surface.json", "gql_targets.txt", "gql_endpoints.json",
                   "introspection_census.json", "bypass_matrix.json",
                   "error_mining.json", "field_authz_matrix.json",
                   "bola_matrix.json", "guard_census.json",
                   "ssrf_surface.json", "inject_census.json",
                   "misconfig_census.json", "ide_census.json",
                   "waf_map_gql.json", "differential_gql.json",
                   "technique_matrix_gql.json", "cwe_map_gql.json",
                   "mitre_map_gql.json", "gql_probe_log.json",
                   "gql_chains.txt", "gql_test_plan.md",
                   "GQL_FINDINGS.md", "TECHNIQUES_CATALOG_GQL.md",
                   "EXEC_SUMMARY.md", "findings.json", "feedforward.json"],
    "ws":         ["ws_endpoints.txt", "ws_handshake_census.json", "ws_h2ws_census.json",
                   "ws_auth_diff.json", "ws_cookie_census.json", "ws_header_injection.json",
                   "ws_downgrade_census.json", "ws_accept_crypto.json", "ws_frames_gated.json",
                   "ws_js_miner.json", "ws_bypass2_matrix.json", "ws_chains.json",
                   "ws_hypotheses.json", "ws_coverage.json", "WS_FINDINGS.md",
                   "ws_test_plan.md", "ws_chains.txt", "ws_kickoff_guide.md",
                   "findings.json", "feedforward.json"],
    "logic":      ["logic_endpoints.txt", "logic_matrix.json", "logic_coupon.json",
                   "logic_idempotency.json", "logic_anti_auto.json", "logic_authz_diff.json",
                   "logic_client_trust.json", "logic_hidden_param.json",
                   "logic_mined_forms.json", "logic_kill_chains.json",
                   "logic_kill_chains.txt", "logic_chains_crossref.json",
                   "logic_bypass2_matrix.json", "logic_hypotheses.json",
                   "logic_coverage.json", "LOGIC_FINDINGS.md", "logic_test_plan.md",
                   "logic_kickoff_guide.md", "findings.json", "feedforward.json"],
    "authz":      ["auth_endpoints.txt", "auth_authz_matrix.json", "auth_buckets.json",
                   "auth_bypass2_matrix.json", "auth_cors.json", "auth_coverage.json",
                   "auth_defense_score.json", "auth_enum_ladder.json",
                   "auth_header_posture.json", "auth_header_trust.json",
                   "auth_http_hardening.json", "auth_hypotheses.json",
                   "auth_exec_summary.md", "AUTH_FINDINGS.md", "auth_test_plan.md",
                   "auth_kill_chains.txt", "auth_kickoff_guide.md",
                   "findings.json", "auth_feedforward.json", "feedforward.json"],
    "replay":     ["replay_endpoints.txt", "replay_live_endpoints.txt",
                   "replay_baseline.json", "replay_matrix.json", "replay_idempotency.json",
                   "replay_api_idempotency.json", "replay_csrf_rotation.json",
                   "replay_anti_automation.json", "replay_cache_replay.json",
                   "replay_gates.txt", "replay_gql_surface.json", "replay_chains.json",
                   "replay_bypass2.json", "replay_hypotheses.json",
                   "replay_coverage.json", "REPLAY_FINDINGS.md",
                   "findings.json", "feedforward.json"],
    "misconfig":  ["misconfig_baseline.json", "misconfig_debug.json",
                   "misconfig_debug_paths.txt", "misconfig_admin.json",
                   "misconfig_admin_paths.txt", "misconfig_artifacts.json",
                   "misconfig_artifact_names.txt", "misconfig_default_creds.json",
                   "misconfig_cors.json", "misconfig_cookies.json",
                   "misconfig_cache.json", "misconfig_cloud.json",
                   "misconfig_container.json", "misconfig_chains.json",
                   "misconfig_bypass2.json", "misconfig_coverage.json",
                   "MISCONFIG_FINDINGS.md", "findings.json", "feedforward.json"],
    "cloud":      ["cloud_endpoints.txt", "cloud_baseline.json", "cloud_bucket.json",
                   "cloud_apitoken.json", "cloud_cdn.json", "cloud_cicd.json",
                   "cloud_cicd_paths.txt", "cloud_console.json",
                   "cloud_console_names.txt", "cloud_container.json",
                   "cloud_container_paths.txt", "cloud_cors.json", "cloud_dns.json",
                   "cloud_chains.json", "cloud_bypass2.json", "cloud_coverage.json",
                   "CLOUD_FINDINGS.md", "findings.json", "feedforward.json"],
    "controls":   ["controls_baseline.json", "controls_authgate.json",
                   "controls_authgate_paths.txt", "controls_api.json",
                   "controls_cors.json", "controls_cookies.json", "controls_csp.json",
                   "controls_cache.json", "controls_cicd.json",
                   "controls_cicd_paths.txt", "controls_bypass2.json",
                   "controls_bypass2_shapes.txt", "controls_checklist_state.json",
                   "controls_chains.json", "controls_coverage.json",
                   "CONTROLS_FINDINGS.md", "findings.json", "feedforward.json"],
    "scanval":    ["scanval.json", "scanval_verdicts.json", "scanval_fp_report.md",
                   "scanval_reliability.json", "findings.json", "feedforward.json"],
    "evidence":   ["evidence.json", "validation_plan.json", "evidence_pack/",
                   "redaction_log.json", "CHAIN_OF_CUSTODY.jsonl",
                   "EVIDENCE_REPORT.md", "findings.json", "feedforward.json"],
    "chaining":   ["chaining.json", "chains.json", "chain_graph.json",
                   "CHAINS.md", "findings.json", "feedforward.json"],
    "cvss":       ["cvss.json", "cvss_assessment.json", "cwe_map.json",
                   "CVSS_REPORT.md", "priority_queue.json", "findings.json",
                   "feedforward.json"],
    "remediation":["remediation.json", "fix_plan.json", "REMEDIATION_PLAN.md",
                   "tickets/", "findings.json", "feedforward.json"],
    "retest":     ["retest.json", "retest_suite.json", "bypass_vectors.json",
                   "retest_state.json", "RETEST_REPORT.md", "findings.json",
                   "feedforward.json"],
    "reporting":  ["reporting.json", "REPORT.md", "EXEC_SUMMARY.md",
                   "bounty_templates/", "findings.json", "feedforward.json"],
}

PROFILES_HINT = ", ".join(["stealth (slow+UA-rotation)", "normal", "fast", "audit (full bodies)"])


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def resolve_module_name(raw):
    """'5' jaise phase numbers ko module name me map karo."""
    r = (raw or "").strip().lower()
    if r in PHASE_ALIAS:
        return PHASE_ALIAS[r]
    if r in REGISTRY:
        return r
    return None


def tier_skip_reason(args, name):
    """FREE tier + PRO module (P9+) -> reason string, warna None.
    Gate skip hua ho (args._license None) to kuch block nahi karte."""
    lic = getattr(args, "_license", None)
    if not lic:
        return None
    try:
        from wasp_license import tier_allows_phase
        if tier_allows_phase(lic.get("tier"), REGISTRY[name][2]):
            return None
    except Exception:
        return None
    return "P%s - PRO tier (FREE = sirf P2-P8 recon)" % REGISTRY[name][2]


def resolve_base(args):
    base = getattr(args, "out", None) or os.environ.get("WASP_OUT") or "~/wasp_out"
    return os.path.abspath(os.path.expanduser(base))


def load_scope_or_die(args):
    path = getattr(args, "scope", None) or os.path.join(HERE, "scope.json")
    if not os.path.exists(path):
        err("scope.json not found: %s" % path)
        err("Fix: cp scope.example.json scope.json  ->  edit karo (authorized=true + apne targets)")
        err("Ya interactive builder: python3 wasp.py wizard")
        sys.exit(3)
    try:
        sc = Scope(path)
    except ScopeError as e:
        err("SCOPE BLOCKED: %s" % e)
        err("Edit scope.json: authorized=true + targets/domains/ips jo tumhe test karne ki PERMISSION hai.")
        sys.exit(3)
    if not str(sc.ref).strip() or str(sc.ref).upper().startswith("REPLACE"):
        warn("authorization_reference placeholder/khaali hai - real proof (program URL / SOW / ticket + date) record karo.")
    return sc


def load_cfg_tuned(args):
    """config.json + profile preset + CLI overrides -> Cfg."""
    path = getattr(args, "config", None) or os.path.join(HERE, "config.json")
    if path and os.path.exists(path):
        cfg = Cfg(path)
    else:
        warn("config.json not found -> built-in defaults use ho rahe hain")
        cfg = Cfg(None)
    prof = getattr(args, "profile", None) or os.environ.get("WASP_PROFILE")
    if prof and str(prof).lower() != "normal":
        if apply_profile(cfg, prof):
            ok("profile '%s' applied (%s)" % (prof, PROFILES_HINT))
        else:
            warn("unknown profile '%s' -> normal (%s)" % (prof, PROFILES_HINT))
    # CLI overrides (sirf diye gaye hi override karte hain)
    omap = [("rate", "rate_limit", float), ("jitter", "jitter", float),
            ("concurrency", "concurrency", int), ("timeout", "timeout", int),
            ("max_requests", "max_requests", int), ("proxy", "proxy", str)]
    for aname, ckey, cast in omap:
        v = getattr(args, aname, None)
        if v is not None:
            try:
                setattr(cfg, ckey, cast(v))
                cfg.data[ckey] = cast(v)
            except (TypeError, ValueError):
                warn("invalid --%s value: %s" % (aname.replace("_", "-"), v))
    if getattr(args, "allow_destructive", False):
        warn("--allow-destructive: sirf jab RoE explicitly permit kare. ON kar diya.")
        cfg.allow_destructive = True
        cfg.data["allow_destructive"] = True
    return cfg


def detect_entrypoints(path):
    """AST-based (module IMPORT nahi hota - side-effects zero): run/main/execute/start."""
    try:
        tree = ast.parse(open(path, errors="ignore").read())
    except Exception:
        return []
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in ("run", "main", "execute", "start"):
            n = len(node.args.args)
            if n:
                n -= len(node.args.defaults or [])
            found.append((node.name, max(0, n)))
    return found


def module_status_row(base, engagement, name):
    mout = outdir_for(base, engagement, name)
    st = checkpoint_status(mout, name)
    st["outdir"] = mout
    return st


def findings_count_for(base, engagement, name):
    """Module ke <mod>.json se quick findings count (0 agar kuch nahi)."""
    agg = aggregate_findings(base, engagement)
    cnt = agg.get("by_module", {}).get(name)
    return (cnt or {}).get("total", 0)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_list(args):
    base = resolve_base(args)
    head("WASP modules (app v%s | core v%s)" % (APP_VERSION, VERSION))
    rows, present = [], 0
    for name in RUN_ORDER:
        f, desc, phase, needs = REGISTRY[name]
        path = mod_path(name)
        exists = bool(path)
        present += 1 if exists else 0
        eps = ""
        if exists:
            eps = ", ".join("%s(%d)" % (n, a) for n, a in detect_entrypoints(path)) or "?"
        rows.append([name, "P" + phase, desc[:52],
                     "OK" if exists else "MISSING", eps or "-", "yes" if needs else "no"])
    table(rows, ["MODULE", "PHASE", "DESCRIPTION", "FILE", "ENTRYPOINT", "ACTIVE"])
    print("\n  module files: %d/%d present in %s" % (present, len(RUN_ORDER), HERE))
    print("  run order   : %s" % " -> ".join(RUN_ORDER))
    print("  phase alias : --module 5 == --module content (2-25 supported)")
    print("\n  blocks (wasp.py run --block N | wasp.py runall --block N):")
    for b, (t, mods) in sorted(BLOCKS.items()):
        if mods:
            print("    %s  [%d modules]" % (t, len(mods)))
        else:
            print("    %s  [upcoming]" % t)
    print("\nTypical flow:")
    for l in ("python3 wasp.py verify", "python3 wasp.py run --module understand",
              "python3 wasp.py run --block 2", "python3 wasp.py runall",
              "python3 wasp.py status",
              "python3 wasp.py findings --min-sev medium", "python3 wasp.py report"):
        print("  %s%s%s" % (C.DIM, l, C.N))
    return 0

def _banner(sc, module=None):
    banner(VERSION)
    head("WASP v%s | engagement=%s%s" % (VERSION, sc.engagement,
                                        (" | module=" + module) if module else ""))
    warn("AUTHORIZED TESTING ONLY. Scope: %s" % sc.describe())
    if sc.notes:
        info("RoE notes: %s" % sc.notes[:200])


def cmd_run_block(args, blk):
    """Ek poora block run karo (order me, checkpoint skip)."""
    if blk not in BLOCKS:
        err("Unknown block: %s (1-6)" % blk)
        sys.exit(2)
    title, mods = BLOCKS[blk]
    if not mods:
        err("Block %s me abhi koi module nahi (P27-P32 upcoming)." % blk)
        sys.exit(2)
    head("BLOCK RUN :: %s" % title)
    args.block = None  # recursion guard - andar wale cmd_run() single module chalayenge
    done, failed, skipped = [], [], []
    for name in mods:
        st = None
        try:
            _b = resolve_base(args)
            _sc = load_scope_or_die(args)
            st = checkpoint_status(outdir_for(_b, _sc.engagement, name), name)
        except SystemExit:
            raise
        except Exception:
            st = None
        if st and st.get("complete") and not getattr(args, "fresh", False):
            ok("SKIP %s (already complete - %d steps)" % (name, st.get("done_steps", 0)))
            skipped.append(name)
            continue
        _ts = tier_skip_reason(args, name)
        if _ts:
            warn("SKIP %s (%s)" % (name, _ts))
            skipped.append("%s[PRO]" % name)
            continue
        info(">>> %s" % REGISTRY[name][1])
        args.module = name
        try:
            rc = cmd_run(args)
            (done if rc == 0 else failed).append(name)
        except SystemExit as e:
            if e.code in (0, None):
                done.append(name)
            else:
                failed.append("%s(rc=%s)" % (name, e.code))
                if e.code == 3:
                    err("Scope violation -> block run stop.")
                    break
    head("block %s summary" % blk)
    ok("completed: %s" % (", ".join(done) or "-"))
    if skipped:
        info("skipped (already done): %s" % ", ".join(skipped))
    if any(s.endswith("[PRO]") for s in skipped):
        warn("PRO modules skipped - poora toolkit (P9-P32) ke liye PRO token chahiye (README.md -> License System)")
    if failed:
        err("failed: %s" % ", ".join(failed))
    return 0 if not failed else 1


def cmd_run(args):
    blk = getattr(args, "block", None)
    if blk:
        return cmd_run_block(args, str(blk))
    if not getattr(args, "module", None):
        err("run ke liye --module <name|phase#> ya --block <1-6> do")
        sys.exit(2)
    name = resolve_module_name(args.module)
    if not name:
        err("Unknown module/phase: %s (available: %s)" % (args.module, ", ".join(RUN_ORDER)))
        sys.exit(2)
    args.module = name
    _ts = tier_skip_reason(args, name)
    if _ts:
        err("Module '%s' chalane ke liye PRO token chahiye (%s)." % (name, _ts))
        info("FREE demo token se recon try karo: python3 wasp.py run --module 2")
        info("PRO token ke liye: README.md -> License System section.")
        sys.exit(2)
    sc = load_scope_or_die(args)
    cfg = load_cfg_tuned(args)
    base = resolve_base(args)
    _banner(sc, name)

    _, _, _, needs_active = REGISTRY[name]
    if needs_active and not getattr(cfg, "allow_active", True):
        warn("config.allow_active=false -> module '%s' passive-only mode me chalega" % name)

    mod = load_mod(name)
    mout = outdir_for(base, sc.engagement, name)
    cp = Checkpoint(mout, name, fresh=getattr(args, "fresh", False))

    cfg.checkpoint = cp
    cfg.resume = not getattr(args, "fresh", False)
    cfg.module_outdir = mout
    cfg.engagement = sc.engagement

    st = cp.progress()
    if st["done_steps"]:
        ok("RESUME: %d steps already done (started %s) - skipping them"
           % (st["done_steps"], st["started"]))
    else:
        info("Fresh start (no prior checkpoint).")

    install_signal_handlers()
    t0 = time.time()
    try:
        out = mod.run(cfg, sc, base)
        cp.mark_complete()
        dt = time.time() - t0
        ok("Module '%s' finished in %s -> %s" % (name, human_dur(dt), out))
        _post_run_hints(base, sc, cfg, name)
    except KeyboardInterrupt:
        ii = interrupt_info()
        err("Interrupted (%s). Progress SAVED." % ii.get("reason", "signal"))
        err("Resume: python3 wasp.py run --module %s" % name)
        sys.exit(130)
    except ScopeError as e:
        err("Scope violation aborted the module: %s" % e)
        sys.exit(3)
    except Exception:
        err("Module crashed - progress up to the last completed step is saved.")
        traceback.print_exc()
        err("Resume with: python3 wasp.py run --module %s   (or --fresh to restart)" % name)
        sys.exit(4)
    return 0


def _post_run_hints(base, sc, cfg, name):
    """Run ke baad: findings count, feedforward next-hints, next module suggestion."""
    try:
        cnt = findings_count_for(base, sc.engagement, name)
        if cnt:
            ok("findings so far: %d (detail: python3 wasp.py findings)" % cnt)
    except Exception:
        pass
    ff = read_feedforward(base, sc.engagement).get(name) or {}
    if ff:
        info("feedforward (%s ne banaya -> agla phase yahan use karega):" % name)
        shown = 0
        for k, v in ff.items():
            if shown >= 6:
                dim("  ... (+%d more)" % (len(ff) - shown))
                break
            vv = ", ".join(v) if isinstance(v, list) else str(v)
            dim("  %-28s -> %s" % (k, str(vv)[:80]))
            shown += 1
    try:
        i = RUN_ORDER.index(name)
        if i + 1 < len(RUN_ORDER):
            info("Next: python3 wasp.py run --module %s" % RUN_ORDER[i + 1])
        else:
            info("Pipeline complete! Report: python3 wasp.py report")
    except ValueError:
        pass


def cmd_runall(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    _banner(sc)
    order = RUN_ORDER
    blk = getattr(args, "block", None)
    if blk:
        if str(blk) not in BLOCKS:
            err("Unknown block: %s (1-6)" % blk)
            sys.exit(2)
        order = BLOCKS[str(blk)][1]
        info("runall limited to :: %s" % BLOCKS[str(blk)][0])
        if not order:
            err("Block %s me abhi koi module nahi (P27-P32 upcoming)." % blk)
            return 2
    done, failed, skipped = [], [], []
    for name in order:
        mout = outdir_for(base, sc.engagement, name)
        st = checkpoint_status(mout, name)
        if st.get("complete") and not getattr(args, "fresh", False):
            ok("SKIP %s (already complete - %d steps; --fresh to redo)" % (name, st["done_steps"]))
            skipped.append(name)
            continue
        _ts = tier_skip_reason(args, name)
        if _ts:
            warn("SKIP %s (%s)" % (name, _ts))
            skipped.append("%s[PRO]" % name)
            continue
        info(">>> %s" % REGISTRY[name][1])
        args.module = name
        args.fresh = bool(getattr(args, "fresh", False))
        try:
            rc = cmd_run(args)
            (done if rc == 0 else failed).append(name)
        except SystemExit as e:
            if e.code in (0, None):
                done.append(name)
            else:
                failed.append("%s(rc=%s)" % (name, e.code))
                if e.code == 3:
                    err("Scope violation -> runall stop.")
                    break
    head("runall summary")
    ok("completed: %s" % (", ".join(done) or "-"))
    if skipped:
        info("skipped (already done): %s" % ", ".join(skipped))
    if any(s.endswith("[PRO]") for s in skipped):
        warn("PRO modules skipped - poora toolkit (P9-P32) ke liye PRO token chahiye (README.md -> License System)")
    if failed:
        warn("needs attention: %s" % ", ".join(failed))
    # ULTRA: poora pipeline hone par findings report auto-generate
    try:
        res = write_findings_report(base, sc.engagement, min_severity="info")
        agg = res["aggregate"]
        if agg["total"]:
            ok("findings report: %s (%d findings) + %s"
               % (res["findings_json"], agg["total"], res["findings_md"]))
        info("Next: python3 wasp.py status | python3 wasp.py report")
    except Exception:
        info("Next: python3 wasp.py status")
    return 0


def cmd_verify(args):
    head("WASP pre-flight (v%s)" % APP_VERSION)
    fails = 0
    sc = load_scope_or_die(args)
    cfg = load_cfg_tuned(args)
    base = resolve_base(args)
    ok("scope OK: engagement=%s" % sc.engagement)
    ok("authorization ref: %s" % sc.ref)
    seeds = sc.seed_urls()
    ok("seeds (%d): %s" % (len(seeds), ", ".join(seeds[:8]) or "-"))
    info("excludes: %s" % (", ".join(sc.excludes) or "-"))
    errs, warns = sc.validate()
    for e in errs:
        err("SCOPE ERROR: %s" % e)
        fails += 1
    for w in warns:
        warn("scope hygiene: %s" % w)
    info("rate_limit=%s req/s | concurrency=%s | budget=%s requests | allow_active=%s | profile=%s"
         % (cfg.rate_limit, cfg.concurrency, cfg.max_requests, cfg.allow_active,
            getattr(cfg, "profile", "normal")))

    head("Optional tooling (missing = graceful fallback)")
    for t in ["subfinder", "assetfinder", "amass", "findomain", "waybackurls", "gau",
              "nmap", "ffuf", "gobuster", "feroxbuster", "nuclei", "dnsx", "httpx", "katana"]:
        print("  %-12s %s" % (t, shutil.which(t) or "MISSING"))
    try:
        import dns.resolver  # noqa
        ok("dnspython present (fast multi-resolver DNS)")
    except ImportError:
        warn("dnspython missing -> socket fallback (sudo apt install python3-dnspython)")
    if shutil.which("httpx"):
        p = shutil.which("httpx")
        if "go/bin" not in p:
            warn("httpx resolves to %s - ProjectDiscovery httpx chahiye to $HOME/go/bin PATH ke aage rakho" % p)

    # module files present?
    head("Module files")
    missing_mods = [n for n in RUN_ORDER if mod_path(n) is None]
    if missing_mods:
        warn("missing mod files: %s (unke bina wo phases skip honge)" % ", ".join(missing_mods))
    else:
        ok("saare %d mod files present" % len(RUN_ORDER))

    # output dir writable?
    try:
        probe = os.path.join(base, ".wasp_write_test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        ok("output dir writable: %s" % base)
    except OSError as e:
        err("output dir NOT writable: %s (%s)" % (base, e))
        fails += 1

    # proxy infra check (koi HTTP request nahi - sirf TCP connect)
    if getattr(cfg, "proxy", None):
        try:
            purl = str(cfg.proxy)
            phost = purl.split("//")[-1].split("/")[0]
            ph, _, pport = phost.partition(":")
            sock = socket.create_connection((ph, int(pport or 8080)), timeout=5)
            sock.close()
            ok("proxy reachable: %s" % cfg.proxy)
        except Exception as e:
            warn("proxy NOT reachable: %s (%s)" % (cfg.proxy, e))

    if getattr(args, "no_net", False):
        info("network checks skipped (--no-net)")
    else:
        head("Network / scope reachability")
        for u in seeds[:10]:
            h = u.split("//")[-1].split("/")[0].split(":")[0]
            try:
                ip = socket.gethostbyname(h)
                ok("%-40s -> %s" % (h, ip))
            except Exception as e:
                warn("%-40s -> does NOT resolve (%s)" % (h, e))
        if seeds:
            info("HTTP reachability run ke pehle khud module test karta hai "
                 "(first request hi reachability probe hai).")
    if fails:
        err("pre-flight FAILED (%d blocker(s)) - pehle fix karo" % fails)
        return 3
    info("Proceed: python3 wasp.py run --module understand")
    return 0


def cmd_status(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    head("WASP status | engagement=%s | out=%s" % (sc.engagement, base))
    rows, total, any_findings = [], 0, 0
    for name in RUN_ORDER:
        st = module_status_row(base, sc.engagement, name)
        total += st.get("done_steps", 0)
        fc = findings_count_for(base, sc.engagement, name)
        any_findings += fc
        rows.append([name, st.get("state"), st.get("done_steps", 0),
                     fc, st.get("updated", "-")[:19] or "-", st.get("complete", False)])
    if getattr(args, "json", False):
        out = {"engagement": sc.engagement, "out": base,
               "modules": {name: module_status_row(base, sc.engagement, name)
                           for name in RUN_ORDER},
               "total_steps": total, "total_findings": any_findings}
        print(json.dumps(out, indent=2, default=str))
        return 0
    table(rows, ["MODULE", "STATE", "STEPS", "FINDINGS", "UPDATED", "COMPLETE"])
    print("\n  total checkpointed steps: %d | findings: %d" % (total, any_findings))
    print("  resume : python3 wasp.py run --module <name>")
    print("  restart: python3 wasp.py run --module <name> --fresh")
    print("  reset  : python3 wasp.py reset --module <name>")
    print("  rollup : python3 wasp.py findings --min-sev medium")
    return 0


def cmd_reset(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    targets = RUN_ORDER if getattr(args, "all", False) else (
        [resolve_module_name(args.module) or args.module]
        if getattr(args, "module", None) else [])
    if not targets and not getattr(args, "cache", False) and not getattr(args, "sessions", False):
        err("--module <name> | --all | --cache | --sessions me se kuch do")
        return 2
    for name in targets:
        if name not in REGISTRY:
            err("unknown module: %s" % name)
            return 2
        mout = outdir_for(base, sc.engagement, name)
        if getattr(args, "hard", False):
            if args.yes or _confirm("poora module dir delete karun: %s" % mout):
                shutil.rmtree(mout, ignore_errors=True)
                ok("hard reset: %s (poora module output)" % name)
            continue
        Checkpoint(mout, name, fresh=True)
        ok("checkpoint reset: module=%s engagement=%s" % (name, sc.engagement))
    if getattr(args, "cache", False):
        pc = ProbeCache(base, sc.engagement)
        pc.clear()
        ok("cross-module probe cache cleared: %s" % pc.path)
    if getattr(args, "sessions", False):
        ss = SessionStore(base, sc.engagement)
        for sname in ss.list():
            ss.delete(sname)
        ok("session store cleared: %s" % ss.path)
    return 0


def _confirm(q):
    try:
        return input("%s [y/N]: " % q).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def load_mod(name):
    if name not in REGISTRY:
        err("Unknown module: %s" % name)
        err("Available: %s" % ", ".join(RUN_ORDER))
        sys.exit(2)
    path = mod_path(name)
    if path is None:
        err("Module file missing: %s.py (phases/<block>/ ya root pe rakho)" % REGISTRY[name][0])
        sys.exit(2)
    mname = REGISTRY[name][0]
    spec = importlib.util.spec_from_file_location(mname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mname] = mod
    spec.loader.exec_module(mod)
    return mod

def cmd_doctor(args):
    """Environment + integrity report - OFFLINE friendly (scope/network optional)."""
    head("WASP doctor (app v%s | core v%s)" % (APP_VERSION, VERSION))
    issues, suggestions = [], []
    print("  python         : %s" % sys.version.split()[0])
    if sys.version_info < (3, 8):
        issues.append("python >= 3.8 chahiye (tumhara: %s)" % sys.version.split()[0])
    print("  wasp dir       : %s" % HERE)
    print("  cwd            : %s" % os.getcwd())
    try:
        import ssl
        print("  openssl        : %s" % ssl.OPENSSL_VERSION)
    except Exception:
        pass
    try:
        import dns.resolver  # noqa
        print("  dnspython      : present")
    except ImportError:
        print("  dnspython      : MISSING (optional)")

    head("Files")
    print("  wasp.py        : OK (ye file)")
    print("  wasp_core.py   : %s" % ("OK (v%s ULTRA)" % VERSION
                                      if os.path.exists(os.path.join(HERE, "wasp_core.py"))
                                      else "MISSING - fatal"))
    if not os.path.exists(os.path.join(HERE, "wasp_core.py")):
        issues.append("wasp_core.py missing - pack adhoora hai")
    mods_present = 0
    for name in RUN_ORDER:
        p = mod_path(name)
        if p:
            mods_present += 1
            eps = detect_entrypoints(p)
            if not eps:
                warn("  mod %-10s: present, par run/main entrypoint NAHI mila (AST detect)" % name)
                suggestions.append("%s ka run(cfg, scope, base) entrypoint check karo" % name)
            else:
                print("  mod %-10s: OK  entrypoints: %s" % (name, ", ".join(n for n, _ in eps)))
        else:
            warn("  mod %-10s: MISSING (phase P%s skip hoga)" % (name, REGISTRY[name][2]))
    if mods_present < len(RUN_ORDER):
        suggestions.append("missing mod files copy karo (drop-in, koi registry edit nahi)")
    print("  wasp_selftest  : %s" % ("present"
                                    if os.path.exists(os.path.join(HERE, "wasp_selftest.py"))
                                    else "MISSING (selftest par builtin engine-checks chalenge)"))
    scope_path = getattr(args, "scope", None) or os.path.join(HERE, "scope.json")
    print("  scope.json     : %s" % ("present" if os.path.exists(scope_path)
                                     else "MISSING (wizard chalao)"))
    if not os.path.exists(scope_path):
        suggestions.append("python3 wasp.py wizard - scope.json banao")
    cfg_path = getattr(args, "config", None) or os.path.join(HERE, "config.json")
    print("  config.json    : %s" % ("present" if os.path.exists(cfg_path)
                                     else "MISSING (defaults chalenge; tune se banao)"))

    head("Output / checkpoints / cache (base=%s)" % resolve_base(args))
    base = resolve_base(args)
    if not os.path.isdir(base):
        info("  output base abhi exist nahi karta (kuch run nahi hua)")
    else:
        if not os.access(base, os.W_OK):
            err("  output base WRITABLE nahi: %s" % base)
            issues.append("output dir permission fix karo: %s" % base)
        for eng in sorted(os.listdir(base)):
            eroot = os.path.join(base, eng)
            if not os.path.isdir(eroot):
                continue
            corrupt = []
            for mod in sorted(os.listdir(eroot)):
                mdir = os.path.join(eroot, mod)
                if not os.path.isdir(mdir):
                    continue
                h, p = checkpoint_healthy(mdir, mod)
                if not h:
                    corrupt.append(p)
            cache = os.path.join(eroot, "_cache", "probes.json")
            sess = os.path.join(eroot, "_state", "sessions.json")
            cp_total = sum(1 for mod in os.listdir(eroot)
                           if os.path.isdir(os.path.join(eroot, mod)))
            print("  engagement %-22s modules:%d  cache:%s  sessions:%s"
                  % (eng[:22], cp_total,
                     human_size(os.path.getsize(cache)) if os.path.exists(cache) else "-",
                     human_size(os.path.getsize(sess)) if os.path.exists(sess) else "-"))
            if corrupt:
                for p in corrupt:
                    warn("  corrupt checkpoint: %s" % p)
                issues.append("%d corrupt checkpoint(s) engagement=%s" % (len(corrupt), eng))
                if getattr(args, "fix", False):
                    for p in corrupt:
                        try:
                            os.remove(p)
                            ok("  removed corrupt: %s" % p)
                        except OSError:
                            pass
                else:
                    suggestions.append("wasp.py doctor --fix (corrupt checkpoints delete)")

    head("Summary")
    if issues:
        for i in issues:
            err("ISSUE: %s" % i)
    else:
        ok("koi blocking issue nahi mila")
    if suggestions:
        print("  suggestions:")
        for s in dict.fromkeys(suggestions):
            dim("  -> %s" % s)
    info("verify ke liye: python3 wasp.py verify")
    return 0


def builtin_selftest():
    """wasp_selftest.py na mile to engine-only offline checks (mock network zero)."""
    head("WASP builtin engine selftest (offline)")
    passed, failed = 0, 0
    import tempfile
    tdir = tempfile.mkdtemp(prefix="wasp_engine_test_")

    def chk(name, fn):
        nonlocal passed, failed
        try:
            fn()
            ok("PASS %s" % name)
            passed += 1
        except Exception as e:
            err("FAIL %s -> %s: %s" % (name, type(e).__name__, e))
            failed += 1

    import wasp_core as wc

    chk("murmur3 deterministic", lambda: (
        wc.murmur3_32("hello") == wc.murmur3_32(b"hello") and wc.murmur3_32("") == 0))
    chk("favicon_hash int", lambda: (
        isinstance(wc.favicon_hash(b"icon"), int)))
    chk("similarity math", lambda: (
        wc.similarity("abcd efgh", "abcd efgh") == 1.0 and wc.similarity("abcd", "wxyz") < 0.1))
    chk("median/mad/robust_z", lambda: (
        wc.median([1, 2, 3]) == 2.0 and wc.mad([1, 1, 1, 100]) > 0))
    chk("redact masks middle", lambda: (
        "*" in wc.redact("SUPERSECRETVALUE", 4) and len(wc.redact("SUPERSECRETVALUE", 4)) >= 8))
    chk("save/load_json roundtrip", lambda: (
        (lambda p: (wc.save_json(p, {"a": [1, 2]}),
                    wc.load_json(p)["a"] == [1, 2]))(os.path.join(tdir, "x.json"))))
    chk("scope firewall allow/deny", lambda: (
        (lambda p: (wc.save_json(p, {"engagement": "t", "authorized": True,
                                     "authorization_reference": "test",
                                     "targets": ["http://127.0.0.1"],
                                     "domains": ["example.com"]}),
                    (lambda sc: (sc.check_url("http://sub.example.com") and
                                 not sc.check_url("http://evil.com", raise_on_fail=False) and
                                 bool(sc.seed_urls())))(wc.Scope(p)))
         )(os.path.join(tdir, "scope.json"))))
    chk("scope unauthorized raises", lambda: (
        (lambda p: (wc.save_json(p, {"engagement": "t", "authorized": False,
                                     "targets": ["http://127.0.0.1"]}),
                    _expect_raise(lambda: wc.Scope(p))))(os.path.join(tdir, "s2.json"))))
    chk("scope.validate hygiene", lambda: (
        (lambda p: (wc.save_json(p, {"engagement": "t", "authorized": True,
                                     "authorization_reference": "REPLACE",
                                     "targets": ["http://127.0.0.1"],
                                     "wildcards": ["*.com"]}),
                    (lambda sc: len(sc.validate()[0]) >= 1)(wc.Scope(p)))
         )(os.path.join(tdir, "s3.json"))))
    chk("checkpoint mark/step/resume", lambda: (
        (lambda cp: (cp.mark("k1", {"v": 1}),
                     cp.is_done("k1") and cp.result_of("k1") == {"v": 1}
                     and cp.step("k2", lambda: 42)[0] == 42
                     and not cp.is_done("nope")))(Checkpoint(tdir, "tmod"))))
    chk("checkpoint_status reads", lambda: (
        checkpoint_status(tdir, "tmod")["done_steps"] >= 2))
    chk("evidence collision-proof", lambda: (
        (lambda ev: (ev.save_body("same.txt", b"1"), ev.save_body("same.txt", b"2"),
                     len([f for f in os.listdir(ev.raw_dir)
                          if f.startswith("same")]) == 2))(Evidence(tdir))))
    chk("parse_robots", lambda: (
        (lambda r: (r["sitemaps"] == ["https://h/sitemap.xml"] and
                    "/admin" in r["interesting"] and r["crawl_delay"] == 2.0)
         )(wc.parse_robots("User-agent: *\nDisallow: /admin\nCrawl-delay: 2\n"
                           "Sitemap: https://h/sitemap.xml"))))
    chk("parse_sitemap + index", lambda: (
        (lambda p: (p["is_index"] and len(p["sitemaps"]) == 1)
         )(wc.parse_sitemap("<sitemapindex><sitemap><loc>https://h/a.xml</loc></sitemap></sitemapindex>"))
        and len(wc.parse_sitemap("<urlset><url><loc>https://h/</loc></url></urlset>")["urls"]) == 1))
    chk("jwt_decode", lambda: (
        (lambda d: (d.get("header", {}).get("alg") == "HS256" and
                    d.get("payload", {}).get("sub") == "1")
         )(wc.jwt_decode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"))))
    chk("scan_secrets redacted", lambda: (
        (lambda hits: (len(hits) >= 1 and "AKIA" not in json.dumps(hits))
         )(wc.scan_secrets('key = "' + "AKI" + "A" + "IOSFODNN7EXAMPLE" + '"'))))
    chk("sensitive param hint", lambda: (
        wc.is_sensitive_param("session_token") and not wc.is_sensitive_param("page")))
    chk("deep_unquote double-encoding", lambda: (
        wc.deep_unquote("%2561dmin") == "admin"))
    chk("analyze_security_headers", lambda: (
        "content-security-policy" in wc.analyze_security_headers({"Server": "x"})["missing"]))
    chk("waf_signature cloudflare", lambda: (
        wc.waf_signature({"CF-RAY": "abc", "Server": "cloudflare"}) == ["Cloudflare"]))
    chk("analyze_cookie_flags", lambda: (
        (lambda a: ("no Secure flag" in a["issues"][0]["issue"])
         )(wc.analyze_cookie_flags(["session=abc; Path=/"]))))
    chk("load_words cap", lambda: (
        len(wc.load_words(cap=25)) == 25 and len(wc.load_words()) > 100))
    chk("make_finding severity normalise", lambda: (
        wc.make_finding("m", "t", "CRIT")["severity"] == "critical"))
    def _agg_test():
        wc.save_json(os.path.join(tdir, "eng", "modA", "modA.json"),
                     {"findings": [{"title": "x", "severity": "high"}]})
        agg = wc.aggregate_findings(tdir, "eng")
        return agg["total"] == 1 and agg["by_severity"]["high"] == 1
    chk("aggregate_findings rollup", _agg_test)
    chk("session store roundtrip", lambda: (
        (lambda ss: (ss.save("user1", [{"name": "sid", "value": "v", "domain": "h",
                                        "path": "/", "secure": False, "expires": None}]),
                     ss.load("user1")[0]["name"] == "sid" and "user1" in ss.list()
                     and ss.delete("user1")))(wc.SessionStore(tdir, "eng"))))
    chk("table render no-crash", lambda: table([[1, "a"], [2, "b"]], ["N", "S"]))
    chk("human_size/human_dur", lambda: (
        wc.human_size(2048).endswith("KB") and wc.human_dur(125) == "2m05s"))

    shutil.rmtree(tdir, ignore_errors=True)
    head("builtin selftest summary")
    ok("%d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


def _expect_raise(fn):
    try:
        fn()
    except Exception:
        return True
    raise AssertionError("expected exception, none raised")


def cmd_selftest(args):
    """Offline self-test: wasp_selftest.py (mock server, ~50 checks) ya builtin fallback."""
    st_path = os.path.join(HERE, "wasp_selftest.py")
    if os.path.exists(st_path):
        try:
            from wasp_selftest import run_selftest
        except Exception as e:
            err("wasp_selftest import failed (%s) -> builtin engine selftest chala raha hoon" % e)
            return builtin_selftest()
        head("WASP selftest (offline, mock server)")
        try:
            return run_selftest(args) or 0
        except SystemExit as e:
            return int(e.code or 0)
    warn("wasp_selftest.py not found next to wasp.py -> builtin engine selftest")
    return builtin_selftest()


def cmd_wizard(args):
    """Interactive scope.json + config.json builder (wizard)."""
    if not args.yes and not sys.stdin.isatty():
        err("interactive shell nahi hai - --yes ke saath answers env/args se do, ya TTY me chalao")
        return 2
    head("WASP wizard - scope.json banate hain")
    print("Authorized targets hi bharo. Scope firewall inhi par lock hota hai.")
    def ask(q, default=""):
        d = (" [%s]" % default) if default else ""
        v = input("%s%s: " % (q, d)).strip()
        return v or default
    eng = ask("engagement ka naam", "my-engagement")
    if not args.yes:
        a = input("authorized=true confirm? (type YES): ").strip()
        if a != "YES":
            err("wizard abort - scope authorized nahi hua (sahi decision, permission ke bina mat chalao)")
            return 2
    ref = ask("authorization_reference (program URL / SOW / ticket+date)", "REPLACE: bharo")
    targets = [t for t in re.split(r"[,\s]+", ask("targets (comma/space separated, https://...)", "")) if t]
    domains = [d for d in re.split(r"[,\s]+", ask("domains (apex + subdomains)", "")) if d]
    wildcards = [w for w in re.split(r"[,\s]+", ask("wildcards (*.example.com)", "")) if w]
    ips = [i for i in re.split(r"[,\s]+", ask("ips", "")) if i]
    excludes = [e for e in re.split(r"[,\s]+", ask("excludes (out-of-scope hosts)", "")) if e]
    notes = ask("RoE notes (no-DoS, manual-only...)", "No DoS. Read-only default.")
    if not (targets or domains or wildcards or ips):
        err("koi target hi nahi - kuch bhi scope nahi hua")
        return 2
    scope = {"engagement": eng, "authorized": True, "authorization_reference": ref,
             "targets": targets, "domains": domains, "wildcards": wildcards,
             "excludes": excludes, "ips": ips, "notes": notes}
    spath = getattr(args, "scope", None) or os.path.join(HERE, "scope.json")
    if os.path.exists(spath) and not (args.yes or _confirm("scope.json already hai - overwrite?")):
        info("scope.json untouched. Naya path chahiye to --scope PATH do.")
    else:
        wc_save = __import__("wasp_core").save_json
        wc_save(spath, scope)
        ok("scope.json written: %s" % spath)

    head("config.json preset")
    print("profiles: %s" % PROFILES_HINT)
    prof = ask("profile", "normal").lower().strip()
    cpath = getattr(args, "config", None) or os.path.join(HERE, "config.json")
    if os.path.exists(cpath):
        bak = cpath + ".bak-" + str(int(time.time()))
        shutil.copy2(cpath, bak)
        info("purana config backup: %s" % bak)
        data = json.load(open(cpath))
    else:
        data = dict(__import__("wasp_core").DEFAULT_CONFIG)
    apply_profile(_CfgShim(data), prof)
    __import__("wasp_core").save_json(cpath, data)
    ok("config.json written (profile=%s): %s" % (prof, cpath))
    info("pre-flight: python3 wasp.py verify")
    return 0


class _CfgShim:
    """wizard ke liye dict-backed shim (apply_profile isi par chalta hai)."""
    def __init__(self, data):
        self.data = data


def cmd_findings(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    min_sev = getattr(args, "min_sev", None) or "info"
    res = write_findings_report(base, sc.engagement, min_severity=min_sev)
    agg = res["aggregate"]
    if getattr(args, "json", False):
        print(json.dumps(agg, indent=2, default=str))
        return 0
    head("WASP findings | engagement=%s | threshold>=%s" % (sc.engagement, min_sev))
    if not agg["total"]:
        warn("koi finding nahi mili (modules chalaye? python3 wasp.py runall)")
        info("report: %s" % res["findings_json"])
        return 0
    rows = [[s.upper(), agg["by_severity"][s]] for s in
            ("critical", "high", "medium", "low", "info") if agg["by_severity"][s]]
    table(rows, ["SEVERITY", "COUNT"])
    print()
    rows2 = [[it["severity"].upper(), it["module"], str(it["title"])[:80]]
             for it in agg["items"][:40]]
    table(rows2, ["SEVERITY", "MODULE", "TITLE"])
    if agg["total"] > len(agg["items"]):
        dim("... +%d more (JSON me poora)" % (agg["total"] - len(agg["items"])))
    print("\n  files: %s | %s" % (res["findings_json"], res["findings_md"]))
    return 0


def cmd_report(args):
    sc = load_scope_or_die(args)
    cfg = load_cfg_tuned(args)
    base = resolve_base(args)
    import wasp_core as wc
    root = os.path.join(base, sc.engagement)
    head("WASP report builder | engagement=%s" % sc.engagement)
    find = write_findings_report(base, sc.engagement,
                                 min_severity=getattr(cfg, "findings_min_severity", "info"))
    agg = find["aggregate"]
    L = ["# WASP ENGAGEMENT REPORT - %s" % sc.engagement, "",
         "- generated : %s" % now_human(),
         "- engine    : wasp.py v%s / wasp_core v%s (ULTRA)" % (APP_VERSION, VERSION),
         "- scope     : %s" % sc.describe(),
         "- auth ref  : %s" % (sc.ref or "-"), ""]
    errs, warns = sc.validate()
    if errs or warns:
        L += ["## Scope hygiene", ""]
        L += ["- ERROR: %s" % e for e in errs] + ["- WARN: %s" % w for w in warns] + [""]

    L += ["## Module execution", "",
          "| Module | Phase | State | Steps | Findings |", "|---|---|---|---|---|"]
    for name in RUN_ORDER:
        st = module_status_row(base, sc.engagement, name)
        fc = findings_count_for(base, sc.engagement, name)
        L.append("| %s | P%s | %s | %s | %d |" % (name, REGISTRY[name][2], st.get("state"),
                                                  st.get("done_steps", 0), fc))

    L += ["", "## Findings (severity >= %s)" % getattr(cfg, "findings_min_severity", "info"), "",
          "Total: %d | critical: %d | high: %d | medium: %d | low: %d | info: %d"
          % (agg["total"], *[agg["by_severity"][s] for s in wc.SEVERITIES]), "",
          "| Severity | Module | Title |", "|---|---|---|"]
    for it in agg["items"][:300]:
        L.append("| %s | %s | %s |" % (it["severity"].upper(), it["module"],
                                       str(it["title"]).replace("|", "\\|")))
    if not agg["items"]:
        L.append("| - | - | (koi finding threshold par nahi) |")

    L += ["", "## Evidence volume", ""]
    for name in RUN_ORDER:
        ev = Evidence(os.path.join(root, name))
        s = ev.summary()
        if s["requests"]:
            top = ", ".join("%s:%s" % kv for kv in sorted(
                s["by_status"].items(), key=lambda kv: -kv[1])[:5])
            L.append("- %-10s %5d requests (%d errors) [%s]" % (name, s["requests"], s["errors"], top))

    L += ["", "## Feedforward chain (is phase ne kya banaya -> agla phase kahan use karega)", ""]
    live = read_feedforward(base, sc.engagement)
    for name in RUN_ORDER:
        arts = CHAIN_TXT.get(name, [])
        if name in live:
            extra = "; ".join("%s -> %s" % (k, ", ".join(v) if isinstance(v, list) else str(v))
                              for k, v in list(live[name].items())[:4])
            L.append("- **P: %s**: %s%s" % (name, ", ".join(arts[:4]) + ("..." if len(arts) > 4 else ""),
                                            (" | ULTRA live: " + extra) if extra else ""))
        elif arts:
            L.append("- **P: %s**: %s" % (name, ", ".join(arts[:4]) + ("..." if len(arts) > 4 else "")))

    L += ["", "---", "*Authorized testing only - scope firewall ke andar generate hua.*"]
    path = os.path.join(root, "REPORT.md")
    wc.save_text(path, "\n".join(L) + "\n")
    ok("REPORT written: %s" % path)
    ok("findings    : %s (%d findings)" % (find["findings_json"], agg["total"]))
    return 0


def cmd_chain(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    head("WASP feedforward chain | engagement=%s" % sc.engagement)
    live = read_feedforward(base, sc.engagement)
    prev = None
    for name in RUN_ORDER:
        if prev:
            print("   %s%s |" % (" " * 3, C.Y + "^" + C.N))
        arts = CHAIN_TXT.get(name, [])
        print("%s[P%s %s]%s" % (C.BOLD, REGISTRY[name][2], name, C.N))
        if arts:
            for a in arts[:6]:
                dim("   - " + a)
            if len(arts) > 6:
                dim("   - ... +%d" % (len(arts) - 6))
        if name in live:
            info("   live routing (%d keys):" % len(live[name]))
            for k, v in list(live[name].items())[:6]:
                vv = ", ".join(v) if isinstance(v, list) else str(v)
                dim("   %-30s -> %s" % (k, str(vv)[:70]))
        prev = name
    print("\n  note: ye default file-map hai; modules apne feedforward.json me live routing likhte hain.")
    return 0


def cmd_tune(args):
    cpath = getattr(args, "config", None) or os.path.join(HERE, "config.json")
    prof = getattr(args, "profile", None)
    head("WASP tune -> config.json preset")
    if prof not in ("stealth", "normal", "fast", "audit"):
        print("profiles: %s" % PROFILES_HINT)
        prof = input("profile choose karo [normal]: ").strip().lower() or "normal"
    if os.path.exists(cpath):
        bak = cpath + ".bak-" + str(int(time.time()))
        shutil.copy2(cpath, bak)
        info("backup: %s" % bak)
        data = json.load(open(cpath))
    else:
        data = dict(__import__("wasp_core").DEFAULT_CONFIG)
    apply_profile(_CfgShim(data), prof)
    __import__("wasp_core").save_json(cpath, data)
    ok("config.json updated (profile=%s): %s" % (prof, cpath))
    info("ab runs ye preset use karenge: python3 wasp.py run --module <name>")
    return 0


def cmd_cache(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    action = getattr(args, "action", "stats")
    pc = ProbeCache(base, sc.engagement)
    st = pc.stats()
    head("WASP probe cache | engagement=%s" % sc.engagement)
    if action == "clear":
        pc.clear()
        ok("cache cleared (entries the: %d)" % st["entries"])
        return 0
    table([["path", st["path"]], ["entries", st["entries"]],
           ["size", human_size(st["size"])], ["ttl_sec", st["ttl"]],
           ["hits_this_session", st["hits"]]], ["KEY", "VALUE"])
    ss = SessionStore(base, sc.engagement)
    names = ss.list()
    info("sessions: %s" % (", ".join(names) or "-"))
    print("\n  ek hi URL dobara probe nahi hota (time+noise bachta hai). Clear: wasp.py cache clear")
    return 0


def cmd_evidence(args):
    sc = load_scope_or_die(args)
    base = resolve_base(args)
    root = os.path.join(base, sc.engagement)
    only = getattr(args, "module", None)
    only = resolve_module_name(only) if only else None
    tail = getattr(args, "tail", 0) or 0
    head("WASP evidence | engagement=%s" % sc.engagement)
    rows, total_req = [], 0
    for name in RUN_ORDER:
        if only and name != only:
            continue
        ev = Evidence(os.path.join(root, name))
        s = ev.summary()
        if not s["requests"]:
            continue
        total_req += s["requests"]
        rows.append([name, s["requests"], s["errors"],
                     len(os.listdir(ev.raw_dir)) if os.path.isdir(ev.raw_dir) else 0])
    if rows:
        table(rows, ["MODULE", "REQUESTS", "ERRORS", "RAW BODIES"])
        print("\n  total logged requests: %d" % total_req)
    else:
        info("abhi koi evidence nahi (module chalao)")
    if tail:
        target = only or (rows[0][0] if rows else None)
        if not target:
            return 0
        path = os.path.join(root, target, "evidence", "requests.jsonl")
        if os.path.exists(path):
            head("last %d requests of '%s'" % (tail, target))
            with open(path, errors="ignore") as f:
                lines = f.readlines()[-tail:]
            for ln in lines:
                try:
                    r = json.loads(ln)
                    if r.get("error"):
                        dim("%s %s -> ERROR %s" % (r.get("method"), r.get("url"), r.get("error")))
                    else:
                        dim("%s %s -> %s (%sB)" % (r.get("method"), r.get("url"),
                                                   r.get("status"), r.get("len")))
                except Exception:
                    dim(ln.strip()[:120])
    return 0

# ---------------------------------------------------------------------------
# parser + main
# ---------------------------------------------------------------------------
def build_parser():
    epilog = """
examples:
  wasp.py verify
  wasp.py run --module 5 --profile stealth        # phase-5 content, stealth preset
  wasp.py run --module content --rate 2 --max-requests 5000
  wasp.py run --block 2                          # poora Block 2 (auth/sessions/access)
  wasp.py runall --block 3                       # sirf Block 3 pipeline
  wasp.py runall --fresh
  wasp.py findings --min-sev medium
  wasp.py report
  wasp.py reset --module content --cache
Authorized testing only. Scope firewall har request par enforce hota hai.
"""
    p = argparse.ArgumentParser(prog="wasp", description="WASP Web Assessment Script Pack (ULTRA) - authorized testing only",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
    p.add_argument("--version", action="version",
                   version="WASP %s (core %s ULTRA)" % (APP_VERSION, VERSION))
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--scope", default=None, help="path to scope.json")
        sp.add_argument("--config", default=None, help="path to config.json")
        sp.add_argument("--out", default=None, help="output base dir (default ~/wasp_out | env WASP_OUT)")
        sp.add_argument("--yes", action="store_true", help="non-interactive (confirmations skip)")
        sp.add_argument("--token", default=None, help="license token (ya env WASP_TOKEN)")

    def perf(sp):
        sp.add_argument("--profile", default=None, help="stealth|normal|fast|audit (env WASP_PROFILE)")
        sp.add_argument("--rate", default=None, help="requests/second override")
        sp.add_argument("--jitter", default=None, help="jitter fraction override (0-1)")
        sp.add_argument("--concurrency", default=None, help="worker threads override")
        sp.add_argument("--timeout", default=None, help="per-request timeout (s) override")
        sp.add_argument("--max-requests", dest="max_requests", default=None, help="hard budget override")
        sp.add_argument("--proxy", default=None, help="proxy URL override (http://127.0.0.1:8080)")
        sp.add_argument("--allow-destructive", dest="allow_destructive", action="store_true",
                        help="RoE permit ho tabhi (default OFF)")

    s = sub.add_parser("list", help="module registry + entrypoints"); common(s)
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("run", help="run one module or a full block (resumable)"); common(s); perf(s)
    s.add_argument("--module", default=None, metavar="name|phase#", help="e.g. content | 5")
    s.add_argument("--block", default=None, metavar="1-6", help="poora block run karo, e.g. --block 2")
    s.add_argument("--fresh", action="store_true", help="ignore checkpoint, start over")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("runall", help="run all modules in order (skip complete)"); common(s); perf(s)
    s.add_argument("--block", default=None, metavar="1-6", help="sirf ek block run karo")
    s.add_argument("--fresh", action="store_true", help="redo even complete modules")
    s.set_defaults(func=cmd_runall)

    s = sub.add_parser("verify", help="pre-flight checks"); common(s); perf(s)
    s.add_argument("--no-net", action="store_true", help="network checks skip karo")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("status", help="checkpoint / findings / resume status"); common(s)
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("reset", help="reset checkpoints / cache / sessions"); common(s)
    s.add_argument("--module", default=None, metavar="name|phase#")
    s.add_argument("--all", action="store_true", help="saare modules ka checkpoint reset")
    s.add_argument("--cache", action="store_true", help="cross-module probe cache clear")
    s.add_argument("--sessions", action="store_true", help="stored identity sessions clear")
    s.add_argument("--hard", action="store_true", help="poora module output dir delete")
    s.set_defaults(func=cmd_reset)

    s = sub.add_parser("doctor", help="environment + checkpoint integrity report"); common(s)
    s.add_argument("--fix", action="store_true", help="corrupt checkpoints auto-remove")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("selftest", help="offline mock-target self-test"); common(s)
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("findings", help="cross-module findings rollup (findings.json+FINDINGS.md)")
    common(s)
    s.add_argument("--min-sev", dest="min_sev", default="info",
                   choices=["info", "low", "medium", "high", "critical"])
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser("report", help="poora REPORT.md generate karo"); common(s); perf(s)
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("chain", help="phase feedforward chain map"); common(s)
    s.set_defaults(func=cmd_chain)

    s = sub.add_parser("wizard", help="scope.json + config.json interactive builder"); common(s)
    s.set_defaults(func=cmd_wizard)

    s = sub.add_parser("tune", help="config.json me profile preset likho"); common(s)
    s.add_argument("--profile", default=None, help="stealth|normal|fast|audit")
    s.set_defaults(func=cmd_tune)

    s = sub.add_parser("cache", help="probe cache stats/clear"); common(s)
    s.add_argument("action", nargs="?", default="stats", choices=["stats", "clear"])
    s.set_defaults(func=cmd_cache)

    s = sub.add_parser("evidence", help="evidence requests summary"); common(s)
    s.add_argument("--module", default=None, metavar="name|phase#")
    s.add_argument("--tail", type=int, default=0, help="last N requests print karo")
    s.set_defaults(func=cmd_evidence)
    return p


def main():
    args = build_parser().parse_args()
    if not getattr(args, "cmd", None):
        build_parser().print_help()
        return 1
    # LICENSE GATE: sirf testing commands par (run/runall).
    # list/doctor/verify/status/selftest/findings/report FREE hain.
    if getattr(args, "cmd", None) in ("run", "runall"):
        try:
            from wasp_license import gate_license
            args._license = gate_license(token=getattr(args, "token", None))
        except ImportError:
            warn("wasp_license.py missing - license gate skip (file repo me hai, dobara clone karo)")
            args._license = None
    try:
        return args.func(args)
    except SystemExit as e:
        raise
    except KeyboardInterrupt:
        err("Interrupted - checkpointed state safe hai (wahi command dobara chalao).")
        return 130
    except ScopeError as e:
        err("SCOPE BLOCKED: %s" % e)
        err("Troubleshooting: scope.json me authorized=true + sahi targets. Detail: wasp.py doctor")
        return 3
    except Exception:
        err("Unexpected error:")
        traceback.print_exc()
        err("Diagnostics: python3 wasp.py doctor")
        return 1


if __name__ == "__main__":
    sys.exit(main())
