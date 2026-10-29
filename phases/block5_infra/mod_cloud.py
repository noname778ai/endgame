#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
WASP Module: mod_cloud.py  |  Phase 24 - Cloud & Container Security
            ULTRA PRO MAX (ProviderFP/Storage-Bucket/Takeover/IMDS/Secrets/
            SignedURL/Container-K8s/Serverless/CDN/CORS/IAM/DNS/Errors/
            Consoles/CI-CD/APIToken/GQL-WS/Bypass2)
=======================================================================================
v30.0.0 FULL ULTRA PRO MAX (koi ek line ki bhi kami nahi - all to all
techniques: hacking hidden secrets + old & new security bypasses + advanced
level secret techniques). Authorized security testing ONLY. Scope firewall +
rate limiter + request budget + evidence + checkpoint sab wasp_core se
inherit hote hain, isliye har census request scope-check, rate-limit aur
budget ke andar hi jaati hai.

KYA KARTA HAI
  Cloud security = "app to theek, infrastructure/konfig galat" - provider
  fingerprints leak, storage buckets public, subdomain takeover-CNAME
  dangling, IMDS/metadata waves, cloud secrets pages/JS me chhap gaye,
  presigned URLs unbounded, container/K8s metrics+registry exposed,
  serverless endpoints internet-facing, CDN cache confusion, storage CORS
  loose, IAM/ARN shapes recon aid, cloud verbose errors, cloud consoles
  exposed, CI/CD + IaC artifacts (.github/tfstate) public, API tokens URL me
  Ye flaws sirf POST/attack se NAHI dikhte - ek INERT GET census kaafi hai.
  P24 ka kaam: (1) CLOUD SURFACE ka poora census (15-module feedforward +
  P23 to_phase24_cloud seeds + 44-path cold pool), (2) har surface par
  INERT marker-differential (provider header shapes, bucket XML shapes,
  takeover service fingerprints, secret-shape regexes - values REDACTED),
  (3) jo execution-class techniques hain (IMDS probe, bucket listing,
  takeover verify, kubelet exec) unka DOCUMENTED-ONLY playbook + GATED
  canary census (GET-only, .invalid canary origins, bounded caps). -> 26
  stages (A..Z):

    A. Cloud surface disc.     - 15-module feedforward (P23 cloud-header
                                  shapes + bucket_surface, P15 metadata/
                                  ssrf seeds, P4 headers, P6 tech, P7 js
                                  secrets/urls, P5 content, P2 endpoints,
                                  P9/P17/P18/P19/P20/P21/P22 handoffs) +
                                  artifact mining + 44-path cold pool
    B. Baseline + WAF           - home marker + soft-404 + WAF fingerprint
    C. Provider fingerprint     - 18-marker census (aws x-amz/awselb/
                                  cloudfront, azure x-ms-/ARR, gcp x-goog/
                                  via-google, cloudflare cf-ray, fastly
                                  x-served-by, akamai, vercel x-vercel-id,
                                  netlify, heroku, OCI, DO-spaces, alibaba,
                                  lambda-runtime, kubernetes, docker) -
                                  header+body shapes, >=2 shapes = identified
    D. Storage/bucket census    - GATED cloud_allow_bucket_probe: 36-path
                                  storage pool (/s3/, /storage/, /minio/,
                                  /uploads/, /backup/, /blobs/...) +
                                  bucket-URL shapes mined from pages/JS
                                  (s3./blob.core/storage.googleapis/do-spaces)
                                  - presence-only, bodies REDACTED
    E. Bucket ACL/error shapes  - GATED cloud_allow_bucket_probe: in-scope
                                  storage endpoints par XML error-shape
                                  census (ListBucketResult, NoSuchKey,
                                  NoSuchBucket, AccessDenied) +
                                  X-Amz-Bucket-Region header shape - sirf
                                  IN-SCOPE hosts (third-party bucket
                                  enumeration FORBIDDEN-AUTO)
    F. Subdomain-takeover       - GATED cloud_allow_takeover_probe: CNAME/
                                  service refs mined from bodies/JS (12-row
                                  fingerprint DB: azurewebsites/s3/github-
                                  pages/heroku/fastly/netlify/vercel/shopify/
                                  zendesk/bitbucket/surge/pantheon) + DNS
                                  alias check (in-scope hosts only) -
                                  unresolved+service-ref = SUSPECTED lead
                                  (manual RoE confirm)
    G. IMDS/metadata playbook   - DOCUMENTED-ONLY 8-row playbook
                                  (FORBIDDEN-AUTO - link-local metadata
                                  probes KABHI nahi; P15 owns bounded smoke)
                                  + instance-metadata header shapes census
                                  (response-side only)
    H. Cloud secrets census     - 34 secret-shape regexes (AKIA/ASIA, gcp
                                  service-account private_key, AIza keys,
                                  azure AccountKey=/SAS sig=, firebase,
                                  ssh-rsa, kube JWT, ECS tokens, presigned
                                  URLs, docker cfg auths, db-url-creds...)
                                  - NAMES + sha1-12 only, values KABHI
                                  store nahi (CWE-798/CWE-200)
    I. Signed-URL lifecycle     - presigned-param census (X-Amz-Date/
                                  X-Amz-Expires/X-Amz-Signature, SAS sig/se/
                                  st, Expires=, token=) -> entropy buckets +
                                  expiry-window math (offline; unbounded
                                  TTL = finding), values sha1-only
    J. Container/K8s census     - GATED cloud_allow_container_probe:
                                  16-path pool (/healthz, /metrics
                                  prometheus shape, /debug/pprof, /env,
                                  /v2/ registry catalog, /kubernetes,
                                  /kubelet, /pods...) + marker shapes -
                                  presence-only
    K. Serverless/API-GW        - GATED cloud_allow_serverless_probe:
                                  12-path pool (/lambda, /functions,
                                  /invoke, /worker...) + lambda-runtime/
                                  execute-api/cloudfunctions/run.app/
                                  azurewebsites/vercel/netlify shapes -
                                  names-only census
    L. CDN/cache posture        - CDN markers (cf-cache-status, x-cache,
                                  x-served-by, age, via) + sensitive-
                                  response cacheability (public/max-age on
                                  storage/auth pages = flag) + P22
                                  cacheable rollup
    M. Storage CORS grading     - GATED cloud_allow_cors_probe: 4 canary
                                  Origins (same/null/sub.evil.invalid/
                                  evil.invalid) on storage-shaped endpoints
                                  -> ACAO reflection grading (P23-compatible)
    N. IAM/ARN shape census     - arn:aws:iam:: / role-shapes, azure tenant
                                  GUID shapes, gcp project-id shapes -
                                  sha1-only REDACTED (recon aid, values
                                  KABHI store nahi)
    O. DNS/alias differential   - GATED cloud_allow_dns_probe: dns_resolve
                                  on IN-SCOPE hostnames only + ff subdomain
                                  candidates -> resolved-IP census + NXDOMAIN
                                  flags (takeover-adjacent lead) - koi
                                  third-party DNS brute nahi
    P. Cloud error shapes       - GATED cloud_allow_error_probe: canary
                                  param probes on cloud endpoints ->
                                  provider error shapes (RequestID,
                                  <Error><Code>, azure ErrorDetails, gcp
                                  error JSON, lambda timeout, k8s forbidden)
    Q. Cloud console fp         - GATED cloud_allow_console_probe: 14
                                  platform markers (AWS console signin,
                                  Azure AD login, GCP login, k8s dashboard,
                                  rancher, portainer, jenkins, gitlab,
                                  argocd, grafana, prometheus UI, consul,
                                  nomad, vault) - presence census
    R. CI/CD + IaC artifacts    - GATED cloud_allow_artifact_probe: 24-path
                                  pool (.github/workflows, .gitlab-ci.yml,
                                  Dockerfile, docker-compose, kube yaml,
                                  terraform.tfstate/.tfvars, .aws/config,
                                  .ssh/id_rsa, Jenkinsfile, azure-
                                  pipelines, cloudbuild) - presence-only,
                                  bodies REDACTED
    S. API-token + header echo  - GATED cloud_allow_header_echo: token-
                                  shaped GET params/headers census (names-
                                  only) + X-Forwarded-Host/X-Original-URL
                                  echo differential on cloud endpoints (6
                                  shapes, GET-only)
    T. Cloud spec + GQL/WS      - GATED cloud_allow_spec_probe: 12 spec
                                  paths (swagger/openapi on api-gw shapes)
                                  + passive GQL mutation-names (NEVER sent)
                                  + WS endpoint rollup (frames NEVER)
    U. Bypass matrix v2         - 20 SECRET cloud-bypass shapes (GATED
                                  cloud_allow_bypass2): path-normalization
                                  (//, /./, /../, %2e%2e, ;params, %09,
                                  case, trailing-slash, double-encode),
                                  header-trust (X-Original-URL, X-Rewrite-
                                  URL, X-Forwarded-Host, X-Forwarded-For,
                                  Host, X-Custom-IP), storage-flavored
                                  (Referer-trust, HEAD differential, Range
                                  partial-content, marker-param) - GET-only
                                  403->2xx differential, canary waspP24
    V. Cloud posture composite  - per-endpoint 14-point (provider-fp-only/
                                  storage-locked/takeover-clean/secrets-
                                  absent/iam-hidden/signedurl-bounded/
                                  container-locked/serverless-hidden/cdn-safe/
                                  cors-strict/dns-clean/errors-masked/
                                  artifacts-absent/bypass2-blocked)
    W. Cross-module chains      - CH01..CH28 cloud kill-chains (P2..P23
                                  handoffs)
    X. Verdict engine           - 6-class ladder (CONFIRMED/SUSPECTED/
                                  HARDENED/BLOCKED/SKIPPED/NOISE) multi-signal
    Y. Technique matrix         - 242 rows x 22 families + CWE + MITRE map
    Z. Reports/artifacts        - 54 artifacts: findings.json,
                                  CLOUD_FINDINGS.md, CLOUD_MATRIX.txt,
                                  census JSONs, test-plan (kill tests),
                                  remediation, exec summary, kickoff,
                                  playbooks + platform fingerprint +
                                  secrets guard + feedforward (P25/P15/P11/
                                  P12/P9/P7/P32) + MANIFEST + RWX-tree
                                  finalize

VERDICT LADDER (6-class, P12..P23-compatible)
  CONFIRMED   -> multi-signal proof (>=2 provider shapes on target;
                 bucket-shape XML live; NoSuchBucket/AccessDenied shape;
                 secret-shape; unbounded presigned TTL; container metrics
                 shape; serverless marker; ACAO canary reflection; verbose
                 provider error; console marker live; CI/CD artifact live;
                 bypass2 403->2xx differential)
  SUSPECTED   -> partial/single signal (1 provider shape, takeover cname-ref
                 unresolved, arn-shape, signed-url present, playground live)
  HARDENED    -> defense present (storage 403 uniform, no-listing shape,
                 cors strict, errors masked, container absent, artifacts
                 absent, dns resolved-clean, bypass2 rejected)
  BLOCKED     -> WAF/probe-level block (fingerprint input, finding nahi)
  SKIPPED     -> RoE-gated probe (gate OFF) - manual wave documented
  NOISE       -> baseline unstable / soft-404 template - verdict nahi

SAFETY MODEL (cloud = 'exposure+infrastructure' surface - P15..P23 jitni
strict discipline)
  * 100% INERT: koi exploitation KABHI nahi hota. Har probe synthetic canary
    identifiers (waspP24 family) use karta hai; artifact bodies KABHI store
    nahi hote - sirf status/len/sha1-12/shape-flags. Secret/IAM VALUES ka
    sirf sha1-12 + shape-name store hota hai, value itself REDACTED (PII
    regex sweep har detail par).
  * GET-ONLY MODULE: saare probes GET/HEAD/OPTIONS - koi POST/PUT/DELETE/
    PATCH KABHI (module-wide assert + wasp_core LAYER-4 read-only
    double-guard). Koi mutation, koi write, koi config-change nahi.
  * NO IMDS PROBES: link-local metadata endpoints (169.254.x.x family)
    KABHI directly probe nahi hote - sirf DOCUMENTED playbook (P15 owns
    bounded IMDS smoke; P24 owns cloud surface census).
  * NO THIRD-PARTY BUCKET ENUMERATION: bucket listing/enumeration sirf
    IN-SCOPE hosts par (scope firewall LAYER-4). External S3/GCS/Azure
    endpoints par koi request KABHI jaati nahi - sirf URL-shape census
    (offline mining) + in-scope host responses.
  * NO TAKEOVER VERIFICATION: takeover = fingerprint-lead ONLY (service-ref
    + unresolved) - koi resource-claim/provision request KABHI nahi
    (manual+RoE confirm wave documented).
  * NO CREDS/STUFFING: cloud cred matrices DOCUMENTED-ONLY - koi credential
    network par nahi jaata (stuffing/brute FORBIDDEN-AUTO).
  * NO KUBELET EXEC/REGISTRY PUSH: container techniques documented-only -
    koi exec/push/exec-request KABHI nahi (presence census only).
  * ZERO EXTERNAL EGRESS: har HTTP probe scope-check se pehle blocked
    (wasp_core LAYER-4). canary origins sirf *.invalid TLD. DNS sirf
    in-scope hostnames (gate-gated).
  * allow_active=False -> PASSIVE mode: offline hypotheses only (0 probes).
  * Har stage checkpointed (Ctrl+C safe), sab caps config se tunable.
  * Sab result files RWX (0777) - save_json/save_text wrappers se guaranteed.
"""

import os
import re
import sys
import json
import time
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
                           write_feedforward, write_manifest, read_feedforward,
                           soft404_baseline, is_soft404, title_of, waf_signature,
                           dns_resolve,
                           interrupted, info, ok, warn, err,
                           head, dim, C, VERSION, now_human, human_size)
    CORE = True
except ImportError:
    CORE = False
    print("[-] wasp_core.py isi folder me hona chahiye (wasp_core.py not found).")
    print("    Ye module WASP framework ka hissa hai: python3 wasp.py run --module 24")
    sys.exit(1)

NAME = "cloud"
PHASE = "24-cloud"
PLAN_VERSION = "30.0.0"

# ===========================================================================
# TUNABLES (config.json attributes override kar sakte hain)
# ===========================================================================
DEFAULTS = {
    # ---- caps ----
    "cloud_paths_cap": 40,          # kitne ranked targets census me jaayenge
    "cloud_probe_cap": 24,          # per-stage probe budget
    "cloud_cold_paths": 44,         # cold-start pool size
    "cloud_storage_paths": 36,      # storage/bucket path pool size
    "cloud_container_paths": 16,    # container/orchestrator pool size
    "cloud_serverless_paths": 12,   # serverless/api-gw pool size
    "cloud_artifact_paths": 24,     # CI/CD + IaC artifact pool size
    "cloud_spec_paths": 12,         # cloud api-spec pool size
    "cloud_bypass2_cap": 20,        # bypass2 shapes per target
    "cloud_secret_cap": 40,         # secret-shape records cap (sha1-only)
    "cloud_depth": 3,               # discovery link-follow depth
    "cloud_dns_cap": 10,            # in-scope DNS resolve cap
    # ---- RoE GATES (sab default OFF - cloud-class probes) ----
    "cloud_allow_bucket_probe": False,   # GATE: storage/bucket + ACL shape census
    "cloud_allow_takeover_probe": False, # GATE: takeover fingerprint census
    "cloud_allow_container_probe": False,# GATE: metrics/registry/kubelet census
    "cloud_allow_serverless_probe": False,# GATE: serverless/api-gw census
    "cloud_allow_cors_probe": False,     # GATE: storage Origin canary reflection
    "cloud_allow_dns_probe": False,      # GATE: in-scope DNS alias differential
    "cloud_allow_error_probe": False,    # GATE: provider error-shape probes
    "cloud_allow_console_probe": False,  # GATE: cloud console/login census
    "cloud_allow_artifact_probe": False, # GATE: CI/CD + IaC artifact census
    "cloud_allow_header_echo": False,    # GATE: token-param + trust-header echo
    "cloud_allow_spec_probe": False,     # GATE: cloud api-spec census
    "cloud_allow_bypass2": False,        # GATE: 20-secret cloud bypass2 matrix
}

# RoE gate registry (CLI/report me use hota hai)
ROE_GATES = [
    ("cloud_allow_bucket_probe",     "storage/bucket + ACL-shape GET census"),
    ("cloud_allow_takeover_probe",   "takeover fingerprint (cname-ref) census"),
    ("cloud_allow_container_probe",  "metrics/registry/kubelet GET census"),
    ("cloud_allow_serverless_probe", "serverless/api-gw endpoint census"),
    ("cloud_allow_cors_probe",       "storage Origin canary CORS differential"),
    ("cloud_allow_dns_probe",        "in-scope DNS alias differential"),
    ("cloud_allow_error_probe",      "provider error-shape canary probes"),
    ("cloud_allow_console_probe",    "cloud console/login surface census"),
    ("cloud_allow_artifact_probe",   "CI/CD + IaC artifact GET census"),
    ("cloud_allow_header_echo",      "token-param + trust-header echo census"),
    ("cloud_allow_spec_probe",       "cloud api-spec exposure census"),
    ("cloud_allow_bypass2",          "20-secret cloud bypass2 shape matrix"),
]

CANARY_FAMILY = "waspP24"

# ---------------------------------------------------------------------------
# PATH POOLS (cold-start discovery - cloud-shaped URL shapes)
# ---------------------------------------------------------------------------
COLD_PATHS = [
    "/s3", "/s3/", "/storage", "/storage/", "/bucket", "/blobs", "/minio",
    "/minio/health/live", "/uploads", "/media", "/backup", "/backup.zip",
    "/files", "/download", "/objects", "/metrics", "/healthz", "/env",
    "/debug/pprof", "/v2", "/v2/_catalog", "/kubernetes", "/k8s", "/docker",
    "/registry", "/lambda", "/functions", "/invoke", "/worker", "/api",
    "/api/health", "/swagger.json", "/openapi.json", "/graphql", "/graphiql",
    "/.github/workflows", "/.gitlab-ci.yml", "/Dockerfile",
    "/docker-compose.yml", "/terraform.tfstate", "/.aws/config", "/kube.yaml",
    "/console", "/dashboard", "/.env",
]

# storage/bucket-shaped paths (stage D pool - in-scope only)
STORAGE_PATHS = [
    "/s3/", "/s3/bucket", "/storage/", "/storage/v1/", "/bucket/", "/blobs/",
    "/objects/", "/minio/", "/minio/health/live", "/minio/health/ready",
    "/uploads/", "/media/", "/backup/", "/backup.zip", "/dump.sql",
    "/files/", "/download/", "/data/", "/static/", "/assets/", "/cdn/",
    "/archive/", "/public/", "/private/", "/swift/", "/v1/", "/oss/",
    "/cos/", "/obs/", "/nas/", "/share/", "/dl/", "/repo/", "/releases/",
    "/snapshots/", "/dumps/", "/export/",
]

# container/orchestrator paths (stage J pool)
CONTAINER_PATHS = [
    "/healthz", "/metrics", "/debug/pprof", "/env", "/v2", "/v2/_catalog",
    "/server-status", "/nginx_status", "/.well-known/", "/kubernetes",
    "/k8s", "/docker", "/registry", "/dashboard", "/pods", "/kubelet",
]

# serverless/api-gw paths (stage K pool)
SERVERLESS_PATHS = [
    "/lambda", "/lambda/", "/functions", "/functions/", "/invoke",
    "/handler", "/fn/", "/serverless", "/api/health", "/edge",
    "/worker", "/workers",
]

# CI/CD + IaC artifact paths (stage R pool - presence-only, bodies REDACTED)
ARTIFACT_PATHS = [
    "/.github/workflows/", "/.gitlab-ci.yml", "/Dockerfile",
    "/docker-compose.yml", "/k8s.yaml", "/deployment.yaml", "/service.yaml",
    "/terraform.tfstate", "/terraform.tfvars", "/main.tf", "/.aws/config",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/kubeconfig", "/helm/values.yaml", "/chart/values.yaml", "/Jenkinsfile",
    "/.circleci/config.yml", "/azure-pipelines.yml", "/cloudbuild.yaml",
    "/.travis.yml", "/bitbucket-pipelines.yml", "/appspec.yml",
]

# cloud api-spec paths (stage T pool)
SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
    "/v2/swagger.json", "/v3/api-docs", "/api-docs", "/api-docs/swagger.json",
    "/api/swagger.json", "/swagger", "/swagger-ui", "/docs", "/redoc",
]

# ---------------------------------------------------------------------------
# MARKER SHAPES (providers / storage / takeover / errors / consoles)
# ---------------------------------------------------------------------------
PROVIDER_MARKERS = [
    ("aws-core",      re.compile(r"(?i)(x-amz-|x-amzn-|awselb|amazonaws)")),
    ("aws-cloudfront", re.compile(r"(?i)(cloudfront|x-amz-cf-id|x-amz-cf-pop)")),
    ("aws-lambda",    re.compile(r"(?i)(lambda-runtime|lambda|execute-api)")),
    ("azure-core",    re.compile(r"(?i)(x-azure-|x-ms-|arrcookie|windows-azure)")),
    ("azure-fn",      re.compile(r"(?i)(azurewebsites|azure-functions|"
                                  r"func-\w+|outbound ip)")),
    ("gcp-core",      re.compile(r"(?i)(x-goog-|x-gcp-|google frontend|"
                                  r"via: 1\.1 google)")),
    ("gcp-appengine", re.compile(r"(?i)(appengine|x-appengine|googleapis)")),
    ("cloudflare",    re.compile(r"(?i)(cf-ray|cf-cache-status|cloudflare|"
                                  r"__cfduid|cf-request-id)")),
    ("fastly",        re.compile(r"(?i)(x-served-by|fastly|x-cache-hits|"
                                  r"x-timer|varnish)")),
    ("akamai",        re.compile(r"(?i)(akamai|x-akamai|server: akamai|"
                                  r"akamaized)")),
    ("vercel",        re.compile(r"(?i)(x-vercel-id|x-vercel-cache|vercel)")),
    ("netlify",       re.compile(r"(?i)(x-nf-request-id|netlify)")),
    ("heroku",        re.compile(r"(?i)(heroku|x-request-id: [0-9a-f]{8,}-"
                                  r"[0-9a-f]{4,})")),
    ("oci",           re.compile(r"(?i)(oracle-cloud|oci-|x-oracle)")),
    ("do-spaces",     re.compile(r"(?i)(do-spaces|digitalocean|"
                                  r"nyc\d\.spaces|sgp\d\.spaces)")),
    ("alibaba",       re.compile(r"(?i)(alibaba|aliyun|x-oss-|ecs-)")),
    ("kubernetes",    re.compile(r"(?i)(kubernetes|x-k8s|minikube|kube-)")),
    ("docker",        re.compile(r"(?i)(docker|docker-registry|containerd|"
                                  r"registry: 2)")),
]
CDN_HDR_RX = [
    ("cf-cache-status", re.compile(r"(?i)cf-cache-status:\s*\S+")),
    ("x-cache",         re.compile(r"(?i)x-cache:\s*\S+")),
    ("age",             re.compile(r"(?i)\bage:\s*\d+")),
    ("via-cdn",         re.compile(r"(?i)\bvia:\s*\S+")),
    ("x-served-by",     re.compile(r"(?i)x-served-by:\s*\S+")),
    ("x-vercel-cache",  re.compile(r"(?i)x-vercel-cache:\s*\S+")),
]
STORAGE_SHAPE_RX = [
    ("listbucket-xml", re.compile(r"(?i)<ListBucketResult")),
    ("contents-key",   re.compile(r"(?i)<Key>[^<]{1,80}</Key>")),
    ("nosuchkey-xml",  re.compile(r"(?i)<Code>NoSuchKey</Code>")),
    ("nosuchbucket-xml", re.compile(r"(?i)<Code>NoSuchBucket</Code>")),
    ("accessdenied-xml", re.compile(r"(?i)<Code>AccessDenied</Code>")),
    ("bucketregion-hdr", re.compile(r"(?i)x-amz-bucket-region")),
    ("s3-url-shape",   re.compile(r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*"
                                   r"\.amazonaws\.com")),
    ("azure-blob-url", re.compile(r"https?://[a-z0-9.-]+\.blob\.core\.windows\.net")),
    ("gcs-url-shape",  re.compile(r"https?://storage\.googleapis\.com/"
                                   r"[a-z0-9._-]+")),
    ("dospaces-url",   re.compile(r"https?://[a-z0-9.-]+\.spaces\.digitaloceanspaces\.com")),
    ("presigned-shape", re.compile(r"(?i)(X-Amz-Signature=|sig=[0-9a-f]{16,})")),
]
# subdomain-takeover fingerprints (DOCUMENTED lead DB - koi claim/provision
# request KABHI nahi; manual RoE confirm wave)
TAKEOVER_FP_ROWS = [
    ("TO-01", "azure-websites", "azurewebsites.net",
     "404 Web Site not found / NXDOMAIN + CNAME azurewebsites",
     "SUSPECTED-lead: manual RoE confirm (resource claim FORBIDDEN-AUTO)"),
    ("TO-02", "aws-s3", "s3.amazonaws.com",
     "NoSuchBucket XML shape + CNAME s3 bucket",
     "SUSPECTED-lead: manual bucket-shape review (listing FORBIDDEN-AUTO)"),
    ("TO-03", "github-pages", "github.io",
     "There isn't a GitHub Pages site here + CNAME",
     "SUSPECTED-lead: manual repo-claim review"),
    ("TO-04", "heroku", "herokuapp.com",
     "No such app + CNAME herokuapp",
     "SUSPECTED-lead: manual app-claim review"),
    ("TO-05", "fastly", "fastly.net",
     "Fastly error: unknown domain + CNAME fastly",
     "SUSPECTED-lead: manual domain-map review"),
    ("TO-06", "netlify", "netlify.app",
     "Not Found - Request ID + CNAME netlify",
     "SUSPECTED-lead: manual site-claim review"),
    ("TO-07", "vercel", "vercel.app",
     "DEPLOYMENT_NOT_FOUND + CNAME vercel",
     "SUSPECTED-lead: manual deployment review"),
    ("TO-08", "shopify", "myshopify.com",
     "Sorry, this shop is currently unavailable + CNAME",
     "SUSPECTED-lead: manual shop review"),
    ("TO-09", "zendesk", "zendesk.com",
     "Help Center Closed + CNAME zendesk",
     "SUSPECTED-lead: manual tenant review"),
    ("TO-10", "bitbucket", "bitbucket.io",
     "Repository not found + CNAME bitbucket",
     "SUSPECTED-lead: manual repo review"),
    ("TO-11", "surge", "surge.sh",
     "project not found + CNAME surge",
     "SUSPECTED-lead: manual project review"),
    ("TO-12", "pantheon", "pantheonsite.io",
     "The gods are wise... + CNAME pantheon",
     "SUSPECTED-lead: manual site review"),
]
CLOUD_ERROR_RX = [
    ("aws-requestid", re.compile(r"(?i)(x-amz-request-id|requestid:|"
                                  r"Request ID:?\s*[0-9A-Za-z]{8,})")),
    ("aws-errorcode", re.compile(r"(?i)<Error><Code>[A-Za-z]+</Code>")),
    ("azure-error",   re.compile(r"(?i)(ErrorDetails|Code:\s*\d{3,}|"
                                  r"Microsoft\.Cloud|ApiVersionUnsupported)")),
    ("gcp-error-json", re.compile(r"(?i)(\"error\"\s*:\s*\{|"
                                   r"googleapi|quotaExceeded)")),
    ("lambda-timeout", re.compile(r"(?i)(Task timed out after \d+|"
                                   r"Lambda timeout|Function.Error)")),
    ("k8s-forbidden", re.compile(r"(?i)(forbidden: User cannot|"
                                  r"k8s.*denied|apiserver)")),
    ("registry-error", re.compile(r"(?i)(NAME_UNKNOWN|"
                                   r"docker-registry.*error)")),
    ("nginx-upstream", re.compile(r"(?i)(upstream (sent|timed out)|"
                                   r"50[234] Bad Gateway)")),
    ("cdn-error",     re.compile(r"(?i)(cloudfront.*error|fastly error|"
                                  r"edge error)")),
    ("generic-500",   re.compile(r"(?i)(internal server error|"
                                  r"an error occurred)")),
]
CONSOLE_MARKERS = [
    ("aws-console",  re.compile(r"(?i)(signin\.aws|aws console|"
                                 r"console\.aws\.amazonaws)")),
    ("azure-login",  re.compile(r"(?i)(login\.microsoftonline|"
                                 r"azure ad sign in|portal\.azure)")),
    ("gcp-login",    re.compile(r"(?i)(accounts\.google\.com/ServiceLogin|"
                                 r"console\.cloud\.google)")),
    ("k8s-dashboard", re.compile(r"(?i)(kubernetes dashboard|k8s dashboard)")),
    ("rancher",      re.compile(r"(?i)(rancher|rancher dashboard)")),
    ("portainer",    re.compile(r"(?i)(portainer|portainer-ce)")),
    ("jenkins",      re.compile(r"(?i)(jenkins|dashboard \[jenkins\])")),
    ("gitlab",       re.compile(r"(?i)(gitlab|sign in.*gitlab)")),
    ("argocd",       re.compile(r"(?i)(argo cd|argocd)")),
    ("grafana",      re.compile(r"(?i)(grafana|login to grafana)")),
    ("prometheus-ui", re.compile(r"(?i)(prometheus time series|prometheus ui)")),
    ("consul",       re.compile(r"(?i)(consul.*hashicorp|consul ui)")),
    ("nomad",        re.compile(r"(?i)(nomad.*hashicorp|nomad ui)")),
    ("vault",        re.compile(r"(?i)(vault.*hashicorp|vault ui)")),
]
IAM_SHAPE_RX = [
    ("aws-arn", re.compile(r"\barn:aws:[a-z0-9-]*:[a-z0-9-]*:\d{12}:[^\s\"']+")),
    ("aws-account-shape", re.compile(r"(?i)(aws_account_id|account[_-]?id)"
                                      r"\s*[:=]\s*['\"]?\d{12}")),
    ("azure-tenant-guid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                                      r"[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("gcp-project", re.compile(r"(?i)(project[_-]?id|gcp[_-]?project)"
                                r"\s*[:=]\s*['\"]?[a-z0-9-]{6,30}")),
    ("role-name", re.compile(r"(?i)(arn:aws:iam::\d{12}:role/|"
                              r"roles/([a-zA-Z0-9_+-]{3,40}))")),
    ("service-account", re.compile(r"(?i)(service[-_]?account|"
                                     r"\biam\.googleapis\.com)")),
    ("instance-profile", re.compile(r"(?i)(instance[-_]?profile|"
                                      r"ec2[-_]?role)")),
]
SIGNEDURL_PARAMS = [
    ("amz-date", re.compile(r"X-Amz-Date=([0-9TZ]+)")),
    ("amz-expires", re.compile(r"X-Amz-Expires=(\d+)")),
    ("amz-signature", re.compile(r"X-Amz-Signature=([0-9a-f]{16,64})")),
    ("amz-credential", re.compile(r"X-Amz-Credential=([^&\s\"']{8,120})")),
    ("sas-sig", re.compile(r"[?&]sig=([0-9A-Za-z_%-]{16,120})")),
    ("sas-expiry", re.compile(r"[?&]se=([0-9TZ:%-]{8,40})")),
    ("sas-start", re.compile(r"[?&]st=([0-9TZ:%-]{8,40})")),
    ("expires-param", re.compile(r"[?&]Expires=(\d{8,12})")),
    ("token-param", re.compile(r"[?&](token|access_token|key)=([0-9A-Za-z_.-]{8,120})")),
]

# ---------------------------------------------------------------------------
# CLOUD SECRET SHAPES (34) - values KABHI store nahi (sha1-12 only)
# ---------------------------------------------------------------------------
CLOUD_SECRET_RX = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-session-token", re.compile(r"(?i)(aws_session_token|"
                                      r"AwsSessionToken)\s*[:=]\s*['\"]?"
                                      r"[0-9A-Za-z/+=]{16,}")),
    ("aws-secret-shape", re.compile(r"(?i)aws.{0,20}(secret|access).{0,10}[:=]")),
    ("gcp-sa-private-key", re.compile(r"(?i)(\"private_key\"\s*:|"
                                        r"-----BEGIN PRIVATE KEY-----)")),
    ("gcp-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("gcp-sa-json", re.compile(r"(?i)(\"type\"\s*:\s*\"service_account\"|"
                                 r"googleapis\.com/auth/cloud-platform)")),
    ("azure-conn-key", re.compile(r"(?i)AccountKey=[0-9A-Za-z/+=]{20,}")),
    ("azure-sas", re.compile(r"(?i)(sig=[0-9A-Za-z_%-]{16,}.*se=|"
                              r"SharedAccessSignature)")),
    ("azure-client-secret", re.compile(r"(?i)(azure.*client[_-]?secret|"
                                         r"AZURE_CLIENT_SECRET)\s*[:=]")),
    ("azure-tenant-guid", re.compile(r"(?i)(tenant[_-]?id)\s*[:=]\s*['\"]?"
                                      r"[0-9a-f-]{36}")),
    ("firebase-config", re.compile(r"(?i)(firebase(apikey|appids?|databaseurl))")),
    ("firebase-dburl", re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
                       r"[A-Za-z0-9_-]{5,}\b")),
    ("kube-jwt", re.compile(r"\beyJhbGciOi[A-Za-z0-9_-]{10,}\."
                            r"[A-Za-z0-9_-]{10,}\.")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("ssh-rsa", re.compile(r"ssh-rsa [0-9A-Za-z/+=]{40,}")),
    ("stripe-key", re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{10,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[0-9A-Za-z_-]{16,}\b")),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{30,}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b")),
    ("mailgun-key", re.compile(r"\bkey-[0-9A-Za-z]{32}\b")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("s3-bucket-url", re.compile(r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*"
                                  r"\.amazonaws\.com")),
    ("azure-blob-url", re.compile(r"https?://[a-z0-9.-]+\.blob\.core\.windows\.net")),
    ("gcs-url", re.compile(r"https?://storage\.googleapis\.com/[a-z0-9._-]+")),
    ("do-spaces-url", re.compile(r"https?://[a-z0-9.-]+\.spaces\.digitaloceanspaces\.com")),
    ("presigned-url", re.compile(r"(?i)(X-Amz-Signature=|X-Amz-Expires=)")),
    ("ecs-task-token", re.compile(r"(?i)(ECS_TASK|ecs[-_]?task[-_]?token|"
                                    r"AWS_CONTAINER_CREDENTIALS)")),
    ("docker-cfg", re.compile(r"(?i)(\"auths\"\s*:\s*\{|"
                                r"docker[-_]?config\.json)")),
    ("db-url-creds", re.compile(r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|"
                                  r"redis|amqp)://[^\s'\"]{4,}:[^\s'\"]{4,}@")),
    ("conn-string", re.compile(r"(?i)(connectionstring|data source=).{0,40}"
                                 r"(password|pwd)=")),
    ("apikey-param", re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?key|"
                                  r"secret[_-]?key|auth[_-]?token|"
                                  r"client[_-]?secret)\s*[:=]\s*['\"]?"
                                  r"[0-9A-Za-z]")),
]

# ---------------------------------------------------------------------------
# DOCUMENTED-ONLY PLAYBOOKS (FORBIDDEN-AUTO techniques - manual+RoE waves)
# ---------------------------------------------------------------------------
IMDS_PLAYBOOK_ROWS = [
    ("IM-01", "IMDSv1 endpoint (link-local 169.254.x.x/meta-data)",
     "FORBIDDEN-AUTO: direct probe KABHI nahi (P15 owns bounded smoke) - "
     "manual+RoE wave only"),
    ("IM-02", "IMDSv2 token-required posture",
     "review: hop-limit 1 + PUT-token enforcement (documented aid)"),
    ("IM-03", "Instance-profile credential shape (x-amz-security-token)",
     "response-header census only - koi token request nahi"),
    ("IM-04", "Cloud metadata via SSRF (P15 handoff)",
     "P15 ff seeds -> manual gopher/link-local wave (RoE)"),
    ("IM-05", "Metadata creds -> role assumption chain",
     "FORBIDDEN-AUTO: assume-role KABHI automate nahi (cred-rotation wave "
     "manual)"),
    ("IM-06", "IMDS block from containers (remediation)",
     "MISCONFIG/CLOUD_REMEDIATION.md fix-guidance: metadata endpoint "
     "network-block + hop-limit"),
    ("IM-07", "IMDS header shapes in responses (census)",
     "P24 stage-G passive: response-side shapes only"),
    ("IM-08", "Egress-callback detection (DNS canary wave)",
     "manual+RoE: canary DNS sirf written authorization par (zero-egress "
     "module rule)"),
]
CLOUD_CREDS_PLAYBOOK_ROWS = [
    ("CC-01", "Metadata-credential harvest (IMDSv1)",
     "FORBIDDEN-AUTO: koi cred fetch/probe network par nahi - manual RoE"),
    ("CC-02", "SSM Parameter Store / Secrets Manager shapes",
     "review: param names-only census (koi GetParameter call nahi)"),
    ("CC-03", "Env-var secrets in debug/error pages (P23 handoff)",
     "census: secret-shape regexes only - values sha1-redacted"),
    ("CC-04", "Kube secrets via RBAC gap",
     "FORBIDDEN-AUTO: koi kubectl/exec/secret-read - manual RoE wave"),
    ("CC-05", "CI/CD pipeline variable exposure",
     "census: variable NAMES from artifacts only (values redacted)"),
    ("CC-06", "Container env dump via /env (P23 container handoff)",
     "presence census: /env live + marker - body KABHI store nahi"),
    ("CC-07", "Cloud cred stuffing / brute",
     "FORBIDDEN-AUTO: brute/stuffing KABHI automate nahi (RoE + manual)"),
    ("CC-08", "Compromised-cred rotation wave",
     "remediation: rotation + IAM least-privilege + audit-log review"),
]
CONTAINER_PLAYBOOK_ROWS = [
    ("KP-01", "Kubelet API (10250) exec/read shapes",
     "FORBIDDEN-AUTO: koi exec/request - manual RoE; census = presence only"),
    ("KP-02", "Docker socket exposure (/var/run/docker.sock)",
     "FORBIDDEN-AUTO: koi socket attach - documented aid"),
    ("KP-03", "Registry push/delete",
     "FORBIDDEN-AUTO: push/delete KABHI - census = catalog-shape presence"),
    ("KP-04", "Pod exec via dashboard",
     "FORBIDDEN-AUTO: exec KABHI - console-exposure finding only"),
    ("KP-05", "RBAC least-privilege review",
     "documented aid: ClusterRole/RBAC audit checklist"),
    ("KP-06", "Network-policy hardening (remediation)",
     "MISCONFIG/CLOUD_REMEDIATION.md: egress/ingress policy + auth-gate"),
]

# ===========================================================================
# SEVERITY HINTS (v30) - key -> (severity, cvss_hint, why_it_matters)
# ===========================================================================
SEVERITY_HINTS = {
    # ---- discovery / surface ----
    "cloud_endpoint_live":       ("info", 0.0, "Cloud-class endpoint live mila "
        "(storage/container/serverless/spec shape) - poora P24 engine ab is "
        "surface par chalega (core targeting aid)."),
    "cloud_candidate_path":      ("info", 0.0, "Cloud candidate path mined - "
        "ranking ke through census me jaayega."),
    # ---- provider fingerprint (stage C) ----
    "cloud_provider_identified": ("medium", 5.3, ">=2 provider shapes ek target "
        "par - infra topology enumeration aid (Server/X-Powered/CDN headers "
        "strip + generic error bodies remediation)."),
    "cloud_provider_hint":       ("low", 3.1, "Single provider shape - "
        "fingerprint disclosure (info-hygiene fix aid)."),
    # ---- storage (stage D/E) ----
    "cloud_storage_shape":       ("high", 7.5, "Bucket-shaped storage surface "
        "live (ListBucketResult/Key shapes) - public listing/reads ka direct "
        "aid; public-block + auth-gate fix."),
    "cloud_bucket_acl_shape":    ("critical", 9.1, "Bucket ACL/error shapes "
        "(NoSuchBucket/AccessDenied/ListBucketResult) se bucket visibility "
        "verify hoti hai - public listing CONFIRMED = data exposure."),
    "cloud_storage_absent":      ("info", 0.0, "Storage pool closed/404 uniform "
        "- positive control."),
    # ---- takeover (stage F) ----
    "cloud_takeover_lead":       ("high", 8.2, "CNAME service-ref + unresolved "
        "alias = takeover lead (SUSPECTED) - manual RoE confirm; dangling "
        "CNAME cleanup fix."),
    "cloud_takeover_clean":      ("info", 0.0, "Koi service-ref/alias lead "
        "nahi - positive control."),
    # ---- IMDS (stage G) ----
    "cloud_imds_documented":     ("info", 0.0, "IMDS playbook documented "
        "(8 rows) - koi metadata probe KABHI network par nahi (P15 handoff)."),
    "cloud_imds_header_shape":   ("low", 3.7, "Instance-metadata header shape "
        "response me (token/profile hints) - response-hygiene fix aid."),
    # ---- secrets (stage H) ----
    "cloud_secret_shape":        ("critical", 9.3, "Cloud secret-shape response "
        "me (key/conn-string/service-account) - rotation + redaction fix; "
        "values sha1-only store hue."),
    "cloud_secret_ip":           ("medium", 5.3, "Internal-IP/email disclosure "
        "shape - recon aid (redaction middleware fix)."),
    # ---- signed URL (stage I) ----
    "cloud_signedurl_unbounded": ("high", 7.4, "Presigned URL unbounded/long "
        "TTL (X-Amz-Expires>=604800 ya long-lived token) - replay window "
        "exposure; minimal-TTL + rotation fix."),
    "cloud_signedurl_bounded":   ("info", 0.0, "Presigned TTL bounded (<24h) - "
        "positive control."),
    # ---- container (stage J) ----
    "cloud_container_live":      ("high", 8.6, "Container/K8s endpoint live "
        "(metrics/registry/pprof shape) - runtime enumeration aid; endpoint "
        "lockdown fix."),
    "cloud_container_absent":    ("info", 0.0, "Container pool closed - "
        "positive control."),
    # ---- serverless (stage K) ----
    "cloud_serverless_live":     ("medium", 6.5, "Serverless/API-GW endpoint "
        "live (lambda/execute-api/functions shape) - business-logic abuse "
        "surface (auth + rate review)."),
    "cloud_serverless_hidden":   ("info", 0.0, "Serverless pool closed - "
        "positive control."),
    # ---- CDN/cache (stage L) ----
    "cloud_cdn_cacheable":       ("medium", 5.8, "CDN cacheable sensitive "
        "response (public/max-age on auth/storage page) - cache-deception "
        "aid; no-store + Vary fix."),
    "cloud_cdn_safe":            ("info", 0.0, "Cache posture safe (no-store/"
        "private on sensitive) - positive control."),
    # ---- CORS (stage M) ----
    "cloud_cors_reflect":        ("high", 8.1, "Storage/cloud endpoint ACAO "
        "canary reflection (REFLECT-ANY/NULL-ALLOWED) - cross-origin data "
        "theft aid; origin-allowlist fix."),
    "cloud_cors_strict":         ("info", 0.0, "CORS strict (canary origins "
        "rejected) - positive control."),
    # ---- IAM (stage N) ----
    "cloud_iam_shape":           ("medium", 5.3, "IAM/ARN/tenant shape disclosed "
        "(sha1-redacted) - privilege-map recon aid; response sanitization fix."),
    "cloud_iam_hidden":          ("info", 0.0, "IAM shapes absent - positive "
        "control."),
    # ---- DNS (stage O) ----
    "cloud_dns_alias_lead":      ("medium", 5.9, "NXDOMAIN/unresolved in-scope "
        "alias - dangling-DNS lead (takeover-adjacent); cleanup fix."),
    "cloud_dns_clean":           ("info", 0.0, "In-scope aliases resolved clean "
        "- positive control."),
    # ---- errors (stage P) ----
    "cloud_verbose_error":       ("high", 7.5, "Provider verbose error shape "
        "(RequestID/<Error><Code>/ErrorDetails) - fingerprint + account aid; "
        "error masking fix."),
    "cloud_error_masked":        ("info", 0.0, "Errors generic/masked - "
        "positive control."),
    # ---- console (stage Q) ----
    "cloud_console_live":        ("high", 8.8, "Cloud console/login surface "
        "live (k8s dashboard/rancher/portainer/vault shape) - console attack "
        "surface (auth-gate + network-isolate fix)."),
    "cloud_console_absent":      ("info", 0.0, "Console pool closed/auth-gated "
        "- positive control."),
    # ---- CI/CD artifacts (stage R) ----
    "cloud_cicd_live":           ("critical", 9.0, "CI/CD + IaC artifact live "
        "(workflows/Dockerfile/tfstate/.ssh) - pipeline + infra disclosure; "
        "artifact removal + rotation fix."),
    "cloud_cicd_absent":         ("info", 0.0, "CI/CD artifact pool closed - "
        "positive control."),
    # ---- token/header echo (stage S) ----
    "cloud_token_param":         ("medium", 6.3, "Token/API-key shaped param "
        "cloud endpoint par (names-only) - token-leak surface (P9/P22 "
        "handoff); URL-token removal fix."),
    "cloud_trust_echo":          ("high", 7.7, "Trust-header echo on cloud "
        "endpoint (X-Forwarded-Host/X-Original-URL) - proxy misroute aid; "
        "edge-strip fix."),
    "cloud_trust_clean":         ("info", 0.0, "No echo/misroute - positive "
        "control."),
    # ---- spec/gql/ws (stage T) ----
    "cloud_spec_live":           ("medium", 6.5, "Cloud API spec live "
        "(swagger/openapi on api-gw) - surface enumeration aid; spec-gating "
        "fix."),
    "cloud_spec_absent":         ("info", 0.0, "Spec paths closed - positive "
        "control."),
    "cloud_gql_mutation_surface": ("low", 3.2, "GraphQL writable-mutation "
        "surface (names-only, NEVER sent) - P18 handoff aid."),
    "cloud_ws_surface":          ("low", 3.2, "WebSocket endpoint census "
        "(frames NEVER) - P19 handoff aid."),
    # ---- bypass2 (stage U) ----
    "cloud_bypass2_accepted":    ("critical", 9.2, "Cloud-bypass shapes "
        "accepted (403->2xx differential) - protected-object access aid; "
        "normalize-before-authz fix."),
    "cloud_bypass2_blocked":     ("info", 0.0, "Bypass shapes rejected/blocked "
        "- positive control."),
    # ---- posture/chains/report ----
    "cloud_posture_weak":        ("medium", 5.0, "Cloud posture composite WEAK "
        "- priority hardening (points missing detail)."),
    "cloud_posture_strong":      ("info", 0.0, "Cloud posture STRONG - "
        "positive controls dominant."),
    "cloud_platform_fp":         ("info", 0.0, "Cloud/platform fingerprint "
        "shapes (census aid)."),
    "cloud_secret_guard_hit":    ("low", 3.0, "Secret/PII shape sweep artifact "
        "par - guard ne redact kiya (CWE-200 aid)."),
    "cloud_creds_documented":    ("info", 0.0, "Cloud-cred playbook documented "
        "(8 rows) - koi cred network par nahi (FORBIDDEN-AUTO)."),
    "cloud_container_playbook":  ("info", 0.0, "Container playbook documented "
        "(6 rows) - exec/push FORBIDDEN-AUTO (presence census only)."),
}


def classify_severity(key):
    """SEVERITY_HINTS lookup (default info/0.0)."""
    sev, cvss, why = SEVERITY_HINTS.get(
        key, ("info", 0.0, "Cloud census row - manual review aid."))
    return sev, cvss, why


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Findings:
    """P24 findings collector (P12..P23-compatible shape)."""

    def __init__(self):
        self.items = []

    def add(self, key, title, endpoint, detail, evidence_ref="", extra=None):
        sev, cvss, why = classify_severity(key)
        rec = {"id": "CL-%03d" % (len(self.items) + 1), "key": key,
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
# PII REDACT (framework rule - P20/P22/P23 pattern)
# ---------------------------------------------------------------------------
_PII_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_PII_CREDS = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(aws_secret_access_key|secret_access_key|api_key|apikey|passwd|password|"
    r"secret|token|AccountKey|sig)\s*[:=]\s*[^\s,;\"]{6,})")
_PII_PAN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def pii_redact(s, limit=420):
    s = _PII_JWT.sub("eyJ***REDACTED***", s or "")
    s = _PII_EMAIL.sub(lambda m: m.group(0)[:2] + "***@***", s)
    s = _PII_PHONE.sub("***PHONE***", s)
    s = _PII_PAN.sub("***PAN***", s)
    s = _PII_CREDS.sub(lambda m: (m.group(0)[:6] + "***REDACTED***"), s)
    return truncate(s, limit)


# ---------------------------------------------------------------------------
# CANARY + INERT ENFORCEMENT (P15..P23 pattern - hard rules)
# ---------------------------------------------------------------------------
def _canary(tag="c"):
    """Synthetic marker ids - waspP24 family (real ids KABHI nahi)."""
    return "%s%s%s" % (CANARY_FAMILY, tag, rand_str(6))


# GET-ONLY MODULE ENFORCEMENT: P24 me koi state-changing method KABHI nahi.
# wasp_core LAYER-4 (READ_ONLY_METHODS = GET/HEAD/OPTIONS) double-guard hai.
_ALLOWED_PROBE_METHODS = ("GET", "HEAD", "OPTIONS")


def assert_inert_method(method):
    if (method or "GET").upper() not in _ALLOWED_PROBE_METHODS:
        raise RuntimeError(
            "P24 INERT violation: method '%s' allowed nahi hai "
            "(GET/HEAD/OPTIONS only)" % method)
    return True


def probe(http, method, url, **kw):
    """INERT probe wrapper: method-guard + scope-firewall (core layer) +
    evidence log. Har P24 network call ISI se jaati hai. Body KABHI nahi."""
    assert_inert_method(method)
    kw.pop("data", None)          # GET-ONLY: body KABHI nahi
    kw.pop("body", None)
    r = http.request(method, url, **kw)
    return r

# ---------------------------------------------------------------------------
# TOLERANT READERS (feedforward/artifact mining - P20/P22/P23 pattern)
# ---------------------------------------------------------------------------
def _artifact(base_dir, mod, fname):
    if not base_dir:
        return ""
    return os.path.join(base_dir, mod, fname)


def _read_json_tolerant(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        return json.loads(txt)
    except Exception:
        # jsonl fallback (first object per line)
        out = []
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            out.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            return None
        return out or None


def _read_text_tolerant(path):
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _walk_lists(obj, depth=0):
    """Nested dict/list me saari string-lists nikaalo (ff routing mining)."""
    if depth > 6:
        return []
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_lists(v, depth + 1))
    elif isinstance(obj, list):
        strs = [x for x in obj if isinstance(x, str)]
        if strs:
            out.append(strs)
        for x in obj:
            if isinstance(x, (dict, list)):
                out.extend(_walk_lists(x, depth + 1))
    return out


# ---------------------------------------------------------------------------
# MARKER DETECTORS (shape classification - values REDACTED)
# ---------------------------------------------------------------------------
def match_markers(rx_table, text):
    """Text me pehla marker-shape (name) ya None - census classification."""
    for name, rx in rx_table:
        if rx.search(text or ""):
            return name
    return None


def match_all_markers(rx_table, text):
    """Text me saare marker-shapes (names list) - census classification."""
    out = []
    for name, rx in rx_table:
        if rx.search(text or ""):
            out.append(name)
    return out


def secret_shape_scan(text):
    """Response body -> cloud secret-shape census rows (values KABHI store
    nahi). Har hit: (shape-name, sha1-12 of matched value, len bucket). Value
    itself REDACTED - framework rule (CWE-798/CWE-200 aid, evidence-safe)."""
    rows = []
    for name, rx in CLOUD_SECRET_RX:
        m = rx.search(text or "")
        if m:
            val = m.group(0)
            rows.append({"shape": name,
                         "sha1_12": hashlib.sha1(
                             val.encode("utf-8", "ignore")).hexdigest()[:12],
                         "len_bucket": "<=16" if len(val) <= 16 else
                                       "17-32" if len(val) <= 32 else
                                       "33-64" if len(val) <= 64 else ">64"})
    return rows


def signed_url_parse(text):
    """Body/URL text -> presigned-param census rows (values sha1-only).

    Expiry-window math offline: X-Amz-Expires seconds; Expires= epoch;
    SAS se= ISO timestamp. TTL >= 7 din = unbounded finding aid."""
    rows = []
    text = (text or "")[:20000]
    for name, rx in SIGNEDURL_PARAMS:
        m = rx.search(text)
        if not m:
            continue
        val = m.group(1) if m.groups() else m.group(0)
        rec = {"param": name, "sha1_12": hashlib.sha1(
            val.encode("utf-8", "ignore")).hexdigest()[:12]}
        try:
            if name == "amz-expires":
                secs = int(val)
                rec["ttl_seconds"] = secs
                rec["ttl_bucket"] = ("<1h" if secs < 3600 else
                                     "1-24h" if secs < 86400 else
                                     "1-7d" if secs < 604800 else
                                     "unbounded")
            elif name == "expires-param":
                import datetime as _dt
                exp = _dt.datetime.fromtimestamp(int(val),
                                                 _dt.timezone.utc)
                ttl = exp - _dt.datetime.now(_dt.timezone.utc)
                rec["ttl_seconds"] = max(0, int(ttl.total_seconds()))
                rec["ttl_bucket"] = ("<1h" if ttl.total_seconds() < 3600
                                     else "1-24h" if ttl.total_seconds()
                                     < 86400 else
                                     "1-7d" if ttl.total_seconds() < 604800
                                     else "unbounded")
            elif name == "sas-expiry":
                import datetime as _dt
                exp = _dt.datetime.fromisoformat(
                    val.replace("Z", "+00:00").replace("%3A", ":"))
                ttl = exp - _dt.datetime.now(_dt.timezone.utc)
                rec["ttl_seconds"] = max(0, int(ttl.total_seconds()))
                rec["ttl_bucket"] = ("<1h" if ttl.total_seconds() < 3600
                                     else "1-24h" if ttl.total_seconds()
                                     < 86400 else
                                     "1-7d" if ttl.total_seconds() < 604800
                                     else "unbounded")
        except Exception:
            rec["ttl_bucket"] = "unknown"
        rows.append(rec)
    return rows


def _prioritize(targets, rx):
    """URLs jisme rx hit -> front (P22/P23 pattern)."""
    hits = [t for t in (targets or []) if isinstance(t, str) and rx.search(t)]
    rest = [t for t in (targets or []) if t not in hits]
    return hits + rest


def _two_stage(targets, rx_primary, rx_secondary=None):
    """Primary-shaped URLs front (preserve order), phir secondary-shaped,
    phir rest - cold-pool crowd-out se explicit-shape targets bachaata hai
    (signed/takeover/cors/error/trust pages hamesha census me aate hain)."""
    tg = [t for t in (targets or []) if isinstance(t, str)]
    prim = [t for t in tg if rx_primary.search(t)]
    rest = [t for t in tg if t not in prim]
    if rx_secondary is not None:
        sec = [t for t in rest if rx_secondary.search(t)]
        rest = [t for t in rest if t not in sec]
        return prim + sec + rest
    return prim + rest


def _base_of(targets):
    """Origin-root base URL (shortest target) - path-pool censuses yahi use
    karte hain (targets[0] deep-path ho sakta hai - root deterministic).
    http(s)-prefixed candidates prefer hote hain (ff-mining me aa sakne
    wale non-URL shape-strings root nahi ban sakte - mining hygiene)."""
    cands = [t.split("?")[0].rstrip("/") for t in (targets or [])
             if isinstance(t, str) and t]
    http_cands = [c for c in cands if c.startswith(("http://", "https://"))]
    pool = http_cands or cands
    return min(pool, key=len) if pool else ""


def _url_like(u):
    """Mining hygiene: sirf URL-shaped strings URL pool me jaate hain
    (shape-names jaise 'aws'/'s3-shape' URLs NAHI hote)."""
    return (isinstance(u, str) and u and
            (u.startswith(("http://", "https://")) or u.startswith("/")))


def same_status_class(a, b):
    return (a or 0) // 100 == (b or 0) // 100


# ===========================================================================
# STAGE A - CLOUD SURFACE DISCOVERY (15-module ff + miners + cold)
# ===========================================================================
def _ff_pairs(base_dir, mod, routing_key):
    """feedforward.json routing[key] -> flat URL list (tolerant)."""
    p = _artifact(base_dir, mod, "feedforward.json")
    d = _read_json_tolerant(p)
    if not isinstance(d, dict):
        return []
    routing = d.get("routing") or {}
    val = routing.get(routing_key) or {}
    urls = []
    if isinstance(val, dict):
        for v in val.values():
            for lst in _walk_lists(v):
                urls.extend(lst)
    elif isinstance(val, list):
        for lst in _walk_lists(val):
            urls.extend(lst)
    return [u for u in urls if isinstance(u, str)]


def _ff_any_pairs(base_dir, mods):
    """Kisi bhi mod ki routing me to_phase24* keys -> URL pool."""
    urls = []
    for mod in mods:
        d = _read_json_tolerant(_artifact(base_dir, mod, "feedforward.json"))
        if not isinstance(d, dict):
            continue
        routing = d.get("routing") or {}
        for rk, val in routing.items():
            if not str(rk).lower().startswith("to_phase24"):
                continue
            for lst in _walk_lists(val):
                urls.extend([u for u in lst if isinstance(u, str)])
    return urls


def _mine_urls_from_artifacts(base_dir, mods, fnames, cap=200):
    """Artifact files (json/txt) se URL/endpoint mining (tolerant)."""
    urls = []
    for mod in mods:
        for fn in fnames:
            p = _artifact(base_dir, mod, fn)
            d = _read_json_tolerant(p)
            if isinstance(d, (dict, list)):
                for lst in _walk_lists(d):
                    urls.extend([u for u in lst if isinstance(u, str)])
            else:
                txt = _read_text_tolerant(p)
                for line in txt.splitlines():
                    line = line.strip()
                    if line.startswith(("/", "http")) and len(line) < 300:
                        urls.append(line)
            if len(urls) >= cap:
                return urls[:cap]
    return urls[:cap]


CLOUD_PATH_RX = re.compile(
    r"(?i)(s3|storage|bucket|blob|minio|uploads?|backup|media|objects|"
    r"blobs|swift|oss|cos|obs|metrics|healthz|pprof|env|registry|kubernetes|"
    r"k8s|docker|lambda|functions?|invoke|worker|serverless|edge|swagger|"
    r"openapi|api-docs|graphql|workflows|jenkins|gitlab|terraform|tfstate|"
    r"dockefile|docker-compose|kube|console|dashboard|vault|rancher|"
    r"portainer|argocd|cdn|assets|download|export|releases|repo|"
    r"secret|signed|presign|takeover|token|error|trust)")


def discover_cloud_surface(ctx, scope, conf):
    """Stage A: 15-module feedforward + artifact mining + cold pool ->
    ranked cloud targets (shape scoring)."""
    base_dir = ctx.get("base_dir")
    sources, urls = [], set()

    # 1) feedforward routing (to_phase24* keys - P4..P23 documented seeds)
    ff = _ff_any_pairs(base_dir, ["understand", "passive", "active", "content",
                                  "tech", "js", "auth", "sessions", "access",
                                  "inject", "ssrf", "files", "api", "graphql",
                                  "ws", "logic", "replay", "misconfig"])
    if ff:
        sources.append("ff_routing(to_phase24*)")
        for u in ff:
            if _url_like(u):
                urls.add(u)

    # 2) P23 misconfig seeds (cloud_header_shapes + bucket_surface)
    p23 = _ff_pairs(base_dir, "misconfig", "to_phase24_cloud")
    if p23:
        sources.append("p23_cloud_seeds")
        for u in p23:
            if _url_like(u):
                urls.add(u)

    # 3) direct artifact mining (endpoints/urls pools of other modules)
    mined = _mine_urls_from_artifacts(
        base_dir,
        ["understand", "content", "js", "api", "ssrf", "active", "tech",
         "replay", "misconfig", "auth"],
        ["endpoints.txt", "api_endpoints.txt", "js_urls.txt", "all_urls.txt",
         "cloud_endpoints.txt", "misconfig_endpoints.txt",
         "ssrf_targets.txt", "inject_targets.txt", "access_endpoints.txt",
         "upload_targets.txt", "targets.json", "bucket_surface.json"],
        cap=200)
    if mined:
        sources.append("artifact_mining(%d)" % len(mined))
        for u in mined:
            if _url_like(u):
                urls.add(u)

    # 4) scope targets (root always included)
    for t in (getattr(scope, "targets", None) or []):
        if _url_like(t) and not t.startswith("/"):
            urls.add(t)

    # 5) cold pool (shape-ranked paths on base)
    base = None
    if urls:
        base = _base_of(sorted(urls))
    if not base:
        for t in (getattr(scope, "targets", None) or []):
            if isinstance(t, str) and t:
                base = t.split("?")[0].rstrip("/")
                break
    cold = []
    if base:
        for p in COLD_PATHS[:max(8, int(conf.get("cloud_cold_paths", 44)))]:
            cold.append(base + p)
        sources.append("cold_pool(%d)" % len(cold))
        for u in cold:
            urls.add(u)

    # scoring: cloud-shaped first (real-vs-cold split - root always in)
    ranked = []
    for u in sorted(urls):
        if not isinstance(u, str) or not u:
            continue
        score = 0
        if CLOUD_PATH_RX.search(u):
            score += 4
        if any(k in u.lower() for k in ("s3", "storage", "bucket", "blob",
                                        "lambda", "registry", "kubernetes",
                                        "terraform", "metrics", "console",
                                        "signed", "takeover", "secret")):
            score += 3
        if u.startswith("http"):
            score += 1
        ranked.append({"url": u[:300], "score": score,
                       "kinds": (["cloud-shape"] if
                                 CLOUD_PATH_RX.search(u) else ["generic"])})
    ranked.sort(key=lambda r: (-r["score"], r["url"]))
    cap = max(6, int(conf.get("cloud_paths_cap", 40)))
    # root deterministic front
    root = (base or "")
    if root:
        root_rec = {"url": root, "score": 99, "kinds": ["root"]}
        ranked = [r for r in ranked if r["url"] != root]
        ranked.insert(0, root_rec)
    ranked = ranked[:cap]
    return {"ranked": ranked, "targets": [r["url"] for r in ranked],
            "sources": sources, "base_url": root or ""}


# ===========================================================================
# STAGE B - BASELINE + WAF + SOFT-404
# ===========================================================================
def baseline_and_waf(http, targets, conf):
    """Baseline rows (status/title/sha1-len) + WAF signature + soft-404."""
    rows, waf = [], []
    base = _base_of(targets)
    soft_paths = None
    for t in (targets or [])[:max(3, int(conf.get("cloud_probe_cap", 24)) // 3)]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        rows.append({"url": t, "status": r.status, "title": title_of(
            (r.text or "")[:4000]),
            "len": len(r.text or ""), "ok": bool(r.ok()),
            "soft404": is_soft404(r, None)})
        wf = waf_signature(r.headers, (r.text or "")[:2000], r.status)
        if wf:
            waf.append({"url": t, "waf": wf})
        if interrupted():
            break
    try:
        if base:
            soft404_baseline(http, base, samples=3, paths=soft_paths)
    except Exception:
        pass
    return {"rows": rows, "waf": waf}

# ===========================================================================
# STAGE C - PROVIDER FINGERPRINT CENSUS (passive GETs, 18 markers)
# ===========================================================================
PROVIDER_PATH_RX = re.compile(
    r"(?i)(aws|azure|gcp|cloudfront|cdn|serverless|functions|lambda|edge)")


def provider_census(http, targets, conf):
    """18 provider/CDN/serverless marker shapes (headers + body prefix).
    >=2 shapes on ek target = provider IDENTIFIED (CONFIRMED aid);
    1 shape = hint (SUSPECTED aid)."""
    rows = []
    cap = max(3, int(conf.get("cloud_probe_cap", 24)) // 2)
    for t in _prioritize(targets, PROVIDER_PATH_RX)[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())[:4000]
        shapes = match_all_markers(PROVIDER_MARKERS, hdr_blob)
        body_shapes = match_all_markers(
            PROVIDER_MARKERS, (r.text or "")[:3000])
        all_shapes = sorted(set(shapes) | set(body_shapes))
        rows.append({"url": t, "status": r.status, "provider_shapes":
                     all_shapes, "identified": len(all_shapes) >= 2})
        if interrupted():
            break
    ident = len([r for r in rows if r.get("identified")])
    return {"rows": rows, "identified_count": ident,
            "note": "provider/CDN/serverless fingerprint census (response-"
                    "side only; topology-enum aid)"}


# ===========================================================================
# STAGE D - STORAGE/BUCKET SHAPE CENSUS (GATED cloud_allow_bucket_probe)
# ===========================================================================
def storage_census(http, targets, conf):
    """GATED cloud_allow_bucket_probe.

    36-path storage pool (in-scope base par) + bucket-URL shapes mined
    from page/JS bodies - presence-only: status/shape, bodies REDACTED.
    Third-party bucket enumeration FORBIDDEN-AUTO (scope firewall)."""
    gate = bool(conf.get("cloud_allow_bucket_probe", False))
    result = {"gate": "cloud_allow_bucket_probe=%s" % gate, "rows": [],
              "url_shapes": [], "skipped_note": "" if gate else
              "RoE gate OFF - manual storage wave documented (KD-01)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = STORAGE_PATHS[:max(6, int(conf.get("cloud_storage_paths", 36)))]
    cap = max(6, int(conf.get("cloud_probe_cap", 24)) // 2)
    tested = 0
    for path in pool:
        if tested >= cap or interrupted() or not base:
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        shape = match_markers(STORAGE_SHAPE_RX, (r.text or "")[:6000]) or ""
        hdr_shape = match_all_markers(
            [("bucketregion-hdr", rx) for n, rx in STORAGE_SHAPE_RX
             if n == "bucketregion-hdr"],
            " ".join("%s: %s" % (k, v) for k, v in
                     (r.headers or {}).items()))
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "shape": shape,
                               "hdr_shapes": hdr_shape,
                               "noise": is_soft404(r, None),
                               "waf_blocked": r.status in
                               (403, 406, 429)})
    # bucket-URL shapes mined from census bodies (offline)
    for t in (targets or [])[:4]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception:
            continue
        for n, rx in STORAGE_SHAPE_RX:
            if n.endswith("-url") or n == "presigned-shape":
                for m in (rx.findall((r.text or "")[:20000]) or [])[:5]:
                    if isinstance(m, tuple):
                        continue
                    result["url_shapes"].append({"shape": n,
                                                 "url": str(m)[:160]})
    result["url_shapes"] = result["url_shapes"][:20]
    return result


# ===========================================================================
# STAGE E - BUCKET ACL/ERROR-SHAPE CENSUS (GATED cloud_allow_bucket_probe)
# ===========================================================================
def bucket_acl_census(http, targets, conf):
    """GATED cloud_allow_bucket_probe.

    IN-SCOPE storage endpoints par XML error-shape census (ListBucketResult,
    NoSuchKey, NoSuchBucket, AccessDenied) + X-Amz-Bucket-Region header.
    Ye visibility-verification census hai - listing/force KABHI nahi
    (sirf live shape classification, canary-only)."""
    gate = bool(conf.get("cloud_allow_bucket_probe", False))
    result = {"gate": "cloud_allow_bucket_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual bucket-ACL wave documented (KD-02)"}
    if not gate:
        return result
    base = _base_of(targets)
    if not base:
        return result
    cap = max(3, int(conf.get("cloud_probe_cap", 24)) // 4)
    tested = 0
    # storage-shaped live paths first (stage-D rows), phir canary paths
    cand = []
    for path in STORAGE_PATHS[:12]:
        cand.append(base + path)
    for url in cand:
        if tested >= cap or interrupted():
            break
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        body = (r.text or "")[:6000]
        shapes = match_all_markers(STORAGE_SHAPE_RX, body)
        acl = [s for s in shapes if s in ("listbucket-xml", "contents-key",
                                          "nosuchkey-xml",
                                          "nosuchbucket-xml",
                                          "accessdenied-xml")]
        region = (r.hget("X-Amz-Bucket-Region", "") or "")[:40]
        result["rows"].append({"url": url, "status": r.status,
                               "acl_shapes": acl, "region_hdr": region,
                               "public_listing": "listbucket-xml" in acl,
                               "visibility_probe":
                                   ("open" if ("listbucket-xml" in acl or
                                               "contents-key" in acl)
                                    else "denied" if "accessdenied-xml"
                                    in acl else
                                    "missing" if ("nosuchkey-xml" in acl or
                                                  "nosuchbucket-xml" in acl)
                                    else "none"),
                               "noise": is_soft404(r, None)})
    return result


# ===========================================================================
# STAGE F - SUBDOMAIN-TAKEOVER FINGERPRINT CENSUS
#           (GATED cloud_allow_takeover_probe)
# ===========================================================================
def takeover_census(http, targets, conf):
    """GATED cloud_allow_takeover_probe.

    Bodies/JS se CNAME service-refs mine (12-row fingerprint DB) + in-scope
    host DNS alias check (sirf in-scope hostnames) -> unresolved+service-ref
    = SUSPECTED lead. Koi resource claim/provision KABHI nahi (manual RoE
    confirm wave; takeover-verification FORBIDDEN-AUTO)."""
    gate = bool(conf.get("cloud_allow_takeover_probe", False))
    result = {"gate": "cloud_allow_takeover_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual takeover wave documented (KD-03)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("cloud_probe_cap", 24)) // 4)
    tested = 0
    for t in _two_stage(targets, re.compile(
            r"(?i)(takeover|cname|alias)"), CLOUD_PATH_RX)[:cap * 2]:
        if tested >= cap or interrupted():
            break
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        tested += 1
        body = (r.text or "")[:20000]
        refs = []
        for tid, svc, cname_dom, marker, disc in TAKEOVER_FP_ROWS:
            if cname_dom.lower() in body.lower():
                refs.append({"service": svc, "cname_domain": cname_dom,
                             "fp_id": tid})
        # in-scope alias DNS check (host_of target only)
        host = host_of(t)
        dns_rec = {"host": host, "resolved": None, "error": None}
        if host:
            try:
                dd = dns_resolve(host, timeout=3.0)
                dns_rec["resolved"] = bool(dd and dd.get("ips"))
                dns_rec["error"] = dd.get("error")
            except Exception as e:
                dns_rec["error"] = str(e)[:80]
        result["rows"].append({"url": t, "status": r.status,
                               "service_refs": refs,
                               "dns": dns_rec,
                               "lead": bool(refs and
                                            dns_rec["resolved"] is False)})
    return result


# ===========================================================================
# STAGE G - IMDS/METADATA PLAYBOOK (DOCUMENTED-ONLY, 0 probes)
# ===========================================================================
def imds_documented(http, targets, conf):
    """IMDS/metadata DOCUMENTED playbook (8 rows, FORBIDDEN-AUTO) +
    response-side header shapes census (x-aws-ec2-metadata-token presence
    in responses - koi token request KABHI nahi)."""
    rows = []
    cap = max(2, int(conf.get("cloud_probe_cap", 24)) // 4)
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())[:3000].lower()
        shapes = []
        if "metadata" in hdr_blob or "instance-profile" in hdr_blob:
            shapes.append("metadata-hint")
        if "security-token" in hdr_blob or "x-amz-security-token" in hdr_blob:
            shapes.append("profile-token-shape")
        rows.append({"url": t, "status": r.status, "imds_probed": False,
                     "header_shapes": shapes})
        if interrupted():
            break
    return {"rows": rows,
            "playbook": [{"id": i, "name": n, "discipline": d}
                         for i, n, d in IMDS_PLAYBOOK_ROWS],
            "note": "IMDS FORBIDDEN-AUTO (koi metadata probe KABHI) - sirf "
                    "documented waves + response-header shapes (P15/P24)"}

# ===========================================================================
# STAGE H - CLOUD SECRETS CENSUS (34 shapes, values REDACTED)
# ===========================================================================
def secrets_census(http, targets, conf):
    """Cloud-secret shapes (34) - names + sha1-12 only, values KABHI store
    nahi (CWE-798/CWE-200)."""
    rows = []
    cap = max(3, int(conf.get("cloud_probe_cap", 24)) // 2)
    rec_cap = int(conf.get("cloud_secret_cap", 40))
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        shapes = secret_shape_scan((r.text or "")[:20000])
        rows.append({"url": t, "status": r.status, "shapes":
                     shapes[:rec_cap], "noise": is_soft404(r, None)})
        if interrupted():
            break
    return {"rows": rows, "shape_table": len(CLOUD_SECRET_RX),
            "note": "secret VALUES KABHI store nahi (sha1-12 + shape-name "
                    "only); rotation wave manual (RoE)"}


# ===========================================================================
# STAGE I - SIGNED-URL LIFECYCLE CENSUS (passive parse)
# ===========================================================================
def signedurl_census(http, targets, conf):
    """Presigned-param census (X-Amz-*/SAS sig|se|st/Expires/token) ->
    entropy buckets + offline TTL math. Unbounded TTL (>=7d) = finding aid.
    Values sha1-only REDACTED."""
    rows = []
    cap = max(3, int(conf.get("cloud_probe_cap", 24)) // 2)
    for t in _two_stage(targets, re.compile(
            r"(?i)(signed|presign|amz-|sig=|sas)"), CLOUD_PATH_RX)[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        body = (r.text or "")[:20000]
        params = signed_url_parse(body + " " + t)
        ent = shannon_entropy(
            "".join(p.get("sha1_12", "") for p in params)[:200]) if params \
            else 0.0
        unbounded = any(p.get("ttl_bucket") == "unbounded" for p in params)
        rows.append({"url": t, "status": r.status, "presigned_params": params,
                     "param_count": len(params), "entropy_hint":
                         round(ent, 2), "unbounded_ttl": unbounded,
                     "noise": is_soft404(r, None)})
        if interrupted():
            break
    unbounded_n = len([r for r in rows if r.get("unbounded_ttl")])
    return {"rows": rows, "unbounded_count": unbounded_n,
            "note": "presigned VALUES sha1-only; TTL math offline "
                    "(expiry-window); rotation/minimal-TTL fix aid"}


# ===========================================================================
# STAGE J - CONTAINER/K8S CENSUS (GATED cloud_allow_container_probe)
# ===========================================================================
CONTAINER_MARKERS = [
    ("prometheus-metrics", re.compile(r"(?i)# (HELP|TYPE) go_|prometheus")),
    ("kubelet-shape", re.compile(r"(?i)(kubelet|pod(s)?|namespace)")),
    ("registry-catalog", re.compile(r"(?i)(\"repositories\"|NAME_UNKNOWN)")),
    ("pprof-shape", re.compile(r"(?i)(types of profiles available|pprof)")),
    ("env-dump", re.compile(r"(?i)(PATH=|KUBERNETES_SERVICE|HOSTNAME=)")),
    ("health-ok", re.compile(r"(?i)(\"status\"\s*:\s*\"(ok|UP)\"|ok)")),
    ("server-status", re.compile(r"(?i)(apache server status|server uptime)")),
]


def container_census(http, targets, conf):
    """GATED cloud_allow_container_probe: 16-path pool (/healthz, /metrics
    prometheus, /debug/pprof, /env, /v2/_catalog registry, /kubernetes...)
    - presence census + marker shapes (koi exec/push KABHI)."""
    gate = bool(conf.get("cloud_allow_container_probe", False))
    result = {"gate": "cloud_allow_container_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual container wave documented (KD-04)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = CONTAINER_PATHS[:max(4, int(conf.get("cloud_container_paths", 16)))]
    cap = max(6, int(conf.get("cloud_probe_cap", 24)) // 2)
    tested = 0
    for path in pool:
        if tested >= cap or interrupted() or not base:
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        shape = match_markers(CONTAINER_MARKERS, (r.text or "")[:4000]) or ""
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "shape": shape, "noise": is_soft404(r, None),
                               "waf_blocked": r.status in (403, 406, 429)})
    return result


# ===========================================================================
# STAGE K - SERVERLESS/API-GW CENSUS (GATED cloud_allow_serverless_probe)
# ===========================================================================
SERVERLESS_MARKERS = [
    ("lambda-shape", re.compile(r"(?i)(lambda-runtime|aws.lambda|"
                                 r"execute-api|lambda error)")),
    ("azure-fn-shape", re.compile(r"(?i)(azure functions|azurewebsites|"
                                   r"func-|FunctionsHost)")),
    ("gcf-shape", re.compile(r"(?i)(cloudfunctions|google cloud functions)")),
    ("run-app", re.compile(r"(?i)(\.run\.app|cloud run)")),
    ("vercel-fn", re.compile(r"(?i)(x-vercel-id|vercel function|\.vercel\.app)")),
    ("netlify-fn", re.compile(r"(?i)(netlify|\.netlify\.app|x-nf-request-id)")),
    ("worker-shape", re.compile(r"(?i)(cloudflare worker|workers\.dev)")),
]


def serverless_census(http, targets, conf):
    """GATED cloud_allow_serverless_probe: 12-path pool + provider shapes
    (lambda/azure-fn/gcf/run/vercel/netlify/workers) - names-only census
    (koi invoke KABHI nahi)."""
    gate = bool(conf.get("cloud_allow_serverless_probe", False))
    result = {"gate": "cloud_allow_serverless_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual serverless wave documented (KD-05)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = SERVERLESS_PATHS[:max(4, int(conf.get("cloud_serverless_paths",
                                                 12)))]
    cap = max(4, int(conf.get("cloud_probe_cap", 24)) // 3)
    tested = 0
    for path in pool:
        if tested >= cap or interrupted() or not base:
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        blob = ((r.text or "")[:3000] + " " + " ".join(
            "%s: %s" % (k, v) for k, v in (r.headers or {}).items()))
        shape = match_markers(SERVERLESS_MARKERS, blob) or ""
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "shape": shape, "noise": is_soft404(r, None),
                               "waf_blocked": r.status in (403, 406, 429)})
    return result


# ===========================================================================
# STAGE L - CDN/CACHE POSTURE (passive-GET)
# ===========================================================================
def cdn_census(http, targets, conf):
    """CDN markers (cf-cache-status/x-cache/x-served-by/age/via) + cache
    posture (public/max-age on sensitive = flag; no-store = safe) +
    P22 cacheable rollup."""
    rows = []
    cap = max(3, int(conf.get("cloud_probe_cap", 24)) // 2)
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        hdr_blob = " ".join("%s: %s" % (k, v) for k, v in
                            (r.headers or {}).items())[:3000]
        cdn = match_all_markers(CDN_HDR_RX, hdr_blob)
        cc = (r.hget("Cache-Control", "") or "")[:120].lower()
        sensitive = bool(re.search(r"(?i)(login|auth|admin|account|session|"
                                   r"token|storage|bucket)", t))
        cacheable = ("public" in cc or "max-age" in cc) and \
            "no-store" not in cc
        rows.append({"url": t, "status": r.status, "cdn_headers": cdn,
                     "cache_control": cc, "sensitive": sensitive,
                     "cacheable": cacheable,
                     "cache_safe": (not sensitive) or (not cacheable)})
        if interrupted():
            break
    unsafe = len([r for r in rows if r.get("sensitive") and
                  r.get("cacheable")])
    return {"rows": rows, "unsafe_count": unsafe,
            "note": "CDN/cache posture census (no-store/Vary fix aid); "
                    "live cache census P22 stage-N owns"}


# ===========================================================================
# STAGE M - STORAGE CORS GRADING (GATED cloud_allow_cors_probe)
# ===========================================================================
CORS_ORIGINS = [
    ("same", None),                                   # target ka apna origin
    ("null", "null"),
    ("subdomain", "https://sub.evil.invalid"),
    ("attacker", "https://evil.invalid"),
]


def storage_cors_census(http, targets, conf):
    """GATED cloud_allow_cors_probe.

    4 canary Origins (same/null/sub.evil.invalid/evil.invalid) GET diff on
    storage/cloud-shaped endpoints -> ACAO reflection census -> grading.
    Koi credentials/cookies attach nahi (INERT census)."""
    gate = bool(conf.get("cloud_allow_cors_probe", False))
    result = {"gate": "cloud_allow_cors_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual storage-CORS wave documented (KD-06)"}
    if not gate:
        return result
    cand = _two_stage(targets, re.compile(r"(?i)(cors|origin)"),
                      re.compile(r"(?i)(s3|storage|bucket|blob|upload|media|"
                                 r"files|api)"))
    cap = max(2, int(conf.get("cloud_probe_cap", 24)) // 4)
    tested = 0
    for t in cand[:cap * 2]:
        if tested >= cap or interrupted():
            break
        parsed = urllib.parse.urlsplit(t)
        own = "%s://%s" % (parsed.scheme, parsed.netloc)
        rows_o = []
        reflect_attacker = reflect_null = wildcard = False
        strict = True
        for olabel, origin in CORS_ORIGINS:
            o = own if origin is None else origin
            try:
                r = probe(http, "GET", t, allow_redirects=False,
                          headers={"Origin": o})
            except Exception as e:
                rows_o.append({"origin": olabel, "error": str(e)[:80]})
                continue
            acao = (r.hget("Access-Control-Allow-Origin", "") or "")[:80]
            acac = (r.hget("Access-Control-Allow-Credentials", "") or "")[:8]
            if acao == "*":
                wildcard = True
            if origin and acao and o in acao:
                if olabel == "attacker":
                    reflect_attacker = True
                if olabel == "null":
                    reflect_null = True
            if acao:
                strict = False
            rows_o.append({"origin": olabel, "acao": acao,
                           "allow_credentials": acac,
                           "status": r.status})
        tested += 1
        result["rows"].append({
            "url": t, "origins": rows_o,
            "reflect_any": reflect_attacker or reflect_null,
            "reflect_attacker": reflect_attacker,
            "reflect_null": reflect_null,
            "wildcard": wildcard, "strict": strict,
            "grade": ("REFLECT-ANY" if reflect_attacker else
                      "NULL-ALLOWED" if reflect_null else
                      "WILDCARD" if wildcard else
                      "STRICT" if strict else "PARTIAL")})
    return result

# ===========================================================================
# STAGE N - IAM/ARN SHAPE CENSUS (passive, sha1-only REDACTED)
# ===========================================================================
def iam_census(http, targets, conf):
    """IAM/ARN/tenant/project shapes (sha1-redacted) - privilege-map recon
    aid. Values KABHI store nahi."""
    rows = []
    cap = max(2, int(conf.get("cloud_probe_cap", 24)) // 4)
    for t in (targets or [])[:cap]:
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            rows.append({"url": t, "error": str(e)[:100]})
            continue
        body = (r.text or "")[:20000]
        shapes = []
        for name, rx in IAM_SHAPE_RX:
            m = rx.search(body)
            if m:
                val = m.group(0)
                shapes.append({"shape": name,
                               "sha1_12": hashlib.sha1(
                                   val.encode("utf-8", "ignore"))
                                   .hexdigest()[:12]})
        rows.append({"url": t, "status": r.status, "iam_shapes": shapes,
                     "noise": is_soft404(r, None)})
        if interrupted():
            break
    return {"rows": rows, "shape_table": len(IAM_SHAPE_RX),
            "note": "IAM VALUES sha1-only (recon aid); sanitization fix"}


# ===========================================================================
# STAGE O - DNS/ALIAS DIFFERENTIAL (GATED cloud_allow_dns_probe)
# ===========================================================================
def dns_census(http, targets, conf):
    """GATED cloud_allow_dns_probe: dns_resolve on IN-SCOPE hostnames only
    (+ ff subdomain candidates on in-scope domains) -> resolved-IP census +
    NXDOMAIN flags. Koi third-party DNS brute nahi (cap-bounded)."""
    gate = bool(conf.get("cloud_allow_dns_probe", False))
    result = {"gate": "cloud_allow_dns_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual DNS-alias wave documented (KD-07)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("cloud_dns_cap", 10)))
    hosts, seen = [], set()
    for t in (targets or []):
        h = host_of(t)
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
        if len(hosts) >= cap or interrupted():
            break
    for h in hosts:
        rec = {"host": h[:120], "ips": [], "error": None, "nxdomain": False}
        try:
            dd = dns_resolve(h, timeout=3.0)
            if dd and dd.get("ips"):
                rec["ips"] = [str(ip)[:40] for ip in dd["ips"]][:4]
            elif dd and dd.get("error"):
                rec["error"] = str(dd["error"])[:100]
                rec["nxdomain"] = True
        except Exception as e:
            rec["error"] = str(e)[:80]
            rec["nxdomain"] = True
        result["rows"].append(rec)
    return result


# ===========================================================================
# STAGE P - CLOUD ERROR-SHAPE CENSUS (GATED cloud_allow_error_probe)
# ===========================================================================
def error_census(http, targets, conf):
    """GATED cloud_allow_error_probe: canary param probes (malformed
    encoding, deep path, long param, marker param) on cloud-shaped
    endpoints -> provider error shapes (RequestID/<Error><Code>/
    ErrorDetails/gcp JSON/lambda timeout/k8s forbidden)."""
    gate = bool(conf.get("cloud_allow_error_probe", False))
    result = {"gate": "cloud_allow_error_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual error-shape wave documented (KD-08)"}
    if not gate:
        return result
    canary = _canary("e")
    variants = [
        ("marker-param", "?marker=%s" % canary),
        ("bad-encoding", "?prefix=%%zz%s" % canary[:6]),
        ("deep-path", "/%s/%s/%s/" % (canary[:6], canary[:6], canary[:6])),
        ("long-param", "?list-type=2&prefix=" + ("A" * 256)),
    ]
    cand = _two_stage(targets, re.compile(r"(?i)(error|exception|500)"),
                      re.compile(r"(?i)(s3|storage|api|serverless|lambda|"
                                 r"invoke)"))[:8]
    cap = max(2, int(conf.get("cloud_probe_cap", 24)) // 4)
    tested = 0
    for t in cand:
        if tested >= cap or interrupted():
            break
        verbose_hits, kinds = 0, set()
        vrows = []
        for vname, suffix in variants:
            url = t + suffix
            try:
                r = probe(http, "GET", url, allow_redirects=False)
            except Exception:
                continue
            body = (r.text or "")[:4000]
            kind = match_markers(CLOUD_ERROR_RX, body)
            if kind and kind != "generic-500" and not is_soft404(r, None):
                verbose_hits += 1
                kinds.add(kind)
            vrows.append({"variant": vname, "status": r.status,
                          "shape": kind or ""})
        tested += 1
        result["rows"].append({"url": t, "verbose_hits": verbose_hits,
                               "shapes": sorted(kinds), "variants": vrows})
    return result


# ===========================================================================
# STAGE Q - CLOUD CONSOLE FINGERPRINT (GATED cloud_allow_console_probe)
# ===========================================================================
def console_census(http, targets, conf):
    """GATED cloud_allow_console_probe: 14 platform markers (aws/azure/gcp
    signin, k8s dashboard, rancher, portainer, jenkins, gitlab, argocd,
    grafana, prometheus-ui, consul, nomad, vault) - presence census +
    auth-gate detection (koi login attempt KABHI nahi)."""
    gate = bool(conf.get("cloud_allow_console_probe", False))
    result = {"gate": "cloud_allow_console_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual console wave documented (KD-09)"}
    if not gate:
        return result
    base = _base_of(targets)
    cand = [base + p for p in ("/console", "/dashboard", "/ui", "/login",
                               "/grafana", "/portainer", "/rancher",
                               "/argocd", "/vault", "/k8s/dashboard")] \
        if base else []
    cand = _prioritize(targets, re.compile(r"(?i)(console|dashboard|login|"
                                           r"grafana|portainer|rancher|"
                                           r"argocd|vault)"))[:6] + cand
    cap = max(3, int(conf.get("cloud_probe_cap", 24)) // 3)
    tested = 0
    seen = set()
    for t in cand:
        if tested >= cap or interrupted() or t in seen:
            continue
        seen.add(t)
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        tested += 1
        body = (r.text or "")[:4000]
        platform = match_markers(CONSOLE_MARKERS, body)
        live = bool(r.ok() and not is_soft404(r, None))
        auth_gate = r.status in (401, 403)
        result["rows"].append({"url": t, "status": r.status, "live": live,
                               "platform": platform or "",
                               "auth_gate": auth_gate,
                               "noise": is_soft404(r, None)})
    return result


# ===========================================================================
# STAGE R - CI/CD + IaC ARTIFACT CENSUS (GATED cloud_allow_artifact_probe)
# ===========================================================================
CICD_MARKERS = [
    ("workflow-yaml", re.compile(r"(?i)(on:\s*push|jobs:|runs-on:|"
                                  r"github\.actions)")),
    ("dockerfile", re.compile(r"(?i)(^FROM [a-z0-9/.-]+:[\w.-]+|"
                               r"dockerfile)")),
    ("compose", re.compile(r"(?i)(services:|docker-compose|version: ['\"]3)")),
    ("kube-yaml", re.compile(r"(?i)(kind:\s*(Deployment|Service|Pod|"
                              r"ConfigMap)|apiVersion:\s*v1)")),
    ("tfstate", re.compile(r"(?i)(\"version\":\s*4|\"terraform_version\"|"
                            r"\"modules\"\s*:)")),
    ("tf-vars", re.compile(r"(?i)([a-z_]+\s*=\s*\"[^\"]+\"\s*#?\s*|"
                            r"variable\s+)")),
    ("aws-config", re.compile(r"(?i)(\[default\]|output\s*=\s*json|"
                               r"region\s*=\s*[a-z]{2}-[a-z]+-\d)")),
    ("ssh-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jenkinsfile", re.compile(r"(?i)(pipeline\s*\{|stages?\s*\{|"
                                r"agent any)")),
    ("ci-generic", re.compile(r"(?i)(circleci|travis|azure-pipelines|"
                               r"cloudbuild|appspec)")),
]


def cicd_census(http, targets, conf):
    """GATED cloud_allow_artifact_probe: 24-path CI/CD + IaC pool
    (.github/workflows, Dockerfile, tfstate, .ssh, kubeconfig...) -
    presence-only: status/shape, bodies KABHI store nahi (REDACTED)."""
    gate = bool(conf.get("cloud_allow_artifact_probe", False))
    result = {"gate": "cloud_allow_artifact_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual CI/CD artifact wave documented (KD-10)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = ARTIFACT_PATHS[:max(6, int(conf.get("cloud_artifact_paths", 24)))]
    cap = max(6, int(conf.get("cloud_probe_cap", 24)) // 2)
    tested = 0
    for path in pool:
        if tested >= cap or interrupted() or not base:
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        shape = match_markers(CICD_MARKERS, (r.text or "")[:6000]) or ""
        live = bool(r.ok() and not is_soft404(r, None))
        result["rows"].append({"url": url, "status": r.status, "live": live,
                               "shape": shape, "noise": is_soft404(r, None),
                               "waf_blocked": r.status in (403, 406, 429)})
    return result

# ===========================================================================
# STAGE S - API-TOKEN SURFACE + HEADER-TRUST ECHO (GATED cloud_allow_header_echo)
# ===========================================================================
TOKEN_PARAM_RX = re.compile(
    r"(?i)([?&](token|access_token|auth_token|api_key|apikey|key|sig|"
    r"X-Amz-Signature|signature)=)")

TRUST_HEADERS = [
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Forwarded-Proto", "https"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]


def token_census(http, targets, conf):
    """GATED cloud_allow_header_echo.

    (a) token-shaped GET params census (names-only, values KABHI nahi),
    (b) 6 trust-header echo + misroute differential on cloud endpoints
    (GET-only). P9/P22 handoff."""
    gate = bool(conf.get("cloud_allow_header_echo", False))
    result = {"gate": "cloud_allow_header_echo=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual token/trust wave documented (KD-11)"}
    if not gate:
        return result
    cap = max(2, int(conf.get("cloud_probe_cap", 24)) // 4)
    tested = 0
    for t in _two_stage(targets, re.compile(
            r"(?i)(trust|header|token|share|key)"),
            re.compile(r"(?i)(api|s3|storage|download|file)"))[:cap * 2]:
        if tested >= cap or interrupted():
            break
        try:
            r = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        tested += 1
        token_params = sorted(set(
            m.group(1).lower() for m in
            TOKEN_PARAM_RX.finditer((r.text or "")[:10000] + " " + t)))[:8]
        echoes = []
        try:
            r0_status = r.status
        except Exception:
            r0_status = None
        for hname, hval in TRUST_HEADERS:
            try:
                rr = probe(http, "GET", t, allow_redirects=False,
                           headers={hname: hval})
            except Exception:
                continue
            body_hit = hval.lower() in (rr.text or "")[:3000].lower()
            status_shift = rr.status != r0_status and rr.status < 400 and \
                (r0_status or 0) >= 400
            hdr_echo = hname.lower() in {str(k).lower() for k in
                                         (rr.headers or {}).keys()}
            if body_hit or status_shift or hdr_echo:
                echoes.append({"header": hname, "value_sent": hval,
                               "status": rr.status, "body_echo": body_hit,
                               "status_shift": status_shift,
                               "header_echo": hdr_echo})
        result["rows"].append({"url": t, "status": r.status,
                               "token_params": token_params,
                               "echoes": echoes,
                               "echo_count": len(echoes)})
    return result


# ===========================================================================
# STAGE T - CLOUD SPEC + GQL/WS SURFACE ROLLUP
#           (spec GATED cloud_allow_spec_probe; gql/ws passive)
# ===========================================================================
def spec_census(http, targets, conf):
    """GATED cloud_allow_spec_probe: 12 spec paths (swagger/openapi/api-docs
    on cloud/api-gw shapes) - presence + op-name census (names-only)."""
    gate = bool(conf.get("cloud_allow_spec_probe", False))
    result = {"gate": "cloud_allow_spec_probe=%s" % gate, "rows": [],
              "skipped_note": "" if gate else
              "RoE gate OFF - manual spec wave documented (KD-12)"}
    if not gate:
        return result
    base = _base_of(targets)
    pool = SPEC_PATHS[:max(4, int(conf.get("cloud_spec_paths", 12)))]
    cap = max(4, int(conf.get("cloud_probe_cap", 24)) // 3)
    tested = 0
    for path in pool:
        if tested >= cap or interrupted() or not base:
            break
        url = base + path
        try:
            r = probe(http, "GET", url, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": url, "error": str(e)[:100]})
            continue
        tested += 1
        body = (r.text or "")[:8000]
        spec_shape = bool(re.search(r"(?i)(\"openapi\"|\"swagger\"|"
                                    r"\"paths\"\s*:)", body))
        op_names = sorted(set(re.findall(
            r"\"(/[a-z0-9_\-/{}.:]{2,60})\"", body)))[:12]
        sensitive_ops = [o for o in op_names if re.search(
            r"(?i)(admin|internal|debug|export|secret|credential|iam|"
            r"role|key)", o)]
        result["rows"].append({"url": url, "status": r.status,
                               "spec_shape": spec_shape,
                               "op_names_count": len(op_names),
                               "sensitive_ops": sensitive_ops[:6],
                               "noise": is_soft404(r, None)})
    return result


def gql_mutations_from_artifacts(base_dir):
    """P18/P22 handoff: mutation names (NEVER sent)."""
    names = []
    for mod in ("graphql", "misconfig", "replay", "ws"):
        d = _read_json_tolerant(_artifact(base_dir, mod, "feedforward.json"))
        if isinstance(d, dict):
            routing = d.get("routing") or {}
            for rk, val in routing.items():
                if not str(rk).lower().startswith("to_phase24"):
                    continue
                for lst in _walk_lists(val):
                    for x in lst:
                        if isinstance(x, str) and re.match(
                                r"^[a-zA-Z][a-zA-Z0-9_]{2,40}$", x) and \
                                not x.startswith(("/", "http")):
                            names.append(x)
    names = sorted(set(names))[:24]
    return {"mutations": names, "count": len(names),
            "note": "mutation NAMES only - koi operation KABHI network par "
                    "nahi (P18 discipline)"}


def ws_surface_from_artifacts(base_dir):
    """P19 handoff: ws endpoint census (frames NEVER)."""
    endpoints = []
    d = _read_json_tolerant(_artifact(base_dir, "ws", "feedforward.json"))
    if isinstance(d, dict):
        for lst in _walk_lists(d.get("routing") or {}):
            endpoints.extend([x for x in lst if isinstance(x, str)
                              and (x.startswith("ws") or "/ws" in x or
                                   "socket" in x.lower())])
    art = _read_json_tolerant(_artifact(base_dir, "ws", "ws_endpoints.json"))
    if isinstance(art, (dict, list)):
        for lst in _walk_lists(art):
            endpoints.extend([x for x in lst if isinstance(x, str)])
    endpoints = sorted(set(e for e in endpoints if len(e) < 200))[:24]
    return {"endpoints": endpoints, "count": len(endpoints),
            "note": "frames NEVER (P19 discipline); ws-cloud manual aid"}


# ===========================================================================
# STAGE U - BYPASS MATRIX v2: 20 SECRET CLOUD-BYPASS SHAPES
#           (GATED cloud_allow_bypass2 - GET-only 403->2xx differential)
# ===========================================================================
def _bypass2_shapes(base_url, canary):
    """20 cloud-bypass GET shapes (canary family waspP24).

    Har shape ek documented cloud/storage-bypass technique ka INERT
    GET-probe equivalent hai: 403-protected path par path-normalization /
    header-trust / storage-differential -> 2xx = validation gap detection."""
    b = base_url.split("?")[0].rstrip("/")
    q = urllib.parse.quote
    return [
        ("CB-01", "double-slash path (normalizer merge differential)",
         "%s//" % b, {}),
        ("CB-02", "dot-segment /./ (canonicalization differential)",
         "%s/./" % b, {}),
        ("CB-03", "parent-segment /../ (traversal-normalizer differential)",
         "%s/%s/../" % (b, canary[:6]), {}),
        ("CB-04", "url-encoded dot %2e%2e (decoder differential)",
         "%s/%%2e%%2e/" % b, {}),
        ("CB-05", "semicolon path-param (matrix-param parser differential)",
         "%s;waspP24=1" % b, {}),
        ("CB-06", "tab-char %09 path (whitespace parser differential)",
         "%s%%09" % b, {}),
        ("CB-07", "space %20 path (trim differential)",
         "%s%%20" % b, {}),
        ("CB-08", "case-shuffle path (case-insensitive authz differential)",
         b.upper(), {}),
        ("CB-09", "trailing-slash add (route-match differential)",
         "%s/" % b, {}),
        ("CB-10", "double-url-encode (double-decoder differential)",
         "%s/%s" % (b, q(q(canary[:6]))), {}),
        ("CB-11", "X-Original-URL trust (proxy misroute shape)",
         b, {"X-Original-URL": "/"}),
        ("CB-12", "X-Rewrite-URL trust (rewrite-bypass shape)",
         b, {"X-Rewrite-URL": "/"}),
        ("CB-13", "X-Forwarded-Host: localhost (vhost-trust shape)",
         b, {"X-Forwarded-Host": "localhost"}),
        ("CB-14", "X-Forwarded-For: 127.0.0.1 (ip-allowlist trust shape)",
         b, {"X-Forwarded-For": "127.0.0.1"}),
        ("CB-15", "Host: localhost (internal-vhost shape)",
         b, {"Host": "localhost"}),
        ("CB-16", "X-Custom-IP-Authorization: 127.0.0.1 (custom-ip trust)",
         b, {"X-Custom-IP-Authorization": "127.0.0.1"}),
        ("CB-17", "Referer-trust shape (referer-based authz differential)",
         b, {"Referer": "%s/storage" % b}),
        ("CB-18", "HEAD-method differential (verb-authz gap shape)",
         b, {}),
        ("CB-19", "marker-param (list-normalizer differential)",
         "%s?marker=%s" % (b, canary[:6]), {}),
        ("CB-20", "Range partial-content (partial-authz gap shape)",
         b, {"Range": "bytes=0-0"}),
    ]


def bypass2_census(http, targets, conf):
    """GATED cloud_allow_bypass2: 20 shapes per top-target (GET/HEAD,
    canary differential). 403 baseline -> 2xx shaped = ACCEPTED (validation
    gap); waf-block = BLOCKED; reject-class = HARDENED."""
    gate = bool(conf.get("cloud_allow_bypass2", False))
    result = {"gate": "cloud_allow_bypass2=%s" % gate, "rows": [],
              "shapes_total": 20,
              "skipped_note": "" if gate else
              "RoE gate OFF - manual bypass2 wave documented (KD-13)"}
    if not gate:
        return result
    # protected (4xx) targets prioritize - differential wahi meaningful hai
    prot = _prioritize(targets, re.compile(
        r"(?i)(protected|s3|storage|private|internal|admin|bucket|secure)"))
    cap = max(1, min(4, int(conf.get("cloud_bypass2_cap", 20)) // 4))
    tested = 0
    for t in prot[:cap * 3]:
        if tested >= cap or interrupted():
            break
        try:
            r0 = probe(http, "GET", t, allow_redirects=False)
        except Exception as e:
            result["rows"].append({"url": t, "error": str(e)[:100]})
            continue
        if r0.status < 400:
            continue          # sirf protected paths (403-family) differential
        canary = _canary("cb")
        shape_rows = []
        for sid, name, url, hdrs in _bypass2_shapes(t, canary):
            method = "HEAD" if sid == "CB-18" else "GET"
            try:
                r = probe(http, method, url, allow_redirects=False,
                          headers=hdrs or None)
            except Exception as e:
                shape_rows.append({"id": sid, "name": name,
                                   "error": str(e)[:100]})
                continue
            accepted = bool(r.ok() and not is_soft404(r, None))
            shape_rows.append({"id": sid, "name": name, "method": method,
                               "status": r.status, "accepted": accepted,
                               "reject_class": r.status in (401, 403, 409,
                                                            410, 422),
                               "waf_blocked": r.status in (403, 406, 429),
                               "range_shape": sid == "CB-20" and
                               r.status == 206})
        tested += 1
        acc = [s for s in shape_rows if s.get("accepted")]
        result["rows"].append({
            "url": t, "baseline_status": r0.status, "shapes": shape_rows,
            "accepted_count": len(acc), "accepted_ids": [s["id"] for s in acc],
            "blocked_count": len([s for s in shape_rows
                                  if s.get("waf_blocked")])})
    return result


# ===========================================================================
# STAGE V - CLOUD POSTURE COMPOSITE (14-point score, offline)
# ===========================================================================
POSTURE_POINTS = [
    ("provider_fp_only",  "provider shapes limited (no leaky stack)"),
    ("storage_locked",    "storage pool closed/denied (no public listing)"),
    ("takeover_clean",    "no takeover cname-ref/unresolved lead"),
    ("secrets_absent",    "cloud secret-shape sweep clean"),
    ("iam_hidden",        "IAM/ARN shapes absent"),
    ("signedurl_bounded", "presigned TTL bounded (<7d)"),
    ("container_locked",  "container pool closed (no metrics/registry)"),
    ("serverless_hidden", "serverless pool closed"),
    ("cdn_safe",          "no cacheable sensitive responses"),
    ("cors_strict",       "canary origins rejected (STRICT grade)"),
    ("dns_clean",         "in-scope aliases resolved (no dangling)"),
    ("errors_masked",     "errors generic/masked (no provider shapes)"),
    ("artifacts_absent",  "CI/CD + IaC artifacts absent"),
    ("bypass2_blocked",   "bypass2 shapes rejected/blocked"),
]


def posture_composite(results):
    """Per-endpoint 14-point cloud posture composite (offline).

    results = stage result dict (provider/storage/bucket/takeover/secrets/
    signedurl/container/serverless/cdn/cors/dns/errors/cicd/bypass2).
    Score 0-14; <5 = WEAK (finding), >=9 = STRONG (positive)."""
    per_ep = {}

    def _bump(url, point, ok_flag):
        d = per_ep.setdefault(url or "?", {p[0]: None for p in POSTURE_POINTS})
        cur = d.get(point)
        d[point] = bool(ok_flag) if cur is None else (cur or bool(ok_flag))

    for row in (results.get("provider") or {}).get("rows", []):
        if row.get("identified"):
            _bump(row.get("url"), "provider_fp_only", False)
        elif row.get("url") and row.get("provider_shapes") is not None:
            _bump(row.get("url"), "provider_fp_only",
                  not row.get("provider_shapes"))
    for row in (results.get("storage") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "storage_locked",
                  not (row.get("live") and row.get("shape")))
    for row in (results.get("bucket") or {}).get("rows", []):
        if row.get("visibility_probe"):
            _bump(row.get("url"), "storage_locked",
                  row.get("visibility_probe") != "open")
    for row in (results.get("takeover") or {}).get("rows", []):
        if row.get("url") and row.get("service_refs") is not None:
            _bump(row.get("url"), "takeover_clean", not row.get("lead"))
    for row in (results.get("secrets") or {}).get("rows", []):
        if row.get("status") and not row.get("noise"):
            _bump(row.get("url"), "secrets_absent", not row.get("shapes"))
    for row in (results.get("signedurl") or {}).get("rows", []):
        if row.get("status") and not row.get("noise"):
            _bump(row.get("url"), "signedurl_bounded",
                  not row.get("unbounded_ttl"))
    for row in (results.get("container") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "container_locked",
                  not (row.get("live") and row.get("shape")))
    for row in (results.get("serverless") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "serverless_hidden",
                  not (row.get("live") and row.get("shape")))
    for row in (results.get("cdn") or {}).get("rows", []):
        _bump(row.get("url"), "cdn_safe", not row.get("cacheable") or
              not row.get("sensitive"))
    for row in (results.get("cors") or {}).get("rows", []):
        _bump(row.get("url"), "cors_strict", row.get("strict"))
        if row.get("reflect_any"):
            _bump(row.get("url"), "cors_strict", False)
    for row in (results.get("dns") or {}).get("rows", []):
        if row.get("host"):
            _bump(row.get("url") or row["host"], "dns_clean",
                  not row.get("nxdomain"))
    for row in (results.get("errors") or {}).get("rows", []):
        _bump(row.get("url"), "errors_masked", not row.get("verbose_hits"))
    for row in (results.get("cicd") or {}).get("rows", []):
        if row.get("status"):
            _bump(row.get("url"), "artifacts_absent", not row.get("live"))
    for row in (results.get("bypass2") or {}).get("rows", []):
        _bump(row.get("url"), "bypass2_blocked",
              not row.get("accepted_count"))

    rows = []
    for url, pts in per_ep.items():
        score = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is True)
        known = sum(1 for p, _ in POSTURE_POINTS if pts.get(p) is not None)
        rows.append({"url": url, "score": score, "known_points": known,
                     "points": pts,
                     "grade": "STRONG" if score >= 9 else
                              "PARTIAL" if score >= 5 else "WEAK"})
    rows.sort(key=lambda r: r["score"])
    return {"points": POSTURE_POINTS, "rows": rows,
            "weak": [r for r in rows if r["grade"] == "WEAK"],
            "strong": [r for r in rows if r["grade"] == "STRONG"]}

# ===========================================================================
# STAGE W - CROSS-MODULE KILL-CHAINS (CH01..CH28)
# ===========================================================================
def build_chains(results, ff_seeds):
    """28 cloud kill-chains (P2..P23 handoffs + P24 census rows)."""
    chains = [
        ("CH01", "Provider fingerprint -> infra topology enumeration",
         "Stage C identified -> header-strip fix"),
        ("CH02", "Public bucket shape -> data listing/reads aid",
         "Stage D/E live shape -> public-block fix"),
        ("CH03", "Bucket ACL shapes -> visibility verification",
         "Stage E visibility_probe -> ACL review"),
        ("CH04", "Dangling CNAME + service-ref -> subdomain takeover lead",
         "Stage F lead -> alias cleanup wave (manual RoE)"),
        ("CH05", "IMDS/metadata wave -> credential exposure (documented)",
         "Stage G playbook -> IMDSv2 + hop-limit fix (P15 handoff)"),
        ("CH06", "Cloud secret in page/JS -> account compromise",
         "Stage H shapes -> secret rotation wave (RoE)"),
        ("CH07", "Unbounded presigned URL -> extended replay window",
         "Stage I unbounded -> minimal-TTL fix"),
        ("CH08", "Container metrics live -> runtime enumeration",
         "Stage J live -> endpoint lockdown fix"),
        ("CH09", "Registry catalog live -> image enumeration",
         "Stage J catalog -> registry auth fix"),
        ("CH10", "Serverless endpoint exposed -> business-logic abuse",
         "Stage K live -> auth + rate review"),
        ("CH11", "CDN cacheable sensitive -> cache deception",
         "Stage L unsafe -> no-store + Vary fix"),
        ("CH12", "Storage CORS reflect-any -> cross-origin theft",
         "Stage M reflect -> origin-allowlist fix"),
        ("CH13", "IAM/ARN shapes -> privilege-map recon",
         "Stage N shapes -> response sanitization"),
        ("CH14", "NXDOMAIN alias -> dangling DNS lead",
         "Stage O nxdomain -> DNS cleanup"),
        ("CH15", "Verbose provider error -> fingerprint + RequestID aid",
         "Stage P verbose -> error masking"),
        ("CH16", "Cloud console exposed -> console attack surface",
         "Stage Q live -> auth-gate + network-isolate"),
        ("CH17", "CI/CD workflow artifact -> pipeline secret exposure",
         "Stage R live -> artifact removal + rotation"),
        ("CH18", "tfstate/IaC artifact -> infra disclosure",
         "Stage R tfstate -> state-store hardening"),
        ("CH19", "Token param in URL -> leak/replay surface",
         "Stage S token_params -> URL-token removal (P9/P22)"),
        ("CH20", "Trust-header echo on cloud endpoint -> misroute access",
         "Stage S echoes -> edge-strip fix"),
        ("CH21", "Cloud API spec live -> surface enumeration",
         "Stage T spec -> spec-gating fix (P17)"),
        ("CH22", "GQL mutation names -> writable surface aid",
         "Stage T gql (names-only) -> P18 handoff"),
        ("CH23", "Bypass2 accepted -> protected-object access",
         "Stage U accepted_ids -> normalize-before-authz fix"),
        ("CH24", "Posture WEAK composite -> priority hardening",
         "Stage V weak rows -> remediation order"),
        ("CH25", "P23 misconfig handoff -> header/cookie posture chain",
         "P23 ff -> Stage C/L cross-check"),
        ("CH26", "P15 SSRF/metadata handoff -> IMDS chain (manual)",
         "P15 ff -> Stage G playbook"),
        ("CH27", "P7 js-secrets + P5 content -> cloud key rotation",
         "P7/P5 ff -> Stage H census"),
        ("CH28", "P25 controls + P32 report -> cloud hardening handoff",
         "Stage V/Z -> P25/P32 ff routing"),
    ]
    out = []
    ff_keys = set((ff_seeds or {}).keys())
    for cid, title, evidence in chains:
        out.append({"id": cid, "title": title, "evidence": evidence,
                    "ff_seeds": sorted(ff_keys)[:6]})
    return out


# ===========================================================================
# STAGE X - VERDICT ENGINE (6-class ladder, multi-signal)
# ===========================================================================
def verdict_engine(results):
    """Stage rows -> 6-class verdict rows (CONFIRMED/SUSPECTED/HARDENED/
    BLOCKED/SKIPPED/NOISE) - P12..P23-compatible ladder."""
    rows = []

    def _add(stage, url, verdict, signals, detail):
        rows.append({"stage": stage, "url": url, "verdict": verdict,
                     "signals": signals, "detail": truncate(str(detail), 220)})

    # ---- PROVIDER (C) ----
    for r in (results.get("provider") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("identified"):
            _add("C", u, "CONFIRMED", ["provider-identified"],
                 "shapes=%s" % ",".join(r.get("provider_shapes", [])[:5]))
        elif r.get("provider_shapes"):
            _add("C", u, "SUSPECTED", ["provider-hint"],
                 "shapes=%s" % ",".join(r.get("provider_shapes", [])[:4]))
    # ---- STORAGE (D) ----
    for r in (results.get("storage") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("D", u, "CONFIRMED", ["live", "storage-shape"],
                 "storage live + %s" % r["shape"])
        elif r.get("live"):
            _add("D", u, "SUSPECTED", ["live", "no-shape"],
                 "storage-shaped 200 (manual confirm)")
        elif r.get("waf_blocked"):
            _add("D", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- BUCKET ACL (E) ----
    for r in (results.get("bucket") or {}).get("rows", []):
        u = r.get("url", "?")
        vp = r.get("visibility_probe")
        if vp == "open":
            _add("E", u, "CONFIRMED", ["public-listing"],
                 "acl_shapes=%s" % ",".join(r.get("acl_shapes", [])[:4]))
        elif vp in ("denied", "missing"):
            _add("E", u, "SUSPECTED", ["acl-shape"], "probe=%s" % vp)
    # ---- TAKEOVER (F) ----
    for r in (results.get("takeover") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("lead"):
            _add("F", u, "SUSPECTED", ["cname-ref", "unresolved"],
                 "services=%s (manual RoE confirm)" %
                 ",".join(x.get("service", "") for x in
                          r.get("service_refs", [])[:4]))
        elif r.get("service_refs"):
            _add("F", u, "SUSPECTED", ["cname-ref"],
                 "services=%s (resolved)" %
                 ",".join(x.get("service", "") for x in
                          r.get("service_refs", [])[:4]))
    # ---- IMDS (G) ----
    for r in (results.get("imds") or {}).get("rows", []):
        if r.get("header_shapes"):
            _add("G", r.get("url", "?"), "SUSPECTED", ["imds-header-shape"],
                 "shapes=%s" % ",".join(r["header_shapes"][:4]))
    # ---- SECRETS (H) ----
    for r in (results.get("secrets") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("shapes"):
            _add("H", u, "CONFIRMED", ["secret-shape"],
                 "shapes=%s" % ",".join(s["shape"] for s in
                                        r.get("shapes", [])[:5]))
    # ---- SIGNEDURL (I) ----
    for r in (results.get("signedurl") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("unbounded_ttl"):
            _add("I", u, "CONFIRMED", ["unbounded-ttl"],
                 "params=%s" % r.get("param_count"))
        elif r.get("param_count"):
            _add("I", u, "SUSPECTED", ["presigned-present"],
                 "params=%s" % r.get("param_count"))
    # ---- CONTAINER (J) ----
    for r in (results.get("container") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("J", u, "CONFIRMED", ["live", "container-marker"],
                 "container live + %s" % r["shape"])
        elif r.get("waf_blocked"):
            _add("J", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- SERVERLESS (K) ----
    for r in (results.get("serverless") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("K", u, "CONFIRMED", ["live", "serverless-marker"],
                 "serverless live + %s" % r["shape"])
        elif r.get("waf_blocked"):
            _add("K", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- CDN (L) ----
    for r in (results.get("cdn") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("sensitive") and r.get("cacheable"):
            _add("L", u, "SUSPECTED", ["cacheable-sensitive"],
                 "cache_control=%s" % r.get("cache_control", ""))
        elif r.get("sensitive") and r.get("cache_safe"):
            _add("L", u, "HARDENED", ["cache-safe"], "no-store/private")
    # ---- CORS (M) ----
    for r in (results.get("cors") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("reflect_attacker") or r.get("reflect_null"):
            _add("M", u, "CONFIRMED", ["acao-reflect"],
                 "grade=%s" % r.get("grade"))
        elif r.get("wildcard"):
            _add("M", u, "SUSPECTED", ["acao-wildcard"],
                 "grade=%s" % r.get("grade"))
        elif r.get("strict"):
            _add("M", u, "HARDENED", ["cors-strict"], "canary origins rejected")
    # ---- IAM (N) ----
    for r in (results.get("iam") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("iam_shapes"):
            _add("N", u, "SUSPECTED", ["iam-shape"],
                 "shapes=%s" % ",".join(s["shape"] for s in
                                        r.get("iam_shapes", [])[:5]))
    # ---- DNS (O) ----
    for r in (results.get("dns") or {}).get("rows", []):
        u = r.get("host", "?")
        if r.get("nxdomain"):
            _add("O", u, "SUSPECTED", ["nxdomain"],
                 "error=%s" % (r.get("error") or "")[:60])
        elif r.get("ips"):
            _add("O", u, "HARDENED", ["resolved"],
                 "ips=%s" % ",".join(r.get("ips", [])[:3]))
    # ---- ERRORS (P) ----
    for r in (results.get("errors") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("verbose_hits"):
            _add("P", u, "CONFIRMED", ["provider-error"],
                 "shapes=%s" % ",".join(r.get("shapes", [])[:5]))
        else:
            _add("P", u, "HARDENED", ["errors-masked"], "no provider shapes")
    # ---- CONSOLE (Q) ----
    for r in (results.get("console") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("platform"):
            _add("Q", u, "CONFIRMED", ["live", "console-marker"],
                 "console live + %s" % r["platform"])
        elif r.get("auth_gate"):
            _add("Q", u, "HARDENED", ["auth-gate"], "401/403 enforced")
        elif r.get("waf_blocked"):
            _add("Q", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- CI/CD (R) ----
    for r in (results.get("cicd") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("live") and r.get("shape"):
            _add("R", u, "CONFIRMED", ["live", "cicd-shape"],
                 "artifact live + %s" % r["shape"])
        elif r.get("live"):
            _add("R", u, "SUSPECTED", ["live", "no-shape"],
                 "artifact-shaped 200 (manual confirm)")
        elif r.get("waf_blocked"):
            _add("R", u, "BLOCKED", ["waf-block"], "fingerprint blocked")
    # ---- TOKEN/TRUST (S) ----
    for r in (results.get("tokens") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("echo_count"):
            _add("S", u, "CONFIRMED", ["trust-echo"],
                 "echoes=%s" % ",".join(e["header"] for e in
                                        r.get("echoes", [])[:4]))
        elif r.get("token_params"):
            _add("S", u, "SUSPECTED", ["token-params"],
                 "params=%s" % ",".join(r.get("token_params", [])[:5]))
        elif r.get("status"):
            _add("S", u, "HARDENED", ["trust-clean"], "no echo/misroute")
    # ---- SPEC (T) ----
    for r in (results.get("spec") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("spec_shape"):
            _add("T", u, "CONFIRMED", ["spec-live"],
                 "ops=%s sensitive=%s" % (r.get("op_names_count"),
                                          len(r.get("sensitive_ops", []))))
        elif r.get("status") and not r.get("noise"):
            _add("T", u, "HARDENED", ["spec-absent"], "closed")
    # ---- BYPASS2 (U) ----
    for r in (results.get("bypass2") or {}).get("rows", []):
        u = r.get("url", "?")
        if r.get("accepted_count"):
            _add("U", u, "CONFIRMED", ["bypass-accept"],
                 "accepted=%s" % ",".join(r.get("accepted_ids", [])[:6]))
        elif r.get("blocked_count"):
            _add("U", u, "BLOCKED", ["waf-block"], "shapes fingerprint-blocked")
        else:
            _add("U", u, "HARDENED", ["reject-all"], "all 20 shapes rejected")
    # ---- GATED SKIPS ----
    for stage_key, gate_name in (
            ("D", "cloud_allow_bucket_probe"),
            ("E", "cloud_allow_bucket_probe"),
            ("F", "cloud_allow_takeover_probe"),
            ("J", "cloud_allow_container_probe"),
            ("K", "cloud_allow_serverless_probe"),
            ("M", "cloud_allow_cors_probe"),
            ("O", "cloud_allow_dns_probe"),
            ("P", "cloud_allow_error_probe"),
            ("Q", "cloud_allow_console_probe"),
            ("R", "cloud_allow_artifact_probe"),
            ("S", "cloud_allow_header_echo"),
            ("T", "cloud_allow_spec_probe"),
            ("U", "cloud_allow_bypass2")):
        st_map = {"D": "storage", "E": "bucket", "F": "takeover",
                  "J": "container", "K": "serverless", "M": "cors",
                  "O": "dns", "P": "errors", "Q": "console", "R": "cicd",
                  "S": "tokens", "T": "spec", "U": "bypass2"}
        st = results.get(st_map.get(stage_key, ""), {})
        if isinstance(st, dict) and st.get("skipped_note"):
            rows.append({"stage": stage_key, "url": "*", "verdict": "SKIPPED",
                         "signals": ["roe-gate-off"], "detail": gate_name})

    order = {"CONFIRMED": 0, "SUSPECTED": 1, "BLOCKED": 2, "HARDENED": 3,
             "SKIPPED": 4, "NOISE": 5}
    rows.sort(key=lambda r: (order.get(r["verdict"], 9), r["stage"]))
    return rows

# ===========================================================================
# STAGE Z - PLATFORM FINGERPRINT + FINAL SECRETS/PII GUARD
# ===========================================================================
PLATFORM_FPS = [
    ("aws-shape", re.compile(r"(?i)(x-amz|awselb|cloudfront|amazonaws)")),
    ("azure-shape", re.compile(r"(?i)(x-azure|x-ms-|arrcookie|azurewebsites)")),
    ("gcp-shape", re.compile(r"(?i)(x-goog|x-gcp|googleapis|appengine)")),
    ("cloudflare-shape", re.compile(r"(?i)(cf-ray|cloudflare|__cfduid)")),
    ("fastly-shape", re.compile(r"(?i)(x-served-by|fastly|varnish)")),
    ("vercel-shape", re.compile(r"(?i)(x-vercel|vercel)")),
    ("netlify-shape", re.compile(r"(?i)(netlify|x-nf-request-id)")),
    ("k8s-shape", re.compile(r"(?i)(kubernetes|k8s|minikube|kubelet)")),
    ("docker-shape", re.compile(r"(?i)(docker|registry|containerd)")),
    ("lambda-shape", re.compile(r"(?i)(lambda-runtime|execute-api)")),
    ("nginx-shape", re.compile(r"(?i)(nginx|server: nginx)")),
    ("apache-shape", re.compile(r"(?i)(apache|server: apache)")),
    ("nodejs-shape", re.compile(r"(?i)(express|x-powered-by: express|node)")),
    ("tomcat-shape", re.compile(r"(?i)(tomcat|jsessionid)")),
    ("dotnet-shape", re.compile(r"(?i)(asp\.net|x-aspnet|aspxauth)")),
]


def platform_fingerprint(probe_texts):
    """Census texts -> platform shapes (offline, census-only)."""
    hits = {}
    blob = " ".join(probe_texts or [])[:40000].lower()
    for name, rx in PLATFORM_FPS:
        m = rx.search(blob)
        if m:
            hits[name] = m.group(0)[:40]
    return {"shapes": sorted(hits.keys()), "evidence": hits}


SECRET_GUARD_RX = re.compile(
    r"(?i)((AKIA|ASIA)[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|"
    r"(secret_access_key|api_key|apikey|passwd|password|db_password|"
    r"AccountKey)\s*[:=]\s*[^\s,;\"]{6,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})")


def secrets_guard(payloads):
    """Final REDACTION sweep: sab artifacts me secret/PII shapes scan.

    Hit = finding (CWE-200 aid) + redaction confirmation. Sirf shape-flag,
    value store nahi."""
    hits = []
    for name, txt in (payloads or []):
        m = SECRET_GUARD_RX.search((txt or "")[:60000])
        if m:
            hits.append({"artifact": name, "shape":
                         m.group(0)[:8] + "***REDACTED***"})
    return {"hits": hits, "swept": len(payloads or []),
            "note": "final PII/secret sweep - values REDACTED by design"}


# ===========================================================================
# STAGE Y - TECHNIQUE MATRIX (242 rows x 22 families + CWE + MITRE)
# ===========================================================================
MATRIX_FAMILIES = [
    "CLOUD_FINGERPRINT", "CLOUD_STORAGE", "CLOUD_TAKEOVER",
    "CLOUD_METADATA", "CLOUD_SECRETS", "CLOUD_SIGNEDURL",
    "CLOUD_CONTAINER", "CLOUD_SERVERLESS", "CLOUD_CDN", "CLOUD_CORS",
    "CLOUD_IAM", "CLOUD_DNS", "CLOUD_ERRORS", "CLOUD_CONSOLE",
    "CLOUD_CICD", "CLOUD_APITOKEN", "CLOUD_GQLWS", "CLOUD_BYPASS2",
    "CLOUD_POSTURE", "CLOUD_TRANSPORT", "CLOUD_COMPLIANCE",
    "CLOUD_HANDOFF",
]

MATRIX_CATALOG = {
    "CLOUD_FINGERPRINT": [
        ("aws header shapes (x-amz/awselb)", "CWE-200", "T1592"),
        ("cloudfront distribution fingerprint", "CWE-200", "T1592"),
        ("azure x-ms-/ARR fingerprint", "CWE-200", "T1592"),
        ("gcp x-goog/via-google fingerprint", "CWE-200", "T1592"),
        ("cloudflare cf-ray fingerprint", "CWE-200", "T1590"),
        ("fastly x-served-by fingerprint", "CWE-200", "T1592"),
        ("akamai edge fingerprint", "CWE-200", "T1592"),
        ("vercel/netlify deployment fingerprint", "CWE-200", "T1592"),
        ("serverless lambda fingerprint", "CWE-200", "T1583"),
        ("k8s/docker runtime fingerprint", "CWE-200", "T1613"),
        ("provider topology enumeration (multi-shape)", "CWE-200", "T1589"),
    ],
    "CLOUD_STORAGE": [
        ("public s3 bucket shape", "CWE-732", "T1619"),
        ("azure blob public shape", "CWE-732", "T1619"),
        ("gcs public shape", "CWE-732", "T1619"),
        ("minio endpoint exposed", "CWE-1234", "T1619"),
        ("ListBucketResult XML shape", "CWE-732", "T1619"),
        ("NoSuchBucket error-shape probe", "CWE-209", "T1619"),
        ("AccessDenied shape (visibility probe)", "CWE-732", "T1619"),
        ("X-Amz-Bucket-Region disclosure", "CWE-200", "T1590"),
        ("bucket URL shapes mined from JS", "CWE-540", "T1619"),
        ("backup/storage dir autoindex", "CWE-548", "T1083"),
        ("third-party enumeration FORBIDDEN-AUTO", "CWE-693", "T1106"),
    ],
    "CLOUD_TAKEOVER": [
        ("azurewebsites dangling CNAME", "CWE-350", "T1584.006"),
        ("s3 NoSuchBucket dangling alias", "CWE-350", "T1584.006"),
        ("github-pages takeover lead", "CWE-350", "T1584.006"),
        ("herokuapp No-such-app lead", "CWE-350", "T1584.006"),
        ("fastly unknown-domain lead", "CWE-350", "T1584.006"),
        ("netlify/vercel deployment lead", "CWE-350", "T1584.006"),
        ("shopify/zendesk tenant lead", "CWE-350", "T1584.006"),
        ("bitbucket/surge/pantheon lead", "CWE-350", "T1584.006"),
        ("NXDOMAIN + service-ref combo", "CWE-350", "T1590"),
        ("resource-claim FORBIDDEN-AUTO", "CWE-693", "T1106"),
        ("manual RoE confirm wave", "CWE-693", "T1106"),
    ],
    "CLOUD_METADATA": [
        ("IMDSv1 reachable (documented)", "CWE-918", "T1552.005"),
        ("IMDSv2 token enforcement review", "CWE-918", "T1552.005"),
        ("instance-profile header shape", "CWE-200", "T1580"),
        ("metadata via SSRF (P15)", "CWE-918", "T1552.005"),
        ("metadata creds chain (documented)", "CWE-798", "T1552.005"),
        ("IMDS block from containers", "CWE-693", "T1106"),
        ("hop-limit 1 remediation", "CWE-693", "T1106"),
        ("x-amz-security-token shape", "CWE-200", "T1552"),
        ("egress-callback DNS canary", "CWE-918", "T1071.004"),
        ("IMDS probe FORBIDDEN-AUTO", "CWE-693", "T1106"),
        ("metadata header census (passive)", "CWE-200", "T1592"),
    ],
    "CLOUD_SECRETS": [
        ("aws access key in response", "CWE-798", "T1552.001"),
        ("gcp service-account private_key", "CWE-321", "T1552.004"),
        ("azure AccountKey/conn-string", "CWE-798", "T1552.001"),
        ("SAS sig token shape", "CWE-798", "T1552.001"),
        ("kube JWT/service-account token", "CWE-522", "T1552.004"),
        ("presigned URL shape in page", "CWE-200", "T1552"),
        ("ssh-rsa/private-key block", "CWE-321", "T1552.004"),
        ("docker cfg auths shape", "CWE-798", "T1552.001"),
        ("firebase config/dburl", "CWE-200", "T1552"),
        ("db-url creds in env shape", "CWE-798", "T1552"),
        ("rotation wave (manual RoE)", "CWE-693", "T1106"),
    ],
    "CLOUD_SIGNEDURL": [
        ("X-Amz-Expires unbounded (>=7d)", "CWE-613", "T1078"),
        ("SAS se= long-lived window", "CWE-613", "T1078"),
        ("Expires= epoch long TTL", "CWE-613", "T1078"),
        ("token param in URL (referrer leak)", "CWE-598", "T1552.001"),
        ("X-Amz-Signature exposure", "CWE-200", "T1552"),
        ("credential scope disclosure", "CWE-200", "T1590"),
        ("entropy-bucket weak token", "CWE-330", "T1078"),
        ("presigned replay window", "CWE-294", "T1078"),
        ("minimal-TTL remediation", "CWE-693", "T1106"),
        ("rotation/one-time-use review", "CWE-613", "T1106"),
        ("values sha1-only discipline", "CWE-693", "T1106"),
    ],
    "CLOUD_CONTAINER": [
        ("prometheus metrics exposed", "CWE-1234", "T1613"),
        ("docker registry catalog live", "CWE-732", "T1619"),
        ("pprof index exposed", "CWE-489", "T1613"),
        ("/env dump live (P23 handoff)", "CWE-200", "T1552"),
        ("kubelet API surface (documented)", "CWE-306", "T1610"),
        ("docker socket exposure (documented)", "CWE-250", "T1610"),
        ("k8s dashboard exposed", "CWE-1234", "T1078.002"),
        ("healthz verbose status", "CWE-200", "T1592"),
        ("registry push FORBIDDEN-AUTO", "CWE-693", "T1106"),
        ("pod-exec FORBIDDEN-AUTO", "CWE-693", "T1106"),
        ("network-policy remediation", "CWE-693", "T1106"),
    ],
    "CLOUD_SERVERLESS": [
        ("lambda endpoint exposed", "CWE-306", "T1583.007"),
        ("execute-api invoke surface", "CWE-306", "T1583.007"),
        ("azure functions exposed", "CWE-306", "T1583.007"),
        ("gcf/cloud-run exposed", "CWE-306", "T1583.007"),
        ("vercel/netlify function live", "CWE-306", "T1583.007"),
        ("cloudflare worker live", "CWE-306", "T1583.007"),
        ("serverless error shapes", "CWE-209", "T1613"),
        ("invoke FORBIDDEN-AUTO (bounded)", "CWE-693", "T1106"),
        ("auth review on functions", "CWE-306", "T1106"),
        ("rate-limit review", "CWE-770", "T1106"),
        ("cold-path serverless pool", "CWE-200", "T1595"),
    ],
    "CLOUD_CDN": [
        ("cf-cache-status on sensitive", "CWE-525", "T1174"),
        ("x-cache HIT on auth response", "CWE-524", "T1174"),
        ("Age/max-age on private", "CWE-525", "T1174"),
        ("Vary absent (shared cache)", "CWE-525", "T1174"),
        ("CDN origin bypass shape", "CWE-290", "T1557"),
        ("host-header cache confusion", "CWE-348", "T1557"),
        ("web-cache poisoning surface", "CWE-444", "T1557"),
        ("cache-key canonicalization", "CWE-444", "T1106"),
        ("no-store present (control)", "CWE-693", "T1106"),
        ("P22 cacheable rollup", "CWE-524", "T1174"),
        ("token-route bypass review", "CWE-524", "T1106"),
    ],
    "CLOUD_CORS": [
        ("ACAO reflects attacker origin", "CWE-942", "T1189"),
        ("ACAO null origin allowed", "CWE-942", "T1189"),
        ("ACAO * with credentials", "CWE-942", "T1189"),
        ("storage endpoint CORS reflect", "CWE-942", "T1189"),
        ("origin allowlist prefix-match", "CWE-942", "T1189"),
        ("preflight permissive methods", "CWE-942", "T1189"),
        ("credentials true + reflect", "CWE-942", "T1189"),
        ("strict origin allowlist (control)", "CWE-693", "T1106"),
        ("wildcard public-only review", "CWE-942", "T1189"),
        ("P14/P23 CORS cross-check", "CWE-942", "T1106"),
        ("canary .invalid discipline", "CWE-693", "T1106"),
    ],
    "CLOUD_IAM": [
        ("arn:aws:iam shape disclosure", "CWE-200", "T1580"),
        ("account-id shape (12-digit)", "CWE-200", "T1580"),
        ("azure tenant GUID shape", "CWE-200", "T1580"),
        ("gcp project-id shape", "CWE-200", "T1580"),
        ("role-name shape (roles/)", "CWE-200", "T1580"),
        ("service-account reference", "CWE-200", "T1580"),
        ("instance-profile shape", "CWE-200", "T1580"),
        ("least-privilege review", "CWE-250", "T1106"),
        ("response sanitization fix", "CWE-200", "T1106"),
        ("values sha1-only discipline", "CWE-693", "T1106"),
        ("privilege-map recon aid", "CWE-200", "T1589"),
    ],
    "CLOUD_DNS": [
        ("in-scope alias resolve census", "CWE-350", "T1590"),
        ("NXDOMAIN dangling alias", "CWE-350", "T1584.006"),
        ("subdomain candidate resolve", "CWE-350", "T1590"),
        ("third-party DNS brute FORBIDDEN", "CWE-693", "T1106"),
        ("zone-walking review", "CWE-200", "T1590"),
        ("wildcard DNS review", "CWE-350", "T1590"),
        ("DNS cleanup remediation", "CWE-350", "T1106"),
        ("CAA/TXT posture review", "CWE-693", "T1590"),
        ("cap-bounded resolve discipline", "CWE-693", "T1106"),
        ("in-scope-only firewall", "CWE-284", "T1106"),
        ("alias-map documentation", "CWE-200", "T1589"),
    ],
    "CLOUD_ERRORS": [
        ("aws RequestID disclosure", "CWE-209", "T1613"),
        ("<Error><Code> XML shape", "CWE-209", "T1613"),
        ("azure ErrorDetails shape", "CWE-209", "T1613"),
        ("gcp error JSON shape", "CWE-209", "T1613"),
        ("lambda Task-timed-out shape", "CWE-209", "T1613"),
        ("k8s forbidden shape", "CWE-209", "T1613"),
        ("registry NAME_UNKNOWN", "CWE-209", "T1613"),
        ("upstream/502 detail", "CWE-209", "T1613"),
        ("generic masking (control)", "CWE-693", "T1106"),
        ("error-correlation id only", "CWE-209", "T1106"),
        ("canary-param probe discipline", "CWE-693", "T1106"),
    ],
    "CLOUD_CONSOLE": [
        ("aws console signin surface", "CWE-1234", "T1078.002"),
        ("azure AD login surface", "CWE-1234", "T1078.003"),
        ("gcp login surface", "CWE-1234", "T1078.003"),
        ("k8s dashboard exposed", "CWE-1234", "T1078.002"),
        ("rancher/portainer exposed", "CWE-1234", "T1078.002"),
        ("jenkins/gitlab exposed", "CWE-1234", "T1078.002"),
        ("argocd exposed", "CWE-1234", "T1078.002"),
        ("vault exposed", "CWE-1234", "T1552"),
        ("consul/nomad UI exposed", "CWE-1234", "T1078.002"),
        ("auth-gate (control)", "CWE-693", "T1106"),
        ("login attempt FORBIDDEN-AUTO", "CWE-307", "T1110"),
    ],
    "CLOUD_CICD": [
        (".github/workflows exposed", "CWE-538", "T1213.003"),
        (".gitlab-ci.yml exposed", "CWE-538", "T1213.003"),
        ("Dockerfile exposed", "CWE-540", "T1083"),
        ("docker-compose exposed", "CWE-540", "T1083"),
        ("kube yaml exposed", "CWE-538", "T1083"),
        ("terraform.tfstate exposed", "CWE-200", "T1552.001"),
        ("terraform.tfvars exposed", "CWE-798", "T1552.001"),
        (".aws/config exposed", "CWE-798", "T1552.001"),
        (".ssh/id_rsa exposed", "CWE-321", "T1552.004"),
        ("Jenkinsfile exposed", "CWE-540", "T1213.003"),
        ("artifact removal + rotation", "CWE-693", "T1106"),
    ],
    "CLOUD_APITOKEN": [
        ("token param in GET (names-only)", "CWE-598", "T1552.001"),
        ("api_key param shape", "CWE-798", "T1552.001"),
        ("X-Amz-Signature in URL", "CWE-598", "T1552.001"),
        ("trust-header echo (X-Original-*)", "CWE-348", "T1557"),
        ("X-Forwarded-Host trust", "CWE-348", "T1557"),
        ("X-Custom-IP trust", "CWE-290", "T1557"),
        ("edge-strip remediation", "CWE-693", "T1106"),
        ("URL-token removal", "CWE-598", "T1106"),
        ("P9 auth handoff", "CWE-287", "T1106"),
        ("P22 replay handoff", "CWE-294", "T1106"),
        ("names-only discipline", "CWE-693", "T1106"),
    ],
    "CLOUD_GQLWS": [
        ("gql mutation names (never sent)", "CWE-200", "T1592"),
        ("ws endpoint census (frames never)", "CWE-200", "T1592"),
        ("P18 handoff rollup", "CWE-693", "T1106"),
        ("P19 handoff rollup", "CWE-693", "T1106"),
        ("introspection cross-check", "CWE-200", "T1592"),
        ("mutation-surface aid", "CWE-284", "T1106"),
        ("ws origin review", "CWE-346", "T1557"),
        ("persisted-queries review", "CWE-693", "T1106"),
        ("subscription-authz review", "CWE-284", "T1106"),
        ("names-only discipline", "CWE-693", "T1106"),
        ("cloud-gql chaining", "CWE-200", "T1106"),
    ],
    "CLOUD_BYPASS2": [
        ("double-slash normalizer differential", "CWE-436", "T1036"),
        ("dot-segment /./ differential", "CWE-436", "T1036"),
        ("parent-segment /../ differential", "CWE-436", "T1036"),
        ("%2e%2e decoder differential", "CWE-436", "T1036"),
        ("semicolon matrix-param differential", "CWE-436", "T1036"),
        ("%09 whitespace differential", "CWE-436", "T1036"),
        ("case-shuffle authz differential", "CWE-436", "T1036"),
        ("double-url-encode differential", "CWE-436", "T1036"),
        ("X-Original-URL misroute", "CWE-348", "T1036"),
        ("X-Forwarded-For allowlist trust", "CWE-290", "T1036"),
        ("Range partial-content gap", "CWE-830", "T1036"),
    ],
    "CLOUD_POSTURE": [
        ("14-point composite scoring", "CWE-693", "T1106"),
        ("storage_locked point", "CWE-732", "T1106"),
        ("takeover_clean point", "CWE-350", "T1106"),
        ("secrets_absent point", "CWE-798", "T1106"),
        ("signedurl_bounded point", "CWE-613", "T1106"),
        ("container_locked point", "CWE-1234", "T1106"),
        ("cdn_safe point", "CWE-525", "T1106"),
        ("cors_strict point", "CWE-942", "T1106"),
        ("dns_clean point", "CWE-350", "T1106"),
        ("bypass2_blocked point", "CWE-436", "T1106"),
        ("weak-row prioritization", "CWE-693", "T1106"),
    ],
    "CLOUD_TRANSPORT": [
        ("http->https redirect shape", "CWE-319", "T1557"),
        ("HSTS absent on cloud storage", "CWE-319", "T1557"),
        ("mixed-content in cloud pages", "CWE-311", "T1557"),
        ("TLS edge config review", "CWE-319", "T1557"),
        ("CDN TLS posture", "CWE-319", "T1557"),
        ("downgrade window (documented)", "CWE-319", "T1557"),
        ("preload review", "CWE-319", "T1106"),
        ("secure-cookie on cloud apps", "CWE-614", "T1557"),
        ("transport-strong control", "CWE-693", "T1106"),
        ("P23 transport cross-check", "CWE-693", "T1106"),
        ("cert-expiry census (passive)", "CWE-319", "T1592"),
    ],
    "CLOUD_COMPLIANCE": [
        ("public-block S3 policy review", "CWE-732", "T1106"),
        ("SAS minimal-TTL policy", "CWE-613", "T1106"),
        ("IMDSv2-required policy", "CWE-918", "T1106"),
        ("least-privilege IAM policy", "CWE-250", "T1106"),
        ("registry auth policy", "CWE-306", "T1106"),
        ("secrets-manager adoption", "CWE-798", "T1106"),
        ("audit-log enablement review", "CWE-778", "T1562"),
        ("egress filtering review", "CWE-693", "T1106"),
        ("backup-exposure policy", "CWE-732", "T1106"),
        ("provider advisory subscribe", "CWE-1104", "T1106"),
        ("RoE-gate documentation", "CWE-693", "T1106"),
    ],
    "CLOUD_HANDOFF": [
        ("P23 misconfig handoff cross-check", "CWE-693", "T1106"),
        ("P15 SSRF/metadata handoff", "CWE-918", "T1106"),
        ("P25 controls handoff", "CWE-693", "T1106"),
        ("P11 access handoff (bypass2)", "CWE-284", "T1106"),
        ("P12 inject handoff (errors)", "CWE-209", "T1106"),
        ("P9 auth handoff (tokens)", "CWE-287", "T1106"),
        ("P7 js-secrets handoff", "CWE-798", "T1106"),
        ("P32 report handoff", "CWE-693", "T1106"),
        ("ff routing (to_phase25/15/11)", "CWE-693", "T1106"),
        ("MANIFEST + RWX discipline", "CWE-693", "T1106"),
        ("checkpoint replay discipline", "CWE-693", "T1106"),
    ],
}


def build_matrix():
    """Matrix rows (id CLOUD-001..) - P12..P23-compatible shape."""
    rows = []
    n = 0
    for fam in MATRIX_FAMILIES:
        for tech, cwe, mitre in MATRIX_CATALOG[fam]:
            n += 1
            rows.append({"id": "CLOUD-%03d" % n, "family": fam,
                         "technique": tech, "cwe": cwe, "mitre": mitre})
    return rows

# ===========================================================================
# STAGE Z - RENDERERS (findings md / test plan / remediation / exec / kickoff)
# ===========================================================================
def render_findings_md(scope, F, verdict_rows, chains, meta):
    L = ["# P24 CLOUD FINDINGS - %s" % scope.engagement, "",
         "**Engine:** WASP v%s / cloud plan v%s | **Mode:** %s | "
         "**100%% INERT detection-only** (canary %s family)" %
         (VERSION, PLAN_VERSION, meta.get("mode", "active"), CANARY_FAMILY),
         "**Discipline:** GET-only | bodies/secret-values REDACTED | zero "
         "egress | IMDS/bucket-enum/takeover-claim/creds FORBIDDEN-AUTO", "",
         "## Severity summary", ""]
    sc = _sev_counts(F)
    for sev in ("critical", "high", "medium", "low", "info"):
        L.append("- **%s:** %d" % (sev.upper(), sc.get(sev, 0)))
    L += ["", "## Findings (%d)" % len(F.items), ""]
    for f in F.items:
        L += ["### %s %s [%s] (cvss~%s)" % (f["id"], f["title"],
                                            f["severity"].upper(),
                                            f["cvss_hint"]),
              "- **Endpoint:** %s" % f["endpoint"],
              "- **Why it matters:** %s" % f["why_it_matters"],
              "- **Detail:** %s" % f["detail"],
              ("- **Evidence:** %s" % f["evidence"]) if f["evidence"] else "",
              ""]
    L += ["## Verdict rows (%d)" % len(verdict_rows), "",
          "| Stage | URL | Verdict | Signals | Detail |", "|---|---|---|---|---|"]
    for r in verdict_rows[:200]:
        L.append("| %s | %s | %s | %s | %s |" % (
            r["stage"], truncate(r["url"], 48), r["verdict"],
            ",".join(r["signals"])[:40], truncate(r["detail"], 60)))
    L += ["", "## Kill-chains (%d)" % len(chains), ""]
    for c in chains:
        L.append("- **%s** %s -> %s" % (c["id"], c["title"], c["evidence"]))
    return "\n".join(L) + "\n"


def render_test_plan(F, gates, matrix_rows):
    L = ["# P24 CLOUD TEST PLAN (kill tests + manual waves)", "",
         "RoE gates (sab default OFF - enable sirf written authorization par):", ""]
    for g, d in ROE_GATES:
        L.append("- `%s` = %s -> %s" % (g, str(gates.get(g, False)).lower(), d))
    L += ["", "## Kill tests (KD-01..KD-13)", ""]
    kds = [
        ("KD-01", "Storage/bucket manual wave",
         "bucket-shape + URL-shapes confirm manual -> public-block + "
         "auth-gate + listing disable (bucket enumeration RoE window me)"),
        ("KD-02", "Bucket-ACL visibility wave",
         "NoSuchBucket/AccessDenied shapes manual review -> ACL/OPA policy "
         "fix (visibility probe manual; koi listing automation nahi)"),
        ("KD-03", "Takeover lead wave",
         "cname-ref + unresolved confirm manual -> alias cleanup / "
         "resource-claim sirf RoE+owner consent ke saath"),
        ("KD-04", "Container wave",
         "metrics/pprof/env/registry presence -> endpoint lockdown "
         "(auth/network-policy; koi exec/push KABHI)"),
        ("KD-05", "Serverless wave",
         "lambda/functions exposure -> auth + rate-limit + error-masking "
         "review (invoke bounded/manual)"),
        ("KD-06", "Storage CORS wave",
         "canary reflection confirm -> origin-allowlist + credentials "
         "false fix"),
        ("KD-07", "DNS alias wave",
         "NXDOMAIN/in-scope resolve census -> dangling DNS cleanup "
         "(third-party brute KABHI)"),
        ("KD-08", "Provider-error wave",
         "RequestID/<Error><Code> shapes -> error masking + correlation-id"),
        ("KD-09", "Console wave",
         "console/login surface -> auth-gate + MFA + network-isolate "
         "(login attempts KABHI automated nahi)"),
        ("KD-10", "CI/CD artifact wave",
         "workflows/tfstate/.ssh presence -> artifact removal + secret "
         "rotation + state-store hardening"),
        ("KD-11", "Token/trust wave",
         "URL-token params + trust-header echo -> edge-strip + URL-token "
         "removal (P9/P22 handoff)"),
        ("KD-12", "Cloud spec wave",
         "swagger/openapi on api-gw -> spec gating on prod (P17 handoff)"),
        ("KD-13", "Bypass2 normalization wave",
         "manual proxy replay with each CB-xx shape -> normalize-before-"
         "authz alignment"),
    ]
    for kid, title, steps in kds:
        L += ["### %s %s" % (kid, title), steps, ""]
    L += ["## FORBIDDEN-AUTO (manual+RoE ONLY - kabhi automate nahi)", "",
          "- link-local metadata (IMDS) probing / credential harvest",
          "- third-party bucket enumeration / listing / object reads",
          "- subdomain-takeover resource claim / DNS modification",
          "- kubelet exec / docker socket / registry push-delete",
          "- cloud cred stuffing / brute loops / console login attempts", "",
          "## Technique matrix snapshot",
          "Rows: %d | Families: %d" % (len(matrix_rows), len(set(
              m["family"] for m in matrix_rows)))]
    return "\n".join(L) + "\n"


def render_remediation(F):
    L = ["# P24 CLOUD REMEDIATION PLAYBOOK", "",
         "Har finding-family ke liye server-side fix guidance:", ""]
    rem = [
        ("CLOUD_FINGERPRINT", "Disclosure headers strip (Server/X-Powered-By/"
         "x-amz-request-id minimize), generic error bodies, CDN fingerprint "
         "standardize, edge rules se provider headers normalize."),
        ("CLOUD_STORAGE", "Bucket public-block (S3 Block Public Access), "
         "auth-gate + signed-URL-only reads, listing disable, bucket "
         "naming entropy, per-object ACL audit, backup dirs webroot se "
         "bahar."),
        ("CLOUD_TAKEOVER", "Dangling CNAME cleanup (DNS audit), unused "
         "resource release, cname inventory + monitoring, takeover "
         "detection on registrar/DNS level."),
        ("CLOUD_METADATA", "IMDSv2 required + hop-limit 1, metadata endpoint "
         "block from containers, instance-profile least-privilege, SSRF "
         "egress filtering (P15 alignment)."),
        ("CLOUD_SECRETS", "Response/JS me secrets KABHI: secret-manager "
         "rotation (leak hue = compromise), redaction middleware, git "
         "history purge, pre-commit secret scans, env templating."),
        ("CLOUD_SIGNEDURL", "Minimal-TTL (<1h ideal), one-time-use tokens, "
         "IP/user-agent binding review, rotation, token URL se cookie/"
         "header me le jao, expired-URL invalidation."),
        ("CLOUD_CONTAINER", "metrics/pprof/env/registry endpoints internal-"
         "network restrict, auth-gate, k8s RBAC + dashboard network-policy, "
         "kubelet cert/auth enforce, docker socket containers se hatao."),
        ("CLOUD_SERVERLESS", "Function auth (IAM/authorizer), rate-limiting "
         "per identity, error masking (no provider shapes), function-URL "
         "disable agar unused, least-privilege execution roles."),
        ("CLOUD_CDN", "Private/auth responses par Cache-Control: no-store, "
         "Vary: Cookie/Authorization, cache-key canonicalization, CDN "
         "origin-shield auth, host-header strict binding."),
        ("CLOUD_CORS", "Origin allowlist exact-match (koi prefix/reflect "
         "nahi), null origin reject, wildcard sirf public data, "
         "Access-Control-Allow-Credentials sirf trusted origins."),
        ("CLOUD_IAM", "ARN/account-id responses se sanitize, "
         "least-privilege policies, roles external-id ke saath, permission "
         "boundaries, access-analyzer periodic."),
        ("CLOUD_DNS", "Dangling alias cleanup, DNS inventory + expiry "
         "monitoring, wildcard DNS review, CAA records, zone-transfer "
         "restrict."),
        ("CLOUD_ERRORS", "Provider errors mask karo (generic 500 template), "
         "RequestID sirf correlation-id me, verbose cloud errors sirf "
         "internal logs, error-bodies se account/region strip."),
        ("CLOUD_CONSOLE", "Consoles VPN/bastion ke peeche, SSO + MFA, "
         "IP-allowlist, separate admin vhost, session-timeout short, "
         "platform version patching."),
        ("CLOUD_CICD", ".github/.gitlab/tfstate/.ssh webroot se hatao, "
         "artifact store private, pipeline secrets secret-manager me, "
         "tfstate remote-backend + locking + encryption."),
        ("CLOUD_APITOKEN", "URL-token params hatao (header/cookie), "
         "trust-headers edge par strip (X-Original-*/X-Forwarded-*), "
         "token rotation + scope-minimal, replay protection (P22)."),
        ("CLOUD_GQLWS", "Introspection prod-off, ws origin allowlist, "
         "subscription authz, persisted queries (P18), depth/cost guards."),
        ("CLOUD_BYPASS2", "Normalize-before-authz (single canonical path), "
         "reject duplicate/malformed segments, proxy headers strip, "
         "host/origin strict binding, Range-request authz alignment."),
        ("CLOUD_POSTURE", "14-point composite ke WEAK rows priority order "
         "me fix karo (storage -> secrets -> bypass2 -> container)."),
        ("CLOUD_TRANSPORT", "http->https 301, HSTS har response, "
         "mixed-content fix, CDN TLS modern-config, secure cookies."),
        ("CLOUD_COMPLIANCE", "Public-block policies, SAS minimal-TTL, "
         "IMDSv2-required, audit-logs enable, egress filtering, "
         "advisories subscribe, periodic posture re-run."),
        ("CLOUD_HANDOFF", "P25 controls + P32 report handoff - "
         "feedforward.json routing follow karo (cross-module remediation "
         "order)."),
    ]
    for fam, txt in rem:
        L += ["## %s" % fam, txt, ""]
    L += ["## Finding-driven priorities", ""]
    for f in F.items[:20]:
        if f["severity"] in ("critical", "high"):
            L.append("- [%s] %s (%s)" % (f["severity"].upper(), f["title"],
                                         f["endpoint"]))
    return "\n".join(L) + "\n"


def render_exec_summary(scope, F, posture, verdict_rows, meta):
    sc = _sev_counts(F)
    weak = len(posture.get("weak") or [])
    conf_n = len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"])
    hard_n = len([r for r in verdict_rows if r["verdict"] == "HARDENED"])
    L = ["# P24 CLOUD EXECUTIVE SUMMARY - %s" % scope.engagement, "",
         "Engagement: %s | Reference: %s | Mode: %s" % (
             scope.engagement, scope.ref or "n/a", meta.get("mode", "active")),
         "Engine: WASP v%s / cloud plan v%s | 100%% INERT (canary %s)" % (
             VERSION, PLAN_VERSION, CANARY_FAMILY),
         "", "## Posture", "",
         "- CONFIRMED cloud exposures: **%d**" % conf_n,
         "- HARDENED positive controls: **%d**" % hard_n,
         "- Findings: critical=%d high=%d medium=%d low=%d info=%d" % (
             sc.get("critical", 0), sc.get("high", 0), sc.get("medium", 0),
             sc.get("low", 0), sc.get("info", 0)),
         "- Posture-WEAK endpoints: **%d**" % weak,
         "", "## Top risks", ""]
    for f in F.items:
        if f["severity"] in ("critical", "high"):
            L.append("- **%s** %s @ %s" % (f["severity"].upper(),
                                           f["title"], f["endpoint"]))
    if not any(f["severity"] in ("critical", "high") for f in F.items):
        L.append("- (koi critical/high CONFIRMED nahi - HARDENED controls "
                 "dominant; manual waves CLOUD_TEST_PLAN.md dekho)")
    L += ["", "## Next steps", "",
          "1. RoE-gated manual waves (CLOUD_TEST_PLAN.md KD-01..KD-13)",
          "2. Remediation order (CLOUD_REMEDIATION.md)",
          "3. P25 controls + P32 report handoff (feedforward.json)"]
    return "\n".join(L) + "\n"


def render_kickoff(scope, gates, conf):
    L = ["# P24 CLOUD KICKOFF GUIDE", "",
         "## Run", "",
         "```",
         "python3 wasp.py run --module 24      # P24 stage (sab gates OFF)",
         "python3 wasp.py run --module cloud --config config.json",
         "python3 mod_cloud.py                 # gate reference",
         "```", "",
         "## Gates enable (sirf written authorization par)", "",
         "```json",
         json.dumps({g: True for g, _ in ROE_GATES[:2]}, indent=2),
         "```", "",
         "## Discipline (non-negotiable)", "",
         "- 100%% INERT detection-only (canary %s family)" % CANARY_FAMILY,
         "- GET-only module: koi POST/PUT/DELETE/PATCH probe KABHI",
         "- bodies/secret-values REDACTED: sirf status/sha1/shape-flags",
         "- NO IMDS probes | NO third-party bucket enumeration | "
         "NO takeover claims | NO creds sending | NO kubelet exec/registry "
         "push",
         "- zero egress: scope firewall (wasp_core LAYER-4)",
         "- outputs RWX 0777", "",
         "## Caps (config.json)", "",
         "```json",
         json.dumps({k: v for k, v in DEFAULTS.items()
                     if k.startswith("cloud_") and not
                     k.startswith("cloud_allow")}, indent=2),
         "```"]
    return "\n".join(L) + "\n"


def render_playbooks():
    L = ["# P24 MANUAL PLAYBOOKS (FORBIDDEN-AUTO techniques)", "",
         "Ye techniques automation me KABHI nahi - sirf written RoE + "
         "manual execution:", ""]
    L += ["## IMDS/metadata waves", ""]
    for sid, name, disc in IMDS_PLAYBOOK_ROWS:
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Cloud-credential waves", ""]
    for sid, name, disc in CLOUD_CREDS_PLAYBOOK_ROWS:
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Container/K8s waves", ""]
    for sid, name, disc in CONTAINER_PLAYBOOK_ROWS:
        L += ["## %s %s" % (sid, name), disc, ""]
    L += ["## Takeover fingerprint DB (lead-only - claim FORBIDDEN-AUTO)", ""]
    for tid, svc, dom, marker, disc in TAKEOVER_FP_ROWS:
        L.append("- %s %s (%s): %s -> %s" % (tid, svc, dom, marker, disc))
    L += ["", "## Evidence discipline", "",
          "- har manual step ka request/response capture (RoE window me)",
          "- canary identifiers use karo (real ids sirf final PoC me, "
          "owner consent ke saath)",
          "- artifact proofs: timestamped GET + status/sha1 (body KABHI "
          "report me copy nahi)",
          "- cleanup: koi canary residue chhodna nahi"]
    return "\n".join(L) + "\n"


def render_chains_txt(chains):
    L = ["P24 CLOUD KILL-CHAINS (CH01..CH%02d)" % len(chains), ""]
    for c in chains:
        L.append("%s | %s | %s" % (c["id"], c["title"], c["evidence"]))
    return "\n".join(L) + "\n"


def render_matrix_txt(matrix_rows):
    L = ["P24 TECHNIQUE MATRIX - %d rows x %d families" % (
        len(matrix_rows), len(set(m["family"] for m in matrix_rows))), ""]
    cur = None
    for m in matrix_rows:
        if m["family"] != cur:
            cur = m["family"]
            L += ["", "## %s" % cur]
        L.append("%s | %-52s | %s | %s" % (m["id"], m["technique"][:52],
                                           m["cwe"], m["mitre"]))
    return "\n".join(L) + "\n"


def build_hypotheses(results, posture):
    """Offline hypotheses (manual-review leads)."""
    hyps = []
    for r in (results.get("storage") or {}).get("rows", []):
        if r.get("live") and r.get("shape"):
            hyps.append({"h": "Storage shape live (%s) @ %s - public-block "
                         "review" % (r.get("shape"), r.get("url")),
                         "prio": "critical"})
    for r in (results.get("bucket") or {}).get("rows", []):
        if r.get("visibility_probe") == "open":
            hyps.append({"h": "Bucket public listing shape @ %s - ACL fix"
                         % r.get("url"), "prio": "critical"})
    for r in (results.get("secrets") or {}).get("rows", []):
        if r.get("shapes"):
            hyps.append({"h": "Cloud secret-shape @ %s - rotation wave"
                         % r.get("url"), "prio": "critical"})
    for r in (results.get("takeover") or {}).get("rows", []):
        if r.get("lead"):
            hyps.append({"h": "Takeover lead @ %s - alias cleanup (manual)"
                         % r.get("url"), "prio": "high"})
    for r in (results.get("signedurl") or {}).get("rows", []):
        if r.get("unbounded_ttl"):
            hyps.append({"h": "Unbounded presigned TTL @ %s - minimal-TTL"
                         % r.get("url"), "prio": "high"})
    for r in (results.get("container") or {}).get("rows", []):
        if r.get("live") and r.get("shape"):
            hyps.append({"h": "Container endpoint live (%s) @ %s - lockdown"
                         % (r.get("shape"), r.get("url")), "prio": "high"})
    for r in (results.get("cicd") or {}).get("rows", []):
        if r.get("live") and r.get("shape"):
            hyps.append({"h": "CI/CD artifact live (%s) @ %s - removal+"
                         "rotation" % (r.get("shape"), r.get("url")),
                         "prio": "critical"})
    for r in (results.get("bypass2") or {}).get("rows", []):
        if r.get("accepted_count"):
            hyps.append({"h": "Bypass2 accepted @ %s - normalize-before-"
                         "authz" % r.get("url"), "prio": "critical"})
    for w in (posture.get("weak") or [])[:4]:
        hyps.append({"h": "Posture WEAK (%d/14) @ %s - hardening wave" %
                     (w["score"], w["url"]), "prio": "medium"})
    if not hyps:
        hyps.append({"h": "Koi high-signal lead nahi - HARDENED controls "
                     "dominant; gates ON wave review karo", "prio": "low"})
    return hyps[:24]

# ===========================================================================
# STAGE Z - REPORTS (54 artifacts) + FEEDFORWARD + MANIFEST
# ===========================================================================
def write_reports(out, scope, F, ctx, meta, results, disc, conf,
                  chains, verdict_rows, matrix_rows, posture, platform,
                  guard, hyps, gql_mut, ws_endpoints):
    """Sab artifacts likh (54). Bodies/secret-values REDACTED (names/
    booleans/sha1 only)."""
    manifest = []

    def _w_json(name, obj):
        save_json(os.path.join(out, name), obj)
        manifest.append(name)

    def _w_text(name, txt):
        save_text(os.path.join(out, name), txt)
        manifest.append(name)

    targets = results.get("targets") or []

    # 1-3 targets/endpoints/ranking
    _w_json("cloud_targets.json", {
        "count": len(targets),
        "targets": [{"url": t.get("url"), "score": t.get("score"),
                     "kinds": t.get("kinds", [])} for t in targets]})
    _w_text("cloud_endpoints.txt", "\n".join(
        [t.get("url", "") for t in targets]) + "\n")
    _w_json("cloud_ranking.json", {
        "paths_cap": conf.get("cloud_paths_cap"),
        "ranked": [{"url": t.get("url"), "score": t.get("score")}
                   for t in targets]})
    # 4 coverage
    gates = {g: bool(conf.get(g)) for g, _ in ROE_GATES}
    _w_json("cloud_coverage.json", {
        "mode": ctx.get("mode"), "sources": disc.get("sources", []),
        "probes_total": meta.get("probes_total", 0),
        "stages": ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
                   "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
                   "W", "X", "Y", "Z"],
        "gates": gates})
    # 5-6 baseline/waf
    _w_json("cloud_baseline.json", results.get("baseline", {}).get("rows", []))
    _w_json("cloud_waf.json", results.get("baseline", {}).get("waf", []))
    # 7-13 censuses
    _w_json("cloud_provider.json", results.get("provider", {}))
    _w_json("cloud_storage.json", results.get("storage", {}))
    _w_text("cloud_storage_paths.txt", "\n".join(STORAGE_PATHS) + "\n")
    _w_json("cloud_bucket.json", results.get("bucket", {}))
    _w_json("cloud_takeover.json", results.get("takeover", {}))
    _w_text("cloud_takeover_playbook.txt", "\n".join(
        ["P24 TAKEOVER FINGERPRINT DB (claim FORBIDDEN-AUTO):"] +
        ["%s | %s | %s | %s" % (i, s, d, m) for i, s, d, m, _ in
         TAKEOVER_FP_ROWS]) + "\n")
    _w_json("cloud_imds.json", results.get("imds", {}))
    # 14-18 secrets/signedurl
    _w_json("cloud_secrets.json", results.get("secrets", {}))
    _w_text("cloud_secret_names.txt", "\n".join(sorted(set(
        [s.get("shape", "") for r in (results.get("secrets") or {})
         .get("rows", []) for s in (r.get("shapes") or [])]))) + "\n")
    _w_json("cloud_signedurl.json", results.get("signedurl", {}))
    # 19-24 container/serverless/cdn/cors/dns/iam
    _w_json("cloud_container.json", results.get("container", {}))
    _w_text("cloud_container_paths.txt", "\n".join(CONTAINER_PATHS) + "\n")
    _w_json("cloud_serverless.json", results.get("serverless", {}))
    _w_text("cloud_serverless_paths.txt", "\n".join(SERVERLESS_PATHS) + "\n")
    _w_json("cloud_cdn.json", results.get("cdn", {}))
    _w_json("cloud_cors.json", results.get("cors", {}))
    _w_json("cloud_dns.json", results.get("dns", {}))
    _w_json("cloud_iam.json", results.get("iam", {}))
    # 25-33 errors/console/cicd/tokens/spec/gql-ws
    _w_json("cloud_errors.json", results.get("errors", {}))
    _w_json("cloud_console.json", results.get("console", {}))
    _w_text("cloud_console_names.txt", "\n".join(
        [n for n, _ in CONSOLE_MARKERS]) + "\n")
    _w_json("cloud_cicd.json", results.get("cicd", {}))
    _w_text("cloud_cicd_paths.txt", "\n".join(ARTIFACT_PATHS) + "\n")
    _w_json("cloud_apitoken.json", results.get("tokens", {}))
    _w_json("cloud_spec.json", results.get("spec", {}))
    _w_json("cloud_gqlws.json", {"gql_mutations": gql_mut,
                                 "ws_endpoints": ws_endpoints})
    _w_json("cloud_bypass2.json", results.get("bypass2", {}))
    # 34-40 posture/platform/guard/verdicts/chains/matrix/hypotheses
    _w_json("cloud_posture.json", posture)
    _w_text("cloud_posture.txt", "\n".join(
        ["P24 CLOUD POSTURE (14-point composite):"] +
        ["%-58s %d/14 %s" % (r["url"][:58], r["score"], r["grade"])
         for r in posture.get("rows", [])] +
        ["", "points: " + ", ".join("%s=%s" % (p, d)
                                    for p, d in posture.get("points", []))]) + "\n")
    _w_json("cloud_platform.json", platform)
    _w_json("cloud_secret_guard.json", guard)
    _w_json("cloud_verdicts.json", {"count": len(verdict_rows),
                                    "rows": verdict_rows})
    _w_json("cloud_chains.json", {"count": len(chains), "chains": chains})
    _w_text("CLOUD_CHAINS.txt", render_chains_txt(chains))
    _w_json("cloud_matrix.json", {
        "rows": len(matrix_rows),
        "families": sorted(set(m["family"] for m in matrix_rows)),
        "matrix": matrix_rows})
    _w_text("CLOUD_MATRIX.txt", render_matrix_txt(matrix_rows))
    _w_json("cloud_hypotheses.json", {"count": len(hyps),
                                      "hypotheses": hyps})
    # 41 findings.json
    _w_json("findings.json", {
        "module": NAME, "phase": PHASE, "plan_version": PLAN_VERSION,
        "engagement": scope.engagement, "generated": now_iso(),
        "mode": ctx.get("mode"), "count": len(F.items),
        "severity_counts": _sev_counts(F),
        "findings": F.items})
    # 42-48 renderers
    _w_text("CLOUD_FINDINGS.md", render_findings_md(
        scope, F, verdict_rows, chains, meta))
    _w_text("CLOUD_TEST_PLAN.md", render_test_plan(F, gates, matrix_rows))
    _w_text("CLOUD_REMEDIATION.md", render_remediation(F))
    _w_text("EXEC_SUMMARY.md", render_exec_summary(
        scope, F, posture, verdict_rows, meta))
    _w_text("CLOUD_KICKOFF.md", render_kickoff(scope, gates, conf))
    _w_text("CLOUD_PLAYBOOKS.md", render_playbooks())
    # 49-52 aux
    _w_text("cloud_gates.txt", "\n".join(
        ["RoE gates (default OFF - enable sirf written authorization par):"] +
        ["%s = %s # %s" % (g, str(bool(conf.get(g))).lower(), d)
         for g, d in ROE_GATES]) + "\n")
    _w_text("cloud_summary.txt", "\n".join([
        "P24 CLOUD SUMMARY - %s" % scope.engagement,
        "mode=%s probes=%s findings=%d matrix=%d chains=%d "
        "verdicts=%d posture_rows=%d" % (
            ctx.get("mode"), meta.get("probes_total", 0), len(F.items),
            len(matrix_rows), len(chains), len(verdict_rows),
            len(posture.get("rows", []))),
        "CONFIRMED=%d SUSPECTED=%d HARDENED=%d BLOCKED=%d SKIPPED=%d" % (
            len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
            len([r for r in verdict_rows if r["verdict"] == "SUSPECTED"]),
            len([r for r in verdict_rows if r["verdict"] == "HARDENED"]),
            len([r for r in verdict_rows if r["verdict"] == "BLOCKED"]),
            len([r for r in verdict_rows if r["verdict"] == "SKIPPED"]))]) + "\n")
    _w_text("cloud_live_endpoints.txt", "\n".join(sorted(set(
        [b.get("url") for b in results.get("baseline", {}).get("rows", [])
         if b.get("status") and b.get("status") < 400]))[:60]) + "\n")
    skipped = [g for g, _ in ROE_GATES if not bool(conf.get(g))]
    _w_text("cloud_skipped_waves.txt", "\n".join(
        ["RoE-gated manual waves (SKIPPED - document in test plan):"] +
        ["%s -> %s" % (g, dict(ROE_GATES)[g]) for g in skipped]) + "\n")

    # 53 feedforward (W)
    ff_map = {
        "to_phase25_controls": {
            "posture_rows": [{"url": r["url"], "score": r["score"],
                              "grade": r["grade"]}
                             for r in posture.get("rows", [])][:12],
            "provider_identified": [r.get("url") for r in
                                    (results.get("provider") or {})
                                    .get("rows", [])
                                    if r.get("identified")][:10]},
        "to_phase15_ssrf": {
            "cloud_header_shapes": sorted(set(sum(
                [r.get("provider_shapes", []) for r in
                 (results.get("provider") or {}).get("rows", [])],
                [])))[:18],
            "imds_playbook": [i for i, _, _ in IMDS_PLAYBOOK_ROWS][:8]},
        "to_phase11_access": {
            "bypass2_accepted": sorted(set(sum(
                [r.get("accepted_ids", []) for r in
                 (results.get("bypass2") or {}).get("rows", [])], [])))[:20],
            "console_exposed": [r.get("url") for r in
                                (results.get("console") or {}).get("rows", [])
                                if r.get("live") and
                                not r.get("auth_gate")][:10]},
        "to_phase12_inject": {
            "verbose_error_urls": [r.get("url") for r in
                                   (results.get("errors") or {})
                                   .get("rows", [])
                                   if r.get("verbose_hits")][:10],
            "secret_shape_urls": [r.get("url") for r in
                                  (results.get("secrets") or {})
                                  .get("rows", []) if r.get("shapes")][:10]},
        "to_phase9_auth": {
            "token_param_urls": [r.get("url") for r in
                                 (results.get("tokens") or {}).get("rows", [])
                                 if r.get("token_params")][:10],
            "console_urls": [r.get("url") for r in
                             (results.get("console") or {}).get("rows", [])
                             if r.get("live")][:10]},
        "to_phase7_js": {
            "secret_shape_urls": [r.get("url") for r in
                                  (results.get("secrets") or {})
                                  .get("rows", []) if r.get("shapes")][:10],
            "bucket_url_shapes": (results.get("storage") or {})
            .get("url_shapes", [])[:10]},
        "to_phase32_report": {
            "exec_summary": "EXEC_SUMMARY.md",
            "findings_json": "findings.json",
            "mode": ctx.get("mode")},
    }
    write_feedforward(out, "phase24", ff_map, notes=[
        "P24 v%s INERT cloud census (GET-only, canary %s)" % (
            PLAN_VERSION, CANARY_FAMILY),
        "%d artifacts | %d probes | gates default OFF" % (
            len(manifest) + 2, meta.get("probes_total", 0))])
    manifest += ["feedforward.json"]

    # MANIFEST
    write_manifest(out, "phase24", manifest, stats={
        "mode": ctx.get("mode"), "probes": meta.get("probes_total", 0),
        "findings": len(F.items), "matrix_rows": len(matrix_rows),
        "chains": len(chains), "verdicts": len(verdict_rows),
        "artifacts": len(manifest) + 1,
        "gates_on": [g for g, _ in ROE_GATES if bool(conf.get(g))],
        "duration_sec": round(meta.get("duration", 0.0), 1)}, notes=[
        "100% INERT detection-only | GET-only module | bodies/values "
        "REDACTED | NO IMDS/bucket-enum/takeover-claim/creds | zero egress "
        "| RWX 0777"])
    return manifest


def read_ff_safe(base_dir, scope):
    """read_feedforward wrapper (tolerant - missing dirs OK)."""
    try:
        return read_feedforward(base_dir, scope.engagement)
    except Exception:
        return {}


def _findings_from_verdicts(F, verdict_rows):
    """Verdict rows -> findings (key-mapped, dedup per endpoint+key)."""
    seen = set()
    for r in verdict_rows:
        v, u = r["verdict"], r.get("url", "?")
        key = {"C": {"CONFIRMED": "cloud_provider_identified",
                     "SUSPECTED": "cloud_provider_hint"},
               "D": {"CONFIRMED": "cloud_storage_shape",
                     "SUSPECTED": "cloud_endpoint_live"},
               "E": {"CONFIRMED": "cloud_bucket_acl_shape"},
               "F": {"SUSPECTED": "cloud_takeover_lead"},
               "G": {"SUSPECTED": "cloud_imds_header_shape"},
               "H": {"CONFIRMED": "cloud_secret_shape"},
               "I": {"CONFIRMED": "cloud_signedurl_unbounded",
                     "SUSPECTED": "cloud_signedurl_bounded"},
               "J": {"CONFIRMED": "cloud_container_live"},
               "K": {"CONFIRMED": "cloud_serverless_live"},
               "L": {"SUSPECTED": "cloud_cdn_cacheable",
                     "HARDENED": "cloud_cdn_safe"},
               "M": {"CONFIRMED": "cloud_cors_reflect",
                     "SUSPECTED": "cloud_cors_reflect",
                     "HARDENED": "cloud_cors_strict"},
               "N": {"SUSPECTED": "cloud_iam_shape"},
               "O": {"SUSPECTED": "cloud_dns_alias_lead",
                     "HARDENED": "cloud_dns_clean"},
               "P": {"CONFIRMED": "cloud_verbose_error",
                     "HARDENED": "cloud_error_masked"},
               "Q": {"CONFIRMED": "cloud_console_live",
                     "HARDENED": "cloud_console_absent"},
               "R": {"CONFIRMED": "cloud_cicd_live",
                     "SUSPECTED": "cloud_endpoint_live"},
               "S": {"CONFIRMED": "cloud_trust_echo",
                     "SUSPECTED": "cloud_token_param",
                     "HARDENED": "cloud_trust_clean"},
               "T": {"CONFIRMED": "cloud_spec_live",
                     "HARDENED": "cloud_spec_absent"},
               "U": {"CONFIRMED": "cloud_bypass2_accepted",
                     "BLOCKED": "cloud_bypass2_blocked",
                     "HARDENED": "cloud_bypass2_blocked"},
               }.get(r["stage"], {}).get(v)
        if not key or u == "*" or u == "?":
            continue
        dk = (key, u)
        if dk in seen:
            continue
        seen.add(dk)
        F.add(key, "%s [%s]" % (key, v), u, r.get("detail", ""))


# ===========================================================================
# RUN ORCHESTRATOR (stages A..Z, checkpointed, passive-aware)
# ===========================================================================
def run(cfg, scope, base_out):
    t_start = time.time()
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    conf = dict(DEFAULTS)
    for k in list(conf.keys()):
        if hasattr(cfg, k):
            conf[k] = getattr(cfg, k)

    head("Phase 24 - Cloud & Container Security (detection-only, INERT) "
         "(v%s) | %s" % (PLAN_VERSION, scope.describe()))
    warn("Cloud discipline: koi exploitation KABHI nahi (canary %s) | "
         "GET-only module (koi POST/PUT/DELETE/PATCH probe nahi) | "
         "bodies/secret-values REDACTED | NO IMDS probes | NO third-party "
         "bucket enumeration | NO takeover claims | NO creds sending | "
         "zero egress." % CANARY_FAMILY)
    on_gates = [g for g, _ in ROE_GATES if bool(conf.get(g))]
    if on_gates:
        warn("RoE gates ON: %s" % ", ".join(on_gates))
    else:
        info("Sab RoE gates OFF (detection-only census mode) - gated waves "
             "CLOUD_TEST_PLAN.md me documented hain.")
    info("caps: paths=%s | probes=%s | bypass2=%s | cold=%s" % (
        conf.get("cloud_paths_cap"), conf.get("cloud_probe_cap"),
        conf.get("cloud_bypass2_cap"), conf.get("cloud_cold_paths")))

    F = Findings()
    meta = {"probes_total": 0, "mode": "active"}
    ctxd = {"out": out, "coverage": {}, "mode": "active",
            "base_dir": os.path.join(base_out, scope.engagement)}
    results = {}
    passive = (not bool(getattr(cfg, "allow_active", True))) or \
        (getattr(scope, "allow_active", True) is False)
    if passive:
        ctxd["mode"] = "passive"
        meta["mode"] = "passive"
        warn("PASSIVE mode (allow_active=false) - offline mining only, "
             "0 network probes.")

    # ---------------- Stage A: discovery ----------------
    head("Stage A - Cloud surface discovery (15-module ff + miners + cold)")
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
        disc = discover_cloud_surface(ctxd, scope, conf)
        cp.mark(ckA, disc, summary="cloud surface")
    results["targets"] = disc.get("ranked", [])
    meta["sources"] = disc.get("sources", [])
    ok("targets=%d | sources: %s" % (len(results["targets"]),
                                     ", ".join(meta["sources"][:6])))

    # ---------------- Stage B: baseline + WAF ----------------
    head("Stage B - Baseline + WAF + soft-404")
    ckB = "stageB:baseline"
    if cp.is_done(ckB):
        results["baseline"] = cp.result_of(ckB) or {"rows": [], "waf": []}
        ok("Replayed baseline (checkpoint)")
    elif passive:
        results["baseline"] = {"rows": [], "waf": []}
        warn("passive: baseline skipped (0 probes)")
    else:
        results["baseline"] = baseline_and_waf(
            http, disc.get("targets", []), conf)
        cp.mark(ckB, results["baseline"], summary="baseline+waf")
    live_n = len([b for b in results["baseline"].get("rows", [])
                  if b.get("status") and b.get("status") < 400])
    ok("baseline rows=%d live=%d" % (
        len(results["baseline"].get("rows", [])), live_n))

    # ---------------- Stage C: provider fingerprint ----------------
    head("Stage C - Cloud provider fingerprint census (18 markers)")
    ckC = "stageC:provider"
    if cp.is_done(ckC):
        results["provider"] = cp.result_of(ckC) or {}
        ok("Replayed provider census (checkpoint)")
    elif passive:
        results["provider"] = {"rows": [], "note": "passive"}
    else:
        results["provider"] = provider_census(http, disc.get("targets", []),
                                              conf)
        cp.mark(ckC, results["provider"], summary="provider census")
    meta["probes_total"] += len(results["provider"].get("rows", []))

    # ---------------- Stage D: storage shapes ----------------
    head("Stage D - Storage/bucket shape census (GATED)")
    ckD = "stageD:storage"
    if cp.is_done(ckD):
        results["storage"] = cp.result_of(ckD) or {}
        ok("Replayed storage census (checkpoint)")
    elif passive:
        results["storage"] = {"rows": [], "url_shapes": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_bucket_probe"):
        results["storage"] = storage_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" % results["storage"].get("skipped_note",
                                                               ""))
    else:
        results["storage"] = storage_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckD, results["storage"], summary="storage census")
    meta["probes_total"] += len(results["storage"].get("rows", []))

    # ---------------- Stage E: bucket ACL shapes ----------------
    head("Stage E - Bucket ACL/error-shape census (GATED)")
    ckE = "stageE:bucket"
    if cp.is_done(ckE):
        results["bucket"] = cp.result_of(ckE) or {}
        ok("Replayed bucket census (checkpoint)")
    elif passive:
        results["bucket"] = {"rows": [],
                             "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_bucket_probe"):
        results["bucket"] = bucket_acl_census(http, disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["bucket"].get("skipped_note",
                                                              ""))
    else:
        results["bucket"] = bucket_acl_census(http, disc.get("targets", []),
                                              conf)
        cp.mark(ckE, results["bucket"], summary="bucket census")
    meta["probes_total"] += len(results["bucket"].get("rows", []))

    # ---------------- Stage F: takeover surface ----------------
    head("Stage F - Subdomain-takeover fingerprint census (GATED)")
    ckF = "stageF:takeover"
    if cp.is_done(ckF):
        results["takeover"] = cp.result_of(ckF) or {}
        ok("Replayed takeover census (checkpoint)")
    elif passive:
        results["takeover"] = {"rows": [],
                               "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_takeover_probe"):
        results["takeover"] = takeover_census(http, disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" %
             results["takeover"].get("skipped_note", ""))
    else:
        results["takeover"] = takeover_census(http, disc.get("targets", []),
                                              conf)
        cp.mark(ckF, results["takeover"], summary="takeover census")
    meta["probes_total"] += len(results["takeover"].get("rows", []))

    # ---------------- Stage G: IMDS playbook (documented) ----------------
    head("Stage G - IMDS/metadata playbook (DOCUMENTED-ONLY, 0 probes)")
    ckG = "stageG:imds"
    if cp.is_done(ckG):
        results["imds"] = cp.result_of(ckG) or {}
    elif passive:
        results["imds"] = {"rows": [], "note": "passive"}
    else:
        results["imds"] = imds_documented(http, disc.get("targets", []), conf)
        cp.mark(ckG, results["imds"], summary="imds playbook")
    meta["probes_total"] += len(results["imds"].get("rows", []))
    F.add("cloud_imds_documented",
          "IMDS playbook documented (8 rows, FORBIDDEN-AUTO)", "*",
          "metadata probes KABHI network par nahi (P15 handoff; "
          "CLOUD_PLAYBOOKS.md)")
    F.add("cloud_creds_documented",
          "Cloud-cred playbook documented (8 rows)", "*",
          "creds KABHI network par nahi (stuffing FORBIDDEN-AUTO)")

    # ---------------- Stage H: cloud secrets ----------------
    head("Stage H - Cloud secrets census (34 shapes, values REDACTED)")
    ckH = "stageH:secrets"
    if cp.is_done(ckH):
        results["secrets"] = cp.result_of(ckH) or {}
    elif passive:
        results["secrets"] = {"rows": [], "note": "passive"}
    else:
        results["secrets"] = secrets_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckH, results["secrets"], summary="secrets census")
    meta["probes_total"] += len(results["secrets"].get("rows", []))

    # ---------------- Stage I: signed-URL lifecycle ----------------
    head("Stage I - Signed-URL lifecycle census (passive parse)")
    ckI = "stageI:signedurl"
    if cp.is_done(ckI):
        results["signedurl"] = cp.result_of(ckI) or {}
    elif passive:
        results["signedurl"] = {"rows": [], "note": "passive"}
    else:
        results["signedurl"] = signedurl_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckI, results["signedurl"], summary="signedurl census")
    meta["probes_total"] += len(results["signedurl"].get("rows", []))

    # ---------------- Stage J: container/K8s ----------------
    head("Stage J - Container/K8s exposure census (GATED)")
    ckJ = "stageJ:container"
    if cp.is_done(ckJ):
        results["container"] = cp.result_of(ckJ) or {}
        ok("Replayed container census (checkpoint)")
    elif passive:
        results["container"] = {"rows": [],
                                "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_container_probe"):
        results["container"] = container_census(http, disc.get("targets", []),
                                                conf)
        warn("SKIPPED (gate OFF): %s" %
             results["container"].get("skipped_note", ""))
    else:
        results["container"] = container_census(http, disc.get("targets", []),
                                                conf)
        cp.mark(ckJ, results["container"], summary="container census")
    meta["probes_total"] += len(results["container"].get("rows", []))

    # ---------------- Stage K: serverless ----------------
    head("Stage K - Serverless/API-GW census (GATED)")
    ckK = "stageK:serverless"
    if cp.is_done(ckK):
        results["serverless"] = cp.result_of(ckK) or {}
        ok("Replayed serverless census (checkpoint)")
    elif passive:
        results["serverless"] = {"rows": [],
                                 "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_serverless_probe"):
        results["serverless"] = serverless_census(http, disc.get("targets",
                                                                 []), conf)
        warn("SKIPPED (gate OFF): %s" %
             results["serverless"].get("skipped_note", ""))
    else:
        results["serverless"] = serverless_census(http, disc.get("targets",
                                                                 []), conf)
        cp.mark(ckK, results["serverless"], summary="serverless census")
    meta["probes_total"] += len(results["serverless"].get("rows", []))

    # ---------------- Stage L: CDN/cache ----------------
    head("Stage L - CDN/cache posture census (passive-GET)")
    ckL = "stageL:cdn"
    if cp.is_done(ckL):
        results["cdn"] = cp.result_of(ckL) or {}
    elif passive:
        results["cdn"] = {"rows": [], "note": "passive"}
    else:
        results["cdn"] = cdn_census(http, disc.get("targets", []), conf)
        cp.mark(ckL, results["cdn"], summary="cdn census")
    meta["probes_total"] += len(results["cdn"].get("rows", []))

    # ---------------- Stage M: storage CORS ----------------
    head("Stage M - Storage CORS misconfig grading (GATED)")
    ckM = "stageM:cors"
    if cp.is_done(ckM):
        results["cors"] = cp.result_of(ckM) or {}
        ok("Replayed cors census (checkpoint)")
    elif passive:
        results["cors"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_cors_probe"):
        results["cors"] = storage_cors_census(http, disc.get("targets", []),
                                              conf)
        warn("SKIPPED (gate OFF): %s" % results["cors"].get("skipped_note",
                                                            ""))
    else:
        results["cors"] = storage_cors_census(http, disc.get("targets", []),
                                              conf)
        cp.mark(ckM, results["cors"], summary="cors census")
    meta["probes_total"] += len(results["cors"].get("rows", []))

    # ---------------- Stage N: IAM shapes ----------------
    head("Stage N - IAM/ARN shape census (sha1-only REDACTED)")
    ckN = "stageN:iam"
    if cp.is_done(ckN):
        results["iam"] = cp.result_of(ckN) or {}
    elif passive:
        results["iam"] = {"rows": [], "note": "passive"}
    else:
        results["iam"] = iam_census(http, disc.get("targets", []), conf)
        cp.mark(ckN, results["iam"], summary="iam census")
    meta["probes_total"] += len(results["iam"].get("rows", []))

    # ---------------- Stage O: DNS/alias ----------------
    head("Stage O - DNS/alias differential census (GATED, in-scope only)")
    ckO = "stageO:dns"
    if cp.is_done(ckO):
        results["dns"] = cp.result_of(ckO) or {}
        ok("Replayed dns census (checkpoint)")
    elif passive:
        results["dns"] = {"rows": [],
                          "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_dns_probe"):
        results["dns"] = dns_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["dns"].get("skipped_note",
                                                           ""))
    else:
        results["dns"] = dns_census(http, disc.get("targets", []), conf)
        cp.mark(ckO, results["dns"], summary="dns census")
    meta["probes_total"] += len(results["dns"].get("rows", []))

    # ---------------- Stage P: cloud errors ----------------
    head("Stage P - Cloud error-shape census (GATED)")
    ckP = "stageP:errors"
    if cp.is_done(ckP):
        results["errors"] = cp.result_of(ckP) or {}
        ok("Replayed error census (checkpoint)")
    elif passive:
        results["errors"] = {"rows": [],
                             "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_error_probe"):
        results["errors"] = error_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["errors"].get("skipped_note",
                                                              ""))
    else:
        results["errors"] = error_census(http, disc.get("targets", []), conf)
        cp.mark(ckP, results["errors"], summary="error census")
    meta["probes_total"] += len(results["errors"].get("rows", []))

    # ---------------- Stage Q: consoles ----------------
    head("Stage Q - Cloud console/login fingerprint census (GATED)")
    ckQ = "stageQ:console"
    if cp.is_done(ckQ):
        results["console"] = cp.result_of(ckQ) or {}
        ok("Replayed console census (checkpoint)")
    elif passive:
        results["console"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_console_probe"):
        results["console"] = console_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" %
             results["console"].get("skipped_note", ""))
    else:
        results["console"] = console_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckQ, results["console"], summary="console census")
    meta["probes_total"] += len(results["console"].get("rows", []))

    # ---------------- Stage R: CI/CD + IaC ----------------
    head("Stage R - CI/CD + IaC artifact census (GATED)")
    ckR = "stageR:cicd"
    if cp.is_done(ckR):
        results["cicd"] = cp.result_of(ckR) or {}
        ok("Replayed cicd census (checkpoint)")
    elif passive:
        results["cicd"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_artifact_probe"):
        results["cicd"] = cicd_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["cicd"].get("skipped_note",
                                                            ""))
    else:
        results["cicd"] = cicd_census(http, disc.get("targets", []), conf)
        cp.mark(ckR, results["cicd"], summary="cicd census")
    meta["probes_total"] += len(results["cicd"].get("rows", []))

    # ---------------- Stage S: token + trust echo ----------------
    head("Stage S - API-token surface + header-trust echo (GATED)")
    ckS = "stageS:tokens"
    if cp.is_done(ckS):
        results["tokens"] = cp.result_of(ckS) or {}
        ok("Replayed token census (checkpoint)")
    elif passive:
        results["tokens"] = {"rows": [],
                             "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_header_echo"):
        results["tokens"] = token_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["tokens"].get("skipped_note",
                                                              ""))
    else:
        results["tokens"] = token_census(http, disc.get("targets", []), conf)
        cp.mark(ckS, results["tokens"], summary="token census")
    meta["probes_total"] += len(results["tokens"].get("rows", []))

    # ---------------- Stage T: spec + gql/ws rollup ----------------
    head("Stage T - Cloud API spec (GATED) + GQL/WS rollup (names-only)")
    ckT = "stageT:spec"
    if cp.is_done(ckT):
        results["spec"] = cp.result_of(ckT) or {}
        ok("Replayed spec census (checkpoint)")
    elif passive:
        results["spec"] = {"rows": [],
                           "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_spec_probe"):
        results["spec"] = spec_census(http, disc.get("targets", []), conf)
        warn("SKIPPED (gate OFF): %s" % results["spec"].get("skipped_note",
                                                            ""))
    else:
        results["spec"] = spec_census(http, disc.get("targets", []), conf)
        cp.mark(ckT, results["spec"], summary="spec census")
    meta["probes_total"] += len(results["spec"].get("rows", []))

    # ---------------- Stage U: bypass2 ----------------
    head("Stage U - Bypass matrix v2: 20 cloud-bypass shapes (GATED)")
    ckU = "stageU:bypass2"
    if cp.is_done(ckU):
        results["bypass2"] = cp.result_of(ckU) or {}
        ok("Replayed bypass2 census (checkpoint)")
    elif passive:
        results["bypass2"] = {"rows": [],
                              "skipped_note": "passive mode (0 probes)"}
    elif not conf.get("cloud_allow_bypass2"):
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        warn("SKIPPED (gate OFF): %s" %
             results["bypass2"].get("skipped_note", ""))
    else:
        results["bypass2"] = bypass2_census(http, disc.get("targets", []),
                                            conf)
        cp.mark(ckU, results["bypass2"], summary="bypass2 census")
    meta["probes_total"] += len(results["bypass2"].get("rows", []))

    # ---------------- Stage V-Z offline engines ----------------
    head("Stage V/W/X/Y - Posture composite + chains + verdict + matrix")
    posture = posture_composite(results)
    ff_all = read_ff_safe(ctxd.get("base_dir"), scope)
    chains = build_chains(results, ff_all)
    verdict_rows = verdict_engine(results)
    matrix_rows = build_matrix()
    gql_mut = gql_mutations_from_artifacts(ctxd.get("base_dir"))
    ws_endpoints = ws_surface_from_artifacts(ctxd.get("base_dir"))

    # findings from verdict rows
    _findings_from_verdicts(F, verdict_rows)
    # posture findings
    for w in posture.get("weak", [])[:8]:
        F.add("cloud_posture_weak", "Cloud posture WEAK",
              w.get("url", ""), "score=%d/14 (points: %s)" % (
                  w["score"], ",".join(k for k, v in w["points"].items()
                                       if v is False)))
    if len(posture.get("strong", [])) >= 1:
        F.add("cloud_posture_strong", "Cloud posture STRONG",
              posture["strong"][0].get("url", ""),
              "score>=%d/14 positive controls dominant" %
              posture["strong"][0]["score"])
    # platform fp
    probe_texts = [(b.get("title") or "") for b in
                   results.get("baseline", {}).get("rows", [])] + \
                  [" ".join(t.get("kinds", [])) for t in
                   results.get("targets", [])] + \
                  [json.dumps(results.get("provider", {}))[:2000]]
    platform = platform_fingerprint(probe_texts)
    if platform.get("shapes"):
        F.add("cloud_platform_fp", "Cloud/platform fingerprint shapes", "*",
              "shapes=%s" % ",".join(platform["shapes"][:8]))
    # gql/ws surface findings
    if gql_mut.get("count"):
        F.add("cloud_gql_mutation_surface", "GraphQL writable-mutation "
              "surface (names-only)", "*",
              "%d mutation names (NEVER sent)" % gql_mut["count"])
    if ws_endpoints.get("count"):
        F.add("cloud_ws_surface", "WebSocket endpoint census (frames "
              "NEVER)", "*", "%d ws endpoints" % ws_endpoints["count"])
    # targeted findings
    for r in (results.get("cors") or {}).get("rows", []):
        if r.get("reflect_any"):
            F.add("cloud_cors_reflect", "Storage CORS canary-origin "
                  "reflection", r.get("url", ""), "grade=%s" %
                  r.get("grade"))
    for r in (results.get("secrets") or {}).get("rows", []):
        for s in (r.get("shapes") or [])[:6]:
            if s.get("shape") == "db-url-creds":
                F.add("cloud_secret_ip", "DB-creds/internal shape",
                      r.get("url", ""), "shape=%s (sha1 %s)" %
                      (s.get("shape"), s.get("sha1_12")))
    for r in (results.get("bypass2") or {}).get("rows", []):
        if r.get("accepted_count"):
            F.add("cloud_bypass2_accepted", "Cloud-bypass shapes accepted",
                  r.get("url", ""), "ids=%s" %
                  ",".join(r.get("accepted_ids", [])[:8]))

    # ---------------- Stage Z: final secrets guard ----------------
    payloads = [("CLOUD_FINDINGS.md", pii_redact(render_findings_md(
        scope, F, verdict_rows, chains, meta)))]
    guard = secrets_guard(payloads)
    if guard.get("hits"):
        F.add("cloud_secret_guard_hit", "Secret-guard sweep triggered",
              "*", "artifact shapes redacted (CWE-200 aid)")

    # ---------------- Stage Z: reports + handoff ----------------
    head("Stage Z - Reports (54 artifacts) + feedforward + manifest")
    meta["duration"] = time.time() - t_start
    manifest_files = write_reports(out, scope, F, ctxd, meta, results, disc,
                                   conf, chains, verdict_rows, matrix_rows,
                                   posture, platform, guard,
                                   build_hypotheses(results, posture),
                                   gql_mut, ws_endpoints)
    cp.mark_complete()
    ok("%d artifacts | findings=%d | verdicts=%d | chains=%d | matrix=%d" % (
        len(manifest_files) + 2, len(F.items), len(verdict_rows),
        len(chains), len(matrix_rows)))
    sc = _sev_counts(F)
    ok("severity: C=%d H=%d M=%d L=%d I=%d | CONFIRMED=%d HARDENED=%d" % (
        sc.get("critical", 0), sc.get("high", 0), sc.get("medium", 0),
        sc.get("low", 0), sc.get("info", 0),
        len([r for r in verdict_rows if r["verdict"] == "CONFIRMED"]),
        len([r for r in verdict_rows if r["verdict"] == "HARDENED"])))
    dim("out: %s" % out)
    return out


# ===========================================================================
# CLI
# ===========================================================================
def main():
    print("WASP mod_cloud.py (Phase 24 - Cloud & Container Security, "
          "v%s)" % PLAN_VERSION)
    print("  run       : python3 wasp.py run --module 24   (ya --module "
          "cloud)")
    print("  self-test : python3 test_mod_cloud.py")
    print("\n  RoE gates (config.json):")
    for g, d in ROE_GATES:
        print("    %s=false (default) # %s" % (g, d))
    print("  Safety: koi exploitation KABHI nahi (canary %s) | GET-only "
          "module | bodies/secret-values REDACTED | NO IMDS probes | "
          "NO third-party bucket enumeration | NO takeover claims | "
          "NO creds sending | zero egress" % CANARY_FAMILY)
    print("  v30 ULTRA: 26 stages (A..Z) | 12 RoE gates | 20-secret "
          "bypass2 | 8 IMDS + 8 creds + 6 container + 12 takeover "
          "playbook rows (documented) | 242-row x 22-family matrix | "
          "28 kill-chains | 54 artifacts | 14-point posture composite | "
          "34 secret-shapes | platform fp")


if __name__ == "__main__":
    main()
