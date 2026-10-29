#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WASP CORE v2.1.0-ULTRA  -  Web Assessment Script Pack (shared engine)
=====================================================================
Authorized security testing only.  Har module isi engine ko import karta hai.

Ye engine kya deta hai:
  * Scope firewall        - authorization + host/URL allow-list (IP, port, wildcard, exclude)
  * Seed targets          - scope.json ke "targets" se canonical base URLs
  * Rate-limited HTTP     - adaptive throttling, jitter, retries, Retry-After, gzip
  * Request budget        - hard kill-switch (global)
  * Identity / sessions   - multi-account jars + disk persistence (resumable logins)
  * Evidence engine       - requests.jsonl + raw bodies + replayable curl commands
  * Cross-module probe cache - ek hi host dobara probe na ho
  * Soft-404 engine       - shared catch-all / wildcard response detection
  * Checkpoint / resume   - Ctrl+C safe, crash safe, power-loss safe
  * Feed-forward writer   - har phase apna output->next-phase map likhta hai
  * Console UX            - coloured levels + progress bars

ULTRA v2.1 ADDITIONS (purani API 100% same rakhi gayi hai - drop-in compatible):
  * Profiles              - stealth / normal / fast / audit presets (apply_profile)
  * Secrets engine        - SECRET_PATTERNS DB + scan_secrets() (hamesha REDACTED)
  * Findings engine       - make_finding + severity scale + aggregate_findings +
                            write_findings_report() -> findings.json + FINDINGS.md
  * Robots/Sitemap        - parse_robots / parse_sitemap / fetch_robots_sitemaps
  * Wordlist engine       - EMBEDDED_CONTENT_WORDS + load_words (WASP_WORDS = cap)
  * Analyzer helpers      - waf_signature, analyze_security_headers,
                            analyze_cookie_flags, redirect_chain, dns_resolve,
                            extract_links / extract_js_urls / extract_comments /
                            meta_generator / find_csrf
  * JWT decode            - jwt_decode() (verification nahi - sirf safe decode)
  * Raw request parser    - parse_raw_request() (Burp/ZAP raw paste import)
  * SessionStore          - identity cookies disk par (_state/sessions.json)
  * Sensitive params      - SENSITIVE_PARAM_HINTS + is_sensitive_param()
  * Evidence summary      - Evidence.summary() + collision-proof body storage
  * Stats                 - RateLimiter.snapshot() / Budget.snapshot() /
                            HttpClient.stats_snapshot() / head() / options()
  * BUGFIX 1              - allow_redirects=False ab sach me redirect FOLLOW NAHI
                            karta (v2 me ulta opener select ho raha tha)
  * BUGFIX 2              - evidence raw bodies ab overwrite nahi hote (unique -N)
"""
import os, sys, re, json, time, ssl, socket, zlib, gzip, hashlib, threading, random
import string, signal, atexit, base64, struct, io, traceback, ipaddress
import urllib.request, urllib.parse, urllib.error, http.cookiejar, http.client
from datetime import datetime, timezone

VERSION = "2.1.0"
WASP_DIR = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "rate_limit": 4.0,          # requests/second (global, adaptive)
    "jitter": 0.35,             # +/- fraction of interval (evasion of naive RL)
    "concurrency": 8,           # worker threads
    "timeout": 12,              # per-request timeout (s)
    "retries": 2,               # retries on transient failures
    "backoff": 1.5,             # exponential backoff base
    "max_requests": 20000,      # hard request budget (kill switch)
    "allow_write_http": False,  # LAYER 4: false = targets par sirf GET/HEAD/OPTIONS (read-only)
    "verify_tls": False,        # lab default; cert still recorded
    "allow_active": True,       # active modules allowed
    "allow_destructive": False, # never unless RoE says so
    "redirects": 5,             # max redirect hops
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "proxy": None,
    "resolvers": ["1.1.1.1", "8.8.8.8"],
    "respect_robots": False,
    "custom_headers": {},
    "accept_encoding": "gzip, deflate",
    "save_bodies": True,        # store raw bodies as evidence
    "max_body_store": 262144,   # bytes of body kept in evidence (per response)
    "adaptive_throttle": True,  # auto-slow down when WAF/429 signs appear
    "negative_cache": True,     # remember dead host:port, stop retrying
    "retry_status": [429, 500, 502, 503, 504],
    # ---- ULTRA v2.1 additions (additive; purani keys/behaviour unchanged) ----
    "profile": "normal",        # stealth | normal | fast | audit (apply_profile)
    "rotate_user_agents": False,# per-request random UA (stealth profile)
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "save_replays": True,       # curl replay scripts in evidence/replay/
    "findings_min_severity": "info",  # aggregate/report threshold
    "content_wordlist_file": None,    # extra wordlist for content phase
}


class Cfg:
    """Attribute-based config (modules do getattr(cfg, 'x', default))."""

    def __init__(self, path=None):
        self.data = dict(DEFAULT_CONFIG)
        if path and os.path.exists(path):
            try:
                user = json.load(open(path))
                if isinstance(user, dict):
                    self.data.update(user)
            except Exception as e:
                print("[!] config.json parse failed (%s) -> using defaults" % e)
        for k, v in self.data.items():
            setattr(self, k, v)
        self._lock = threading.Lock()

    def get(self, key, default=None):
        return getattr(self, key, default)

    def dump(self, path):
        save_json(path, self.data)


# ----------------------------------------------------------------------------
# PROFILES (ULTRA) - ek line me poora engine retune
# ----------------------------------------------------------------------------
PROFILES = {
    "normal": {},
    "stealth": {
        "rate_limit": 1.2, "jitter": 0.55, "concurrency": 2, "timeout": 20,
        "retries": 3, "rotate_user_agents": True, "adaptive_throttle": True,
    },
    "fast": {
        "rate_limit": 10.0, "jitter": 0.20, "concurrency": 16, "timeout": 8,
        "retries": 1,
    },
    "audit": {
        "save_bodies": True, "save_replays": True, "max_body_store": 1048576,
    },
}


def apply_profile(cfg, name):
    """Profile preset ko cfg par apply karo (existing keys hi override hote hain)."""
    name = (name or "normal").lower().strip()
    if name not in PROFILES:
        return False
    cfg.data.update(PROFILES[name])
    cfg.data["profile"] = name
    for k, v in PROFILES[name].items():
        setattr(cfg, k, v)
    setattr(cfg, "profile", name)
    return True


# ----------------------------------------------------------------------------
# FINDINGS SCALE (ULTRA) - shared severity vocabulary
# ----------------------------------------------------------------------------
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def make_finding(module, title, severity="info", target=None, detail=None,
                 evidence=None, remediation=None, confidence=None, **extra):
    """Standard finding dict - sab modules isi se banayein taaki aggregate ho sake."""
    sev = (severity or "info").lower().strip()
    if sev in ("crit",):
        sev = "critical"
    if sev not in SEV_ORDER:
        sev = "info"
    f = {"module": module, "title": title, "severity": sev, "target": target,
         "detail": detail, "evidence": evidence, "remediation": remediation,
         "confidence": confidence, "found_at": now_iso()}
    for k, v in extra.items():
        if v is not None:
            f[k] = v
    return f


# ----------------------------------------------------------------------------
# SCOPE - the authorization firewall
# ----------------------------------------------------------------------------
class ScopeError(Exception):
    pass


class Scope:
    """scope.json -> authorization + target allow-list.

    {
      "engagement": "name",
      "authorized": true,
      "authorization_reference": "program url / SOW / ticket + date",
      "targets": ["https://app.example.com", "http://127.0.0.1:8443"],
      "domains": ["example.com"],          # apex + all subdomains
      "wildcards": ["*.example.com"],
      "excludes": ["blog.example.com"],
      "ips": ["127.0.0.1"],
      "notes": "no DoS, manual-only endpoints, ..."
    }
    """

    def __init__(self, path):
        if not os.path.exists(path):
            raise ScopeError("scope file not found: %s" % path)
        self.path = path
        try:
            self.raw = json.load(open(path))
        except Exception as e:
            raise ScopeError("scope.json is not valid JSON: %s" % e)
        self.authorized = bool(self.raw.get("authorized", False))
        self.engagement = self.raw.get("engagement", "unnamed")
        self.ref = self.raw.get("authorization_reference", "")
        self.notes = self.raw.get("notes", "")
        self.targets = [normalize_url(t) for t in self.raw.get("targets", []) if t]
        self.domains = [d.lower().strip(".") for d in self.raw.get("domains", []) if d]
        self.wildcards = [w.lower().strip() for w in self.raw.get("wildcards", []) if w]
        self.excludes = [e.lower().strip() for e in self.raw.get("excludes", []) if e]
        self.ips = [str(i).strip() for i in self.raw.get("ips", []) if i]
        if not self.authorized:
            raise ScopeError("scope.json -> authorized=false. Testing is NOT permitted. Aborting.")
        if not (self.targets or self.domains or self.wildcards or self.ips):
            raise ScopeError("scope.json has no targets/domains/wildcards/ips. Nothing authorized.")
        # ULTRA BUGFIX 3: jo hosts targets me EXPLICITLY likhe hain wo khud authorized
        # hain (v2 me domains/ips me na hon to seed_urls() khaali aa jaata tha -
        # apna hi target firewall se block ho jaata tha)
        self._target_hosts = set()
        for t in self.targets:
            h = host_of(t)
            if h:
                self._target_hosts.add(h.lower())

    # ---------- allow-list logic ----------
    def _host_allowed(self, host):
        host = (host or "").lower().strip().strip(".")
        host = host.split(":")[0]
        if not host:
            return False
        for ex in self.excludes:
            ex = ex.lstrip("*.")
            if host == ex or host.endswith("." + ex):
                return False
        if host in getattr(self, "_target_hosts", ()):  # ULTRA BF3: explicit targets
            return True
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        for w in self.wildcards:
            base = w.lstrip("*.")
            if host == base or host.endswith("." + base):
                return True
        if host in self.ips or (is_ip(host) and host in self.ips):
            return True
        return False

    def check_url(self, url, raise_on_fail=True):
        host = host_of(url)
        ok = bool(host) and self._host_allowed(host)
        if not ok and raise_on_fail:
            raise ScopeError("OUT-OF-SCOPE blocked: %s (host=%s)" % (url, host))
        return ok

    def check_host(self, host, raise_on_fail=True):
        ok = self._host_allowed(host)
        if not ok and raise_on_fail:
            raise ScopeError("OUT-OF-SCOPE blocked: host=%s" % host)
        return ok

    def filter_hosts(self, hosts):
        ins, outs = [], []
        for h in hosts:
            (ins if self._host_allowed(h) else outs).append(h)
        return ins, outs

    # ---------- canonical seeds (fixes IP/port-only + multi-target scopes) ----
    def root_domains(self):
        out = []
        for d in self.domains:
            if d not in out:
                out.append(d)
        for w in self.wildcards:
            b = w.lstrip("*.")
            if b not in out:
                out.append(b)
        return out

    def seed_urls(self):
        """Base URLs to start every active module from (highest priority first)."""
        seeds = list(self.targets)
        if not seeds:
            for d in self.root_domains():
                seeds.append("https://%s" % d)
            for ip in self.ips:
                seeds.append("http://%s" % ip)
        # dedupe, scope-filter
        seen, out = set(), []
        for u in seeds:
            u = normalize_url(u).rstrip("/")
            if u in seen:
                continue
            seen.add(u)
            if self.check_url(u, raise_on_fail=False):
                out.append(u)
        return out

    def describe(self):
        return ("engagement=%s | targets=%d | domains=%s | ips=%s | excludes=%s"
                % (self.engagement, len(self.seed_urls()),
                   ",".join(self.domains) or "-", ",".join(self.ips) or "-",
                   ",".join(self.excludes) or "-"))

    # ---------- ULTRA: hygiene validation (verify/doctor use karte hain) ------
    def all_hosts(self):
        """Scope ke saare candidate hosts (targets+domains+wildcards+ips)."""
        hosts = set()
        for t in self.targets:
            h = host_of(t)
            if h:
                hosts.add(h)
        hosts.update(self.domains)
        hosts.update(w.lstrip("*.").strip() for w in self.wildcards if w)
        hosts.update(self.ips)
        return sorted(h for h in hosts if h)

    def validate(self):
        """(errors, warnings) - authorization hygiene issues, firewall nahi.
        errors  -> testing shuru karne se pehle fix karo
        warnings -> dhyan do, permissive ho sakte hain"""
        errs, warns = [], []
        if not str(self.ref or "").strip():
            warns.append("authorization_reference khali hai - proof-of-auth record karo")
        elif str(self.ref).upper().startswith("REPLACE"):
            warns.append("authorization_reference abhi placeholder hai - real SOW/program link daalo")
        for w in self.wildcards:
            base = w.lstrip("*.").strip()
            if base and base.count(".") <= 0:
                errs.append("Wildcard bahut broad hai: %s (TLD-level wildcard = poora internet)" % w)
        if not self.targets:
            warns.append("koi explicit targets nahi - seeds domains/ips se https pe banenge "
                         "(http-only app ho to targets me daalo)")
        for t in self.targets:
            if t.startswith("http://"):
                warns.append("target plain http:// hai: %s (on-path tampering possible)" % t)
        for ip in self.ips:
            try:
                if ipaddress.ip_address(ip).is_private:
                    warns.append("private IP scope me hai: %s (lab internal - intended?)" % ip)
            except ValueError:
                errs.append("invalid IP scope me hai: %s" % ip)
        for d in self.domains:
            for ex in self.excludes:
                if d == ex or d.endswith("." + ex.lstrip("*.")):
                    warns.append("domain '%s' aur exclude '%s' overlap karte hain" % (d, ex))
        if not self.notes:
            warns.append("scope notes khali - RoE (no-DoS, rate caps) likh do")
        return errs, warns

# ----------------------------------------------------------------------------
# UTIL
# ----------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def port_of(url, default=None):
    try:
        p = urllib.parse.urlsplit(url).port
        if p:
            return p
        return 443 if urllib.parse.urlsplit(url).scheme == "https" else 80 if default is None else default
    except Exception:
        return default


def is_ip(s):
    s = (s or "").strip()
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except OSError:
        return False


def normalize_url(url, scheme="https"):
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.I):
        url = scheme + "://" + url.lstrip("/")
    return url.split("#")[0]


def shannon_entropy(s):
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def _digest(algo, b):
    if isinstance(b, str):
        b = b.encode("utf-8", "ignore")
    h = hashlib.new(algo)
    h.update(b)
    return h.hexdigest()


def sha1(b):
    return _digest("sha1", b)


def sha256(b):
    return _digest("sha256", b)


def md5(b):
    return _digest("md5", b)


def rand_str(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def rand_token(n=24):
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")[:n]


# ---------------------------------------------------------------------------
# RWX STANDING RULE (user memory): pentest ke SAARE result/output files ko
# read+write+execute (0777 rwxrwxrwx) permission milni chahiye. save_json /
# save_text / ensure_dir / evidence-writers sab is helper se enforce karte
# hain - matlab findings.json, module outputs, raw bodies, replay scripts,
# sessions.json: HAR result file + uska folder automatically rwx hoga.
# ---------------------------------------------------------------------------
def _rwx_result(path):
    """Result file/folder par rwxrwxrwx (0777) enforce (best-effort, Windows-safe)."""
    try:
        os.chmod(path, 0o777)
    except Exception:
        pass


def save_json(path, obj):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
        _rwx_result(d)                      # RWX RULE: result folder rwx
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    os.replace(tmp, path)
    _rwx_result(path)                       # RWX RULE: result file rwx


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    try:
        return json.load(open(path))
    except Exception:
        return default


def save_text(path, text):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
        _rwx_result(d)                      # RWX RULE: result folder rwx
    with open(path, "w") as f:
        f.write(text if text is not None else "")
    _rwx_result(path)                       # RWX RULE: result file rwx


def truncate(s, n=4000):
    s = s or ""
    return s if len(s) <= n else s[:n] + "\n...[truncated %d bytes]..." % (len(s) - n)


def redact(secret, keep=4):
    """Mask a secret so evidence never stores live credentials verbatim."""
    s = str(secret or "")
    if len(s) <= keep * 2:
        return s[:2] + "*" * max(0, len(s) - 2)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def median(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return 0.0
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def mad(xs, med=None):
    xs = [x for x in xs if x is not None]
    if not xs:
        return 0.0
    med = median(xs) if med is None else med
    return median([abs(x - med) for x in xs])


def robust_z(x, med, m):
    """Modified z-score (Iglewicz-Hoban). |z|>3.5 => outlier."""
    if m <= 0:
        return 0.0
    return 0.6745 * (x - med) / m


def murmur3_32(data, seed=0):
    """Pure-python MurmurHash3 x86_32 - needed for Shodan-style favicon hashes."""
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length & ~0x3
    for i in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


def favicon_hash(body):
    """Shodan-style favicon hash (mmh3 of base64 with newlines every 76 chars)."""
    b64 = base64.b64encode(body or b"").decode()
    wrapped = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76)) + "\n"
    return murmur3_32(wrapped)


# ---- ULTRA utils ------------------------------------------------------------
def env_int(name, default=0):
    """WASP_WORDS jaisi env vars ko int me lo (fail-safe)."""
    try:
        v = os.environ.get(name, "").strip()
        return int(v) if v else int(default)
    except (TypeError, ValueError):
        return int(default)


def env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return v.strip().lower() in ("1", "true", "yes", "on")


def now_human():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def human_size(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%.1f%s" % (n, u)).replace(".0B", "B")
        n /= 1024.0
    return "%.1fTB" % n


def human_dur(sec):
    sec = int(sec or 0)
    if sec < 60:
        return "%ds" % sec
    m, s = divmod(sec, 60)
    if m < 60:
        return "%dm%02ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh%02dm" % (h, m)


def safe_filename(s, maxlen=120):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", str(s or ""))[:maxlen] or "x"


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
    _rwx_result(p)                          # RWX RULE: result folder rwx
    return p


def engagement_root(base_out, engagement):
    return os.path.join(base_out, engagement)


def dedupe(seq):
    """Order-preserving dedupe (dicts bhi chalein - JSON key se)."""
    out, seen = [], set()
    for x in seq:
        k = x if isinstance(x, (str, int, float, bool)) else json.dumps(x, sort_keys=True, default=str)
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def deep_unquote(s, rounds=3):
    """Bar-bar URL-encoded string ko decode karo (double/triple encoding detect)."""
    s = str(s or "")
    for _ in range(max(1, rounds)):
        try:
            t = urllib.parse.unquote(s)
        except Exception:
            break
        if t == s:
            break
        s = t
    return s

# ----------------------------------------------------------------------------
# SECRETS ENGINE (ULTRA) - shared DB, hamesha REDACTED store hota hai
# ----------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b"),
    ("AWS Secret (inline assign)", r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
    ("Private Key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Google OAuth client", r"\b[0-9]{8,12}-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ("GitHub token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("GitLab PAT", r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    ("Stripe key", r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    ("Twilio SID", r"\bAC[0-9a-fA-F]{32}\b"),
    ("SendGrid key", r"\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b"),
    ("Mailgun key", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("NPM token", r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]+"),
    ("Shopify token", r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"),
    ("Telegram bot token", r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"),
    ("Anthropic key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("OpenAI-style key", r"\bsk-[A-Za-z0-9_\-]{32,}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}\b"),
    ("Firebase/FCM server key", r"\bAAAA[A-Za-z0-9_\-]{25,}:[A-Za-z0-9_\-]{60,}\b"),
    ("DB conn string w/ password", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s'\"@/]+:[^\s'\"@]+@"),
    ("Basic-auth in URL", r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/@:]+:[^\s/@]+@[^\s/]+"),
    ("Heroku API key (uuid)", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
]

_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9_/+=\-]{32,}")


def scan_secrets(text, limit=60, entropy_threshold=4.4):
    """Text me known-format + high-entropy secrets dhoondo. Output HAMESHA redacted.

    Return: list of {"kind", "match"(redacted), "line", "context"(redacted)}
    Evidence me kabhi bhi raw secret nahi jaata (No secret misuse rule).
    """
    out, seen = [], set()
    text = text or ""
    for i, line in enumerate(text.splitlines(), 1):
        if len(out) >= limit:
            break
        stripped = line.strip()
        if not stripped:
            continue
        for kind, pat in SECRET_PATTERNS:
            m = re.search(pat, stripped)
            if not m:
                continue
            raw = m.group(0)
            masked = redact(raw, 4)
            key = (kind, masked)
            if key in seen:
                continue
            seen.add(key)
            ctx = stripped.replace(raw, masked)[:160]
            out.append({"kind": kind, "match": masked, "line": i, "context": ctx})
            if len(out) >= limit:
                break
    # generic high-entropy pass (unknown-format tokens)
    if len(out) < limit:
        for i, line in enumerate(text.splitlines(), 1):
            if len(out) >= limit:
                break
            for tok in _ENTROPY_TOKEN_RE.findall(line):
                if len(out) >= limit:
                    break
                if shannon_entropy(tok) >= entropy_threshold:
                    masked = redact(tok, 4)
                    key = ("high-entropy token", masked)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({"kind": "high-entropy token", "match": masked,
                                "line": i, "context": stripped.replace(tok, masked)[:160]})
    return out


SENSITIVE_PARAM_HINTS = (
    "password", "passwd", "pwd", "pass", "token", "secret", "api_key", "apikey",
    "api-key", "access_key", "accesskey", "auth", "session", "sess", "sid",
    "jwt", "credential", "cred", "ssn", "credit", "card", "cvv", "cvc", "pin",
    "otp", "mfa", "secretkey", "private", "key", "sig", "signature", "hmac",
    "reset", "confirmation", "invoice", "account", "user_id", "uid", "email",
)


def is_sensitive_param(name):
    n = (name or "").lower()
    return any(h in n for h in SENSITIVE_PARAM_HINTS)


# ----------------------------------------------------------------------------
# JWT / RAW-REQUEST HELPERS (ULTRA)
# ----------------------------------------------------------------------------
def _b64url_decode(s):
    s = (s or "").strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def jwt_decode(token):
    """JWT ko decode karo (SIGNATURE VERIFY NAHI hota - sirf inspection).
    Tamper/crack probes ke liye modules khud decide karte hain."""
    tok = (token or "").strip()
    parts = tok.split(".")
    if not tok or len(parts) not in (2, 3):
        return {"error": "not a JWT (expected header.payload[.signature])"}
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", "ignore"))
    except Exception as e:
        return {"error": "header decode failed: %s" % e}
    payload = {}
    if len(parts) >= 2:
        try:
            payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", "ignore"))
        except Exception as e:
            payload = {"_error": str(e)}
    exp = payload.get("exp") if isinstance(payload, dict) else None
    expired = None
    if isinstance(exp, (int, float)):
        expired = float(exp) < time.time()
    return {"header": header, "payload": payload, "signature_present": len(parts) == 3,
            "alg": header.get("alg"), "kid": header.get("kid"), "expired": expired,
            "claims": {k: payload.get(k) for k in ("iss", "sub", "aud", "iat", "exp", "nbf", "jti")
                       if isinstance(payload, dict) and k in payload}}


def parse_raw_request(raw):
    """Burp/ZAP style raw request text -> {"method","path","url","headers","body","host"}.
    Absolute-form target (proxy logs) aur relative-form dono support."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "ignore")
    raw = (raw or "").replace("\r\n", "\n")
    if "\n\n" in raw:
        head_part, body = raw.split("\n\n", 1)
    else:
        head_part, body = raw, ""
    lines = [l for l in head_part.split("\n") if l.strip()]
    if not lines:
        return None
    parts = lines[0].split()
    method = parts[0].upper() if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            headers[k.strip()] = v.strip()
    out = {"method": method, "headers": headers, "body": body}
    if target.startswith("http://") or target.startswith("https://"):
        out["url"] = target
        sp = urllib.parse.urlsplit(target)
        out["path"] = sp.path or "/"
        if sp.query:
            out["path"] += "?" + sp.query
    else:
        out["path"] = target or "/"
        host = headers.get("Host") or headers.get("host") or ""
        out["host"] = host
        if host:
            scheme = "https" if "443" in host.split(":")[-1] else "http"
            out["url"] = "%s://%s%s" % (scheme, host, out["path"])
    out["host"] = out.get("host") or headers.get("Host") or headers.get("host") or ""
    return out


# ----------------------------------------------------------------------------
# ROBOTS + SITEMAP PARSERS (ULTRA)
# ----------------------------------------------------------------------------
INTERESTING_PATH_HINTS = ("admin", "api", "private", "backup", "secret", "internal",
                          "test", "staging", "dev", "config", "old", ".git", "panel",
                          "cpanel", "manager", "console", "jenkins", "actuator", "debug")


def parse_robots(text):
    """robots.txt -> {"sitemaps","disallow","allow","crawl_delay","agents","interesting"}"""
    res = {"sitemaps": [], "disallow": [], "allow": [], "crawl_delay": None,
           "agents": [], "interesting": []}
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        low = ln.lower()
        if ":" not in ln:
            continue
        key, val = ln.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if key == "sitemap":
            if val and val not in res["sitemaps"]:
                res["sitemaps"].append(val)
        elif key == "disallow":
            if val:
                res["disallow"].append(val)
        elif key == "allow":
            if val:
                res["allow"].append(val)
        elif key == "crawl-delay":
            try:
                res["crawl_delay"] = float(val)
            except ValueError:
                pass
        elif key == "user-agent":
            if val and val not in res["agents"]:
                res["agents"].append(val)
    for p in res["disallow"]:
        if any(h in p.lower() for h in INTERESTING_PATH_HINTS):
            res["interesting"].append(p)
    res["interesting"] = sorted(set(res["interesting"]))
    return res


def parse_sitemap(text):
    """sitemap.xml -> {"is_index","urls","sitemaps"} (regex-based, koi XML dep nahi)."""
    text = text or ""
    locs = re.findall(r"(?is)<loc>\s*(.*?)\s*</loc>", text)
    is_index = "<sitemapindex" in text.lower()
    urls, subs = [], []
    for u in locs:
        u = u.strip()
        if not u:
            continue
        if is_index and u.lower().endswith(".xml"):
            subs.append(u)
        else:
            urls.append(u)
    return {"is_index": is_index, "urls": dedupe(urls), "sitemaps": dedupe(subs)}


def fetch_robots_sitemaps(http, base_url, max_sitemaps=4, max_children=2):
    """robots.txt + sitemap(s) fetch/parse - P5/P6 feed ke liye ek-shot helper."""
    res = {"robots": None, "sitemaps": [], "urls": []}
    try:
        r = http.get(urllib.parse.urljoin(base_url.rstrip("/") + "/", "robots.txt"),
                     allow_redirects=False)
    except Exception as e:
        res["error"] = str(e)
        return res
    if r.error or r.status != 200 or not r.text:
        return res
    res["robots"] = parse_robots(r.text)
    sm_urls = res["robots"]["sitemaps"][:max_sitemaps]
    if not sm_urls:
        sm_urls = [urllib.parse.urljoin(base_url.rstrip("/") + "/", "sitemap.xml")]
    todo = list(sm_urls)
    seen_sm = set()
    while todo and len(res["sitemaps"]) < max_sitemaps + max_children:
        sm = todo.pop(0)
        if sm in seen_sm:
            continue
        seen_sm.add(sm)
        rr = http.get(sm, allow_redirects=False)
        if rr.error or rr.status != 200 or not rr.text:
            continue
        p = parse_sitemap(rr.text)
        res["sitemaps"].append({"url": sm, "is_index": p["is_index"],
                                "url_count": len(p["urls"])})
        res["urls"].extend(p["urls"])
        for child in p["sitemaps"]:
            if len(res["sitemaps"]) < max_sitemaps + max_children:
                todo.append(child)
    res["urls"] = dedupe(res["urls"])[:2000]
    return res


# ----------------------------------------------------------------------------
# WORDLIST ENGINE (ULTRA) - embedded fallback + file + WASP_WORDS cap
# ----------------------------------------------------------------------------
EMBEDDED_CONTENT_WORDS = [
    ".env", ".env.local", ".env.production", ".env.bak", ".git/config", ".git/HEAD",
    ".git/logs/HEAD", ".svn/entries", ".hg/hgrc", ".DS_Store", ".htaccess", ".htpasswd",
    "web.config", "WEB-INF/web.xml", "backup.zip", "backup.tar.gz", "backup.sql",
    "dump.sql", "db.sql", "database.sql", "site.bak", "old.zip", "www.zip",
    "swagger.json", "swagger.yaml", "swagger-ui/", "openapi.json", "openapi.yaml",
    "api-docs", "api-docs/", "docs/", "graphql", "graphiql", "graphql/playground",
    "graphql/console", "api", "api/v1", "api/v2", "api/v3", "rest", "rest/v1",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump", "actuator/mappings",
    "debug", "debug/vars", "trace", "phpinfo.php", "info.php", "test.php", "admin",
    "admin/", "admin/login", "admin panel", "administrator", "administrator/",
    "manager", "manager/html", "console", "dashboard", "panel", "cpanel", "whm",
    "login", "login/", "signin", "signup", "register", "logout", "oauth", "oauth2",
    "sso", "sso/login", "auth", "token", "jwks.json", ".well-known/jwks.json",
    ".well-known/openid-configuration", ".well-known/security.txt", ".well-known/apple-app-site-association",
    ".well-known/assetlinks.json", "security.txt", "robots.txt", "robots.txt.bak",
    "sitemap.xml", "sitemap_index.xml", "sitemaps.xml", "humans.txt", "crossdomain.xml",
    "clientaccesspolicy.xml", "CHANGELOG.md", "CHANGELOG.txt", "README.md", "readme.txt",
    "TODO.txt", "TODO.md", "LICENSE", "composer.json", "composer.lock", "package.json",
    "package-lock.json", "yarn.lock", ".npmrc", ".yarnrc", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "poetry.lock", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".dockerenv", "Jenkinsfile", ".gitlab-ci.yml", ".github/workflows",
    ".circleci/config.yml", "bitbucket-pipelines.yml", "Vagrantfile", "Makefile",
    "wp-admin/", "wp-admin/admin-ajax.php", "wp-login.php", "wp-content/", "wp-includes/",
    "wp-json/wp/v2/users", "wp-json/", "xmlrpc.php", "wp-config.php.bak",
    "administrator/index.php", "user/login", "?q=admin", "sites/default/settings.php",
    "config.php", "config.php.bak", "configuration.php", "settings.py", "local_settings.py",
    "app.py", "wsgi.py", "manage.py", "artisan", "storage/logs/laravel.log",
    "server-status", "server-info", ".server-status", "status", "health", "healthz",
    "ping", "version", "VERSION", "metrics", "prometheus", "metrics/", "debug/pprof/",
    "cgi-bin/", "cgi-bin/test.cgi", "test", "test/", "dev", "dev/", "staging", "beta",
    "uat", "old", "new", "temp", "tmp", "logs/", "log/", "error.log", "access.log",
    "app.log", "debug.log", "database.yml", "config/database.yml", "id_rsa", "id_rsa.pub",
    "aws/credentials", ".aws/credentials", "credentials.json", "client_secret.json",
    "service-account.json", "secrets.json", "secrets.yaml", "vault/", "k8s/", "kubernetes/",
    "deploy/", "deployment/", "ansible/", "jenkins/", "backup/", "backups/", "archive/",
    "private/", "internal/", "secret/", "confidential/", "conf/", "etc/", "home/",
    "static/", "assets/", "js/", "css/", "img/", "images/", "media/", "files/",
    "uploads/", "upload/", "download/", "downloads/", "export/", "exports/",
    "api/swagger", "api/openapi", "api/graphql", "api/status", "api/health", "api/users",
    "api/config", "api/debug", "api/internal", "api/admin", "v1/", "v2/", "v3/",
    "index.php", "index.bak", "index.php.bak", "index.html.bak", "main.php.bak",
    "app.js.bak", "config.js.bak", "db.php", "db.inc.php", "common.php", "functions.php",
]

_WORDLIST_CACHE = {}


def load_words(cfg=None, cap=0):
    """Content-phase wordlist:
      1. config.content_wordlist_file (agar diya)
      2. embedded EMBEDDED_CONTENT_WORDS (fallback)
      cap  = config.content_total_cap ya WASP_WORDS env ya explicit cap arg
    Order-preserving dedupe. (WASP_WORDS ek NUMBER/CAP hai, list nahi.)"""
    words = []
    f = getattr(cfg, "content_wordlist_file", None) if cfg is not None else None
    if f and os.path.exists(str(f)):
        try:
            for ln in open(str(f), errors="ignore"):
                w = ln.strip()
                if w and not w.startswith("#"):
                    words.append(w)
        except OSError:
            pass
    if not words:
        words = list(EMBEDDED_CONTENT_WORDS)
    words = dedupe([w.strip().strip("/") for w in words if w and w.strip()])
    if not cap:
        cap = env_int("WASP_WORDS", 0)
    if not cap and cfg is not None:
        cap = env_int("WASP_WORDS_CAP", 0) or int(getattr(cfg, "content_total_cap", 0) or 0)
    if cap and cap > 0:
        words = words[:int(cap)]
    return words

# ----------------------------------------------------------------------------
# RATE LIMITER + BUDGET (adaptive)
# ----------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, rps, jitter=0.0, adaptive=True):
        self.base_interval = 1.0 / max(0.1, float(rps))
        self.jitter = max(0.0, float(jitter))
        self.adaptive = adaptive
        self.multiplier = 1.0
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            interval = self.base_interval * self.multiplier
            if self.jitter:
                interval *= 1.0 + random.uniform(-self.jitter, self.jitter)
            delta = time.time() - self.last
            if delta < interval:
                time.sleep(interval - delta)
            self.last = time.time()

    def penalize(self, factor=1.75, cap=20.0):
        """WAF/429 signal -> slow down globally."""
        if not self.adaptive:
            return
        with self.lock:
            self.multiplier = min(cap, self.multiplier * factor)

    def relax(self, factor=0.97, floor=1.0):
        if not self.adaptive:
            return
        with self.lock:
            self.multiplier = max(floor, self.multiplier * factor)

    def effective_rps(self):
        with self.lock:
            return 1.0 / max(0.0001, self.base_interval * self.multiplier)

    def snapshot(self):
        with self.lock:
            return {"effective_rps": round(self.effective_rps(), 2),
                    "multiplier": round(self.multiplier, 2), "jitter": self.jitter}


class Budget:
    def __init__(self, max_requests):
        self.max = int(max_requests)
        self.count = 0
        self.lock = threading.Lock()
        self.exhausted = False

    def take(self, n=1):
        with self.lock:
            if self.count + n > self.max:
                self.exhausted = True
                return False
            self.count += n
            return True

    def remaining(self):
        with self.lock:
            return max(0, self.max - self.count)

    def snapshot(self):
        with self.lock:
            return {"used": self.count, "max": self.max,
                    "remaining": max(0, self.max - self.count),
                    "pct": round(100.0 * self.count / max(1, self.max), 1),
                    "exhausted": self.exhausted}


# ----------------------------------------------------------------------------
# EVIDENCE
# ----------------------------------------------------------------------------
class Evidence:
    """Structured evidence: requests.jsonl (index) + raw bodies + curl replays."""

    def __init__(self, outdir):
        self.dir = outdir
        self.raw_dir = os.path.join(outdir, "evidence", "raw")
        self.jsonl = os.path.join(outdir, "evidence", "requests.jsonl")
        self.curl_dir = os.path.join(outdir, "evidence", "replay")
        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.jsonl), exist_ok=True)
        os.makedirs(self.curl_dir, exist_ok=True)
        for _d in (self.dir, self.raw_dir, os.path.dirname(self.jsonl), self.curl_dir):
            _rwx_result(_d)                     # RWX RULE: evidence folders rwx
        self._lock = threading.Lock()
        self.count = 0

    def log(self, rec):
        rec = dict(rec)
        rec["ts"] = now_iso()
        with self._lock:
            self.count += 1
            with open(self.jsonl, "a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
            _rwx_result(self.jsonl)             # RWX RULE: requests.jsonl rwx

    @staticmethod
    def _unique_path(directory, name):
        """ULTRA BUGFIX 2: same-name body/replay evidence ko OVERWRITE na karo."""
        base, ext = os.path.splitext(name)
        path = os.path.join(directory, name)
        i = 2
        while os.path.exists(path) and i < 999:
            path = os.path.join(directory, "%s-%d%s" % (base, i, ext))
            i += 1
        return path

    def save_body(self, name, body, limit=None):
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", name)[:120] or "body"
        if limit:
            body = body[:limit]
        path = self._unique_path(self.raw_dir, safe)
        with open(path, "wb") as f:
            f.write(body if isinstance(body, bytes) else body.encode("utf-8", "ignore"))
        _rwx_result(path)                   # RWX RULE: raw evidence file rwx
        return path

    def save_replay(self, name, curl_cmd):
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", name)[:120] or "req"
        path = self._unique_path(self.curl_dir, safe + ".sh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n# WASP replay - authorized testing only\n")
            f.write(curl_cmd + "\n")
        _rwx_result(path)                   # RWX RULE: replay script rwx (executable)
        return path

    def summary(self):
        """requests.jsonl ka quick count (status breakdown + errors)."""
        st = {"requests": 0, "errors": 0, "by_status": {}}
        if not os.path.exists(self.jsonl):
            return st
        try:
            with open(self.jsonl, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    st["requests"] += 1
                    if rec.get("error"):
                        st["errors"] += 1
                    s = rec.get("status")
                    if s is not None:
                        k = str(s)
                        st["by_status"][k] = st["by_status"].get(k, 0) + 1
        except OSError:
            pass
        return st


def raw_request_text(method, url, headers, body=None):
    u = urllib.parse.urlsplit(url)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % (u.netloc)]
    for k, v in (headers or {}).items():
        lines.append("%s: %s" % (k, v))
    out = "\n".join(lines)
    if body:
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", "ignore")
            except Exception:
                body = "<binary>"
        out += "\n\n" + body
    return out


def curl_command(method, url, headers, body=None):
    parts = ["curl -isk -X %s" % method]
    for k, v in (headers or {}).items():
        if k.lower() in ("accept-encoding",):
            continue
        parts.append("-H %s" % shell_quote("%s: %s" % (k, v)))
    if body:
        if isinstance(body, bytes):
            body = body.decode("utf-8", "ignore")
        parts.append("--data-raw %s" % shell_quote(body))
    parts.append(shell_quote(url))
    return " ".join(parts)


def shell_quote(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


# ----------------------------------------------------------------------------
# HTTP RESPONSE
# ----------------------------------------------------------------------------
class Resp:
    __slots__ = ("url", "method", "status", "headers", "set_cookies", "raw_headers",
                 "body", "error", "elapsed", "chain", "request_headers", "request_body")

    def __init__(self, url, status=None, headers=None, body=b"", error=None,
                 elapsed=0.0, chain=None, method="GET", set_cookies=None,
                 raw_headers=None, request_headers=None, request_body=None):
        self.url = url
        self.method = method
        self.status = status
        self.headers = headers or {}
        self.set_cookies = set_cookies or []
        self.raw_headers = raw_headers or []
        self.body = body or b""
        self.error = error
        self.elapsed = elapsed
        self.chain = chain or []
        self.request_headers = request_headers or {}
        self.request_body = request_body

    @property
    def text(self):
        return self.body.decode("utf-8", "ignore")

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def hget(self, name, default=""):
        return self.header(name, default)

    def ok(self):
        return self.status is not None and 200 <= self.status < 400

    def is_json(self):
        return "json" in (self.hget("Content-Type") or "").lower()

    def is_html(self):
        return "html" in (self.hget("Content-Type") or "").lower() or \
            bool(re.search(r"(?is)<html|<!doctype", self.text[:400]))

    def json(self, default=None):
        try:
            return json.loads(self.text)
        except Exception:
            return default

    def sha1(self, limit=6000):
        return sha1(self.body[:limit])

    def to_dict(self, body_limit=0):
        d = {"url": self.url, "method": self.method, "status": self.status,
             "headers": self.headers, "set_cookies": self.set_cookies,
             "len": len(self.body), "error": self.error,
             "elapsed": round(self.elapsed, 4), "chain": self.chain,
             "request_headers": self.request_headers}
        if body_limit:
            d["body"] = self.body[:body_limit].decode("utf-8", "ignore")
        return d

    @staticmethod
    def from_dict(d, body=b""):
        return Resp(d.get("url", ""), d.get("status"), d.get("headers") or {},
                    body, d.get("error"), d.get("elapsed", 0.0), d.get("chain") or [],
                    d.get("method", "GET"), d.get("set_cookies") or [],
                    request_headers=d.get("request_headers") or {})

    def __repr__(self):
        return "<Resp %s %s status=%s len=%d>" % (self.method, self.url, self.status, len(self.body))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ----------------------------------------------------------------------------
# HTTP CLIENT
# ----------------------------------------------------------------------------
# LAYER 4 (RWX RULE - user memory): rwx sirf RESULT files par hota hai.
# TARGETS par testing READ-ONLY hai -> default sirf GET/HEAD/OPTIONS jaata hai.
# Writes sirf in 2 explicit tareeko se: (1) read_only_post=True - pure-read POST
# (GraphQL introspection jaisa, kuch modify nahi karta), (2) force_write=True -
# module ka apna explicit config gate (jaise access_allow_write_probes).
# Master switch: config.json me "allow_write_http": true.
# Scope firewall (request() me) out-of-scope hosts block karta hai - dono milke
# "sirf authorized targets par GET/HEAD-only" guarantee karte hain.
READ_ONLY_METHODS = ("GET", "HEAD", "OPTIONS")


class HttpClient:
    def __init__(self, cfg, evidence=None, scope=None, label="http", limiter=None,
                 budget=None, cookie_jar=None):
        self.cfg = cfg
        self.scope = scope
        self.ev = evidence
        self.label = label
        self.limiter = limiter or RateLimiter(cfg.rate_limit, getattr(cfg, "jitter", 0.0),
                                             getattr(cfg, "adaptive_throttle", True))
        self.budget = budget or Budget(cfg.max_requests)
        self.cj = cookie_jar if cookie_jar is not None else http.cookiejar.CookieJar()
        self.stats = {"sent": 0, "errors": 0, "retries": 0, "blocked": 0, "cache_hits": 0}
        self._dead = set()
        self._lock = threading.Lock()
        self._forced_cookie = None
        self._default_headers = {}
        self.identities = {}
        self._build_openers()

    # ---------- setup ----------
    def _build_openers(self):
        ctx = ssl.create_default_context()
        if not self.cfg.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ssl_ctx = ctx
        handlers = [urllib.request.HTTPSHandler(context=ctx),
                    urllib.request.HTTPCookieProcessor(self.cj)]
        if getattr(self.cfg, "proxy", None):
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.cfg.proxy, "https": self.cfg.proxy}))
        self.opener = urllib.request.build_opener(*handlers)
        self.opener_noredir = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.cj))

    def set_cookie_header(self, cookie_header):
        self._forced_cookie = cookie_header

    def set_default_headers(self, headers):
        self._default_headers = dict(headers or {})

    def identity(self, name, headers=None, cookie_header=None):
        """Independent session (own cookie jar) sharing limiter/budget/evidence."""
        c = HttpClient(self.cfg, self.ev, self.scope, label="%s:%s" % (self.label, name),
                       limiter=self.limiter, budget=self.budget)
        c.set_default_headers(headers or {})
        if cookie_header:
            c.set_cookie_header(cookie_header)
        c.identities = self.identities
        self.identities[name] = c
        return c

    def session_export(self):
        out = []
        for c in self.cj:
            out.append({"name": c.name, "value": c.value, "domain": c.domain,
                        "path": c.path, "secure": c.secure, "expires": c.expires})
        return out

    def session_import(self, cookies):
        for d in cookies or []:
            try:
                c = http.cookiejar.Cookie(
                    version=0, name=d.get("name", ""), value=d.get("value", ""),
                    port=None, port_specified=False, domain=d.get("domain", ""),
                    domain_specified=True, domain_initial_dot=False,
                    path=d.get("path", "/"), path_specified=True,
                    secure=bool(d.get("secure")), expires=d.get("expires"),
                    discard=False, comment=None, comment_url=None, rest={})
                self.cj.set_cookie(c)
            except Exception:
                continue
        return len(cookies or [])

    # ---------- request ----------
    def request(self, method, url, headers=None, data=None, allow_redirects=True,
                save=None, raise_scope=True, retries=None, scope_host=None,
                read_only_post=False, force_write=False):
        """scope_host: authorize against this host instead of the URL host
        (used for virtual-host probing: connect to an IP, send Host: in-scope-name)."""
        # ------------------------------------------------------------------
        # LAYER 4 (RWX RULE): targets par read-only. rwx sirf result files par.
        # Non-GET/HEAD/OPTIONS default blocked - writes sirf explicit opt-in par:
        #   read_only_post=True (pure-read POST) | force_write=True (module gate)
        #   | cfg "allow_write_http": true (master switch)
        # ------------------------------------------------------------------
        m = (method or "GET").upper()
        if m not in READ_ONLY_METHODS and not (
                read_only_post or force_write
                or getattr(self.cfg, "allow_write_http", False)):
            self.stats["blocked"] += 1
            if raise_scope:
                raise ScopeError("READ-ONLY blocked: %s %s (writes ke liye "
                                 "config.json me allow_write_http=true chahiye)" % (m, url))
            return Resp(url, error="READ-ONLY-BLOCKED", method=m)

        if self.scope is not None:
            allowed = (self.scope.check_host(scope_host, raise_on_fail=False)
                       if scope_host else self.scope.check_url(url, raise_on_fail=False))
            if not allowed:
                self.stats["blocked"] += 1
                if raise_scope:
                    raise ScopeError("OUT-OF-SCOPE blocked: %s (host=%s)"
                                     % (url, scope_host or host_of(url)))
                return Resp(url, error="OUT-OF-SCOPE", method=method)

        key = "%s://%s" % (urllib.parse.urlsplit(url).scheme, urllib.parse.urlsplit(url).netloc)
        if getattr(self.cfg, "negative_cache", True) and key in self._dead:
            self.stats["cache_hits"] += 1
            return Resp(url, error="HOST-CACHED-DEAD", method=method)

        tries = int(self.cfg.retries if retries is None else retries)
        attempt = 0
        last = None
        while attempt <= tries:
            if not self.budget.take(1):
                return Resp(url, error="REQUEST-BUDGET-EXHAUSTED", method=method)
            last = self._one_hop_chain(method, url, headers, data, allow_redirects, save)
            attempt += 1
            retryable = last.error is not None or (last.status in getattr(self.cfg, "retry_status", []))
            if last.status in (429, 503):
                self.limiter.penalize()
                ra = last.hget("Retry-After")
                if ra and ra.strip().isdigit():
                    time.sleep(min(30, int(ra.strip())))
            if not retryable or attempt > tries:
                break
            self.stats["retries"] += 1
            time.sleep((self.cfg.backoff ** attempt) * random.uniform(0.6, 1.4))
        if last.error is not None:
            self.stats["errors"] += 1
            if getattr(self.cfg, "negative_cache", True) and "refused" in str(last.error).lower():
                with self._lock:
                    self._dead.add(key)
        else:
            if last.status in (429, 403, 406) and self.limiter.multiplier > 1.0:
                pass
            elif last.status and last.status < 400:
                self.limiter.relax()
        self.stats["sent"] += 1
        return last

    def _one_hop_chain(self, method, url, headers, data, allow_redirects, save):
        ua = self.cfg.user_agent
        if getattr(self.cfg, "rotate_user_agents", False):
            pool = getattr(self.cfg, "user_agents", None) or []
            if pool:
                ua = random.choice(pool)
        h = {"User-Agent": ua, "Accept": "*/*",
             "Accept-Language": "en-US,en;q=0.9"}
        ae = getattr(self.cfg, "accept_encoding", "")
        if ae:
            h["Accept-Encoding"] = ae
        if self._forced_cookie:
            h["Cookie"] = self._forced_cookie
        h.update(getattr(self.cfg, "custom_headers", {}) or {})
        h.update(self._default_headers)
        if headers:
            h.update(headers)

        chain, total = [], 0.0
        body = data
        hops = int(self.cfg.redirects) + 1 if allow_redirects else 1
        for hop in range(hops):
            self.limiter.wait()
            req = urllib.request.Request(url, data=body, headers=h, method=method)
            t0 = time.time()
            status, rh, raw, setc = None, {}, b"", []
            try:
                # ULTRA BUGFIX 1: pehle allow_redirects=False par auto-following
                # wala opener chal raha tha. Redirect chain hamesha MANUAL follow
                # hoti hai (scope-check + auth-strip + evidence per hop) - isliye
                # dono cases me no-redirect opener hi sahi hai.
                op = self.opener_noredir
                r = op.open(req, timeout=self.cfg.timeout)
                status, raw = r.status, r.read()
                rh = dict(r.headers.items())
                setc = r.headers.get_all("Set-Cookie") or []
                if r.headers.get("Content-Encoding", "").lower() in ("gzip", "deflate"):
                    raw = _decompress(raw, r.headers.get("Content-Encoding"))
            except urllib.error.HTTPError as e:
                status = e.code
                rh = dict(e.headers.items()) if e.headers else {}
                setc = (e.headers.get_all("Set-Cookie") or []) if e.headers else []
                try:
                    raw = e.read()
                    if (e.headers or {}).get("Content-Encoding", "").lower() in ("gzip", "deflate"):
                        raw = _decompress(raw, e.headers.get("Content-Encoding"))
                except Exception:
                    raw = b""
            except Exception as e:
                dt = time.time() - t0
                err = "%s: %s" % (type(e).__name__, e)
                if self.ev:
                    self.ev.log({"mod": self.label, "method": method, "url": url,
                                 "error": err, "elapsed": round(dt, 3)})
                return Resp(url, error=err, elapsed=total + dt, chain=chain, method=method,
                            request_headers=h, request_body=data)
            dt = time.time() - t0
            total += dt
            chain.append({"url": url, "status": status, "location": rh.get("Location", "")})
            if self.ev:
                self.ev.log({"mod": self.label, "method": method, "url": url, "status": status,
                             "len": len(raw), "elapsed": round(dt, 3),
                             "server": rh.get("Server", ""), "ct": rh.get("Content-Type", ""),
                             "location": rh.get("Location", "")})
                if self.ev and (save or getattr(self.cfg, "save_bodies", True)) and raw:
                    name = save or ("%s_%s" % (method, re.sub(r"[^A-Za-z0-9._-]", "_", url)[-70:]))
                    self.ev.save_body(name, raw, limit=int(getattr(self.cfg, "max_body_store", 262144)))
                    if getattr(self.cfg, "save_replays", True):
                        self.ev.save_replay(re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100],
                                            curl_command(method, url, h, data))
            loc = rh.get("Location", "")
            if allow_redirects and status in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(url, loc)
                if self.scope is not None and not self.scope.check_url(nxt, raise_on_fail=False):
                    return Resp(nxt, status, rh, raw, elapsed=total, chain=chain, method=method,
                                set_cookies=setc, request_headers=h, request_body=data)
                # cross-host redirect: never leak Authorization/Cookie
                if host_of(nxt) != host_of(url):
                    h = {k: v for k, v in h.items()
                         if k.lower() not in ("authorization", "cookie", "x-api-key")}
                if status == 303:
                    method, body = "GET", None
                url = nxt
                continue
            return Resp(url, status, rh, raw, elapsed=total, chain=chain, method=method,
                        set_cookies=setc, request_headers=h, request_body=data)
        return Resp(url, error="TOO-MANY-REDIRECTS", chain=chain, method=method)

    # ---------- helpers ----------
    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, data=None, headers=None, **kw):
        h = dict(headers or {})
        if isinstance(data, dict):
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
            data = urllib.parse.urlencode(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        return self.request("POST", url, headers=h, data=data, **kw)

    def post_json(self, url, obj, headers=None, **kw):
        h = dict(headers or {})
        h.setdefault("Content-Type", "application/json")
        return self.request("POST", url, headers=h, data=json.dumps(obj).encode(), **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)

    def fingerprint(self, url):
        """Fetch a URL and return a cheap comparison signature."""
        r = self.request("GET", url, allow_redirects=False)
        return {"url": url, "status": r.status, "len": len(r.body),
                "sha1": r.sha1(), "error": r.error, "title": title_of(r.text)}

    def stats_snapshot(self):
        d = dict(self.stats)
        d["budget"] = self.budget.snapshot()
        d["rate"] = self.limiter.snapshot()
        return d


def _decompress(raw, encoding):
    try:
        enc = (encoding or "").lower()
        if enc == "gzip":
            return gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        if enc == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        return raw
    return raw


def title_of(html):
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html or "")
    return re.sub(r"\s+", " ", m.group(1)).strip()[:150] if m else ""

# ----------------------------------------------------------------------------
# SOFT-404 ENGINE (shared by content / tech / active)
# ----------------------------------------------------------------------------
def _shingles(text, k=4):
    text = re.sub(r"\s+", " ", text or "")
    return set(text[i:i + k] for i in range(max(0, len(text) - k + 1)))


def similarity(a, b):
    """Jaccard similarity over character shingles. 1.0 = identical, 0.0 = unrelated."""
    A, B = _shingles(a), _shingles(b)
    if not A and not B:
        return 1.0
    if not A or not B:
        return 0.0
    return len(A & B) / float(len(A | B))


def soft404_baseline(http, base_url, samples=4, paths=None):
    """Catch-all / soft-404 baseline from random non-existent paths.

    Records status set, length statistics AND a body sample, so later comparisons
    use *both* length proximity and body similarity (length alone is unreliable:
    a 100-byte .env file can be within 50 bytes of a 111-byte 404 template).
    """
    sigs, texts = [], []
    for i in range(samples):
        p = paths[i] if paths and i < len(paths) else "/%s-%s" % (rand_str(7), rand_str(5))
        r = http.request("GET", urllib.parse.urljoin(base_url.rstrip("/") + "/", p.lstrip("/")),
                         allow_redirects=False)
        if r.error:
            continue
        sigs.append({"status": r.status, "len": len(r.body), "sha1": r.sha1(),
                     "title": title_of(r.text)})
        texts.append(r.text[:4000])
    if not sigs:
        return {}
    lens = [s["len"] for s in sigs]
    statuses = [s["status"] for s in sigs]
    med = median(lens)
    spread = max(lens) - min(lens)
    dominant = max(set(statuses), key=statuses.count)
    tol = max(16, int(0.02 * max(1, med)))
    return {
        "status": dominant, "statuses": sorted(set(statuses)),
        "len_min": min(lens), "len_max": max(lens), "len_median": med, "spread": spread,
        "identical_body": len(set(s["sha1"] for s in sigs)) == 1,
        "hashes": sorted(set(s["sha1"] for s in sigs)),
        "titles": sorted(set(s["title"] for s in sigs)),
        "body_sample": texts[0] if texts else "",
        "tolerance": tol,
        "stable_len": spread <= tol,
        "serves_200_on_missing": dominant == 200,
        "samples": len(sigs),
    }


def is_soft404(r, base, sim_threshold=0.70):
    """True => response looks like the server's catch-all / 404 template.

    Decision order (high precision first):
      1. byte-identical to a baseline sample            -> catch-all
      2. body near-identical to the template (sim>=.90) -> catch-all
      3. similar body AND close length                  -> catch-all
      4. same status + close length + moderate similarity -> catch-all (non-200 servers)
    """
    if not base or r.error:
        return False
    status, ln = r.status, len(r.body)
    text = r.text[:4000]

    if base.get("identical_body") and r.sha1() in base.get("hashes", []):
        return True

    sim = similarity(text, base.get("body_sample", ""))
    med = base.get("len_median", base.get("len_min", 0))
    tol = base.get("tolerance", 32)
    len_close = abs(ln - med) <= tol

    if sim >= 0.90:
        return True
    if len_close and sim >= sim_threshold:
        return True
    if base.get("serves_200_on_missing") and len_close and sim >= 0.55:
        return True
    if (not base.get("serves_200_on_missing")) and status in base.get("statuses", []) \
            and len_close and sim >= 0.55:
        return True
    return False


# ----------------------------------------------------------------------------
# WAF / EDGE SIGNATURES (ULTRA)
# ----------------------------------------------------------------------------
WAF_SIGNATURES = [
    ("Cloudflare", lambda h, b: "cf-ray" in h or "cf-cache-status" in h
        or "cloudflare" in h.get("server", "")),
    ("AWS WAF", lambda h, b: "x-amzn-waf" in h or "awswaf" in b),
    ("Akamai", lambda h, b: "akamai" in h.get("server", "") or "akamaighost" in b
        or ("reference #" in b and "access denied" in b)),
    ("CloudFront", lambda h, b: "cloudfront" in h.get("via", "")
        or "cloudfront" in h.get("server", "")
        or "x-amz-cf-id" in h),
    ("Fastly", lambda h, b: "fastly" in h.get("via", "") or "x-served-by" in h
        and "cache" in h.get("x-served-by", "")),
    ("Imperva/Incapsula", lambda h, b: "x-iinfo" in h or "incapsula" in b),
    ("Sucuri", lambda h, b: "x-sucuri-id" in h or "x-sucuri-cache" in h or "sucuri" in b),
    ("F5 BIG-IP", lambda h, b: "bigipserver" in h.get("set-cookie", "")
        or "x-cnection" in h or "ts=" in h.get("set-cookie", "")),
    ("ModSecurity", lambda h, b: "mod_security" in b or "modsecurity" in b),
    ("Wordfence", lambda h, b: "wordfence" in b or "wfvt_" in h.get("set-cookie", "")),
    ("DataDome", lambda h, b: "x-datadome" in h or "datadome" in b),
    ("PerimeterX/HUMAN", lambda h, b: "_px" in h.get("set-cookie", "")
        or "perimeterx" in b or "px-captcha" in b),
    ("Kasada", lambda h, b: "x-kasada" in h or "_kpsdk" in b),
    ("Wallarm", lambda h, b: "wallarm" in h.get("server", "") or "x-wallarm" in h),
    ("Barracuda", lambda h, b: "barra" in h.get("server", "") or "barracuda" in b),
]


def waf_signature(headers=None, body="", status=None):
    """Response headers/body se WAF/CDN/edge guess karo -> list of names.
    Guess hai, guarantee nahi - modules ise finding ke evidence ke saath rakhein."""
    h = {}
    for k, v in (headers or {}).items():
        try:
            h.setdefault(k.lower(), str(v).lower())
        except Exception:
            continue
    b = (body or "").lower()
    hits = []
    for name, fn in WAF_SIGNATURES:
        try:
            if fn(h, b):
                hits.append(name)
        except Exception:
            continue
    return hits


# ----------------------------------------------------------------------------
# SECURITY HEADERS / COOKIE FLAGS (ULTRA)
# ----------------------------------------------------------------------------
SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
)


def analyze_security_headers(headers):
    """Headers -> {"present", "missing", "notes"} (P2/P4 feed ke liye)."""
    h = {}
    for k, v in (headers or {}).items():
        h[k.lower()] = v
    present = {k: h[k] for k in SECURITY_HEADERS if k in h}
    missing = [k for k in SECURITY_HEADERS if k not in h]
    notes = []
    if "x-xss-protection" in h:
        notes.append("x-xss-protection deprecated hai (modern browsers ignore karte hain)")
    csp = (present.get("content-security-policy") or "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        notes.append("CSP weak hai (unsafe-inline/unsafe-eval allowed)")
    hsts = (present.get("strict-transport-security") or "").replace(" ", "")
    if hsts and "max-age=0" in hsts:
        notes.append("HSTS max-age=0 (effectively disabled)")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        notes.append("clickjacking guard missing (frame-ancestors/CSP bhi nahi)")
    return {"present": present, "missing": missing, "notes": notes}


def analyze_cookie_flags(set_cookies):
    """Set-Cookie list -> per-cookie flag analysis + issues (P2/P10 feed)."""
    issues, cookies = [], []
    for raw in set_cookies or []:
        first = (raw or "").split(";", 1)[0]
        name = first.split("=", 1)[0].strip() or "?"
        flags = [f.strip().lower() for f in (raw or "").split(";")[1:]]

        def has(f, flags=flags):
            return any(x == f or x.startswith(f + "=") for x in flags)

        iss = []
        if not has("secure"):
            iss.append("no Secure flag")
        if not has("httponly"):
            iss.append("no HttpOnly flag")
        if not has("samesite"):
            iss.append("no SameSite attribute")
        else:
            ss = [x for x in flags if x.startswith("samesite=")]
            if ss and ss[0] == "samesite=none" and not has("secure"):
                iss.append("SameSite=None without Secure")
        for x in flags:
            if x.startswith("max-age="):
                v = x.split("=", 1)[1].strip().lstrip("-")
                if v.isdigit() and int(v) > 31536000:
                    iss.append("Max-Age > 1 year (long-lived session)")
        cookies.append({"name": name, "raw": raw[:200], "flags": flags, "issues": iss})
        for i in iss:
            issues.append({"cookie": name, "issue": i})
    return {"cookies": cookies, "issues": issues}


def redirect_chain(http, url, max_hops=8, headers=None):
    """Manual redirect-chain follow (hopp-by-hop evidence + cross-host flag).
    http = HttpClient (scope-aware); return {"hops","cross_host","final","count"}"""
    hops, cross, cur = [], False, url
    for _ in range(max_hops):
        r = http.request("GET", cur, headers=headers, allow_redirects=False)
        if r.error:
            hops.append({"url": cur, "error": r.error})
            break
        hops.append({"url": cur, "status": r.status, "location": r.hget("Location")})
        if r.status in (301, 302, 303, 307, 308) and r.hget("Location"):
            nxt = urllib.parse.urljoin(cur, r.hget("Location"))
            if host_of(nxt) != host_of(cur):
                cross = True
            cur = nxt
            continue
        break
    return {"hops": hops, "cross_host": cross, "final": cur,
            "count": sum(1 for x in hops if "status" in x)}


def dns_resolve(host, timeout=4.0):
    """A-record resolve (getaddrinfo) -> {"ips":[...], "error":None|str}.
    Best-effort; system resolver use hota hai (custom resolvers passive module me)."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = sorted({i[4][0] for i in infos})
        return {"ips": ips, "error": None}
    except Exception as e:
        return {"ips": [], "error": "%s: %s" % (type(e).__name__, e)}


# ----------------------------------------------------------------------------
# HTML/JS EXTRACTORS (ULTRA) - modules ke liye shared parsers
# ----------------------------------------------------------------------------
_LINK_ATTR_RE = re.compile(
    r"""(?is)(?:href|src|action|data-url|data-href|data-src)\s*=\s*["']([^"']+)["']""")


def extract_links(html, base=""):
    """HTML se href/src/action/data-* URLs (base ke saath absolute banake)."""
    out = []
    for m in _LINK_ATTR_RE.finditer(html or ""):
        u = (m.group(1) or "").strip()
        if not u or u.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
            continue
        try:
            out.append(urllib.parse.urljoin(base, u) if base else u)
        except ValueError:
            out.append(u)
    return dedupe(out)


def extract_js_urls(html, base=""):
    """HTML/inline se .js URLs."""
    urls = []
    for u in extract_links(html, base):
        path = u.split("?", 1)[0].split("#", 1)[0]
        if path.lower().endswith(".js"):
            urls.append(u)
    return urls


def extract_comments(html):
    """HTML comments (info leakage check)."""
    return [c.strip() for c in re.findall(r"(?s)<!--(.*?)-->", html or "") if c.strip()]


def meta_generator(html):
    m = re.search(r"""(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""",
                  html or "")
    if not m:
        m = re.search(r"""(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""",
                      html or "")
    return m.group(1).strip() if m else None


def find_csrf(html):
    """Common CSRF token inputs -> [{"name","value"}]."""
    hints = ("csrf", "_token", "authenticity_token", "xsrf", "csrfmiddlewaretoken",
             "__requestverificationtoken", "nonce", "_csrf_token", "csrf_token")
    out = []
    for m in re.finditer(r"(?is)<input[^>]*>", html or ""):
        tag = m.group(0)
        nm = re.search(r"""name=["']([^"']+)["']""", tag)
        if not nm or not any(h in nm.group(1).lower() for h in hints):
            continue
        vl = re.search(r"""value=["']([^"']*)["']""", tag)
        out.append({"name": nm.group(1), "value": vl.group(1) if vl else ""})
    return out

# ----------------------------------------------------------------------------
# CROSS-MODULE PROBE CACHE
# ----------------------------------------------------------------------------
class ProbeCache:
    """Disk cache so an already-probed URL is never re-requested across modules."""

    def __init__(self, base_out, engagement, ttl=3600):
        self.dir = os.path.join(base_out, engagement, "_cache")
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "probes.json")
        self.ttl = ttl
        self.lock = threading.Lock()
        self.data = load_json(self.path, {}) or {}
        self.hits = 0

    @staticmethod
    def key(method, url):
        return "%s %s" % (method.upper(), url)

    def get(self, method, url):
        k = self.key(method, url)
        rec = self.data.get(k)
        if not rec:
            return None
        if time.time() - rec.get("_ts", 0) > self.ttl:
            return None
        self.hits += 1
        return rec

    def put(self, method, url, rec):
        k = self.key(method, url)
        rec = dict(rec)
        rec["_ts"] = time.time()
        with self.lock:
            self.data[k] = rec
            if len(self.data) % 25 == 0:
                save_json(self.path, self.data)

    def flush(self):
        with self.lock:
            save_json(self.path, self.data)
        return len(self.data)

    def stats(self):
        """ULTRA: cache size/entries snapshot (doctor/cache command use karte hain)."""
        size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        return {"path": self.path, "entries": len(self.data), "size": size,
                "ttl": self.ttl, "hits": self.hits}

    def clear(self):
        with self.lock:
            self.data = {}
            try:
                os.remove(self.path)
            except OSError:
                pass
        return True


# ----------------------------------------------------------------------------
# CHECKPOINT / RESUME
# ----------------------------------------------------------------------------
_INTERRUPT = {"flag": False, "reason": "", "ts": None, "count": 0}


def _sig_handler(signum, frame):
    _INTERRUPT["count"] += 1
    _INTERRUPT["flag"] = True
    _INTERRUPT["reason"] = "SIGINT" if signum == int(getattr(signal, "SIGINT", 2)) else "SIGTERM"
    _INTERRUPT["ts"] = now_iso()
    if _INTERRUPT["count"] >= 2:
        err("Second interrupt - force quitting (state already saved per step).")
        os._exit(130)
    raise KeyboardInterrupt


def install_signal_handlers():
    for name in ("SIGINT", "SIGTERM"):
        s = getattr(signal, name, None)
        if s is None:
            continue
        try:
            signal.signal(s, _sig_handler)
        except Exception:
            pass


def interrupted():
    return _INTERRUPT["flag"]


def interrupt_info():
    return dict(_INTERRUPT)


class Checkpoint:
    """Resumable step tracker (atomic writes, per-step persistence)."""

    def __init__(self, outdir, module, fresh=False):
        self.module = module
        self.dir = os.path.join(outdir, "_state")
        os.makedirs(self.dir, exist_ok=True)
        _rwx_result(self.dir)                   # RWX RULE: _state folder rwx
        self.path = os.path.join(self.dir, "checkpoint_%s.json" % module)
        self.results_path = os.path.join(self.dir, "results_%s.jsonl" % module)
        for _p in (self.path, self.results_path):
            if os.path.exists(_p):
                _rwx_result(_p)                 # RWX RULE: checkpoint/results rwx
        self.lock = threading.Lock()
        self.done = {}
        self.cache = {}
        self.started = now_iso()
        self.resumed_from = 0
        if fresh:
            self.wipe()
        self._load()

    def wipe(self):
        for pth in (self.path, self.results_path):
            try:
                os.remove(pth)
            except OSError:
                pass
        self.done, self.cache, self.resumed_from = {}, {}, 0

    def _load(self):
        d = load_json(self.path, None)
        if isinstance(d, dict):
            self.done = d.get("done", {}) or {}
            self.started = d.get("started", self.started)
            self.resumed_from = len(self.done)
        if os.path.exists(self.results_path):
            for line in open(self.results_path):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    self.cache[rec.get("key")] = rec.get("result")
                except Exception:
                    continue

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"module": self.module, "version": VERSION, "started": self.started,
                       "updated": now_iso(), "count": len(self.done), "done": self.done},
                      f, indent=2, default=str)
        os.replace(tmp, self.path)
        _rwx_result(self.path)                  # RWX RULE: checkpoint file rwx

    @staticmethod
    def key_str(key):
        return key if isinstance(key, str) else json.dumps(key, sort_keys=True, default=str)

    def is_done(self, key):
        return self.key_str(key) in self.done

    def result_of(self, key):
        return self.cache.get(self.key_str(key))

    def mark(self, key, result=None, summary=""):
        k = self.key_str(key)
        with self.lock:
            self.done[k] = {"ts": now_iso(), "summary": summary}
            with open(self.results_path, "a") as f:
                f.write(json.dumps({"key": k, "result": result, "ts": now_iso()},
                                   default=str) + "\n")
            _rwx_result(self.results_path)      # RWX RULE: results jsonl rwx
            self.cache[k] = result
            self._save()

    def step(self, key, fn, *a, **kw):
        if self.is_done(key):
            return self.result_of(key), True
        res = fn(*a, **kw)
        self.mark(key, res)
        return res, False

    def map_steps(self, items, keyfn, fn, verbose=True, label="step"):
        out, total = {}, len(items)
        for i, it in enumerate(items, 1):
            k = self.key_str(keyfn(it))
            res, skipped = self.step(k, fn, it)
            out[k] = res
            if verbose:
                (info if skipped else ok)("[%d/%d] %s %s" % (i, total, "SKIP" if skipped else "done",
                                                             str(it)[:90]))
            if interrupted():
                warn("Interrupt - stopping cleanly (state saved, rerun to resume).")
                break
        return out

    def progress(self):
        return {"module": self.module, "done_steps": len(self.done),
                "resumed_from": self.resumed_from, "started": self.started,
                "results_file": self.results_path}

    def mark_complete(self):
        self.mark("__module_complete__", {"done": True}, summary="module finished")

    def keys(self):
        return sorted(self.done.keys())

    def stats(self):
        return {"module": self.module, "steps": len(self.done), "started": self.started,
                "complete": self.is_done("__module_complete__")}


def checkpoint_status(outdir, module):
    d = os.path.join(outdir, "_state")
    cp_path = os.path.join(d, "checkpoint_%s.json" % module)
    res_path = os.path.join(d, "results_%s.jsonl" % module)
    if not os.path.exists(cp_path):
        return {"module": module, "state": "not-started", "done_steps": 0, "complete": False}
    data = load_json(cp_path, {}) or {}
    steps = 0
    if os.path.exists(res_path):
        steps = sum(1 for l in open(res_path) if l.strip())
    return {"module": module, "state": "in-progress",
            "done_steps": len(data.get("done", {})), "result_records": steps,
            "started": data.get("started"), "updated": data.get("updated"),
            "complete": "__module_complete__" in (data.get("done") or {})}


def checkpoint_healthy(outdir, module):
    """ULTRA: checkpoint file corrupt hai ya nahi (doctor integrity scan)."""
    p = os.path.join(outdir, "_state", "checkpoint_%s.json" % module)
    if not os.path.exists(p):
        return True, None
    d = load_json(p, None)
    if isinstance(d, dict) and "done" in d:
        return True, None
    return False, p


# ----------------------------------------------------------------------------
# FINDINGS AGGREGATION (ULTRA) - cross-module rollup
# ----------------------------------------------------------------------------
FINDINGS_CONTAINER_KEYS = ("findings", "issues", "vulns", "vulnerabilities",
                           "hits", "secret_hits", "secrets", "results", "observations")


def _extract_findings(data, depth=0):
    """Module JSON me se findings-list nikalo (module formats alag ho sakte hain)."""
    if depth > 3 or data is None:
        return []
    if isinstance(data, list):
        return [x for x in data if x]
    if isinstance(data, dict):
        items = []
        for k in FINDINGS_CONTAINER_KEYS:
            v = data.get(k)
            if isinstance(v, list) and v:
                items.extend(x for x in v if x)
        if items:
            return items
        for k, v in data.items():
            if k in ("summary", "stats", "config", "meta", "scope", "routing", "files"):
                continue
            if isinstance(v, (dict, list)):
                items.extend(_extract_findings(v, depth + 1))
        return items
    return []


def _sev_of(item):
    if not isinstance(item, dict):
        return "info"
    for k in ("severity", "risk", "sev", "level", "impact", "priority"):
        v = item.get(k)
        if isinstance(v, str) and v.lower().strip() in SEV_ORDER:
            return v.lower().strip()
    return "info"


def _title_of(item, i):
    if isinstance(item, dict):
        for k in ("title", "name", "issue", "type", "kind", "finding", "summary",
                  "desc", "description", "message", "url", "key"):
            v = item.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()[:110]
    return (str(item)[:110] if str(item).strip() else "item-%d" % i)


def aggregate_findings(base_out, engagement, min_severity="info", max_items=800):
    """Har module ke <mod>/<mod>.json se findings nikaalo -> unified rollup."""
    root = os.path.join(base_out, engagement)
    res = {"engagement": engagement, "generated_at": now_iso(), "engine_version": VERSION,
           "total": 0, "by_severity": {s: 0 for s in SEVERITIES},
           "by_module": {}, "items": []}
    if not os.path.isdir(root):
        return res
    min_i = SEV_ORDER.get(min_severity, 0)
    for mod in sorted(os.listdir(root)):
        mdir = os.path.join(root, mod)
        if not os.path.isdir(mdir) or mod.startswith("_"):
            continue
        data = load_json(os.path.join(mdir, "%s.json" % mod))
        if data is None:
            continue
        items = _extract_findings(data)
        cnt = {"total": 0, "by_severity": {s: 0 for s in SEVERITIES}}
        for i, it in enumerate(items):
            sev = _sev_of(it)
            cnt["total"] += 1
            cnt["by_severity"][sev] += 1
            if SEV_ORDER.get(sev, 0) >= min_i and len(res["items"]) < max_items:
                clean = it if not isinstance(it, dict) else \
                    {k: v for k, v in it.items() if k not in ("request_headers", "headers")}
                res["items"].append({"module": mod, "severity": sev,
                                     "title": _title_of(it, i), "item": clean})
        res["by_module"][mod] = cnt
        res["total"] += cnt["total"]
        for s in SEVERITIES:
            res["by_severity"][s] += cnt["by_severity"][s]
    res["items"].sort(key=lambda x: (-SEV_ORDER.get(x.get("severity"), 0), x.get("module", "")))
    return res


def write_findings_report(base_out, engagement, min_severity="info"):
    """findings.json + FINDINGS.md likho engagement root me. Return paths+summary."""
    agg = aggregate_findings(base_out, engagement, min_severity=min_severity)
    root = os.path.join(base_out, engagement)
    ensure_dir(root)
    jp = os.path.join(root, "findings.json")
    save_json(jp, agg)
    L = ["# WASP FINDINGS - %s" % engagement, "",
         "- generated : %s" % agg["generated_at"],
         "- engine    : wasp_core v%s (ULTRA)" % VERSION,
         "- threshold : severity >= %s" % min_severity, "",
         "Total: %d | critical: %d | high: %d | medium: %d | low: %d | info: %d"
         % (agg["total"], *[agg["by_severity"][s] for s in SEVERITIES]), "",
         "| Severity | Module | Title |", "|---|---|---|"]
    for it in agg["items"][:300]:
        L.append("| %s | %s | %s |" % (it["severity"].upper(), it["module"],
                                       str(it["title"]).replace("|", "\\|")))
    if not agg["items"]:
        L.append("| - | - | (is threshold par koi finding nahi) |")
    mp = os.path.join(root, "FINDINGS.md")
    save_text(mp, "\n".join(L) + "\n")
    return {"aggregate": agg, "findings_json": jp, "findings_md": mp}


# ----------------------------------------------------------------------------
# SESSION STORE (ULTRA) - identity cookies disk par (resumable logins)
# ----------------------------------------------------------------------------
class SessionStore:
    """Named identities ke cookie jars ko `_state/sessions.json` me save/load karo.
    Login karne wale modules (P9/P10/P11) ise use karke resume ke baad
    re-login avoid karte hain."""

    def __init__(self, base_out, engagement):
        self.dir = os.path.join(base_out, engagement, "_state")
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "sessions.json")

    def _load_all(self):
        d = load_json(self.path, {})
        return d if isinstance(d, dict) else {}

    def save(self, name, client_or_cookies):
        data = self._load_all()
        getter = getattr(client_or_cookies, "session_export", None)
        cookies = getter() if callable(getter) else list(client_or_cookies or [])
        data[name] = {"updated": now_iso(), "cookies": cookies}
        save_json(self.path, data)
        return data[name]

    def load(self, name):
        return self._load_all().get(name, {}).get("cookies", [])

    def apply(self, name, client):
        cookies = self.load(name)
        return client.session_import(cookies) if cookies else 0

    def list(self):
        return sorted(self._load_all().keys())

    def delete(self, name):
        data = self._load_all()
        gone = data.pop(name, None)
        save_json(self.path, data)
        return gone is not None


# ----------------------------------------------------------------------------
# MODULE BOILERPLATE + FEED-FORWARD
# ----------------------------------------------------------------------------
def module_ctx(cfg, scope, base_out, name):
    """One-liner setup every module uses: (out, evidence, http, checkpoint)."""
    out = getattr(cfg, "module_outdir", None) or outdir_for(base_out, scope.engagement, name)
    os.makedirs(out, exist_ok=True)
    ev = Evidence(out)
    http = HttpClient(cfg, ev, scope, label=name)
    cp = getattr(cfg, "checkpoint", None) or Checkpoint(out, name,
                                                        fresh=not getattr(cfg, "resume", True))
    cfg.checkpoint = cp
    cfg.module_outdir = out
    return out, ev, http, cp


def write_feedforward(out, phase, mapping, notes=None):
    """Standard artifact: what this phase produced and where it is consumed next."""
    payload = {"phase": phase, "generated_at": now_iso(), "engine_version": VERSION,
               "routing": mapping, "notes": notes or []}
    save_json(os.path.join(out, "feedforward.json"), payload)
    return payload


def write_manifest(out, phase, files, stats=None, notes=None):
    payload = {"phase": phase, "generated_at": now_iso(), "engine_version": VERSION,
               "files": files, "stats": stats or {}, "notes": notes or []}
    save_json(os.path.join(out, "MANIFEST.json"), payload)
    return payload


def read_feedforward(base_out, engagement):
    """ULTRA: engagement ke saare feedforward.json ek dict me (chain command)."""
    root = os.path.join(base_out, engagement)
    out = {}
    if not os.path.isdir(root):
        return out
    for mod in sorted(os.listdir(root)):
        p = os.path.join(root, mod, "feedforward.json")
        if os.path.isfile(p):
            d = load_json(p)
            if isinstance(d, dict):
                out[mod] = d.get("routing") or {}
    return out


def safe_map(items, fn, workers=8, label=None, every=0):
    """Threaded map with exception isolation + optional progress line."""
    import concurrent.futures as cf
    results, total, done = [], len(items), 0
    with cf.ThreadPoolExecutor(max_workers=max(1, int(workers))) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for f in cf.as_completed(futs):
            it = futs[f]
            try:
                results.append((it, f.result()))
            except Exception as e:
                results.append((it, {"_error": "%s: %s" % (type(e).__name__, e)}))
            done += 1
            if label and every and done % every == 0:
                info("%s %d/%d" % (label, done, total))
    return results


def progress(i, n, label="", width=28):
    if not n:
        return
    filled = int(width * i / n)
    bar = "#" * filled + "." * (width - filled)
    sys.stdout.write("\r  [%s] %d/%d %s" % (bar, i, n, label[:40].ljust(40)))
    if i >= n:
        sys.stdout.write("\n")
    sys.stdout.flush()


# ----------------------------------------------------------------------------
# CONSOLE HELPERS
# ----------------------------------------------------------------------------
class C:
    R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[0;33m"; B = "\033[0;34m"
    M = "\033[0;35m"; CY = "\033[0;36m"; N = "\033[0m"; BOLD = "\033[1m"
    DIM = "\033[2m"


if os.environ.get("NO_COLOR"):
    for _a in ("R", "G", "Y", "B", "M", "CY", "N", "BOLD", "DIM"):
        setattr(C, _a, "")


def info(m): print("%s[*]%s %s" % (C.CY, C.N, m))
def ok(m): print("%s[+]%s %s" % (C.G, C.N, m))
def warn(m): print("%s[!]%s %s" % (C.Y, C.N, m))
def err(m): print("%s[-]%s %s" % (C.R, C.N, m))
def head(m): print("\n%s==== %s ====%s" % (C.B, m, C.N))
def dim(m): print("%s  %s%s" % (C.DIM, m, C.N))


def table(rows, headers=None, indent="  "):
    """Simple aligned ASCII table - status/findings/modules commands use karte hain."""
    rows = [list(map(str, r)) for r in rows]
    allr = ([list(map(str, headers))] if headers else []) + rows
    if not allr:
        return
    ncol = max(len(r) for r in allr)
    widths = [0] * ncol
    for r in allr:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    if headers:
        print(indent + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
        print(indent + "  ".join("-" * widths[i] for i in range(ncol)))
    for r in rows:
        print(indent + "  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))


def banner(version=VERSION):
    print("%s" % (C.B + "  " + "=" * 62 + C.N))
    print("%s   WASP  v%s  -  Web Assessment Script Pack (ULTRA)%s" % (C.BOLD, version, C.N))
    print("%s   Sirf AUTHORIZED testing ke liye - scope firewall ON%s" % (C.Y, C.N))
    print("%s  " + "=" * 62 + C.N)


def outdir_for(base, engagement, mod):
    p = os.path.join(base, engagement, mod)
    os.makedirs(p, exist_ok=True)
    return p
