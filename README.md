<div align="center">

# 🕷️ WASP — Web Assessment Script Pack

**33-Phase Web Pentesting Framework — Recon se Professional Report tak**

`v2.3.0` · Python 3.8+ · Kali Linux (kahi bhi chalega) · **Zero mandatory dependencies**

[![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)](#-changelog)
[![Python](https://img.shields.io/badge/python-3.8%2B-informational.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux-success.svg)](#-quick-start)
[![License](https://img.shields.io/badge/license-MIT%20%2B%20Ethical%20Addendum-red.svg)](LICENSE)
[![Deps](https://img.shields.io/badge/deps-stdlib%20only-brightgreen.svg)](requirements.txt)

</div>

---

## ⚠️ Legal Notice — Pehle Ye Padho

> **WASP sirf AUTHORIZED security testing ke liye hai.**
> Bina **written permission** ke kisi bhi system par chalana **ILLEGAL hai** (India: IT Act 2000 §43/66, US: CFAA, EU: NIS2).
>
> - Har run se pehle WASP `scope.json` maangta hai — `authorized: true` nahi to **tool start hi nahi hoga**
> - `scope.json` = tumhara authorization record (program URL / SOW / ticket + date)
> - Sab modules **detection-only, non-destructive** design par hain (write-methods default OFF)
>
> **Apni machine, apna authorization, apni zimmedari.**

---

## 🤔 WASP Kya Hai?

WASP ek **phase-by-phase web pentesting framework** hai jo bug-bounty hunters aur
pentesters ke real workflow ko follow karta hai. Ek command me poora pipeline
chalao, ya koi bhi ek phase — har phase ka output agle phase me **automatically
feedforward** hota hai (recon ke endpoints → injection module ke targets).

| | |
|---|---|
| 🧱 **31 modules / 6 blocks** | P2–P25 fully implemented (ULTRA PRO MAX engines), P26–P32 stubs (apna script daalo) |
| 🔥 **Scope firewall** | Har HTTP request scope-checked — out-of-scope request kabhi nahi jaati |
| 💾 **Checkpoint / Resume** | Ctrl+C, crash, power-loss — kuch nahi dobara hota, wahi se resume |
| 🧾 **Evidence engine** | Har probe ka request/response log + replayable curl |
| 📊 **Findings rollup** | Saare modules ke findings unified `FINDINGS.md` + `findings.json` me |
| 🎛️ **Profiles** | `ghost / stealth / normal / fast / audit` — rate, concurrency, caps presets |
| 🔐 **License gate** | Token-based (FREE tier abhi sabke liye) — detail niche |
| 🧪 **Selftest** | Offline mock-target self-test — bina internet verify karo |

---

## 🚀 Quick Start

### 1. Clone + Setup (Kali Linux)

```bash
git clone https://github.com/YOUR-USERNAME/wasp-framework.git
cd wasp-framework
chmod +x setup.sh
./setup.sh
```

`setup.sh` khud karta hai: python check → optional deps → `scope.json` template →
kali-tools presence check → `wasp.py doctor` health report.

### 2. License Token (FREE)

```bash
export WASP_TOKEN=WASP-FREE-2025-DEMO      # FREE tier = poora toolkit
# ya har command ke saath: --token WASP-FREE-2025-DEMO
```

| Token | Tier | Valid Till | Notes |
|---|---|---|---|
| `WASP-FREE-2025-DEMO` | FREE | 2027-12-31 | Poora toolkit, community support |
| `WASP-PRO-2025-DEMO` | PRO | 2027-12-31 | Future: no watermark, priority updates, API verify |

> Token **ek baar** daalne par `~/.wasp/token_cache.json` me cache ho jaata hai.
> Diagnostics commands (`list/doctor/verify/status/selftest/findings/report`) **bina token** bhi chalte hain.

### 3. Scope Configure (ZAROORI)

```bash
nano scope.json
```

```json
{
  "engagement": "my-first-engagement",
  "authorized": true,
  "authorization_reference": "hackerone.com/xyz policy + 2026-10-29",
  "domains": ["target.com"],
  "wildcards": ["*.target.com"],
  "excludes": ["blog.target.com"]
}
```

> ⚠️ Sirf **wahi targets** daalo jinpar tumhe **written permission** hai.

### 4. Run

```bash
python3 wasp.py verify              # pre-flight: scope, deps, network
python3 wasp.py run --module 2      # P2: app understanding + threat model
python3 wasp.py run --block 1       # poora Block 1 (recon, P2-P8)
python3 wasp.py runall              # P2 -> P32 full pipeline (skip-done)
python3 wasp.py runall --block 2    # sirf highest-bounty block (auth)
```

---

## 🗺️ Phase Map — 6 Blocks (P2–P32)

| Block | Phases | Modules | Status |
|---|---|---|---|
| **1 · Reconnaissance** | P2–P8 | understand, passive, active, content, tech, js, surface | ✅ Implemented |
| **2 · Auth, Session & Access** 🔥 | P9–P11 | auth, sessions, access | ✅ Implemented — *highest bounty* |
| **3 · Input & Server-Side Injections** | P12–P16 | inject, xss, client, ssrf, files | ✅ Implemented |
| **4 · Modern Protocols & Business Logic** | P17–P22 | api, graphql, ws, logic, authz, replay | ✅ Implemented |
| **5 · Misconfig, Cloud & Controls** | P23–P26 | misconfig, cloud, controls, scanval | ✅ + 📝 P26 stub |
| **6 · Validation, Chaining & Reporting** | P27–P32 | evidence, chaining, cvss, remediation, retest, reporting | 📝 Stubs (roadmap) |

📝 = **placeholder stub** — file structure + TODO checklist ready hai (`MODULE_TODO.md`
har stub folder me), apna real script `run()` me daalo. Guide: [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🧰 Commands Cheat-Sheet

```bash
python3 wasp.py list                    # 31-module registry (ULTRA table)
python3 wasp.py verify                  # pre-flight (scope, deps, network)
python3 wasp.py run --module 5          # resumable single phase (alias: --module content)
python3 wasp.py run --module 5 --fresh  # checkpoint ignore karke fresh start
python3 wasp.py run --block 2           # poora block
python3 wasp.py runall                  # full pipeline (order me, skip-done)
python3 wasp.py status                  # kya complete hua, kya pending (--json bhi)
python3 wasp.py findings --min-sev high # cross-module findings rollup
python3 wasp.py report                  # REPORT.md (poora engagement)
python3 wasp.py chain                   # phase feedforward chain map
python3 wasp.py evidence --tail 20      # last N evidence requests
python3 wasp.py reset --module 5        # checkpoint reset (--all/--cache/--hard)
python3 wasp.py doctor                  # environment + integrity report
python3 wasp.py selftest                # OFFLINE mock-target self-test
python3 wasp.py wizard                  # scope.json + config.json builder
python3 wasp.py tune --profile stealth  # config preset likho
```

**Profiles:** `ghost` (silent) · `stealth` (slow, UA-rotation) · `normal` · `fast` · `audit` (full bodies)
**Global flags:** `--scope PATH` · `--config PATH` · `--out DIR` · `--profile NAME` · `--rate F` · `--max-requests N` · `--proxy URL` · `--yes` · `--token TOK`

Ctrl+C dabao → progress **save** hota hai. Wahi command dobara chalao → **resume**.

---

## 📁 Output Kahan Jaata Hai?

Default: `~/wasp_out/<engagement>/` (override: `--out DIR` ya env `WASP_OUT`)

```
~/wasp_out/my-first-engagement/
├── understand/           # P2: threat model, endpoints, forms
├── passive/              # P3: subdomains, URLs, CT logs
├── active/               # P4: live hosts, ports, TLS, WAF
├── ...
├── reporting/            # P32: REPORT.md, EXEC_SUMMARY.md
├── findings.json         # unified rollup (saare modules)
├── FINDINGS.md           # human-readable findings table
├── license_audit.jsonl   # license audit trail
└── ...
```

Har module folder me: `<mod>.json` (results), `requests.jsonl` (evidence),
`_state/` (checkpoint), `feedforward.json` (agle phase ke liye handoff).

---

## 🔧 Optional Kali Tools

WASP **stdlib-only** hai — ye tools optional hain (modules builtin fallback use karte hain):

```bash
sudo apt install nmap subfinder amass httpx-toolkit ffuf gobuster dnsutils
```

---

## 🔐 License System (Free First, Paid Later)

- **FREE tier (abhi)**: poora toolkit (P2–P32), community support — token upar table me
- **PRO tier (baad me)**: report watermark removal, priority updates, API-based verification
- Token gate sirf `run`/`runall` par lagta hai; har successful gate `license_audit.jsonl` me audit line likhta hai
- Future: `WASP_API_URL` env set karke apne license-server se verify karo (protocol README me `wasp_license.py` docstring me hai)

## 📚 Documentation

| Doc | Kya Hai |
|---|---|
| [`docs/GUIDE_WASP.txt`](docs/GUIDE_WASP.txt) | Poora WASP guide (Hinglish, original author notes) |
| [`docs/RESUME.txt`](docs/RESUME.txt) | Checkpoint/resume system detail |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Naya phase module kaise likho (P26–P32 ready slots) |
| [`SECURITY.md`](SECURITY.md) | Toolkit ki khud ki vulnerabilities report karne ka process |

## 🗺️ Roadmap

- [ ] P26–P32 real modules (scanval → evidence → chaining → CVSS → remediation → retest → report)
- [ ] License server + user dashboard (API verify)
- [ ] REPORT.md → PDF export
- [ ] Web docs site (phases/tutorials guide)
- [ ] Plugin marketplace (community modules)

## 🤝 Contributing

Bug fix / naya module / docs improvement — sab welcome! Padho
[`CONTRIBUTING.md`](CONTRIBUTING.md) (module contract: `run(cfg, scope, base_out)`
signature, scope-firewall rules, evidence conventions).

## ⚖️ License

MIT + **binding Ethical Use Addendum** — padho [`LICENSE`](LICENSE).
Short: *sirf authorized targets, responsibility tester ki, misuse = license termination.*

---

<div align="center">

**🕷️ WASP** — *Scan smart. Stay authorized. Report professionally.*

</div>
