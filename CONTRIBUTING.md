# Contributing — WASP Framework

Bhai, welcome! WASP modular hai — naya phase module likhna ek **fixed contract**
follow karta hai. Pehle ye padho, phir PR bhejo.

---

## 1. Module Contract (NON-NEGOTIABLE)

Har phase module ek file hai: `phases/blockN_<name>/mod_<name>.py`

```python
NAME = "mymod"          # registry name (wasp.py REGISTRY key se match)
PHASE_NUM = "27"        # phase number (string)
PHASE_TITLE = "..."

def run(cfg, scope, base_out):
    """wasp.py isi ko call karta hai. Return: module output dir path."""
    out, ev, http, cp = module_ctx(cfg, scope, base_out, NAME)
    # ... apna kaam ...
    return out
```

| Rule | Kyun |
|---|---|
| `run(cfg, scope, base_out)` signature **same rakho** | wasp.py `mod.run(cfg, sc, base)` call karta hai |
| Setup ke liye `module_ctx()` use karo | out-dir + evidence + http + checkpoint ek saath milte hain |
| Results `<mod>.json` me save karo | `findings` rollup isi file ko padhta hai |
| Findings `make_finding()` se banao | unified severity scale + aggregation |
| Long steps me `cp.mark(key, result)` / `cp.step()` | resume/checkpoint system isi par chalta hai |
| End me `write_feedforward()` + `write_manifest()` | agla phase tumhara output auto-use karega |
| **Koi direct network request NAHI** | `http` (HttpClient) hi use karo — wo scope-check + rate-limit + budget karta hai |

## 2. Safety Rules (Har Module Par)

1. **Scope firewall kabhi bypass mat karo** — saare requests `HttpClient` se
2. **GET/HEAD/OPTIONS default** — write-methods sirf RoE gate (`config.json` opt-in) ke saath
3. **Secrets/PII values KABHI store nahi** — sha1-12 hash ya REDACTED
4. **Destructive payloads nahi** — detection-only, inert markers
5. Har probe `ev.log()` se evidence me jaana chahiye

## 3. Naya Module Add Karne Ke Steps

1. File banao: `phases/blockN_<name>/mod_<name>.py` (upar wala template)
2. `wasp.py` me 4 jagah entry:
   - `REGISTRY` — name, file, description, phase#, requires_active
   - `RUN_ORDER` — pipeline position
   - `PHASE_ALIAS` — `"27": "evidence"` (phase-number alias)
   - `BLOCKS["N"]` — block ke module list me add
3. (optional) `CHAIN_TXT` — expected artifacts list
4. Test: `python3 wasp.py list` (entrypoint OK dikhna chahiye) → `python3 wasp.py doctor`
5. (recommended) `tests/test_mod_<name>.py` — offline mock test

## 4. P26–P32 Stubs — Apna Script Daalo

Ye 6 slots **ready** hain (stub files + MODULE_TODO.md checklist har folder me):

| Phase | File | Kya Bharna Hai |
|---|---|---|
| P26 | `phases/block5_infra/mod_scanval.py` | FP-filter / scanner validation |
| P27 | `phases/block6_report/mod_evidence.py` | safe validation + evidence pack |
| P28 | `phases/block6_report/mod_chaining.py` | vulnerability chaining |
| P29 | `phases/block6_report/mod_cvss.py` | CVSS 3.1 + impact |
| P30 | `phases/block6_report/mod_remediation.py` | code-level fixes |
| P31 | `phases/block6_report/mod_retest.py` | regression + bypass vectors |
| P32 | `phases/block6_report/mod_reporting.py` | professional report |

Stub file kholo → `IMPLEMENTATION_CHECKLIST` dekho → `run()` me apna logic likho →
baki sab (registry, alias, chain) **already wired hai**.

## 5. PR Checklist

- [ ] `python3 wasp.py selftest` pass
- [ ] `python3 wasp.py list` me naya module OK dikhta hai
- [ ] Koi hardcoded target/IP nahi (sab scope.json se)
- [ ] Secrets/PII redaction follow kiya
- [ ] New dep add ki to `requirements.txt` update (stdlib prefer karo)
- [ ] Commit message: `mod_<name>: <kya kiya>` (e.g. `mod_evidence: P27 evidence pack + redaction`)

## 6. Code Style

- Python 3.8+ compatible (Kali default)
- Stdlib-first — heavy deps avoid karo
- Docstring me: kya karta hai + expected artifacts + safety notes
- Console output ke liye `wasp_core` ke `info/ok/warn/err/head/dim` use karo
