# Security Policy — WASP Toolkit

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.3.x   | ✅ |
| < 2.3   | ❌ (upgrade karo) |

## Reporting a Vulnerability (is TOOLKIT me)

Agar WASP toolkit ke code me koi security issue milo (e.g. scope firewall bypass,
evidence redaction leak, license gate bypass):

1. **Public issue mat kholo** (exploit detail ke saath)
2. Private report bhejo: **SECURITY ADVISORY** via GitHub → "Report a vulnerability" (Security tab)
3. Response target: **72 hours** me acknowledgement, 7 days me fix/plan
4. Fix release hone ke baad credit (agar chaho to)

## Scope (kya report karna hai)

- ✅ Scope firewall bypass (`Scope` class ko out-of-scope request bhejne ka koi rasta)
- ✅ Evidence/secrets redaction failure (raw secrets evidence files me)
- ✅ License gate bypass (bina token run/runall chalana)
- ✅ Arbitrary file write / code injection via config/scope JSON

## Out of Scope

- ❌ Tool ka galat USE (bina authorization scan karna) — wo tumhari legal problem hai
- ❌ Demo tokens ka "leak" (wo intentionally public hain — Free tier)

## Safe Harbor

Good-faith research ko legal action nahi milega — bas dos/uptime attacks aur
data exfiltration mat karo.
