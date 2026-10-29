#!/usr/bin/env bash
# =============================================================================
# WASP setup.sh - Kali Linux (aur koi bhi Debian-based) quick installer
# Usage:  chmod +x setup.sh && ./setup.sh
# =============================================================================
set -u
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[x]${NC} $1"; }

cd "$(dirname "$0")"
echo ""
echo "=========================================="
echo "  WASP setup - Web Assessment Script Pack"
echo "  Authorized security testing ONLY"
echo "=========================================="
echo ""

# ---- 1. Python check -------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 nahi mila. Install: sudo apt install python3 python3-pip"
    exit 1
fi
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
ok "python3 $PYV"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
    || { fail "Python 3.8+ chahiye (tumhara: $PYV)"; exit 1; }

# ---- 2. Dependencies -------------------------------------------------------
# WASP pure stdlib hai - pip install OPTIONAL hai (dnspython).
MISSING=$(python3 - <<'EOF'
missing = []
try:
    import dns.resolver  # noqa
except ImportError:
    missing.append("dnspython")
print(" ".join(missing))
EOF
)
if [ -n "$MISSING" ]; then
    warn "Optional dependency missing: $MISSING"
    if command -v pip3 >/dev/null 2>&1; then
        # Kali (PEP 668) par system pip block karta hai - graceful fallback
        pip3 install --quiet $MISSING 2>/dev/null \
            || pip3 install --quiet --break-system-packages $MISSING 2>/dev/null \
            || warn "dnspython install nahi hua (optional hai - WASP phir bhi chalega)"
        ok "optional deps installed: $MISSING"
    else
        warn "pip3 nahi mila - optional deps skip (WASP stdlib par chalta hai)"
    fi
else
    ok "dependencies: saare present (pure stdlib + optional dnspython)"
fi

# ---- 3. config.json (engine tuning - template se banao) --------------------
if [ ! -f config.json ]; then
    cp wasp_config.json config.json
    ok "config.json bana diya (wasp_config.json ULTRA master se)"
else
    ok "config.json already present (untouched)"
fi

# ---- 4. scope.json (PRIVATE - template se banao) ---------------------------
if [ ! -f scope.json ]; then
    cp scope.example.json scope.json
    chmod 600 scope.json
    ok "scope.json bana diya (scope.example.json se) - AB EDIT KARO"
    warn "scope.json me authorized=false hai - apne authorized targets daalo"
else
    ok "scope.json already present (untouched)"
fi

# ---- 5. Optional Kali tools (presence-only check) --------------------------
echo ""
echo "-- Optional Kali tools (na ho to modules builtin fallback use karte hain) --"
for t in nmap subfinder amass httpx ffuf gobuster; do
    if command -v "$t" >/dev/null 2>&1; then
        ok "$t: present"
    else
        warn "$t: missing (optional)"
    fi
done

# ---- 6. Health check -------------------------------------------------------
echo ""
python3 wasp.py doctor || warn "doctor me kuch issues - upar padho"
echo ""
ok "Setup complete! Next steps:"
echo "    1) nano scope.json                # authorized=true + APNE targets"
echo "    2) export WASP_TOKEN=WASP-FREE-2025-DEMO"
echo "    3) python3 wasp.py verify         # pre-flight"
echo "    4) python3 wasp.py run --module 2 # pehla phase (understand)"
echo ""
echo "  Legal: sirf AUTHORIZED targets par chalao (scope.json = tumhara proof)."
echo ""
