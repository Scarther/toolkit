#!/usr/bin/env bash
# Recon Script — run this first on every new target
# Usage: ./recon.sh <IP> [HOSTNAME]

set -euo pipefail

IP="${1:-}"
HOST="${2:-}"

if [[ -z "$IP" ]]; then
    echo "Usage: $0 <IP> [hostname]"
    exit 1
fi

HOST="${HOST:-$IP}"
OUTDIR="$(pwd)/output/${HOST}"
mkdir -p "$OUTDIR"

echo "[*] Target: $IP ($HOST)"
echo "[*] Output: $OUTDIR"
echo ""

# ── STEP 1: /etc/hosts entry ────────────────────────────────────────────────
if ! grep -q "$IP" /etc/hosts 2>/dev/null; then
    echo "[*] Adding $IP $HOST to /etc/hosts"
    echo "$IP    $HOST" | sudo tee -a /etc/hosts > /dev/null
else
    echo "[+] /etc/hosts already has $IP"
fi

# ── STEP 2: Fast port scan (all ports) ──────────────────────────────────────
echo ""
echo "[*] Phase 1: Fast full-port scan..."
nmap -p- --min-rate 5000 -T4 -oN "$OUTDIR/ports_fast.txt" "$IP" 2>/dev/null
echo "[+] Done. Open ports:"
grep "^[0-9].*open" "$OUTDIR/ports_fast.txt" | awk '{print "    "$1, $3}'

# Extract open ports for targeted scan
PORTS=$(grep "^[0-9].*open" "$OUTDIR/ports_fast.txt" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
echo "[*] Ports found: $PORTS"

# ── STEP 3: Detailed scan on open ports ─────────────────────────────────────
echo ""
echo "[*] Phase 2: Detailed scan on open ports ($PORTS)..."
nmap -p "$PORTS" -sV -sC -O --script=vuln -oN "$OUTDIR/ports_detail.txt" "$IP" 2>/dev/null
echo "[+] Detailed scan saved to $OUTDIR/ports_detail.txt"

# ── STEP 4: HTTP enumeration (if 80/443/8080 found) ─────────────────────────
for PORT in 80 443 8080 8443 8000 3000; do
    if echo "$PORTS" | grep -q "\b${PORT}\b"; then
        PROTO="http"
        [[ "$PORT" == "443" || "$PORT" == "8443" ]] && PROTO="https"
        URL="${PROTO}://${HOST}:${PORT}"

        echo ""
        echo "[*] Phase 3: Web enumeration on $URL"

        # whatweb fingerprint
        echo "  [*] Tech fingerprint..."
        whatweb "$URL" 2>/dev/null | tee "$OUTDIR/whatweb_${PORT}.txt" || \
            curl -sk -I "$URL" | tee "$OUTDIR/headers_${PORT}.txt"

        # Directory brute-force
        echo "  [*] Directory fuzzing (gobuster)..."
        if command -v gobuster &>/dev/null; then
            gobuster dir \
                -u "$URL" \
                -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
                -x php,html,txt,js,json,bak,old,zip \
                -t 40 \
                --timeout 10s \
                -o "$OUTDIR/gobuster_${PORT}.txt" 2>/dev/null &
            echo "  [+] gobuster running in background → $OUTDIR/gobuster_${PORT}.txt"
        elif command -v ffuf &>/dev/null; then
            ffuf -u "${URL}/FUZZ" \
                -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
                -e .php,.html,.txt,.js,.bak \
                -t 40 \
                -o "$OUTDIR/ffuf_${PORT}.json" \
                -of json 2>/dev/null &
            echo "  [+] ffuf running in background → $OUTDIR/ffuf_${PORT}.json"
        else
            echo "  [!] No gobuster/ffuf found. Install: sudo apt install gobuster ffuf"
        fi

        # Nikto
        echo "  [*] Nikto scan..."
        nikto -h "$URL" -output "$OUTDIR/nikto_${PORT}.txt" 2>/dev/null &
        echo "  [+] nikto running in background → $OUTDIR/nikto_${PORT}.txt"
    fi
done

# ── STEP 5: SSH banner grab (if 22 open) ─────────────────────────────────────
if echo "$PORTS" | grep -q "\b22\b"; then
    echo ""
    echo "[*] Phase 4: SSH banner + version..."
    nc -w 3 "$IP" 22 2>/dev/null | head -2 | tee "$OUTDIR/ssh_banner.txt" || true
    echo "[+] Note: SSH = do NOT brute-force. Wait for creds from web exploitation."
fi

# ── STEP 6: Summary ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo " RECON COMPLETE — $HOST ($IP)"
echo "════════════════════════════════════════════════"
echo " All output: $OUTDIR/"
echo " Open ports: $PORTS"
echo ""
echo " NEXT STEPS:"
echo "   1. Check $OUTDIR/whatweb_80.txt — what tech stack?"
echo "   2. Watch gobuster: tail -f $OUTDIR/gobuster_80.txt"
echo "   3. Read nikto output: cat $OUTDIR/nikto_80.txt"
echo "   4. Browse $URL manually — view-source, check cookies, JS files"
echo "   5. Look for login pages, upload forms, version numbers"
echo "════════════════════════════════════════════════"
