#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# recon_phase.sh — Phased Recon + Vulnerability Scan
#
# Usage: bash recon_phase.sh <target_domain>
#
# Phases:
#   1. Subdomain enumeration   (subfinder)
#   2. Live host detection     (httpx)
#   3. Historical URLs         (gau + waybackurls)
#   4. Vuln pattern matching   (gf)
#   5. Vulnerability scanning  (vuln_scan.py — JWT, cookies, info disclosure, injections)
#   6. Summary + attack plan
# ─────────────────────────────────────────────────────────────────────────────

export PATH=/usr/bin:/bin:/usr/local/bin:$PATH

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

OUTDIR="$(pwd)/output/${TARGET}"
mkdir -p "$OUTDIR/subdomains" "$OUTDIR/endpoints" "$OUTDIR/screenshots" "$OUTDIR/vuln"

RATE=5
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN_SCAN="$SCRIPT_DIR/vuln_scan.py"

# ── Helpers ───────────────────────────────────────────────────────────────────

phase() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    printf "║  %-60s ║\n" "$1"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

explain() {
    echo "  WHY: $1"
    echo ""
}

found() {
    echo "  FOUND: $1"
    echo ""
}

pause() {
    echo "  NEXT: $1"
    echo ""
    echo "  Press ENTER to continue, Ctrl+C to stop."
    read -r
}

# ─── Header ───────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
printf "║  Recon — %-51s ║\n" "$TARGET"
printf "║  Output: %-51s ║\n" "$OUTDIR"
echo "╚══════════════════════════════════════════════════════════════╝"

# ─── PHASE 1: Subdomain Enumeration ──────────────────────────────────────────

phase "PHASE 1 of 6: Subdomain Enumeration"

explain "Passive subdomain discovery via certificate transparency logs,
         DNS datasets, and public sources. No requests to the target yet.
         Forgotten dev/staging subdomains are where most bugs live."

if command -v subfinder &>/dev/null; then
    subfinder -d "$TARGET" -silent 2>/dev/null \
        | tee "$OUTDIR/subdomains/subfinder.txt"
    COUNT=$(wc -l < "$OUTDIR/subdomains/subfinder.txt")
    found "$COUNT subdomains → $OUTDIR/subdomains/subfinder.txt"
else
    echo "  [!] subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "$TARGET" > "$OUTDIR/subdomains/subfinder.txt"
    COUNT=1
    found "Skipped — added base domain as fallback"
fi

pause "Phase 2 checks which of these $COUNT subdomains are actually alive."

# ─── PHASE 2: Live Host Detection ────────────────────────────────────────────

phase "PHASE 2 of 6: Live Host Detection"

explain "httpx probes each subdomain for HTTP/HTTPS response, extracting
         status code, page title, server, and tech stack. Dead hosts are
         filtered out. What survives is your actual attack surface."

if command -v httpx &>/dev/null; then
    cat "$OUTDIR/subdomains/subfinder.txt" | \
        httpx -silent \
              -rate-limit "$RATE" \
              -status-code \
              -title \
              -tech-detect \
              -o "$OUTDIR/subdomains/live_hosts.txt" 2>/dev/null

    LIVE=$(wc -l < "$OUTDIR/subdomains/live_hosts.txt")
    found "$LIVE live hosts → $OUTDIR/subdomains/live_hosts.txt"
    cat "$OUTDIR/subdomains/live_hosts.txt" | head -20
else
    echo "  [!] httpx not installed. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "https://$TARGET" > "$OUTDIR/subdomains/live_hosts.txt"
    LIVE=1
    found "Skipped — using base domain as fallback"
fi

# Extract just URLs for later phases
grep -oP 'https?://[^\s]+' "$OUTDIR/subdomains/live_hosts.txt" \
    > "$OUTDIR/subdomains/live_urls.txt" 2>/dev/null || \
    echo "https://$TARGET" > "$OUTDIR/subdomains/live_urls.txt"

pause "Phase 3 pulls historical URLs from Wayback Machine and crawl archives."

# ─── PHASE 3: Historical URL Collection ──────────────────────────────────────

phase "PHASE 3 of 6: Historical URL Collection"

explain "gau queries Wayback Machine, Common Crawl, and AlienVault OTX for
         every URL ever seen on this domain. Old API endpoints, forgotten
         upload forms, and deprecated admin panels often still work.
         Old endpoints = less security focus = more bugs."

if command -v gau &>/dev/null; then
    gau --threads 1 \
        --blacklist png,jpg,gif,css,svg,ico,woff,woff2,ttf,eot \
        "$TARGET" 2>/dev/null | \
        tee "$OUTDIR/endpoints/gau_raw.txt"

    URL_COUNT=$(wc -l < "$OUTDIR/endpoints/gau_raw.txt")
    found "$URL_COUNT historical URLs collected"

    echo "  Interesting patterns:"
    grep -iE "(upload|import|export|admin|api|redirect|url=|src=|callback|webhook)" \
        "$OUTDIR/endpoints/gau_raw.txt" | \
        sort -u | \
        tee "$OUTDIR/endpoints/interesting_urls.txt" | \
        head -20

    INTERESTING=$(wc -l < "$OUTDIR/endpoints/interesting_urls.txt")
    found "$INTERESTING URLs match interesting patterns → $OUTDIR/endpoints/interesting_urls.txt"
else
    echo "  [!] gau not installed. Install: go install github.com/lc/gau/v2/cmd/gau@latest"
    found "Skipped"
fi

pause "Phase 4 categorizes URLs by vulnerability type using gf patterns."

# ─── PHASE 4: Vulnerability Pattern Matching ─────────────────────────────────

phase "PHASE 4 of 6: Vulnerability Pattern Matching"

explain "gf applies regex patterns to the URL list to surface parameters
         that commonly lead to specific bugs: SSRF (url=, src=, dest=),
         IDOR (numeric IDs in paths), SQLi (id=, cat=), open redirects
         (return=, next=). Shortcut from 10k URLs to 50 worth testing."

ALL_URLS="$OUTDIR/endpoints/all_urls.txt"
cat "$OUTDIR/endpoints/"*.txt 2>/dev/null | sort -u > "$ALL_URLS"

if command -v gf &>/dev/null; then
    echo ""
    for pattern in ssrf redirect sqli xss idor lfi rce; do
        OUT="$OUTDIR/endpoints/gf_${pattern}.txt"
        gf "$pattern" "$ALL_URLS" > "$OUT" 2>/dev/null || true
        COUNT=$(wc -l < "$OUT" 2>/dev/null || echo 0)
        if [ "$COUNT" -gt 0 ]; then
            echo "  [HIT] gf $pattern: $COUNT URLs → $OUT"
        else
            echo "  [---] gf $pattern: 0 matches"
        fi
    done
else
    echo "  [!] gf not installed. Install: go install github.com/tomnomnom/gf@latest"
    echo "      Add patterns: https://github.com/1ndianl33t/Gf-Patterns"
fi

pause "Phase 5 runs active vulnerability scanning against live hosts."

# ─── PHASE 5: Vulnerability Scanning ─────────────────────────────────────────

phase "PHASE 5 of 6: Active Vulnerability Scanning"

explain "Runs vuln_scan.py against each live host to check for:
         - JWT weaknesses (alg:none, weak secrets, privilege escalation)
         - Cookie security (missing Secure/HttpOnly/SameSite flags)
         - Cookie dissection (decode base64/JWT values, check entropy)
         - Info disclosure (.env, .git, phpinfo, debug endpoints)
         - Security headers (HSTS, CSP, X-Frame-Options)
         - CORS misconfiguration
         - SQLi, XSS, SSRF, LFI, SSTI, CMDi, IDOR, XXE, open redirect"

if [ ! -f "$VULN_SCAN" ]; then
    echo "  [!] vuln_scan.py not found at $VULN_SCAN"
    echo "      Skipping — place vuln_scan.py in the same directory as this script."
else
    if command -v python3 &>/dev/null; then
        # Scan up to 10 live hosts (respect rate limits)
        head -10 "$OUTDIR/subdomains/live_urls.txt" 2>/dev/null | while read -r url; do
            if [ -n "$url" ]; then
                echo ""
                echo "  Scanning: $url"
                python3 "$VULN_SCAN" "$url" --no-crawl --delay 1.0 \
                    2>/dev/null | tee -a "$OUTDIR/vuln/scan_output.txt"
            fi
        done

        echo ""
        found "Scan output → $OUTDIR/vuln/scan_output.txt"
        echo "  JSON/MD reports saved in current directory."
        echo "  Review for VULN and WARNING findings before manual testing."
    else
        echo "  [!] python3 not found. Install python3 to use vuln_scan.py."
    fi
fi

pause "Phase 6 shows your full attack plan."

# ─── PHASE 6: Summary ────────────────────────────────────────────────────────

phase "PHASE 6 of 6: Summary + Attack Plan"

echo "  RECON COMPLETE: $TARGET"
echo "  ═══════════════════════════════════════════════════════"
echo ""
echo "  Output: $OUTDIR"
echo ""
echo "  RESULTS:"
echo "  ─────────────────────────────────────────────────────"
printf "  Subdomains found:   %s\n" "$(wc -l < "$OUTDIR/subdomains/subfinder.txt" 2>/dev/null || echo 0)"
printf "  Live hosts:         %s\n" "$(wc -l < "$OUTDIR/subdomains/live_hosts.txt" 2>/dev/null || echo 0)"
printf "  Historical URLs:    %s\n" "$(wc -l < "$OUTDIR/endpoints/gau_raw.txt" 2>/dev/null || echo 0)"
printf "  SSRF candidates:    %s\n" "$(wc -l < "$OUTDIR/endpoints/gf_ssrf.txt" 2>/dev/null || echo 0)"
printf "  Redirect params:    %s\n" "$(wc -l < "$OUTDIR/endpoints/gf_redirect.txt" 2>/dev/null || echo 0)"
printf "  SQLi candidates:    %s\n" "$(wc -l < "$OUTDIR/endpoints/gf_sqli.txt" 2>/dev/null || echo 0)"
echo ""
echo "  ATTACK PRIORITIES:"
echo "  ─────────────────────────────────────────────────────"
echo "  1. Review vuln scan output:  $OUTDIR/vuln/scan_output.txt"
echo "     Focus on VULN findings first, then WARNINGs."
echo ""
echo "  2. SSRF — test URL params from gf_ssrf.txt:"
echo "     Try AWS metadata: http://169.254.169.254/latest/meta-data/"
echo "     Try internal: http://127.0.0.1/, http://localhost/"
echo ""
echo "  3. IDOR — test numeric IDs from gf_idor.txt:"
echo "     Increment/decrement IDs, try negative values, try UUIDs."
echo ""
echo "  4. Manual browse each live host through Burp Suite:"
echo "     Intercept OFF. Walk through the app. Map endpoints."
echo ""
echo "  5. Check interesting_urls.txt for upload/API/admin paths."
echo ""
echo "  Happy hunting."
