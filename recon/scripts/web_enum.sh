#!/usr/bin/env bash
# Web Enumeration — run when port 80/443 found
# Usage: ./web_enum.sh <URL> [output_dir]

URL="${1:-}"
OUTDIR="${2:-./web_enum_output}"

if [[ -z "$URL" ]]; then
    echo "Usage: $0 <URL> [output_dir]"
    exit 1
fi

mkdir -p "$OUTDIR"
echo "[*] Web enum: $URL"

# Headers + cookies
echo "[*] Headers..."
curl -skL -D "$OUTDIR/headers.txt" "$URL" -o "$OUTDIR/index.html"
echo "[+] Response headers → $OUTDIR/headers.txt"
echo "[+] Index page → $OUTDIR/index.html"

# Extract links from index
echo "[*] Extracting links from index..."
grep -oP 'href="[^"]*"' "$OUTDIR/index.html" | sort -u | tee "$OUTDIR/links.txt"

# Vhost fuzzing — critical step most beginners miss
echo ""
echo "[*] Vhost fuzzing (subdomains)..."
DOMAIN=$(echo "$URL" | sed 's|https\?://||' | cut -d/ -f1)
if command -v ffuf &>/dev/null; then
    ffuf -u "$URL" \
        -H "Host: FUZZ.${DOMAIN}" \
        -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        -fs 0 \
        -t 40 \
        -o "$OUTDIR/vhosts.json" -of json 2>/dev/null &
    echo "[+] vhost scan running → $OUTDIR/vhosts.json"
fi

# Common sensitive files
echo "[*] Checking common sensitive paths..."
for path in /robots.txt /sitemap.xml /.git/HEAD /.env /config.php /admin /login /wp-login.php /phpinfo.php /backup.zip; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${URL}${path}")
    [[ "$CODE" != "404" && "$CODE" != "000" ]] && echo "  [$CODE] ${URL}${path}"
done | tee "$OUTDIR/sensitive_paths.txt"

echo ""
echo "[+] Done. Check $OUTDIR/"
