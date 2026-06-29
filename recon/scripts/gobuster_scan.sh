#!/usr/bin/env bash
# gobuster_scan.sh — Thorough directory, file, and vhost enumeration
# Usage: ./gobuster_scan.sh <URL> [HOSTNAME]
#
# Phases:
#   1. Directory brute-force
#   2. File extension fuzzing (smaller wordlist for speed)
#   3. Sensitive path check (manual list, instant)
#   4. Vhost / subdomain fuzzing
#   5. Summary

export PATH=/usr/bin:/bin:/usr/local/bin:$PATH

URL="${1:?Usage: $0 <URL> [HOSTNAME]}"
HOST="${2:-$(echo "$URL" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)}"
OUTDIR="$(pwd)/output/${HOST}/gobuster"
mkdir -p "$OUTDIR"

# Threads
THREADS=30

# SSL flag for https targets
CURL_FLAGS="-sk"
GB_FLAGS=""
echo "$URL" | grep -q "^https" && GB_FLAGS="-k"

# ── Wordlists ─────────────────────────────────────────────────────────────────
pick_wordlist() {
    for w in "$@"; do [ -f "$w" ] && echo "$w" && return; done
    echo ""
}

WL_DIR=$(pick_wordlist \
    /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    /usr/share/wordlists/dirb/common.txt)

WL_FILES=$(pick_wordlist \
    /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt \
    /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
    /usr/share/wordlists/dirb/common.txt)

WL_VHOST=$(pick_wordlist \
    /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/seclists/Discovery/DNS/namelist.txt)

# ── Helpers ───────────────────────────────────────────────────────────────────
RED='\033[91m'; YLW='\033[93m'; GRN='\033[92m'; RST='\033[0m'
SEP="════════════════════════════════════════════════════════════"

header() { echo ""; echo "$SEP"; echo "  $1"; echo "$SEP"; echo ""; }
skip()   { echo "  [---] $1 — skipped ($2)"; }

linecount() { [ -f "$1" ] && grep -c '' "$1" 2>/dev/null || echo 0; }

if ! command -v gobuster &>/dev/null; then
    echo "[!] gobuster not installed: sudo apt install gobuster"
    exit 1
fi

echo ""
echo "$SEP"
echo "  Gobuster Scan — $URL"
echo "  Host: $HOST"
echo "  Output: $OUTDIR"
echo "$SEP"

# ── Phase 1: Directory brute-force ───────────────────────────────────────────
header "Phase 1: Directory brute-force"

if [ -z "$WL_DIR" ]; then
    skip "directory scan" "no wordlist found — install seclists or dirbuster"
else
    echo "  Wordlist: $WL_DIR"
    echo "  Threads:  $THREADS"
    echo "  Running..."
    gobuster dir \
        -u "$URL" \
        -w "$WL_DIR" \
        -t "$THREADS" \
        --timeout 10s \
        -b 404 \
        -q \
        $GB_FLAGS \
        -o "$OUTDIR/dirs.txt" 2>/dev/null

    COUNT=$(linecount "$OUTDIR/dirs.txt")
    echo "  Found $COUNT paths:"
    cat "$OUTDIR/dirs.txt" 2>/dev/null
fi

# ── Phase 2: File extension fuzzing ──────────────────────────────────────────
header "Phase 2: File extension fuzzing"

# Use smaller wordlist — full list × 18 extensions is very slow
WL_F="${WL_FILES:-$WL_DIR}"
EXTENSIONS="php,html,txt,js,json,bak,old,zip,env,config,xml,log,sql,inc,sh,py,asp,aspx"

if [ -z "$WL_F" ]; then
    skip "file fuzzing" "no wordlist"
else
    echo "  Wordlist:   $WL_F"
    echo "  Extensions: $EXTENSIONS"
    echo "  Running..."
    gobuster dir \
        -u "$URL" \
        -w "$WL_F" \
        -x "$EXTENSIONS" \
        -t "$THREADS" \
        --timeout 10s \
        -b 404 \
        -q \
        $GB_FLAGS \
        -o "$OUTDIR/files.txt" 2>/dev/null

    COUNT=$(linecount "$OUTDIR/files.txt")
    echo "  Found $COUNT files:"
    echo ""
    echo "  -- High interest (backup/config/source) --"
    grep -iE "\.(bak|old|zip|sql|env|config|log|sh|py|inc|tar|gz)" \
        "$OUTDIR/files.txt" 2>/dev/null && true || echo "  none"
    echo ""
    echo "  -- PHP/ASP/HTML --"
    grep -iE "\.(php|asp|aspx|html)" "$OUTDIR/files.txt" 2>/dev/null \
        | head -30 || echo "  none"
    echo ""
    echo "  Full list: $OUTDIR/files.txt"
fi

# ── Phase 3: Sensitive path check ────────────────────────────────────────────
header "Phase 3: Sensitive path check (${#PATHS[@]:-0} paths)"

PATHS=(
    /.env /.env.local /.env.backup /.env.production /.env.example
    /.git/HEAD /.git/config /.gitignore /.git/COMMIT_EDITMSG
    /phpinfo.php /info.php /test.php /debug.php
    /config.php /config.json /config.yml /config.yaml
    /composer.json /composer.lock /package.json
    /robots.txt /sitemap.xml /.htaccess /.htpasswd
    /backup.zip /backup.sql /dump.sql /db.sql /database.sql
    /admin /administrator /admin.php /admin/login /admin/index.php
    /login /dashboard /panel /console /manage
    /api /api/v1 /api/v2 /graphql /swagger.json /api-docs /openapi.json
    /server-status /server-info
    /actuator /actuator/env /actuator/health /actuator/mappings
    /wp-login.php /wp-admin /wp-config.php /xmlrpc.php
    /changelog.txt /CHANGELOG.md /readme.txt /README.md
    /install.php /setup.php /upgrade.php
    /Dockerfile /docker-compose.yml
    /.DS_Store /web.config /WEB-INF/web.xml
)

echo "  Checking ${#PATHS[@]} paths..."
> "$OUTDIR/sensitive.txt"

for path in "${PATHS[@]}"; do
    CODE=$(/usr/bin/curl $CURL_FLAGS -o /dev/null -w "%{http_code}" \
           -H "Host: $HOST" --max-time 5 "${URL}${path}" 2>/dev/null)
    case "$CODE" in
        200)
            echo -e "  ${RED}[200 EXPOSED]${RST} $path"
            echo "[200] $path" >> "$OUTDIR/sensitive.txt"
            ;;
        301|302)
            REDIR=$(/usr/bin/curl $CURL_FLAGS -o /dev/null -w "%{redirect_url}" \
                    -H "Host: $HOST" --max-time 5 "${URL}${path}" 2>/dev/null)
            echo -e "  ${YLW}[${CODE} REDIR ]${RST} $path → $REDIR"
            echo "[${CODE}] $path → $REDIR" >> "$OUTDIR/sensitive.txt"
            ;;
        401)
            echo -e "  ${YLW}[401 AUTH  ]${RST} $path ← needs credentials"
            echo "[401] $path" >> "$OUTDIR/sensitive.txt"
            ;;
        403)
            echo -e "  ${YLW}[403 FORBID]${RST} $path ← exists but blocked"
            echo "[403] $path" >> "$OUTDIR/sensitive.txt"
            ;;
    esac
done

# ── Phase 4: Vhost fuzzing ────────────────────────────────────────────────────
header "Phase 4: Vhost / subdomain fuzzing"

if [ -z "$WL_VHOST" ]; then
    skip "vhost fuzzing" "no wordlist — install seclists"
else
    echo "  Fuzzing vhosts against $HOST..."
    echo "  Wordlist: $WL_VHOST"
    gobuster vhost \
        -u "$URL" \
        -w "$WL_VHOST" \
        --append-domain \
        -t "$THREADS" \
        --timeout 10s \
        -q \
        $GB_FLAGS \
        -o "$OUTDIR/vhosts.txt" 2>/dev/null

    COUNT=$(linecount "$OUTDIR/vhosts.txt")
    if [ "$COUNT" -gt 0 ]; then
        echo -e "  ${GRN}Found $COUNT vhost(s):${RST}"
        cat "$OUTDIR/vhosts.txt"
        echo ""
        echo "  → Add to /etc/hosts then re-run this script on each new vhost"
    else
        echo "  No additional vhosts found"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
header "Summary"

DIR_COUNT=$(linecount "$OUTDIR/dirs.txt")
FILE_COUNT=$(linecount "$OUTDIR/files.txt")
SENS_COUNT=$(linecount "$OUTDIR/sensitive.txt")
VHOST_COUNT=$(linecount "$OUTDIR/vhosts.txt")

echo "  Target:    $URL"
echo "  Output:    $OUTDIR/"
echo ""
printf "  Dirs:      %s found\n" "$DIR_COUNT"
printf "  Files:     %s found\n" "$FILE_COUNT"
printf "  Sensitive: %s found\n" "$SENS_COUNT"
printf "  Vhosts:    %s found\n" "$VHOST_COUNT"
echo ""

if [ "$SENS_COUNT" -gt 0 ]; then
    echo -e "  ${RED}EXPOSED PATHS:${RST}"
    grep "^\[200\]" "$OUTDIR/sensitive.txt" 2>/dev/null | while read -r line; do
        echo -e "    ${RED}$line${RST}"
    done
    echo ""
fi

echo "  NEXT STEPS:"
echo "    1. Any .bak/.zip/.sql files → download: curl -O ${URL}/<file>"
echo "    2. Any .env/config.php → read for credentials"
echo "    3. Any admin panels → try default creds (admin/admin, admin/password)"
echo "    4. Any vhosts found → add to /etc/hosts, re-run on new host"
echo "    5. Run vuln scanner: python3 scan/scripts/vuln_scan.py $URL"
echo ""
echo "$SEP"
