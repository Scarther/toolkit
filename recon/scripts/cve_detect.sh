#!/usr/bin/env bash
# CVE Detection — identifies CMS/framework and checks known critical CVEs
# Usage: ./cve_detect.sh <IP> [hostname]

export PATH=/usr/bin:/bin:$PATH

IP="${1:-}"
HOST="${2:-$IP}"
URL="http://${HOST}"
[[ -z "$IP" ]] && { echo "Usage: $0 <IP> [hostname]"; exit 1; }

echo "════════════════════════════════════════"
echo " CVE Detection — $HOST ($IP)"
echo "════════════════════════════════════════"

# ── Tech fingerprint ──────────────────────────────────────────────────────────
echo ""
echo "[*] Fingerprinting..."
HEADERS=$(/usr/bin/curl -skI "$URL")
INDEX=$(/usr/bin/curl -skL "$URL")

SERVER=$(echo "$HEADERS" | grep -i "^server:" | awk '{print $2}')
echo "    Server: $SERVER"

POWERED=$(echo "$HEADERS" | grep -i "x-powered-by:" | awk '{print $2}')
[[ -n "$POWERED" ]] && echo "    X-Powered-By: $POWERED"

# ── CraftCMS detection ────────────────────────────────────────────────────────
if echo "$INDEX" | grep -qi "window\.Craft\s*=" || /usr/bin/curl -skL "$URL/admin" | grep -qi "craftcms\|window\.Craft"; then
    echo ""
    echo "[!] DETECTED: CraftCMS"

    # Try to get version
    VER=$(/usr/bin/curl -skL "$URL/admin/login" | grep -oP '"appVersion":"[^"]*"' | head -1)
    [[ -z "$VER" ]] && VER="unknown (check composer.lock)"
    echo "    Version: $VER"

    echo ""
    echo "    CVEs to test:"
    echo "    ► CVE-2023-41892 — Unauthenticated RCE via SSTI (Craft < 4.4.15)"
    echo "      Test: POST /index.php with conditions/render action"
    echo "      Script: ../exploit/scripts/craft_cve_2023_41892.sh"
    echo ""
    echo "    ► CVE-2024-56145 — Unauthenticated RCE (Craft CMS 4.x/5.x)"
    echo "      Test: Template injection via user-supplied input"
    echo "      Script: ../exploit/scripts/craft_cve_2024_56145.sh"

    # Quick CVE-2023-41892 probe
    echo ""
    echo "    [*] Quick probe — CVE-2023-41892..."
    PROBE=$(/usr/bin/curl -sk -X POST "$URL/index.php" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d 'action=conditions/render&test[class]=craft\elements\conditions\ElementCondition&test[config]={"name":"test","as+x":{"class":"craft\\web\\twig\\variables\\CraftVariable"}}' \
      2>/dev/null | grep -oi "exception\|error\|twig\|craftcms" | head -3)
    echo "    Response signals: ${PROBE:-none}"
fi

# ── WordPress detection ───────────────────────────────────────────────────────
if echo "$INDEX" | grep -qi "wp-content\|wp-includes\|wordpress"; then
    echo ""
    echo "[!] DETECTED: WordPress"
    VER=$(echo "$INDEX" | grep -oP 'WordPress [0-9]+\.[0-9]+[^<"]*' | head -1)
    echo "    Version: ${VER:-unknown}"
    echo "    CVEs to test:"
    echo "    ► Run: wpscan --url $URL --enumerate p,u,t --api-token YOUR_TOKEN"
    echo "    ► CVE-2024-27956 — WP Automatic plugin SQLi (if plugin present)"
fi

# ── Drupal detection ─────────────────────────────────────────────────────────
if echo "$INDEX" | grep -qi "drupal\|Drupal.settings\|/sites/default"; then
    echo ""
    echo "[!] DETECTED: Drupal"
    VER=$(echo "$INDEX" | grep -oP 'Drupal [0-9]+\.[0-9]+' | head -1)
    echo "    Version: ${VER:-unknown}"
    echo "    CVEs: Drupalgeddon2 (CVE-2018-7600), CVE-2019-6340"
    echo "    Check: curl '$URL/CHANGELOG.txt' for exact version"
fi

# ── Laravel detection ─────────────────────────────────────────────────────────
if echo "$HEADERS$INDEX" | grep -qi "laravel\|laravel_session\|X-Powered-By: PHP"; then
    LARAVEL_CHECK=$(/usr/bin/curl -sk "$URL/_ignition/health-check" | grep -i "can_execute_commands\|laravel" | head -2)
    if [[ -n "$LARAVEL_CHECK" ]]; then
        echo ""
        echo "[!] DETECTED: Laravel + Ignition"
        echo "    ► CVE-2021-3129 — Unauthenticated RCE via Ignition debug endpoint"
        echo "    Response: $LARAVEL_CHECK"
    fi
fi

# ── PHP version disclosure ─────────────────────────────────────────────────────
PHP_VER=$(echo "$HEADERS" | grep -oP "PHP/[0-9]+\.[0-9]+\.[0-9]+" | head -1)
[[ -n "$PHP_VER" ]] && echo "" && echo "[!] PHP version disclosed: $PHP_VER"

# ── Interesting status codes ─────────────────────────────────────────────────
echo ""
echo "[*] Checking interesting paths (200/301/302/403 only)..."
for path in /robots.txt /sitemap.xml /.git/HEAD /.env /.htaccess /admin /login /dashboard \
            /api /api/v1 /api/v2 /graphql /upload /backup /phpinfo.php /config.php \
            /wp-login.php /wp-admin /xmlrpc.php /server-status /server-info \
            /console /actuator /actuator/env /.well-known/security.txt \
            /changelog.txt /CHANGELOG.md /readme.txt /README.md /composer.json; do
    CODE=$(/usr/bin/curl -sk -o /dev/null -w "%{http_code}" \
           -H "Host: $HOST" "http://${IP}${path}" 2>/dev/null)
    case "$CODE" in
        200) echo "    [200 OK    ] $path" ;;
        301|302) REDIR=$(/usr/bin/curl -sk -o /dev/null -w "%{redirect_url}" -H "Host: $HOST" "http://${IP}${path}")
                 echo "    [${CODE} REDIR ] $path → $REDIR" ;;
        401) echo "    [401 AUTH  ] $path ← needs credentials" ;;
        403) echo "    [403 FORBID] $path ← exists but blocked" ;;
    esac
done

echo ""
echo "════════════════════════════════════════"
echo " Done. Check exploit/scripts/ for CVE PoCs."
echo "════════════════════════════════════════"
