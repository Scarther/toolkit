#!/usr/bin/env python3
"""
deeprecon.py — Full deep recon from a single IP
Phases:
  1. Fast full-port scan (all 65535 ports)
  2. Detailed service/version/script scan on open ports
  3. Service-specific enum (web, SSH, FTP, SMB, DNS, Redis, etc.)
  4. Web path discovery (gobuster/ffuf)
  5. Summary: ports, services, web paths, interesting finds, next steps

Usage:
  python3 deeprecon.py <IP>
  python3 deeprecon.py <IP> <HOSTNAME>
  python3 deeprecon.py <IP> --output ./results
"""

import subprocess
import sys
import os
import re
import json
import shutil
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

# ── Colors ────────────────────────────────────────────────────────────────────

class C:
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'
    BLUE   = '\033[94m'
    BOLD   = '\033[1m'
    END    = '\033[0m'

def red(s):    return f"{C.RED}{s}{C.END}"
def yellow(s): return f"{C.YELLOW}{s}{C.END}"
def green(s):  return f"{C.GREEN}{s}{C.END}"
def cyan(s):   return f"{C.CYAN}{s}{C.END}"
def bold(s):   return f"{C.BOLD}{s}{C.END}"

# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(title: str):
    print(f"\n{bold('═'*62)}")
    print(f"{bold(f'  {title}')}")
    print(f"{bold('═'*62)}\n")

def section(title: str):
    print(f"\n{cyan('┌─')} {bold(title)}")

def item(label: str, value: str, color=None):
    val = color(value) if color else value
    print(f"   {label:<20} {val}")

def run(cmd: list, timeout: int = 300, capture: bool = True) -> str:
    """Run command, return stdout. Returns '' on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout
        )
        return result.stdout or ''
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ''

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def save(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

# ── Nmap parsing ──────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_path: Path) -> list[dict]:
    """Parse nmap XML output into list of port dicts."""
    if not xml_path.exists():
        return []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return []

    ports = []
    for host in root.findall('host'):
        for port_el in host.findall('.//port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue

            service_el = port_el.find('service')
            scripts = {}
            for script in port_el.findall('script'):
                scripts[script.get('id', '')] = script.get('output', '')

            ports.append({
                'port':     int(port_el.get('portid', 0)),
                'proto':    port_el.get('protocol', 'tcp'),
                'service':  service_el.get('name', '') if service_el is not None else '',
                'product':  service_el.get('product', '') if service_el is not None else '',
                'version':  service_el.get('version', '') if service_el is not None else '',
                'extrainfo': service_el.get('extrainfo', '') if service_el is not None else '',
                'tunnel':   service_el.get('tunnel', '') if service_el is not None else '',
                'scripts':  scripts,
            })

    return sorted(ports, key=lambda p: p['port'])


# ── Phase 1+2: Nmap ───────────────────────────────────────────────────────────

def phase_nmap(ip: str, outdir: Path) -> list[dict]:
    section("Phase 1 — Fast full-port scan")
    print(f"   Target: {ip}  |  All 65535 ports  |  --min-rate 5000")

    fast_xml = outdir / 'nmap_fast.xml'
    run(['nmap', '-p-', '--min-rate', '5000', '-T4',
         '-oX', str(fast_xml), '-oN', str(outdir / 'nmap_fast.txt'),
         ip], timeout=600)

    fast_ports = parse_nmap_xml(fast_xml)
    open_ports = ','.join(str(p['port']) for p in fast_ports) or '22,80'

    print(f"\n   Open ports found: {green(open_ports)}\n")

    section("Phase 2 — Detailed service/version/script scan")
    print(f"   Ports: {open_ports}  |  -sV -sC -O --script=vuln")

    detail_xml = outdir / 'nmap_detail.xml'
    run(['nmap', '-p', open_ports,
         '-sV', '-sC', '-O',
         '--script', 'vuln,auth,default,discovery',
         '-oX', str(detail_xml),
         '-oN', str(outdir / 'nmap_detail.txt'),
         ip], timeout=600)

    detailed = parse_nmap_xml(detail_xml)
    ports = detailed if detailed else fast_ports

    # CVE lookup for each detected service
    section("Phase 2b — CVE lookup (searchsploit + cve.circl.lu)")
    seen = set()
    for p in ports:
        product = p['product'] or p['service']
        version = p['version']
        key = f"{product}:{version}"
        if key not in seen and product:
            seen.add(key)
            lookup_cves(product, version)

    return ports


# ── Phase 3: Service-specific enum ───────────────────────────────────────────

INTERESTING = []   # global findings list
WEB_URLS    = []   # web URLs discovered during enum

def add_to_hosts(ip: str, host: str):
    """Add IP/hostname to /etc/hosts if not already present."""
    if ip == host:
        return  # no hostname provided, skip
    try:
        current = Path('/etc/hosts').read_text()
    except PermissionError:
        current = ''

    if ip in current and host in current:
        print(f"   {green('[/etc/hosts]')} {ip} {host} already present")
        return

    entry = f"{ip}    {host}"
    result = subprocess.run(
        ['sudo', 'tee', '-a', '/etc/hosts'],
        input=f"\n{entry}\n", capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"   {green('[/etc/hosts]')} Added: {entry}")
    else:
        print(f"   {yellow('[/etc/hosts]')} Could not auto-add — run manually:")
        print(f"   echo '{entry}' | sudo tee -a /etc/hosts")


def link(url: str) -> str:
    """Return OSC 8 clickable hyperlink for terminals that support it."""
    return f"\033]8;;{url}\033\\{url}\033]8;;\033\\"


def flag(finding: str, severity: str = 'medium'):
    icon = red('[CRITICAL]') if severity == 'critical' else \
           yellow('[WARN]') if severity == 'medium' else \
           cyan('[INFO]')
    msg = f"   {icon} {finding}"
    print(msg)
    INTERESTING.append({'severity': severity, 'finding': finding})

def enum_web(ip: str, port: int, host: str, outdir: Path, https: bool = False):
    proto = 'https' if https else 'http'
    url = f"{proto}://{host}:{port}" if port not in (80, 443) else f"{proto}://{host}"

    if url not in WEB_URLS:
        WEB_URLS.append(url)

    add_to_hosts(ip, host)

    section(f"Web — {url}")

    # Headers
    headers_out = run(['curl', '-skI', '--max-time', '10', url])
    if headers_out:
        save(outdir / f'web_{port}_headers.txt', headers_out)
        for line in headers_out.splitlines()[:5]:
            print(f"   {line}")

        for h in ('Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version'):
            m = re.search(rf'^{h}:\s*(.+)', headers_out, re.IGNORECASE | re.MULTILINE)
            if m:
                flag(f"Version disclosure — {h}: {m.group(1).strip()}", 'medium')

    # whatweb
    if tool_exists('whatweb'):
        ww = run(['whatweb', '--quiet', url], timeout=30)
        if ww:
            save(outdir / f'web_{port}_whatweb.txt', ww)
            print(f"\n   Tech stack: {ww[:200]}")

    # gobuster
    wordlist = next((w for w in [
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
        '/usr/share/wordlists/dirb/common.txt',
    ] if os.path.exists(w)), None)

    if wordlist and tool_exists('gobuster'):
        print(f"\n   Directory fuzzing (gobuster)...")
        gb_out = outdir / f'web_{port}_gobuster.txt'
        run(['gobuster', 'dir', '-u', url, '-w', wordlist,
             '-x', 'php,html,txt,js,json,bak,zip,env,config',
             '-t', '30', '--timeout', '10s', '-q', '-o', str(gb_out)],
            timeout=300)
        if gb_out.exists():
            paths = gb_out.read_text()
            hits = [l for l in paths.splitlines() if l.strip()]
            print(f"   Found {green(str(len(hits)))} paths")
            for h in hits[:30]:
                print(f"   {h}")
            if len(hits) > 30:
                print(f"   ... {len(hits)-30} more in {gb_out}")
    elif tool_exists('ffuf'):
        print(f"\n   Directory fuzzing (ffuf)...")
        ff_out = outdir / f'web_{port}_ffuf.json'
        run(['ffuf', '-u', f'{url}/FUZZ', '-w', wordlist or '', '-t', '30',
             '-o', str(ff_out), '-of', 'json', '-s'], timeout=300)
    else:
        print(f"\n   {yellow('[!] Install gobuster or ffuf for path discovery')}")

    # Quick sensitive path check
    print(f"\n   Checking sensitive paths...")
    sensitive = [
        '/.env', '/.git/HEAD', '/phpinfo.php', '/admin', '/login',
        '/api', '/swagger.json', '/api-docs', '/actuator/env',
        '/backup.zip', '/backup.sql', '/.htaccess', '/config.php',
        '/wp-login.php', '/robots.txt', '/sitemap.xml',
    ]
    for path in sensitive:
        code = run(['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}',
                    '--max-time', '5', f'{url}{path}'])
        code = code.strip()
        if code in ('200', '301', '302', '403', '401'):
            color = red if code == '200' else yellow
            print(f"   {color(f'[{code}]')} {path}")
            if code == '200' and path in ('/.env', '/.git/HEAD', '/phpinfo.php', '/actuator/env'):
                flag(f"Sensitive path exposed: {url}{path}", 'critical')

def enum_ftp(ip: str, port: int, outdir: Path):
    section(f"FTP — {ip}:{port}")
    out = run(['nmap', '-p', str(port), '--script', 'ftp-anon,ftp-bounce,ftp-syst',
               '-oN', str(outdir / 'ftp.txt'), ip], timeout=60)
    if 'Anonymous FTP login allowed' in out or 'ftp-anon' in out:
        flag(f"FTP anonymous login ALLOWED on port {port}", 'critical')
    else:
        print(f"   Anonymous login: {red('denied')}")
    print(f"   Full output → {outdir}/ftp.txt")

def enum_ssh(ip: str, port: int, outdir: Path):
    section(f"SSH — {ip}:{port}")
    banner_out = run(['nc', '-w', '3', ip, str(port)], timeout=10)
    if banner_out:
        save(outdir / 'ssh_banner.txt', banner_out)
        print(f"   Banner: {banner_out[:100].strip()}")
        m = re.search(r'OpenSSH[_\s]([\d.]+)', banner_out)
        if m:
            ver = float(m.group(1).split('p')[0]) if m else 99.0
            if ver < 7.7:
                flag(f"SSH OpenSSH {m.group(1)} — check CVE-2018-15473 (user enumeration)", 'medium')
            if ver < 6.6:
                flag(f"SSH OpenSSH {m.group(1)} — OLD version, multiple known CVEs", 'critical')
    print(f"   Note: do NOT brute-force SSH. Wait for credentials from other services.")

def enum_smb(ip: str, port: int, outdir: Path):
    section(f"SMB — {ip}:{port}")
    if tool_exists('enum4linux'):
        print(f"   Running enum4linux (null session)...")
        out = run(['enum4linux', '-a', ip], timeout=120)
        save(outdir / 'smb_enum4linux.txt', out)
        if 'No password required' in out or 'NULL session' in out.lower():
            flag(f"SMB null session allowed on {ip}", 'critical')
        shares = re.findall(r'Sharename\s+Type\s+Comment.*?\n(.*?)\n\n', out, re.DOTALL)
        if shares:
            print(f"   Shares found:\n   {shares[0][:300]}")
    else:
        print(f"   {yellow('[!] enum4linux not found — running nmap SMB scripts')}")
        out = run(['nmap', '-p', str(port),
                   '--script', 'smb-enum-shares,smb-enum-users,smb-vuln-ms17-010,smb-security-mode',
                   '-oN', str(outdir / 'smb_nmap.txt'), ip], timeout=120)
        if 'VULNERABLE' in out:
            flag(f"SMB vulnerability detected — check {outdir}/smb_nmap.txt", 'critical')
        if 'NT_STATUS_OK' in out:
            flag(f"SMB null session allowed", 'critical')
        print(out[:500] if out else "   No output")

def enum_dns(ip: str, port: int, outdir: Path, host: str):
    section(f"DNS — {ip}:{port}")
    print(f"   Zone transfer attempt on {host}...")
    out = run(['dig', f'@{ip}', host, 'AXFR'], timeout=30)
    save(outdir / 'dns_zonetransfer.txt', out)
    if 'XFR size' in out or '; Transfer failed' not in out:
        flag(f"DNS zone transfer may be allowed — check {outdir}/dns_zonetransfer.txt", 'critical')
    else:
        print(f"   Zone transfer: denied (expected)")
    # Any records
    any_out = run(['dig', f'@{ip}', host, 'ANY'], timeout=15)
    save(outdir / 'dns_any.txt', any_out)

def enum_smtp(ip: str, port: int, outdir: Path):
    section(f"SMTP — {ip}:{port}")
    out = run(['nmap', '-p', str(port),
               '--script', 'smtp-commands,smtp-enum-users,smtp-open-relay',
               '-oN', str(outdir / 'smtp.txt'), ip], timeout=60)
    if 'open-relay' in out.lower():
        flag(f"SMTP open relay on port {port}", 'critical')
    if 'smtp-enum-users' in out:
        flag(f"SMTP user enumeration possible", 'medium')
    print(out[:400] if out else "   Check smtp.txt")

def enum_snmp(ip: str, port: int, outdir: Path):
    section(f"SNMP — {ip}:{port}")
    if tool_exists('snmpwalk'):
        for community in ('public', 'private', 'community', 'manager'):
            out = run(['snmpwalk', '-c', community, '-v1', ip, '1.3.6.1.2.1.1.1.0'], timeout=10)
            if out and 'No Such' not in out:
                flag(f"SNMP community string '{community}' works on {ip}", 'critical')
                save(outdir / f'snmp_{community}.txt', out)
                break
    else:
        out = run(['nmap', '-sU', '-p', str(port),
                   '--script', 'snmp-info,snmp-sysdescr',
                   '-oN', str(outdir / 'snmp.txt'), ip], timeout=60)

def enum_redis(ip: str, port: int, outdir: Path):
    section(f"Redis — {ip}:{port}")
    out = run(['redis-cli', '-h', ip, '-p', str(port), 'INFO', 'server'], timeout=10)
    if out and 'redis_version' in out:
        flag(f"Redis unauthenticated access on port {port}", 'critical')
        save(outdir / 'redis_info.txt', out)
        m = re.search(r'redis_version:(.+)', out)
        if m:
            print(f"   Redis version: {m.group(1).strip()}")
    else:
        print(f"   Redis: authentication required or not accessible")

def enum_mysql(ip: str, port: int, outdir: Path):
    section(f"MySQL — {ip}:{port}")
    out = run(['nmap', '-p', str(port),
               '--script', 'mysql-empty-password,mysql-info,mysql-databases',
               '-oN', str(outdir / 'mysql.txt'), ip], timeout=60)
    if 'mysql-empty-password' in out and 'account has empty password' in out:
        flag(f"MySQL empty password account found on port {port}", 'critical')
    print(out[:300] if out else "   Check mysql.txt")

def enum_nfs(ip: str, port: int, outdir: Path):
    section(f"NFS — {ip}:{port}")
    out = run(['showmount', '-e', ip], timeout=15)
    save(outdir / 'nfs_mounts.txt', out)
    if out and 'Export list' in out:
        flag(f"NFS exports available — check for world-readable mounts", 'critical')
        print(out)
    else:
        print(f"   No NFS exports found")

def enum_mongo(ip: str, port: int, outdir: Path):
    section(f"MongoDB — {ip}:{port}")
    out = run(['nmap', '-p', str(port),
               '--script', 'mongodb-info,mongodb-databases',
               '-oN', str(outdir / 'mongo.txt'), ip], timeout=60)
    if 'MongoDB' in out:
        flag(f"MongoDB accessible on port {port} — check for auth bypass", 'medium')
    print(out[:300] if out else "   Check mongo.txt")


# ── Service dispatch ──────────────────────────────────────────────────────────

WEB_PORTS    = {80, 443, 8080, 8443, 8000, 8008, 3000, 5000, 8888}
HTTPS_PORTS  = {443, 8443}

def enum_services(ports: list[dict], ip: str, host: str, outdir: Path):
    section("Phase 3 — Service-specific enumeration")

    for p in ports:
        port = p['port']
        svc  = p['service'].lower()
        tunnel = p['tunnel'].lower()

        if port in WEB_PORTS or svc in ('http', 'https', 'http-alt') or 'http' in svc:
            https = port in HTTPS_PORTS or tunnel == 'ssl' or 'ssl' in svc
            enum_web(ip, port, host, outdir / 'web', https)

        elif port == 21 or svc == 'ftp':
            enum_ftp(ip, port, outdir)

        elif port == 22 or svc == 'ssh':
            enum_ssh(ip, port, outdir)

        elif port in (139, 445) or svc in ('netbios-ssn', 'microsoft-ds', 'smb'):
            enum_smb(ip, port, outdir)

        elif port == 53 or svc == 'domain':
            enum_dns(ip, port, outdir, host)

        elif port in (25, 465, 587) or svc == 'smtp':
            enum_smtp(ip, port, outdir)

        elif port == 161 or svc == 'snmp':
            enum_snmp(ip, port, outdir)

        elif port == 6379 or svc == 'redis':
            enum_redis(ip, port, outdir)

        elif port == 3306 or svc in ('mysql', 'mariadb'):
            enum_mysql(ip, port, outdir)

        elif port in (111, 2049) or svc in ('rpcbind', 'nfs'):
            enum_nfs(ip, port, outdir)

        elif port == 27017 or svc == 'mongodb':
            enum_mongo(ip, port, outdir)

        else:
            svc_name = p['product'] or svc or 'unknown'
            print(f"\n   {cyan(f'{port}/tcp')} — {svc_name} {p['version']} "
                  f"(no specific enum module — check nmap_detail.txt)")


# ── Phase 4: Summary ─────────────────────────────────────────────────────────

def print_summary(ip: str, host: str, ports: list[dict], outdir: Path):
    banner(f"RECON SUMMARY — {host} ({ip})")

    # Ports table
    print(bold("OPEN PORTS"))
    print(f"  {'PORT':<10} {'PROTO':<6} {'SERVICE':<16} {'VERSION'}")
    print(f"  {'─'*10} {'─'*6} {'─'*16} {'─'*30}")
    for p in ports:
        version = f"{p['product']} {p['version']}".strip() or '—'
        portlabel = green(f"{p['port']}/{p['proto']}")
        print(f"  {portlabel:<28} {p['proto']:<6} {p['service']:<16} {version}")

    # Web paths
    web_dir = outdir / 'web'
    gb_files = list(web_dir.glob('*_gobuster.txt')) if web_dir.exists() else []
    if gb_files:
        print(f"\n{bold('WEB PATHS FOUND')}")
        for f in gb_files:
            lines = [l for l in f.read_text().splitlines() if l.strip()]
            port_m = re.search(r'_(\d+)_gobuster', f.name)
            port_label = port_m.group(1) if port_m else '?'
            print(f"\n  Port {port_label}:")
            for l in lines[:40]:
                status = re.search(r'\(Status: (\d+)\)', l)
                code = status.group(1) if status else '???'
                color = red if code == '200' else (yellow if code in ('301','302','403') else str)
                print(f"  {color(f'[{code}]')} {l.split('(')[0].strip()}")
            if len(lines) > 40:
                print(f"  ... {len(lines)-40} more → {f}")

    # CVE summary
    if CVE_HITS:
        print(f"\n{bold('CVEs / EXPLOITS FOUND')}")
        for product, version, source, cve_id, score, title in CVE_HITS:
            score_str = f"{score:.1f}" if isinstance(score, float) else str(score)
            color = red if source == 'searchsploit' or (isinstance(score, float) and score >= 9.0) \
                    else (yellow if isinstance(score, float) and score >= 7.0 else cyan)
            print(f"  {color(f'[{source}]')} {product} {version} — {cve_id} (CVSS {score_str})")
            print(f"           {title[:80]}")

    # Interesting findings
    if INTERESTING:
        print(f"\n{bold('INTERESTING FINDINGS')}")
        crits = [i for i in INTERESTING if i['severity'] == 'critical']
        warns = [i for i in INTERESTING if i['severity'] == 'medium']
        infos = [i for i in INTERESTING if i['severity'] == 'info']
        for i in crits:
            print(f"  {red('[CRITICAL]')} {i['finding']}")
        for i in warns:
            print(f"  {yellow('[WARN]   ')} {i['finding']}")
        for i in infos:
            print(f"  {cyan('[INFO]   ')} {i['finding']}")
    else:
        print(f"\n{bold('INTERESTING FINDINGS')}")
        print(f"  {green('None flagged automatically — review nmap_detail.txt')}")

    # Next steps
    print(f"\n{bold('RECOMMENDED NEXT STEPS')}")
    has_web = any(p['port'] in WEB_PORTS or 'http' in p['service'] for p in ports)
    has_smb = any(p['port'] in (139, 445) for p in ports)
    has_ftp = any(p['port'] == 21 for p in ports)
    has_ssh = any(p['port'] == 22 for p in ports)

    step = 1
    if crits if INTERESTING else []:
        print(f"  {step}. Fix critical findings above first — highest reward")
        step += 1
    if has_web:
        web_url = f"http://{host}"
        print(f"  {step}. Run vuln scanner:  python3 vuln_scan.py {web_url}")
        step += 1
        print(f"  {step}. Browse manually through Burp (intercept OFF)")
        step += 1
    if has_ftp:
        print(f"  {step}. FTP: ftp {ip}  →  try anonymous / anonymous")
        step += 1
    if has_smb:
        print(f"  {step}. SMB: smbclient -L //{ip} -N  →  list shares")
        print(f"       smbclient //{ip}/<share> -N  →  browse share")
        step += 1
    if has_ssh:
        print(f"  {step}. SSH: do NOT brute-force. Get credentials from other services first.")
        step += 1
    print(f"  {step}. Full nmap detail: {outdir}/nmap_detail.txt")

    # Save markdown report
    save_report(ip, host, ports, outdir)
    print(f"\n  Report saved: {outdir}/report.md")
    print(f"  All output:   {outdir}/")

    # Clickable URLs + vuln scan prompt
    if WEB_URLS:
        print(f"\n{bold('WEB TARGETS FOUND')}")
        for u in WEB_URLS:
            print(f"  {green('→')} {link(u)}")

        prompt_vuln_scan(outdir)


# ── CVE Lookup ────────────────────────────────────────────────────────────────

CVE_HITS = []   # (product, version, source, cve_id, score, title)

def cve_searchsploit(product: str, version: str):
    """Search local Exploit-DB via searchsploit."""
    if not tool_exists('searchsploit'):
        return
    query = f"{product} {version}".strip()
    if not query or query == ' ':
        return
    out = run(['searchsploit', '--color', query], timeout=15)
    if not out or 'No Results' in out or '0 results' in out.lower():
        return
    lines = [l for l in out.splitlines() if '|' in l and 'Exploit Title' not in l and '---' not in l]
    for line in lines[:5]:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 2:
            title = parts[0]
            path  = parts[1] if len(parts) > 1 else ''
            CVE_HITS.append((product, version, 'searchsploit', path, '?', title))
            print(f"   {red('[EXPLOIT]')} {product} {version} — {title[:60]}")
            if path:
                print(f"             Path: {path}")

def cve_circl(product: str, version: str):
    """Query cve.circl.lu — no API key required."""
    if not product:
        return
    vendor  = product.lower().replace(' ', '_')
    prod    = version.split('.')[0] if version else ''
    url     = f"https://cve.circl.lu/api/search/{urllib.parse.quote(vendor)}/{urllib.parse.quote(product.lower())}"
    try:
        req  = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
    except Exception:
        return

    results = data if isinstance(data, list) else data.get('results', [])
    if not results:
        return

    matched = []
    for cve in results:
        if not isinstance(cve, dict):
            continue
        cvss = cve.get('cvss', 0) or 0
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0
        cve_id  = cve.get('id', '')
        summary = cve.get('summary', '')[:80]
        if version and version not in str(cve.get('vulnerable_configuration', '')):
            if cvss < 7.0:
                continue
        matched.append((cvss, cve_id, summary))

    matched.sort(reverse=True)
    for cvss, cve_id, summary in matched[:5]:
        color = red if cvss >= 9.0 else (yellow if cvss >= 7.0 else cyan)
        print(f"   {color(f'[CVE {cvss:.1f}]')} {cve_id} — {summary}")
        CVE_HITS.append((product, version, 'circl.lu', cve_id, cvss, summary))

def lookup_cves(product: str, version: str):
    """Run both CVE sources for a detected product/version."""
    if not product:
        return
    label = f"{product} {version}".strip()
    print(f"\n   {cyan('CVE lookup:')} {label}")
    cve_searchsploit(product, version)
    cve_circl(product, version)
    if not any(h[0] == product for h in CVE_HITS):
        print(f"   No known exploits found for {label}")


def prompt_vuln_scan(outdir: Path):
    """Ask which URL to scan, then launch vuln_scan.py."""
    script_dir = Path(__file__).parent
    vuln_script = script_dir.parent.parent / 'scan' / 'scripts' / 'vuln_scan.py'

    if not vuln_script.exists():
        print(f"\n  {yellow('[!]')} vuln_scan.py not found at {vuln_script}")
        print(f"      Run manually: python3 scan/scripts/vuln_scan.py <URL>")
        return

    print(f"\n{bold('VULNERABILITY SCAN')}")
    print(f"  Available targets:")
    for i, u in enumerate(WEB_URLS, 1):
        print(f"  {cyan(str(i))}. {u}")

    default = WEB_URLS[0]
    try:
        choice = input(f"\n  URL to scan [{default}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n  Skipping vuln scan.")
        return

    target_url = choice if choice else default

    # Validate looks like a URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"http://{target_url}"

    print(f"\n  {green('→')} Launching: python3 vuln_scan.py {target_url}")
    print(f"  Output will save JSON + Markdown to current directory.\n")

    try:
        subprocess.run(
            ['python3', str(vuln_script), target_url, '--delay', '1.0'],
            timeout=1800
        )
    except KeyboardInterrupt:
        print(f"\n  {yellow('Vuln scan interrupted.')}")
    except Exception as e:
        print(f"  {red(f'Error: {e}')}")
        print(f"  Run manually: python3 {vuln_script} {target_url}")


def save_report(ip: str, host: str, ports: list[dict], outdir: Path):
    lines = [
        f"# Recon Report — {host} ({ip})",
        f"\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"\n## Open Ports\n",
        f"| Port | Proto | Service | Version |",
        f"|------|-------|---------|---------|",
    ]
    for p in ports:
        ver = f"{p['product']} {p['version']}".strip() or '—'
        lines.append(f"| {p['port']}/{p['proto']} | {p['proto']} | {p['service']} | {ver} |")

    if INTERESTING:
        lines += ["\n## Findings\n"]
        for i in INTERESTING:
            icon = '🔴' if i['severity'] == 'critical' else ('🟡' if i['severity'] == 'medium' else '🔵')
            lines.append(f"- {icon} {i['finding']}")

    web_dir = outdir / 'web'
    gb_files = list(web_dir.glob('*_gobuster.txt')) if web_dir.exists() else []
    if gb_files:
        lines += ["\n## Web Paths\n"]
        for f in gb_files:
            port_m = re.search(r'_(\d+)_gobuster', f.name)
            lines.append(f"\n### Port {port_m.group(1) if port_m else '?'}\n```")
            lines.append(f.read_text()[:3000])
            lines.append("```")

    save(outdir / 'report.md', '\n'.join(lines))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    ip = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else ip

    outdir = Path('./output') / host
    outdir.mkdir(parents=True, exist_ok=True)

    if not tool_exists('nmap'):
        print(red("nmap not found — install: sudo apt install nmap"))
        sys.exit(1)

    banner(f"Deep Recon — {host} ({ip})")
    print(f"  Output: {outdir}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

    # Nmap phases
    ports = phase_nmap(ip, outdir)

    if not ports:
        print(red("No open ports found. Check connectivity."))
        sys.exit(1)

    # Service enum
    enum_services(ports, ip, host, outdir)

    # Summary
    print_summary(ip, host, ports, outdir)


if __name__ == '__main__':
    main()
