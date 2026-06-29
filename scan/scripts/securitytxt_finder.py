#!/usr/bin/env python3
"""
Security.txt Finder — discover targets via RFC 9116 security.txt files

Usage:
    python3 securitytxt_finder.py --domain <DOMAIN>
    python3 securitytxt_finder.py --domains domains.txt --output results.json
"""

import argparse
import json
import time
import sys
from pathlib import Path
import urllib.request
import urllib.error
import ssl
import re

# ── Platform check lists ───────────────────────────────────────────────────────
PLATFORM_INDICATORS = [
    "hackerone.com",
    "bugcrowd.com",
    "yeswehack.com",
    "synack.com",
    "cobalt.io",
    "immunefi.com",
]

# ── Security.txt locations ─────────────────────────────────────────────────────
# RFC 9116 says /.well-known/security.txt is the standard location
# /security.txt is the old location — many companies still use it
SECURITYTXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

# ── Colors for terminal output ─────────────────────────────────────────────────
class C:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def fetch_url(url: str, timeout: int = 8) -> tuple[int, str]:
    """
    Fetch a URL and return (status_code, body).
    Returns (-1, error_message) on failure.

    WHY NOT REQUESTS LIBRARY?
    This script needs to run inside and outside the container.
    urllib is built-in — no dependencies needed.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Many companies have self-signed certs

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (security researcher; security@researcher.com)",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(50000).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)


def parse_securitytxt(body: str) -> dict:
    """
    Parse a security.txt file and extract key fields.

    SECURITY.TXT FIELDS WE CARE ABOUT:
    - Contact:    where to send reports (email or URL)
    - Scope:      what's in/out of scope
    - Policy:     link to full disclosure policy
    - Expires:    when this file expires (outdated = company may not be responsive)
    - Hiring:     sometimes links to security team jobs (signals active security team)
    - Canonical:  the authoritative URL for this file
    """
    result = {
        "contact": [],
        "scope": [],
        "policy": None,
        "expires": None,
        "hiring": None,
        "canonical": None,
        "bug_bounty": None,
        "raw_lines": [],
    }

    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        result["raw_lines"].append(line)

        lower = line.lower()
        if lower.startswith("contact:"):
            result["contact"].append(line.split(":", 1)[1].strip())
        elif lower.startswith("scope:"):
            result["scope"].append(line.split(":", 1)[1].strip())
        elif lower.startswith("policy:"):
            result["policy"] = line.split(":", 1)[1].strip()
        elif lower.startswith("expires:"):
            result["expires"] = line.split(":", 1)[1].strip()
        elif lower.startswith("hiring:"):
            result["hiring"] = line.split(":", 1)[1].strip()
        elif lower.startswith("canonical:"):
            result["canonical"] = line.split(":", 1)[1].strip()
        elif lower.startswith("bug-bounty:") or lower.startswith("bug_bounty:"):
            result["bug_bounty"] = line.split(":", 1)[1].strip()

    return result


def check_platform(body: str, policy_url: str = "") -> str | None:
    """
    Check if the security.txt links to a known disclosure platform.
    """
    text = (body + " " + policy_url).lower()
    for platform in PLATFORM_INDICATORS:
        if platform in text:
            return platform
    return None


def probe_domain(domain: str) -> dict | None:
    """
    Check a single domain for security.txt.

    PHASE EXPLANATION:
    1. Try https://domain/.well-known/security.txt (standard)
    2. If 404, try https://domain/security.txt (legacy)
    3. If 404, try http:// versions (some companies don't have HTTPS on root)
    4. Parse what we find
    5. Check if it links to a major platform
    """
    domain = domain.strip().lower()
    if not domain or domain.startswith("#"):
        return None

    # Remove protocol if someone included it
    domain = re.sub(r'^https?://', '', domain).rstrip('/')

    for scheme in ["https", "http"]:
        for path in SECURITYTXT_PATHS:
            url = f"{scheme}://{domain}{path}"
            status, body = fetch_url(url)

            if status == 200 and len(body) > 20:
                # Sanity check: does it look like a security.txt?
                if any(field in body.lower() for field in ["contact:", "policy:", "expires:"]):
                    parsed = parse_securitytxt(body)
                    platform = check_platform(body, parsed.get("policy") or "")

                    return {
                        "domain": domain,
                        "url": url,
                        "status": "found",
                        "on_platform": platform,
                        "parsed": parsed,
                    }

    return {"domain": domain, "status": "not_found"}


def print_finding(result: dict, verbose: bool = False):
    """Print a finding in a human-readable format with context."""
    if result["status"] == "not_found":
        if verbose:
            print(f"  {C.RED}✗{C.RESET} {result['domain']}")
        return

    p = result["parsed"]
    on_platform = result["on_platform"]

    if on_platform:
        # Already on a platform — competitive, lower priority
        print(f"\n{C.YELLOW}◆ {result['domain']}{C.RESET}")
        print(f"  Already on platform: {on_platform} — skip (competitive)")
        return

    # No platform — this is what we want!
    print(f"\n{C.GREEN}{C.BOLD}★ FOUND: {result['domain']}{C.RESET}")
    print(f"  URL: {result['url']}")

    if p["contact"]:
        print(f"  {C.BLUE}Contact:{C.RESET}")
        for c in p["contact"]:
            print(f"    → {c}")

    if p["scope"]:
        print(f"  {C.BLUE}Scope:{C.RESET}")
        for s in p["scope"]:
            print(f"    → {s}")

    if p["policy"]:
        print(f"  {C.BLUE}Policy:{C.RESET} {p['policy']}")

    if p["expires"]:
        print(f"  {C.BLUE}Expires:{C.RESET} {p['expires']}")

    if p["bug_bounty"]:
        print(f"  {C.BLUE}Policy:{C.RESET} {p['bug_bounty']}")

    print(f"  {C.YELLOW}→ NEXT STEP:{C.RESET} Read their policy, check scope, add to programs/ folder")


def main():
    parser = argparse.ArgumentParser(
        description="Find targets via security.txt files (RFC 9116)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--domain", help="Check a single domain")
    parser.add_argument("--domains", help="File with one domain per line")
    parser.add_argument("--output", help="Save results as JSON to this file")
    parser.add_argument("--no-platform", action="store_true",
                        help="Only show domains NOT on major platforms (default: show all)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show domains with no security.txt too")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds between requests (default: 0.5 — be polite)")
    args = parser.parse_args()

    if not args.domain and not args.domains:
        parser.print_help()
        sys.exit(1)

    domains = []
    if args.domain:
        domains = [args.domain]
    if args.domains:
        with open(args.domains) as f:
            domains.extend(f.readlines())

    domains = [d.strip() for d in domains if d.strip() and not d.startswith("#")]

    print(f"\n{C.BOLD}Security.txt Finder{C.RESET}")
    print(f"Checking {len(domains)} domain(s) | delay: {args.delay}s between requests")
    print(f"Looking for: targets with security.txt not listed on major platforms")
    print("─" * 60)

    results = []
    found_count = 0

    for i, domain in enumerate(domains, 1):
        if len(domains) > 1:
            print(f"\r[{i}/{len(domains)}] Checking {domain}...", end="", flush=True)

        result = probe_domain(domain)
        if result:
            results.append(result)
            if result["status"] == "found":
                found_count += 1
                if len(domains) > 1:
                    print()  # newline after progress
                print_finding(result, args.verbose)
            elif args.verbose:
                print_finding(result, args.verbose)

        time.sleep(args.delay)

    print(f"\n\n{'─'*60}")
    print(f"{C.BOLD}Summary:{C.RESET}")
    print(f"  Checked:      {len(domains)} domains")
    print(f"  Found:        {found_count} with security.txt")
    on_platform = sum(1 for r in results if r.get("status") == "found" and r.get("on_platform"))
    self_run = found_count - on_platform
    print(f"  On platform:  {on_platform} (competitive — skip)")
    print(f"  Self-run VDP: {C.GREEN}{self_run}{C.RESET} (your targets)")

    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to: {output_path}")

    if self_run > 0:
        print(f"\n{C.GREEN}Next steps:{C.RESET}")
        print("  1. Read each company's policy URL")
        print("  2. Check what's in scope (domains, APIs, mobile apps)")
        print("  3. Run passive recon (subfinder, waybackurls) on in-scope domains")
        print("  4. Add promising targets to Desktop/Bug_Bounty/programs/")
        print("  5. Start with methodology.md Phase 2 (passive recon)")


if __name__ == "__main__":
    main()
