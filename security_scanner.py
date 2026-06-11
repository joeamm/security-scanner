#!/usr/bin/env python3
"""
Scans a website URL and checks for common security misconfigurations:
missing HTTP security headers, HTTPS enforcement, admin panel exposure,
server version leakage, and more.

Usage:
    pip install requests
    python security_scanner.py <url>

Examples:
    python security_scanner.py https://example.com
    python security_scanner.py http://mybusiness.com
"""

import sys
import datetime
import socket

try:
    import requests
    from requests.exceptions import SSLError, ConnectionError, Timeout
except ImportError:
    print("\n[!] Missing dependency. Run: pip install requests\n")
    sys.exit(1)

TIMEOUT_SECONDS = 10  # Wait up to 10s per request

# Common admin panel paths to check
ADMIN_PATHS = [
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/login",
    "/dashboard",
    "/manager",
    "/phpmyadmin",
    "/cpanel",
]

class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(t):    return f"{Color.RED}{t}{Color.RESET}"
def green(t):  return f"{Color.GREEN}{t}{Color.RESET}"
def yellow(t): return f"{Color.YELLOW}{t}{Color.RESET}"
def cyan(t):   return f"{Color.CYAN}{t}{Color.RESET}"
def bold(t):   return f"{Color.BOLD}{t}{Color.RESET}"


def make_result(status, label, detail, advice=""):
    return {"status": status, "label": label, "detail": detail, "advice": advice}

def check_https(url, session):
    results = []

    # Check 1a: Does the site use HTTPS at all?
    if url.startswith("https://"):
        results.append(make_result(
            "pass", "HTTPS in use",
            "Site is served over HTTPS (encrypted connection)."
        ))
    else:
        results.append(make_result(
            "fail", "HTTPS not used",
            "Site is served over plain HTTP — all traffic is unencrypted.",
            "Move to HTTPS. Most hosts offer free SSL via Let's Encrypt."
        ))
        return results  # No point continuing HTTPS checks

    # Check 1b: Does HTTP redirect to HTTPS?
    http_url = url.replace("https://", "http://", 1)
    try:
        resp = session.get(http_url, timeout=TIMEOUT_SECONDS, allow_redirects=True)
        if resp.url.startswith("https://"):
            results.append(make_result(
                "pass", "HTTP redirects to HTTPS",
                f"HTTP request was redirected to {resp.url}"
            ))
        else:
            results.append(make_result(
                "fail", "HTTP does not redirect to HTTPS",
                "Visiting the HTTP version does not force a secure connection.",
                "Add a 301 redirect from HTTP to HTTPS in your web server config."
            ))
    except Exception as e:
        results.append(make_result(
            "warn", "HTTP redirect check failed",
            str(e)
        ))

    return results


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "advice": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "why":    "Tells browsers to always use HTTPS, even if user types HTTP.",
    },
    "X-Frame-Options": {
        "advice": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
        "why":    "Prevents your site from being embedded in iframes (clickjacking attacks).",
    },
    "X-Content-Type-Options": {
        "advice": "Add: X-Content-Type-Options: nosniff",
        "why":    "Stops browsers from guessing file types, which can enable XSS attacks.",
    },
    "Content-Security-Policy": {
        "advice": "Add a Content-Security-Policy header. Start with: default-src 'self'",
        "why":    "Controls which scripts/resources the browser is allowed to load.",
    },
    "Referrer-Policy": {
        "advice": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "why":    "Controls what URL info is sent to other sites when users click links.",
    },
    "Permissions-Policy": {
        "advice": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "why":    "Restricts access to sensitive browser APIs like camera and location.",
    },
}

def check_security_headers(response):
    results = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() in headers:
            value = headers[header_name.lower()]
            results.append(make_result(
                "pass",
                f"Header present: {header_name}",
                f"Value: {value}"
            ))
        else:
            results.append(make_result(
                "fail",
                f"Missing header: {header_name}",
                info["why"],
                info["advice"]
            ))

    return results

def check_server_leakage(response):
    results = []
    headers = response.headers

    server = headers.get("Server", "")
    x_powered = headers.get("X-Powered-By", "")

    if server:
        # Check if version number is exposed (e.g. "nginx/1.14.0")
        has_version = any(char.isdigit() for char in server)
        if has_version:
            results.append(make_result(
                "fail", "Server version exposed",
                f"Server header reveals: '{server}'",
                "Configure your web server to hide version info. "
                "In Apache: 'ServerTokens Prod'. In Nginx: 'server_tokens off'."
            ))
        else:
            results.append(make_result(
                "pass", "Server header safe",
                f"Server header present but version hidden: '{server}'"
            ))
    else:
        results.append(make_result(
            "pass", "No Server header",
            "Server header is not exposed."
        ))

    if x_powered:
        results.append(make_result(
            "fail", "X-Powered-By header exposed",
            f"Reveals technology stack: '{x_powered}'",
            "Remove the X-Powered-By header. In PHP: 'expose_php = Off' in php.ini."
        ))
    else:
        results.append(make_result(
            "pass", "No X-Powered-By header",
            "Technology stack is not exposed via headers."
        ))

    return results

def check_admin_panels(base_url, session):
    results = []
    exposed = []

    print(f"  Checking {len(ADMIN_PATHS)} admin paths...", end="", flush=True)

    for path in ADMIN_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True)
            # 200 = page exists, 401/403 = exists but protected
            if resp.status_code in (200, 401, 403):
                exposed.append((path, resp.status_code))
        except Exception:
            pass  # Connection error = path doesn't exist, that's fine

    print(" done")

    if exposed:
        for path, code in exposed:
            status_note = "publicly accessible" if code == 200 else "exists but access-restricted"
            results.append(make_result(
                "fail" if code == 200 else "warn",
                f"Admin path found: {path}",
                f"HTTP {code} — {status_note}",
                "Restrict admin panels by IP whitelist or put behind a VPN."
            ))
    else:
        results.append(make_result(
            "pass", "No common admin panels exposed",
            f"Checked {len(ADMIN_PATHS)} common paths — none were accessible."
        ))

    return results

def check_cookies(response):
    results = []
    cookies = response.cookies

    if not cookies:
        results.append(make_result(
            "pass", "No cookies set on homepage",
            "No cookies were set by the initial response."
        ))
        return results

    for cookie in cookies:
        if not cookie.secure:
            results.append(make_result(
                "fail", f"Cookie '{cookie.name}' missing Secure flag",
                "Cookie can be sent over unencrypted HTTP connections.",
                f"Set the Secure flag on cookie '{cookie.name}'."
            ))
        else:
            results.append(make_result(
                "pass", f"Cookie '{cookie.name}' has Secure flag", ""
            ))

        if not cookie.has_nonstandard_attr("HttpOnly"):
            results.append(make_result(
                "warn", f"Cookie '{cookie.name}' may be missing HttpOnly flag",
                "HttpOnly prevents JavaScript from reading the cookie (XSS protection).",
                f"Set the HttpOnly flag on cookie '{cookie.name}'."
            ))

    return results


# REPORT PRINTING
def print_report(url, all_results, duration):
    divider = "─" * 62
    passes  = [r for r in all_results if r["status"] == "pass"]
    fails   = [r for r in all_results if r["status"] == "fail"]
    warns   = [r for r in all_results if r["status"] == "warn"]

    print(f"\n{bold(divider)}")
    print(bold("  SECURITY CHECKLIST REPORT"))
    print(bold(divider))
    print(f"  Target   : {cyan(url)}")
    print(f"  Scanned  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration : {duration:.2f}s")
    print(f"  Results  : {green(str(len(passes)) + ' passed')}  "
          f"{red(str(len(fails)) + ' failed')}  "
          f"{yellow(str(len(warns)) + ' warnings')}")
    print(bold(divider))

    # Score calculation (simple percentage)
    total = len(all_results)
    score = int((len(passes) / total) * 100) if total else 0
    score_color = green if score >= 80 else yellow if score >= 50 else red
    print(f"\n  Security score: {score_color(bold(str(score) + '/100'))}\n")

    # Print all checks
    sections = [
        ("HTTPS", [r for r in all_results if "HTTPS" in r["label"] or "HTTP" in r["label"]]),
        ("Security Headers", [r for r in all_results if "header" in r["label"].lower() or "Header" in r["label"]]),
        ("Server Info", [r for r in all_results if "Server" in r["label"] or "Powered" in r["label"]]),
        ("Admin Panels", [r for r in all_results if "Admin" in r["label"] or "admin" in r["label"]]),
        ("Cookies", [r for r in all_results if "Cookie" in r["label"] or "cookie" in r["label"]]),
    ]

    for section_name, section_results in sections:
        if not section_results:
            continue
        print(f"  {bold(section_name)}")
        for r in section_results:
            if r["status"] == "pass":
                icon = green("✓")
            elif r["status"] == "fail":
                icon = red("✗")
            else:
                icon = yellow("!")

            print(f"    {icon}  {r['label']}")
            if r["detail"] and r["status"] != "pass":
                print(f"       {r['detail']}")
        print()

    # Actionable recommendations
    if fails or warns:
        print(bold(divider))
        print(f"  {bold('RECOMMENDATIONS')}\n")
        priority = 1
        for r in fails + warns:
            if r["advice"]:
                badge = red("CRITICAL") if r["status"] == "fail" else yellow("WARNING")
                print(f"  {priority}. [{badge}] {r['label']}")
                print(f"     → {r['advice']}\n")
                priority += 1

    print(bold(divider))
    print(f"\n  Scan complete.\n")


def main():
    if len(sys.argv) < 2:
        print(f"\n  Usage: python security_scanner.py <url>")
        print(f"  Example: python security_scanner.py https://example.com\n")
        sys.exit(1)

    url = sys.argv[1]

    # Add https:// if no scheme given
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n{bold('Security Checklist Scanner')}")
    print(f"  Target: {cyan(url)}\n")

    # Set up HTTP session with a realistic browser User-Agent
    # (some servers block requests without one)
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    })

    all_results = []
    start_time  = datetime.datetime.now()

    # Fetch the main page
    print("  Fetching homepage...", end="", flush=True)
    try:
        response = session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True)
        print(f" {green('OK')} (HTTP {response.status_code})")
    except SSLError:
        print(red("\n[!] SSL certificate error. The site may have an invalid cert."))
        sys.exit(1)
    except ConnectionError:
        print(red(f"\n[!] Could not connect to {url}"))
        sys.exit(1)
    except Timeout:
        print(red(f"\n[!] Connection timed out after {TIMEOUT_SECONDS}s"))
        sys.exit(1)

    # Run all checks
    print("  Running security checks...")

    all_results += check_https(url, session)
    all_results += check_security_headers(response)
    all_results += check_server_leakage(response)
    all_results += check_admin_panels(url, session)
    all_results += check_cookies(response)

    duration = (datetime.datetime.now() - start_time).total_seconds()

    print_report(url, all_results, duration)

if __name__ == "__main__":
    main()
