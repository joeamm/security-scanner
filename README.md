# 🛡️ Website Security Checklist Scanner

An automated Python tool that audits any website for common security misconfigurations — missing headers, exposed admin panels, server version leakage, and more — and outputs a prioritized, plain-English report.

Built as part of a cybersecurity freelance portfolio.
---

## What It Does

Runs 5 categories of security checks on any URL in under 30 seconds:

| Check | What It Looks For |
|-------|------------------|
| ✅ HTTPS enforcement | Is the site encrypted? Does HTTP redirect to HTTPS? |
| ✅ Security headers | 6 critical HTTP headers that most small sites are missing |
| ✅ Server info leakage | Does the server reveal its software version to attackers? |
| ✅ Exposed admin panels | Are login pages like `/wp-admin` or `/phpmyadmin` publicly accessible? |
| ✅ Cookie security | Are session cookies protected with Secure and HttpOnly flags? |

Outputs a **security score out of 100** with prioritized, actionable recommendations your client can hand to their developer.

---

## Example Output

```
Security Checklist Scanner
  Target: https://example.com

  Fetching homepage... OK (HTTP 200)
  Running security checks...
  Checking 10 admin paths... done

  ──────────────────────────────────────────────────────────────
  SECURITY CHECKLIST REPORT
  ──────────────────────────────────────────────────────────────
  Target   : https://example.com
  Scanned  : 2026-06-10 14:45:12
  Duration : 8.34s
  Results  : 6 passed  5 failed  1 warnings

  Security score: 54/100

  HTTPS
    ✓  HTTPS in use
    ✗  HTTP does not redirect to HTTPS

  Security Headers
    ✓  Header present: Strict-Transport-Security
    ✗  Missing header: X-Frame-Options
    ✗  Missing header: Content-Security-Policy
    ✗  Missing header: X-Content-Type-Options

  Server Info
    ✗  Server version exposed
    ✓  No X-Powered-By header

  Admin Panels
    ✓  No common admin panels exposed

  ──────────────────────────────────────────────────────────────
  RECOMMENDATIONS

  1. [CRITICAL] HTTP does not redirect to HTTPS
     → Add a 301 redirect from HTTP to HTTPS in your web server config.

  2. [CRITICAL] Missing header: X-Frame-Options
     → Add: X-Frame-Options: DENY  (or SAMEORIGIN)

  3. [CRITICAL] Server version exposed
     → In Apache: 'ServerTokens Prod'. In Nginx: 'server_tokens off'.
  ──────────────────────────────────────────────────────────────
```

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/security-scanner.git
cd security-scanner

# Install the one dependency
pip install requests

# Scan a website
python security_scanner.py https://yourwebsite.com
```

> ⚠️ **Legal notice:** Only scan websites you own or have explicit written permission to test.

---

## How It Works

### 1. HTTPS Check
Fetches both the `http://` and `https://` versions of the URL. Verifies the site serves encrypted traffic and that unencrypted requests are automatically redirected.

### 2. Security Headers
Inspects the HTTP response headers for 6 browser security controls:

| Header | Protects Against |
|--------|-----------------|
| `Strict-Transport-Security` | Forces HTTPS even if user types HTTP |
| `X-Frame-Options` | Clickjacking via malicious iframes |
| `X-Content-Type-Options` | MIME-type sniffing attacks |
| `Content-Security-Policy` | Cross-site scripting (XSS) |
| `Referrer-Policy` | Leaking URLs to third-party sites |
| `Permissions-Policy` | Unauthorized camera/mic/location access |

### 3. Server Info Leakage
Checks `Server` and `X-Powered-By` headers for version numbers. Example: `Server: Apache/2.4.1` tells an attacker exactly which CVEs to target.

### 4. Admin Panel Exposure
Sends requests to 10 common admin paths and checks if any return a real page (HTTP 200/401/403).

### 5. Cookie Security
Inspects cookies set by the homepage for missing `Secure` and `HttpOnly` flags.

---

## Requirements

- Python 3.7+
- `requests` library (`pip install requests`)

---

## Use Cases for Clients

- **Pre-launch security review** — catch misconfigurations before going live
- **Quarterly security check** — fast recurring audit for retainer clients
- **Compliance baseline** — evidence of due diligence for GDPR, PCI-DSS
- **After a developer handoff** — verify the new site was configured securely

---

## About

Built by joe ammoun — Python developer with a Google Cybersecurity Professional Certificate.  
Available for freelance security audits, scripting, and automation projects.

📧 your@email.com  
💼 [Upwork Profile](https://www.upwork.com/freelancers/~01620d7d3c7e1378b8?mp_source=share)  
🔗 [LinkedIn](https://www.linkedin.com/in/joe-ammoun-019850344)
