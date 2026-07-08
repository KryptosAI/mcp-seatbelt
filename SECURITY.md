# Security Policy

## Supported Versions

Security updates are provided for the current minor release line.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

> **Audit Status:** This project has not undergone a third-party security audit. We are committed to addressing all responsibly disclosed vulnerabilities.

## Reporting a Vulnerability

If you discover a security vulnerability in mcp-seatbelt, please report it privately rather than opening a public issue.

**Contact:** william@banksey.com

**What to include:**
- Detailed description of the vulnerability
- Steps to reproduce (proof-of-concept code, tool names, configuration)
- Affected versions
- Any suggested mitigations or patches

**PGP Key:** Not required, but if you prefer encrypted communication, request our PGP key in your initial email.

**Response time:** We aim to acknowledge your report within **48 hours** and provide an initial assessment within **5 business days**.

## Disclosure Policy

We follow a **90-day responsible disclosure** timeline:

1. The vulnerability is reported privately to william@banksey.com
2. Within 48 hours, we acknowledge receipt and begin triage
3. Within 5 business days, we provide an initial assessment and severity rating
4. A fix is developed and privately shared with the reporter for validation
5. A release is published with the fix
6. A public advisory is issued **90 days** after the initial report, or sooner if both parties agree

If the vulnerability is actively being exploited, we may shorten the disclosure window and coordinate an emergency release.

## Hall of Fame / Acknowledgments

We gratefully recognize the following individuals for responsibly disclosing security issues:

| Name | Issue | Date |
| ---- | ----- | ---- |
| —    | —     | —    |

To be added to this list, report a valid vulnerability following the process above and indicate that you would like to be acknowledged.

## Scope

Security issues in scope include:

- Policy bypass (deny rules not enforced, allowlist escapes)
- Request smuggling or injection via the JSON-RPC proxy
- Credential leakage through error messages, logs, or reports
- Arbitrary code execution via malicious server configurations
- Denial of service against the proxy server
- Template injection in report generation

## Out of Scope

- Issues in third-party MCP servers (report to the server's maintainer)
- Social engineering or phishing attacks
- Missing HTTP security headers not directly exploitable
- Denial of service via resource exhaustion in local-only proxy (without remote vector)
