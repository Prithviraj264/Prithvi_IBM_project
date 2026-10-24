#!/usr/bin/env python3
"""Check one authorized website for common security headers and permissive CORS."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

USER_AGENT = "SimpleSecurityHeaderScanner/1.0 (single-target passive check)"
PROBE_ORIGIN = "https://cors-probe.example"
TIMEOUT = (5, 12)


def normalize_url(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL must start with http:// or https:// and include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in the URL")
    return value


def finding(severity: str, title: str, detail: str) -> dict[str, str]:
    return {"severity": severity, "title": title, "detail": detail}


def header_findings(headers: requests.structures.CaseInsensitiveDict, https: bool) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    checks = [
        ("content-security-policy", "Content Security Policy (CSP)", "Helps limit script and content sources."),
        ("x-content-type-options", "X-Content-Type-Options", "Set this to nosniff to reduce MIME-type confusion."),
        ("referrer-policy", "Referrer-Policy", "Controls how much referrer information browsers send."),
        ("permissions-policy", "Permissions-Policy", "Restricts browser features such as camera and microphone."),
    ]
    for key, label, advice in checks:
        if not headers.get(key):
            findings.append(finding("INFO", f"{label} not observed", advice))
    if https:
        if not headers.get("strict-transport-security"):
            findings.append(finding("INFO", "HSTS not observed", "HTTPS sites commonly set Strict-Transport-Security."))
    else:
        findings.append(finding("INFO", "Target used HTTP", "This request was not encrypted. Test the HTTPS URL if the site supports it."))
    if not headers.get("x-frame-options") and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        findings.append(finding("INFO", "Framing protection not observed", "Use CSP frame-ancestors or X-Frame-Options if the site should not be embedded."))
    return findings


def cors_findings(headers: requests.structures.CaseInsensitiveDict) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    allowed = (headers.get("access-control-allow-origin") or "").strip()
    credentials = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
    if not allowed:
        findings.append(finding("PASS", "No CORS allow-origin header observed", "The server did not advertise cross-origin access on the probe response."))
    elif allowed == "*":
        if credentials:
            findings.append(finding("INFO", "Wildcard CORS with credentials header", "Browsers reject wildcard origin with credentialed requests; verify actual browser behavior."))
        else:
            findings.append(finding("INFO", "Wildcard CORS observed", "Any origin may read non-credentialed responses. This can be intentional for public resources."))
    elif allowed.lower() == PROBE_ORIGIN.lower():
        if credentials:
            findings.append(finding("HIGH", "Untrusted origin reflected with credentials", "The response allowed the scanner's unrelated origin and enabled credentials. Confirm with the application owner."))
        else:
            findings.append(finding("MEDIUM", "Untrusted origin reflected", "The response allowed the scanner's unrelated origin. Check whether sensitive unauthenticated data is exposed."))
    else:
        findings.append(finding("INFO", "Specific CORS origin observed", f"The server allowed {allowed!r}; compare it with the intended trusted-origin list."))
    return findings


def scan(url: str) -> dict:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Origin": PROBE_ORIGIN, "Accept": "*/*"})
    response = session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
    try:
        headers = response.headers
        findings = header_findings(headers, response.url.lower().startswith("https://"))
        findings.extend(cors_findings(headers))
        result = {
            "target": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "method": "GET with a test Origin header",
            "cors_probe_origin": PROBE_ORIGIN,
            "response_headers": dict(headers),
            "findings": findings,
            "note": "Automated checks are preliminary. Missing headers are not proof of a vulnerability; confirm against the application's requirements.",
        }
        return result
    finally:
        response.close()
        session.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check one authorized website for common security headers and CORS behavior.")
    parser.add_argument("url", help="site URL (for example, https://example.com)")
    parser.add_argument("--output", help="write JSON report to a file instead of stdout")
    args = parser.parse_args()
    try:
        url = normalize_url(args.url)
        report = scan(url)
    except ValueError as exc:
        parser.error(str(exc))
    except requests.RequestException as exc:
        print(f"Could not complete the request: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
