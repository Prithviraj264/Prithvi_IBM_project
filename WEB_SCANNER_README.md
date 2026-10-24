# Automated Web Scanner

A small Python command-line tool that checks one website for common security response headers and basic CORS behavior. It needs no account, API key, or paid service. Use it only on sites you own or have permission to assess.

## Setup

Python 3.10+ and `requests` are required. From this folder:

```powershell
pip install -r requirements.txt
```

## Run

```powershell
python .\web_scanner.py https://example.com
```

Save a JSON report:

```powershell
python .\web_scanner.py https://example.com --output report.json
```

If PowerShell is not already in this folder, either use the full path to `web_scanner.py` or change directory first:

```powershell
Set-Location "C:\Users\prith\Documents\Codex\2026-10-24\1-threat-intelligence-aggregator-built-a\outputs"
python .\web_scanner.py https://example.com --output report.json
```

## What it checks

- Common browser security headers: CSP, HSTS (for HTTPS), content type, referrer, permissions, and framing protections.
- CORS response to a harmless test `Origin` value. It flags reflected origins and credentialed reflection for manual review.
- Final URL and HTTP status after redirects.

This performs a single GET request, does not crawl pages, submit forms, or attempt exploitation. INFO findings are observations, not proof of a vulnerability. A wildcard CORS policy can be appropriate for public resources. Review results in the context of the application's intended behavior.
