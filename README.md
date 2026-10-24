# Automated Web Scanner

A lightweight Python command-line scanner for a single website. It requests the target once with a test `Origin` header, records the HTTP response headers, and reports common browser security headers and basic CORS behavior. It does not crawl the site or attempt exploitation.

## Project files

- `Prith_AutomatedWebScanner.py` — complete scanner source code.
- `requirements.txt` — Python dependency list.
- `Prith_ProjectReport.docx` — project documentation and sample results.
- `cors_reference_dataset.csv` — small illustrative CORS reference dataset for understanding the scanner's result categories. It is not an input to the scanner.

## Technologies

- Python 3.10 or later
- `requests` for the HTTP request
- Python standard library modules for URL parsing, timestamps, command-line options, and JSON output

## Dataset

The scanner evaluates live HTTP response headers, so it does not need a training dataset. For the assignment's dataset link requirement, this project includes an illustrative reference dataset: [cors_reference_dataset.csv](cors_reference_dataset.csv). Its examples explain how to interpret common `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` combinations; they are not empirical scan results.

## Setup

Open PowerShell in this folder and install the dependency:

```powershell
python -m pip install -r requirements.txt
```

## Run

Print the report in the terminal:

```powershell
python .\Prith_AutomatedWebScanner.py https://example.com
```

Save the report as JSON:

```powershell
python .\Prith_AutomatedWebScanner.py https://example.com --output report.json
```

If you are in another folder, change into the project folder first or use the full path to the script:

```powershell
Set-Location "C:\Users\prith\Documents\Codex\2026-10-24\1-threat-intelligence-aggregator-built-a\outputs"
python .\Prith_AutomatedWebScanner.py https://example.com --output report.json
```

Use the scanner only on websites you own or have permission to assess. It makes one GET request and adds `Origin: https://cors-probe.example`; no credentials are sent by the tool. Results are preliminary: a missing header is not proof of a vulnerability, and wildcard CORS can be appropriate for public resources.

## Checks performed

- Content Security Policy (CSP)
- Strict Transport Security (HSTS) for HTTPS responses
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Framing protection using CSP `frame-ancestors` or X-Frame-Options
- CORS response to the test origin, including whether credentialed origin reflection appears

## References

- [OWASP Secure Headers Project](https://owasp.org/projects/secure-headers-project)
- [MDN CORS Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
