#!/usr/bin/env python3
"""Collect IoCs from AlienVault OTX and enrich chosen indicators with VirusTotal."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = (5, 25)


def request_json(url: str, *, headers: dict[str, str], params: dict[str, Any] | None = None) -> dict[str, Any]:
    response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("API returned an unexpected response")
    return data


def fetch_otx(api_key: str, limit: int) -> list[dict[str, Any]]:
    """Fetch at most limit subscribed pulses, following OTX pagination."""
    rows: list[dict[str, Any]] = []
    pulses_read = 0
    url: str | None = OTX_URL
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    while url and pulses_read < limit:
        page = request_json(url, headers=headers, params={"limit": min(100, limit - pulses_read)} if url == OTX_URL else None)
        for pulse in page.get("results", []):
            pulses_read += 1
            if pulses_read > limit:
                break
            if not isinstance(pulse, dict):
                continue
            pulse_name = pulse.get("name", "")
            pulse_id = pulse.get("id", "")
            for item in pulse.get("indicators", []):
                if not isinstance(item, dict):
                    continue
                value = str(item.get("indicator", "")).strip()
                if value:
                    rows.append({
                        "indicator": value,
                        "type": str(item.get("type", "unknown")),
                        "source": "AlienVault OTX",
                        "pulse_name": str(pulse_name),
                        "pulse_id": str(pulse_id),
                    })
        url = page.get("next")
        if url and not str(url).startswith("https://otx.alienvault.com/"):
            raise ValueError("OTX returned an unexpected pagination URL")
    return rows


def vt_endpoint(indicator: str) -> tuple[str, str]:
    """Map common indicators to VirusTotal v3 object endpoint and identifier."""
    try:
        ipaddress.ip_address(indicator)
        return "ip_addresses", indicator
    except ValueError:
        pass
    if indicator.lower().startswith(("http://", "https://")):
        import base64
        encoded = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        return "urls", encoded
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
        return "files", indicator.lower()
    if "." in indicator and " " not in indicator and "/" not in indicator:
        return "domains", indicator
    raise ValueError("unsupported or unrecognized indicator format")


def enrich_vt(indicator: str, api_key: str) -> dict[str, Any]:
    kind, identifier = vt_endpoint(indicator)
    data = request_json(f"{VT_URL}/{kind}/{quote(identifier, safe='')}", headers={"x-apikey": api_key, "Accept": "application/json"})
    attrs = data.get("data", {}).get("attributes", {})
    return {
        "indicator": indicator,
        "vt_type": kind,
        "vt_reputation": attrs.get("reputation"),
        "vt_analysis_stats": attrs.get("last_analysis_stats", {}),
        "vt_last_analysis_date": attrs.get("last_analysis_date"),
        "vt_checked_at": datetime.now(timezone.utc).isoformat(),
    }


def write_json(rows: list[dict[str, Any]], output: str | None) -> None:
    stream = open(output, "w", encoding="utf-8", newline="") if output else sys.stdout
    try:
        json.dump(rows, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    finally:
        if output:
            stream.close()


def write_csv(rows: list[dict[str, Any]], output: str | None) -> None:
    fields = sorted({key for row in rows for key in row}) or ["indicator", "type", "source"]
    stream = open(output, "w", encoding="utf-8", newline="") if output else sys.stdout
    try:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value for key, value in row.items()})
    finally:
        if output:
            stream.close()


def collect(args: argparse.Namespace) -> int:
    rows: list[dict[str, Any]] = []
    errors = 0
    otx_key = os.getenv("OTX_API_KEY", "").strip()
    vt_key = os.getenv("VT_API_KEY", "").strip()
    if not otx_key:
        print("OTX_API_KEY is required to collect subscribed pulses.", file=sys.stderr)
        return 2
    try:
        rows.extend(fetch_otx(otx_key, args.limit))
    except (requests.RequestException, ValueError, KeyError) as exc:
        errors += 1
        print(f"OTX collection failed: {exc}", file=sys.stderr)

    if args.enrich and not vt_key:
        errors += 1
        print("VT_API_KEY is required when using --enrich.", file=sys.stderr)
    elif args.enrich:
        for indicator in dict.fromkeys(args.enrich):
            try:
                rows.append({"type": "enrichment", "source": "VirusTotal", **enrich_vt(indicator, vt_key)})
            except (requests.RequestException, ValueError, KeyError) as exc:
                errors += 1
                print(f"VirusTotal lookup failed for {indicator!r}: {exc}", file=sys.stderr)
            if len(args.enrich) > 1:
                time.sleep(0.25)

    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (str(row.get("indicator", "")).lower(), str(row.get("source", "")), str(row.get("pulse_id", "")))
        unique.setdefault(key, row)
    output_rows = list(unique.values())
    if args.format == "csv":
        write_csv(output_rows, args.output)
    else:
        write_json(output_rows, args.output)
    return 1 if errors and not output_rows else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect threat indicators from OTX and enrich selected IoCs with VirusTotal.")
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("collect", help="collect OTX subscribed pulses and optionally enrich indicators")
    cmd.add_argument("--limit", type=int, default=10, help="maximum OTX pulses to read (1-1000; default: 10)")
    cmd.add_argument("--enrich", nargs="+", metavar="IOC", help="look up one or more IPs, domains, URLs, or file hashes in VirusTotal")
    cmd.add_argument("--format", choices=("json", "csv"), default="json", help="output format")
    cmd.add_argument("--output", help="output file; defaults to stdout")
    cmd.set_defaults(func=collect)
    args = parser.parse_args()
    if args.command == "collect" and not 1 <= args.limit <= 1000:
        parser.error("--limit must be between 1 and 1000")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

