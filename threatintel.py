#!/usr/bin/env python3
"""
Threat Intelligence Summarizer
Takes a URL, domain, or file hash -> queries VirusTotal + URLhaus ->
uses an LLM to produce an analyst-grade risk report.

Usage:
    python threatintel.py <indicator> [--output report.md]

Examples:
    python threatintel.py 44d88612fea8a8f36de82e1278abb02f
    python threatintel.py http://malicious-example.com --output report.md
"""

import argparse
import base64
import json
import logging
import os
import re
import sys

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")

VT_BASE = "https://www.virustotal.com/api/v3"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("threatintel.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Indicator detection
# ---------------------------------------------------------------------------
def classify_indicator(indicator: str) -> str:
    """Return one of: 'hash', 'url', 'domain', 'ip'."""
    indicator = indicator.strip()

    # Hashes: MD5 (32), SHA-1 (40), SHA-256 (64) hex chars
    if re.fullmatch(r"[a-fA-F0-9]{32}", indicator):
        return "hash"
    if re.fullmatch(r"[a-fA-F0-9]{40}", indicator):
        return "hash"
    if re.fullmatch(r"[a-fA-F0-9]{64}", indicator):
        return "hash"

    # IPv4
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", indicator):
        return "ip"

    # URL (has a scheme or a path/query)
    if indicator.startswith(("http://", "https://")) or "/" in indicator:
        return "url"

    # Otherwise treat as a domain
    return "domain"


# ---------------------------------------------------------------------------
# VirusTotal queries
# ---------------------------------------------------------------------------
def vt_lookup(indicator: str, kind: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    headers = {"x-apikey": VT_API_KEY}

    if kind == "hash":
        endpoint = f"{VT_BASE}/files/{indicator}"
    elif kind == "ip":
        endpoint = f"{VT_BASE}/ip_addresses/{indicator}"
    elif kind == "domain":
        endpoint = f"{VT_BASE}/domains/{indicator}"
    elif kind == "url":
        # VT wants the URL as a base64 (url-safe, no padding) id
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        endpoint = f"{VT_BASE}/urls/{url_id}"
    else:
        return {"error": f"unsupported kind: {kind}"}

    try:
        r = requests.get(endpoint, headers=headers, timeout=30)
        if r.status_code == 404:
            return {"found": False, "note": "Indicator not found in VirusTotal."}
        r.raise_for_status()
        data = r.json()
        # Pull the most useful slice so we don't drown the LLM in JSON
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "found": True,
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation"),
            "total_votes": attrs.get("total_votes"),
            "tags": attrs.get("tags", []),
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
        }
    except requests.exceptions.RequestException as e:
        log.error("VirusTotal request failed: %s", e)
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# URLhaus queries
# ---------------------------------------------------------------------------
def urlhaus_lookup(indicator: str, kind: str) -> dict:
    headers = {"Auth-Key": URLHAUS_API_KEY} if URLHAUS_API_KEY else {}
    try:
        if kind == "url":
            r = requests.post(
                f"{URLHAUS_BASE}/url/", data={"url": indicator},
                headers=headers, timeout=30
            )
        elif kind in ("domain", "ip"):
            r = requests.post(
                f"{URLHAUS_BASE}/host/", data={"host": indicator},
                headers=headers, timeout=30
            )
        elif kind == "hash":
            field = "sha256_hash" if len(indicator) == 64 else "md5_hash"
            r = requests.post(
                f"{URLHAUS_BASE}/payload/", data={field: indicator},
                headers=headers, timeout=30
            )
        else:
            return {"error": f"unsupported kind: {kind}"}

        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "no_results":
            return {"found": False, "note": "No URLhaus records."}
        return {
            "found": True,
            "query_status": data.get("query_status"),
            "threat": data.get("threat"),
            "url_status": data.get("url_status"),
            "date_added": data.get("date_added") or data.get("firstseen"),
            "tags": data.get("tags"),
            "urlhaus_reference": data.get("urlhaus_reference"),
        }
    except requests.exceptions.RequestException as e:
        log.error("URLhaus request failed: %s", e)
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# LLM summarizer
# ---------------------------------------------------------------------------
def summarize_with_llm(indicator: str, kind: str, combined: dict) -> str:
    if not ANTHROPIC_API_KEY:
        return "[LLM skipped: ANTHROPIC_API_KEY not set]\n\nRaw data:\n" + json.dumps(
            combined, indent=2
        )

    try:
        import anthropic
    except ImportError:
        return "[anthropic package not installed: run `pip install anthropic`]"

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    prompt = f"""You are a threat intelligence analyst. You are given raw lookup data \
from two sources (VirusTotal and URLhaus) for the indicator below.

Indicator: {indicator}
Type: {kind}

Data:
{json.dumps(combined, indent=2)}

Write a concise analyst report in Markdown with these sections:
1. **Verdict** — one of: CLEAN / SUSPICIOUS / MALICIOUS, with a confidence level out of 10.
2. **Key Findings** — the specific evidence, per source.
3. **Correlation** — do the two sources corroborate or conflict? Reason explicitly \
about what it means when they agree or disagree.
4. **Recommended Action** — what an analyst should do next.

Be direct. If the data is thin or the indicator wasn't found, say so plainly rather \
than inventing risk."""

    try:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text
    except Exception as e:
        log.error("LLM request failed: %s", e)
        return f"[LLM error: {e}]\n\nRaw data:\n{json.dumps(combined, indent=2)}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Threat intelligence summarizer (VirusTotal + URLhaus + LLM)."
    )
    parser.add_argument("indicator", help="URL, domain, IP, or file hash to look up")
    parser.add_argument("--output", "-o", help="Write the report to this file (e.g. report.md)")
    args = parser.parse_args()

    kind = classify_indicator(args.indicator)
    log.info("Indicator '%s' classified as: %s", args.indicator, kind)

    log.info("Querying VirusTotal...")
    vt = vt_lookup(args.indicator, kind)

    log.info("Querying URLhaus...")
    uh = urlhaus_lookup(args.indicator, kind)

    combined = {"indicator": args.indicator, "type": kind, "virustotal": vt, "urlhaus": uh}

    log.info("Generating LLM report...")
    report = summarize_with_llm(args.indicator, kind, combined)

    print("\n" + "=" * 70)
    print(report)
    print("=" * 70 + "\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"# Threat Intelligence Report: {args.indicator}\n\n")
            f.write(report)
            f.write("\n\n---\n\n## Raw Data\n\n```json\n")
            f.write(json.dumps(combined, indent=2))
            f.write("\n```\n")
        log.info("Report written to %s", args.output)


if __name__ == "__main__":
    main()
