#!/usr/bin/env python3
"""
PhishGuard - Phishing Email Analyzer
Usage: python main.py -f <path_to_email.eml> [-o json|text]
"""

import argparse
import json
import sys
import os
from datetime import datetime

from phishguard.email_parser import parse_eml


def build_report(parsed: dict, file_path: str) -> dict:
    """
    Build a structured alert report from parsed email data.
    Includes a basic risk score based on findings.
    """
    flags = []
    score = 0

    # --- SPF / DKIM / DMARC checks ---
    spf = parsed.get("spf", "").lower()
    dkim = parsed.get("dkim", "")
    dmarc = parsed.get("dmarc", "").lower()

    if "fail" in spf or "softfail" in spf:
        flags.append("SPF check failed")
        score += 30
    elif not spf:
        flags.append("SPF header missing")
        score += 15

    if not dkim:
        flags.append("DKIM signature missing")
        score += 20

    if "fail" in dmarc:
        flags.append("DMARC check failed")
        score += 25
    elif not dmarc:
        flags.append("DMARC result missing")
        score += 10

    # --- Reply-To mismatch ---
    sender = parsed.get("from", "")
    reply_to = parsed.get("reply_to", "")
    if reply_to and reply_to != sender:
        flags.append(f"Reply-To mismatch: sender={sender}, reply_to={reply_to}")
        score += 20

    # --- Suspicious URLs ---
    urls = parsed.get("urls", [])
    suspicious_keywords = ["login", "verify", "secure", "account", "update", "confirm", "password", "bank"]
    sus_urls = [u for u in urls if any(kw in u.lower() for kw in suspicious_keywords)]
    if sus_urls:
        flags.append(f"Suspicious URLs found: {sus_urls}")
        score += min(len(sus_urls) * 10, 30)

    # --- Attachments ---
    attachments = parsed.get("attachments", [])
    risky_exts = [".exe", ".js", ".vbs", ".bat", ".ps1", ".docm", ".xlsm", ".zip"]
    for att in attachments:
        fname = att.get("filename", "").lower()
        if any(fname.endswith(ext) for ext in risky_exts):
            flags.append(f"Risky attachment: {att['filename']}")
            score += 40

    # --- Risk level ---
    if score >= 70:
        risk_level = "HIGH"
    elif score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    report = {
        "tool": "PhishGuard",
        "version": "0.1.0",
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "file": os.path.basename(file_path),
        "risk_level": risk_level,
        "risk_score": score,
        "flags": flags,
        "email_metadata": {
            "subject":    parsed["subject"],
            "from":       parsed["from"],
            "reply_to":   parsed["reply_to"],
            "to":         parsed["to"],
            "date":       parsed["date"],
            "message_id": parsed["message_id"],
        },
        "auth_headers": {
            "spf":   parsed["spf"],
            "dkim":  "present" if parsed["dkim"] else "missing",
            "dmarc": parsed["dmarc"],
        },
        "iocs": {
            "urls":        parsed["urls"],
            "ips":         parsed["ips"],
            "attachments": parsed["attachments"],
        },
        "received_chain": parsed["received_chain"],
    }
    return report


def print_text_report(report: dict):
    """Print a human-readable summary of the report."""
    sep = "=" * 60
    print(sep)
    print(f"  PhishGuard Analysis Report")
    print(f"  File       : {report['file']}")
    print(f"  Analyzed   : {report['analyzed_at']}")
    print(sep)
    print(f"  Risk Level : {report['risk_level']} (score: {report['risk_score']})")
    print(sep)
    print("  Email Metadata:")
    for k, v in report["email_metadata"].items():
        print(f"    {k:<12}: {v}")
    print(sep)
    print("  Auth Headers:")
    for k, v in report["auth_headers"].items():
        status = v if v else "not present"
        print(f"    {k.upper():<6}: {status[:80]}")
    print(sep)
    print("  Flags:")
    if report["flags"]:
        for flag in report["flags"]:
            print(f"    [!] {flag}")
    else:
        print("    [+] No flags raised.")
    print(sep)
    print("  IOCs:")
    print(f"    URLs        : {len(report['iocs']['urls'])} found")
    for url in report["iocs"]["urls"]:
        print(f"      - {url}")
    print(f"    IPs         : {report['iocs']['ips']}")
    print(f"    Attachments : {len(report['iocs']['attachments'])} found")
    for att in report["iocs"]["attachments"]:
        print(f"      - {att['filename']} ({att['content_type']}, {att['size_bytes']} bytes)")
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - Phishing Email Analyzer for SOC Analysts"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the .eml file to analyze")
    parser.add_argument("-o", "--output", choices=["json", "text"], default="text",
                        help="Output format: json or text (default: text)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {args.file} ...", file=sys.stderr)
    parsed = parse_eml(args.file)
    report = build_report(parsed, args.file)

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_report(report)


if __name__ == "__main__":
    main()
