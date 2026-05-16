# PhishGuard

> A Python-based phishing email analyzer built for SOC analysts. Designed to automate Tier 1 email triage — extracting IOCs, validating authentication headers, and generating structured alert reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![SOC](https://img.shields.io/badge/role-SOC%20Analyst-red)

---

## What It Does

Given a `.eml` file, PhishGuard will:

1. **Parse** all email headers — From, Reply-To, Received chain, Message-ID, X-Originating-IP
2. **Validate** SPF, DKIM, and DMARC authentication results
3. **Extract IOCs** — URLs, IPv4 addresses, and attachment metadata from the email body
4. **Score risk** using a weighted flag system (SPF fail, DKIM missing, Reply-To mismatch, suspicious URLs, risky attachments)
5. **Output** a structured report in human-readable text or JSON (SIEM-ready)

---

## Project Structure

```
PhishGuard/
├── main.py                  # CLI entry point
├── requirements.txt         # Dependencies
├── phishguard/
│   └── email_parser.py      # .eml parsing & IOC extraction module
└── samples/                 # Sample .eml files for testing (coming soon)
```

---

## Installation

```bash
git clone https://github.com/psycho-manav/PhishGuard.git
cd PhishGuard
pip install -r requirements.txt
```

---

## Usage

```bash
# Human-readable report (default)
python main.py -f samples/phishing_test.eml

# JSON output (SIEM-ready)
python main.py -f samples/phishing_test.eml -o json
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Path to the `.eml` file (required) |
| `-o`, `--output` | Output format: `text` (default) or `json` |

---

## Risk Scoring

PhishGuard calculates a risk score based on weighted flags:

| Check | Score |
|-------|-------|
| SPF fail / softfail | +30 |
| SPF header missing | +15 |
| DKIM signature missing | +20 |
| DMARC fail | +25 |
| DMARC result missing | +10 |
| Reply-To mismatch | +20 |
| Suspicious URL keywords | +10 per URL (max 30) |
| Risky attachment extension | +40 |

| Score | Risk Level |
|-------|------------|
| 0–34 | LOW |
| 35–69 | MEDIUM |
| 70+ | HIGH |

---

## Sample JSON Output

```json
{
  "tool": "PhishGuard",
  "version": "0.1.0",
  "risk_level": "HIGH",
  "risk_score": 85,
  "flags": [
    "SPF check failed",
    "DKIM signature missing",
    "Reply-To mismatch: sender=billing@paypal.com, reply_to=collect@evil.ru",
    "Suspicious URLs found: ['http://paypal-verify.login.evil.ru/account']"
  ],
  "iocs": {
    "urls": ["http://paypal-verify.login.evil.ru/account"],
    "ips": ["185.220.101.47"],
    "attachments": []
  }
}
```

---

## Tech Stack

- **Python 3** — `email`, `re`, `argparse`, `json`, `datetime`
- **requests** — for future API integrations (AbuseIPDB, VirusTotal)
- **dnspython** — SPF/DMARC DNS lookups (Week 2)
- **ipwhois** — IP geolocation and ASN lookup (Week 2)

---

## Roadmap

- [x] `.eml` parsing — headers, body, URLs, IPs, attachments
- [x] SPF / DKIM / DMARC header validation
- [x] Risk scoring engine
- [x] JSON + text report output
- [ ] AbuseIPDB API integration for IP reputation checks
- [ ] VirusTotal API integration for URL/domain checks
- [ ] Live DNS SPF/DMARC record validation
- [ ] Sample phishing `.eml` test files
- [ ] HTML report output

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**. Use it to analyze emails you own or have explicit permission to analyze.

---

*Built as part of a SOC analyst portfolio project.*
