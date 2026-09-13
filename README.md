# Threat Intelligence Summarizer

A Python tool that takes a suspicious **URL, domain, IP, or file hash**, queries
**VirusTotal** and **URLhaus**, and uses an **LLM** to generate an analyst-grade
risk report with cross-source correlation reasoning.

## Why

Over summer 2026 I did an undergraduate research project comparing static and
dynamic techniques for detecting malicious open-source packages (GuardDog vs.
OpenSSF package-analysis) in an isolated Linux lab. One thing that stuck with me
was how much stronger a verdict becomes when independent methods agree, and how
much manual work it takes to line those signals up by hand.

At my IT helpdesk job I also spend a lot of time on access and authentication
issues, where checking whether an indicator is known-bad is a routine but tedious
step. I built this tool to automate that: pull reputation data from two independent
threat-intel sources and let an LLM synthesize them into a single analyst-grade
verdict, with explicit reasoning about whether the sources corroborate or conflict which uses
the same "agreement across methods" idea from my research, applied to IOC triage.

## Features

- Auto-detects indicator type (hash / URL / domain / IP)
- Queries VirusTotal (v3 API) and URLhaus in one run
- LLM summarizer produces a Markdown report with **verdict, key findings,
  cross-source correlation, and recommended action**
- Correlation reasoning: explicitly notes when sources corroborate or conflict
- CLI with `--output` flag to save reports
- Logging to file and console
- Secrets kept in `.env` (never committed)

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env      # then edit .env with your real keys
```

Get free keys:
- VirusTotal: https://www.virustotal.com/gui/join-us (public API, ~4 req/min)
- Anthropic: https://console.anthropic.com/
- URLhaus: https://auth.abuse.ch/ (sign in, connect a second login provider, Save profile, then generate an Auth-Key under "Optional")

## Usage

```bash
python3 threatintel.py 44d88612fea8a8f36de82e1278abb02f
python3 threatintel.py http://suspicious-example.com --output report.md
python3 threatintel.py 8.8.8.8
```

## Example output

Running the tool against a live Mirai botnet URL from the URLhaus feed:

```
python3 threatintel.py "http://64.89.160.197/bot_client_amd64" --output report.md
```

**Verdict:** MALICIOUS — High Confidence

**Key Findings**
- *VirusTotal:* 10 engines flagged malicious, 5 suspicious (15 negative verdicts total); reputation score −11.
- *URLhaus:* classified as `malware_download`, status `online` (live threat), tagged `DDoSAgent` / `elf` — a Linux DDoS botnet binary. [URLhaus reference](https://urlhaus.abuse.ch/url/3915659/)

**Correlation:** Both sources fully corroborate. A broad multi-engine scanner and a curated malware feed independently agree on maliciousness, and URLhaus adds specificity VirusTotal lacks (threat family, binary type, live status). When two methodologically different sources agree, confidence increases substantially. The 47 "harmless" VirusTotal verdicts are a known scanner artifact and don't weaken the verdict.

**Recommended Action:** Block the URL and host IP immediately; hunt SIEM/EDR/DNS logs for connections to the IP; treat any host that fetched the binary as potentially compromised.

## Security note

This project keeps API keys in a `.env` file that is excluded via `.gitignore`.
Never commit real credentials — use `.env.example` as the shared template.

## Possible extensions

- AbuseIPDB and AlienVault OTX as additional sources
- Async requests for batch IOC processing
- HTML report output
- Confidence scoring across >2 sources
