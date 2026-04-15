# OSINT Tool v1.0

> Automated entity discovery and professional investigation report generation.  
> Built as a technical assessment submission for AI Geeks.

---

## What It Does

Given a **Company Name** or **Individual Name**, this tool:

1. **Acquires data** from three source categories in parallel (modular Adapter pattern)
2. **Resolves entities** — groups assets to the parent, filters false positives with confidence scoring
3. **Scores risk** — weighted algorithm across breach, sanctions, infrastructure, and press signals
4. **Generates reports** — PDF and/or Markdown with executive summary, categorised tables, and full audit trail

---

## Architecture

```
osint-tool/
├── index.js                    ← CLI entry point
├── core/
│   ├── engine.js               ← Orchestrator — runs adapters, pipes to resolver + scorer
│   ├── entityResolver.js       ← Confidence scoring, false positive filtering, grouping
│   ├── riskScorer.js           ← Weighted risk algorithm (0–100 + CRITICAL/HIGH/MEDIUM/LOW)
│   └── logger.js               ← Timestamped logger
├── adapters/
│   ├── baseAdapter.js          ← Abstract base — fetch(), robots.txt check, finding() factory
│   ├── robotsChecker.js        ← Parses & caches robots.txt, OPSEC-compliant blocking
│   ├── socialAdapter.js        ← DuckDuckGo, LinkedIn, GitHub, Google Dorks
│   ├── infrastructureAdapter.js← DNS, WHOIS/RDAP, crt.sh, Shodan InternetDB, HIBP
│   └── regulatoryAdapter.js    ← OpenCorporates, NewsAPI, OFAC SDN sanctions
└── output/
    ├── pdfReporter.js          ← PDFKit-based professional PDF report
    └── markdownReporter.js     ← Markdown report (portable, version-control friendly)
```

### Adapter Pattern

Each adapter extends `BaseAdapter` and implements a single method:

```js
async collect(target, type) → Finding[]
```

To add a new source, create a file in `adapters/`, extend `BaseAdapter`, and pass it into `OSINTEngine`:

```js
const { MyNewAdapter } = require('./adapters/myNewAdapter');
const engine = new OSINTEngine([..., new MyNewAdapter()]);
```

---

## Setup

### Prerequisites

- Node.js ≥ 18
- npm

### Install

```bash
git clone <your-repo-url>
cd osint-tool
npm install
```

### API Keys (all optional — tool degrades gracefully without them)

| Key | Service | Purpose | Get it |
|-----|---------|---------|--------|
| `HIBP_API_KEY` | Have I Been Pwned | Domain/email breach check | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| `NEWS_API_KEY` | NewsAPI.org | Adverse press detection | [newsapi.org](https://newsapi.org) |
| `OPENCORP_API_KEY` | OpenCorporates | Company registry lookup | [opencorporates.com/api](https://opencorporates.com/api) |

Set them in your environment:

```bash
export HIBP_API_KEY=your_key_here
export NEWS_API_KEY=your_key_here
export OPENCORP_API_KEY=your_key_here
```

Or create a `.env` file and load with `dotenv` (not bundled — add `require('dotenv').config()` to `index.js` if needed).

---

## Usage

```bash
# Company investigation — both PDF and Markdown
node index.js --target "AiGeeks" --type company

# Individual investigation — PDF only
node index.js --target "Travis Haasch" --type individual --format pdf

# With proxy for OPSEC
node index.js --target "AiGeeks" --type company --proxy http://user:pass@proxyhost:8080

# Custom output directory
node index.js --target "AiGeeks" --type company --out ./my-reports
```

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--target` | *(required)* | Company or individual name |
| `--type` | `company` | `company` or `individual` |
| `--format` | `both` | `pdf`, `md`, or `both` |
| `--proxy` | none | HTTP/HTTPS proxy URL |
| `--out` | `./reports` | Output directory |

---

## Data Sources

### Social & Public Footprint
| Source | Method | Key Required |
|--------|--------|--------------|
| DuckDuckGo HTML | Scraping | No |
| LinkedIn | Profile URL construction | No |
| GitHub | Public API | No |
| Google Dorks | Query construction (manual execution) | No |

### Technical Infrastructure
| Source | Method | Key Required |
|--------|--------|--------------|
| DNS (A/AAAA/MX/NS/TXT) | Node `dns.promises` | No |
| WHOIS / RDAP | rdap.org API | No |
| Certificate Transparency | crt.sh JSON API | No |
| Shodan InternetDB | HTTP API (no auth tier) | No |
| Have I Been Pwned | v3 API | **Yes** (`HIBP_API_KEY`) |

### Contextual & Regulatory
| Source | Method | Key Required |
|--------|--------|--------------|
| OpenCorporates | Public API (rate-limited) | Optional |
| OFAC SDN Sanctions | Public API | No |
| NewsAPI | REST API | **Yes** (`NEWS_API_KEY`) |

---

## OPSEC Design

- **robots.txt**: Every HTTP request is checked against the target domain's `robots.txt` before execution. Disallowed paths are skipped and logged.
- **Proxy rotation**: Pass `--proxy` or set `PROXY_URL` to route all adapter requests through a proxy. Supports HTTP/HTTPS with optional `user:pass` auth.
- **User-Agent**: Requests identify as `OSINTBot/1.0` — transparent and honest, not disguised as a real browser.
- **Passive only**: No active port scanning, no credential stuffing, no direct enumeration of email addresses.
- **Timeout**: All requests timeout at 10 seconds (configurable via `adapter.timeout`).

---

## Entity Resolution

The `EntityResolver` scores every raw finding against the target entity using:

- **Token match**: How many words from the target appear in the finding
- **Exact match**: Full entity name present (stronger signal)
- **Category alignment**: Social findings scored higher for individuals; infra/regulatory for companies
- **Mismatch penalty**: Adapters can flag probable mismatches; those findings are penalised

Findings below the confidence threshold (default: 0.4) are moved to `falsePositives` — still included in the audit trail but excluded from risk scoring and report tables.

---

## Risk Scoring

Weighted scoring across 9 signal types:

| Signal | Weight | Severity |
|--------|--------|---------|
| Breach Exposure | 90 | CRITICAL |
| Dark Web Mention | 85 | CRITICAL |
| Sanctions Hit | 80 | HIGH |
| Derogatory Press | 70 | HIGH |
| Open Port | 45 | MEDIUM |
| Expired Certificate | 35 | MEDIUM |
| Infrastructure Opacity | 25 | MEDIUM |
| No Code Repository | 10 | LOW |

Final score = sum of (weight × confidence) for triggered signals, normalised to 0–100.

---

## Output

Reports are written to `./reports/` (or `--out` directory).

Every finding in the report includes:
- **Source name** — which adapter collected it
- **Source URL** — direct link to where the data was retrieved
- **Retrieval timestamp** — ISO 8601 UTC

---

## Sample Report

A sample PDF and Markdown report generated for **Travis Haasch** (CEO, AI Geeks) are included in `reports/`.

Generated by running:
```bash
node index.js --target "Travis Haasch" --type individual
```

---

## Adding New Adapters

```js
// adapters/myAdapter.js
const { BaseAdapter } = require('./baseAdapter');

class MyAdapter extends BaseAdapter {
  constructor(options = {}) {
    super({ ...options, name: 'MyAdapter', category: 'social' }); // or infrastructure/regulatory
  }

  async collect(target, type) {
    const data = await this.fetch(`https://api.example.com/search?q=${target}`);
    return [
      this.finding({
        title:     `MyAdapter — ${target}`,
        value:     data.someField,
        summary:   `Found: ${data.someField}`,
        sourceUrl: `https://api.example.com/search?q=${target}`,
        riskSignal: null, // or a key from RiskScorer WEIGHTS
      })
    ];
  }
}

module.exports = { MyAdapter };
```

Then in `index.js`:
```js
const { MyAdapter } = require('./adapters/myAdapter');
const adapters = [
  new SocialAdapter(adapterOpts),
  new InfrastructureAdapter(adapterOpts),
  new RegulatoryAdapter(adapterOpts),
  new MyAdapter(adapterOpts),  // ← add here
];
```

---

## Evaluation Criteria — Self Assessment

| Criteria | Approach |
|----------|---------|
| **Data Integrity** | Entity resolver with confidence scoring; false positives documented in audit trail |
| **Architecture** | Fully modular — BaseAdapter contract, plug-and-play new sources |
| **OPSEC** | robots.txt checked on every request; proxy rotation; passive-only collection |

---

*OSINT Tool v1.0 — Dharam Kathiriya (Dark) | Deveillance OSINT Analyst Intern*
