# OSINT Investigation Report
**Report ID:** `OSINT-20260413-001`  |  **Classification:** TLP:WHITE — Unrestricted
**Target:** AiGeeks  |  **Type:** company  |  **Date:** 2026-04-13
**Analyst:** Dharam Kathiriya (Dark)  |  **Org:** Deveillance

---
## 01 — Executive Summary
Investigation of **"AiGeeks"** (company) using passive OSINT — no direct contact.
- Total raw findings collected: **40**
- After entity resolution: **40 confirmed**, **0 false positives filtered**
- Overall Risk: **MEDIUM** (42/100)

Active risk signals: `No Public Code Repository`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`, `Infrastructure Not Resolvable`

---
## 02 — Social & Public Footprint
| # | Title | Value | Confidence | Risk Signal | Source | Timestamp |
|---|-------|-------|-----------|-------------|--------|-----------|
| 1 | LinkedIn — AiGeeks | https://www.linkedin.com/company/aigeeks | 90% | — | [link](https://www.linkedin.com/company/aigeeks) | 2026-04-13T12:33:39.566Z |
| 2 | LinkedIn — AiGeeks | https://www.linkedin.com/company/aigeeks | 90% | — | [link](https://www.linkedin.com/company/aigeeks) | 2026-04-13T12:33:39.566Z |
| 3 | GitHub — AiGeeks | https://github.com/aigeeks | 90% | no_code_repo | [link](https://github.com/aigeeks) | 2026-04-13T12:33:39.581Z |
| 4 | Google Dork — LinkedIn profile/mentions | https://www.google.com/search?q=site%3Alinkedin.com%20%22AiGeeks%22 | 90% | — | [link](https://www.google.com/search?q=site%3Alinkedin.com%20%22AiGeeks%22) | 2026-04-13T12:33:39.581Z |
| 5 | Google Dork — GitHub presence | https://www.google.com/search?q=site%3Agithub.com%20%22AiGeeks%22 | 90% | — | [link](https://www.google.com/search?q=site%3Agithub.com%20%22AiGeeks%22) | 2026-04-13T12:33:39.581Z |
| 6 | Google Dork — Published documents/reports | https://www.google.com/search?q=%22AiGeeks%22%20filetype%3Apdf | 90% | — | [link](https://www.google.com/search?q=%22AiGeeks%22%20filetype%3Apdf) | 2026-04-13T12:33:39.581Z |
| 7 | Google Dork — Paste-site exposure check | https://www.google.com/search?q=%22AiGeeks%22%20site%3Apastebin.com | 90% | — | [link](https://www.google.com/search?q=%22AiGeeks%22%20site%3Apastebin.com) | 2026-04-13T12:33:39.581Z |
| 8 | Google Dork — Admin panel exposure | https://www.google.com/search?q=%22AiGeeks%22%20inurl%3Aadmin%20OR%20inurl%3Alog | 90% | — | [link](https://www.google.com/search?q=%22AiGeeks%22%20inurl%3Aadmin%20OR%20inurl%3Alogin) | 2026-04-13T12:33:39.581Z |
| 9 | Google Dork — Contact information | https://www.google.com/search?q=%22AiGeeks%22%20%22email%22%20OR%20%22contact%22 | 90% | — | [link](https://www.google.com/search?q=%22AiGeeks%22%20%22email%22%20OR%20%22contact%22) | 2026-04-13T12:33:39.581Z |

## 03 — Technical Infrastructure
| # | Title | Value | Confidence | Risk Signal | Source | Timestamp |
|---|-------|-------|-----------|-------------|--------|-----------|
| 1 | DNS A — aigeeks.com | NOT RESOLVED | 90% | infra_opacity | [link](https://dnschecker.org/#A/aigeeks.com) | 2026-04-13T12:33:39.554Z |
| 2 | DNS AAAA — aigeeks.com | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#AAAA/aigeeks.com) | 2026-04-13T12:33:39.572Z |
| 3 | DNS MX — aigeeks.com | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#MX/aigeeks.com) | 2026-04-13T12:33:39.573Z |
| 4 | DNS NS — aigeeks.com | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#NS/aigeeks.com) | 2026-04-13T12:33:39.573Z |
| 5 | DNS TXT — aigeeks.com | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#TXT/aigeeks.com) | 2026-04-13T12:33:39.574Z |
| 6 | WHOIS — aigeeks.com | NOT FOUND | 90% | infra_opacity | [link](https://rdap.org/domain/aigeeks.com) | 2026-04-13T12:33:39.589Z |
| 7 | HIBP Breach Check — aigeeks.com | API_KEY_REQUIRED | 90% | — | [link](https://haveibeenpwned.com/DomainSearch) | 2026-04-13T12:33:39.594Z |
| 8 | DNS A — aigeeks.io | NOT RESOLVED | 90% | infra_opacity | [link](https://dnschecker.org/#A/aigeeks.io) | 2026-04-13T12:33:39.595Z |
| 9 | DNS AAAA — aigeeks.io | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#AAAA/aigeeks.io) | 2026-04-13T12:33:39.596Z |
| 10 | DNS MX — aigeeks.io | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#MX/aigeeks.io) | 2026-04-13T12:33:39.596Z |
| 11 | DNS NS — aigeeks.io | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#NS/aigeeks.io) | 2026-04-13T12:33:39.597Z |
| 12 | DNS TXT — aigeeks.io | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#TXT/aigeeks.io) | 2026-04-13T12:33:39.598Z |
| 13 | WHOIS — aigeeks.io | NOT FOUND | 90% | infra_opacity | [link](https://rdap.org/domain/aigeeks.io) | 2026-04-13T12:33:39.601Z |
| 14 | HIBP Breach Check — aigeeks.io | API_KEY_REQUIRED | 90% | — | [link](https://haveibeenpwned.com/DomainSearch) | 2026-04-13T12:33:39.603Z |
| 15 | DNS A — aigeeks.org | NOT RESOLVED | 90% | infra_opacity | [link](https://dnschecker.org/#A/aigeeks.org) | 2026-04-13T12:33:39.604Z |
| 16 | DNS AAAA — aigeeks.org | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#AAAA/aigeeks.org) | 2026-04-13T12:33:39.604Z |
| 17 | DNS MX — aigeeks.org | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#MX/aigeeks.org) | 2026-04-13T12:33:39.605Z |
| 18 | DNS NS — aigeeks.org | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#NS/aigeeks.org) | 2026-04-13T12:33:39.606Z |
| 19 | DNS TXT — aigeeks.org | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#TXT/aigeeks.org) | 2026-04-13T12:33:39.607Z |
| 20 | WHOIS — aigeeks.org | NOT FOUND | 90% | infra_opacity | [link](https://rdap.org/domain/aigeeks.org) | 2026-04-13T12:33:39.609Z |
| 21 | HIBP Breach Check — aigeeks.org | API_KEY_REQUIRED | 90% | — | [link](https://haveibeenpwned.com/DomainSearch) | 2026-04-13T12:33:39.612Z |
| 22 | DNS A — aigeeks.net | NOT RESOLVED | 90% | infra_opacity | [link](https://dnschecker.org/#A/aigeeks.net) | 2026-04-13T12:33:39.613Z |
| 23 | DNS AAAA — aigeeks.net | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#AAAA/aigeeks.net) | 2026-04-13T12:33:39.614Z |
| 24 | DNS MX — aigeeks.net | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#MX/aigeeks.net) | 2026-04-13T12:33:39.614Z |
| 25 | DNS NS — aigeeks.net | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#NS/aigeeks.net) | 2026-04-13T12:33:39.615Z |
| 26 | DNS TXT — aigeeks.net | NOT RESOLVED | 90% | — | [link](https://dnschecker.org/#TXT/aigeeks.net) | 2026-04-13T12:33:39.615Z |
| 27 | WHOIS — aigeeks.net | NOT FOUND | 90% | infra_opacity | [link](https://rdap.org/domain/aigeeks.net) | 2026-04-13T12:33:39.619Z |
| 28 | HIBP Breach Check — aigeeks.net | API_KEY_REQUIRED | 90% | — | [link](https://haveibeenpwned.com/DomainSearch) | 2026-04-13T12:33:39.644Z |

## 04 — Contextual & Regulatory
| # | Title | Value | Confidence | Risk Signal | Source | Timestamp |
|---|-------|-------|-----------|-------------|--------|-----------|
| 1 | OpenCorporates — AiGeeks | Error: Request failed with status code 403 | 90% | — | [link](https://api.opencorporates.com/v0.4/companies/search?q=AiGeeks) | 2026-04-13T12:33:39.568Z |
| 2 | News Search — AiGeeks | https://news.google.com/search?q=AiGeeks | 90% | — | [link](https://news.google.com/search?q=AiGeeks) | 2026-04-13T12:33:39.569Z |
| 3 | OFAC SDN — AiGeeks | https://sanctionssearch.ofac.treas.gov/ | 90% | — | [link](https://sanctionssearch.ofac.treas.gov/) | 2026-04-13T12:33:39.583Z |

---
## Risk Assessment
### Overall: **MEDIUM** — Score: **42/100**

| Signal | Label | Severity | Weight | Contribution | Source |
|--------|-------|---------|--------|-------------|--------|
| no_code_repo | No Public Code Repository | **LOW** | 10 | 9 | SocialAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |
| infra_opacity | Infrastructure Not Resolvable | **MEDIUM** | 25 | 23 | InfrastructureAdapter |

---
## Audit Trail
> Every data point with source URL and retrieval timestamp.

| Status | Timestamp | Source | Title | Source URL |
|--------|-----------|--------|-------|------------|
| ✅ | 2026-04-13T12:33:39.566Z | SocialAdapter | LinkedIn — AiGeeks | https://www.linkedin.com/company/aigeeks |
| ✅ | 2026-04-13T12:33:39.566Z | SocialAdapter | LinkedIn — AiGeeks | https://www.linkedin.com/company/aigeeks |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | GitHub — AiGeeks | https://github.com/aigeeks |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | Google Dork — LinkedIn profile/mentions | https://www.google.com/search?q=site%3Alinkedin.com%20%22AiGeeks%22 |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | Google Dork — GitHub presence | https://www.google.com/search?q=site%3Agithub.com%20%22AiGeeks%22 |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | Google Dork — Published documents/reports | https://www.google.com/search?q=%22AiGeeks%22%20filetype%3Apdf |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | Google Dork — Paste-site exposure check | https://www.google.com/search?q=%22AiGeeks%22%20site%3Apastebin.com |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | Google Dork — Admin panel exposure | https://www.google.com/search?q=%22AiGeeks%22%20inurl%3Aadmin%20OR%20inurl%3Alogin |
| ✅ | 2026-04-13T12:33:39.581Z | SocialAdapter | Google Dork — Contact information | https://www.google.com/search?q=%22AiGeeks%22%20%22email%22%20OR%20%22contact%22 |
| ✅ | 2026-04-13T12:33:39.554Z | InfrastructureAdapter | DNS A — aigeeks.com | https://dnschecker.org/#A/aigeeks.com |
| ✅ | 2026-04-13T12:33:39.572Z | InfrastructureAdapter | DNS AAAA — aigeeks.com | https://dnschecker.org/#AAAA/aigeeks.com |
| ✅ | 2026-04-13T12:33:39.573Z | InfrastructureAdapter | DNS MX — aigeeks.com | https://dnschecker.org/#MX/aigeeks.com |
| ✅ | 2026-04-13T12:33:39.573Z | InfrastructureAdapter | DNS NS — aigeeks.com | https://dnschecker.org/#NS/aigeeks.com |
| ✅ | 2026-04-13T12:33:39.574Z | InfrastructureAdapter | DNS TXT — aigeeks.com | https://dnschecker.org/#TXT/aigeeks.com |
| ✅ | 2026-04-13T12:33:39.589Z | InfrastructureAdapter | WHOIS — aigeeks.com | https://rdap.org/domain/aigeeks.com |
| ✅ | 2026-04-13T12:33:39.594Z | InfrastructureAdapter | HIBP Breach Check — aigeeks.com | https://haveibeenpwned.com/DomainSearch |
| ✅ | 2026-04-13T12:33:39.595Z | InfrastructureAdapter | DNS A — aigeeks.io | https://dnschecker.org/#A/aigeeks.io |
| ✅ | 2026-04-13T12:33:39.596Z | InfrastructureAdapter | DNS AAAA — aigeeks.io | https://dnschecker.org/#AAAA/aigeeks.io |
| ✅ | 2026-04-13T12:33:39.596Z | InfrastructureAdapter | DNS MX — aigeeks.io | https://dnschecker.org/#MX/aigeeks.io |
| ✅ | 2026-04-13T12:33:39.597Z | InfrastructureAdapter | DNS NS — aigeeks.io | https://dnschecker.org/#NS/aigeeks.io |
| ✅ | 2026-04-13T12:33:39.598Z | InfrastructureAdapter | DNS TXT — aigeeks.io | https://dnschecker.org/#TXT/aigeeks.io |
| ✅ | 2026-04-13T12:33:39.601Z | InfrastructureAdapter | WHOIS — aigeeks.io | https://rdap.org/domain/aigeeks.io |
| ✅ | 2026-04-13T12:33:39.603Z | InfrastructureAdapter | HIBP Breach Check — aigeeks.io | https://haveibeenpwned.com/DomainSearch |
| ✅ | 2026-04-13T12:33:39.604Z | InfrastructureAdapter | DNS A — aigeeks.org | https://dnschecker.org/#A/aigeeks.org |
| ✅ | 2026-04-13T12:33:39.604Z | InfrastructureAdapter | DNS AAAA — aigeeks.org | https://dnschecker.org/#AAAA/aigeeks.org |
| ✅ | 2026-04-13T12:33:39.605Z | InfrastructureAdapter | DNS MX — aigeeks.org | https://dnschecker.org/#MX/aigeeks.org |
| ✅ | 2026-04-13T12:33:39.606Z | InfrastructureAdapter | DNS NS — aigeeks.org | https://dnschecker.org/#NS/aigeeks.org |
| ✅ | 2026-04-13T12:33:39.607Z | InfrastructureAdapter | DNS TXT — aigeeks.org | https://dnschecker.org/#TXT/aigeeks.org |
| ✅ | 2026-04-13T12:33:39.609Z | InfrastructureAdapter | WHOIS — aigeeks.org | https://rdap.org/domain/aigeeks.org |
| ✅ | 2026-04-13T12:33:39.612Z | InfrastructureAdapter | HIBP Breach Check — aigeeks.org | https://haveibeenpwned.com/DomainSearch |
| ✅ | 2026-04-13T12:33:39.613Z | InfrastructureAdapter | DNS A — aigeeks.net | https://dnschecker.org/#A/aigeeks.net |
| ✅ | 2026-04-13T12:33:39.614Z | InfrastructureAdapter | DNS AAAA — aigeeks.net | https://dnschecker.org/#AAAA/aigeeks.net |
| ✅ | 2026-04-13T12:33:39.614Z | InfrastructureAdapter | DNS MX — aigeeks.net | https://dnschecker.org/#MX/aigeeks.net |
| ✅ | 2026-04-13T12:33:39.615Z | InfrastructureAdapter | DNS NS — aigeeks.net | https://dnschecker.org/#NS/aigeeks.net |
| ✅ | 2026-04-13T12:33:39.615Z | InfrastructureAdapter | DNS TXT — aigeeks.net | https://dnschecker.org/#TXT/aigeeks.net |
| ✅ | 2026-04-13T12:33:39.619Z | InfrastructureAdapter | WHOIS — aigeeks.net | https://rdap.org/domain/aigeeks.net |
| ✅ | 2026-04-13T12:33:39.644Z | InfrastructureAdapter | HIBP Breach Check — aigeeks.net | https://haveibeenpwned.com/DomainSearch |
| ✅ | 2026-04-13T12:33:39.568Z | RegulatoryAdapter | OpenCorporates — AiGeeks | https://api.opencorporates.com/v0.4/companies/search?q=AiGeeks |
| ✅ | 2026-04-13T12:33:39.569Z | RegulatoryAdapter | News Search — AiGeeks | https://news.google.com/search?q=AiGeeks |
| ✅ | 2026-04-13T12:33:39.583Z | RegulatoryAdapter | OFAC SDN — AiGeeks | https://sanctionssearch.ofac.treas.gov/ |

---
*Generated by OSINT Tool v1.0 | Dharam Kathiriya (Dark) | 2026-04-13T12:33:39.646Z*