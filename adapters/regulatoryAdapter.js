/**
 * RegulatoryAdapter — Category: Contextual & Regulatory
 *
 * Collects:
 *   - OpenCorporates company search (public API, no key for basic)
 *   - NewsAPI / open news archive mentions (requires free API key)
 *   - OFAC SDN sanctions list check (public CSV)
 *   - Open Corporates officer search (for individuals)
 *
 * All keys are optional — adapter documents what requires a key and degrades gracefully.
 */

'use strict';

const { BaseAdapter } = require('./baseAdapter');

class RegulatoryAdapter extends BaseAdapter {
  constructor(options = {}) {
    super({ ...options, name: 'RegulatoryAdapter', category: 'regulatory' });
    this.openCorpApiKey = options.openCorpApiKey || null;
    this.newsApiKey     = options.newsApiKey     || null;
  }

  async collect(target, type) {
    const findings = [];

    const corpFindings = await this._openCorporates(target, type);
    const newsFindings = await this._newsSearch(target);
    const ofacFindings = await this._ofacCheck(target);

    findings.push(...corpFindings, ...newsFindings, ...ofacFindings);
    return findings;
  }

  // ─── OpenCorporates ────────────────────────────────────────────────────────
  async _openCorporates(target, type) {
    const findings = [];

    if (type === 'individual') {
      // Officer search
      const url = `https://api.opencorporates.com/v0.4/officers/search?q=${encodeURIComponent(target)}${this.openCorpApiKey ? `&api_token=${this.openCorpApiKey}` : ''}`;
      try {
        const data = await this.fetch(url);
        const officers = data?.results?.officers || [];
        for (const item of officers.slice(0, 5)) {
          const o = item.officer;
          findings.push(this.finding({
            title:     `OpenCorporates Officer — ${o.name}`,
            value:     o.name,
            summary:   `Officer role: ${o.position || 'Unknown'} at ${o.company?.name || 'Unknown company'} (${o.company?.jurisdiction_code || ''})`,
            sourceUrl: o.opencorporates_url || url,
            extra:     { companyName: o.company?.name, jurisdiction: o.company?.jurisdiction_code },
          }));
        }
        if (officers.length === 0) {
          findings.push(this.finding({
            title:    `OpenCorporates — ${target}`,
            value:    'No officer record found',
            summary:  `No officer record found in OpenCorporates for "${target}"`,
            sourceUrl: url,
          }));
        }
      } catch (err) {
        findings.push(this.finding({
          title:    `OpenCorporates — ${target}`,
          value:    `Error: ${err.message}`,
          summary:  `OpenCorporates officer search failed: ${err.message}`,
          sourceUrl: url,
        }));
      }
    } else {
      // Company search
      const url = `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(target)}${this.openCorpApiKey ? `&api_token=${this.openCorpApiKey}` : ''}`;
      try {
        const data = await this.fetch(url);
        const companies = data?.results?.companies || [];
        for (const item of companies.slice(0, 5)) {
          const c = item.company;
          findings.push(this.finding({
            title:     `OpenCorporates — ${c.name}`,
            value:     c.name,
            summary:   `Company: ${c.name} | Jurisdiction: ${c.jurisdiction_code} | Status: ${c.current_status || 'Unknown'} | Incorporated: ${c.incorporation_date || 'Unknown'}`,
            sourceUrl: c.opencorporates_url || url,
            mismatch:  !c.name.toLowerCase().includes(target.toLowerCase().split(' ')[0]),
            extra:     {
              jurisdiction:       c.jurisdiction_code,
              status:             c.current_status,
              incorporationDate:  c.incorporation_date,
              companyNumber:      c.company_number,
            },
          }));
        }
        if (companies.length === 0) {
          findings.push(this.finding({
            title:    `OpenCorporates — ${target}`,
            value:    'No company record found',
            summary:  `No company record found in OpenCorporates for "${target}"`,
            sourceUrl: url,
          }));
        }
      } catch (err) {
        findings.push(this.finding({
          title:    `OpenCorporates — ${target}`,
          value:    `Error: ${err.message}`,
          summary:  `OpenCorporates company search failed: ${err.message}`,
          sourceUrl: url,
        }));
      }
    }

    return findings;
  }

  // ─── News search (NewsAPI or fallback to DuckDuckGo news) ─────────────────
  async _newsSearch(target) {
    const findings = [];

    if (this.newsApiKey) {
      const url = `https://newsapi.org/v2/everything?q=${encodeURIComponent(target)}&sortBy=relevancy&pageSize=5&apiKey=${this.newsApiKey}`;
      try {
        const data = await this.fetch(url);
        for (const article of (data?.articles || [])) {
          const isDerogatory = this._isDerogatory(article.title + ' ' + article.description);
          findings.push(this.finding({
            title:      article.title,
            value:      article.url,
            summary:    `[${article.source?.name}] ${article.description || article.title} | Published: ${article.publishedAt}`,
            sourceUrl:  article.url,
            riskSignal: isDerogatory ? 'derogatory_press' : null,
            extra:      { publishedAt: article.publishedAt, source: article.source?.name },
          }));
        }
      } catch (err) {
        findings.push(this.finding({
          title:    `NewsAPI — ${target}`,
          value:    `Error: ${err.message}`,
          summary:  `NewsAPI search failed. Set NEWS_API_KEY env var.`,
          sourceUrl: 'https://newsapi.org',
          extra:    { requiresApiKey: true },
        }));
      }
    } else {
      // Fallback: document the query for manual execution
      findings.push(this.finding({
        title:    `News Search — ${target}`,
        value:    `https://news.google.com/search?q=${encodeURIComponent(target)}`,
        summary:  `News search requires NEWS_API_KEY env var for automated collection. Manual search URL provided.`,
        sourceUrl: `https://news.google.com/search?q=${encodeURIComponent(target)}`,
        extra:    { requiresApiKey: true, manualUrl: `https://news.google.com/search?q=${encodeURIComponent(target)}` },
      }));
    }

    return findings;
  }

  // ─── OFAC SDN sanctions check (public, no key) ────────────────────────────
  async _ofacCheck(target) {
    const findings = [];

    // OFAC provides a public API search endpoint
    const url = `https://api.ofac-api.com/v3/search`;

    try {
      const data = await this.fetch(url, {
        method: 'POST',
        data: {
          apiKey:  'public',
          minScore: 85,
          sources: ['SDN'],
          type:    ['entity', 'individual'],
          search:  target,
        },
      });

      const matches = data?.matches || [];
      if (matches.length > 0) {
        findings.push(this.finding({
          title:      `OFAC SDN HIT — ${target}`,
          value:      `${matches.length} match(es) found`,
          summary:    `SANCTIONS ALERT: ${target} returned ${matches.length} result(s) in OFAC SDN list. Immediate review required.`,
          sourceUrl:  'https://sanctionssearch.ofac.treas.gov/',
          riskSignal: 'sanctions',
        }));
      } else {
        findings.push(this.finding({
          title:    `OFAC SDN — ${target}`,
          value:    'No match',
          summary:  `${target} not found in OFAC SDN sanctions list (score ≥85).`,
          sourceUrl: 'https://sanctionssearch.ofac.treas.gov/',
        }));
      }
    } catch {
      // Fallback — document manual check URL
      findings.push(this.finding({
        title:    `OFAC SDN — ${target}`,
        value:    `https://sanctionssearch.ofac.treas.gov/`,
        summary:  `Automated OFAC check unavailable. Manual verification URL provided.`,
        sourceUrl: `https://sanctionssearch.ofac.treas.gov/`,
        extra:    { manualUrl: `https://sanctionssearch.ofac.treas.gov/` },
      }));
    }

    return findings;
  }

  // ─── Derogatory press heuristics ──────────────────────────────────────────
  _isDerogatory(text) {
    const keywords = [
      'fraud', 'scam', 'arrested', 'convicted', 'lawsuit', 'scandal',
      'breach', 'hack', 'fine', 'penalty', 'banned', 'illegal', 'investigation',
    ];
    const lower = text.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }
}

module.exports = { RegulatoryAdapter };
