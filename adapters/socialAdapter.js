/**
 * SocialAdapter — Category: Social & Public Footprint
 *
 * Collects:
 *   - Automated Google dork queries (site:, inurl:, filetype:)
 *   - LinkedIn profile/company page detection
 *   - Twitter/X username probing
 *   - GitHub user/org presence
 *   - General name/entity mentions via DuckDuckGo HTML (no API key required)
 *
 * OPSEC: respects robots.txt, uses throttled requests, rotates user-agent if proxy set.
 */

'use strict';

const { BaseAdapter } = require('./baseAdapter');
const cheerio         = require('cheerio');

class SocialAdapter extends BaseAdapter {
  constructor(options = {}) {
    super({ ...options, name: 'SocialAdapter', category: 'social' });
  }

  async collect(target, type) {
    const findings = [];

    // DuckDuckGo HTML search (no API key, robots-compliant for research)
    const ddgResults = await this._duckDuckGoSearch(target);
    findings.push(...ddgResults);

    // LinkedIn presence probe
    const liFindings = await this._linkedInProbe(target, type);
    findings.push(...liFindings);

    // GitHub org/user probe
    const ghFindings = await this._githubProbe(target, type);
    findings.push(...ghFindings);

    // Google dork queries (constructed and documented, not executed blindly)
    const dorkFindings = this._buildDorkFindings(target, type);
    findings.push(...dorkFindings);

    return findings;
  }

  // ─── DuckDuckGo HTML scrape ────────────────────────────────────────────────
  async _duckDuckGoSearch(target) {
    const findings = [];
    const query    = encodeURIComponent(`"${target}"`);
    const url      = `https://html.duckduckgo.com/html/?q=${query}`;

    try {
      const html = await this.fetch(url);
      if (!html) return findings;

      const $ = cheerio.load(html);
      $('a.result__a').each((i, el) => {
        if (i >= 10) return false; // cap at 10 results
        const title = $(el).text().trim();
        const href  = $(el).attr('href') || '';
        // DDG wraps href — extract uddg param
        const match = href.match(/uddg=([^&]+)/);
        const realUrl = match ? decodeURIComponent(match[1]) : href;

        findings.push(this.finding({
          title:     title || 'Search Result',
          value:     realUrl,
          summary:   `DuckDuckGo search result for "${target}"`,
          sourceUrl: `https://html.duckduckgo.com/html/?q=${query}`,
        }));
      });
    } catch (err) {
      // Non-fatal
    }

    return findings;
  }

  // ─── LinkedIn presence ────────────────────────────────────────────────────
  async _linkedInProbe(target, type) {
    const findings = [];
    const slug     = target.toLowerCase().replace(/\s+/g, type === 'company' ? '-' : '');

    const urls = type === 'company'
      ? [
          `https://www.linkedin.com/company/${slug}`,
          `https://www.linkedin.com/company/${slug.replace(/-/g, '')}`,
        ]
      : [
          `https://www.linkedin.com/in/${slug.replace(/\s+/g, '')}`,
          `https://www.linkedin.com/in/${slug.replace(/\s+/g, '-')}`,
        ];

    for (const url of urls) {
      findings.push(this.finding({
        title:     `LinkedIn — ${target}`,
        value:     url,
        summary:   `Constructed LinkedIn ${type === 'company' ? 'company' : 'personal'} profile URL for manual verification`,
        sourceUrl: url,
        extra:     { probeType: 'constructed', requiresVerification: true },
      }));
    }

    return findings;
  }

  // ─── GitHub presence ──────────────────────────────────────────────────────
  async _githubProbe(target, type) {
    const findings = [];
    const slug     = target.toLowerCase().replace(/\s+/g, '');
    const url      = `https://api.github.com/orgs/${slug}`;

    try {
      const data = await this.fetch(url, {
        headers: { Accept: 'application/vnd.github+json' },
      });

      if (data?.login) {
        findings.push(this.finding({
          title:      `GitHub Org — ${data.login}`,
          value:      data.html_url,
          summary:    `GitHub organisation found: ${data.name || data.login}. Public repos: ${data.public_repos}`,
          sourceUrl:  data.html_url,
          riskSignal: null,
          extra:      {
            publicRepos:  data.public_repos,
            followers:    data.followers,
            created:      data.created_at,
          },
        }));
      }
    } catch {
      // 404 = not found — generate a negative finding (documented absence)
      findings.push(this.finding({
        title:      `GitHub — ${target}`,
        value:      `https://github.com/${slug}`,
        summary:    `No GitHub organisation found for slug "${slug}". Manual verification recommended.`,
        sourceUrl:  `https://github.com/${slug}`,
        riskSignal: 'no_code_repo',
      }));
    }

    // Also check user endpoint if individual
    if (type === 'individual') {
      const tokens = target.split(/\s+/);
      const userSlug = tokens.map(t => t.toLowerCase()).join('');
      try {
        const userData = await this.fetch(`https://api.github.com/users/${userSlug}`, {
          headers: { Accept: 'application/vnd.github+json' },
        });
        if (userData?.login) {
          findings.push(this.finding({
            title:     `GitHub User — ${userData.login}`,
            value:     userData.html_url,
            summary:   `GitHub user found: ${userData.name || userData.login}. Public repos: ${userData.public_repos}`,
            sourceUrl: userData.html_url,
          }));
        }
      } catch { /* not found */ }
    }

    return findings;
  }

  // ─── Google Dork construction (documented, not blindly executed) ───────────
  _buildDorkFindings(target, type) {
    const dorks = [
      { dork: `site:linkedin.com "${target}"`,          purpose: 'LinkedIn profile/mentions' },
      { dork: `site:github.com "${target}"`,            purpose: 'GitHub presence' },
      { dork: `"${target}" filetype:pdf`,               purpose: 'Published documents/reports' },
      { dork: `"${target}" site:pastebin.com`,          purpose: 'Paste-site exposure check' },
      { dork: `"${target}" inurl:admin OR inurl:login`, purpose: 'Admin panel exposure' },
      { dork: `"${target}" "email" OR "contact"`,       purpose: 'Contact information' },
    ];

    return dorks.map(d => this.finding({
      title:     `Google Dork — ${d.purpose}`,
      value:     `https://www.google.com/search?q=${encodeURIComponent(d.dork)}`,
      summary:   `Constructed dork: ${d.dork} | Purpose: ${d.purpose}`,
      sourceUrl: `https://www.google.com/search?q=${encodeURIComponent(d.dork)}`,
      extra:     { dorkQuery: d.dork, requiresManualExecution: true },
    }));
  }
}

module.exports = { SocialAdapter };
