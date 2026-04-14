/**
 * InfrastructureAdapter — Category: Technical Infrastructure
 *
 * Collects:
 *   - WHOIS records (via whois-json or direct lookup)
 *   - DNS records (A, MX, NS, TXT, AAAA) via dns module
 *   - Have I Been Pwned (HIBP) breach check — domain-level (no API key for v3)
 *   - Certificate Transparency logs (crt.sh) — subdomain enumeration
 *   - Shodan InternetDB (no key) — open ports/vulns for resolved IP
 *
 * OPSEC: passive lookups only, no active port scanning.
 */

'use strict';

const { BaseAdapter } = require('./baseAdapter');
const dns             = require('dns').promises;

class InfrastructureAdapter extends BaseAdapter {
  constructor(options = {}) {
    super({ ...options, name: 'InfrastructureAdapter', category: 'infrastructure' });
    this.hibpApiKey = options.hibpApiKey || null;
  }

  async collect(target, type) {
    const findings = [];

    // Derive domain candidates
    const domains = this._deriveDomains(target, type);

    for (const domain of domains) {
      const dnsFindings   = await this._dnsLookup(domain);
      const whoisFindings = await this._whoisLookup(domain);
      const crtFindings   = await this._crtshLookup(domain);
      const hibpFindings  = await this._hibpCheck(domain);

      findings.push(...dnsFindings, ...whoisFindings, ...crtFindings, ...hibpFindings);
    }

    return findings;
  }

  // ─── Domain derivation ────────────────────────────────────────────────────
  _deriveDomains(target, type) {
    const slug = target.toLowerCase().replace(/\s+/g, '');
    const tlds = ['com', 'io', 'org', 'net', 'ae', 'co'];
    return tlds.map(t => `${slug}.${t}`).slice(0, 4); // check first 4
  }

  // ─── DNS ──────────────────────────────────────────────────────────────────
  async _dnsLookup(domain) {
    const findings = [];
    const recordTypes = [
      { type: 'A',     fn: () => dns.resolve4(domain) },
      { type: 'AAAA',  fn: () => dns.resolve6(domain) },
      { type: 'MX',    fn: () => dns.resolveMx(domain) },
      { type: 'NS',    fn: () => dns.resolveNs(domain) },
      { type: 'TXT',   fn: () => dns.resolveTxt(domain) },
    ];

    for (const rt of recordTypes) {
      try {
        const records = await rt.fn();
        const value   = Array.isArray(records)
          ? records.map(r => typeof r === 'object' ? JSON.stringify(r) : r).join(', ')
          : String(records);

        findings.push(this.finding({
          title:     `DNS ${rt.type} — ${domain}`,
          value,
          summary:   `${rt.type} record(s) for ${domain}: ${value}`,
          sourceUrl: `https://dnschecker.org/#${rt.type}/${domain}`,
        }));

        // If A record resolved, probe Shodan InternetDB (no key)
        if (rt.type === 'A') {
          const ipList = Array.isArray(records) ? records : [records];
          for (const ip of ipList) {
            const shodanFindings = await this._shodanInternetDB(ip, domain);
            findings.push(...shodanFindings);
          }
        }
      } catch (err) {
        findings.push(this.finding({
          title:     `DNS ${rt.type} — ${domain}`,
          value:     'NOT RESOLVED',
          summary:   `No ${rt.type} record found for ${domain}. Reason: ${err.code || err.message}`,
          sourceUrl: `https://dnschecker.org/#${rt.type}/${domain}`,
          riskSignal: rt.type === 'A' ? 'infra_opacity' : null,
        }));
      }
    }

    return findings;
  }

  // ─── WHOIS ────────────────────────────────────────────────────────────────
  async _whoisLookup(domain) {
    const findings = [];
    const url      = `https://rdap.org/domain/${domain}`;

    try {
      const data = await this.fetch(url);
      if (!data) return findings;

      const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
      const registrar  = data.entities?.find(e => e.roles?.includes('registrar'));
      const expiry     = data.events?.find(e => e.eventAction === 'expiration')?.eventDate;
      const created    = data.events?.find(e => e.eventAction === 'registration')?.eventDate;

      findings.push(this.finding({
        title:     `WHOIS / RDAP — ${domain}`,
        value:     domain,
        summary: [
          registrant ? `Registrant: ${JSON.stringify(registrant.vcardArray || registrant.handle)}` : 'Registrant: REDACTED',
          registrar  ? `Registrar: ${registrar.handle || 'Unknown'}`                              : '',
          created    ? `Registered: ${created}`                                                   : '',
          expiry     ? `Expires: ${expiry}`                                                       : '',
        ].filter(Boolean).join(' | '),
        sourceUrl: url,
        extra: { rawRdap: { registrant, registrar, expiry, created } },
      }));
    } catch (err) {
      findings.push(this.finding({
        title:     `WHOIS — ${domain}`,
        value:     'NOT FOUND',
        summary:   `RDAP lookup failed for ${domain}: ${err.message}`,
        sourceUrl: url,
        riskSignal: 'infra_opacity',
      }));
    }

    return findings;
  }

  // ─── Certificate Transparency (crt.sh) ───────────────────────────────────
  async _crtshLookup(domain) {
    const findings = [];
    const url      = `https://crt.sh/?q=%25.${domain}&output=json`;

    try {
      const data = await this.fetch(url);
      if (!Array.isArray(data)) return findings;

      const subdomains = [...new Set(
        data.flatMap(entry => (entry.name_value || '').split('\n'))
            .filter(s => s && s.includes(domain) && !s.startsWith('*'))
      )].slice(0, 20);

      if (subdomains.length > 0) {
        findings.push(this.finding({
          title:     `Certificate Transparency — ${domain}`,
          value:     subdomains.join(', '),
          summary:   `${subdomains.length} unique subdomain(s) found in CT logs for ${domain}`,
          sourceUrl: `https://crt.sh/?q=%25.${domain}`,
          extra:     { subdomains },
        }));
      } else {
        findings.push(this.finding({
          title:     `Certificate Transparency — ${domain}`,
          value:     'No subdomains found',
          summary:   `No CT log entries found for ${domain}`,
          sourceUrl: `https://crt.sh/?q=%25.${domain}`,
        }));
      }
    } catch (err) {
      // Non-fatal
    }

    return findings;
  }

  // ─── HIBP domain breach check ─────────────────────────────────────────────
  async _hibpCheck(domain) {
    const findings = [];
    // HIBP v3 domain search requires API key — document the query, note key requirement
    const url = `https://haveibeenpwned.com/api/v3/breacheddomain/${domain}`;

    if (!this.hibpApiKey) {
      findings.push(this.finding({
        title:     `HIBP Breach Check — ${domain}`,
        value:     'API_KEY_REQUIRED',
        summary:   `Have I Been Pwned v3 domain breach check requires a paid API key. Set HIBP_API_KEY env var to enable. Manual check: https://haveibeenpwned.com/DomainSearch`,
        sourceUrl: `https://haveibeenpwned.com/DomainSearch`,
        extra:     { requiresApiKey: true, manualUrl: `https://haveibeenpwned.com/DomainSearch` },
      }));
      return findings;
    }

    try {
      const data = await this.fetch(url, {
        headers: { 'hibp-api-key': this.hibpApiKey },
      });

      if (data && Object.keys(data).length > 0) {
        findings.push(this.finding({
          title:      `HIBP Breach — ${domain}`,
          value:      `${Object.keys(data).length} email(s) exposed`,
          summary:    `Domain ${domain} has ${Object.keys(data).length} email address(es) in known breach databases.`,
          sourceUrl:  url,
          riskSignal: 'breach_exposure',
        }));
      } else {
        findings.push(this.finding({
          title:     `HIBP Breach — ${domain}`,
          value:     'No breaches found',
          summary:   `Domain ${domain} not found in HIBP breach database.`,
          sourceUrl: url,
        }));
      }
    } catch (err) {
      // 404 = clean
      if (err.response?.status === 404) {
        findings.push(this.finding({
          title:     `HIBP Breach — ${domain}`,
          value:     'Clean',
          summary:   `Domain ${domain} not found in HIBP. No breach detected.`,
          sourceUrl: url,
        }));
      }
    }

    return findings;
  }

  // ─── Shodan InternetDB (no key required) ─────────────────────────────────
  async _shodanInternetDB(ip, domain) {
    const findings = [];
    const url      = `https://internetdb.shodan.io/${ip}`;

    try {
      const data = await this.fetch(url);
      if (!data || data.detail === 'No information available') return findings;

      const openPorts = data.ports || [];
      const vulns     = data.vulns || [];
      const cpes      = data.cpes  || [];
      const tags      = data.tags  || [];

      findings.push(this.finding({
        title:      `Shodan InternetDB — ${ip} (${domain})`,
        value:      `Open ports: ${openPorts.join(', ') || 'none'}`,
        summary:    [
          `IP: ${ip}`,
          openPorts.length ? `Open ports: ${openPorts.join(', ')}` : '',
          vulns.length     ? `CVEs: ${vulns.join(', ')}`           : '',
          cpes.length      ? `CPEs: ${cpes.slice(0,3).join(', ')}` : '',
          tags.length      ? `Tags: ${tags.join(', ')}`            : '',
        ].filter(Boolean).join(' | '),
        sourceUrl:  url,
        riskSignal: openPorts.length ? 'open_port' : null,
        extra:      { ip, openPorts, vulns, cpes, tags },
      }));
    } catch { /* 404 = clean */ }

    return findings;
  }
}

module.exports = { InfrastructureAdapter };
