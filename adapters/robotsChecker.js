/**
 * RobotsChecker
 * Fetches and caches robots.txt for each domain, checks path permission.
 * Ensures OPSEC compliance — adapters that use fetch() are robots-aware.
 */

'use strict';

const axios = require('axios');
const { URL } = require('url');

class RobotsChecker {
  constructor() {
    this._cache = new Map(); // domain → rules[]
    this._ua    = 'OSINTBot';
  }

  async isAllowed(targetUrl) {
    try {
      const parsed = new URL(targetUrl);
      const origin = `${parsed.protocol}//${parsed.host}`;
      const path   = parsed.pathname;

      if (!this._cache.has(origin)) {
        await this._load(origin);
      }

      const rules = this._cache.get(origin) || [];
      return this._check(rules, path);
    } catch {
      return true; // if we can't check, allow (fail-open for research)
    }
  }

  async _load(origin) {
    try {
      const resp = await axios.get(`${origin}/robots.txt`, { timeout: 5000 });
      this._cache.set(origin, this._parse(resp.data));
    } catch {
      this._cache.set(origin, []); // no robots.txt = allow all
    }
  }

  _parse(text) {
    const rules = [];
    let applicable = false;

    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      if (line.toLowerCase().startsWith('user-agent:')) {
        const ua = line.split(':')[1].trim();
        applicable = (ua === '*' || ua.toLowerCase().includes(this._ua.toLowerCase()));
      } else if (applicable && line.toLowerCase().startsWith('disallow:')) {
        const p = line.split(':')[1].trim();
        if (p) rules.push({ type: 'disallow', path: p });
      } else if (applicable && line.toLowerCase().startsWith('allow:')) {
        const p = line.split(':')[1].trim();
        if (p) rules.push({ type: 'allow', path: p });
      }
    }
    return rules;
  }

  _check(rules, path) {
    // Most-specific rule wins; allow overrides disallow at same specificity
    let best = null;
    for (const rule of rules) {
      if (path.startsWith(rule.path)) {
        if (!best || rule.path.length > best.path.length) {
          best = rule;
        }
      }
    }
    return !best || best.type === 'allow';
  }
}

module.exports = { RobotsChecker };
