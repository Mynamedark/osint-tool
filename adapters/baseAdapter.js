/**
 * BaseAdapter — Abstract base class for all OSINT adapters.
 *
 * Each adapter implements:
 *   collect(target, type) → Promise<Finding[]>
 *
 * Finding shape:
 * {
 *   category:    'social' | 'infrastructure' | 'regulatory'
 *   source:      string  (source name)
 *   sourceUrl:   string  (direct URL of retrieved data)
 *   title:       string
 *   value:       string  (the raw discovered value)
 *   summary:     string  (human-readable interpretation)
 *   timestamp:   string  (ISO 8601 UTC)
 *   riskSignal:  string  (key from WEIGHTS map, or null)
 *   mismatch:    bool    (true = adapter thinks this is wrong entity)
 *   confidence:  number  (0–1, set by EntityResolver; adapters may set initial)
 * }
 */

'use strict';

const { RobotsChecker } = require('./robotsChecker');

class BaseAdapter {
  constructor(options = {}) {
    this.name           = options.name || this.constructor.name;
    this.category       = options.category || 'uncategorised';
    this.proxyUrl       = options.proxyUrl  || null; // e.g. 'http://user:pass@host:port'
    this.respectRobots  = options.respectRobots !== false; // default true
    this.robotsChecker  = new RobotsChecker();
    this.timeout        = options.timeout || 10000;
  }

  /**
   * Override in subclass.
   */
  async collect(target, type) {
    throw new Error(`${this.name}.collect() not implemented`);
  }

  /**
   * Shared HTTP helper with optional proxy and robots.txt check.
   */
  async fetch(url, options = {}) {
    if (this.respectRobots) {
      const allowed = await this.robotsChecker.isAllowed(url);
      if (!allowed) {
        console.warn(`[${this.name}] robots.txt disallows: ${url}`);
        return null;
      }
    }

    const axios   = require('axios');
    const config  = {
      url,
      timeout: this.timeout,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; OSINTBot/1.0; +https://github.com/osint-tool)',
        ...options.headers,
      },
      ...options,
    };

    if (this.proxyUrl) {
      const { URL } = require('url');
      const p = new URL(this.proxyUrl);
      config.proxy = {
        protocol: p.protocol.replace(':', ''),
        host:     p.hostname,
        port:     parseInt(p.port),
        auth:     p.username ? { username: p.username, password: p.password } : undefined,
      };
    }

    const resp = await axios(config);
    return resp.data;
  }

  /**
   * Convenience factory for a Finding object.
   */
  finding({ title, value, summary, sourceUrl, riskSignal = null, mismatch = false, extra = {} }) {
    return {
      category:   this.category,
      source:     this.name,
      sourceUrl:  sourceUrl || '',
      title:      title     || '',
      value:      value     || '',
      summary:    summary   || '',
      timestamp:  new Date().toISOString(),
      riskSignal,
      mismatch,
      confidence: null,  // set by EntityResolver
      ...extra,
    };
  }
}

module.exports = { BaseAdapter };
