/**
 * OSINT Engine — Core Orchestrator
 * Coordinates adapters, resolves entities, scores risk, drives reporting.
 */

'use strict';

const { EntityResolver } = require('./entityResolver');
const { RiskScorer }     = require('./riskScorer');
const { Logger }         = require('./logger');

class OSINTEngine {
  constructor(adapters = [], reporterClass = null) {
    this.adapters      = adapters;     // pluggable adapter list
    this.reporterClass = reporterClass;
    this.logger        = new Logger();
    this.resolver      = new EntityResolver();
    this.scorer        = new RiskScorer();
  }

  /**
   * Main entry point.
   * @param {string} target  - Company Name or Individual Name
   * @param {string} type    - 'company' | 'individual'
   * @returns {object}       - Full investigation result
   */
  async investigate(target, type = 'company') {
    this.logger.info(`[ENGINE] Starting investigation: "${target}" (${type})`);

    const rawFindings = [];

    // Phase I — Data Acquisition (parallel across adapters)
    const adapterResults = await Promise.allSettled(
      this.adapters.map(adapter => this._runAdapter(adapter, target, type))
    );

    for (const result of adapterResults) {
      if (result.status === 'fulfilled' && result.value?.length) {
        rawFindings.push(...result.value);
      } else if (result.status === 'rejected') {
        this.logger.warn(`[ENGINE] Adapter failed: ${result.reason?.message}`);
      }
    }

    this.logger.info(`[ENGINE] Raw findings collected: ${rawFindings.length}`);

    // Phase II — Entity Resolution & Disambiguation
    const resolved = this.resolver.resolve(rawFindings, target, type);
    this.logger.info(`[ENGINE] After resolution: ${resolved.confirmed.length} confirmed, ${resolved.falsePositives.length} false positives filtered`);

    // Risk Scoring
    const riskProfile = this.scorer.score(resolved.confirmed);

    // Compile final result
    const investigation = {
      meta: {
        target,
        type,
        timestamp: new Date().toISOString(),
        totalRaw: rawFindings.length,
        confirmedFindings: resolved.confirmed.length,
        falsePositivesFiltered: resolved.falsePositives.length,
      },
      findings: resolved.confirmed,
      falsePositives: resolved.falsePositives,
      riskProfile,
    };

    return investigation;
  }

  async _runAdapter(adapter, target, type) {
    const name = adapter.name || adapter.constructor?.name || 'Unknown';
    this.logger.info(`[ENGINE] Running adapter: ${name}`);
    try {
      const results = await adapter.collect(target, type);
      this.logger.info(`[ENGINE] ${name} returned ${results?.length ?? 0} findings`);
      return results || [];
    } catch (err) {
      this.logger.warn(`[ENGINE] Adapter "${name}" threw: ${err.message}`);
      return [];
    }
  }
}

module.exports = { OSINTEngine };
