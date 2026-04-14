/**
 * Entity Resolver
 * Groups findings, links assets to parent entity, filters false positives.
 * Pattern: confidence scoring per finding, threshold-based filtering.
 */

'use strict';

class EntityResolver {
  constructor(options = {}) {
    this.threshold = options.threshold || 0.4; // min confidence to keep
  }

  /**
   * @param {Array}  findings  - Raw findings from all adapters
   * @param {string} target    - The primary entity name
   * @param {string} type      - 'company' | 'individual'
   * @returns {{ confirmed: Array, falsePositives: Array }}
   */
  resolve(findings, target, type) {
    const confirmed     = [];
    const falsePositives = [];

    for (const finding of findings) {
      const score = this._scoreRelevance(finding, target, type);
      finding.confidence = score;

      if (score >= this.threshold) {
        confirmed.push(finding);
      } else {
        falsePositives.push({
          ...finding,
          falsePositiveReason: this._explainLowScore(finding, target),
        });
      }
    }

    // Group confirmed findings by category for report structure
    const grouped = this._groupByCategory(confirmed);

    return { confirmed, falsePositives, grouped };
  }

  /**
   * Relevance scoring — combines keyword match, domain match, type alignment.
   * Returns 0.0 – 1.0.
   */
  _scoreRelevance(finding, target, type) {
    const targetTokens = target.toLowerCase().split(/\s+/);
    const text = [
      finding.title   || '',
      finding.summary || '',
      finding.value   || '',
      finding.url     || '',
    ].join(' ').toLowerCase();

    let score = 0;

    // Keyword match — each target token found in finding text
    const hits = targetTokens.filter(t => t.length > 2 && text.includes(t));
    score += (hits.length / targetTokens.length) * 0.5;

    // Exact entity name match (stronger signal)
    if (text.includes(target.toLowerCase())) score += 0.3;

    // Category alignment with expected type
    if (type === 'company' && ['infrastructure', 'regulatory', 'social'].includes(finding.category)) {
      score += 0.1;
    }
    if (type === 'individual' && finding.category === 'social') {
      score += 0.1;
    }

    // Penalise if finding has an explicit mismatch flag set by adapter
    if (finding.mismatch) score -= 0.4;

    // Penalise vague/empty findings
    if (!finding.value && !finding.summary) score -= 0.2;

    return Math.max(0, Math.min(1, score));
  }

  _explainLowScore(finding, target) {
    const text = [finding.title, finding.summary, finding.value].join(' ').toLowerCase();
    if (!text.includes(target.toLowerCase().split(' ')[0])) {
      return `No primary name token match for "${target}"`;
    }
    if (finding.mismatch) return 'Adapter flagged as probable mismatch';
    return 'Confidence below threshold';
  }

  _groupByCategory(findings) {
    const groups = {};
    for (const f of findings) {
      const cat = f.category || 'uncategorised';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(f);
    }
    return groups;
  }
}

module.exports = { EntityResolver };
