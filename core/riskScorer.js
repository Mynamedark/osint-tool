/**
 * Risk Scorer
 * Weighted algorithm that assigns a risk level and numeric score to findings.
 *
 * Weights (0–100 per signal):
 *   breachExposure    = 90  (CRITICAL)
 *   darkWebMention    = 85  (CRITICAL)
 *   sanctionsHit      = 80  (HIGH)
 *   derogatorPress    = 70  (HIGH)
 *   openPort          = 45  (MEDIUM)
 *   expiredCert       = 35  (MEDIUM)
 *   infraOpacity      = 25  (MEDIUM)
 *   noGitHub          = 10  (LOW)
 */

'use strict';

const WEIGHTS = {
  breach_exposure:    { weight: 90,  severity: 'CRITICAL', label: 'Data Breach Exposure'         },
  dark_web:           { weight: 85,  severity: 'CRITICAL', label: 'Dark Web Mention'              },
  sanctions:          { weight: 80,  severity: 'HIGH',     label: 'Sanctions / Regulatory Hit'   },
  derogatory_press:   { weight: 70,  severity: 'HIGH',     label: 'Adverse Press Coverage'       },
  open_port:          { weight: 45,  severity: 'MEDIUM',   label: 'Exposed Network Service'      },
  expired_cert:       { weight: 35,  severity: 'MEDIUM',   label: 'Expired TLS Certificate'      },
  infra_opacity:      { weight: 25,  severity: 'MEDIUM',   label: 'Infrastructure Not Resolvable'},
  no_code_repo:       { weight: 10,  severity: 'LOW',      label: 'No Public Code Repository'    },
  generic:            { weight: 5,   severity: 'LOW',      label: 'Generic Signal'               },
};

class RiskScorer {
  score(findings) {
    const signals = [];
    let totalScore = 0;

    for (const f of findings) {
      if (!f.riskSignal) continue;
      const def = WEIGHTS[f.riskSignal] || WEIGHTS.generic;
      const contribution = def.weight * (f.confidence || 0.5);
      totalScore += contribution;
      signals.push({
        signal:      f.riskSignal,
        label:       def.label,
        severity:    def.severity,
        rawWeight:   def.weight,
        confidence:  f.confidence,
        contribution: Math.round(contribution),
        source:      f.source,
        detail:      f.value || f.summary,
      });
    }

    // Normalise to 0–100
    const maxPossible = Object.values(WEIGHTS).reduce((s, v) => s + v.weight, 0);
    const normalised  = Math.min(100, Math.round((totalScore / maxPossible) * 100));

    const level = normalised >= 70 ? 'CRITICAL'
                : normalised >= 45 ? 'HIGH'
                : normalised >= 20 ? 'MEDIUM'
                :                    'LOW';

    return { score: normalised, level, signals };
  }
}

module.exports = { RiskScorer };
