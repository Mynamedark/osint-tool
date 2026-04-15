/**
 * PDFReporter — Phase III Reporting Engine
 *
 * Generates a professional PDF containing:
 *   - Executive Summary (narrative)
 *   - Categorised finding tables
 *   - Risk assessment
 *   - Audit trail with source URLs + timestamps
 */

'use strict';

const PDFDocument = require('pdfkit');
const fs          = require('fs');
const path        = require('path');

// ─── Palette ─────────────────────────────────────────────────────────────────
const C = {
  bg:      '#0D1117',
  panel:   '#161B22',
  border:  '#30363D',
  accent:  '#238636',
  blue:    '#1F6FEB',
  white:   '#FFFFFF',
  muted:   '#8B949E',
  red:     '#B71C1C',
  orange:  '#E65100',
  green:   '#1B5E20',
  yellow:  '#F57F17',
};

class PDFReporter {
  constructor(options = {}) {
    this.outputDir = options.outputDir || './reports';
    if (!fs.existsSync(this.outputDir)) fs.mkdirSync(this.outputDir, { recursive: true });
  }

  /**
   * @param {object} investigation  — result from OSINTEngine.investigate()
   * @param {string} filename       — output filename (no extension)
   * @returns {string}              — absolute path to generated PDF
   */
  generate(investigation, filename = 'osint_report') {
    const outPath = path.join(this.outputDir, `${filename}.pdf`);
    const doc     = new PDFDocument({ size: 'A4', margin: 50, autoFirstPage: true });
    const stream  = fs.createWriteStream(outPath);

    doc.pipe(stream);

    this._drawBackground(doc);
    this._coverPage(doc, investigation);
    this._execSummary(doc, investigation);
    this._findingsTables(doc, investigation);
    this._riskSection(doc, investigation);
    this._auditTrail(doc, investigation);

    doc.end();

    return new Promise((resolve, reject) => {
      stream.on('finish', () => resolve(outPath));
      stream.on('error',  reject);
    });
  }

  // ─── Background fill ──────────────────────────────────────────────────────
  _drawBackground(doc) {
    doc.on('pageAdded', () => {
      doc.rect(0, 0, doc.page.width, doc.page.height).fill(C.bg);
    });
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(C.bg);
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────
  _heading1(doc, text) {
    doc.moveDown(0.5);
    doc.rect(50, doc.y, doc.page.width - 100, 28).fill(C.panel);
    doc.fillColor(C.accent).font('Courier-Bold').fontSize(13)
       .text(`// ${text}`, 60, doc.y - 22);
    doc.fillColor(C.white).font('Helvetica').fontSize(10);
    doc.moveDown(0.8);
  }

  _heading2(doc, text) {
    doc.moveDown(0.3);
    doc.fillColor(C.blue).font('Courier-Bold').fontSize(11).text(text);
    doc.fillColor(C.white).font('Helvetica').fontSize(9);
    doc.moveDown(0.4);
  }

  _label(doc, label, value, valueColor = C.blue) {
    doc.font('Courier-Bold').fontSize(9).fillColor(C.muted).text(`${label}: `, { continued: true });
    doc.font('Courier').fontSize(9).fillColor(valueColor).text(value);
    doc.fillColor(C.white).font('Helvetica').fontSize(9);
  }

  _divider(doc) {
    doc.moveDown(0.3);
    doc.strokeColor(C.border).lineWidth(0.5)
       .moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).stroke();
    doc.moveDown(0.4);
  }

  _riskColor(level) {
    return { CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.green }[level] || C.muted;
  }

  _body(doc, text, color = C.muted) {
    doc.fillColor(color).font('Helvetica').fontSize(9).text(text, { align: 'left' });
    doc.moveDown(0.3);
  }

  // ─── Cover page ───────────────────────────────────────────────────────────
  _coverPage(doc, inv) {
    const { target, type, timestamp } = inv.meta;
    const reportId = `OSINT-${timestamp.slice(0,10).replace(/-/g,'')}-001`;

    doc.moveDown(2);
    doc.fillColor(C.accent).font('Courier-Bold').fontSize(11).text('OPEN-SOURCE INTELLIGENCE', { align: 'center' });
    doc.fillColor(C.white).font('Courier-Bold').fontSize(22).text('DIGITAL FOOTPRINT INVESTIGATION', { align: 'center' });
    doc.moveDown(0.5);

    doc.strokeColor(C.accent).lineWidth(2)
       .moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).stroke();
    doc.moveDown(0.5);

    doc.fillColor(C.blue).font('Courier-Bold').fontSize(12)
       .text(`TARGET: ${target.toUpperCase()}  |  TYPE: ${type.toUpperCase()}`, { align: 'center' });
    doc.moveDown(1.5);

    // Metadata box
    const rows = [
      ['Report ID',          reportId],
      ['Classification',     'TLP:WHITE — Unrestricted'],
      ['Collection Date',    timestamp.slice(0,10)],
      ['Collection Time',    timestamp.slice(11,19) + ' UTC'],
      ['Total Findings',     String(inv.meta.totalRaw)],
      ['Confirmed Findings', String(inv.meta.confirmedFindings)],
      ['False Positives',    String(inv.meta.falsePositivesFiltered)],
      ['Overall Risk',       inv.riskProfile.level + ` (${inv.riskProfile.score}/100)`],
    ];

    const tX = 150, tW = doc.page.width - 300;
    let tY = doc.y;
    for (const [k, v] of rows) {
      doc.rect(tX, tY, tW/2, 18).fill(C.panel);
      doc.rect(tX + tW/2, tY, tW/2, 18).fill(C.bg);
      doc.fillColor(C.muted).font('Courier-Bold').fontSize(8).text(k, tX + 6, tY + 5, { width: tW/2 - 6 });
      const vc = k === 'Overall Risk' ? this._riskColor(inv.riskProfile.level) : C.blue;
      doc.fillColor(vc).font('Courier').fontSize(8).text(v, tX + tW/2 + 6, tY + 5, { width: tW/2 - 6 });
      tY += 18;
    }

    doc.moveDown(10);
    doc.fillColor(C.muted).font('Helvetica').fontSize(8)
       .text('Methodology: Passive OSINT — No Direct Contact | OPSEC Compliant', { align: 'center' });

    doc.addPage();
    this._drawBackground(doc);
  }

  // ─── Executive Summary ────────────────────────────────────────────────────
  _execSummary(doc, inv) {
    this._heading1(doc, 'EXECUTIVE SUMMARY');

    const { target, type, confirmedFindings, falsePositivesFiltered } = inv.meta;
    const risk = inv.riskProfile;

    const summary = [
      `This report documents an open-source intelligence investigation into "${target}" (${type}).`,
      `Collection was conducted using three source categories: Social & Public Footprint, Technical Infrastructure, and Contextual & Regulatory.`,
      ``,
      `A total of ${inv.meta.totalRaw} raw findings were collected across all adapters.`,
      `Entity resolution filtered ${falsePositivesFiltered} false positives, leaving ${confirmedFindings} confirmed findings attributed to the target.`,
      ``,
      `Overall Risk Assessment: ${risk.level} (score ${risk.score}/100).`,
      risk.signals.length > 0
        ? `Active risk signals: ${risk.signals.map(s => s.label).join(', ')}.`
        : 'No material adverse risk signals were identified during this collection cycle.',
    ].join('\n');

    this._body(doc, summary, C.white);
    this._divider(doc);
  }

  // ─── Findings tables by category ─────────────────────────────────────────
  _findingsTables(doc, inv) {
    const grouped = {};
    for (const f of inv.findings) {
      const cat = f.category || 'uncategorised';
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(f);
    }

    const categoryLabels = {
      social:          'SOCIAL & PUBLIC FOOTPRINT',
      infrastructure:  'TECHNICAL INFRASTRUCTURE',
      regulatory:      'CONTEXTUAL & REGULATORY',
      uncategorised:   'UNCATEGORISED',
    };

    for (const [cat, findings] of Object.entries(grouped)) {
      if (!findings.length) continue;
      this._heading1(doc, categoryLabels[cat] || cat.toUpperCase());

      for (const f of findings) {
        // Check if we need a new page
        if (doc.y > doc.page.height - 140) {
          doc.addPage();
          this._drawBackground(doc);
        }

        doc.rect(50, doc.y, doc.page.width - 100, 14).fill(C.panel);
        doc.fillColor(C.accent).font('Courier-Bold').fontSize(8.5)
           .text(f.title || 'Finding', 56, doc.y - 12, { width: doc.page.width - 112 });
        doc.moveDown(0.3);

        const conf   = f.confidence != null ? `${Math.round(f.confidence * 100)}%` : 'N/A';
        const risk   = f.riskSignal || '—';
        doc.fillColor(C.muted).font('Courier').fontSize(7.5)
           .text(`Confidence: ${conf}  |  Risk Signal: ${risk}  |  Source: ${f.source}  |  ${f.timestamp}`, 56);

        doc.fillColor(C.blue).font('Courier').fontSize(7.5).text(`Value: ${f.value || '—'}`, 56);

        if (f.summary) {
          doc.fillColor(C.muted).font('Helvetica').fontSize(8).text(f.summary, 56, doc.y, { width: doc.page.width - 112 });
        }

        if (f.sourceUrl) {
          doc.fillColor(C.blue).font('Helvetica-Oblique').fontSize(7).text(f.sourceUrl, 56);
        }

        doc.moveDown(0.6);
      }

      doc.moveDown(0.3);
    }
  }

  // ─── Risk section ─────────────────────────────────────────────────────────
  _riskSection(doc, inv) {
    if (doc.y > doc.page.height - 200) { doc.addPage(); this._drawBackground(doc); }

    this._heading1(doc, 'RISK ASSESSMENT');

    const { score, level, signals } = inv.riskProfile;
    const col = this._riskColor(level);

    doc.fillColor(col).font('Courier-Bold').fontSize(18)
       .text(`${level}  —  ${score}/100`, { align: 'center' });
    doc.moveDown(0.5);

    if (signals.length === 0) {
      this._body(doc, 'No material risk signals identified. All checked indicators returned clean results.', C.green);
    } else {
      for (const s of signals) {
        if (doc.y > doc.page.height - 80) { doc.addPage(); this._drawBackground(doc); }
        const sCol = this._riskColor(s.severity);
        doc.fillColor(sCol).font('Courier-Bold').fontSize(9)
           .text(`[ ${s.severity} ]  ${s.label}  (weight: ${s.rawWeight}, contribution: ${s.contribution})`, 56);
        doc.fillColor(C.muted).font('Helvetica').fontSize(8)
           .text(s.detail || s.signal, 56, doc.y, { width: doc.page.width - 112 });
        doc.fillColor(C.muted).font('Courier').fontSize(7)
           .text(`Source: ${s.source}`, 56);
        doc.moveDown(0.5);
      }
    }

    this._divider(doc);
  }

  // ─── Audit Trail ──────────────────────────────────────────────────────────
  _auditTrail(doc, inv) {
    if (doc.y > doc.page.height - 200) { doc.addPage(); this._drawBackground(doc); }

    this._heading1(doc, 'AUDIT TRAIL');
    this._body(doc, 'Every data point collected during this investigation is documented below with source URL and retrieval timestamp.', C.muted);

    const allFindings = [...inv.findings, ...inv.falsePositives];

    for (const f of allFindings) {
      if (doc.y > doc.page.height - 80) { doc.addPage(); this._drawBackground(doc); }

      const isFP = f.falsePositiveReason != null;
      const mark = isFP ? '[FP]' : '[OK]';
      const markColor = isFP ? C.muted : C.accent;

      doc.fillColor(markColor).font('Courier-Bold').fontSize(8).text(mark, 50, doc.y, { continued: true, width: 30 });
      doc.fillColor(C.white).font('Courier').fontSize(8)
         .text(`  ${f.timestamp}  |  ${f.source}  |  ${f.title}`, { width: doc.page.width - 110 });
      doc.fillColor(C.blue).font('Courier').fontSize(7)
         .text(f.sourceUrl || '—', 56, doc.y, { width: doc.page.width - 112 });

      if (isFP) {
        doc.fillColor(C.muted).font('Helvetica-Oblique').fontSize(7)
           .text(`Filtered: ${f.falsePositiveReason}`, 56);
      }

      doc.moveDown(0.4);
    }
  }
}

module.exports = { PDFReporter };
