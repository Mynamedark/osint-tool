'use strict';

/**
 * server.js — Express wrapper for Render/Railway deployment
 *
 * Endpoints:
 *   GET  /                    → health check
 *   POST /investigate         → run investigation, returns JSON + report links
 *   GET  /reports/:filename   → download generated report
 *
 * Body (JSON):
 *   { "target": "AiGeeks", "type": "company", "format": "both" }
 */

const express  = require('express');
const path     = require('path');
const fs       = require('fs');

const { OSINTEngine }           = require('./core/engine');
const { SocialAdapter }         = require('./adapters/socialAdapter');
const { InfrastructureAdapter } = require('./adapters/infrastructureAdapter');
const { RegulatoryAdapter }     = require('./adapters/regulatoryAdapter');
const { PDFReporter }           = require('./output/pdfReporter');
const { MarkdownReporter }      = require('./output/markdownReporter');

const app     = express();
const PORT    = process.env.PORT || 3000;
const REPORTS = path.join(__dirname, 'reports');

if (!fs.existsSync(REPORTS)) fs.mkdirSync(REPORTS, { recursive: true });

app.use(express.json());

// ─── Health check ─────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status:  'online',
    service: 'OSINT Tool v1.0',
    author:  'Dharam Kathiriya (Dark)',
    usage: {
      endpoint: 'POST /investigate',
      body:     { target: 'string (required)', type: 'company | individual', format: 'pdf | md | both' },
      example:  { target: 'AiGeeks', type: 'company', format: 'both' },
    },
  });
});

// ─── Main investigation endpoint ──────────────────────────────────────────
app.post('/investigate', async (req, res) => {
  const { target, type = 'company', format = 'both' } = req.body || {};

  if (!target || typeof target !== 'string' || !target.trim()) {
    return res.status(400).json({ error: '`target` is required (string).' });
  }

  const proxyUrl = process.env.PROXY_URL || null;

  const adapterOpts = {
    proxyUrl,
    respectRobots:  true,
    hibpApiKey:     process.env.HIBP_API_KEY     || null,
    newsApiKey:     process.env.NEWS_API_KEY      || null,
    openCorpApiKey: process.env.OPENCORP_API_KEY  || null,
  };

  const engine = new OSINTEngine([
    new SocialAdapter(adapterOpts),
    new InfrastructureAdapter(adapterOpts),
    new RegulatoryAdapter(adapterOpts),
  ]);

  let investigation;
  try {
    investigation = await engine.investigate(target.trim(), type);
  } catch (err) {
    return res.status(500).json({ error: 'Investigation failed.', detail: err.message });
  }

  // Generate reports
  const slug      = target.trim().replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  const datestamp = new Date().toISOString().slice(0, 10);
  const filename  = `OSINT_${slug}_${datestamp}`;
  const baseUrl   = `${req.protocol}://${req.get('host')}`;
  const files     = [];

  if (format === 'pdf' || format === 'both') {
    try {
      const pdfPath = await new PDFReporter({ outputDir: REPORTS }).generate(investigation, filename);
      files.push({ type: 'pdf', url: `${baseUrl}/reports/${path.basename(pdfPath)}` });
    } catch (e) {
      files.push({ type: 'pdf', error: e.message });
    }
  }

  if (format === 'md' || format === 'both') {
    const mdPath = new MarkdownReporter({ outputDir: REPORTS }).generate(investigation, filename);
    files.push({ type: 'markdown', url: `${baseUrl}/reports/${path.basename(mdPath)}` });
  }

  res.json({
    status:   'complete',
    target:   investigation.meta.target,
    type:     investigation.meta.type,
    timestamp: investigation.meta.timestamp,
    summary: {
      totalRaw:            investigation.meta.totalRaw,
      confirmedFindings:   investigation.meta.confirmedFindings,
      falsePositives:      investigation.meta.falsePositivesFiltered,
      riskLevel:           investigation.riskProfile.level,
      riskScore:           investigation.riskProfile.score,
      riskSignals:         investigation.riskProfile.signals.length,
    },
    reports: files,
  });
});

// ─── Report download ──────────────────────────────────────────────────────
app.get('/reports/:filename', (req, res) => {
  const filePath = path.join(REPORTS, path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Report not found.' });
  }
  res.download(filePath);
});

// ─── Start ────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[OSINT Tool] Server running on port ${PORT}`);
  console.log(`[OSINT Tool] Health check: http://localhost:${PORT}/`);
  console.log(`[OSINT Tool] Investigate:  POST http://localhost:${PORT}/investigate`);
});
