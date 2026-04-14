#!/usr/bin/env node
/**
 * OSINT Tool — CLI Entry Point
 *
 * Usage:
 *   node index.js --target "Travis Haasch" --type individual
 *   node index.js --target "AiGeeks"       --type company
 *   node index.js --target "AiGeeks"       --type company --format pdf
 *   node index.js --target "AiGeeks"       --type company --proxy http://user:pass@host:8080
 *
 * Environment variables:
 *   HIBP_API_KEY        — Have I Been Pwned v3 API key
 *   NEWS_API_KEY        — NewsAPI.org API key
 *   OPENCORP_API_KEY    — OpenCorporates API token
 *   PROXY_URL           — HTTP proxy (overrides --proxy)
 */

'use strict';

const { OSINTEngine }          = require('./core/engine');
const { SocialAdapter }        = require('./adapters/socialAdapter');
const { InfrastructureAdapter }= require('./adapters/infrastructureAdapter');
const { RegulatoryAdapter }    = require('./adapters/regulatoryAdapter');
const { PDFReporter }          = require('./output/pdfReporter');
const { MarkdownReporter }     = require('./output/markdownReporter');
const path                     = require('path');

// ─── CLI arg parsing (no deps — built-in) ───────────────────────────────────
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      args[argv[i].slice(2)] = argv[i + 1] || true;
      i++;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);

  const target   = args.target   || process.env.OSINT_TARGET;
  const type     = args.type     || 'company';
  const format   = args.format   || 'both';
  const proxyUrl = args.proxy    || process.env.PROXY_URL || null;
  const outDir   = args.out      || './reports';

  if (!target) {
    console.error('ERROR: --target is required. Example: node index.js --target "AiGeeks" --type company');
    process.exit(1);
  }

  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║  OSINT Tool v1.0 — Dharam Kathiriya      ║`);
  console.log(`╚══════════════════════════════════════════╝`);
  console.log(`  Target : ${target}`);
  console.log(`  Type   : ${type}`);
  console.log(`  Format : ${format}`);
  console.log(`  Proxy  : ${proxyUrl || 'none'}`);
  console.log(`  Out    : ${outDir}\n`);

  // ─── Adapter configuration ────────────────────────────────────────────────
  const adapterOpts = {
    proxyUrl,
    respectRobots: true,
    hibpApiKey:    process.env.HIBP_API_KEY        || null,
    newsApiKey:    process.env.NEWS_API_KEY         || null,
    openCorpApiKey:process.env.OPENCORP_API_KEY     || null,
  };

  const adapters = [
    new SocialAdapter(adapterOpts),
    new InfrastructureAdapter(adapterOpts),
    new RegulatoryAdapter(adapterOpts),
  ];

  // ─── Run ──────────────────────────────────────────────────────────────────
  const engine = new OSINTEngine(adapters);
  let investigation;
  try {
    investigation = await engine.investigate(target, type);
  } catch (err) {
    console.error('FATAL: Investigation failed:', err.message);
    process.exit(1);
  }

  // ─── Report ───────────────────────────────────────────────────────────────
  const slug     = target.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  const datestamp = new Date().toISOString().slice(0, 10);
  const filename  = `OSINT_${slug}_${datestamp}`;

  const generatedFiles = [];

  if (format === 'pdf' || format === 'both') {
    try {
      const pdfReporter = new PDFReporter({ outputDir: outDir });
      const pdfPath     = await pdfReporter.generate(investigation, filename);
      console.log(`\n✅ PDF report: ${path.resolve(pdfPath)}`);
      generatedFiles.push(pdfPath);
    } catch (err) {
      console.warn(`⚠️  PDF generation failed: ${err.message}`);
    }
  }

  if (format === 'md' || format === 'both') {
    const mdReporter = new MarkdownReporter({ outputDir: outDir });
    const mdPath     = mdReporter.generate(investigation, filename);
    console.log(`✅ Markdown report: ${path.resolve(mdPath)}`);
    generatedFiles.push(mdPath);
  }

  // ─── Summary to stdout ────────────────────────────────────────────────────
  const risk = investigation.riskProfile;
  console.log(`\n┌─ INVESTIGATION SUMMARY ───────────────────────`);
  console.log(`│  Target            : ${target}`);
  console.log(`│  Total collected   : ${investigation.meta.totalRaw}`);
  console.log(`│  Confirmed         : ${investigation.meta.confirmedFindings}`);
  console.log(`│  False positives   : ${investigation.meta.falsePositivesFiltered}`);
  console.log(`│  Risk level        : ${risk.level} (${risk.score}/100)`);
  console.log(`│  Risk signals      : ${risk.signals.length}`);
  console.log(`└───────────────────────────────────────────────\n`);

  return investigation;
}

main().catch(err => {
  console.error('Unhandled error:', err);
  process.exit(1);
});
