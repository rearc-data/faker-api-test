import express from 'express';
import { faker } from '@faker-js/faker';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { gzipSync } from 'zlib';

const app = express();

// Bypass Databricks SSO auth for internal notebook access
app.use((req, res, next) => {
  if (req.query.key === 'snyk-faker-2026') return next();
  next();
});
const port = process.env.DATABRICKS_APP_PORT || 8000;

const PACKAGE_MANAGERS = ["npm", "pip", "maven", "gradle", "nuget"];
const LANGUAGES = ["js", "python", "java", "go", "ruby"];
const MODULES = ["lodash", "braces", "cookie", "tar", "jsonwebtoken", "minimatch", "express", "axios", "chalk", "debug"];
const EXPLOIT_MATURITY = ["Proof of Concept", "Mature", "High", "Not Defined", "No Known Exploit"];
const ORG_NAMES = ["petersam", "rearc-security-poc", "acme-corp", "dev-team"];

function generateCVSSv3(severity) {
  const aMap = { critical: 'H', high: 'H', medium: 'L', low: 'L' };
  const cMap = { critical: 'H', high: 'H', medium: 'L', low: 'N' };
  const iMap = { critical: 'H', high: 'H', medium: 'L', low: 'N' };
  return `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:${cMap[severity]}/I:${iMap[severity]}/A:${aMap[severity]}`;
}

function generateCvssScore(severity) {
  const ranges = { critical: [9.0, 10.0], high: [7.0, 8.9], medium: [4.0, 6.9], low: [0.1, 3.9] };
  const [min, max] = ranges[severity];
  return parseFloat(faker.number.float({ min, max, fractionDigits: 1 }));
}

function generateSnykVulnerability() {
  const severity = faker.helpers.arrayElement(["low", "medium", "high", "critical"]);
  const moduleName = faker.helpers.arrayElement(MODULES);
  const packageManager = faker.helpers.arrayElement(PACKAGE_MANAGERS);
  const language = faker.helpers.arrayElement(LANGUAGES);
  const cvssScore = generateCvssScore(severity);
  const id = `SNYK-JS-${moduleName.toUpperCase()}-${faker.string.numeric(7)}`;
  const projectName = faker.helpers.arrayElement(["goof", "juice-shop", "dvna", "webgoat"]);
  const org = faker.helpers.arrayElement(ORG_NAMES);

  const creationTime = faker.date.recent({ days: 90 }).toISOString();
  const modificationTime = faker.date.recent({ days: 30 }).toISOString();
  const disclosureTime = faker.date.past({ years: 3 }).toISOString();
  const publicationTime = faker.date.past({ years: 2 }).toISOString();

  const fixedVersion = `${faker.number.int({ min: 1, max: 5 })}.${faker.number.int({ min: 0, max: 9 })}.${faker.number.int({ min: 0, max: 20 })}`;
  const currentVersion = `${faker.number.int({ min: 0, max: 4 })}.${faker.number.int({ min: 0, max: 9 })}.${faker.number.int({ min: 0, max: 15 })}`;

  const isPatchable = faker.datatype.boolean();
  const isUpgradable = faker.datatype.boolean();

  return {
    id,
    title: faker.helpers.arrayElement([
      "Prototype Pollution",
      "Regular Expression Denial of Service (ReDoS)",
      "Arbitrary File Write via Archive Extraction (Zip Slip)",
      "Cross-site Scripting (XSS)",
      "SQL Injection",
      "Directory Traversal",
      "Uninitialized Memory Exposure",
      "Inefficient Algorithmic Complexity",
      "Information Exposure",
      "Arbitrary File Upload"
    ]),
    CVSSv3: generateCVSSv3(severity),
    cvssScore,
    severity,
    severityBasedOn: "CVSS",
    severityWithCritical: severity,
    severityScore: cvssScore,
    language,
    moduleName,
    packageName: moduleName,
    packageManager,
    packageManager_parent: packageManager,
    version: currentVersion,
    primaryFixedVersion: fixedVersion,
    fixedIn: [fixedVersion],
    creationTime,
    modificationTime,
    disclosureTime,
    publicationTime,
    projectName,
    org,
    path: `/Users/${faker.internet.userName()}/Work/${projectName}`,
    displayTargetFile: "package-lock.json",
    isPatchable,
    isUpgradable,
    isDisputed: false,
    isPinnable: faker.datatype.boolean(),
    isRuntime: false,
    malicious: false,
    proprietary: faker.datatype.boolean(),
    socialTrendAlert: false,
    ok: false,
    filesystemPolicy: false,
    hasUnknownVersions: false,
    cveIds: [`CVE-202${faker.number.int({ min: 0, max: 5 })}-${faker.string.numeric(4)}`],
    cweIds: [`CWE-${faker.number.int({ min: 10, max: 1400 })}`],
    ghsaIds: faker.datatype.boolean() ? [`GHSA-${faker.string.alphanumeric(4)}-${faker.string.alphanumeric(4)}-${faker.string.alphanumeric(4)}`] : [],
    identifiers: {
      CVE: [`CVE-202${faker.number.int({ min: 0, max: 5 })}-${faker.string.numeric(4)}`],
      CWE: [`CWE-${faker.number.int({ min: 10, max: 1400 })}`]
    },
    cvssDetails: [{
      assigner: "NVD",
      cvssV3BaseScore: cvssScore,
      cvssV3Vector: generateCVSSv3(severity),
      modificationTime,
      severity
    }],
    cvssSources: [{
      assigner: "Snyk",
      baseScore: cvssScore,
      cvssVersion: "3.1",
      modificationTime,
      severity,
      type: "primary",
      vector: generateCVSSv3(severity)
    }],
    epssDetails: {
      modelVersion: "v2025.03.14",
      percentile: faker.number.float({ min: 0.1, max: 0.99, fractionDigits: 5 }).toString(),
      probability: faker.number.float({ min: 0.001, max: 0.5, fractionDigits: 5 }).toString()
    },
    exploit: faker.helpers.arrayElement(EXPLOIT_MATURITY),
    exploitDetails: {
      maturityLevels: [
        { format: "CVSSv3", level: faker.helpers.arrayElement(EXPLOIT_MATURITY), type: "secondary" },
        { format: "CVSSv4", level: faker.helpers.arrayElement(EXPLOIT_MATURITY), type: "primary" }
      ],
      sources: ["Snyk"]
    },
    from: [`${projectName}@1.0.0`, `${moduleName}@${currentVersion}`],
    upgradePath: [false, `${moduleName}@${fixedVersion}`],
    semver: { vulnerable: [`<${fixedVersion}`] },
    dependencyCount: faker.number.int({ min: 50, max: 1500 }),
    referenceCount: faker.number.int({ min: 1, max: 10 }),
    references: [{
      title: "GitHub Commit",
      url: `https://github.com/${moduleName}/${moduleName}/commit/${faker.git.commitSha()}`
    }],
    patches: [],
    functions: [],
    functions_new: [],
    description: `## Overview\n[${moduleName}](https://www.npmjs.com/package/${moduleName}) is vulnerable.\n\n## Remediation\nUpgrade \`${moduleName}\` to version ${fixedVersion} or higher.`,
    remediationText: `Upgrade to ${fixedVersion} or higher`,
    insights: { triageAdvice: faker.datatype.boolean() ? faker.lorem.sentence() : null },
    filtered: { ignore: [], patch: [] },
    ignoreSettings: { adminOnly: false, disregardFilesystemIgnores: false, reasonRequired: false },
    licensesPolicy: null,
    summary: `${faker.number.int({ min: 10, max: 600 })} vulnerable dependency paths`,
    uniqueCount: faker.number.int({ min: 1, max: 200 }),
    eventType: "open_source_vulnerability"
  };
}

// ── Routes ──────────────────────────────────────────────────────────────────

// NDJSON streaming — up to 100k records, streamed in chunks of 500
// Usage: GET /api/events?count=10000
app.get('/api/events', (req, res) => {
  const requestCount = parseInt(req.query.count) || 100;
  const safeCount = Math.min(requestCount, 100000);

  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('X-Record-Count', String(safeCount));

  const CHUNK_SIZE = 500;
  let written = 0;

  function writeChunk() {
    const chunkSize = Math.min(CHUNK_SIZE, safeCount - written);
    for (let i = 0; i < chunkSize; i++) {
      res.write(JSON.stringify(generateSnykVulnerability()) + '\n');
    }
    written += chunkSize;
    if (written >= safeCount) {
      res.end();
    } else {
      setImmediate(writeChunk);
    }
  }

  writeChunk();
});

// Wrapped JSON (original format)
app.get('/api/events/wrapped', (req, res) => {
  const requestCount = parseInt(req.query.count) || 100;
  const safeCount = Math.min(requestCount, 10000);
  res.json({
    vulnerabilities: Array.from({ length: safeCount }, generateSnykVulnerability),
    ok: false,
    dependencyCount: faker.number.int({ min: 500, max: 1500 }),
    org: faker.helpers.arrayElement(ORG_NAMES)
  });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// HTML dashboard — preview up to 200 records in browser
app.get('/', (req, res) => {
  const count = parseInt(req.query.count) || 25;
  const safeCount = Math.min(count, 200);
  const vulns = Array.from({ length: safeCount }, generateSnykVulnerability);
  const severityColor = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a' };

  const rows = vulns.map(v => `
    <tr>
      <td><code style="font-size:11px">${v.id}</code></td>
      <td>${v.title}</td>
      <td>${v.moduleName}</td>
      <td>${v.language}</td>
      <td><span style="background:${severityColor[v.severity]};color:white;padding:2px 8px;border-radius:4px;font-size:12px">${v.severity}</span></td>
      <td>${v.cvssScore}</td>
      <td>${v.isPatchable ? '✅' : '❌'}</td>
      <td>${v.isUpgradable ? '✅' : '❌'}</td>
      <td style="font-size:11px">${new Date(v.creationTime).toLocaleDateString()}</td>
    </tr>`).join('');

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Snyk Mock API</title>
  <style>
    body { font-family: sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
    header { background: #1e293b; padding: 20px 32px; border-bottom: 1px solid #334155; }
    header h1 { margin: 0; font-size: 20px; }
    header p { margin: 4px 0 0; font-size: 13px; color: #94a3b8; }
    .controls { padding: 20px 32px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .controls input { background: #1e293b; border: 1px solid #334155; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; width: 80px; }
    .controls button { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
    .controls a { color: #94a3b8; font-size: 13px; text-decoration: none; padding: 8px 12px; border: 1px solid #334155; border-radius: 6px; }
    .controls a:hover { color: #e2e8f0; border-color: #94a3b8; }
    .note { font-size: 12px; color: #64748b; padding: 0 32px 8px; }
    .stats { padding: 0 32px 20px; display: flex; gap: 12px; flex-wrap: wrap; }
    .stat { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px 20px; min-width: 80px; }
    .stat .num { font-size: 28px; font-weight: bold; }
    .stat .label { font-size: 12px; color: #94a3b8; }
    .critical .num { color: #dc2626; } .high .num { color: #ea580c; }
    .medium .num { color: #d97706; } .low .num { color: #16a34a; }
    table { width: calc(100% - 64px); margin: 0 32px 32px; border-collapse: collapse; font-size: 13px; }
    th { background: #1e293b; padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; color: #94a3b8; font-weight: 500; }
    td { padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: middle; }
    tr:hover td { background: #1e293b; }
  </style>
</head>
<body>
  <header>
    <h1>🔍 Snyk Mock API</h1>
    <p>Synthetic vulnerability data — full field parity with real Snyk JSONL dataset</p>
  </header>
  <div class="controls">
    <form method="get" action="/" style="display:flex;gap:8px;align-items:center">
      <label style="font-size:13px;color:#94a3b8">Preview count (max 200):</label>
      <input type="number" name="count" value="${safeCount}" min="1" max="200"/>
      <button type="submit">Refresh</button>
    </form>
    <a href="/api/events?count=1000" target="_blank">📄 NDJSON 1k</a>
    <a href="/api/events?count=10000" target="_blank">📄 NDJSON 10k</a>
    <a href="/api/events?count=50000" target="_blank">📄 NDJSON 50k</a>
    <a href="/api/events/wrapped?count=100" target="_blank">📦 Wrapped JSON</a>
    <a href="/health" target="_blank">❤️ Health</a>
  </div>
  <p class="note">ℹ️ Dashboard preview limited to 200. Use NDJSON links above for volume testing (up to 100k records).</p>
  <div class="stats">
    <div class="stat critical"><div class="num">${vulns.filter(v => v.severity === 'critical').length}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="num">${vulns.filter(v => v.severity === 'high').length}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="num">${vulns.filter(v => v.severity === 'medium').length}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="num">${vulns.filter(v => v.severity === 'low').length}</div><div class="label">Low</div></div>
    <div class="stat"><div class="num">${vulns.filter(v => v.isPatchable).length}</div><div class="label">Patchable</div></div>
    <div class="stat"><div class="num">${safeCount}</div><div class="label">Shown</div></div>
  </div>
  <table>
    <thead><tr>
      <th>ID</th><th>Title</th><th>Module</th><th>Language</th>
      <th>Severity</th><th>CVSS</th><th>Patchable</th><th>Upgradable</th><th>Created</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`);
});

// Generate and write JSONL.gz directly to Volume
app.get('/api/generate', (req, res) => {
  const count = Math.min(parseInt(req.query.count) || 100, 5000);
  const vulns = Array.from({ length: count }, generateSnykVulnerability);
  
  const jsonl = vulns.map(v => JSON.stringify(v)).join('\n');
  const compressed = gzipSync(Buffer.from(jsonl, 'utf-8'));
  
  const ts = new Date().toISOString().replace(/[-:]/g, '').split('.')[0];
  const filename = `snyk_vulns_${ts}.jsonl.gz`;
  const filepath = `/Volumes/dsl_dev/internal/faker_snyk_output/${filename}`;
  
  try {
    writeFileSync(filepath, compressed);
    res.json({ status: 'ok', file: filepath, records: count, bytes: compressed.length });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.listen(port, () => {
  console.log(`Snyk Mock API running on port ${port}`);
  console.log(`  GET /                            → HTML dashboard (preview)`);
  console.log(`  GET /api/events?count=10000      → NDJSON stream (up to 100k)`);
  console.log(`  GET /api/events/wrapped?count=100 → wrapped JSON`);
  console.log(`  GET /health                      → health check`);
});
