import express from 'express';
import { faker } from '@faker-js/faker';
import { existsSync, readdirSync } from 'fs';
import { gzipSync } from 'zlib';
import crypto from 'crypto';

const app = express();

// ── Config ──────────────────────────────────────────────────────────────────
// Set these in Noop: App → snyk-faker-api → Dev → Environment Variables
//
//   APP_TOKEN              → strong secret (e.g. openssl rand -hex 32)
//   APP_HOST               → https://snyk-faker-dev.noop.app
//   APP_ENDPOINT           → /api/events
//   DATABRICKS_HOST        → <workspace>.cloud.databricks.com
//   DATABRICKS_CLIENT_ID   → service principal client id
//   DATABRICKS_CLIENT_SECRET → service principal secret
//
const APP_HOST     = process.env.APP_HOST     || 'https://snyk-faker-dev.noop.app';
const APP_TOKEN    = process.env.APP_TOKEN    || '';  // NO default — must be set
const APP_ENDPOINT = process.env.APP_ENDPOINT || '/api/events';
const VOLUME_PATH  = process.env.VOLUME_PATH  || '/Volumes/dsl_dev/internal/faker_snyk_output';

const port = process.env.PORT || process.env.DATABRICKS_APP_PORT || 8000;

// ── Auth Middleware (ALL routes) ────────────────────────────────────────────
// Every single request must provide one of:
//   1. Query param:   ?key=<APP_TOKEN>
//   2. Header:        Authorization: Bearer <APP_TOKEN>
//   3. Cookie:        snyk_faker_token=<APP_TOKEN>  (set after browser login)
//
// If APP_TOKEN env var is not set, the app refuses to start.

if (!APP_TOKEN) {
  console.error('═══════════════════════════════════════════════════════════');
  console.error('  FATAL: APP_TOKEN environment variable is not set.');
  console.error('  Set it in Noop → App → Dev → Environment Variables');
  console.error('  Generate one:  openssl rand -hex 32');
  console.error('═══════════════════════════════════════════════════════════');
  process.exit(1);
}

// Constant-time comparison to prevent timing attacks
function safeCompare(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function isAuthenticated(req) {
  // 1. Query param
  if (req.query.key && safeCompare(req.query.key, APP_TOKEN)) return true;
  // 2. Authorization header
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    if (safeCompare(token, APP_TOKEN)) return true;
  }
  // 3. Cookie (for browser sessions after login)
  const cookies = parseCookies(req.headers.cookie || '');
  if (cookies.snyk_faker_token && safeCompare(cookies.snyk_faker_token, APP_TOKEN)) return true;

  return false;
}

function parseCookies(cookieStr) {
  return cookieStr.split(';').reduce((acc, pair) => {
    const [key, ...val] = pair.trim().split('=');
    if (key) acc[key.trim()] = val.join('=').trim();
    return acc;
  }, {});
}

// Login page — the ONLY unauthenticated route
// Serves a simple form where you enter the token in the browser
app.get('/login', (req, res) => {
  const error = req.query.error ? '<p style="color:#ef4444;margin:0 0 16px">Invalid token. Try again.</p>' : '';
  res.send(`<!DOCTYPE html>
<html>
<head><title>Snyk Mock API — Login</title>
<style>
  body { font-family: sans-serif; margin: 0; background: #0f172a; color: #e2e8f0;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
          padding: 40px; width: 360px; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p.sub { font-size: 13px; color: #94a3b8; margin: 0 0 24px; }
  label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 6px; }
  input { width: 100%; background: #0f172a; border: 1px solid #334155; color: #e2e8f0;
          padding: 10px 12px; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
  button { width: 100%; margin-top: 16px; background: #3b82f6; color: white; border: none;
           padding: 10px; border-radius: 6px; font-size: 14px; cursor: pointer; }
  button:hover { background: #2563eb; }
  .hint { font-size: 11px; color: #475569; margin-top: 20px; text-align: center; }
  .hint code { color: #60a5fa; }
</style>
</head>
<body>
  <div class="card">
    <h1>🔒 Snyk Mock API</h1>
    <p class="sub">Enter your API token to access the dashboard and endpoints.</p>
    ${error}
    <form method="POST" action="/login">
      <label for="token">API Token</label>
      <input type="password" id="token" name="token" placeholder="Paste your APP_TOKEN" required autofocus />
      <button type="submit">Sign In</button>
    </form>
    <p class="hint">Programmatic access: <code>?key=TOKEN</code> or <code>Authorization: Bearer TOKEN</code></p>
  </div>
</body>
</html>`);
});

// Login POST — validates token and sets a session cookie
app.use(express.urlencoded({ extended: false }));
app.post('/login', (req, res) => {
  const token = (req.body.token || '').trim();
  if (safeCompare(token, APP_TOKEN)) {
    // Set httpOnly secure cookie — 7 day expiry
    res.setHeader('Set-Cookie',
      `snyk_faker_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${7 * 24 * 60 * 60}`
    );
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'snyk_faker_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  res.redirect('/login');
});

// ── Auth gate — everything below this requires a valid token ────────────────
app.use((req, res, next) => {
  if (isAuthenticated(req)) return next();

  // For API requests, return JSON 401
  if (req.path.startsWith('/api/') || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Provide ?key=<APP_TOKEN> or Authorization: Bearer <APP_TOKEN>',
      login: `${APP_HOST}/login`
    });
  }

  // For browser requests, redirect to login
  res.redirect('/login');
});

// ── Data Generation ─────────────────────────────────────────────────────────
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

// ── Protected Routes (all require auth) ─────────────────────────────────────

// Config endpoint — shows connection details for notebooks
app.get('/api/config', (req, res) => {
  const host = APP_HOST;
  res.json({
    host,
    endpoint: APP_ENDPOINT,
    auth: {
      method: 'Bearer token or query param',
      header: 'Authorization: Bearer <APP_TOKEN>',
      query: '?key=<APP_TOKEN>',
      cookie: 'Browser login at /login'
    },
    endpoints: {
      dashboard:       `${host}/`,
      ndjson_stream:   `${host}/api/events?count=1000`,
      wrapped_json:    `${host}/api/events/wrapped?count=100`,
      generate_to_vol: `${host}/api/generate?count=1000`,
      health:          `${host}/health`,
      config:          `${host}/api/config`,
      login:           `${host}/login`,
      logout:          `${host}/logout`
    },
    databricks_notebook_example: [
      '# Python — pull NDJSON into Spark DataFrame',
      'import requests, json',
      `HOST = "${host}"`,
      'TOKEN = dbutils.secrets.get(scope="snyk-faker", key="app-token")',
      'resp = requests.get(',
      '    f"{HOST}/api/events",',
      '    params={"count": 5000, "key": TOKEN},',
      '    stream=True',
      ')',
      'resp.raise_for_status()',
      'records = [json.loads(line) for line in resp.iter_lines() if line]',
      'df = spark.createDataFrame(records)',
      'df.write.mode("overwrite").saveAsTable("dsl_dev.silver.snyk_mock_vulns")'
    ],
    curl_example: `curl -H "Authorization: Bearer <APP_TOKEN>" "${host}/api/events?count=10"`
  });
});

// Health check
app.get('/health', (req, res) => res.json({
  status: 'ok',
  timestamp: new Date().toISOString(),
  host: APP_HOST
}));

// NDJSON streaming — up to 100k records
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

// Wrapped JSON
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

// Generate and upload JSONL.gz to Databricks Volume
app.get('/api/generate', async (req, res) => {
  const count = Math.min(parseInt(req.query.count) || 100, 5000);
  const vulns = Array.from({ length: count }, generateSnykVulnerability);

  const jsonl = vulns.map(v => JSON.stringify(v)).join('\n');
  const compressed = gzipSync(Buffer.from(jsonl, 'utf-8'));

  const ts = new Date().toISOString().replace(/[-:]/g, '').split('.')[0];
  const filename = `snyk_vulns_${ts}.jsonl.gz`;
  const volumePath = `/Volumes/dsl_dev/internal/faker_snyk_output/${filename}`;

  try {
    const host = process.env.DATABRICKS_HOST;
    const clientId = process.env.DATABRICKS_CLIENT_ID;
    const clientSecret = process.env.DATABRICKS_CLIENT_SECRET;

    if (!host || !clientId || !clientSecret) {
      throw new Error('Missing DATABRICKS_HOST, DATABRICKS_CLIENT_ID, or DATABRICKS_CLIENT_SECRET env vars');
    }

    const tokenRes = await fetch(`https://${host}/oidc/v1/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${clientId}&client_secret=${clientSecret}&scope=all-apis`
    });
    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    const uploadRes = await fetch(`https://${host}/api/2.0/fs/files${volumePath}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/octet-stream'
      },
      body: compressed
    });

    if (!uploadRes.ok) {
      const err = await uploadRes.text();
      throw new Error(`Upload failed (${uploadRes.status}): ${err}`);
    }

    res.json({ status: 'ok', file: volumePath, records: count, bytes: compressed.length });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Debug endpoint (masks secrets)
app.get('/api/debug', (req, res) => {
  const env = Object.entries(process.env)
    .filter(([k]) => k.includes('VOLUME') || k.includes('DATABRICKS') || k.includes('APP_') || k === 'PORT')
    .reduce((acc, [k, v]) => {
      const masked = k.includes('SECRET') || k.includes('TOKEN')
        ? v.slice(0, 4) + '****'
        : v;
      return { ...acc, [k]: masked };
    }, {});

  res.json({ env, configuredHost: APP_HOST, port });
});

// HTML dashboard
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
    header { background: #1e293b; padding: 20px 32px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
    header h1 { margin: 0; font-size: 20px; }
    header p { margin: 4px 0 0; font-size: 13px; color: #94a3b8; }
    header .auth-info { display: flex; gap: 12px; align-items: center; font-size: 13px; }
    header .auth-info span { color: #22c55e; }
    header .auth-info a { color: #94a3b8; text-decoration: none; padding: 6px 12px; border: 1px solid #334155; border-radius: 6px; }
    header .auth-info a:hover { color: #e2e8f0; border-color: #94a3b8; }
    .config-banner { background: #1e3a5f; border: 1px solid #2563eb; margin: 16px 32px; padding: 16px 20px; border-radius: 8px; font-size: 13px; }
    .config-banner code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #60a5fa; }
    .config-banner a { color: #60a5fa; }
    .controls { padding: 20px 32px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .controls input { background: #1e293b; border: 1px solid #334155; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; width: 80px; }
    .controls button { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
    .controls a { color: #94a3b8; font-size: 13px; text-decoration: none; padding: 8px 12px; border: 1px solid #334155; border-radius: 6px; }
    .controls a:hover { color: #e2e8f0; border-color: #94a3b8; }
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
    <div>
      <h1>🔍 Snyk Mock API</h1>
      <p>Synthetic vulnerability data — full field parity with real Snyk JSONL dataset</p>
    </div>
    <div class="auth-info">
      <span>🔒 Authenticated</span>
      <a href="/api/config" target="_blank">⚙️ Config</a>
      <a href="/logout">Logout</a>
    </div>
  </header>
  <div class="config-banner">
    🔗 <strong>Pull URL:</strong> <code>${APP_HOST}/api/events?count=1000</code><br/>
    🔑 <strong>Auth:</strong> <code>Authorization: Bearer &lt;APP_TOKEN&gt;</code> or <code>?key=&lt;APP_TOKEN&gt;</code><br/>
    📋 <a href="/api/config" target="_blank">Full connection config &amp; notebook example →</a>
  </div>
  <div class="controls">
    <form method="get" action="/" style="display:flex;gap:8px;align-items:center">
      <label style="font-size:13px;color:#94a3b8">Preview count (max 200):</label>
      <input type="number" name="count" value="${safeCount}" min="1" max="200"/>
      <button type="submit">Refresh</button>
    </form>
    <a href="/health" target="_blank">❤️ Health</a>
  </div>
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

// Auto-generate on startup
const autoCount = parseInt(process.env.AUTO_GENERATE_COUNT || '0');
if (autoCount > 0) {
  (async () => {
    try {
      const vulns = Array.from({ length: autoCount }, generateSnykVulnerability);
      const jsonl = vulns.map(v => JSON.stringify(v)).join('\n');
      const compressed = gzipSync(Buffer.from(jsonl, 'utf-8'));

      const ts = new Date().toISOString().replace(/[-:]/g, '').split('.')[0];
      const filename = `snyk_vulns_${ts}.jsonl.gz`;
      const volumePath = `/Volumes/dsl_dev/internal/faker_snyk_output/${filename}`;

      const host = process.env.DATABRICKS_HOST;
      const clientId = process.env.DATABRICKS_CLIENT_ID;
      const clientSecret = process.env.DATABRICKS_CLIENT_SECRET;

      const tokenRes = await fetch(`https://${host}/oidc/v1/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${clientId}&client_secret=${clientSecret}&scope=all-apis`
      });
      const { access_token } = await tokenRes.json();

      const uploadRes = await fetch(`https://${host}/api/2.0/fs/files${volumePath}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/octet-stream' },
        body: compressed
      });

      if (uploadRes.ok) {
        console.log(`Auto-generated ${autoCount} records → ${volumePath}`);
      } else {
        console.error(`Auto-generate failed: ${await uploadRes.text()}`);
      }
    } catch (err) {
      console.error(`Auto-generate error: ${err.message}`);
    }
  })();
}

app.listen(port, () => {
  console.log(`Snyk Mock API running on port ${port}`);
  console.log(`  Host:  ${APP_HOST}`);
  console.log(`  Auth:  ALL routes locked — token required`);
  console.log('');
  console.log('  Unauthenticated:');
  console.log('    GET /login            → Browser login page');
  console.log('    POST /login           → Validate token & set cookie');
  console.log('  Authenticated:');
  console.log('    GET /                 → Dashboard');
  console.log('    GET /health           → Health check');
  console.log('    GET /api/config       → Connection config & examples');
  console.log('    GET /api/events       → NDJSON stream (up to 100k)');
  console.log('    GET /api/events/wrapped → Wrapped JSON');
  console.log('    GET /api/generate     → Generate & upload to Volume');
  console.log('    GET /api/debug        → Environment debug');
  console.log('    GET /logout           → Clear session');
});