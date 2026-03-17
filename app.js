import express from 'express';
import { faker } from '@faker-js/faker';

const app = express();
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
    // ── Core identity ──────────────────────────────────────────────────────
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

    // ── Package info ───────────────────────────────────────────────────────
    language,
    moduleName,
    packageName: moduleName,
    packageManager,
    packageManager_parent: packageManager,
    version: currentVersion,
    primaryFixedVersion: fixedVersion,
    fixedIn: [fixedVersion],

    // ── Timestamps ─────────────────────────────────────────────────────────
    creationTime,
    modificationTime,
    disclosureTime,
    publicationTime,

    // ── Project / org context ──────────────────────────────────────────────
    projectName,
    org,
    path: `/Users/${faker.internet.username()}/Work/${projectName}`,
    displayTargetFile: "package-lock.json",
    packageManager_parent: packageManager,

    // ── Remediation flags ──────────────────────────────────────────────────
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

    // ── CVE/CWE identifiers ────────────────────────────────────────────────
    cveIds: [`CVE-202${faker.number.int({ min: 0, max: 5 })}-${faker.string.numeric(4)}`],
    cweIds: [`CWE-${faker.number.int({ min: 10, max: 1400 })}`],
    ghsaIds: faker.datatype.boolean() ? [`GHSA-${faker.string.alphanumeric(4)}-${faker.string.alphanumeric(4)}-${faker.string.alphanumeric(4)}`] : [],
    identifiers: {
      CVE: [`CVE-202${faker.number.int({ min: 0, max: 5 })}-${faker.string.numeric(4)}`],
      CWE: [`CWE-${faker.number.int({ min: 10, max: 1400 })}`]
    },

    // ── CVSS details ───────────────────────────────────────────────────────
    cvssDetails: [
      {
        assigner: "NVD",
        cvssV3BaseScore: cvssScore,
        cvssV3Vector: generateCVSSv3(severity),
        modificationTime,
        severity
      }
    ],
    cvssSources: [
      {
        assigner: "Snyk",
        baseScore: cvssScore,
        cvssVersion: "3.1",
        modificationTime,
        severity,
        type: "primary",
        vector: generateCVSSv3(severity)
      }
    ],

    // ── EPSS ───────────────────────────────────────────────────────────────
    epssDetails: {
      modelVersion: "v2025.03.14",
      percentile: faker.number.float({ min: 0.1, max: 0.99, fractionDigits: 5 }).toString(),
      probability: faker.number.float({ min: 0.001, max: 0.5, fractionDigits: 5 }).toString()
    },

    // ── Exploit info ───────────────────────────────────────────────────────
    exploit: faker.helpers.arrayElement(EXPLOIT_MATURITY),
    exploitDetails: {
      maturityLevels: [
        { format: "CVSSv3", level: faker.helpers.arrayElement(EXPLOIT_MATURITY), type: "secondary" },
        { format: "CVSSv4", level: faker.helpers.arrayElement(EXPLOIT_MATURITY), type: "primary" }
      ],
      sources: ["Snyk"]
    },

    // ── Dependency / remediation ───────────────────────────────────────────
    from: [`${projectName}@1.0.0`, `${moduleName}@${currentVersion}`],
    upgradePath: [false, `${moduleName}@${fixedVersion}`],
    semver: {
      vulnerable: [`<${fixedVersion}`]
    },
    dependencyCount: faker.number.int({ min: 50, max: 1500 }),
    referenceCount: faker.number.int({ min: 1, max: 10 }),
    references: [
      {
        title: "GitHub Commit",
        url: `https://github.com/${moduleName}/${moduleName}/commit/${faker.git.commitSha()}`
      }
    ],
    patches: [],
    functions: [],
    functions_new: [],

    // ── Description ────────────────────────────────────────────────────────
    description: `## Overview\n[${moduleName}](https://www.npmjs.com/package/${moduleName}) is vulnerable.\n\n## Remediation\nUpgrade \`${moduleName}\` to version ${fixedVersion} or higher.`,
    remediationText: `Upgrade to ${fixedVersion} or higher`,

    // ── Insights / triage ──────────────────────────────────────────────────
    insights: {
      triageAdvice: faker.datatype.boolean() ? faker.lorem.sentence() : null
    },

    // ── Policy / settings ──────────────────────────────────────────────────
    filtered: {
      ignore: [],
      patch: []
    },
    ignoreSettings: {
      adminOnly: false,
      disregardFilesystemIgnores: false,
      reasonRequired: false
    },
    licensesPolicy: null,

    // ── Scan metadata ──────────────────────────────────────────────────────
    summary: `${faker.number.int({ min: 10, max: 600 })} vulnerable dependency paths`,
    uniqueCount: faker.number.int({ min: 1, max: 200 }),
    eventType: "open_source_vulnerability"
  };
}

// ── Routes ─────────────────────────────────────────────────────────────────

// Returns a JSON array of flat vulnerability objects (JSONL-compatible)
// Each object matches what the Snyk JSONL.gz file contains per line
app.get('/api/events', (req, res) => {
  const requestCount = parseInt(req.query.count) || 10;
  const safeCount = Math.min(requestCount, 5000);

  const vulnerabilities = Array.from({ length: safeCount }, generateSnykVulnerability);

  // Return as newline-delimited JSON (JSONL) so Lakewatch autoloader
  // can ingest directly if written to a .jsonl file
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.send(vulnerabilities.map(v => JSON.stringify(v)).join('\n'));
});

// Optional: return as wrapped JSON object (original format)
app.get('/api/events/wrapped', (req, res) => {
  const requestCount = parseInt(req.query.count) || 10;
  const safeCount = Math.min(requestCount, 5000);

  res.json({
    vulnerabilities: Array.from({ length: safeCount }, generateSnykVulnerability),
    ok: false,
    dependencyCount: faker.number.int({ min: 500, max: 1500 }),
    org: faker.helpers.arrayElement(ORG_NAMES)
  });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(port, () => {
  console.log(`Snyk Mock API running on port ${port}`);
  console.log(`  GET /api/events?count=100       → JSONL (one vulnerability per line)`);
  console.log(`  GET /api/events/wrapped?count=100 → wrapped JSON object`);
  console.log(`  GET /health                     → health check`);
});
