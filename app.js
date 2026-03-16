import express from 'express';
import { faker } from '@faker-js/faker';

const app = express();
const port = process.env.DATABRICKS_APP_PORT || 8000;

// Helper to generate a full Snyk Vulnerability Object
function generateSnykVulnerability() {
  const id = `SNYK-JS-${faker.word.adjective().toUpperCase()}-${faker.string.numeric(7)}`;
  const moduleName = faker.helpers.arrayElement(["braces", "cookie", "lodash", "tar", "jsonwebtoken"]);
  
  return {
    id: id,
    title: faker.helpers.arrayElement([
      "Excessive Platform Resource Consumption within a Loop",
      "Cross-site Scripting (XSS)",
      "Prototype Pollution",
      "Directory Traversal"
    ]),
    CVSSv3: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:${faker.helpers.arrayElement(['H', 'L', 'M'])}`,
    severity: faker.helpers.arrayElement(["low", "medium", "high", "critical"]),
    cvssScore: faker.number.float({ min: 3.0, max: 10.0, fractionDigits: 1 }),
    language: "js",
    moduleName: moduleName,
    packageName: faker.helpers.arrayElement(["micromatch", "jshttp", "isaacs", "juice-shop"]),
    version: `${faker.number.int({min: 1, max: 10})}.${faker.number.int({min: 0, max: 5})}.${faker.number.int({min: 0, max: 20})}`,
    
    // Discovery Timestamps
    creationTime: faker.date.recent().toISOString(),
    disclosureTime: faker.date.past().toISOString(),
    
    // Nested Object structures (Mocking the report layout)
    identifiers: {
      CVE: [`CVE-202${faker.number.int({min: 0, max: 5})}-${faker.string.numeric(4)}`],
      CWE: [`CWE-${faker.number.int({min: 10, max: 1000})}`]
    },
    
    remediation: {
      unresolved: faker.datatype.boolean(),
      upgradePath: [false, `${moduleName}@${faker.number.int({min: 11, max: 15})}.0.0`]
    }
  };
}

app.get('/api/events', (req, res) => {
  const requestCount = parseInt(req.query.count) || 10;
  const safeCount = Math.min(requestCount, 5000); 

  // Wrap the vulnerabilities in the top-level "vulnerabilities" array as seen in Snyk
  res.json({
    vulnerabilities: Array.from({ length: safeCount }, generateSnykVulnerability),
    ok: false,
    dependencyCount: faker.number.int({min: 500, max: 1500}),
    org: "rearc-security-poc"
  });
});

app.listen(port, () => console.log(`Snyk Mock API running on port ${port}`));