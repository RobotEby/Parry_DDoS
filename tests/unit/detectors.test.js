'use strict';

const { SQLInjectionDetector } = require('../../src/detectors/sql');
const { XSSDetector } = require('../../src/detectors/xss');
const { NoSQLDetector } = require('../../src/detectors/nosql');
const {
  SQL_MALICIOUS,
  SQL_CLEAN,
  XSS_MALICIOUS,
  XSS_CLEAN,
  NOSQL_MALICIOUS_OBJECTS,
  NOSQL_MALICIOUS_STRINGS,
  NOSQL_CLEAN,
} = require('../fixtures/payloads');

let passed = 0,
  failed = 0;

function assert(description, condition) {
  if (condition) {
    console.log(`  ✓ ${description}`);
    passed++;
  } else {
    console.error(`  ✗ FAILED: ${description}`);
    failed++;
  }
}

console.log('\n── SQL Injection Detector ──────────────────────────────────');
SQL_MALICIOUS.forEach((p, i) =>
  assert(`Detects malicious payloads #${i + 1}`, SQLInjectionDetector.scan(p) !== null)
);
SQL_CLEAN.forEach((p, i) =>
  assert(`Allows clean values #${i + 1}`, SQLInjectionDetector.scan(p) === null)
);

console.log('\n── XSS Detector ────────────────────────────────────────────');
XSS_MALICIOUS.forEach((p, i) =>
  assert(`Detects malicious payloads #${i + 1}`, XSSDetector.scan(p) !== null)
);
XSS_CLEAN.forEach((p, i) => assert(`Allows clean values #${i + 1}`, XSSDetector.scan(p) === null));

console.log('\n── NoSQL Injection Detector ────────────────────────────────');
NOSQL_MALICIOUS_OBJECTS.forEach((p, i) =>
  assert(`Detects malicious objects #${i + 1}`, NoSQLDetector.scan(p) !== null)
);
NOSQL_MALICIOUS_STRINGS.forEach((p, i) =>
  assert(`Detects malicious strings #${i + 1}`, NoSQLDetector.scan(p) !== null)
);
NOSQL_CLEAN.forEach((p, i) =>
  assert(`Allows clean values #${i + 1}`, NoSQLDetector.scan(p) === null)
);

module.exports = { passed, failed };
