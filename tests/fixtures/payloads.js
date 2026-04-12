'use strict';

/**
 * tests/fixtures/payloads.js
 * Reusable attack payloads across unit and integration tests.
 */

const SQL_MALICIOUS = [
  "' OR 1=1 --",
  "' UNION SELECT * FROM users",
  '; DROP TABLE users;',
  "' AND SLEEP(5) --",
  "admin' --",
  "' AND 1=2 UNION SELECT table_name FROM information_schema.tables",
  'admin%27%20OR%201%3D1',
];

const SQL_CLEAN = ['john.doe@example.com', 'hello world 123', 'produto-slug_01', ''];

const XSS_MALICIOUS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<a href="javascript:alert(1)">x</a>',
  '{{constructor.constructor("alert(1)")()}}',
  '%3Cscript%3Ealert(1)%3C/script%3E',
  'vbscript:msgbox("xss")',
  '<input autofocus onfocus=alert(1)>',
];

const XSS_CLEAN = ['https://example.com/page?id=42', 'Olá mundo', 'produto <b>destaque</b>'];

const NOSQL_MALICIOUS_OBJECTS = [
  { $gt: '' },
  { $ne: null },
  { $where: 'function() { return true; }' },
  { $or: [{ a: 1 }, { b: 2 }] },
];

const NOSQL_MALICIOUS_STRINGS = ['{"$gt":""}', '{"$where":"function(){return true;}"}'];

const NOSQL_CLEAN = [{ username: 'alice', age: 30 }, 'alice', 'standard product'];

module.exports = {
  SQL_MALICIOUS,
  SQL_CLEAN,
  XSS_MALICIOUS,
  XSS_CLEAN,
  NOSQL_MALICIOUS_OBJECTS,
  NOSQL_MALICIOUS_STRINGS,
  NOSQL_CLEAN,
};
