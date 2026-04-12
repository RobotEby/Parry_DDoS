'use strict';

const {
  NOSQL_DANGEROUS_OPERATORS,
  NOSQL_SUSPICIOUS_OPERATORS,
  NOSQL_STRING_PATTERNS,
} = require('../../constants/patterns');

const NoSQLDetector = {
  /** @param {*} value @returns {string|null} */
  scan(value) {
    if (value !== null && typeof value === 'object') return _scanObject(value);
    if (typeof value === 'string') return _scanString(value);
    return null;
  },
};

function _scanObject(obj, depth = 0) {
  if (depth > 6) return null;
  for (const key of Object.keys(obj)) {
    if (NOSQL_DANGEROUS_OPERATORS.has(key)) return `Operador perigoso: ${key}`;
    if (NOSQL_SUSPICIOUS_OPERATORS.has(key)) return `Operador suspeito: ${key}`;
    const val = obj[key];
    if (val && typeof val === 'object') {
      const nested = _scanObject(val, depth + 1);
      if (nested) return nested;
    }
    if (typeof val === 'string') {
      const hit = _scanString(val);
      if (hit) return hit;
    }
  }
  return null;
}

function _scanString(value) {
  if (!value || value.trim() === '') return null;
  if (value.trim().startsWith('{') || value.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object') {
        const hit = _scanObject(parsed);
        if (hit) return hit;
      }
    } catch (_) {}
  }
  for (const pattern of NOSQL_STRING_PATTERNS) {
    if (pattern.test(value)) return pattern.toString();
  }
  return null;
}

module.exports = { NoSQLDetector };
