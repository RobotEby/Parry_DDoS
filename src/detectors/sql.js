'use strict';

const { SQL_PATTERNS } = require('../../constants/patterns');

const SQLInjectionDetector = {
  /** @param {string} value @returns {string|null} */
  scan(value) {
    if (typeof value !== 'string' || value.trim() === '') return null;
    const decoded = _decodeVariants(value);
    for (const pattern of SQL_PATTERNS) {
      if (pattern.test(decoded)) return pattern.toString();
    }
    return null;
  },
};

function _decodeVariants(input) {
  let result = input;
  try {
    result = decodeURIComponent(result.replace(/\+/g, ' '));
  } catch (_) {}
  return result
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/gi, (_, c) => String.fromCharCode(Number(c)));
}

module.exports = { SQLInjectionDetector };
