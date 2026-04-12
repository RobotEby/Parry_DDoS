'use strict';

const { XSS_PATTERNS } = require('../../constants/patterns');

const XSSDetector = {
  /** @param {string} value @returns {string|null} */
  scan(value) {
    if (typeof value !== 'string' || value.trim() === '') return null;
    const decoded = _decodeVariants(value);
    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(decoded)) return pattern.toString();
    }
    return null;
  },
};

function _decodeVariants(input) {
  let result = input;
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(result.replace(/\+/g, ' '));
      if (next === result) break;
      result = next;
    } catch (_) {
      break;
    }
  }
  result = result.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '');
  return result
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/gi, (_, c) => String.fromCharCode(Number(c)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

module.exports = { XSSDetector };
