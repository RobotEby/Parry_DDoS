'use strict';

const DEFAULTS = {
  sql: true,
  xss: true,
  nosql: true,

  rateLimit: true,
  maxRequests: 100,
  windowMs: 60_000,

  suspiciousThreshold: 5,
  banDurationMs: 300_000,

  logThreats: true,

  onThreat: null,

  maxObjectDepth: 5,
};

module.exports = { DEFAULTS };
