'use strict';

const { SQLInjectionDetector, XSSDetector, NoSQLDetector } = require('../detectors');
const { RateLimiter } = require('../core/rateLimiter');
const { ThreatLogger } = require('../core/logger');
const { DEFAULTS } = require('../../config/defaults');
const { SENSITIVE_HEADERS } = require('../../constants/patterns');

/**
 * Detects SQL Injection, XSS and NoSQL Injection in real-time.
 * Applies intelligent Rate Limiting with automatic banning for suspicious behavior.
 *
 * @param {import('../../types/index').Parry_DDoSOptions} options
 * @returns {import('express').RequestHandler}
 */
function Parry_DDoS(options = {}) {
  const config = { ...DEFAULTS, ...options };

  const rateLimiter = new RateLimiter(config);
  const logger = new ThreatLogger(config.logThreats);

  return function Parry_DDoSMiddleware(req, res, next) {
    const ip = _getClientIP(req);
    const timestamp = new Date().toISOString();

    if (config.rateLimit) {
      const rl = rateLimiter.check(ip);

      res.setHeader('X-RateLimit-Limit', config.maxRequests);
      res.setHeader('X-RateLimit-Remaining', rl.remaining);
      res.setHeader('X-RateLimit-Reset', rl.resetAt);

      if (rl.banned) {
        logger.log({
          type: 'BAN',
          ip,
          reason: 'Ban for suspicious activity',
          timestamp,
        });
        return _respond(res, 429, 'Too many suspicious requests. IP temporarily banned.', {
          banExpiresAt: rl.banExpiresAt,
        });
      }

      if (rl.limited) {
        logger.log({ type: 'RATE_LIMIT', ip, timestamp });
        return _respond(res, 429, 'Request limit reached. Please try again shortly.');
      }
    }

    const targets = _collectTargets(req, config.maxObjectDepth);

    const threats = [];

    for (const { label, value } of targets) {
      const str = _safeStringify(value);

      if (config.sql) {
        const hit = SQLInjectionDetector.scan(str);
        if (hit)
          threats.push({
            detector: 'SQL_INJECTION',
            field: label,
            pattern: hit,
          });
      }
      if (config.xss) {
        const hit = XSSDetector.scan(str);
        if (hit) threats.push({ detector: 'XSS', field: label, pattern: hit });
      }
      if (config.nosql) {
        const hit = NoSQLDetector.scan(value);
        if (hit)
          threats.push({
            detector: 'NOSQL_INJECTION',
            field: label,
            pattern: hit,
          });
      }
    }

    if (threats.length > 0) {
      if (config.rateLimit) rateLimiter.recordSuspicious(ip);

      const entry = {
        type: 'THREAT',
        ip,
        timestamp,
        method: req.method,
        url: req.originalUrl || req.url,
        threats,
      };

      logger.log(entry);
      if (config.onThreat) config.onThreat(entry, req, res);

      return _respond(res, 400, 'Request blocked: malicious pattern detected.', {
        threats: threats.map((t) => ({
          detector: t.detector,
          field: t.field,
        })),
      });
    }

    next();
  };
}

function _getClientIP(req) {
  return (
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown'
  );
}

function _collectTargets(req, maxDepth) {
  const targets = [];
  const add = (label, value) => {
    if (value != null) targets.push({ label, value });
  };

  if (req.query && typeof req.query === 'object') {
    for (const [k, v] of Object.entries(req.query)) add(`query.${k}`, v);
  }
  if (req.params && typeof req.params === 'object') {
    for (const [k, v] of Object.entries(req.params)) add(`params.${k}`, v);
  }
  if (req.body && typeof req.body === 'object') {
    // Includes the root object so that top-level NoSQL operators are detected
    // e.g., body = { $or: [...] } — without this, only the array value would be inspected
    add('body', req.body);
    _flattenObject(req.body, 'body', add, maxDepth);
  }
  for (const h of SENSITIVE_HEADERS) {
    if (req.headers[h]) add(`header.${h}`, req.headers[h]);
  }

  return targets;
}

function _flattenObject(obj, prefix, callback, maxDepth, depth = 0) {
  if (depth >= maxDepth) return;
  for (const [key, val] of Object.entries(obj)) {
    const path = `${prefix}.${key}`;
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      callback(path, val);
      _flattenObject(val, path, callback, maxDepth, depth + 1);
    } else {
      callback(path, val);
    }
  }
}

function _safeStringify(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function _respond(res, status, message, extra = {}) {
  res.status(status).json({ error: true, message, ...extra });
}

module.exports = { Parry_DDoS };
