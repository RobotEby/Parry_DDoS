'use strict';

/**
 * src/core/rateLimiter.js
 * Sliding-window rate limiter com contador de atividade suspeita e auto-ban.
 */
class RateLimiter {
  /**
   * @param {{ maxRequests: number, windowMs: number, suspiciousThreshold: number, banDurationMs: number }} config
   */
  constructor(config) {
    this.maxRequests = config.maxRequests;
    this.windowMs = config.windowMs;
    this.suspiciousThreshold = config.suspiciousThreshold;
    this.banDurationMs = config.banDurationMs;

    /** @type {Map<string, { timestamps: number[], suspicious: number, banUntil: number|null }>} */
    this.store = new Map();

    this._cleanupInterval = setInterval(() => this._cleanup(), 600_000);
    if (this._cleanupInterval.unref) this._cleanupInterval.unref();
  }

  /**
   * Verifica um IP contra os limites configurados.
   * @param {string} ip
   * @returns {import('../../types/index').RateLimitResult}
   */
  check(ip) {
    const now = Date.now();
    const entry = this._getOrCreate(ip);

    if (entry.banUntil !== null) {
      if (now < entry.banUntil) {
        return {
          limited: false,
          banned: true,
          remaining: 0,
          resetAt: entry.banUntil,
          banExpiresAt: entry.banUntil,
        };
      }
      entry.banUntil = null;
      entry.suspicious = 0;
      entry.timestamps = [];
    }

    const windowStart = now - this.windowMs;
    entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
    entry.timestamps.push(now);

    const count = entry.timestamps.length;
    const oldest = entry.timestamps[0] || now;
    const resetAt = oldest + this.windowMs;
    const remaining = Math.max(0, this.maxRequests - count);

    if (count > this.maxRequests) {
      return { limited: true, banned: false, remaining: 0, resetAt, banExpiresAt: null };
    }

    return { limited: false, banned: false, remaining, resetAt, banExpiresAt: null };
  }

  /**
   * Registra uma tentativa suspeita. Bane automaticamente ao atingir o limiar.
   * @param {string} ip
   */
  recordSuspicious(ip) {
    const entry = this._getOrCreate(ip);
    entry.suspicious += 1;
    if (entry.suspicious >= this.suspiciousThreshold) {
      entry.banUntil = Date.now() + this.banDurationMs;
    }
  }

  /**
   * Desbane manualmente um IP (ex.: endpoint de admin).
   * @param {string} ip
   */
  unban(ip) {
    const entry = this.store.get(ip);
    if (entry) {
      entry.banUntil = null;
      entry.suspicious = 0;
    }
  }

  /**
   * Retorna snapshot de todos os IPs rastreados.
   * @returns {import('../../types/index').IPSnapshot[]}
   */
  snapshot() {
    const now = Date.now();
    return [...this.store.entries()].map(([ip, entry]) => {
      const active = entry.timestamps.filter((t) => t > now - this.windowMs).length;
      return {
        ip,
        requests: active,
        suspicious: entry.suspicious,
        banned: entry.banUntil !== null && entry.banUntil > now,
        banExpiresAt: entry.banUntil,
      };
    });
  }

  _getOrCreate(ip) {
    if (!this.store.has(ip)) this.store.set(ip, { timestamps: [], suspicious: 0, banUntil: null });
    return this.store.get(ip);
  }

  _cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    for (const [ip, entry] of this.store.entries()) {
      const active = entry.timestamps.some((t) => t > windowStart);
      const banned = entry.banUntil !== null && entry.banUntil > now;
      if (!active && !banned) this.store.delete(ip);
    }
  }

  destroy() {
    clearInterval(this._cleanupInterval);
    this.store.clear();
  }
}

module.exports = { RateLimiter };
