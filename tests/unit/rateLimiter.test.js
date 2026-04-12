'use strict';

const { RateLimiter } = require('../../src/core/rateLimiter');

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

console.log('\n── RateLimiter ─────────────────────────────────────────────');

const rl = new RateLimiter({
  maxRequests: 3,
  windowMs: 5_000,
  suspiciousThreshold: 2,
  banDurationMs: 1_000,
});

const ip = '10.0.0.1';
const ip2 = '10.0.0.2';

const r1 = rl.check(ip);
assert('First request allowed', !r1.limited && !r1.banned);
assert('Remaining decreases correctly', r1.remaining === 2);

rl.check(ip);
rl.check(ip);
const r4 = rl.check(ip);
assert('4th request is blocked by rate limit', r4.limited);

assert('The resetAt header is a future number', r4.resetAt > Date.now());

rl.check(ip2);
rl.recordSuspicious(ip2);
rl.recordSuspicious(ip2);
const banned = rl.check(ip2);
assert('IP banned after reaching suspiciousThreshold', banned.banned);
assert('banExpiresAt is defined in the result', banned.banExpiresAt !== null);

const snap = rl.snapshot();
assert('Snapshot returns an array', Array.isArray(snap));
assert(
  'Snapshot contains ip2 as banned',
  snap.some((s) => s.ip === ip2 && s.banned)
);

rl.unban(ip2);
const unbanned = rl.check(ip2);
assert('IP unbaned manually with success', !unbanned.banned);

rl.destroy();

module.exports = { passed, failed };
