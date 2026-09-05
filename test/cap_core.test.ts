import { describe, it, expect } from 'vitest';
import {
  fnv1a,
  fnv1aResume,
  prngFromHash,
  parseHexPrefix,
  powMatchesPrefix,
  generateCapChallenge,
  validateCapChallenge,
  verifyCapTokenPayload,
  jwtSign,
  jwtVerify,
} from '../src/challenge/cap_core';

describe('Cap Core (Serverless Zero-Dependency PoW Engine)', () => {
  const testSecret = 'cap_test_master_secret_key_1234567890';

  it('1. verifies FNV-1a and PRNG deterministic seed derivation', () => {
    const hash1 = fnv1a('hello world');
    expect(hash1).toBeGreaterThan(0);
    expect(fnv1a('hello world')).toBe(hash1); // deterministic

    const resumed = fnv1aResume(hash1, ':salt_extension');
    expect(resumed).not.toBe(hash1);

    const randHex1 = prngFromHash(hash1, 32);
    expect(randHex1).toHaveLength(32);
    expect(/^[0-9a-f]{32}$/.test(randHex1)).toBe(true);

    const randHex2 = prngFromHash(hash1, 32);
    expect(randHex2).toBe(randHex1); // deterministic
  });

  it('2. verifies hex prefix matching logic', () => {
    const parsed = parseHexPrefix('00ab');
    expect(parsed.fullBytes).toBe(2);
    expect(parsed.partialNibble).toBe(-1);

    // Matching hash: starts with 0x00, 0xab
    const matchingHash = new Uint8Array([0x00, 0xab, 0x12, 0x34]);
    expect(powMatchesPrefix(matchingHash, parsed)).toBe(true);

    // Non-matching hash
    const nonMatchingHash = new Uint8Array([0x00, 0xac, 0x12, 0x34]);
    expect(powMatchesPrefix(nonMatchingHash, parsed)).toBe(false);
  });

  it('3. generates valid signed Cap challenges with JWT token', async () => {
    const res = await generateCapChallenge(testSecret, {
      challengeCount: 5,
      challengeSize: 16,
      challengeDifficulty: 2,
      expiresMs: 60000,
    });

    expect(res.challenge.c).toBe(5);
    expect(res.challenge.s).toBe(16);
    expect(res.challenge.d).toBe(2);
    expect(res.expires).toBeGreaterThan(Date.now());
    expect(res.token.split('.')).toHaveLength(3);

    const payload = await jwtVerify(res.token, testSecret);
    expect(payload).not.toBeNull();
    expect(payload?.c).toBe(5);
    expect(payload?.s).toBe(16);
    expect(payload?.d).toBe(2);
  });

  it('4. solves and validates complete proof-of-work challenge cycle', async () => {
    // Generate small challenge for fast test execution
    const challengeRes = await generateCapChallenge(testSecret, {
      challengeCount: 3,
      challengeSize: 16,
      challengeDifficulty: 2, // 1 byte prefix: fast to solve (~256 tries), zero chance for random solution to match
    });

    const token = challengeRes.token;
    const tokenFnv = fnv1a(token);
    const solutions: number[] = [];

    // Simulate Client WASM Solver in TypeScript
    for (let i = 0; i < challengeRes.challenge.c; i++) {
      const idxStr = String(i + 1);
      const saltSeed = fnv1aResume(tokenFnv, idxStr);
      const targetSeed = fnv1aResume(saltSeed, 'd');
      const salt = prngFromHash(saltSeed, challengeRes.challenge.s);
      const target = prngFromHash(targetSeed, challengeRes.challenge.d);
      const targetPrefix = parseHexPrefix(target);

      let found = -1;
      for (let n = 0; n < 100000; n++) {
        const encoder = new TextEncoder();
        const hashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(salt + n));
        if (powMatchesPrefix(new Uint8Array(hashBuf), targetPrefix)) {
          found = n;
          break;
        }
      }
      expect(found).toBeGreaterThanOrEqual(0);
      solutions.push(found);
    }

    // 1. Validate authentic solutions
    const validResult = await validateCapChallenge(testSecret, {
      token,
      solutions,
    });
    expect(validResult.success).toBe(true);
    expect(validResult.token).toBeDefined();

    // 2. Validate redeemed token
    const tokenVerification = await verifyCapTokenPayload(validResult.token!, testSecret);
    expect(tokenVerification.success).toBe(true);

    // 3. Direct JSON payload verification
    const directVerification = await verifyCapTokenPayload(
      JSON.stringify({ token, solutions }),
      testSecret
    );
    expect(directVerification.success).toBe(true);

    // 4. Reject tampered solution
    const tamperedSolutions = [...solutions];
    tamperedSolutions[0] = tamperedSolutions[0] + 9999999;
    const tamperedResult = await validateCapChallenge(testSecret, {
      token,
      solutions: tamperedSolutions,
    });
    expect(tamperedResult.success).toBe(false);
    expect(tamperedResult.message).toContain('failed');

    // 5. Reject wrong secret
    const wrongSecretResult = await validateCapChallenge('wrong_secret_key_123', {
      token,
      solutions,
    });
    expect(wrongSecretResult.success).toBe(false);
  });

  it('5. rejects expired challenge token', async () => {
    const expiredPayload = {
      n: 'random_nonce',
      c: 1,
      s: 16,
      d: 1,
      exp: Date.now() - 1000, // expired 1s ago
      iat: Date.now() - 2000,
    };
    const expiredToken = await jwtSign(expiredPayload, testSecret);

    const res = await validateCapChallenge(testSecret, {
      token: expiredToken,
      solutions: [0],
    });
    expect(res.success).toBe(false);
    expect(res.message).toContain('expired');
  });
});
