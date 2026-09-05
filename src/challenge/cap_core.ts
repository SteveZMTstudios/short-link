/**
 * Edge-native, zero-external-dependency Cap Core engine for Cloudflare Workers.
 * Implements stateless Cap Proof-of-Work challenge generation and verification,
 * fully compatible with the official Cap web component widget (trycap.dev).
 * 
 * Based on the stateless algorithm specification (FNV-1a, Xorshift32 PRNG, SHA-256 PoW).
 */

export interface CapChallengeOptions {
  challengeCount?: number; // c: number of puzzle items, default 50
  challengeSize?: number; // s: length of salt in hex chars, default 32
  challengeDifficulty?: number; // d: difficulty prefix length, default 4
  expiresMs?: number; // expiration in ms, default 10 min (600_000)
}

export interface CapChallengeResponse {
  challenge: {
    c: number;
    s: number;
    d: number;
  };
  token: string;
  expires: number;
}

export interface CapValidationBody {
  token?: string;
  solutions?: number[];
  [key: string]: unknown;
}

export interface CapValidationResult {
  success: boolean;
  message?: string;
  token?: string;
  expires?: number;
}

// -------------------------------------------------------------
// 1. FNV-1a & Xorshift32 PRNG (Deterministic Seed Derivation)
// -------------------------------------------------------------

export function fnv1a(str: string): number {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
}

export function fnv1aResume(state: number, str: string): number {
  let h = state;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }
  return h >>> 0;
}

export function prngFromHash(initialHash: number, length: number): string {
  let state = initialHash;
  let result = '';
  while (result.length < length) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    result += state.toString(16).padStart(8, '0');
  }
  return result.substring(0, length);
}

// -------------------------------------------------------------
// 2. Web Crypto Helpers (HMAC-SHA256, Base64URL, Timing-Safe Equal)
// -------------------------------------------------------------

function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlToBuffer(b64url: string): Uint8Array {
  try {
    let base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return new Uint8Array(0);
  }
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hmacSha256(secret: string, text: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(text));
  return new Uint8Array(sigBuffer);
}

async function sha256Bytes(text: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return new Uint8Array(hashBuffer);
}

function randomHex(bytesCount: number): string {
  const bytes = new Uint8Array(bytesCount);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

// -------------------------------------------------------------
// 3. Lightweight JWT (Signed by Secret Key)
// -------------------------------------------------------------

const JWT_HEADER_B64 = bufferToBase64Url(new TextEncoder().encode('{"alg":"HS256","typ":"JWT"}'));

export async function jwtSign(payload: Record<string, unknown>, secret: string): Promise<string> {
  const bodyB64 = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const sigInput = `${JWT_HEADER_B64}.${bodyB64}`;
  const sigBytes = await hmacSha256(secret, sigInput);
  return `${sigInput}.${bufferToBase64Url(sigBytes)}`;
}

export async function jwtVerify(token: string, secret: string): Promise<Record<string, unknown> | null> {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const sigInput = `${parts[0]}.${parts[1]}`;
  const expectedSig = await hmacSha256(secret, sigInput);
  const actualSig = base64UrlToBuffer(parts[2]);

  if (!timingSafeEqual(expectedSig, actualSig)) return null;

  try {
    const jsonStr = new TextDecoder().decode(base64UrlToBuffer(parts[1]));
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

// -------------------------------------------------------------
// 4. PoW Matching Logic
// -------------------------------------------------------------

export function parseHexPrefix(target: string): { bytes: Uint8Array; fullBytes: number; partialNibble: number } {
  const len = target.length;
  const fullBytes = len >> 1;
  const bytes = new Uint8Array(fullBytes);
  for (let i = 0; i < fullBytes; i++) {
    const a = target.charCodeAt(i * 2);
    const b = target.charCodeAt(i * 2 + 1);
    bytes[i] = (((a <= 57 ? a - 48 : (a | 32) - 87) << 4) | (b <= 57 ? b - 48 : (b | 32) - 87)) & 0xff;
  }
  let partialNibble = -1;
  if (len & 1) {
    const c = target.charCodeAt(len - 1);
    partialNibble = c <= 57 ? c - 48 : (c | 32) - 87;
  }
  return { bytes, fullBytes, partialNibble };
}

export function powMatchesPrefix(
  hashBytes: Uint8Array,
  parsed: { bytes: Uint8Array; fullBytes: number; partialNibble: number }
): boolean {
  const { bytes, fullBytes, partialNibble } = parsed;
  for (let i = 0; i < fullBytes; i++) {
    if (hashBytes[i] !== bytes[i]) return false;
  }
  if (partialNibble !== -1) {
    if (hashBytes[fullBytes] >> 4 !== partialNibble) return false;
  }
  return true;
}

// -------------------------------------------------------------
// 5. High-Level Cap Challenge Generator & Validator
// -------------------------------------------------------------

const DEFAULT_CHALLENGE_COUNT = 50;
const DEFAULT_CHALLENGE_SIZE = 32;
const DEFAULT_CHALLENGE_DIFFICULTY = 4;
const DEFAULT_CHALLENGE_TTL_MS = 600_000; // 10 minutes
const DEFAULT_TOKEN_TTL_MS = 1_200_000; // 20 minutes

export async function generateCapChallenge(
  secret: string,
  opts: CapChallengeOptions = {}
): Promise<CapChallengeResponse> {
  if (!secret) throw new Error('Cap Secret is required to generate challenge');

  const c = opts.challengeCount ?? DEFAULT_CHALLENGE_COUNT;
  const s = opts.challengeSize ?? DEFAULT_CHALLENGE_SIZE;
  const d = opts.challengeDifficulty ?? DEFAULT_CHALLENGE_DIFFICULTY;
  const ttlMs = opts.expiresMs ?? DEFAULT_CHALLENGE_TTL_MS;
  const now = Date.now();
  const expires = now + ttlMs;

  const payload = {
    n: randomHex(25),
    c,
    s,
    d,
    exp: expires,
    iat: now,
  };

  const token = await jwtSign(payload, secret);
  return {
    challenge: { c, s, d },
    token,
    expires,
  };
}

export async function validateCapChallenge(
  secret: string,
  body: CapValidationBody
): Promise<CapValidationResult> {
  if (!secret) return { success: false, message: 'Missing secret' };
  if (!body || typeof body !== 'object') return { success: false, message: 'Invalid body' };
  if (!body.token || typeof body.token !== 'string') return { success: false, message: 'Missing token' };
  if (!Array.isArray(body.solutions)) return { success: false, message: 'Missing solutions' };

  const payload = await jwtVerify(body.token, secret);
  if (!payload) return { success: false, message: 'Invalid token signature' };

  if (typeof payload.exp === 'number' && payload.exp < Date.now()) {
    return { success: false, message: 'Challenge has expired' };
  }

  const c = payload.c as number;
  const size = payload.s as number;
  const difficulty = payload.d as number;

  if (body.solutions.length !== c) {
    return { success: false, message: 'Solutions count mismatch' };
  }

  const token = body.token;
  const tokenFnv = fnv1a(token);

  // Verify each PoW sub-puzzle solution
  for (let i = 0; i < c; i++) {
    const sol = body.solutions[i];
    if (typeof sol !== 'number') return { success: false, message: 'Invalid solution type' };

    const idxStr = String(i + 1);
    const saltSeed = fnv1aResume(tokenFnv, idxStr);
    const targetSeed = fnv1aResume(saltSeed, 'd');
    const salt = prngFromHash(saltSeed, size);
    const target = prngFromHash(targetSeed, difficulty);

    const hash = await sha256Bytes(salt + sol);
    if (!powMatchesPrefix(hash, parseHexPrefix(target))) {
      return { success: false, message: `Solution verification failed at index ${i}` };
    }
  }

  // Generate verified token for redemption
  const tokenExpires = Date.now() + DEFAULT_TOKEN_TTL_MS;
  const verifiedToken = await jwtSign(
    {
      type: 'cap_verified',
      verified: true,
      exp: tokenExpires,
      iat: Date.now(),
      ref: randomHex(12),
    },
    secret
  );

  return {
    success: true,
    token: verifiedToken,
    expires: tokenExpires,
  };
}

/**
 * Validates whether a token submitted by form is either:
 * 1) A direct challenge solution { token, solutions } that passes proof-of-work, OR
 * 2) A pre-redeemed verified JWT token issued by validateCapChallenge.
 */
export async function verifyCapTokenPayload(
  tokenOrJson: string,
  secret: string
): Promise<CapValidationResult> {
  if (!tokenOrJson || !secret) {
    return { success: false, message: 'Missing token or secret' };
  }

  const trimmed = tokenOrJson.trim();

  // 1. Try JSON solution object { token, solutions } first if formatted as JSON
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && parsed.token && Array.isArray(parsed.solutions)) {
        return await validateCapChallenge(secret, parsed);
      }
    } catch {
      // Fall through to JWT parse
    }
  }

  // 2. Try to parse as pre-redeemed JWT token
  const payload = await jwtVerify(trimmed, secret);
  if (payload && payload.verified === true) {
    if (typeof payload.exp === 'number' && payload.exp < Date.now()) {
      return { success: false, message: 'Token has expired' };
    }
    return { success: true };
  }

  return { success: false, message: 'Cap token verification failed' };
}
