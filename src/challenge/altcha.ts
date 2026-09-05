/**
 * Edge-native Altcha Proof-of-Work generator and verifier using Web Crypto API.
 * Zero external network requests, sub-millisecond CPU execution time.
 */

import { AltchaChallenge, AltchaPayload, VerificationResult } from './types';

function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBuffer(hex: string): Uint8Array {
  const cleanHex = hex.trim();
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

async function hmacSha256Hex(secret: string, text: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(text));
  return bufferToHex(sigBuffer);
}

/**
 * Creates an Altcha PoW challenge directly in Worker runtime.
 */
export async function createAltchaChallenge(
  secret: string,
  maxNumber = 100000,
  expiresInSeconds = 300
): Promise<AltchaChallenge> {
  const randomBytes = crypto.getRandomValues(new Uint8Array(12));
  const randomSalt = bufferToHex(randomBytes.buffer);
  const expires = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const salt = `${randomSalt}?expires=${expires}`;

  // Random secret number between 0 and maxNumber
  const randomArr = new Uint32Array(1);
  crypto.getRandomValues(randomArr);
  const targetNumber = randomArr[0] % maxNumber;

  const challenge = await sha256Hex(salt + targetNumber);
  const signature = await hmacSha256Hex(secret, challenge);

  return {
    algorithm: 'SHA-256',
    challenge,
    salt,
    signature,
    maxnumber: maxNumber,
  };
}

/**
 * Verifies an Altcha payload submitted by the client widget.
 */
export async function verifyAltchaPayload(
  rawPayload: string,
  secret: string
): Promise<VerificationResult> {
  if (!rawPayload || !secret) {
    return { success: false, error: 'Missing Altcha payload or secret' };
  }

  let payload: AltchaPayload;
  try {
    let clean = rawPayload.trim();
    if (clean.includes('%')) {
      try {
        clean = decodeURIComponent(clean);
      } catch {
        // Keep original if URI decoding fails
      }
    }
    let jsonStr = '';
    if (clean.startsWith('{') && clean.endsWith('}')) {
      jsonStr = clean;
    } else {
      // Handle standard base64 or base64url
      const base64 = clean.replace(/-/g, '+').replace(/_/g, '/');
      jsonStr = atob(base64);
    }
    payload = JSON.parse(jsonStr);
  } catch {
    return { success: false, error: 'Invalid Altcha payload encoding' };
  }

  if (
    !payload.algorithm ||
    payload.algorithm !== 'SHA-256' ||
    !payload.challenge ||
    !payload.salt ||
    !payload.signature ||
    typeof payload.number !== 'number'
  ) {
    return { success: false, error: 'Malformed Altcha payload fields' };
  }

  // Check expiration if embedded in salt
  const expiresMatch = payload.salt.match(/[?&]expires=(\d+)/);
  if (expiresMatch) {
    const expires = parseInt(expiresMatch[1], 10);
    const now = Math.floor(Date.now() / 1000);
    if (now > expires) {
      return { success: false, error: 'Altcha challenge has expired' };
    }
  }

  // 1. Verify HMAC signature of challenge
  const expectedSignature = await hmacSha256Hex(secret, payload.challenge);
  if (expectedSignature.toLowerCase() !== payload.signature.toLowerCase()) {
    return { success: false, error: 'Altcha challenge signature mismatch' };
  }

  // 2. Verify PoW solution: SHA-256(salt + number) === challenge
  const calculatedChallenge = await sha256Hex(payload.salt + payload.number);
  if (calculatedChallenge.toLowerCase() !== payload.challenge.toLowerCase()) {
    return { success: false, error: 'Altcha challenge PoW solution invalid' };
  }

  return { success: true };
}
