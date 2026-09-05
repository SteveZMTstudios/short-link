/**
 * Lightweight HMAC-signed Clearance Cookie generator and validator.
 * Provides optional temporary exemption from repeated challenges when clearanceDuration > 0.
 */

const CLEARANCE_COOKIE_NAME = '__shortlink_clearance';

function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

async function hmacSha256(secret: string, text: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(text));
  return bufferToHex(sig);
}

/**
 * Creates a Set-Cookie header string for clearance.
 */
export async function createClearanceCookie(
  secret: string,
  durationSeconds: number
): Promise<string> {
  const expires = Math.floor(Date.now() / 1000) + durationSeconds;
  const sig = await hmacSha256(secret, String(expires));
  const val = `${expires}.${sig}`;
  return `${CLEARANCE_COOKIE_NAME}=${val}; Path=/; Max-Age=${durationSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

/**
 * Checks whether a request contains a valid and unexpired clearance cookie.
 */
export async function hasValidClearance(
  request: Request,
  secret: string
): Promise<boolean> {
  if (!secret) return false;

  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const cookies = cookieHeader.split(';');
  let clearanceVal: string | undefined;

  for (const c of cookies) {
    const [k, ...v] = c.trim().split('=');
    if (k === CLEARANCE_COOKIE_NAME) {
      clearanceVal = v.join('=');
      break;
    }
  }

  if (!clearanceVal) return false;

  const parts = clearanceVal.split('.');
  if (parts.length !== 2) return false;

  const [expiresStr, sig] = parts;
  const expires = parseInt(expiresStr, 10);
  if (isNaN(expires)) return false;

  const now = Math.floor(Date.now() / 1000);
  if (now > expires) return false;

  const expectedSig = await hmacSha256(secret, expiresStr);
  return expectedSig.toLowerCase() === sig.toLowerCase();
}
