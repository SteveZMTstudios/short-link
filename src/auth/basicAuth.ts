/**
 * HTTP Basic Authentication handler with salted SHA-256 support.
 * Validates credentials against route configuration and produces RFC-compliant 401 responses.
 *
 * Design:
 * - RFC 7617 HTTP Basic Auth only (zero custom HTML prompt pages or JS prompts)
 * - Ignores username; only validates password field
 * - Informs visitor in the WWW-Authenticate realm that username can be anything
 * - Constant-time comparison to prevent timing attacks
 * - Pure cryptographic hash verification (raw hash inputs cannot authenticate)
 */

import { AuthConfig } from '../types';

/**
 * Constant-time comparison helper to mitigate timing attacks.
 * Hashes both inputs to fixed 32-byte SHA-256 digests before XOR comparison,
 * ensuring comparisons take identical time regardless of input string lengths.
 */
export async function safeCompare(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const hashA = await crypto.subtle.digest('SHA-256', encoder.encode(a));
  const hashB = await crypto.subtle.digest('SHA-256', encoder.encode(b));
  const bufA = new Uint8Array(hashA);
  const bufB = new Uint8Array(hashB);
  let result = 0;
  for (let i = 0; i < 32; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

/**
 * Computes a SHA-256 hash of (password + ":" + salt) using native Web Crypto API.
 */
export async function hashPasswordWithSalt(password: string, salt = ''): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${password}:${salt}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Decodes base64 credentials supporting standard UTF-8 (RFC 7617 section 2.1).
 * Prevents Latin-1 byte truncation or corruption on multi-byte international passwords.
 */
export function decodeBase64Utf8(base64: string): string {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    // Fallback to Latin-1 binary string if invalid UTF-8
    return binary;
  }
}

/**
 * Verifies a single password string against the provided route AuthConfig.
 * Strictly prevents submitting raw hashes: if expected is a hash, input password MUST be hashed.
 */
export async function verifyPassword(
  password: string,
  config: AuthConfig,
  defaultSalt = '',
  masterPassword?: string
): Promise<boolean> {
  const salt = config.salt || defaultSalt;

  // 1. Explicit passwordHash check ('sha256:<hex>' or raw hex)
  if (config.passwordHash !== undefined) {
    const cleanExpected = config.passwordHash.replace(/^sha256:/i, '').toLowerCase();
    const calculatedHash = await hashPasswordWithSalt(password, salt);
    return safeCompare(calculatedHash, cleanExpected);
  }

  // 2. Password check (supports 'sha256:<hex>' hash or plaintext)
  if (config.password !== undefined) {
    if (config.password.toLowerCase().startsWith('sha256:')) {
      const cleanExpected = config.password.slice(7).toLowerCase();
      const calculatedHash = await hashPasswordWithSalt(password, salt);
      return safeCompare(calculatedHash, cleanExpected);
    }
    // Plaintext password comparison
    if (await safeCompare(password, config.password)) {
      return true;
    }
  }

  // 3. Multi-user dictionary check (username ignored: validates password against any configured user)
  if (config.users && typeof config.users === 'object') {
    for (const expected of Object.values(config.users)) {
      if (typeof expected === 'string') {
        if (expected.toLowerCase().startsWith('sha256:')) {
          const cleanExpected = expected.slice(7).toLowerCase();
          const calculatedHash = await hashPasswordWithSalt(password, salt);
          if (await safeCompare(calculatedHash, cleanExpected)) {
            return true;
          }
        } else {
          if (await safeCompare(password, expected)) {
            return true;
          }
        }
      }
    }
  }

  // 4. Master password check (for routes configured with password: true or useMasterPassword: true)
  if (config.useMasterPassword || (config.password === undefined && config.passwordHash === undefined && !config.users)) {
    if (masterPassword) {
      if (masterPassword.toLowerCase().startsWith('sha256:')) {
        const cleanExpected = masterPassword.slice(7).toLowerCase();
        const calculatedHash = await hashPasswordWithSalt(password, salt);
        if (await safeCompare(calculatedHash, cleanExpected)) {
          return true;
        }
      } else {
        if (await safeCompare(password, masterPassword)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Parses and verifies Basic Auth credentials from incoming Request.
 * Usernames are completely ignored; only the password field is validated.
 */
export async function verifyBasicAuth(
  request: Request,
  config: AuthConfig,
  defaultSalt = '',
  masterPassword?: string
): Promise<boolean> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false;
  }

  const base64Credentials = authHeader.slice(6).trim();
  let decoded: string;
  try {
    decoded = decodeBase64Utf8(base64Credentials);
  } catch {
    return false;
  }

  const separatorIndex = decoded.indexOf(':');
  // Username is ignored per design: only password part is evaluated
  const password = separatorIndex !== -1 ? decoded.substring(separatorIndex + 1) : decoded;

  return verifyPassword(password, config, defaultSalt, masterPassword);
}

/**
 * Creates an RFC-compliant HTTP 401 Unauthorized response with WWW-Authenticate header.
 * Realm clearly communicates to visitor that username is ignored and only password is required.
 */
export function createUnauthorizedResponse(realm?: string): Response {
  const baseRealm = realm ? realm.trim() : 'Protected Link';
  const displayRealm = `${baseRealm} (Password required, username ignored)`;
  // HTTP header values must be ByteString (ASCII <= 255)
  const asciiRealm = displayRealm.replace(/[^\x20-\x7E]/g, '').trim() || 'Protected Link - Password Required';
  const safeRealm = asciiRealm.replace(/"/g, '\\"');

  return new Response(
    '401 Unauthorized: Password required. Username is ignored and can be left blank or set to anything.\n',
    {
      status: 401,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'WWW-Authenticate': `Basic realm="${safeRealm}", charset="UTF-8"`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    }
  );
}

/**
 * Deep Module: Authenticates an incoming request for a protected route.
 * Checks Basic Auth header and optional ?pwd=/ ?password= query fallback.
 */
export async function authenticateRequest(
  request: Request,
  url: URL,
  config: AuthConfig,
  defaultSalt = '',
  masterPassword?: string
): Promise<{ authenticated: boolean; response?: Response }> {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Basic ')) {
    const ok = await verifyBasicAuth(request, config, defaultSalt, masterPassword);
    if (ok) {
      return { authenticated: true };
    }
  }

  // Convenience query param fallback: ?pwd= or ?password=
  const queryPwd = url.searchParams.get('pwd') || url.searchParams.get('password');
  if (queryPwd) {
    const ok = await verifyPassword(queryPwd, config, defaultSalt, masterPassword);
    if (ok) {
      return { authenticated: true };
    }
  }

  return {
    authenticated: false,
    response: createUnauthorizedResponse(config.realm),
  };
}
