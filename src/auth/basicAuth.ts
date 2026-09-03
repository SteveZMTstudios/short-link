/**
 * HTTP Basic Authentication handler with salted SHA-256 support.
 * Validates credentials against route configuration and produces RFC-compliant 401 responses.
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
 * Parses and verifies Basic Auth credentials from incoming Request.
 * Supports:
 * - Unified master password (from env.AUTH_PASSWORD or env.ROUTES_KEY)
 * - Domain-salted SHA-256 hashes ('sha256:<hex>' or passwordHash)
 * - Plaintext passwords (for backwards compatibility)
 */
/**
 * Verifies a single password string against the provided route AuthConfig.
 * Used by both HTTP Basic Auth and the standalone web password unlock form.
 */
export async function verifyPassword(
  password: string,
  config: AuthConfig,
  defaultSalt = '',
  unifiedPassword?: string,
  username?: string
): Promise<boolean> {
  const salt = config.salt || defaultSalt;

  // 1. Unified password check (if route enabled unified password from .env)
  if (config.useUnifiedPassword || (config.password === undefined && !config.passwordHash && !config.users)) {
    if (unifiedPassword) {
      if (await safeCompare(password, unifiedPassword)) {
        return true;
      }
      const calculatedHash = await hashPasswordWithSalt(password, salt);
      if (await safeCompare(calculatedHash, unifiedPassword.replace(/^sha256:/i, '').toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  // 2. Explicit passwordHash check
  if (config.passwordHash !== undefined) {
    const cleanExpected = config.passwordHash.replace(/^sha256:/i, '').toLowerCase();
    const calculatedHash = await hashPasswordWithSalt(password, salt);
    if (await safeCompare(calculatedHash, cleanExpected)) {
      return true;
    }
  }

  // 3. Single password check (supports 'sha256:<hex>' or plaintext)
  if (config.password !== undefined) {
    if (config.password.toLowerCase().startsWith('sha256:')) {
      const cleanExpected = config.password.slice(7).toLowerCase();
      const calculatedHash = await hashPasswordWithSalt(password, salt);
      if (await safeCompare(calculatedHash, cleanExpected)) {
        return true;
      }
    } else {
      if (await safeCompare(password, config.password)) {
        return true;
      }
    }
  }

  // 4. Multi-user dictionary check
  if (config.users && username && Object.prototype.hasOwnProperty.call(config.users, username)) {
    const expected = config.users[username];
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

  return false;
}

/**
 * Parses and verifies Basic Auth credentials from incoming Request.
 */
export async function verifyBasicAuth(
  request: Request,
  config: AuthConfig,
  defaultSalt = '',
  unifiedPassword?: string
): Promise<boolean> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false;
  }

  const base64Credentials = authHeader.slice(6).trim();
  let decoded: string;
  try {
    decoded = atob(base64Credentials);
  } catch {
    return false;
  }

  const separatorIndex = decoded.indexOf(':');
  if (separatorIndex === -1) {
    return false;
  }

  const username = decoded.substring(0, separatorIndex);
  const password = decoded.substring(separatorIndex + 1);

  return verifyPassword(password, config, defaultSalt, unifiedPassword, username);
}

/**
 * Creates an RFC-compliant HTTP 401 Unauthorized response with WWW-Authenticate header.
 */
export function createUnauthorizedResponse(realm = 'Protected Link'): Response {
  // HTTP header values must be ByteString (ASCII <= 255)
  const asciiRealm = realm.replace(/[^\x20-\x7E]/g, '').trim() || 'Protected Link';
  const safeRealm = asciiRealm.replace(/"/g, '\\"');
  return new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1><p>This link is password protected.</p></body></html>`,
    {
      status: 401,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'WWW-Authenticate': `Basic realm="${safeRealm}", charset="UTF-8"`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    }
  );
}

/**
 * Creates a minimal standalone HTML password unlock response.
 * Uses native browser prompt() when JS is enabled, and falls back to a clean,
 * unstyled semantic HTML form when JS is disabled or prompt is dismissed.
 * Zero bloated CSS, zero icons, zero theme maintenance.
 */
export function createPasswordPromptResponse(options: {
  errorMessage?: string;
  realm?: string;
} = {}): Response {
  const errorHtml = options.errorMessage
    ? `<p style="color:#dc2626;">${options.errorMessage}</p>`
    : '';

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>受保护的短链接</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto; max-width: 360px; padding: 0 1rem; }
    form { display: flex; flex-direction: column; gap: 0.75rem; }
    input, button { font-size: 1rem; padding: 0.5rem; box-sizing: border-box; }
  </style>
</head>
<body>
  <h3>受保护的短链接</h3>
  <p>${options.realm || '请输入访问密码：'}</p>
  ${errorHtml}
  <form method="POST">
    <input type="password" name="password" autofocus required placeholder="访问密码">
    <button type="submit">前往</button>
  </form>
  <script>
    (function() {
      var p = prompt("请输入访问密码：");
      if (p) {
        var f = document.forms[0];
        f.password.value = p;
        f.submit();
      }
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    status: 401,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
}
