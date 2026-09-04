import { describe, it, expect } from 'vitest';
import { interpolateTargetUrl, buildDestinationUrl } from '../src/utils/url';
import { isSafeRedirectUrl, createTieredRedirectResponse } from '../src/utils/response';
import { safeCompare, hashPasswordWithSalt } from '../src/auth/basicAuth';
import { encryptData, decryptData } from '../src/utils/crypto';
import { createShortLinkHandler } from '../src/index';

describe('Security & Architectural Fixes Verification', () => {
  describe('URL Interpolation & Parameter Preservation', () => {
    it('safely handles wildcard replacements containing $ without regex backreference injection', () => {
      const target = 'https://store.example.com/item/*';
      // Wildcard match containing '$' like a price or coupon code: '$100_coupon'
      const matches = ['/promo/$100_coupon', '$100_coupon'];
      const result = interpolateTargetUrl(target, undefined, matches);

      expect(result).toBe('https://store.example.com/item/$100_coupon');
    });

    it('preserves multi-value query parameters instead of overwriting', () => {
      const incoming = new URL('https://short.link/search?tag=javascript&tag=cloudflare&sort=asc');
      const target = 'https://target.com/results';
      const destination = buildDestinationUrl(target, incoming);
      const parsed = new URL(destination);

      expect(parsed.searchParams.getAll('tag')).toEqual(['javascript', 'cloudflare']);
      expect(parsed.searchParams.get('sort')).toBe('asc');
    });

    it('blocks protocol-relative URLs (//attacker.com) to prevent open redirects', () => {
      expect(isSafeRedirectUrl('//attacker.com/steal')).toBe(false);
      expect(isSafeRedirectUrl('//google.com')).toBe(false);
      expect(isSafeRedirectUrl('https://example.com')).toBe(true);
      expect(isSafeRedirectUrl('/local-path')).toBe(true);
      expect(isSafeRedirectUrl('javascript:alert(1)')).toBe(false);
    });
  });

  describe('Constant-Time Comparison (safeCompare)', () => {
    it('accurately verifies matching strings and rejects different strings regardless of length', async () => {
      expect(await safeCompare('my-secret-password-123', 'my-secret-password-123')).toBe(true);
      expect(await safeCompare('short', 'a-much-longer-string-with-different-length')).toBe(false);
      expect(await safeCompare('', '')).toBe(true);
      expect(await safeCompare('abc', 'abd')).toBe(false);
    });
  });

  describe('Tiered Cache-Control', () => {
    it('sets public edge caching headers on standard public routes', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/public-link': 'https://example.com/public',
        },
      });

      const response = await handler(new Request('https://stevezmt.top/public-link'));
      expect(response.status).toBe(302);
      const cacheHeader = response.headers.get('Cache-Control');
      expect(cacheHeader).toContain('public');
      expect(cacheHeader).toContain('max-age');
    });

    it('sets strict no-cache/no-store on password-protected routes', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/secret': {
            target: 'https://example.com/secret',
            password: 'secret-pass-2026',
          },
        },
      });

      // 401 response
      const unauthRes = await handler(new Request('https://stevezmt.top/secret'));
      expect(unauthRes.status).toBe(401);
      expect(unauthRes.headers.get('Cache-Control')).toContain('no-store');

      // 302 response with valid credentials
      const authHeader = `Basic ${btoa('user:secret-pass-2026')}`;
      const authRes = await handler(
        new Request('https://stevezmt.top/secret', {
          headers: { Authorization: authHeader },
        })
      );
      expect(authRes.status).toBe(302);
      expect(authRes.headers.get('Cache-Control')).toContain('no-store');
    });

    it('allows public edge caching on passwordless encrypted routes (ROUTE_KEY protects routes from dumping)', async () => {
      const masterKey = 'master-key-xyz';
      const encryptedTarget = await encryptData('https://example.com/encrypted-target', masterKey);

      const handler = createShortLinkHandler({
        links: {
          '/vault': encryptedTarget,
        },
      });

      const response = await handler(new Request('https://stevezmt.top/vault'), {
        ROUTES_KEY: masterKey,
      });

      expect(response.status).toBe(302);
      expect(response.headers.get('Cache-Control')).toContain('public');
      expect(response.headers.get('Cache-Control')).not.toContain('no-store');
    });

    it('verifies strict alignment: ROUTES_KEY masks destination targets while visitor password is authenticated independently by Worker', async () => {
      // 1. ROUTES_KEY is used to mask the destination target (AES-GCM-256 with HKDF)
      const routesKey = 'my-super-secret-routes-key';
      const hiddenDestination = 'https://stevezmt.top/internal-admin-dashboard?ref=secret';
      const encryptedTarget = await encryptData(hiddenDestination, routesKey);

      // Verify the target is indeed masked as aes-gcm cipher
      expect(encryptedTarget).toMatch(/^aes-gcm:v1:/);
      expect(encryptedTarget).not.toContain('internal-admin-dashboard');

      // 2. Visitor access password is calculated as a salted hash and verified by the Worker
      const visitorPassword = 'Pass123_Visit!@#';
      const salt = 'stevezmt.top';
      const saltedHash = await hashPasswordWithSalt(visitorPassword, salt);

      // Route definition mirrors exactly what admin.html outputs to routes.ts
      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          salt,
        },
        links: {
          '/admin-portal': {
            target: encryptedTarget,
            password: `sha256:${saltedHash}`,
          },
        },
      });

      // Request A: Visiting without password returns 401 Unauthorized (Worker auth check)
      const unauthResponse = await handler(new Request('https://stevezmt.top/admin-portal'), {
        ROUTES_KEY: routesKey,
      });
      expect(unauthResponse.status).toBe(401);
      expect(unauthResponse.headers.get('WWW-Authenticate')).toContain('Basic realm=');

      // Request B: Visiting with wrong password returns 401
      const wrongAuthHeader = 'Basic ' + btoa('user:wrong-password');
      const badPassResponse = await handler(
        new Request('https://stevezmt.top/admin-portal', {
          headers: { Authorization: wrongAuthHeader },
        }),
        { ROUTES_KEY: routesKey }
      );
      expect(badPassResponse.status).toBe(401);

      // Request C: Visiting with correct password, but missing ROUTES_KEY returns 500 error
      // (Proving password auth succeeded, but destination target decryption requires ROUTES_KEY)
      const validAuthHeader = 'Basic ' + btoa(`visitor:${visitorPassword}`);
      const missingKeyResponse = await handler(
        new Request('https://stevezmt.top/admin-portal', {
          headers: { Authorization: validAuthHeader },
        }),
        {} // No ROUTES_KEY in environment
      );
      expect(missingKeyResponse.status).toBe(500);
      expect(await missingKeyResponse.text()).toContain('ROUTES_KEY is missing');

      // Request D: Visiting with correct password AND correct ROUTES_KEY succeeds:
      // decrypts destination and redirects, with strict no-cache because it is password protected
      const successResponse = await handler(
        new Request('https://stevezmt.top/admin-portal', {
          headers: { Authorization: validAuthHeader },
        }),
        { ROUTES_KEY: routesKey }
      );
      expect(successResponse.status).toBe(302);
      expect(successResponse.headers.get('Location')).toBe(hiddenDestination);
      // Because this route has password auth, it must NOT be cached on edge
      expect(successResponse.headers.get('Cache-Control')).toContain('no-store');
    });
  });

  describe('Route Normalization Consistency', () => {
    it('applies normalizePattern consistently to routes array as well as links object', async () => {
      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
        },
        routes: [
          {
            pattern: 's:/docs',
            target: 'https://stevezmt.top/documentation',
          },
        ],
      });

      // Visiting s.stevezmt.top/docs matches the route
      const response = await handler(new Request('https://s.stevezmt.top/docs'));
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toContain('https://stevezmt.top/documentation');
    });
  });

  describe('Robots.txt & Crawler Isolation', () => {
    it('serves /robots.txt disallowing all crawlers with 200 OK and long TTL cache', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/': 'https://stevezmt.top',
        },
      });

      const response = await handler(new Request('https://stevezmt.top/robots.txt'));
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/plain');
      expect(response.headers.get('X-Robots-Tag')).toBe('noindex, nofollow');

      const body = await response.text();
      expect(body).toContain('User-agent: *');
      expect(body).toContain('Disallow: /');
    });

    it('injects X-Robots-Tag: noindex, nofollow into all redirect responses', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/link': 'https://example.com/target',
        },
      });

      const response = await handler(new Request('https://stevezmt.top/link'));
      expect(response.status).toBe(302);
      expect(response.headers.get('X-Robots-Tag')).toBe('noindex, nofollow');
    });
  });

  describe('Password Exemption Flag (password: false)', () => {
    it('does not accidentally trigger unified password when password is explicitly set to false', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/open-link': {
            target: 'https://example.com/open',
            password: false, // Explicitly disabled
          },
        },
      });

      // Even if ROUTES_KEY exists in env, visitor should NOT be challenged with 401
      const response = await handler(new Request('https://stevezmt.top/open-link'), {
        ROUTES_KEY: 'master-super-password',
      });

      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toContain('https://example.com/open');
    });
  });

  describe('Referrer-Policy & Credential Sanitization', () => {
    it('injects Referrer-Policy: no-referrer on all redirect responses', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/test-ref': 'https://example.com/dest',
        },
      });

      const response = await handler(new Request('https://stevezmt.top/test-ref'));
      expect(response.status).toBe(302);
      expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
    });

    it('strips ?pwd= and ?password= parameters when resolving 404 URL templates', async () => {
      const handler = createShortLinkHandler({
        settings: {
          notFoundUrl: 'https://example.com/404?from=${FULL_URL}',
        },
        links: {},
      });

      const response = await handler(new Request('https://stevezmt.top/missing?pwd=secret-pass-123&user=john'));
      expect(response.status).toBe(404);
      const location = response.headers.get('Location') || '';
      expect(decodeURIComponent(location)).toContain('user=john');
      expect(location).not.toContain('secret-pass-123');
      expect(location).not.toContain('pwd=');
    });

    it('rejects protocol-relative target URLs in buildDestinationUrl', () => {
      expect(() => {
        buildDestinationUrl('//attacker.com/steal', new URL('https://stevezmt.top'));
      }).toThrow();
    });

    it('blocks bots case-insensitively', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/bot-check': {
            target: 'https://example.com/allowed',
            blockBots: true,
          },
        },
      });

      // Lowercase user agent should still be blocked
      const responseLower = await handler(
        new Request('https://stevezmt.top/bot-check', {
          headers: { 'User-Agent': 'go-http-client/1.1' },
        })
      );
      expect(responseLower.status).toBe(403);

      const responseBytespider = await handler(
        new Request('https://stevezmt.top/bot-check', {
          headers: { 'User-Agent': 'bytespider' },
        })
      );
      expect(responseBytespider.status).toBe(403);
    });
  });
});
