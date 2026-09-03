import { describe, it, expect } from 'vitest';
import { interpolateTargetUrl, buildDestinationUrl } from '../src/utils/url';
import { isSafeRedirectUrl, createTieredRedirectResponse } from '../src/utils/response';
import { safeCompare } from '../src/auth/basicAuth';
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

    it('sets strict no-cache/no-store on encrypted destination routes', async () => {
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
      expect(response.headers.get('Cache-Control')).toContain('no-store');
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

      // Even if ROUTES_KEY / AUTH_PASSWORD exists in env, visitor should NOT be challenged with 401
      const response = await handler(new Request('https://stevezmt.top/open-link'), {
        ROUTES_KEY: 'master-super-password',
      });

      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toContain('https://example.com/open');
    });
  });
});
