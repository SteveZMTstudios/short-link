import { describe, it, expect } from 'vitest';
import { createShortLinkHandler } from '../src/index';
import { matchesPattern, findMatchingRoute } from '../src/router/matcher';
import { interpolateTargetUrl, buildDestinationUrl } from '../src/utils/url';
import { isSafeRedirectUrl } from '../src/utils/response';

describe('Edge Cases & Design Flaw Reproduction Tests', () => {
  describe('1. Path-based Regular Expression Routing', () => {
    it('should match path-based regex patterns starting with /', () => {
      const url = new URL('https://example.com/api/v2/users');
      // A route regex specifying only the path
      const matched = matchesPattern('regex:^/api/v\\d+/(.*)$', url);
      expect(matched).toBe(true);
    });

    it('should resolve and capture path groups from path regex in findMatchingRoute', () => {
      const routes = [
        {
          pattern: 'regex:^/item/(\\d+)$',
          target: 'https://store.example.com/product/$1',
        },
      ];
      const url = new URL('https://example.com/item/42');
      const match = findMatchingRoute(routes, url);
      expect(match).not.toBeNull();
      expect(match?.target).toBe('https://store.example.com/product/$1');
      expect(match?.matches[1]).toBe('42');
    });
  });

  describe('2. Wildcard Subdomain Routing & Target Substitution', () => {
    it('substitutes path wildcard into target instead of subdomain for *.domain/*', () => {
      // In pattern *.domain.com/*, group 1 is subdomain, group 2 is path
      // Target with '*' should receive the path, NOT the subdomain!
      const matches = ['sub.domain.com/hello/world', 'sub', 'hello/world'];
      const target = 'https://dest.example.com/*';

      const interpolated = interpolateTargetUrl(target, undefined, matches);
      expect(interpolated).toBe('https://dest.example.com/hello/world');
    });

    it('end-to-end: *.domain.com/* redirects with path preserved in handler', async () => {
      const handler = createShortLinkHandler({
        routes: [
          {
            pattern: '*.stevezmt.top/*',
            target: 'https://cdn.example.com/*',
          },
        ],
      });

      const response = await handler(
        new Request('https://assets.stevezmt.top/images/logo.png')
      );
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toBe(
        'https://cdn.example.com/images/logo.png'
      );
    });
  });

  describe('3. Dynamic Parameter Query Injection & Special Characters', () => {
    it('properly encodes named parameters interpolated into URL query strings', () => {
      const incoming = new URL('https://short.link/search/hello%20world%26filter%3D1');
      const target = 'https://search.engine.com/?q=:keyword';
      const params = { keyword: 'hello world&filter=1' };

      const destination = buildDestinationUrl(target, incoming, undefined, params);
      const destUrl = new URL(destination);

      // The query param 'q' should have the full string without creating an extra 'filter' query param!
      expect(destUrl.searchParams.get('q')).toBe('hello world&filter=1');
      expect(destUrl.searchParams.has('filter')).toBe(false);
    });
  });

  describe('4. Define Errors Out of Existence: Malformed Target URLs', () => {
    it('gracefully falls back to 404 instead of throwing 500 when target is invalid', async () => {
      const handler = createShortLinkHandler({
        routes: [
          {
            pattern: '/broken-link',
            target: 'http://[invalid-url-with-brackets',
          },
        ],
      });

      // Should not throw unhandled exception and should not return 500
      const response = await handler(new Request('https://stevezmt.top/broken-link'));
      expect(response.status).toBe(404); // falls back to 404 without 500 crash
      expect(response.headers.get('Location')).toBeNull();
    });
  });

  describe('5. App Deep Links & Custom URL Schemes', () => {
    it('allows safe standard deep link schemes like tg://, mailto:, weixin://', () => {
      expect(isSafeRedirectUrl('tg://resolve?domain=stevezmt')).toBe(true);
      expect(isSafeRedirectUrl('mailto:contact@stevezmt.top')).toBe(true);
      expect(isSafeRedirectUrl('weixin://dl/business/?t=123')).toBe(true);

      // Malicious pseudo-protocols must still be blocked
      expect(isSafeRedirectUrl('javascript:alert(1)')).toBe(false);
      expect(isSafeRedirectUrl('data:text/html;base64,...')).toBe(false);
      expect(isSafeRedirectUrl('vbscript:msgbox')).toBe(false);
    });
  });

  describe('6. HTTP Redirection Specification for Form POST (RFC 7231)', () => {
    it('uses 303 See Other for redirecting browser POST password unlocking', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/private': {
            target: 'https://example.com/secret',
            password: 'pass',
          },
        },
      });

      const form = new FormData();
      form.set('password', 'pass');

      const response = await handler(
        new Request('https://stevezmt.top/private', {
          method: 'POST',
          body: form,
        })
      );

      // RFC 7231 Section 6.4.4: 303 See Other guarantees client switches to GET
      expect(response.status).toBe(303);
      expect(response.headers.get('Location')).toBe('https://example.com/secret');
    });
  });
});
