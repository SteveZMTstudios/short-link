import { describe, it, expect, vi } from 'vitest';
import { createShortLinkHandler, resolveMasterKey } from '../src/index';
import {
  decodeBase64Utf8,
  verifyPassword,
  verifyBasicAuth,
  authenticateRequest,
  createUnauthorizedResponse,
} from '../src/auth/basicAuth';
import {
  compilePattern,
  compileRoute,
  matchCompiledRoute,
  getRouteSpecificity,
  matchesPattern,
} from '../src/router/matcher';
import { KvRouteProvider } from '../src/router/provider';
import {
  matchHeader,
  blockUserAgent,
  chainRules,
  Actions,
} from '../src/rules/predicates';
import { encryptData, decryptData } from '../src/utils/crypto';
import {
  interpolateTargetUrl,
  buildDestinationUrl,
  resolveUrlTemplate,
} from '../src/utils/url';
import { createTieredRedirectResponse } from '../src/utils/response';

describe('Comprehensive Security & Coverage Audit Test Suite', () => {
  describe('1. basicAuth UTF-8 & Master Password Enhancements', () => {
    it('decodes UTF-8 Base64 strings including Chinese and emojis accurately', () => {
      // 'user:密码🎉2026'
      const raw = 'user:密码🎉2026';
      const encoded = btoa(unescape(encodeURIComponent(raw)));
      expect(decodeBase64Utf8(encoded)).toBe(raw);

      // Fallback on invalid UTF-8 bytes
      const invalidUtf8 = btoa('\xFF\xFE\xFD');
      expect(decodeBase64Utf8(invalidUtf8)).toBe('\xFF\xFE\xFD');
    });

    it('verifies non-ASCII UTF-8 Basic Auth password end-to-end', async () => {
      const handler = createShortLinkHandler({
        settings: { domain: 'stevezmt.top' },
        links: {
          '/chinese-pass': {
            target: 'https://example.com/vault',
            password: '测试密码2026',
          },
        },
      });

      const authHeader = `Basic ${btoa(unescape(encodeURIComponent('anyone:测试密码2026')))}`;
      const res = await handler(
        new Request('https://stevezmt.top/chinese-pass', {
          headers: { Authorization: authHeader },
        })
      );
      expect(res.status).toBe(302);
      expect(res.headers.get('Location')).toContain('https://example.com/vault');
    });

    it('verifies config.users with sha256: hashed passwords', async () => {
      const handler = createShortLinkHandler({
        settings: { domain: 'stevezmt.top' },
        links: {
          '/multi-user-hash': {
            target: 'https://example.com/vault',
            auth: {
              users: {
                // SHA-256('hashpass1:stevezmt.top')
                user1: 'sha256:7ce5bb06ad8953bccc9a7111097cc567362a17b2b0400dff5a8bd848ec6e183e',
              },
            },
          },
        },
      });

      // Correct password
      const goodAuth = `Basic ${btoa('user1:hashpass1')}`;
      const resGood = await handler(
        new Request('https://stevezmt.top/multi-user-hash', {
          headers: { Authorization: goodAuth },
        })
      );
      expect(resGood.status).toBe(302);

      // Incorrect password
      const badAuth = `Basic ${btoa('user1:wrongpass')}`;
      const resBad = await handler(
        new Request('https://stevezmt.top/multi-user-hash', {
          headers: { Authorization: badAuth },
        })
      );
      expect(resBad.status).toBe(401);
    });

    it('verifyBasicAuth directly rejects missing or malformed Authorization headers', async () => {
      const config = { password: 'test-password' };
      // Missing header
      const reqNoAuth = new Request('https://example.com/test');
      expect(await verifyBasicAuth(reqNoAuth, config)).toBe(false);

      // Non-Basic scheme (e.g. Bearer)
      const reqBearer = new Request('https://example.com/test', {
        headers: { Authorization: 'Bearer my-token' },
      });
      expect(await verifyBasicAuth(reqBearer, config)).toBe(false);

      // Malformed Base64 string
      const reqMalformed = new Request('https://example.com/test', {
        headers: { Authorization: 'Basic !!!invalid-base64!!!' },
      });
      expect(await verifyBasicAuth(reqMalformed, config)).toBe(false);
    });

    it('authenticates using masterPassword when useMasterPassword is true (e.g. password: true)', async () => {
      const handler = createShortLinkHandler({
        settings: { domain: 'stevezmt.top' },
        links: {
          '/unified-protected': {
            target: 'https://example.com/protected-page',
            password: true, // Enables master password auth
          },
        },
      });

      const masterKey = 'global-master-secret-2026';

      // 1. Without credentials -> 401
      const resNoAuth = await handler(
        new Request('https://stevezmt.top/unified-protected'),
        { ROUTES_KEY: masterKey }
      );
      expect(resNoAuth.status).toBe(401);

      // 2. With correct master credentials via Basic Auth -> 302
      const resGood = await handler(
        new Request('https://stevezmt.top/unified-protected', {
          headers: { Authorization: `Basic ${btoa(`ignored:${masterKey}`)}` },
        }),
        { ROUTES_KEY: masterKey }
      );
      expect(resGood.status).toBe(302);

      // 3. With query param ?pwd=masterKey -> 302
      const resQuery = await handler(
        new Request(`https://stevezmt.top/unified-protected?pwd=${masterKey}`),
        { ROUTES_KEY: masterKey }
      );
      expect(resQuery.status).toBe(302);

      // 4. With sha256-hashed masterPassword
      // SHA-256('hashmaster:stevezmt.top')
      const hashedMaster = 'sha256:b0819490c56a5c2f7ef4050bbf95eb40757972b96655e861c9a3da96bd082937';
      const resHashedMaster = await handler(
        new Request('https://stevezmt.top/unified-protected?pwd=hashmaster'),
        { AUTH_PASSWORD: hashedMaster }
      );
      expect(resHashedMaster.status).toBe(302);

      // 5. Without master password in env -> 401
      const resNoEnv = await handler(
        new Request('https://stevezmt.top/unified-protected?pwd=anypass'),
        {}
      );
      expect(resNoEnv.status).toBe(401);
    });
  });

  describe('2. index.ts Error Branches & Cache-Control Hardening', () => {
    it('returns 500 when encrypted config payload is corrupted', async () => {
      const handler = createShortLinkHandler({
        encrypted: 'aes-gcm:v1:corrupted-payload-data',
      });

      const res = await handler(new Request('https://example.com/test'), {
        ROUTES_KEY: 'test-key',
      });
      expect(res.status).toBe(500);
      expect(await res.text()).toContain('Configuration Decryption Error');
    });

    it('returns 500 when individual target is encrypted but ROUTES_KEY is missing', async () => {
      const masterKey = 'key-123';
      const encryptedTarget = await encryptData('https://example.com/dest', masterKey);
      const handler = createShortLinkHandler({
        links: {
          '/vault': encryptedTarget,
        },
      });

      const res = await handler(new Request('https://example.com/vault'), {});
      expect(res.status).toBe(500);
      expect(await res.text()).toContain('ROUTES_KEY is missing');
    });

    it('returns 500 when individual target is encrypted but ROUTES_KEY is incorrect', async () => {
      const masterKey = 'key-123';
      const encryptedTarget = await encryptData('https://example.com/dest', masterKey);
      const handler = createShortLinkHandler({
        links: {
          '/vault': encryptedTarget,
        },
      });

      const res = await handler(new Request('https://example.com/vault'), {
        ROUTES_KEY: 'wrong-key-456',
      });
      expect(res.status).toBe(500);
      expect(await res.text()).toContain('Failed to decrypt destination target');
    });

    it('allows public edge cache when encrypted target has mobile redirection but no password, and forbids cache when password protected', async () => {
      const masterKey = 'key-123';
      const encryptedTarget = await encryptData('https://example.com/desktop-dest', masterKey);
      const handler = createShortLinkHandler({
        links: {
          '/mobile-vault': {
            target: encryptedTarget,
            mobile: 'https://example.com/mobile-dest',
          },
          '/mobile-vault-auth': {
            target: encryptedTarget,
            mobile: 'https://example.com/mobile-dest',
            password: 'sha256:custom-hash',
          },
        },
      });

      // Desktop access without password: edge-cacheable
      const resDesktop = await handler(
        new Request('https://example.com/mobile-vault', {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        }),
        { ROUTES_KEY: masterKey }
      );
      expect(resDesktop.status).toBe(302);
      expect(resDesktop.headers.get('Location')).toContain('desktop-dest');
      expect(resDesktop.headers.get('Cache-Control')).toContain('public');
      expect(resDesktop.headers.get('Cache-Control')).not.toContain('no-store');

      // Route with password: must NOT be cached
      const resAuth = await handler(
        new Request('https://example.com/mobile-vault-auth', {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            Authorization: 'Basic ' + btoa('user:test'),
          },
        }),
        { ROUTES_KEY: masterKey }
      );
      expect(resAuth.headers.get('Cache-Control')).toContain('no-store');
    });

    it('handles 404 with empty/whitespace target and prevents proxy recursion', async () => {
      // 1. Whitespace notFoundUrl returns default 404 response
      const handlerEmpty404 = createShortLinkHandler({
        settings: { notFoundUrl: '   ' },
        links: {},
      });
      const resEmpty = await handlerEmpty404(new Request('https://example.com/missing'));
      expect(resEmpty.status).toBe(404);
      expect(resEmpty.headers.get('Location')).toBeNull();

      // 2. Proxy mode prevents recursive loop when X-ShortLink-Proxy is received
      const handlerLoop = createShortLinkHandler({
        notFound: {
          target: 'https://example.com/404',
          mode: 'proxy',
        },
      });
      const resLoop = await handlerLoop(
        new Request('https://example.com/missing', {
          headers: { 'X-ShortLink-Proxy': '1' },
        })
      );
      expect(resLoop.status).toBe(404);
      expect(resLoop.headers.get('Location')).toBeNull();

      // 3. Proxy fetch failure falls back to 404 tiered redirect
      const origFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
      try {
        const handlerFetchErr = createShortLinkHandler({
          notFound: {
            target: 'https://stevezmt.top/404?from=${FULL_URL}',
            mode: 'proxy',
          },
        });
        const resErr = await handlerFetchErr(new Request('https://example.com/missing'));
        expect(resErr.status).toBe(404);
        expect(resErr.headers.get('Location')).toContain('/404?from=');
      } finally {
        globalThis.fetch = origFetch;
      }
    });
  });

  describe('3. Router & Matcher Robustness & Safety', () => {
    it('appends /* when host pattern has no slash', () => {
      const compiled = compilePattern('example.com');
      expect(compiled.isHostSpecific).toBe(true);
      expect(compiled.regex.test('example.com/any/path')).toBe(true);
    });

    it('normalizes patterns ending in slash (e.g. /docs/)', () => {
      const compiled = compilePattern('/docs/');
      expect(compiled.regex.test('/docs')).toBe(true);
      expect(compiled.regex.test('/docs/')).toBe(true);
    });

    it('safely compiles duplicate parameter names without throwing SyntaxError', () => {
      // /:slug/:slug shouldn't crash
      const compiled = compileRoute({ pattern: '/:slug/:slug', target: '' });
      expect(compiled.paramNames).toEqual(['slug', 'slug']);
      const match = matchCompiledRoute(compiled, new URL('https://example.com/cat/dog'));
      expect(match).not.toBeNull();
      expect(match?.params.slug).toBe('dog');
    });

    it('safely handles malformed regex patterns from KV/config without crashing', () => {
      // regex:[unclosed should not throw SyntaxError
      const compiled = compilePattern('regex:[unclosed');
      expect(compiled.regex).toBeDefined();
      expect(compiled.regex.test('anything')).toBe(false);
    });

    it('compileRoute normalizes subdomain shorthand s:/docs directly', () => {
      const route = compileRoute({
        pattern: 's:/docs',
        target: 'https://example.com/docs',
      });
      expect(route.pattern).toContain('s.*');
      expect(route.isHostSpecific).toBe(true);
    });

    it('matchesPattern handles positional fallback correctly', () => {
      expect(matchesPattern('/items/:id', new URL('https://example.com/items/123'))).toBe(true);
    });
  });

  describe('4. Provider Error Handling & Graceful Fallbacks', () => {
    it('KvRouteProvider falls back to defaultStaticConfig when KV is missing and no fallbackConfig', async () => {
      const provider = new KvRouteProvider();
      const routes = await provider.getRoutes();
      expect(routes).toBeDefined();
      expect((routes as any).links?.['/']).toBe('https://stevezmt.top');
    });

    it('KvRouteProvider returns parsed JSON directly when fallbackConfig is omitted', async () => {
      const mockKv = {
        get: vi.fn().mockResolvedValue(
          JSON.stringify({
            links: { '/dynamic': 'https://example.com/dynamic' },
          })
        ),
      };

      const provider = new KvRouteProvider();
      const routes = await provider.getRoutes({
        env: { SHORT_LINK_KV: mockKv as unknown as KVNamespace },
      });
      expect((routes as any).links?.['/dynamic']).toBe('https://example.com/dynamic');
    });

    it('KvRouteProvider gracefully catches JSON parse errors in KV and returns fallback', async () => {
      const mockKv = {
        get: vi.fn().mockResolvedValue('INVALID_JSON_CONTENT{{{'),
      };

      const provider = new KvRouteProvider({
        fallbackConfig: { links: { '/fallback': 'https://fallback.com' } },
      });
      const routes = await provider.getRoutes({
        env: { SHORT_LINK_KV: mockKv as unknown as KVNamespace },
      });
      expect((routes as any).links?.['/fallback']).toBe('https://fallback.com');
    });
  });

  describe('5. Rules & Predicates Full Coverage', () => {
    it('matchHeader supports string, RegExp, function matchers, and non-matching fallbacks', () => {
      const ctxWithHeader = {
        request: new Request('https://example.com', {
          headers: { 'X-Custom-Header': 'SecretValue' },
        }),
      } as any;

      const ctxWithoutHeader = {
        request: new Request('https://example.com'),
      } as any;

      // 1. String matcher (case-insensitive)
      const ruleStr = matchHeader('X-Custom-Header', 'secretvalue', Actions.block(403));
      expect((ruleStr(ctxWithHeader) as any).type).toBe('block');
      expect((ruleStr(ctxWithoutHeader) as any).type).toBe('pass');

      // 2. RegExp matcher
      const ruleRegex = matchHeader('X-Custom-Header', /^secret/i, Actions.block(403));
      expect((ruleRegex(ctxWithHeader) as any).type).toBe('block');
      expect((ruleRegex(ctxWithoutHeader) as any).type).toBe('pass');

      // 3. Function matcher
      const ruleFunc = matchHeader(
        'X-Custom-Header',
        (val) => val === 'SecretValue',
        Actions.block(403)
      );
      expect((ruleFunc(ctxWithHeader) as any).type).toBe('block');
      expect((ruleFunc(ctxWithoutHeader) as any).type).toBe('pass');
    });

    it('blockUserAgent supports RegExp patterns', () => {
      const rule = blockUserAgent([/BadBot/i, /SpamCrawler/]);
      const ctxBad = {
        request: new Request('https://example.com', {
          headers: { 'User-Agent': 'Mozilla/5.0 badbot/3.0' },
        }),
      } as any;
      const ctxGood = {
        request: new Request('https://example.com', {
          headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' },
        }),
      } as any;

      expect((rule(ctxBad) as any).type).toBe('block');
      expect((rule(ctxGood) as any).type).toBe('pass');
    });

    it('chainRules stops at first blocking or redirecting rule, or passes if all pass', async () => {
      const ctx = { request: new Request('https://example.com') } as any;

      // Chain that blocks
      const chainBlock = chainRules(
        () => Actions.pass(),
        () => Actions.block(403, 'Denied'),
        () => Actions.redirect('https://never-reached.com')
      );
      const resBlock = await chainBlock(ctx);
      expect((resBlock as any).type).toBe('block');
      expect((resBlock as any).body).toBe('Denied');

      // Chain that redirects
      const chainRedirect = chainRules(
        () => Actions.pass(),
        () => Actions.redirect('https://example.com/redirect')
      );
      const resRedirect = await chainRedirect(ctx);
      expect((resRedirect as any).type).toBe('redirect');

      // Chain that passes
      const chainPass = chainRules(
        () => Actions.pass(),
        () => Actions.pass()
      );
      const resPass = await chainPass(ctx);
      expect((resPass as any).type).toBe('pass');
    });
  });

  describe('6. Crypto Error Handling', () => {
    it('throws when encryptData is called with empty password', async () => {
      await expect(encryptData('data', '')).rejects.toThrow('Encryption password cannot be empty');
    });

    it('throws when decryptData is called with empty password', async () => {
      await expect(decryptData('aes-gcm:v1:...', '')).rejects.toThrow('Decryption password cannot be empty');
    });

    it('throws when decryptData is called with malformed base64 payload', async () => {
      await expect(decryptData('aes-gcm:v1:!@#$invalid-base64!', 'password')).rejects.toThrow(
        'Malformed encrypted payload base64'
      );
    });

    it('throws when decryptData payload is too short', async () => {
      // Short base64 (< 29 bytes)
      const shortPayload = 'aes-gcm:v1:' + btoa('short');
      await expect(decryptData(shortPayload, 'password')).rejects.toThrow(
        'Encrypted payload is too short or corrupted'
      );
    });
  });

  describe('7. URL Template & Interpolation Edge Cases', () => {
    it('leaves undefined :param and ${param} unreplaced in substituteParams', () => {
      const target = 'https://example.com/:existing/:missing/${alsoMissing}';
      const interpolated = interpolateTargetUrl(target, { existing: 'val' });
      expect(interpolated).toBe('https://example.com/val/:missing/${alsoMissing}');
    });

    it('leaves undefined $N capture unreplaced in interpolateTargetUrl', () => {
      const target = 'https://example.com/$1/$99';
      const interpolated = interpolateTargetUrl(target, undefined, ['full', 'first']);
      expect(interpolated).toBe('https://example.com/first/$99');
    });

    it('resolveUrlTemplate substitutes ${ENCODED_FULL_URL} and strips Basic Auth credentials from URL authority', () => {
      const incoming = new URL('https://user:supersecret@stevezmt.top/missing?param=1');
      const template = 'https://example.com/404?encoded=${ENCODED_FULL_URL}&raw=${RAW_FULL_URL}&path=${PATH}';

      const resolved = resolveUrlTemplate(template, incoming);
      // Verify Basic Auth username & password are completely purged
      expect(resolved).not.toContain('supersecret');
      expect(resolved).not.toContain('user:');
      expect(resolved).toContain('/missing');
      expect(resolved).toContain('param%3D1');
    });

    it('interpolates query parameters containing ${param}', () => {
      const target = 'https://example.com/search?keyword=${q}';
      const interpolated = interpolateTargetUrl(target, { q: 'react & vue' });
      expect(interpolated).toBe('https://example.com/search?keyword=react%20%26%20vue');
    });
  });

  describe('8. Remaining Micro-Branches Coverage', () => {
    it('supports minTls: 1.2 and custom rules array in declarative link options', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/tls12-with-rules': {
            target: 'https://example.com/dest',
            minTls: '1.2',
            rules: [
              (ctx) => Actions.pass(),
            ],
          },
        },
      });

      const req = new Request('https://example.com/tls12-with-rules');
      Object.defineProperty(req, 'cf', {
        value: { tlsVersion: 'TLSv1.2' },
        writable: true,
      });
      const res = await handler(req);
      expect(res.status).toBe(302);
    });

    it('handles RouteProvider returning array of RouteDefinitions directly', async () => {
      const arrayProvider = {
        isStatic: false,
        getRoutes: () => [
          { pattern: '/direct-array', target: 'https://example.com/direct-array' },
        ],
      };

      const handler = createShortLinkHandler(arrayProvider);
      const res = await handler(new Request('https://example.com/direct-array'));
      expect(res.status).toBe(302);
      expect(res.headers.get('Location')).toBe('https://example.com/direct-array');
    });

    it('verifies config.password starting with sha256: directly in verifyPassword', async () => {
      // SHA-256('mypassword:mysalt') = 63b199fb2d8708bd066edc3e35f2ae7b2c54f895481a5be910e6d478f27766e1
      const calculated = await verifyPassword(
        'mypassword',
        {
          password: 'sha256:63b199fb2d8708bd066edc3e35f2ae7b2c54f895481a5be910e6d478f27766e1',
          salt: 'mysalt',
        }
      );
      expect(calculated).toBe(true);

      // Explicit passwordHash check
      const hashChecked = await verifyPassword(
        'mypassword',
        {
          passwordHash: 'sha256:63b199fb2d8708bd066edc3e35f2ae7b2c54f895481a5be910e6d478f27766e1',
          salt: 'mysalt',
        }
      );
      expect(hashChecked).toBe(true);

      const wrong = await verifyPassword(
        'wrongpassword',
        {
          password: 'sha256:63b199fb2d8708bd066edc3e35f2ae7b2c54f895481a5be910e6d478f27766e1',
          salt: 'mysalt',
        }
      );
      expect(wrong).toBe(false);
    });

    it('populates params from positional matches when named groups are absent in matchCompiledRoute', () => {
      const compiledWithoutGroups = {
        pattern: '/custom/(.*)',
        regex: new RegExp('^/custom/(.*)$'),
        isHostSpecific: false,
        paramNames: ['posParam'],
        specificity: 100,
        definition: { pattern: '/custom/(.*)', target: '' },
      };

      const result = matchCompiledRoute(compiledWithoutGroups, new URL('https://example.com/custom/hello'));
      expect(result?.params.posParam).toBe('hello');
    });

    it('decrypts raw base64 payload without aes-gcm:v1: prefix', async () => {
      const fullEncrypted = await encryptData('secret text', 'pass123');
      const rawBase64 = fullEncrypted.slice('aes-gcm:v1:'.length);
      const decrypted = await decryptData(rawBase64, 'pass123');
      expect(decrypted).toBe('secret text');
    });

    it('falls back to text/html when upstream proxy response lacks Content-Type', async () => {
      const origFetch = globalThis.fetch;
      // Byte buffer payload has no default Content-Type in Response
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(new TextEncoder().encode('<h1>No Header 404</h1>'), {
          status: 404,
        })
      );
      try {
        const handler = createShortLinkHandler({
          notFound: {
            target: 'https://stevezmt.top/404',
            mode: 'proxy',
          },
        });
        const res = await handler(new Request('https://example.com/missing-route'));
        expect(res.status).toBe(404);
        expect(res.headers.get('Content-Type')).toContain('text/html');
      } finally {
        globalThis.fetch = origFetch;
      }
    });
  });
});
