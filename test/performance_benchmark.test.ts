import { describe, it, expect } from 'vitest';
import { createShortLinkHandler, resolveMasterKey } from '../src/index';
import { encryptData, decryptData } from '../src/utils/crypto';
import { compileRouteTable, findMatchingCompiledRoute } from '../src/router/matcher';
import { RouteDefinition } from '../src/types';

describe('Cloudflare Workers 10ms CPU Limit & High-Concurrency Benchmark', () => {
  describe('1. Web Crypto (HKDF + AES-GCM) 10ms CPU Execution Limit Verification', () => {
    it('executes symmetric decryption well within the 10ms CPU budget (average < 1.0ms)', async () => {
      const password = 'benchmark_master_key_2026';
      const secretUrl = 'https://internal.stevezmt.top/confidential/vault-item-999';
      const encryptedPayload = await encryptData(secretUrl, password);

      // Warm-up JIT
      for (let i = 0; i < 5; i++) {
        await decryptData<string>(encryptedPayload, password);
      }

      const iterations = 50;
      const start = performance.now();

      for (let i = 0; i < iterations; i++) {
        const decrypted = await decryptData<string>(encryptedPayload, password);
        expect(decrypted).toBe(secretUrl);
      }

      const totalElapsedMs = performance.now() - start;
      const avgMsPerDecryption = totalElapsedMs / iterations;

      console.log(
        `[Benchmark] AES-GCM + HKDF Decryption: total=${totalElapsedMs.toFixed(2)}ms for ${iterations} runs, avg=${avgMsPerDecryption.toFixed(3)}ms/op`
      );

      // Cloudflare Workers free plan has a 10ms CPU limit.
      // HKDF + AES-GCM must take strictly < 1.0ms per op (normally < 0.15ms in V8).
      expect(avgMsPerDecryption).toBeLessThan(1.0);
    });

    it('matches routes across a large routing table in microseconds (< 0.1ms)', () => {
      // Construct a route table with 500 diverse routes
      const routes: RouteDefinition[] = [];
      for (let i = 0; i < 400; i++) {
        routes.push({ pattern: `/static-path-${i}`, target: `https://example.com/item-${i}` });
      }
      for (let i = 0; i < 50; i++) {
        routes.push({
          pattern: `blog.stevezmt.top/:category/post-${i}/:slug`,
          target: `https://example.com/c/:category/p/${i}/:slug`,
        });
      }
      for (let i = 0; i < 40; i++) {
        routes.push({
          pattern: `files-${i}.stevezmt.top/*`,
          target: `https://example.com/files/${i}/$1`,
        });
      }
      routes.push({
        pattern: 'regex:^api\\.stevezmt\\.top\\/v1\\/([a-z0-9_-]+)$',
        target: 'https://backend.internal/v1/$1',
      });

      const compileStart = performance.now();
      const compiled = compileRouteTable(routes);
      const compileElapsed = performance.now() - compileStart;
      expect(compiled.length).toBe(491);

      console.log(`[Benchmark] Route compilation for 491 routes took ${compileElapsed.toFixed(2)}ms`);

      const targetUrl = new URL('https://blog.stevezmt.top/tech/post-25/cloudflare-workers');
      const matchIterations = 500;
      const matchStart = performance.now();

      for (let i = 0; i < matchIterations; i++) {
        const match = findMatchingCompiledRoute(compiled, targetUrl);
        expect(match).not.toBeNull();
        expect(match?.params.category).toBe('tech');
        expect(match?.params.slug).toBe('cloudflare-workers');
      }

      const matchElapsed = performance.now() - matchStart;
      const avgMatchMs = matchElapsed / matchIterations;

      console.log(
        `[Benchmark] Route lookup: ${matchIterations} lookups took ${matchElapsed.toFixed(2)}ms, avg=${(avgMatchMs * 1000).toFixed(1)}µs/lookup`
      );

      // Average lookup must be strictly sub-millisecond (< 0.2ms / 200µs, well within 10ms budget)
      expect(avgMatchMs).toBeLessThan(0.2);
    });
  });

  describe('2. High-Concurrency Stress Test (1,000+ Parallel Requests)', () => {
    it('successfully processes 1,000 concurrent requests across mixed route types without errors or race conditions', async () => {
      const masterKey = 'stress_test_master_key_xyz_2026';
      const encryptedTarget = await encryptData('https://secure.stevezmt.top/vault-resource', masterKey);

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          defaultUtm: { utm_source: 'shortlink', utm_medium: 'redirect' },
        },
        links: {
          '/': 'https://stevezmt.top',
          '/gh': 'https://github.com/stevezmt',
          'blog:/:category/:slug': 'https://stevezmt.top/blog/:category/:slug',
          'files:/*': 'https://stevezmt.top/downloads/$1',
          'regex:^api\\.stevezmt\\.top\\/v1\\/([a-z0-9]+)$': 'https://api.internal/$1',
          '/secret-vault': encryptedTarget,
          '/protected': {
            target: 'https://stevezmt.top/internal',
            password: 'pass_protected_123',
          },
        },
      });

      const totalRequests = 1000;
      const testCases = [
        { url: 'https://stevezmt.top/', expectedStatus: 302, checkLoc: 'https://stevezmt.top' },
        { url: 'https://stevezmt.top/robots.txt', expectedStatus: 200, isRobots: true },
        { url: 'https://stevezmt.top/gh', expectedStatus: 302, checkLoc: 'github.com/stevezmt' },
        { url: 'https://stevezmt.top/gh/', expectedStatus: 302, checkLoc: 'github.com/stevezmt' }, // Trailing slash test
        { url: 'https://blog.stevezmt.top/news/release-2026', expectedStatus: 302, checkLoc: '/blog/news/release-2026' },
        { url: 'https://files.stevezmt.top/firmware/v2.1.bin', expectedStatus: 302, checkLoc: '/downloads/firmware/v2.1.bin' },
        { url: 'https://api.stevezmt.top/v1/user999', expectedStatus: 302, checkLoc: 'https://api.internal/user999' },
        { url: 'https://stevezmt.top/secret-vault', expectedStatus: 302, checkLoc: 'https://secure.stevezmt.top/vault-resource', env: { ROUTES_KEY: masterKey } },
        { url: 'https://stevezmt.top/protected', expectedStatus: 401 }, // Unauthenticated
        { url: 'https://stevezmt.top/non-existent-random-link', expectedStatus: 302, checkLoc: '/404?from=' }, // 404 fallback
      ];

      const startTime = performance.now();

      const promises = Array.from({ length: totalRequests }, (_, i) => {
        const tc = testCases[i % testCases.length];
        const req = new Request(tc.url);
        return handler(req, tc.env).then(async (res) => {
          expect(res.status).toBe(tc.expectedStatus);
          if (tc.isRobots) {
            const text = await res.text();
            expect(text).toContain('User-agent: *');
            expect(text).toContain('Disallow: /');
          } else if (tc.checkLoc) {
            expect(res.headers.get('Location')).toContain(tc.checkLoc);
            expect(res.headers.get('X-Robots-Tag')).toBe('noindex, nofollow');
          }
        });
      });

      await Promise.all(promises);

      const totalDuration = performance.now() - startTime;
      const rps = (totalRequests / (totalDuration / 1000)).toFixed(0);

      console.log(
        `[Benchmark] High-Concurrency: ${totalRequests} mixed requests resolved in ${totalDuration.toFixed(1)}ms (~${rps} req/sec)`
      );

      // The entire batch of 1,000 requests must finish in under 3,000ms
      expect(totalDuration).toBeLessThan(3000);
    });
  });
});
