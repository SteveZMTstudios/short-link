import { describe, it, expect, vi } from 'vitest';
import { createShortLinkHandler } from '../src/index';

describe('Custom 404 Handling', () => {
  it('redirects to https://stevezmt.top/404?from=${FULL_URL} by default', async () => {
    const handler = createShortLinkHandler({
      routes: [{ pattern: '/existing', target: 'https://example.com' }],
      notFound: {
        target: 'https://stevezmt.top/404?from=${FULL_URL}',
        mode: 'redirect',
      },
    });

    const nonExistentUrl = 'https://s.stevezmt.top/unknown/page?q=1';
    const response = await handler(new Request(nonExistentUrl));

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toBe(
      `https://stevezmt.top/404?from=${encodeURIComponent(nonExistentUrl)}`
    );

    // Also ensures tiered fallback meta and script are present
    const html = await response.text();
    expect(html).toContain('<meta http-equiv="refresh"');
    expect(html).toContain('window.location.replace');
  });

  it('supports proxy mode returning status 404 and upstream body', async () => {
    const mockHtml = '<!DOCTYPE html><html><body><h1>Custom 404</h1></body></html>';
    // Mock global fetch for upstream proxy
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(mockHtml, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      })
    );

    try {
      const handler = createShortLinkHandler({
        routes: [],
        notFound: {
          target: 'https://stevezmt.top/404?from=${FULL_URL}',
          mode: 'proxy',
        },
      });

      const response = await handler(new Request('https://test.link/missing-subpath'));
      expect(response.status).toBe(404);
      expect(await response.text()).toBe(mockHtml);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
