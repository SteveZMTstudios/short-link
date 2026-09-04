import { describe, it, expect } from 'vitest';
import { createShortLinkHandler } from '../src/index';

describe('Dynamic Batch & Regex Route Forwarding', () => {
  it('routes subdomain with named parameter to long target (user example: blog:/:name -> /blog/post/:name)', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
        defaultUtm: {
          utm_source: 'shortlink',
          utm_medium: 'redirect',
        },
      },
      links: {
        // blog.stevezmt.top/博客名 -> stevezmt.top/blog/post/博客名
        'blog:/:post': 'https://stevezmt.top/blog/post/:post',
      },
    });

    const res = await handler(new Request('https://blog.stevezmt.top/my-first-article'));
    expect(res.status).toBe(302);
    const location = res.headers.get('Location')!;
    expect(location).toContain('https://stevezmt.top/blog/post/my-first-article');
    expect(location).toContain('utm_source=shortlink');
    expect(location).toContain('utm_medium=redirect');
  });

  it('routes wildcard capture groups (* -> $1)', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        'blog:/*': 'https://stevezmt.top/blog/post/$1',
      },
    });

    const res = await handler(new Request('https://blog.stevezmt.top/2026/09/special-issue'));
    expect(res.status).toBe(302);
    const location = res.headers.get('Location')!;
    expect(location).toContain('https://stevezmt.top/blog/post/2026/09/special-issue');
  });

  it('routes with pure regular expressions (regex:^... -> $1)', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        'regex:^blog\\.[^/]+/([a-z0-9_-]+)$': 'https://stevezmt.top/blog/post/$1',
      },
    });

    // Matches regex
    const res = await handler(new Request('https://blog.stevezmt.top/cloud-flare-workers-2026'));
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('https://stevezmt.top/blog/post/cloud-flare-workers-2026');

    // Non-matching path (slashes inside) goes to 404
    const res404 = await handler(new Request('https://blog.stevezmt.top/invalid/nested'));
    expect(res404.status).toBe(404);
    expect(res404.headers.get('Location')).toBeNull();
  });

  it('handles multi-segment parameters (:category/:slug) and forwards query strings', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        'blog:/:category/:slug': 'https://stevezmt.top/categories/:category/articles/:slug',
      },
    });

    const res = await handler(
      new Request('https://blog.stevezmt.top/coding/rust-wasm?src=github&theme=dark')
    );
    expect(res.status).toBe(302);
    const location = res.headers.get('Location')!;
    expect(location).toContain('https://stevezmt.top/categories/coding/articles/rust-wasm');
    expect(location).toContain('src=github');
    expect(location).toContain('theme=dark');
  });
});
