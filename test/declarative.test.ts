import { describe, it, expect } from 'vitest';
import { createShortLinkHandler } from '../src/index';

describe('Declarative Configuration & Centralized Domain Settings', () => {
  it('handles simple string mappings with global inherited UTMs', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'example.com',
        defaultUtm: { utm_source: 'mybrand', utm_medium: 'cpc' },
      },
      links: {
        '/gh': 'https://github.com/myaccount',
      },
    });

    const res = await handler(new Request('https://example.com/gh'));
    expect(res.status).toBe(302);
    const loc = res.headers.get('Location') || '';
    expect(loc).toContain('https://github.com/myaccount');
    expect(loc).toContain('utm_source=mybrand');
    expect(loc).toContain('utm_medium=cpc');
  });

  it('handles declarative password protection', async () => {
    const handler = createShortLinkHandler({
      links: {
        '/vault': {
          target: 'https://secret.com/docs',
          password: 'my-pass-123',
        },
      },
    });

    // Unauthenticated
    const resUnauthorized = await handler(new Request('https://example.com/vault'));
    expect(resUnauthorized.status).toBe(401);
    expect(resUnauthorized.headers.get('WWW-Authenticate')).toContain('Basic');

    // Authenticated
    const authHeader = `Basic ${btoa('steve:my-pass-123')}`;
    const resAuth = await handler(
      new Request('https://example.com/vault', {
        headers: { Authorization: authHeader },
      })
    );
    expect(resAuth.status).toBe(302);
    expect(resAuth.headers.get('Location')).toContain('https://secret.com/docs');
  });

  it('handles declarative TLS version check and bot blocking', async () => {
    const handler = createShortLinkHandler({
      links: {
        '/secure': {
          target: 'https://example.com/safe',
          minTls: '1.3',
          blockBots: true,
        },
      },
    });

    // Low TLS
    const reqLow = new Request('https://example.com/secure');
    Object.defineProperty(reqLow, 'cf', {
      value: { tlsVersion: 'TLSv1.2' },
      writable: true,
    });
    const resLow = await handler(reqLow);
    expect(resLow.status).toBe(403);

    // Bot User-Agent
    const reqBot = new Request('https://example.com/secure', {
      headers: { 'User-Agent': 'Mozilla/5.0 ScraperBot/1.0' },
    });
    Object.defineProperty(reqBot, 'cf', {
      value: { tlsVersion: 'TLSv1.3' },
      writable: true,
    });
    const resBot = await handler(reqBot);
    expect(resBot.status).toBe(403);

    // Good request
    const reqGood = new Request('https://example.com/secure', {
      headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' },
    });
    Object.defineProperty(reqGood, 'cf', {
      value: { tlsVersion: 'TLSv1.3' },
      writable: true,
    });
    const resGood = await handler(reqGood);
    expect(resGood.status).toBe(302);
  });

  it('handles declarative mobile redirection', async () => {
    const handler = createShortLinkHandler({
      links: {
        '/download': {
          target: 'https://example.com/desktop-setup.exe',
          mobile: 'https://example.com/mobile-app-store',
        },
      },
    });

    const mobileReq = new Request('https://example.com/download', {
      headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)' },
    });
    const mobileRes = await handler(mobileReq);
    expect(mobileRes.status).toBe(302);
    expect(mobileRes.headers.get('Location')).toContain('mobile-app-store');

    const desktopReq = new Request('https://example.com/download', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    });
    const desktopRes = await handler(desktopReq);
    expect(desktopRes.status).toBe(302);
    expect(desktopRes.headers.get('Location')).toContain('desktop-setup.exe');
  });

  it('binds shorthand subdomain "s:/path" to central domain', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        's:/blog/*': 'https://stevezmt.top/articles',
      },
    });

    const resSub = await handler(new Request('https://s.stevezmt.top/blog/my-post'));
    expect(resSub.status).toBe(302);
    expect(resSub.headers.get('Location')).toContain('https://stevezmt.top/articles');

    const resOther = await handler(new Request('https://other.stevezmt.top/blog/my-post'));
    // Should not match "s:"
    expect(resOther.status).toBe(302);
    expect(resOther.headers.get('Location')).toContain('/404?from=');
  });

  it('allows shorthand subdomain "s:/path" to adapt automatically when domain is omitted', async () => {
    const handler = createShortLinkHandler({
      // settings.domain omitted -> auto-adapts to whatever base domain is hit!
      links: {
        'go:/deal': 'https://example.com/deal',
      },
    });

    const res1 = await handler(new Request('https://go.mycompany.org/deal'));
    expect(res1.status).toBe(302);
    expect(res1.headers.get('Location')).toContain('https://example.com/deal');

    const res2 = await handler(new Request('https://go.another-site.io/deal'));
    expect(res2.status).toBe(302);
    expect(res2.headers.get('Location')).toContain('https://example.com/deal');
  });
});
