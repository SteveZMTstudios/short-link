import { describe, it, expect } from 'vitest';
import { createShortLinkHandler } from '../src/index';
import { requireMinTls, blockUserAgent, matchHeader, redirectBrowser, Actions } from '../src/rules/predicates';

describe('Rules & Interception Engine', () => {
  const handler = createShortLinkHandler({
    routes: [
      {
        pattern: '/secure-tls',
        target: 'https://stevezmt.top/secure',
        rules: [requireMinTls('TLSv1.3')],
      },
      {
        pattern: '/no-bots',
        target: 'https://stevezmt.top/human-page',
        rules: [blockUserAgent(['BadBot', 'EvilCrawler'])],
      },
      {
        pattern: '/custom-header-check',
        target: 'https://stevezmt.top/vip',
        rules: [
          matchHeader('X-VIP-Token', 'secret-vip-token', Actions.pass()),
          matchHeader('X-VIP-Token', (val) => val !== 'secret-vip-token', Actions.block(403, 'VIP token invalid')),
        ],
      },
      {
        pattern: '/app-download',
        target: 'https://stevezmt.top/desktop-client',
        rules: [
          redirectBrowser(/Android|iPhone/i, 'https://stevezmt.top/mobile-store'),
        ],
      },
    ],
  });

  it('blocks requests with TLS version lower than required', async () => {
    const reqLowTls = new Request('https://link.test/secure-tls');
    Object.defineProperty(reqLowTls, 'cf', {
      value: { tlsVersion: 'TLSv1.2' },
      writable: true,
    });

    const resLow = await handler(reqLowTls);
    expect(resLow.status).toBe(403);
    expect(await resLow.text()).toContain('TLS TLSv1.3+ required');

    const reqHighTls = new Request('https://link.test/secure-tls');
    Object.defineProperty(reqHighTls, 'cf', {
      value: { tlsVersion: 'TLSv1.3' },
      writable: true,
    });
    const resHigh = await handler(reqHighTls);
    expect(resHigh.status).toBe(302);
  });

  it('blocks blocked user agents', async () => {
    const botReq = new Request('https://link.test/no-bots', {
      headers: { 'User-Agent': 'Mozilla/5.0 BadBot/2.0' },
    });
    const botRes = await handler(botReq);
    expect(botRes.status).toBe(403);

    const normalReq = new Request('https://link.test/no-bots', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' },
    });
    const normalRes = await handler(normalReq);
    expect(normalRes.status).toBe(302);
  });

  it('redirects specific browsers (e.g. mobile) to designated landing page', async () => {
    const mobileReq = new Request('https://link.test/app-download', {
      headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)' },
    });
    const mobileRes = await handler(mobileReq);
    expect(mobileRes.status).toBe(302);
    expect(mobileRes.headers.get('Location')).toBe('https://stevezmt.top/mobile-store');

    const desktopReq = new Request('https://link.test/app-download', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    });
    const desktopRes = await handler(desktopReq);
    expect(desktopRes.status).toBe(302);
    expect(desktopRes.headers.get('Location')).toBe('https://stevezmt.top/desktop-client');
  });

  it('blocks request with 403 when rule returns boolean false', async () => {
    const customHandler = createShortLinkHandler({
      routes: [
        {
          pattern: '/blocked-by-bool',
          target: 'https://example.com/secret',
          rules: [
            () => false, // returns boolean false
          ],
        },
      ],
    });

    const res = await customHandler(new Request('https://link.test/blocked-by-bool'));
    expect(res.status).toBe(403);
    expect(await res.text()).toContain('Forbidden');
  });
});
