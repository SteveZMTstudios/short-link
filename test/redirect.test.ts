import { describe, it, expect } from 'vitest';
import { createShortLinkHandler } from '../src/index';
import { buildDestinationUrl } from '../src/utils/url';
import { createTieredRedirectResponse } from '../src/utils/response';

describe('Tiered Redirection & UTM Parameters', () => {
  it('generates 3-tier redirect response (302 Location + Meta Refresh + Inline Script)', async () => {
    const target = 'https://example.com/dest';
    const response = createTieredRedirectResponse(target, 302);

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe(target);
    expect(response.headers.get('Content-Type')).toContain('text/html');

    const html = await response.text();
    // Tier 2: Meta refresh
    expect(html).toContain('<meta http-equiv="refresh" content="0;url=https://example.com/dest">');
    // Tier 3: Inline JS redirect
    expect(html).toContain('window.location.replace("https://example.com/dest")');
    // Tier fallback anchor
    expect(html).toContain('href="https://example.com/dest"');
  });

  it('merges UTM parameters and query string correctly', () => {
    // 1. Injects default UTMs when visitor provides none
    const incoming1 = new URL('https://short.link/go?custom=123');
    const result1 = buildDestinationUrl('https://target.com/page', incoming1, {
      utm_source: 'shortlink',
      utm_medium: 'referral',
      utm_campaign: 'promo',
    });
    const parsed1 = new URL(result1);
    expect(parsed1.searchParams.get('custom')).toBe('123');
    expect(parsed1.searchParams.get('utm_source')).toBe('shortlink');
    expect(parsed1.searchParams.get('utm_medium')).toBe('referral');
    expect(parsed1.searchParams.get('utm_campaign')).toBe('promo');

    // 2. Preserves visitor-provided UTMs over defaults
    const incoming2 = new URL('https://short.link/go?utm_source=my_campaign&utm_medium=custom_med');
    const result2 = buildDestinationUrl('https://target.com/page', incoming2, {
      utm_source: 'default_source',
      utm_medium: 'default_medium',
      utm_campaign: 'default_campaign',
    });
    const parsed2 = new URL(result2);
    expect(parsed2.searchParams.get('utm_source')).toBe('my_campaign');
    expect(parsed2.searchParams.get('utm_medium')).toBe('custom_med');
    expect(parsed2.searchParams.get('utm_campaign')).toBe('default_campaign');
  });

  it('handles standard shortlink end-to-end request', async () => {
    const handler = createShortLinkHandler({
      routes: [
        {
          pattern: '/github',
          target: 'https://github.com/stevezmt',
          utm: { utm_source: 'worker', utm_medium: 'redirect' },
        },
      ],
    });

    const request = new Request('https://s.stevezmt.top/github?ref=test');
    const response = await handler(request);

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toContain('https://github.com/stevezmt');
    expect(location).toContain('ref=test');
    expect(location).toContain('utm_source=worker');
    expect(location).toContain('utm_medium=redirect');
  });

  it('sanitizes script tags in target to prevent script breakout XSS', async () => {
    const maliciousTarget = 'https://example.com/test</script><script>alert(1)</script>';
    const response = createTieredRedirectResponse(maliciousTarget, 302);
    const html = await response.text();

    // Ensure literal </script> does not appear inside the inline script tag
    expect(html).not.toContain('window.location.replace("https://example.com/test</script>');
    expect(html).toContain('\\u003c/script\\u003e');
  });

  it('rejects unsafe pseudo-protocols like javascript:', async () => {
    const maliciousTarget = 'javascript:alert(document.domain)';
    const response = createTieredRedirectResponse(maliciousTarget, 302);

    expect(response.headers.get('Location')).toBe('about:blank');
    const html = await response.text();
    expect(html).not.toContain('javascript:');
    expect(html).toContain('about:blank');
  });

  it('omits UTM parameters when values are empty string or whitespace', () => {
    const incoming = new URL('https://short.link/go');
    const result = buildDestinationUrl('https://target.com/page', incoming, {
      utm_source: '',
      utm_medium: '   ',
      utm_campaign: 'spring_sale',
    });
    const parsed = new URL(result);
    expect(parsed.searchParams.has('utm_source')).toBe(false);
    expect(parsed.searchParams.has('utm_medium')).toBe(false);
    expect(parsed.searchParams.get('utm_campaign')).toBe('spring_sale');
  });

  it('automatically prepends https:// when target is a bare domain like baidu.com', () => {
    const incoming = new URL('https://short.link/search');
    const result = buildDestinationUrl('baidu.com', incoming);
    expect(result).toBe('https://baidu.com/');

    const resultWithPath = buildDestinationUrl('example.com/docs/api', incoming);
    expect(resultWithPath).toBe('https://example.com/docs/api');
  });
});
