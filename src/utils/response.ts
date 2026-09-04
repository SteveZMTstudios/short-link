/**
 * Response utilities for tiered redirection and error responses.
 * Implements:
 * 1. HTTP 302 (or configured status) with Location header
 * 2. <meta http-equiv="refresh"> fallback in HTML body
 * 3. <script>window.location.replace(...)</script> inline script fallback
 * 4. XSS sanitization for HTML and JS injection
 */

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Serializes a string safely for injection inside an HTML <script> tag.
 * Replaces '<', '>', and '/' to prevent </script> tag breakout XSS.
 */
export function safeJsonForScript(str: string): string {
  return JSON.stringify(str)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e');
}

/**
 * Validates whether a target URL is safe for redirection.
 * Rejects javascript:, data:, vbscript:, and protocol-relative (//) URLs.
 */
export function isSafeRedirectUrl(url: string): boolean {
  const trimmed = url.trim();
  if (/^(?:javascript|data|vbscript|blob|file):/i.test(trimmed)) {
    return false;
  }
  // Block protocol-relative URLs (e.g. //attacker.com)
  if (trimmed.startsWith('//')) {
    return false;
  }
  return (
    /^https?:\/\//i.test(trimmed) ||
    /^(?:tg|weixin|bilibili|mailto|tel|sms|magnet|itms-apps|intent|applink):/i.test(trimmed) ||
    (trimmed.startsWith('/') && !trimmed.startsWith('//'))
  );
}

/**
 * Generates a unified response implementing all 3 redirection layers simultaneously:
 * Layer 1: HTTP 302 status + Location header (for standard HTTP clients/browsers)
 * Layer 2: HTML <meta http-equiv="refresh"> (for clients ignoring HTTP redirects but rendering HTML)
 * Layer 3: Inline JavaScript window.location.replace() (for dynamic DOM environments)
 * Fallback: Clickable HTML anchor tag for no-script and no-redirect clients.
 *
 * Cache-Control Strategy:
 * - Sensitive routes (auth, rules, encrypted payloads): no-cache, no-store, must-revalidate
 * - Public static routes: public, max-age=60, s-maxage=300 (Cloudflare edge CDN caching)
 */
export function createTieredRedirectResponse(
  targetUrl: string,
  status = 302,
  extraHeaders: HeadersInit = {},
  isSensitive = false
): Response {
  // Guard against unsafe protocols like javascript:
  const sanitizedTarget = isSafeRedirectUrl(targetUrl) ? targetUrl : 'about:blank';
  const safeUrl = escapeHtml(sanitizedTarget);
  const jsSafeUrl = safeJsonForScript(sanitizedTarget);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="0;url=${safeUrl}">
  <title>Redirecting…</title>
</head>
<body>
  <div id="fallback" style="display:none;">
    <p>If not redirected automatically, please click <a href="${safeUrl}">here</a>.</p>
  </div>
  <noscript>
    <p>If not redirected automatically, please click <a href="${safeUrl}">here</a>.</p>
  </noscript>
  <script>
    try {
      window.location.replace(${jsSafeUrl});
    } catch (_) {
      window.location.href = ${jsSafeUrl};
    }
    setTimeout(function () {
      document.getElementById('fallback').style.display = 'block';
    }, 3000);
  </script>
</body>
</html>`;

  const headers = new Headers(extraHeaders);
  headers.set('Location', sanitizedTarget);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Robots-Tag', 'noindex, nofollow');
  headers.set('Referrer-Policy', 'no-referrer');
  // Tiered cache control: sensitive/authenticated routes are not cached, public static routes allow edge caching
  if (!headers.has('Cache-Control')) {
    if (isSensitive) {
      headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else {
      headers.set('Cache-Control', 'public, max-age=60, s-maxage=300');
    }
  }

  return new Response(html, {
    status,
    headers,
  });
}

/**
 * Creates an edge-native robots.txt response disallowing all crawlers.
 */
export function createRobotsTxtResponse(): Response {
  return new Response('User-agent: *\nDisallow: /\n', {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
}
