import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createShortLinkHandler } from '../src/index';
import { encryptData } from '../src/utils/crypto';
import {
  createAltchaChallenge,
  verifyAltchaPayload,
} from '../src/challenge/altcha';
import { createClearanceCookie, hasValidClearance } from '../src/challenge/clearance';
import {
  shouldChallengeRoute,
  resolveChallengeConfig,
  hasChallengeConfigured,
} from '../src/challenge';
import { RouteDefinition, ShortLinkConfig } from '../src/types';

describe('Challenge / Proof-of-Work Protection for Encrypted Routes', () => {
  const masterKey = 'test-master-key-2026';

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('1. Route Challenge Trigger Decision Logic', () => {
    it('automatically triggers challenge for individually encrypted target when challenge provider is configured', () => {
      const route: RouteDefinition = {
        pattern: '^/secret$',
        target: 'aes-gcm:v1:dummy',
        isIndividuallyEncrypted: true,
      };
      // When challenge provider is configured, should challenge
      expect(shouldChallengeRoute(route, false, true)).toBe(true);
    });

    it('bypasses challenge for full-table encrypted configuration by default', () => {
      const route: RouteDefinition = {
        pattern: '^/secret$',
        target: 'aes-gcm:v1:dummy',
        isIndividuallyEncrypted: true,
      };
      // Full table encrypted (second arg = true) -> skip challenge
      expect(shouldChallengeRoute(route, true, true)).toBe(false);
    });

    it('respects challenge: false explicit override even on encrypted targets', () => {
      const route: RouteDefinition = {
        pattern: '^/secret$',
        target: 'aes-gcm:v1:dummy',
        isIndividuallyEncrypted: true,
        challenge: false,
      };
      expect(shouldChallengeRoute(route, false, true)).toBe(false);
    });

    it('enforces challenge when challenge: true is explicitly specified on unencrypted targets', () => {
      const route: RouteDefinition = {
        pattern: '^/public-but-protected$',
        target: 'https://example.com/file.zip',
        isIndividuallyEncrypted: false,
        challenge: true,
      };
      expect(shouldChallengeRoute(route, false, true)).toBe(true);
    });

    it('supports route-level provider override (challenge: "altcha")', () => {
      const route: RouteDefinition = {
        pattern: '^/altcha-only$',
        target: 'https://example.com',
        challenge: 'altcha',
      };
      expect(shouldChallengeRoute(route, false, false)).toBe(true);
    });

    it('detects whether challenge is configured in settings or env', () => {
      expect(hasChallengeConfigured(undefined, undefined)).toBe(false);
      expect(hasChallengeConfigured({ challenge: { provider: 'turnstile' } }, undefined)).toBe(true);
      expect(hasChallengeConfigured(undefined, { CHALLENGE_PROVIDER: 'altcha' })).toBe(true);
    });
  });

  describe('2. Altcha Edge-Native WebCrypto HMAC & PoW', () => {
    const altchaSecret = 'altcha-secret-key-32-chars-long-1234';

    it('creates a valid challenge with HMAC signature and expiration', async () => {
      const challenge = await createAltchaChallenge(altchaSecret, 1000, 60);
      expect(challenge.algorithm).toBe('SHA-256');
      expect(challenge.challenge).toBeDefined();
      expect(challenge.salt).toContain('?expires=');
      expect(challenge.signature).toHaveLength(64); // SHA-256 hex length
    });

    it('verifies a correctly solved Altcha Proof-of-Work payload', async () => {
      const maxNumber = 500;
      const challenge = await createAltchaChallenge(altchaSecret, maxNumber, 60);

      // Simulate client finding the number
      let solvedNumber: number | null = null;
      for (let i = 0; i <= maxNumber; i++) {
        const text = challenge.salt + i;
        const data = new TextEncoder().encode(text);
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        const bytes = new Uint8Array(hashBuf);
        let hex = '';
        for (let b = 0; b < bytes.length; b++) {
          hex += bytes[b].toString(16).padStart(2, '0');
        }
        if (hex.toLowerCase() === challenge.challenge.toLowerCase()) {
          solvedNumber = i;
          break;
        }
      }

      expect(solvedNumber).not.toBeNull();

      const payload = {
        algorithm: 'SHA-256',
        challenge: challenge.challenge,
        number: solvedNumber!,
        salt: challenge.salt,
        signature: challenge.signature,
      };
      const rawPayload = btoa(JSON.stringify(payload));

      const result = await verifyAltchaPayload(rawPayload, altchaSecret);
      expect(result.success).toBe(true);
    });

    it('rejects an Altcha payload with invalid number / forged signature', async () => {
      const challenge = await createAltchaChallenge(altchaSecret, 100, 60);
      const forgedPayload = {
        algorithm: 'SHA-256',
        challenge: challenge.challenge,
        number: 999999,
        salt: challenge.salt,
        signature: challenge.signature,
      };
      const rawPayload = btoa(JSON.stringify(forgedPayload));

      const result = await verifyAltchaPayload(rawPayload, altchaSecret);
      expect(result.success).toBe(false);
      expect(result.error).toContain('PoW solution invalid');
    });

    it('rejects an expired Altcha challenge', async () => {
      // Create challenge that expired 10 seconds ago
      const challenge = await createAltchaChallenge(altchaSecret, 100, -10);
      const payload = {
        algorithm: 'SHA-256',
        challenge: challenge.challenge,
        number: 0,
        salt: challenge.salt,
        signature: challenge.signature,
      };
      const rawPayload = btoa(JSON.stringify(payload));

      const result = await verifyAltchaPayload(rawPayload, altchaSecret);
      expect(result.success).toBe(false);
      expect(result.error).toContain('expired');
    });
  });

  describe('3. Cloudflare Turnstile Verification Flow', () => {
    it('renders minimal Turnstile challenge HTML on GET request', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/target', masterKey);

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'turnstile',
            siteKey: '0x4AAAAAAATestSiteKey',
          },
        },
        links: {
          '/turnstile-test': encryptedTarget,
        },
      });

      const res = await handler(new Request('https://stevezmt.top/turnstile-test'), {
        ROUTES_KEY: masterKey,
        TURNSTILE_SECRET_KEY: '0x4AAAAAAATestSecretKey',
      });

      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('cf-turnstile');
      expect(html).toContain('0x4AAAAAAATestSiteKey');
      expect(html).toContain('challenges.cloudflare.com/turnstile');
      expect(html).toContain('prefers-color-scheme: dark');
      expect(html).toContain('<noscript>');
      expect(res.headers.get('Cache-Control')).toContain('no-store');
    });

    it('redirects with 303 after successful Turnstile POST verification', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/target', masterKey);

      // Mock Cloudflare Turnstile API response
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const urlStr = typeof input === 'string' ? input : (input as Request).url;
        if (urlStr.includes('challenges.cloudflare.com/turnstile/v0/siteverify')) {
          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response('Not found', { status: 404 });
      });

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'turnstile',
            siteKey: '0x4AAAAAAATestSiteKey',
          },
        },
        links: {
          '/turnstile-test': encryptedTarget,
        },
      });

      const formData = new FormData();
      formData.append('cf-turnstile-response', 'valid-turnstile-token');

      const postReq = new Request('https://stevezmt.top/turnstile-test', {
        method: 'POST',
        body: formData,
      });

      const res = await handler(postReq, {
        ROUTES_KEY: masterKey,
        TURNSTILE_SECRET_KEY: '0x4AAAAAAATestSecretKey',
      });

      expect(res.status).toBe(303);
      expect(res.headers.get('Location')).toBe('https://dest.example.com/target');
    });

    it('returns 403 with retry card when Turnstile token verification fails', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/target', masterKey);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
        const urlStr = typeof input === 'string' ? input : (input as Request).url;
        if (urlStr.includes('challenges.cloudflare.com/turnstile/v0/siteverify')) {
          return new Response(
            JSON.stringify({ success: false, 'error-codes': ['invalid-input-response'] }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }
        return new Response('Not found', { status: 404 });
      });

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: { provider: 'turnstile', siteKey: '0x4AAAAAAA' },
        },
        links: {
          '/turnstile-test': encryptedTarget,
        },
      });

      const formData = new FormData();
      formData.append('cf-turnstile-response', 'bad-token');

      const res = await handler(
        new Request('https://stevezmt.top/turnstile-test', {
          method: 'POST',
          body: formData,
        }),
        {
          ROUTES_KEY: masterKey,
          TURNSTILE_SECRET_KEY: '0x4AAAAAAASecret',
        }
      );

      expect(res.status).toBe(403);
      const text = await res.text();
      expect(text).toContain('invalid-input-response');
      expect(text).toContain('href="/turnstile-test"');
    });
  });

  describe('4. Cap (trycap.dev) Verification Flow', () => {
    it('renders Cap widget HTML on GET and calls /siteverify on POST', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/cap-target', masterKey);

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const urlStr = typeof input === 'string' ? input : (input as Request).url;
        if (urlStr.includes('cap.example.com/siteverify')) {
          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response('Not found', { status: 404 });
      });

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'cap',
            siteKey: 'cap_site_123',
            capEndpoint: 'https://cap.example.com',
          },
        },
        links: {
          '/cap-test': encryptedTarget,
        },
      });

      // GET
      const getRes = await handler(new Request('https://stevezmt.top/cap-test'), {
        ROUTES_KEY: masterKey,
        CAP_SECRET_KEY: 'cap_secret_xyz',
      });
      expect(getRes.status).toBe(200);
      const html = await getRes.text();
      expect(html).toContain('cap-widget');
      expect(html).toContain('data-cap-api-endpoint="https://cap.example.com/cap_site_123/"');

      // POST with JSON body
      const postReq = new Request('https://stevezmt.top/cap-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 'cap-token': 'token-abc-123' }),
      });

      const postRes = await handler(postReq, {
        ROUTES_KEY: masterKey,
        CAP_SECRET_KEY: 'cap_secret_xyz',
      });

      expect(postRes.status).toBe(303);
      expect(postRes.headers.get('Location')).toBe('https://dest.example.com/cap-target');
      expect(fetchSpy).toHaveBeenCalled();
    });

    it('automatically uses built-in serverless Cap engine when CAP_ENDPOINT is omitted', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/cap-target', masterKey);

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'cap',
          },
        },
        links: {
          '/cap-test': encryptedTarget,
        },
      });

      // 1. GET challenge page: uses built-in endpoint
      const getRes = await handler(new Request('https://stevezmt.top/cap-test'), {
        ROUTES_KEY: masterKey,
      });
      expect(getRes.status).toBe(200);
      const html = await getRes.text();
      expect(html).toContain('cap-widget');
      expect(html).toContain('data-cap-api-endpoint="/_challenge/cap/"');

      // 2. Request built-in challenge endpoint: POST /_challenge/cap/challenge
      const challengeReq = new Request('https://stevezmt.top/_challenge/cap/challenge', {
        method: 'POST',
      });
      const challengeRes = await handler(challengeReq, { ROUTES_KEY: masterKey });
      expect(challengeRes.status).toBe(200);
      const challengeData = (await challengeRes.json()) as {
        challenge: { c: number; s: number; d: number };
        token: string;
        expires: number;
      };
      expect(challengeData.challenge.c).toBe(50);
      expect(challengeData.token).toBeDefined();

      // 3. Request built-in Altcha endpoint: GET /_challenge/altcha
      const altchaReq = new Request('https://stevezmt.top/_challenge/altcha');
      const altchaRes = await handler(altchaReq, { ROUTES_KEY: masterKey });
      expect(altchaRes.status).toBe(200);
      const altchaData = (await altchaRes.json()) as { challenge: string; salt: string };
      expect(altchaData.challenge).toBeDefined();
      expect(altchaData.salt).toBeDefined();

      // 4. Test CORS preflight: OPTIONS /_challenge/cap/challenge
      const corsReq = new Request('https://stevezmt.top/_challenge/cap/challenge', {
        method: 'OPTIONS',
      });
      const corsRes = await handler(corsReq, { ROUTES_KEY: masterKey });
      expect(corsRes.status).toBe(204);
      expect(corsRes.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    });
  });

  describe('5. Altcha End-to-End Worker Verification Flow', () => {
    it('embeds challengejson directly in GET HTML (0 network roundtrips) and verifies POST without external APIs', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/altcha-target', masterKey);

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'altcha',
            altchaMaxNumber: 200,
          },
        },
        links: {
          '/altcha-test': encryptedTarget,
        },
      });

      const getRes = await handler(new Request('https://stevezmt.top/altcha-test'), {
        ROUTES_KEY: masterKey,
        ALTCHA_HMAC_KEY: 'altcha-secret-key-test',
      });

      expect(getRes.status).toBe(200);
      const html = await getRes.text();
      expect(html).toContain('altcha-widget');
      expect(html).toContain('challengejson');

      // Extract challenge from HTML
      const match = html.match(/challengejson='([^']+)'/);
      expect(match).not.toBeNull();
      const rawJson = match![1].replace(/&quot;/g, '"');
      const challengeObj = JSON.parse(rawJson);

      // Solve challenge
      let solvedNum = 0;
      for (let i = 0; i <= 200; i++) {
        const text = challengeObj.salt + i;
        const data = new TextEncoder().encode(text);
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        const bytes = new Uint8Array(hashBuf);
        let hex = '';
        for (let b = 0; b < bytes.length; b++) hex += bytes[b].toString(16).padStart(2, '0');
        if (hex === challengeObj.challenge) {
          solvedNum = i;
          break;
        }
      }

      const payload = {
        algorithm: 'SHA-256',
        challenge: challengeObj.challenge,
        number: solvedNum,
        salt: challengeObj.salt,
        signature: challengeObj.signature,
      };

      const formData = new FormData();
      formData.append('altcha', btoa(JSON.stringify(payload)));

      const postRes = await handler(
        new Request('https://stevezmt.top/altcha-test', {
          method: 'POST',
          body: formData,
        }),
        {
          ROUTES_KEY: masterKey,
          ALTCHA_HMAC_KEY: 'altcha-secret-key-test',
        }
      );

      expect(postRes.status).toBe(303);
      expect(postRes.headers.get('Location')).toBe('https://dest.example.com/altcha-target');
    });
  });

  describe('6. Clearance Cookie Exemption (clearanceDuration)', () => {
    it('sets __shortlink_clearance cookie on solve and bypasses challenge on subsequent requests', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/clearance-dest', masterKey);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      });

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'turnstile',
            siteKey: '0x4AAAAAAA',
            clearanceDuration: 300, // 5 minutes clearance
          },
        },
        links: {
          '/vault-1': encryptedTarget,
          '/vault-2': encryptedTarget,
        },
      });

      const env = {
        ROUTES_KEY: masterKey,
        TURNSTILE_SECRET_KEY: 'turnstile_secret',
      };

      // 1. Solve challenge on /vault-1 via POST
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'valid-token');

      const solveRes = await handler(
        new Request('https://stevezmt.top/vault-1', {
          method: 'POST',
          body: formData,
        }),
        env
      );

      expect(solveRes.status).toBe(303);
      const setCookie = solveRes.headers.get('Set-Cookie');
      expect(setCookie).toContain('__shortlink_clearance=');
      expect(setCookie).toContain('Max-Age=300');

      // Extract cookie value
      const cookieVal = setCookie!.split(';')[0];

      // 2. Next request to /vault-2 carrying clearance cookie should redirect immediately without 200 challenge page
      const nextReq = new Request('https://stevezmt.top/vault-2', {
        headers: {
          Cookie: cookieVal,
        },
      });

      const nextRes = await handler(nextReq, env);
      expect(nextRes.status).toBe(302);
      expect(nextRes.headers.get('Location')).toBe('https://dest.example.com/clearance-dest');
    });

    it('rejects forged or tampered clearance cookie and presents challenge', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/clearance-dest', masterKey);

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'turnstile',
            siteKey: '0x4AAAAAAA',
            clearanceDuration: 300,
          },
        },
        links: {
          '/vault': encryptedTarget,
        },
      });

      const reqWithForgedCookie = new Request('https://stevezmt.top/vault', {
        headers: {
          Cookie: '__shortlink_clearance=9999999999.forgedsignaturehex',
        },
      });

      const res = await handler(reqWithForgedCookie, {
        ROUTES_KEY: masterKey,
        TURNSTILE_SECRET_KEY: 'secret',
      });

      // Must present challenge (200), not direct redirect (302)
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toContain('cf-turnstile');
    });
  });

  describe('7. Internationalization (i18n) & Minimal Aesthetics', () => {
    it('adapts language based on Accept-Language header (Simplified Chinese, Traditional Chinese, English)', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com', masterKey);

      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: { provider: 'turnstile', siteKey: '0x4A' },
        },
        links: { '/lang-test': encryptedTarget },
      });

      const env = { ROUTES_KEY: masterKey, TURNSTILE_SECRET_KEY: 'sec' };

      // zh-CN
      const resZh = await handler(
        new Request('https://stevezmt.top/lang-test', {
          headers: { 'Accept-Language': 'zh-CN,zh;q=0.9' },
        }),
        env
      );
      const htmlZh = await resZh.text();
      expect(htmlZh).toContain('安全验证');
      expect(htmlZh).toContain('您的浏览器不安全。');
      expect(htmlZh).toContain('目标服务需要确认您的浏览器安全性。');
      expect(htmlZh).toContain('您通常不需要执行任何操作');
      expect(htmlZh).toContain('https://browser-update.org/update-browser.html');
      expect(htmlZh).toContain('https://www.enablejavascript.io/');
      expect(htmlZh).toContain('如何启用它？');

      // zh-TW
      const resTw = await handler(
        new Request('https://stevezmt.top/lang-test', {
          headers: { 'Accept-Language': 'zh-TW,zh;q=0.8' },
        }),
        env
      );
      const htmlTw = await resTw.text();
      expect(htmlTw).toContain('安全驗證');
      expect(htmlTw).toContain('您的瀏覽器不安全。');
      expect(htmlTw).toContain('目標服務需要確認您的瀏覽器安全性。');
      expect(htmlTw).toContain('您通常不需要執行任何操作');
      expect(htmlTw).toContain('如何啟用它？');

      // en
      const resEn = await handler(
        new Request('https://stevezmt.top/lang-test', {
          headers: { 'Accept-Language': 'en-US,en;q=0.9' },
        }),
        env
      );
      const htmlEn = await resEn.text();
      expect(htmlEn).toContain('Security Check');
      expect(htmlEn).toContain('Your browser is not secure.');
      expect(htmlEn).toContain('The destination service needs to verify your browser security.');
      expect(htmlEn).toContain('How to enable it?');
    });
  });

  describe('8. Configuration Error Handling', () => {
    it('returns clear 500 when route requires challenge but no provider is configured', async () => {
      const handler = createShortLinkHandler({
        links: {
          '/must-challenge': {
            target: 'https://example.com',
            challenge: true, // explicitly requested challenge
          },
        },
      });

      const res = await handler(new Request('https://example.com/must-challenge'));
      expect(res.status).toBe(500);
      const body = await res.text();
      expect(body).toContain('Challenge Configuration Error');
      expect(body).toContain('CHALLENGE_PROVIDER');
    });

    it('returns clear 500 when Turnstile is chosen but secret key is missing', async () => {
      const handler = createShortLinkHandler({
        settings: {
          challenge: { provider: 'turnstile', siteKey: '0x4A' },
        },
        links: {
          '/test': { target: 'https://example.com', challenge: true },
        },
      });

      const res = await handler(new Request('https://example.com/test'));
      expect(res.status).toBe(500);
      const body = await res.text();
      expect(body).toContain('TURNSTILE_SECRET_KEY is missing');
    });
  });

  describe('9. Declarative Config with Settings & Per-Route Challenge', () => {
    it('integrates full declarative config with challenge settings into AppConfig and routing', async () => {
      const config: ShortLinkConfig = {
        settings: {
          domain: 'stevezmt.top',
          challenge: {
            provider: 'turnstile',
            siteKey: '0x4AAAAAAATestKey',
            clearanceDuration: 600,
          },
        },
        links: {
          '/exempt-link': {
            target: 'aes-gcm:v1:some_encrypted_payload',
            challenge: false, // exempt
          },
          '/custom-altcha': {
            target: 'https://example.com/download',
            challenge: 'altcha', // route-level override
          },
        },
      };

      const handler = createShortLinkHandler(config);

      // 1. /exempt-link skips challenge even though target has aes-gcm prefix
      // (will fail with ROUTES_KEY is missing, NOT challenge error)
      const resExempt = await handler(new Request('https://stevezmt.top/exempt-link'));
      expect(resExempt.status).toBe(500);
      expect(await resExempt.text()).toContain('ROUTES_KEY is missing');

      // 2. /custom-altcha triggers altcha challenge (GET returns altcha widget)
      const resAltcha = await handler(new Request('https://stevezmt.top/custom-altcha'), {
        ALTCHA_HMAC_KEY: 'altcha-key-secret-12345678901234',
      });
      expect(resAltcha.status).toBe(200);
      const altchaHtml = await resAltcha.text();
      expect(altchaHtml).toContain('altcha-widget');
      expect(altchaHtml).toContain('<input type="hidden" name="altcha" id="altcha-input"');
      expect(altchaHtml).toContain('challengeurl="/_challenge/altcha"');
    });

    it('robustly extracts token from alternative field names or urlencoded payloads to prevent empty token errors', async () => {
      const encryptedTarget = await encryptData('https://dest.example.com/altcha-robust', masterKey);
      const handler = createShortLinkHandler({
        settings: {
          domain: 'stevezmt.top',
          challenge: { provider: 'altcha', altchaMaxNumber: 10 },
        },
        links: {
          '/test-robust': encryptedTarget,
        },
      });

      // Solve a tiny challenge
      const ch = await createAltchaChallenge(masterKey, 10);
      const payload = {
        algorithm: 'SHA-256',
        challenge: ch.challenge,
        number: 0,
        salt: ch.salt,
        signature: ch.signature,
      };
      // Find valid number
      for (let i = 0; i <= 10; i++) {
        const text = ch.salt + i;
        const data = new TextEncoder().encode(text);
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        const bytes = new Uint8Array(hashBuf);
        let hex = '';
        for (let b = 0; b < bytes.length; b++) hex += bytes[b].toString(16).padStart(2, '0');
        if (hex === ch.challenge) {
          payload.number = i;
          break;
        }
      }

      const encodedPayload = btoa(JSON.stringify(payload));

      // Test submission using fallback field 'payload' instead of 'altcha'
      const form = new FormData();
      form.append('payload', encodedPayload);

      const res = await handler(
        new Request('https://stevezmt.top/test-robust', {
          method: 'POST',
          body: form,
        }),
        { ROUTES_KEY: masterKey }
      );

      expect(res.status).toBe(303);
      expect(res.headers.get('Location')).toBe('https://dest.example.com/altcha-robust');
    });
  });
});


