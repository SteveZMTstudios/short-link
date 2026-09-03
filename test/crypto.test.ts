import { describe, it, expect } from 'vitest';
import { encryptData, decryptData } from '../src/utils/crypto';
import { createShortLinkHandler } from '../src/index';

describe('Symmetric Encryption for Public Repositories', () => {
  it('encrypts and decrypts route data cleanly using AES-GCM and HKDF', async () => {
    const originalRoutes = {
      '/secret-partner': 'https://partner.com/campaign-2026',
      '/private-doc': {
        target: 'https://docs.internal/spec',
        password: 'doc-password',
      },
    };

    const password = 'my-super-secret-repo-key-2026';
    const encrypted = await encryptData(originalRoutes, password);

    expect(encrypted).toMatch(/^aes-gcm:v1:[A-Za-z0-9+/=]+$/);

    // Decrypt with correct password
    const decrypted = await decryptData(encrypted, password);
    expect(decrypted).toEqual(originalRoutes);

    // Decrypt with wrong password throws
    await expect(decryptData(encrypted, 'wrong-password')).rejects.toThrow(
      /Decryption failed/i
    );
  });

  it('worker dynamically decrypts routes from environment variable ROUTES_KEY', async () => {
    const hiddenRoutes = {
      '/hidden-promo': 'https://example.com/promo-landing',
    };
    const secretKey = 'env-passphrase-xyz';
    const encryptedPayload = await encryptData(hiddenRoutes, secretKey);

    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        '/': 'https://stevezmt.top', // public root redirect
      },
      encrypted: encryptedPayload,
    });

    // 1. Missing environment variable returns 500 error
    const resNoEnv = await handler(new Request('https://stevezmt.top/hidden-promo'), {});
    expect(resNoEnv.status).toBe(500);
    expect(await resNoEnv.text()).toContain('ROUTES_KEY');

    // 2. Correct environment variable decrypts and handles request successfully
    const resWithEnv = await handler(
      new Request('https://stevezmt.top/hidden-promo'),
      { ROUTES_KEY: secretKey }
    );
    expect(resWithEnv.status).toBe(302);
    expect(resWithEnv.headers.get('Location')).toContain('https://example.com/promo-landing');

    // 3. Public root / still works directly
    const resRoot = await handler(new Request('https://stevezmt.top/'), { ROUTES_KEY: secretKey });
    expect(resRoot.status).toBe(302);
    expect(resRoot.headers.get('Location')).toContain('https://stevezmt.top');
  });

  it('default minimal template redirects only root path', async () => {
    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
        notFoundUrl: 'https://stevezmt.top/404?from=${FULL_URL}',
      },
      links: {
        '/': 'https://stevezmt.top',
      },
    });

    // Root / redirects
    const resRoot = await handler(new Request('https://stevezmt.top/'));
    expect(resRoot.status).toBe(302);
    expect(resRoot.headers.get('Location')).toContain('https://stevezmt.top');

    // Other non-existent path goes to 404
    const resMissing = await handler(new Request('https://stevezmt.top/unmapped'));
    expect(resMissing.status).toBe(302);
    expect(resMissing.headers.get('Location')).toContain('/404?from=');
  });

  it('supports selective on-demand encryption of individual target URLs (< 0.1ms CPU)', async () => {
    const key = 'secret-key-123';
    const encryptedTarget = await encryptData('https://super-confidential.internal/page', key);

    const handler = createShortLinkHandler({
      settings: { domain: 'stevezmt.top' },
      links: {
        '/public': 'https://stevezmt.top/blog', // 0 crypto CPU time
        '/private': encryptedTarget,             // on-demand decryption
      },
    });

    // Public link needs no decryption
    const resPub = await handler(new Request('https://stevezmt.top/public'));
    expect(resPub.status).toBe(302);
    expect(resPub.headers.get('Location')).toContain('https://stevezmt.top/blog');

    // Private link decrypts on the fly using ROUTES_KEY
    const resPriv = await handler(new Request('https://stevezmt.top/private'), {
      ROUTES_KEY: key,
    });
    expect(resPriv.status).toBe(302);
    expect(resPriv.headers.get('Location')).toContain('https://super-confidential.internal/page');
  });
});
