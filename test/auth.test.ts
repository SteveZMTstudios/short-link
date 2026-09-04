import { describe, it, expect } from 'vitest';
import { createShortLinkHandler } from '../src/index';

describe('Password Protection & HTTP Basic Auth', () => {
  const handler = createShortLinkHandler({
    routes: [
      {
        pattern: '/protected',
        target: 'https://stevezmt.top/secret-vault',
        auth: {
          realm: 'Secret Vault',
          password: 'correct-horse-battery',
        },
      },
      {
        pattern: '/admin',
        target: 'https://stevezmt.top/admin',
        auth: {
          realm: 'Admin Zone',
          users: {
            alice: 'alice-secret',
            bob: 'bob-secret',
          },
        },
      },
    ],
  });

  it('returns 401 Unauthorized with WWW-Authenticate header informing that username is ignored', async () => {
    const request = new Request('https://link.test/protected');
    const response = await handler(request);

    expect(response.status).toBe(401);
    const wwwAuth = response.headers.get('WWW-Authenticate');
    expect(wwwAuth).not.toBeNull();
    expect(wwwAuth).toContain('Basic realm="Secret Vault (Password required, username ignored)"');
    expect(wwwAuth).toContain('charset="UTF-8"');
  });

  it('returns 401 when invalid password is provided', async () => {
    const badAuth = btoa('user:wrong-password');
    const request = new Request('https://link.test/protected', {
      headers: {
        Authorization: `Basic ${badAuth}`,
      },
    });
    const response = await handler(request);

    expect(response.status).toBe(401);
  });

  it('succeeds and redirects when valid password is provided (username is completely ignored)', async () => {
    // Arbitrary username: only password field is checked
    const goodAuth = btoa('any-random-user:correct-horse-battery');
    const request = new Request('https://link.test/protected', {
      headers: {
        Authorization: `Basic ${goodAuth}`,
      },
    });
    const response = await handler(request);

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://stevezmt.top/secret-vault');
  });

  it('verifies multi-user credentials by password (username ignored)', async () => {
    // Valid password for alice
    const aliceAuth = btoa('anyone:alice-secret');
    const resAlice = await handler(
      new Request('https://link.test/admin', {
        headers: { Authorization: `Basic ${aliceAuth}` },
      })
    );
    expect(resAlice.status).toBe(302);

    // Valid password for bob
    const bobAuth = btoa('randomuser:bob-secret');
    const resBob = await handler(
      new Request('https://link.test/admin', {
        headers: { Authorization: `Basic ${bobAuth}` },
      })
    );
    expect(resBob.status).toBe(302);

    // Wrong password
    const badAuth = btoa('alice:wrong');
    const resBad = await handler(
      new Request('https://link.test/admin', {
        headers: { Authorization: `Basic ${badAuth}` },
      })
    );
    expect(resBad.status).toBe(401);
  });

  it('verifies salted SHA-256 password hashes using domain as salt', async () => {
    // Plaintext: 'open-sesame-2026', salt: 'stevezmt.top'
    // SHA-256('open-sesame-2026:stevezmt.top') = 26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b
    const hashHandler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        '/vault': {
          target: 'https://stevezmt.top/vault-dest',
          password: 'sha256:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b',
        },
      },
    });

    // Valid plaintext password 'open-sesame-2026'
    const goodAuth = `Basic ${btoa('ignored_user:open-sesame-2026')}`;
    const resGood = await hashHandler(
      new Request('https://stevezmt.top/vault', {
        headers: { Authorization: goodAuth },
      })
    );
    expect(resGood.status).toBe(302);
    expect(resGood.headers.get('Location')).toBe('https://stevezmt.top/vault-dest');

    // Invalid password
    const badAuth = `Basic ${btoa('ignored_user:wrong-password')}`;
    const resBad = await hashHandler(
      new Request('https://stevezmt.top/vault', {
        headers: { Authorization: badAuth },
      })
    );
    expect(resBad.status).toBe(401);
  });

  it('strictly rejects raw hash string submitted as password (prevents authentication bypass)', async () => {
    const hashHandler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        '/vault': {
          target: 'https://stevezmt.top/vault-dest',
          password: 'sha256:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b',
        },
      },
    });

    // Attacker submits the known hash string directly as the password
    const attackAuth = `Basic ${btoa('attacker:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b')}`;
    const resAttack = await hashHandler(
      new Request('https://stevezmt.top/vault', {
        headers: { Authorization: attackAuth },
      })
    );
    expect(resAttack.status).toBe(401);

    const attackAuthPrefix = `Basic ${btoa('attacker:sha256:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b')}`;
    const resAttackPrefix = await hashHandler(
      new Request('https://stevezmt.top/vault', {
        headers: { Authorization: attackAuthPrefix },
      })
    );
    expect(resAttackPrefix.status).toBe(401);
  });

  it('always returns RFC 7617 401 with WWW-Authenticate header even for browser text/html requests (no custom HTML prompt)', async () => {
    const handler = createShortLinkHandler({
      settings: { domain: 'stevezmt.top' },
      links: {
        '/vip': {
          target: 'https://stevezmt.top/vip-landing',
          password: 'vip-pass-2026',
        },
      },
    });

    // Browser request with Accept: text/html
    const browserReq = new Request('https://stevezmt.top/vip', {
      headers: { Accept: 'text/html,application/xhtml+xml' },
    });
    const res = await handler(browserReq);

    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).not.toBeNull();
    expect(res.headers.get('WWW-Authenticate')).toContain('Basic realm=');
    expect(res.headers.get('WWW-Authenticate')).toContain('Password required, username ignored');
  });

  it('supports unlocking password-protected link via ?pwd query parameter without leaking to upstream target', async () => {
    const handler = createShortLinkHandler({
      settings: { domain: 'stevezmt.top' },
      links: {
        '/share': {
          target: 'https://example.com/shared-doc',
          password: 'doc-pass-123',
        },
      },
    });

    // Visiting link with ?pwd=doc-pass-123
    const res = await handler(new Request('https://stevezmt.top/share?pwd=doc-pass-123&from=chat'));
    expect(res.status).toBe(302);
    const location = res.headers.get('Location');
    expect(location).toContain('https://example.com/shared-doc');
    expect(location).toContain('from=chat');
    // Critical security check: pwd is not forwarded upstream
    expect(location).not.toContain('pwd=doc-pass-123');
  });
});
