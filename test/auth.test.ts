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

  it('returns 401 Unauthorized with WWW-Authenticate header when no credentials sent', async () => {
    const request = new Request('https://link.test/protected');
    const response = await handler(request);

    expect(response.status).toBe(401);
    const wwwAuth = response.headers.get('WWW-Authenticate');
    expect(wwwAuth).toBe('Basic realm="Secret Vault", charset="UTF-8"');
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

  it('succeeds and redirects when valid single password is provided', async () => {
    const goodAuth = btoa('anyuser:correct-horse-battery');
    const request = new Request('https://link.test/protected', {
      headers: {
        Authorization: `Basic ${goodAuth}`,
      },
    });
    const response = await handler(request);

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://stevezmt.top/secret-vault');
  });

  it('verifies multi-user credentials correctly', async () => {
    // Correct alice
    const aliceAuth = btoa('alice:alice-secret');
    const resAlice = await handler(
      new Request('https://link.test/admin', {
        headers: { Authorization: `Basic ${aliceAuth}` },
      })
    );
    expect(resAlice.status).toBe(302);

    // Wrong alice password
    const badAliceAuth = btoa('alice:wrong');
    const resBad = await handler(
      new Request('https://link.test/admin', {
        headers: { Authorization: `Basic ${badAliceAuth}` },
      })
    );
    expect(resBad.status).toBe(401);

    // Unknown user
    const eveAuth = btoa('eve:any');
    const resEve = await handler(
      new Request('https://link.test/admin', {
        headers: { Authorization: `Basic ${eveAuth}` },
      })
    );
    expect(resEve.status).toBe(401);
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
    const goodAuth = `Basic ${btoa('steve:open-sesame-2026')}`;
    const resGood = await hashHandler(
      new Request('https://stevezmt.top/vault', {
        headers: { Authorization: goodAuth },
      })
    );
    expect(resGood.status).toBe(302);
    expect(resGood.headers.get('Location')).toBe('https://stevezmt.top/vault-dest');

    // Invalid password
    const badAuth = `Basic ${btoa('steve:wrong-password')}`;
    const resBad = await hashHandler(
      new Request('https://stevezmt.top/vault', {
        headers: { Authorization: badAuth },
      })
    );
    expect(resBad.status).toBe(401);
  });

  it('supports unified password protection (password: true) loaded from .env (ROUTES_KEY)', async () => {
    const unifiedMasterSecret = 'my-master-pass-2026';

    const handler = createShortLinkHandler({
      settings: {
        domain: 'stevezmt.top',
      },
      links: {
        // password: true 启用统一密码保护，无需在代码中硬编码任何密码
        '/internal': {
          target: 'https://stevezmt.top/internal-dashboard',
          password: true,
        },
      },
    });

    const env = { ROUTES_KEY: unifiedMasterSecret };

    // 1. 未提供 Authorization 时返回 401
    const resNoAuth = await handler(new Request('https://stevezmt.top/internal'), env);
    expect(resNoAuth.status).toBe(401);

    // 2. 提供错误的密码返回 401
    const resBad = await handler(
      new Request('https://stevezmt.top/internal', {
        headers: { Authorization: `Basic ${btoa('guest:wrong-password')}` },
      }),
      env
    );
    expect(resBad.status).toBe(401);

    // 3. 提供与 .env (ROUTES_KEY) 相同的统一密码成功重定向 302
    const resGood = await handler(
      new Request('https://stevezmt.top/internal', {
        headers: { Authorization: `Basic ${btoa('guest:my-master-pass-2026')}` },
      }),
      env
    );
    expect(resGood.status).toBe(302);
    expect(resGood.headers.get('Location')).toContain('https://stevezmt.top/internal-dashboard');
  });

  it('renders standalone HTML password unlock page for browser requests without Basic Auth modal', async () => {
    const handler = createShortLinkHandler({
      settings: { domain: 'stevezmt.top' },
      links: {
        '/vip': {
          target: 'https://stevezmt.top/vip-landing',
          password: 'vip-pass-2026',
        },
      },
    });

    // 浏览器发起请求 (带 Accept: text/html)
    const browserReq = new Request('https://stevezmt.top/vip', {
      headers: { Accept: 'text/html,application/xhtml+xml' },
    });
    const res = await handler(browserReq);

    expect(res.status).toBe(401);
    // 关键：不能有 WWW-Authenticate 标头，否则浏览器强制弹原生“账号密码”框！
    expect(res.headers.get('WWW-Authenticate')).toBeNull();
    expect(res.headers.get('Content-Type')).toContain('text/html');

    const html = await res.text();
    expect(html).toContain('受保护的短链接');
    expect(html).toContain('name="password"');
    // 确保没有账号/用户名输入框
    expect(html).not.toContain('name="username"');
  });

  it('supports unlocking password-protected link via form POST', async () => {
    const handler = createShortLinkHandler({
      settings: { domain: 'stevezmt.top' },
      links: {
        '/vip': {
          target: 'https://stevezmt.top/vip-landing',
          password: 'vip-pass-2026',
        },
      },
    });

    // 1. POST 错误密码
    const formDataBad = new FormData();
    formDataBad.set('password', 'wrong-pass');
    const resBad = await handler(
      new Request('https://stevezmt.top/vip', {
        method: 'POST',
        headers: { Accept: 'text/html' },
        body: formDataBad,
      })
    );
    expect(resBad.status).toBe(401);
    const htmlBad = await resBad.text();
    expect(htmlBad).toContain('访问密码错误，请重新输入');

    // 2. POST 正确密码 -> 302 重定向到真实目标
    const formDataGood = new FormData();
    formDataGood.set('password', 'vip-pass-2026');
    const resGood = await handler(
      new Request('https://stevezmt.top/vip', {
        method: 'POST',
        headers: { Accept: 'text/html' },
        body: formDataGood,
      })
    );
    expect(resGood.status).toBe(302);
    expect(resGood.headers.get('Location')).toContain('https://stevezmt.top/vip-landing');
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

    // 访问带 ?pwd=doc-pass-123 链接
    const res = await handler(new Request('https://stevezmt.top/share?pwd=doc-pass-123&from=chat'));
    expect(res.status).toBe(302);
    const location = res.headers.get('Location');
    expect(location).toContain('https://example.com/shared-doc');
    expect(location).toContain('from=chat');
    // 关键安全防泄漏：pwd 不能透传至第三方目标
    expect(location).not.toContain('pwd=doc-pass-123');
  });
});
