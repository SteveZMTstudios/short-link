import { describe, it, expect, vi } from 'vitest';
import {
  createShortLinkHandler,
  StaticRouteProvider,
  KvRouteProvider,
  CompositeRouteProvider,
  RouteProvider,
} from '../src/index';

describe('Route Provider Abstraction & KV Integration', () => {
  it('works with StaticRouteProvider', async () => {
    const provider = new StaticRouteProvider({
      links: {
        '/docs': 'https://example.com/docs',
      },
    });

    const handler = createShortLinkHandler(provider);
    const res = await handler(new Request('https://example.com/docs'));
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('https://example.com/docs');
  });

  it('works with a custom dynamic RouteProvider', async () => {
    const dynamicProvider: RouteProvider = {
      getRoutes: vi.fn().mockResolvedValue({
        links: {
          '/dynamic-link': 'https://dynamic-target.com/page',
        },
      }),
    };

    const handler = createShortLinkHandler(dynamicProvider);
    const res = await handler(new Request('https://example.com/dynamic-link'));
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('https://dynamic-target.com/page');
    expect(dynamicProvider.getRoutes).toHaveBeenCalled();
  });

  it('works with KvRouteProvider when KV namespace is provided in env', async () => {
    // Mock Cloudflare KV namespace
    const mockKv = {
      get: vi.fn().mockImplementation(async (key: string) => {
        if (key === 'SHORT_LINK_CONFIG') {
          return JSON.stringify({
            links: {
              '/kv-link': 'https://kv-target.com/landing',
            },
          });
        }
        return null;
      }),
    };

    const kvProvider = new KvRouteProvider({
      kvBindingName: 'MY_KV',
      fallbackConfig: {
        links: {
          '/fallback': 'https://fallback.com',
        },
      },
    });

    const handler = createShortLinkHandler(kvProvider);

    // Call with KV in env
    const res = await handler(
      new Request('https://example.com/kv-link'),
      { MY_KV: mockKv as unknown as KVNamespace }
    );
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('https://kv-target.com/landing');
  });

  it('works with CompositeRouteProvider merging static and dynamic routes', async () => {
    const staticProvider = new StaticRouteProvider({
      links: {
        '/static-page': 'https://static.com',
      },
    });

    const dynamicProvider: RouteProvider = {
      getRoutes: () => ({
        links: {
          '/dynamic-page': 'https://dynamic.com',
        },
      }),
    };

    const composite = new CompositeRouteProvider(staticProvider, dynamicProvider);
    const handler = createShortLinkHandler(composite);

    const resStatic = await handler(new Request('https://example.com/static-page'));
    expect(resStatic.status).toBe(302);
    expect(resStatic.headers.get('Location')).toContain('https://static.com');

    const resDynamic = await handler(new Request('https://example.com/dynamic-page'));
    expect(resDynamic.status).toBe(302);
    expect(resDynamic.headers.get('Location')).toContain('https://dynamic.com');
  });
});
