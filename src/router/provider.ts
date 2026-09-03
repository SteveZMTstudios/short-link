/**
 * Route Provider Implementations.
 * Decouples link definitions from the Cloudflare Worker request handler.
 *
 * Supports:
 * 1. StaticRouteProvider: Default GitOps mode, reads from in-code TypeScript definitions.
 * 2. KvRouteProvider: Dynamic mode, reads short links from Cloudflare KV (e.g. SHORT_LINK_KV).
 * 3. CompositeRouteProvider: Combines static fallback routes with dynamic KV overrides.
 */

import {
  ShortLinkConfig,
  RouteDefinition,
  RouteProvider,
  RouteProviderContext,
  LinkItem,
} from '../types';
import { config as defaultStaticConfig } from '../config/routes';

/**
 * Default provider using static in-code ShortLinkConfig.
 */
export class StaticRouteProvider implements RouteProvider {
  readonly isStatic = true;

  constructor(private readonly config: ShortLinkConfig = defaultStaticConfig) {}

  getRoutes(): ShortLinkConfig {
    return this.config;
  }
}

export interface KvRouteProviderOptions {
  /** Name of the KV binding in Env (defaults to 'SHORT_LINK_KV') */
  kvBindingName?: string;
  /** Key inside KV storing the serialized ShortLinkConfig JSON (defaults to 'SHORT_LINK_CONFIG') */
  configKey?: string;
  /** Optional static base config to merge with KV routes */
  fallbackConfig?: ShortLinkConfig;
}

/**
 * Cloudflare KV Route Provider.
 * Allows managing routes dynamically via Cloudflare KV without redeploying Worker code.
 */
export class KvRouteProvider implements RouteProvider {
  private readonly bindingName: string;
  private readonly configKey: string;
  private readonly fallbackConfig?: ShortLinkConfig;

  constructor(options: KvRouteProviderOptions = {}) {
    this.bindingName = options.kvBindingName || 'SHORT_LINK_KV';
    this.configKey = options.configKey || 'SHORT_LINK_CONFIG';
    this.fallbackConfig = options.fallbackConfig;
  }

  async getRoutes(ctx?: RouteProviderContext): Promise<ShortLinkConfig> {
    const env = ctx?.env;
    const kv = env ? (env[this.bindingName] as KVNamespace | undefined) : undefined;

    if (!kv) {
      // If KV binding is not available, gracefully fallback to static configuration
      return this.fallbackConfig || defaultStaticConfig;
    }

    try {
      // 1. Try reading whole config payload JSON
      const rawJson = await kv.get(this.configKey, 'text');
      if (rawJson) {
        const parsed = JSON.parse(rawJson) as ShortLinkConfig;
        if (this.fallbackConfig) {
          return {
            ...this.fallbackConfig,
            ...parsed,
            settings: { ...this.fallbackConfig.settings, ...parsed.settings },
            links: { ...this.fallbackConfig.links, ...parsed.links },
          };
        }
        return parsed;
      }
    } catch (err) {
      console.error('[KvRouteProvider] Failed to parse KV route configuration:', err);
    }

    return this.fallbackConfig || defaultStaticConfig;
  }
}

/**
 * Composite Provider: Merges a base provider with dynamic KV or external overrides.
 */
export class CompositeRouteProvider implements RouteProvider {
  constructor(
    private readonly baseProvider: RouteProvider,
    private readonly dynamicProvider: RouteProvider
  ) {}

  async getRoutes(ctx?: RouteProviderContext): Promise<ShortLinkConfig> {
    const [base, dynamic] = await Promise.all([
      Promise.resolve(this.baseProvider.getRoutes(ctx)),
      Promise.resolve(this.dynamicProvider.getRoutes(ctx)),
    ]);

    const baseConfig: ShortLinkConfig = Array.isArray(base) ? { routes: base } : base;
    const dynamicConfig: ShortLinkConfig = Array.isArray(dynamic) ? { routes: dynamic } : dynamic;

    // Dynamic routes override base routes with the same pattern
    const dynamicRoutes = dynamicConfig.routes || [];
    const baseRoutes = baseConfig.routes || [];
    const dynamicPatterns = new Set(dynamicRoutes.map((r) => r.pattern));
    const mergedRoutes = [
      ...dynamicRoutes,
      ...baseRoutes.filter((r) => !dynamicPatterns.has(r.pattern)),
    ];

    return {
      ...baseConfig,
      ...dynamicConfig,
      settings: { ...baseConfig.settings, ...dynamicConfig.settings },
      links: { ...baseConfig.links, ...dynamicConfig.links },
      routes: mergedRoutes,
    };
  }
}

/**
 * Normalizes user input into a valid RouteProvider.
 */
export function createRouteProvider(
  input?: ShortLinkConfig | RouteProvider
): RouteProvider {
  if (input && typeof (input as RouteProvider).getRoutes === 'function') {
    return input as RouteProvider;
  }
  return new StaticRouteProvider((input as ShortLinkConfig) || defaultStaticConfig);
}
