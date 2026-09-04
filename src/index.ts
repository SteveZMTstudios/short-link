/**
 * Main Cloudflare Worker entry point for short-link redirection service.
 * Pulls complexity downward, defines errors out of existence, and exposes a clean, intuitive interface.
 * Supports transparent symmetric decryption of routes from environment variables (ROUTES_KEY).
 * Decouples route storage via RouteProvider (Static, KV, external).
 */

import {
  AppConfig,
  ShortLinkConfig,
  RouteContext,
  RouteDefinition,
  Rule,
  Env,
  LinkItem,
  type RouteProvider,
  SettingsConfig,
} from './types';
import { config as defaultConfig } from './config/routes';
import {
  compileRouteTable,
  findMatchingCompiledRoute,
  normalizePattern,
  CompiledRoute,
} from './router/matcher';
import {
  createRouteProvider,
  StaticRouteProvider,
  KvRouteProvider,
  CompositeRouteProvider,
} from './router/provider';
import { buildDestinationUrl, resolveUrlTemplate } from './utils/url';
import { createTieredRedirectResponse, createRobotsTxtResponse } from './utils/response';
import {
  authenticateRequest,
  createUnauthorizedResponse,
} from './auth/basicAuth';
import {
  requireMinTls,
  blockUserAgent,
  redirectBrowser,
  COMMON_BOTS,
} from './rules/predicates';
import { decryptData, isEncryptedPayload } from './utils/crypto';

/**
 * Resolves master encryption/auth key from environment with unified fallback ordering.
 */
export function resolveMasterKey(env?: Env): string | undefined {
  return (
    (env?.ROUTES_KEY as string | undefined) ||
    (env?.AUTH_PASSWORD as string | undefined) ||
    (env?.MASTER_KEY as string | undefined) ||
    (env?.CONFIG_KEY as string | undefined) ||
    (env?.PASSWORD as string | undefined) ||
    (env?.ENCRYPTION_KEY as string | undefined)
  );
}

export type { RouteProvider };
export {
  StaticRouteProvider,
  KvRouteProvider,
  CompositeRouteProvider,
  createRouteProvider,
};

/**
 * Normalizes user-friendly ShortLinkConfig into executable AppConfig.
 */
export function normalizeConfig(
  shortConfig: ShortLinkConfig,
  decryptedLinks?: Record<string, LinkItem>
): AppConfig {
  const routes: RouteDefinition[] = [];
  const settings = shortConfig.settings || {};
  const baseDomain = settings.domain;
  const defaultUtm = settings.defaultUtm;

  const mergedLinks: Record<string, LinkItem> = {
    ...shortConfig.links,
    ...decryptedLinks,
  };

  // 1. Process declarative links mapping
  for (const [key, val] of Object.entries(mergedLinks)) {
    const pattern = normalizePattern(key, baseDomain);

    if (typeof val === 'string') {
      routes.push({
        pattern,
        target: val,
        utm: defaultUtm,
      });
    } else if (val && typeof val === 'object') {
      const rules: Rule[] = [];

      // Declarative: min TLS version
      if (val.minTls) {
        const tlsVer =
          val.minTls === '1.3' || val.minTls === 'TLSv1.3'
            ? 'TLSv1.3'
            : 'TLSv1.2';
        rules.push(requireMinTls(tlsVer));
      }

      // Declarative: block crawlers / bots
      if (val.blockBots) {
        rules.push(blockUserAgent(COMMON_BOTS));
      }

      // Declarative: mobile redirection
      // Integrate into target resolution pipeline so parameters (:slug, $1), Query params, and UTM are fully preserved
      let targetResolver = val.target;
      if (val.mobile) {
        const baseTarget = val.target;
        const mobileTarget = val.mobile;
        targetResolver = (ctx: RouteContext) => {
          const ua = ctx.request.headers.get('user-agent') || '';
          if (/iPhone|iPad|Android/i.test(ua)) {
            return mobileTarget;
          }
          return typeof baseTarget === 'function' ? baseTarget(ctx) : baseTarget;
        };
      }

      // Custom escape hatch rules
      if (val.rules && Array.isArray(val.rules)) {
        rules.push(...val.rules);
      }

      // Declarative: auth
      let auth = val.auth;
      if (val.password === false) {
        auth = undefined;
      } else if (val.password === true) {
        auth = {
          useMasterPassword: true,
          salt: val.salt,
          ...val.auth,
        };
      } else if (typeof val.password === 'string' || val.passwordHash !== undefined) {
        auth = {
          password: typeof val.password === 'string' ? val.password : undefined,
          passwordHash: val.passwordHash,
          salt: val.salt,
          ...val.auth,
        };
      }

      routes.push({
        pattern,
        target: targetResolver,
        redirectStatus: val.redirectStatus,
        utm: { ...defaultUtm, ...val.utm },
        auth,
        rules: rules.length > 0 ? rules : undefined,
      });
    }
  }

  // 2. Append legacy/direct RouteDefinition array
  if (shortConfig.routes && Array.isArray(shortConfig.routes)) {
    for (const r of shortConfig.routes) {
      routes.push({
        ...r,
        pattern: normalizePattern(r.pattern, baseDomain),
      });
    }
  }

  const notFoundTarget =
    settings.notFoundUrl ||
    shortConfig.notFound?.target;

  const notFoundMode =
    settings.notFoundMode || shortConfig.notFound?.mode || 'redirect';

  return {
    routes,
    notFound: {
      target: notFoundTarget,
      mode: notFoundMode,
    },
  };
}

interface ResolvedRuntimeConfig {
  appConfig: AppConfig;
  compiledRoutes: CompiledRoute[];
  settings?: SettingsConfig;
}

export function createDefault404Response(): Response {
  return new Response(null, {
    status: 404,
    statusText: 'Not Found',
    headers: {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
}

async function handleNotFound(
  appConfig: AppConfig,
  url: URL,
  request: Request
): Promise<Response> {
  const notFoundConf = appConfig.notFound || {};
  const targetTemplate = notFoundConf.target;

  // 如果没有配置 404 目标地址，不使用任何外部回路，直接返回默认 404 页面
  if (!targetTemplate || !targetTemplate.trim()) {
    return createDefault404Response();
  }

  const resolved404Url = resolveUrlTemplate(targetTemplate, url);

  if (notFoundConf.mode === 'proxy') {
    // Prevent recursive proxy loops
    if (request.headers.get('X-ShortLink-Proxy')) {
      return createDefault404Response();
    }
    try {
      const upstreamRes = await fetch(resolved404Url, {
        headers: {
          'User-Agent':
            request.headers.get('User-Agent') || 'Cloudflare-Worker-ShortLink',
          Accept: request.headers.get('Accept') || '*/*',
          'X-ShortLink-Proxy': '1',
        },
      });
      return new Response(upstreamRes.body, {
        status: 404,
        headers: {
          'Content-Type':
            upstreamRes.headers.get('Content-Type') ||
            'text/html; charset=utf-8',
          'Cache-Control': 'no-cache, no-store',
        },
      });
    } catch {
      // If proxy fetch fails, fallback to tiered redirect response with status 404
      return createTieredRedirectResponse(resolved404Url, 404);
    }
  }

  // 状态码忠实返回 404，并通过 HTML Meta Refresh + JS Replace 执行客户端重定向
  return createTieredRedirectResponse(resolved404Url, 404);
}

/**
 * Creates a fetch request handler configured with custom or default routes.
 * Supports symmetric decryption of routes from environment variables.
 * Supports custom RouteProvider (e.g. StaticRouteProvider, KvRouteProvider).
 */
export function createShortLinkHandler(
  configOrProvider: ShortLinkConfig | RouteProvider = defaultConfig
) {
  const provider = createRouteProvider(configOrProvider);
  const isStatic = provider.isStatic ?? (provider instanceof StaticRouteProvider);
  let cachedRuntimeConfig: ResolvedRuntimeConfig | null = null;

  return async function handleRequest(
    request: Request,
    env?: Env,
    ctx?: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // 0. Robots.txt edge interception (disallow all crawlers immediately, 0 overhead)
    if (url.pathname === '/robots.txt') {
      return createRobotsTxtResponse();
    }

    // 1. Resolve configuration (cached for static provider, evaluated on demand for dynamic providers)
    let runtimeConfig = cachedRuntimeConfig;

    if (!runtimeConfig || !isStatic) {
      const rawRoutes = await provider.getRoutes({ request, env });
      const userConfig: ShortLinkConfig = Array.isArray(rawRoutes)
        ? { routes: rawRoutes }
        : rawRoutes;

      let appConfig: AppConfig;

      if (userConfig.encrypted) {
        const encryptionKey = resolveMasterKey(env);

        if (!encryptionKey) {
          return new Response(
            'Configuration Error: This short-link deployment uses encrypted routes, but no decryption key was found in environment variables (ROUTES_KEY).',
            { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
          );
        }

        try {
          const decryptedLinks = await decryptData<Record<string, LinkItem>>(
            userConfig.encrypted,
            String(encryptionKey)
          );
          appConfig = normalizeConfig(userConfig, decryptedLinks);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          return new Response(
            `Configuration Decryption Error: ${msg}`,
            { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
          );
        }
      } else {
        appConfig = normalizeConfig(userConfig);
      }

      const compiledRoutes = compileRouteTable(appConfig.routes);
      runtimeConfig = {
        appConfig,
        compiledRoutes,
        settings: userConfig.settings,
      };

      if (isStatic) {
        cachedRuntimeConfig = runtimeConfig;
      }
    }

    const { appConfig, compiledRoutes, settings } = runtimeConfig;

    // 2. Match route using pre-compiled route table (0 regex recompilation on request)
    const matched = findMatchingCompiledRoute(compiledRoutes, url);

    // 3. If no route matches, trigger 404 fallback
    if (!matched) {
      return handleNotFound(appConfig, url, request);
    }

    const matchedRoute = matched.route || matched;
    const params = matched.params || {};
    const matches = matched.matches || [];

    const routeContext: RouteContext = {
      request,
      url,
      fullUrl: request.url,
      hostname: url.hostname,
      pathname: url.pathname,
      cf: (request as unknown as { cf?: IncomingRequestCfProperties }).cf,
      params,
      matches,
    };

    // 4. Evaluate rules (TLS, Request Headers, User-Agent, browser filters)
    if (matchedRoute.rules && matchedRoute.rules.length > 0) {
      for (const rule of matchedRoute.rules) {
        const action = await rule(routeContext);

        // Explicit boolean false means access denied / blocked
        if (action === false) {
          return new Response('Forbidden: Request blocked by security rule.', {
            status: 403,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          });
        }

        if (action && typeof action === 'object') {
          if (action.type === 'block') {
            return new Response(action.body || 'Forbidden', {
              status: action.status || 403,
              headers:
                action.headers || { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          }
          if (action.type === 'redirect') {
            return createTieredRedirectResponse(
              action.url,
              action.status || 302,
              action.headers
            );
          }
        }
      }
    }

    // 5. Password / Auth protection (Standard HTTP Basic Auth, username ignored)
    if (matchedRoute.auth) {
      const defaultSalt =
        settings?.salt || settings?.domain || url.hostname;
      const masterKey = resolveMasterKey(env);
      const authResult = await authenticateRequest(
        request,
        url,
        matchedRoute.auth,
        defaultSalt,
        masterKey
      );
      if (!authResult.authenticated) {
        return authResult.response || createUnauthorizedResponse(matchedRoute.auth.realm);
      }
    }

    // 6. Resolve target URL
    let rawTarget =
      typeof matchedRoute.target === 'function'
        ? await matchedRoute.target(routeContext)
        : matchedRoute.target;

    let wasEncrypted = isEncryptedPayload(matchedRoute.target);

    // Decrypt encrypted destination targets on demand
    if (isEncryptedPayload(rawTarget)) {
      wasEncrypted = true;
      const encryptionKey = resolveMasterKey(env);
      if (!encryptionKey) {
        return new Response(
          'Configuration Error: This target link is encrypted, but ROUTES_KEY is missing in environment variables.',
          { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
        );
      }
      try {
        rawTarget = await decryptData<string>(rawTarget, String(encryptionKey));
      } catch {
        return new Response(
          'Decryption Error: Failed to decrypt destination target with ROUTES_KEY.',
          { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
        );
      }
    }

    // 7. Build final destination with dynamic param interpolation, merged query params & default UTM tags
    let finalDestination: string;
    try {
      finalDestination = buildDestinationUrl(
        rawTarget,
        url,
        matchedRoute.utm,
        params,
        matches
      );
    } catch {
      // Define Errors Out of Existence: gracefully fall back to 404 on malformed target URLs
      return handleNotFound(appConfig, url, request);
    }

    // Only routes with an access password (auth) must NOT be cached.
    // ROUTE_KEY protects routing rules from being dumped in one click; encrypted targets without password remain edge-cacheable.
    const isSensitive = !!matchedRoute.auth;

    // 8. Return 3-tier redirect response
    // RFC 7231 Section 6.4.4: 303 See Other ensures browser POST redirect switches to GET
    const redirectStatus =
      request.method === 'POST'
        ? 303
        : (matchedRoute.redirectStatus || 302);

    return createTieredRedirectResponse(
      finalDestination,
      redirectStatus,
      undefined,
      isSensitive
    );
  };
}

// Default export for Cloudflare Workers runtime
export default {
  fetch: createShortLinkHandler(defaultConfig),
};
