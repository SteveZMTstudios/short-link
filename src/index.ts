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
  verifyBasicAuth,
  verifyPassword,
  createUnauthorizedResponse,
  createPasswordPromptResponse,
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
      if (val.mobile) {
        rules.push(redirectBrowser(/iPhone|iPad|Android/i, val.mobile));
      }

      // Custom escape hatch rules
      if (val.rules && Array.isArray(val.rules)) {
        rules.push(...val.rules);
      }

      // Declarative: auth
      let auth = val.auth;
      if (val.password === false) {
        auth = undefined;
      } else if (val.password !== undefined || val.passwordHash !== undefined) {
        auth = {
          useUnifiedPassword: val.password === true,
          password: typeof val.password === 'string' ? val.password : undefined,
          passwordHash: val.passwordHash,
          salt: val.salt,
          ...val.auth,
        };
      }

      routes.push({
        pattern,
        target: val.target,
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
    shortConfig.notFound?.target ||
    'https://stevezmt.top/404?from=${FULL_URL}';

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
      const notFoundConf = appConfig.notFound || {};
      const targetTemplate =
        notFoundConf.target || 'https://stevezmt.top/404?from=${FULL_URL}';
      const resolved404Url = resolveUrlTemplate(targetTemplate, url);

      if (notFoundConf.mode === 'proxy') {
        try {
          const upstreamRes = await fetch(resolved404Url, {
            headers: {
              'User-Agent':
                request.headers.get('User-Agent') || 'Cloudflare-Worker-ShortLink',
              Accept: request.headers.get('Accept') || '*/*',
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
          // If proxy fetch fails, fallback gracefully to 302 redirect
          return createTieredRedirectResponse(resolved404Url, 302);
        }
      }

      // Default redirect mode
      return createTieredRedirectResponse(resolved404Url, 302);
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

    // 5. Password / Auth protection
    if (matchedRoute.auth) {
      const defaultSalt =
        settings?.salt || settings?.domain || url.hostname;
      const unifiedPassword = resolveMasterKey(env);

      let isAuthenticated = false;
      let candidatePassword: string | undefined;

      const authHeader = request.headers.get('Authorization');
      if (authHeader && authHeader.startsWith('Basic ')) {
        isAuthenticated = await verifyBasicAuth(
          request,
          matchedRoute.auth,
          defaultSalt,
          unifiedPassword
        );
      } else {
        // Support URL query param (e.g. ?pwd=123 or ?password=123)
        const queryPwd = url.searchParams.get('pwd') || url.searchParams.get('password');
        if (queryPwd) {
          candidatePassword = queryPwd;
        } else if (request.method === 'POST') {
          // Support standalone HTML password form submission
          try {
            const contentType = request.headers.get('content-type') || '';
            if (
              contentType.includes('application/x-www-form-urlencoded') ||
              contentType.includes('multipart/form-data')
            ) {
              const formData = await request.formData();
              candidatePassword =
                ((formData.get('password') || formData.get('pwd')) as string) || undefined;
            } else if (contentType.includes('application/json')) {
              const bodyJson = (await request.json()) as { password?: string; pwd?: string };
              candidatePassword = bodyJson.password || bodyJson.pwd;
            }
          } catch (_) {}
        }

        if (candidatePassword !== undefined) {
          isAuthenticated = await verifyPassword(
            candidatePassword,
            matchedRoute.auth,
            defaultSalt,
            unifiedPassword
          );
        }
      }

      if (!isAuthenticated) {
        // Determine whether to show standalone HTML password unlock page or HTTP 401 Basic Auth modal
        const isBrowserRequest = request.headers.get('Accept')?.includes('text/html');
        const showPasswordPage =
          matchedRoute.auth.mode === 'page' ||
          (matchedRoute.auth.mode !== 'basic' && isBrowserRequest);

        if (showPasswordPage) {
          const hasFailedAttempt =
            candidatePassword !== undefined ||
            !!(authHeader && authHeader.startsWith('Basic '));
          return createPasswordPromptResponse({
            errorMessage: hasFailedAttempt ? '访问密码错误，请重新输入' : undefined,
            realm: matchedRoute.auth.realm,
          });
        }

        return createUnauthorizedResponse(matchedRoute.auth.realm);
      }
    }

    // 6. Resolve target URL
    let rawTarget =
      typeof matchedRoute.target === 'function'
        ? await matchedRoute.target(routeContext)
        : matchedRoute.target;

    // Decrypt encrypted destination targets on demand
    if (isEncryptedPayload(rawTarget)) {
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
    const finalDestination = buildDestinationUrl(
      rawTarget,
      url,
      matchedRoute.utm,
      params,
      matches
    );

    const isSensitive = !!(
      matchedRoute.auth ||
      isEncryptedPayload(matchedRoute.target) ||
      (matchedRoute.rules && matchedRoute.rules.length > 0)
    );

    // 8. Return 3-tier redirect response (HTTP 302 + Meta refresh + inline script)
    return createTieredRedirectResponse(
      finalDestination,
      matchedRoute.redirectStatus || 302,
      undefined,
      isSensitive
    );
  };
}

// Default export for Cloudflare Workers runtime
export default {
  fetch: createShortLinkHandler(defaultConfig),
};
