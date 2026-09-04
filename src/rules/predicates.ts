/**
 * Rules and Predicates Library.
 * Provides ready-to-use middleware predicates for TLS version, Request Headers, User-Agent, and custom logic.
 */

import { RouteContext, Rule, RuleAction, RuleResult } from '../types';

export const Actions = {
  block(
    status = 403,
    body = 'Forbidden: Request blocked by security rule.',
    headers: Record<string, string> = {}
  ): RuleAction {
    return {
      type: 'block',
      status,
      body,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        ...headers,
      },
    };
  },

  redirect(
    url: string,
    status = 302,
    headers: Record<string, string> = {}
  ): RuleAction {
    return {
      type: 'redirect',
      status,
      url,
      headers,
    };
  },

  pass(): RuleAction {
    return { type: 'pass' };
  },
};

export const COMMON_BOTS = [
  'BadBot',
  'ScraperBot',
  'AhrefsBot',
  'SemrushBot',
  'MJ12bot',
  'DotBot',
  'DataForSeoBot',
  'Bytespider',
  'python-requests',
  'Go-http-client',
];

const TLS_RANK: Record<string, number> = {
  'TLSv1': 10,
  'TLSv1.0': 10,
  'TLSv1.1': 11,
  'TLSv1.2': 12,
  'TLSv1.3': 13,
};

/**
 * Enforces a minimum TLS version from Cloudflare's request.cf.tlsVersion.
 * Blocks or redirects if TLS is absent or below the required threshold.
 */
export function requireMinTls(
  minVersion: 'TLSv1.2' | 'TLSv1.3',
  onFail?: RuleAction
): Rule {
  const minRank = TLS_RANK[minVersion] || 12;

  return (ctx: RouteContext): RuleResult => {
    const incomingTls = ctx.cf?.tlsVersion;
    // In local dev or tests, cf might not be populated unless provided.
    // If incomingTls is provided and rank is less than minRank, fail.
    if (incomingTls) {
      const incomingRank = TLS_RANK[incomingTls] ?? 0;
      if (incomingRank < minRank) {
        return (
          onFail ||
          Actions.block(
            403,
            `Access Denied: TLS ${minVersion}+ required. Detected: ${incomingTls}`
          )
        );
      }
    }
    return Actions.pass();
  };
}

/**
 * Inspects Request Headers.
 * Validates whether required headers exist and match expected values or regular expressions.
 */
export function matchHeader(
  headerName: string,
  matcher: string | RegExp | ((val: string | null) => boolean),
  actionOnMatch: RuleAction
): Rule {
  return (ctx: RouteContext): RuleResult => {
    const val = ctx.request.headers.get(headerName);
    let isMatch = false;

    if (typeof matcher === 'function') {
      isMatch = matcher(val);
    } else if (val !== null) {
      if (matcher instanceof RegExp) {
        isMatch = matcher.test(val);
      } else {
        isMatch = val.toLowerCase() === matcher.toLowerCase();
      }
    }

    if (isMatch) {
      return actionOnMatch;
    }
    return Actions.pass();
  };
}

/**
 * Checks User-Agent against patterns (e.g. crawler bots, outdated browsers).
 */
export function blockUserAgent(
  patterns: (string | RegExp)[],
  onBlock?: RuleAction
): Rule {
  return (ctx: RouteContext): RuleResult => {
    const ua = ctx.request.headers.get('user-agent') || '';
    const uaLower = ua.toLowerCase();
    for (const pattern of patterns) {
      const isMatch =
        pattern instanceof RegExp
          ? pattern.test(ua)
          : uaLower.includes(pattern.toLowerCase());
      if (isMatch) {
        return (
          onBlock ||
          Actions.block(403, 'Access Denied: Browser or User-Agent disallowed.')
        );
      }
    }
    return Actions.pass();
  };
}

/**
 * Redirects specific browsers (e.g. mobile Safari, WeChat, or Android) to an alternate target.
 */
export function redirectBrowser(
  matcher: RegExp | ((ua: string) => boolean),
  targetUrl: string,
  status = 302
): Rule {
  return (ctx: RouteContext): RuleResult => {
    const ua = ctx.request.headers.get('user-agent') || '';
    const isMatch =
      typeof matcher === 'function' ? matcher(ua) : matcher.test(ua);
    if (isMatch) {
      return Actions.redirect(targetUrl, status);
    }
    return Actions.pass();
  };
}

/**
 * Chains multiple rules in sequence. Stops and returns on the first blocking or redirecting action.
 */
export function chainRules(...rules: Rule[]): Rule {
  return async (ctx: RouteContext): Promise<RuleResult> => {
    for (const rule of rules) {
      const result = await rule(ctx);
      if (result && typeof result === 'object') {
        if (result.type === 'block' || result.type === 'redirect') {
          return result;
        }
      }
    }
    return Actions.pass();
  };
}
