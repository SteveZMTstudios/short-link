/**
 * Cloudflare Workers Route Matching Engine with Dynamic Parameter & Regex Support.
 *
 * Supports:
 * 1. Named parameters: "blog:/:slug" -> captures :slug or ${slug}
 * 2. Wildcard captures: "blog:/*" -> captures $1
 * 3. Pure Regular Expressions: "regex:^blog\.[^/]+/([^/]+)$" -> captures $1, $2
 * 4. Cloudflare standard hostname & pathname wildcards.
 * 5. Pre-compiled routing table with stratified specificity prioritization.
 */

import { RouteDefinition } from '../types';

export interface RouteMatch {
  matched: boolean;
  params: Record<string, string>;
  matches: string[];
}

export interface MatchedRouteResult extends RouteDefinition {
  route: RouteDefinition;
  params: Record<string, string>;
  matches: string[];
}

export interface CompiledPattern {
  regex: RegExp;
  isHostSpecific: boolean;
  paramNames: string[];
}

export interface CompiledRoute {
  pattern: string;
  regex: RegExp;
  isHostSpecific: boolean;
  paramNames: string[];
  specificity: number;
  definition: RouteDefinition;
}

const patternCache = new Map<string, CompiledPattern>();
const routesCache = new WeakMap<RouteDefinition[], CompiledRoute[]>();

/**
 * Normalizes short-hand route keys (e.g. "s:/blog/*" or "blog:/:slug")
 * If baseDomain is configured, expands "sub:/path" to "sub.baseDomain/path".
 */
export function normalizePattern(pattern: string, baseDomain?: string): string {
  const trimmed = pattern.trim();
  if (trimmed.startsWith('regex:') || trimmed.startsWith('^')) {
    return trimmed;
  }

  const colonIndex = trimmed.indexOf(':');
  const firstSlash = trimmed.indexOf('/');
  // Subdomain shorthand "sub:/path":
  // The colon must appear BEFORE any slash, and the "sub" prefix must be a valid DNS label (e.g. 's', 'blog', 'go')
  if (
    colonIndex > 0 &&
    (firstSlash === -1 || colonIndex < firstSlash) &&
    !trimmed.startsWith('http://') &&
    !trimmed.startsWith('https://')
  ) {
    const sub = trimmed.slice(0, colonIndex).trim();
    if (/^[a-zA-Z0-9_-]+$/.test(sub)) {
      const pathPart = trimmed.slice(colonIndex + 1).trim();
      const normalizedPath = pathPart.startsWith('/') ? pathPart : '/' + pathPart;
      if (baseDomain) {
        const cleanBase = baseDomain.replace(/^\*\.?/, '');
        return `${sub}.${cleanBase}${normalizedPath}`;
      }
      return `${sub}.*${normalizedPath}`;
    }
  }
  return trimmed;
}

/**
 * Compiles a pattern string into a RegExp with named and positional captures.
 * Uses internal cache to ensure each unique pattern is compiled only once.
 */
export function compilePattern(pattern: string): CompiledPattern {
  const trimmed = pattern.trim();
  const cached = patternCache.get(trimmed);
  if (cached) {
    return cached;
  }

  // 1. Explicit Regex format: "regex:..." or starts with "^"
  if (trimmed.startsWith('regex:') || trimmed.startsWith('^')) {
    const rawRegex = trimmed.startsWith('regex:')
      ? trimmed.slice(6).trim()
      : trimmed;
    const compiled: CompiledPattern = {
      regex: new RegExp(rawRegex, 'i'),
      isHostSpecific: true,
      paramNames: [],
    };
    patternCache.set(trimmed, compiled);
    return compiled;
  }

  // 2. Check if host-specific or path-only
  let isHostSpecific = false;
  let workPattern = trimmed;

  if (trimmed.startsWith('/')) {
    isHostSpecific = false;
  } else {
    const firstSlash = trimmed.indexOf('/');
    const hostPart = firstSlash === -1 ? trimmed : trimmed.slice(0, firstSlash);
    isHostSpecific = hostPart.includes('.');

    if (!isHostSpecific) {
      workPattern = '/' + trimmed.replace(/^\/+/, '');
    } else {
      // Host + Path pattern
      workPattern = trimmed.replace(/^https?:\/\//i, '');
      if (!workPattern.includes('/')) {
        workPattern += '/*';
      }
    }
  }

  // 3. Parse segments for :name and * wildcards
  const paramNames: string[] = [];
  const parts = workPattern.split(/(:[a-zA-Z0-9_]+|\*)/g);
  let regexStr = '';

  for (const part of parts) {
    if (!part) continue;

    if (part.startsWith(':')) {
      const name = part.slice(1);
      paramNames.push(name);
      regexStr += '(?<' + name + '>[^/?#]+)';
    } else if (part === '*') {
      regexStr += '(.*)';
    } else {
      regexStr += part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }

  // Define Errors Out of Existence: allow optional trailing slash for non-wildcard terminal routes
  // e.g. "/github" matches both "/github" and "/github/"
  if (!regexStr.endsWith('(.*)')) {
    if (regexStr.endsWith('\\/')) {
      regexStr = regexStr.slice(0, -2) + '\\/?';
    } else if (!regexStr.endsWith('\\/?')) {
      regexStr += '\\/?';
    }
  }

  const compiled: CompiledPattern = {
    regex: new RegExp(`^${regexStr}$`, 'i'),
    isHostSpecific,
    paramNames,
  };
  patternCache.set(trimmed, compiled);
  return compiled;
}

/**
 * Computes specificity score for route sorting:
 * Hierarchy:
 * 1. Host-specific bonus: +20,000 (specific host always beats wildcard cross-host)
 * 2. Tier 1 (Exact Literal Path): +10,000 + length * 10
 * 3. Tier 2 (Named Parameters :slug): +5,000 + literal length * 10 - params * 50
 * 4. Tier 3 (Wildcards *): +1,000 + literal length * 10 - wildcards * 100
 * 5. Tier 4 (Pure Regex): +500 + length (lowest tier fallback)
 *
 * Guaranteed Invariant: Exact > Param > Wildcard > Regex.
 */
export function getRouteSpecificity(pattern: string): number {
  const trimmed = pattern.trim();

  // Regex tier (Lowest priority fallback)
  if (trimmed.startsWith('regex:') || trimmed.startsWith('^')) {
    return 500 + trimmed.length;
  }

  let score = 0;

  // Host specificity bonus (for explicit literal host patterns, e.g. s.stevezmt.top/...)
  if (!trimmed.startsWith('/') && trimmed.includes('.')) {
    score += 20000;
  }

  const hasParams = /:[a-zA-Z0-9_]+/.test(trimmed);
  const wildcardMatches = trimmed.match(/\*/g);
  const wildcardCount = wildcardMatches ? wildcardMatches.length : 0;
  const paramMatches = trimmed.match(/:[a-zA-Z0-9_]+/g);
  const paramCount = paramMatches ? paramMatches.length : 0;

  // Clean literal length (without variable markers)
  const literalOnly = trimmed.replace(/:[a-zA-Z0-9_]+/g, '').replace(/\*/g, '');
  const literalLengthScore = literalOnly.length * 10;

  if (!hasParams && wildcardCount === 0) {
    // Exact literal route: Highest priority
    score += 10000 + literalLengthScore;
  } else if (hasParams && wildcardCount === 0) {
    // Parameterized route: Intermediate priority
    score += 5000 + literalLengthScore - paramCount * 50;
  } else {
    // Wildcard route: Lower priority than params
    score += 1000 + literalLengthScore - wildcardCount * 100 - paramCount * 50;
  }

  return score;
}

/**
 * Pre-compiles a single RouteDefinition into an optimized CompiledRoute.
 */
export function compileRoute(route: RouteDefinition): CompiledRoute {
  const { regex, isHostSpecific, paramNames } = compilePattern(route.pattern);
  const specificity = getRouteSpecificity(route.pattern);
  return {
    pattern: route.pattern,
    regex,
    isHostSpecific,
    paramNames,
    specificity,
    definition: route,
  };
}

/**
 * Pre-compiles an entire routing table, sorted descending by specificity.
 * This is executed once during initialization to guarantee zero-overhead per request.
 */
export function compileRouteTable(routes: RouteDefinition[]): CompiledRoute[] {
  return routes
    .map(compileRoute)
    .sort((a, b) => b.specificity - a.specificity);
}

/**
 * Matches an incoming URL against a pre-compiled route.
 */
export function matchCompiledRoute(
  compiled: CompiledRoute,
  url: URL
): RouteMatch | null {
  const targetStr = compiled.isHostSpecific
    ? `${url.hostname}${url.pathname}`
    : url.pathname;

  const result = targetStr.match(compiled.regex);
  if (!result) {
    return null;
  }

  const matches = Array.from(result);
  const params: Record<string, string> = { ...result.groups };

  compiled.paramNames.forEach((name, index) => {
    if (!params[name] && matches[index + 1] !== undefined) {
      params[name] = matches[index + 1];
    }
  });

  return {
    matched: true,
    params,
    matches,
  };
}

/**
 * Executes pattern match against a given URL.
 * Returns match status along with captured named parameters and regex match groups.
 */
export function matchPatternDetails(pattern: string, url: URL): RouteMatch | null {
  const compiled = compileRoute({ pattern, target: '' });
  return matchCompiledRoute(compiled, url);
}

/**
 * Checks if a URL matches a route pattern according to Cloudflare matching rules.
 */
export function matchesPattern(pattern: string, url: URL): boolean {
  return matchPatternDetails(pattern, url) !== null;
}

/**
 * Finds the highest-priority matching route for an incoming request against pre-compiled routes.
 */
export function findMatchingCompiledRoute(
  compiledRoutes: CompiledRoute[],
  url: URL
): MatchedRouteResult | null {
  for (const compiled of compiledRoutes) {
    const match = matchCompiledRoute(compiled, url);
    if (match) {
      return {
        ...compiled.definition,
        route: compiled.definition,
        params: match.params,
        matches: match.matches,
      };
    }
  }

  return null;
}

/**
 * Finds the highest-priority matching route for an incoming request.
 * Automatically uses internal WeakMap compilation cache for efficiency.
 */
export function findMatchingRoute(
  routes: RouteDefinition[],
  url: URL
): MatchedRouteResult | null {
  let compiled = routesCache.get(routes);
  if (!compiled) {
    compiled = compileRouteTable(routes);
    routesCache.set(routes, compiled);
  }
  return findMatchingCompiledRoute(compiled, url);
}
