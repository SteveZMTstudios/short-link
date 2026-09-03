/**
 * URL and UTM manipulation utilities.
 * Handles parameter interpolation (:slug, $1), UTM default-injection, and template substitution.
 */

import { UtmConfig } from '../types';

/**
 * Interpolates dynamic parameters (:name, ${name}), capture groups ($1, $2),
 * and wildcards (*) into a destination target URL.
 */
export function interpolateTargetUrl(
  targetUrl: string,
  params?: Record<string, string>,
  matches?: string[]
): string {
  let result = targetUrl;

  // 1. Substitute $1, $2, ... from regex or wildcard matches
  if (matches && matches.length > 0) {
    result = result.replace(/\$([0-9]+)/g, (fullMatch, numStr) => {
      const idx = Number(numStr);
      if (matches[idx] !== undefined) {
        return matches[idx];
      }
      return fullMatch;
    });

    // Replace literal '*' in target with first wildcard match if present
    if (matches[1] !== undefined && result.includes('*')) {
      const wildcardVal = matches[1];
      result = result
        .replace(/\/\*/g, () => '/' + wildcardVal)
        .replace(/\*/g, () => wildcardVal);
    }
  }

  // 2. Substitute :name from named parameters
  if (params) {
    result = result.replace(/:([a-zA-Z0-9_]+)/g, (fullMatch, name) => {
      if (params[name] !== undefined) {
        return params[name];
      }
      return fullMatch;
    });

    // Also support ${name} syntax
    result = result.replace(/\$\{([a-zA-Z0-9_]+)\}/g, (fullMatch, name) => {
      if (params[name] !== undefined) {
        return params[name];
      }
      return fullMatch;
    });
  }

  return result;
}

/**
 * Merges target URL with incoming request parameters and default UTM parameters.
 * Automatically interpolates dynamic route params (:param, $1).
 *
 * Strategy:
 * 1. Base query parameters already on target URL are preserved unless overridden by visitor.
 * 2. Incoming request's query parameters are forwarded onto the target URL (preserving multi-value keys).
 * 3. Default UTM parameters are injected ONLY if the visitor did NOT supply them.
 */
export function buildDestinationUrl(
  targetUrl: string,
  incomingUrl: URL,
  defaultUtm?: UtmConfig,
  params?: Record<string, string>,
  matches?: string[]
): string {
  // Interpolate route parameters (:slug, $1) into target template
  let interpolatedTarget = interpolateTargetUrl(targetUrl, params, matches).trim();

  // If target is a bare domain (e.g. "baidu.com" or "example.com/page"), auto-prepend https://
  if (!/^https?:\/\//i.test(interpolatedTarget) && !interpolatedTarget.startsWith('/')) {
    interpolatedTarget = 'https://' + interpolatedTarget;
  }

  // Parse safely
  const parsedTarget = new URL(interpolatedTarget, incomingUrl.origin);

  // Forward incoming query parameters, preserving multi-value keys
  // (omit auth-related internal params like pwd/password so they don't leak upstream)
  const seenIncomingKeys = new Set<string>();
  for (const [key, value] of incomingUrl.searchParams.entries()) {
    if (key === 'pwd' || key === 'password') {
      continue;
    }
    if (!seenIncomingKeys.has(key)) {
      parsedTarget.searchParams.set(key, value);
      seenIncomingKeys.add(key);
    } else {
      parsedTarget.searchParams.append(key, value);
    }
  }

  // Inject default UTM parameters ONLY if value is non-empty AND missing from target
  if (defaultUtm) {
    for (const [key, value] of Object.entries(defaultUtm)) {
      if (
        value !== undefined &&
        value !== null &&
        typeof value === 'string' &&
        value.trim() !== '' &&
        !parsedTarget.searchParams.has(key)
      ) {
        parsedTarget.searchParams.set(key, value.trim());
      }
    }
  }

  return parsedTarget.toString();
}

/**
 * Replaces placeholders in URLs such as 404 targets.
 * Supported tokens:
 * - ${FULL_URL} -> URL-encoded full URL
 * - ${RAW_FULL_URL} -> raw full URL
 * - ${PATH} -> incoming pathname
 */
export function resolveUrlTemplate(template: string, incomingUrl: URL): string {
  const fullUrl = incomingUrl.toString();
  const encodedFullUrl = encodeURIComponent(fullUrl);
  const path = incomingUrl.pathname;

  return template
    .replace(/\$\{FULL_URL\}/g, encodedFullUrl)
    .replace(/\$\{RAW_FULL_URL\}/g, fullUrl)
    .replace(/\$\{ENCODED_FULL_URL\}/g, encodedFullUrl)
    .replace(/\$\{PATH\}/g, encodeURIComponent(path));
}
