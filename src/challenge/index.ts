/**
 * Challenge Module Facade.
 * Implements Software Design Philosophy (Deep Module, Pull Complexity Downward).
 * Exposes a clean, high-level interface to handle Turnstile, Altcha, and Cap challenges.
 */

import {
  ChallengeConfig,
  ChallengeProviderType,
  Env,
  RouteDefinition,
  SettingsConfig,
} from '../types';
import { createAltchaChallenge, verifyAltchaPayload } from './altcha';
import { verifyCapToken } from './cap';
import {
  generateCapChallenge,
  validateCapChallenge,
  CapValidationBody,
} from './cap_core';
import { createClearanceCookie, hasValidClearance } from './clearance';
import { verifyTurnstileToken } from './turnstile';
import { renderChallengeHtml } from './view';

export interface ChallengeFlowResult {
  passed: boolean;
  response?: Response;
  setCookieHeader?: string;
}

/**
 * Handles built-in serverless challenge endpoints for Cap and Altcha:
 * - OPTIONS /_challenge/* (CORS Preflight)
 * - POST /_challenge/cap/challenge (Generates Cap PoW challenge)
 * - POST /_challenge/cap/redeem (Verifies Cap solutions and returns token)
 * - GET /_challenge/altcha (Generates Altcha challenge JSON)
 */
export async function handleBuiltinChallengeEndpoints(
  request: Request,
  url: URL,
  settings?: SettingsConfig,
  env?: Env
): Promise<Response | null> {
  if (!url.pathname.startsWith('/_challenge/')) {
    return null;
  }

  // 1. CORS Preflight & Security Check (inspired by CFCap)
  const origin = request.headers.get('Origin') || '';
  const allowedDomain = settings?.domain || url.hostname;
  const isAllowedOrigin =
    !origin ||
    origin.endsWith(allowedDomain) ||
    origin.includes('localhost') ||
    origin.includes('127.0.0.1');

  const corsHeaders: Record<string, string> = {
    'Access-Control-Allow-Origin': isAllowedOrigin && origin ? origin : '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const path = url.pathname.replace(/\/+$/, '');

  // 2. Cap Endpoints: /_challenge/cap/challenge & /_challenge/cap/redeem
  if (path === '/_challenge/cap/challenge' || path === '/_challenge/cap') {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
    }
    const capSecret =
      (env?.CAP_SECRET_KEY as string | undefined) ||
      (env?.ROUTES_KEY as string | undefined) ||
      (env?.MASTER_KEY as string | undefined) ||
      'default-cap-secret';

    const challengeData = await generateCapChallenge(capSecret);
    return new Response(JSON.stringify(challengeData), {
      status: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  }

  if (path === '/_challenge/cap/redeem') {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
    }
    let body: CapValidationBody;
    try {
      body = (await request.json()) as CapValidationBody;
    } catch {
      return new Response(JSON.stringify({ success: false, message: 'Invalid JSON' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const capSecret =
      (env?.CAP_SECRET_KEY as string | undefined) ||
      (env?.ROUTES_KEY as string | undefined) ||
      (env?.MASTER_KEY as string | undefined) ||
      'default-cap-secret';

    const result = await validateCapChallenge(capSecret, body);
    return new Response(JSON.stringify(result), {
      status: result.success ? 200 : 400,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  }

  // 3. Altcha Endpoint: GET /_challenge/altcha
  if (path === '/_challenge/altcha') {
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
    }
    const altchaSecret =
      (env?.ALTCHA_HMAC_KEY as string | undefined) ||
      (env?.ROUTES_KEY as string | undefined) ||
      (env?.MASTER_KEY as string | undefined) ||
      'default-altcha-secret';

    const maxNumber = settings?.challenge?.altchaMaxNumber || 100000;
    const expiresIn = settings?.challenge?.altchaExpiresIn || 300;
    const challengeData = await createAltchaChallenge(altchaSecret, maxNumber, expiresIn);

    return new Response(JSON.stringify(challengeData), {
      status: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  }

  return new Response('Not Found', { status: 404, headers: corsHeaders });
}

/**
 * Checks if challenge configuration exists in settings or environment.
 */
export function hasChallengeConfigured(
  settings?: SettingsConfig,
  env?: Env
): boolean {
  return !!(settings?.challenge?.provider || env?.CHALLENGE_PROVIDER);
}

/**
 * Determines whether a route requires human verification / proof-of-work.
 */
export function shouldChallengeRoute(
  route: RouteDefinition,
  isFullTableEncrypted = false,
  hasChallengeConfig = true
): boolean {
  // 1. Explicit route-level override takes precedence
  if (route.challenge !== undefined) {
    if (route.challenge === false) {
      return false;
    }
    return true; // true or provider name ('turnstile' | 'altcha' | 'cap')
  }

  // 2. Full-table encryption protects route paths from public scraping; skip by default
  if (isFullTableEncrypted) {
    return false;
  }

  // 3. Individually encrypted target: trigger challenge if challenge is configured
  return !!route.isIndividuallyEncrypted && hasChallengeConfig;
}

export interface ResolvedChallengeConfig {
  provider: ChallengeProviderType;
  siteKey?: string;
  secretKey: string;
  capEndpoint: string;
  capScriptUrl?: string;
  altchaMaxNumber: number;
  altchaExpiresIn: number;
  clearanceDuration: number;
}

/**
 * Resolves configuration and keys for the selected challenge provider.
 * Throws clear configuration errors if required settings/secrets are missing.
 */
export function resolveChallengeConfig(
  route: RouteDefinition,
  settings?: SettingsConfig,
  env?: Env
): ResolvedChallengeConfig {
  const challengeSettings = settings?.challenge || {};

  // 1. Determine provider
  let provider: ChallengeProviderType | undefined;
  if (typeof route.challenge === 'string') {
    provider = route.challenge;
  } else if (challengeSettings.provider) {
    provider = challengeSettings.provider;
  } else if (env?.CHALLENGE_PROVIDER) {
    provider = env.CHALLENGE_PROVIDER as ChallengeProviderType;
  }

  if (!provider || !['turnstile', 'altcha', 'cap'].includes(provider)) {
    throw new Error(
      'Challenge Configuration Error: An encrypted target requires verification, but no valid CHALLENGE_PROVIDER was specified in route.ts settings or environment variables (CHALLENGE_PROVIDER=turnstile|altcha|cap).'
    );
  }

  // 2. Determine secrets and site keys
  let secretKey = '';
  let siteKey = challengeSettings.siteKey;

  if (provider === 'turnstile') {
    secretKey = (env?.TURNSTILE_SECRET_KEY as string | undefined) || '';
    siteKey = siteKey || (env?.TURNSTILE_SITE_KEY as string | undefined);
    if (!secretKey) {
      throw new Error(
        'Turnstile Configuration Error: TURNSTILE_SECRET_KEY is missing in environment variables.'
      );
    }
  } else if (provider === 'altcha') {
    secretKey =
      (env?.ALTCHA_HMAC_KEY as string | undefined) ||
      (env?.ROUTES_KEY as string | undefined) ||
      (env?.MASTER_KEY as string | undefined) ||
      '';
    if (!secretKey) {
      throw new Error(
        'Altcha Configuration Error: ALTCHA_HMAC_KEY (or ROUTES_KEY) is missing in environment variables for HMAC challenge generation.'
      );
    }
  } else if (provider === 'cap') {
    secretKey =
      (env?.CAP_SECRET_KEY as string | undefined) ||
      (env?.ROUTES_KEY as string | undefined) ||
      (env?.MASTER_KEY as string | undefined) ||
      '';
    if (!secretKey) {
      throw new Error(
        'Cap Configuration Error: CAP_SECRET_KEY (or ROUTES_KEY) is missing in environment variables.'
      );
    }
    siteKey = siteKey || (env?.CAP_SITE_KEY as string | undefined) || 'cap_internal';
    const rawEndpoint =
      challengeSettings.capEndpoint || (env?.CAP_ENDPOINT as string | undefined);
    // If external endpoint is omitted, default to built-in serverless endpoint '/_challenge/cap/'
    const capEndpoint = rawEndpoint || '/_challenge/cap/';

    return {
      provider,
      siteKey,
      secretKey,
      capEndpoint,
      capScriptUrl: challengeSettings.capScriptUrl,
      altchaMaxNumber: challengeSettings.altchaMaxNumber || 100000,
      altchaExpiresIn: challengeSettings.altchaExpiresIn || 300,
      clearanceDuration: challengeSettings.clearanceDuration || 0,
    };
  }

  return {
    provider,
    siteKey,
    secretKey,
    capEndpoint: '',
    capScriptUrl: challengeSettings.capScriptUrl,
    altchaMaxNumber: challengeSettings.altchaMaxNumber || 100000,
    altchaExpiresIn: challengeSettings.altchaExpiresIn || 300,
    clearanceDuration: challengeSettings.clearanceDuration || 0,
  };
}

/**
 * Handles the end-to-end challenge lifecycle for a matched route.
 * Returns { passed: true } if the request is cleared to proceed.
 * Returns { passed: false, response: Response } if a challenge page or error response is returned.
 */
export async function handleChallengeFlow(
  request: Request,
  url: URL,
  route: RouteDefinition,
  settings?: SettingsConfig,
  env?: Env
): Promise<ChallengeFlowResult> {
  let config: ResolvedChallengeConfig;
  try {
    config = resolveChallengeConfig(route, settings, env);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      passed: false,
      response: new Response(msg, {
        status: 500,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      }),
    };
  }

  const actionUrl = url.pathname + url.search;
  const acceptLanguage = request.headers.get('Accept-Language');

  // Check clearance cookie if clearance duration is configured
  if (config.clearanceDuration > 0) {
    const isCleared = await hasValidClearance(request, config.secretKey);
    if (isCleared) {
      return { passed: true };
    }
  }

  // GET: Render the initial challenge page
  if (request.method === 'GET' || request.method === 'HEAD') {
    let altchaChallenge;
    if (config.provider === 'altcha') {
      altchaChallenge = await createAltchaChallenge(
        config.secretKey,
        config.altchaMaxNumber,
        config.altchaExpiresIn
      );
    }

    const html = renderChallengeHtml({
      provider: config.provider,
      siteKey: config.siteKey,
      actionUrl,
      altchaChallenge,
      capEndpoint: config.capEndpoint,
      capScriptUrl: config.capScriptUrl,
      acceptLanguage,
    });

    const response = new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });

    return { passed: false, response };
  }

  // POST: Verify challenge solution
  if (request.method === 'POST') {
    let token = '';

    const contentType = request.headers.get('Content-Type') || '';
    if (
      contentType.includes('application/x-www-form-urlencoded') ||
      contentType.includes('multipart/form-data') ||
      !contentType
    ) {
      try {
        const formData = await request.formData();
        if (config.provider === 'turnstile') {
          token =
            (formData.get('cf-turnstile-response') as string) ||
            (formData.get('response') as string) ||
            (formData.get('token') as string) ||
            '';
        } else if (config.provider === 'altcha') {
          token =
            (formData.get('altcha') as string) ||
            (formData.get('payload') as string) ||
            (formData.get('token') as string) ||
            '';
        } else if (config.provider === 'cap') {
          token =
            (formData.get('cap-token') as string) ||
            (formData.get('response') as string) ||
            (formData.get('token') as string) ||
            '';
        }

        // Deep fallback: scan all common field names
        if (!token) {
          token =
            (formData.get('altcha') as string) ||
            (formData.get('cf-turnstile-response') as string) ||
            (formData.get('cap-token') as string) ||
            (formData.get('payload') as string) ||
            (formData.get('response') as string) ||
            (formData.get('token') as string) ||
            '';
        }
      } catch {
        token = '';
      }
    } else if (contentType.includes('application/json')) {
      try {
        const json = (await request.json()) as Record<string, string>;
        token =
          json['altcha'] ||
          json['cf-turnstile-response'] ||
          json['cap-token'] ||
          json['payload'] ||
          json['response'] ||
          json['token'] ||
          '';
      } catch {
        token = '';
      }
    }

    // Fallback: check query params if post body was empty
    if (!token) {
      token =
        url.searchParams.get('token') ||
        url.searchParams.get('altcha') ||
        url.searchParams.get('cap-token') ||
        url.searchParams.get('cf-turnstile-response') ||
        '';
    }

    let verification = { success: false, error: 'Empty challenge response token' };

    if (token) {
      if (config.provider === 'turnstile') {
        const clientIp = request.headers.get('CF-Connecting-IP');
        verification = await verifyTurnstileToken(token, config.secretKey, clientIp);
      } else if (config.provider === 'altcha') {
        verification = await verifyAltchaPayload(token, config.secretKey);
      } else if (config.provider === 'cap') {
        verification = await verifyCapToken(token, config.secretKey, config.capEndpoint);
      }
    }

    if (verification.success) {
      let setCookieHeader: string | undefined;
      if (config.clearanceDuration > 0) {
        setCookieHeader = await createClearanceCookie(config.secretKey, config.clearanceDuration);
      }
      return { passed: true, setCookieHeader };
    }

    // Verification failed: Re-render challenge page with error notification and HTTP 403
    let newAltchaChallenge;
    if (config.provider === 'altcha') {
      newAltchaChallenge = await createAltchaChallenge(
        config.secretKey,
        config.altchaMaxNumber,
        config.altchaExpiresIn
      );
    }

    const html = renderChallengeHtml({
      provider: config.provider,
      siteKey: config.siteKey,
      actionUrl,
      altchaChallenge: newAltchaChallenge,
      capEndpoint: config.capEndpoint,
      capScriptUrl: config.capScriptUrl,
      error: verification.error || 'Verification failed. Please retry.',
      acceptLanguage,
    });

    const response = new Response(html, {
      status: 403,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });

    return { passed: false, response };
  }

  // Non GET/POST methods for a challenge-protected route are rejected
  return {
    passed: false,
    response: new Response('Method Not Allowed', { status: 405 }),
  };
}
