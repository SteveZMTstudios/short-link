/**
 * Type definitions for the short-link service.
 *
 * - Simple, declarative interface for daily usage
 * - Rich capabilities (salted SHA-256 password hashes, symmetric AES-GCM encryption, bots, TLS)
 */

export interface UtmConfig {
  utm_source?: string;
  utm_medium?: string;
  utm_campaign?: string;
  utm_term?: string;
  utm_content?: string;
  [key: string]: string | undefined;
}

export interface AuthConfig {
  realm?: string;
  password?: string;
  passwordHash?: string;
  salt?: string;
  users?: Record<string, string>;
  useMasterPassword?: boolean;
}

export interface RouteContext {
  request: Request;
  url: URL;
  fullUrl: string;
  hostname: string;
  pathname: string;
  cf?: IncomingRequestCfProperties;
  params?: Record<string, string>;
  matches?: string[];
}

export type RuleAction =
  | { type: 'pass' }
  | {
      type: 'block';
      status?: number;
      body?: string;
      headers?: Record<string, string>;
    }
  | {
      type: 'redirect';
      status?: number;
      url: string;
      headers?: Record<string, string>;
    };

export type RuleResult = RuleAction | boolean | void | null | undefined;
export type Rule = (ctx: RouteContext) => RuleResult | Promise<RuleResult>;

export type ChallengeProviderType = 'turnstile' | 'altcha' | 'cap';

export interface ChallengeConfig {
  /**
   * Challenge provider type: 'turnstile' | 'altcha' | 'cap'.
   */
  provider?: ChallengeProviderType;
  /**
   * Public site key (for Turnstile or Cap).
   * Can also be provided via TURNSTILE_SITE_KEY or CAP_SITE_KEY environment variables.
   */
  siteKey?: string;
  /**
   * Cap API endpoint for self-hosted instances (e.g. 'https://cap.yourdomain.com').
   * Cap (trycap.dev) is an open-source self-hosted CAPTCHA and has no public cloud API.
   */
  capEndpoint?: string;
  /**
   * Custom Cap widget script URL. Defaults to official CDN.
   */
  capScriptUrl?: string;
  /**
   * Altcha maximum number for PoW difficulty. Defaults to 100000.
   */
  altchaMaxNumber?: number;
  /**
   * Altcha challenge expiration in seconds. Defaults to 300 (5 minutes).
   */
  altchaExpiresIn?: number;
  /**
   * Duration in seconds for which an HMAC-signed clearance cookie is valid.
   * 0 means one-shot (redirect immediately, no persistent cookie). Default: 0.
   */
  clearanceDuration?: number;
}

export interface LinkOptions {
  target: string | ((ctx: RouteContext) => string | Promise<string>);
  /**
   * Password protection:
   * String containing plaintext password or salted hash ('sha256:<hex>').
   * Authenticated via standard HTTP Basic Auth (username is ignored; password is required).
   */
  password?: string | boolean;
  passwordHash?: string;
  salt?: string;
  auth?: AuthConfig;
  minTls?: '1.2' | '1.3' | 'TLSv1.2' | 'TLSv1.3';
  blockBots?: boolean;
  mobile?: string;
  utm?: UtmConfig;
  redirectStatus?: number;
  rules?: Rule[];
  /**
   * Human verification / Proof-of-Work challenge protection:
   * - undefined: Automatically enabled if target is individually encrypted and full-table encryption is not used
   * - false: Explicitly disable challenge even if target is encrypted
   * - true: Enforce challenge using provider from settings.challenge or env
   * - 'turnstile' | 'altcha' | 'cap': Enforce challenge using specific provider
   */
  challenge?: boolean | ChallengeProviderType;
}

export type LinkItem = string | LinkOptions;

export interface SettingsConfig {
  domain?: string;
  salt?: string;
  notFoundUrl?: string;
  notFoundMode?: 'redirect' | 'proxy';
  defaultUtm?: UtmConfig;
  /**
   * Security challenge configuration (Turnstile, Altcha, Cap)
   * used to prevent automated scraping of encrypted links.
   */
  challenge?: ChallengeConfig;
}

/**
 * Encrypted configuration payload structure.
 * Protects destination links from leaking in public Git repositories.
 * The decryption key is passed via Worker environment variables (e.g. ROUTES_KEY).
 */
export interface EncryptedConfig {
  settings?: SettingsConfig;
  /** AES-GCM encrypted payload ('aes-gcm:v1:...') */
  encrypted: string;
  notFound?: NotFoundConfig;
}

/**
 * Primary configuration structure for the short-link service.
 */
export interface ShortLinkConfig {
  settings?: SettingsConfig;
  links?: Record<string, LinkItem>;
  /** Optional symmetric encrypted links payload */
  encrypted?: string;
  routes?: RouteDefinition[];
  notFound?: NotFoundConfig;
}

export interface RouteDefinition {
  pattern: string;
  target: string | ((ctx: RouteContext) => string | Promise<string>);
  utm?: UtmConfig;
  auth?: AuthConfig;
  rules?: Rule[];
  redirectStatus?: number;
  /**
   * Whether this route requires challenge verification, or provider name.
   */
  challenge?: boolean | ChallengeProviderType;
  /**
   * Internal metadata tracking whether this route's target was individually encrypted in config.
   */
  isIndividuallyEncrypted?: boolean;
}

export interface NotFoundConfig {
  target?: string;
  mode?: 'redirect' | 'proxy';
}

export interface AppConfig {
  routes: RouteDefinition[];
  notFound?: NotFoundConfig;
  settings?: SettingsConfig;
}

export interface RouteProviderContext {
  request?: Request;
  env?: Env;
}

/**
 * Route Provider abstraction to decouple route storage (static config, KV, D1, external API)
 * from edge request handling and dispatching.
 */
export interface RouteProvider {
  /** Optional flag indicating route definitions are static and immutable (enables edge caching) */
  readonly isStatic?: boolean;
  /**
   * Retrieves short link configuration or route definitions.
   * Can be synchronous or asynchronous.
   */
  getRoutes(
    ctx?: RouteProviderContext
  ): Promise<RouteDefinition[] | ShortLinkConfig> | RouteDefinition[] | ShortLinkConfig;
}

/**
 * Cloudflare Worker Environment Variables bindings.
 */
export interface Env {
  /** Master password for symmetric decryption and unified Basic Auth */
  ROUTES_KEY?: string;
  AUTH_PASSWORD?: string;
  PASSWORD?: string;
  CONFIG_KEY?: string;
  ENCRYPTION_KEY?: string;
  /** Optional Cloudflare KV namespace for dynamic routes */
  SHORT_LINK_KV?: KVNamespace;

  /** Security Challenge Environment Variables */
  CHALLENGE_PROVIDER?: ChallengeProviderType;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  ALTCHA_HMAC_KEY?: string;
  CAP_SITE_KEY?: string;
  CAP_SECRET_KEY?: string;
  CAP_ENDPOINT?: string;

  [key: string]: unknown;
}


