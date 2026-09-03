/**
 * Type definitions for the short-link service.
 * Designed with deep module philosophy:
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
  useUnifiedPassword?: boolean;
  password?: string;
  passwordHash?: string;
  salt?: string;
  users?: Record<string, string>;
  /**
   * 'page': Elegant standalone HTML password unlock page (default, no browser username prompt)
   * 'basic': Browser-native HTTP Basic Auth modal with Username + Password fields
   */
  mode?: 'page' | 'basic';
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

export interface LinkOptions {
  target: string | ((ctx: RouteContext) => string | Promise<string>);
  /**
   * Password protection:
   * - true: Uses unified password from .env / environment variables (ROUTES_KEY or AUTH_PASSWORD)
   * - string: Specific password or salted hash ('sha256:<hex>')
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
}

export type LinkItem = string | LinkOptions;

export interface SettingsConfig {
  domain?: string;
  salt?: string;
  notFoundUrl?: string;
  notFoundMode?: 'redirect' | 'proxy';
  defaultUtm?: UtmConfig;
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
}

export interface NotFoundConfig {
  target?: string;
  mode?: 'redirect' | 'proxy';
}

export interface AppConfig {
  routes: RouteDefinition[];
  notFound?: NotFoundConfig;
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
  [key: string]: unknown;
}

