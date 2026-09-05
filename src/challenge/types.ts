import { ChallengeConfig, ChallengeProviderType, Env, RouteContext, SettingsConfig } from '../types';

export interface VerificationResult {
  success: boolean;
  error?: string;
}

export interface AltchaChallenge {
  algorithm: string;
  challenge: string;
  salt: string;
  signature: string;
  maxnumber?: number;
}

export interface AltchaPayload {
  algorithm: string;
  challenge: string;
  number: number;
  salt: string;
  signature: string;
}

export interface RenderChallengeOptions {
  provider: ChallengeProviderType;
  siteKey?: string;
  actionUrl: string;
  altchaChallenge?: AltchaChallenge;
  capEndpoint?: string;
  capScriptUrl?: string;
  error?: string;
  acceptLanguage?: string | null;
}
