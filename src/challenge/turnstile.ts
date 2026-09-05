/**
 * Cloudflare Turnstile server-side verification handler.
 */

import { VerificationResult } from './types';

export async function verifyTurnstileToken(
  token: string,
  secretKey: string,
  remoteIp?: string | null
): Promise<VerificationResult> {
  if (!token || !secretKey) {
    return { success: false, error: 'Missing Turnstile token or secret key' };
  }

  const formData = new URLSearchParams();
  formData.append('secret', secretKey);
  formData.append('response', token);
  if (remoteIp) {
    formData.append('remoteip', remoteIp);
  }

  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    if (!res.ok) {
      return { success: false, error: `Turnstile verify service error: HTTP ${res.status}` };
    }

    const data = (await res.json()) as { success?: boolean; 'error-codes'?: string[] };
    if (data.success) {
      return { success: true };
    }

    const errorCodes = data['error-codes']?.join(', ') || 'Verification failed';
    return { success: false, error: errorCodes };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `Turnstile network error: ${msg}` };
  }
}
