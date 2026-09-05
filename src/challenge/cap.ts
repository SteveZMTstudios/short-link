/**
 * Cap (trycap.dev) server-side verification handler.
 */

import { VerificationResult } from './types';
import { verifyCapTokenPayload } from './cap_core';

export async function verifyCapToken(
  token: string,
  secretKey: string,
  endpoint?: string
): Promise<VerificationResult> {
  if (!token || !secretKey) {
    return { success: false, error: 'Missing Cap token or secret key' };
  }

  // 1. Built-in Serverless Mode: If endpoint is omitted or internal, verify locally via cap_core
  const isInternal =
    !endpoint ||
    endpoint.startsWith('/') ||
    endpoint.includes('/_challenge/cap') ||
    endpoint.includes('/api/cap');

  if (isInternal) {
    const localRes = await verifyCapTokenPayload(token, secretKey);
    if (localRes.success) {
      return { success: true };
    }
    return { success: false, error: localRes.message || 'Cap verification failed' };
  }

  // 2. External Mode: Forward verification to external standalone instance
  const cleanEndpoint = endpoint.replace(/\/+$/, '');
  const verifyUrl = `${cleanEndpoint}/siteverify`;

  try {
    const res = await fetch(verifyUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        secret: secretKey,
        response: token,
      }),
    });

    if (!res.ok) {
      return { success: false, error: `Cap verify service error: HTTP ${res.status}` };
    }

    const data = (await res.json()) as { success?: boolean; message?: string; error?: string };
    if (data.success) {
      return { success: true };
    }

    return { success: false, error: data.message || data.error || 'Cap verification failed' };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `Cap network error: ${msg}` };
  }
}
