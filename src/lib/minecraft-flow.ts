import { z } from 'zod';

/**
 * OIDC entry parameters used by the Minecraft mod.
 *
 * The mod opens `<auth_base>/login` with these query parameters (via the
 * `authorize` endpoint redirect), carrying the PKCE challenge, nonce and the
 * loopback redirect URI. Once the user signs in, the SPA completes the
 * authorization by redirecting the browser to the mod's loopback callback
 * with the code (the mod exchanges it at the token endpoint itself).
 */
export const oidcSearchSchema = z.object({
  client_id: z.string().optional(),
  redirect_uri: z.string().optional(),
  scope: z.string().optional(),
  state: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.string().optional(),
  nonce: z.string().optional(),
});

export type OidcSearchParams = z.infer<typeof oidcSearchSchema>;

export function isOidcFlow(
  params: OidcSearchParams,
): params is Required<OidcSearchParams> {
  return Boolean(
    params.client_id &&
      params.redirect_uri &&
      params.code_challenge &&
      params.nonce,
  );
}

/**
 * Complete the OIDC authorization by redirecting the browser back to the
 * mod's loopback callback with the authorization code.
 *
 * Called after any successful authentication (password, passkey or OAuth).
 * Returns true when a redirect was started.
 */
export async function completeOidcFlow(
  params: OidcSearchParams,
): Promise<boolean> {
  if (!isOidcFlow(params)) return false;

  // The token endpoint is not involved here: the mod performs the code
  // exchange itself. We just need to send the code back to the loopback URI.
  // Because the browser must not expose the code to the mod's local server
  // as a raw query parameter on a cross-origin redirect, we POST it to our
  // own `/api/v1/oidc/complete` endpoint which performs the final redirect
  // to the loopback URI with the code.
  const resp = await fetch('/api/v1/oidc/complete', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      redirect_uri: params.redirect_uri,
      state: params.state ?? '',
      client_id: params.client_id,
      code_challenge: params.code_challenge,
      code_challenge_method: 'S256',
      nonce: params.nonce,
    }),
  });
  if (!resp.ok) {
    console.error('OIDC completion failed', resp.status);
    return false;
  }
  const data = (await resp.json()) as { redirectUrl?: string };
  if (!data.redirectUrl) return false;
  window.location.href = data.redirectUrl;
  return true;
}

/**
 * Finish an auth flow: hand off to Minecraft (OIDC) when requested,
 * otherwise go to the settings page. Uses a hard navigation to avoid SPA
 * cache edge cases.
 */
export async function redirectAfterAuth(
  params: OidcSearchParams,
): Promise<void> {
  if (await completeOidcFlow(params)) return;
  window.location.href = '/settings';
}
