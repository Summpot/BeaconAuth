import { z } from 'zod';
import { apiClient } from '@/utils/api';

export const minecraftSearchSchema = z.object({
  challenge: z.string().min(1).optional(),
  redirect_port: z.coerce.number().min(1).max(65535).optional(),
});

export type MinecraftSearchParams = z.infer<typeof minecraftSearchSchema>;

export function isMinecraftFlow(
  params: MinecraftSearchParams,
): params is Required<MinecraftSearchParams> {
  return Boolean(params.challenge && params.redirect_port);
}

/**
 * Exchange the current session for a Minecraft JWT and hand the browser back
 * to the game. Returns true when a redirect was started.
 */
export async function tryCompleteMinecraftFlow(
  params: MinecraftSearchParams,
): Promise<boolean> {
  if (!isMinecraftFlow(params)) return false;
  const result = await apiClient<{ redirectUrl?: string }>(
    '/api/v1/minecraft-jwt',
    {
      method: 'POST',
      body: {
        challenge: params.challenge,
        redirect_port: params.redirect_port,
        profile_url: `${window.location.origin}/profile`,
      },
    },
  );
  if (result.redirectUrl) {
    window.location.href = result.redirectUrl;
    return true;
  }
  return false;
}

/**
 * Finish an auth flow: hand off to Minecraft when requested, otherwise go to
 * the profile page. Uses a hard navigation to avoid SPA cache edge cases.
 */
export async function redirectAfterAuth(
  params: MinecraftSearchParams,
): Promise<void> {
  if (await tryCompleteMinecraftFlow(params)) return;
  window.location.href = '/profile';
}
