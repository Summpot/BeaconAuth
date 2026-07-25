package io.github.summpot.beaconauth.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.User;

/**
 * Detects offline / non-Mojang client sessions used by community launchers.
 * Used so dual-path online-mode servers can still complete encryption and fall
 * back to BeaconAuth instead of the vanilla "Invalid session" disconnect.
 */
public final class MinecraftSessionSupport {
    private static final String NEOAUTH_OFFLINE_TOKEN = "invalidtoken";

    private MinecraftSessionSupport() {
    }

    public static boolean isOfflineSession() {
        try {
            Minecraft minecraft = Minecraft.getInstance();
            return minecraft != null && isOfflineSession(minecraft.getUser());
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean isOfflineSession(User user) {
        if (user == null) {
            return false;
        }

        try {
            if (user.getType() == User.Type.LEGACY) {
                return true;
            }
        } catch (Throwable ignored) {
            // User.Type may differ across loaders; fall through to token checks.
        }

        String accessToken = user.getAccessToken();
        if (accessToken == null || accessToken.isBlank()) {
            return true;
        }

        // Common offline / cracked launcher placeholders.
        String trimmed = accessToken.trim();
        return NEOAUTH_OFFLINE_TOKEN.equalsIgnoreCase(trimmed)
            || "0".equals(trimmed)
            || "null".equalsIgnoreCase(trimmed)
            || "offline".equalsIgnoreCase(trimmed);
    }
}
