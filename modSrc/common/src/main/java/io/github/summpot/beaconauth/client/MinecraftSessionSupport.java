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
            var getType = user.getClass().getMethod("getType");
            Object type = getType.invoke(user);
            if (type != null && "LEGACY".equals(String.valueOf(type))) {
                return true;
            }
        } catch (Throwable ignored) {
            // User.Type was removed in 26.x; fall through to token checks.
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
