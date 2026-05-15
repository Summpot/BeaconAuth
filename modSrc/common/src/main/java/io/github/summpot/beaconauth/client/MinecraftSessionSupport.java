package io.github.summpot.beaconauth.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.User;

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
            return false;
        }

        String accessToken = user.getAccessToken();
        return accessToken == null || accessToken.isBlank() || NEOAUTH_OFFLINE_TOKEN.equals(accessToken);
    }
}
