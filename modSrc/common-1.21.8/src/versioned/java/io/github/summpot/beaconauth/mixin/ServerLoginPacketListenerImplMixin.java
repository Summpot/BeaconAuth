package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.config.BeaconAuthConfig;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.contents.TranslatableContents;
import net.minecraft.network.protocol.cookie.ServerboundCookieResponsePacket;
import net.minecraft.network.protocol.login.ServerboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Mixin entry point for BeaconAuth login-phase negotiation on server.
 * All logic delegated to ServerLoginHandler (Kotlin).
 *
 * Dual-path online-mode login (default when bypass_if_online_mode_verified=true):
 * 1. Do NOT consume/cancel handleHello — let vanilla send encryption + Mojang hasJoinedServer.
 * 2. Mojang success → negotiate at VERIFYING:
 *    - no BeaconAuth handshake (vanilla) → allow-through, keep Mojang UUID
 *    - modded + bypass → allow-through, keep Mojang UUID
 * 3. Mojang failure (invalid session / auth servers down) → cancel disconnect, fall back to
 *    BeaconAuth with a placeholder offline UUID (not Mojang-verified).
 *    - modded → BeaconAuth web login → stable UUID
 *    - unmodded → mod_required
 *
 * When bypass_if_online_mode_verified=false: force-consume HELLO and require BeaconAuth for all.
 *
 * 1.21.x state machine uses VERIFYING (not READY_TO_ACCEPT).
 */
@Mixin(value = ServerLoginPacketListenerImpl.class, priority = 1100)
public abstract class ServerLoginPacketListenerImplMixin {
    @Unique private static final org.slf4j.Logger BEACON_LOGGER = LoggerFactory.getLogger("BeaconAuth/Mixin");

    @Shadow @Final private MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow private int tick;
    @Shadow @Nullable private GameProfile authenticatedProfile;
    @Shadow @Nullable private String requestedUsername;

    @Shadow public abstract void disconnect(Component reason);

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted = false;
    /**
     * True when the current profile is NOT Mojang-verified:
     * forced HELLO consume, or Mojang-failure fallback to BeaconAuth.
     */
    @Unique private boolean beaconAuth$helloWasIntercepted = false;
    @Unique private boolean beaconAuth$mojangFallbackScheduled = false;
    @Unique @Nullable private GameProfile beaconAuth$loginProfile;

    @Unique
    private ServerLoginPacketListenerImplAccessor beaconAuth$accessor() {
        return (ServerLoginPacketListenerImplAccessor) (Object) this;
    }

    /**
     * Only force-consume HELLO when bypass is disabled (everyone must use BeaconAuth).
     * Default dual-path leaves HELLO alone so Mojang can run; PROBE happens after success or on failure fallback.
     */
    @Inject(method = "handleHello", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$onHandleHello(ServerboundHelloPacket packet, CallbackInfo ci) {
        if (!beaconAuth$isInState("HELLO")) {
            return;
        }

        GameProfile singleplayerProfile = server.getSingleplayerProfile();
        if (singleplayerProfile != null && packet.name().equalsIgnoreCase(singleplayerProfile.getName())) {
            return;
        }

        boolean serverOnlineMode = server.usesAuthentication();
        if (!serverOnlineMode || connection.isMemoryConnection()) {
            return;
        }

        if (BeaconAuthConfig.INSTANCE.shouldBypassIfOnlineModeVerified()) {
            BEACON_LOGGER.debug(
                "Dual-path online-mode for {}: leaving HELLO to Mojang; BeaconAuth negotiates after success or on failure fallback",
                packet.name()
            );
            return;
        }

        BEACON_LOGGER.info("Force BeaconAuth for online-mode login {}; consuming HELLO", packet.name());
        beaconAuth$helloWasIntercepted = true;
        requestedUsername = packet.name();
        GameProfile loginProfile = new GameProfile(beaconAuth$offlineUuid(packet.name()), packet.name());
        beaconAuth$loginProfile = loginProfile;
        beaconAuth$setAuthenticatedProfile(loginProfile);
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$startNegotiation(loginProfile);
        ci.cancel();
    }

    @Inject(method = "disconnect", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$onDisconnect(Component reason, CallbackInfo ci) {
        if (!beaconAuth$tryScheduleMojangFailureFallback(reason)) {
            return;
        }
        ci.cancel();
    }

    @Unique
    private boolean beaconAuth$tryScheduleMojangFailureFallback(Component reason) {
        if (beaconAuth$negotiationStarted || beaconAuth$handler != null || beaconAuth$mojangFallbackScheduled) {
            return false;
        }
        if (!BeaconAuthConfig.INSTANCE.shouldBypassIfOnlineModeVerified()) {
            return false;
        }
        if (!server.usesAuthentication() || connection.isMemoryConnection()) {
            return false;
        }
        if (!beaconAuth$isMojangSessionFailure(reason)) {
            return false;
        }

        final String username = requestedUsername;
        if (username == null || username.isEmpty()) {
            return false;
        }

        beaconAuth$mojangFallbackScheduled = true;
        BEACON_LOGGER.info(
            "Mojang verification failed for {} ({}); falling back to BeaconAuth",
            username,
            beaconAuth$translationKey(reason)
        );

        server.execute(() -> {
            if (beaconAuth$negotiationStarted || beaconAuth$handler != null) {
                return;
            }
            if (!connection.isConnected()) {
                BEACON_LOGGER.warn("Cannot fall back to BeaconAuth for {}: connection already closed", username);
                return;
            }

            beaconAuth$helloWasIntercepted = true;
            GameProfile offlineProfile = new GameProfile(beaconAuth$offlineUuid(username), username);
            beaconAuth$loginProfile = offlineProfile;
            beaconAuth$setAuthenticatedProfile(offlineProfile);
            beaconAuth$setState("NEGOTIATING");
            tick = 0;
            beaconAuth$startNegotiation(offlineProfile);
        });
        return true;
    }

    @Unique
    private static boolean beaconAuth$isMojangSessionFailure(Component reason) {
        String key = beaconAuth$translationKey(reason);
        return "multiplayer.disconnect.unverified_username".equals(key)
            || "multiplayer.disconnect.authservers_down".equals(key);
    }

    @Unique
    @Nullable
    private static String beaconAuth$translationKey(Component reason) {
        if (reason.getContents() instanceof TranslatableContents translatable) {
            return translatable.getKey();
        }
        return null;
    }

    @Unique
    private static UUID beaconAuth$offlineUuid(String username) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
    }

    @Inject(method = "tick", at = @At("HEAD"))
    private void beaconAuth$onTick(CallbackInfo ci) {
        if (beaconAuth$handler != null) {
            tick = 0;
            beaconAuth$handler.tick();
            return;
        }

        if (!beaconAuth$negotiationStarted && beaconAuth$isInState("VERIFYING")) {
            GameProfile profile = beaconAuth$getAuthenticatedProfile();
            if (profile != null) {
                BEACON_LOGGER.info("Starting BeaconAuth negotiation at VERIFYING state for {}", profile.getName());
                beaconAuth$loginProfile = profile;
                beaconAuth$setState("NEGOTIATING");
                beaconAuth$startNegotiation(profile);
            }
        }
    }

    @Inject(method = "handleCookieResponse", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleCookieResponse(ServerboundCookieResponsePacket packet, CallbackInfo ci) {
        if (beaconAuth$handler == null) {
            return;
        }
        boolean handled = beaconAuth$handler.handleCookieResponse(packet.key(), packet.payload());
        if (handled) {
            ci.cancel();
        }
    }

    @Unique
    private boolean beaconAuth$isInState(String expectedState) {
        return beaconAuth$accessor().beaconAuth$getState().toString().equals(expectedState);
    }

    @Unique
    private void beaconAuth$startNegotiation(GameProfile profile) {
        if (beaconAuth$negotiationStarted) {
            return;
        }

        beaconAuth$negotiationStarted = true;
        BEACON_LOGGER.info(
            "Starting BeaconAuth negotiation for {} (mojangVerified={})",
            profile.getName(),
            !beaconAuth$helloWasIntercepted
        );

        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            profile,
            (Component failReason) -> {
                BEACON_LOGGER.info("BeaconAuth negotiation failed for {}: {}", profile.getName(), failReason.getString());
                beaconAuth$setAuthenticatedProfile(beaconAuth$loginProfile != null ? beaconAuth$loginProfile : profile);
                disconnect(failReason);
                beaconAuth$handler = null;
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                BEACON_LOGGER.info("BeaconAuth negotiation finished successfully for {}", profile.getName());

                GameProfile updated = null;
                if (beaconAuth$handler != null) {
                    updated = beaconAuth$handler.getCurrentGameProfile();
                }
                if (updated != null) {
                    beaconAuth$loginProfile = updated;
                }
                if (beaconAuth$loginProfile != null) {
                    beaconAuth$setAuthenticatedProfile(beaconAuth$loginProfile);
                }

                beaconAuth$handler = null;
                beaconAuth$setState("VERIFYING");
                return kotlin.Unit.INSTANCE;
            },
            beaconAuth$helloWasIntercepted
        );
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$handler.start();
    }

    @Unique
    private void beaconAuth$setState(String stateName) {
        for (ServerLoginPacketListenerImpl.State state : ServerLoginPacketListenerImpl.State.values()) {
            if (state.toString().equals(stateName)) {
                beaconAuth$accessor().beaconAuth$setState(state);
                return;
            }
        }
        BEACON_LOGGER.error("Unknown login state name: {}", stateName);
    }

    @Unique
    @Nullable
    private GameProfile beaconAuth$getAuthenticatedProfile() {
        return authenticatedProfile;
    }

    @Unique
    private void beaconAuth$setAuthenticatedProfile(@Nullable GameProfile profile) {
        if (profile == null) {
            return;
        }
        authenticatedProfile = profile;
    }
}
