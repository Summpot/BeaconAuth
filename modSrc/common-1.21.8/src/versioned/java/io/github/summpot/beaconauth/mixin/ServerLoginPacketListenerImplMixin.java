package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.config.BeaconAuthConfig;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
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
 * This Mixin works on both Fabric and Forge:
 * - Intercepts handleHello only when configuration requires BeaconAuth instead of Mojang auth
 * - Uses @Inject to handle BeaconAuth flow after vanilla profile verification
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
    @Unique private boolean beaconAuth$helloWasIntercepted = false;
    @Unique @Nullable private GameProfile beaconAuth$loginProfile;

    @Unique
    private ServerLoginPacketListenerImplAccessor beaconAuth$accessor() {
        return (ServerLoginPacketListenerImplAccessor) (Object) this;
    }

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
            BEACON_LOGGER.debug("Allowing Mojang online-mode verification for {}", packet.name());
            return;
        }

        BEACON_LOGGER.info("BeaconAuth is forced for online-mode login {}; starting BeaconAuth flow", packet.name());
        beaconAuth$helloWasIntercepted = true;
        requestedUsername = packet.name();
        GameProfile loginProfile = new GameProfile(beaconAuth$offlineUuid(packet.name()), packet.name());
        beaconAuth$loginProfile = loginProfile;
        beaconAuth$setAuthenticatedProfile(loginProfile);
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$startNegotiation(loginProfile);
        ci.cancel();
    }

    @Unique
    private static UUID beaconAuth$offlineUuid(String username) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Main injection point that works on both Fabric and Forge.
     * Checks if we should start BeaconAuth negotiation when state becomes READY_TO_ACCEPT.
     */
    @Inject(method = "tick", at = @At("HEAD"))
    private void beaconAuth$onTick(CallbackInfo ci) {
        // If we've already started or finished, handle ongoing negotiation
        if (beaconAuth$handler != null) {
            tick = 0; // prevent vanilla slow-login disconnect
            beaconAuth$handler.tick();
            return;
        }

        // Start negotiation for flows where we did NOT intercept handleHello:
        // - offline-mode servers (game profile already assigned)
        // - online-mode players already verified by Mojang (UUID present)
        if (!beaconAuth$negotiationStarted && beaconAuth$isInState("VERIFYING")) {
            GameProfile profile = beaconAuth$getAuthenticatedProfile();
            if (profile != null) {
                BEACON_LOGGER.info("Starting BeaconAuth negotiation at VERIFYING state");
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
        BEACON_LOGGER.info("Starting BeaconAuth negotiation for {}", profile.getName());

        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            profile,
            (Component reason) -> {
                BEACON_LOGGER.info("BeaconAuth negotiation failed for {}: {}", profile.getName(), reason.getString());
                beaconAuth$setAuthenticatedProfile(beaconAuth$loginProfile != null ? beaconAuth$loginProfile : profile);
                disconnect(reason);
                beaconAuth$handler = null;
                // Mark terminal state to avoid additional processing after disconnect.
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
                // Continue vanilla flow: tick() will verify and finish login.
                beaconAuth$setState("VERIFYING");
                return kotlin.Unit.INSTANCE;
            },
            beaconAuth$helloWasIntercepted
        );
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
