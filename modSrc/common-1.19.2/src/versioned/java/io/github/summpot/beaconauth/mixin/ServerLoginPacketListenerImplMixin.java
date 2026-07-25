package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.config.BeaconAuthConfig;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.contents.TranslatableContents;
import net.minecraft.network.protocol.login.ServerboundCustomQueryPacket;
import net.minecraft.network.protocol.login.ServerboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Mixin entry point for BeaconAuth login-phase negotiation on server.
 *
 * Dual-path online-mode (default when bypass_if_online_mode_verified=true):
 * 1. Do NOT consume HELLO — Mojang encryption + hasJoinedServer still run.
 * 2. Mojang success → negotiate at READY_TO_ACCEPT; vanilla / verified modded allow-through.
 * 3. Mojang failure → cancel disconnect, fall back to BeaconAuth (mod required if unmodded).
 *
 * When bypass=false: force-consume HELLO and require BeaconAuth for all.
 */
@Mixin(value = ServerLoginPacketListenerImpl.class, priority = 1100)
public abstract class ServerLoginPacketListenerImplMixin {
    @Unique private static final org.slf4j.Logger BEACON_LOGGER = LoggerFactory.getLogger("BeaconAuth/Mixin");

    @Shadow @Final private MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow private int tick;
    @Shadow @Nullable GameProfile gameProfile;
    @Shadow @Nullable private ServerPlayer delayedAcceptPlayer;

    @Shadow protected abstract void disconnect(Component reason);

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted = false;
    @Unique private boolean beaconAuth$helloWasIntercepted = false;
    @Unique private boolean beaconAuth$mojangFallbackScheduled = false;
    @Unique @Nullable private GameProfile beaconAuth$loginProfile;
    /** Preserved across Mojang failure (vanilla nulls gameProfile before disconnect). */
    @Unique @Nullable private String beaconAuth$pendingUsername;

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

        beaconAuth$pendingUsername = packet.name();

        if (BeaconAuthConfig.INSTANCE.shouldBypassIfOnlineModeVerified()) {
            BEACON_LOGGER.debug(
                "Dual-path online-mode for {}: leaving HELLO to Mojang; BeaconAuth negotiates after success or on failure fallback",
                packet.name()
            );
            return;
        }

        BEACON_LOGGER.info("Force BeaconAuth for online-mode login {}; consuming HELLO", packet.name());
        beaconAuth$helloWasIntercepted = true;
        this.gameProfile = new GameProfile(beaconAuth$offlineUuid(packet.name()), packet.name());
        beaconAuth$loginProfile = this.gameProfile;
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$startNegotiation();
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

        final String username = beaconAuth$resolveUsername();
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
            this.gameProfile = new GameProfile(beaconAuth$offlineUuid(username), username);
            beaconAuth$loginProfile = this.gameProfile;
            beaconAuth$setState("NEGOTIATING");
            tick = 0;
            beaconAuth$startNegotiation();
        });
        return true;
    }

    @Unique
    @Nullable
    private String beaconAuth$resolveUsername() {
        if (beaconAuth$pendingUsername != null && !beaconAuth$pendingUsername.isEmpty()) {
            return beaconAuth$pendingUsername;
        }
        if (gameProfile != null && gameProfile.getName() != null && !gameProfile.getName().isEmpty()) {
            return gameProfile.getName();
        }
        return null;
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

    @Redirect(
        method = "tick",
        at = @At(
            value = "INVOKE",
            target = "Lnet/minecraftforge/network/NetworkHooks;tickNegotiation(Lnet/minecraft/server/network/ServerLoginPacketListenerImpl;Lnet/minecraft/network/Connection;Lnet/minecraft/server/level/ServerPlayer;)Z",
            remap = false
        ),
        require = 0
    )
    private boolean beaconAuth$redirectForgeNegotiation(
        ServerLoginPacketListenerImpl listener,
        Connection connection,
        ServerPlayer delayedPlayer
    ) {
        if (beaconAuth$handler != null) {
            return false;
        }

        try {
            Class<?> networkHooks = Class.forName("net.minecraftforge.network.NetworkHooks");
            java.lang.reflect.Method method = networkHooks.getMethod(
                "tickNegotiation",
                ServerLoginPacketListenerImpl.class,
                Connection.class,
                ServerPlayer.class
            );
            return (boolean) method.invoke(null, listener, connection, delayedPlayer);
        } catch (Exception e) {
            return true;
        }
    }

    @Inject(method = "tick", at = @At("HEAD"))
    private void beaconAuth$onTick(CallbackInfo ci) {
        if (beaconAuth$handler != null) {
            tick = 0;
            beaconAuth$handler.tick();
            return;
        }

        if (!beaconAuth$negotiationStarted && beaconAuth$isReadyToAccept()) {
            BEACON_LOGGER.info("Starting BeaconAuth negotiation at READY_TO_ACCEPT state");
            beaconAuth$startNegotiation();
        }
    }

    @Inject(method = "handleCustomQueryPacket", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleCustomQuery(ServerboundCustomQueryPacket packet, CallbackInfo ci) {
        if (beaconAuth$handler == null) {
            return;
        }
        boolean handled = beaconAuth$handler.handleCustomQuery(packet.getTransactionId(), packet.getData());
        if (handled) {
            ci.cancel();
        }
    }

    @Unique
    private boolean beaconAuth$isReadyToAccept() {
        return beaconAuth$isInState("READY_TO_ACCEPT") && gameProfile != null;
    }

    @Unique
    private boolean beaconAuth$isInState(String expectedState) {
        return beaconAuth$accessor().beaconAuth$getState().toString().equals(expectedState);
    }

    @Unique
    private void beaconAuth$startNegotiation() {
        if (gameProfile == null) {
            BEACON_LOGGER.warn("Cannot start negotiation: gameProfile is null");
            return;
        }
        if (beaconAuth$negotiationStarted) {
            return;
        }

        GameProfile negotiationProfile = gameProfile;
        beaconAuth$loginProfile = negotiationProfile;

        BEACON_LOGGER.info(
            "Starting BeaconAuth negotiation for {} (mojangVerified={})",
            negotiationProfile.getName(),
            !beaconAuth$helloWasIntercepted
        );
        beaconAuth$negotiationStarted = true;
        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            negotiationProfile,
            (Component failReason) -> {
                BEACON_LOGGER.info(
                    "BeaconAuth negotiation failed for {}: {}",
                    negotiationProfile.getName(),
                    failReason.getString()
                );
                if (gameProfile == null) {
                    gameProfile = beaconAuth$loginProfile != null ? beaconAuth$loginProfile : negotiationProfile;
                }
                disconnect(failReason);
                beaconAuth$handler = null;
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                BEACON_LOGGER.info(
                    "BeaconAuth negotiation finished successfully for {}",
                    negotiationProfile.getName()
                );

                if (beaconAuth$handler != null) {
                    GameProfile updated = beaconAuth$handler.getCurrentGameProfile();
                    if (updated != null) {
                        this.gameProfile = updated;
                        beaconAuth$loginProfile = updated;
                    }
                }

                beaconAuth$handler = null;
                beaconAuth$setState("READY_TO_ACCEPT");
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
}
