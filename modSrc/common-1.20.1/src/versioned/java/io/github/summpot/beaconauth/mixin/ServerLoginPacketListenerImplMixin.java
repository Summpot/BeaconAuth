package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.config.BeaconAuthConfig;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
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
 * All logic delegated to ServerLoginHandler (Kotlin).
 * 
 * This Mixin works on both Fabric and Forge:
 * - Intercepts handleHello only when configuration requires BeaconAuth instead of Mojang auth
 * - On Forge: Intercepts NetworkHooks.tickNegotiation() via @Redirect to prevent NPE
 * - On Fabric & Forge: Uses @Inject to handle BeaconAuth flow at READY_TO_ACCEPT state
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
        this.gameProfile = new GameProfile(beaconAuth$offlineUuid(packet.name()), packet.name());
        beaconAuth$loginProfile = this.gameProfile;
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$startNegotiation();
        ci.cancel();
    }

    @Unique
    private static UUID beaconAuth$offlineUuid(String username) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Redirect Forge's NetworkHooks.tickNegotiation() call to prevent NPE.
     * When we're handling BeaconAuth, we return false to keep vanilla in NEGOTIATING state.
     * Otherwise, we call the original Forge method.
     */
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
        // If we're handling BeaconAuth, prevent Forge from proceeding
        if (beaconAuth$handler != null) {
            return false; // Keep vanilla in NEGOTIATING state
        }

        // Otherwise, let Forge handle it normally
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
            return true; // Fallback: assume negotiation is complete
        }
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
        
        GameProfile negotiationProfile = gameProfile;
        beaconAuth$loginProfile = negotiationProfile;

        BEACON_LOGGER.info("Starting BeaconAuth negotiation for {}", negotiationProfile.getName());
        beaconAuth$negotiationStarted = true;
        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            negotiationProfile,
            (Component reason) -> {
                BEACON_LOGGER.info("BeaconAuth negotiation failed for {}: {}", negotiationProfile.getName(), reason.getString());
                if (gameProfile == null) {
                    gameProfile = beaconAuth$loginProfile != null ? beaconAuth$loginProfile : negotiationProfile;
                }
                disconnect(reason);
                beaconAuth$handler = null;
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                BEACON_LOGGER.info("BeaconAuth negotiation finished successfully for {}", negotiationProfile.getName());

                // IMPORTANT: ServerLoginHandler may update the GameProfile UUID after BeaconAuth verification.
                // Copy it back so the server uses a stable per-account UUID (not username-derived).
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
    }
}
