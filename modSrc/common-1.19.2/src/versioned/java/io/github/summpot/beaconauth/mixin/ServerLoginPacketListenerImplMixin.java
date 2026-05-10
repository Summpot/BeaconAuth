package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.config.BeaconAuthConfig;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.login.ServerboundCustomQueryPacket;
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
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Mixin entry point for BeaconAuth login-phase negotiation on server.
 * All logic delegated to ServerLoginHandler (Kotlin).
 * 
 * This Mixin works on both Fabric and Forge:
 * - Intercepts handleHello to route login to BeaconAuth negotiation when BeaconAuth should be used
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

    @Shadow protected abstract void disconnect(Component reason);
    @Shadow public abstract void handleAcceptedLogin();

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted = false;
    @Unique private boolean beaconAuth$helloWasIntercepted = false;
    @Unique private boolean beaconAuth$completingVanillaLogin = false;
    @Unique private boolean beaconAuth$completeVanillaLoginPending = false;
    @Unique private boolean beaconAuth$loginTerminated = false;

    /**
     * Intercept handleHello to decide whether to use BeaconAuth or Mojang authentication.
     * 
     * BeaconAuth is designed to work on online-mode=true servers, allowing offline-mode
     * players (using community-managed accounts) to authenticate via the custom BeaconAuth system.
     * 
     * This intercept routes the login to BeaconAuth negotiation and goes directly to NEGOTIATING state,
     * where BeaconAuth will probe the client and decide whether to:
     * - Use BeaconAuth authentication (for modded clients that need community-managed server access)
     * - Allow the existing session (for clients that already passed Mojang auth)
     * - Reject the connection (for vanilla clients when configured to require the mod)
     */
    @Redirect(
        method = "handleHello",
        at = @At(
            value = "INVOKE",
            target = "Lnet/minecraft/server/MinecraftServer;usesAuthentication()Z"
        )
    )
    private boolean beaconAuth$redirectUsesAuthentication(MinecraftServer minecraftServer) {
        boolean serverOnlineMode = minecraftServer.usesAuthentication();
        boolean isMemoryConnection = connection.isMemoryConnection();

        if (serverOnlineMode && !isMemoryConnection) {
            String name = gameProfile == null ? "<unknown>" : gameProfile.getName();
            BEACON_LOGGER.info("Routing online-mode login for {} through BeaconAuth negotiation", name);
            beaconAuth$helloWasIntercepted = true;
            return false;
        }
        return serverOnlineMode;
    }

    /**
     * Main injection point that works on both Fabric and Forge.
     * Checks if we should start BeaconAuth negotiation when state becomes READY_TO_ACCEPT.
     */
    @Inject(method = "tick", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$onTick(CallbackInfo ci) {
        if (beaconAuth$loginTerminated) {
            ci.cancel();
            return;
        }

        if (beaconAuth$completeVanillaLoginPending) {
            beaconAuth$completeVanillaLoginPending = false;
            beaconAuth$completeVanillaLogin();
            ci.cancel();
            return;
        }

        // If we've already started or finished, handle ongoing negotiation
        if (beaconAuth$handler != null) {
            tick = 0; // prevent vanilla slow-login disconnect
            beaconAuth$handler.tick();
            ci.cancel();
        }
    }

    @Inject(method = "handleAcceptedLogin", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$beforeAcceptedLogin(CallbackInfo ci) {
        if (beaconAuth$completingVanillaLogin) {
            return;
        }
        if (beaconAuth$loginTerminated || beaconAuth$handler != null) {
            ci.cancel();
            return;
        }
        if (beaconAuth$negotiationStarted) {
            ci.cancel();
            return;
        }
        if (!beaconAuth$negotiationStarted && gameProfile != null) {
            BEACON_LOGGER.info("Starting BeaconAuth negotiation before accepting login");
            beaconAuth$startNegotiation(gameProfile, beaconAuth$helloWasIntercepted);
            ci.cancel();
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
    private void beaconAuth$startNegotiation(GameProfile profile, boolean helloWasIntercepted) {
        if (beaconAuth$negotiationStarted) {
            return;
        }
        
        BEACON_LOGGER.info("Starting BeaconAuth negotiation for {}", profile.getName());
        beaconAuth$negotiationStarted = true;
        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            profile,
            (Component reason) -> {
                BEACON_LOGGER.info("BeaconAuth negotiation failed for {}: {}", profile.getName(), reason.getString());
                beaconAuth$loginTerminated = true;
                disconnect(reason);
                beaconAuth$handler = null;
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                BEACON_LOGGER.info("BeaconAuth negotiation finished successfully for {}", profile.getName());

                // IMPORTANT: ServerLoginHandler may update the GameProfile UUID after BeaconAuth verification.
                // Copy it back so the server uses a stable per-account UUID (not username-derived).
                if (beaconAuth$handler != null) {
                    GameProfile updated = beaconAuth$handler.getCurrentGameProfile();
                    if (updated != null) {
                        this.gameProfile = updated;
                    }
                }

                beaconAuth$handler = null;
                beaconAuth$completeVanillaLoginPending = true;
                return kotlin.Unit.INSTANCE;
            },
            helloWasIntercepted
        );
        beaconAuth$handler.start();
    }

    @Unique
    private void beaconAuth$completeVanillaLogin() {
        if (gameProfile == null) {
            BEACON_LOGGER.warn("Cannot complete login: gameProfile is null");
            return;
        }
        beaconAuth$completingVanillaLogin = true;
        try {
            handleAcceptedLogin();
        } finally {
            beaconAuth$completingVanillaLogin = false;
        }
    }
}
