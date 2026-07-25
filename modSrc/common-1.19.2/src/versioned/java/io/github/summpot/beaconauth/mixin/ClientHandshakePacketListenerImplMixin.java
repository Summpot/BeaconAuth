package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.ClientLoginHandler;
import io.github.summpot.beaconauth.client.MinecraftSessionSupport;
import io.github.summpot.beaconauth.login.LoginQueryType;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.contents.TranslatableContents;
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket;
import net.minecraft.resources.ResourceLocation;
import org.jetbrains.annotations.Nullable;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Mixin entry point for BeaconAuth login-phase custom queries on client.
 * All logic delegated to ClientLoginHandler (Kotlin).
 *
 * Also keeps offline/modded clients alive through online-mode encryption:
 * vanilla would disconnect with "Invalid session" before the server can fall
 * back to BeaconAuth. Premium sessions still call Mojang joinServer normally.
 */
@Mixin(ClientHandshakePacketListenerImpl.class)
public abstract class ClientHandshakePacketListenerImplMixin {
    @Unique
    private static final org.slf4j.Logger BEACON_LOGGER = LoggerFactory.getLogger("BeaconAuth/ClientHandshake");

    @Shadow @Final private Connection connection;

    @Inject(method = "handleCustomQuery", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$handleCustomQuery(ClientboundCustomQueryPacket packet, CallbackInfo ci) {
        ResourceLocation id = packet.getIdentifier();
        if (id.equals(LoginQueryType.PROBE.id())) {
            ClientLoginHandler.respondProbe(connection, packet.getTransactionId());
            ci.cancel();
        } else if (id.equals(LoginQueryType.INIT.id())) {
            ClientLoginHandler.respondInit(connection, packet.getTransactionId());
            ci.cancel();
        } else if (id.equals(LoginQueryType.LOGIN_URL.id())) {
            ClientLoginHandler.handleLoginUrl(connection, packet.getTransactionId(), packet.getData());
            ci.cancel();
        } else if (id.equals(LoginQueryType.VERIFY.id())) {
            ClientLoginHandler.handleVerifyRequest(connection, packet.getTransactionId());
            ci.cancel();
        }
    }

    /**
     * Skip Mojang joinServer for known offline sessions (no useless network call).
     * authenticateServer returns null = "no error" → encryption continues.
     */
    @Inject(method = "authenticateServer", at = @At("HEAD"), cancellable = true)
    private void beaconAuth$skipJoinWhenOffline(String serverId, CallbackInfoReturnable<Component> cir) {
        if (MinecraftSessionSupport.isOfflineSession()) {
            BEACON_LOGGER.info(
                "Offline client session detected; skipping Mojang joinServer so dual-path BeaconAuth can run on the server"
            );
            cir.setReturnValue(null);
        }
    }

    /**
     * Cracked launchers often look like MSA with a dummy token. Vanilla then
     * returns invalidSession / serversUnavailable and aborts before Key is sent.
     * Clear those errors so encryption completes; the online-mode server either
     * verifies via hasJoinedServer (premium) or falls back to BeaconAuth.
     */
    @Inject(method = "authenticateServer", at = @At("RETURN"), cancellable = true)
    private void beaconAuth$continueAfterSessionReject(String serverId, CallbackInfoReturnable<Component> cir) {
        Component error = cir.getReturnValue();
        if (error == null || !beaconAuth$isRecoverableSessionFailure(error)) {
            return;
        }
        BEACON_LOGGER.info(
            "Mojang session check failed ({}); continuing encryption for BeaconAuth dual-path",
            beaconAuth$innerTranslationKey(error)
        );
        cir.setReturnValue(null);
    }

    @Unique
    private static boolean beaconAuth$isRecoverableSessionFailure(Component error) {
        String inner = beaconAuth$innerTranslationKey(error);
        return "disconnect.loginFailedInfo.invalidSession".equals(inner)
            || "disconnect.loginFailedInfo.serversUnavailable".equals(inner);
    }

    @Unique
    @Nullable
    private static String beaconAuth$innerTranslationKey(Component error) {
        if (!(error.getContents() instanceof TranslatableContents outer)) {
            return null;
        }
        if (!"disconnect.loginFailedInfo".equals(outer.getKey()) || outer.getArgs().length == 0) {
            if ("disconnect.loginFailedInfo.invalidSession".equals(outer.getKey())
                || "disconnect.loginFailedInfo.serversUnavailable".equals(outer.getKey())) {
                return outer.getKey();
            }
            return null;
        }
        Object arg = outer.getArgs()[0];
        if (arg instanceof Component component && component.getContents() instanceof TranslatableContents inner) {
            return inner.getKey();
        }
        return null;
    }
}
