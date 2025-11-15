package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import io.github.summpot.beaconauth.server.ServerLoginHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.login.ServerboundCustomQueryPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Mixin entry point for BeaconAuth login-phase negotiation on server.
 * All logic delegated to ServerLoginHandler (Kotlin).
 */
@Mixin(ServerLoginPacketListenerImpl.class)
public abstract class ServerLoginPacketListenerImplMixin {
    @Shadow @Final private MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow private int tick;
    @Shadow @Nullable GameProfile gameProfile;

    @Shadow protected abstract void disconnect(Component reason);

    @Unique private ServerLoginHandler beaconAuth$handler;
    @Unique private boolean beaconAuth$negotiationStarted;
    @Unique private boolean beaconAuth$isInNegotiation = false;

    @Unique
    private boolean beaconAuth$isReadyToAccept() {
        try {
            java.lang.reflect.Field stateField = ServerLoginPacketListenerImpl.class.getDeclaredField("state");
            stateField.setAccessible(true);
            Object stateValue = stateField.get(this);
            return stateValue.toString().equals("READY_TO_ACCEPT");
        } catch (Exception e) {
            return false;
        }
    }

    @Unique
    private boolean beaconAuth$isNegotiating() {
        return beaconAuth$isInNegotiation;
    }

    @Unique
    private void beaconAuth$setState(String stateName) {
        try {
            java.lang.reflect.Field stateField = ServerLoginPacketListenerImpl.class.getDeclaredField("state");
            stateField.setAccessible(true);
            Class<?> stateClass = Class.forName("net.minecraft.server.network.ServerLoginPacketListenerImpl$State");
            Object stateValue = java.util.Arrays.stream(stateClass.getEnumConstants())
                .filter(e -> e.toString().equals(stateName))
                .findFirst()
                .orElse(null);
            if (stateValue != null) {
                stateField.set(this, stateValue);
                beaconAuth$isInNegotiation = stateName.equals("NEGOTIATING");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Inject(method = "tick", at = @At("HEAD"))
    private void beaconAuth$guardNegotiation(CallbackInfo ci) {
        if (!beaconAuth$negotiationStarted && beaconAuth$isReadyToAccept()) {
            beaconAuth$startNegotiation();
        }

        if (beaconAuth$isNegotiating() && beaconAuth$handler != null) {
            tick = 0; // prevent vanilla slow-login disconnect
            beaconAuth$handler.tick();
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

    private void beaconAuth$startNegotiation() {
        if (gameProfile == null) {
            return;
        }
        beaconAuth$negotiationStarted = true;
        beaconAuth$handler = new ServerLoginHandler(
            server,
            connection,
            gameProfile,
            (Component reason) -> {
                disconnect(reason);
                beaconAuth$handler = null;
                beaconAuth$setState("ACCEPTED");
                return kotlin.Unit.INSTANCE;
            },
            () -> {
                beaconAuth$handler = null;
                beaconAuth$setState("READY_TO_ACCEPT");
                return kotlin.Unit.INSTANCE;
            }
        );
        beaconAuth$setState("NEGOTIATING");
        beaconAuth$handler.start();
    }
}
