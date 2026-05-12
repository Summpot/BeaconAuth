package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.BeaconAuthClientSession;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Pseudo;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.util.concurrent.CompletableFuture;

@Pseudo
@Mixin(targets = "com.mrbysco.neoauth.util.SessionUtils", remap = false)
public abstract class NeoAuthSessionUtilsMixin {
    @Inject(method = "getStatus", at = @At("HEAD"), cancellable = true, require = 0)
    private static void beaconAuth$skipStatusDuringBeaconAuth(CallbackInfoReturnable<CompletableFuture<?>> cir) {
        if (!BeaconAuthClientSession.isBeaconAuthLoginActive()) {
            return;
        }

        try {
            Class<?> statusClass = Class.forName("com.mrbysco.neoauth.util.SessionUtils$SessionStatus");
            @SuppressWarnings({"unchecked", "rawtypes"})
            Object unknown = Enum.valueOf((Class<? extends Enum>) statusClass.asSubclass(Enum.class), "UNKNOWN");
            cir.setReturnValue(CompletableFuture.completedFuture(unknown));
        } catch (ReflectiveOperationException ignored) {
            // NeoAuth changed shape; allow its own status check to run.
        }
    }
}
