package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.MinecraftSessionSupport;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Pseudo;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Pseudo
@Mixin(targets = "net.rocketplatform.game.client.mod.ui.FTBWorldsButton", remap = false)
public abstract class FTBWorldsButtonMixin {
    @Inject(method = "createVanilla", at = @At("HEAD"), cancellable = true, require = 0, remap = false)
    private static void beaconAuth$hideButtonForOfflineSession(
        int x,
        int y,
        int width,
        int height,
        CallbackInfoReturnable<Object> cir
    ) {
        if (MinecraftSessionSupport.isOfflineSession()) {
            cir.setReturnValue(null);
        }
    }
}
