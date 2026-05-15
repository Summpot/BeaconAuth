package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.client.MinecraftSessionSupport;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Pseudo;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Pseudo
@Mixin(targets = "net.rocketplatform.game.client.mod.RocketClientMod", remap = false)
public abstract class RocketClientModMixin {
    @Inject(method = "onInitialize", at = @At("HEAD"), cancellable = true, require = 0, remap = false)
    private void beaconAuth$skipRocketServicesForOfflineSession(boolean loadLayouts, CallbackInfo ci) {
        if (MinecraftSessionSupport.isOfflineSession()) {
            ci.cancel();
        }
    }
}
