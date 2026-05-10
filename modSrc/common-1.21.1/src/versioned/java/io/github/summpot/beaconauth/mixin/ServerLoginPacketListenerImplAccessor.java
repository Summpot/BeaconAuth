package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;
import org.spongepowered.asm.mixin.gen.Invoker;

@Mixin(ServerLoginPacketListenerImpl.class)
public interface ServerLoginPacketListenerImplAccessor {
    @Accessor("requestedUsername")
    void beaconAuth$setRequestedUsername(@Nullable String username);

    @Accessor("authenticatedProfile")
    @Nullable
    GameProfile beaconAuth$getAuthenticatedProfile();

    @Accessor("authenticatedProfile")
    void beaconAuth$setAuthenticatedProfile(@Nullable GameProfile profile);

    @Invoker("startClientVerification")
    void beaconAuth$startClientVerification(GameProfile profile);
}
