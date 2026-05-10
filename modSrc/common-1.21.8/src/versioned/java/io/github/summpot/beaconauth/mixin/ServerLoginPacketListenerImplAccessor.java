package io.github.summpot.beaconauth.mixin;

import com.mojang.authlib.GameProfile;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.jetbrains.annotations.Nullable;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(ServerLoginPacketListenerImpl.class)
public interface ServerLoginPacketListenerImplAccessor {
    @Accessor("state")
    ServerLoginPacketListenerImpl.State beaconAuth$getState();

    @Accessor("state")
    void beaconAuth$setState(ServerLoginPacketListenerImpl.State state);

    @Accessor("authenticatedProfile")
    @Nullable
    GameProfile beaconAuth$getAuthenticatedProfile();

    @Accessor("authenticatedProfile")
    void beaconAuth$setAuthenticatedProfile(GameProfile profile);

    @Accessor("requestedUsername")
    void beaconAuth$setRequestedUsername(String requestedUsername);
}
