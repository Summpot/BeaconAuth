package io.github.summpot.beaconauth.mixin;

import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(ServerLoginPacketListenerImpl.class)
public interface ServerLoginPacketListenerImplAccessor {
    @Accessor("state")
    ServerLoginPacketListenerImpl.State beaconAuth$getState();

    @Accessor("state")
    void beaconAuth$setState(ServerLoginPacketListenerImpl.State state);
}
