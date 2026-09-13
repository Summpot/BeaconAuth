package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.server.AuthServer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.minecraft.network.chat.LastSeenMessages;
import net.minecraft.network.chat.PlayerChatMessage;
import net.minecraft.network.chat.SignableCommand;
import net.minecraft.network.protocol.game.ServerboundChatPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Server-side: allow BeaconAuth sessions to keep chat usable.
 *
 * Vanilla will throw {@link net.minecraft.network.chat.SignedMessageChain.DecodeException} with
 * "chat.disabled.missingProfileKey" if a chat/command signature is missing while a signed chat
 * decoder is active.
 *
 * For BeaconAuth players (who intentionally do not have Mojang-signed profile keys), and for any
 * server that does not enforce secure profiles, we treat missing signatures as unsigned messages.
 */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class ServerGamePacketListenerImplMixin {
	@Shadow public ServerPlayer player;

	@Inject(method = "getSignedMessage", at = @At("HEAD"), cancellable = true)
	private void beaconAuth$allowUnsignedChatWhenAllowed(
		ServerboundChatPacket packet,
		LastSeenMessages lastSeenMessages,
		CallbackInfoReturnable<PlayerChatMessage> cir
	) {
		if (packet.signature() == null && beaconAuth$shouldAllowUnsigned()) {
			cir.setReturnValue(PlayerChatMessage.unsigned(this.player.getUUID(), packet.message()));
		}
	}

	@Inject(method = "collectUnsignedArguments", at = @At("HEAD"), cancellable = true, require = 0)
	private <S> void beaconAuth$allowUnsignedCommandArgsWhenAllowed(
		List<SignableCommand.Argument<S>> parsedArguments,
		CallbackInfoReturnable<Map<String, PlayerChatMessage>> cir
	) {
		if (beaconAuth$shouldAllowUnsigned()) {
			Map<String, PlayerChatMessage> arguments = new HashMap<>();
			for (SignableCommand.Argument<S> parsedArgument : parsedArguments) {
				arguments.put(parsedArgument.name(), PlayerChatMessage.unsigned(this.player.getUUID(), parsedArgument.value()));
			}
			cir.setReturnValue(arguments);
		}
	}

	private boolean beaconAuth$shouldAllowUnsigned() {
		try {
			MinecraftServer server = this.player.level() instanceof ServerLevel serverLevel
				? serverLevel.getServer()
				: null;
			if (server == null) {
				return false;
			}
			if (!server.enforceSecureProfile()) {
				return true;
			}
			return AuthServer.INSTANCE.isPlayerAuthenticated(this.player.getUUID());
		} catch (Throwable ignored) {
			return false;
		}
	}
}
