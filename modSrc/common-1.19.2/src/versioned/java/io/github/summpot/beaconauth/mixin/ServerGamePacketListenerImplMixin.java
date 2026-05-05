package io.github.summpot.beaconauth.mixin;

import io.github.summpot.beaconauth.server.AuthServer;
import net.minecraft.network.chat.ChatMessageContent;
import net.minecraft.network.chat.LastSeenMessages;
import net.minecraft.network.chat.MessageSigner;
import net.minecraft.network.chat.PlayerChatMessage;
import net.minecraft.network.chat.SignedMessageChain;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/**
 * Server-side: allow BeaconAuth sessions to keep chat usable.
 *
 * See common-1.21.8's variant for detailed rationale.
 */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class ServerGamePacketListenerImplMixin {
	@Shadow @Final private MinecraftServer server;
	@Shadow public ServerPlayer player;

	@Redirect(
		method = "getSignedMessage",
		at = @At(
			value = "INVOKE",
			target = "Lnet/minecraft/network/chat/SignedMessageChain$Decoder;unpack(Lnet/minecraft/network/chat/SignedMessageChain$Link;Lnet/minecraft/network/chat/MessageSigner;Lnet/minecraft/network/chat/ChatMessageContent;Lnet/minecraft/network/chat/LastSeenMessages;)Lnet/minecraft/network/chat/PlayerChatMessage;"
		)
	)
	private PlayerChatMessage beaconAuth$allowUnsignedChatWhenAllowed(
		SignedMessageChain.Decoder decoder,
		SignedMessageChain.Link link,
		MessageSigner signer,
		ChatMessageContent content,
		LastSeenMessages lastSeenMessages
	) {
		if (link.signature().isEmpty() && beaconAuth$shouldAllowUnsigned()) {
			return PlayerChatMessage.unsigned(signer, content);
		}
		return decoder.unpack(link, signer, content, lastSeenMessages);
	}

	@Redirect(
		method = "collectSignedArguments",
		at = @At(
			value = "INVOKE",
			target = "Lnet/minecraft/network/chat/SignedMessageChain$Decoder;unpack(Lnet/minecraft/network/chat/SignedMessageChain$Link;Lnet/minecraft/network/chat/MessageSigner;Lnet/minecraft/network/chat/ChatMessageContent;Lnet/minecraft/network/chat/LastSeenMessages;)Lnet/minecraft/network/chat/PlayerChatMessage;"
		),
		require = 0
	)
	private PlayerChatMessage beaconAuth$allowUnsignedCommandArgsWhenAllowed(
		SignedMessageChain.Decoder decoder,
		SignedMessageChain.Link link,
		MessageSigner signer,
		ChatMessageContent content,
		LastSeenMessages lastSeenMessages
	) {
		if (link.signature().isEmpty() && beaconAuth$shouldAllowUnsigned()) {
			return PlayerChatMessage.unsigned(signer, content);
		}
		return decoder.unpack(link, signer, content, lastSeenMessages);
	}

	private boolean beaconAuth$shouldAllowUnsigned() {
		try {
			if (!this.server.enforceSecureProfile()) {
				return true;
			}
			return AuthServer.INSTANCE.isPlayerAuthenticated(this.player.getUUID());
		} catch (Throwable ignored) {
			return false;
		}
	}
}
