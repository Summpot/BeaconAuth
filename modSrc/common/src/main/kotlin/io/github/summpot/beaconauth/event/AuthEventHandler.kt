package io.github.summpot.beaconauth.event

import dev.architectury.event.events.common.PlayerEvent
import io.github.summpot.beaconauth.config.MigrationConfig
import io.github.summpot.beaconauth.server.AuthServer
import io.github.summpot.beaconauth.server.migration.MigrationManager
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.server.level.ServerPlayer
import org.slf4j.LoggerFactory

/**
 * Event handlers for authentication checks and migration prompts.
 */
object AuthEventHandler {
    private val logger = LoggerFactory.getLogger("BeaconAuth/Events")

    fun register() {
        PlayerEvent.PLAYER_JOIN.register { player ->
            if (player is ServerPlayer) {
                handlePlayerJoin(player)
            }
        }
        PlayerEvent.PLAYER_QUIT.register { player ->
            if (player is ServerPlayer) {
                handlePlayerQuit(player)
            }
        }
    }

    private fun handlePlayerJoin(player: ServerPlayer) {
        logger.info("Player ${player.gameProfile.name} joined the server")
        try {
            // Migration prompts (best-effort; never block join).
            if (MigrationConfig.isEnabled()) {
                val pending = MigrationManager.getPending(player.uuid)
                if (pending != null) {
                    player.sendSystemMessage(TranslationHelper.migrationPromptClaimAccept(pending.matchName))
                } else if (
                    !AuthServer.isPlayerAuthenticated(player.uuid) &&
                    MigrationConfig.getPromptMode() != MigrationConfig.PromptMode.OFF &&
                    MigrationManager.shouldPrompt(player.uuid)
                ) {
                    player.sendSystemMessage(TranslationHelper.migrationPromptRegister())
                }
            }
        } catch (e: Exception) {
            logger.warn("Migration prompt failed for ${player.gameProfile.name}: ${e.message}", e)
        }
    }

    private fun handlePlayerQuit(player: ServerPlayer) {
        logger.info("Player ${player.gameProfile.name} left the server")
        AuthServer.removeAuthenticatedPlayer(player.uuid)
        MigrationManager.clearPromptState(player.uuid)
        // Pending claims are intentionally retained across sessions; the player can still /accept later.
    }
}