package io.github.summpot.beaconauth.command

import com.mojang.brigadier.CommandDispatcher
import com.mojang.brigadier.arguments.StringArgumentType
import com.mojang.brigadier.context.CommandContext
import io.github.summpot.beaconauth.server.migration.MigrationLedger
import io.github.summpot.beaconauth.server.migration.MigrationManager
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.commands.CommandSourceStack
import net.minecraft.commands.Commands
import net.minecraft.network.chat.Component
import net.minecraft.server.level.ServerPlayer
import java.util.function.Supplier
import java.util.UUID

/**
 * BeaconAuth commands for both client and server.
 *
 * Server subcommands:
 *  - /beaconauth login                              (existing)
 *  - /beaconauth migration status <name|uuid>
 *  - /beaconauth migration claim <legacyName> <targetPlayerName|uuid>
 *  - /beaconauth migration accept                    (player-only; finalize a staged confirm claim)
 *  - /beaconauth migration undo <claimId>            (op; restores from backup then removes ledger entry)
 *  - /beaconauth migration list
 */
object AuthCommand {
    private const val PERM_LEVEL_ADMIN = 2

    fun registerClient(dispatcher: CommandDispatcher<CommandSourceStack>) {
        dispatcher.register(
            Commands.literal("beaconauth")
                .then(
                    Commands.literal("login")
                        .executes { context -> executeClientLogin(context) }
                )
        )
    }

    fun registerServer(dispatcher: CommandDispatcher<CommandSourceStack>) {
        dispatcher.register(
            Commands.literal("beaconauth")
                .then(
                    Commands.literal("login")
                        .executes { context -> executeServerLogin(context) }
                )
                .then(
                    Commands.literal("migration")
                        .requires { it.hasPermission(PERM_LEVEL_ADMIN) }
                        .then(
                            Commands.literal("status")
                                .then(
                                    Commands.argument("query", StringArgumentType.string())
                                        .executes { ctx -> executeStatus(ctx) }
                                )
                        )
                        .then(
                            Commands.literal("claim")
                                .then(
                                    Commands.argument("legacyName", StringArgumentType.string())
                                        .then(
                                            Commands.argument("target", StringArgumentType.string())
                                                .executes { ctx -> executeAdminClaim(ctx) }
                                        )
                                )
                        )
                        .then(
                            Commands.literal("undo")
                                .then(
                                    Commands.argument("claimId", StringArgumentType.string())
                                        .executes { ctx -> executeUndo(ctx) }
                                )
                        )
                        .then(
                            Commands.literal("list")
                                .executes { ctx -> executeList(ctx) }
                        )
                        .then(
                            Commands.literal("accept")
                                .executes { ctx -> executeAccept(ctx) }
                        )
                )
        )
    }

    private fun executeClientLogin(context: CommandContext<CommandSourceStack>): Int {
        sendSuccess(context.source, TranslationHelper.autoLogin(), false)
        return 1
    }

    private fun executeServerLogin(context: CommandContext<CommandSourceStack>): Int {
        sendSuccess(context.source, TranslationHelper.autoLogin(), false)
        return 1
    }

    private fun executeStatus(context: CommandContext<CommandSourceStack>): Int {
        val source = context.source
        val query = StringArgumentType.getString(context, "query")
        val server = source.server ?: run {
            sendFailure(source, TranslationHelper.migrationStatusNotFound(query))
            return 0
        }
        val ledger = MigrationLedger.get(server)
        // Try UUID first, then name.
        val asUuid = runCatching { UUID.fromString(query) }.getOrNull()
        val claim = when {
            asUuid != null -> ledger.findByFrom(asUuid) ?: ledger.findByTo(asUuid) ?: ledger.all().firstOrNull { it.id == query }
            else -> ledger.all().firstOrNull { it.name.equals(query, ignoreCase = true) }
        }
        if (claim == null) {
            sendFailure(source, TranslationHelper.migrationStatusNotFound(query))
            return 0
        }
        sendSuccess(source, TranslationHelper.migrationStatusHeader(), false)
        sendSuccess(source, TranslationHelper.migrationStatusEntry(claim.name, claim.fromUuid, claim.toUuid, claim.actor), false)
        return 1
    }

    private fun executeList(context: CommandContext<CommandSourceStack>): Int {
        val source = context.source
        val server = source.server ?: return 0
        val ledger = MigrationLedger.get(server)
        val all = ledger.all()
        if (all.isEmpty()) {
            sendSuccess(source, TranslationHelper.migrationListEmpty(), false)
            return 0
        }
        sendSuccess(source, TranslationHelper.migrationStatusHeader(), false)
        for (c in all) {
            sendSuccess(source, TranslationHelper.migrationListItem(c.id, c.name, c.fromUuid, c.toUuid), false)
        }
        return all.size
    }

    private fun executeAdminClaim(context: CommandContext<CommandSourceStack>): Int {
        val source = context.source
        val server = source.server ?: return 0
        val legacyName = StringArgumentType.getString(context, "legacyName")
        val targetRaw = StringArgumentType.getString(context, "target")
        val targetUuid = resolveTargetUuid(server, source, targetRaw)
        if (targetUuid == null) {
            sendFailure(source, TranslationHelper.migrationInvalidUuid(targetRaw))
            return 0
        }
        val result = MigrationManager.adminClaim(server, legacyName, targetUuid)
        if (result == null) {
            sendFailure(source, TranslationHelper.migrationAdminClaimSkipped("disabled/target-empty/no-source/already-claimed"))
            return 0
        }
        if (result.success) {
            sendSuccess(source, TranslationHelper.migrationAdminClaimed(legacyName, targetRaw), false)
        } else {
            sendFailure(source, TranslationHelper.migrationAdminClaimSkipped(result.failed.joinToString(", ")))
        }
        return 1
    }

    private fun executeUndo(context: CommandContext<CommandSourceStack>): Int {
        val source = context.source
        val server = source.server ?: return 0
        val claimId = StringArgumentType.getString(context, "claimId")
        val ok = MigrationManager.undo(server, claimId)
        if (ok) sendSuccess(source, TranslationHelper.migrationUndoSuccess(claimId), false)
        else sendFailure(source, TranslationHelper.migrationUndoFailed(claimId))
        return if (ok) 1 else 0
    }

    private fun executeAccept(context: CommandContext<CommandSourceStack>): Int {
        val source = context.source
        val player = source.player
        if (player == null) {
            sendFailure(source, TranslationHelper.migrationPlayerOnly())
            return 0
        }
        val server = source.server ?: return 0
        val pending = MigrationManager.getPending(player.uuid)
        if (pending == null) {
            sendFailure(source, TranslationHelper.migrationClaimNoPending())
            return 0
        }
        val result = MigrationManager.finalizePending(server, player.uuid)
        if (result == null) {
            sendFailure(source, TranslationHelper.migrationClaimFailed("no-op"))
            return 0
        }
        if (result.success) {
            sendSuccess(source, TranslationHelper.migrationClaimAccepted(pending.matchName), false)
        } else {
            sendFailure(source, TranslationHelper.migrationClaimFailed(result.failed.joinToString(", ")))
        }
        return 1
    }

    private fun resolveTargetUuid(
        server: net.minecraft.server.MinecraftServer,
        source: CommandSourceStack,
        raw: String
    ): UUID? {
        // Try as UUID first.
        val parsed = try { UUID.fromString(raw) } catch (e: IllegalArgumentException) { null }
        if (parsed != null) {
            return parsed
        }
        // Otherwise as an online player name (case-insensitive lookup via PlayerList).
        val player: ServerPlayer? = server.playerList.getPlayerByName(raw)
        if (player != null) {
            return player.uuid
        }
        // Fall back to whitelist/profile cache by name (best-effort, reflective).
        val cache = server.profileCache
        if (cache != null) {
            try {
                val getMethod = cache.javaClass.methods.firstOrNull {
                    it.name == "get" && it.parameterCount == 1 && it.parameterTypes[0] == String::class.java
                }
                if (getMethod != null) {
                    val opt = getMethod.invoke(cache, raw) as? java.util.Optional<*>
                    @Suppress("UNCHECKED_CAST")
                    val profile = opt?.orElse(null) as? com.mojang.authlib.GameProfile
                    if (profile != null && profile.id != null) {
                        return profile.id
                    }
                }
            } catch (e: Exception) {
                // ignore
            }
        }
        return null
    }

    private fun sendSuccess(source: CommandSourceStack, message: Component, broadcastToOps: Boolean) {
        val method = CommandSourceStack::class.java.methods.firstOrNull {
            it.name == "sendSuccess" &&
                it.parameterTypes.size == 2 &&
                it.parameterTypes[0] == Supplier::class.java
        }

        if (method != null) {
            method.invoke(source, Supplier { message }, broadcastToOps)
        } else {
            CommandSourceStack::class.java.getMethod(
                "sendSuccess",
                Component::class.java,
                Boolean::class.javaPrimitiveType
            ).invoke(source, message, broadcastToOps)
        }
    }

    private fun sendFailure(source: CommandSourceStack, message: Component) {
        val method = CommandSourceStack::class.java.methods.firstOrNull {
            it.name == "sendFailure" && it.parameterTypes.size == 1 && it.parameterTypes[0] == Component::class.java
        }
        method?.invoke(source, message)
    }
}