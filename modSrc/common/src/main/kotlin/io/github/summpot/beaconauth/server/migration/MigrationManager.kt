package io.github.summpot.beaconauth.server.migration

import io.github.summpot.beaconauth.config.MigrationConfig
import net.minecraft.server.MinecraftServer
import net.minecraft.world.level.storage.LevelResource
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Orchestrates offline->BeaconAuth playerdata claims.
 *
 * Decision tree (per login):
 *  - claim disabled -> no-op
 *  - compute legacyUuid = OfflinePlayer:<matchName>
 *  - legacyUuid == toUuid -> no-op (already using legacy UUID; nothing to migrate)
 *  - ledger.isClaimed(legacyUuid) -> no-op (already claimed by someone; first-claim-wins)
 *  - target has existing data + onlyIfTargetEmpty -> no-op (don't overwrite new account data)
 *  - no source data -> no-op (nothing to migrate)
 *  - mode == AUTO   -> execute migration immediately, record in ledger
 *  - mode == CONFIRM -> record a PendingClaim, prompt the player post-join; they run
 *                       /beaconauth migration accept to finalize
 *
 * All file I/O is scheduled on the server thread by the caller (we do not spawn threads).
 */
object MigrationManager {
    private val logger = LoggerFactory.getLogger("BeaconAuth/MigrationManager")

    data class PendingClaim(
        val playerUuid: UUID,
        val legacyUuid: UUID,
        val matchName: String,
        val createdAt: Instant
    )

    private val pending = ConcurrentHashMap<UUID, PendingClaim>()
    private val prompted = ConcurrentHashMap<UUID, Long>() // playerUuid -> last prompt epochMilli

    fun clearPending(playerUuid: UUID) {
        pending.remove(playerUuid)
    }

    fun getPending(playerUuid: UUID): PendingClaim? = pending[playerUuid]

    /**
     * Compute the match name for a login given config [claimNameSource].
     *  - BEACON_USERNAME: use the BeaconAuth-verified [beaconUsername]
     *  - LAUNCHER_USERNAME: use the launcher-reported [launcherUsername]
     *  - EITHER: prefer beaconUsername if non-null, else launcherUsername
     */
    fun matchName(beaconUsername: String?, launcherUsername: String?): String? {
        val source = MigrationConfig.getClaimNameSource()
        return when (source) {
            MigrationConfig.ClaimNameSource.BEACON_USERNAME -> beaconUsername
            MigrationConfig.ClaimNameSource.LAUNCHER_USERNAME -> launcherUsername
            MigrationConfig.ClaimNameSource.EITHER -> beaconUsername ?: launcherUsername
        }?.takeIf { it.isNotBlank() }
    }

    /**
     * Evaluate a login and perform (or stage) a claim. Call from ServerLoginHandler after
     * the final GameProfile UUID is decided and BEFORE finish().
     *
     * Returns the result of an immediate AUTO migration, or null if no migration ran
     * (confirm-mode staging, or no-op conditions).
     */
    fun evaluateLogin(
        server: MinecraftServer,
        targetUuid: UUID,
        beaconUsername: String?,
        launcherUsername: String?
    ): PlayerDataMigrator.MigrationResult? {
        if (!MigrationConfig.shouldClaim()) return null

        // Premium-bypass path: beaconUsername is null. Only claim when autoForPremium is set,
        // and only in AUTO mode (confirm-mode needs a modded client to run /accept).
        if (beaconUsername == null && !MigrationConfig.shouldAutoForPremium()) return null
        if (beaconUsername == null && MigrationConfig.getPlayerdataClaim() != MigrationConfig.ClaimMode.AUTO) return null

        val matchName = matchName(beaconUsername, launcherUsername) ?: return null
        val legacyUuid = PlayerDataMigrator.offlineUuid(matchName)
        if (legacyUuid == targetUuid) return null

        val ledger = MigrationLedger.get(server)
        if (ledger.isClaimed(legacyUuid)) {
            logger.debug("Legacy $legacyUuid already claimed; skipping migration for $matchName")
            return null
        }

        if (MigrationConfig.shouldOnlyIfTargetEmpty() && hasPlayerData(server, targetUuid)) {
            logger.debug("Target $targetUuid already has playerdata; skipping migration for $matchName")
            return null
        }

        if (!hasPlayerData(server, legacyUuid)) {
            logger.debug("No legacy playerdata for $legacyUuid; nothing to migrate for $matchName")
            return null
        }

        return when (MigrationConfig.getPlayerdataClaim()) {
            MigrationConfig.ClaimMode.AUTO -> executeClaim(server, targetUuid, legacyUuid, matchName, "login")
            MigrationConfig.ClaimMode.CONFIRM -> {
                pending[targetUuid] = PendingClaim(targetUuid, legacyUuid, matchName, Instant.now())
                logger.info("Staged pending migration claim for $matchName ($legacyUuid -> $targetUuid); awaiting /beaconauth migration accept")
                null
            }
            MigrationConfig.ClaimMode.OFF -> null
        }
    }

    /**
     * Finalize a staged confirm-mode claim. Call from the migration accept command.
     */
    fun finalizePending(
        server: MinecraftServer,
        playerUuid: UUID
    ): PlayerDataMigrator.MigrationResult? {
        val claim = pending.remove(playerUuid) ?: return null
        return executeClaim(server, claim.playerUuid, claim.legacyUuid, claim.matchName, "command")
    }

    /**
     * Admin-forced claim via command. Bypasses confirm staging; runs immediately.
     */
    fun adminClaim(
        server: MinecraftServer,
        legacyName: String,
        targetUuid: UUID
    ): PlayerDataMigrator.MigrationResult? {
        if (!MigrationConfig.isEnabled()) return null
        val legacyUuid = PlayerDataMigrator.offlineUuid(legacyName)
        if (legacyUuid == targetUuid) return null
        val ledger = MigrationLedger.get(server)
        if (ledger.isClaimed(legacyUuid)) return null
        if (!hasPlayerData(server, legacyUuid)) return null
        if (MigrationConfig.shouldOnlyIfTargetEmpty() && hasPlayerData(server, targetUuid)) return null
        return executeClaim(server, targetUuid, legacyUuid, legacyName, "command")
    }

    /**
     * Undo a claim by ledger id. Restores files from backup if available, then removes
     * the ledger entry. Only safe before the player has played on the new UUID.
     */
    fun undo(server: MinecraftServer, claimId: String): Boolean {
        val ledger = MigrationLedger.get(server)
        val claim = ledger.findById(claimId) ?: return false
        val restored = restoreFromBackup(server, claim)
        if (restored) {
            ledger.removeById(claimId)
            logger.info("Undid migration claim $claimId (${claim.name})")
        }
        return restored
    }

    private fun executeClaim(
        server: MinecraftServer,
        targetUuid: UUID,
        legacyUuid: UUID,
        name: String,
        actor: String
    ): PlayerDataMigrator.MigrationResult? {
        val ledger = MigrationLedger.get(server)
        if (ledger.isClaimed(legacyUuid)) return null

        val plan = PlayerDataMigrator.MigrationPlan(
            fromUuid = legacyUuid,
            toUuid = targetUuid,
            name = name,
            onlyIfTargetEmpty = MigrationConfig.shouldOnlyIfTargetEmpty(),
            keepLegacyBackup = MigrationConfig.shouldKeepLegacyBackup(),
            dryRun = MigrationConfig.isDryRun()
        )

        val result = PlayerDataMigrator.execute(server, plan)
        if (result.success && !plan.dryRun) {
            val claim = MigrationLedger.Claim(
                id = UUID.randomUUID().toString(),
                fromUuid = legacyUuid.toString(),
                toUuid = targetUuid.toString(),
                name = name,
                actor = actor,
                timestamp = Instant.now().toString(),
                backupPath = result.backupPath
            )
            val recorded = ledger.add(claim)
            if (recorded == null) {
                logger.warn("Race: legacy $legacyUuid was claimed concurrently; migration for $name may be orphaned")
            }
        }
        return result
    }

    private fun hasPlayerData(server: MinecraftServer, uuid: UUID): Boolean {
        val dir = server.getWorldPath(net.minecraft.world.level.storage.LevelResource.PLAYER_DATA_DIR)
        return Files.isRegularFile(dir.resolve("$uuid.dat"))
            || Files.isRegularFile(dir.resolve("$uuid.dat_old"))
    }

    private fun restoreFromBackup(server: MinecraftServer, claim: MigrationLedger.Claim): Boolean {
        val fromUuid = UUID.fromString(claim.fromUuid)
        val toUuid = UUID.fromString(claim.toUuid)
        val backupPath = claim.backupPath ?: return false
        val backupDir = Paths.get(backupPath)
        if (!Files.isDirectory(backupDir)) return false

        val dirs: List<Path> = listOf(
            server.getWorldPath(LevelResource.PLAYER_DATA_DIR),
            server.getWorldPath(LevelResource.ROOT).resolve("stats"),
            server.getWorldPath(LevelResource.ROOT).resolve("advancements")
        )
        var anyRestored = false
        for (base in dirs) {
            // Move target file back to source UUID.
            val targetDat = base.resolve("$toUuid.dat")
            val targetJson = base.resolve("$toUuid.json")
            val sourceDat = base.resolve("$fromUuid.dat")
            val sourceJson = base.resolve("$fromUuid.json")
            try {
                if (Files.isRegularFile(targetDat)) {
                    Files.move(targetDat, sourceDat, StandardCopyOption.REPLACE_EXISTING)
                    anyRestored = true
                }
                if (Files.isRegularFile(targetJson)) {
                    Files.move(targetJson, sourceJson, StandardCopyOption.REPLACE_EXISTING)
                    anyRestored = true
                }
            } catch (e: java.io.IOException) {
                logger.error("Undo: failed to restore $base for claim ${claim.id}: ${e.message}", e)
            }
        }
        return anyRestored
    }

    fun shouldPrompt(playerUuid: UUID): Boolean {
        if (!MigrationConfig.isEnabled() || MigrationConfig.getPromptMode() == MigrationConfig.PromptMode.OFF) {
            return false
        }
        if (!MigrationConfig.shouldPromptOnJoin()) return false
        val now = System.currentTimeMillis()
        val last = prompted[playerUuid] ?: 0L
        val intervalMs = MigrationConfig.getPromptIntervalMinutes() * 60_000L
        if (now - last < intervalMs) return false
        prompted[playerUuid] = now
        return true
    }

    fun clearPromptState(playerUuid: UUID) {
        prompted.remove(playerUuid)
    }
}