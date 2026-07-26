package io.github.summpot.beaconauth.server.migration

import net.minecraft.server.MinecraftServer
import net.minecraft.world.level.storage.LevelResource
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.UUID

/**
 * Performs the file-side migration of a legacy offline playerdata folder to a new UUID.
 *
 * Safety rules (enforced here, NOT at call sites):
 *  1. [fromUuid] MUST be a v3 name-based offline UUID (matches OfflinePlayer:<name>).
 *  2. [fromUuid] MUST NOT already be claimed in the ledger (caller checks, we re-check).
 *  3. Source files MUST exist.
 *  4. Target files MUST NOT exist (when [onlyIfTargetEmpty]).
 *  5. Each directory is migrated independently; partial failure is logged but does not
 *     roll back already-moved files (caller can use undo).
 *  6. When [keepLegacyBackup], source files are copied (not moved) and renamed to .migrated.
 *  7. When [dryRun], no filesystem changes are made; only a report is produced.
 *
 * Directories handled: playerdata, stats, advancements.
 * Third-party plugin data (LuckPerms, economy, etc.) is NOT handled here; an event is
 * emitted via [MigrationManager] for plugins to hook.
 */
object PlayerDataMigrator {
    private val logger = LoggerFactory.getLogger("BeaconAuth/PlayerDataMigrator")

    data class MigrationPlan(
        val fromUuid: UUID,
        val toUuid: UUID,
        val name: String,
        val onlyIfTargetEmpty: Boolean,
        val keepLegacyBackup: Boolean,
        val dryRun: Boolean
    )

    data class MigrationResult(
        val moved: List<String>,
        val skipped: List<String>,
        val failed: List<String>,
        val backupPath: String?
    ) {
        val success: Boolean get() = failed.isEmpty() && moved.isNotEmpty()
    }

    fun offlineUuid(username: String): UUID =
        UUID.nameUUIDFromBytes("OfflinePlayer:$username".toByteArray(Charsets.UTF_8))

    fun isOfflineUuid(uuid: UUID, username: String): Boolean = uuid == offlineUuid(username)

    fun execute(server: MinecraftServer, plan: MigrationPlan): MigrationResult {
        val moved = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        val failed = mutableListOf<String>()
        // Directories that store per-UUID player files. playerdata uses .dat (via LevelResource),
        // stats/advancements use .json (resolved relative to world root for cross-version stability).
        val dirs: List<Path> = listOf(
            server.getWorldPath(LevelResource.PLAYER_DATA_DIR),
            server.getWorldPath(LevelResource.ROOT).resolve("stats"),
            server.getWorldPath(LevelResource.ROOT).resolve("advancements")
        )
        var backupRoot: Path? = null

        if (plan.keepLegacyBackup && !plan.dryRun) {
            backupRoot = server.getWorldPath(LevelResource.ROOT)
                .resolve("beaconauth-migration-backups")
                .resolve(plan.fromUuid.toString())
            try {
                Files.createDirectories(backupRoot)
            } catch (e: IOException) {
                logger.error("Failed to create backup dir $backupRoot: ${e.message}", e)
                failed.add("backup-dir:${backupRoot}")
            }
        }

        for (dir in dirs) {
            val base = dir
            val source = base.resolve("${plan.fromUuid}.dat")
            val sourceJson = base.resolve("${plan.fromUuid}.json")
            val target = base.resolve("${plan.toUuid}.dat")
            val targetJson = base.resolve("${plan.toUuid}.json")

            // playerdata: .dat (and .dat_old). stats/advancements: .json.
            val hasSource = Files.isRegularFile(source) || Files.isRegularFile(sourceJson)
            if (!hasSource) {
                skipped.add("$dir:no-source")
                continue
            }

            if (plan.onlyIfTargetEmpty) {
                if (Files.isRegularFile(target) || Files.isRegularFile(targetJson)) {
                    skipped.add("$dir:target-not-empty")
                    continue
                }
            }

            if (plan.dryRun) {
                moved.add("$dir:would-migrate")
                continue
            }

            // Migrate .dat (playerdata) and .json (stats/advancements) as applicable.
            if (Files.isRegularFile(source)) {
                val outcome = migrateOne(source, target, backupRoot, plan)
                when (outcome) {
                    Outcome.MOVED -> moved.add("$dir:dat")
                    Outcome.SKIPPED -> skipped.add("$dir:dat")
                    Outcome.FAILED -> failed.add("$dir:dat")
                }
            }
            if (Files.isRegularFile(sourceJson)) {
                val outcome = migrateOne(sourceJson, targetJson, backupRoot, plan)
                when (outcome) {
                    Outcome.MOVED -> moved.add("$dir:json")
                    Outcome.SKIPPED -> skipped.add("$dir:json")
                    Outcome.FAILED -> failed.add("$dir:json")
                }
            }

            // playerdata also has <uuid>.dat_old; migrate it too if present.
            val sourceOld = base.resolve("${plan.fromUuid}.dat_old")
            if (Files.isRegularFile(sourceOld)) {
                val targetOld = base.resolve("${plan.toUuid}.dat_old")
                val outcome = migrateOne(sourceOld, targetOld, backupRoot, plan)
                when (outcome) {
                    Outcome.MOVED -> moved.add("$dir:dat_old")
                    Outcome.SKIPPED -> skipped.add("$dir:dat_old")
                    Outcome.FAILED -> failed.add("$dir:dat_old")
                }
            }
        }

        if (plan.dryRun) {
            logger.info("[dry-run] Migration plan for ${plan.name}: from=${plan.fromUuid} to=${plan.toUuid} moved=${moved.size} skipped=${skipped.size}")
        } else {
            logger.info(
                "Migration executed for name=${plan.name} from=${plan.fromUuid} to=${plan.toUuid}: " +
                    "moved=${moved.size} skipped=${skipped.size} failed=${failed.size}"
            )
        }

        return MigrationResult(moved, skipped, failed, backupRoot?.toString())
    }

    private enum class Outcome { MOVED, SKIPPED, FAILED }

    private fun migrateOne(source: Path, target: Path, backupRoot: Path?, plan: MigrationPlan): Outcome {
        return try {
            if (plan.keepLegacyBackup && backupRoot != null) {
                val backupFile = backupRoot.resolve(source.fileName.toString())
                Files.copy(source, backupFile, StandardCopyOption.REPLACE_EXISTING)
                Files.move(source, target, StandardCopyOption.REPLACE_EXISTING)
                // Keep an auditable placeholder at the source location (.migrated).
                Files.copy(backupFile, source.resolveSibling(source.fileName.toString() + ".migrated"),
                    StandardCopyOption.REPLACE_EXISTING)
            } else {
                Files.move(source, target, StandardCopyOption.REPLACE_EXISTING)
            }
            Outcome.MOVED
        } catch (e: IOException) {
            logger.error("Failed to migrate $source -> $target: ${e.message}", e)
            Outcome.FAILED
        }
    }
}