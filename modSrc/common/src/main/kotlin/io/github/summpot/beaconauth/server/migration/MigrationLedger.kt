package io.github.summpot.beaconauth.server.migration

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import net.minecraft.server.MinecraftServer
import net.minecraft.world.level.storage.LevelResource
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Persistent append-style ledger of offline->BeaconAuth playerdata claims.
 *
 * Stored as `beaconauth-migrations.json` next to the world directory.
 * One claim per source UUID (first-claim-wins, never re-claimable).
 *
 * Format (single JSON object with an array, rewritten atomically on each add):
 * {
 *   "version": 1,
 *   "claims": [
 *     { "id", "fromUuid", "toUuid", "name", "actor", "timestamp", "backupPath" }
 *   ]
 * }
 *
 * Thread-safe: serializes all reads/writes with a ReentrantLock.
 * File operations use atomic move (StandardCopyOption.ATOMIC_MOVE where supported).
 */
class MigrationLedger private constructor(private val file: Path) {
    private val lock = ReentrantLock()
    @Volatile private var data: LedgerData = loadOrInit()

    data class Claim(
        val id: String,
        val fromUuid: String,
        val toUuid: String,
        val name: String,
        val actor: String,
        val timestamp: String,
        val backupPath: String? = null
    )

    private data class LedgerData(val version: Int = 1, val claims: MutableList<Claim> = mutableListOf())

    fun all(): List<Claim> = lock.withLock { data.claims.toList() }

    fun findByFrom(fromUuid: UUID): Claim? = lock.withLock {
        data.claims.firstOrNull { it.fromUuid == fromUuid.toString() }
    }

    fun findByTo(toUuid: UUID): Claim? = lock.withLock {
        data.claims.firstOrNull { it.toUuid == toUuid.toString() }
    }

    fun findById(id: String): Claim? = lock.withLock {
        data.claims.firstOrNull { it.id == id }
    }

    fun isClaimed(fromUuid: UUID): Boolean = lock.withLock {
        data.claims.any { it.fromUuid == fromUuid.toString() }
    }

    /**
     * Append a claim. Returns the recorded Claim, or null if [fromUuid] was already claimed
     * (first-claim-wins). Persists atomically.
     */
    fun add(claim: Claim): Claim? = lock.withLock {
        if (data.claims.any { it.fromUuid == claim.fromUuid }) {
            return null
        }
        data.claims.add(claim)
        persist()
        claim
    }

    /**
     * Remove a claim by id. Used by the undo command. Does NOT restore files; caller
     * must handle file restoration before/after calling this.
     */
    fun removeById(id: String): Claim? = lock.withLock {
        val idx = data.claims.indexOfFirst { it.id == id }
        if (idx < 0) return null
        val removed = data.claims.removeAt(idx)
        persist()
        removed
    }

    private fun loadOrInit(): LedgerData = lock.withLock {
        try {
            if (Files.isRegularFile(file)) {
                val parsed = Gson().fromJson(
                    Files.newBufferedReader(file, Charsets.UTF_8),
                    LedgerData::class.java
                )
                if (parsed != null) {
                    return LedgerData(claims = parsed.claims.toMutableList())
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to load migration ledger at $file, starting fresh: ${e.message}", e)
        }
        LedgerData()
    }

    private fun persist() {
        try {
            val tmp = file.resolveSibling(file.fileName.toString() + ".tmp")
            val gson = GsonBuilder().setPrettyPrinting().create()
            Files.createDirectories(file.parent)
            Files.newBufferedWriter(tmp, Charsets.UTF_8).use { writer ->
                gson.toJson(data, writer)
            }
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (e: IOException) {
            logger.error("Failed to persist migration ledger at $file: ${e.message}", e)
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger("BeaconAuth/MigrationLedger")
        private val instances = ConcurrentHashMap<Path, MigrationLedger>()

        @JvmStatic
        fun get(server: MinecraftServer): MigrationLedger {
            val worldDir = server.getWorldPath(LevelResource.ROOT)
            val file = worldDir.resolve("beaconauth-migrations.json")
            return instances.computeIfAbsent(file) { MigrationLedger(it) }
        }

        @JvmStatic
        fun reload(server: MinecraftServer): MigrationLedger {
            val worldDir = server.getWorldPath(LevelResource.ROOT)
            val file = worldDir.resolve("beaconauth-migrations.json")
            val ledger = MigrationLedger(file)
            instances[file] = ledger
            return ledger
        }
    }
}