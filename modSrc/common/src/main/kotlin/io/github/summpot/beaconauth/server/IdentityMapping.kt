package io.github.summpot.beaconauth.server

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import net.minecraft.server.MinecraftServer
import net.minecraft.world.level.storage.LevelResource
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Maps BeaconAuth account subjects to legacy offline-mode player UUIDs.
 *
 * On offline-mode servers, world data (playerdata/, stats/, advancements/) is keyed by the
 * deterministic "OfflinePlayer:<name>" UUID. This store records, on first authenticated login,
 * which offline UUID a BeaconAuth account owns, and keeps serving that identity afterwards so
 * existing world data is preserved without renaming files.
 *
 * The mapping is stored per-world in <world>/beaconauth-identities.json (alongside the player
 * data it references) and is meant for small community servers: an account keeps the offline
 * UUID it claimed on first login.
 */
object IdentityMapping {
    private val logger = LoggerFactory.getLogger("BeaconAuth/IdentityMapping")

    private data class FileShape(
        val version: Int = 1,
        val identities: Map<String, String> = emptyMap(),
        val owners: Map<String, String> = emptyMap(),
    )

    private val gson: Gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

    // subject -> offline uuid; guarded by [lock].
    private val identities = HashMap<String, UUID>()
    // offline uuid -> claiming subject; guarded by [lock]. Derived from [identities] when loading v1 files.
    private val owners = HashMap<UUID, String>()
    private val lock = ReentrantLock()
    private var mappingPath: Path? = null

    /**
     * Outcome of trying to claim a legacy offline identity for a BeaconAuth account.
     */
    sealed class Resolution {
        /** The subject already owns, or has just claimed, [uuid]. */
        data class Bound(val subject: String, val uuid: UUID) : Resolution()

        /** The offline UUID is already claimed by a different BeaconAuth account. */
        data class ClaimedByOther(val uuid: UUID, val claimedBy: String) : Resolution()
    }

    /**
     * Binds this server's world to [server]. Loads any existing mapping file.
     * Must be called on server start (server thread) before players log in.
     */
    fun attach(server: MinecraftServer) {
        val path = server.getWorldPath(LevelResource.ROOT).resolve("beaconauth-identities.json")
        lock.withLock {
            if (path == mappingPath) {
                return
            }
            mappingPath = path
            identities.clear()
            owners.clear()
            if (Files.isRegularFile(path)) {
                try {
                    Files.newBufferedReader(path).use { reader ->
                        val data = gson.fromJson(reader, FileShape::class.java)
                        if (data?.identities != null) {
                            for ((subject, uuidString) in data.identities) {
                                val uuid = try {
                                    UUID.fromString(uuidString)
                                } catch (e: IllegalArgumentException) {
                                    logger.warn("Ignoring invalid UUID '$uuidString' for subject '$subject' in $path")
                                    continue
                                }
                                identities[subject] = uuid
                            }
                            // Rebuild ownership index; explicit owners entries win over derived ones.
                            for ((subject, uuid) in identities) {
                                owners.putIfAbsent(uuid, subject)
                            }
                            for ((uuidString, subject) in data.owners.orEmpty()) {
                                val uuid = try {
                                    UUID.fromString(uuidString)
                                } catch (e: IllegalArgumentException) {
                                    logger.warn("Ignoring invalid owner UUID '$uuidString' in $path")
                                    continue
                                }
                                owners[uuid] = subject
                            }
                        }
                    }
                    logger.info("Loaded {} BeaconAuth identity mappings from {}", identities.size, path)
                } catch (e: Exception) {
                    logger.error("Failed to load BeaconAuth identity mappings from $path: ${e.message}")
                }
            } else {
                logger.info("No BeaconAuth identity mapping file at {}; a new one will be created on first login", path)
            }
        }
    }

    /**
     * Returns the offline UUID already mapped to [subject], or null when none is mapped yet.
     */
    fun lookup(subject: String): UUID? = lock.withLock { identities[subject] }

    /**
     * Returns the BeaconAuth subject that owns [uuid], or null when unclaimed.
     */
    fun ownerOf(uuid: UUID): String? = lock.withLock { owners[uuid] }

    /**
     * Atomically claims [offlineUuid] for [subject] unless it is already claimed by a different
     * account. Returns [Resolution.Bound] when [subject] already owns it or the claim succeeded,
     * or [Resolution.ClaimedByOther] when the offline identity is already owned elsewhere.
     */
    fun claim(subject: String, offlineUuid: UUID): Resolution {
        lock.withLock {
            val existing = identities[subject]
            if (existing != null) {
                return Resolution.Bound(subject, existing)
            }
            val currentOwner = owners[offlineUuid]
            if (currentOwner != null && currentOwner != subject) {
                return Resolution.ClaimedByOther(offlineUuid, currentOwner)
            }
            identities[subject] = offlineUuid
            owners[offlineUuid] = subject
            saveLocked()
            logger.info(
                "Mapped BeaconAuth subject $subject to legacy offline UUID $offlineUuid (world data preserved)"
            )
            return Resolution.Bound(subject, offlineUuid)
        }
    }

    /**
     * Deterministic offline-mode UUID as used by vanilla servers.
     */
    fun offlineUuidFor(name: String): UUID =
        UUID.nameUUIDFromBytes("OfflinePlayer:$name".toByteArray(Charsets.UTF_8))

    /**
     * Administrator-only rescue: transfers the offline identity [uuid] to the BeaconAuth account
     * whose username is [beaconUsername], so that account can log in with the preserved world data.
     * Returns true on success; false when the identity has no current owner, or when the target
     * account already owns a different identity (refuse to clobber it).
     */
    fun transferToUsername(uuid: UUID, beaconUsername: String): Boolean {
        lock.withLock {
            val oldOwner = owners[uuid] ?: return false
            val targetExisting = identities[beaconUsername]
            if (targetExisting != null && targetExisting != uuid) {
                logger.warn(
                    "Refusing to transfer legacy offline identity $uuid to $beaconUsername: " +
                        "that account is already mapped to $targetExisting"
                )
                return false
            }
            identities.remove(oldOwner)
            identities[beaconUsername] = uuid
            owners[uuid] = beaconUsername
            saveLocked()
            logger.info(
                "Transferred legacy offline identity $uuid from BeaconAuth account $oldOwner to $beaconUsername"
            )
            return true
        }
    }

    private fun saveLocked() {
        val path = mappingPath ?: return
        try {
            Files.createDirectories(path.parent)
            val data = FileShape(
                version = 1,
                identities = identities.mapValues { it.value.toString() },
                owners = owners.mapKeys { it.key.toString() },
            )
            Files.newBufferedWriter(path).use { writer ->
                gson.toJson(data, writer)
            }
        } catch (e: Exception) {
            logger.error("Failed to save BeaconAuth identity mappings to $path: ${e.message}")
        }
    }
}
