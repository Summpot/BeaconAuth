package io.github.summpot.beaconauth.server

import com.mojang.authlib.GameProfile
import net.minecraft.server.MinecraftServer
import net.minecraft.world.level.storage.LevelResource
import org.slf4j.LoggerFactory
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.util.Optional
import java.util.UUID

/**
 * Prevents BeaconAuth display names from colliding with official Minecraft players already known to this server.
 */
object OfficialNameGuard {
    private val logger = LoggerFactory.getLogger("BeaconAuth/OfficialNameGuard")

    fun findConflict(server: MinecraftServer, username: String, beaconAuthUuid: UUID?): GameProfile? {
        val requestedName = username.trim()
        if (requestedName.isEmpty()) {
            return null
        }

        val mojangProfile = lookupMojangProfile(server, requestedName)
        if (mojangProfile != null && isDifferentProfile(mojangProfile, beaconAuthUuid)) {
            if (hasServerRecordFor(server, mojangProfile)) {
                return mojangProfile
            }
            return null
        }

        return findLocalDifferentProfile(server, requestedName, beaconAuthUuid)
            ?.takeIf { isLikelyOfficialProfile(it, requestedName, beaconAuthUuid) && hasServerRecordFor(server, it) }
    }

    private fun hasServerRecordFor(server: MinecraftServer, profile: GameProfile): Boolean {
        val uuid = profile.id ?: return false
        val playerList = server.playerList

        if (playerList.getPlayer(uuid) != null || hasPlayerData(server, uuid)) {
            return true
        }

        val profileCache = server.profileCache
        if (profileCache != null && profileCache.get(uuid).isPresent) {
            return true
        }

        return playerList.whiteList.isWhiteListed(profile)
            || playerList.ops.get(profile) != null
            || playerList.bans.get(profile) != null
    }

    private fun hasPlayerData(server: MinecraftServer, uuid: UUID?): Boolean {
        if (uuid == null) {
            return false
        }

        val playerDataDir = server.getWorldPath(LevelResource.PLAYER_DATA_DIR)
        return Files.isRegularFile(playerDataDir.resolve("$uuid.dat"))
            || Files.isRegularFile(playerDataDir.resolve("$uuid.dat_old"))
    }

    private fun findLocalDifferentProfile(
        server: MinecraftServer,
        username: String,
        beaconAuthUuid: UUID?,
    ): GameProfile? {
        val profileCache = server.profileCache ?: return null
        return try {
            val loadMethod = profileCache.javaClass.methods.firstOrNull { it.name == "load" && it.parameterCount == 0 }
                ?: return null
            loadMethod.isAccessible = true
            val entries = loadMethod.invoke(profileCache) as? Iterable<*> ?: return null
            entries.asSequence()
                .mapNotNull { entry ->
                    val getProfile = entry?.javaClass?.methods?.firstOrNull {
                        it.name == "getProfile" && it.parameterCount == 0
                    }
                    getProfile?.isAccessible = true
                    getProfile?.invoke(entry) as? GameProfile
                }
                .firstOrNull { profile ->
                    profile.name?.equals(username, ignoreCase = true) == true && isDifferentProfile(profile, beaconAuthUuid)
                }
        } catch (e: Exception) {
            logger.debug("Unable to inspect local profile cache for '$username': ${e.message}")
            null
        }
    }

    private fun lookupMojangProfile(server: MinecraftServer, username: String): GameProfile? {
        val repository = server.profileRepository

        lookupWithFindProfileByName(repository, username)?.let { return it }
        return lookupWithLegacyCallback(repository, username)
    }

    private fun lookupWithFindProfileByName(repository: Any, username: String): GameProfile? {
        val method = repository.javaClass.methods.firstOrNull {
            it.name == "findProfileByName" &&
                it.parameterCount == 1 &&
                it.parameterTypes[0] == String::class.java
        } ?: return null

        return try {
            when (val result = method.invoke(repository, username)) {
                is Optional<*> -> result.orElse(null) as? GameProfile
                is GameProfile -> result
                else -> null
            }
        } catch (e: Exception) {
            logger.warn("Unable to look up official Minecraft profile for '$username': ${e.message}")
            null
        }
    }

    private fun lookupWithLegacyCallback(repository: Any, username: String): GameProfile? {
        return try {
            val agentClass = Class.forName("com.mojang.authlib.Agent")
            val callbackClass = Class.forName("com.mojang.authlib.ProfileLookupCallback")
            val minecraftAgent = agentClass.getField("MINECRAFT").get(null)
            val method = repository.javaClass.methods.firstOrNull {
                it.name == "findProfilesByNames" && it.parameterCount == 3
            } ?: return null

            var foundProfile: GameProfile? = null
            val callback = Proxy.newProxyInstance(
                callbackClass.classLoader,
                arrayOf(callbackClass),
            ) { _, invokedMethod, args ->
                if (invokedMethod.name == "onProfileLookupSucceeded") {
                    foundProfile = args?.getOrNull(0) as? GameProfile
                }
                null
            }

            method.invoke(repository, arrayOf(username), minecraftAgent, callback)
            foundProfile
        } catch (e: Exception) {
            logger.warn("Unable to look up official Minecraft profile for '$username': ${e.message}")
            null
        }
    }

    private fun isDifferentProfile(profile: GameProfile, beaconAuthUuid: UUID?): Boolean {
        val profileUuid = profile.id ?: return false
        return profileUuid != beaconAuthUuid
    }

    private fun isLikelyOfficialProfile(profile: GameProfile, username: String, beaconAuthUuid: UUID?): Boolean {
        val profileUuid = profile.id ?: return false
        return profileUuid.version() == 4 && profileUuid != beaconAuthUuid && profileUuid != offlineUuid(username)
    }

    private fun offlineUuid(username: String): UUID {
        return UUID.nameUUIDFromBytes("OfflinePlayer:$username".toByteArray(Charsets.UTF_8))
    }
}
