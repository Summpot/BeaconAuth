package io.github.summpot.beaconauth.server

import com.google.gson.Gson
import com.google.gson.JsonParser
import com.mojang.authlib.properties.Property
import org.slf4j.LoggerFactory
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Caches official Mojang textures properties (skin/cape + RSA signatures)
 * retrieved from Mojang's public Session Server.
 *
 * Public endpoint: GET https://sessionserver.mojang.com/session/minecraft/profile/<uuid>?unsigned=false
 * No authentication or API keys required.
 */
object MojangProfileCache {
    private val logger = LoggerFactory.getLogger("BeaconAuth/MojangProfileCache")
    private val gson = Gson()
    private val executor = Executors.newFixedThreadPool(2) { r ->
        Thread(r, "BeaconAuth-MojangProfileCache").apply { isDaemon = true }
    }

    private data class CacheEntry(val property: Property, val timestamp: Long)

    private val cache = ConcurrentHashMap<UUID, CacheEntry>()
    private const val CACHE_TTL_MS = 12 * 60 * 60 * 1000L // 12 hours

    /**
     * Put verified Mojang textures into cache (e.g. from a successful online-mode login).
     */
    fun put(uuid: UUID, property: Property) {
        cache[uuid] = CacheEntry(property, System.currentTimeMillis())
    }

    /**
     * Get cached textures property for [uuid]. Returns null if not cached or expired.
     * When expired or missing, triggers a background refresh.
     */
    fun get(uuid: UUID): Property? {
        val entry = cache[uuid]
        val now = System.currentTimeMillis()
        if (entry != null && (now - entry.timestamp) < CACHE_TTL_MS) {
            return entry.property
        }

        // Trigger background fetch if missing or expired
        asyncFetch(uuid)
        return entry?.property
    }

    /**
     * Synchronously fetch textures for [uuid] if not cached, waiting up to [timeoutMs].
     */
    fun getOrFetch(uuid: UUID, timeoutMs: Int = 3000): Property? {
        val entry = cache[uuid]
        val now = System.currentTimeMillis()
        if (entry != null && (now - entry.timestamp) < CACHE_TTL_MS) {
            return entry.property
        }

        return try {
            val future = executor.submit<Property?> {
                fetchDirect(uuid)
            }
            future.get(timeoutMs.toLong(), java.util.concurrent.TimeUnit.MILLISECONDS) ?: entry?.property
        } catch (_: Exception) {
            entry?.property
        }
    }

    private fun asyncFetch(uuid: UUID) {
        executor.submit {
            try {
                fetchDirect(uuid)
            } catch (e: Exception) {
                logger.debug("Background fetch failed for Mojang profile {}: {}", uuid, e.message)
            }
        }
    }

    private fun fetchDirect(uuid: UUID): Property? {
        val uuidNoDashes = uuid.toString().replace("-", "")
        val url = URL("https://sessionserver.mojang.com/session/minecraft/profile/$uuidNoDashes?unsigned=false")
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = 3000
        conn.readTimeout = 3000
        conn.requestMethod = "GET"
        conn.setRequestProperty("User-Agent", "BeaconAuth-Mod")

        if (conn.responseCode != 200) {
            logger.debug("Mojang session server returned HTTP {} for {}", conn.responseCode, uuid)
            return null
        }

        val json = conn.inputStream.bufferedReader().use { it.readText() }
        val root = JsonParser.parseString(json).asJsonObject
        val properties = root.getAsJsonArray("properties") ?: return null

        for (elem in properties) {
            val propObj = elem.asJsonObject
            val name = propObj.get("name")?.asString
            if (name == "textures") {
                val value = propObj.get("value")?.asString ?: continue
                val signature = propObj.get("signature")?.asString
                val property = Property("textures", value, signature)
                cache[uuid] = CacheEntry(property, System.currentTimeMillis())
                logger.info("Cached Mojang textures property for {}", uuid)
                return property
            }
        }
        return null
    }
}
