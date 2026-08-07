package io.github.summpot.beaconauth.server

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

/**
 * Result of the mod→auth-server `/api/v1/minecraft/lookup` query for a Mojang-verified UUID.
 *
 * @property bound whether the Mojang UUID is bound to a BeaconAuth account
 * @property identityMode the user's effective identity preference: "mojang" | "legacy" | null
 * @property texturesValue Mojang-signed `textures` property value, when cached
 * @property texturesSignature Mojang-signed `textures` property signature, when cached
 */
data class MinecraftLookupResult(
    val bound: Boolean,
    val identityMode: String?,
    val userSubject: String?,
    val texturesValue: String?,
    val texturesSignature: String?,
) {
    /** Whether the linked premium player should be mapped to the legacy offline UUID. */
    val useLegacyIdentity: Boolean
        get() = bound && identityMode == "legacy"
}

/**
 * Queries the BeaconAuth auth server for the identity binding of a Mojang-verified UUID.
 *
 * Used by the online-mode bypass path: when a premium player (verified by Mojang `hasJoined`)
 * is bound to a BeaconAuth account whose identity preference is "legacy", the mod maps the
 * player to the account's legacy offline UUID so world data from a migrated offline-mode
 * server is preserved, and replays the cached Mojang textures for a real skin.
 *
 * The lookup is authenticated with a shared secret (config `minecraft_lookup_secret`), so only
 * servers the operator trusts can query bindings. When no secret is configured, the lookup is
 * disabled and the premium player keeps the Mojang UUID (vanilla behavior).
 */
object MinecraftLookup {
    private val logger = LoggerFactory.getLogger("BeaconAuth/MinecraftLookup")

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    /** Empty = lookup disabled (no shared secret configured). */
    private fun lookupUrl(mojangUuid: String): String? {
        val secret = BeaconAuthConfig.getMinecraftLookupSecret()
        if (secret.isEmpty()) {
            return null
        }
        val base = BeaconAuthConfig.getAuthBaseUrl().trimEnd('/')
        return "$base/api/v1/minecraft/lookup?uuid=" +
            URLEncoder.encode(mojangUuid, StandardCharsets.UTF_8.name())
    }

    /**
     * Start an asynchronous lookup for [mojangUuid]. Returns null when the lookup is disabled
     * (no shared secret configured) or the request could not be started. The result is delivered
     * into [resultRef] when the HTTP response arrives (off the server thread).
     */
    fun lookupAsync(
        mojangUuid: UUID,
        resultRef: AtomicReference<MinecraftLookupResult?>,
    ): Boolean {
        val url = lookupUrl(mojangUuid.toString()) ?: return false
        val secret = BeaconAuthConfig.getMinecraftLookupSecret()

        val request = try {
            HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .header("X-Minecraft-Auth", secret)
                .GET()
                .build()
        } catch (e: Exception) {
            logger.warn("Failed to build Minecraft lookup request: ${e.message}")
            return false
        }

        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .whenComplete { response, throwable ->
                val result = parseResponse(response, throwable)
                if (result != null) {
                    resultRef.set(result)
                } else {
                    // Failed lookups resolve as "not bound" so the premium player keeps the
                    // Mojang UUID; never block login on lookup errors.
                    resultRef.set(MinecraftLookupResult(false, null, null, null, null))
                }
            }
        return true
    }

    private fun parseResponse(
        response: HttpResponse<String>?,
        throwable: Throwable?,
    ): MinecraftLookupResult? {
        if (throwable != null) {
            logger.warn("Minecraft lookup request failed: ${throwable.message}")
            return null
        }
        if (response == null) {
            return null
        }
        if (response.statusCode() != 200) {
            logger.warn("Minecraft lookup returned HTTP ${response.statusCode()}")
            return null
        }
        return try {
            val root: JsonObject = JsonParser.parseString(response.body()).asJsonObject
            val bound = root.get("bound")?.asBoolean ?: false
            val identityMode = root.get("identity_mode")?.takeIf { !it.isJsonNull }?.asString
            val userSubject = root.get("user_subject")?.takeIf { !it.isJsonNull }?.asString
            val texturesValue = root.get("textures_value")?.takeIf { !it.isJsonNull }?.asString
            val texturesSignature = root.get("textures_signature")?.takeIf { !it.isJsonNull }?.asString
            MinecraftLookupResult(bound, identityMode, userSubject, texturesValue, texturesSignature)
        } catch (e: Exception) {
            logger.warn("Failed to parse Minecraft lookup response: ${e.message}")
            null
        }
    }
}
