package io.github.summpot.beaconauth.config

/**
 * BeaconAuth configuration values used by common code.
 *
 * This object is version-agnostic and compiled into every Minecraft target.
 *
 * Platform modules (Fabric/Forge/NeoForge) are responsible for:
 *  - registering a config spec (ForgeConfigSpec / ModConfigSpec)
 *  - reading the loaded values
 *  - applying them here via [apply]
 */
object BeaconAuthConfig {
	// Defaults are development-friendly. Platform config should overwrite these on load.
	@Volatile private var authBaseUrl: String = "https://beaconauth.pages.dev"
	@Volatile private var jwksUrl: String = "https://beaconauth.pages.dev/.well-known/jwks.json"
	@Volatile private var oidcClientId: String = "beaconauth-mod"
	@Volatile private var tokenEndpoint: String = "https://beaconauth.pages.dev/api/v1/oidc/token"
	@Volatile private var jkuAllowedHostPatterns: Set<String> = emptySet()
	@Volatile private var bypassIfOnlineModeVerified: Boolean = true
	@Volatile private var forceAuthIfOfflineMode: Boolean = true
	@Volatile private var allowVanillaOfflineClients: Boolean = true
	@Volatile private var useLegacyOfflineUuids: Boolean = false
	@Volatile private var minecraftLookupSecret: String = ""
	@Volatile private var minecraftLinkSecret: String = ""
	@Volatile private var resolveLinkedPremiumLegacy: Boolean = true

	private fun normalizeBaseUrl(raw: String): String = raw.trim().trimEnd('/')

	private fun defaultJwksUrl(baseUrl: String): String = "${normalizeBaseUrl(baseUrl)}/.well-known/jwks.json"

	private fun defaultTokenEndpoint(baseUrl: String): String =
		"${normalizeBaseUrl(baseUrl)}/api/v1/oidc/token"

	private fun normalizeHostPatterns(csv: String): Set<String> {
		return csv
			.split(',', ' ', '\t', '\n', ';')
			.asSequence()
			.map { it.trim() }
			.filter { it.isNotEmpty() }
			.map { it.lowercase() }
			.toSet()
	}

    @JvmStatic
    fun apply(
        authBaseUrl: String,
        jwksUrl: String,
        oidcClientId: String,
        tokenEndpoint: String,
        jkuAllowedHostPatternsCsv: String,
        bypassIfOnlineModeVerified: Boolean,
        forceAuthIfOfflineMode: Boolean,
        allowVanillaOfflineClients: Boolean,
        useLegacyOfflineUuids: Boolean,
        minecraftLookupSecret: String = "",
        resolveLinkedPremiumLegacy: Boolean = true,
        minecraftLinkSecret: String = ""
    ) {
        val normalizedBaseUrl = normalizeBaseUrl(authBaseUrl)
        this.authBaseUrl = normalizedBaseUrl
        this.jwksUrl = jwksUrl.trim().ifEmpty { defaultJwksUrl(normalizedBaseUrl) }
        this.oidcClientId = oidcClientId.trim().ifEmpty { "beaconauth-mod" }
        this.tokenEndpoint = tokenEndpoint.trim().ifEmpty { defaultTokenEndpoint(normalizedBaseUrl) }
        this.jkuAllowedHostPatterns = normalizeHostPatterns(jkuAllowedHostPatternsCsv)
        this.bypassIfOnlineModeVerified = bypassIfOnlineModeVerified
        this.forceAuthIfOfflineMode = forceAuthIfOfflineMode
        this.allowVanillaOfflineClients = allowVanillaOfflineClients
        this.useLegacyOfflineUuids = useLegacyOfflineUuids
        this.minecraftLookupSecret = minecraftLookupSecret.trim()
        this.minecraftLinkSecret = if (minecraftLinkSecret.isNotBlank()) minecraftLinkSecret.trim() else this.minecraftLookupSecret
        this.resolveLinkedPremiumLegacy = resolveLinkedPremiumLegacy
    }

	fun getAuthBaseUrl(): String = authBaseUrl
	fun getJwksUrl(): String = jwksUrl
	fun getExpectedIssuer(): String = authBaseUrl
	fun getOidcClientId(): String = oidcClientId
	fun getTokenEndpoint(): String = tokenEndpoint
	fun getJkuAllowedHostPatterns(): Set<String> = jkuAllowedHostPatterns
	fun shouldBypassIfOnlineModeVerified(): Boolean = bypassIfOnlineModeVerified
	fun shouldForceAuthIfOfflineMode(): Boolean = forceAuthIfOfflineMode
	fun shouldAllowVanillaOfflineClients(): Boolean = allowVanillaOfflineClients
	fun shouldUseLegacyOfflineUuids(): Boolean = useLegacyOfflineUuids

	/** Secret used for signing in-game /beaconauth link tickets */
	fun getMinecraftLinkSecret(): String =
		if (minecraftLinkSecret.isNotBlank()) minecraftLinkSecret else minecraftLookupSecret

	/** Backwards-compatible alias for getMinecraftLinkSecret */
	fun getMinecraftLookupSecret(): String = getMinecraftLinkSecret()

	fun shouldResolveLinkedPremiumLegacy(): Boolean = resolveLinkedPremiumLegacy
}
