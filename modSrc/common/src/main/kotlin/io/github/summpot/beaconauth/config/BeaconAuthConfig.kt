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
	@Volatile private var expectedAudience: String = "minecraft-client"
	@Volatile private var jkuAllowedHostPatterns: Set<String> = emptySet()
	@Volatile private var bypassIfOnlineModeVerified: Boolean = true
	@Volatile private var forceAuthIfOfflineMode: Boolean = true
	@Volatile private var allowVanillaOfflineClients: Boolean = false

	private fun normalizeBaseUrl(raw: String): String = raw.trim().trimEnd('/')

	private fun defaultJwksUrl(baseUrl: String): String = "${normalizeBaseUrl(baseUrl)}/.well-known/jwks.json"

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
		expectedAudience: String,
		jkuAllowedHostPatternsCsv: String,
		bypassIfOnlineModeVerified: Boolean,
		forceAuthIfOfflineMode: Boolean,
		allowVanillaOfflineClients: Boolean
	) {
		val normalizedBaseUrl = normalizeBaseUrl(authBaseUrl)
		this.authBaseUrl = normalizedBaseUrl
		this.jwksUrl = jwksUrl.trim().ifEmpty { defaultJwksUrl(normalizedBaseUrl) }
		this.expectedAudience = expectedAudience
		this.jkuAllowedHostPatterns = normalizeHostPatterns(jkuAllowedHostPatternsCsv)
		this.bypassIfOnlineModeVerified = bypassIfOnlineModeVerified
		this.forceAuthIfOfflineMode = forceAuthIfOfflineMode
		this.allowVanillaOfflineClients = allowVanillaOfflineClients
	}

	fun getAuthBaseUrl(): String = authBaseUrl
	fun getJwksUrl(): String = jwksUrl
	fun getExpectedIssuer(): String = authBaseUrl
	fun getExpectedAudience(): String = expectedAudience
	fun getJkuAllowedHostPatterns(): Set<String> = jkuAllowedHostPatterns
	/**
	 * Dual-path switch for online-mode servers.
	 *
	 * When true (default):
	 * - Do not consume `handleHello`; let Mojang verification run.
	 * - Mojang success → post-PROBE allow-through for vanilla and for modded clients
	 *   (keep Mojang UUID; no BeaconAuth web login required).
	 * - Mojang failure → fall back to BeaconAuth for modded offline/community clients.
	 *
	 * When false:
	 * - Force-consume HELLO and require BeaconAuth for all online-mode logins.
	 */
	fun shouldBypassIfOnlineModeVerified(): Boolean = bypassIfOnlineModeVerified
	fun shouldForceAuthIfOfflineMode(): Boolean = forceAuthIfOfflineMode
	fun shouldAllowVanillaOfflineClients(): Boolean = allowVanillaOfflineClients
}
