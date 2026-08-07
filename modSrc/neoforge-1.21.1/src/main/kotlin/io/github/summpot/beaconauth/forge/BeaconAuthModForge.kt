package io.github.summpot.beaconauth.neoforge

import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import net.neoforged.api.distmarker.Dist
import net.neoforged.bus.api.IEventBus
import net.neoforged.fml.ModContainer
import net.neoforged.fml.common.Mod
import net.neoforged.fml.config.ModConfig
import net.neoforged.fml.event.config.ModConfigEvent
import net.neoforged.neoforge.common.ModConfigSpec

@Mod(BeaconAuthMod.MOD_ID)
class BeaconAuthModNeoForge(
    private val modEventBus: IEventBus,
    private val dist: Dist,
    private val container: ModContainer
) {
    private var serverInitialized = false

    init {
        // Register configuration (SERVER config loads during world loading)
        container.registerConfig(ModConfig.Type.SERVER, BeaconAuthServerConfig.SPEC)

        // Run common setup (network packet registration)
        BeaconAuthMod.init()

        // Listen for config loading and reloading events.
        // NeoForge configs are not immediately available upon registration.
        modEventBus.addListener(this::onConfigLoading)
        modEventBus.addListener(this::onConfigReloading)

        // Initialize client-side immediately (doesn't need config)
        if (dist == Dist.CLIENT) {
            BeaconAuthMod.initClient()
        }
    }

    private fun onConfigLoading(event: ModConfigEvent.Loading) {
        // Only initialize when our SERVER config is loaded
        if (event.config.modId == BeaconAuthMod.MOD_ID &&
            event.config.type == ModConfig.Type.SERVER &&
            !serverInitialized) {
            BeaconAuthServerConfig.applyToCommon()
            serverInitialized = true
            BeaconAuthMod.initServer()
        }
    }

    private fun onConfigReloading(event: ModConfigEvent.Reloading) {
        // If server config is reloaded and server was already initialized, reinitialize
        if (event.config.modId == BeaconAuthMod.MOD_ID &&
            event.config.type == ModConfig.Type.SERVER &&
            serverInitialized) {
            BeaconAuthServerConfig.applyToCommon()
            BeaconAuthMod.initServer()
        }
    }
}

private class BeaconAuthServerConfig(builder: ModConfigSpec.Builder) {
    private val authBaseUrl: ModConfigSpec.ConfigValue<String>
    private val jwksUrl: ModConfigSpec.ConfigValue<String>
    private val oidcClientId: ModConfigSpec.ConfigValue<String>
    private val tokenEndpoint: ModConfigSpec.ConfigValue<String>
    private val jkuAllowedHostPatterns: ModConfigSpec.ConfigValue<String>
    private val bypassIfOnlineModeVerified: ModConfigSpec.BooleanValue
    private val forceAuthIfOfflineMode: ModConfigSpec.BooleanValue
    private val allowVanillaOfflineClients: ModConfigSpec.BooleanValue
    private val useLegacyOfflineUuids: ModConfigSpec.BooleanValue
    private val minecraftLookupSecret: ModConfigSpec.ConfigValue<String>
    private val resolveLinkedPremiumLegacy: ModConfigSpec.BooleanValue

    init {
        builder.comment(
            "BeaconAuth Server Configuration",
            "",
            "IMPORTANT: Configure these values to match your authentication server!",
            "The default values point to https://beaconauth.pages.dev."
        ).push("authentication")

        authBaseUrl = builder
            .comment(
                "Base URL of your authentication server",
                "Example: https://beaconauth.pages.dev (development) or https://auth.example.com (production)",
                "WARNING: Always use HTTPS in production!"
            )
            .define("base_url", "https://beaconauth.pages.dev")

        jwksUrl = builder
            .comment(
                "JWKS (JSON Web Key Set) URL for JWT signature verification",
                "This endpoint must provide the public keys used to sign JWTs",
                "Usually: <base_url>/.well-known/jwks.json"
            )
            .define("jwks_url", "")

        builder.pop()

        builder.comment(
            "JWT Token Validation Settings",
            "These values must match your authentication server's configuration"
        ).push("jwt")

        oidcClientId = builder
            .comment(
                "OIDC client_id used for the authorization-code flow",
                "Must match the server's registered public client for the Minecraft mod",
                "The client is public (no secret): PKCE is the only proof of possession"
            )
            .define("oidc_client_id", "beaconauth-mod")

        tokenEndpoint = builder
            .comment(
                "OIDC token endpoint for the authorization-code exchange",
                "Usually: <base_url>/api/v1/oidc/token",
                "Leave empty to derive from base_url"
            )
            .define("token_endpoint", "")

        builder.pop()

        builder.comment(
            "JWT JWKS Discovery (JKU)",
            "If allowed_host_patterns is non-empty and the JWT has a 'jku' header, BeaconAuth will fetch keys from that JWKS URL.",
            "Security: You MUST restrict allowed hosts to avoid SSRF.",
            "When enabled, JKU ALWAYS requires https://.",
            "If JKU is disabled, BeaconAuth ignores token 'jku' and falls back to authentication.jwks_url (which defaults to <base_url>/.well-known/jwks.json)."
        ).push("jku")

        jkuAllowedHostPatterns = builder
            .comment(
                "Comma/space-separated allowed host patterns for token 'jku' host matching",
                "Supported: example.com, *.example.com (both allow subdomains)",
                "Not supported: bare '*' or mid-string wildcards (auth*.example.com)",
                "Empty means: JKU disabled"
            )
            .define("allowed_host_patterns", "")

        builder.pop()

        builder.comment(
            "Authentication Behavior Settings",
            "Configure how BeaconAuth interacts with Minecraft's authentication system"
        ).push("behavior")

        bypassIfOnlineModeVerified = builder
            .comment(
                "Online-mode: allow premium players without BeaconAuth web login (recommended true)",
                "If true: premium keep Mojang UUID (including vanilla); offline+mod can still use BeaconAuth",
                "If false: every player must use BeaconAuth (vanilla without the mod is rejected)",
                "Recommended: true"
            )
            .define("bypass_if_online_mode_verified", true)

        forceAuthIfOfflineMode = builder
            .comment(
                "Force BeaconAuth for modded clients when server is in offline-mode",
                "Recommended: true"
            )
            .define("force_auth_if_offline_mode", true)

        allowVanillaOfflineClients = builder
            .comment(
                "Allow vanilla clients (without BeaconAuth mod) in offline-mode",
                "Only applies when force_auth_if_offline_mode is true"
            )
            .define("allow_vanilla_offline_clients", true)

        useLegacyOfflineUuids = builder
            .comment(
                "Legacy offline identity mode (for migrating existing offline-mode servers)",
                "If true: each BeaconAuth account is mapped to the offline-mode UUID it claimed on first login",
                "World data (playerdata/stats/advancements) is preserved without renaming files",
                "Mapping is stored per-world in <world>/beaconauth-identities.json",
                "Security: the identity is bound to the username used on first login (small servers only)",
                "Recommended: false"
            )
            .define("use_legacy_offline_uuids", false)
        minecraftLookupSecret = builder
            .comment(
                "Shared secret for the auth server's /api/v1/minecraft/lookup endpoint",
                "Enables mapping Mojang-verified (premium) players bound to a BeaconAuth account",
                "with a 'legacy' identity preference back to their legacy offline UUID on online-mode bypass.",
                "Leave empty to disable (premium players keep the Mojang UUID).",
                "Recommended: empty, unless migrating an offline-mode server and premium bound players should preserve world data."
            )
            .define("minecraft_lookup_secret", "")

        resolveLinkedPremiumLegacy = builder
            .comment(
                "Resolve linked premium players to their legacy offline identity on online-mode bypass",
                "Only meaningful when minecraft_lookup_secret is set and the BeaconAuth account has identity mode 'legacy'.",
                "When true: the player is mapped to their legacy offline UUID and receives their real skin.",
                "Recommended: true"
            )
            .define("resolve_linked_premium_legacy", true)

        builder.pop()
    }

    fun applyToCommon() {
        BeaconAuthConfig.apply(
            authBaseUrl.get(),
            jwksUrl.get(),
            oidcClientId.get(),
            tokenEndpoint.get(),
            jkuAllowedHostPatterns.get(),
            bypassIfOnlineModeVerified.getAsBoolean(),
            forceAuthIfOfflineMode.getAsBoolean(),
            allowVanillaOfflineClients.getAsBoolean(),
            useLegacyOfflineUuids.getAsBoolean(),
            minecraftLookupSecret.get(),
            resolveLinkedPremiumLegacy.getAsBoolean()
        )
    }

    companion object {
        val SPEC: ModConfigSpec
        private val INSTANCE: BeaconAuthServerConfig

        init {
            val specPair = ModConfigSpec.Builder().configure(::BeaconAuthServerConfig)
            SPEC = specPair.right
            INSTANCE = specPair.left
        }

        fun applyToCommon() {
            INSTANCE.applyToCommon()
        }
    }
}
