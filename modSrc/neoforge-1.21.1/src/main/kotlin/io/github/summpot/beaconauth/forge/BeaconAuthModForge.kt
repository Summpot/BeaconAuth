package io.github.summpot.beaconauth.neoforge

import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.config.MigrationConfig
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
    private val expectedAudience: ModConfigSpec.ConfigValue<String>
    private val jkuAllowedHostPatterns: ModConfigSpec.ConfigValue<String>
    private val bypassIfOnlineModeVerified: ModConfigSpec.BooleanValue
    private val forceAuthIfOfflineMode: ModConfigSpec.BooleanValue
    private val allowVanillaOfflineClients: ModConfigSpec.BooleanValue
    private val migrationEnabled: ModConfigSpec.BooleanValue
    private val migrationPromptMode: ModConfigSpec.ConfigValue<String>
    private val migrationPromptOnJoin: ModConfigSpec.BooleanValue
    private val migrationPromptInterval: ModConfigSpec.IntValue
    private val migrationForceAuthAfter: ModConfigSpec.ConfigValue<String>
    private val migrationPlayerdataClaim: ModConfigSpec.ConfigValue<String>
    private val migrationClaimNameSource: ModConfigSpec.ConfigValue<String>
    private val migrationOnlyIfTargetEmpty: ModConfigSpec.BooleanValue
    private val migrationKeepLegacyBackup: ModConfigSpec.BooleanValue
    private val migrationDryRun: ModConfigSpec.BooleanValue
    private val migrationAutoForPremium: ModConfigSpec.BooleanValue

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

        expectedAudience = builder
            .comment(
                "Expected JWT audience (aud claim)",
                "This must match the 'aud' claim in the JWT token"
            )
            .define("audience", "minecraft-client")

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
            .define("allow_vanilla_offline_clients", false)

        builder.pop()

        builder.comment(
            "Offline -> BeaconAuth Identity Migration",
            "Helps migrate an offline-mode server's existing players to BeaconAuth by",
            "claiming their legacy OfflinePlayer:<name> playerdata when they log in.",
            "Read the docs before enabling; claims are first-claim-wins and cannot be safely reversed after the player has played.",
            "All defaults are OFF/disabled so existing servers see no behavior change."
        ).push("migration")

        migrationEnabled = builder
            .comment(
                "Master switch for the migration feature (prompts + claims).",
                "When false, all migration behavior is disabled regardless of the other options below."
            )
            .define("enabled", false)

        migrationPromptMode = builder
            .comment(
                "Prompt mode for unauthenticated players: off | soft | force_after_date",
                "soft: prompt players to register / install the mod periodically.",
                "force_after_date: like soft, but after force_auth_after the server behaves as if force_auth_if_offline_mode=true.",
                "off: no prompts."
            )
            .define("prompt_mode", "off")

        migrationPromptOnJoin = builder
            .comment("Show the migration prompt when a player joins the server.")
            .define("prompt_on_join", true)

        migrationPromptInterval = builder
            .comment("Minimum minutes between repeated soft prompts to the same player.")
            .defineInRange("prompt_interval_minutes", 30, 1, 1440)

        migrationForceAuthAfter = builder
            .comment(
                "ISO-8601 instant (e.g. 2026-09-01T00:00:00Z) after which force_auth_if_offline_mode becomes effective.",
                "Empty means never auto-escalate. Only used when prompt_mode = force_after_date."
            )
            .define("force_auth_after", "")

        migrationPlayerdataClaim = builder
            .comment(
                "When and how to claim legacy offline playerdata on login: off | auto | confirm",
                "off: never claim.",
                "auto: claim immediately on successful login (first-claim-wins).",
                "confirm: stage the claim and prompt the player to run /beaconauth migration accept."
            )
            .define("playerdata_claim", "off")

        migrationClaimNameSource = builder
            .comment(
                "Which username to match the legacy OfflinePlayer:<name> data against:",
                "beacon_username (default) | launcher_username | either"
            )
            .define("claim_name_source", "beacon_username")

        migrationOnlyIfTargetEmpty = builder
            .comment(
                "Only claim when the target UUID has no existing playerdata.",
                "Recommended true to avoid overwriting a new account's progress."
            )
            .define("only_if_target_empty", true)

        migrationKeepLegacyBackup = builder
            .comment(
                "Keep a backup copy of the migrated source files (renamed to .migrated) and store copies under beaconauth-migration-backups/.",
                "Recommended true so claims can be undone."
            )
            .define("keep_legacy_backup", true)

        migrationDryRun = builder
            .comment(
                "Report what WOULD be migrated without changing any files.",
                "Use to audit before enabling real claims."
            )
            .define("dry_run", false)

        migrationAutoForPremium = builder
            .comment(
                "Allow auto-claiming legacy offline data for premium players that bypass BeaconAuth (online-mode bypass path).",
                "Only applies when playerdata_claim = auto. confirm-mode claims are not possible for vanilla premium clients (no mod UI)."
            )
            .define("auto_for_premium", false)

        builder.pop()
    }

    fun applyToCommon() {
        BeaconAuthConfig.apply(
            authBaseUrl.get(),
            jwksUrl.get(),
            expectedAudience.get(),
            jkuAllowedHostPatterns.get(),
            bypassIfOnlineModeVerified.getAsBoolean(),
            forceAuthIfOfflineMode.getAsBoolean(),
            allowVanillaOfflineClients.getAsBoolean()
        )
        MigrationConfig.apply(
            migrationEnabled.getAsBoolean(),
            migrationPromptMode.get(),
            migrationPromptOnJoin.getAsBoolean(),
            migrationPromptInterval.getAsInt(),
            migrationForceAuthAfter.get(),
            migrationPlayerdataClaim.get(),
            migrationClaimNameSource.get(),
            migrationOnlyIfTargetEmpty.getAsBoolean(),
            migrationKeepLegacyBackup.getAsBoolean(),
            migrationDryRun.getAsBoolean(),
            migrationAutoForPremium.getAsBoolean()
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
