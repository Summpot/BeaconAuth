package io.github.summpot.beaconauth.forge

import dev.architectury.platform.forge.EventBuses
import io.github.summpot.beaconauth.BeaconAuthMod
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.config.MigrationConfig
import net.minecraftforge.common.ForgeConfigSpec
import net.minecraftforge.api.distmarker.Dist
import net.minecraftforge.fml.common.Mod
import net.minecraftforge.fml.event.config.ModConfigEvent
import net.minecraftforge.fml.loading.FMLEnvironment
import net.minecraftforge.fml.ModLoadingContext
import net.minecraftforge.fml.config.ModConfig
import thedarkcolour.kotlinforforge.forge.MOD_BUS
import thedarkcolour.kotlinforforge.forge.MOD_CONTEXT

@Mod(BeaconAuthMod.MOD_ID)
object BeaconAuthModForge {
    private var serverInitialized = false

    init {
        // Submit our event bus to let Architectury API register our content on the right time.
        EventBuses.registerModEventBus(BeaconAuthMod.MOD_ID, MOD_CONTEXT.getKEventBus())
        
        // Register configuration
        ModLoadingContext.get().registerConfig(ModConfig.Type.SERVER, BeaconAuthServerConfig.spec)

        // Run common setup (network packet registration)
        BeaconAuthMod.init()

        // Listen for config loading and reloading events
        MOD_BUS.addListener(::onConfigLoading)
        MOD_BUS.addListener(::onConfigReloading)

        // Initialize client-side immediately (doesn't need config)
        if (FMLEnvironment.dist == Dist.CLIENT) {
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

private object BeaconAuthServerConfig {
    private val authBaseUrl: ForgeConfigSpec.ConfigValue<String>
    private val jwksUrl: ForgeConfigSpec.ConfigValue<String>
    private val expectedAudience: ForgeConfigSpec.ConfigValue<String>
    private val jkuAllowedHostPatterns: ForgeConfigSpec.ConfigValue<String>
    private val bypassIfOnlineModeVerified: ForgeConfigSpec.BooleanValue
    private val forceAuthIfOfflineMode: ForgeConfigSpec.BooleanValue
    private val allowVanillaOfflineClients: ForgeConfigSpec.BooleanValue
    private val migrationEnabled: ForgeConfigSpec.BooleanValue
    private val migrationPromptMode: ForgeConfigSpec.ConfigValue<String>
    private val migrationPromptOnJoin: ForgeConfigSpec.BooleanValue
    private val migrationPromptInterval: ForgeConfigSpec.IntValue
    private val migrationForceAuthAfter: ForgeConfigSpec.ConfigValue<String>
    private val migrationPlayerdataClaim: ForgeConfigSpec.ConfigValue<String>
    private val migrationClaimNameSource: ForgeConfigSpec.ConfigValue<String>
    private val migrationOnlyIfTargetEmpty: ForgeConfigSpec.BooleanValue
    private val migrationKeepLegacyBackup: ForgeConfigSpec.BooleanValue
    private val migrationDryRun: ForgeConfigSpec.BooleanValue
    private val migrationAutoForPremium: ForgeConfigSpec.BooleanValue

    val spec: ForgeConfigSpec

    init {
        val builder = ForgeConfigSpec.Builder()

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
            .comment("Master switch for the migration feature (prompts + claims).")
            .define("enabled", false)

        migrationPromptMode = builder
            .comment("Prompt mode: off | soft | force_after_date")
            .define("prompt_mode", "off")

        migrationPromptOnJoin = builder
            .comment("Show the migration prompt when a player joins the server.")
            .define("prompt_on_join", true)

        migrationPromptInterval = builder
            .comment("Minimum minutes between repeated soft prompts to the same player.")
            .defineInRange("prompt_interval_minutes", 30, 1, 1440)

        migrationForceAuthAfter = builder
            .comment("ISO-8601 instant after which force_auth_if_offline_mode becomes effective. Empty = never.")
            .define("force_auth_after", "")

        migrationPlayerdataClaim = builder
            .comment("off | auto | confirm")
            .define("playerdata_claim", "off")

        migrationClaimNameSource = builder
            .comment("beacon_username | launcher_username | either")
            .define("claim_name_source", "beacon_username")

        migrationOnlyIfTargetEmpty = builder
            .comment("Only claim when the target UUID has no existing playerdata.")
            .define("only_if_target_empty", true)

        migrationKeepLegacyBackup = builder
            .comment("Keep a backup copy of migrated source files so claims can be undone.")
            .define("keep_legacy_backup", true)

        migrationDryRun = builder
            .comment("Report what WOULD be migrated without changing files.")
            .define("dry_run", false)

        migrationAutoForPremium = builder
            .comment("Allow auto-claiming for premium bypass players (auto mode only).")
            .define("auto_for_premium", false)

        builder.pop()

        spec = builder.build()
    }

    fun applyToCommon() {
        BeaconAuthConfig.apply(
            authBaseUrl.get(),
            jwksUrl.get(),
            expectedAudience.get(),
            jkuAllowedHostPatterns.get(),
            bypassIfOnlineModeVerified.get(),
            forceAuthIfOfflineMode.get(),
            allowVanillaOfflineClients.get()
        )
        MigrationConfig.apply(
            migrationEnabled.get(),
            migrationPromptMode.get(),
            migrationPromptOnJoin.get(),
            migrationPromptInterval.get(),
            migrationForceAuthAfter.get(),
            migrationPlayerdataClaim.get(),
            migrationClaimNameSource.get(),
            migrationOnlyIfTargetEmpty.get(),
            migrationKeepLegacyBackup.get(),
            migrationDryRun.get(),
            migrationAutoForPremium.get()
        )
    }
}
