package io.github.summpot.beaconauth.server

import com.mojang.authlib.GameProfile
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.login.LoginQueryType
import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.login.ServerLoginNegotiation
import io.github.summpot.beaconauth.server.migration.MigrationManager
import io.netty.buffer.Unpooled
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.chat.Component
import net.minecraft.network.protocol.cookie.ClientboundCookieRequestPacket
import net.minecraft.resources.ResourceLocation
import net.minecraft.server.MinecraftServer
import org.slf4j.LoggerFactory

/**
 * Kotlin helper for server-side login-phase custom query negotiation.
 * Called by ServerLoginPacketListenerImplMixin (Java).
 */
class ServerLoginHandler @JvmOverloads constructor(
    private val server: MinecraftServer,
    private val connection: Connection,
    private var gameProfile: GameProfile?,
    private val disconnectCallback: (Component) -> Unit,
    private val finishCallback: () -> Unit,
    /**
     * True if BeaconAuth intercepted HELLO on an online-mode server and routed login to BeaconAuth negotiation.
     * In that case, the profile UUID may be a placeholder and MUST NOT be treated as Mojang-verified.
     */
    private val helloWasIntercepted: Boolean = false,
) {
    companion object {
        private val logger = LoggerFactory.getLogger("BeaconAuth/ServerLogin")
        const val NEGOTIATION_TIMEOUT_TICKS = 20 * 90 // 90 seconds
    }

    private fun sanitizeMinecraftUsername(raw: String?): String? {
        val s = raw?.trim() ?: return null
        if (s.length !in 3..16) {
            return null
        }
        // Vanilla usernames are limited to [A-Za-z0-9_] and 3..16 chars.
        if (!s.all { it.isLetterOrDigit() || it == '_' }) {
            return null
        }
        return s
    }

    private val negotiation = ServerLoginNegotiation()

    /**
     * Expose the current GameProfile (potentially updated with a stable UUID) back to the mixin.
     */
    val currentGameProfile: GameProfile?
        get() = gameProfile

    fun tick() {
        negotiation.incrementTick()
        if (negotiation.ticks > NEGOTIATION_TIMEOUT_TICKS) {
            fail(Component.translatable("disconnect.beaconauth.timeout"))
        }
    }

    fun start() {
        if (gameProfile == null) {
            logger.warn("Cannot start negotiation: gameProfile is null")
            return
        }
        logger.info("Starting login-phase negotiation for ${gameProfile?.name}")
        negotiation.resetTick()
        sendRequest(LoginQueryType.PROBE)
    }

    fun handleCookieResponse(key: ResourceLocation, payload: ByteArray?): Boolean {
        val type = negotiation.consume(key) ?: return false
        // Vanilla clients may reply to unknown cookie requests with a null payload.
        // Treat null/empty payload as "not modded" for PROBE, and as invalid for INIT/VERIFY.
        val data = if (payload == null || payload.isEmpty()) {
            null
        } else {
            FriendlyByteBuf(Unpooled.wrappedBuffer(payload))
        }
        when (type) {
            LoginQueryType.PROBE -> handleProbeResponse(data)
            LoginQueryType.INIT -> handleInitResponse(data)
            LoginQueryType.VERIFY -> handleVerifyResponse(data)
            LoginQueryType.LOGIN_URL -> {
                // LOGIN_URL is not used on 1.21.x because cookie requests are request-only.
                // Client computes the URL locally after INIT.
                logger.debug("Ignoring LOGIN_URL cookie response (unused on 1.21.x)")
            }
        }
        return true
    }

    private fun handleProbeResponse(data: FriendlyByteBuf?) {
        val modded = data?.readBoolean() ?: false
        negotiation.markModded(modded)
        logger.info("Client modded status: $modded")

        val onlineMode = server.usesAuthentication()
        logger.info("Server online-mode: $onlineMode")
        
        if (!modded) {
            // On online-mode servers: only allow vanilla clients if they already passed Mojang verification.
            // If we intercepted handleHello, the UUID is only a placeholder; allowing vanilla would effectively downgrade
            // online-mode to offline-mode, which is unsafe.
            val hasMojangVerifiedUUID = !helloWasIntercepted && gameProfile?.id != null
            val allowVanilla = if (onlineMode) {
                hasMojangVerifiedUUID
            } else {
                BeaconAuthConfig.shouldAllowVanillaOfflineClients()
            }

            if (allowVanilla) {
                logger.info("Vanilla client allowed; finishing negotiation")
                // Vanilla premium client: also attempt auto-claim to the Mojang UUID.
                val vanillaTarget = gameProfile?.id
                if (vanillaTarget != null) {
                    try {
                        MigrationManager.evaluateLogin(server, vanillaTarget, null, gameProfile?.name)
                    } catch (e: Exception) {
                        logger.warn("Migration evaluation failed for vanilla ${gameProfile?.name}: ${e.message}", e)
                    }
                }
                finish()
            } else {
                logger.warn("Vanilla client rejected (mod required)")
                fail(Component.translatable("disconnect.beaconauth.mod_required"))
            }
            return
        }

        // Post-PROBE allow-through:
        // - Online-mode dual-path: Mojang already succeeded (helloWasIntercepted=false) →
        //   allow-through keeps Mojang UUID (vanilla or modded+bypass).
        // - Online-mode fallback / force path: helloWasIntercepted=true (placeholder UUID) →
        //   must complete BeaconAuth web flow.
        // - Offline-mode: allow existing session only when force_auth_if_offline_mode is false.
        val hasMojangVerifiedUUID = !helloWasIntercepted && gameProfile?.id != null

        val bypassOnlineMode = onlineMode && BeaconAuthConfig.shouldBypassIfOnlineModeVerified() && hasMojangVerifiedUUID
        val bypassOfflineMode = !onlineMode && !BeaconAuthConfig.shouldForceAuthIfOfflineMode()
        val bypass = bypassOnlineMode || bypassOfflineMode

        logger.info(
            "Existing session check: allowOnlineModeSession=$bypassOnlineMode, allowOfflineModeSession=$bypassOfflineMode, " +
                "finalAllow=$bypass, hasMojangUUID=$hasMojangVerifiedUUID, helloWasIntercepted=$helloWasIntercepted"
        )
        logger.info(
            "Config values: bypass_if_online_mode_verified=${BeaconAuthConfig.shouldBypassIfOnlineModeVerified()}, " +
                "force_auth_if_offline_mode=${BeaconAuthConfig.shouldForceAuthIfOfflineMode()}"
        )

        if (bypass) {
            logger.info("Existing session allowed (post-PROBE allow-through); finishing negotiation")
            // Premium-bypass path: attempt to claim legacy offline data to the Mojang UUID.
            // Gated by auto_for_premium inside MigrationManager.evaluateLogin.
            val bypassTarget = gameProfile?.id
            if (bypassTarget != null) {
                try {
                    MigrationManager.evaluateLogin(server, bypassTarget, null, gameProfile?.name)
                } catch (e: Exception) {
                    logger.warn("Migration evaluation failed for bypass ${gameProfile?.name}: ${e.message}", e)
                }
            }
            finish()
        } else {
            logger.info("Starting BeaconAuth web flow")
            startBeaconFlow()
        }
    }

    private fun handleInitResponse(data: FriendlyByteBuf?) {
        if (data == null || data.readableBytes() <= 0) {
            logger.error("Invalid INIT response: no data")
            fail(Component.translatable("disconnect.beaconauth.invalid_init"))
            return
        }
        val challenge = data.readUtf(512)
        val redirectPort = data.readVarInt()
        negotiation.setChallenge(challenge, redirectPort)
        logger.info("Received INIT: challenge length=${challenge.length}, port=$redirectPort")

        negotiation.phase = ServerLoginNegotiation.Phase.VERIFY
        negotiation.resetTick()
        sendRequest(LoginQueryType.VERIFY)
        logger.debug("Sent VERIFY cookie request")
    }

    private fun handleVerifyResponse(data: FriendlyByteBuf?) {
        if (data == null) {
            logger.error("Invalid VERIFY response: no data")
            fail(Component.translatable("disconnect.beaconauth.invalid_verify"))
            return
        }
        val profile = gameProfile
        if (profile == null) {
            logger.error("Invalid VERIFY: gameProfile is null")
            fail(Component.translatable("disconnect.beaconauth.invalid_verify"))
            return
        }

        val statusOrdinal = data.readVarInt()

        val status = LoginVerificationStatus.values()[
            statusOrdinal.coerceIn(0, LoginVerificationStatus.values().size - 1)
        ]
        logger.info("Received VERIFY status: $status")

        when (status) {
            LoginVerificationStatus.SUCCESS -> {
                val jwt = data.readUtf(4096)
                val verifier = data.readUtf(512)
                val result = AuthServer.verifyForProfile(profile.name, jwt, verifier)
                if (result.success) {
                    val effectiveName = sanitizeMinecraftUsername(result.username) ?: profile.name
                    val stableUuid = result.stableUuid
                    val conflictingProfile = OfficialNameGuard.findConflict(server, effectiveName, stableUuid)
                    if (conflictingProfile != null) {
                        logger.warn(
                            "Rejecting BeaconAuth user ${profile.name}: name '$effectiveName' conflicts with existing official Minecraft profile ${conflictingProfile.id}"
                        )
                        if (stableUuid != null) {
                            AuthServer.removeAuthenticatedPlayer(stableUuid)
                        }
                        fail(Component.translatable("disconnect.beaconauth.official_name_conflict", effectiveName))
                        return
                    }
                    if (stableUuid != null) {
                        // Replace the login profile UUID with a stable per-account UUID.
                        // This prevents account takeover on offline-mode servers via username changes.
                        gameProfile = GameProfile(stableUuid, effectiveName)
                        logger.info(
                            "Using BeaconAuth identity for ${profile.name}: name=$effectiveName stableUuid=$stableUuid"
                        )
                    } else if (effectiveName != profile.name && profile.id != null) {
                        // Best-effort: still apply the BeaconAuth username even if stableUuid was not returned.
                        gameProfile = GameProfile(profile.id, effectiveName)
                        logger.info("Using BeaconAuth username for ${profile.name}: $effectiveName")
                    }
                    // Attempt to claim legacy OfflinePlayer:<name> playerdata to this identity.
                    // Runs synchronously on the negotiation thread; file I/O is minimal and the
                    // ledger+files live on the server's world directory.
                    val targetUuid = gameProfile?.id ?: stableUuid
                    if (targetUuid != null) {
                        try {
                            MigrationManager.evaluateLogin(
                                server,
                                targetUuid,
                                effectiveName,
                                profile.name
                            )
                        } catch (e: Exception) {
                            logger.warn("Migration evaluation failed for ${profile.name}: ${e.message}", e)
                        }
                    }
                    logger.info("✓ Verification successful for ${profile.name}")
                    finish()
                } else {
                    logger.error("✗ Verification failed: ${result.message}")
                    fail(Component.translatable("disconnect.beaconauth.failure", result.message))
                }
            }
            LoginVerificationStatus.CANCELLED -> {
                val reason = data.readUtf(256)
                logger.warn("User cancelled: $reason")
                fail(Component.translatable("disconnect.beaconauth.cancelled", reason))
            }
            LoginVerificationStatus.ERROR -> {
                val error = data.readUtf(256)
                logger.error("Client error: $error")
                fail(Component.translatable("disconnect.beaconauth.failure", error))
            }
        }
    }

    private fun startBeaconFlow() {
        negotiation.phase = ServerLoginNegotiation.Phase.INIT
        sendRequest(LoginQueryType.INIT)
        negotiation.resetTick()
    }

    private fun finish() {
        negotiation.markFinished()
        logger.info("Negotiation finished successfully")
        finishCallback()
    }

    private fun fail(reason: Component) {
        logger.warn("Negotiation failed: ${reason.string}")
        disconnectCallback(reason)
    }

    private fun sendRequest(type: LoginQueryType) {
        val key = type.id()
        negotiation.registerTransaction(key, type)
        connection.send(ClientboundCookieRequestPacket(key))
    }
}
