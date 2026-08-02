package io.github.summpot.beaconauth.server

import com.mojang.authlib.GameProfile
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.login.LoginQueryType
import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.login.ServerLoginNegotiation
import io.github.summpot.beaconauth.server.AuthServer.VerificationResult
import io.netty.buffer.Unpooled
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.chat.Component
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket
import net.minecraft.server.MinecraftServer
import org.slf4j.LoggerFactory
import java.util.*
import java.util.function.Consumer

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
     * In that case, the profile UUID is only a placeholder and MUST NOT be treated as Mojang-verified.
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
    private var transactionCounter = 0

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
        sendQuery(LoginQueryType.PROBE) { }
    }

    fun handleCustomQuery(transactionId: Int, data: FriendlyByteBuf?): Boolean {
        val type = negotiation.consume(transactionId) ?: return false
        when (type) {
            LoginQueryType.PROBE -> handleProbeResponse(data)
            LoginQueryType.INIT -> handleInitResponse(data)
            LoginQueryType.LOGIN_URL -> handleLoginUrlAck(data)
            LoginQueryType.VERIFY -> handleVerifyResponse(data)
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
            // On online-mode servers, only allow vanilla clients if they already passed Mojang verification.
            // If we intercepted handleHello, the UUID is only a placeholder.
            val hasMojangVerifiedUUID = !helloWasIntercepted && gameProfile?.id != null
            val allowVanilla = if (onlineMode) {
                hasMojangVerifiedUUID
            } else {
                BeaconAuthConfig.shouldAllowVanillaOfflineClients()
            }

            if (allowVanilla) {
                logger.info("Vanilla client allowed; finishing negotiation")
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
        val nonce = data.readUtf(256)
        negotiation.setChallenge(challenge, redirectPort)
        negotiation.setNonce(nonce)
        logger.info("Received INIT: challenge length=${challenge.length}, port=$redirectPort, nonce length=${nonce.length}")

        try {
            val loginUrl = AuthServer.buildLoginUrl(challenge, redirectPort, nonce)
            negotiation.phase = ServerLoginNegotiation.Phase.LOGIN_URL
            sendQuery(LoginQueryType.LOGIN_URL) { buf -> buf.writeUtf(loginUrl, 2048) }
            negotiation.resetTick()
            sendQuery(LoginQueryType.VERIFY) { }
            negotiation.phase = ServerLoginNegotiation.Phase.VERIFY
            logger.debug("Sent LOGIN_URL & VERIFY queries")
        } catch (e: Exception) {
            logger.error("Error building login URL: ${e.message}", e)
            fail(Component.translatable("disconnect.beaconauth.server_error"))
        }
    }

    private fun handleLoginUrlAck(data: FriendlyByteBuf?) {
        logger.debug("Received LOGIN_URL acknowledgement")
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
                val result = AuthServer.verifyForProfile(profile.name, jwt, negotiation.getPendingNonce(), server)
                if (result.success) {
                    val effectiveName = sanitizeMinecraftUsername(result.username) ?: profile.name
                    val stableUuid = result.stableUuid
                    val conflictingProfile = if (BeaconAuthConfig.shouldUseLegacyOfflineUuids()) {
                        // Legacy offline identity mode: the UUID is the offline-mode UUID, which by
                        // design does not collide with official Mojang profiles. Skip the guard.
                        null
                    } else {
                        OfficialNameGuard.findConflict(server, effectiveName, stableUuid)
                    }
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
                        // Replace the login profile UUID with the BeaconAuth identity UUID
                        // (stable per-account UUID, or the mapped legacy offline UUID in
                        // legacy offline identity mode). This keeps world data intact.
                        gameProfile = GameProfile(stableUuid, effectiveName)
                        logger.info(
                            "Using BeaconAuth identity for ${profile.name}: name=$effectiveName stableUuid=$stableUuid"
                        )
                    } else if (effectiveName != profile.name && profile.id != null) {
                        // Best-effort: still apply the BeaconAuth username even if stableUuid was not returned.
                        gameProfile = GameProfile(profile.id, effectiveName)
                        logger.info("Using BeaconAuth username for ${profile.name}: $effectiveName")
                    }
                    logger.info("✓ Verification successful for ${profile.name}")
                    finish()
                } else {
                    logger.error("✗ Verification failed: ${result.message}")
                    if (result.legacyIdentityClaimed) {
                        fail(Component.translatable("disconnect.beaconauth.legacy_identity_claimed"))
                    } else {
                        fail(Component.translatable("disconnect.beaconauth.failure", result.message))
                    }
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
        sendQuery(LoginQueryType.INIT) { }
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

    private fun sendQuery(type: LoginQueryType, writer: Consumer<FriendlyByteBuf>) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        writer.accept(buf)
        val transactionId = ++transactionCounter
        negotiation.registerTransaction(transactionId, type)
        connection.send(ClientboundCustomQueryPacket(transactionId, type.id(), buf))
    }
}
