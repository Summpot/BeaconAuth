package io.github.summpot.beaconauth.client

import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.login.LoginQueryType
import io.github.summpot.beaconauth.util.TranslationHelper
import io.netty.buffer.Unpooled
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.protocol.cookie.ServerboundCookieResponsePacket
import net.minecraft.resources.ResourceLocation
import org.slf4j.LoggerFactory

/**
 * Kotlin helper for handling BeaconAuth login-phase custom queries on the client.
 * Called by ClientHandshakePacketListenerImplMixin (Java).
 */
object ClientLoginHandler {
    private val logger = LoggerFactory.getLogger("BeaconAuth/ClientLogin")

    private var verifyRequested: Boolean = false
    private var cancelledBeforeVerify: Boolean = false
    private var cancelReason: String = ""

    @JvmStatic
    fun handleCookieRequest(connection: Connection, key: ResourceLocation): Boolean {
        return when (key) {
            LoginQueryType.PROBE.id() -> {
                respondProbe(connection)
                true
            }
            LoginQueryType.INIT.id() -> {
                BeaconAuthClientSession.noteHandshake(connection)
                respondInit(connection)
                true
            }
            LoginQueryType.VERIFY.id() -> {
                BeaconAuthClientSession.noteHandshake(connection)
                handleVerifyRequest(connection)
                true
            }
            else -> false
        }
    }

    private fun respondProbe(connection: Connection) {
        sendCookieResponse(connection, LoginQueryType.PROBE.id()) { buf ->
            buf.writeBoolean(true)
            buf.writeUtf("beaconauth", 64)
        }
        logger.debug("Sent probe response (mod detected)")
    }

    private fun respondInit(connection: Connection) {
        val payload = AuthClient.prepareLoginPhaseCredentials()

        sendCookieResponse(connection, LoginQueryType.INIT.id()) { buf ->
            buf.writeUtf(payload.codeChallenge, 512)
            buf.writeVarInt(payload.boundPort)
            buf.writeUtf(payload.nonce, 256)
        }
        logger.debug("Sent init response with challenge, port and nonce")

        // Cookie requests cannot carry server->client payloads, so the client computes the login URL locally.
        // This requires the client's config to match the server's authentication server.
        val loginUrl = AuthClient.buildOidcLoginUrl()
        AuthClient.showLoginConfirmation(
            loginUrl,
            onConfirm = { },
            onCancel = { reason -> cancelDuringVerify(connection, reason) }
        )
    }

    @JvmStatic
    fun handleVerifyRequest(connection: Connection) {
        if (cancelledBeforeVerify) {
            sendVerifyResponse(connection, LoginVerificationStatus.CANCELLED, null, cancelReason)
            cancelledBeforeVerify = false
            cancelReason = ""
            BeaconAuthClientSession.clearHandshake()
            logger.info("User cancelled before verify; sent CANCELLED status")
            return
        }

        verifyRequested = true
        logger.debug("Waiting for OAuth callback to complete verification...")

        AuthClient.registerLoginPhaseCallback(object : AuthClient.LoginPhaseCallback {
            override fun onAuthSuccess(idToken: String) {
                BeaconAuthClientSession.markAuthenticated(connection)
                sendVerifyResponse(connection, LoginVerificationStatus.SUCCESS, idToken, null)
                logger.info("OIDC flow succeeded; sent ID token")
            }

            override fun onAuthError(message: String) {
                BeaconAuthClientSession.clearHandshake()
                sendVerifyResponse(connection, LoginVerificationStatus.ERROR, null, message)
                logger.error("OIDC flow failed: $message")
            }
        })
    }

    private fun cancelDuringVerify(connection: Connection, reason: String) {
        if (verifyRequested) {
            logger.warn("User cancelled during verify phase; sending CANCELLED")
            sendVerifyResponse(connection, LoginVerificationStatus.CANCELLED, null, reason)
        } else {
            // Not yet in verify, store for later
            cancelledBeforeVerify = true
            cancelReason = reason
            logger.warn("User cancelled before verify phase; will report on next verify query")
        }
    }

    private fun sendCookieResponse(
        connection: Connection,
        key: ResourceLocation,
        writer: (FriendlyByteBuf) -> Unit
    ) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        writer(buf)
        val bytes = ByteArray(buf.readableBytes())
        buf.getBytes(0, bytes)
        connection.send(ServerboundCookieResponsePacket(key, bytes))
    }

    private fun sendVerifyResponse(
        connection: Connection,
        status: LoginVerificationStatus,
        idToken: String?,
        message: String?
    ) {
        sendCookieResponse(connection, LoginQueryType.VERIFY.id()) { buf ->
            buf.writeVarInt(status.ordinal)
            when (status) {
                LoginVerificationStatus.SUCCESS -> {
                    buf.writeUtf(idToken ?: "", 4096)
                }
                LoginVerificationStatus.CANCELLED, LoginVerificationStatus.ERROR -> {
                    buf.writeUtf(message ?: "", 256)
                }
            }
        }
        if (status != LoginVerificationStatus.SUCCESS) {
            BeaconAuthClientSession.clearHandshake()
        }
        verifyRequested = false
        cancelledBeforeVerify = false
        cancelReason = ""
        AuthClient.registerLoginPhaseCallback(null)
    }
}
