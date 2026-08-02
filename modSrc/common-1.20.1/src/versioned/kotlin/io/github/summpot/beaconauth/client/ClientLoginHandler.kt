package io.github.summpot.beaconauth.client

import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.login.LoginVerificationStatus
import io.github.summpot.beaconauth.util.TranslationHelper
import io.netty.buffer.Unpooled
import net.minecraft.Util
import net.minecraft.client.Minecraft
import net.minecraft.client.gui.screens.ConfirmLinkScreen
import net.minecraft.network.Connection
import net.minecraft.network.FriendlyByteBuf
import net.minecraft.network.protocol.login.ServerboundCustomQueryPacket
import org.slf4j.LoggerFactory

/**
 * Kotlin helper for handling BeaconAuth login-phase custom queries on the client.
 * Called by ClientHandshakePacketListenerImplMixin (Java).
 */
object ClientLoginHandler {
    private val logger = LoggerFactory.getLogger("BeaconAuth/ClientLogin")

    private var pendingVerifyTransaction: Int = -1
    private var cancelledBeforeVerify: Boolean = false
    private var cancelReason: String = ""

    @JvmStatic
    fun respondProbe(connection: Connection, transactionId: Int) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        buf.writeBoolean(true)
        buf.writeUtf("beaconauth", 64)
        connection.send(ServerboundCustomQueryPacket(transactionId, buf))
        logger.debug("Sent probe response (mod detected)")
    }

    @JvmStatic
    fun respondInit(connection: Connection, transactionId: Int) {
        BeaconAuthClientSession.noteHandshake(connection)
        val payload = AuthClient.prepareLoginPhaseCredentials()
        val buf = FriendlyByteBuf(Unpooled.buffer())
        buf.writeUtf(payload.codeChallenge, 512)
        buf.writeVarInt(payload.boundPort)
        buf.writeUtf(payload.nonce, 256)
        connection.send(ServerboundCustomQueryPacket(transactionId, buf))
        logger.debug("Sent init response with challenge, port and nonce")
    }

    @JvmStatic
    fun handleLoginUrl(connection: Connection, transactionId: Int, data: FriendlyByteBuf?) {
        BeaconAuthClientSession.noteHandshake(connection)
        // The server pushes the OIDC authorize URL (built from the INIT-echoed
        // challenge + nonce). Prefer it; fall back to a locally-built URL using
        // the credentials already generated at INIT (never regenerate them here,
        // or the verifier/nonce would diverge from what the server recorded).
        val loginUrl = data?.readUtf(2048)?.takeIf { it.isNotBlank() }
            ?: AuthClient.buildOidcLoginUrl()

        // Acknowledge receipt immediately
        val ack = FriendlyByteBuf(Unpooled.buffer())
        ack.writeBoolean(true)
        connection.send(ServerboundCustomQueryPacket(transactionId, ack))
        logger.debug("Acknowledged login URL, showing UI confirmation")

        AuthClient.showLoginConfirmation(
            loginUrl,
            onConfirm = { },
            onCancel = { reason -> cancelDuringVerify(reason) }
        )
    }

    @JvmStatic
    fun handleVerifyRequest(connection: Connection, transactionId: Int) {
        BeaconAuthClientSession.noteHandshake(connection)
        if (cancelledBeforeVerify) {
            sendVerifyResponse(connection, transactionId, LoginVerificationStatus.CANCELLED, null, cancelReason)
            cancelledBeforeVerify = false
            cancelReason = ""
            logger.info("User cancelled before verify; sent CANCELLED status")
            return
        }

        pendingVerifyTransaction = transactionId
        logger.debug("Waiting for OAuth callback to complete verification...")

        AuthClient.registerLoginPhaseCallback(object : AuthClient.LoginPhaseCallback {
            override fun onAuthSuccess(idToken: String) {
                BeaconAuthClientSession.markAuthenticated(connection)
                sendVerifyResponse(connection, transactionId, LoginVerificationStatus.SUCCESS, idToken, null)
                logger.info("OIDC flow succeeded; sent ID token")
            }

            override fun onAuthError(message: String) {
                sendVerifyResponse(connection, transactionId, LoginVerificationStatus.ERROR, null, message)
                logger.error("OIDC flow failed: $message")
            }
        })
    }

    private fun cancelDuringVerify(reason: String) {
        if (pendingVerifyTransaction >= 0) {
            // Already in verify phase, send immediately
            logger.warn("User cancelled during verify phase")
        } else {
            // Not yet in verify, store for later
            cancelledBeforeVerify = true
            cancelReason = reason
            logger.warn("User cancelled before verify phase; will report on next verify query")
        }
    }

    private fun sendVerifyResponse(
        connection: Connection,
        transactionId: Int,
        status: LoginVerificationStatus,
        idToken: String?,
        message: String?
    ) {
        val buf = FriendlyByteBuf(Unpooled.buffer())
        buf.writeVarInt(status.ordinal)
        when (status) {
            LoginVerificationStatus.SUCCESS -> {
                buf.writeUtf(idToken ?: "", 4096)
            }
            LoginVerificationStatus.CANCELLED, LoginVerificationStatus.ERROR -> {
                buf.writeUtf(message ?: "", 256)
            }
        }
        connection.send(ServerboundCustomQueryPacket(transactionId, buf))
        pendingVerifyTransaction = -1
        cancelledBeforeVerify = false
        cancelReason = ""
        AuthClient.registerLoginPhaseCallback(null)
    }
}
