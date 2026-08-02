package io.github.summpot.beaconauth.util

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * PKCE (Proof Key for Code Exchange) utilities for OAuth 2.0 flow
 * Implements S256 challenge method (SHA-256 hash)
 */
object PKCEUtils {
    private val secureRandom = SecureRandom()
    private val base64Encoder = Base64.getUrlEncoder().withoutPadding()

    /**
     * Generate a cryptographically secure PKCE code verifier
     * Length: 43-128 characters (we use 64 for high entropy)
     */
    fun generateCodeVerifier(): String {
        val bytes = ByteArray(48) // 48 bytes = 64 base64url characters
        secureRandom.nextBytes(bytes)
        return base64Encoder.encodeToString(bytes)
    }

    /**
     * Generate code challenge from verifier using S256 method
     * Challenge = BASE64URL(SHA256(verifier))
     */
    fun generateCodeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.US_ASCII))
        return base64Encoder.encodeToString(hash)
    }

    /**
     * Constant-time string comparison (used for OIDC nonce validation).
     */
    fun constantTimeEquals(a: String, b: String): Boolean {
        return try {
            MessageDigest.isEqual(
                a.toByteArray(Charsets.UTF_8),
                b.toByteArray(Charsets.UTF_8)
            )
        } catch (e: Exception) {
            false
        }
    }
}
