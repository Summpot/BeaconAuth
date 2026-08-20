package io.github.summpot.beaconauth.client

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import io.github.summpot.beaconauth.config.BeaconAuthConfig
import io.github.summpot.beaconauth.util.PKCEUtils
import io.github.summpot.beaconauth.util.TranslationHelper
import com.google.gson.JsonParser
import net.minecraft.Util
import net.minecraft.client.Minecraft
import net.minecraft.client.gui.screens.ConfirmLinkScreen
import org.slf4j.LoggerFactory
import java.net.BindException
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.jvm.Volatile

/**
 * Client helper responsible for PKCE generation, loopback HTTP server, and
 * bridging OAuth callbacks back into the login-phase negotiation.
 *
 * Implements the OIDC authorization-code flow as a public client:
 *  1. The login URL points at the server's `/api/v1/oidc/authorize` endpoint
 *     with `code_challenge`, `nonce`, `state` and the loopback redirect URI.
 *  2. After the user authenticates in the browser, the server redirects to
 *     `http://127.0.0.1:<port>/auth-callback?code=...&state=...`.
 *  3. This client exchanges the code at the token endpoint (with the PKCE
 *     verifier) and validates the `nonce` in the returned ID token before
 *     handing it to the login-phase negotiation.
 */
object AuthClient {
    private val logger = LoggerFactory.getLogger("BeaconAuth/Client")

    private const val PORT_RANGE_START = 38123
    private const val PORT_RANGE_END = 38133
    private const val CALLBACK_PATH = "/auth-callback"

    data class LoginInitPayload(val codeChallenge: String, val boundPort: Int, val nonce: String)

    interface LoginPhaseCallback {
        fun onAuthSuccess(idToken: String)
        fun onAuthError(message: String)
    }

    private var httpServer: HttpServer? = null
    private var boundPort: Int = -1
    private var currentCodeVerifier: String? = null
    private var currentNonce: String? = null
    private var currentState: String? = null
    @Volatile private var loginPhaseCallback: LoginPhaseCallback? = null
    private val serverReady = AtomicBoolean(false)

    fun init() {
        if (!serverReady.get()) {
            startLocalHttpServer()
        }
    }

    private fun randomUrlSafe(bytes: Int): String {
        val buf = ByteArray(bytes)
        SecureRandom().nextBytes(buf)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf)
    }

    @JvmStatic
    fun prepareLoginPhaseCredentials(): LoginInitPayload {
        startLocalHttpServer()
        val verifier = PKCEUtils.generateCodeVerifier()
        val challenge = PKCEUtils.generateCodeChallenge(verifier)
        val nonce = randomUrlSafe(24)
        val state = randomUrlSafe(24)
        currentCodeVerifier = verifier
        currentNonce = nonce
        currentState = state
        logger.info("Generated PKCE challenge + nonce for OIDC login-phase handshake")
        return LoginInitPayload(challenge, boundPort, nonce)
    }

    /**
     * Build the OIDC authorization URL from the credentials generated at INIT.
     * Used by 1.20.x when the server pushes no LOGIN_URL payload.
     */
    @JvmStatic
    fun buildOidcLoginUrl(): String {
        val challenge = currentCodeVerifier?.let { PKCEUtils.generateCodeChallenge(it) }
            ?: throw IllegalStateException("Login flow not initiated")
        val nonce = currentNonce ?: throw IllegalStateException("Login flow not initiated")
        val redirectUri = "http://127.0.0.1:$boundPort$CALLBACK_PATH"
        return "${BeaconAuthConfig.getAuthBaseUrl()}/api/v1/oidc/authorize?" +
            "response_type=code&client_id=" + java.net.URLEncoder.encode(BeaconAuthConfig.getOidcClientId(), "UTF-8") +
            "&redirect_uri=" + java.net.URLEncoder.encode(redirectUri, "UTF-8") +
            "&scope=openid" +
            "&state=" + java.net.URLEncoder.encode(nonce, "UTF-8") +
            "&code_challenge=" + java.net.URLEncoder.encode(challenge, "UTF-8") +
            "&code_challenge_method=S256" +
            "&nonce=" + java.net.URLEncoder.encode(nonce, "UTF-8")
    }

    @JvmStatic
    fun registerLoginPhaseCallback(callback: LoginPhaseCallback?) {
        loginPhaseCallback = callback
    }

    @JvmStatic
    fun showLoginConfirmation(loginUrl: String, onConfirm: () -> Unit, onCancel: (String) -> Unit) {
        val minecraft = Minecraft.getInstance()
        val previous = minecraft.screen
        minecraft.execute {
            minecraft.setScreen(
                ConfirmLinkScreen({ accepted ->
                    minecraft.setScreen(previous)
                    if (accepted) {
                        Util.getPlatform().openUri(loginUrl)
                        onConfirm()
                    } else {
                        onCancel(TranslationHelper.loginCancelled().string)
                    }
                }, loginUrl, true)
            )
        }
    }

    private fun startLocalHttpServer() {
        if (serverReady.get()) {
            return
        }

        synchronized(this) {
            if (serverReady.get()) {
                return
            }

            for (port in PORT_RANGE_START..PORT_RANGE_END) {
                try {
                    logger.info("Attempting to bind HTTP server on port $port...")
                    val server = HttpServer.create(InetSocketAddress("127.0.0.1", port), 0)
                    server.createContext(CALLBACK_PATH, this::handleAuthCallback)
                    server.executor = null
                    server.start()
                    httpServer = server
                    boundPort = port
                    serverReady.set(true)
                    logger.info("✓ HTTP server successfully bound to port $port")
                    return
                } catch (e: BindException) {
                    logger.warn("Port $port is already in use, trying next...")
                } catch (e: Exception) {
                    logger.error("Failed to bind on port $port: ${e.message}", e)
                }
            }

            logger.error("CRITICAL: Failed to bind HTTP server on any port in range $PORT_RANGE_START-$PORT_RANGE_END")
            throw IllegalStateException("BeaconAuth client cannot start loopback server")
        }
    }

    private fun handleAuthCallback(exchange: HttpExchange) {
        try {
            val query = exchange.requestURI.query
            val params = query?.split("&")
                ?.map { it.split("=", limit = 2) }
                ?.filter { it.size == 2 }
                ?.associate { it[0] to java.net.URLDecoder.decode(it[1], "UTF-8") }
                ?: emptyMap()

            val code = params["code"]
            val error = params["error"]
            val state = params["state"]

            if (!error.isNullOrBlank()) {
                logger.error("OIDC authorization error: $error")
                sendRedirectResponse(exchange, "/settings?status=error&message=" + java.net.URLEncoder.encode(error, "UTF-8"))
                loginPhaseCallback?.onAuthError("Authorization error: $error")
                return
            }

            if (code.isNullOrBlank()) {
                logger.error("Received callback without code parameter")
                sendRedirectResponse(exchange, "/settings?status=error&message=Missing+code+parameter")
                loginPhaseCallback?.onAuthError("Missing code parameter")
                return
            }

            // Validate state (CSRF protection).
            val expectedState = currentState
            if (expectedState == null || state == null || state != expectedState) {
                logger.error("OIDC state mismatch")
                sendRedirectResponse(exchange, "/settings?status=error&message=State+mismatch")
                loginPhaseCallback?.onAuthError("State mismatch")
                return
            }

            val verifier = currentCodeVerifier
            if (verifier == null) {
                logger.error("No code verifier found - login flow not initiated properly")
                sendRedirectResponse(exchange, "/settings?status=error&message=Login+flow+not+initiated")
                loginPhaseCallback?.onAuthError("Login flow not initiated")
                return
            }

            logger.info("Received OIDC code from browser, exchanging at token endpoint...")

            val idToken = exchangeCodeForIdToken(code, verifier, state)
            currentCodeVerifier = null
            currentState = null

            // Try to bring Minecraft window to foreground
            try {
                focusMinecraftWindow()
            } catch (e: Exception) {
                logger.warn("Failed to focus Minecraft window: ${e.message}")
            }

            loginPhaseCallback?.onAuthSuccess(idToken)
            currentNonce = null

            // Redirect to settings page with success status
            sendRedirectResponse(exchange, "/settings?status=success&message=Authentication+successful")
        } catch (e: Exception) {
            logger.error("Error handling auth callback: ${e.message}", e)
            sendRedirectResponse(exchange, "/settings?status=error&message=" + java.net.URLEncoder.encode(e.message ?: "Unknown error", "UTF-8"))
            loginPhaseCallback?.onAuthError(e.message ?: "Unknown error")
        } finally {
            exchange.close()
        }
    }

    /**
     * Exchange the authorization code for an ID token at the token endpoint (RFC 6749 §4.1.3).
     * Returns the raw ID token JWT. The nonce is verified by the server-side mod.
     */
    private fun exchangeCodeForIdToken(code: String, verifier: String, state: String): String {
        val form = "grant_type=authorization_code" +
            "&code=" + java.net.URLEncoder.encode(code, "UTF-8") +
            "&redirect_uri=" + java.net.URLEncoder.encode("http://127.0.0.1:$boundPort$CALLBACK_PATH", "UTF-8") +
            "&client_id=" + java.net.URLEncoder.encode(BeaconAuthConfig.getOidcClientId(), "UTF-8") +
            "&code_verifier=" + java.net.URLEncoder.encode(verifier, "UTF-8")

        val client = HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(10)).build()
        val request = HttpRequest.newBuilder()
            .uri(URI.create(BeaconAuthConfig.getTokenEndpoint()))
            .timeout(java.time.Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            val snippet = response.body().take(512)
            throw IllegalStateException("Token endpoint returned HTTP ${response.statusCode()}: $snippet")
        }

        val body = response.body()
        val parsed = JsonParser.parseString(body).asJsonObject
        val idToken = parsed.get("id_token")?.asString ?: ""
        if (idToken.isEmpty()) {
            throw IllegalStateException("Token response missing id_token")
        }
        return idToken
    }

    private fun sendRedirectResponse(exchange: HttpExchange, location: String) {
        try {
            exchange.responseHeaders.set("Location", location)
            exchange.sendResponseHeaders(302, -1)
        } catch (e: Exception) {
            logger.error("Failed to send redirect response: ${e.message}", e)
        }
    }

    /**
     * Attempts to bring the Minecraft window to the foreground.
     * Uses a smart strategy that switches to fullscreen temporarily if needed.
     *
     * IMPORTANT: We avoid glfwFocusWindow() and glfwShowWindow() in windowed mode as these can cause
     * Minecraft to think it has focus and enable mouse capture, even when the browser
     * actually has focus. This would trap the user's cursor.
     *
     * STRATEGY:
     * - In fullscreen mode: Can reliably focus by restoring if minimized
     * - In windowed mode while not focused: Switch to fullscreen, focus, then restore windowed mode
     * - This provides seamless window activation across all scenarios
     */
    private fun focusMinecraftWindow() {
        try {
            val minecraft = Minecraft.getInstance()
            minecraft.execute {
                val windowHandle = minecraft.window.window

                // Check current window state
                val isIconified = org.lwjgl.glfw.GLFW.glfwGetWindowAttrib(windowHandle, org.lwjgl.glfw.GLFW.GLFW_ICONIFIED) == org.lwjgl.glfw.GLFW.GLFW_TRUE
                val isFocused = org.lwjgl.glfw.GLFW.glfwGetWindowAttrib(windowHandle, org.lwjgl.glfw.GLFW.GLFW_FOCUSED) == org.lwjgl.glfw.GLFW.GLFW_TRUE
                val isFullscreen = minecraft.window.isFullscreen

                logger.info("Window state: Minimized=$isIconified, Focused=$isFocused, Fullscreen=$isFullscreen")

                // Restore if minimized
                if (isIconified) {
                    org.lwjgl.glfw.GLFW.glfwRestoreWindow(windowHandle)
                    logger.info("Restored minimized window")
                }

                // If already focused or fullscreen, just request attention
                if (isFocused || isFullscreen) {
                    org.lwjgl.glfw.GLFW.glfwRequestWindowAttention(windowHandle)
                    logger.info("Window is fullscreen or already focused, requested attention")
                    return@execute
                }

                // Windowed mode and not focused: Use fullscreen trick for reliable activation
                logger.info("Windowed mode without focus - switching to fullscreen temporarily")

                // Save current windowed mode state
                val wasWindowed = !isFullscreen

                // Switch to fullscreen (this reliably grabs focus)
                minecraft.window.toggleFullScreen()

                // Schedule restoration back to windowed mode after a short delay
                if (wasWindowed) {
                    // Use a scheduled task to switch back after 100ms
                    Thread {
                        Thread.sleep(100)
                        minecraft.execute {
                            // Switch back to windowed mode
                            if (minecraft.window.isFullscreen) {
                                minecraft.window.toggleFullScreen()
                                logger.info("Restored windowed mode after focus grab")
                            }
                        }
                    }.start()
                }

                // Close pause screen if it's open (so player returns to gameplay)
                val currentScreen = minecraft.screen
                if (currentScreen != null && currentScreen.javaClass.simpleName == "PauseScreen") {
                    minecraft.setScreen(null)
                    logger.info("Closed pause screen to resume gameplay")
                }

                logger.info("Window activation sequence initiated")
            }
        } catch (e: Exception) {
            logger.warn("Failed to focus window: ${e.message}", e)
            // Fallback to basic window attention request
            try {
                val minecraft = Minecraft.getInstance()
                minecraft.execute {
                    org.lwjgl.glfw.GLFW.glfwRequestWindowAttention(minecraft.window.window)
                }
            } catch (fallbackError: Exception) {
                logger.error("Fallback focus also failed: ${fallbackError.message}")
            }
        }
    }
}
