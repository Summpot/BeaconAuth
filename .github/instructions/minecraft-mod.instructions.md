# Minecraft Mod Instructions (Kotlin/Architectury)

> **Applies to:** `modSrc/` directory (self-contained Gradle project)

## Tech Stack

* **Language:** Kotlin 2.2.21
* **Build System:** Gradle 8.x with Kotlin DSL
* **Mod Framework:** Architectury (Loom 1.11)
* **HTTP Server:** `com.sun.net.httpserver` (Java built-in)
* **JWT:** `nimbus-jose-jwt:10.6`
* **Minecraft Version:** 1.20.1

## Project Structure

**IMPORTANT:** The `modSrc/` directory is a **separate, self-contained Gradle project**.

To work on the Mod in an IDE, you **MUST** open the `modSrc/` directory as the project root (or open `modSrc/build.gradle.kts`).

### Subprojects

| Subproject | Description |
|------------|-------------|
| `modSrc/common/` | Common code shared between loaders |
| `modSrc/fabric/` | Fabric-specific implementation |
| `modSrc/forge/` | Forge-specific implementation |

## Dependency Management

Gradle dependencies are managed in `modSrc/build.gradle.kts` and subproject build files.

### Required Dependencies (`modSrc/common/build.gradle.kts`)

* **MUST** include `com.nimbusds:nimbus-jose-jwt:10.6` for JWT validation.
* **MUST** use `modImplementation` for Architectury dependencies.
* **MUST** include `fuzs.forgeconfigapiport:forgeconfigapiport-common:8.0.2` for cross-loader config API.

## Configuration

* A server-side config file (`beaconauth-server.toml`) **MUST** be used via FuzzyConfig.
* The config loader **MUST** auto-generate this file on first run.
* **Default URLs** must point to `http://localhost:8080`:
    * Login URL: `http://localhost:8080/`
    * JWKS URL: `http://localhost:8080/.well-known/jwks.json`

## Internationalization (i18n)

Translation files location: `modSrc/common/src/main/resources/assets/beaconauth/lang/`

| File | Language |
|------|----------|
| `en_us.json` | English |
| `zh_cn.json` | Simplified Chinese |

All user-facing strings (chat messages, HTML pages, commands) **MUST** use `TranslationHelper`.

## Client-Side (`AuthClient.kt`)

### HTTP Server Setup

* **MUST** use `com.sun.net.httpserver.HttpServer` (Java built-in, NOT Ktor).
* **MUST** find a free port in the `38123-38133` range using `NetUtils.findAvailablePort()` and save it.

### Login Flow

1. Receives `RequestClientLoginPacket` (S2C)
2. Calls `startLoginProcess()`
3. `startLoginProcess()`: Generates PKCE challenge/verifier via `PKCEUtils`, sends `RequestLoginUrlPacket` (C2S) with `challenge` and `boundPort`.

### Auth Callback Handler (`/auth-callback`)

* Receives callback with `?jwt=...&profile_url=...` query params (both URL-encoded).
* Parses query parameters using `URLDecoder.decode()`.
* Attempts to focus the Minecraft window using **safe** GLFW functions:
    * `glfwRestoreWindow()` if minimized
    * `glfwRequestWindowAttention()` for taskbar flash
* Parses JWT, sends `VerifyAuthPacket` (C2S) with JWT and verifier.
* Returns HTTP 302 Redirect to `{profile_url}?status=success&message=...` (or error).

**CRITICAL**: The `profile_url` is provided by the backend, **NOT** read from `ServerConfig`. This ensures proper client-server separation.

### Window Focus Behavior

Window focus attempts are **best-effort only**. Due to OS-level security restrictions (especially on Windows), the window focus request **will fail** when the browser has focus.

The most reliable behavior is taskbar icon flashing via `glfwRequestWindowAttention()`.

**DO NOT** use:
* `glfwFocusWindow()` - Can cause input capture issues
* `glfwShowWindow()` - Can trap the user's cursor

This is an OS limitation, not a bug.

## Server-Side (`AuthServer.kt`)

### State Management

* **MUST** maintain a `MutableSet<UUID>` of `authenticatedPlayers` (thread-safe).

### Auto-Login

* **MUST** hook the `PlayerJoinEvent` via `AuthEventHandler`.
* If player UUID is not in the `authenticatedPlayers` set, send `RequestClientLoginPacket` (S2C) to trigger login flow.

### Network Handlers (via `ServerLoginHandler`)

| Handler | Direction | Description |
|---------|-----------|-------------|
| `onReceiveRequestLoginUrl` | C2S | Receives `challenge` & `boundPort`, builds login URL, sends `LoginUrlPacket` (S2C) |
| `onReceiveVerifyAuth` | C2S | Receives `jwt` & `verifier`, validates JWT and PKCE, sends `AuthResultPacket` (S2C) |

### JWT Validation (Nimbus)

1. The `jwtProcessor` **MUST** be initialized lazily using `RemoteJWKSet` pointing to `ServerConfig.jwksUrl`.
2. The processor **MUST** be configured with:
    * `JWSAlgorithm.ES256`
    * Required claims: `iss`, `aud`, `exp`
3. Validation:
    * Call `jwtProcessor.process(jwt, null)` to validate signature and standard claims.
    * Perform PKCE check: `PKCEUtils.verifyChallenge(verifier, claims.challenge)`.
4. On success:
    * Add player UUID to `authenticatedPlayers`
    * Send success `AuthResultPacket`
    * Log success message
5. On failure:
    * Send failure `AuthResultPacket` with error message
    * Kick player

### Events

* **MUST** hook `PlayerQuitEvent` to remove player UUID from `authenticatedPlayers` set.

### Commands

A `/beaconauth login` command **MUST** exist (registered via `AuthCommand`) to manually trigger `RequestClientLoginPacket` (S2C) for the executing player.

## Build Verification

After modifying any Kotlin/Mod code, run from `modSrc/` directory:

```bash
./gradlew build
```
