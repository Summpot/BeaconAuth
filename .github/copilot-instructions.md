# BeaconAuth Monorepo - AI Guidance

## 1. Our Goal
You are an AI assistant helping to build the **BeaconAuth** monorepo. Your task is to understand and correctly modify the three distinct projects within this repository:
1.  **The Frontend** (React/Rsbuild)
2.  **The Backend** (Rust/Actix-web API)
3.  **The Minecraft Mod** (Kotlin/Architectury/Gradle)

## 2. Core Monorepo Structure (CRITICAL)
This repository contains three projects with two different "root" concepts.

* **Project 1: Root (Frontend & Backend)**
    * The **project root** directory contains the **React Frontend** (`package.json`, `rsbuild.config.ts`, `src/`) and the **Rust Backend** (`Cargo.toml`, `crates/`).
    * This is the "main" project for web development.
    * `cargo` and `pnpm` commands are run from here.

* **Project 2: `modSrc/` (Minecraft Mod)**
    * The `modSrc/` directory is a **separate, self-contained Gradle project**.
    * It contains all Kotlin Mod code (`common/`, `fabric/`, `forge/`) and its own build system (`build.gradle.kts`, `settings.gradle.kts`, `gradlew`).
    * **To work on the Mod in an IDE, you MUST open the `modSrc/` directory as the project root (or open `modSrc/build.gradle.kts`).**

## 3. Global Coding Guidelines
* **[NEW] Language:** All non-code content (comments, documentation, commit messages, console logs) **must** be written in **English** for consistency.
* **[CRITICAL] Code Verification:** 
    * **After modifying any Rust code**, you **MUST** run `cargo check --workspace` to verify compilation before completing your task.
    * **After modifying any Kotlin/Mod code**, you **SHOULD** run `./gradlew build` (from `modSrc/`) to verify compilation when feasible.
    * Never consider a code modification complete without verification.
* **Dependency Management:**
    * **Frontend:** Always use `pnpm add <package-name>` from the **root** directory.
    * **Backend:** Always use `cargo add -p <crate-name>` (or `--build -p`) from the **root** directory to add dependencies to the correct workspace crate.
    * **Mod:** Gradle dependencies are managed in `modSrc/build.gradle.kts`.

---

## Project 1: Frontend (Root - `src/`, `package.json`, etc.)
* **Tech Stack:** React (Hooks), Rsbuild, `pnpm`, `tailwind`, `@tanstack/react-router`, `react-hook-form`.
* **Routing & State:** **`@tanstack/react-router`** is the *only* tool for routing and URL search parameter management.
    * The index route (`/`) **must** use `validateSearch` to parse and require `challenge` (string) and `redirect_port` (number).
    * The component **must** use the `useSearch()` hook to retrieve these values.
* **Forms:** **`react-hook-form`** must be used for the login and registration forms.
* **Styling:** **`tailwind`** must be used for all styling.
* **Login Flow (Standard):**
    * The login form `onSubmit` handler must:
        * Get `username`, `password` (from `react-hook-form`) and `challenge`, `redirect_port` (from `useSearch()`).
        * `fetch` `POST /api/v1/login` with all 4 values in a JSON body.
        * On 200 OK, parse the `{"redirectUrl": "..."}` JSON response.
        * **Execute `window.location.href = data.redirectUrl;`** to trigger the redirect back to the Mod.
* **Login Flow (OAuth):**
    * The "Login with..." buttons must:
        * Get `challenge` and `redirect_port` from `useSearch()`.
        * `fetch` `POST /api/v1/oauth/start` with `{ provider, challenge, redirect_port }`.
        * On 200 OK, parse the `{"authorizationUrl": "..."}` JSON response.
        * **Execute `window.location.href = data.authorizationUrl;`** to redirect to the OAuth provider.
* **Registration Flow:**
    * The register form must `fetch` `POST /api/v1/register`.
    * On 201 Created, it must use the `router` from `TanStack Router` to navigate back to the login page (`/`).

---

## Project 2: Backend (Root - `crates/`, `Cargo.toml`)
* **Tech Stack:** Rust, Actix-web, Sea-ORM, `jsonwebtoken`, `p256`, `ecdsa`, `clap`, `rust-embed`, `actix-files`, `which`.
* **Project Structure:** This is a **virtual Cargo workspace** defined in the **root `Cargo.toml`**. All Rust code lives in the `crates/` directory (e.g., `auth_server`, `entity`, `migration`).
* **Application:** The `auth_server` crate is a **CLI application** using `clap`. The `main` function parses commands (`serve`, etc.).
* **`build.rs` (in `crates/auth_server`):**
    * **Must** have a `[build-dependencies]` section that includes `which`.
    * **Must** use `which::which("pnpm")` to find the full path to `pnpm` (or `pnpm.cmd`) to ensure Windows compatibility.
    * **Must** execute `pnpm build` in the **root directory** (`../../`) before the Rust build proceeds.
* **`serve` Command Logic:**
    * **Crypto:** All JWTs **must** be signed using **`ES256`** (Elliptic Curve, P-256).
    * **Keys:** `ES256` keys must be generated on startup.
    * **JWKS:** The `/.well-known/jwks.json` endpoint **must** serve the `ES256` public key in `kty: "EC"`, `crv: "P-256"` format.
    * **Static Serving (Dual Mode):**
        * **Debug (`cfg(debug_assertions)`)**: Must serve files from the `dist/` directory using `actix-files`, with a SPA fallback to `dist/index.html`.
        * **Release (`cfg(not(debug_assertions)`)**: Must serve files from memory using `rust-embed` and `rust-embed-actix-web`.
* **API Endpoints:**
    * **`POST /api/v1/login`**: Receives JSON. Verifies password (`bcrypt`). On success, creates `ES256` JWT (embedding `challenge` claim) and returns JSON: `{ "redirectUrl": "..." }`.
    * **`POST /api/v1/register`**: Receives JSON. Hashes password. Creates user in Sea-ORM. Returns 201 Created.
    * **`POST /api/v1/oauth/start`**: Receives JSON. Creates a *separate, internal* `state` JWT (encoding `challenge` and `port`). Returns JSON: `{ "authorizationUrl": "..." }`.
    * **`GET /api/v1/oauth/callback`**: Verifies the `state` JWT. Exchanges `code`. Finds/Creates user. Creates the final *Minecraft `ES256` JWT*. Returns an **HTTP 302 Redirect** back to the Mod's `localhost` URL.

---

## Project 3: Minecraft Mod (`modSrc/`)
* **Tech Stack:** Kotlin, Architectury, Gradle, `com.sun.net.httpserver`, `nimbus-jose-jwt`.
* **Build System:** This is a **self-contained Gradle project**.
* **`build.gradle.kts` (in `modSrc/`):**
    * **Must** correctly shadow/embed the `com.nimbusds:nimbus-jose-jwt` dependency into the final Mod jar. (See Architectury Loom docs for "Embedding Libraries").
* **Config:**
    * A server-side config file (`beaconauth-server.toml`) **must** be used.
    * The config loader **must** auto-generate this file on first run (`CONFIG.load(); CONFIG.save()`).
    * The **default** URLs in the config **must** point to `http://localhost:8080` (e.g., `http://localhost:8080/api/v1/login`, etc.) to match the Rust server's default.
* **Internationalization (i18n):**
    * `en_us.json` and `zh_cn.json` **must** be used.
    * **No** user-facing strings (chat, HTML, logs) may be hardcoded.
* **`AuthClient.kt` (Client-Side):**
    * **Must** use `com.sun.net.httpserver.HttpServer` (not Ktor).
    * **Must** find a free port in the `38123-38133` range and save it.
    * Receives `RequestClientLoginPacket` (S2C), then calls `startLoginProcess()`.
    * `startLoginProcess()`: Generates PKCE, sends `RequestLoginUrlPacket` (C2S) with `challenge` and `boundPort`.
    * `HttpHandler`: Receives `localhost` callback, parses `jwt`, sends `VerifyAuthPacket` (C2S). Returns a simple, **i18n-translated** HTML "Success" page.
* **`AuthServer.kt` (Server-Side):**
    * **State:** Must maintain a `Set<UUID>` of `authenticatedPlayers`.
    * **Auto-Login:** **Must** hook the `PlayerJoinEvent`. If player is not in the `Set`, send `RequestClientLoginPacket` (S2C).
    * **Network Handlers:**
        * `onReceiveRequestLoginUrl`: (C2S) Receives `challenge` & `port`, uses config to build full URL, sends `LoginUrlPacket` (S2C).
        * `onReceiveVerifyAuth`: (C2S) Receives `jwt` & `verifier`.
    * **Validation (Nimbus):**
        * The `jwtProcessor` **must** be configured to use `JWSAlgorithm.ES256` (or `setOf(ES256, RS256)`) and a `RemoteJWKSet` pointing to the config's JWKS URL.
        * The processor **must** call `jwtProcessor.process(jwt, null)` to validate the signature, `iss`, `aud`, and `exp`.
        * Then, it **must** perform the PKCE check (`HASH(verifier)` vs `challenge` claim).
        * On success, add player UUID to the `authenticatedPlayers` set.
    * **Events:** Must hook `PlayerDisconnectEvent` to remove players from the `authenticatedPlayers` set.
    * **Fallback:** A `/beaconauth login` command **must** exist to manually trigger the `RequestClientLoginPacket` (S2C).