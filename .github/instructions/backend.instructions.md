# Backend Instructions (Rust/Actix-web)

> **Applies to:** Root directory - `crates/`, `Cargo.toml`

## Tech Stack

* **Language:** Rust
* **Web Framework:** Actix-web
* **ORM:** Sea-ORM
* **JWT:** `jsonwebtoken`, `p256`, `ecdsa`
* **CLI:** `clap`
* **Static Serving:** `rust-embed`, `actix-files`
* **Utilities:** `which`, `reqwest`, `bcrypt`
* **WebAuthn:** `webauthn-rs`

## Project Structure

This is a **virtual Cargo workspace** defined in the **root `Cargo.toml`**. All Rust code lives in the `crates/` directory:

| Crate | Description |
|-------|-------------|
| `crates/beacon/` | Main auth server binary (`beacon`) |
| `crates/entity/` | Sea-ORM entity definitions |
| `crates/migration/` | Database migration definitions |

## Dependency Management

Always use `cargo add -p <crate-name>` (or `--build -p`) from the **root** directory to add dependencies to the correct workspace crate.

## Database Schema Conventions

* **Table names MUST use plural form** (e.g., `users`, `passkeys`, `refresh_tokens`).
* Entity structs use singular names (e.g., `User`, `Passkey`, `RefreshToken`) but map to plural table names.
* All timestamps should use `chrono::DateTime<Utc>` and be named with `_at` suffix (e.g., `created_at`, `updated_at`).

## Database Migrations (CRITICAL)

* **Always assume migrations have been applied successfully** unless the error specifically indicates a migration failure.
* **Do NOT manually run migrations** (e.g., `cargo run -- migrate`) during development or debugging, unless you are explicitly testing the migration system itself.
* The application **automatically runs migrations on startup** via `migration::Migrator::up(&db, None)` in the `serve` command.
* If database errors occur, investigate the **schema definition** (entities and migrations) rather than attempting to re-run migrations.

## Application CLI

The `beacon` crate is a **CLI application** using `clap`. The `main` function parses commands:

| Command | Description |
|---------|-------------|
| `serve` | Start the HTTP server |
| `migrate` | Run database migrations |
| `create-user` | Create a new user |
| `list-users` | List all users |
| `delete-user` | Delete a user |

## Build Script (`crates/beacon/build.rs`)

* **MUST** have a `[build-dependencies]` section that includes `which`.
* **MUST** use `which::which("pnpm")` to find the full path to `pnpm` (or `pnpm.cmd`) to ensure Windows compatibility.
* **MUST** execute `pnpm build` in the **root directory** (`../../`) before the Rust build proceeds.

## Serve Command Logic

### Cryptography

* All JWTs **MUST** be signed using **`ES256`** (Elliptic Curve, P-256).
* `ES256` keys must be generated on startup using `p256` crate.
* **DecodingKey Creation:** The `DecodingKey` for JWT verification **MUST** be created using `DecodingKey::from_ec_components(x, y)` with base64url-encoded x and y coordinates.
* **DO NOT** use `DecodingKey::from_ec_der()` with SPKI format as `jsonwebtoken`'s `rust_crypto` backend expects PKCS#8 format which is incompatible.

### JWKS Endpoint

The `/.well-known/jwks.json` endpoint **MUST** serve the `ES256` public key in `kty: "EC"`, `crv: "P-256"` format.

### Static Serving (Dual Mode)

* **Debug (`cfg(debug_assertions)`)**: Serve files from the `dist/` directory using `actix-files`, with a SPA fallback to `dist/index.html`.
* **Release (`cfg(not(debug_assertions)`)**: Serve files from memory using `rust-embed` and `rust-embed-actix-web`.

## Configuration

* **`--base-url` / `BASE_URL`**: Single unified URL parameter (default: `http://localhost:8080`) used for:
    * OAuth redirect callbacks
    * JWT issuer (`iss`) claim
    * WebAuthn Relying Party origin

## API Endpoints

### Public Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/config` | GET | Returns available auth providers |
| `/api/v1/login` | POST | User login with username/password |
| `/api/v1/register` | POST | User registration |
| `/api/v1/refresh` | POST | Refresh access token |
| `/api/v1/oauth/start` | POST | Start OAuth flow |
| `/api/v1/oauth/callback` | GET | OAuth callback handler |
| `/api/v1/passkey/auth/start` | POST | Start passkey authentication |
| `/api/v1/passkey/auth/finish` | POST | Complete passkey authentication |

### Authenticated Endpoints (Require `access_token` cookie)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/minecraft-jwt` | POST | Generate Minecraft JWT |
| `/api/v1/user/me` | GET | Get current user info |
| `/api/v1/user/change-password` | POST | Change user password |
| `/api/v1/logout` | POST | Logout user |
| `/api/v1/passkey/register/start` | POST | Start passkey registration |
| `/api/v1/passkey/register/finish` | POST | Complete passkey registration |
| `/api/v1/passkey/list` | GET | List user's passkeys |
| `/api/v1/passkey/{id}` | DELETE | Delete a passkey |

### Endpoint Details

#### `POST /api/v1/login`
* Receives JSON `{ username, password }`.
* Verifies password (`bcrypt`).
* Creates `access_token` (ES256 JWT, 15 min expiry) and `refresh_token` (random SHA-256 hashed, stored in DB with family_id for rotation tracking, 30 day expiry).
* Sets `HttpOnly` cookies.
* Returns `{ "success": true }`.

#### `POST /api/v1/register`
* Receives JSON `{ username, password }`.
* Validates input (min 6 chars password).
* Hashes password with bcrypt, creates user in Sea-ORM.
* Auto-logs in user by creating session tokens and setting cookies.
* Returns 201 Created with `{ "success": true }`.

#### `POST /api/v1/refresh`
* Receives `refresh_token` from cookie.
* Validates refresh token from database by SHA-256 hash lookup.
* Checks expiration and revocation.
* **Implements token rotation**: revokes old refresh token and generates new token pair with same `family_id`.
* Returns new tokens as cookies.

#### `POST /api/v1/minecraft-jwt`
* **[Authenticated]**
* Receives JSON `{ challenge, redirect_port, profile_url }`.
* Verifies `access_token` cookie using proper ES256 signature verification.
* Creates Minecraft-specific `ES256` JWT with `challenge` claim (audience: `minecraft-client`, 1 hour expiry).
* Returns `{ "redirectUrl": "http://localhost:{port}/auth-callback?jwt={token}&profile_url={encoded_url}" }`.

#### `POST /api/v1/passkey/auth/start`
* Receives optional `{ username }`.
* Starts passkey authentication.
* Returns `{ "request_options": RequestChallengeResponse }`.
* Stores auth state in moka cache (5-min TTL, keyed by **base64url-encoded** (no padding) challenge).
* **CRITICAL**: Must use `BASE64URL` encoder, not `BASE64`, to match WebAuthn client format.

#### `POST /api/v1/passkey/auth/finish`
* Receives `{ credential }`.
* **CRITICAL**: The challenge must be extracted from `client_data_json` by first decoding it as UTF-8, parsing as JSON, then accessing the `challenge` field.
* Completes passkey auth, updates credential counter and last_used_at.
* Creates session tokens and returns them as cookies.
* Returns `{ "success": true, "username": str }`.

## Token Verification

* Access tokens are verified using `jsonwebtoken::decode()` with proper ES256 signature verification.
* Validation checks: issuer (must match `base_url`), audience (`beaconauth-web`), expiration, and token type (`access`).
* The `verify_access_token()` helper function in `handlers/auth.rs` handles this verification.
