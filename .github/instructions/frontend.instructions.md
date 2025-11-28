# Frontend Instructions (React/Rsbuild)

> **Applies to:** Root directory - `src/`, `package.json`, `rsbuild.config.ts`

## Tech Stack

* **Framework:** React (Hooks)
* **Build Tool:** Rsbuild
* **Package Manager:** `pnpm` (run from project root)
* **Styling:** Tailwind CSS
* **Routing:** `@tanstack/react-router`
* **Server State:** `@tanstack/react-query`
* **Forms:** `react-hook-form`
* **WebAuthn:** `@simplewebauthn/browser`

## Dependency Management

Always use `pnpm add <package-name>` from the **root** directory.

## Data Fetching

* **`@tanstack/react-query`** is used for server state management.
* The `QueryClient` is configured in `__root.tsx` with appropriate defaults (1-minute stale time, refetchOnWindowFocus disabled).

## API Utilities (`src/utils/api.ts`)

* `fetchWithAuth()` - Fetch wrapper for automatic token refresh on 401 responses. **ALL** authenticated API calls **MUST** use `fetchWithAuth()` instead of plain `fetch()`.
* `fetchJsonWithAuth()` - Type-safe JSON wrapper that throws `ApiError` for better error handling with TanStack Query.
* `queryKeys` - Query key factory for consistent cache key management (e.g., `queryKeys.userMe()`, `queryKeys.passkeys()`).
* `fetchWithAuth()` automatically calls `POST /api/v1/refresh` on 401, retries the original request, and redirects to `/` if refresh fails.

## Routing & State

**`@tanstack/react-router`** is the *only* tool for routing and URL search parameter management.

### Routes Overview

| Route | Description | Auth Required |
|-------|-------------|---------------|
| `/` | Home page (dashboard) | No |
| `/login` | Login page with optional `challenge` and `redirect_port` params | No |
| `/register` | Registration page | No |
| `/profile` | User profile page | Yes |
| `/settings` | Profile settings (password, passkeys) | Yes |
| `/oauth-complete` | OAuth callback processing page | No |

### Login Route Parameters

* The login route (`/login`) has **optional** `challenge` and `redirect_port` params (used for Minecraft mode).
* Non-Minecraft web login works without these params.
* The component **MUST** use the `useSearch()` hook to retrieve these values.

## Forms

* **`react-hook-form`** must be used for login and registration forms.

## Styling

* **Tailwind CSS** must be used for all styling.

## Configuration Fetching

On component mount, the login page **MUST** fetch `GET /api/v1/config` to determine which auth providers are available.

Response: `{ database_auth: boolean, github_oauth: boolean, google_oauth: boolean }`

## Conditional UI Rendering

* **Challenge/Port info box**: Only shown if `challenge` and `redirect_port` params are present (Minecraft mode).
* **Database login form**: Only shown if `config.database_auth === true`.
* **OAuth buttons**: Only shown if `config.github_oauth === true` or `config.google_oauth === true`.
* **"Or continue with" divider**: Only shown if both database auth and at least one OAuth provider are enabled.
* **Register link**: Only shown if `config.database_auth === true`.

## Login Flow (Standard)

1. Get `username`, `password` from `react-hook-form` and `challenge`, `redirect_port` from `useSearch()`.
2. **Step 1**: `fetch` (NOT `fetchWithAuth`) `POST /api/v1/login` with `{ username, password }` and `credentials: 'include'`. This sets `HttpOnly` session cookies.
3. **Step 2 (Minecraft mode)**: If `challenge` and `redirect_port` exist, call `fetchWithAuth` `POST /api/v1/minecraft-jwt` with `{ challenge, redirect_port, profile_url }`. The `profile_url` is `window.location.origin + '/profile'`. On success, execute `window.location.href = data.redirectUrl;`.
4. **Step 2 (Web mode)**: If no challenge/redirect_port, redirect to `/` home page.
5. **Auto-Login**: On mount, if `challenge` and `redirect_port` exist, check for valid session by calling `fetchWithAuth` `POST /api/v1/minecraft-jwt`. If successful, auto-redirect immediately.

## Login Flow (OAuth)

1. Get `challenge` and `redirect_port` from `useSearch()` (may be undefined for web-only OAuth).
2. If challenge/redirect_port exist, save to `sessionStorage` with keys `minecraft_challenge` and `minecraft_redirect_port`. Otherwise, clear these keys.
3. `fetch` (NOT `fetchWithAuth`) `POST /api/v1/oauth/start` with `{ provider, challenge: challenge || '', redirect_port: redirect_port || 0 }`.
4. On 200 OK, parse the `{"authorizationUrl": "..."}` JSON response.
5. Execute `window.location.href = data.authorizationUrl;` to redirect to the OAuth provider.

### OAuth Callback Flow

1. The backend `/api/v1/oauth/callback` endpoint sets session cookies and redirects to `/oauth-complete`.
2. The `/oauth-complete` page retrieves `challenge` and `redirect_port` from `sessionStorage`.
3. **Minecraft mode**: Calls `fetchWithAuth` `POST /api/v1/minecraft-jwt`, cleans up sessionStorage, redirects to Minecraft via `redirectUrl`.
4. **Web mode**: Cleans up sessionStorage, redirects to `/` home page.

## Registration Flow

1. `fetch` (NOT `fetchWithAuth`) `POST /api/v1/register` with `{ username, password }`.
2. On 201 Created, session cookies are automatically set.
3. If challenge/redirect_port exist, call `fetchWithAuth` `POST /api/v1/minecraft-jwt` and redirect via `redirectUrl`.

## Passkey Registration

* Use `@simplewebauthn/browser`'s `startRegistration()` function to handle WebAuthn ceremony.
* **CRITICAL**: Pass `data.creation_options.publicKey` to `startRegistration()`, NOT `data.creation_options`. The response has a nested structure: `{ creation_options: { publicKey: {...} } }`.
* The `startRegistration()` function automatically handles all base64url ↔ ArrayBuffer conversions.
