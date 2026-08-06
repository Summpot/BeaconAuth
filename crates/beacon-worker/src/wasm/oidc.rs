//! OpenID Connect Provider pieces for the BeaconAuth worker.
//!
//! Implements the minimal OIDC surface needed by the Minecraft mod client:
//!   - `/.well-known/openid-configuration`   (discovery)
//!   - `GET /v1/oidc/authorize`              (authorization endpoint)
//!   - `POST /v1/oidc/token`                 (token endpoint)
//!   - `GET /v1/oidc/userinfo`               (userinfo endpoint)
//!
//! The authorization code is a short-lived opaque value stored in the database
//! (via the same `passkey_states` table used for WebAuthn ceremonies, keyed
//! `oidc:auth:<code>`), which is consumed on first use at the token endpoint.
//! This is the standard OAuth2 authorization-code grant with PKCE (RFC 7636)
//! against a single statically-registered public client for the Minecraft mod.

use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use worker::{Env, Request, Response, Result};
use url::Url;

use beacon_core::models::{
    self, AuthCodeState, IdTokenClaims, OidcClient, OidcDiscovery, TokenErrorResponse,
    TokenResponse,
};
use sha2::{Digest, Sha256};

use crate::wasm::{
    db::{db_connect, db_put_passkey_state, db_take_passkey_state, db_user_by_id},
    env::env_string,
    http::{error_response, internal_error_response, json_with_cors},
    jwt::{sign_jwt, verify_oidc_access_token, verify_access_token},
    state::get_jwt_state,
    util::now_ts,
};

/// Statically registered OIDC client for the Minecraft mod.
///
/// This is a public client (no secret): the mod runs on the player's machine and
/// could be decompiled, so client authentication is impossible. PKCE is the only
/// proof of possession, per RFC 8252 §8.5.
pub const MINECRAFT_CLIENT_ID: &str = "beaconauth-mod";

/// Loopback redirect URIs for the mod's local callback server (RFC 8252 §7.3).
pub const LOOPBACK_REDIRECT_PREFIX: &str = "http://127.0.0.1:";

/// TTL for authorization codes (short, one-time use).
pub const AUTH_CODE_TTL_SECS: i64 = 60;
/// TTL for OIDC access tokens (used by userinfo).
pub const OIDC_ACCESS_TOKEN_TTL_SECS: i64 = 300;
/// TTL for ID tokens.
pub const ID_TOKEN_TTL_SECS: i64 = 300;

fn oidc_client(env: &Env) -> OidcClient {
    OidcClient {
        client_id: env_string(env, "OIDC_CLIENT_ID").unwrap_or_else(|| MINECRAFT_CLIENT_ID.to_string()),
        redirect_uri_prefix: env_string(env, "OIDC_REDIRECT_PREFIX")
            .unwrap_or_else(|| LOOPBACK_REDIRECT_PREFIX.to_string()),
    }
}

fn code_challenge_s256(verifier: &str) -> String {
    use base64::Engine;
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    // Simple constant-time comparison over UTF-8 bytes.
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate that `redirect_uri` is a loopback URI with a numeric port,
/// and matches the registered prefix (RFC 8252 §7.3).
fn is_loopback_redirect_uri(uri: &str, prefix: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
        return false;
    }
    let Some(port) = url.port() else {
        return false;
    };
    if !(1..=65535).contains(&port) {
        return false;
    }
    uri.starts_with(prefix)
}

/// GET /.well-known/openid-configuration
pub async fn handle_discovery(req: &Request, env: &Env) -> Result<Response> {
    let jwt = get_jwt_state(env).await?;
    let issuer = jwt.issuer.trim_end_matches('/').to_string();
    let base = format!("{issuer}/api/v1/oidc");

    let doc = OidcDiscovery {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        userinfo_endpoint: format!("{base}/userinfo"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        scopes_supported: vec!["openid".to_string()],
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["ES256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
    };

    let resp = Response::from_json(&doc)?;
    json_with_cors(req, resp)
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

fn redirect_error(redirect_uri: &str, state: Option<&str>, error: &str, description: &str) -> Result<Response> {
    let mut url = match Url::parse(redirect_uri) {
        Ok(mut u) => {
            u.query_pairs_mut().append_pair("error", error);
            if let Some(s) = state {
                u.query_pairs_mut().append_pair("state", s);
            }
            u
        }
        Err(_) => return Ok(Response::empty()?.with_status(400)),
    };
    url.query_pairs_mut().append_pair("error_description", description);
    Response::redirect(url)
}

/// GET /v1/oidc/authorize
///
/// Serves the login page when the user is not authenticated, or redirects back
/// with an authorization code when a session cookie is present. The mod opens
/// this URL in the browser; the loopback redirect carries `code` + `state`.
pub async fn handle_authorize(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let pairs: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    let query = AuthorizeQuery {
        response_type: pairs.get("response_type").cloned().unwrap_or_default(),
        client_id: pairs.get("client_id").cloned().unwrap_or_default(),
        redirect_uri: pairs.get("redirect_uri").cloned().unwrap_or_default(),
        scope: pairs.get("scope").cloned(),
        state: pairs.get("state").cloned(),
        code_challenge: pairs.get("code_challenge").cloned(),
        code_challenge_method: pairs.get("code_challenge_method").cloned(),
        nonce: pairs.get("nonce").cloned(),
    };

    // Standard parameter validation.
    if query.response_type != "code" {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "unsupported_response_type", "response_type must be 'code'");
    }
    let client = oidc_client(env);
    if query.client_id != client.client_id {
        return error_response(req, 400, "unauthorized_client", "Unknown client_id");
    }
    if !is_loopback_redirect_uri(&query.redirect_uri, &client.redirect_uri_prefix) {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_request", "redirect_uri must be a loopback URI (http://127.0.0.1:<port>)");
    }
    if !query.scope.as_deref().unwrap_or("").split_whitespace().any(|s| s == "openid") {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_scope", "scope must include 'openid'");
    }
    match query.code_challenge_method.as_deref() {
        Some("S256") | None => {}
        Some(m) => {
            return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_request", format!("unsupported code_challenge_method: {m}").as_str());
        }
    }
    let Some(challenge) = query.code_challenge.as_deref() else {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_request", "code_challenge is required (PKCE S256)");
    };
    if challenge.len() < 43 || challenge.len() > 128 {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_request", "code_challenge must be 43..128 characters");
    }
    let Some(nonce) = query.nonce.as_deref() else {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_request", "nonce is required");
    };
    if nonce.len() > 256 {
        return redirect_error(&query.redirect_uri, query.state.as_deref(), "invalid_request", "nonce too long");
    }

    // Require an authenticated session.
    let Some(access_token) = crate::wasm::cookies::get_cookie(req, "access_token")? else {
        // Not signed in: send the user to the login page, preserving the OIDC
        // request parameters so login can continue the flow.
        let mut login = Url::parse(&format!("{}/login", jwt_issuer(env).await?))?;
        login
            .query_pairs_mut()
            .append_pair("client_id", &query.client_id)
            .append_pair("redirect_uri", &query.redirect_uri)
            .append_pair("scope", query.scope.as_deref().unwrap_or("openid"))
            .append_pair("state", query.state.as_deref().unwrap_or(""))
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", nonce);
        return Response::redirect(login);
    };

    let jwt = get_jwt_state(env).await?;
    let user_id = match verify_access_token(&jwt, &access_token).await {
        Ok(id) => id,
        Err(_) => {
            // Expired/invalid session: treat as unauthenticated and route to login.
            let mut login = Url::parse(&format!("{}/login", jwt.issuer.trim_end_matches('/')))?;
            login
                .query_pairs_mut()
                .append_pair("client_id", &query.client_id)
                .append_pair("redirect_uri", &query.redirect_uri)
                .append_pair("scope", query.scope.as_deref().unwrap_or("openid"))
                .append_pair("state", query.state.as_deref().unwrap_or(""))
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("nonce", nonce);
            return Response::redirect(login);
        }
    };

    // Mint a one-time authorization code bound to user, nonce, PKCE challenge and redirect_uri.
    let code = uuid::Uuid::new_v4().to_string();
    let state = AuthCodeState {
        user_id,
        nonce: nonce.to_string(),
        code_challenge: challenge.to_string(),
        redirect_uri: query.redirect_uri.clone(),
        expires_at: now_ts() + AUTH_CODE_TTL_SECS,
    };

    let db = db_connect(env).await?;
    db_put_passkey_state(&db, &format!("oidc:auth:{code}"), &state, AUTH_CODE_TTL_SECS).await?;

    let mut redirect = Url::parse(&query.redirect_uri)?;
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(s) = query.state.as_deref() {
        redirect.query_pairs_mut().append_pair("state", s);
    }
    Response::redirect(redirect)
}

async fn jwt_issuer(env: &Env) -> Result<String> {
    let jwt = get_jwt_state(env).await?;
    Ok(jwt.issuer)
}

#[derive(Debug, Deserialize)]
pub struct CompleteRequest {
    pub redirect_uri: String,
    #[serde(default)]
    pub state: String,
    pub client_id: String,
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
    pub nonce: String,
}

/// POST /v1/oidc/complete
///
/// Called by the SPA after a successful login in the OIDC flow. Validates the
/// authenticated session and mints the authorization code, then 302-redirects
/// the browser to the mod's loopback callback with `code` + `state`.
///
/// This endpoint is equivalent to the `authorize` endpoint when the user is
/// already authenticated, but accepts the OIDC parameters in a POST body so
/// the SPA can keep the code out of server logs and browser history.
pub async fn handle_oidc_complete(mut req: Request, env: &Env) -> Result<Response> {
    let payload: CompleteRequest = match req.json().await {
        Ok(p) => p,
        Err(_) => return error_response(&req, 400, "invalid_request", "Malformed JSON body"),
    };

    let client = oidc_client(env);
    if payload.client_id != client.client_id {
        return error_response(&req, 400, "unauthorized_client", "Unknown client_id");
    }
    if !is_loopback_redirect_uri(&payload.redirect_uri, &client.redirect_uri_prefix) {
        return error_response(
            &req,
            400,
            "invalid_request",
            "redirect_uri must be a loopback URI (http://127.0.0.1:<port>)",
        );
    }
    if payload.code_challenge.len() < 43 || payload.code_challenge.len() > 128 {
        return error_response(&req, 400, "invalid_request", "code_challenge is required (PKCE S256)");
    }
    if payload.nonce.is_empty() || payload.nonce.len() > 256 {
        return error_response(&req, 400, "invalid_request", "nonce is required");
    }
    if !payload.code_challenge_method.is_empty() && payload.code_challenge_method != "S256" {
        return error_response(&req, 400, "invalid_request", "unsupported code_challenge_method");
    }

    let Some(access_token) = crate::wasm::cookies::get_cookie(&req, "access_token")? else {
        let resp = Response::from_json(&models::ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated. Please log in again.".to_string(),
        })?
        .with_status(401);
        return json_with_cors(&req, resp);
    };

    let jwt = get_jwt_state(env).await?;
    let user_id = match verify_access_token(&jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => {
            let resp = Response::from_json(&models::ErrorResponse {
                error: "unauthorized".to_string(),
                message: format!("Not authenticated. Please log in again. ({e})"),
            })?
            .with_status(401);
            return json_with_cors(&req, resp);
        }
    };

    // Mint a one-time authorization code bound to user, nonce, PKCE challenge and redirect_uri.
    let code = uuid::Uuid::new_v4().to_string();
    let state = AuthCodeState {
        user_id,
        nonce: payload.nonce.clone(),
        code_challenge: payload.code_challenge.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        expires_at: now_ts() + AUTH_CODE_TTL_SECS,
    };

    let db = db_connect(env).await?;
    db_put_passkey_state(&db, &format!("oidc:auth:{code}"), &state, AUTH_CODE_TTL_SECS).await?;

    let mut redirect = match Url::parse(&payload.redirect_uri) {
        Ok(u) => u,
        Err(_) => return error_response(&req, 400, "invalid_request", "Invalid redirect_uri"),
    };
    redirect.query_pairs_mut().append_pair("code", &code);
    if !payload.state.is_empty() {
        redirect.query_pairs_mut().append_pair("state", &payload.state);
    }
    Response::redirect(redirect)
}

/// POST /v1/oidc/token
///
/// `grant_type=authorization_code` + `code` + `redirect_uri` + `client_id` + `code_verifier`.
/// Consumes the authorization code, validates PKCE, and returns access_token + id_token.
pub async fn handle_token(mut req: Request, env: &Env) -> Result<Response> {
    let body = req.text().await?;
    let params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();

    let grant_type = params.get("grant_type").map(String::as_str).unwrap_or("");
    if grant_type != "authorization_code" {
        return token_error(req, "unsupported_grant_type", "Only authorization_code is supported");
    }
    let Some(code) = params.get("code") else {
        return token_error(req, "invalid_request", "Missing code");
    };
    let Some(redirect_uri) = params.get("redirect_uri") else {
        return token_error(req, "invalid_request", "Missing redirect_uri");
    };
    let client_id = params.get("client_id").map(String::as_str).unwrap_or("");
    let Some(verifier) = params.get("code_verifier") else {
        return token_error(req, "invalid_request", "Missing code_verifier");
    };

    let client = oidc_client(env);
    if client_id != client.client_id {
        return token_error(req, "invalid_client", "Unknown client_id");
    }
    if !is_loopback_redirect_uri(redirect_uri, &client.redirect_uri_prefix) {
        return token_error(req, "invalid_grant", "redirect_uri must be a loopback URI");
    }

    // Consume the code (one-time).
    let db = db_connect(env).await?;
    let state: Option<AuthCodeState> =
        db_take_passkey_state(&db, &format!("oidc:auth:{code}")).await?;
    let Some(state) = state else {
        return token_error(req, "invalid_grant", "Unknown, expired or already-used code");
    };
    if state.redirect_uri != *redirect_uri {
        return token_error(req, "invalid_grant", "redirect_uri does not match the authorization request");
    }

    // PKCE validation (RFC 7636 §4.6).
    let computed = code_challenge_s256(verifier);
    if !constant_time_eq(&computed, &state.code_challenge) {
        return token_error(req, "invalid_grant", "PKCE verification failed");
    }

    let jwt = get_jwt_state(env).await?;
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(ID_TOKEN_TTL_SECS);

    let claims = IdTokenClaims {
        iss: jwt.issuer.clone(),
        sub: state.user_id.clone(),
        aud: client.client_id.clone(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        auth_time: now.timestamp(),
        nonce: state.nonce.clone(),
        preferred_username: None,
    };
    let id_token = match sign_jwt(&jwt, &claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(&req, "Failed to sign id_token", &e),
    };

    // Short-lived access token for userinfo.
    let access_claims = models::SessionClaims {
        iss: jwt.issuer.clone(),
        sub: state.user_id.clone(),
        aud: "beaconauth-oidc".to_string(),
        exp: (now + chrono::Duration::seconds(OIDC_ACCESS_TOKEN_TTL_SECS)).timestamp(),
        token_type: "access".to_string(),
    };
    let access_token = match sign_jwt(&jwt, &access_claims) {
        Ok(t) => t,
        Err(e) => return internal_error_response(&req, "Failed to sign access token", &e),
    };

    let resp = Response::from_json(&TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: OIDC_ACCESS_TOKEN_TTL_SECS,
        id_token,
    })?;
    json_with_cors(&req, resp)
}

fn token_error(req: Request, error: &str, description: &str) -> Result<Response> {
    let resp = Response::from_json(&TokenErrorResponse {
        error: error.to_string(),
        error_description: Some(description.to_string()),
    })?
    .with_status(400);
    json_with_cors(&req, resp)
}

/// GET /v1/oidc/userinfo
///
/// Returns the canonical BeaconAuth username for the OIDC access token.
pub async fn handle_userinfo(req: &Request, env: &Env) -> Result<Response> {
    let Some(auth) = req.headers().get("Authorization")? else {
        let resp = Response::from_json(&json!({"error": "invalid_token"}))?.with_status(401);
        return json_with_cors(req, resp);
    };
    let token = auth.strip_prefix("Bearer ").unwrap_or(&auth).trim();
    if token.is_empty() {
        let resp = Response::from_json(&json!({"error": "invalid_token"}))?.with_status(401);
        return json_with_cors(req, resp);
    }

    let jwt = get_jwt_state(env).await?;
    let user_id = match verify_oidc_access_token(&jwt, token).await {
        Ok(id) => id,
        Err(_) => {
            let resp = Response::from_json(&json!({"error": "invalid_token"}))?.with_status(401);
            return json_with_cors(req, resp);
        }
    };

    let db = db_connect(env).await?;
    let Some(user) = db_user_by_id(&db, &user_id).await? else {
        let resp = Response::from_json(&json!({"error": "invalid_token"}))?.with_status(401);
        return json_with_cors(req, resp);
    };

    let resp = Response::from_json(&json!({
        "sub": user.id,
        "preferred_username": user.username,
    }))?;
    json_with_cors(req, resp)
}
