//! OpenID Connect Provider endpoints for the standalone (actix) server.
//!
//! Mirrors the Cloudflare Worker OIDC surface:
//!   - `/.well-known/openid-configuration`
//!   - `GET /v1/oidc/authorize`
//!   - `POST /v1/oidc/token`
//!   - `GET /v1/oidc/userinfo`
//!
//! Authorization codes are stored in the `passkey_states` table (one-time, short TTL),
//! shared with the WebAuthn ceremony state.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use base64::Engine;
use chrono::Utc;
use entity::passkey_state;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use beacon_core::models::{
    AuthCodeState, IdTokenClaims, OidcClient, OidcDiscovery, SessionClaims, TokenErrorResponse,
    TokenResponse,
};

use crate::{app_state::AppState, models::ErrorResponse};

pub const MINECRAFT_CLIENT_ID: &str = "beaconauth-mod";
pub const LOOPBACK_REDIRECT_PREFIX: &str = "http://127.0.0.1:";
const AUTH_CODE_TTL_SECS: i64 = 60;
const OIDC_ACCESS_TOKEN_TTL_SECS: i64 = 300;
const ID_TOKEN_TTL_SECS: i64 = 300;

fn oidc_client() -> OidcClient {
    OidcClient {
        client_id: MINECRAFT_CLIENT_ID.to_string(),
        redirect_uri_prefix: LOOPBACK_REDIRECT_PREFIX.to_string(),
    }
}

fn code_challenge_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
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
pub async fn discovery(app_state: web::Data<AppState>) -> impl Responder {
    let issuer = app_state.oauth_config.redirect_base.trim_end_matches('/').to_string();
    let base = format!("{issuer}/api/v1/oidc");

    HttpResponse::Ok().json(OidcDiscovery {
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
    })
}

fn redirect_error(redirect_uri: &str, state: Option<&str>, error: &str, description: &str) -> HttpResponse {
    let mut url = match Url::parse(redirect_uri) {
        Ok(mut u) => {
            u.query_pairs_mut().append_pair("error", error);
            if let Some(s) = state {
                u.query_pairs_mut().append_pair("state", s);
            }
            u
        }
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    url.query_pairs_mut().append_pair("error_description", description);
    HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, url.to_string()))
        .finish()
}

fn login_redirect(
    app_state: &AppState,
    query: &std::collections::HashMap<String, String>,
) -> HttpResponse {
    let issuer = app_state.oauth_config.redirect_base.trim_end_matches('/');
    let mut login = Url::parse(&format!("{issuer}/login")).unwrap();
    login
        .query_pairs_mut()
        .append_pair("oidc", "1")
        .append_pair("client_id", query.get("client_id").map(String::as_str).unwrap_or(""))
        .append_pair("redirect_uri", query.get("redirect_uri").map(String::as_str).unwrap_or(""))
        .append_pair("scope", query.get("scope").map(String::as_str).unwrap_or("openid"))
        .append_pair("state", query.get("state").map(String::as_str).unwrap_or(""))
        .append_pair("code_challenge", query.get("code_challenge").map(String::as_str).unwrap_or(""))
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", query.get("nonce").map(String::as_str).unwrap_or(""));
    HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, login.to_string()))
        .finish()
}

/// GET /v1/oidc/authorize
pub async fn authorize(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    web::Query(params): web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let query = params.clone();

    if query.get("response_type").map(String::as_str) != Some("code") {
        return redirect_error(
            query.get("redirect_uri").map(String::as_str).unwrap_or(""),
            query.get("state").map(String::as_str),
            "unsupported_response_type",
            "response_type must be 'code'",
        );
    }
    let client = oidc_client();
    if query.get("client_id").map(String::as_str) != Some(client.client_id.as_str()) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "unauthorized_client".to_string(),
            message: "Unknown client_id".to_string(),
        });
    }
    let redirect_uri = query.get("redirect_uri").map(String::as_str).unwrap_or("");
    if !is_loopback_redirect_uri(redirect_uri, &client.redirect_uri_prefix) {
        return redirect_error(
            redirect_uri,
            query.get("state").map(String::as_str),
            "invalid_request",
            "redirect_uri must be a loopback URI (http://127.0.0.1:<port>)",
        );
    }
    let scope = query.get("scope").map(String::as_str).unwrap_or("");
    if !scope.split_whitespace().any(|s| s == "openid") {
        return redirect_error(redirect_uri, query.get("state").map(String::as_str), "invalid_scope", "scope must include 'openid'");
    }
    match query.get("code_challenge_method").map(String::as_str) {
        Some("S256") | None => {}
        Some(m) => {
            return redirect_error(redirect_uri, query.get("state").map(String::as_str), "invalid_request", &format!("unsupported code_challenge_method: {m}"));
        }
    }
    let challenge = query.get("code_challenge").map(String::as_str).unwrap_or("");
    if challenge.len() < 43 || challenge.len() > 128 {
        return redirect_error(redirect_uri, query.get("state").map(String::as_str), "invalid_request", "code_challenge is required (PKCE S256)");
    }
    let nonce = query.get("nonce").map(String::as_str).unwrap_or("");
    if nonce.is_empty() || nonce.len() > 256 {
        return redirect_error(redirect_uri, query.get("state").map(String::as_str), "invalid_request", "nonce is required");
    }

    // Require an authenticated session.
    let access_token = match req.cookie("access_token") {
        Some(c) => c.value().to_string(),
        None => return login_redirect(&app_state, &query),
    };
    let user_id = match super::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(_) => return login_redirect(&app_state, &query),
    };

    // Mint a one-time authorization code.
    let code = Uuid::new_v4().to_string();
    let state = AuthCodeState {
        user_id,
        nonce: nonce.to_string(),
        code_challenge: challenge.to_string(),
        redirect_uri: redirect_uri.to_string(),
        expires_at: Utc::now().timestamp() + AUTH_CODE_TTL_SECS,
    };

    let now = Utc::now().timestamp();
    let model = passkey_state::ActiveModel {
        key: Set(format!("oidc:auth:{code}")),
        state_json: Set(serde_json::to_string(&state).unwrap_or_default()),
        expires_at: Set(now + AUTH_CODE_TTL_SECS),
        created_at: Set(now),
        ..Default::default()
    };
    if let Err(e) = model.insert(&app_state.db).await {
        log::error!("Failed to persist OIDC auth code: {e}");
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Failed to persist authorization code".to_string(),
        });
    }

    let mut redirect = Url::parse(redirect_uri).unwrap();
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(s) = query.get("state") {
        redirect.query_pairs_mut().append_pair("state", s);
    }
    HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, redirect.to_string()))
        .finish()
}

/// POST /v1/oidc/token
pub async fn token(
    app_state: web::Data<AppState>,
    body: web::Form<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let params = body.into_inner();

    let grant_type = params.get("grant_type").map(String::as_str).unwrap_or("");
    if grant_type != "authorization_code" {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: Some("Only authorization_code is supported".to_string()),
        });
    }
    let Some(code) = params.get("code") else {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: Some("Missing code".to_string()),
        });
    };
    let Some(redirect_uri) = params.get("redirect_uri") else {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: Some("Missing redirect_uri".to_string()),
        });
    };
    let client_id = params.get("client_id").map(String::as_str).unwrap_or("");
    let Some(verifier) = params.get("code_verifier") else {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: Some("Missing code_verifier".to_string()),
        });
    };

    let client = oidc_client();
    if client_id != client.client_id {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_client".to_string(),
            error_description: Some("Unknown client_id".to_string()),
        });
    }
    if !is_loopback_redirect_uri(redirect_uri, &client.redirect_uri_prefix) {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("redirect_uri must be a loopback URI".to_string()),
        });
    }

    // Consume the code (one-time).
    let key = format!("oidc:auth:{code}");
    let row = match passkey_state::Entity::find_by_id(key.clone()).one(&app_state.db).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return HttpResponse::BadRequest().json(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Unknown, expired or already-used code".to_string()),
            });
        }
        Err(e) => {
            log::error!("Failed to load OIDC auth code: {e}");
            return HttpResponse::InternalServerError().json(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Database error".to_string()),
            });
        }
    };
    let _ = passkey_state::Entity::delete_by_id(key).exec(&app_state.db).await;

    if row.expires_at <= Utc::now().timestamp() {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("Code expired".to_string()),
        });
    }
    let state: AuthCodeState = match serde_json::from_str(&row.state_json) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Invalid OIDC auth code payload: {e}");
            return HttpResponse::InternalServerError().json(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Invalid stored state".to_string()),
            });
        }
    };
    if state.redirect_uri != *redirect_uri {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("redirect_uri does not match the authorization request".to_string()),
        });
    }
    let computed = code_challenge_s256(verifier);
    if !constant_time_eq(&computed, &state.code_challenge) {
        return HttpResponse::BadRequest().json(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("PKCE verification failed".to_string()),
        });
    }

    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(ID_TOKEN_TTL_SECS);
    let id_claims = IdTokenClaims {
        iss: app_state.oauth_config.redirect_base.clone(),
        sub: state.user_id.clone(),
        aud: client.client_id.clone(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        auth_time: now.timestamp(),
        nonce: state.nonce.clone(),
        preferred_username: None,
    };
    let id_token = match super::auth::generate_jwt(&app_state, &id_claims) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to sign id_token: {e}");
            return HttpResponse::InternalServerError().json(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Failed to sign id_token".to_string()),
            });
        }
    };

    let access_claims = SessionClaims {
        iss: app_state.oauth_config.redirect_base.clone(),
        sub: state.user_id.clone(),
        aud: "beaconauth-oidc".to_string(),
        exp: (now + chrono::Duration::seconds(OIDC_ACCESS_TOKEN_TTL_SECS)).timestamp(),
        token_type: "access".to_string(),
    };
    let access_token = match super::auth::generate_jwt(&app_state, &access_claims) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to sign OIDC access token: {e}");
            return HttpResponse::InternalServerError().json(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Failed to sign access token".to_string()),
            });
        }
    };

    HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: OIDC_ACCESS_TOKEN_TTL_SECS,
        id_token,
    })
}

/// POST /v1/oidc/complete
///
/// Called by the SPA after a successful login in the OIDC flow. Validates the
/// authenticated session and mints the authorization code, then 302-redirects
/// the browser to the mod's loopback callback with `code` + `state`.
#[derive(serde::Deserialize)]
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

pub async fn complete(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<CompleteRequest>,
) -> impl Responder {
    let client = oidc_client();
    if payload.client_id != client.client_id {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "unauthorized_client".to_string(),
            message: "Unknown client_id".to_string(),
        });
    }
    if !is_loopback_redirect_uri(&payload.redirect_uri, &client.redirect_uri_prefix) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "redirect_uri must be a loopback URI (http://127.0.0.1:<port>)".to_string(),
        });
    }
    if payload.code_challenge.len() < 43 || payload.code_challenge.len() > 128 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "code_challenge is required (PKCE S256)".to_string(),
        });
    }
    if payload.nonce.is_empty() || payload.nonce.len() > 256 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "nonce is required".to_string(),
        });
    }
    if !payload.code_challenge_method.is_empty() && payload.code_challenge_method != "S256" {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "unsupported code_challenge_method".to_string(),
        });
    }

    let Some(access_token) = req.cookie("access_token").map(|c| c.value().to_string()) else {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Not authenticated. Please log in again.".to_string(),
        });
    };
    let user_id = match super::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            log::warn!("Invalid access token for oidc/complete: {}", e);
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated. Please log in again.".to_string(),
            });
        }
    };

    let code = Uuid::new_v4().to_string();
    let state = AuthCodeState {
        user_id,
        nonce: payload.nonce.clone(),
        code_challenge: payload.code_challenge.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        expires_at: Utc::now().timestamp() + AUTH_CODE_TTL_SECS,
    };

    let now = Utc::now().timestamp();
    let model = passkey_state::ActiveModel {
        key: Set(format!("oidc:auth:{code}")),
        state_json: Set(serde_json::to_string(&state).unwrap_or_default()),
        expires_at: Set(now + AUTH_CODE_TTL_SECS),
        created_at: Set(now),
        ..Default::default()
    };
    if let Err(e) = model.insert(&app_state.db).await {
        log::error!("Failed to persist OIDC auth code: {e}");
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Failed to persist authorization code".to_string(),
        });
    }

    let mut redirect = Url::parse(&payload.redirect_uri).unwrap();
    redirect.query_pairs_mut().append_pair("code", &code);
    if !payload.state.is_empty() {
        redirect.query_pairs_mut().append_pair("state", &payload.state);
    }
    HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, redirect.to_string()))
        .finish()
}

/// GET /v1/oidc/userinfo
pub async fn userinfo(app_state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some(auth) = req.headers().get(actix_web::http::header::AUTHORIZATION) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid_token"}));
    };
    let auth = auth.to_str().unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    if token.is_empty() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid_token"}));
    }
    let user_id = match super::auth::verify_oidc_access_token(&app_state, token) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid_token"})),
    };

    use entity::user;
    match user::Entity::find_by_id(user_id.clone()).one(&app_state.db).await {
        Ok(Some(u)) => HttpResponse::Ok().json(serde_json::json!({
            "sub": u.id,
            "preferred_username": u.username,
        })),
        Ok(None) => HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid_token"})),
        Err(e) => {
            log::error!("userinfo DB error: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "server_error"}))
        }
    }
}
