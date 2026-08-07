//! Minecraft identity endpoints (Cloudflare Worker).
//!
//! Mirrors the native server's `handlers::minecraft`:
//! - `GET /api/v1/minecraft/lookup?uuid=U` — mod-facing lookup, gated by the shared secret.
//! - `GET /api/v1/minecraft/identity-mode` — user's effective identity preference.
//! - `POST /api/v1/minecraft/identity-mode` — set the per-user identity preference.

use beacon_core::models::{
    MinecraftIdentityModeResponse, MinecraftLookupResponse, SetMinecraftIdentityModeRequest,
    SetMinecraftIdentityModeResponse,
};
use worker::{Env, Request, Response, Result};

use crate::wasm::{
    cookies::get_cookie,
    db::{
        db_connect, db_identity_by_provider_user_id, db_user_by_id, db_update_user_identity_mode,
    },
    env::env_string,
    http::{error_response, internal_error_response, json_with_cors},
    jwt::verify_access_token,
    state::get_jwt_state,
    util::query_param,
};

/// Constant-time byte comparison for the shared lookup secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn effective_default_mode(env: &Env) -> &'static str {
    match env_string(env, "MINECRAFT_IDENTITY_MODE")
        .unwrap_or_else(|| "mojang".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "legacy" => "legacy",
        _ => "mojang",
    }
}

fn resolve_identity_mode(env: &Env, user: &crate::wasm::db::UserRow) -> &'static str {
    match user.identity_mode.as_deref() {
        Some("legacy") => "legacy",
        Some("mojang") => "mojang",
        _ => effective_default_mode(env),
    }
}

pub async fn handle_minecraft_lookup(req: &Request, env: &Env) -> Result<Response> {
    // Shared-secret gate.
    let Some(expected) = env_string(env, "MINECRAFT_LOOKUP_SECRET") else {
        return error_response(
            req,
            503,
            "lookup_disabled",
            "MINECRAFT_LOOKUP_SECRET is not configured",
        );
    };
    let provided = req.headers().get("X-Minecraft-Auth")?.unwrap_or_default();
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return error_response(req, 401, "unauthorized", "Invalid lookup secret");
    }

    let url = req.url()?;
    let Some(uuid) = query_param(&url, "uuid") else {
        return error_response(req, 400, "missing_uuid", "uuid query parameter is required");
    };
    let uuid = uuid.trim().to_string();
    if uuid.is_empty() {
        return error_response(req, 400, "missing_uuid", "uuid query parameter is required");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };

    let identity_row = match db_identity_by_provider_user_id(&db, "minecraft", &uuid).await {
        Ok(v) => v,
        Err(e) => return internal_error_response(req, "Failed to query identity", &e),
    };
    let Some(identity_row) = identity_row else {
        let resp = Response::from_json(&MinecraftLookupResponse {
            bound: false,
            identity_mode: None,
            user_subject: None,
            textures_value: None,
            textures_signature: None,
        })?;
        return json_with_cors(req, resp);
    };

    let user_row = match db_user_by_id(&db, &identity_row.user_id).await {
        Ok(v) => v,
        Err(e) => return internal_error_response(req, "Failed to load user", &e),
    };
    let Some(user_row) = user_row else {
        return internal_error_response(req, "Linked user not found", &"user missing");
    };

    let resp = Response::from_json(&MinecraftLookupResponse {
        bound: true,
        identity_mode: Some(resolve_identity_mode(env, &user_row).to_string()),
        user_subject: Some(user_row.id.clone()),
        textures_value: user_row.minecraft_textures_value.clone(),
        textures_signature: user_row.minecraft_textures_signature.clone(),
    })?;
    json_with_cors(req, resp)
}

pub async fn handle_get_identity_mode(req: &Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open database binding", &e),
    };
    let jwt = match get_jwt_state(env).await {
        Ok(jwt) => jwt,
        Err(e) => return internal_error_response(req, "Failed to initialize JWT state", &e),
    };

    let Some(access_token) = get_cookie(req, "access_token")? else {
        return error_response(req, 401, "unauthorized", "Not authenticated");
    };
    let user_id = match verify_access_token(&jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => return error_response(req, 401, "invalid_token", e),
    };

    let Some(user_row) = db_user_by_id(&db, &user_id).await? else {
        return error_response(req, 404, "user_not_found", "User not found");
    };

    let resp = Response::from_json(&MinecraftIdentityModeResponse {
        mode: resolve_identity_mode(env, &user_row).to_string(),
    })?;
    json_with_cors(req, resp)
}

pub async fn handle_set_identity_mode(mut req: Request, env: &Env) -> Result<Response> {
    let payload: SetMinecraftIdentityModeRequest = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in /v1/minecraft/identity-mode: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let mode = payload.mode.trim().to_ascii_lowercase();
    let mode = match mode.as_str() {
        "legacy" => "legacy",
        "mojang" => "mojang",
        _ => return error_response(&req, 400, "invalid_mode", "mode must be 'mojang' or 'legacy'"),
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open database binding", &e),
    };
    let jwt = match get_jwt_state(env).await {
        Ok(jwt) => jwt,
        Err(e) => return internal_error_response(&req, "Failed to initialize JWT state", &e),
    };

    let Some(access_token) = get_cookie(&req, "access_token")? else {
        return error_response(&req, 401, "unauthorized", "Not authenticated");
    };
    let user_id = match verify_access_token(&jwt, &access_token).await {
        Ok(id) => id,
        Err(e) => return error_response(&req, 401, "invalid_token", e),
    };

    let Some(user_row) = db_user_by_id(&db, &user_id).await? else {
        return error_response(&req, 404, "user_not_found", "User not found");
    };
    if user_row.identity_mode.as_deref() != Some(mode) {
        if let Err(e) = db_update_user_identity_mode(&db, &user_id, mode).await {
            return internal_error_response(&req, "Failed to update identity mode", &e);
        }
    }

    let resp = Response::from_json(&SetMinecraftIdentityModeResponse { success: true })?;
    json_with_cors(&req, resp)
}
