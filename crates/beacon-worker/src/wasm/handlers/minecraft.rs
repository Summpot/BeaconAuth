use beacon_core::minecraft::verify_minecraft_link_token;
use beacon_core::models::{
    self, ConfirmMinecraftLinkRequest, SetMinecraftIdentityModeRequest,
    VerifyMinecraftTicketRequest, VerifyMinecraftTicketResponse,
};
use worker::{Env, Request, Response, Result};

use crate::wasm::{
    cookies::get_cookie,
    db::{
        db_connect, db_delete_identity_by_id, db_identities_by_user_id,
        db_identity_by_provider_user_id, db_insert_identity, db_update_user_identity_mode,
        db_user_by_id,
    },
    env::env_string,
    http::{error_response, internal_error_response, json_with_cors},
    jwt::verify_access_token,
    state::get_jwt_state,
};

pub async fn handle_minecraft_link_verify(mut req: Request, env: &Env) -> Result<Response> {
    let payload: VerifyMinecraftTicketRequest = match req.json().await {
        Ok(p) => p,
        Err(_) => return error_response(&req, 400, "invalid_request", "Malformed JSON body"),
    };

    let secret = match env_string(env, "MINECRAFT_LINK_SECRET") {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return error_response(
                &req,
                400,
                "not_configured",
                "Minecraft link secret is not configured on the server",
            );
        }
    };

    let claims = match verify_minecraft_link_token(&payload.token, &secret) {
        Ok(c) => c,
        Err(e) => {
            return error_response(
                &req,
                400,
                "invalid_ticket",
                format!("Invalid or expired Minecraft link ticket: {}", e),
            );
        }
    };

    let resp = Response::from_json(&VerifyMinecraftTicketResponse {
        uuid: claims.uuid,
        username: claims.name,
        expires_at: claims.exp,
    })?;
    json_with_cors(&req, resp)
}

pub async fn handle_minecraft_link_confirm(mut req: Request, env: &Env) -> Result<Response> {
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

    let payload: ConfirmMinecraftLinkRequest = match req.json().await {
        Ok(p) => p,
        Err(_) => return error_response(&req, 400, "invalid_request", "Malformed JSON body"),
    };

    let secret = match env_string(env, "MINECRAFT_LINK_SECRET") {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return error_response(
                &req,
                400,
                "not_configured",
                "Minecraft link secret is not configured on the server",
            );
        }
    };

    let claims = match verify_minecraft_link_token(&payload.token, &secret) {
        Ok(c) => c,
        Err(e) => {
            return error_response(
                &req,
                400,
                "invalid_ticket",
                format!("Invalid or expired Minecraft link ticket: {}", e),
            );
        }
    };

    // Check if Mojang UUID is already linked to another user
    if let Ok(Some(existing)) = db_identity_by_provider_user_id(&db, "minecraft", &claims.uuid).await {
        if existing.user_id != user_id {
            return error_response(
                &req,
                409,
                "already_linked",
                "This Minecraft account is already linked to another BeaconAuth user",
            );
        }
    }

    // Delete existing minecraft identities for this user
    let identities = db_identities_by_user_id(&db, &user_id).await?;
    for iden in identities {
        if iden.provider == "minecraft" {
            let _ = db_delete_identity_by_id(&db, &iden.id).await;
        }
    }

    db_insert_identity(&db, &user_id, "minecraft", &claims.uuid, None).await?;

    // Default identity mode to "mojang" if unset
    if let Ok(Some(u)) = db_user_by_id(&db, &user_id).await {
        if u.identity_mode.is_none() {
            let _ = db_update_user_identity_mode(&db, &user_id, "mojang").await;
        }
    }

    let resp = Response::from_json(&serde_json::json!({
        "success": true,
        "uuid": claims.uuid,
        "username": claims.name,
    }))?;
    json_with_cors(&req, resp)
}

pub async fn handle_minecraft_link_unlink(req: &Request, env: &Env) -> Result<Response> {
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

    let identities = db_identities_by_user_id(&db, &user_id).await?;
    for iden in identities {
        if iden.provider == "minecraft" {
            let _ = db_delete_identity_by_id(&db, &iden.id).await;
        }
    }

    let resp = Response::from_json(&serde_json::json!({ "success": true }))?;
    json_with_cors(req, resp)
}

pub async fn handle_minecraft_identity_mode(mut req: Request, env: &Env) -> Result<Response> {
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

    let payload: SetMinecraftIdentityModeRequest = match req.json().await {
        Ok(p) => p,
        Err(_) => return error_response(&req, 400, "invalid_request", "Malformed JSON body"),
    };

    let mode = payload.identity_mode.trim().to_lowercase();
    if mode != "mojang" && mode != "legacy" {
        return error_response(
            &req,
            400,
            "invalid_identity_mode",
            "identity_mode must be 'mojang' or 'legacy'",
        );
    }

    db_update_user_identity_mode(&db, &user_id, &mode).await?;

    let resp = Response::from_json(&serde_json::json!({
        "success": true,
        "identity_mode": mode,
    }))?;
    json_with_cors(&req, resp)
}
