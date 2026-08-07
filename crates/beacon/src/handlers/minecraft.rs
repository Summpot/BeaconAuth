//! Minecraft identity endpoints.
//!
//! - `GET /api/v1/minecraft/lookup?uuid=U` — mod-facing lookup used by the online-mode bypass
//!   path to decide whether a Mojang-verified UUID is bound to a BeaconAuth account and how
//!   to resolve its in-game identity (legacy offline UUID vs the Mojang UUID itself).
//! - `GET /api/v1/minecraft/identity-mode` — the user's effective identity preference.
//! - `POST /api/v1/minecraft/identity-mode` — set the per-user identity preference.

use actix_web::{web, HttpRequest, HttpResponse};
use beacon_core::models::{
    MinecraftIdentityModeResponse, MinecraftLookupResponse, SetMinecraftIdentityModeRequest,
    SetMinecraftIdentityModeResponse,
};
use entity::{identity, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    app_state::AppState,
    handlers::{extract_session_user, ErrorResponse},
};

/// Constant-time byte comparison to avoid leaking the lookup secret via timing.
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

/// Parse the configured default identity mode, falling back to "mojang" for invalid values.
fn effective_default_mode(app_state: &AppState) -> &'static str {
    match app_state
        .oauth_config
        .minecraft_identity_mode
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "legacy" => "legacy",
        _ => "mojang",
    }
}

/// Resolve the effective identity mode for a user (user preference wins over the default).
fn resolve_identity_mode(app_state: &AppState, user: &user::Model) -> &'static str {
    match user.identity_mode.as_deref() {
        Some("legacy") => "legacy",
        Some("mojang") => "mojang",
        _ => effective_default_mode(app_state),
    }
}

/// GET /api/v1/minecraft/lookup?uuid=U
///
/// Mod-facing endpoint. Requires the shared secret configured via
/// `MINECRAFT_LOOKUP_SECRET` in the `X-Minecraft-Auth` header.
///
/// Only answers whether the given Mojang UUID is bound to a BeaconAuth account and, if so,
/// how the mod should resolve its in-game identity. The UUID comes from Mojang's own
/// `hasJoined` verification on online-mode servers, so this endpoint does not leak anything
/// a caller could not already know.
pub async fn minecraft_lookup(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    // Shared-secret gate.
    let expected = app_state.oauth_config.minecraft_lookup_secret.clone();
    let Some(expected) = expected else {
        return HttpResponse::ServiceUnavailable().json(ErrorResponse {
            error: "lookup_disabled".to_string(),
            message: "MINECRAFT_LOOKUP_SECRET is not configured".to_string(),
        });
    };
    let provided = req
        .headers()
        .get("X-Minecraft-Auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid lookup secret".to_string(),
        });
    }

    let uuid = match query.get("uuid").map(|s| s.trim()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "missing_uuid".to_string(),
                message: "uuid query parameter is required".to_string(),
            });
        }
    };

    let Some(identity_row) = (match identity::Entity::find()
        .filter(identity::Column::Provider.eq("minecraft"))
        .filter(identity::Column::ProviderUserId.eq(&uuid))
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Minecraft lookup: database error: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error".to_string(),
            });
        }
    }) else {
        return HttpResponse::Ok().json(MinecraftLookupResponse {
            bound: false,
            identity_mode: None,
            user_subject: None,
            textures_value: None,
            textures_signature: None,
        });
    };

    let Some(user_row) = (match user::Entity::find_by_id(identity_row.user_id.clone())
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Minecraft lookup: database error (user): {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error".to_string(),
            });
        }
    }) else {
        log::error!(
            "Minecraft lookup: identity {} references missing user {}",
            identity_row.id,
            identity_row.user_id
        );
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Invalid identity mapping".to_string(),
        });
    };

    HttpResponse::Ok().json(MinecraftLookupResponse {
        bound: true,
        identity_mode: Some(resolve_identity_mode(&app_state, &user_row).to_string()),
        user_subject: Some(user_row.id.clone()),
        textures_value: user_row.minecraft_textures_value.clone(),
        textures_signature: user_row.minecraft_textures_signature.clone(),
    })
}

/// GET /api/v1/minecraft/identity-mode
pub async fn get_identity_mode(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let Some(user_row) = user::Entity::find_by_id(user_id)
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    else {
        return Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "user_not_found".to_string(),
            message: "User not found".to_string(),
        }));
    };

    Ok(HttpResponse::Ok().json(MinecraftIdentityModeResponse {
        mode: resolve_identity_mode(&app_state, &user_row).to_string(),
    }))
}

/// POST /api/v1/minecraft/identity-mode
pub async fn set_identity_mode(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<SetMinecraftIdentityModeRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let mode = payload.mode.trim().to_ascii_lowercase();
    let mode = match mode.as_str() {
        "legacy" => "legacy",
        "mojang" => "mojang",
        _ => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_mode".to_string(),
                message: "mode must be 'mojang' or 'legacy'".to_string(),
            }));
        }
    };

    let Some(user_row) = user::Entity::find_by_id(&user_id)
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    else {
        return Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "user_not_found".to_string(),
            message: "User not found".to_string(),
        }));
    };

    let mut active: user::ActiveModel = user_row.into();
    active.identity_mode = sea_orm::Set(Some(mode.to_string()));
    active.updated_at = sea_orm::Set(chrono::Utc::now().timestamp());
    active
        .update(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(SetMinecraftIdentityModeResponse { success: true }))
}
