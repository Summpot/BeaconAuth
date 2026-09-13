use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use entity::{identity, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set, TransactionTrait};
use uuid::Uuid;

use beacon_core::minecraft::verify_minecraft_link_token;
use beacon_core::models::{
    ConfirmMinecraftLinkRequest, ErrorResponse, SetMinecraftIdentityModeRequest,
    VerifyMinecraftTicketRequest, VerifyMinecraftTicketResponse,
};

use crate::{app_state::AppState, handlers::extract_session_user};

/// POST /api/v1/minecraft/link/verify
///
/// Inspect an in-game signed Minecraft link ticket and return the target Mojang player profile.
pub async fn verify_link_ticket(
    app_state: web::Data<AppState>,
    payload: web::Json<VerifyMinecraftTicketRequest>,
) -> impl Responder {
    let secret = match app_state.oauth_config.minecraft_link_secret.as_deref() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "not_configured".to_string(),
                message: "Minecraft link secret is not configured on the server".to_string(),
            });
        }
    };

    let claims = match verify_minecraft_link_token(&payload.token, secret) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_ticket".to_string(),
                message: format!("Invalid or expired Minecraft link ticket: {}", e),
            });
        }
    };

    HttpResponse::Ok().json(VerifyMinecraftTicketResponse {
        uuid: claims.uuid,
        username: claims.name,
        expires_at: claims.exp,
    })
}

/// POST /api/v1/minecraft/link/confirm
///
/// Bind the verified Minecraft identity to the currently logged-in BeaconAuth user.
pub async fn confirm_link_ticket(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<ConfirmMinecraftLinkRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let secret = match app_state.oauth_config.minecraft_link_secret.as_deref() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "not_configured".to_string(),
                message: "Minecraft link secret is not configured on the server".to_string(),
            }));
        }
    };

    let claims = match verify_minecraft_link_token(&payload.token, secret) {
        Ok(c) => c,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_ticket".to_string(),
                message: format!("Invalid or expired Minecraft link ticket: {}", e),
            }));
        }
    };

    let txn = app_state
        .db
        .begin()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // Check if this Mojang UUID is already linked to a different BeaconAuth user
    let existing_link = identity::Entity::find()
        .filter(identity::Column::Provider.eq("minecraft"))
        .filter(identity::Column::ProviderUserId.eq(&claims.uuid))
        .one(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    if let Some(existing) = existing_link {
        if existing.user_id != user_id {
            return Ok(HttpResponse::Conflict().json(ErrorResponse {
                error: "already_linked".to_string(),
                message: "This Minecraft account is already linked to another BeaconAuth user"
                    .to_string(),
            }));
        }
    }

    // Remove any previous minecraft identity for this user
    let user_identities = identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.clone()))
        .filter(identity::Column::Provider.eq("minecraft"))
        .all(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    for iden in user_identities {
        let _ = iden.delete(&txn).await;
    }

    let now = Utc::now().timestamp();
    let new_identity = identity::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_id: Set(user_id.clone()),
        provider: Set("minecraft".to_string()),
        provider_user_id: Set(claims.uuid.clone()),
        password_hash: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    new_identity
        .insert(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // Ensure default identity_mode is set to "mojang" if unset
    if let Some(u) = user::Entity::find_by_id(user_id)
        .one(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        if u.identity_mode.is_none() {
            let mut active_user: user::ActiveModel = u.into();
            active_user.identity_mode = Set(Some("mojang".to_string()));
            active_user.updated_at = Set(now);
            active_user
                .update(&txn)
                .await
                .map_err(actix_web::error::ErrorInternalServerError)?;
        }
    }

    txn.commit()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "uuid": claims.uuid,
        "username": claims.name,
    })))
}

/// POST /api/v1/minecraft/link/unlink
///
/// Remove any linked Minecraft account from the currently logged-in BeaconAuth user.
pub async fn unlink_minecraft(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let txn = app_state
        .db
        .begin()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let user_identities = identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.clone()))
        .filter(identity::Column::Provider.eq("minecraft"))
        .all(&txn)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    for iden in user_identities {
        let _ = iden.delete(&txn).await;
    }

    txn.commit()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "success": true })))
}

/// POST /api/v1/minecraft/identity-mode
///
/// Update the current user's Minecraft identity mode ("mojang" | "legacy").
pub async fn set_identity_mode(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<SetMinecraftIdentityModeRequest>,
) -> actix_web::Result<HttpResponse> {
    let user_id = extract_session_user(&req, &app_state)?;

    let mode = payload.identity_mode.trim().to_lowercase();
    if mode != "mojang" && mode != "legacy" {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_identity_mode".to_string(),
            message: "identity_mode must be 'mojang' or 'legacy'".to_string(),
        }));
    }

    let user_model = match user::Entity::find_by_id(user_id)
        .one(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        Some(u) => u,
        None => {
            return Ok(HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
            }));
        }
    };

    let mut active: user::ActiveModel = user_model.into();
    active.identity_mode = Set(Some(mode.clone()));
    active.updated_at = Set(Utc::now().timestamp());
    active
        .update(&app_state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "identity_mode": mode,
    })))
}
