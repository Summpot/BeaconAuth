use actix_web::{web, HttpRequest, HttpResponse, Responder};
use entity::{identity, user};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use chrono::Utc;
use base64::Engine;

use beacon_core::password;
use beacon_core::username;

use crate::{
    app_state::AppState,
    handlers::auth::get_access_token_from_cookie,
    models::*,
};

fn compute_avatar_url(user: &user::Model) -> Option<String> {
    let source = user.avatar_source.as_deref()?;

    match source {
        "github" => user.github_avatar_url.clone(),
        "google" => user.google_avatar_url.clone(),
        "microsoft" => {
            if user.microsoft_avatar_b64.is_some() {
                Some("/api/v1/user/me/avatar".to_string())
            } else {
                None
            }
        }
        "gravatar" => user
            .email
            .as_deref()
            .map(|e| beacon_core::avatar::gravatar_url(e, 128)),
        _ => None,
    }
}

/// GET /api/v1/user/me
/// Get current user information
pub async fn get_user_info(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Get and verify access token
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    // Query user from database
    let user_result = user::Entity::find_by_id(user_id.clone())
        .one(&app_state.db)
        .await;

    let user = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    let avatar_url = compute_avatar_url(&user);

    let body = UserMeResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        avatar_source: user.avatar_source,
        avatar_url,
    };

    HttpResponse::Ok().json(body)
}

/// POST /api/v1/user/profile
/// Update user profile fields (email + avatar preference)
pub async fn update_profile(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<UpdateUserProfileRequest>,
) -> impl Responder {
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    let Some(user_model) = (match user::Entity::find_by_id(user_id.clone()).one(&app_state.db).await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Database error (user lookup): {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    }) else {
        return HttpResponse::NotFound().json(ErrorResponse {
            error: "user_not_found".to_string(),
            message: "User not found".to_string(),
        });
    };

    let email_trimmed = payload.email.trim();
    let email_opt = if email_trimmed.is_empty() {
        None
    } else {
        Some(email_trimmed.to_string())
    };

    let avatar_source_trimmed = payload.avatar_source.trim();
    let avatar_source_opt = if avatar_source_trimmed.is_empty() {
        None
    } else {
        Some(avatar_source_trimmed.to_ascii_lowercase())
    };

    if let Some(ref source) = avatar_source_opt {
        match source.as_str() {
            "github" => {
                let configured = app_state.oauth_config.github_client_id.is_some()
                    && app_state.oauth_config.github_client_secret.is_some();
                if !configured {
                    return HttpResponse::BadRequest().json(ErrorResponse {
                        error: "invalid_avatar_source".to_string(),
                        message: "GitHub OAuth is not configured".to_string(),
                    });
                }
            }
            "google" => {
                let configured = app_state.oauth_config.google_client_id.is_some()
                    && app_state.oauth_config.google_client_secret.is_some();
                if !configured {
                    return HttpResponse::BadRequest().json(ErrorResponse {
                        error: "invalid_avatar_source".to_string(),
                        message: "Google OAuth is not configured".to_string(),
                    });
                }
            }
            "microsoft" => {
                let configured = app_state.oauth_config.microsoft_client_id.is_some()
                    && app_state.oauth_config.microsoft_client_secret.is_some();
                if !configured {
                    return HttpResponse::BadRequest().json(ErrorResponse {
                        error: "invalid_avatar_source".to_string(),
                        message: "Microsoft OAuth is not configured".to_string(),
                    });
                }
            }
            "gravatar" => {
                // If email is being cleared (or absent), gravatar can't work.
                let effective_email = email_opt.as_ref().or(user_model.email.as_ref());
                if effective_email.is_none() {
                    return HttpResponse::BadRequest().json(ErrorResponse {
                        error: "email_required".to_string(),
                        message: "Email is required to use Gravatar".to_string(),
                    });
                }
            }
            _ => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "invalid_avatar_source".to_string(),
                    message: "Unsupported avatar source".to_string(),
                });
            }
        }

        // For OAuth-based avatars, require that the identity is linked.
        if source != "gravatar" {
            let linked = match identity::Entity::find()
                .filter(identity::Column::UserId.eq(user_id.clone()))
                .filter(identity::Column::Provider.eq(source.clone()))
                .one(&app_state.db)
                .await
            {
                Ok(v) => v.is_some(),
                Err(e) => {
                    log::error!("Database error (identity lookup): {e}");
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "internal_error".to_string(),
                        message: "Database error occurred".to_string(),
                    });
                }
            };

            if !linked {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "identity_not_linked".to_string(),
                    message: "That provider is not linked to this account".to_string(),
                });
            }
        }
    }

    let now = Utc::now().timestamp();
    let mut active: user::ActiveModel = user_model.into();
    active.email = Set(email_opt);
    active.avatar_source = Set(avatar_source_opt);
    active.updated_at = Set(now);

    if let Err(e) = active.update(&app_state.db).await {
        log::error!("Failed to update user profile: {e}");
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Failed to update profile".to_string(),
        });
    }

    HttpResponse::Ok().json(UpdateUserProfileResponse { success: true })
}

/// GET /api/v1/user/me/avatar
/// Returns the user's selected avatar if it is stored locally (currently Microsoft avatars).
pub async fn get_my_avatar(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    let Some(user_model) = (match user::Entity::find_by_id(user_id).one(&app_state.db).await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Database error (user lookup): {e}");
            return HttpResponse::InternalServerError().finish();
        }
    }) else {
        return HttpResponse::NotFound().finish();
    };

    let Some(b64) = user_model.microsoft_avatar_b64.as_deref() else {
        return HttpResponse::NotFound().finish();
    };

    let content_type = user_model
        .microsoft_avatar_content_type
        .as_deref()
        .unwrap_or("image/jpeg");

    let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Failed to decode stored avatar base64: {e}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    HttpResponse::Ok().content_type(content_type).body(bytes)
}

/// POST /api/v1/user/change-username
/// Change the user's username (Minecraft rules + case-insensitive uniqueness)
pub async fn change_username(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<ChangeUsernameRequest>,
) -> impl Responder {
    // Get and verify access token
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    let requested_username = payload.username.trim().to_string();
    if let Err(msg) = username::validate_minecraft_username(&requested_username) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_username".to_string(),
            message: msg.to_string(),
        });
    }
    let requested_lower = username::normalize_username(&requested_username);

    // Load current user
    let user_model = match user::Entity::find_by_id(user_id.clone()).one(&app_state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error (user lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    // Check uniqueness (case-insensitive) against other users.
    let existing = match user::Entity::find()
        .filter(user::Column::UsernameLower.eq(&requested_lower))
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Database error (username check): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    if let Some(other) = existing {
        if other.id != user_model.id {
            return HttpResponse::Conflict().json(ErrorResponse {
                error: "username_taken".to_string(),
                message: "Username already exists".to_string(),
            });
        }
    }

    let now = Utc::now().timestamp();
    let txn = match app_state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to begin transaction: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    // Update user
    let mut user_active: user::ActiveModel = user_model.into();
    user_active.username = Set(requested_username.clone());
    user_active.username_lower = Set(requested_lower.clone());
    user_active.updated_at = Set(now);

    if let Err(e) = user_active.update(&txn).await {
        let _ = txn.rollback().await;
        log::error!("Failed to update user username: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Failed to update username".to_string(),
        });
    }

    // Keep the password identity identifier aligned with the normalized username.
    let password_identity = match identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.clone()))
        .filter(identity::Column::Provider.eq("password"))
        .one(&txn)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            let _ = txn.rollback().await;
            log::error!("Database error (password identity lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    if let Some(identity_model) = password_identity {
        let mut active: identity::ActiveModel = identity_model.into();
        active.provider_user_id = Set(requested_lower.clone());
        active.updated_at = Set(now);
        if let Err(e) = active.update(&txn).await {
            let _ = txn.rollback().await;
            log::error!("Failed to update password identity identifier: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to update username".to_string(),
            });
        }
    }

    if let Err(e) = txn.commit().await {
        log::error!("Failed to commit transaction: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Database error occurred".to_string(),
        });
    }

    HttpResponse::Ok().json(ChangeUsernameResponse {
        success: true,
        username: requested_username,
    })
}

/// POST /api/v1/user/change-password
/// Change user password
pub async fn change_password(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    // Get and verify access token
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: e,
            });
        }
    };

    // Query user from database
    let user_result = user::Entity::find_by_id(user_id.clone())
        .one(&app_state.db)
        .await;

    let user = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User not found".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    // Load existing password identity if present.
    let existing_password_identity = match identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.clone()))
        .filter(identity::Column::Provider.eq("password"))
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Database error (password identity lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    if let Some(ref identity_model) = existing_password_identity {
        let Some(existing_hash) = identity_model.password_hash.as_deref() else {
            log::error!("Password identity missing password_hash (id={})", identity_model.id);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Invalid password identity".to_string(),
            });
        };

        // Verify current password.
        let password_valid = match password::verify_password(&payload.current_password, existing_hash) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to verify stored password hash for identity_id={}: {e}", identity_model.id);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to verify password".to_string(),
                });
            }
        };

        if !password_valid {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_password".to_string(),
                message: "Current password is incorrect".to_string(),
            });
        }
    }

    // Validate new password
    if payload.new_password.len() < 6 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_password".to_string(),
            message: "New password must be at least 6 characters".to_string(),
        });
    }

    // Hash new password (Argon2id)
    let new_password_hash = match password::hash_password(&payload.new_password) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to process password".to_string(),
            });
        }
    };

    // Upsert password identity.
    let now = Utc::now().timestamp();
    if let Some(identity_model) = existing_password_identity {
        let mut active: identity::ActiveModel = identity_model.into();
        active.password_hash = Set(Some(new_password_hash));
        active.updated_at = Set(now);

        match active.update(&app_state.db).await {
            Ok(_) => {
                log::info!("Password changed successfully for user ID: {}", user_id);
                HttpResponse::Ok().json(serde_json::json!({ "success": true }))
            }
            Err(e) => {
                log::error!("Failed to update password identity: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to update password".to_string(),
                })
            }
        }
    } else {
        let identity_id = uuid::Uuid::now_v7().to_string();
        let new_identity = identity::ActiveModel {
            id: Set(identity_id),
            user_id: Set(user_id.clone()),
            provider: Set("password".to_string()),
            provider_user_id: Set(user.username_lower.clone()),
            password_hash: Set(Some(new_password_hash)),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        match new_identity.insert(&app_state.db).await {
            Ok(_) => {
                log::info!("Password set successfully for user ID: {}", user_id);
                HttpResponse::Ok().json(serde_json::json!({ "success": true }))
            }
            Err(e) => {
                log::error!("Failed to insert password identity: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to update password".to_string(),
                })
            }
        }
    }
}

/// POST /api/v1/logout
/// Logout user by revoking all their refresh tokens
pub async fn logout(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Get and verify access token
    let access_token = match get_access_token_from_cookie(&req) {
        Some(token) => token,
        None => {
            // Already logged out
            return HttpResponse::Ok().json(serde_json::json!({ "success": true }));
        }
    };

    let user_id = match crate::handlers::auth::verify_access_token(&app_state, &access_token) {
        Ok(id) => id,
        Err(_) => {
            // Invalid token, consider already logged out
            return HttpResponse::Ok().json(serde_json::json!({ "success": true }));
        }
    };

    // Revoke all refresh tokens for this user
    use entity::refresh_token;
    match refresh_token::Entity::update_many()
        .filter(refresh_token::Column::UserId.eq(user_id.clone()))
        .col_expr(refresh_token::Column::Revoked, sea_orm::sea_query::Expr::value(1_i64))
        .exec(&app_state.db)
        .await
    {
        Ok(_) => {
            log::info!("User logged out successfully: {}", user_id);
        }
        Err(e) => {
            log::error!("Failed to revoke tokens: {}", e);
        }
    }

    // Clear cookies
    HttpResponse::Ok()
        .cookie(
            actix_web::cookie::Cookie::build("access_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", "")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .json(serde_json::json!({ "success": true }))
}
