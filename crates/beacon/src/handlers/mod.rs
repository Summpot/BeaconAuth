// Re-export all handlers
pub mod auth;
pub mod identity;
pub mod minecraft;
pub mod oidc;
pub mod passkey;
pub mod user;

// Re-export the auth handlers
pub use auth::refresh_token;

// Keep original handlers here
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use beacon_core::password;
use beacon_core::username;
use entity::identity as identity_entity;
use entity::user as user_entity;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    models::{
        ConfigResponse, ErrorResponse, LoginPayload, OAuthCallbackQuery,
        OAuthStartPayload, OAuthStartResponse, OAuthStateClaims, RegisterPayload,
    },
};

/// GET /.well-known/jwks.json
/// Returns the JWKS JSON containing the public key
pub async fn get_jwks(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(app_state.jwks_json.clone())
}

/// GET /api/v1/config
/// Returns the available authentication providers configuration
pub async fn get_config(app_state: web::Data<AppState>) -> impl Responder {
    let config = ConfigResponse {
        database_auth: true, // Always enabled if server is running
        github_oauth: app_state.oauth_config.github_client_id.is_some()
            && app_state.oauth_config.github_client_secret.is_some(),
        google_oauth: app_state.oauth_config.google_client_id.is_some()
            && app_state.oauth_config.google_client_secret.is_some(),
        microsoft_oauth: app_state.oauth_config.microsoft_client_id.is_some()
            && app_state.oauth_config.microsoft_client_secret.is_some(),
        minecraft_oauth: app_state.oauth_config.microsoft_client_id.is_some()
            && app_state.oauth_config.microsoft_client_secret.is_some(),
    };

    HttpResponse::Ok().json(config)
}

/// POST /api/v1/login
/// Authenticates user and sets session cookies
pub async fn login(
    app_state: web::Data<AppState>,
    payload: web::Json<LoginPayload>,
) -> impl Responder {
    log::info!("Login attempt for user: {}", payload.username);

    let identifier = username::normalize_username(&payload.username);

    // 1. Resolve the canonical user via the password identity.
    let identity = match identity_entity::Entity::find()
        .filter(identity_entity::Column::Provider.eq("password"))
        .filter(identity_entity::Column::ProviderUserId.eq(&identifier))
        .one(&app_state.db)
        .await
    {
        Ok(Some(i)) => i,
        Ok(None) => {
            log::warn!("Password identity not found for: {}", payload.username);
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Invalid username or password".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error (identity lookup): {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
    };

    let Some(password_hash) = identity.password_hash.as_deref() else {
        log::error!("Password identity row missing password_hash (id={})", identity.id);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Invalid password identity".to_string(),
        });
    };

    let user = match user_entity::Entity::find_by_id(identity.user_id.clone())
        .one(&app_state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            log::error!("Identity references missing user_id={}", identity.user_id);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Invalid identity mapping".to_string(),
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

    // 2. Verify password using Argon2
    let password_valid = match password::verify_password(&payload.password, password_hash) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Failed to verify password hash for identity_id={}: {e}", identity.id);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to verify password".to_string(),
            });
        }
    };

    if !password_valid {
        log::warn!("Invalid password for user: {}", payload.username);
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid username or password".to_string(),
        });
    }

    log::info!("User authenticated successfully: {}", payload.username);

    // 3. Create session tokens
    let (access_token, refresh_token) =
        match auth::create_session_for_user(&app_state, &user.id).await {
            Ok(tokens) => tokens,
            Err(e) => {
                log::error!("Failed to create session: {}", e);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to create session".to_string(),
                });
            }
        };

    log::info!("Login successful for user: {}", payload.username);

    // 4. Return success with cookies
    auth::set_auth_cookies(&app_state, access_token, refresh_token)
}

/// POST /api/v1/register
/// Register a new user and set session cookies
pub async fn register(
    app_state: web::Data<AppState>,
    payload: web::Json<RegisterPayload>,
) -> impl Responder {
    log::info!("Registration attempt for user: {}", payload.username);

    let requested_username = payload.username.trim().to_string();
    let requested_username_lower = username::normalize_username(&requested_username);

    // 1. Validate username (Minecraft-style)
    if let Err(msg) = username::validate_minecraft_username(&requested_username) {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_username".to_string(),
            message: msg.to_string(),
        });
    }

    // 2. Validate password (basic validation)
    if payload.password.len() < 6 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_password".to_string(),
            message: "Password must be at least 6 characters".to_string(),
        });
    }

    // 3. Check if user already exists
    let existing_user = user_entity::Entity::find()
        .filter(user_entity::Column::UsernameLower.eq(&requested_username_lower))
        .one(&app_state.db)
        .await;

    match existing_user {
        Ok(Some(_)) => {
            log::warn!(
                "Registration failed: username already exists: {}",
                requested_username
            );
            return HttpResponse::Conflict().json(ErrorResponse {
                error: "username_taken".to_string(),
                message: "Username already exists".to_string(),
            });
        }
        Err(e) => {
            log::error!("Database error during registration check: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Database error occurred".to_string(),
            });
        }
        Ok(None) => {
            // Username is available, continue
        }
    }

    // 4. Hash password (Argon2id)
    let password_hash = match password::hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to process password".to_string(),
            });
        }
    };

    // 5. Create new user and its password identity atomically.
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

    let user_id = Uuid::now_v7().to_string();

    let new_user = user_entity::ActiveModel {
        id: Set(user_id.clone()),
        username: Set(requested_username.clone()),
        username_lower: Set(requested_username_lower.clone()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = user_entity::Entity::insert(new_user).exec_without_returning(&txn).await {
            let _ = txn.rollback().await;
            log::error!("Failed to insert user: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to create user".to_string(),
            });
    }

    let identity_id = Uuid::now_v7().to_string();

    let new_identity = identity_entity::ActiveModel {
        id: Set(identity_id),
        user_id: Set(user_id.clone()),
        provider: Set("password".to_string()),
        provider_user_id: Set(requested_username_lower.clone()),
        password_hash: Set(Some(password_hash)),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = new_identity.insert(&txn).await {
        let _ = txn.rollback().await;
        log::error!("Failed to insert password identity: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Failed to create user".to_string(),
        });
    }

    if let Err(e) = txn.commit().await {
        log::error!("Failed to commit transaction: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal_error".to_string(),
            message: "Database error occurred".to_string(),
        });
    }

    log::info!(
        "User registered successfully: {} (ID: {})",
        payload.username,
        user_id
    );

    // 6. Create session tokens for auto-login
    let (access_token, refresh_token) =
        match auth::create_session_for_user(&app_state, &user_id).await {
            Ok(tokens) => tokens,
            Err(e) => {
                log::error!("Failed to create session: {}", e);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to create session".to_string(),
                });
            }
        };

    log::info!(
        "Registration successful for user: {}",
        payload.username
    );

    auth::set_auth_cookies(&app_state, access_token, refresh_token)
}

/// POST /api/v1/oauth/start
/// Initiate OAuth flow
pub async fn oauth_start(
    app_state: web::Data<AppState>,
    payload: web::Json<OAuthStartPayload>,
) -> impl Responder {
    log::info!("OAuth start request for provider: {}", payload.provider);

    // Stateless OAuth state: encode as a signed JWT so callbacks work across instances.
    let now = Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let state_id = Uuid::new_v4().to_string();

    let claims = OAuthStateClaims {
        iss: app_state.oauth_config.redirect_base.clone(),
        sub: state_id,
        aud: "beaconauth-oauth".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        token_type: "oauth_state".to_string(),
        provider: payload.provider.clone(),
        link_user_id: None,
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(app_state.jwt_kid.clone());

    let state_token = match jsonwebtoken::encode(&header, &claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to encode OAuth state JWT: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to start OAuth flow".to_string(),
            });
        }
    };

    // Build authorization URL based on provider
    let authorization_url = match payload.provider.as_str() {
        "github" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.github_client_id,
                &app_state.oauth_config.github_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );
                format!(
                    "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user user:email&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("GitHub OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "GitHub OAuth is not configured".to_string(),
                });
            }
        }
        "google" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.google_client_id,
                &app_state.oauth_config.google_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );
                format!(
                    "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid email profile&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("Google OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "Google OAuth is not configured".to_string(),
                });
            }
        }
        "microsoft" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.microsoft_client_id,
                &app_state.oauth_config.microsoft_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );

                let tenant_raw = app_state.oauth_config.microsoft_tenant.trim();
                let tenant = if tenant_raw.is_empty() { "common" } else { tenant_raw };
                let scope = "openid email profile User.Read";

                format!(
                    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&response_mode=query&scope={}&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(scope),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("Microsoft OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "Microsoft OAuth is not configured".to_string(),
                });
            }
        }
        "minecraft" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.microsoft_client_id,
                &app_state.oauth_config.microsoft_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );
                let scope = "XboxLive.signin offline_access";
                format!(
                    "https://login.live.com/oauth20_authorize.srf?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(scope),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("Microsoft OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "Microsoft OAuth is not configured".to_string(),
                });
            }
        }
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_provider".to_string(),
                message: "Unsupported OAuth provider".to_string(),
            });
        }
    };

    log::info!(
        "OAuth authorization URL generated for provider: {}",
        payload.provider
    );

    HttpResponse::Ok().json(OAuthStartResponse { authorization_url })
}

/// POST /api/v1/oauth/link/start
///
/// Starts an OAuth flow intended to *link* an additional identity to an existing logged-in user.
///
/// This endpoint is required because `SameSite=Strict` cookies will not be sent on the
/// cross-site OAuth callback request, so we embed the linking user_id in the signed state JWT.
pub async fn oauth_link_start(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<OAuthStartPayload>,
) -> impl Responder {
    let user_id = match extract_session_user(&req, &app_state) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Not authenticated".to_string(),
            });
        }
    };

    log::info!(
        "OAuth link start request for provider: {} (user_id={})",
        payload.provider,
        user_id
    );

    let now = Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let state_id = Uuid::new_v4().to_string();

    let claims = OAuthStateClaims {
        iss: app_state.oauth_config.redirect_base.clone(),
        sub: state_id,
        aud: "beaconauth-oauth".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        token_type: "oauth_state".to_string(),
        provider: payload.provider.clone(),
        link_user_id: Some(user_id.clone()),
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(app_state.jwt_kid.clone());

    let state_token = match jsonwebtoken::encode(&header, &claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to encode OAuth state JWT: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to start OAuth flow".to_string(),
            });
        }
    };

    let authorization_url = match payload.provider.as_str() {
        "github" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.github_client_id,
                &app_state.oauth_config.github_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );
                format!(
                    "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user user:email&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("GitHub OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "GitHub OAuth is not configured".to_string(),
                });
            }
        }
        "google" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.google_client_id,
                &app_state.oauth_config.google_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );
                format!(
                    "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid email profile&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("Google OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "Google OAuth is not configured".to_string(),
                });
            }
        }
        "microsoft" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.microsoft_client_id,
                &app_state.oauth_config.microsoft_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );

                let tenant_raw = app_state.oauth_config.microsoft_tenant.trim();
                let tenant = if tenant_raw.is_empty() { "common" } else { tenant_raw };
                let scope = "openid email profile User.Read";

                format!(
                    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&response_mode=query&scope={}&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(scope),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("Microsoft OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "Microsoft OAuth is not configured".to_string(),
                });
            }
        }
        "minecraft" => {
            if let (Some(client_id), Some(_)) = (
                &app_state.oauth_config.microsoft_client_id,
                &app_state.oauth_config.microsoft_client_secret,
            ) {
                let redirect_uri = format!(
                    "{}/api/v1/oauth/callback",
                    app_state.oauth_config.redirect_base
                );
                let scope = "XboxLive.signin offline_access";
                format!(
                    "https://login.live.com/oauth20_authorize.srf?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    urlencoding::encode(scope),
                    urlencoding::encode(&state_token)
                )
            } else {
                log::error!("Microsoft OAuth not configured");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    error: "oauth_not_configured".to_string(),
                    message: "Microsoft OAuth is not configured".to_string(),
                });
            }
        }
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_provider".to_string(),
                message: "Unsupported OAuth provider".to_string(),
            });
        }
    };

    HttpResponse::Ok().json(OAuthStartResponse { authorization_url })
}

/// GET /api/v1/oauth/callback
/// Handle OAuth callback and set session cookies
pub async fn oauth_callback(
    app_state: web::Data<AppState>,
    query: web::Query<OAuthCallbackQuery>,
) -> impl Responder {
    log::info!("OAuth callback received with state: {}", query.state);

    // 1. Validate and decode stateless OAuth state
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&app_state.oauth_config.redirect_base]);
    validation.set_audience(&["beaconauth-oauth"]);
    validation.validate_exp = true;

    let oauth_state = match jsonwebtoken::decode::<OAuthStateClaims>(
        &query.state,
        &app_state.decoding_key,
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(e) => {
            log::error!("Invalid OAuth state token: {:?}", e);
            return HttpResponse::BadRequest().body("Invalid or expired OAuth state");
        }
    };

    if oauth_state.token_type != "oauth_state" {
        log::error!("Invalid OAuth state token_type: {}", oauth_state.token_type);
        return HttpResponse::BadRequest().body("Invalid OAuth state");
    }

    // 2. Exchange code for access token and get user info
    let exchange = match oauth_state.provider.as_str() {
        "github" => match exchange_github_code(&app_state, &query.code).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("GitHub OAuth failed: {}", e);
                return HttpResponse::InternalServerError().body("GitHub authentication failed");
            }
        },
        "google" => match exchange_google_code(&app_state, &query.code).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("Google OAuth failed: {}", e);
                return HttpResponse::InternalServerError().body("Google authentication failed");
            }
        },
        "microsoft" => match exchange_microsoft_code(&app_state, &query.code).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("Microsoft OAuth failed: {}", e);
                return HttpResponse::InternalServerError().body("Microsoft authentication failed");
            }
        },
        "minecraft" => match exchange_minecraft_xbox_code(&app_state, &query.code).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("Minecraft OAuth failed: {}", e);
                return HttpResponse::InternalServerError().body("Minecraft authentication failed");
            }
        },
        _ => {
            return HttpResponse::BadRequest().body("Invalid provider");
        }
    };

    let provider_user_id = exchange.provider_user_id.clone();
    let derived_username = exchange.username.clone();

    // 3. Resolve the canonical user via identities (provider + provider_user_id).
    let provider = oauth_state.provider.clone();
    let existing_identity = match identity_entity::Entity::find()
        .filter(identity_entity::Column::Provider.eq(&provider))
        .filter(identity_entity::Column::ProviderUserId.eq(&provider_user_id))
        .one(&app_state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::error!("Database error (identity lookup): {}", e);
            return HttpResponse::InternalServerError().body("Database error");
        }
    };

    let db_user = if let Some(identity) = existing_identity {
        if let Some(link_user_id) = oauth_state.link_user_id {
            if identity.user_id != link_user_id {
                return HttpResponse::Conflict().json(ErrorResponse {
                    error: "identity_already_linked".to_string(),
                    message: "That provider account is already linked to a different user".to_string(),
                });
            }
        }

        match user_entity::Entity::find_by_id(identity.user_id.clone())
            .one(&app_state.db)
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                log::error!("Identity references missing user_id={}", identity.user_id);
                return HttpResponse::InternalServerError().body("Invalid identity mapping");
            }
            Err(e) => {
                log::error!("Database error (user lookup): {}", e);
                return HttpResponse::InternalServerError().body("Database error");
            }
        }
    } else if let Some(link_user_id) = oauth_state.link_user_id {
        // Link flow: attach identity to the specified existing user.
        let user = match user_entity::Entity::find_by_id(link_user_id.clone())
            .one(&app_state.db)
            .await
        {
            Ok(Some(u)) => u,
            Ok(None) => {
                return HttpResponse::NotFound().json(ErrorResponse {
                    error: "user_not_found".to_string(),
                    message: "User not found".to_string(),
                });
            }
            Err(e) => {
                log::error!("Database error (link user lookup): {}", e);
                return HttpResponse::InternalServerError().body("Database error");
            }
        };

        let now = Utc::now().timestamp();
        let identity_id = Uuid::now_v7().to_string();
        let new_identity = identity_entity::ActiveModel {
            id: Set(identity_id),
            user_id: Set(link_user_id),
            provider: Set(provider.clone()),
            provider_user_id: Set(provider_user_id.clone()),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        // Best-effort insert; if it raced, load again.
        match new_identity.insert(&app_state.db).await {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                if msg.contains("unique") {
                    // Someone else inserted; fine.
                } else {
                    log::error!("Failed to insert identity: {}", e);
                    return HttpResponse::InternalServerError().body("Failed to link identity");
                }
            }
        }

        user
    } else {
        // Login/registration flow: no compatibility behavior. Create a new user if identity is new.
        let now = Utc::now().timestamp();

        // Allocate a unique Minecraft-valid username derived from the provider.
        let prefix = match provider.as_str() {
            "github" => "gh_",
            "google" => "gg_",
            "microsoft" => "ms_",
            "minecraft" => "mc_",
            _ => "id_",
        };

        let mut candidate_username = String::new();
        let mut candidate_lower = String::new();

        for attempt in 0u32..=100u32 {
            let candidate = username::make_minecraft_username_with_prefix(prefix, &derived_username, attempt);
            let lower = username::normalize_username(&candidate);

            let existing = user_entity::Entity::find()
                .filter(user_entity::Column::UsernameLower.eq(&lower))
                .one(&app_state.db)
                .await;

            match existing {
                Ok(None) => {
                    candidate_username = candidate;
                    candidate_lower = lower;
                    break;
                }
                Ok(Some(_)) => continue,
                Err(e) => {
                    log::error!("Database error (username check): {}", e);
                    return HttpResponse::InternalServerError().body("Database error");
                }
            }
        }

        if candidate_username.is_empty() {
            log::error!("Failed to allocate a unique username after many collisions");
            return HttpResponse::InternalServerError().body("Failed to allocate unique username");
        }

        let new_user_id = Uuid::now_v7().to_string();
        let new_user = user_entity::ActiveModel {
            id: Set(new_user_id.clone()),
            username: Set(candidate_username),
            username_lower: Set(candidate_lower),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        if let Err(e) = user_entity::Entity::insert(new_user)
            .exec_without_returning(&app_state.db)
            .await
        {
            log::error!("Failed to create user: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create user");
        }

        let Some(user) = (match user_entity::Entity::find_by_id(new_user_id).one(&app_state.db).await {
            Ok(u) => u,
            Err(e) => {
                log::error!("Failed to reload inserted user: {}", e);
                return HttpResponse::InternalServerError().body("Failed to create user");
            }
        }) else {
            return HttpResponse::InternalServerError().body("Failed to resolve user");
        };

        let now = Utc::now().timestamp();
        let identity_id = Uuid::now_v7().to_string();
        let new_identity = identity_entity::ActiveModel {
            id: Set(identity_id),
            user_id: Set(user.id.clone()),
            provider: Set(provider.clone()),
            provider_user_id: Set(provider_user_id.clone()),
            password_hash: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        let canonical_user = match new_identity.insert(&app_state.db).await {
            Ok(_) => user,
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                if msg.contains("unique") {
                    // Someone else inserted; resolve and use the existing mapping.
                    let existing_identity = match identity_entity::Entity::find()
                        .filter(identity_entity::Column::Provider.eq(&provider))
                        .filter(identity_entity::Column::ProviderUserId.eq(&provider_user_id))
                        .one(&app_state.db)
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!("Database error (identity reload): {}", e);
                            return HttpResponse::InternalServerError().body("Database error");
                        }
                    };

                    let Some(identity) = existing_identity else {
                        log::error!("Identity insert raced but could not be reloaded");
                        return HttpResponse::InternalServerError().body("Failed to persist identity");
                    };

                    match user_entity::Entity::find_by_id(identity.user_id.clone())
                        .one(&app_state.db)
                        .await
                    {
                        Ok(Some(u)) => u,
                        _ => {
                            return HttpResponse::InternalServerError().body("Invalid identity mapping");
                        }
                    }
                } else {
                    log::error!("Failed to insert identity: {}", e);
                    return HttpResponse::InternalServerError().body("Failed to persist identity");
                }
            }
        };

        canonical_user
    };

    // Cache provider avatar info best-effort. Never fail login for avatar issues.
    {
        let now = Utc::now().timestamp();
        let mut update = user_entity::ActiveModel {
            id: Set(db_user.id.clone()),
            updated_at: Set(now),
            ..Default::default()
        };

        let mut has_avatar_update = false;

        match provider.as_str() {
            "github" => {
                if exchange.avatar_url.is_some() {
                    update.github_avatar_url = Set(exchange.avatar_url.clone());
                    has_avatar_update = true;
                }
            }
            "google" => {
                if exchange.avatar_url.is_some() {
                    update.google_avatar_url = Set(exchange.avatar_url.clone());
                    has_avatar_update = true;
                }
            }
            "microsoft" => {
                if exchange.microsoft_avatar_b64.is_some() {
                    update.microsoft_avatar_b64 = Set(exchange.microsoft_avatar_b64.clone());
                    update.microsoft_avatar_content_type = Set(exchange.microsoft_avatar_content_type.clone());
                    has_avatar_update = true;
                }
            }
            "minecraft" => {
                if exchange.minecraft_textures_value.is_some() {
                    update.minecraft_textures_value = Set(exchange.minecraft_textures_value.clone());
                    update.minecraft_textures_signature = Set(exchange.minecraft_textures_signature.clone());
                    has_avatar_update = true;
                }
            }
            _ => {}
        }

        if db_user.avatar_source.is_none() {
            let should_default = match provider.as_str() {
                "github" | "google" => exchange.avatar_url.is_some(),
                "microsoft" => exchange.microsoft_avatar_b64.is_some(),
                _ => false,
            };
            if should_default {
                update.avatar_source = Set(Some(provider.clone()));
                has_avatar_update = true;
            }
        }

        if has_avatar_update {
            if let Err(e) = update.update(&app_state.db).await {
                log::warn!("Failed to cache provider avatar: {e}");
            }
        }
    }

    // 4. Create session tokens
    let (access_token, refresh_token) =
        match auth::create_session_for_user(&app_state, &db_user.id).await {
            Ok(tokens) => tokens,
            Err(e) => {
                log::error!("Failed to create session: {}", e);
                return HttpResponse::InternalServerError().body("Failed to create session");
            }
        };

    log::info!(
        "OAuth authentication successful for user: {} (provider={}, provider_user_id={})",
        db_user.username,
        provider,
        provider_user_id
    );

    // 5. Redirect to OAuth complete page with cookies set
    HttpResponse::Found()
        .append_header(("Location", "/oauth-complete"))
        .cookie(
            actix_web::cookie::Cookie::build("access_token", access_token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::seconds(
                    app_state.access_token_expiration,
                ))
                .finish(),
        )
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", refresh_token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::seconds(
                    app_state.refresh_token_expiration,
                ))
                .finish(),
        )
        .finish()
}

struct OAuthExchangeResult {
    provider_user_id: String,
    username: String,

    // Cacheable avatar information.
    avatar_url: Option<String>,
    microsoft_avatar_b64: Option<String>,
    microsoft_avatar_content_type: Option<String>,

    // Minecraft (Xbox) flow extras: cached Mojang-signed `textures` property.
    minecraft_textures_value: Option<String>,
    minecraft_textures_signature: Option<String>,
}

// Helper function to exchange GitHub code for user info
async fn exchange_github_code(
    app_state: &AppState,
    code: &str,
) -> Result<OAuthExchangeResult, anyhow::Error> {
    let client = reqwest::Client::new();

    let redirect_uri = format!(
        "{}/api/v1/oauth/callback",
        app_state.oauth_config.redirect_base.trim_end_matches('/')
    );

    // Exchange code for access token
    let token_resp = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            (
                "client_id",
                app_state
                    .oauth_config
                    .github_client_id
                    .as_ref()
                    .unwrap()
                    .as_str(),
            ),
            (
                "client_secret",
                app_state
                    .oauth_config
                    .github_client_secret
                    .as_ref()
                    .unwrap()
                    .as_str(),
            ),
            ("code", code),
            ("redirect_uri", &redirect_uri),
        ])
        .send()
        .await?;

    let status = token_resp.status();
    let body = token_resp.text().await?;

    if !status.is_success() {
        anyhow::bail!("GitHub token exchange failed ({status}): {body}");
    }

    let access_token = match beacon_core::oauth::parse_access_token_from_token_exchange_body(&body) {
        Ok(tok) => tok,
        Err(beacon_core::oauth::OAuthTokenParseError::ProviderError(e)) => {
            anyhow::bail!(
                "GitHub token exchange returned error '{}': {}{} (check GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET and callback URL: {redirect_uri})",
                e.error,
                e.error_description.unwrap_or_default(),
                e.error_uri.map(|u| format!(" ({u})")).unwrap_or_default(),
            );
        }
        Err(other) => {
            anyhow::bail!(
                "GitHub token exchange failed (status {status}): {other} (check callback URL: {redirect_uri})"
            );
        }
    };

    // Get user info
    let user_response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "BeaconAuth")
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let user_id = user_response["id"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("No user ID in response"))?
        .to_string();

    let username = user_response["login"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No username in response"))?
        .to_string();

    let avatar_url = user_response
        .get("avatar_url")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Ok(OAuthExchangeResult {
        provider_user_id: user_id,
        username,
        avatar_url,
        microsoft_avatar_b64: None,
        microsoft_avatar_content_type: None,
        minecraft_textures_value: None,
        minecraft_textures_signature: None,
    })
}

// Helper function to exchange Google code for user info
async fn exchange_google_code(
    app_state: &AppState,
    code: &str,
) -> Result<OAuthExchangeResult, anyhow::Error> {
    let client = reqwest::Client::new();

    let redirect_uri = format!(
        "{}/api/v1/oauth/callback",
        app_state.oauth_config.redirect_base
    );

    // Exchange code for access token
    let token_response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            (
                "client_id",
                app_state
                    .oauth_config
                    .google_client_id
                    .as_ref()
                    .unwrap()
                    .as_str(),
            ),
            (
                "client_secret",
                app_state
                    .oauth_config
                    .google_client_secret
                    .as_ref()
                    .unwrap()
                    .as_str(),
            ),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect_uri),
        ])
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let access_token = token_response["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access token in response"))?;

    // Get user info
    let user_response = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let user_id = user_response["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No user ID in response"))?
        .to_string();

    let email = user_response["email"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No email in response"))?;

    // Use email prefix as username
    let username = email.split('@').next().unwrap_or(email);

    let avatar_url = user_response
        .get("picture")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Ok(OAuthExchangeResult {
        provider_user_id: user_id,
        username: username.to_string(),
        avatar_url,
        microsoft_avatar_b64: None,
        microsoft_avatar_content_type: None,
        minecraft_textures_value: None,
        minecraft_textures_signature: None,
    })
}

// Helper function to exchange Microsoft code for user info
async fn exchange_microsoft_code(
    app_state: &AppState,
    code: &str,
) -> Result<OAuthExchangeResult, anyhow::Error> {
    let client = reqwest::Client::new();

    let redirect_uri = format!(
        "{}/api/v1/oauth/callback",
        app_state.oauth_config.redirect_base.trim_end_matches('/')
    );

    let tenant_raw = app_state.oauth_config.microsoft_tenant.trim();
    let tenant = if tenant_raw.is_empty() { "common" } else { tenant_raw };
    let token_url = format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    );

    // Exchange code for access token
    let token_resp = client
        .post(&token_url)
        .form(&[
            (
                "client_id",
                app_state
                    .oauth_config
                    .microsoft_client_id
                    .as_ref()
                    .unwrap()
                    .as_str(),
            ),
            (
                "client_secret",
                app_state
                    .oauth_config
                    .microsoft_client_secret
                    .as_ref()
                    .unwrap()
                    .as_str(),
            ),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect_uri),
            ("scope", "openid email profile User.Read"),
        ])
        .send()
        .await?;

    let status = token_resp.status();
    let token_body = token_resp.text().await?;

    if !status.is_success() {
        anyhow::bail!(
            "Microsoft token exchange failed ({status}): {token_body} (check MICROSOFT_CLIENT_ID/MICROSOFT_CLIENT_SECRET and callback URL: {redirect_uri})"
        );
    }

    let token_json: serde_json::Value = serde_json::from_str(&token_body)
        .map_err(|e| anyhow::anyhow!("Failed to parse Microsoft token response JSON: {e}; body={token_body}"))?;

    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            let err = token_json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown_error");
            let desc = token_json
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("no error_description");
            anyhow::anyhow!("No access_token in Microsoft response (error={err}): {desc}")
        })?;

    // Get user info
    let user_resp = client
        .get("https://graph.microsoft.com/v1.0/me")
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await?;

    let user_status = user_resp.status();
    let user_body = user_resp.text().await?;
    if !user_status.is_success() {
        anyhow::bail!("Microsoft user fetch failed ({user_status}): {user_body}");
    }

    let user_json: serde_json::Value = serde_json::from_str(&user_body)
        .map_err(|e| anyhow::anyhow!("Failed to parse Microsoft user JSON: {e}; body={user_body}"))?;

    let user_id = user_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("No id in Microsoft profile response"))?
        .to_string();

    let username_source = user_json
        .get("mail")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            user_json
                .get("userPrincipalName")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| {
            user_json
                .get("displayName")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| anyhow::anyhow!("No mail/userPrincipalName/displayName in Microsoft profile response"))?;

    let username_raw = username_source.split('@').next().unwrap_or(username_source);

    // Fetch avatar bytes from Microsoft Graph (best-effort).
    let (microsoft_avatar_b64, microsoft_avatar_content_type) = {
        let photo_resp = client
            .get("https://graph.microsoft.com/v1.0/me/photo/$value")
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await?;

        let status = photo_resp.status();
        if !status.is_success() {
            (None, None)
        } else {
            let ct = photo_resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "image/jpeg".to_string());

            let bytes = photo_resp.bytes().await?;
            let b64 = BASE64.encode(bytes);
            (Some(b64), Some(ct))
        }
    };

    Ok(OAuthExchangeResult {
        provider_user_id: user_id,
        username: username_raw.to_string(),
        avatar_url: None,
        microsoft_avatar_b64,
        microsoft_avatar_content_type,
        minecraft_textures_value: None,
        minecraft_textures_signature: None,
    })
}

/// Exchange a Microsoft consumer authorization code for a real Minecraft (Xbox/Mojang) profile.
///
/// This implements the standard Minecraft authentication stack used by first-party clients:
///
/// 1. OAuth code → Microsoft access token (`login.live.com` token endpoint, consumer scope).
/// 2. Access token → XBL user token (`user.auth.xboxlive.com`).
/// 3. XBL user token → XSTS token (`xsts.auth.xboxlive.com`), which performs the ToS/age
///    (child-account) gate.
/// 4. XSTS token → Minecraft login token (`api.minecraftservices.com/authentication/login_with_xbox`).
/// 5. Fetch the Minecraft profile (`minecraft/profile`) → Mojang UUID + gamertag + signed `textures`.
///
/// The resulting `provider_user_id` is the **Mojang UUID** (stable), and `username` is the
/// Minecraft gamertag. Textures are captured so the mod can serve the real skin/cape when a
/// legacy offline identity is used.
async fn exchange_minecraft_xbox_code(
    app_state: &AppState,
    code: &str,
) -> Result<OAuthExchangeResult, anyhow::Error> {
    use beacon_core::minecraft_xbox as mx;

    let client = reqwest::Client::new();
    let redirect_uri = format!(
        "{}/api/v1/oauth/callback",
        app_state.oauth_config.redirect_base.trim_end_matches('/')
    );

    let client_id = app_state
        .oauth_config
        .microsoft_client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MICROSOFT_CLIENT_ID not configured"))?
        .clone();
    let client_secret = app_state
        .oauth_config
        .microsoft_client_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MICROSOFT_CLIENT_SECRET not configured"))?
        .clone();

    // Step 1: Microsoft OAuth token exchange (consumer tenant, Xbox scope).
    let token_resp = client
        .post("https://login.live.com/oauth20_token.srf")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", mx::MICROSOFT_SCOPE),
        ])
        .send()
        .await?;

    let status = token_resp.status();
    let token_body = token_resp.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "Microsoft (Minecraft) token exchange failed ({status}): {token_body} (check MICROSOFT_CLIENT_ID/MICROSOFT_CLIENT_SECRET and redirect URL: {redirect_uri})"
        );
    }

    let token_json: serde_json::Value = serde_json::from_str(&token_body)
        .map_err(|e| anyhow::anyhow!("Failed to parse Microsoft token response JSON: {e}"))?;
    let microsoft_access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            let err = token_json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown_error");
            let desc = token_json
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("no error_description");
            anyhow::anyhow!("No Microsoft access_token (error={err}): {desc}")
        })?;

    // Step 2: XBL exchange.
    let xbl_resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&mx::xbl_token_body(microsoft_access_token))
        .send()
        .await?;

    let xbl_status = xbl_resp.status();
    let xbl_body = xbl_resp.text().await?;
    if !xbl_status.is_success() {
        anyhow::bail!("XBL token exchange failed ({xbl_status}): {xbl_body}");
    }
    let xbl_json: serde_json::Value =
        serde_json::from_str(&xbl_body).map_err(|e| anyhow::anyhow!("Invalid XBL response: {e}"))?;
    let xbl_token = xbl_json
        .get("Token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("XBL response missing Token"))?;

    // Step 3: XSTS exchange (performs ToS/child-account enforcement).
    let xsts_resp = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&mx::xsts_token_body(xbl_token))
        .send()
        .await?;

    let xsts_status = xsts_resp.status();
    let xsts_body = xsts_resp.text().await?;
    if !xsts_status.is_success() {
        anyhow::bail!("XSTS token exchange failed ({xsts_status}): {xsts_body}")
    }
    let xsts_json: serde_json::Value =
        serde_json::from_str(&xsts_body).map_err(|e| anyhow::anyhow!("Invalid XSTS response: {e}"))?;
    let xsts_token_raw = xsts_json
        .get("Token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("XSTS response missing Token"))?;
    let xsts_token = mx::split_xsts_token(xsts_token_raw);

    let uhs = mx::user_hash_from_xsts(&xsts_json)
        .ok_or_else(|| anyhow::anyhow!("XSTS response missing DisplayClaims uhs"))?;

    // Step 4: Minecraft login.
    let mc_login_resp = client
        .post("https://api.minecraftservices.com/authentication/login_with_xbox")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&mx::minecraft_login_body(&uhs, xsts_token))
        .send()
        .await?;

    let mc_login_status = mc_login_resp.status();
    let mc_login_body = mc_login_resp.text().await?;
    if !mc_login_status.is_success() {
        anyhow::bail!("Minecraft login exchange failed ({mc_login_status}): {mc_login_body}")
    }
    let mc_login_json: serde_json::Value =
        serde_json::from_str(&mc_login_body).map_err(|e| anyhow::anyhow!("Invalid Minecraft login response: {e}"))?;
    let mc_access_token = mc_login_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Minecraft login response missing access_token"))?;

    // Step 5: Fetch the Minecraft profile.
    let profile_resp = client
        .get("https://api.minecraftservices.com/minecraft/profile")
        .header("Authorization", format!("Bearer {mc_access_token}"))
        .header("Accept", "application/json")
        .send()
        .await?;

    let profile_status = profile_resp.status();
    let profile_body = profile_resp.text().await?;
    if !profile_status.is_success() {
        anyhow::bail!("Minecraft profile fetch failed ({profile_status}): {profile_body}");
    }
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_body).map_err(|e| anyhow::anyhow!("Invalid Minecraft profile response: {e}"))?;

    let mojang_uuid = profile_json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Minecraft profile missing id"))?
        .to_string();
    let gamertag = profile_json
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Minecraft profile missing name"))?
        .to_string();

    let (minecraft_textures_value, minecraft_textures_signature) = profile_json
        .get("properties")
        .and_then(mx::textures_property)
        .map(|(v, s)| (Some(v), Some(s)))
        .unwrap_or((None, None));

    Ok(OAuthExchangeResult {
        provider_user_id: mojang_uuid,
        username: gamertag,
        avatar_url: None,
        microsoft_avatar_b64: None,
        microsoft_avatar_content_type: None,
        minecraft_textures_value,
        minecraft_textures_signature,
    })
}

/// Helper function to extract user ID from session cookie
pub fn extract_session_user(
    req: &HttpRequest,
    app_state: &web::Data<AppState>,
) -> actix_web::Result<String> {
    use crate::models::SessionClaims;

    // Get access token from cookie
    let access_token = req
        .cookie("access_token")
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("No access token"))?
        .value()
        .to_string();

    // Create validation with proper issuer and audience checks
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&app_state.oauth_config.redirect_base]);
    validation.set_audience(&["beaconauth-web"]);
    validation.validate_exp = true;

    // Decode and validate JWT
    let token_data = jsonwebtoken::decode::<SessionClaims>(
        &access_token,
        &app_state.decoding_key,
        &validation,
    )
    .map_err(|e| {
        log::warn!("Failed to decode access token: {:?}", e);
        actix_web::error::ErrorUnauthorized("Invalid access token")
    })?;

    // Verify token type
    if token_data.claims.token_type != "access" {
        return Err(actix_web::error::ErrorUnauthorized("Invalid token type"));
    }

    let user_id = uuid::Uuid::parse_str(&token_data.claims.sub)
        .map_err(|e| {
            log::error!("Failed to parse user ID from token: {:?}", e);
            actix_web::error::ErrorInternalServerError("Invalid user ID in token")
        })?
        .to_string();

    Ok(user_id)
}
