// Re-export all handlers
pub mod auth;
pub mod identity;
pub mod passkey;
pub mod user;

// Re-export the auth handlers
pub use auth::{get_minecraft_jwt, refresh_token};

// Keep original handlers here
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use entity::identity as identity_entity;
use entity::user as user_entity;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
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

    // 1. Query user from database
    let user_result = user_entity::Entity::find()
        .filter(user_entity::Column::Username.eq(&payload.username))
        .one(&app_state.db)
        .await;

    let user = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            log::warn!("User not found: {}", payload.username);
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Invalid username or password".to_string(),
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

    // 2. Verify password using bcrypt
    let password_valid = bcrypt::verify(&payload.password, &user.password_hash).unwrap_or(false);

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
        match auth::create_session_for_user(&app_state, user.id).await {
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

    // 1. Validate username (basic validation)
    if payload.username.is_empty() || payload.username.len() > 50 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_username".to_string(),
            message: "Username must be between 1 and 50 characters".to_string(),
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
        .filter(user_entity::Column::Username.eq(&payload.username))
        .one(&app_state.db)
        .await;

    match existing_user {
        Ok(Some(_)) => {
            log::warn!(
                "Registration failed: username already exists: {}",
                payload.username
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

    // 4. Hash password
    let password_hash = match bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to process password".to_string(),
            });
        }
    };

    // 5. Create new user
    let now = Utc::now();
    let new_user = user_entity::ActiveModel {
        username: Set(payload.username.clone()),
        password_hash: Set(password_hash),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let insert_result = user_entity::Entity::insert(new_user).exec(&app_state.db).await;

    let user_id = match insert_result {
        Ok(result) => result.last_insert_id,
        Err(e) => {
            log::error!("Failed to insert user: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to create user".to_string(),
            });
        }
    };

    log::info!(
        "User registered successfully: {} (ID: {})",
        payload.username,
        user_id
    );

    // 6. Create session tokens for auto-login
    let (access_token, refresh_token) =
        match auth::create_session_for_user(&app_state, user_id).await {
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
        challenge: if payload.challenge.is_empty() {
            None
        } else {
            Some(payload.challenge.clone())
        },
        redirect_port: if payload.redirect_port == 0 {
            None
        } else {
            Some(payload.redirect_port)
        },
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
        link_user_id: Some(user_id),
        challenge: if payload.challenge.is_empty() {
            None
        } else {
            Some(payload.challenge.clone())
        },
        redirect_port: if payload.redirect_port == 0 {
            None
        } else {
            Some(payload.redirect_port)
        },
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
    let (provider_user_id, derived_username) = match oauth_state.provider.as_str() {
        "github" => match exchange_github_code(&app_state, &query.code).await {
            Ok((id, name)) => (id, name),
            Err(e) => {
                log::error!("GitHub OAuth failed: {}", e);
                return HttpResponse::InternalServerError().body("GitHub authentication failed");
            }
        },
        "google" => match exchange_google_code(&app_state, &query.code).await {
            Ok((id, name)) => (id, name),
            Err(e) => {
                log::error!("Google OAuth failed: {}", e);
                return HttpResponse::InternalServerError().body("Google authentication failed");
            }
        },
        _ => {
            return HttpResponse::BadRequest().body("Invalid provider");
        }
    };

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

        match user_entity::Entity::find_by_id(identity.user_id)
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
        let user = match user_entity::Entity::find_by_id(link_user_id)
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

        let now = Utc::now();
        let new_identity = identity_entity::ActiveModel {
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
        // Login/registration flow: migrate legacy users by `password_hash` and backfill identity.
        let legacy_hash = format!("oauth_{}_{}", provider, provider_user_id);

        let mut user = match user_entity::Entity::find()
            .filter(user_entity::Column::PasswordHash.eq(&legacy_hash))
            .one(&app_state.db)
            .await
        {
            Ok(u) => u,
            Err(e) => {
                log::error!("Database error (legacy user lookup): {}", e);
                return HttpResponse::InternalServerError().body("Database error");
            }
        };

        if user.is_none() {
            // Create a new OAuth-only user.
            let now = Utc::now();

            let base = derived_username.clone();
            let mut candidate = base.clone();
            for i in 0..=100 {
                let existing = user_entity::Entity::find()
                    .filter(user_entity::Column::Username.eq(&candidate))
                    .one(&app_state.db)
                    .await;

                match existing {
                    Ok(None) => break,
                    Ok(Some(_)) => {
                        candidate = format!("{}_{}", base, i + 1);
                        continue;
                    }
                    Err(e) => {
                        log::error!("Database error (username check): {}", e);
                        return HttpResponse::InternalServerError().body("Database error");
                    }
                }
            }

            let new_user = user_entity::ActiveModel {
                username: Set(candidate),
                password_hash: Set(legacy_hash.clone()),
                created_at: Set(now),
                updated_at: Set(now),
                ..Default::default()
            };

            let inserted = match user_entity::Entity::insert(new_user).exec(&app_state.db).await {
                Ok(r) => r.last_insert_id,
                Err(e) => {
                    log::error!("Failed to create user: {}", e);
                    return HttpResponse::InternalServerError().body("Failed to create user");
                }
            };

            user = match user_entity::Entity::find_by_id(inserted).one(&app_state.db).await {
                Ok(u) => u,
                Err(e) => {
                    log::error!("Failed to reload inserted user: {}", e);
                    return HttpResponse::InternalServerError().body("Failed to create user");
                }
            };
        }

        let Some(user) = user else {
            return HttpResponse::InternalServerError().body("Failed to resolve user");
        };

        let now = Utc::now();
        let new_identity = identity_entity::ActiveModel {
            user_id: Set(user.id),
            provider: Set(provider.clone()),
            provider_user_id: Set(provider_user_id.clone()),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };
        match new_identity.insert(&app_state.db).await {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                if msg.contains("unique") {
                    // Someone else inserted; fine.
                } else {
                    log::error!("Failed to insert identity: {}", e);
                    return HttpResponse::InternalServerError().body("Failed to persist identity");
                }
            }
        }

        user
    };

    // 4. Create session tokens
    let (access_token, refresh_token) =
        match auth::create_session_for_user(&app_state, db_user.id).await {
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

// Helper function to exchange GitHub code for user info
async fn exchange_github_code(
    app_state: &AppState,
    code: &str,
) -> Result<(String, String), anyhow::Error> {
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

    Ok((user_id, format!("gh_{}", username)))
}

// Helper function to exchange Google code for user info
async fn exchange_google_code(
    app_state: &AppState,
    code: &str,
) -> Result<(String, String), anyhow::Error> {
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

    Ok((user_id, format!("gg_{}", username)))
}

/// Helper function to extract user ID from session cookie
pub fn extract_session_user(
    req: &HttpRequest,
    app_state: &web::Data<AppState>,
) -> actix_web::Result<i32> {
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

    // Parse user_id from sub (subject) field
    let user_id: i32 = token_data.claims.sub.parse().map_err(|e| {
        log::error!("Failed to parse user ID from token: {:?}", e);
        actix_web::error::ErrorInternalServerError("Invalid user ID in token")
    })?;

    Ok(user_id)
}
