use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use entity::user;
use jsonwebtoken::{encode, Header};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    models::{
        Claims, ConfigResponse, ErrorResponse, LoginPayload, LoginResponse, OAuthCallbackQuery,
        OAuthStartPayload, OAuthStartResponse, OAuthState, RegisterPayload,
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
/// Authenticates user and returns redirect URL with JWT
pub async fn login(
    app_state: web::Data<AppState>,
    payload: web::Json<LoginPayload>,
) -> impl Responder {
    log::info!("Login attempt for user: {}", payload.username);

    // 1. Query user from database
    let user_result = user::Entity::find()
        .filter(user::Column::Username.eq(&payload.username))
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

    // 3. Create JWT Claims
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(app_state.jwt_expiration);

    let claims = Claims {
        iss: "http://localhost:8080".to_string(),
        sub: user.id.to_string(),
        aud: "minecraft-client".to_string(),
        exp: exp.timestamp(),
        challenge: payload.challenge.clone(), // Critical: include the challenge
    };

    // 4. Sign JWT with ES256
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("beacon-auth-key-1".to_string());

    let token = match encode(&header, &claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to sign JWT: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to generate token".to_string(),
            });
        }
    };

    // 5. Build dynamic redirect URL
    let redirect_url = format!(
        "http://localhost:{}/auth-callback?jwt={}",
        payload.redirect_port, token
    );

    log::info!(
        "Login successful for user: {}, redirecting to port: {}",
        payload.username,
        payload.redirect_port
    );

    // 6. Return JSON response with redirect URL
    HttpResponse::Ok().json(LoginResponse { redirect_url })
}

/// POST /api/v1/register
/// Register a new user and return redirect URL with JWT
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
    let existing_user = user::Entity::find()
        .filter(user::Column::Username.eq(&payload.username))
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
    let new_user = user::ActiveModel {
        username: Set(payload.username.clone()),
        password_hash: Set(password_hash),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let insert_result = user::Entity::insert(new_user).exec(&app_state.db).await;

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

    // 6. Generate JWT for auto-login
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(app_state.jwt_expiration);

    let claims = Claims {
        iss: "http://localhost:8080".to_string(),
        sub: user_id.to_string(),
        aud: "minecraft-client".to_string(),
        exp: exp.timestamp(),
        challenge: payload.challenge.clone(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("beacon-auth-key-1".to_string());

    let token = match encode(&header, &claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to sign JWT: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to generate token".to_string(),
            });
        }
    };

    // 7. Build redirect URL
    let redirect_url = format!(
        "http://localhost:{}/auth-callback?jwt={}",
        payload.redirect_port, token
    );

    log::info!(
        "Registration successful for user: {}, redirecting to port: {}",
        payload.username,
        payload.redirect_port
    );

    HttpResponse::Created().json(LoginResponse { redirect_url })
}

/// POST /api/v1/oauth/start
/// Initiate OAuth flow
pub async fn oauth_start(
    app_state: web::Data<AppState>,
    payload: web::Json<OAuthStartPayload>,
) -> impl Responder {
    log::info!("OAuth start request for provider: {}", payload.provider);

    // Generate state token
    let state_token = Uuid::new_v4().to_string();

    // Store OAuth state
    let oauth_state = OAuthState {
        provider: payload.provider.clone(),
        challenge: payload.challenge.clone(),
        redirect_port: payload.redirect_port,
        state_token: state_token.clone(),
    };

    {
        let mut states = app_state.oauth_states.write().await;
        states.insert(state_token.clone(), oauth_state);
    }

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
                    state_token
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
                    state_token
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

/// GET /api/v1/oauth/callback
/// Handle OAuth callback
pub async fn oauth_callback(
    app_state: web::Data<AppState>,
    query: web::Query<OAuthCallbackQuery>,
) -> impl Responder {
    log::info!("OAuth callback received with state: {}", query.state);

    // 1. Retrieve OAuth state
    let oauth_state = {
        let mut states = app_state.oauth_states.write().await;
        states.remove(&query.state)
    };

    let oauth_state = match oauth_state {
        Some(state) => state,
        None => {
            log::error!("Invalid or expired OAuth state: {}", query.state);
            return HttpResponse::BadRequest().body("Invalid or expired OAuth state");
        }
    };

    // 2. Exchange code for access token and get user info
    let (user_id, username) = match oauth_state.provider.as_str() {
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

    // 3. Find or create user
    let db_user = match user::Entity::find()
        .filter(user::Column::Username.eq(&username))
        .one(&app_state.db)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Create new user with OAuth
            let now = Utc::now();
            let new_user = user::ActiveModel {
                username: Set(username.clone()),
                password_hash: Set(format!("oauth_{}_{}", oauth_state.provider, user_id)), // Not a real password
                created_at: Set(now),
                updated_at: Set(now),
                ..Default::default()
            };

            match user::Entity::insert(new_user).exec(&app_state.db).await {
                Ok(result) => {
                    match user::Entity::find_by_id(result.last_insert_id)
                        .one(&app_state.db)
                        .await
                    {
                        Ok(Some(user)) => user,
                        _ => {
                            log::error!("Failed to retrieve newly created user");
                            return HttpResponse::InternalServerError()
                                .body("Failed to create user");
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to create user: {}", e);
                    return HttpResponse::InternalServerError().body("Failed to create user");
                }
            }
        }
        Err(e) => {
            log::error!("Database error: {}", e);
            return HttpResponse::InternalServerError().body("Database error");
        }
    };

    // 4. Generate JWT
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(app_state.jwt_expiration);

    let claims = Claims {
        iss: "http://localhost:8080".to_string(),
        sub: db_user.id.to_string(),
        aud: "minecraft-client".to_string(),
        exp: exp.timestamp(),
        challenge: oauth_state.challenge.clone(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("beacon-auth-key-1".to_string());

    let token = match encode(&header, &claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to sign JWT: {}", e);
            return HttpResponse::InternalServerError().body("Failed to generate token");
        }
    };

    // 5. Redirect to Minecraft mod
    let redirect_url = format!(
        "http://localhost:{}/auth-callback?jwt={}",
        oauth_state.redirect_port, token
    );

    log::info!("OAuth authentication successful for user: {}", username);

    HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish()
}

// Helper function to exchange GitHub code for user info
async fn exchange_github_code(
    app_state: &AppState,
    code: &str,
) -> Result<(String, String), anyhow::Error> {
    let client = reqwest::Client::new();

    // Exchange code for access token
    let token_response = client
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{app_state::OAuthConfig, crypto};
    use actix_web::{test, web, App};
    use bcrypt::hash;
    use chrono::Utc;
    use entity::user;
    use migration::MigratorTrait;
    use sea_orm::{Database, EntityTrait, Set};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn setup_test_db() -> (sea_orm::DatabaseConnection, AppState) {
        let db = Database::connect("sqlite::memory:").await.unwrap();

        // Run migrations
        migration::Migrator::up(&db, None).await.unwrap();

        // Create test user
        let password_hash = hash("testpass", bcrypt::DEFAULT_COST).unwrap();
        let now = Utc::now();
        let test_user = user::ActiveModel {
            username: Set("testuser".to_string()),
            password_hash: Set(password_hash),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };
        user::Entity::insert(test_user).exec(&db).await.unwrap();

        // Generate keys
        let (encoding_key, jwks_json) = crypto::generate_ecdsa_keypair().unwrap();

        let app_state = AppState {
            db: db.clone(),
            encoding_key,
            jwks_json,
            jwt_expiration: 3600,
            oauth_config: OAuthConfig {
                github_client_id: None,
                github_client_secret: None,
                google_client_id: None,
                google_client_secret: None,
                redirect_base: "http://localhost:8080".to_string(),
            },
            oauth_states: Arc::new(RwLock::new(HashMap::new())),
        };

        (db, app_state)
    }

    #[actix_web::test]
    async fn test_get_jwks() {
        let (_db, app_state) = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/.well-known/jwks.json", web::get().to(get_jwks)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/.well-known/jwks.json")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body = test::read_body(resp).await;
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[actix_web::test]
    async fn test_login_success() {
        let (_db, app_state) = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/api/v1/login", web::post().to(login)),
        )
        .await;

        let payload = LoginPayload {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            challenge: "test-challenge".to_string(),
            redirect_port: 25585,
        };

        let req = test::TestRequest::post()
            .uri("/api/v1/login")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body = test::read_body(resp).await;
        let response: LoginResponse = serde_json::from_slice(&body).unwrap();

        assert!(response.redirect_url.contains("localhost:25585"));
        assert!(response.redirect_url.contains("jwt="));
    }

    #[actix_web::test]
    async fn test_login_wrong_password() {
        let (_db, app_state) = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/api/v1/login", web::post().to(login)),
        )
        .await;

        let payload = LoginPayload {
            username: "testuser".to_string(),
            password: "wrongpass".to_string(),
            challenge: "test-challenge".to_string(),
            redirect_port: 25585,
        };

        let req = test::TestRequest::post()
            .uri("/api/v1/login")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_login_user_not_found() {
        let (_db, app_state) = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/api/v1/login", web::post().to(login)),
        )
        .await;

        let payload = LoginPayload {
            username: "nonexistent".to_string(),
            password: "somepass".to_string(),
            challenge: "test-challenge".to_string(),
            redirect_port: 25585,
        };

        let req = test::TestRequest::post()
            .uri("/api/v1/login")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }
}
