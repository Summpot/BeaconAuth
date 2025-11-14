use jsonwebtoken::EncodingKey;
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::OAuthState;

/// Shared application state
pub struct AppState {
    /// Sea-ORM database connection pool
    pub db: DatabaseConnection,

    /// ECDSA private key for signing JWTs (ES256)
    pub encoding_key: EncodingKey,

    /// Pre-generated JWKS JSON string containing the public key (EC P-256)
    pub jwks_json: String,

    /// JWT expiration time in seconds
    pub jwt_expiration: i64,

    /// OAuth configuration
    pub oauth_config: OAuthConfig,

    /// Temporary OAuth state storage (state_token -> OAuthState)
    pub oauth_states: Arc<RwLock<HashMap<String, OAuthState>>>,
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub redirect_base: String,
}
