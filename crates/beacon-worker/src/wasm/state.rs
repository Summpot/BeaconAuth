use std::sync::{Mutex, OnceLock};

use serde_json::Value;
use url::Url;
use worker::{Env, Error, Result};

use super::{
    db::{db_connect, db_get_or_create_jwks, db_list_jwks_keys_by_kid_prefix},
    env::env_string,
    util::now_ts,
};

const JWKS_ROTATION_SECS: i64 = 24 * 60 * 60;
const JWKS_PUBLISHED_ROTATING_KEYS: u64 = 2;

#[derive(Clone)]
pub struct JwtState {
    pub issuer: String,
    /// JWKS URL to advertise in the JWT header `jku`.
    pub jwks_url: String,
    /// Allowed host patterns for trusting token header `jku` (SSRF protection).
    ///
    /// Patterns are comma/space-separated. Supported:
    /// - `example.com`
    /// - `*.example.com` (matches both `example.com` and any subdomain)
    pub jku_allowed_host_patterns: Vec<String>,
    pub kid: String,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
    pub jwks_json: String,
    /// Timestamp at which the worker should refresh/rotate its active signing key.
    pub next_jwks_rotation_at: i64,

    pub access_token_expiration: i64,
    pub refresh_token_expiration: i64,
    pub jwt_expiration: i64,
}

static JWT_STATE: OnceLock<Mutex<JwtState>> = OnceLock::new();

static PASSKEY_RP: OnceLock<beacon_passkey::RpConfig> = OnceLock::new();

fn format_rotating_kid(prefix: &str, bucket: i64) -> String {
    if prefix.ends_with('-') {
        format!("{prefix}{bucket}")
    } else {
        format!("{prefix}-{bucket}")
    }
}

fn mutex_poisoned(name: &str) -> Error {
    Error::RustError(format!("{name} mutex poisoned"))
}

async fn init_jwt_state(env: &Env) -> Result<JwtState> {
    let issuer = env_string(env, "BASE_URL").unwrap_or_else(|| "https://beaconauth.pages.dev".to_string());
    let kid_prefix = env_string(env, "JWT_KID").unwrap_or_else(|| "beacon-auth-key-1".to_string());

    // BeaconAuth is JWKS-first: this worker serves its public key at `/.well-known/jwks.json` and
    // advertises that URL via the JWT header `jku`.
    //
    // Use libsql to persist the ES256 keypair so all worker instances share the same JWKS.
    let db = db_connect(env).await?;

    let now = now_ts();
    let bucket = now / JWKS_ROTATION_SECS;
    let kid = format_rotating_kid(&kid_prefix, bucket);
    let next_jwks_rotation_at = (bucket + 1) * JWKS_ROTATION_SECS;

    let (encoding_key, decoding_key, active_jwks_json) = db_get_or_create_jwks(&db, &kid).await?;

    // Build a multi-key JWKS set. We keep the current and previous rotation keys published
    // at the same time to avoid edge cases where an access token minted right before rotation
    // becomes unverifiable right after.
    let jwks_rows = db_list_jwks_keys_by_kid_prefix(&db, &kid_prefix, JWKS_PUBLISHED_ROTATING_KEYS).await?;
    let mut keys: Vec<Value> = Vec::new();
    for row in jwks_rows {
        let parsed: Value = serde_json::from_str(&row.jwks_json)
            .map_err(|e| Error::RustError(format!("Invalid JWKS JSON in database for kid='{}': {e}", row.kid)))?;
        if let Some(arr) = parsed.get("keys").and_then(|v| v.as_array()) {
            for k in arr {
                keys.push(k.clone());
            }
        }
    }
    // Fallback: never publish an empty JWKS.
    if keys.is_empty() {
        let parsed: Value = serde_json::from_str(&active_jwks_json)
            .map_err(|e| Error::RustError(format!("Failed to parse active JWKS JSON: {e}")))?;
        if let Some(arr) = parsed.get("keys").and_then(|v| v.as_array()) {
            for k in arr {
                keys.push(k.clone());
            }
        }
    }
    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": keys }))
        .map_err(|e| Error::RustError(e.to_string()))?;

    let jwks_url = env_string(env, "JWKS_URL").unwrap_or_else(|| {
        format!(
            "{}/.well-known/jwks.json",
            issuer.trim_end_matches('/')
        )
    });

    let jku_allowed_host_patterns = env_string(env, "JKU_ALLOWED_HOST_PATTERNS")
        .map(|raw| {
            raw.split(|c: char| c == ',' || c.is_whitespace())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            // Default to trusting only our own configured JWKS host.
            // This keeps JKU enabled for same-origin tokens while mitigating SSRF.
            let host = Url::parse(&jwks_url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()));
            host.into_iter().collect()
        });

    let access_token_expiration = env_string(env, "ACCESS_TOKEN_EXPIRATION")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(900);

    let refresh_token_expiration = env_string(env, "REFRESH_TOKEN_EXPIRATION")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2_592_000);

    let jwt_expiration = env_string(env, "JWT_EXPIRATION")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3600);

    Ok(JwtState {
        issuer,
        jwks_url,
        jku_allowed_host_patterns,
        kid,
        encoding_key,
        decoding_key,
        jwks_json,
        next_jwks_rotation_at,
        access_token_expiration,
        refresh_token_expiration,
        jwt_expiration,
    })
}

pub async fn get_jwt_state(env: &Env) -> Result<JwtState> {
    // Fast path: initialized and not yet due for rotation.
    if let Some(m) = JWT_STATE.get() {
        let now = now_ts();
        let snapshot = {
            let guard = m.lock().map_err(|_| mutex_poisoned("JWT_STATE"))?;
            guard.clone()
        };
        if now < snapshot.next_jwks_rotation_at {
            return Ok(snapshot);
        }

        // Due for rotation/refresh.
        let refreshed = init_jwt_state(env).await?;
        {
            let mut guard = m.lock().map_err(|_| mutex_poisoned("JWT_STATE"))?;
            *guard = refreshed.clone();
        }
        return Ok(refreshed);
    }

    // First initialization.
    let state = init_jwt_state(env).await?;
    let _ = JWT_STATE.set(Mutex::new(state.clone()));
    Ok(state)
}

fn init_passkey_rp(env: &Env) -> Result<beacon_passkey::RpConfig> {
    let base_url = env_string(env, "BASE_URL").unwrap_or_else(|| "https://beaconauth.pages.dev".to_string());
    let rp_origin = Url::parse(&base_url)
        .map_err(|e| Error::RustError(format!("Invalid BASE_URL '{base_url}': {e}")))?;

    let rp_id = rp_origin
        .host_str()
        .ok_or_else(|| Error::RustError("BASE_URL must include a host".to_string()))?
        .to_string();

    Ok(beacon_passkey::RpConfig::new(rp_id, rp_origin, "BeaconAuth"))
}

pub fn get_passkey_rp(env: &Env) -> Result<&'static beacon_passkey::RpConfig> {
    if let Some(rp) = PASSKEY_RP.get() {
        return Ok(rp);
    }

    let rp = init_passkey_rp(env)?;
    let _ = PASSKEY_RP.set(rp);
    Ok(PASSKEY_RP
        .get()
        .expect("PASSKEY_RP must be initialized after set()"))
}
