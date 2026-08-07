use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use worker::{Env, Error, Result};

use beacon_core::crypto;
use entity::{identity, jwks_key, passkey, passkey_state, refresh_token, user};
use migration::MigratorTrait;
use uuid::Uuid;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use sea_orm::sea_query::Expr;

use super::{env::env_string, util::now_ts};

/// Guards the lazily-run auto-migration so it only runs once per isolate, and only after a
/// successful connection. This makes the Worker self-heal its schema on the first DB-touching
/// request after a deploy, regardless of which Turso/LibSQL URL is bound at runtime.
static MIGRATION_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static MIGRATION_DONE: AtomicBool = AtomicBool::new(false);

pub type UserRow = user::Model;
pub type RefreshTokenRow = refresh_token::Model;
pub type PasskeyDbRow = passkey::Model;
pub type IdentityRow = identity::Model;
pub type PasskeyStateRow = passkey_state::Model;
pub type JwksKeyRow = jwks_key::Model;

pub const PASSKEY_STATE_TTL_SECS: i64 = 5 * 60;

pub fn passkey_reg_state_key(user_id: &str) -> String {
    format!("passkey:reg:{user_id}")
}

pub fn passkey_auth_state_key(challenge_b64: &str) -> String {
    format!("passkey:auth:{challenge_b64}")
}

fn map_db_err(e: sea_orm::DbErr) -> Error {
    Error::RustError(e.to_string())
}

pub async fn db_connect(env: &Env) -> Result<DatabaseConnection> {
    let url = env_string(env, "LIBSQL_URL").ok_or_else(|| {
        Error::RustError("LIBSQL_URL is required for libsql connections".to_string())
    })?;

    let mut options = ConnectOptions::new(url);
    if let Some(token) = env_string(env, "LIBSQL_AUTH_TOKEN") {
        options.libsql_auth_token(token);
    }

    // Worker runtime note:
    // - Cloudflare may suspend/resume isolates and aggressively limit background activity.
    // - Some connection pool defaults can lead to "never resolves" behavior in edge runtimes.
    // Keep the pool tiny and prefer short timeouts so requests fail fast instead of hanging.
    options.max_connections(1);
    options.min_connections(0);
    options.connect_timeout(Duration::from_secs(5));
    options.acquire_timeout(Duration::from_secs(5));
    options.idle_timeout(Duration::from_secs(30));
    options.sqlx_logging(false);

    let db = Database::connect(options).await.map_err(map_db_err)?;

    // Self-heal the schema on first use. `Migrator::up` is idempotent (only applies pending
    // migrations), so this is safe to run on every fresh isolate. We guard it so it runs at
    // most once per isolate and never blocks the request's DB work on a later retry.
    if !MIGRATION_DONE.load(Ordering::Acquire) && !MIGRATION_ATTEMPTED.swap(true, Ordering::AcqRel) {
        match migration::Migrator::up(&db, None).await {
            Ok(_) => {
                MIGRATION_DONE.store(true, Ordering::Release);
                worker::console_log!("Auto-migration: schema is up to date");
            }
            Err(e) => {
                // Transient connection/lock errors during cold start should not fail user
                // requests. The migration is re-attempted on the next fresh isolate.
                worker::console_log!("Auto-migration failed (will retry on next isolate): {e}");
            }
        }
    }

    Ok(db)
}

pub async fn db_user_by_username(db: &DatabaseConnection, username: &str) -> Result<Option<UserRow>> {
    let username_lower = beacon_core::username::normalize_username(username);
    user::Entity::find()
        .filter(user::Column::UsernameLower.eq(username_lower))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_user_by_id(db: &DatabaseConnection, id: &str) -> Result<Option<UserRow>> {
    user::Entity::find_by_id(id.to_string())
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_insert_user(db: &DatabaseConnection, username: &str) -> Result<String> {
    let ts = now_ts();
    let username_lower = beacon_core::username::normalize_username(username);

    let user_id = Uuid::now_v7().to_string();

    // NOTE: Insert metadata (rows_affected / last_insert_id) is not always available/reliable
    // across drivers and edge environments. Insert and then reload by the known primary key.
    let new_user = user::ActiveModel {
        id: Set(user_id.clone()),
        username: Set(username.to_string()),
        username_lower: Set(username_lower.clone()),
        created_at: Set(ts),
        updated_at: Set(ts),
        ..Default::default()
    };

    // Use exec_without_returning + reload by primary key.
    user::Entity::insert(new_user)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    let Some(user) = db_user_by_id(db, &user_id).await? else {
        return Err(Error::RustError("Inserted user could not be reloaded".to_string()));
    };

    Ok(user.id)
}

pub async fn db_update_user_username(
    db: &DatabaseConnection,
    user_id: &str,
    username: &str,
    username_lower: &str,
) -> Result<()> {
    let ts = now_ts();
    user::Entity::update_many()
        .col_expr(user::Column::Username, Expr::value(username))
        .col_expr(user::Column::UsernameLower, Expr::value(username_lower))
        .col_expr(user::Column::UpdatedAt, Expr::value(ts))
        .filter(user::Column::Id.eq(user_id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_update_user_profile_fields(
    db: &DatabaseConnection,
    user_id: &str,
    email: Option<String>,
    avatar_source: Option<String>,
) -> Result<()> {
    let Some(row) = db_user_by_id(db, user_id).await? else {
        return Err(Error::RustError("User not found".to_string()));
    };

    let ts = now_ts();
    let mut active: user::ActiveModel = row.into();
    active.email = Set(email);
    active.avatar_source = Set(avatar_source);
    active.updated_at = Set(ts);

    active.update(db).await.map_err(map_db_err)?;
    Ok(())
}

pub async fn db_update_user_avatar_cache(
    db: &DatabaseConnection,
    user_id: &str,
    provider: &str,
    avatar_url: Option<&str>,
    microsoft_avatar_b64: Option<&str>,
    microsoft_avatar_content_type: Option<&str>,
) -> Result<()> {
    let Some(row) = db_user_by_id(db, user_id).await? else {
        return Err(Error::RustError("User not found".to_string()));
    };

    let ts = now_ts();
    let mut active: user::ActiveModel = row.clone().into();
    active.updated_at = Set(ts);

    match provider {
        "github" => {
            if let Some(url) = avatar_url {
                active.github_avatar_url = Set(Some(url.to_string()));
            }
        }
        "google" => {
            if let Some(url) = avatar_url {
                active.google_avatar_url = Set(Some(url.to_string()));
            }
        }
        "microsoft" => {
            if let Some(b64) = microsoft_avatar_b64 {
                active.microsoft_avatar_b64 = Set(Some(b64.to_string()));
                active.microsoft_avatar_content_type =
                    Set(microsoft_avatar_content_type.map(|s| s.to_string()));
            }
        }
        _ => {}
    }

    // If the user has never chosen an avatar source, default it to the current provider
    // when we successfully captured an avatar for that provider.
    if row.avatar_source.is_none() {
        if provider == "github" && avatar_url.is_some() {
            active.avatar_source = Set(Some("github".to_string()));
        } else if provider == "google" && avatar_url.is_some() {
            active.avatar_source = Set(Some("google".to_string()));
        } else if provider == "microsoft" && microsoft_avatar_b64.is_some() {
            active.avatar_source = Set(Some("microsoft".to_string()));
        }
    }

    active.update(db).await.map_err(map_db_err)?;
    Ok(())
}

/// Cache the Mojang-signed `textures` profile property for a Minecraft-bound user.
pub async fn db_update_user_minecraft_textures(
    db: &DatabaseConnection,
    user_id: &str,
    textures_value: Option<&str>,
    textures_signature: Option<&str>,
) -> Result<()> {
    let Some(row) = db_user_by_id(db, user_id).await? else {
        return Err(Error::RustError("User not found".to_string()));
    };

    let ts = now_ts();
    let mut active: user::ActiveModel = row.into();
    active.updated_at = Set(ts);
    if let Some(v) = textures_value {
        active.minecraft_textures_value = Set(Some(v.to_string()));
    }
    if let Some(s) = textures_signature {
        active.minecraft_textures_signature = Set(Some(s.to_string()));
    }

    active.update(db).await.map_err(map_db_err)?;
    Ok(())
}

/// Set the per-user Minecraft identity preference ("mojang" | "legacy").
pub async fn db_update_user_identity_mode(
    db: &DatabaseConnection,
    user_id: &str,
    mode: &str,
) -> Result<()> {
    let Some(row) = db_user_by_id(db, user_id).await? else {
        return Err(Error::RustError("User not found".to_string()));
    };

    let ts = now_ts();
    let mut active: user::ActiveModel = row.into();
    active.updated_at = Set(ts);
    active.identity_mode = Set(Some(mode.to_string()));

    active.update(db).await.map_err(map_db_err)?;
    Ok(())
}

pub async fn db_passkeys_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<Vec<PasskeyDbRow>> {
    passkey::Entity::find()
    .filter(passkey::Column::UserId.eq(user_id.to_string()))
        .order_by_desc(passkey::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_passkeys_all(db: &DatabaseConnection) -> Result<Vec<PasskeyDbRow>> {
    passkey::Entity::find()
        .order_by_desc(passkey::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_passkey_by_id(db: &DatabaseConnection, id: &str) -> Result<Option<PasskeyDbRow>> {
    passkey::Entity::find_by_id(id.to_string())
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_passkey_by_credential_id(
    db: &DatabaseConnection,
    credential_id: &str,
) -> Result<Option<PasskeyDbRow>> {
    passkey::Entity::find()
        .filter(passkey::Column::CredentialId.eq(credential_id))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_insert_passkey(
    db: &DatabaseConnection,
    user_id: &str,
    credential_id: &str,
    credential_data: &str,
    name: &str,
) -> Result<String> {
    let ts = now_ts();

    let passkey_id = Uuid::now_v7().to_string();

    let new_passkey = passkey::ActiveModel {
        id: Set(passkey_id.clone()),
        user_id: Set(user_id.to_string()),
        credential_id: Set(credential_id.to_string()),
        credential_data: Set(credential_data.to_string()),
        name: Set(name.to_string()),
        last_used_at: Set(None),
        created_at: Set(ts),
        ..Default::default()
    };

    // See note in db_insert_user (insert metadata can be unreliable).
    passkey::Entity::insert(new_passkey)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    let Some(row) = db_passkey_by_credential_id(db, credential_id).await? else {
        return Err(Error::RustError("Inserted passkey could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn db_update_passkey_usage(
    db: &DatabaseConnection,
    id: &str,
    credential_data: &str,
    last_used_at: i64,
) -> Result<()> {
    passkey::Entity::update_many()
        .col_expr(passkey::Column::CredentialData, Expr::value(credential_data))
        .col_expr(passkey::Column::LastUsedAt, Expr::value(last_used_at))
        .filter(passkey::Column::Id.eq(id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_delete_passkey_by_id(db: &DatabaseConnection, id: &str) -> Result<()> {
    passkey::Entity::delete_by_id(id.to_string())
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_insert_refresh_token(
    db: &DatabaseConnection,
    user_id: &str,
    token_hash: &str,
    family_id: &str,
    expires_at: i64,
) -> Result<()> {
    let ts = now_ts();

    let refresh_token_id = Uuid::now_v7().to_string();

    let model = refresh_token::ActiveModel {
        id: Set(refresh_token_id),
        user_id: Set(user_id.to_string()),
        token_hash: Set(token_hash.to_string()),
        family_id: Set(family_id.to_string()),
        expires_at: Set(expires_at),
        revoked: Set(0),
        created_at: Set(ts),
        ..Default::default()
    };

    // Use exec_without_returning to avoid DbErr::RecordNotInserted when the driver reports 0 rows_affected.
    refresh_token::Entity::insert(model)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    // Verify that the inserted row exists and matches our expected values.
    // This also helps detect the extremely unlikely case of token hash collision.
    let Some(row) = db_refresh_token_by_hash(db, token_hash).await? else {
        return Err(Error::RustError(
            "Inserted refresh token could not be reloaded".to_string(),
        ));
    };
    if row.user_id != user_id
        || row.family_id != family_id
        || row.expires_at != expires_at
        || row.created_at != ts
    {
        return Err(Error::RustError(
            "Refresh token insert did not persist expected row (possible hash collision)"
                .to_string(),
        ));
    }

    Ok(())
}

pub async fn db_refresh_token_by_hash(
    db: &DatabaseConnection,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_revoke_refresh_token_by_id(db: &DatabaseConnection, id: &str) -> Result<()> {
    refresh_token::Entity::update_many()
        .col_expr(refresh_token::Column::Revoked, Expr::value(1_i64))
        .filter(refresh_token::Column::Id.eq(id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_revoke_all_refresh_tokens_for_user(db: &DatabaseConnection, user_id: &str) -> Result<()> {
    refresh_token::Entity::update_many()
        .col_expr(refresh_token::Column::Revoked, Expr::value(1_i64))
        .filter(refresh_token::Column::UserId.eq(user_id.to_string()))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_identity_by_provider_user_id(
    db: &DatabaseConnection,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<IdentityRow>> {
    identity::Entity::find()
        .filter(identity::Column::Provider.eq(provider))
        .filter(identity::Column::ProviderUserId.eq(provider_user_id))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_identity_by_id(db: &DatabaseConnection, id: &str) -> Result<Option<IdentityRow>> {
    identity::Entity::find_by_id(id.to_string())
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_identities_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<Vec<IdentityRow>> {
    identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .order_by_desc(identity::Column::CreatedAt)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_insert_identity(
    db: &DatabaseConnection,
    user_id: &str,
    provider: &str,
    provider_user_id: &str,
    password_hash: Option<&str>,
) -> Result<String> {
    let ts = now_ts();

    let identity_id = Uuid::now_v7().to_string();

    let model = identity::ActiveModel {
        id: Set(identity_id),
        user_id: Set(user_id.to_string()),
        provider: Set(provider.to_string()),
        provider_user_id: Set(provider_user_id.to_string()),
        password_hash: Set(password_hash.map(|s| s.to_string())),
        created_at: Set(ts),
        updated_at: Set(ts),
        ..Default::default()
    };

    // See note in db_insert_user (insert metadata can be unreliable).
    identity::Entity::insert(model)
        .exec_without_returning(db)
        .await
        .map_err(map_db_err)?;

    // Reload by the unique pair.
    let Some(row) = db_identity_by_provider_user_id(db, provider, provider_user_id).await? else {
        return Err(Error::RustError("Inserted identity could not be reloaded".to_string()));
    };

    Ok(row.id)
}

pub async fn db_password_identity_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<Option<IdentityRow>> {
    identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .filter(identity::Column::Provider.eq("password"))
        .one(db)
        .await
        .map_err(map_db_err)
}

pub async fn db_password_identity_by_identifier(
    db: &DatabaseConnection,
    identifier: &str,
) -> Result<Option<IdentityRow>> {
    let identifier_lower = beacon_core::username::normalize_username(identifier);

    identity::Entity::find()
        .filter(identity::Column::Provider.eq("password"))
        .filter(identity::Column::ProviderUserId.eq(identifier_lower))
        .one(db)
        .await
        .map_err(map_db_err)
}

    pub async fn db_update_password_identity_hash(db: &DatabaseConnection, user_id: &str, new_hash: &str) -> Result<()> {
    let ts = now_ts();

    identity::Entity::update_many()
        .col_expr(identity::Column::PasswordHash, Expr::value(new_hash))
        .col_expr(identity::Column::UpdatedAt, Expr::value(ts))
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .filter(identity::Column::Provider.eq("password"))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_update_password_identity_identifier(
    db: &DatabaseConnection,
    user_id: &str,
    new_identifier: &str,
) -> Result<()> {
    let ts = now_ts();

    identity::Entity::update_many()
        .col_expr(identity::Column::ProviderUserId, Expr::value(new_identifier))
        .col_expr(identity::Column::UpdatedAt, Expr::value(ts))
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .filter(identity::Column::Provider.eq("password"))
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_delete_identity_by_id(db: &DatabaseConnection, id: &str) -> Result<()> {
    identity::Entity::delete_by_id(id.to_string())
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_count_identities_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<i64> {
    let count = identity::Entity::find()
        .filter(identity::Column::UserId.eq(user_id.to_string()))
        .count(db)
        .await
        .map_err(map_db_err)?;

    Ok(count as i64)
}

pub async fn db_count_passkeys_by_user_id(db: &DatabaseConnection, user_id: &str) -> Result<i64> {
    let count = passkey::Entity::find()
        .filter(passkey::Column::UserId.eq(user_id.to_string()))
        .count(db)
        .await
        .map_err(map_db_err)?;

    Ok(count as i64)
}

pub async fn db_put_passkey_state<T: Serialize>(
    db: &DatabaseConnection,
    key: &str,
    state: &T,
    ttl_secs: i64,
) -> Result<()> {
    let now = now_ts();
    let expires_at = now + ttl_secs;
    let state_json = serde_json::to_string(state)
        .map_err(|e| Error::RustError(e.to_string()))?;

    if let Some(existing) = passkey_state::Entity::find_by_id(key.to_string())
        .one(db)
        .await
        .map_err(map_db_err)?
    {
        let mut model: passkey_state::ActiveModel = existing.into();
        model.state_json = Set(state_json);
        model.expires_at = Set(expires_at);
        model.created_at = Set(now);
        passkey_state::Entity::update(model)
            .exec(db)
            .await
            .map_err(map_db_err)?;
        return Ok(());
    }

    let model = passkey_state::ActiveModel {
        key: Set(key.to_string()),
        state_json: Set(state_json),
        expires_at: Set(expires_at),
        created_at: Set(now),
        ..Default::default()
    };

    passkey_state::Entity::insert(model)
        .exec(db)
        .await
        .map_err(map_db_err)?;

    Ok(())
}

pub async fn db_take_passkey_state<T: DeserializeOwned>(
    db: &DatabaseConnection,
    key: &str,
) -> Result<Option<T>> {
    let Some(row) = passkey_state::Entity::find_by_id(key.to_string())
        .one(db)
        .await
        .map_err(map_db_err)?
    else {
        return Ok(None);
    };

    // Delete regardless to prevent replays.
    let _ = passkey_state::Entity::delete_by_id(key.to_string())
        .exec(db)
        .await;

    if row.expires_at <= now_ts() {
        return Ok(None);
    }

    let parsed = serde_json::from_str(&row.state_json)
        .map_err(|e| Error::RustError(e.to_string()))?;
    Ok(Some(parsed))
}

pub async fn db_get_or_create_jwks(
    db: &DatabaseConnection,
    kid: &str,
) -> Result<(jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey, String)> {
    if let Some(row) = jwks_key::Entity::find_by_id(kid.to_string())
        .one(db)
        .await
        .map_err(map_db_err)?
    {
        let pkcs8 = crypto::decode_pkcs8_der_b64(&row.pkcs8_der_b64)
            .map_err(|e| Error::RustError(e.to_string()))?;
        let (encoding, decoding, jwks_json) =
            crypto::ecdsa_keypair_from_pkcs8_der(&pkcs8, &row.kid)
                .map_err(|e| Error::RustError(e.to_string()))?;
        return Ok((encoding, decoding, jwks_json));
    }

    let pkcs8 = crypto::generate_ecdsa_pkcs8_der()
        .map_err(|e| Error::RustError(e.to_string()))?;
    let (encoding, decoding, jwks_json) =
        crypto::ecdsa_keypair_from_pkcs8_der(&pkcs8, kid)
            .map_err(|e| Error::RustError(e.to_string()))?;
    let pkcs8_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pkcs8);
    let now = now_ts();

    let model = jwks_key::ActiveModel {
        kid: Set(kid.to_string()),
        pkcs8_der_b64: Set(pkcs8_b64),
        jwks_json: Set(jwks_json.clone()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = jwks_key::Entity::insert(model)
        .exec_without_returning(db)
        .await
    {
        let msg = e.to_string();
        if msg.to_ascii_lowercase().contains("unique") {
            if let Some(row) = jwks_key::Entity::find_by_id(kid.to_string())
                .one(db)
                .await
                .map_err(map_db_err)?
            {
                let pkcs8 = crypto::decode_pkcs8_der_b64(&row.pkcs8_der_b64)
                    .map_err(|e| Error::RustError(e.to_string()))?;
                let (encoding, decoding, jwks_json) =
                    crypto::ecdsa_keypair_from_pkcs8_der(&pkcs8, &row.kid)
                        .map_err(|e| Error::RustError(e.to_string()))?;
                return Ok((encoding, decoding, jwks_json));
            }
        }
        return Err(map_db_err(e));
    }

    Ok((encoding, decoding, jwks_json))
}

pub async fn db_list_jwks_keys_by_kid_prefix(
    db: &DatabaseConnection,
    kid_prefix: &str,
    rotating_limit: u64,
) -> Result<Vec<JwksKeyRow>> {
    let mut rows: Vec<JwksKeyRow> = Vec::new();

    // Legacy / non-rotating kid: include if present (backwards compatible rollout).
    if let Some(row) = jwks_key::Entity::find_by_id(kid_prefix.to_string())
        .one(db)
        .await
        .map_err(map_db_err)?
    {
        rows.push(row);
    }

    // Rotating kids: include the most recently created N keys.
    let dashed_prefix = format!("{kid_prefix}-");
    let rotating = jwks_key::Entity::find()
        .filter(jwks_key::Column::Kid.starts_with(dashed_prefix))
        .order_by_desc(jwks_key::Column::CreatedAt)
        .limit(rotating_limit)
        .all(db)
        .await
        .map_err(map_db_err)?;

    rows.extend(rotating);
    Ok(rows)
}
