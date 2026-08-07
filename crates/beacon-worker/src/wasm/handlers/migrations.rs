use serde::Deserialize;
use serde_json::json;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Response, Result};

use migration::MigratorTrait;
use sea_orm::{ConnectionTrait, Statement};

use crate::wasm::{
    db::db_connect,
    env::env_string,
    http::{error_response, json_with_cors},
};

/// Columns that the current production schema must have on the `users` table. The migration
/// handler verifies these actually exist after `Migrator::up`, so an "applied" record alone
/// doesn't mask a DDL that silently did not take effect (the earlier production bug).
const REQUIRED_USERS_COLUMNS: &[&str] = &["identity_mode", "minecraft_textures_value", "minecraft_textures_signature"];

#[derive(Debug, Deserialize)]
struct CloudflareApiMessage {
    #[allow(dead_code)]
    code: Option<i64>,
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareVerifyResult {
    id: String,
    status: String,
    #[allow(dead_code)]
    expires_on: Option<String>,
    #[allow(dead_code)]
    not_before: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    #[allow(dead_code)]
    errors: Vec<CloudflareApiMessage>,
    #[allow(dead_code)]
    messages: Vec<CloudflareApiMessage>,
    result: Option<T>,
}

fn extract_bearer_token(req: &Request) -> Result<Option<String>> {
    let Some(raw) = req.headers().get("Authorization")? else {
        return Ok(None);
    };

    // Allow some tolerance for casing/whitespace.
    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }

    let token = rest.trim();
    if token.is_empty() {
        return Ok(None);
    }

    Ok(Some(token.to_string()))
}

async fn verify_cloudflare_api_token_against_url(token: &str, url: &str) -> Result<CloudflareVerifyResult> {
    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {token}"))?;
    headers.set("Accept", "application/json")?;
    // Cloudflare API endpoints sometimes behave better with an explicit UA.
    headers.set("User-Agent", "BeaconAuth/1.0 (Cloudflare Worker)")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);

    let cf_req = Request::new_with_init(url, &init)?;

    let mut resp = Fetch::Request(cf_req).send().await?;
    let status = resp.status_code();
    let body = resp.text().await.unwrap_or_default();

    let parsed: CloudflareEnvelope<CloudflareVerifyResult> = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let snippet = body.chars().take(512).collect::<String>();
            return Err(worker::Error::RustError(format!(
                "Cloudflare verify returned non-JSON body (status={status}): {e}; body_snippet={snippet:?}"
            )));
        }
    };

    if !parsed.success {
        let mut details = String::new();
        if !parsed.errors.is_empty() {
            details.push_str(" errors=");
            details.push_str(
                &parsed
                    .errors
                    .iter()
                    .map(|m| {
                        let code = m.code.map(|c| c.to_string()).unwrap_or_else(|| "?".to_string());
                        let msg = m.message.clone().unwrap_or_else(|| "".to_string());
                        format!("[{code}:{msg}]")
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        return Err(worker::Error::RustError(format!(
            "Cloudflare API token verification failed (status={status}, url={url}).{details}"
        )));
    }

    parsed.result.ok_or_else(|| {
        worker::Error::RustError(format!(
            "Cloudflare verify response missing result (status={status}, url={url})"
        ))
    })
}

async fn verify_cloudflare_api_token(env: &Env, token: &str) -> Result<CloudflareVerifyResult> {
    // There are two token "families":
    // - User API tokens: verified via `/user/tokens/verify`
    // - Account API tokens: verified via `/accounts/{account_id}/tokens/verify`
    // See: https://api.cloudflare.com/client/v4/user/tokens/verify
    // See: https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify

    let user_url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
    match verify_cloudflare_api_token_against_url(token, user_url).await {
        Ok(v) => return Ok(v),
        Err(user_err) => {
            if let Some(account_id) = env_string(env, "CLOUDFLARE_ACCOUNT_ID") {
                let account_url = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify"
                );
                match verify_cloudflare_api_token_against_url(token, &account_url).await {
                    Ok(v) => return Ok(v),
                    Err(account_err) => {
                        return Err(worker::Error::RustError(format!(
                            "Cloudflare token verification failed. user_verify={user_err}; account_verify={account_err}"
                        )));
                    }
                }
            }

            Err(worker::Error::RustError(format!(
                "Cloudflare token verification failed using user token endpoint, and CLOUDFLARE_ACCOUNT_ID is not configured for account-token verification: {user_err}"
            )))
        }
    }
}

/// List migration names in a given status set as a sorted Vec<String>.
async fn migration_names(
    db: &sea_orm::DatabaseConnection,
    pending: bool,
) -> Result<Vec<String>, worker::Error> {
    let names = if pending {
        migration::Migrator::get_pending_migrations(db).await
    } else {
        migration::Migrator::get_applied_migrations(db).await
    }
    .map_err(|e| worker::Error::RustError(format!("migration status query failed: {e}")))?;

    let mut out: Vec<String> = names
        .into_iter()
        .map(|m| m.name().to_string())
        .collect();
    out.sort();
    Ok(out)
}

/// Query `PRAGMA table_info(users)` and return the set of column names present.
async fn users_columns(db: &sea_orm::DatabaseConnection) -> Result<Vec<String>, worker::Error> {
    let backend = db.get_database_backend();
    let pragma = if backend == sea_orm::DatabaseBackend::Sqlite {
        "PRAGMA table_info(users)"
    } else {
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"
    };
    let stmt = Statement::from_string(backend, pragma.to_string());
    let rows = db
        .query_all_raw(stmt)
        .await
        .map_err(|e| worker::Error::RustError(format!("column introspection failed: {e}")))?;

    let mut cols = Vec::new();
    for row in rows {
        if let Ok(name) = row.try_get("", "name") {
            cols.push(name);
        }
    }
    cols.sort();
    Ok(cols)
}

pub async fn handle_migrations_up(req: &Request, env: &worker::Env) -> Result<Response> {
    let Some(token) = extract_bearer_token(req)? else {
        return error_response(req, 401, "missing_token", "Missing Authorization Bearer token");
    };

    let verify = match verify_cloudflare_api_token(env, &token).await {
        Ok(v) => v,
        Err(e) => {
            // Log details server-side (no token included) to diagnose CI issues like IP restrictions.
            worker::console_log!("/v1/admin/migrations/up token verification failed: {e}");
            // Do not leak Cloudflare details to clients.
            return error_response(req, 401, "unauthorized", "Invalid Cloudflare API token");
        }
    };

    // Report which database we are about to migrate (host only — never the token/secret).
    let database = env_string(env, "LIBSQL_URL")
        .and_then(|u| {
            let host = u
                .trim_start_matches("libsql://")
                .split('?')
                .next()
                .unwrap_or(&u)
                .to_string();
            Some(host)
        })
        .unwrap_or_else(|| "<unset>".to_string());

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => {
            return error_response(
                req,
                500,
                "migration_error",
                format!("Failed to open database binding (libsql host `{database}`): {e}"),
            )
        }
    };

    // Snapshot before applying so we can diff what `up` actually did.
    let applied_before = match migration_names(&db, false).await {
        Ok(v) => v,
        Err(e) => return error_response(
            req,
            500,
            "migration_error",
            format!("Failed to list applied migrations: {e}"),
        ),
    };
    let pending_before = match migration_names(&db, true).await {
        Ok(v) => v,
        Err(e) => return error_response(
            req,
            500,
            "migration_error",
            format!("Failed to list pending migrations: {e}"),
        ),
    };
    let columns_before = match users_columns(&db).await {
        Ok(v) => v,
        Err(e) => {
            worker::console_log!("Column introspection failed (non-fatal): {e}");
            vec![]
        }
    };
    let missing_before: Vec<&str> = REQUIRED_USERS_COLUMNS
        .iter()
        .copied()
        .filter(|c| !columns_before.contains(&c.to_string()))
        .collect();

    worker::console_log!(
        "migrations/up: db={database} applied_before={applied_before:?} pending_before={pending_before:?} missing_users_columns_before={missing_before:?}"
    );

    if let Err(e) = migration::Migrator::up(&db, None).await {
        return error_response(
            req,
            500,
            "migration_error",
            format!(
                "Failed to apply migrations (db={database}, applied_before={applied_before:?}, pending_before={pending_before:?}): {e}"
            ),
        );
    }

    // Recompute after applying, and verify the DDL actually took effect.
    let applied_after = match migration_names(&db, false).await {
        Ok(v) => v,
        Err(e) => return error_response(
            req,
            500,
            "migration_error",
            format!("Failed to list applied migrations after: {e}"),
        ),
    };
    let pending_after = match migration_names(&db, true).await {
        Ok(v) => v,
        Err(e) => return error_response(
            req,
            500,
            "migration_error",
            format!("Failed to list pending migrations after: {e}"),
        ),
    };
    let columns_after = match users_columns(&db).await {
        Ok(v) => v,
        Err(e) => {
            worker::console_log!("Column introspection after migration failed (non-fatal): {e}");
            vec![]
        }
    };
    let missing_after: Vec<&str> = REQUIRED_USERS_COLUMNS
        .iter()
        .copied()
        .filter(|c| !columns_after.contains(&c.to_string()))
        .collect();

    let newly_applied: Vec<String> = applied_after
        .iter()
        .filter(|m| !applied_before.contains(m))
        .cloned()
        .collect();

    // If our expected columns are still missing after a reported-successful up, that is exactly
    // the silent-DDL-failure mode we want to surface, not paper over.
    let schema_ok = missing_after.is_empty();
    let effective_status = if newly_applied.is_empty() && pending_after.is_empty() && schema_ok {
        "up_to_date"
    } else if newly_applied.is_empty() && !pending_after.is_empty() {
        "pending_remain"
    } else if !schema_ok {
        "schema_incomplete"
    } else {
        "applied"
    };

    let resp = Response::from_json(&json!({
        "success": true,
        "database": {
            // Host only. Credentials/tokens are never returned.
            "host": database,
        },
        "token": {
            "id": verify.id,
            "status": verify.status,
        },
        "migration_table": migration::Migrator::migration_table_name().to_string(),
        "migrations": {
            "status": effective_status,
            "applied_before": applied_before,
            "applied_after": applied_after,
            "newly_applied": newly_applied,
            "pending_after": pending_after,
        },
        "schema": {
            "users_columns": columns_after,
            "missing_required_columns": missing_after,
            "required_columns_ok": schema_ok,
        }
    }))?;

    worker::console_log!(
        "migrations/up done: status={effective_status} newly_applied={newly_applied:?} pending_after={pending_after:?} missing_after={missing_after:?}"
    );

    json_with_cors(req, resp)
}
