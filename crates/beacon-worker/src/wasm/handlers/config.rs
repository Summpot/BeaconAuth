use beacon_core::models;
use worker::{Cache, Env, Method, Request, RequestInit, Response, Result};

use crate::wasm::{
    env::env_string,
    http::json_with_cors,
    state::get_jwt_state,
    util::{now_ts, sha256_hex},
};

pub async fn handle_get_config(req: &Request, env: &Env) -> Result<Response> {
    // We can infer OAuth config from env variables, even if Workers OAuth routes are not enabled yet.
    let github_ok = env_string(env, "GITHUB_CLIENT_ID").is_some()
        && env_string(env, "GITHUB_CLIENT_SECRET").is_some();
    let google_ok = env_string(env, "GOOGLE_CLIENT_ID").is_some()
        && env_string(env, "GOOGLE_CLIENT_SECRET").is_some();
    let microsoft_ok = env_string(env, "MICROSOFT_CLIENT_ID").is_some()
        && env_string(env, "MICROSOFT_CLIENT_SECRET").is_some();

    let body = models::ConfigResponse {
        database_auth: true,
        github_oauth: github_ok,
        google_oauth: google_ok,
        microsoft_oauth: microsoft_ok,
    };

    let resp = Response::from_json(&body)?;
    json_with_cors(req, resp)
}

pub async fn handle_get_jwks(req: &Request, env: &Env) -> Result<Response> {
    // JWKS is public and changes rarely. Cache it at the edge using the Workers Cache API.
    //
    // IMPORTANT: Cache API requires a cache-control header with max-age or s-maxage.
    // See: https://developers.cloudflare.com/workers/runtime-apis/cache/
    let max_age = env_string(env, "JWKS_CACHE_MAX_AGE")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(3600);
    let s_maxage = env_string(env, "JWKS_CACHE_S_MAXAGE")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(86400);

    // Canonicalize the cache key so both `/.well-known/jwks.json` and `/api/.well-known/jwks.json`
    // share a single cache entry.
    let mut cache_url = req.url()?;
    if cache_url.path().ends_with("/.well-known/jwks.json") {
        cache_url.set_path("/.well-known/jwks.json");
    }
    cache_url.set_query(None);

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let cache_key_req = Request::new_with_init(cache_url.as_str(), &init)?;

    let cache = Cache::default();
    if let Some(resp) = cache.get(&cache_key_req, false).await? {
        // Prevent serving a stale JWKS across a rotation boundary.
        // Cache API does not revalidate by ETag; we must enforce freshness ourselves.
        if let Some(not_after_raw) = resp.headers().get("X-JWKS-Not-After")? {
            if let Ok(not_after) = not_after_raw.parse::<i64>() {
                if now_ts() < not_after {
                    return Ok(resp);
                }
            }
        }
    }

    // Cache miss: build the JWKS response.
    // We fetch JwtState only after checking the cache to avoid unnecessary cold-start DB work.
    let jwt = get_jwt_state(env).await?;
    let etag = format!("\"{}\"", sha256_hex(&jwt.jwks_json));
    let not_after = jwt.next_jwks_rotation_at;

    // If the client already has this JWKS, allow an efficient conditional response.
    if let Some(if_none_match) = req.headers().get("If-None-Match")? {
        let matched = if_none_match
            .split(',')
            .map(|v| v.trim())
            .any(|v| v == "*" || v == etag);
        if matched {
            let mut resp = Response::empty()?.with_status(304);
            resp.headers_mut().set("ETag", &etag)?;
            resp.headers_mut().set("X-JWKS-Not-After", &not_after.to_string())?;
            resp.headers_mut().set(
                "Cache-Control",
                &format!("public, max-age={max_age}, s-maxage={s_maxage}"),
            )?;
            // JWKS is public; keep CORS invariant so it can be safely cached/shared.
            resp.headers_mut().set("Access-Control-Allow-Origin", "*")?;
            resp.headers_mut().set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
            return Ok(resp);
        }
    }

    let build_response = |body: &str| -> Result<Response> {
        let mut resp = Response::ok(body.to_string())?;
        resp.headers_mut().set("Content-Type", "application/json")?;
        resp.headers_mut().set(
            "Cache-Control",
            &format!("public, max-age={max_age}, s-maxage={s_maxage}"),
        )?;
        resp.headers_mut().set("ETag", &etag)?;
        resp.headers_mut().set("X-JWKS-Not-After", &not_after.to_string())?;
        // JWKS is public; keep CORS invariant so it can be safely cached/shared.
        resp.headers_mut().set("Access-Control-Allow-Origin", "*")?;
        resp.headers_mut().set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
        Ok(resp)
    };

    let resp_for_cache = build_response(&jwt.jwks_json)?;
    // Best-effort: never fail the request if cache.put fails.
    let _ = cache.put(&cache_key_req, resp_for_cache).await;

    build_response(&jwt.jwks_json)
}
