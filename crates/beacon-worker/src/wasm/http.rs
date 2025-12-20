use beacon_core::models;
use worker::{console_log, Request, Response, Result};

pub fn json_with_cors(req: &Request, mut resp: Response) -> Result<Response> {
    let origin = req.headers().get("Origin")?.unwrap_or_else(|| "*".to_string());

    resp.headers_mut().set("Access-Control-Allow-Origin", &origin)?;
    resp.headers_mut().set("Access-Control-Allow-Credentials", "true")?;
    resp.headers_mut().set("Access-Control-Allow-Headers", "Content-Type, Authorization")?;
    resp.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")?;
    Ok(resp)
}

pub fn error_response(
    req: &Request,
    status: u16,
    error: &str,
    message: impl Into<String>,
) -> Result<Response> {
    let resp = Response::from_json(&models::ErrorResponse {
        error: error.to_string(),
        message: message.into(),
    })?
    .with_status(status);
    json_with_cors(req, resp)
}

pub fn internal_error_response(
    req: &Request,
    context: &str,
    err: &dyn std::fmt::Display,
) -> Result<Response> {
    // Log detailed server-side context for diagnostics.
    // Client receives a stable, non-sensitive message.
    console_log!("{context}: {err}");
    error_response(req, 500, "internal_error", context)
}

pub fn not_found(req: &Request) -> Result<Response> {
    let resp = Response::from_json(&models::ErrorResponse {
        error: "not_found".to_string(),
        message: "Route not found".to_string(),
    })?
    .with_status(404);
    json_with_cors(req, resp)
}

pub fn method_not_allowed(req: &Request) -> Result<Response> {
    let resp = Response::from_json(&models::ErrorResponse {
        error: "method_not_allowed".to_string(),
        message: "Method not allowed".to_string(),
    })?
    .with_status(405);
    json_with_cors(req, resp)
}

