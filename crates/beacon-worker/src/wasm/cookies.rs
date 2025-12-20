use worker::{Headers, Request, Result};

pub fn get_cookie(req: &Request, name: &str) -> Result<Option<String>> {
    let Some(header) = req.headers().get("Cookie")? else {
        return Ok(None);
    };

    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Ok(Some(v.trim().to_string()));
            }
        }
    }

    Ok(None)
}

pub fn append_set_cookie(headers: &mut Headers, value: &str) -> Result<()> {
    headers.append("Set-Cookie", value)
}

pub fn cookie_kv(name: &str, value: &str, max_age_seconds: i64) -> String {
    // Keep settings aligned with the Actix server: HttpOnly + SameSite=Strict + Path=/.
    // (We intentionally do not force Secure here because some dev flows use http.)
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_seconds}"
    )
}

pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0")
}
