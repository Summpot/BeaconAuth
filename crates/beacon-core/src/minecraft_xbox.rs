//! Minecraft (Xbox) authentication flow helpers shared by the native server and the
//! Cloudflare Worker.
//!
//! The Microsoft **Entra** provider (`provider = "microsoft"`) is unrelated to this: that
//! flow logs into a generic Microsoft account and returns an Entra user id. This module
//! implements the *Minecraft* flow (used with `provider = "minecraft"`), which authenticates
//! a Microsoft **consumer** account and exchanges it for a Mojang/Xbox profile (the real
//! Minecraft account, with a Mojang UUID, gamertag and signed `textures` property).

use serde_json::{json, Value};

/// The PlayFab/consumers relying party for the XSTS exchange. This is the standard value
/// used by first-party Minecraft clients.
pub const XBL_RELYING_PARTY: &str = "http://auth.xboxlive.com";
/// The API.relyingparty.minecraftservices.com relying party that produces a token usable
/// by the Minecraft login endpoint.
pub const XSTS_RELYING_PARTY: &str = "rp://api.minecraftservices.com/";
pub const XSTS_SANDBOX: &str = "RETAIL";
/// The Microsoft consumer OAuth client asked for by this flow.
pub const MICROSOFT_SCOPE: &str = "XboxLive.signin offline_access";
/// The tile id / client id used for the XSTS device token (shared tile known to the
/// Minecraft auth stack).
pub const XBX_TILE_ID: &str = "000000004C12AE6F";

/// HTTP `User-Agent` sent on the OAuth/Xbox/Minecraft exchange requests.
///
/// `api.minecraftservices.com` sits behind an Azure Front Door WAF that blocks requests
/// without a `User-Agent` header (and flags non-browser agents from cloud egress as bots),
/// returning a "The request is blocked" HTML error. The Cloudflare Workers runtime does not
/// inject a `User-Agent`, so we must set one explicitly across every step of the exchange.
/// A plain application-agent (e.g. "BeaconAuth") still trips this WAF, so a browser-style
/// agent is used, matching the ecosystem's standard practice for server-side Minecraft auth.
pub const MINECRAFT_HTTP_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// Request body for the OAuth authorize step (Microsoft consumer account).
pub fn microsoft_access_token_body(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> String {
    let mut pairs = vec![
        ("client_id".to_string(), client_id.to_string()),
        ("client_secret".to_string(), client_secret.to_string()),
        ("code".to_string(), code.to_string()),
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("redirect_uri".to_string(), redirect_uri.to_string()),
        ("scope".to_string(), MICROSOFT_SCOPE.to_string()),
    ];
    // Entra's consumer token endpoint expects form-encoded.
    let body = pairs
        .drain(..)
        .map(|(k, v)| format!("{}={}", urlencoding::encode(&k), urlencoding::encode(&v)))
        .collect::<Vec<_>>()
        .join("&");
    body
}

/// Request body for the XBL token exchange.
pub fn xbl_token_body(access_token: &str) -> Value {
    json!({
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": format!("d={access_token}"),
        },
        "RelyingParty": XBL_RELYING_PARTY,
        "TokenType": "JWT",
    })
}

/// Build a device token body for the XSTS step.
pub fn xsts_device_token() -> Value {
    json!({
        "Properties": {
            "AuthMethod": "ProofOfPossession",
            "Id": "RETAIL",
            "DeviceType": "Nintendo",
            "SerialNumber": "XTBX-1",
            "Version": "0.1"
        },
        "RelyingParty": XSTS_RELYING_PARTY,
        "TokenType": "JWT",
    })
}

/// Request body for the XSTS token exchange (standard Minecraft flow: SandboxId + user token).
pub fn xsts_token_body(user_token: &str) -> Value {
    json!({
        "Properties": {
            "SandboxId": XSTS_SANDBOX,
            "UserTokens": [user_token],
        },
        "RelyingParty": XSTS_RELYING_PARTY,
        "TokenType": "JWT",
    })
}

/// Request body for the Minecraft `login_with_xbox` step.
pub fn minecraft_login_body(user_hash: &str, xsts_token: &str) -> Value {
    json!({
        "identityToken": format!("XBL3.0 x={user_hash};{xsts_token}")
    })
}

/// Extract the userhash (`uhs`) from an XSTS token's `DisplayClaims.xui[0].uhs`.
pub fn user_hash_from_xsts(xsts: &Value) -> Option<String> {
    xsts
        .pointer("/DisplayClaims/xui/0/uhs")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Parse the `<signature>|<jwt>` XBX XSTS token string into the raw JWT, if split.
pub fn split_xsts_token(token: &str) -> &str {
    token.split_once('|').map(|(_, jwt)| jwt).unwrap_or(token)
}

/// Build a `textures` profile property from a Minecraft profile `properties[]` array.
///
/// Returns `(value, signature)` for the entry whose `name == "textures"`, if present.
pub fn textures_property(properties: &Value) -> Option<(String, String)> {
    let arr = properties.as_array()?;
    for entry in arr {
        let name = entry.get("name").and_then(|v| v.as_str())?;
        if name != "textures" {
            continue;
        }
        let value = entry.get("value").and_then(|v| v.as_str())?;
        let signature = entry.get("signature").and_then(|v| v.as_str())?;
        return Some((value.to_string(), signature.to_string()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_xsts_handles_signature_prefix() {
        assert_eq!(split_xsts_token("abc|def.ghi"), "def.ghi");
        assert_eq!(split_xsts_token("no-separator"), "no-separator");
    }

    #[test]
    fn textures_property_finds_textures() {
        let props = json!([
            { "name": "textures", "value": "abc", "signature": "sig" },
            { "name": "another", "value": "x", "signature": "y" }
        ]);
        assert_eq!(textures_property(&props), Some(("abc".to_string(), "sig".to_string())));
    }

    #[test]
    fn user_hash_extraction() {
        let xsts = json!({ "DisplayClaims": { "xui": [{ "uhs": "U123" }] } });
        assert_eq!(user_hash_from_xsts(&xsts), Some("U123".to_string()));
    }
}
