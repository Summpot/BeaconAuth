use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::models::MinecraftLinkClaims;

/// Verify an in-game signed Minecraft link token using the shared HMAC secret.
pub fn verify_minecraft_link_token(token: &str, secret: &str) -> anyhow::Result<MinecraftLinkClaims> {
    if secret.trim().is_empty() {
        anyhow::bail!("Minecraft link secret is not configured");
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["beaconauth-minecraft-mod"]);
    validation.sub = Some("minecraft-link".to_string());
    // Allow up to 10 seconds of clock skew
    validation.leeway = 10;

    let token_data = jsonwebtoken::decode::<MinecraftLinkClaims>(
        token,
        &DecodingKey::from_secret(secret.trim().as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}

/// Create a signed Minecraft link token (useful for mod simulation and unit testing).
pub fn create_minecraft_link_token(
    uuid: &str,
    name: &str,
    secret: &str,
    ttl_secs: i64,
) -> anyhow::Result<String> {
    use jsonwebtoken::{EncodingKey, Header};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = MinecraftLinkClaims {
        iss: "beaconauth-minecraft-mod".to_string(),
        sub: "minecraft-link".to_string(),
        uuid: uuid.to_string(),
        name: name.to_string(),
        exp: now + ttl_secs,
        iat: now,
        nonce: format!("nonce-{}", now),
    };

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.trim().as_bytes()),
    )?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minecraft_link_token_roundtrip() {
        let secret = "super-secret-key-12345678901234567890";
        let uuid = "069a79f4-44e9-4726-a5be-fca90e38aaf5";
        let name = "Notch";

        let token = create_minecraft_link_token(uuid, name, secret, 300).unwrap();
        let claims = verify_minecraft_link_token(&token, secret).unwrap();

        assert_eq!(claims.uuid, uuid);
        assert_eq!(claims.name, name);
        assert_eq!(claims.iss, "beaconauth-minecraft-mod");
        assert_eq!(claims.sub, "minecraft-link");
    }

    #[test]
    fn test_minecraft_link_token_wrong_secret() {
        let secret = "correct-secret-key-12345678901234567890";
        let wrong_secret = "wrong-secret-key-12345678901234567890";
        let uuid = "069a79f4-44e9-4726-a5be-fca90e38aaf5";
        let name = "Notch";

        let token = create_minecraft_link_token(uuid, name, secret, 300).unwrap();
        let err = verify_minecraft_link_token(&token, wrong_secret);
        assert!(err.is_err());
    }

    #[test]
    fn test_minecraft_link_token_expired() {
        let secret = "correct-secret-key-12345678901234567890";
        let uuid = "069a79f4-44e9-4726-a5be-fca90e38aaf5";
        let name = "Notch";

        // Expired 20 seconds ago (leeway is 10)
        let token = create_minecraft_link_token(uuid, name, secret, -20).unwrap();
        let err = verify_minecraft_link_token(&token, secret);
        assert!(err.is_err());
    }
}
