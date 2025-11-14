use serde::{Deserialize, Serialize};

/// Request payload for POST /api/v1/register
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub username: String,
    pub password: String,
    pub challenge: String,
    pub redirect_port: u16,
}

/// Request payload for POST /api/v1/login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
    pub challenge: String,
    pub redirect_port: u16,
}

/// Response for successful login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    #[serde(rename = "redirectUrl")]
    pub redirect_url: String,
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Request payload for POST /api/v1/oauth/start
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStartPayload {
    pub provider: String,
    pub challenge: String,
    pub redirect_port: u16,
}

/// Response for OAuth start
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStartResponse {
    #[serde(rename = "authorizationUrl")]
    pub authorization_url: String,
}

/// Request payload for GET /api/v1/oauth/callback
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

/// OAuth state stored temporarily
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub provider: String,
    pub challenge: String,
    pub redirect_port: u16,
    pub state_token: String,
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer
    pub iss: String,

    /// Subject (user ID)
    pub sub: String,

    /// Audience
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// PKCE challenge (critical for BeaconAuth)
    pub challenge: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_payload_deserialization() {
        let json = r#"{
            "username": "testuser",
            "password": "testpass",
            "challenge": "abc123",
            "redirect_port": 25585
        }"#;

        let payload: LoginPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.username, "testuser");
        assert_eq!(payload.password, "testpass");
        assert_eq!(payload.challenge, "abc123");
        assert_eq!(payload.redirect_port, 25585);
    }

    #[test]
    fn test_login_response_serialization() {
        let response = LoginResponse {
            redirect_url: "http://localhost:25585/callback?jwt=token".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("redirectUrl"));
        assert!(json.contains("http://localhost:25585"));
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Invalid credentials".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("unauthorized"));
        assert!(json.contains("Invalid credentials"));
    }

    #[test]
    fn test_claims_serialization() {
        let claims = Claims {
            iss: "test-issuer".to_string(),
            sub: "user123".to_string(),
            aud: "test-audience".to_string(),
            exp: 1234567890,
            challenge: "challenge123".to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("test-issuer"));
        assert!(json.contains("user123"));
        assert!(json.contains("challenge123"));

        // Test deserialization
        let decoded: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.iss, claims.iss);
        assert_eq!(decoded.challenge, claims.challenge);
    }
}
