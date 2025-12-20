//! WebAuthn / passkey RP logic that is compatible with wasm32 (e.g. Cloudflare Workers).
//!
//! This module intentionally avoids OpenSSL. It targets the JSON shapes used by
//! `@simplewebauthn/browser`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub const DEFAULT_TIMEOUT_MS: u32 = 60_000;

#[derive(Clone, Debug)]
pub struct RpConfig {
    pub rp_id: String,
    pub origin: Url,
    pub rp_name: String,
}

impl RpConfig {
    pub fn new(rp_id: impl Into<String>, origin: Url, rp_name: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            origin,
            rp_name: rp_name.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreationChallengeResponse {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestChallengeResponse {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: RelyingPartyEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: String,

    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,

    #[serde(rename = "authenticatorSelection")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,

    #[serde(rename = "excludeCredentials")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    #[serde(rename = "rpId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,

    #[serde(rename = "allowCredentials")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    #[serde(rename = "userVerification")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelyingPartyEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    /// Base64url-encoded bytes.
    pub id: String,
    pub name: String,

    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    /// Base64url-encoded credential ID.
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "residentKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,

    #[serde(rename = "requireResidentKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,

    #[serde(rename = "userVerification")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,

    #[serde(rename = "authenticatorAttachment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
}

/// JSON from `@simplewebauthn/browser` for registration.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisterPublicKeyCredential {
    pub id: String,

    #[serde(rename = "rawId")]
    pub raw_id: String,

    #[serde(rename = "type")]
    pub type_: String,

    pub response: AuthenticatorAttestationResponse,

    #[serde(default, rename = "clientExtensionResults")]
    pub client_extension_results: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,

    #[serde(rename = "attestationObject")]
    pub attestation_object: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// JSON from `@simplewebauthn/browser` for authentication.
#[derive(Clone, Debug, Deserialize)]
pub struct PublicKeyCredential {
    pub id: String,

    #[serde(rename = "rawId")]
    pub raw_id: String,

    #[serde(rename = "type")]
    pub type_: String,

    pub response: AuthenticatorAssertionResponse,

    #[serde(default, rename = "clientExtensionResults")]
    pub client_extension_results: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,

    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,

    pub signature: String,

    #[serde(rename = "userHandle")]
    #[serde(default)]
    pub user_handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationState {
    /// Base64url string.
    pub challenge: String,

    /// Base64url string.
    pub user_handle: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationState {
    /// Base64url string.
    pub challenge: String,

    /// Optional allow list (base64url credential IDs). None means discoverable.
    pub allow_credentials: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredPasskey {
    /// Credential ID (base64url).
    pub credential_id: String,

    /// COSE algorithm identifier, typically -7 for ES256.
    pub alg: i32,

    /// P-256 public key coordinates (base64url).
    pub x: String,
    pub y: String,

    /// Stored signature counter.
    pub sign_count: u32,

    /// Optional transports reported by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct AuthResult {
    pub new_sign_count: u32,
}

#[derive(Debug, Clone)]
pub struct PasskeyError {
    pub code: &'static str,
    pub message: String,
}

impl PasskeyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn b64url_encode(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, PasskeyError> {
    B64URL
        .decode(s)
        .map_err(|_| PasskeyError::new("invalid_base64", "Invalid base64url data"))
}

fn random_challenge_b64url() -> String {
    let bytes = rand::random::<[u8; 32]>();
    b64url_encode(&bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    sha256(rp_id.as_bytes())
}

fn normalize_origin(origin: &Url) -> (String, String, u16) {
    let scheme = origin.scheme().to_string();
    let host = origin.host_str().unwrap_or_default().to_string();
    let port = origin.port_or_known_default().unwrap_or(0);
    (scheme, host, port)
}

fn verify_origin(expected: &Url, got: &str) -> Result<(), PasskeyError> {
    let got_url = Url::parse(got)
        .map_err(|_| PasskeyError::new("invalid_origin", "Invalid origin"))?;

    let (es, eh, ep) = normalize_origin(expected);
    let (gs, gh, gp) = normalize_origin(&got_url);

    if es != gs || eh != gh || ep != gp {
        return Err(PasskeyError::new(
            "origin_mismatch",
            format!("Origin mismatch (expected {es}://{eh}:{ep}, got {gs}://{gh}:{gp})"),
        ));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ClientDataJson {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
}

pub fn extract_challenge_from_client_data_b64url(client_data_json_b64url: &str) -> Result<String, PasskeyError> {
    let bytes = b64url_decode(client_data_json_b64url)?;
    let cd: ClientDataJson = serde_json::from_slice(&bytes)
        .map_err(|_| PasskeyError::new("invalid_client_data", "Invalid clientDataJSON"))?;
    Ok(cd.challenge)
}

pub fn start_passkey_registration(
    rp: &RpConfig,
    user_handle: &[u8],
    username: &str,
    display_name: &str,
    exclude_credentials: Option<Vec<Vec<u8>>>,
) -> (CreationChallengeResponse, RegistrationState) {
    let challenge = random_challenge_b64url();
    let user_handle_b64 = b64url_encode(user_handle);

    let exclude = exclude_credentials.map(|ids| {
        ids.into_iter()
            .map(|id| PublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: b64url_encode(&id),
                transports: None,
            })
            .collect::<Vec<_>>()
    });

    let public_key = PublicKeyCredentialCreationOptions {
        rp: RelyingPartyEntity {
            id: Some(rp.rp_id.clone()),
            name: rp.rp_name.clone(),
        },
        user: PublicKeyCredentialUserEntity {
            id: user_handle_b64.clone(),
            name: username.to_string(),
            display_name: display_name.to_string(),
        },
        challenge: challenge.clone(),
        pub_key_cred_params: vec![
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -7, // ES256
            },
        ],
        timeout: Some(DEFAULT_TIMEOUT_MS),
        attestation: Some("none".to_string()),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            resident_key: Some("required".to_string()),
            require_resident_key: Some(true),
            user_verification: Some("preferred".to_string()),
            authenticator_attachment: None,
        }),
        exclude_credentials: exclude,
        extensions: None,
    };

    let resp = CreationChallengeResponse { public_key };
    let state = RegistrationState {
        challenge,
        user_handle: user_handle_b64,
    };

    (resp, state)
}

pub fn start_passkey_authentication(
    rp: &RpConfig,
    allow_credentials: Option<Vec<Vec<u8>>>,
) -> (RequestChallengeResponse, AuthenticationState) {
    let challenge = random_challenge_b64url();

    let allow = allow_credentials.map(|ids| {
        ids.into_iter()
            .map(|id| PublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: b64url_encode(&id),
                transports: None,
            })
            .collect::<Vec<_>>()
    });

    let public_key = PublicKeyCredentialRequestOptions {
        challenge: challenge.clone(),
        timeout: Some(DEFAULT_TIMEOUT_MS),
        rp_id: Some(rp.rp_id.clone()),
        allow_credentials: allow.clone(),
        user_verification: Some("preferred".to_string()),
        extensions: None,
    };

    let resp = RequestChallengeResponse { public_key };
    let state = AuthenticationState {
        challenge,
        allow_credentials: allow.map(|v| v.into_iter().map(|d| d.id).collect()),
    };

    (resp, state)
}

pub fn finish_passkey_registration(
    rp: &RpConfig,
    credential: &RegisterPublicKeyCredential,
    state: &RegistrationState,
) -> Result<StoredPasskey, PasskeyError> {
    // clientDataJSON validation
    let client_data_bytes = b64url_decode(&credential.response.client_data_json)?;
    let cd: ClientDataJson = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| PasskeyError::new("invalid_client_data", "Invalid clientDataJSON"))?;

    if cd.ty != "webauthn.create" {
        return Err(PasskeyError::new(
            "invalid_type",
            format!("Expected clientData type webauthn.create, got {}", cd.ty),
        ));
    }

    // Compare challenge bytes (robust to padding/encoding differences)
    let expected_chal = b64url_decode(&state.challenge)?;
    let got_chal = b64url_decode(&cd.challenge)?;
    if expected_chal != got_chal {
        return Err(PasskeyError::new("challenge_mismatch", "Challenge mismatch"));
    }

    verify_origin(&rp.origin, &cd.origin)?;

    // Parse attestationObject
    let att_obj_bytes = b64url_decode(&credential.response.attestation_object)?;
    let att_obj: serde_cbor_2::Value = serde_cbor_2::from_slice(&att_obj_bytes)
        .map_err(|_| PasskeyError::new("invalid_attestation", "Invalid attestationObject"))?;

    let auth_data = extract_attestation_auth_data(&att_obj)?;
    let parsed = parse_authenticator_data(&auth_data)?;

    if parsed.rp_id_hash != rp_id_hash(&rp.rp_id) {
        return Err(PasskeyError::new("rp_id_mismatch", "rpIdHash mismatch"));
    }

    // Require user presence.
    if (parsed.flags & 0x01) == 0 {
        return Err(PasskeyError::new("user_not_present", "User presence flag not set"));
    }

    // Prefer UV for passkeys; tolerate missing UV only if authenticator cannot.
    // (We keep this as a hard check to match the security intent of passkeys.)
    if (parsed.flags & 0x04) == 0 {
        return Err(PasskeyError::new("user_not_verified", "User verification flag not set"));
    }

    let att = parsed
        .attested
        .ok_or_else(|| PasskeyError::new("invalid_auth_data", "Missing attested credential data"))?;

    // Ensure the credential ID matches the rawId we received.
    let raw_id = b64url_decode(&credential.raw_id)?;
    if raw_id != att.credential_id {
        return Err(PasskeyError::new(
            "credential_id_mismatch",
            "Credential ID mismatch",
        ));
    }

    let (alg, x, y) = cose_parse_p256_public_key(&att.credential_public_key)?;

    Ok(StoredPasskey {
        credential_id: b64url_encode(&att.credential_id),
        alg,
        x: b64url_encode(&x),
        y: b64url_encode(&y),
        sign_count: parsed.sign_count,
        transports: credential.response.transports.clone(),
    })
}

pub fn finish_passkey_authentication(
    rp: &RpConfig,
    credential: &PublicKeyCredential,
    state: &AuthenticationState,
    stored: &StoredPasskey,
) -> Result<AuthResult, PasskeyError> {
    // Validate allowCredentials when present.
    if let Some(allow) = &state.allow_credentials {
        if !allow.iter().any(|id| id == &credential.raw_id) {
            return Err(PasskeyError::new(
                "not_allowed",
                "Credential not in allowCredentials",
            ));
        }
    }

    // clientDataJSON
    let client_data_bytes = b64url_decode(&credential.response.client_data_json)?;
    let cd: ClientDataJson = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| PasskeyError::new("invalid_client_data", "Invalid clientDataJSON"))?;

    if cd.ty != "webauthn.get" {
        return Err(PasskeyError::new(
            "invalid_type",
            format!("Expected clientData type webauthn.get, got {}", cd.ty),
        ));
    }

    let expected_chal = b64url_decode(&state.challenge)?;
    let got_chal = b64url_decode(&cd.challenge)?;
    if expected_chal != got_chal {
        return Err(PasskeyError::new("challenge_mismatch", "Challenge mismatch"));
    }

    verify_origin(&rp.origin, &cd.origin)?;

    // authenticatorData
    let auth_data = b64url_decode(&credential.response.authenticator_data)?;
    let parsed = parse_authenticator_data(&auth_data)?;

    if parsed.rp_id_hash != rp_id_hash(&rp.rp_id) {
        return Err(PasskeyError::new("rp_id_mismatch", "rpIdHash mismatch"));
    }

    if (parsed.flags & 0x01) == 0 {
        return Err(PasskeyError::new("user_not_present", "User presence flag not set"));
    }

    // Prefer UV for passkeys.
    if (parsed.flags & 0x04) == 0 {
        return Err(PasskeyError::new("user_not_verified", "User verification flag not set"));
    }

    // Verify signature (ES256 only for now).
    if stored.alg != -7 {
        return Err(PasskeyError::new(
            "unsupported_alg",
            format!("Unsupported COSE alg {}", stored.alg),
        ));
    }

    let x = b64url_decode(&stored.x)?;
    let y = b64url_decode(&stored.y)?;

    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| PasskeyError::new("invalid_public_key", "Invalid stored public key"))?;

    let client_data_hash = sha256(&client_data_bytes);

    let mut signed_data = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    let sig_bytes = b64url_decode(&credential.response.signature)?;
    let sig = Signature::from_der(&sig_bytes)
        .or_else(|_| {
            if sig_bytes.len() == 64 {
                Signature::from_slice(&sig_bytes)
            } else {
                Err(p256::ecdsa::Error::new())
            }
        })
        .map_err(|_| PasskeyError::new("invalid_signature", "Invalid signature encoding"))?;

    verifying_key
        .verify(&signed_data, &sig)
        .map_err(|_| PasskeyError::new("bad_signature", "Signature verification failed"))?;

    // Counter check (best-effort; 0 means not supported)
    let new_count = parsed.sign_count;
    if new_count != 0 && new_count <= stored.sign_count {
        return Err(PasskeyError::new(
            "bad_counter",
            "Authenticator counter did not increase",
        ));
    }

    Ok(AuthResult {
        new_sign_count: new_count.max(stored.sign_count),
    })
}

#[derive(Clone, Debug)]
struct ParsedAuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredentialData>,
}

#[derive(Clone, Debug)]
struct AttestedCredentialData {
    credential_id: Vec<u8>,
    credential_public_key: serde_cbor_2::Value,
}

fn parse_authenticator_data(auth_data: &[u8]) -> Result<ParsedAuthenticatorData, PasskeyError> {
    if auth_data.len() < 37 {
        return Err(PasskeyError::new("invalid_auth_data", "authenticatorData too short"));
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[0..32]);

    let flags = auth_data[32];

    let sign_count = u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]);

    let mut idx = 37;

    let has_attested = (flags & 0x40) != 0;
    let has_ext = (flags & 0x80) != 0;

    let attested = if has_attested {
        if auth_data.len() < idx + 16 + 2 {
            return Err(PasskeyError::new("invalid_auth_data", "attested data too short"));
        }

        // aaguid (ignored)
        idx += 16;

        let cred_len = u16::from_be_bytes([auth_data[idx], auth_data[idx + 1]]) as usize;
        idx += 2;

        if auth_data.len() < idx + cred_len {
            return Err(PasskeyError::new("invalid_auth_data", "credentialId truncated"));
        }

        let credential_id = auth_data[idx..idx + cred_len].to_vec();
        idx += cred_len;

        // Remaining bytes: credentialPublicKey (CBOR), optionally followed by extensions.
        // In the common case (no extensions), the remaining bytes are exactly the COSE key.
        let remaining = &auth_data[idx..];
        let (cose_key, consumed) = if !has_ext {
            let key: serde_cbor_2::Value = serde_cbor_2::from_slice(remaining)
                .map_err(|_| PasskeyError::new("invalid_cbor", "Invalid COSE key CBOR"))?;
            (key, remaining.len())
        } else {
            parse_first_cbor_value(remaining)?
        };

        // If extensions are present, we just ensure they are valid CBOR.
        if has_ext {
            let ext_bytes = &remaining[consumed..];
            if !ext_bytes.is_empty() {
                let _ext: serde_cbor_2::Value = serde_cbor_2::from_slice(ext_bytes)
                    .map_err(|_| PasskeyError::new("invalid_auth_data", "Invalid extensions CBOR"))?;
            }
        }

        Some(AttestedCredentialData {
            credential_id,
            credential_public_key: cose_key,
        })
    } else {
        None
    };

    Ok(ParsedAuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

fn parse_first_cbor_value(input: &[u8]) -> Result<(serde_cbor_2::Value, usize), PasskeyError> {
    // serde_cbor_2 doesn't currently expose a stable "bytes consumed" API.
    // We implement a minimal "prefix parser" by trying progressive lengths.
    // This is safe because COSE keys are small (< 512 bytes typically).
    //
    // If the input is large and includes extensions, this still finds the first CBOR object.
    let max = input.len().min(2048);
    for len in 1..=max {
        if let Ok(val) = serde_cbor_2::from_slice::<serde_cbor_2::Value>(&input[..len]) {
            // `from_slice` requires full consumption, so `len` is the consumed prefix.
            return Ok((val, len));
        }
    }

    Err(PasskeyError::new(
        "invalid_cbor",
        "Failed to parse CBOR value from authenticator data",
    ))
}

fn extract_attestation_auth_data(att_obj: &serde_cbor_2::Value) -> Result<Vec<u8>, PasskeyError> {
    let map = match att_obj {
        serde_cbor_2::Value::Map(m) => m,
        _ => {
            return Err(PasskeyError::new(
                "invalid_attestation",
                "attestationObject must be a CBOR map",
            ))
        }
    };

    for (k, v) in map {
        if let serde_cbor_2::Value::Text(s) = k {
            if s == "authData" {
                if let serde_cbor_2::Value::Bytes(b) = v {
                    return Ok(b.clone());
                }
                return Err(PasskeyError::new(
                    "invalid_attestation",
                    "authData must be bytes",
                ));
            }
        }
    }

    Err(PasskeyError::new(
        "invalid_attestation",
        "attestationObject missing authData",
    ))
}

fn cose_parse_p256_public_key(
    cose_key: &serde_cbor_2::Value,
) -> Result<(i32, Vec<u8>, Vec<u8>), PasskeyError> {
    let map = match cose_key {
        serde_cbor_2::Value::Map(m) => m,
        _ => {
            return Err(PasskeyError::new(
                "invalid_cose",
                "credentialPublicKey must be a CBOR map",
            ))
        }
    };

    let mut kty: Option<i128> = None;
    let mut alg: Option<i128> = None;
    let mut crv: Option<i128> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;

    for (k, v) in map {
        let key = match k {
            serde_cbor_2::Value::Integer(i) => *i,
            _ => continue,
        };

        match key {
            1 => {
                // kty
                if let serde_cbor_2::Value::Integer(i) = v {
                    kty = Some(*i);
                }
            }
            3 => {
                // alg
                if let serde_cbor_2::Value::Integer(i) = v {
                    alg = Some(*i);
                }
            }
            -1 => {
                // crv
                if let serde_cbor_2::Value::Integer(i) = v {
                    crv = Some(*i);
                }
            }
            -2 => {
                // x
                if let serde_cbor_2::Value::Bytes(b) = v {
                    x = Some(b.clone());
                }
            }
            -3 => {
                // y
                if let serde_cbor_2::Value::Bytes(b) = v {
                    y = Some(b.clone());
                }
            }
            _ => {}
        }
    }

    let kty = kty.ok_or_else(|| PasskeyError::new("invalid_cose", "Missing kty"))?;
    let alg = alg.ok_or_else(|| PasskeyError::new("invalid_cose", "Missing alg"))?;

    // COSE kty=2 means EC2.
    if kty != 2 {
        return Err(PasskeyError::new(
            "unsupported_key",
            format!("Unsupported COSE key type {kty}"),
        ));
    }

    // crv=1 is P-256.
    let crv = crv.ok_or_else(|| PasskeyError::new("invalid_cose", "Missing crv"))?;
    if crv != 1 {
        return Err(PasskeyError::new(
            "unsupported_curve",
            format!("Unsupported COSE curve {crv}"),
        ));
    }

    let x = x.ok_or_else(|| PasskeyError::new("invalid_cose", "Missing x"))?;
    let y = y.ok_or_else(|| PasskeyError::new("invalid_cose", "Missing y"))?;

    Ok((alg as i32, x, y))
}
