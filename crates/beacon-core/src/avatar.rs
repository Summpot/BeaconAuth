/// Avatar-related helpers.
///
/// Keep this module dependency-light and shared between native server and Workers builds.

/// Build a Gravatar URL for the given email.
///
/// Gravatar uses an MD5 of the normalized email ($lowercase(trim(email))$).
///
/// `size` is the desired pixel size (e.g. 128).
#[must_use]
pub fn gravatar_url(email: &str, size: u32) -> String {
    let normalized = email.trim().to_ascii_lowercase();
    let digest = md5::compute(normalized.as_bytes());
    let hash = format!("{:x}", digest);

    // Use identicon as a reasonable default without leaking email.
    // https://en.gravatar.com/site/implement/images/
    format!(
        "https://www.gravatar.com/avatar/{hash}?d=identicon&s={size}",
        hash = hash,
        size = size
    )
}
