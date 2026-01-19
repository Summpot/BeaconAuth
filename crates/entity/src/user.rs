use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    #[sea_orm(unique)]
    pub username: String,

    /// Normalized username for case-insensitive uniqueness and lookups.
    ///
    /// This should always be `username.to_ascii_lowercase()`.
    #[sea_orm(unique)]
    pub username_lower: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,

    /// User-supplied email address (NOT verified by BeaconAuth).
    /// Used only for display and for computing Gravatar URLs.
    pub email: Option<String>,

    /// Selected avatar source: "github" | "google" | "microsoft" | "gravatar".
    pub avatar_source: Option<String>,

    /// Cached avatar URLs (public) from OAuth providers.
    pub github_avatar_url: Option<String>,
    pub google_avatar_url: Option<String>,

    /// Cached Microsoft avatar (base64-encoded) and its content type.
    pub microsoft_avatar_b64: Option<String>,
    pub microsoft_avatar_content_type: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

