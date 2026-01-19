//! Legacy module: user profile API types.
//!
//! Canonical definitions live in `crate::models`. This module re-exports them to avoid
//! duplication and to keep older imports working.

pub use crate::models::{UpdateUserProfileRequest, UpdateUserProfileResponse, UserMeResponse};
