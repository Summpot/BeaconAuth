-- Add identities table for linking multiple auth methods (OAuth providers) to the same user.
--
-- This is intentionally close to the SeaORM migration, but uses INTEGER unix timestamps.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(provider, provider_user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identities_user_id ON identities(user_id);
