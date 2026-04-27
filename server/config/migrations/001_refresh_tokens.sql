-- ============================================================
-- Migration 001: Refresh Token Store
-- Purpose: Supports RS256 refresh token rotation with DB-backed
--          invalidation. Each token is stored as a SHA-256 hash
--          to prevent exposure of raw token values at rest.
-- ============================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          SERIAL       PRIMARY KEY,
  user_id     INTEGER      NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  token_hash  TEXT         NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ  NOT NULL,
  revoked     BOOLEAN      NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Index for fast token lookup on every authenticated request
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash
  ON refresh_tokens(token_hash);

-- Index for cleanup jobs and user-scoped revocation
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id
  ON refresh_tokens(user_id);
