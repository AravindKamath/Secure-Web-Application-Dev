/**
 * refreshToken.db.js
 * DB layer for refresh token lifecycle management.
 * Tokens are stored as SHA-256 hashes — never raw values.
 */
const crypto = require("crypto");
const pool = require("../config");

/**
 * Hash a raw refresh token for safe DB storage.
 * @param {string} rawToken
 * @returns {string} hex-encoded SHA-256 hash
 */
const hashToken = (rawToken) =>
  crypto.createHash("sha256").update(rawToken).digest("hex");

/**
 * Store a new refresh token in the DB.
 * @param {{ userId: number, rawToken: string, expiresAt: Date }} params
 */
const storeRefreshTokenDb = async ({ userId, rawToken, expiresAt }) => {
  const tokenHash = hashToken(rawToken);
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT (token_hash) DO NOTHING`,
    [userId, tokenHash, expiresAt]
  );
  return tokenHash;
};

/**
 * Revoke a single refresh token by its raw value.
 * @param {string} rawToken
 */
const revokeRefreshTokenDb = async (rawToken) => {
  const tokenHash = hashToken(rawToken);
  await pool.query(
    `UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1`,
    [tokenHash]
  );
};

/**
 * Revoke all refresh tokens for a given user (e.g., on logout-all or password change).
 * @param {number} userId
 */
const revokeAllUserRefreshTokensDb = async (userId) => {
  await pool.query(
    `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`,
    [userId]
  );
};

/**
 * Validate a raw refresh token — must exist, not be revoked, and not be expired.
 * @param {string} rawToken
 * @returns {boolean}
 */
const isValidRefreshTokenDb = async (rawToken) => {
  const tokenHash = hashToken(rawToken);
  const { rows } = await pool.query(
    `SELECT EXISTS (
       SELECT 1 FROM refresh_tokens
       WHERE token_hash = $1
         AND revoked = false
         AND expires_at > NOW()
     )`,
    [tokenHash]
  );
  return rows[0].exists;
};

/**
 * Purge expired tokens — call periodically (e.g., daily cron).
 */
const purgeExpiredRefreshTokensDb = async () => {
  await pool.query(
    `DELETE FROM refresh_tokens WHERE expires_at <= NOW()`
  );
};

module.exports = {
  hashToken,
  storeRefreshTokenDb,
  revokeRefreshTokenDb,
  revokeAllUserRefreshTokensDb,
  isValidRefreshTokenDb,
  purgeExpiredRefreshTokensDb,
};
