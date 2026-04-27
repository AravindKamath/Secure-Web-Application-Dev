/**
 * hashPassword.js
 * Centralised password hashing helper.
 * Uses bcrypt with a cost factor of 12 (SDLC minimum requirement).
 */
const bcrypt = require("bcrypt");

const BCRYPT_ROUNDS = 12;

/**
 * Hash a plaintext password.
 * @param {string} password
 * @returns {Promise<string>} bcrypt hash
 */
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
  return bcrypt.hash(password, salt);
};

/**
 * Compare a plaintext password against a stored hash.
 * @param {string} password
 * @param {string} passwordHash
 * @returns {Promise<boolean>}
 */
const comparePassword = async (password, passwordHash) =>
  bcrypt.compare(password, passwordHash);

module.exports = { hashPassword, comparePassword };
