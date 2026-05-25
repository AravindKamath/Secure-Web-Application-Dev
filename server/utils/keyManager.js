/**
 * keyManager.js
 * RSA key pair management for RS256 JWT signing.
 * Production: Load from environment variables
 * Development: Generate and persist to server/keys/ (must be in .gitignore)
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { logger } = require("./logger");

const KEYS_DIR = path.join(__dirname, "..", "keys");
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, "private.pem");
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, "public.pem");

let privateKey;
let publicKey;

const generateAndPersistKeys = () => {
  logger.info("[keyManager] Generating new 2048-bit RSA key pair.");
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync(
    "rsa",
    {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    }
  );

  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }

  fs.writeFileSync(PRIVATE_KEY_PATH, priv, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, pub, { mode: 0o644 });
  logger.info("[keyManager] Keys generated and saved to server/keys/");
  return { priv, pub };
};

const loadKeys = () => {
  try {
    // Priority 1: Environment variables (PRODUCTION)
    if (process.env.PRIVATE_KEY && process.env.PUBLIC_KEY) {
      privateKey = process.env.PRIVATE_KEY;
      publicKey = process.env.PUBLIC_KEY;
      logger.info("[keyManager] RSA keys loaded from environment variables.");
      return;
    }

    // Priority 2: Load from disk (DEVELOPMENT)
    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
      privateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
      publicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
      logger.info("[keyManager] RSA keys loaded from disk.");
      return;
    }

    // Fallback: Generate new keys (FIRST RUN)
    const { priv, pub } = generateAndPersistKeys();
    privateKey = priv;
    publicKey = pub;
  } catch (err) {
    logger.error(
      { err },
      "[keyManager] Fatal — could not load or generate RSA keys."
    );
    process.exit(1);
  }
};

loadKeys();

module.exports = {
  getPrivateKey: () => privateKey,
  getPublicKey: () => publicKey,
};
