/**
 * keyManager.js
 * Generates and persists a 2048-bit RSA key pair for RS256 JWT signing.
 * Keys are stored in server/keys/ which MUST be added to .gitignore.
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
  logger.info("[keyManager] No RSA keys found — generating new 2048-bit key pair.");
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }

  fs.writeFileSync(PRIVATE_KEY_PATH, priv, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, pub, { mode: 0o644 });
  logger.info("[keyManager] RSA key pair generated and saved to server/keys/");
  return { priv, pub };
};

const loadKeys = () => {
  try {
    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
      privateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
      publicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
      logger.info("[keyManager] RSA keys loaded from disk.");
    } else {
      const { priv, pub } = generateAndPersistKeys();
      privateKey = priv;
      publicKey = pub;
    }
  } catch (err) {
    logger.error({ err }, "[keyManager] Fatal — could not load or generate RSA keys.");
    process.exit(1);
  }
};

// Load at module initialisation time
loadKeys();

module.exports = {
  getPrivateKey: () => privateKey,
  getPublicKey: () => publicKey,
};
