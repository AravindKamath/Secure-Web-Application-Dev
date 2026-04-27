/**
 * verifyToken.js
 * JWT authentication middleware.
 *
 * Reads the access token from the HttpOnly `accessToken` cookie (not headers).
 * Verifies using the RS256 public key — rejects any HS256-signed tokens.
 */
const jwt = require("jsonwebtoken");
const { getPublicKey } = require("../utils/keyManager");
const { ErrorHandler } = require("../helpers/error");
const { logger } = require("../utils/logger");

const verifyToken = (req, res, next) => {
  const token = req.cookies?.accessToken;

  if (!token) {
    logger.warn({
      event: "AUTH_FAILURE",
      reason: "Access token cookie missing",
      path: req.path,
      ip: req.ip,
    });
    throw new ErrorHandler(401, "Authentication required");
  }

  try {
    const verified = jwt.verify(token, getPublicKey(), { algorithms: ["RS256"] });
    req.user = verified;
    next();
  } catch (error) {
    logger.warn({
      event: "AUTH_FAILURE",
      reason: error.message,
      path: req.path,
      ip: req.ip,
    });
    throw new ErrorHandler(401, "Invalid or expired token");
  }
};

module.exports = verifyToken;
