/**
 * rateLimiter.js
 * Rate limiting middleware using express-rate-limit.
 *
 * globalLimiter  — 100 requests per 15 minutes for all API routes
 * authLimiter    — 10 attempts per 15 minutes for login/signup endpoints
 */
const rateLimit = require("express-rate-limit");
const { logger } = require("../utils/logger");

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,  // Return rate limit info in RateLimit-* headers
  legacyHeaders: false,   // Disable X-RateLimit-* headers
  message: {
    status: "error",
    statusCode: 429,
    message: "Too many requests. Please try again after 15 minutes.",
  },
  handler: (req, res, next, options) => {
    logger.warn({
      event: "RATE_LIMIT_GLOBAL",
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    res.status(options.statusCode).json(options.message);
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "error",
    statusCode: 429,
    message: "Too many authentication attempts. Please try again after 15 minutes.",
  },
  handler: (req, res, next, options) => {
    logger.warn({
      event: "RATE_LIMIT_AUTH",
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    res.status(options.statusCode).json(options.message);
  },
});

module.exports = { globalLimiter, authLimiter };
