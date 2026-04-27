/**
 * logger.js
 * Winston-based structured logger.
 * - Console transport in development
 * - DailyRotateFile transport in production
 * - morganStream for HTTP request logging via Morgan
 */
const winston = require("winston");
const DailyRotateFile = require("winston-daily-rotate-file");
const path = require("path");

const { combine, timestamp, json, colorize, printf, errors } = winston.format;

const isProduction = process.env.NODE_ENV === "production";

// ── Formats ────────────────────────────────────────────────────────────────

const devFormat = combine(
  colorize(),
  timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  errors({ stack: true }),
  printf(({ level, message, timestamp, stack, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    return `${timestamp} [${level}]: ${stack || message} ${metaStr}`;
  })
);

const prodFormat = combine(
  timestamp(),
  errors({ stack: true }),
  json()
);

// ── Transports ──────────────────────────────────────────────────────────────

const transports = [];

if (isProduction) {
  transports.push(
    new DailyRotateFile({
      filename: path.join(__dirname, "..", "logs", "app-%DATE%.log"),
      datePattern: "YYYY-MM-DD",
      zippedArchive: true,
      maxSize: "20m",
      maxFiles: "30d",
      level: "info",
      format: prodFormat,
    }),
    new DailyRotateFile({
      filename: path.join(__dirname, "..", "logs", "error-%DATE%.log"),
      datePattern: "YYYY-MM-DD",
      zippedArchive: true,
      maxSize: "20m",
      maxFiles: "30d",
      level: "error",
      format: prodFormat,
    })
  );
} else {
  transports.push(
    new winston.transports.Console({
      level: "debug",
      format: devFormat,
    })
  );
}

const logger = winston.createLogger({
  level: isProduction ? "info" : "debug",
  transports,
  exitOnError: false,
});

// ── Morgan stream integration ───────────────────────────────────────────────

const morganStream = {
  write: (message) => {
    // Morgan appends a newline — trim it
    logger.http(message.trim());
  },
};

module.exports = { logger, morganStream };
