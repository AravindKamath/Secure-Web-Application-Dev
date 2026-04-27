/**
 * validate.js
 * Generic Joi validation middleware factory.
 *
 * Usage:
 *   router.post("/signup", validate(signupSchema), createAccount);
 *
 * On validation failure returns HTTP 422 with field-level error details.
 */
const { logger } = require("../utils/logger");

/**
 * @param {import("joi").Schema} schema — Joi schema to validate req.body against
 * @param {"body"|"query"|"params"} [target="body"]
 */
const validate = (schema, target = "body") => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[target], {
      abortEarly: false,   // collect all errors, not just the first
      stripUnknown: true,  // remove unrecognised fields from req.body
    });

    if (error) {
      const details = error.details.map((d) => ({
        field: d.path.join("."),
        message: d.message.replace(/['"]/g, ""),
      }));

      logger.warn({
        event: "VALIDATION_FAILURE",
        path: req.path,
        method: req.method,
        errors: details,
      });

      return res.status(422).json({
        status: "error",
        statusCode: 422,
        message: "Validation failed",
        errors: details,
      });
    }

    // Replace req[target] with the sanitised, validated value
    req[target] = value;
    next();
  };
};

module.exports = validate;
