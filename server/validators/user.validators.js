/**
 * user.validators.js
 * Joi schemas for user management endpoints.
 */
const Joi = require("joi");

const updateUserSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).messages({
    "string.alphanum": "Username must only contain alphanumeric characters",
    "string.min": "Username must be at least 3 characters",
  }),
  email: Joi.string().email({ tlds: { allow: false } }).messages({
    "string.email": "A valid email address is required",
  }),
  fullname: Joi.string().min(2).max(100),
  address: Joi.string().max(255).allow("", null),
  city: Joi.string().max(100).allow("", null),
  state: Joi.string().max(100).allow("", null),
  country: Joi.string().max(100).allow("", null),
}).min(1).messages({
  "object.min": "At least one field must be provided for update",
});

const createUserSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).required(),
  password: Joi.string().min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/)
    .required()
    .messages({
      "string.min": "Password must be at least 8 characters",
      "string.pattern.base": "Password must meet complexity requirements",
    }),
  fullname: Joi.string().min(2).max(100).required(),
  username: Joi.string().alphanum().min(3).max(30).required(),
});

module.exports = { updateUserSchema, createUserSchema };
