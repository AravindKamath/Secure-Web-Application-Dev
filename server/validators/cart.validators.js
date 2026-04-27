/**
 * cart.validators.js
 * Joi schemas for cart endpoints.
 */
const Joi = require("joi");

const addItemSchema = Joi.object({
  product_id: Joi.number().integer().positive().required().messages({
    "number.integer": "product_id must be an integer",
    "number.positive": "product_id must be a positive integer",
    "any.required": "product_id is required",
  }),
  quantity: Joi.number().integer().min(1).max(100).default(1).messages({
    "number.min": "Quantity must be at least 1",
    "number.max": "Quantity cannot exceed 100",
  }),
});

const cartItemSchema = Joi.object({
  product_id: Joi.number().integer().positive().required().messages({
    "any.required": "product_id is required",
  }),
});

module.exports = { addItemSchema, cartItemSchema };
