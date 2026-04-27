/**
 * products.controller.js
 * All DB interactions now go through the proper DB layer (review.db.js).
 * Direct pool.query calls have been removed from this controller.
 */
const productService = require("../services/product.service");
const { getReviewsDb, createReviewDb, updateReviewDb } = require("../db/review.db");
const { ErrorHandler } = require("../helpers/error");

const getAllProducts = async (req, res) => {
  const { page = 1 } = req.query;
  const products = await productService.getAllProducts(page);
  res.json(products);
};

const createProduct = async (req, res) => {
  const newProduct = await productService.addProduct(req.body);
  res.status(201).json(newProduct);
};

const getProduct = async (req, res) => {
  const product = await productService.getProductById(req.params);
  res.status(200).json(product);
};

const getProductBySlug = async (req, res) => {
  const product = await productService.getProductBySlug(req.params);
  res.status(200).json(product);
};

const getProductByName = async (req, res) => {
  const product = await productService.getProductByName(req.params);
  res.status(200).json(product);
};

const updateProduct = async (req, res) => {
  const { name, price, description, image_url } = req.body;
  const { id } = req.params;

  const updatedProduct = await productService.updateProduct({
    name,
    price,
    description,
    image_url,
    id,
  });
  res.status(200).json(updatedProduct);
};

const deleteProduct = async (req, res) => {
  const { id } = req.params;
  const deletedProduct = await productService.removeProduct(id);
  res.status(200).json(deletedProduct);
};

// ── Reviews — delegated to DB layer ─────────────────────────────────────────

const getProductReviews = async (req, res) => {
  const { product_id, user_id } = req.query;
  const result = await getReviewsDb({ productId: product_id, userId: user_id });
  res.status(200).json(result);
};

const createProductReview = async (req, res) => {
  const { product_id, content, rating } = req.body;
  const user_id = req.user.id;

  const review = await createReviewDb({ productId: product_id, content, rating, userId: user_id });
  res.status(201).json(review);
};

const updateProductReview = async (req, res) => {
  const { content, rating, id } = req.body;
  const review = await updateReviewDb({ content, rating, id });
  res.status(200).json(review);
};

module.exports = {
  getProduct,
  createProduct,
  updateProduct,
  deleteProduct,
  getAllProducts,
  getProductByName,
  getProductBySlug,
  getProductReviews,
  updateProductReview,
  createProductReview,
};
