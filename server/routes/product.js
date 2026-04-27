const router = require("express").Router();
const {
  getAllProducts,
  createProduct,
  getProduct,
  updateProduct,
  deleteProduct,
  getProductByName,
  getProductReviews,
  createProductReview,
  updateProductReview,
  getProductBySlug,
} = require("../controllers/products.controller");
const verifyAdmin = require("../middleware/verifyAdmin");
const verifyToken = require("../middleware/verifyToken");
const validate = require("../middleware/validate");
const {
  createProductSchema,
  updateProductSchema,
  createReviewSchema,
  updateReviewSchema,
} = require("../validators/product.validators");

router
  .route("/")
  .get(getAllProducts)
  .post(verifyToken, verifyAdmin, validate(createProductSchema), createProduct);

router
  .route("/:slug")
  .get(getProductBySlug)
  .put(verifyToken, verifyAdmin, validate(updateProductSchema), updateProduct)
  .delete(verifyToken, verifyAdmin, deleteProduct);

router
  .route("/:id/reviews")
  .get(getProductReviews)
  .post(verifyToken, validate(createReviewSchema), createProductReview)
  .put(verifyToken, validate(updateReviewSchema), updateProductReview);

module.exports = router;
