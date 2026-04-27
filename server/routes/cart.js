const router = require("express").Router();
const verifyToken = require("../middleware/verifyToken");
const validate = require("../middleware/validate");
const { addItemSchema, cartItemSchema } = require("../validators/cart.validators");
const {
  getCart,
  addItem,
  deleteItem,
  increaseItemQuantity,
  decreaseItemQuantity,
} = require("../controllers/cart.controller");

// All cart routes require a valid access token
router.use(verifyToken);

// Get cart items
router.route("/").get(getCart);

// Add item to cart
router.route("/add").post(validate(addItemSchema), addItem);

// Delete item from cart
router.route("/delete").delete(validate(cartItemSchema), deleteItem);

// Increment item quantity
router.route("/increment").put(validate(cartItemSchema), increaseItemQuantity);

// Decrement item quantity
router.route("/decrement").put(validate(cartItemSchema), decreaseItemQuantity);

module.exports = router;
