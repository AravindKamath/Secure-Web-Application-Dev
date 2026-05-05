const { createOrder, verifyPayment } = require("../controllers/payment.controller");

const router = require("express").Router();

router.route("/order").post(createOrder);
router.route("/verify").post(verifyPayment);

module.exports = router;
