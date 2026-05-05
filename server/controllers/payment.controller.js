const paymentService = require("../services/payment.service");

const createOrder = async (req, res) => {
  const { amount, currency } = req.body;

  const order = await paymentService.createOrder(amount, currency);
  res.json(order);
};

const verifyPayment = async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  paymentService.verifyPayment(razorpay_order_id, razorpay_payment_id, razorpay_signature);

  res.json({
    status: "success",
    message: "Payment verified successfully",
    order_id: razorpay_order_id,
    payment_id: razorpay_payment_id,
  });
};

module.exports = {
  createOrder,
  verifyPayment,
};
