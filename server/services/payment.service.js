const Razorpay = require("razorpay");
const crypto = require("crypto");
const { ErrorHandler } = require("../helpers/error");

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

class PaymentService {
  /**
   * Create a Razorpay order.
   * @param {number} amount  – Amount in the smallest currency unit (e.g. paise for INR)
   * @param {string} currency – ISO currency code (default: "INR")
   * @returns {Promise<Object>} Razorpay order object
   */
  createOrder = async (amount, currency = "INR") => {
    try {
      const options = {
        amount,
        currency,
        receipt: `order_${Date.now()}`,
      };
      return await razorpay.orders.create(options);
    } catch (error) {
      throw new ErrorHandler(error.statusCode || 500, error.error?.description || error.message);
    }
  };

  /**
   * Verify Razorpay payment signature (Zero-Trust).
   * HMAC_SHA256(razorpay_order_id + "|" + razorpay_payment_id, RAZORPAY_KEY_SECRET)
   *
   * @param {string} razorpay_order_id
   * @param {string} razorpay_payment_id
   * @param {string} razorpay_signature
   * @returns {boolean} true if signature is valid
   * @throws {ErrorHandler} if verification fails
   */
  verifyPayment = (razorpay_order_id, razorpay_payment_id, razorpay_signature) => {
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    const isValid = crypto.timingSafeEqual(
      Buffer.from(expectedSignature),
      Buffer.from(razorpay_signature)
    );

    if (!isValid) {
      throw new ErrorHandler(400, "Payment verification failed: invalid signature");
    }

    return true;
  };
}

module.exports = new PaymentService();
