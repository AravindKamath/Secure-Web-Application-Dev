const router = require("express").Router();
const {
  createAccount,
  loginUser,
  googleLogin,
  logoutUser,
  forgotPassword,
  verifyResetToken,
  resetPassword,
  refreshToken,
} = require("../controllers/auth.controller");
const { authLimiter } = require("../middleware/rateLimiter");
const validate = require("../middleware/validate");
const {
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  checkTokenSchema,
  resetPasswordSchema,
  googleLoginSchema,
} = require("../validators/auth.validators");

// Apply strict rate limiter to login and signup
router.post("/signup", authLimiter, validate(signupSchema), createAccount);
router.post("/login", authLimiter, validate(loginSchema), loginUser);

router.post("/google", validate(googleLoginSchema), googleLogin);
router.post("/logout", logoutUser);
router.post("/forgot-password", validate(forgotPasswordSchema), forgotPassword);
router.post("/check-token", validate(checkTokenSchema), verifyResetToken);
router.post("/reset-password", validate(resetPasswordSchema), resetPassword);
router.post("/refresh-token", refreshToken);

module.exports = router;
