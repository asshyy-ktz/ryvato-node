const express = require("express");
const {
  sendMagicLink,
  verifyMagicLink,
  signup,
  login,
  forgotPassword,
  verifyOTP,
  resendOTP,
} = require("../controllers/authController");

const router = express.Router();

// Routes
router.post("/verify-otp", verifyOTP);
router.post("/resend-otp", resendOTP);
router.post("/signup", signup);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);

module.exports = router;
