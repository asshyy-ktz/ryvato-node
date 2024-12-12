const express = require("express");
const {
  sendMagicLink,
  verifyMagicLink,
  signup,
  login,
  forgotPassword,
} = require("../controllers/authController");

const router = express.Router();

// Routes
router.post("/send-magic-link", sendMagicLink);
router.get("/verify", verifyMagicLink);

router.post("/signup", signup);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);

module.exports = router;
