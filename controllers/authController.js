const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const User = require("../models/User");
const { generateOTP } = require("../utils/otpUtils");

// Send Magic Link
const sendOTPEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your Email Verification OTP",
    html: `<p>Your OTP for email verification is: <strong>${otp}</strong></p>
           <p>This OTP will expire in 15 minutes.</p>`,
  });
};

// Verify Magic Link
const verifyMagicLink = (req, res) => {
  const { token } = req.query;

  if (!token) return res.status(400).json({ message: "Token is required" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Optionally, you can issue a new session token here
    const sessionToken = jwt.sign(
      { email: decoded.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      message: "Authentication successful",
      sessionToken,
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ message: "Invalid or expired token" });
  }
};

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const signup = async (req, res) => {
  try {
    // 1. Validate request body
    const { userEmail, userFullname, password, confirmPassword, isIndividual } =
      req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({
        status: "fail",
        message: "Passwords do not match",
      });
    }

    // 2. Generate OTP
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // 3. Create user
    const newUser = await User.create({
      userEmail,
      userFullname,
      password,
      isIndividual: isIndividual ?? true,
      otp: {
        code: otp,
        expiresAt: otpExpiresAt,
      },
    });

    // 4. Send OTP email
    await sendOTPEmail(userEmail, otp);

    // 5. Generate JWT token
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    res.status(201).json({
      status: "success",
      message: "OTP sent to your email for verification.",
      token,
      data: {
        user: {
          id: newUser._id,
          userFullname: newUser.userFullname,
          userEmail: newUser.userEmail,
          isIndividual: newUser.isIndividual,
          isVerified: false,
        },
      },
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ userEmail: email });

    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "User not found",
      });
    }

    // Check if OTP exists and hasn't expired
    if (
      !user.otp ||
      !user.otp.code ||
      !user.otp.expiresAt ||
      new Date() > user.otp.expiresAt
    ) {
      return res.status(400).json({
        status: "fail",
        message: "OTP has expired. Please request a new one.",
      });
    }

    // Verify OTP
    if (user.otp.code !== otp) {
      return res.status(400).json({
        status: "fail",
        message: "Invalid OTP",
      });
    }

    // Update user status
    user.isVerified = true;
    user.userStatus = 1; // active
    user.otp = undefined; // Clear OTP after successful verification
    await user.save();

    res.status(200).json({
      status: "success",
      message: "Email verified successfully",
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ userEmail: email });

    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "User not found",
      });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Update user's OTP
    user.otp = {
      code: otp,
      expiresAt: otpExpiresAt,
    };
    await user.save();

    // Send new OTP email
    await sendOTPEmail(email, otp);

    res.status(200).json({
      status: "success",
      message: "New OTP sent to your email",
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

const login = async (req, res) => {
  try {
    const { userEmail, password } = req.body;

    // Check if email and password exist
    if (!userEmail || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Please provide email and password",
      });
    }

    // Check if user exists && password is correct
    const user = await User.findOne({ userEmail }).select("+password");

    if (!user || !(await user.correctPassword(password))) {
      return res.status(401).json({
        status: "fail",
        message: "Incorrect email or password",
      });
    }

    // Update last login
    user.lastLoginAt = new Date();
    await user.save({ validateBeforeSave: false });

    const token = signToken(user._id);

    res.status(200).json({
      status: "success",
      token,
      data: {
        user: {
          id: user._id,
          userFullname: user.userFullname,
          userEmail: user.userEmail,
          isIndividual: user.isIndividual,
        },
      },
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ userEmail: req.body.userEmail });
    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "There is no user with this email address",
      });
    }

    // Generate reset token (you might want to implement your own token generation logic)
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // In a real application, you would send this token via email
    // For now, we'll just return it in the response
    res.status(200).json({
      status: "success",
      message: "Token sent to email",
      resetToken, // In production, remove this and only send via email
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

module.exports = {
  verifyMagicLink,
  signup,
  login,
  forgotPassword,
  verifyOTP,
  resendOTP,
};
