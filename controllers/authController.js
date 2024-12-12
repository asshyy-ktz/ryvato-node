const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const User = require("../models/User");
const { promisify } = require("util");

// Send Magic Link
const sendMagicLink = async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    // Generate a JWT token
    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    // Send email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const magicLink = `${process.env.CLIENT_URL}/auth/verify?token=${token}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Magic Link",
      html: `<p>Click the link below to log in:</p><a href="${magicLink}">${magicLink}</a>`,
    });

    res.status(200).json({ message: "Magic link sent to email" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error sending magic link" });
  }
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
    const newUser = await User.create({
      userFullname: req.body.userFullname,
      userEmail: req.body.userEmail,
      password: req.body.password,
      isIndividual: req.body.isIndividual,
      companyId: req.body.companyId,
    });

    const token = signToken(newUser._id);

    res.status(201).json({
      status: "success",
      token,
      data: {
        user: {
          id: newUser._id,
          userFullname: newUser.userFullname,
          userEmail: newUser.userEmail,
          isIndividual: newUser.isIndividual,
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
  sendMagicLink,
  verifyMagicLink,
  signup,
  login,
  forgotPassword,
};
