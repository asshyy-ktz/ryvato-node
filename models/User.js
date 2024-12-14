// models/User.js
// models/User.js
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  userFullname: {
    type: String,
    required: [true, "Full name is required"],
    trim: true,
  },
  userEmail: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: 6,
    select: false,
  },
  isIndividual: {
    type: Boolean,
    default: true,
    required: true,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  otp: {
    code: String,
    expiresAt: Date,
  },
  userStatus: {
    type: Number,
    enum: [1, 2, 3, 4, 5], // active, inactive, banned, pending, deleted
    default: 4, // pending until email verification
  },
  userCreatedAt: {
    type: Date,
    default: Date.now,
  },
  companyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Company",
  },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

module.exports = mongoose.model("User", userSchema);
