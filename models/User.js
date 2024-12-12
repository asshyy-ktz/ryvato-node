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
    select: false, // Don't return password in queries by default
  },
  userStatus: {
    type: Number,
    enum: [1, 2, 3, 4, 5], // active, inactive, banned, pending, deleted
    default: 4, // pending
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  userCreatedAt: {
    type: Date,
    default: Date.now,
  },
  userUpdatedAt: {
    type: Date,
    default: Date.now,
  },
  lastLoginAt: {
    type: Date,
  },
  isIndividual: {
    type: Boolean,
    required: true,
  },
  companyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Company",
  },
  profilePic: String,
  projects: [
    {
      projectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" },
      projectName: String,
      role: String,
    },
  ],
  tasks: [
    {
      taskId: String,
      taskName: String,
      status: String,
    },
  ],
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Check if password is correct
userSchema.methods.correctPassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
