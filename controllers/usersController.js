const Users = require("../models/Users");
const Note = require("../models/Note");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");

// Get all users
const getAllUsers = asyncHandler(async (_req, res) => {
  const users = await Users.find().select("-password").lean();
  if (!users?.length) {
    return res.status(400).json({ message: "No users found" });
  }
  res.json(users);
});

// Create new user
const createNewUser = asyncHandler(async (req, res) => {
  const { username, password, roles } = req.body;

  //Confirm data
  if (!username || !password || !Array.isArray(roles) || !roles.length) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Check for duplicates
  const duplicates = await Users.findOne({ username }).lean().exec();

  if (duplicates) {
    return res.status(409).json({ message: "Duplicate username" });
  }

  // Hash password
  const hashedPwd = await bcrypt.hash(password, 10); // salt rounds

  const userObject = {
    username,
    password: hashedPwd,
    roles,
  };

  //create and store user
  const user = await Users.create(userObject);

  if (user) {
    res.status(201).json({ message: `New user ${username} created` });
  } else {
    res.status(400).json({ message: "invalid user data received" });
  }
});

// Update a user
const updateUser = asyncHandler(async (req, res) => {
  const { id, username, roles, active, password } = req.body;
  //Confirm data
  if (
    (!id,
    !username ||
      !password ||
      !Array.isArray(roles) ||
      !roles.length ||
      typeof active !== "boolean")
  ) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const user = await Users.findById(id).exec();
  if (!user) {
    return res.status(400).json({ message: `User not found` });
  }

  // Check for duplicates
  const duplicates = await Users.findOne({ username }).lean().exec();

  if (duplicates && duplicates?._id.toString() !== id) {
    return res.status(409).json({ message: "Duplicate username" });
  }

  user.username = username;
  user.roles = roles;
  user.active = active;

  if (password) {
    // Hash password
    user.password = await bcrypt.hash(password, 10);
  }

  const updatedUser = await user.save();

  res.json({ message: `${updatedUser.username} updated` });
});

// Delete a user
const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ message: "User ID required" });
  }

  const note = await Note.findOne({ user: id }).lean().exec();

  if (note) {
    return res.status(400).json({ message: "User has assigned notes" });
  }

  const user = await Users.findById(id).exec();

  if (!user) {
    return res.status(400).json({
      message: "User not found",
    });
  }
  const result = await user.deleteOne();

  res.json(`Username ${result.username} with ID ${result._id} deleted`);
});

module.exports = {
  getAllUsers,
  createNewUser,
  updateUser,
  deleteUser,
};
