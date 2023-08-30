const express = require("express");
const loginLimiter = require("../../middleware/loginLimiter");
const { login } = require("../../controllers/authController");
const { refresh } = require("../../controllers/authController");
const { logout } = require("../../controllers/authController");
const router = express.Router();

router.route("/").post(loginLimiter, login);

router.route("/refresh").get(refresh);

router.route("/logout").post(logout);

module.exports = router;
