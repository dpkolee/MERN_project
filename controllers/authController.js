const Users = require("../models/Users");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// @desc Login
// @route POST /auth
// @access Public
const login = asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ message: "Username and Password are required" });

  const foundUser = await Users.findOne({ username }).exec();

  if (!foundUser || !foundUser.active)
    return res.status(401).json({
      message: "Unauthorized",
    });

  const match = await bcrypt.compare(password, foundUser.password);

  if (!match) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const accessToken = jwt.sign(
    {
      UserInfo: {
        username: foundUser.username,
        roles: foundUser.roles,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: "60s",
    }
  );

  const refreshToken = jwt.sign(
    {
      username: foundUser.username,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: "1d",
    }
  );

  // Create secure token with refresh token
  res.cookie("jwt", refreshToken, {
    httpOnly: true, // accessible only by web server
    secure: true, // https
    sameSite: "none", // cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 1000, // cookie expiry
  });

  //Send access token containing username and roles
  res.json({ accessToken });
});

// @desc refresh
// @route GET /auth/refresh
// @access Public - because access token has expired
const refresh = asyncHandler(async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.status(401).json({ message: "Unauthorized" });

  const refreshToken = cookies.jwt;
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Forbidden" });

      const foundUser = await Users.findOne({
        username: decoded.username,
      }).exec();

      if (!foundUser) return res.status(401).json({ message: "Unauthorized" });

      const accessToken = jwt.sign(
        {
          UserInfo: {
            username: foundUser.username,
            roles: foundUser.roles,
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
      );

      res.json({ accessToken });
    })
  );
});

// @desc logout
// @route POST /auth/logout
// @access Public - just to clear cookie if exists
const logout = asyncHandler(async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
  res.json({ message: "Cookie cleared" });
});

module.exports = {
  login,
  refresh,
  logout,
};
