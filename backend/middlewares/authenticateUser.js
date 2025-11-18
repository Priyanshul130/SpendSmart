import jwt from "jsonwebtoken";
import User from "../models/userModel.js";
import asyncHandler from "./asyncHandler.js";

const authenticateUser = asyncHandler(async (req, res, next) => {
  const token = req.cookies.session;

  if (!token) {
    return res.status(401).json({
      error: "You must be authenticated to access this resource!",
    });
  }

  try {
    // 🔥 CORRECT SECRET
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    // 🔥 CORRECT FIELD NAME (id not userId)
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({ error: "User not found!" });
    }

    if (!user.verified) {
      return res.status(401).json({
        error: "Email is not verified. Please verify your email!",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Authentication failed. Invalid or expired token!",
    });
  }
});

export default authenticateUser;
