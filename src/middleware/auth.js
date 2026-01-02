const { verifyToken } = require("../utils/tokens");
const User = require("../models/User");
const { AppError } = require("./error");

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) throw new AppError("Missing Authorization token", 401, "UNAUTHORIZED");

    const decoded = verifyToken(token);
    const user = await User.findById(decoded.sub).lean();

    if (!user) throw new AppError("User not found", 401, "UNAUTHORIZED");

    req.user = {
      id: String(user._id),
      role: user.role,
      email: user.email,
      hospitalId: user.hospitalId,
      name: user.name,
    };

    next();
  } catch (e) {
    next(new AppError("Invalid or expired token", 401, "UNAUTHORIZED"));
  }
}

module.exports = auth;
