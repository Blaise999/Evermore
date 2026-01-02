class AppError extends Error {
  constructor(message, statusCode = 400, code = "BAD_REQUEST") {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

function notFound(req, res, next) {
  next(new AppError(`Route not found: ${req.method} ${req.originalUrl}`, 404, "NOT_FOUND"));
}

function errorHandler(err, req, res, next) { // eslint-disable-line
  const status = err.statusCode || 500;
  const code = err.code || "SERVER_ERROR";

  // Mongoose duplicate key
  if (err && err.code === 11000) {
    return res.status(409).json({
      ok: false,
      code: "DUPLICATE",
      message: "Duplicate value (already exists).",
      details: err.keyValue || null,
    });
  }

  // Mongoose validation
  if (err && err.name === "ValidationError") {
    return res.status(400).json({
      ok: false,
      code: "VALIDATION_ERROR",
      message: "Validation failed.",
      details: err.errors || null,
    });
  }

  res.status(status).json({
    ok: false,
    code,
    message: err.message || "Something went wrong",
  });
}

function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = { AppError, notFound, errorHandler, asyncHandler };
