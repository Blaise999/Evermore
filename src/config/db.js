const mongoose = require("mongoose");

module.exports = async function connectDB() {
  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error("MONGO_URI missing in env");

  mongoose.set("strictQuery", true);

  await mongoose.connect(uri, {
    autoIndex: process.env.NODE_ENV !== "production",
  });

  console.log("✅ MongoDB connected");
};
