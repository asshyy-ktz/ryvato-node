const mongoose = require("mongoose");

module.exports = function () {
  mongoose
    .connect(process.env.MONGODB_URI)
    .then(() => console.log("connected to mongodb..."))
    .catch((err) => console.error("could not connect to mongodb...", err));
};
