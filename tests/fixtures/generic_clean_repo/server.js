// Clean JS module (no findings expected).
const express = require("express");
const app = express();

app.get("/user/:id", (req, res) => {
  const id = Number(req.params.id);
  res.json({ id });
});

module.exports = app;
