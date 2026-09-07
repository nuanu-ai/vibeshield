// Scanner input only; never execute this file.
// @ts-nocheck
const { execFile } = require("node:child_process");
const mysql = require("mysql");
const axios = require("axios");
const jwt = require("jsonwebtoken");
app.get("/command", function (req, res) {
  if (!["--version", "--help"].includes(req.query.option)) return res.sendStatus(400);
  execFile("/usr/bin/git", [req.query.option]);
});
app.get("/database", function (req, res) {
  const connection = mysql.createConnection({});
  connection.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
});
app.get("/template", function (req, res) {
  res.render("index", { title: "Page" });
});
app.get("/fetch", function (req, res) {
  axios.get("https://example.com/status");
});
app.get("/deserialize", function (req, res) {
  const payload = JSON.parse(req.query.payload);
  if (typeof payload.name !== "string") return res.sendStatus(400);
  res.json({ name: payload.name });
});
app.get("/jwt", function (req, res) {
  jwt.verify(req.query.token, publicKey, {
    algorithms: ["RS256"],
    issuer: "https://example.com",
    audience: "service",
  });
});
