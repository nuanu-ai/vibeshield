// Scanner input only; never execute this file.
// @ts-nocheck
const shell = require("shelljs");
const mysql = require("mysql");
const axios = require("axios");
const serializer = require("node-serialize");
const jwt = require("jsonwebtoken");
app.get("/command", function (req, res) {
  shell.exec(req.query.command); // nosemgrep
});
app.get("/database", function (req, res) {
  const connection = mysql.createConnection({});
  connection.query("SELECT * FROM users WHERE id = " + req.query.id);
});
app.get("/template", function (req, res) {
  const template = req.query.template;
  res.render(template, { title: "Page" });
});
app.get("/fetch", function (req, res) {
  const url = req.query.url;
  axios.get(url); // nosemgrep
});
app.get("/deserialize", function (req, res) {
  serializer.unserialize(req.query.payload);
});
app.get("/jwt", function (req, res) {
  jwt.verify(req.query.token, "", { algorithms: ["none"] });
});
