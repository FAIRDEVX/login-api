var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");

// create application/json parser
var jsonParser = bodyParser.json();

const bcrypt = require("bcrypt");
const saltRounds = 10;

var jwt = require("jsonwebtoken");
const secret = "";

app.use(cors());

// get the client
const mysql = require("mysql2");

// create the connection to database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "my_db",
});

app.post("/register", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    connection.execute(
      "INSERT INTO user_info (email, password, fname, lname) VALUES (?,?,?,?)",
      [req.body.email, hash, req.body.fname, req.body.lname],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          return;
        }
        res.json({ status: "ok" });
      }
    );
  });
});

app.post("/login", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT * FROM user_info WHERE email=?",
    [req.body.email],
    function (err, users, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      if (users.length == 0) {
        res.json({ status: "error", message: "no user found" });
      }
      // Load hash from your password DB.
      bcrypt.compare(req.body.password, users[0].password).then(function (isLogin) {
        if (isLogin) {
            res.json({status: 'ok', message: 'Login success'})
        }   else {
            res.json({status: 'error', message: 'Login failed'})
        }
      });
    }
  );
});

app.listen(3333, function () {
  console.log("CORS-enabled web server listening on port 3333");
});
