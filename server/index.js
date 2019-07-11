require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const massive = require("massive");

const app = express();

//MIDDLEWARE
app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set("db", db);
});

//ENDPOINTS
app.post("/auth/signup", async (req, res) => {
  let { email, password } = req.body;
  let db = req.app.get("db");
  let response = await db.check_user_exists(email);
  if (response[0]) return res.status(200).send("Username is unavailable");
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);
  let createCustomer = await db.create_user([email, hash]);
  console.log("Created customer", createCustomer);
  req.session.user = {
    id: createCustomer[0].id,
    email: createCustomer[0].email
  };
  res.status(200).send(req.session.user);
});

app.post("/auth/login", async (req, res) => {
  let { email, password } = req.body;
  let db = req.app.get("db");
  let response = await db.check_user_exists(email);
  if (!response[0]) return res.status(200).send("Email not correct");
  let result = bcrypt.compareSync(password, response[0].user_password);
  if (result) {
    req.session.user = {
      id: response[0].id,
      email: response[0].email
    };
    res.status(200).send(req.session.user);
  } else {
    res.status(401).send("Password was incorrect");
  }
});
app.get("/auth/logout", (req, res) => {
  req.session.destroy();
  res.sendStatus(200);
});

app.get("/auth/user", (req, res) => {
  if (req.session.user) res.status(200).send(req.session.user);
  else res.status(401).send("No user found");
});

//LISTENING
app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
