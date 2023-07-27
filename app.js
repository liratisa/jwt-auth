require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require("./model/User");

// Private route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // Check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado." });
  }

  return res.status(200).json({ user: user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado" });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (err) {
    res.status(400).json({ msg: "Token inválido" });
  }
}

// Public route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API" });
});

// Register user
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // Validations
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório." });
  }

  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório." });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória." });
  }

  if (!confirmPassword) {
    return res
      .status(422)
      .json({ msg: "A confirmação de senha é obrigatória." });
  }

  if (confirmPassword !== password) {
    return res.status(422).json({ msg: "As senhas não conferem." });
  }

  // Check if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "Este email já foi cadastrado." });
  }

  // Create password
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);

  // Create user
  const user = new User({
    name,
    email,
    password: passwordHash, // Saves encrypted password
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      msg: "Aconteceu um erro ao cadastrar o usuário. Por favor, tente novamente mais tarde.",
    });
  }
});

// Login user
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validations
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório." });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória." });
  }

  // Check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(422).json({ msg: "Usuário não encontrado." });
  }

  // Check if password matches
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(404).send({ msg: "Senha inválida." });
  }

  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res
      .status(200)
      .json({ msg: "Autenticação realizada com sucesso!", token: token });
  } catch (err) {
    console.log(err);
    return res.status(422).json({ msg: "Não foi possível fazer login." });
  }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.xet2l3m.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao banco de dados");
  })
  .catch((err) => {
    console.log(err);
  });
