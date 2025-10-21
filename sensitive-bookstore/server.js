const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = 3000;

// Configuração básica
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "sensitive_secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Banco SQLite
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) console.error(err.message);
  console.log("✅ Conectado ao banco SQLite.");
});

// Cria tabelas e usuários padrão
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    author TEXT,
    description TEXT
  )`);

  // Usuário admin padrão
  db.get(`SELECT * FROM users WHERE username = ?`, ["admin"], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync("admin123", 10);
      db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
        ["admin", hash, "admin"]);
      console.log("Admin criado (admin / admin123)");
    }
  });

  // Usuário comum padrão
  db.get(`SELECT * FROM users WHERE username = ?`, ["user"], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync("user123", 10);
      db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
        ["user", hash, "user"]);
      console.log("Usuário comum criado (user / user123)");
    }
  });
});

// Middleware de autenticação
function checkAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function isAdmin(req, res, next) {
  if (req.session.user?.role !== "admin") return res.redirect("/");
  next();
}

// Rotas

// Home (usuário comum)
app.get("/", checkAuth, (req, res) => {
  db.all("SELECT * FROM books", (err, books) => {
    res.render("home", { user: req.session.user, books });
  });
});

// Login
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.render("login", { error: "Usuário ou senha incorretos." });
    }
    req.session.user = user;
    res.redirect(user.role === "admin" ? "/admin" : "/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Admin (CRUD)
app.get("/admin", checkAuth, isAdmin, (req, res) => {
  db.all("SELECT * FROM books", (err, books) => {
    res.render("admin", { user: req.session.user, books });
  });
});

app.get("/add", checkAuth, isAdmin, (req, res) => {
  res.render("add", { user: req.session.user });
});

app.post("/add", checkAuth, isAdmin, (req, res) => {
  const { title, author, description } = req.body;
  db.run(
    "INSERT INTO books (title, author, description) VALUES (?, ?, ?)",
    [title, author, description],
    () => res.redirect("/admin")
  );
});

app.get("/edit/:id", checkAuth, isAdmin, (req, res) => {
  db.get("SELECT * FROM books WHERE id = ?", [req.params.id], (err, book) => {
    res.render("edit", { user: req.session.user, book });
  });
});

app.post("/edit/:id", checkAuth, isAdmin, (req, res) => {
  const { title, author, description } = req.body;
  db.run(
    "UPDATE books SET title=?, author=?, description=? WHERE id=?",
    [title, author, description, req.params.id],
    () => res.redirect("/admin")
  );
});

app.get("/delete/:id", checkAuth, isAdmin, (req, res) => {
  db.run("DELETE FROM books WHERE id=?", [req.params.id], () => res.redirect("/admin"));
});

// Servidor
app.listen(PORT, () => console.log(`🚀 Servidor rodando em http://localhost:${PORT}`));
