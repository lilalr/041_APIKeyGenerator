require("dotenv").config();
const mysql = require("mysql2/promise");
const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;

// ===============================================
// GLOBAL CONFIG
// ===============================================
const KEY_PREFIX = "Lila_secr3t_";
const JWT_SECRET = process.env.JWT_SECRET || "iniJWTsecretLila";

// ===============================================
// MYSQL CONNECTION (POOL)
// ===============================================
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "Mysql2lila",
  database: process.env.DB_NAME || "apikey_lila",
  port: process.env.DB_PORT || 3308,
});

// ===============================================
// GENERATE API KEY (VALID 30 DAYS)
// ===============================================
app.get("/generate-apikey", async (req, res) => {
  try {
    const token = crypto.randomBytes(8).toString("hex");
    const apiKey = KEY_PREFIX + token;

    const sql =
      "INSERT INTO apikey (`key`, outofdate, status) VALUES (?, NOW() + INTERVAL 30 DAY, 'active')";
    const [result] = await pool.query(sql, [apiKey]);
    const newId = result.insertId;

    res.json({ id: newId, apiKey });
  } catch (err) {
    console.error("generate key error:", err);
    res.status(500).json({ error: "Gagal membuat API key" });
  }
});


// ===============================================
// REGISTER USER
// ===============================================
app.post("/api/register", async (req, res) => {
  const { firstname, lastname, email, apikey_id } = req.body;

  if (!firstname || !lastname || !email || !apikey_id)
    return res.status(400).json({
      error: "firstname, lastname, email, apikey_id wajib diisi",
    });

  try {
    const [keyCheck] = await pool.query(
      "SELECT * FROM apikey WHERE id = ? AND status = 'active'",
      [apikey_id]
    );

    if (keyCheck.length === 0)
      return res.status(400).json({ error: "API Key tidak valid" });

    const sql = `
      INSERT INTO user (firstname, lastname, email, start_date, last_date, apikey)
      VALUES (?, ?, ?, CURDATE(), NULL, ?)
    `;

    await pool.query(sql, [firstname, lastname, email, apikey_id]);

    res.json({ message: "User berhasil dibuat" });
  } catch (err) {
    console.error("register user error:", err);
    res.status(500).json({ error: "Gagal mendaftar user" });
  }
});

// ===============================================
// CREATE ADMIN
// ===============================================
app.post("/api/admin/create", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res
      .status(400)
      .json({ error: "email dan password tidak boleh kosong" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO admin (email, password) VALUES (?, ?)", [
      email,
      hashed,
    ]);
    res.json({ message: "Admin berhasil dibuat" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY")
      return res.status(409).json({ error: "Email admin sudah ada" });

    console.error("create admin error:", err);
    res.status(500).json({ error: "Gagal membuat admin" });
  }
});

// ===============================================
// LOGIN ADMIN
// ===============================================
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM admin WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0)
      return res.status(401).json({ error: "Email atau password salah" });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);

    if (!match)
      return res.status(401).json({ error: "Email atau password salah" });

    const token = jwt.sign(
      { id: admin.id, role: "admin" },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    console.error("login admin error:", err);
    res.status(500).json({ error: "Gagal login admin" });
  }
});

// ===============================================
// ADMIN AUTH MIDDLEWARE
// ===============================================
function adminAuth(req, res, next) {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token tidak ada" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token tidak valid" });

    req.admin = user;
    next();
  });
}

// ===============================================
// GET LIST USER (ADMIN)
// ===============================================
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM user");
    res.json(rows);
  } catch (err) {
    console.error("list users error:", err);
    res.status(500).json({ error: "Gagal mengambil data user" });
  }
});

// ===============================================
// GET LIST API KEY (ADMIN)
// ===============================================
app.get("/api/admin/apikey", adminAuth, async (req, res) => {
  const [rows] = await pool.query(`
    SELECT 
      id,
      \`key\` as api_key,
      status,
      user_id,
      outofdate as expires_at
    FROM apikey ORDER BY id DESC
  `);
  res.json(rows);
});


// ===============================================
// DELETE/DEACTIVATE API KEY (ADMIN)
// ===============================================
app.delete("/api/admin/apikey/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query(
      "UPDATE apikey SET status = 'inactive' WHERE id = ?",
      [id]
    );

    if (result.affectedRows === 0)
      return res.status(404).json({ error: "API Key tidak ditemukan" });

    res.json({ message: `API Key ${id} dinonaktifkan` });
  } catch (err) {
    console.error("delete apikey error:", err);
    res.status(500).json({ error: "Gagal menonaktifkan apikey" });
  }
});

// ===============================================
// START SERVER
// ===============================================
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
  console.log(
    `Terhubung ke database MySQL '${process.env.DB_NAME || "apikey_lila"}'`
  );
});
