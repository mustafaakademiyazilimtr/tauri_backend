const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// ================= CONFIG =================
const SECRET = "super_secret_key_change_this";

// ================= MYSQL =================
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "tauri_app",
    database: "tauri_app"
});

db.connect((err) => {
    if (err) {
        console.log("MySQL hata:", err);
    } else {
        console.log("MySQL bağlandı");
    }
});


// ================= REGISTER =================
app.post("/register", async (req, res) => {

    const { username, email, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO users (username, email, password) VALUES (?,?,?)";

    db.query(sql, [username, email, hash], (err) => {
        if (err) {
            console.log(err);
            return res.json({ success: false, message: "Kayıt hatası" });
        }

        res.json({ success: true });
    });
});


// ================= LOGIN =================
app.post("/login", (req, res) => {

    const { username, password } = req.body;

    const sql = "SELECT * FROM users WHERE username=?";

    db.query(sql, [username], async (err, result) => {

        if (err) {
            return res.json({ success: false });
        }

        if (result.length === 0) {
            return res.json({ success: false });
        }

        const user = result[0];

        const ok = await bcrypt.compare(password, user.password);

        if (!ok) {
            return res.json({ success: false });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            token: token
        });
    });
});


// ================= TOKEN MIDDLEWARE =================
function auth(req, res, next) {

    const header = req.headers.authorization;

    if (!header) {
        return res.json({ success: false, message: "Token yok" });
    }

    const token = header.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.json({ success: false, message: "Geçersiz token" });
    }
}


// ================= PROTECTED ROUTE =================
app.get("/profile", auth, (req, res) => {

    res.json({
        success: true,
        user: req.user
    });
});


// ================= START =================
app.listen(3000, () => {
    console.log("API çalışıyor → http://localhost:3000");
});