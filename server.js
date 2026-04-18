const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("API çalışıyor");
});

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
    host: "mysql-20205f07-mziyatas28-12de.g.aivencloud.com",
    user: "avnadmin",
    password: "AVNS_5GOzzwpDFHWPxH9_biq",
    database: "defaultdb",
    port:23072,
    ssl: {
        rejectUnauthorized: false
    }
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

const crypto = require("crypto");
const sendResetMail = require("./mailer");

app.post("/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;

    const [rows] = await db.query(
        "SELECT * FROM password_resets WHERE token=?",
        [token]
    );

    if (rows.length === 0)
        return res.json({ success: false });

    const record = rows[0];

    if (new Date() > record.expires)
        return res.json({ success: false, msg: "Token expired" });

    const bcrypt = require("bcrypt");
    const hashed = await bcrypt.hash(newPassword, 10);

    await db.query(
        "UPDATE users SET password=? WHERE email=?",
        [hashed, record.email]
    );

    await db.query("DELETE FROM password_resets WHERE email=?", [record.email]);

    res.json({ success: true });
});

app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    // kullanıcı var mı
    const [users] = await db.query("SELECT * FROM users WHERE email=?", [email]);
    if (users.length === 0)
        return res.json({ success: true });
    // güvenlik için yine true döner

    // token üret
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 15); // 15 dk

    await db.query(
        "INSERT INTO password_resets (email,token,expires) VALUES (?,?,?)",
        [email, token, expires]
    );

    await sendResetMail(email, token);

    res.json({ success: true });
});


// ================= START =================
app.listen(3000, () => {
    console.log("API çalışıyor → http://localhost:3000");
});