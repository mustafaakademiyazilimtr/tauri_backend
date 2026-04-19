const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "SUPER_SECRET_KEY";

// AIVEN MYSQL BAĞLANTI
const db = mysql.createPool({
  host: "mysql-20205f07-mziyatas28-12de.g.aivencloud.com",
  user: "avnadmin",
  password: "AVNS_5GOzzwpDFHWPxH9_biq",
  database: "defaultdb",
  port: 23072,
  ssl: { rejectUnauthorized: false }
});

console.log("MySQL connected");

// ================= REGISTER =================
app.post("/register", async (req,res)=>{
  try{
    const {username,email,password} = req.body;

    if(!username || !email || !password)
      return res.json({success:false});

    const [varMi] = await db.query(
      "SELECT id FROM users WHERE username=? OR email=?",
      [username,email]
    );

    if(varMi.length > 0)
      return res.json({success:false});

    const hash = await bcrypt.hash(password,10);

    await db.query(
      "INSERT INTO users (username,email,password) VALUES (?,?,?)",
      [username,email,hash]
    );

    res.json({success:true});
  }
  catch(err){
    console.log(err);
    res.json({success:false});
  }
});


// ================= LOGIN =================
app.post("/login", async (req,res)=>{
  try{
    const {username,password} = req.body;

    const [rows] = await db.query(
      "SELECT * FROM users WHERE username=?",
      [username]
    );

    if(rows.length === 0)
      return res.json({success:false});

    const user = rows[0];

    const dogruMu = await bcrypt.compare(password, user.password);

    if(!dogruMu)
      return res.json({success:false});

    const token = jwt.sign({id:user.id}, JWT_SECRET);

    res.json({success:true, token});
  }
  catch(err){
    console.log(err);
    res.json({success:false});
  }
});


// ================= TOKEN KONTROL =================
app.get("/profile", async (req,res)=>{
  try{
    const auth = req.headers.authorization;
    if(!auth) return res.json({success:false});

    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await db.query(
      "SELECT id,username,email FROM users WHERE id=?",
      [decoded.id]
    );

    res.json(rows[0]);
  }
  catch{
    res.json({success:false});
  }
});


// ================= FORGOT PASSWORD =================
app.post("/forgot-password", async (req,res)=>{
  try{
    const {username} = req.body;

    const [rows] = await db.query(
      "SELECT email FROM users WHERE username=?",
      [username]
    );

    if(rows.length === 0)
      return res.json({success:false});

    // şimdilik mail atmıyoruz
    // sadece çalıştığını test ediyoruz
    res.json({
      success:true,
      message:"Mail gönderme sistemi sonra eklenecek"
    });
  }
  catch{
    res.json({success:false});
  }
});


app.listen(3000, ()=> console.log("SERVER READY"));
