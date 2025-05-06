const express = require("express");
const cors = require("cors");
const axios = require("axios");
const NodeCache = require("node-cache");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
app.use(express.json());

// CORS settings
const corsOptions = {
  origin: [
    "http://ilkecandan.github.io", 
    "https://ilkecandan.github.io",  
    "https://cabinetofselves.space",
    "http://cabinetofselves.space"
  ],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true
};
app.use(cors(corsOptions));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err.stack);
  } else {
    console.log('Connected to database');
  }
});

// Cache setup
const cache = new NodeCache({ stdTTL: 300 });

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// User registration endpoint
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email and password are required" });
    }
    
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }
    
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    
    const newUser = await pool.query(
      'INSERT INTO users (name, email, password_hash, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email, created_at',
      [name, email, passwordHash]
    );
    
    const token = jwt.sign(
      { id: newUser.rows[0].id, email: newUser.rows[0].email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.status(201).json({ 
      token,
      user: {
        id: newUser.rows[0].id,
        name: newUser.rows[0].name,
        email: newUser.rows[0].email,
        created_at: newUser.rows[0].created_at
      }
    });
    
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// User login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const token = jwt.sign(
      { id: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({ 
      token,
      user: {
        id: user.rows[0].id,
        name: user.rows[0].name,
        email: user.rows[0].email,
        created_at: user.rows[0].created_at,
        hasAccess: user.rows[0].has_access || false
      }
    });
    
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Validate access code endpoint
app.post("/validate-access-code", authenticateToken, async (req, res) => {
  try {
    const { accessCode } = req.body;
    const correctCode = "99005445";
    
    if (!accessCode) {
      return res.status(400).json({ error: "Access code is required" });
    }
    
    if (accessCode !== correctCode) {
      return res.status(400).json({ error: "Invalid access code" });
    }
    
    await pool.query('UPDATE users SET has_access = true WHERE id = $1', [req.user.id]);
    res.json({ success: true, message: "Access granted" });
    
  } catch (error) {
    console.error("Access code validation error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Protected user profile endpoint
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await pool.query(
      'SELECT id, name, email, created_at, has_access FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json(user.rows[0]);
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Chat endpoint (without message truncation)
app.post("/api/chat", authenticateToken, async (req, res) => {
  try {
    const userMessage = req.body.message;
    const partDetails = req.body.partDetails || "";
    const cacheKey = JSON.stringify({ userMessage, partDetails });

    const cachedResponse = cache.get(cacheKey);
    if (cachedResponse) {
      return res.json({ response: cachedResponse });
    }

    const apiResponse = await axios.post(
      "https://api.deepseek.com/v1/chat/completions",
      {
        model: "deepseek-chat",
        messages: [
          {
            role: "system",
            content: `You are an AI therapist guiding the user through self-exploration. You specialize in Internal Family Systems therapy. Keep responses concise, friendly, amusing, and supportive. They are working with this part: ${partDetails}`
          },
          { role: "user", content: userMessage }
        ],
        temperature: 0.7,
        stream: false
      },
      {
        headers: { Authorization: `Bearer ${process.env.DEEPSEEKAPI}` }
      }
    );

    const fullResponse = apiResponse.data.choices[0]?.message?.content || "No response";
    cache.set(cacheKey, fullResponse);
    res.json({ response: fullResponse });

  } catch (error) {
    console.error("DeepSeek API Error:", error.response ? error.response.data : error.message);
    res.status(500).json({ error: "Error connecting to DeepSeek API" });
  }
});

// Request password reset with email sending
app.post("/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "Email not found" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 3600000);

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_expires = $2 WHERE email = $3',
      [token, expires, email]
    );

    const resetLink = `https://cabinetofselves.space/reset-password.html?token=${token}`;
    
    await transporter.sendMail({
      from: `"Cabinet of Selves" <${process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      text: `Click this link to reset your password: ${resetLink}`,
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Password Reset</h2>
          <p>Click <a href="${resetLink}">here</a> to reset your password.</p>
          <p>This link expires in 1 hour.</p>
        </div>
      `
    });

    res.json({ message: "Password reset link sent to your email" });
  } catch (err) {
    console.error("Password reset error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Reset password endpoint
app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()',
      [token]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query(
      `UPDATE users 
       SET password_hash = $1, reset_token = NULL, reset_expires = NULL 
       WHERE reset_token = $2`,
      [hashed, token]
    );

    res.json({ message: "Password successfully reset." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Save a new part
app.post("/parts", authenticateToken, async (req, res) => {
  try {
    const {
      name,
      description,
      role,
      positiveIntentions,
      triggers,
      relationships,
      image,
      journal
    } = req.body;

    const result = await pool.query(
      `INSERT INTO parts (user_id, name, description, role, positive_intentions, triggers, relationships, image, journal)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        req.user.id,
        name,
        description,
        role,
        positiveIntentions,
        triggers,
        relationships,
        image,
        journal
      ]
    );

    res.status(201).json({ message: "Part saved successfully", part: result.rows[0] });
  } catch (error) {
    console.error("Error saving part:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

