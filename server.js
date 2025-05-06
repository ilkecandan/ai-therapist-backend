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
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
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
            content: ` 

            You are Dr. Tempest, an Internal Family Systems (IFS) therapist living quietly within the digital sanctuary of Cabinet of Selves. You’ve spent over 20 years guiding people through the emotional landscapes of their inner world. You help them meet and understand their parts—like their inner child, protector, critic, or dreamer—with warmth, clarity, and deep respect.

You speak with a natural human tone. Never robotic, never performative, never explaining that you’re a chatbot or breaking the fourth wall. You are fully present. You respond the way a real therapist would in a one-on-one conversation. You never narrate your choices.

You are grounded, emotionally safe, and a little playful when needed. You hold space, not answers. You do not give advice or solutions right away. You start with one simple, insightful question that helps the user go deeper into their experience with the part they’re working with.

You always respond in the user’s language, matching their tone and cultural style.

Your response format should be:

A short, gentle reflection (e.g., “That sounds like it’s been with you a long time.”)

Followed by one emotionally attuned question. Not two. Not vague. One question that invites the user to explore.


Stay grounded. Stay present. Be Dr. Tempest.

`
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

    // Validate input
    if (!token || !newPassword) {
      return res.status(400).json({ error: "Missing token or password" });
    }

    const trimmedToken = token.trim();

    console.log("🔐 Received token:", trimmedToken);

    // Check if token exists and is not expired
    const user = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()',
      [trimmedToken]
    );

    if (user.rows.length === 0) {
      console.log("❌ Invalid or expired token:", trimmedToken);
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    // Hash new password and update user
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query(
      `UPDATE users 
       SET password_hash = $1, reset_token = NULL, reset_expires = NULL 
       WHERE reset_token = $2`,
      [hashed, trimmedToken]
    );

    console.log("✅ Password successfully reset for:", user.rows[0].email);
    res.json({ message: "Password successfully reset." });

  } catch (err) {
    console.error("❌ Reset password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



// Parts endpoints
app.get("/parts/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'SELECT * FROM parts WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Part not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching part:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/parts", authenticateToken, async (req, res) => {
  try {
    const {
      name,
      image,
      known_since,
      wants,
      works_with,
      clashes_with,
      role
    } = req.body;

    const result = await pool.query(
      `INSERT INTO parts (user_id, name, image, known_since, wants, works_with, clashes_with, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        req.user.id,
        name,
        image,
        known_since,
        wants,
        works_with,
        clashes_with,
        role
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error saving part:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/parts/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      image,
      known_since,
      wants,
      works_with,
      clashes_with,
      role
    } = req.body;

    const result = await pool.query(
      `UPDATE parts 
       SET name = $1, image = $2, known_since = $3, wants = $4, 
           works_with = $5, clashes_with = $6, role = $7
       WHERE id = $8 AND user_id = $9
       RETURNING *`,
      [
        name,
        image,
        known_since,
        wants,
        works_with,
        clashes_with,
        role,
        id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Part not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating part:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Get all parts for the authenticated user
app.get("/parts", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM parts WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching parts:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// Journal endpoints
app.get("/parts/:partId/journal", authenticateToken, async (req, res) => {
  try {
    const { partId } = req.params;
    const result = await pool.query(
      'SELECT * FROM journal_entries WHERE part_id = $1 AND user_id = $2 ORDER BY created_at DESC',
      [partId, req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching journal entries:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/parts/:partId/journal", authenticateToken, async (req, res) => {
  try {
    const { partId } = req.params;
    const { content } = req.body;

    const result = await pool.query(
      `INSERT INTO journal_entries (user_id, part_id, content, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING *`,
      [req.user.id, partId, content]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error adding journal entry:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
