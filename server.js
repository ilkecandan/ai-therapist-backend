const express = require("express");
const cors = require("cors");
const axios = require("axios");
const NodeCache = require("node-cache");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
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
const cache = new NodeCache({ stdTTL: 300 }); // Cache responses for 5 minutes

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

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
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
    // Check if user already exists
    const userExists = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    
    // Create user
    const newUser = await pool.query(
      'INSERT INTO users (email, password_hash, created_at) VALUES ($1, $2, NOW()) RETURNING id, email, created_at',
      [email, passwordHash]
    );
    
    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.rows[0].id, email: newUser.rows[0].email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.status(201).json({ 
      token,
      user: {
        id: newUser.rows[0].id,
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
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
    // Find user
    const user = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (user.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({ 
      token,
      user: {
        id: user.rows[0].id,
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
    const correctCode = "99005445"; // Your access code
    
    if (!accessCode) {
      return res.status(400).json({ error: "Access code is required" });
    }
    
    if (accessCode !== correctCode) {
      return res.status(400).json({ error: "Invalid access code" });
    }
    
    // Update user to mark as having access
    await pool.query(
      'UPDATE users SET has_access = true WHERE id = $1',
      [req.user.id]
    );
    
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
      'SELECT id, email, created_at, has_access FROM users WHERE id = $1',
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

// Existing chat endpoint (protected)
app.post("/api/chat", authenticateToken, async (req, res) => {
  try {
    const userMessage = req.body.message;
    const partDetails = req.body.partDetails ? req.body.partDetails.slice(0, 200) : "";
    const cacheKey = JSON.stringify({ userMessage, partDetails });

    // Check cache before making API call
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
        max_tokens: 150,
        temperature: 0.7,
        stream: false
      },
      {
        headers: { Authorization: `Bearer ${process.env.DEEPSEEKAPI}` }
      }
    );

    const fullResponse = apiResponse.data.choices[0]?.message?.content || "No response";

    // Cache the response
    cache.set(cacheKey, fullResponse);

    res.json({ response: fullResponse });

  } catch (error) {
    console.error("DeepSeek API Error:", error.response ? error.response.data : error.message);
    res.status(500).json({ error: "Error connecting to DeepSeek API" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
