require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();

// Database connection with enhanced configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { 
    rejectUnauthorized: false 
  } : false,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// Test database connection with retry logic
const testConnection = async () => {
  try {
    const client = await pool.connect();
    console.log('Connected to PostgreSQL database');
    client.release();
  } catch (err) {
    console.error('Database connection error:', err.stack);
    // Retry after 5 seconds
    setTimeout(testConnection, 5000);
  }
};
testConnection();

// Enhanced security middleware with specific Helmet configurations
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://*.spotify.com"],
      connectSrc: ["'self'", "https://api.deepseek.com", "https://accounts.spotify.com"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// Configure trust proxy based on environment
app.set('trust proxy', process.env.NODE_ENV === 'production');

// Rate limiting configuration with proxy support
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later',
  validate: { trustProxy: true } // Respect X-Forwarded-For header
});

// Apply rate limiter to all routes
app.use(limiter);

// Enhanced CORS configuration
const allowedOrigins = [
  'http://ilkecandan.github.io',
  'https://ilkecandan.github.io',
  'https://cabinetofselves.space',
  'http://cabinetofselves.space'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' })); // Limit JSON body size

// Cache configuration with enhanced settings
const cache = new NodeCache({
  stdTTL: 300, // 5 minutes
  checkperiod: 120, // check for expired items every 2 minutes
  useClones: false // better performance
});

// JWT configuration with stronger defaults
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h'; // Shorter default for better security

// Spotify configuration with validation
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;

if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
  console.warn('Spotify credentials not configured - Spotify features will be disabled');
}

// Enhanced auth middleware with additional security checks
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.sendStatus(403);
    }
    
    // Additional security checks
    if (!user.userId || !user.email) {
      return res.sendStatus(403);
    }
    
    req.user = user;
    next();
  });
};

// User Routes with enhanced validation
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Enhanced validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if user already exists with transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [email]);
      if (existingUser.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'User already exists' });
      }

      // Hash password with higher salt rounds in production
      const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Create user
      const newUser = await client.query(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
        [email, passwordHash]
      );

      // Generate JWT token with additional security
      const token = jwt.sign(
        { 
          userId: newUser.rows[0].id, 
          email: newUser.rows[0].email,
          iat: Math.floor(Date.now() / 1000) // issued at
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      await client.query('COMMIT');
      
      // Set secure cookie in production
      if (process.env.NODE_ENV === 'production') {
        res.cookie('token', token, {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          maxAge: 24 * 60 * 60 * 1000 // 1 day
        });
      }

      res.status(201).json({
        user: newUser.rows[0],
        token
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint with more comprehensive checks
app.get('/health', async (req, res) => {
  try {
    // Test database connection with timeout
    await Promise.race([
      pool.query('SELECT 1'),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Database timeout')), 3000);
      })
    ]);
    
    // Check cache health
    cache.set('healthcheck', 'ok', 10);
    if (cache.get('healthcheck') !== 'ok') {
      throw new Error('Cache not working');
    }
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      services: {
        database: 'connected',
        deepseek: !!process.env.DEEPSEEKAPI,
        spotify: !!(SPOTIFY_CLIENT_ID && SPOTIFY_CLIENT_SECRET),
        cache: 'working'
      }
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      details: error.stack
    });
  }
});

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  
  // Rate limit errors
  if (err.statusCode === 429) {
    return res.status(429).json({ 
      error: 'Too many requests',
      code: 'RATE_LIMIT_EXCEEDED'
    });
  }
  
  // Database errors
  if ((err.code && err.code.startsWith('22')) || err.code === 'ECONNREFUSED') {
    return res.status(503).json({ 
      error: 'Service unavailable',
      code: 'DATABASE_ERROR'
    });
  }
  
  res.status(500).json({ 
    error: 'Internal server error',
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// Start server with proper error handling
const PORT = process.env.PORT || 8080;
let server;

try {
  server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
} catch (error) {
  console.error('Failed to start server:', error);
  process.exit(1);
}

// Enhanced graceful shutdown
const shutdown = async () => {
  console.log('Shutting down gracefully...');
  
  try {
    // Close server first to stop new connections
    await new Promise((resolve) => server.close(resolve));
    
    // Close database connections
    await pool.end();
    
    console.log('Clean shutdown complete');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
  shutdown();
});
