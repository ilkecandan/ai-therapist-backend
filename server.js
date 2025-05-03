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

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch(err => console.error('Database connection error:', err.stack));

// Enhanced security middleware
app.use(helmet());
app.use(morgan('combined'));

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// CORS configuration
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
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// Cache configuration
const cache = new NodeCache({
  stdTTL: 300, // 5 minutes
  checkperiod: 120 // check for expired items every 2 minutes
});

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';

// Spotify configuration
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;

if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
  console.warn('Spotify credentials not configured - Spotify features will be disabled');
}

// Auth middleware
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

// User Routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const newUser = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, passwordHash]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.rows[0].id, email: newUser.rows[0].email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      user: newUser.rows[0],
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      user: {
        id: user.rows[0].id,
        email: user.rows[0].email,
        created_at: user.rows[0].created_at
      },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Parts Routes
app.post('/api/parts', authenticateToken, async (req, res) => {
  try {
    const { name, image } = req.body;
    const userId = req.user.userId;

    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }

    const newPart = await pool.query(
      'INSERT INTO parts (user_id, name, image) VALUES ($1, $2, $3) RETURNING *',
      [userId, name, image]
    );

    res.status(201).json(newPart.rows[0]);

  } catch (error) {
    console.error('Create part error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/parts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const parts = await pool.query(
      'SELECT * FROM parts WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    res.json(parts.rows);

  } catch (error) {
    console.error('Get parts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/parts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    const part = await pool.query(
      'SELECT * FROM parts WHERE id = $1 AND user_id = $2',
      [id, userId]
    );

    if (part.rows.length === 0) {
      return res.status(404).json({ error: 'Part not found' });
    }

    res.json(part.rows[0]);

  } catch (error) {
    console.error('Get part error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/parts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const { name, image } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }

    const updatedPart = await pool.query(
      'UPDATE parts SET name = $1, image = $2, updated_at = NOW() WHERE id = $3 AND user_id = $4 RETURNING *',
      [name, image, id, userId]
    );

    if (updatedPart.rows.length === 0) {
      return res.status(404).json({ error: 'Part not found' });
    }

    res.json(updatedPart.rows[0]);

  } catch (error) {
    console.error('Update part error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/parts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    const deletedPart = await pool.query(
      'DELETE FROM parts WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, userId]
    );

    if (deletedPart.rows.length === 0) {
      return res.status(404).json({ error: 'Part not found' });
    }

    res.json({ message: 'Part deleted successfully' });

  } catch (error) {
    console.error('Delete part error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Updated DeepSeek API endpoint with user context
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    // Validate request
    if (!req.body.message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const userMessage = req.body.message;
    const partId = req.body.partId;
    let partDetails = '';

    // If partId is provided, get part details from database
    if (partId) {
      const part = await pool.query(
        'SELECT * FROM parts WHERE id = $1 AND user_id = $2',
        [partId, req.user.userId]
      );
      
      if (part.rows.length > 0) {
        partDetails = `They are working with a part named "${part.rows[0].name}"`;
        if (part.rows[0].image) {
          partDetails += ` which they visualize as: ${part.rows[0].image}`;
        }
      }
    }

    const cacheKey = JSON.stringify({ userId: req.user.userId, userMessage, partDetails });

    // Check cache
    const cachedResponse = cache.get(cacheKey);
    if (cachedResponse) {
      return res.json({ response: cachedResponse });
    }

    // Call DeepSeek API
    const apiResponse = await axios.post(
      'https://api.deepseek.com/v1/chat/completions',
      {
        model: 'deepseek-chat',
        messages: [
          {
            role: 'system',
            content: `You are an AI therapist guiding the user through self-exploration. You specialize in Internal Family Systems therapy. Keep responses concise, friendly, amusing, and supportive. ${partDetails}`
          },
          { role: 'user', content: userMessage }
        ],
        max_tokens: 150,
        temperature: 0.7,
        stream: false
      },
      {
        headers: { 
          Authorization: `Bearer ${process.env.DEEPSEEKAPI}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000 // 10 second timeout
      }
    );

    const fullResponse = apiResponse.data.choices[0]?.message?.content || 'No response';

    // Cache the response
    cache.set(cacheKey, fullResponse);

    res.json({ response: fullResponse });

  } catch (error) {
    console.error('DeepSeek API Error:', error.response ? error.response.data : error.message);
    
    let status = 500;
    let errorMessage = 'Error connecting to DeepSeek API';
    
    if (error.response) {
      status = error.response.status;
      errorMessage = error.response.data.error?.message || errorMessage;
    } else if (error.request) {
      errorMessage = 'No response received from DeepSeek API';
    }
    
    res.status(status).json({ 
      error: errorMessage,
      details: error.response?.data || null
    });
  }
});

// Spotify token endpoint with enhanced error handling
app.get('/spotify-token', async (req, res) => {
  try {
    if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
      return res.status(501).json({ 
        error: 'Spotify integration not configured',
        code: 'SPOTIFY_NOT_CONFIGURED'
      });
    }

    const auth = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
    
    const response = await axios.post(
      'https://accounts.spotify.com/api/token',
      'grant_type=client_credentials',
      {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 5000
      }
    );

    // Cache the token for 1 hour (Spotify tokens typically expire in 1 hour)
    res.set('Cache-Control', 'public, max-age=3600');
    
    res.json({ 
      access_token: response.data.access_token,
      expires_in: response.data.expires_in || 3600
    });

  } catch (error) {
    console.error('Spotify token error:', error.response?.data || error.message);
    
    let status = 500;
    let errorMessage = 'Failed to fetch Spotify token';
    let errorCode = 'SPOTIFY_API_ERROR';
    
    if (error.response) {
      status = error.response.status;
      errorMessage = error.response.data.error_description || errorMessage;
      errorCode = error.response.data.error || errorCode;
    } else if (error.request) {
      errorMessage = 'No response received from Spotify API';
      errorCode = 'SPOTIFY_NO_RESPONSE';
    }
    
    res.status(status).json({ 
      error: errorMessage,
      code: errorCode,
      details: error.response?.data || null
    });
  }
});

// Spotify recommendations endpoint
app.get('/spotify-recommendations', async (req, res) => {
  try {
    const { mood } = req.query;
    
    if (!mood) {
      return res.status(400).json({ 
        error: 'Mood parameter is required',
        code: 'MOOD_REQUIRED'
      });
    }

    // Mood to Spotify parameters mapping
    const moodMap = {
      calm: { valence: 0.8, energy: 0.2 },
      anxious: { valence: 0.2, energy: 0.7 },
      angry: { valence: 0.1, energy: 0.9 },
      joyful: { valence: 0.9, energy: 0.7 },
      tired: { valence: 0.3, energy: 0.2 },
      neutral: { valence: 0.5, energy: 0.5 },
      hopeful: { valence: 0.7, energy: 0.4 }
    };

    const moodData = moodMap[mood];
    if (!moodData) {
      return res.status(400).json({ 
        error: 'Invalid mood parameter',
        code: 'INVALID_MOOD',
        validMoods: Object.keys(moodMap)
      });
    }

    // Get Spotify token
    const tokenRes = await axios.get(`http://${req.headers.host}/spotify-token`);
    const { access_token } = tokenRes.data;

    // Get recommendations
    const params = new URLSearchParams({
      limit: '5',
      seed_genres: 'chill,ambient,classical',
      target_valence: moodData.valence,
      target_energy: moodData.energy
    });

    const recommendationsRes = await axios.get(
      `https://api.spotify.com/v1/recommendations?${params}`,
      {
        headers: {
          'Authorization': `Bearer ${access_token}`
        },
        timeout: 5000
      }
    );

    // Format response
    const tracks = recommendationsRes.data.tracks.map(track => ({
      id: track.id,
      name: track.name,
      artists: track.artists.map(artist => artist.name),
      album: track.album.name,
      image: track.album.images[0]?.url,
      preview_url: track.preview_url,
      external_url: track.external_urls.spotify,
      duration_ms: track.duration_ms
    }));

    res.json({
      mood,
      tracks,
      seed_parameters: {
        target_valence: moodData.valence,
        target_energy: moodData.energy
      }
    });

  } catch (error) {
    console.error('Spotify recommendations error:', error.response?.data || error.message);
    
    let status = 500;
    let errorMessage = 'Failed to get Spotify recommendations';
    let errorCode = 'SPOTIFY_RECOMMENDATIONS_ERROR';
    
    if (error.response) {
      status = error.response.status;
      errorMessage = error.response.data.error?.message || errorMessage;
      errorCode = error.response.data.error || errorCode;
    } else if (error.request) {
      errorMessage = 'No response received from Spotify API';
      errorCode = 'SPOTIFY_NO_RESPONSE';
    }
    
    res.status(status).json({ 
      error: errorMessage,
      code: errorCode,
      details: error.response?.data || null
    });
  }
});

// Health check endpoint with database check
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: {
        database: 'connected',
        deepseek: !!process.env.DEEPSEEKAPI,
        spotify: !!(SPOTIFY_CLIENT_ID && SPOTIFY_CLIENT_SECRET)
      }
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: 'Database connection failed',
      details: error.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ 
    error: 'Internal server error',
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
