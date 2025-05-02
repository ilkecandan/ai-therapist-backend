require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');

// Initialize Express app
const app = express();

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

// Spotify configuration
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;

if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
  console.warn('Spotify credentials not configured - Spotify features will be disabled');
}

// DeepSeek API endpoint
app.post('/api/chat', async (req, res) => {
  try {
    // Validate request
    if (!req.body.message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const userMessage = req.body.message;
    const partDetails = req.body.partDetails ? req.body.partDetails.slice(0, 200) : '';
    const cacheKey = JSON.stringify({ userMessage, partDetails });

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
            content: `You are an AI therapist guiding the user through self-exploration. You specialize in Internal Family Systems therapy. Keep responses concise, friendly, amusing, and supportive. They are working with this part: ${partDetails}`
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

// New Spotify recommendations endpoint
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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    services: {
      deepseek: !!process.env.DEEPSEEKAPI,
      spotify: !!(SPOTIFY_CLIENT_ID && SPOTIFY_CLIENT_SECRET)
    }
  });
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
