import express from 'express';
import Gun from 'gun';

const app = express();
const port = process.env.PORT || 3000;

// Initialize Gun with multiple reliable relay peers
const gunRelays = process.env.GUN_RELAYS 
  ? process.env.GUN_RELAYS.split(',')
  : [
      'https://gun-manhattan.herokuapp.com/gun',
      'https://gunjs.herokuapp.com/gun',
      'https://gun-us.herokuapp.com/gun',
      'https://gun-eu.herokuapp.com/gun',
      'https://peer.wallie.io/gun',
      'https://relay.peer.ooo/gun',
      'wss://gun-manhattan.herokuapp.com/gun',
      'wss://gunjs.herokuapp.com/gun',
      'wss://relay.peer.ooo/gun'
    ];

const gun = Gun(gunRelays);

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS for browser requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    service: 'GunAuth Identity Provider',
    status: 'running',
    timestamp: Date.now()
  });
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required'
      });
    }

    // Check if user already exists
    const existingUser = await new Promise((resolve) => {
      gun.get('users').get(username).once((data) => {
        resolve(data);
      });
    });

    if (existingUser) {
      return res.status(409).json({
        error: 'User already exists'
      });
    }

    // Generate SEA key pair
    const pair = await Gun.SEA.pair();
    
    // Hash the password using SEA.work
    const hashedPassword = await Gun.SEA.work(password, pair.pub);
    
    // Store user data (only public information)
    const userData = {
      pub: pair.pub,
      hashedPassword,
      createdAt: Date.now()
    };

    // Store in Gun database
    gun.get('users').get(username).put(userData);
    
    // Store the key pair privately for this user session
    // In a real implementation, you'd want to encrypt this properly
    gun.get('keys').get(pair.pub).put(pair);

    res.status(201).json({
      success: true,
      username,
      pub: pair.pub,
      createdAt: userData.createdAt
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed'
    });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required'
      });
    }

    // Get user data
    const userData = await new Promise((resolve) => {
      gun.get('users').get(username).once((data) => {
        resolve(data);
      });
    });

    if (!userData || !userData.pub) {
      return res.status(401).json({
        error: 'Invalid credentials'
      });
    }

    // Verify password by hashing with the user's public key
    const hashedPassword = await Gun.SEA.work(password, userData.pub);
    
    if (hashedPassword !== userData.hashedPassword) {
      return res.status(401).json({
        error: 'Invalid credentials'
      });
    }

    // Get the user's key pair
    const keyPair = await new Promise((resolve) => {
      gun.get('keys').get(userData.pub).once((data) => {
        resolve(data);
      });
    });

    if (!keyPair || !keyPair.priv) {
      return res.status(500).json({
        error: 'Key pair not found'
      });
    }

    // Create token claims
    const now = Date.now();
    const issuer = process.env.ISSUER_URL || `${req.protocol}://${req.get('host')}`;
    const tokenClaims = {
      sub: username,
      iss: issuer,
      iat: now,
      exp: now + (3600 * 1000) // 1 hour expiration
    };

    // Sign the token using the user's private key
    const token = await Gun.SEA.sign(tokenClaims, keyPair);

    res.json({
      success: true,
      token,
      pub: userData.pub,
      exp: tokenClaims.exp
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed'
    });
  }
});

// Token Verification
app.post('/verify', async (req, res) => {
  try {
    const { token, pub } = req.body;

    if (!token || !pub) {
      return res.status(400).json({
        error: 'Token and public key are required'
      });
    }

    // Verify the token using the public key
    const verifiedClaims = await Gun.SEA.verify(token, pub);

    if (!verifiedClaims) {
      return res.status(401).json({
        error: 'Invalid token'
      });
    }

    // Check if token has expired
    const now = Date.now();
    if (verifiedClaims.exp && now > verifiedClaims.exp) {
      return res.status(401).json({
        error: 'Token expired'
      });
    }

    res.json({
      success: true,
      claims: verifiedClaims,
      valid: true
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({
      error: 'Token verification failed'
    });
  }
});

// Get user public key by username (utility endpoint)
app.get('/user/:username/pub', async (req, res) => {
  try {
    const { username } = req.params;

    const userData = await new Promise((resolve) => {
      gun.get('users').get(username).once((data) => {
        resolve(data);
      });
    });

    if (!userData || !userData.pub) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      username,
      pub: userData.pub,
      createdAt: userData.createdAt
    });

  } catch (error) {
    console.error('User lookup error:', error);
    res.status(500).json({
      error: 'User lookup failed'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found'
  });
});

app.listen(port, () => {
  console.log(`GunAuth Identity Provider running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
