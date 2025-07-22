import express from 'express';
import Gun from 'gun';
import http from 'http';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

// Utility function for conditional logging
function debugLog(...args) {
  if (process.env.NODE_ENV !== 'production') {
    console.log(...args);
  }
}

function errorLog(...args) {
  console.error(...args); // Always log errors
}

// JWT Security - Use dedicated key for JWT signing instead of Gun keypairs
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// JWT utility functions
function createJWT(payload) {
  const header = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'HS256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyJWT(token) {
  try {
    const [header, body, signature] = token.split('.');
    const expectedSignature = crypto.createHmac('sha256', JWT_SECRET)
      .update(`${header}.${body}`)
      .digest('base64url');
    
    if (signature !== expectedSignature) {
      return null;
    }
    
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    
    // Check expiration
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return null;
    }
    
    return payload;
  } catch (error) {
    return null;
  }
}

// Rate limiting configuration
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // 50 authentication attempts per window (increased for testing)
  message: {
    error: 'Too many authentication attempts, please try again in 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: {
    error: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Public Gun instance for all functionality (users, OAuth, encrypted sessions)
const gunRelays = process.env.GUN_RELAYS 
  ? process.env.GUN_RELAYS.split(',')
  : [
      'https://gun-manhattan.herokuapp.com/gun',
      'https://gunjs.herokuapp.com/gun', 
      'https://gun-us.herokuapp.com/gun',
      'https://gun-eu.herokuapp.com/gun',
      'https://peer.wallie.io/gun',
      'https://relay.peer.ooo/gun'
    ];

// Create Express app
const app = express();

const server = http.createServer(app);

// Create Gun with local server support
const gun = Gun({
  web: server,
  peers: gunRelays
});

// User-scoped encrypted session sharing via public Gun network
// Sessions encrypted with user credentials, stored using hash-based paths
async function getUserSession(userPub) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      debugLog('User session timeout for pub:', userPub.substring(0, 20) + '...');
      resolve(null);
    }, 10000);
    
    // Create deterministic hash for session lookup (immutable storage)
    const sessionHash = crypto.createHash('sha256')
      .update(`session_${userPub}`)
      .digest('hex')
      .substring(0, 16); // Shorter for efficiency
    
    // Use collection-based immutable storage pattern to prevent enumeration attacks
    gun.get("sessions").get(sessionHash).once((encryptedSession, key) => {
      clearTimeout(timeout);
      
      if (encryptedSession && encryptedSession.exp && Date.now() > encryptedSession.exp) {
        // Mark session as expired rather than deleting (immutable principle)
        debugLog('User session expired');
        gun.get("sessions").get(sessionHash + "_exp").put(Date.now());
        resolve(null);
      } else if (encryptedSession) {
        // Verify data integrity if present
        if (encryptedSession.integrity) {
          const expectedHash = crypto.createHash('sha256')
            .update(JSON.stringify({
              encrypted: encryptedSession.encrypted,
              exp: encryptedSession.exp,
              userPub: encryptedSession.userPub,
              timestamp: encryptedSession.timestamp
            }))
            .digest('hex');
          
          if (encryptedSession.integrity !== expectedHash) {
            debugLog('⚠️ Session integrity check failed');
            resolve(null);
            return;
          }
        }
        
        debugLog('Retrieved encrypted user session');
        resolve(encryptedSession);
      } else {
        // Fallback to legacy storage for backward compatibility
        gun.get('user_sessions').get(userPub).once((legacySession, key) => {
          if (legacySession && legacySession.exp && Date.now() <= legacySession.exp) {
            debugLog('Retrieved session from legacy storage, migrating...');
            // Migrate to immutable storage
            gun.get("sessions").get(sessionHash).put(legacySession);
            resolve(legacySession);
          } else {
            resolve(null);
          }
        });
      }
    });
  });
}

async function setUserSession(userPub, sessionData, userCredentials) {
  try {
    // Derive encryption key from user credentials + pub key
    const encryptionKey = await Gun.SEA.work(
      userCredentials.username + userCredentials.password, 
      userPub
    );
    
    // Encrypt session data
    const encrypted = await Gun.SEA.encrypt(sessionData, encryptionKey);
    
    const secureSessionData = {
      encrypted: encrypted,
      exp: sessionData.exp,
      userPub: userPub,
      timestamp: Date.now(),
      // Add integrity hash to detect tampering
      integrity: crypto.createHash('sha256')
        .update(JSON.stringify({
          encrypted,
          exp: sessionData.exp,
          userPub,
          timestamp: Date.now()
        }))
        .digest('hex')
    };
    
    // Only add domains if they exist and are non-empty
    if (sessionData.domains && sessionData.domains.length > 0) {
      secureSessionData.domains = sessionData.domains.join(','); // Store as comma-separated string
    }
    
    // Create deterministic hash for immutable storage
    const sessionHash = crypto.createHash('sha256')
      .update(`session_${userPub}`)
      .digest('hex')
      .substring(0, 16); // Shorter for efficiency
    
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        console.log('User session set timeout');
        resolve(false);
      }, 5000);
      
    // Use collection-based storage pattern 
    gun.get("sessions").get(sessionHash).put(secureSessionData, (ack) => {
        clearTimeout(timeout);
        if (ack.err) {
          console.error('Failed to store session:', ack.err);
          resolve(false);
        } else {
          debugLog('✅ Session stored with integrity hash');
          // Also store session metadata in separate immutable path
          gun.get("sessions_meta").get(sessionHash).put({
            userPub,
            created: Date.now(),
            version: "1.0"
          });
          resolve(true);
        }
      });
    });
  } catch (error) {
    console.error('Session encryption error:', error);
    return false;
  }
}

async function clearUserSession(userPub) {
  // Create deterministic hash for immutable storage
  const sessionHash = crypto.createHash('sha256')
    .update(`session_${userPub}`)
    .digest('hex')
    .substring(0, 16); // Shorter for efficiency
    
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 10000);
    
    // Instead of deleting data (which breaks immutability), mark as cleared
    gun.get("sessions").get(sessionHash + "_clr").put(Date.now(), (ack) => {
      clearTimeout(timeout);
      if (ack.err) {
        console.error('Failed to clear session:', ack.err);
        resolve(false);
      } else {
        debugLog('User session cleared');
        resolve(true);
      }
    });
  });
}

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Apply general rate limiting to all requests
app.use(generalLimiter);

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

// Input validation middleware (moved before routes for proper initialization)
const validateRegistration = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, hyphens, and underscores'),
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
];

const validateLogin = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Invalid username format'),
  body('password')
    .isLength({ min: 1, max: 128 })
    .withMessage('Password is required')
];

const validateSSO = [
  body('token')
    .notEmpty()
    .withMessage('Token is required'),
  body('pub')
    .notEmpty()
    .withMessage('Public key is required'),
  body('redirect_uri')
    .custom((value) => {
      try {
        const url = new URL(value);
        if (!['http:', 'https:'].includes(url.protocol)) {
          throw new Error('Invalid protocol');
        }
        // Allow localhost and IP addresses for development
        if (url.hostname === 'localhost' || 
            url.hostname.match(/^127\.\d+\.\d+\.\d+$/) || 
            url.hostname.match(/^\d+\.\d+\.\d+\.\d+$/) ||
            url.hostname.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
          return true;
        }
        throw new Error('Invalid hostname');
      } catch (error) {
        throw new Error('Valid redirect URI is required');
      }
    }),
  body('client_id')
    .optional({ nullable: true, checkFalsy: true })
    .isLength({ max: 100 })
    .withMessage('Client ID must be less than 100 characters')
];

// Validation error handler
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation failed for', req.path, '- errors count:', errors.array().length);
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
}

// Serve Gun database over HTTP/WebSocket
app.use(Gun.serve);

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    service: 'GunAuth Identity Provider',
    status: 'running',
    timestamp: Date.now()
  });
});

// Session API endpoints for the session bridge (DEPRECATED - using user-scoped sessions now)
/*
app.get('/api/session', async (req, res) => {
  try {
    console.log('API: Getting session from GUN');
    const session = await getActiveSession('localhost:8000');
    console.log('API: Retrieved session:', session);
    res.json({ session: session || null });
  } catch (error) {
    console.error('API: Session get error:', error);
    res.json({ session: null, error: error.message });
  }
});

// Clear all sessions endpoint for testing
app.delete('/api/sessions/clear', async (req, res) => {
  try {
    console.log('API: Clearing all sessions from GUN');
    await clearActiveSession('localhost:8000');
    console.log('API: All sessions cleared successfully');
    res.json({ success: true, message: 'All sessions cleared' });
  } catch (error) {
    console.error('API: Session clear error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/session', async (req, res) => {
  try {
    console.log('API: Setting session in GUN:', req.body);
    await setActiveSession('localhost:8000', req.body);
    console.log('API: Session set successfully');
    res.json({ success: true });
  } catch (error) {
    console.error('API: Session set error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/session', async (req, res) => {
  try {
    console.log('API: Clearing session from GUN');
    await clearActiveSession('localhost:8000');
    console.log('API: Session cleared successfully');
    res.json({ success: true });
  } catch (error) {
    console.error('API: Session clear error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
*/

// Session bridge endpoint for PostMessage communication
app.get('/session-bridge.html', (req, res) => {
  const bridgeHtml = `<!DOCTYPE html>
<html>
<head>
    <title>GunAuth Session Bridge</title>
    <meta charset="utf-8">
</head>
<body>
    <script>
        // This file should be hosted on your auth domain
        // It handles postMessage communication for cross-domain session sharing
        
        class SessionBridge {
            constructor() {
                window.addEventListener('message', this.handleMessage.bind(this));
                console.log('GunAuth Session Bridge loaded');
            }

            handleMessage(event) {
                // Verify trusted origins
                const trustedOrigins = [
                    'https://app1.example.com',
                    'https://app2.example.com',
                    'http://localhost:8001',
                    'http://localhost:8002'
                ];

                if (!trustedOrigins.some(origin => event.origin.startsWith(origin))) {
                    console.warn('Untrusted origin:', event.origin);
                    return;
                }

                const { type, action, messageId, data } = event.data;

                if (type === 'gunauth-request') {
                    this.handleRequest(event, action, messageId, data);
                }
            }

            async handleRequest(event, action, messageId, data) {
                console.log('Session bridge handling request:', { action, messageId, origin: event.origin });
                try {
                    let result;

                    switch (action) {
                        case 'getSession':
                            result = await this.getSession();
                            break;
                        case 'setSession':
                            result = await this.setSession(data);
                            break;
                        case 'clearSession':
                            result = await this.clearSession();
                            break;
                        case 'verifyToken':
                            console.log('Session bridge calling verifyToken with:', data);
                            result = await this.verifyToken(data);
                            console.log('Session bridge verifyToken completed:', result);
                            break;
                        default:
                            throw new Error(\`Unknown action: \${action}\`);
                    }

                    console.log('Session bridge sending response:', { messageId, result });
                    event.source.postMessage({
                        type: 'gunauth-response',
                        messageId,
                        data: result
                    }, event.origin);

                } catch (error) {
                    console.error('Session bridge error:', { messageId, error: error.message, stack: error.stack });
                    event.source.postMessage({
                        type: 'gunauth-response',
                        messageId,
                        error: error.message
                    }, event.origin);
                }
            }

            async getSession() {
                console.log('Getting session via HTTP endpoint');
                try {
                    const response = await fetch('/api/session');
                    const result = await response.json();
                    console.log('Retrieved session:', result);
                    return result.session;
                } catch (error) {
                    console.error('Failed to get session:', error);
                    return null;
                }
            }

            async setSession(sessionData) {
                console.log('Session bridge setSession called with:', sessionData);
                if (sessionData && sessionData.token && sessionData.pub) {
                    try {
                        const response = await fetch('/api/session', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(sessionData)
                        });
                        const result = await response.json();
                        console.log('Session stored successfully');
                        return result.success;
                    } catch (error) {
                        console.error('Failed to store session:', error);
                        return false;
                    }
                }
                console.log('Failed to set session - invalid data');
                return false;
            }

            async clearSession() {
                console.log('Clearing session via HTTP endpoint');
                try {
                    const response = await fetch('/api/session', {
                        method: 'DELETE'
                    });
                    const result = await response.json();
                    console.log('Session cleared successfully');
                    return result.success;
                } catch (error) {
                    console.error('Failed to clear session:', error);
                    return false;
                }
            }

            async verifyToken(data) {
                console.log('Session bridge verifyToken called with:', data);
                const authServerUrl = window.location.origin;

                try {
                    const response = await fetch(\`\${authServerUrl}/verify\`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });

                    const result = await response.json();
                    console.log('Session bridge verifyToken result:', result);
                    return result;
                } catch (error) {
                    console.error('Session bridge verifyToken error:', error);
                    throw new Error(\`Token verification failed: \${error.message}\`);
                }
            }
        }

        // Initialize the bridge
        new SessionBridge();
    </script>
</body>
</html>`;
  
  res.setHeader('Content-Type', 'text/html');
  res.send(bridgeHtml);
});

// SSO Authorization endpoint - initiates cross-domain login
app.get('/sso/authorize', (req, res) => {
  const { redirect_uri, client_id, state } = req.query;
  
  if (!redirect_uri) {
    return res.status(400).json({ error: 'redirect_uri is required' });
  }
  
  // Create a login form that will handle the authentication
  const loginForm = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>GunAuth - Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .error { color: red; margin-top: 10px; }
            .loading { opacity: 0.7; }
        </style>
    </head>
    <body>
        <h2>Login to GunAuth</h2>
        <form id="loginForm">
            <div class="form-group">
                <input type="text" id="username" placeholder="Username" required>
            </div>
            <div class="form-group">
                <input type="password" id="password" placeholder="Password" required>
            </div>
            <button type="submit" id="submitBtn">Login</button>
            <div id="error" class="error"></div>
        </form>
        
        <script>
            const REDIRECT_URI = ${JSON.stringify(redirect_uri)};
            const CLIENT_ID = ${JSON.stringify(client_id || '')};
            const STATE = ${JSON.stringify(state || '')};
            
            const form = document.getElementById('loginForm');
            const submitBtn = document.getElementById('submitBtn');
            const errorDiv = document.getElementById('error');
            
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                submitBtn.textContent = 'Logging in...';
                submitBtn.disabled = true;
                form.classList.add('loading');
                errorDiv.textContent = '';
                
                try {
                    const response = await fetch('/sso/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const result = await response.json();
                    
 e authorization code and redirect
                        const codeResponse = await fetch('/sso/code', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                token: result.token, 
                                pub: result.pub,
                                redirect_uri: REDIRECT_URI,
                                client_id: CLIENT_ID,
                                state: STATE
                            })
                        });
                        
                        const codeResult = await codeResponse.json();
                        
                        if (codeResult.success) {
                            const params = new URLSearchParams({
                                code: codeResult.code,
                                state: STATE
                            });
                            window.location.href = REDIRECT_URI + '?' + params.toString();
                        } else {
                            throw new Error(codeResult.error);
                        }
                    } else {
                        throw new Error(result.error);
                    }
                } catch (error) {
                    errorDiv.textContent = error.message;
                    submitBtn.textContent = 'Login';
                    submitBtn.disabled = false;
                    form.classList.remove('loading');
                }
            });
        </script>
    </body>
    </html>
  `;
  
  res.send(loginForm);
});

// SSO Login endpoint - handles authentication for SSO flow using Gun SEA properly
app.post('/sso/login', async (req, res) => {
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

    // For SSO flow, create a temporary keypair for token signing
    // This is only used for the SSO token, not stored permanently
    const tempKeyPair = await Gun.SEA.pair();

    // Create token claims
    const now = Math.floor(Date.now() / 1000); // JWT uses seconds
    const issuer = process.env.ISSUER_URL || `${req.protocol}://${req.get('host')}`;
    const tokenClaims = {
      sub: username,
      iss: issuer,
      iat: now,
      exp: now + 3600, // 1 hour expiration (in seconds)
      sso: true, // Mark as SSO token
      pub: tempKeyPair.pub // Include public key for verification
    };

    // Create JWT using dedicated signing key (not Gun keypair)
    const token = createJWT(tokenClaims);

    // Store the session in Gun for cross-domain access
    const sessionData = {
      token,
      pub: tempKeyPair.pub, // Use temp keypair pub for verification
      exp: tokenClaims.exp * 1000, // Convert back to milliseconds for storage
      username: username,
      loginTime: Date.now(),
      sso: true
    };

    debugLog('🔐 Server: SSO session created for user');
    // Note: Not storing SSO sessions server-side - client handles its own session storage

    res.json({
      success: true,
      token,
      pub: tempKeyPair.pub,
      exp: tokenClaims.exp * 1000, // Convert back to milliseconds for client
      username: username
    });

  } catch (error) {
    console.error('SSO Login error:', error);
    res.status(500).json({
      error: 'SSO Login failed'
    });
  }
});

// SSO Code exchange - creates temporary authorization codes
app.post('/sso/code', authLimiter, validateSSO, handleValidationErrors, async (req, res) => {
  try {
    const { token, pub, redirect_uri, client_id, state } = req.body;
    
    if (!token || !pub) {
      console.log('SSO code request missing required fields');
      return res.status(400).json({ error: 'Token and pub are required' });
    }
    
    // Verify the token using JWT verification
    const verifiedClaims = verifyJWT(token);
    if (!verifiedClaims) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Generate a temporary authorization code
    const code = await Gun.SEA.work(JSON.stringify({
      token,
      pub,
      redirect_uri,
      client_id,
      timestamp: Date.now()
    }), 'gunauth-sso-secret-' + Date.now());
    
    // Store the code temporarily (expires in 10 minutes)
    const codeData = {
      token,
      pub,
      username: verifiedClaims.sub, // Extract username from token claims
      redirect_uri,
      client_id,
      state,
      expires: Date.now() + (10 * 60 * 1000) // 10 minutes
    };
    
    gun.get('sso-codes').get(code).put(codeData);
    
    res.json({ success: true, code });
  } catch (error) {
    console.error('SSO code error:', error);
    res.status(500).json({ error: 'Failed to create authorization code' });
  }
});

// SSO Token exchange - exchanges authorization code for token
app.post('/sso/token', async (req, res) => {
  try {
    const { code, client_id } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Authorization code is required' });
    }
    
    // Retrieve the stored code data
    const codeData = await new Promise((resolve) => {
      gun.get('sso-codes').get(code).once((data) => {
        resolve(data);
      });
    });
    
    if (!codeData) {
      return res.status(401).json({ error: 'Invalid authorization code' });
    }
    
    // Check if code has expired
    if (Date.now() > codeData.expires) {
      // Clean up expired code
      gun.get('sso-codes').get(code).put(null);
      return res.status(401).json({ error: 'Authorization code expired' });
    }
    
    // Verify client_id if provided
    if (client_id && codeData.client_id !== client_id) {
      return res.status(401).json({ error: 'Invalid client_id' });
    }
    
    // Clean up the used code
    gun.get('sso-codes').get(code).put(null);
    
    // Return the token data
    res.json({
      success: true,
      token: codeData.token,
      pub: codeData.pub,
      username: codeData.username, // Include username in response
      token_type: 'Bearer'
    });
    
  } catch (error) {
    console.error('SSO token exchange error:', error);
    res.status(500).json({ error: 'Token exchange failed' });
  }
});

// User Registration
app.post('/register', authLimiter, validateRegistration, handleValidationErrors, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required'
      });
    }

    // Check if user already exists - use immutable storage pattern
    const userHash = crypto.createHash('sha256')
      .update(`user_${username}`)
      .digest('hex')
      .substring(0, 16); // Shorter for efficiency
      
    const existingUser = await new Promise((resolve) => {
      // Check both new immutable storage and legacy storage
      gun.get("users").get(userHash).once((data) => {
        if (data) {
          resolve(data);
        } else {
          // Fallback to legacy storage for existing users
          gun.get('users').get(username).once((legacyData) => {
            resolve(legacyData);
          });
        }
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
    
    // Store user data (only public information) with integrity protection
    const userData = {
      username,
      pub: pair.pub,
      hashedPassword,
      createdAt: Date.now(),
      // Add integrity hash to detect tampering
      integrity: crypto.createHash('sha256')
        .update(JSON.stringify({
          username,
          pub: pair.pub,
          hashedPassword,
          createdAt: Date.now()
        }))
        .digest('hex')
    };

    // Store in collection storage
    gun.get("users").get(userHash).put(userData);
    // Also store metadata separately
    gun.get("users_meta").get(userHash).put({
      username,
      created: Date.now(),
      version: "1.0"
    });
    
    // SECURITY: Never store private keys server-side
    // Return the keypair to client for secure client-side storage
    res.status(201).json({
      success: true,
      username,
      pub: pair.pub,
      priv: pair.priv, // Client will store this securely
      createdAt: userData.createdAt
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed'
    });
  }
});

// Login Challenge - Step 1: Request authentication challenge
app.post('/login-challenge', authLimiter, validateLogin, handleValidationErrors, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required'
      });
    }

    // Get user data using immutable storage pattern
    const userHash = crypto.createHash('sha256')
      .update(`user_${username}`)
      .digest('hex')
      .substring(0, 16); // Shorter for efficiency
      
    const userData = await new Promise((resolve) => {
      // Check immutable storage first
      gun.get("users").get(userHash).once((data) => {
        if (data) {
          // Verify data integrity
          const expectedHash = crypto.createHash('sha256')
            .update(JSON.stringify({
              username: data.username,
              pub: data.pub,
              hashedPassword: data.hashedPassword,
              createdAt: data.createdAt
            }))
            .digest('hex');
          
          if (data.integrity === expectedHash) {
            debugLog('✅ User data integrity verified');
            resolve(data);
          } else {
            debugLog('⚠️ User data integrity check failed');
            resolve(null);
          }
        } else {
          // Fallback to legacy storage for existing users
          gun.get('users').get(username).once((legacyData) => {
            if (legacyData) {
              debugLog('📦 Loading user from legacy storage');
            }
            resolve(legacyData);
          });
        }
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

    // Generate challenge for cryptographic proof
    const challenge = crypto.randomBytes(32).toString('hex');
    const challengeId = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 300000; // 5 minutes

    // Store challenge temporarily
    gun.get('auth-challenges').get(challengeId).put({
      challenge,
      username,
      pub: userData.pub,
      expires: expiresAt
    });

    debugLog('🔐 Server: Challenge generated for user:', username);

    res.json({
      success: true,
      challengeId,
      challenge,
      pub: userData.pub
    });

  } catch (error) {
    console.error('Challenge generation error:', error);
    res.status(500).json({
      error: 'Challenge generation failed'
    });
  }
});

// Login Verify - Step 2: Verify cryptographic signature (NO PRIVATE KEYS!)
app.post('/login-verify', authLimiter, async (req, res) => {
  try {
    const { challengeId, signedChallenge } = req.body;

    if (!challengeId || !signedChallenge) {
      return res.status(400).json({
        error: 'Challenge ID and signed challenge are required'
      });
    }

    // Get stored challenge
    const challengeData = await new Promise((resolve) => {
      gun.get('auth-challenges').get(challengeId).once((data) => {
        resolve(data);
      });
    });

    if (!challengeData) {
      return res.status(401).json({
        error: 'Invalid or expired challenge'
      });
    }

    // Check if challenge has expired
    if (Date.now() > challengeData.expires) {
      // Clean up expired challenge
      gun.get('auth-challenges').get(challengeId).put(null);
      return res.status(401).json({
        error: 'Challenge expired'
      });
    }

    // Verify signature using Gun SEA - NO PRIVATE KEY NEEDED!
    const verified = await Gun.SEA.verify(signedChallenge, challengeData.pub);

    if (verified !== challengeData.challenge) {
      return res.status(401).json({
        error: 'Invalid signature'
      });
    }

    // Clean up used challenge
    gun.get('auth-challenges').get(challengeId).put(null);

    // Create token claims with proper JWT structure
    const now = Math.floor(Date.now() / 1000);
    const issuer = process.env.ISSUER_URL || `${req.protocol}://${req.get('host')}`;
    const tokenClaims = {
      sub: challengeData.username,
      iss: issuer,
      iat: now,
      exp: now + 3600, // 1 hour expiration
      pub: challengeData.pub
    };

    // Create JWT using dedicated signing key
    const token = createJWT(tokenClaims);

    // Store the session in Gun for cross-domain access
    const sessionData = {
      token,
      pub: challengeData.pub,
      exp: tokenClaims.exp * 1000,
      username: challengeData.username,
      loginTime: Date.now()
    };

    debugLog('🔐 Server: Storing session in GUN database for user:', challengeData.username);
    await setUserSession(challengeData.pub, sessionData, { username: challengeData.username, password: 'dummy' });
    debugLog('✅ Server: Session stored successfully in GUN database');

    res.json({
      success: true,
      token,
      pub: challengeData.pub,
      exp: tokenClaims.exp * 1000,
      username: challengeData.username
    });

  } catch (error) {
    console.error('Login verification error:', error);
    res.status(500).json({
      error: 'Login verification failed'
    });
  }
});

// Token Verification
app.post('/verify', async (req, res) => {
  try {
    const { token } = req.body; // Only need token now, pub key is embedded

    if (!token) {
      return res.status(400).json({
        error: 'Token is required'
      });
    }

    // Verify the token using JWT verification
    const verifiedClaims = verifyJWT(token);

    if (!verifiedClaims) {
      return res.status(401).json({
        error: 'Invalid or expired token'
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

    // Get user data using immutable storage pattern
    const userHash = crypto.createHash('sha256')
      .update(`user_${username}`)
      .digest('hex')
      .substring(0, 16); // Shorter for efficiency
      
    const userData = await new Promise((resolve) => {
      // Check immutable storage first
      gun.get("users").get(userHash).once((data) => {
        if (data) {
          // Verify data integrity
          const expectedHash = crypto.createHash('sha256')
            .update(JSON.stringify({
              username: data.username,
              pub: data.pub,
              hashedPassword: data.hashedPassword,
              createdAt: data.createdAt
            }))
            .digest('hex');
          
          if (data.integrity === expectedHash) {
            debugLog('✅ User data integrity verified');
            resolve(data);
          } else {
            debugLog('⚠️ User data integrity check failed');
            resolve(null);
          }
        } else {
          // Fallback to legacy storage
          gun.get('users').get(username).once((legacyData) => {
            if (legacyData) {
              debugLog('📦 Loading user from legacy storage');
            }
            resolve(legacyData);
          });
        }
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

// Server setup
const port = process.env.PORT || 8000;

server.listen(port, () => {
  console.log(`GunAuth Identity Provider running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
