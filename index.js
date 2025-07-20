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

// Helper functions for GUN-based session storage
function getActiveSession(domain) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      console.log('GUN getActiveSession timeout for domain:', domain);
      resolve(null);
    }, 5000);
    
    gun.get('sessions').get(domain).once((session, key) => {
      clearTimeout(timeout);
      console.log('GUN getActiveSession result:', { session, key, domain });
      
      if (session && session.exp && Date.now() > session.exp) {
        // Remove expired session
        console.log('Session expired, removing:', session);
        gun.get('sessions').get(domain).put(null);
        resolve(null);
      } else {
        resolve(session);
      }
    });
  });
}

function setActiveSession(domain, sessionData) {
  return new Promise((resolve) => {
    console.log('GUN setActiveSession:', { domain, sessionData });
    const timeout = setTimeout(() => {
      console.log('GUN setActiveSession timeout for domain:', domain);
      resolve(false);
    }, 5000);
    
    gun.get('sessions').get(domain).put(sessionData, (ack) => {
      clearTimeout(timeout);
      console.log('GUN setActiveSession result:', ack);
      resolve(ack);
    });
  });
}

function clearActiveSession(domain) {
  return new Promise((resolve) => {
    console.log('GUN clearActiveSession for domain:', domain);
    const timeout = setTimeout(() => {
      console.log('GUN clearActiveSession timeout for domain:', domain);
      resolve(false);
    }, 5000);
    
    gun.get('sessions').get(domain).put(null, (ack) => {
      clearTimeout(timeout);
      console.log('GUN clearActiveSession result:', ack);
      resolve(ack);
    });
  });
}

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

// Session API endpoints for the session bridge
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
                    
                    if (result.success) {
                        // Create authorization code and redirect
                        const codeResponse = await fetch('/sso/code', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                token: result.token, 
                                pub: result.pub,
                                redirect_uri: '${redirect_uri}',
                                client_id: '${client_id}',
                                state: '${state}'
                            })
                        });
                        
                        const codeResult = await codeResponse.json();
                        
                        if (codeResult.success) {
                            const params = new URLSearchParams({
                                code: codeResult.code,
                                state: '${state || ''}'
                            });
                            window.location.href = '${redirect_uri}?' + params.toString();
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

// SSO Login endpoint - handles authentication for SSO flow
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
    const now = Date.now();
    const issuer = process.env.ISSUER_URL || `${req.protocol}://${req.get('host')}`;
    const tokenClaims = {
      sub: username,
      iss: issuer,
      iat: now,
      exp: now + (3600 * 1000), // 1 hour expiration
      sso: true // Mark as SSO token
    };

    // Sign the token using temporary keypair
    const token = await Gun.SEA.sign(tokenClaims, tempKeyPair);

    // Store the session in Gun for cross-domain access
    const sessionData = {
      token,
      pub: tempKeyPair.pub, // Use temp keypair pub for verification
      exp: tokenClaims.exp,
      username: username,
      loginTime: now,
      sso: true
    };

    console.log('🔐 Server: Storing SSO session in GUN database:', { username, sessionData });
    await setActiveSession('localhost:8000', sessionData);
    console.log('✅ Server: SSO session stored successfully in GUN database');

    res.json({
      success: true,
      token,
      pub: tempKeyPair.pub,
      exp: tokenClaims.exp,
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
app.post('/sso/code', async (req, res) => {
  try {
    const { token, pub, redirect_uri, client_id, state } = req.body;
    
    if (!token || !pub) {
      return res.status(400).json({ error: 'Token and pub are required' });
    }
    
    // Verify the token first
    const verifiedClaims = await Gun.SEA.verify(token, pub);
    if (!verifiedClaims) {
      return res.status(401).json({ error: 'Invalid token' });
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

// User Login
app.post('/login', async (req, res) => {
  try {
    const { username, password, priv } = req.body;

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

    // If private key provided by client, use it; otherwise use challenge-response
    let keyPair;
    if (priv) {
      // Verify the private key matches the stored public key
      const testPair = { pub: userData.pub, priv };
      const testMessage = 'auth-test-' + Date.now();
      const signed = await Gun.SEA.sign(testMessage, testPair);
      const verified = await Gun.SEA.verify(signed, userData.pub);
      
      if (!verified || verified !== testMessage) {
        return res.status(401).json({
          error: 'Invalid private key'
        });
      }
      
      keyPair = testPair;
    } else {
      return res.status(400).json({
        error: 'Private key required for token signing'
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

    // Store the session in Gun for cross-domain access
    const sessionData = {
      token,
      pub: userData.pub,
      exp: tokenClaims.exp,
      username: username,
      loginTime: now
    };

    console.log('🔐 Server: Storing session in GUN database:', { username, sessionData });
    await setActiveSession('localhost:8000', sessionData);
    console.log('✅ Server: Session stored successfully in GUN database');

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
