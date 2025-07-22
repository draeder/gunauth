/**
 * GunAuth Client Library
 * Secure client-side authentication using Gun SEA
 * Handles keypair storage and token management securely
 * Supports encrypted local session sharing across domains
 */

class GunAuthClient {
    constructor(serverUrl = 'http://localhost:8000', enableSessionSharing = true) {
        this.serverUrl = serverUrl.replace(/\/$/, ''); // Remove trailing slash
        this.keyPair = null;
        this.session = null;
        this.enableSessionSharing = enableSessionSharing;
        
        // Initialize TOTP client for session encryption
        this.totp = new TOTPClient();
        
        // Initialize Gun instance for session sharing
        if (this.enableSessionSharing) {
            this.initGun();
        }
        
        // Load existing session on initialization
        this.loadSession();

        // Create Gun.user-like interface integrated with existing SSO/TOTP
        this.user = {
            // Recall user session using existing SSO/TOTP infrastructure
            recall: (options, callback) => {
                if (typeof options === 'function') {
                    callback = options;
                    options = {};
                }
                return this.recallSession(options || {}, callback);
            },
            
            // Create/register new user (Gun.js compatibility)  
            create: (alias, pass, callback) => {
                if (typeof pass === 'function') {
                    callback = pass;
                    pass = alias;
                    alias = pass;
                }
                return this.register(alias, pass).then(result => {
                    if (callback) callback(result.success ? null : new Error(result.error), result);
                    return result;
                });
            },
            
            // Authenticate user using existing login flow
            auth: (alias, pass, callback) => {
                if (typeof pass === 'function') {
                    callback = pass;
                    pass = alias;
                    alias = pass;
                }
                return this.login(alias, pass).then(result => {
                    if (callback) callback(result.success ? null : new Error(result.error), result);
                    return result;
                });
            },
            
            // Check if user is authenticated
            is: () => {
                return this.isAuthenticated() ? this.session : false;
            },
            
            // Get user's public key
            pub: () => {
                return this.keyPair ? this.keyPair.pub : null;
            },
            
            // Leave/logout user
            leave: (callback) => {
                return this.logout().then(result => {
                    if (callback) callback(result ? null : new Error('Logout failed'));
                    return result;
                });
            }
        };
    }

    /**
     * Initialize Gun instance for user session sharing
     */
    initGun() {
        try {
            // Use public Gun relays for encrypted session sharing
            this.gun = Gun([
                'https://gun-manhattan.herokuapp.com/gun',
                'https://gunjs.herokuapp.com/gun',
                'https://gun-us.herokuapp.com/gun',
                'https://gun-eu.herokuapp.com/gun'
            ]);
            console.log('🔗 Gun session sharing initialized');
        } catch (error) {
            console.warn('Gun sharing unavailable:', error.message);
            this.enableSessionSharing = false;
        }
    }

    /**
     * Generate 6-digit session key
     */
    generateSessionKey() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    /**
     * Validate 6-digit key format
     */
    isValidSessionKey(key) {
        return /^\d{6}$/.test(key);
    }

    /**
     * Securely store keypair in browser storage
     * Uses encrypted localStorage with password-derived key
     */
    async storeKeyPair(keyPair, password) {
        try {
            // Derive encryption key from password
            const encryptionKey = await Gun.SEA.work(password, keyPair.pub);
            
            // Encrypt the private key before storage
            const encryptedPriv = await Gun.SEA.encrypt(keyPair.priv, encryptionKey);
            
            const storageData = {
                pub: keyPair.pub,
                encryptedPriv: encryptedPriv,
                timestamp: Date.now()
            };
            
            localStorage.setItem('gunauth_keypair', JSON.stringify(storageData));
            console.log('🔐 Client: KeyPair stored securely');
            
            return true;
        } catch (error) {
            console.error('Failed to store keypair:', error);
            return false;
        }
    }

    /**
     * Load and decrypt keypair from storage
     */
    async loadKeyPair(password) {
        try {
            const stored = localStorage.getItem('gunauth_keypair');
            if (!stored) return null;
            
            const storageData = JSON.parse(stored);
            
            // Derive decryption key from password
            const decryptionKey = await Gun.SEA.work(password, storageData.pub);
            
            // Decrypt the private key
            const decryptedPriv = await Gun.SEA.decrypt(storageData.encryptedPriv, decryptionKey);
            
            if (!decryptedPriv) {
                console.error('Failed to decrypt private key - wrong password?');
                return null;
            }
            
            const keyPair = {
                pub: storageData.pub,
                priv: decryptedPriv
            };
            
            // Verify keypair integrity
            const testMessage = 'integrity-test-' + Date.now();
            const signed = await Gun.SEA.sign(testMessage, keyPair);
            const verified = await Gun.SEA.verify(signed, keyPair.pub);
            
            if (verified !== testMessage) {
                console.error('KeyPair integrity check failed');
                return null;
            }
            
            this.keyPair = keyPair;
            console.log('🔐 Client: KeyPair loaded and verified');
            return keyPair;
            
        } catch (error) {
            console.error('Failed to load keypair:', error);
            return null;
        }
    }

    /**
     * Register a new user
     */
    async register(username, password) {
        try {
            const response = await fetch(`${this.serverUrl}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Store the returned keypair securely
                const keyPair = { pub: result.pub, priv: result.priv };
                await this.storeKeyPair(keyPair, password);
                this.keyPair = keyPair;
                
                console.log('✅ User registered successfully:', username);
                return { success: true, username: result.username, pub: result.pub };
            } else {
                throw new Error(result.error);
            }
            
        } catch (error) {
            console.error('Registration failed:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Login with username and password using proper Gun SEA pattern
     * NO PRIVATE KEYS are transmitted - only cryptographic signatures!
     */
    async login(username, password) {
        try {
            // First load the keypair from storage for local signing
            const keyPair = await this.loadKeyPair(password);
            
            if (!keyPair) {
                throw new Error('No keypair found or wrong password');
            }

            // Step 1: Request authentication challenge
            console.log('🔐 Client: Requesting authentication challenge...');
            const challengeResponse = await fetch(`${this.serverUrl}/login-challenge`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username, 
                    password // Only for password verification, not key transmission
                })
            });
            
            const challengeResult = await challengeResponse.json();
            
            if (!challengeResult.success) {
                throw new Error(challengeResult.error || 'Challenge request failed');
            }

            console.log('✅ Client: Challenge received');

            // Step 2: Sign the challenge locally (PRIVATE KEY NEVER LEAVES CLIENT!)
            console.log('🔐 Client: Signing challenge locally...');
            const signedChallenge = await Gun.SEA.sign(challengeResult.challenge, keyPair);
            
            if (!signedChallenge) {
                throw new Error('Failed to sign challenge');
            }

            // Step 3: Send signature for verification
            console.log('🔐 Client: Sending signature for verification...');
            const verifyResponse = await fetch(`${this.serverUrl}/login-verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    challengeId: challengeResult.challengeId,
                    signedChallenge: signedChallenge
                })
            });
            
            const result = await verifyResponse.json();
            
            if (result.success) {
                this.session = {
                    token: result.token,
                    pub: result.pub,
                    exp: result.exp,
                    username: result.username,
                    loginTime: Date.now()
                };
                
                // Store session securely
                this.storeSession();
                
                // Set up TOTP automatically
                await this.autoSetupTOTP(username, keyPair.priv);
                
                // Share session locally if enabled
                if (this.enableLocalSharing) {
                    try {
                        // Generate 6-digit key for session sharing
                        const sessionKey = this.generateSessionKey();
                        const shareResult = await this.shareSessionLocally(sessionKey);
                        
                        if (shareResult.success) {
                            console.log('🔗 Session shared locally for cross-domain access');
                            // Store the key hint for the user
                            this.sessionKey = sessionKey;
                        } else {
                            console.warn('Local session sharing failed:', shareResult.error);
                        }
                    } catch (error) {
                        console.warn('Local session sharing failed:', error);
                    }
                }
                
                console.log('✅ Login successful using Gun SEA signatures:', username);
                return { 
                    success: true, 
                    session: this.session,
                    sessionKey: this.sessionKey || null 
                };
            } else {
                throw new Error(result.error);
            }
            
        } catch (error) {
            console.error('Login failed:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Store session in localStorage (encrypted)
     */
    async storeSession() {
        if (!this.session || !this.keyPair) return;
        
        try {
            // Encrypt session data with user's public key
            const encryptedSession = await Gun.SEA.encrypt(this.session, this.keyPair.pub);
            localStorage.setItem('gunauth_session', encryptedSession);
        } catch (error) {
            console.error('Failed to store session:', error);
        }
    }

    /**
     * Load session from localStorage
     */
    async loadSession() {
        try {
            const encryptedSession = localStorage.getItem('gunauth_session');
            if (!encryptedSession || !this.keyPair) return null;
            
            const session = await Gun.SEA.decrypt(encryptedSession, this.keyPair.priv);
            
            if (session && session.exp > Date.now()) {
                this.session = session;
                return session;
            } else {
                // Session expired
                this.clearSession();
                return null;
            }
        } catch (error) {
            console.error('Failed to load session:', error);
            return null;
        }
    }

    /**
     * Get current session
     */
    getSession() {
        return this.session;
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return this.session && this.session.exp > Date.now();
    }

    /**
     * Logout - clear all local data
     */
    async logout() {
        try {
            // Clear server-side session
            await fetch(`${this.serverUrl}/api/session`, {
                method: 'DELETE'
            });
            
            this.clearSession();
            console.log('✅ Logged out successfully');
            return true;
            
        } catch (error) {
            console.error('Logout error:', error);
            this.clearSession(); // Clear local session anyway
            return false;
        }
    }

    /**
     * Clear local session data
     */
    clearSession() {
        this.session = null;
        localStorage.removeItem('gunauth_session');
    }

    /**
     * Verify a token
     */
    async verifyToken(token, pub) {
        try {
            const response = await fetch(`${this.serverUrl}/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, pub })
            });
            
            return await response.json();
        } catch (error) {
            console.error('Token verification failed:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get user's public key
     */
    getPublicKey() {
        return this.keyPair ? this.keyPair.pub : null;
    }

    /**
     * Sign data with user's private key
     */
    async sign(data) {
        if (!this.keyPair) {
            throw new Error('No keypair available');
        }
        
        return await Gun.SEA.sign(data, this.keyPair);
    }

    /**
     * Clear all stored data (nuclear option)
     */
    clearAllData() {
        this.keyPair = null;
        this.session = null;
        localStorage.removeItem('gunauth_keypair');
        localStorage.removeItem('gunauth_session');
        console.log('🧹 All client data cleared');
    }

    /**
     * SSO Methods - OAuth2-like flow for cross-domain authentication
     */

    /**
     * Initiate SSO login by redirecting to auth server
     */
    ssoLogin(options = {}) {
        const state = this.generateState();
        const redirectUri = options.redirectUri || window.location.origin + window.location.pathname;
        const clientId = options.clientId || 'gunauth-client';
        
        // Store state and client_id for validation
        localStorage.setItem('gunauth_sso_state', state);
        localStorage.setItem('gunauth_sso_redirect', redirectUri);
        localStorage.setItem('gunauth_sso_client_id', clientId);
        
        const params = new URLSearchParams({
            redirect_uri: redirectUri,
            client_id: clientId,
            state: state
        });
        
        console.log('🔐 Initiating SSO login redirect');
        window.location.href = `${this.serverUrl}/sso/authorize?${params.toString()}`;
    }

    /**
     * Handle SSO callback after authentication
     */
    async handleSSOCallback() {
        try {
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const storedState = localStorage.getItem('gunauth_sso_state');
            const storedClientId = localStorage.getItem('gunauth_sso_client_id');
            
            if (!code) {
                throw new Error('No authorization code received');
            }
            
            if (state !== storedState) {
                throw new Error('Invalid state parameter');
            }
            
            // Exchange code for token
            const response = await fetch(`${this.serverUrl}/sso/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    code: code,
                    client_id: storedClientId || 'gunauth-client'
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Create session from SSO token
                this.session = {
                    token: result.token,
                    pub: result.pub,
                    username: result.username,
                    exp: await this.extractTokenExpiry(result.token, result.pub),
                    loginTime: Date.now(),
                    ssoLogin: true
                };
                
                // Store session
                await this.storeSession();
                
                // Set up TOTP automatically for SSO users (using session token)
                await this.autoSetupTOTPForSSO(result.username, result.token);
                
                // Clean up SSO state
                localStorage.removeItem('gunauth_sso_state');
                localStorage.removeItem('gunauth_sso_redirect');
                localStorage.removeItem('gunauth_sso_client_id');
                
                // Remove query params from URL
                const cleanUrl = window.location.origin + window.location.pathname;
                window.history.replaceState({}, document.title, cleanUrl);
                
                console.log('✅ SSO login successful');
                return { success: true, session: this.session };
            } else {
                throw new Error(result.error || 'Token exchange failed');
            }
            
        } catch (error) {
            console.error('SSO callback failed:', error);
            
            // Clean up on error
            localStorage.removeItem('gunauth_sso_state');
            localStorage.removeItem('gunauth_sso_redirect');
            
            return { success: false, error: error.message };
        }
    }

    /**
     * Get current TOTP code for SSO users
     * @param {string} username - User's username  
     * @param {string} sessionToken - User's session token
     * @returns {Promise<object>} - Current TOTP code
     */
    async getCurrentTOTPForSSO(username, sessionToken) {
        try {
            // Load the existing TOTP secret
            const secret = await this.totp.loadSecret(username, sessionToken);
            if (!secret) {
                return { success: false, error: 'TOTP not configured' };
            }
            
            // Generate current TOTP code
            const code = await this.totp.generateTOTP(secret);
            
            return {
                success: true,
                code: code,
                message: 'Current TOTP code generated'
            };
        } catch (error) {
            console.error('Failed to get current TOTP for SSO user:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Display TOTP QR code for SSO users (already configured)
     * @param {string} username - User's username  
     * @param {string} sessionToken - User's session token
     * @returns {Promise<object>} - Display info with QR code URL
     */
    async displayTOTPForSSO(username, sessionToken) {
        try {
            // Load the existing TOTP secret
            const secret = await this.totp.loadSecret(username, sessionToken);
            if (!secret) {
                // If no secret exists, create one (fallback)
                return await this.autoSetupTOTPForSSO(username, sessionToken);
            }
            
            // Generate QR code URL for existing secret
            const qrURL = this.totp.generateQRCodeURL(secret, username, 'GunAuth');
            
            console.log('🔐 TOTP QR code displayed for SSO user:', username);
            
            return {
                success: true,
                secret: secret,
                qrURL: qrURL,
                manualEntry: `Secret: ${secret}`,
                message: 'TOTP QR code displayed for SSO user'
            };
        } catch (error) {
            console.error('TOTP display failed for SSO user:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Automatically set up TOTP for SSO users using session token
     * @param {string} username - User's username
     * @param {string} sessionToken - User's session token
     * @returns {Promise<object>} - Setup result
     */
    async autoSetupTOTPForSSO(username, sessionToken) {
        try {
            // For SSO users, use session token as key material for deterministic TOTP
            const secret = await this.totp.generateDeterministicSecret(username, sessionToken);
            
            // Check if TOTP is already set up (using session token as password)
            const existingSecret = await this.totp.loadSecret(username, sessionToken);
            if (existingSecret) {
                console.log('🔐 TOTP already configured for SSO user:', username);
                return { success: true, existed: true };
            }
            
            // Store the deterministic secret (using session token as password)
            const stored = await this.totp.storeSecret(username, secret, sessionToken);
            if (!stored) {
                throw new Error('Failed to store TOTP secret for SSO user');
            }
            
            console.log('🔐 TOTP automatically configured for SSO user:', username);
            
            return {
                success: true,
                secret: secret,
                qrURL: this.totp.generateQRCodeURL(secret, username, 'GunAuth'),
                message: 'TOTP automatically configured for SSO login'
            };
        } catch (error) {
            console.error('Auto TOTP setup failed for SSO user:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Automatically set up TOTP for user with deterministic secret
     * @param {string} username - User's username
     * @param {string} privateKey - User's private key
     * @returns {Promise<object>} - Setup result
     */
    async autoSetupTOTP(username, privateKey) {
        try {
            // Generate deterministic secret based on username and private key
            const secret = await this.totp.generateDeterministicSecret(username, privateKey);
            
            // Check if TOTP is already set up for this user
            const existingSecret = await this.totp.loadSecret(username, privateKey);
            if (existingSecret) {
                console.log('🔐 TOTP already configured for user:', username);
                return { success: true, existed: true };
            }
            
            // Store the deterministic secret
            const stored = await this.totp.storeSecret(username, secret, privateKey);
            if (!stored) {
                throw new Error('Failed to store TOTP secret');
            }
            
            console.log('🔐 TOTP automatically configured for user:', username);
            
            return {
                success: true,
                secret: secret,
                qrURL: this.totp.generateQRCodeURL(secret, username, 'GunAuth'),
                message: 'TOTP automatically configured on login'
            };
        } catch (error) {
            console.error('Auto TOTP setup failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Generate and store TOTP secret for user
     * @param {string} username - User's username
     * @param {string} password - User's password
     * @returns {Promise<object>} - Setup info with QR code URL
     */
    async setupTOTP(username, password) {
        try {
            // For deterministic TOTP, we need the private key
            // Try to get it from current session or load from storage
            let privateKey = this.keyPair?.priv;
            
            if (!privateKey) {
                // Try to load the keypair with the provided password
                const keyPair = await this.loadKeyPair(password);
                if (keyPair) {
                    privateKey = keyPair.priv;
                } else {
                    throw new Error('Cannot access private key. Please login first or check password.');
                }
            }
            
            // Generate deterministic TOTP secret
            const secret = await this.totp.generateDeterministicSecret(username, privateKey);
            
            // Store encrypted secret
            const stored = await this.totp.storeSecret(username, secret, password);
            if (!stored) {
                throw new Error('Failed to store TOTP secret');
            }
            
            // Generate QR code URL
            const qrURL = this.totp.generateQRCodeURL(secret, username, 'GunAuth');
            
            console.log('🔐 TOTP setup complete for user:', username);
            
            return {
                success: true,
                secret: secret,
                qrURL: qrURL,
                manualEntry: `Secret: ${secret}`,
                message: 'TOTP setup successful. Scan QR code with authenticator app.'
            };
        } catch (error) {
            console.error('TOTP setup failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Share current session using TOTP-encrypted keys
     * @param {string} username - User's username
     * @param {string} password - User's password
     * @param {string} totpCode - Current 6-digit TOTP code
     * @returns {Promise<object>} - Response with encrypted session info
     */
    async shareSessionWithTOTP(username, password, totpCode) {
        if (!this.enableSessionSharing || !this.gun) {
            return { success: false, error: 'Session sharing not available' };
        }

        if (!this.session) {
            return { success: false, error: 'No active session to share' };
        }

        try {
            // Load TOTP secret
            const totpSecret = await this.totp.loadSecret(username, password);
            if (!totpSecret) {
                return { 
                    success: false, 
                    error: 'TOTP not set up. Please set up TOTP first.' 
                };
            }

            // Verify TOTP code
            const isValidTOTP = await this.totp.verifyTOTP(totpCode, totpSecret);
            if (!isValidTOTP) {
                return { 
                    success: false, 
                    error: 'Invalid TOTP code' 
                };
            }

            // Create session data to share
            const sessionData = {
                token: this.session.token,
                pub: this.session.pub,
                exp: this.session.exp,
                username: this.session.username,
                loginTime: this.session.loginTime,
                keyPair: this.keyPair,
                timestamp: Date.now()
            };

            // Create encryption key using password + TOTP code
            const encryptionSeed = password + totpCode;
            const encryptionKey = await Gun.SEA.work(encryptionSeed, this.session.pub);
            
            // Encrypt session data with TOTP-derived key
            const encryptedSession = await Gun.SEA.encrypt(sessionData, encryptionKey);
            
            // Store encrypted session in Gun network
            const userPath = `totp_sessions.${this.session.pub}`;
            
            return new Promise((resolve) => {
                this.gun.get(userPath).put({
                    encrypted: encryptedSession,
                    timestamp: Date.now(),
                    exp: this.session.exp,
                    username: username
                }, (ack) => {
                    if (ack.err) {
                        console.error('Failed to store TOTP-encrypted session:', ack.err);
                        resolve({ 
                            success: false, 
                            error: 'Failed to store encrypted session' 
                        });
                    } else {
                        console.log('✅ Session encrypted with TOTP and stored');
                        resolve({ 
                            success: true, 
                            message: `Session shared with TOTP encryption. Valid for ${Math.round((this.session.exp - Date.now()) / 1000 / 60)} minutes.`,
                            totpWindow: '30-60 seconds'
                        });
                    }
                });
            });
        } catch (error) {
            console.error('❌ TOTP session sharing failed:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Load shared session using TOTP-encrypted keys
     * @param {string} username - User's username
     * @param {string} password - User's password  
     * @param {string} totpCode - Current 6-digit TOTP code
     * @returns {Promise<object>} - Response with session data if successful
     */
    async loadTOTPSession(username, password, totpCode) {
        if (!this.enableSessionSharing || !this.gun) {
            return { success: false, error: 'Session sharing not available' };
        }

        try {
            // Load TOTP secret
            const totpSecret = await this.totp.loadSecret(username, password);
            if (!totpSecret) {
                return { 
                    success: false, 
                    error: 'TOTP not set up for this user' 
                };
            }

            // Verify TOTP code  
            const isValidTOTP = await this.totp.verifyTOTP(totpCode, totpSecret);
            if (!isValidTOTP) {
                return { 
                    success: false, 
                    error: 'Invalid TOTP code' 
                };
            }

            // Get user's public key for session lookup
            // We need to authenticate first to get pub key
            const authResult = await this.login(username, password);
            if (!authResult.success) {
                return {
                    success: false,
                    error: 'Authentication failed: ' + authResult.error
                };
            }

            const userPub = authResult.pub || this.session?.pub;
            if (!userPub) {
                return {
                    success: false,
                    error: 'Could not determine user public key'
                };
            }

            // Try to decrypt session with current and previous TOTP windows
            const currentTOTP = await this.totp.generateTOTP(totpSecret);
            const previousTOTP = await this.totp.generateTOTP(totpSecret, Date.now() - 30000);
            
            const userPath = `totp_sessions.${userPub}`;
            
            return new Promise((resolve) => {
                this.gun.get(userPath).once(async (encryptedData) => {
                    if (!encryptedData || !encryptedData.encrypted) {
                        resolve({ 
                            success: false, 
                            error: 'No TOTP-encrypted session found' 
                        });
                        return;
                    }

                    // Check if session has expired
                    if (encryptedData.exp && Date.now() > encryptedData.exp) {
                        resolve({ 
                            success: false, 
                            error: 'Shared session expired' 
                        });
                        return;
                    }

                    // Try decrypting with current and previous TOTP codes
                    for (const code of [totpCode, currentTOTP, previousTOTP]) {
                        try {
                            const encryptionSeed = password + code;
                            const decryptionKey = await Gun.SEA.work(encryptionSeed, userPub);
                            
                            const decryptedSession = await Gun.SEA.decrypt(
                                encryptedData.encrypted, 
                                decryptionKey
                            );
                            
                            if (decryptedSession && decryptedSession.token) {
                                // Restore session and keypair
                                this.session = {
                                    token: decryptedSession.token,
                                    pub: decryptedSession.pub,
                                    exp: decryptedSession.exp,
                                    username: decryptedSession.username,
                                    loginTime: decryptedSession.loginTime
                                };
                                this.keyPair = decryptedSession.keyPair;
                                
                                // Store locally
                                this.saveSession();
                                
                                console.log('✅ TOTP-encrypted session loaded for user:', decryptedSession.username);
                                
                                resolve({ 
                                    success: true, 
                                    session: this.session,
                                    message: `TOTP session loaded for ${decryptedSession.username}`,
                                    decryptedWith: code === totpCode ? 'provided' : 'generated'
                                });
                                return;
                            }
                        } catch (decryptError) {
                            // Try next code
                            continue;
                        }
                    }
                    
                    // If we get here, decryption failed with all codes
                    resolve({ 
                        success: false, 
                        error: 'Failed to decrypt session. Check TOTP code and timing.' 
                    });
                });

                // Timeout after 5 seconds
                setTimeout(() => {
                    resolve({ 
                        success: false, 
                        error: 'Session lookup timeout' 
                    });
                }, 5000);
            });
        } catch (error) {
            console.error('❌ Failed to load TOTP session:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Clear TOTP-encrypted session
     * @param {string} username - User's username
     * @param {string} password - User's password
     * @param {string} totpCode - Current 6-digit TOTP code
     * @returns {Promise<object>} - Response indicating success
     */
    async clearTOTPSession(username, password, totpCode) {
        if (!this.enableSessionSharing || !this.gun) {
            return { success: false, error: 'Session sharing not available' };
        }

        try {
            // Load TOTP secret and verify
            const totpSecret = await this.totp.loadSecret(username, password);
            if (!totpSecret) {
                return { success: false, error: 'TOTP not set up' };
            }

            const isValidTOTP = await this.totp.verifyTOTP(totpCode, totpSecret);
            if (!isValidTOTP) {
                return { success: false, error: 'Invalid TOTP code' };
            }

            // Get user's public key
            const userPub = this.session?.pub;
            if (!userPub) {
                return { success: false, error: 'No active session to determine user' };
            }

            const userPath = `totp_sessions.${userPub}`;
            
            return new Promise((resolve) => {
                this.gun.get(userPath).put(null, (ack) => {
                    if (ack.err) {
                        resolve({ success: false, error: ack.err });
                    } else {
                        console.log('✅ TOTP-encrypted session cleared');
                        resolve({ 
                            success: true, 
                            message: 'TOTP-encrypted session cleared' 
                        });
                    }
                });
            });
        } catch (error) {
            console.error('❌ Failed to clear TOTP session:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Check if current page is an SSO callback
     */
    isSSOCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.has('code') && urlParams.has('state');
    }

    /**
     * Extract token expiry from token claims
     */
    async extractTokenExpiry(token, pub) {
        try {
            const verified = await Gun.SEA.verify(token, pub);
            return verified && verified.exp ? verified.exp : Date.now() + (3600 * 1000);
        } catch (error) {
            console.error('Failed to extract token expiry:', error);
            return Date.now() + (3600 * 1000); // Default 1 hour
        }
    }

    /**
     * Generate random state for CSRF protection
     */
    generateState() {
        return Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Integrated recall using existing SSO/TOTP infrastructure
     * Leverages the existing cross-domain session sharing and TOTP systems
     */
    async recallSession(options = {}, callback = null) {
        try {
            console.log('🔄 Recalling user session using existing infrastructure...');

            // 1. Check if we already have an active session
            if (this.isAuthenticated()) {
                const result = { success: true, session: this.session, source: 'active_session' };
                if (callback) callback(null, result);
                return result;
            }

            // 2. Try to load existing session from localStorage
            const storedSession = await this.loadSession();
            if (storedSession) {
                console.log('✅ Session recalled from storage');
                const result = { success: true, session: this.session, source: 'stored_session' };
                if (callback) callback(null, result);
                return result;
            }

            // 3. Check if this is an SSO callback
            if (this.isSSOCallback()) {
                console.log('� Handling SSO callback for recall...');
                const ssoResult = await this.handleSSOCallback();
                if (ssoResult.success) {
                    const result = { success: true, session: this.session, source: 'sso_callback' };
                    if (callback) callback(null, result);
                    return result;
                }
            }

            // 4. Try TOTP-based cross-domain recall if enabled
            if (this.enableSessionSharing && this.gun && options.username && options.totpCode) {
                console.log('🔐 Attempting TOTP cross-domain recall...');
                const totpResult = await this.loadTOTPSession(options.username, options.password || '', options.totpCode);
                if (totpResult.success) {
                    console.log('✅ Session recalled via TOTP');
                    const result = { success: true, session: this.session, source: 'totp_session' };
                    if (callback) callback(null, result);
                    return result;
                }
            }

            // 5. If password provided, try to restore from keypair
            if (options.password && options.username) {
                console.log('🔐 Attempting login-based recall...');
                const loginResult = await this.login(options.username, options.password);
                if (loginResult.success) {
                    const result = { success: true, session: this.session, source: 'login_recall' };
                    if (callback) callback(null, result);
                    return result;
                }
            }

            // No recall possible
            const result = { 
                success: false, 
                error: 'No session to recall. Try SSO login or provide credentials.',
                availableOptions: {
                    sso: 'Use ssoLogin() for OAuth flow',
                    totp: 'Provide username, password, and totpCode',
                    login: 'Provide username and password'
                }
            };
            
            if (callback) callback(new Error(result.error), null);
            return result;

        } catch (error) {
            console.error('❌ Recall failed:', error);
            const result = { success: false, error: error.message };
            if (callback) callback(error, null);
            return result;
        }
    }
}

// Export for use in browser or Node.js
if (typeof window !== 'undefined') {
    window.GunAuthClient = GunAuthClient;
} else if (typeof module !== 'undefined' && module.exports) {
    module.exports = GunAuthClient;
    module.exports.default = GunAuthClient;
}
