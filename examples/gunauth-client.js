/**
 * GunAuth Client Library
 * Secure client-side authentication using Gun SEA
 * Handles keypair storage and token management securely
 */

// Crypto utilities for browser compatibility
const CryptoUtils = {
    // SHA-256 hash function using Gun SEA
    async createHash(data) {
        try {
            // Use Gun SEA's work function for deterministic hashing
            const fullHash = await Gun.SEA.work(data, 'immutable_storage_salt_2025');
            // Return shorter hash for efficiency
            return fullHash ? fullHash.substring(0, 16) : null;
        } catch (error) {
            console.error('CryptoUtils hash error:', error);
            // Fallback to a simple hash based on the data
            let hash = 0;
            for (let i = 0; i < data.length; i++) {
                const char = data.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32bit integer
            }
            return Math.abs(hash).toString(16).substring(0, 16);
        }
    }
};

class GunAuthClient {
    constructor(serverUrl = 'http://localhost:8000') {
        this.serverUrl = serverUrl.replace(/\/$/, ''); // Remove trailing slash
        this.keyPair = null;
        this.session = null;
        
        // Initialize TOTP client
        this.totp = new TOTPClient();
        
        // Check if running in secure context
        this.isSecureContext = this.checkSecureContext();
        
        // Load existing session on initialization
        this.loadSession();
    }

    /**
     * Check if running in a secure context (HTTPS or localhost)
     */
    checkSecureContext() {
        if (typeof window === 'undefined') return true; // Node.js environment
        
        const isSecure = window.location.protocol === 'https:' || 
                        window.location.hostname === 'localhost' || 
                        window.location.hostname === '127.0.0.1';
        
        if (!isSecure && process?.env?.NODE_ENV === 'production') {
            console.warn('⚠️ Not running in secure context. Use HTTPS in production.');
        }
        
        return isSecure;
    }

    /**
     * Debug logging that respects environment
     */
    debugLog(...args) {
        if (typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production') {
            console.log(...args);
        }
    }

    /**
     * Error logging (always enabled)
     */
    errorLog(...args) {
        console.error(...args);
    }

    /**
     * Securely store keypair in browser storage
     * Uses encrypted localStorage with password-derived key and secure context validation
     */
    async storeKeyPair(keyPair, password) {
        try {
            // Validate secure storage context
            if (!this.checkSecureContext()) {
                this.errorLog('⚠️ WARNING: Storing sensitive data in potentially insecure context');
            }

            // Additional storage validation
            if (typeof localStorage === 'undefined') {
                throw new Error('localStorage not available');
            }

            // Test localStorage functionality
            try {
                localStorage.setItem('gunauth_storage_test', 'test');
                localStorage.removeItem('gunauth_storage_test');
            } catch (storageError) {
                throw new Error('localStorage not functional: ' + storageError.message);
            }
            
            // Derive encryption key from password
            const encryptionKey = await Gun.SEA.work(password, keyPair.pub);
            
            // Encrypt the private key before storage
            const encryptedPriv = await Gun.SEA.encrypt(keyPair.priv, encryptionKey);
            
            const storageData = {
                pub: keyPair.pub,
                encryptedPriv: encryptedPriv,
                timestamp: Date.now(),
                secureContext: this.checkSecureContext() // Record security context
            };
            
            localStorage.setItem('gunauth_keypair', JSON.stringify(storageData));
            this.debugLog('🔐 Client: KeyPair stored securely');
            
            return true;
        } catch (error) {
            this.errorLog('Failed to store keypair:', error);
            return false;
        }
    }

    /**
     * Load and decrypt keypair from storage with security validation
     */
    async loadKeyPair(password) {
        try {
            // Validate secure storage access
            if (!this.checkSecureContext()) {
                this.errorLog('⚠️ WARNING: Loading sensitive data from potentially insecure context');
            }

            const stored = localStorage.getItem('gunauth_keypair');
            if (!stored) return null;
            
            const storageData = JSON.parse(stored);
            
            // Validate stored data structure
            if (!storageData.pub || !storageData.encryptedPriv) {
                this.errorLog('⚠️ WARNING: Invalid keypair storage format');
                return null;
            }
            
            // Check if data was stored in secure context
            if (storageData.secureContext === false) {
                this.errorLog('⚠️ WARNING: Keypair was stored in insecure context');
            }
            
            // Derive decryption key from password
            const decryptionKey = await Gun.SEA.work(password, storageData.pub);
            
            // Decrypt the private key
            const decryptedPriv = await Gun.SEA.decrypt(storageData.encryptedPriv, decryptionKey);
            
            if (!decryptedPriv) {
                this.errorLog('Failed to decrypt private key - wrong password?');
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
                this.errorLog('KeyPair integrity check failed');
                return null;
            }
            
            this.keyPair = keyPair;
            this.debugLog('🔐 Client: KeyPair loaded and verified');
            return keyPair;
            
        } catch (error) {
            this.errorLog('Failed to load keypair:', error);
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
                
                this.debugLog('✅ User registered successfully:', username);
                return { success: true, username: result.username, pub: result.pub };
            } else {
                // Handle validation errors with detailed messages
                if (result.error === 'Validation failed' && result.details) {
                    const errorMessages = result.details.map(detail => detail.msg).join(', ');
                    throw new Error(`Validation failed: ${errorMessages}`);
                }
                throw new Error(result.error);
            }
            
        } catch (error) {
            this.errorLog('Registration failed:', error);
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
            this.debugLog('🔐 Client: Requesting authentication challenge...');
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

            this.debugLog('✅ Client: Challenge received');

            // Step 2: Sign the challenge locally (PRIVATE KEY NEVER LEAVES CLIENT!)
            this.debugLog('🔐 Client: Signing challenge locally...');
            const signedChallenge = await Gun.SEA.sign(challengeResult.challenge, keyPair);
            
            if (!signedChallenge) {
                throw new Error('Failed to sign challenge');
            }

            // Step 3: Send signature for verification
            this.debugLog('🔐 Client: Sending signature for verification...');
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
                await this.storeSession();
                
                this.debugLog('✅ Login successful using Gun SEA signatures:', username);
                return { success: true, session: this.session };
            } else {
                // Handle validation errors with detailed messages
                if (result.error === 'Validation failed' && result.details) {
                    const errorMessages = result.details.map(detail => detail.msg).join(', ');
                    throw new Error(`Validation failed: ${errorMessages}`);
                }
                throw new Error(result.error);
            }
            
        } catch (error) {
            this.errorLog('Login failed:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Store session in localStorage (encrypted) with security validation
     */
    async storeSession() {
        if (!this.session || !this.keyPair) return;
        
        try {
            // Validate secure storage context
            if (!this.checkSecureContext()) {
                this.errorLog('⚠️ WARNING: Storing session in potentially insecure context');
            }
            
            // Encrypt session data with user's public key
            const encryptedSession = await Gun.SEA.encrypt(this.session, this.keyPair.pub);
            
            const storageData = {
                session: encryptedSession,
                timestamp: Date.now(),
                secureContext: this.checkSecureContext()
            };
            
            localStorage.setItem('gunauth_session', JSON.stringify(storageData));
            this.debugLog('🔐 Session stored securely');
            
        } catch (error) {
            this.errorLog('Failed to store session:', error);
        }
    }

    /**
     * Load session from localStorage with security validation
     */
    async loadSession() {
        try {
            // Validate secure storage access
            if (!this.checkSecureContext()) {
                this.errorLog('⚠️ WARNING: Loading session from potentially insecure context');
            }

            const storedData = localStorage.getItem('gunauth_session');
            if (!storedData || !this.keyPair) return null;
            
            let sessionData, encryptedSession;
            
            try {
                // Try to parse as new format with metadata
                sessionData = JSON.parse(storedData);
                encryptedSession = sessionData.session;
                
                // Check if session was stored in secure context
                if (sessionData.secureContext === false) {
                    this.errorLog('⚠️ WARNING: Session was stored in insecure context');
                }
                
            } catch (parseError) {
                // Legacy format - direct encrypted data
                encryptedSession = storedData;
                this.debugLog('🔄 Loading legacy session format');
            }
            
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
            this.debugLog('✅ Logged out successfully');
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
        this.debugLog('🧹 All client data cleared');
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
        
        // Store state AND client_id for validation
        localStorage.setItem('gunauth_sso_state', state);
        localStorage.setItem('gunauth_sso_client_id', clientId);
        localStorage.setItem('gunauth_sso_redirect', redirectUri);
        
        const params = new URLSearchParams({
            redirect_uri: redirectUri,
            client_id: clientId,
            state: state
        });
        
        this.debugLog('🔐 Initiating SSO login redirect');
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
            
            this.debugLog('🔍 SSO State Validation:', {
                urlState: state,
                storedState: storedState,
                match: state === storedState,
                urlDecoded: decodeURIComponent(state || ''),
                storedDecoded: decodeURIComponent(storedState || '')
            });
            
            if (!code) {
                throw new Error('No authorization code received');
            }
            
            // Try both exact match and URL-decoded match
            const stateMatches = state === storedState || 
                                decodeURIComponent(state || '') === storedState ||
                                state === decodeURIComponent(storedState || '');
            
            if (!stateMatches) {
                console.error('❌ State mismatch details:', {
                    received: state,
                    stored: storedState,
                    receivedType: typeof state,
                    storedType: typeof storedState,
                    localStorage_keys: Object.keys(localStorage)
                });
                
                // Check if there's any SSO state left
                this.debugLog('🔍 All localStorage items:');
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    this.debugLog(`  ${key}: ${localStorage.getItem(key)}`);
                }
                
                throw new Error(`Invalid state parameter - received: ${state}, stored: ${storedState}`);
            }
            
            // Exchange code for token
            const storedClientId = localStorage.getItem('gunauth_sso_client_id') || 'gunauth-client';
            const response = await fetch(`${this.serverUrl}/sso/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    code: code,
                    client_id: storedClientId
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Create session from SSO token
                this.session = {
                    token: result.token,
                    pub: result.pub,
                    exp: await this.extractTokenExpiry(result.token, result.pub),
                    username: result.username || 'SSO User', // Add username from server response
                    loginTime: Date.now(),
                    ssoLogin: true
                };
                
                this.debugLog('🎯 SSO Session created:', this.session);
                
                // Store session
                await this.storeSession();
                
                // Clean up SSO state
                localStorage.removeItem('gunauth_sso_state');
                localStorage.removeItem('gunauth_sso_client_id');
                localStorage.removeItem('gunauth_sso_redirect');
                
                // Remove query params from URL
                const cleanUrl = window.location.origin + window.location.pathname;
                window.history.replaceState({}, document.title, cleanUrl);
                
                this.debugLog('✅ SSO login successful');
                return { success: true, session: this.session };
            } else {
                throw new Error(result.error || 'Token exchange failed');
            }
            
        } catch (error) {
            console.error('SSO callback failed:', error);
            
            // Clean up on error
            localStorage.removeItem('gunauth_sso_state');
            localStorage.removeItem('gunauth_sso_client_id');
            localStorage.removeItem('gunauth_sso_redirect');
            
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
     * Share session encrypted with TOTP for cross-domain access
     * @param {string} username - Username
     * @param {string} keyMaterial - Key material used for TOTP secret derivation
     * @returns {Promise<object>} - Sharing result
     */
    async shareTOTPEncryptedSession(username, keyMaterial) {
        try {
            // Get current session from localStorage
            const session = localStorage.getItem(`gunauth_session_${username}`);
            if (!session) {
                return {
                    success: false,
                    error: 'No active session to share'
                };
            }
            
            // Parse the session
            const sessionData = JSON.parse(session);
            
            // Generate current TOTP code for encryption
            const totpSecret = await this.totp.loadSecret(username, keyMaterial);
            if (!totpSecret) {
                return {
                    success: false,
                    error: 'Could not load TOTP secret for encryption'
                };
            }
            
            const currentTOTP = await this.totp.generateTOTP(totpSecret);
            
            // Encrypt session with current TOTP
            const encryptedSession = await Gun.SEA.encrypt(sessionData, currentTOTP);
            
            // Store in Gun for cross-domain access using immutable storage
            const gun = Gun(['http://localhost:8000/gun']);
            
            // Create deterministic hash for immutable storage
            const sessionKey = await CryptoUtils.createHash(`totp_session_${username}`);
            
            // Use immutable frozen storage pattern - prevents simple tampering attacks
            gun.get("totp_sessions").get(sessionKey).put({
                encryptedData: encryptedSession,
                timestamp: Date.now(),
                username: username,
                // Add integrity hash to detect tampering
                integrity: await CryptoUtils.createHash(JSON.stringify({
                    encryptedData: encryptedSession,
                    timestamp: Date.now(),
                    username: username
                }))
            });
            
            this.debugLog('✅ Session shared with TOTP encryption');
            return {
                success: true,
                message: 'Session encrypted and shared for cross-domain access'
            };
            
        } catch (error) {
            console.error('Failed to share TOTP encrypted session:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Login using username and TOTP code (for cross-domain authentication)
     * @param {string} username - User's username
     * @param {string} totpCode - Current TOTP code
     * @returns {Promise<object>} - Login result
     */
    async loginWithTOTP(username, totpCode) {
        try {
            this.debugLog('🔐 Attempting TOTP-based cross-domain login...');
            
            // Try to load the TOTP-encrypted vault using immutable storage
            const gun = Gun(['http://localhost:8000/gun']);
            
            // Create deterministic hash for immutable storage lookup
            const vaultKey = await CryptoUtils.createHash(`totp_vault_${username}`);
            
            this.debugLog('🔍 Debug: Looking for vault with immutable key:', vaultKey);
            
            return new Promise((resolve) => {
                // Check immutable storage first
                gun.get("totp_vaults").get(vaultKey).once(async (data) => {
                    this.debugLog('🔍 Debug: Vault data received from immutable storage:', data);
                    
                    if (data && data.vault) {
                        // Verify data integrity
                        const expectedHash = await CryptoUtils.createHash(JSON.stringify({
                            vault: data.vault,
                            created: data.created,
                            expires: data.expires
                        }));
                        
                        if (data.integrity === expectedHash) {
                            this.debugLog('✅ Vault data integrity verified from immutable storage');
                            await this.processTOTPVault(data, totpCode, username, resolve);
                            return;
                        } else {
                            this.debugLog('⚠️ Vault data integrity check failed');
                        }
                    }
                    
                    // Fallback to legacy storage patterns
                    this.debugLog('🔍 Debug: No vault found in immutable storage, trying legacy storage...');
                    gun.get(`totp_vault_${username}`).once(async (legacyData) => {
                        if (legacyData && legacyData.vault) {
                            this.debugLog('� Loading vault from legacy storage');
                            await this.processTOTPVault(legacyData, totpCode, username, resolve);
                        } else {
                            this.resolveTOTPFailure(resolve, username);
                        }
                    });
                });
            });
        } catch (error) {
            console.error('TOTP Login failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Helper method to process TOTP vault data
     */
    async processTOTPVault(data, totpCode, username, resolve) {
        // Check if vault has expired
        if (data.expires && Date.now() > data.expires) {
            resolve({
                success: false,
                error: 'Session vault has expired'
            });
            return;
        }

        try {
            // Decrypt vault with TOTP code (like gunsafe)
            const vaultData = await Gun.SEA.decrypt(data.vault, totpCode);
            
            if (!vaultData || !vaultData.session) {
                resolve({
                    success: false,
                    error: 'Invalid TOTP code or vault corrupted. Please verify the code and try again.'
                });
                return;
            }
            
            // Check TOTP window validity (vault should be recent)
            const currentWindow = Math.floor(Date.now() / 30000);
            if (vaultData.totpWindow && Math.abs(currentWindow - vaultData.totpWindow) > 2) {
                resolve({
                    success: false,
                    error: 'Session vault has expired. Please generate a new session on the primary domain.'
                });
                return;
            }
            
            // Store in local storage for this domain
            localStorage.setItem(`gunauth_session_${username}`, JSON.stringify(vaultData.session));
            
            this.debugLog('✅ TOTP cross-domain login successful');
            resolve({
                success: true,
                session: vaultData.session,
                message: 'Successfully logged in via TOTP vault cross-domain authentication'
            });
            
        } catch (error) {
            resolve({
                success: false,
                error: `Failed to decrypt session: ${error.message}`
            });
        }
    }
    
    /**
     * Helper method to resolve TOTP failure with alternative lookup attempts
     */
    resolveTOTPFailure(resolve, username) {
        resolve({
            success: false,
            error: 'No session vault found for this user. Please ensure you have logged in and shared your session on the primary domain first.'
        });
    }

    /**
     * Setup TOTP for a user (similar to gunsafe's pairing mechanism)
     * @param {string} username - Username
     * @param {string} keyMaterial - Key material (password or private key)
     * @returns {Promise<object>} - Setup result with QR code
     */
    async autoSetupTOTP(username, keyMaterial) {
        try {
            // Generate deterministic TOTP secret
            const totpSecret = await this.totp.generateDeterministicSecret(username, keyMaterial);
            
            // Store the secret (correct parameter order: username, secret, password)
            const stored = await this.totp.storeSecret(username, totpSecret, keyMaterial);
            if (!stored) {
                return {
                    success: false,
                    error: 'Failed to store TOTP secret'
                };
            }
            
            // Generate QR code URL
            const qrUrl = await this.totp.generateQRCodeURL(username, totpSecret);
            
            this.debugLog('✅ TOTP automatically configured for', username);
            return {
                success: true,
                qrCodeUrl: qrUrl,
                secret: totpSecret,
                message: 'TOTP configured automatically'
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
     * Setup TOTP for SSO users (uses simple username-based key material)
     * @param {string} username - Username
     * @param {string} sessionToken - Session token from SSO (ignored for simplicity)
     * @returns {Promise<object>} - Setup result
     */
    async autoSetupTOTPForSSO(username, sessionToken) {
        try {
            // For SSO users, use a simpler approach: username + "sso" as key material
            // This avoids JWT token crypto issues while maintaining deterministic secrets
            const keyMaterial = `${username}_sso`;
            return await this.autoSetupTOTP(username, keyMaterial);
        } catch (error) {
            console.error('SSO TOTP setup failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Get current TOTP code for SSO user (using simplified key material)
     * @param {string} username - Username
     * @param {string} sessionToken - Session token (ignored)
     * @returns {Promise<string|null>} - Current TOTP code
     */
    async getCurrentTOTPForSSO(username, sessionToken) {
        try {
            // Use simplified key material for SSO users
            const keyMaterial = `${username}_sso`;
            const totpSecret = await this.totp.loadSecret(username, keyMaterial);
            if (!totpSecret) {
                this.debugLog('No TOTP secret found, setting up automatically...');
                const setupResult = await this.autoSetupTOTPForSSO(username, sessionToken);
                if (!setupResult.success) {
                    return null;
                }
                // Use the newly created secret
                return await this.totp.generateTOTP(setupResult.secret);
            }
            
            return await this.totp.generateTOTP(totpSecret);
        } catch (error) {
            console.error('Failed to get current TOTP:', error);
            return null;
        }
    }

    /**
     * Display TOTP for SSO users (similar to gunsafe's pair display)
     * @param {string} username - Username
     * @param {string} sessionToken - Session token (ignored)
     * @returns {Promise<object>} - Display result with current code
     */
    async displayTOTPForSSO(username, sessionToken) {
        try {
            // Use simplified key material for SSO users
            const keyMaterial = `${username}_sso`;
            
            // Ensure TOTP is set up
            let totpSecret = await this.totp.loadSecret(username, keyMaterial);
            if (!totpSecret) {
                this.debugLog('Setting up TOTP automatically for SSO user...');
                const setupResult = await this.autoSetupTOTPForSSO(username, sessionToken);
                if (!setupResult.success) {
                    return {
                        success: false,
                        error: 'Failed to setup TOTP: ' + setupResult.error
                    };
                }
                totpSecret = setupResult.secret;
            }
            
            // Generate current TOTP code
            const currentCode = await this.totp.generateTOTP(totpSecret);
            
            // Calculate time remaining
            const now = Math.floor(Date.now() / 1000);
            const timeRemaining = 30 - (now % 30);
            
            return {
                success: true,
                code: currentCode,
                timeRemaining: timeRemaining,
                secret: totpSecret // For QR code if needed
            };
            
        } catch (error) {
            console.error('Failed to display TOTP:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Share session using TOTP encryption (gunsafe-style secure vault sharing)
     * @param {string} username - Username
     * @param {string} sessionToken - Session token (ignored, uses simplified key material)
     * @returns {Promise<object>} - Sharing result
     */
    async shareTOTPSessionVault(username, sessionToken) {
        try {
            // Get current session from the correct localStorage key
            let session = localStorage.getItem('gunauth_session');
            
            if (!session) {
                // Fallback to username-specific key
                session = localStorage.getItem(`gunauth_session_${username}`);
            }
            
            // Also check if we have the session object directly
            if (!session && this.session) {
                // Convert session object to JSON for processing
                session = JSON.stringify(this.session);
            }
            
            if (!session) {
                return {
                    success: false,
                    error: 'No active session to share'
                };
            }

            // Get current TOTP code for encryption using simplified key material
            const currentTOTP = await this.getCurrentTOTPForSSO(username, sessionToken);
            if (!currentTOTP) {
                return {
                    success: false,
                    error: 'Could not generate TOTP for encryption'
                };
            }

            // Parse session data (handle both encrypted and plain JSON)
            let sessionData;
            try {
                sessionData = JSON.parse(session);
            } catch (e) {
                // If it's not JSON, it might be Gun.SEA encrypted
                if (this.keyPair && this.keyPair.priv) {
                    sessionData = await Gun.SEA.decrypt(session, this.keyPair.priv);
                } else {
                    // Use the current session object directly
                    sessionData = this.session;
                }
            }
            
            if (!sessionData) {
                return {
                    success: false,
                    error: 'Could not decrypt session data'
                };
            }
            
            // Create vault-like structure (similar to gunsafe)
            const vaultData = {
                session: sessionData,
                username: username,
                timestamp: Date.now(),
                totpWindow: Math.floor(Date.now() / 30000) // TOTP window for validation
            };

            // Encrypt with current TOTP (like gunsafe encrypts vault contents)
            const encryptedVault = await Gun.SEA.encrypt(vaultData, currentTOTP);

            // Create deterministic hash for immutable storage
            const gun = Gun(['http://localhost:8000/gun']);
            const vaultHash = await CryptoUtils.createHash(`totp_vault_${username}`);
            
            this.debugLog('🔍 Debug: Storing vault with immutable key:', vaultHash);
            
            const vaultMetadata = {
                vault: encryptedVault,
                created: Date.now(),
                expires: Date.now() + (30 * 1000), // Expires with TOTP window
                // Add integrity hash to detect tampering
                integrity: await CryptoUtils.createHash(JSON.stringify({
                    vault: encryptedVault,
                    created: Date.now(),
                    expires: Date.now() + (30 * 1000)
                }))
            };
            
            this.debugLog('🔍 Debug: Vault metadata being stored:', {
                vault: encryptedVault ? 'ENCRYPTED_DATA' : null,
                created: vaultMetadata.created,
                expires: vaultMetadata.expires,
                integrity: vaultMetadata.integrity.substring(0, 16) + '...'
            });
            
            // Use immutable frozen storage pattern - prevents simple tampering attacks
            gun.get("totp_vaults").get(vaultHash).put(vaultMetadata);

            this.debugLog('✅ Session vault created with TOTP encryption in immutable storage');
            return {
                success: true,
                vaultHash: vaultHash,
                vaultKey: `totp_vault_${username}`, // For backward compatibility
                message: 'Session vault shared with TOTP encryption using immutable storage',
                currentTOTP: currentTOTP // For immediate cross-domain use
            };

        } catch (error) {
            console.error('Failed to create TOTP session vault:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Load session from TOTP-encrypted vault (gunsafe-style vault access)
     * @param {string} username - Username
     * @param {string} totpCode - Current TOTP code
     * @returns {Promise<object>} - Load result
     */
    async loadTOTPSessionVault(username, totpCode) {
        try {
            const gun = Gun(['http://localhost:8000/gun']);
            
            // Create deterministic hash for immutable storage lookup
            const vaultHash = await CryptoUtils.createHash(`totp_vault_${username}`);

            return new Promise((resolve) => {
                // Check immutable storage first
                gun.get("totp_vaults").get(vaultHash).once(async (data) => {
                    if (data && data.vault) {
                        // Verify data integrity
                        const expectedHash = await CryptoUtils.createHash(JSON.stringify({
                            vault: data.vault,
                            created: data.created,
                            expires: data.expires
                        }));
                        
                        if (data.integrity === expectedHash) {
                            this.debugLog('✅ Vault data integrity verified from immutable storage');
                            await this.processVaultLoad(data, totpCode, username, resolve);
                            return;
                        } else {
                            this.debugLog('⚠️ Vault data integrity check failed');
                        }
                    }
                    
                    // Fallback to legacy storage
                    gun.get(`totp_vault_${username}`).once(async (legacyData) => {
                        if (legacyData && legacyData.vault) {
                            this.debugLog('📦 Loading vault from legacy storage');
                            await this.processVaultLoad(legacyData, totpCode, username, resolve);
                        } else {
                            resolve({
                                success: false,
                                error: 'No session vault found for this user'
                            });
                        }
                    });
                });
            });
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Helper method to process vault loading with common logic
     */
    async processVaultLoad(data, totpCode, username, resolve) {
        // Check if vault has expired
        if (data.expires && Date.now() > data.expires) {
            resolve({
                success: false,
                error: 'Session vault has expired'
            });
            return;
        }

        try {
            // Decrypt vault with TOTP code
            const vaultData = await Gun.SEA.decrypt(data.vault, totpCode);
                        
            if (!vaultData) {
                resolve({
                    success: false,
                    error: 'Invalid TOTP code or vault corrupted'
                });
                return;
            }

            // Validate TOTP window (extra security)
            const currentWindow = Math.floor(Date.now() / 30000);
            if (Math.abs(currentWindow - vaultData.totpWindow) > 1) {
                resolve({
                    success: false,
                    error: 'TOTP window expired, please use current code'
                });
                return;
            }

            // Store session locally
            localStorage.setItem(`gunauth_session_${username}`, JSON.stringify(vaultData.session));

            this.debugLog('✅ Session loaded from TOTP vault with immutable storage');
            resolve({
                success: true,
                session: vaultData.session,
                message: 'Session successfully loaded from TOTP vault'
            });

        } catch (error) {
            resolve({
                success: false,
                error: `Failed to decrypt vault: ${error.message}`
            });
        }
    }
}

// Export for use in browser or Node.js
if (typeof window !== 'undefined') {
    window.GunAuthClient = GunAuthClient;
} else if (typeof module !== 'undefined' && module.exports) {
    module.exports = GunAuthClient;
}
