/**
 * GunAuth Client Library
 * Secure client-side authentication using Gun SEA
 * Handles keypair storage and token management securely
 */

class GunAuthClient {
    constructor(serverUrl = 'http://localhost:8000') {
        this.serverUrl = serverUrl.replace(/\/$/, ''); // Remove trailing slash
        this.keyPair = null;
        this.session = null;
        
        // Load existing session on initialization
        this.loadSession();
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
     * Login with username and password
     */
    async login(username, password) {
        try {
            // First load the keypair from storage
            const keyPair = await this.loadKeyPair(password);
            
            if (!keyPair) {
                throw new Error('No keypair found or wrong password');
            }
            
            const response = await fetch(`${this.serverUrl}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username, 
                    password,
                    priv: keyPair.priv // Send private key for token signing
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.session = {
                    token: result.token,
                    pub: result.pub,
                    exp: result.exp,
                    username: username,
                    loginTime: Date.now()
                };
                
                // Store session securely
                this.storeSession();
                
                console.log('✅ Login successful:', username);
                return { success: true, session: this.session };
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
        
        // Store state AND client_id for validation
        localStorage.setItem('gunauth_sso_state', state);
        localStorage.setItem('gunauth_sso_client_id', clientId);
        localStorage.setItem('gunauth_sso_redirect', redirectUri);
        
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
            
            console.log('🔍 SSO State Validation:', {
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
                console.log('🔍 All localStorage items:');
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    console.log(`  ${key}: ${localStorage.getItem(key)}`);
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
                
                console.log('🎯 SSO Session created:', this.session);
                
                // Store session
                await this.storeSession();
                
                // Clean up SSO state
                localStorage.removeItem('gunauth_sso_state');
                localStorage.removeItem('gunauth_sso_client_id');
                localStorage.removeItem('gunauth_sso_redirect');
                
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
}

// Export for use in browser or Node.js
if (typeof window !== 'undefined') {
    window.GunAuthClient = GunAuthClient;
} else if (typeof module !== 'undefined' && module.exports) {
    module.exports = GunAuthClient;
}
