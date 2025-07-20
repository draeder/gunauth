/**
 * GunAuth SSO Client Library
 * Handles cross-domain authentication using OAuth2-like flow
 */

class GunAuthSSO {
  constructor(options = {}) {
    this.authServerUrl = options.authServerUrl || 'http://localhost:8000';
    this.clientId = options.clientId || 'default-client';
    this.storage = options.storage || localStorage;
    this.storagePrefix = options.storagePrefix || 'gunauth_sso_';
  }

  /**
   * Initiates SSO login by redirecting to auth server
   */
  login(options = {}) {
    const state = this.generateState();
    const redirectUri = options.redirectUri || window.location.origin + '/sso/callback';
    
    // Store state and redirect URI for validation
    this.storage.setItem(this.storagePrefix + 'state', state);
    this.storage.setItem(this.storagePrefix + 'redirect_uri', redirectUri);
    
    const params = new URLSearchParams({
      redirect_uri: redirectUri,
      client_id: this.clientId,
      state: state
    });
    
    window.location.href = `${this.authServerUrl}/sso/authorize?${params.toString()}`;
  }

  /**
   * Handles the callback after successful authentication
   */
  async handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const storedState = this.storage.getItem(this.storagePrefix + 'state');
    
    if (!code) {
      throw new Error('No authorization code received');
    }
    
    if (state !== storedState) {
      throw new Error('Invalid state parameter');
    }
    
    // Clean up stored state
    this.storage.removeItem(this.storagePrefix + 'state');
    this.storage.removeItem(this.storagePrefix + 'redirect_uri');
    
    // Exchange code for token
    const tokenResponse = await fetch(`${this.authServerUrl}/sso/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: code,
        client_id: this.clientId
      })
    });
    
    const tokenResult = await tokenResponse.json();
    
    if (!tokenResult.success) {
      throw new Error(tokenResult.error || 'Token exchange failed');
    }
    
    // Store the token
    this.storage.setItem(this.storagePrefix + 'token', tokenResult.token);
    this.storage.setItem(this.storagePrefix + 'pub', tokenResult.pub);
    
    // Clean up URL
    window.history.replaceState({}, document.title, window.location.pathname);
    
    return {
      token: tokenResult.token,
      pub: tokenResult.pub
    };
  }

  /**
   * Gets stored authentication data
   */
  getAuth() {
    const token = this.storage.getItem(this.storagePrefix + 'token');
    const pub = this.storage.getItem(this.storagePrefix + 'pub');
    
    if (token && pub) {
      return { token, pub };
    }
    
    return null;
  }

  /**
   * Verifies if current token is valid
   */
  async verifyToken() {
    const auth = this.getAuth();
    if (!auth) return null;
    
    try {
      const response = await fetch(`${this.authServerUrl}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: auth.token,
          pub: auth.pub
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        return result.claims;
      }
      
      // Token is invalid, clear stored data
      this.logout();
      return null;
    } catch (error) {
      console.error('Token verification failed:', error);
      this.logout();
      return null;
    }
  }

  /**
   * Checks if user is authenticated (has valid token)
   */
  async isAuthenticated() {
    const claims = await this.verifyToken();
    return !!claims;
  }

  /**
   * Logs out by clearing stored authentication data
   */
  logout() {
    this.storage.removeItem(this.storagePrefix + 'token');
    this.storage.removeItem(this.storagePrefix + 'pub');
    this.storage.removeItem(this.storagePrefix + 'state');
    this.storage.removeItem(this.storagePrefix + 'redirect_uri');
  }

  /**
   * Generates a random state for CSRF protection
   */
  generateState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}

// Export for both ES modules and CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = GunAuthSSO;
} else if (typeof window !== 'undefined') {
  window.GunAuthSSO = GunAuthSSO;
}
