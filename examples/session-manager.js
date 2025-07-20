/**
 * GunAuth Cross-Domain Session Manager
 * Uses Gun database for secure cross-domain session storage
 */

class GunAuthSessionManager {
  constructor(options = {}) {
    this.authServerUrl = options.authServerUrl || 'http://localhost:8000';
    
    // Initialize Gun with the same relays as the server
    this.gun = Gun([
      'https://gun-manhattan.herokuapp.com/gun',
      'https://gunjs.herokuapp.com/gun',
      'https://gun-us.herokuapp.com/gun',
      'https://gun-eu.herokuapp.com/gun',
      'https://peer.wallie.io/gun',
      'https://relay.peer.ooo/gun',
      'wss://gun-manhattan.herokuapp.com/gun',
      'wss://gunjs.herokuapp.com/gun',
      'wss://relay.peer.ooo/gun'
    ]);
    
    console.log('� SessionManager: Gun initialized for cross-domain session storage');
  }

  // Public API methods

  async getSession() {
    console.log('� SessionManager: Getting session from Gun database');
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        console.log('� SessionManager: Gun getSession timeout');
        resolve(null);
      }, 5000);
      
      this.gun.get('sessions').get('localhost:8000').once((session, key) => {
        clearTimeout(timeout);
        console.log('� SessionManager: Retrieved session from Gun:', { session, key });
        
        if (session && session.exp && Date.now() > session.exp) {
          console.log('� SessionManager: Session expired, removing');
          this.gun.get('sessions').get('localhost:8000').put(null);
          resolve(null);
        } else {
          resolve(session);
        }
      });
    });
  }

  async clearSession() {
    console.log('� SessionManager: Clearing session from Gun database');
    return new Promise((resolve) => {
      this.gun.get('sessions').get('localhost:8000').put(null, (ack) => {
        console.log('� SessionManager: Session cleared from Gun:', ack);
        resolve(true);
      });
    });
  }

  async verifyToken(token, pub) {
    console.log('🔫 SessionManager: Verifying token with auth server');
    try {
      const response = await fetch(`${this.authServerUrl}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, pub })
      });
      
      const result = await response.json();
      console.log('🔫 SessionManager: Token verification result:', result);
      return result;
    } catch (error) {
      console.error('🔫 SessionManager: Token verification failed:', error);
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  async isAuthenticated() {
    try {
      console.log('🔫 SessionManager: Checking authentication status');
      const session = await this.getSession();
      if (!session) {
        console.log('� SessionManager: No session found');
        return false;
      }
      
      console.log('� SessionManager: Session found, verifying token');
      const verification = await this.verifyToken(session.token, session.pub);
      const isAuth = verification.success;
      console.log('🔫 SessionManager: Authentication result:', isAuth);
      return isAuth;
    } catch (error) {
      console.error('🔫 SessionManager: Authentication check failed:', error);
      return false;
    }
  }

  async login(username, password) {
    try {
      console.log('� SessionManager: Login attempt for username:', username);
      const response = await fetch(`${this.authServerUrl}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const result = await response.json();
      console.log('� SessionManager: Login response received:', result);
      
      if (result.success) {
        console.log('✅ SessionManager: Login successful! Server has stored session in GUN.');
        
        // Wait a moment for the server to finish storing the session
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Verify the session was stored by the server
        console.log('🔍 SessionManager: Verifying server-stored session...');
        const storedSession = await this.getSession();
        console.log('🔍 SessionManager: Retrieved server-stored session:', storedSession);
        
        if (storedSession && storedSession.token === result.token) {
          console.log('✅ SessionManager: Session successfully verified in GUN database');
        } else {
          console.error('❌ SessionManager: Session verification failed!');
          console.error('❌ SessionManager: Expected token:', result.token);
          console.error('❌ SessionManager: Retrieved session:', storedSession);
        }
        
        return result;
      }
      
      throw new Error(result.error);
    } catch (error) {
      console.error('❌ SessionManager: Login error:', error);
      throw new Error(`Login failed: ${error.message}`);
    }
  }

  async register(username, password) {
    try {
      const response = await fetch(`${this.authServerUrl}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const result = await response.json();
      
      if (result.success) {
        return result;
      }
      
      throw new Error(result.error);
    } catch (error) {
      throw new Error(`Registration failed: ${error.message}`);
    }
  }

  async logout() {
    await this.clearSession();
  }
}

// Export for both ES modules and CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = GunAuthSessionManager;
} else if (typeof window !== 'undefined') {
  window.GunAuthSessionManager = GunAuthSessionManager;
}
