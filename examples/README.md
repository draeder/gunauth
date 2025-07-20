# GunAuth Examples

This directory contains example implementations and client libraries for GunAuth cross-domain authentication.

## 📁 Files Overview

### Client Libraries
- **`sso-client.js`** - SSO client library for OAuth2-like redirect flow
- **`session-manager.js`** - PostMessage-based session manager for seamless cross-domain sessions
- **`session-bridge.html`** - Bridge page for postMessage communication (served by auth server)

### Example Applications
- **`app1.html`** - Demo application 1 showing both authentication methods
- **`app2.html`** - Demo application 2 demonstrating cross-domain session sharing

### Setup & Testing
- **`start-demo.sh`** - Script to start all required servers for testing
- **`test-cross-domain.js`** - Automated test suite for cross-domain functionality
- **`CROSS_DOMAIN_README.md`** - Complete documentation and implementation guide

## 🚀 Quick Start

1. **Start all servers**:
   ```bash
   cd examples
   ./start-demo.sh
   ```

2. **Or start manually**:
   ```bash
   # Terminal 1 - GunAuth server
   npm start
   
   # Terminal 2 - App 1
   cd examples && python3 -m http.server 3001
   
   # Terminal 3 - App 2 
   cd examples && python3 -m http.server 3002
   ```

3. **Test the setup**:
   ```bash
   npm run test:cross-domain
   ```

4. **Try it out**:
   - Open http://localhost:3001/app1.html
   - Login with `crossdomaintest` / `testpassword123`
   - Open http://localhost:3002/app2.html
   - Click "Check Cross-Domain Auth" to see session sharing!

## 📚 Integration

To use these libraries in your own applications:

### SSO Method (Production Ready)
```javascript
import { GunAuthSSO } from './sso-client.js';

const sso = new GunAuthSSO({
    authServerUrl: 'https://your-auth-server.com',
    clientId: 'your-app-id'
});

// Login
sso.login({ redirectUri: window.location.origin + '/callback' });

// Handle callback
await sso.handleCallback();
```

### PostMessage Method (Trusted Domains)
```javascript
import { GunAuthSessionManager } from './session-manager.js';

const sessionManager = new GunAuthSessionManager({
    authDomain: 'your-auth-domain.com'
});

// Check authentication
const isAuth = await sessionManager.isAuthenticated();

// Login
await sessionManager.login(username, password);
```

## 🔧 Configuration

Update trusted domains in:
- `session-manager.js` - `isTrustedDomain()` method
- `session-bridge.html` - `trustedOrigins` array

## 🛡️ Security Notes

- SSO method works across any domains (most secure)
- PostMessage method requires trusted domain configuration
- Always use HTTPS in production
- Validate all origins in PostMessage handlers

For detailed implementation guide, see [CROSS_DOMAIN_README.md](CROSS_DOMAIN_README.md).
