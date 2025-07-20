# GunAuth Cross-Domain Session Implementation

This implementation provides multiple methods for sharing authentication sessions across different domains/applications using GunAuth.

## 🎯 Solutions Implemented

### 1. SSO Redirect Flow (OAuth2-like)
**Best for: Production environments, high security requirements**

- Uses authorization codes and redirect flows
- Most secure method with CSRF protection
- Similar to OAuth2/OpenID Connect flow
- Works across any domains

### 2. PostMessage Session Sharing
**Best for: Same organization apps, seamless UX**

- Uses hidden iframe and postMessage API
- Near-instant session sharing
- Good for related applications
- Requires trusted domain configuration

## 🚀 Quick Start

### 1. Start GunAuth Server
```bash
npm start
```

### 2. Serve Example Apps
You need to serve the example HTML files on different ports to simulate cross-domain:

```bash
# Terminal 1 - App 1 on port 3001
cd examples
python3 -m http.server 3001

# Terminal 2 - App 2 on port 3002
cd examples
python3 -m http.server 3002
```

### 3. Test Cross-Domain Sessions
1. Open http://localhost:3001/app1.html
2. Login using either method
3. Open http://localhost:3002/app2.html
4. Click "Check Cross-Domain Auth" - you should be authenticated!

## 📁 Files Added

### Server-Side (Added to index.js)
- `/sso/authorize` - SSO authorization endpoint with login form
- `/sso/code` - Creates temporary authorization codes
- `/sso/token` - Exchanges codes for tokens

### Client Libraries
- `sso-client.js` - SSO client library for redirect flow
- `session-manager.js` - PostMessage-based session manager
- `session-bridge.html` - Bridge page for postMessage communication

### Examples
- `examples/app1.html` - Demo app 1
- `examples/app2.html` - Demo app 2

## 🔧 Implementation Details

### SSO Flow
1. App redirects to `/sso/authorize?redirect_uri=...&client_id=...`
2. User logs in on auth server
3. Auth server creates authorization code
4. User redirected back with code
5. App exchanges code for token via `/sso/token`
6. App stores token locally

### PostMessage Flow
1. App loads hidden iframe pointing to auth domain
2. App sends postMessage requests to iframe
3. Iframe handles requests against localStorage on auth domain
4. Responses sent back via postMessage
5. Requires trusted domain configuration

## 🛠️ Configuration

### Environment Variables
```bash
# Auth server URL
GUNAUTH_URL=http://localhost:3000

# Trusted domains for postMessage (comma-separated)
TRUSTED_DOMAINS=https://app1.example.com,https://app2.example.com

# Client configuration
CLIENT_ID=your-app-id
```

### Client Configuration
```javascript
// SSO Client
const sso = new GunAuthSSO({
    authServerUrl: 'https://your-auth-server.com',
    clientId: 'your-app-id'
});

// Session Manager
const sessionManager = new GunAuthSessionManager({
    authDomain: 'your-auth-domain.com'
});
```

## 🔒 Security Considerations

### SSO Method Security
- ✅ CSRF protection via state parameter
- ✅ Authorization codes expire in 10 minutes
- ✅ One-time use codes
- ✅ Client ID validation
- ✅ Works across any domains

### PostMessage Method Security
- ✅ Origin validation for trusted domains
- ✅ Message ID tracking prevents replay
- ✅ Timeout protection
- ⚠️ Requires careful domain trust configuration
- ⚠️ Limited to predefined trusted domains

## 🌐 Production Deployment

### 1. Domain Setup
For production, you'll need:
- Auth server: `https://auth.yourcompany.com`
- Bridge page: `https://auth.yourcompany.com/session-bridge.html`
- Apps: `https://app1.yourcompany.com`, `https://app2.yourcompany.com`

### 2. HTTPS Requirements
- SSO method works with HTTP (development only)
- PostMessage method requires HTTPS in production
- Secure cookies recommended for production

### 3. Configuration Updates
Update the trusted domains in:
- `session-manager.js` - `isTrustedDomain()` method
- `session-bridge.html` - `trustedOrigins` array
- Server CORS configuration

## 🧪 Testing

### Basic Test Flow
1. Register a test user:
   ```bash
   curl -X POST http://localhost:3000/register \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser","password":"testpass"}'
   ```

2. Test SSO flow manually:
   - Visit: http://localhost:3000/sso/authorize?redirect_uri=http://localhost:3001/app1.html&client_id=test
   - Login with testuser/testpass
   - Should redirect back with authorization code

3. Test PostMessage:
   - Open two apps in different ports
   - Login in one, check auth status in the other

### Automated Tests
```bash
npm test
```

## 🔮 Advanced Features

### Token Refresh
For longer sessions, implement token refresh:
```javascript
// Add to session manager
async refreshToken() {
    const refreshToken = this.getRefreshToken();
    // Implement refresh logic
}
```

### Single Logout
Implement logout across all domains:
```javascript
// Broadcast logout to all apps
async globalLogout() {
    await this.clearSession();
    // Notify other apps via postMessage
}
```

### Session Events
Add event listeners for session changes:
```javascript
sessionManager.on('login', (user) => {
    console.log('User logged in:', user);
});

sessionManager.on('logout', () => {
    console.log('User logged out');
});
```

## 📚 API Reference

### GunAuthSSO Methods
```javascript
sso.login(options)           // Initiate SSO login
sso.handleCallback()         // Handle SSO callback
sso.getAuth()               // Get stored auth data
sso.verifyToken()           // Verify current token
sso.logout()                // Clear SSO session
```

### GunAuthSessionManager Methods
```javascript
sessionManager.login(username, password)  // Direct login
sessionManager.getSession()               // Get session from auth domain
sessionManager.setSession(data)           // Set session on auth domain
sessionManager.clearSession()             // Clear session
sessionManager.verifyToken(token, pub)    // Verify token
sessionManager.isAuthenticated()          // Check auth status
sessionManager.logout()                   // Logout
```

## 🐛 Troubleshooting

### Common Issues

1. **PostMessage not working**
   - Check trusted domains configuration
   - Ensure iframe loads correctly
   - Verify CORS settings

2. **SSO redirect fails**
   - Check redirect_uri matches exactly
   - Verify client_id configuration
   - Check for URL encoding issues

3. **Sessions not persisting**
   - Check localStorage/sessionStorage
   - Verify token expiration times
   - Check network connectivity

### Debug Mode
Enable debug logging:
```javascript
const sessionManager = new GunAuthSessionManager({
    authDomain: 'localhost:3000',
    debug: true  // Add debug logging
});
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details.
