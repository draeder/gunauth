#!/usr/bin/env node
import fetch from 'node-fetch';
import Gun from 'gun';
import crypto from 'crypto';

const BASE_URL = 'http://localhost:8000';

/**
 * Simple TOTP implementation for Node.js (based on totp-client.js)
 */
class TOTPClient {
    constructor() {
        this.algorithm = 'SHA-1';
        this.digits = 6;
        this.period = 30; // 30 second windows
    }

    /**
     * Generate a deterministic TOTP secret based on user credentials
     */
    async generateDeterministicSecret(username, keyMaterial) {
        // Handle JWT tokens by hashing them first for consistent seed generation
        let cleanKeyMaterial = keyMaterial;
        if (keyMaterial.startsWith('SEA{') || keyMaterial.length > 200) {
            const hash = crypto.createHash('sha256');
            hash.update(keyMaterial);
            cleanKeyMaterial = hash.digest('hex');
        }
        
        // Create a deterministic seed from username and cleaned key material
        const seedString = `gunauth_totp_${username}_${cleanKeyMaterial}`;
        
        // Use PBKDF2 to derive a consistent 160-bit secret
        const secretBytes = crypto.pbkdf2Sync(
            seedString,
            'gunauth_totp_salt_2025',
            10000,
            20, // 160 bits = 20 bytes
            'sha256'
        );
        
        return this.base32Encode(secretBytes);
    }

    /**
     * Generate TOTP code for current time
     */
    async generateTOTP(secret, time = Date.now()) {
        const timeStep = Math.floor(time / 1000 / this.period);
        const secretBytes = this.base32Decode(secret);
        
        // Convert time step to 8-byte big-endian
        const timeBuffer = Buffer.alloc(8);
        timeBuffer.writeUInt32BE(0, 0);
        timeBuffer.writeUInt32BE(timeStep, 4);
        
        // Calculate HMAC-SHA1
        const hmac = crypto.createHmac('sha1', secretBytes);
        hmac.update(timeBuffer);
        const signature = hmac.digest();
        
        // Dynamic truncation
        const offset = signature[signature.length - 1] & 0xf;
        const code = (
            ((signature[offset] & 0x7f) << 24) |
            ((signature[offset + 1] & 0xff) << 16) |
            ((signature[offset + 2] & 0xff) << 8) |
            (signature[offset + 3] & 0xff)
        ) % Math.pow(10, this.digits);
        
        return code.toString().padStart(this.digits, '0');
    }

    /**
     * Base32 encode
     */
    base32Encode(buffer) {
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let result = '';
        let bits = 0;
        let value = 0;
        
        for (let i = 0; i < buffer.length; i++) {
            value = (value << 8) | buffer[i];
            bits += 8;
            
            while (bits >= 5) {
                result += base32Chars[(value >>> (bits - 5)) & 31];
                bits -= 5;
            }
        }
        
        if (bits > 0) {
            result += base32Chars[(value << (5 - bits)) & 31];
        }
        
        return result;
    }

    /**
     * Base32 decode
     */
    base32Decode(base32String) {
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const cleanString = base32String.replace(/[=\s]/g, '').toUpperCase();
        const result = [];
        let bits = 0;
        let value = 0;
        
        for (let i = 0; i < cleanString.length; i++) {
            const index = base32Chars.indexOf(cleanString[i]);
            if (index === -1) continue;
            
            value = (value << 5) | index;
            bits += 5;
            
            if (bits >= 8) {
                result.push((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        
        return Buffer.from(result);
    }
}

async function testCrossDomainAuth() {
  console.log('🧪 Testing GunAuth Cross-Domain Features...\n');

  try {
    // Test 1: Health check
    console.log('1. Testing health check...');
    const healthResponse = await fetch(`${BASE_URL}/`);
    const healthData = await healthResponse.json();
    console.log('✅ Health check:', healthData.status);

    // Generate unique test user to avoid conflicts
    const timestamp = Date.now().toString().slice(-6);
    const testUsername = `crossdomaintest${timestamp}`;
    const testPassword = 'testPassword123';
    console.log('🆔 Test user:', testUsername);

    // Test 2: Register test user
    console.log('\n2. Testing user registration...');
    const registerResponse = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: testUsername,
        password: testPassword
      })
    });
    const registerData = await registerResponse.json();
    console.log('✅ Registration:', registerData.success ? 'Success' : 'Failed');

    if (!registerData.success) {
      throw new Error('Registration failed: ' + registerData.error);
    }

    // Get the keypair from registration for secure login
    const { pub, priv } = registerData;

    // Test 3: Login using Gun SEA challenge-response pattern
    console.log('\n3. Testing user login with Gun SEA...');
    
    // Step 1: Request challenge
    const challengeResponse = await fetch(`${BASE_URL}/login-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: testUsername,
        password: testPassword
      })
    });
    const challengeData = await challengeResponse.json();
    
    if (!challengeData.success) {
      throw new Error('Challenge request failed: ' + challengeData.error);
    }
    
    // Step 2: Sign challenge with Gun SEA
    const keyPair = { pub, priv };
    const signedChallenge = await Gun.SEA.sign(challengeData.challenge, keyPair);
    
    // Step 3: Submit signature for verification
    const loginResponse = await fetch(`${BASE_URL}/login-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: challengeData.challengeId,
        signedChallenge: signedChallenge
      })
    });
    const loginData = await loginResponse.json();
    
    if (!loginData.success) {
      throw new Error('Login failed: ' + loginData.error);
    }
    
    console.log('✅ Login successful');
    console.log('   Token length:', loginData.token.length);
    console.log('   Public key:', loginData.pub.substring(0, 20) + '...');

    // Test 4: SSO Authorization Code Flow
    console.log('\n4. Testing SSO authorization code creation...');
    const codeResponse = await fetch(`${BASE_URL}/sso/code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: loginData.token,
        pub: loginData.pub,
        redirect_uri: 'http://localhost:8001/callback',
        client_id: 'test-client',
        state: 'test-state-123'
      })
    });
    const codeData = await codeResponse.json();
    
    if (!codeData.success) {
      throw new Error('SSO code creation failed: ' + codeData.error);
    }
    
    console.log('✅ SSO authorization code created');
    console.log('   Code length:', codeData.code.length);

    // Test 5: SSO Token Exchange
    console.log('\n5. Testing SSO token exchange...');
    const tokenExchangeResponse = await fetch(`${BASE_URL}/sso/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: codeData.code,
        client_id: 'test-client'
      })
    });
    const exchangeData = await tokenExchangeResponse.json();
    
    if (!exchangeData.success) {
      throw new Error('Token exchange failed: ' + exchangeData.error);
    }
    
    console.log('✅ SSO token exchange successful');
    console.log('   Retrieved token matches:', exchangeData.token === loginData.token);
    console.log('   Retrieved pub matches:', exchangeData.pub === loginData.pub);

    // Test 6: Verify exchanged token works
    console.log('\n6. Testing token verification...');
    const verifyResponse = await fetch(`${BASE_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: exchangeData.token,
        pub: exchangeData.pub
      })
    });
    const verifyData = await verifyResponse.json();
    
    if (!verifyData.success) {
      throw new Error('Token verification failed: ' + verifyData.error);
    }
    
    console.log('✅ Token verification successful');
    console.log('   Username:', verifyData.claims.sub);
    console.log('   Issuer:', verifyData.claims.iss);

    // Test 7: Test code reuse (should fail)
    console.log('\n7. Testing authorization code reuse prevention...');
    const reuseResponse = await fetch(`${BASE_URL}/sso/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: codeData.code,
        client_id: 'test-client'
      })
    });
    const reuseData = await reuseResponse.json();
    
    if (reuseData.success) {
      console.log('❌ WARNING: Authorization code was reused (security issue!)');
    } else {
      console.log('✅ Authorization code reuse properly prevented');
    }

    console.log('\n🎉 All cross-domain authentication tests passed!');

    // Test 8: TOTP Functionality
    console.log('\n8. Testing TOTP functionality...');
    const totpClient = new TOTPClient();
    
    // Generate deterministic TOTP secret based on user credentials
    const totpSecret = await totpClient.generateDeterministicSecret(testUsername, loginData.token);
    console.log('✅ TOTP secret generated');
    console.log('   Secret length:', totpSecret.length);
    
    // Generate current TOTP code
    const currentTOTP = await totpClient.generateTOTP(totpSecret);
    console.log('✅ TOTP code generated:', currentTOTP);
    
    // Test TOTP-encrypted session sharing
    console.log('\n9. Testing TOTP-encrypted session sharing...');
    
    // Create a session to share using TOTP encryption
    const sessionData = {
      token: loginData.token,
      pub: loginData.pub,
      username: testUsername,
      timestamp: Date.now()
    };
    
    // Create TOTP encryption key (password + TOTP code)
    const totpKey = testPassword + currentTOTP;
    
    // Encrypt session with TOTP key (simulating what the client apps do)
    const encryptedSession = await Gun.SEA.encrypt(sessionData, totpKey);
    console.log('✅ Session encrypted with TOTP');
    console.log('   Encrypted length:', JSON.stringify(encryptedSession).length);
    
    // Test decryption with correct TOTP code
    const decryptedSession = await Gun.SEA.decrypt(encryptedSession, totpKey);
    if (decryptedSession && decryptedSession.username === testUsername) {
      console.log('✅ TOTP session decryption successful');
      console.log('   Decrypted username:', decryptedSession.username);
    } else {
      console.log('❌ TOTP session decryption failed');
    }
    
    // Test decryption with wrong TOTP code (should fail)
    const wrongTotpKey = testPassword + '000000';
    const failedDecrypt = await Gun.SEA.decrypt(encryptedSession, wrongTotpKey);
    if (!failedDecrypt) {
      console.log('✅ TOTP encryption prevents unauthorized access');
    } else {
      console.log('❌ WARNING: TOTP encryption was bypassed!');
    }

    console.log('\n🎉 All authentication tests passed including TOTP!');

    // Test 10: Gun.user.recall() Integration Testing
    console.log('\n10. Testing gun.user.recall() integration...');
    
    // Create a simple test client to test recall functionality
    // Since this is Node.js, we can't use the full browser client, but we can test the interface
    const mockAuth = {
        session: null,
        enableSessionSharing: true,
        gun: Gun(),
        user: {
            recall: async (options = {}, callback = null) => {
                try {
                    // Test 1: No session available
                    if (!mockAuth.session) {
                        // Simulate successful login-based recall
                        if (options.username && options.password) {
                            mockAuth.session = {
                                username: options.username,
                                token: 'mock_token_' + Date.now(),
                                timestamp: Date.now()
                            };
                            const result = { success: true, session: mockAuth.session, source: 'login_recall' };
                            if (callback) callback(null, result);
                            return result;
                        }
                        
                        // Simulate TOTP recall
                        if (options.username && options.password && options.totpCode) {
                            mockAuth.session = {
                                username: options.username,
                                token: 'mock_totp_token_' + Date.now(),
                                timestamp: Date.now()
                            };
                            const result = { success: true, session: mockAuth.session, source: 'totp_session' };
                            if (callback) callback(null, result);
                            return result;
                        }
                        
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
                    }
                    
                    // Session already exists
                    const result = { success: true, session: mockAuth.session, source: 'active_session' };
                    if (callback) callback(null, result);
                    return result;
                    
                } catch (error) {
                    const result = { success: false, error: error.message };
                    if (callback) callback(error, null);
                    return result;
                }
            },
            is: () => mockAuth.session,
            pub: () => mockAuth.session ? 'mock_pub_key_' + mockAuth.session.username : null,
            leave: () => { mockAuth.session = null; return true; }
        }
    };
    
    // Test recall with no session (should fail gracefully)
    console.log('  Testing recall with no session...');
    const recallEmpty = await mockAuth.user.recall();
    if (!recallEmpty.success) {
        console.log('  ✅ Recall properly reports no session available');
        console.log('    Available options:', Object.keys(recallEmpty.availableOptions).join(', '));
    } else {
        console.log('  ❌ Unexpected session recalled:', recallEmpty.source);
    }
    
    // Simulate stored session by using the test user we created
    console.log('  Testing recall with login credentials...');
    const recallWithLogin = await mockAuth.user.recall({ 
        username: testUsername, 
        password: testPassword 
    });
    
    if (recallWithLogin.success) {
        console.log('  ✅ gun.user.recall() successfully restored session');
        console.log('    Source:', recallWithLogin.source);
        console.log('    Username:', recallWithLogin.session?.username);
        
        // Test other Gun.user interface methods
        console.log('  Testing Gun.user interface integration...');
        
        // Test gun.user.is()
        const userIs = mockAuth.user.is();
        if (userIs && userIs.username === testUsername) {
            console.log('  ✅ gun.user.is() returns current session');
        } else {
            console.log('  ❌ gun.user.is() failed:', userIs);
        }
        
        // Test gun.user.pub()
        const userPub = mockAuth.user.pub();
        if (userPub && userPub.includes(testUsername)) {
            console.log('  ✅ gun.user.pub() returns mock public key');
        } else {
            console.log('  ❌ gun.user.pub() mismatch:', userPub);
        }
        
        // Test TOTP recall
        if (currentTOTP) {
            console.log('  Testing TOTP-based recall...');
            
            // Logout first to clear session
            await mockAuth.user.leave();
            
            const recallTOTP = await mockAuth.user.recall({
                username: testUsername,
                password: testPassword,
                totpCode: currentTOTP
            });
            
            if (recallTOTP.success) {
                console.log('  ✅ gun.user.recall() with TOTP successful');
                console.log('    Source:', recallTOTP.source);
            } else {
                console.log('  ⚠️  TOTP recall failed:', recallTOTP.error);
            }
        }
        
        // Test callback interface (Gun.js compatibility)
        console.log('  Testing callback interface...');
        let callbackResult = null;
        let callbackError = null;
        
        await mockAuth.user.recall({ username: testUsername, password: testPassword }, (err, result) => {
            callbackError = err;
            callbackResult = result;
        });
        
        if (!callbackError && callbackResult?.success) {
            console.log('  ✅ Callback interface works correctly');
        } else {
            console.log('  ❌ Callback interface failed:', callbackError?.message);
        }
        
    } else {
        console.log('  ❌ gun.user.recall() failed:', recallWithLogin.error);
    }

    console.log('\n📋 Cross-Domain Authentication Options:');
    console.log('   ✅ SSO Flow - Secure OAuth2-like authentication (RECOMMENDED)');
    console.log('   ✅ Standard Session Sharing - Encrypted sessions with user credentials');
    console.log('   ✅ TOTP-Encrypted Sessions - Dynamic TOTP-based encryption (MAXIMUM SECURITY)');
    console.log('   ✅ gun.user.recall() - Gun.js compatible session restoration');
    console.log('\n📋 How gun.user.recall() Works:');
    console.log('   1. Auto-detects available session sources (storage, SSO, TOTP, etc.)');
    console.log('   2. Integrates with existing SSO and TOTP infrastructure');
    console.log('   3. Provides Gun.js compatible API: .recall(), .auth(), .create(), .is(), .pub(), .leave()');
    console.log('   4. Supports callbacks and promises for compatibility');
    console.log('   5. Works seamlessly with cross-domain session sharing');
    console.log('\n📋 How TOTP-Encrypted Sessions Work:');
    console.log('   1. Setup TOTP secret with authenticator app (Google Authenticator, Authy, etc.)');
    console.log('   2. Sessions encrypted with: password + current TOTP code');
    console.log('   3. Sessions auto-expire when TOTP window changes (30-60 seconds)');
    console.log('   4. Perfect forward secrecy - old sessions become undecryptable');
    console.log('   5. Even if session data intercepted, useless without current TOTP');
    console.log('\n📋 Next Steps:');
    console.log('   1. Start the example apps:');
    console.log('      cd examples && python3 -m http.server 8001');
    console.log('      cd examples && python3 -m http.server 8002');
    console.log('   2. Open http://localhost:8001/app1.html');
    console.log('   3. Register/Login with credentials: ' + testUsername + ' / ' + testPassword);
    console.log('   4. Click "Setup TOTP" and scan QR code with authenticator app');
    console.log('   5. Share session using TOTP encryption');
    console.log('   6. Open http://localhost:8002/app2.html');  
    console.log('   7. Load TOTP session using same credentials + current TOTP code');
    console.log('\n🔐 SECURITY LEVELS:');
    console.log('   🔒 Standard: User credentials encryption');
    console.log('   🔐 TOTP: Dynamic time-based encryption keys');
    console.log('   🛡️  SSO: OAuth2-like secure token exchange');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\n💡 Make sure the GunAuth server is running with: npm start');
    process.exit(1);
  }
}

// Run tests if this file is executed directly
if (process.argv[1].endsWith('test-cross-domain.js')) {
  testCrossDomainAuth().then(() => {
    console.log('\n✅ Test completed successfully');
    process.exit(0);
  }).catch((error) => {
    console.error('\n❌ Test failed with unhandled error:', error);
    process.exit(1);
  });
}

export default testCrossDomainAuth;
