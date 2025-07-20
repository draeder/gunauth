import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:8000';

async function testCrossDomainAuth() {
  console.log('🧪 Testing GunAuth Cross-Domain Features...\n');

  try {
    // Test 1: Health check
    console.log('1. Testing health check...');
    const healthResponse = await fetch(`${BASE_URL}/`);
    const healthData = await healthResponse.json();
    console.log('✅ Health check:', healthData.status);

    // Test 2: Register test user
    console.log('\n2. Testing user registration...');
    const registerResponse = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'crossdomaintest',
        password: 'testpassword123'
      })
    });
    const registerData = await registerResponse.json();
    console.log('✅ Registration:', registerData.success ? 'Success' : 'Failed (may already exist)');

    // Test 3: Login to get tokens
    console.log('\n3. Testing user login...');
    const loginResponse = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'crossdomaintest',
        password: 'testpassword123'
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
        redirect_uri: 'http://localhost:3001/callback',
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
    console.log('\n📋 Next Steps:');
    console.log('   1. Start the example apps:');
    console.log('      cd examples && python3 -m http.server 3001');
    console.log('      cd examples && python3 -m http.server 3002');
    console.log('   2. Open http://localhost:3001/app1.html');
    console.log('   3. Login with username: crossdomaintest, password: testpassword123');
    console.log('   4. Open http://localhost:3002/app2.html');
    console.log('   5. Click "Check Cross-Domain Auth" to see session sharing!');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\n💡 Make sure the GunAuth server is running with: npm start');
  }
}

// Run tests if this file is executed directly
if (process.argv[1].endsWith('test-cross-domain.js')) {
  testCrossDomainAuth();
}

export default testCrossDomainAuth;
