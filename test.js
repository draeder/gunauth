import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:3001';

async function testAPI() {
  console.log('🧪 Testing GunAuth API...\n');

  try {
    // Test health check
    console.log('1. Testing health check...');
    const healthResponse = await fetch(`${BASE_URL}/`);
    const healthData = await healthResponse.json();
    console.log('✅ Health check:', healthData);

    // Test registration
    console.log('\n2. Testing user registration...');
    const registerResponse = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser',
        password: 'testpassword123'
      })
    });
    const registerData = await registerResponse.json();
    console.log('✅ Registration:', registerData);

    if (registerData.success) {
      const { pub } = registerData;

      // Test login
      console.log('\n3. Testing user login...');
      const loginResponse = await fetch(`${BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'testuser',
          password: 'testpassword123'
        })
      });
      const loginData = await loginResponse.json();
      console.log('✅ Login:', loginData);

      if (loginData.success) {
        const { token } = loginData;

        // Test token verification
        console.log('\n4. Testing token verification...');
        const verifyResponse = await fetch(`${BASE_URL}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, pub })
        });
        const verifyData = await verifyResponse.json();
        console.log('✅ Token verification:', verifyData);

        // Test user lookup
        console.log('\n5. Testing user lookup...');
        const userResponse = await fetch(`${BASE_URL}/user/testuser/pub`);
        const userData = await userResponse.json();
        console.log('✅ User lookup:', userData);
      }
    }

    console.log('\n🎉 All tests completed!');

  } catch (error) {
    console.error('❌ Test error:', error.message);
  }
}

// Run tests if this file is executed directly
if (process.argv[1].endsWith('test.js')) {
  testAPI();
}

export default testAPI;
