import fetch from 'node-fetch';
import readline from 'readline';

const BASE_URL = 'http://localhost:8000';

// Helper function to get user input
function getUserInput(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// Helper function for password input (hidden)
function getPasswordInput(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
    // Hide password input
    rl.stdoutMuted = true;
    rl._writeToOutput = function _writeToOutput(stringToWrite) {
      if (rl.stdoutMuted) {
        rl.output.write('*');
      } else {
        rl.output.write(stringToWrite);
      }
    };
  });
}

async function testAPI() {
  console.log('🧪 Testing GunAuth API...\n');

  try {
    // Get user credentials
    console.log('Please provide test credentials:');
    const username = await getUserInput('Username: ');
    const password = await getPasswordInput('Password: ');
    console.log(''); // New line after password input
    
    if (!username || !password) {
      throw new Error('Username and password are required');
    }

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
        username: username,
        password: password
      })
    });
    const registerData = await registerResponse.json();
    console.log('✅ Registration:', registerData);

    if (registerData.success) {
      const { pub, priv } = registerData; // Get both pub and priv from registration

      // Test login (secure implementation requires private key)
      console.log('\n3. Testing user login...');
      const loginResponse = await fetch(`${BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username,
          password: password,
          priv: priv // Include private key for secure login
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
        const userResponse = await fetch(`${BASE_URL}/user/${username}/pub`);
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
