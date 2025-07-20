# GunAuth - Minimal Identity Provider

A minimal identity provider built with GUN and SEA, designed for peer-to-peer authentication.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/draeder/gunauth.git
cd gunauth

# Install dependencies
npm install

# Start the server
npm start
```

Or use as a template:
```bash
npx create-gunauth-app my-auth-server
```

## 🚀 Deployment

This service is designed to run on any Node.js hosting platform. Below are detailed instructions for major cloud providers.

### Deploy to Heroku

```bash
# Login to Heroku
heroku login

# Create a new Heroku app
heroku create your-app-name

# Deploy
git add .
git commit -m "Initial commit"
git push heroku main
```

### Deploy to Vercel

1. **Install Vercel CLI:**
   ```bash
   npm i -g vercel
   ```

2. **Deploy:**
   ```bash
   vercel
   ```

3. **Create `vercel.json` config:**
   ```json
   {
     "version": 2,
     "builds": [
       {
         "src": "index.js",
         "use": "@vercel/node"
       }
     ],
     "routes": [
       {
         "src": "/(.*)",
         "dest": "index.js"
       }
     ]
   }
   ```

### Deploy to Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

### Deploy to AWS Lambda (Serverless)

1. **Install Serverless Framework:**
   ```bash
   npm install -g serverless
   npm install serverless-http
   ```

2. **Create `serverless.yml`:**
   ```yaml
   service: gunauth
   provider:
     name: aws
     runtime: nodejs18.x
     region: us-east-1
   functions:
     app:
       handler: lambda.handler
       events:
         - http:
             path: /{proxy+}
             method: ANY
             cors: true
         - http:
             path: /
             method: ANY
             cors: true
   ```

3. **Create `lambda.js` wrapper:**
   ```javascript
   import serverless from 'serverless-http';
   import app from './index.js';
   
   export const handler = serverless(app);
   ```

4. **Deploy:**
   ```bash
   serverless deploy
   ```

### Deploy to Google Cloud Run

```bash
# Build and deploy
gcloud run deploy gunauth \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

### Deploy to Azure Container Apps

1. **Create `Dockerfile`:**
   ```dockerfile
   FROM node:18-alpine
   WORKDIR /app
   COPY package*.json ./
   RUN npm ci --only=production
   COPY . .
   EXPOSE 3000
   CMD ["npm", "start"]
   ```

2. **Deploy:**
   ```bash
   az containerapp up \
     --name gunauth \
     --source . \
     --environment-variables PORT=3000
   ```

## ☁️ Using as Identity Provider with Major Clouds

GunAuth can serve as a custom identity provider for various cloud services and applications.

### Integration with AWS

#### AWS API Gateway Custom Authorizer

```javascript
// lambda-authorizer.js
export const handler = async (event) => {
  const token = event.authorizationToken?.replace('Bearer ', '');
  const pub = event.headers?.['X-Public-Key'];
  
  try {
    const response = await fetch(`${process.env.GUNAUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, pub })
    });
    
    const result = await response.json();
    
    if (result.success) {
      return {
        principalId: result.claims.sub,
        policyDocument: {
          Version: '2012-10-17',
          Statement: [{
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: event.methodArn
          }]
        },
        context: {
          username: result.claims.sub,
          issuer: result.claims.iss
        }
      };
    }
  } catch (error) {
    console.error('Authorization failed:', error);
  }
  
  throw new Error('Unauthorized');
};
```

#### AWS Cognito Custom Authentication Flow

```javascript
// cognito-trigger.js
export const handler = async (event) => {
  if (event.triggerSource === 'DefineAuthChallenge_Authentication') {
    const { token, pub } = event.request.privateChallengeParameters;
    
    const response = await fetch(`${process.env.GUNAUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, pub })
    });
    
    const result = await response.json();
    event.response.answerCorrect = result.success;
  }
  
  return event;
};
```

### Integration with Google Cloud

#### Cloud Identity-Aware Proxy (IAP) Header Verification

```javascript
// gcp-iap-middleware.js
import jwt from 'jsonwebtoken';

export const verifyGunAuthToken = async (req, res, next) => {
  const token = req.headers['x-gunauth-token'];
  const pub = req.headers['x-gunauth-pub'];
  
  if (!token || !pub) {
    return res.status(401).json({ error: 'Missing authentication headers' });
  }
  
  try {
    const response = await fetch(`${process.env.GUNAUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, pub })
    });
    
    const result = await response.json();
    
    if (result.success) {
      req.user = result.claims;
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Authentication service error' });
  }
};
```

#### Google Cloud Functions Authentication

```javascript
// functions/auth.js
import { onRequest } from 'firebase-functions/v2/https';

export const authenticatedFunction = onRequest(async (request, response) => {
  const token = request.headers.authorization?.replace('Bearer ', '');
  const pub = request.headers['x-public-key'];
  
  if (!token || !pub) {
    response.status(401).send('Unauthorized');
    return;
  }
  
  try {
    const authResponse = await fetch(`${process.env.GUNAUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, pub })
    });
    
    const result = await authResponse.json();
    
    if (result.success) {
      response.json({ 
        message: 'Authenticated successfully',
        user: result.claims.sub 
      });
    } else {
      response.status(401).send('Invalid token');
    }
  } catch (error) {
    response.status(500).send('Authentication error');
  }
});
```

### Integration with Microsoft Azure

#### Azure API Management Policy

```xml
<!-- Azure APIM Policy -->
<policies>
  <inbound>
    <validate-jwt header-name="Authorization" failed-validation-httpcode="401">
      <openid-config url="{{gunauth-url}}/.well-known/openid-configuration" />
      <issuers>
        <issuer>{{gunauth-url}}</issuer>
      </issuers>
    </validate-jwt>
    <send-request mode="new" response-variable-name="authResponse">
      <set-url>{{gunauth-url}}/verify</set-url>
      <set-method>POST</set-method>
      <set-header name="Content-Type" exists-action="override">
        <value>application/json</value>
      </set-header>
      <set-body>
        @{
          var token = context.Request.Headers["Authorization"].First().Replace("Bearer ", "");
          var pub = context.Request.Headers["X-Public-Key"].First();
          return JsonConvert.SerializeObject(new { token = token, pub = pub });
        }
      </set-body>
    </send-request>
    <choose>
      <when condition="@(((IResponse)context.Variables["authResponse"]).StatusCode != 200)">
        <return-response>
          <set-status code="401" reason="Unauthorized" />
          <set-body>Invalid authentication</set-body>
        </return-response>
      </when>
    </choose>
  </inbound>
</policies>
```

#### Azure Functions with Custom Authentication

```javascript
// Azure Function
import { app } from '@azure/functions';

app.http('authenticatedEndpoint', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    const token = request.headers.get('authorization')?.replace('Bearer ', '');
    const pub = request.headers.get('x-public-key');
    
    if (!token || !pub) {
      return { status: 401, body: 'Unauthorized' };
    }
    
    try {
      const response = await fetch(`${process.env.GUNAUTH_URL}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, pub })
      });
      
      const result = await response.json();
      
      if (result.success) {
        return { 
          status: 200, 
          body: { 
            message: 'Success', 
            user: result.claims 
          }
        };
      } else {
        return { status: 401, body: 'Invalid token' };
      }
    } catch (error) {
      return { status: 500, body: 'Authentication error' };
    }
  }
});
```

### Integration with Kubernetes

#### Kubernetes Ingress with Authentication

```yaml
# k8s-auth-middleware.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gunauth-config
data:
  GUNAUTH_URL: "https://your-gunauth-instance.com"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-middleware
spec:
  replicas: 2
  selector:
    matchLabels:
      app: auth-middleware
  template:
    metadata:
      labels:
        app: auth-middleware
    spec:
      containers:
      - name: auth-middleware
        image: your-registry/gunauth-middleware:latest
        ports:
        - containerPort: 3000
        envFrom:
        - configMapRef:
            name: gunauth-config
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authenticated-ingress
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://auth-middleware.default.svc.cluster.local:3000/verify"
    nginx.ingress.kubernetes.io/auth-method: POST
    nginx.ingress.kubernetes.io/auth-response-headers: X-User,X-Issuer
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: your-api-service
            port:
              number: 80
```

### Client Integration Examples

#### React/Next.js Frontend

```javascript
// hooks/useGunAuth.js
import { useState, useEffect } from 'react';

const GUNAUTH_URL = process.env.NEXT_PUBLIC_GUNAUTH_URL;

export function useGunAuth() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [pub, setPub] = useState(null);

  const register = async (username, password) => {
    const response = await fetch(`${GUNAUTH_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    const result = await response.json();
    if (result.success) {
      setPub(result.pub);
      return result;
    }
    throw new Error(result.error);
  };

  const login = async (username, password) => {
    const response = await fetch(`${GUNAUTH_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    const result = await response.json();
    if (result.success) {
      setToken(result.token);
      setPub(result.pub);
      localStorage.setItem('gunauth_token', result.token);
      localStorage.setItem('gunauth_pub', result.pub);
      return result;
    }
    throw new Error(result.error);
  };

  const logout = () => {
    setToken(null);
    setPub(null);
    setUser(null);
    localStorage.removeItem('gunauth_token');
    localStorage.removeItem('gunauth_pub');
  };

  const verifyToken = async (tokenToVerify, pubKey) => {
    const response = await fetch(`${GUNAUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: tokenToVerify, pub: pubKey })
    });
    
    const result = await response.json();
    if (result.success) {
      setUser(result.claims);
      return result.claims;
    }
    return null;
  };

  // Auto-verify on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('gunauth_token');
    const storedPub = localStorage.getItem('gunauth_pub');
    
    if (storedToken && storedPub) {
      setToken(storedToken);
      setPub(storedPub);
      verifyToken(storedToken, storedPub);
    }
  }, []);

  return {
    user,
    token,
    pub,
    register,
    login,
    logout,
    verifyToken,
    isAuthenticated: !!user
  };
}
```

#### Vue 3 Composition API

```javascript
// composables/useGunAuth.js
import { ref, onMounted, computed } from 'vue'

const GUNAUTH_URL = import.meta.env.VITE_GUNAUTH_URL

export function useGunAuth() {
  const user = ref(null)
  const token = ref(null)
  const pub = ref(null)
  const loading = ref(false)
  const error = ref(null)

  const isAuthenticated = computed(() => !!user.value)

  const register = async (username, password) => {
    loading.value = true
    error.value = null
    
    try {
      const response = await fetch(`${GUNAUTH_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      
      const result = await response.json()
      
      if (result.success) {
        pub.value = result.pub
        return result
      } else {
        throw new Error(result.error)
      }
    } catch (err) {
      error.value = err.message
      throw err
    } finally {
      loading.value = false
    }
  }

  const login = async (username, password) => {
    loading.value = true
    error.value = null
    
    try {
      const response = await fetch(`${GUNAUTH_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      
      const result = await response.json()
      
      if (result.success) {
        token.value = result.token
        pub.value = result.pub
        localStorage.setItem('gunauth_token', result.token)
        localStorage.setItem('gunauth_pub', result.pub)
        
        // Verify the token to get user claims
        await verifyToken(result.token, result.pub)
        
        return result
      } else {
        throw new Error(result.error)
      }
    } catch (err) {
      error.value = err.message
      throw err
    } finally {
      loading.value = false
    }
  }

  const logout = () => {
    token.value = null
    pub.value = null
    user.value = null
    error.value = null
    localStorage.removeItem('gunauth_token')
    localStorage.removeItem('gunauth_pub')
  }

  const verifyToken = async (tokenToVerify, pubKey) => {
    if (!tokenToVerify || !pubKey) return null
    
    try {
      const response = await fetch(`${GUNAUTH_URL}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: tokenToVerify, pub: pubKey })
      })
      
      const result = await response.json()
      
      if (result.success) {
        user.value = result.claims
        return result.claims
      } else {
        // Token is invalid, clear stored data
        logout()
        return null
      }
    } catch (err) {
      console.error('Token verification failed:', err)
      logout()
      return null
    }
  }

  const refreshAuth = async () => {
    const storedToken = localStorage.getItem('gunauth_token')
    const storedPub = localStorage.getItem('gunauth_pub')
    
    if (storedToken && storedPub) {
      token.value = storedToken
      pub.value = storedPub
      await verifyToken(storedToken, storedPub)
    }
  }

  // Auto-verify on mount
  onMounted(async () => {
    await refreshAuth()
  })

  return {
    // State
    user: readonly(user),
    token: readonly(token),
    pub: readonly(pub),
    loading: readonly(loading),
    error: readonly(error),
    isAuthenticated,
    
    // Methods
    register,
    login,
    logout,
    verifyToken,
    refreshAuth
  }
}
```

#### Vue 3 Component Example

```vue
<!-- components/AuthForm.vue -->
<template>
  <div class="auth-form">
    <div v-if="!isAuthenticated">
      <form @submit.prevent="handleSubmit">
        <h2>{{ isLogin ? 'Login' : 'Register' }}</h2>
        
        <div class="form-group">
          <input
            v-model="form.username"
            type="text"
            placeholder="Username"
            required
            :disabled="loading"
          />
        </div>
        
        <div class="form-group">
          <input
            v-model="form.password"
            type="password"
            placeholder="Password"
            required
            :disabled="loading"
          />
        </div>
        
        <div class="form-actions">
          <button type="submit" :disabled="loading">
            {{ loading ? 'Processing...' : (isLogin ? 'Login' : 'Register') }}
          </button>
          
          <button type="button" @click="toggleMode" :disabled="loading">
            {{ isLogin ? 'Need to register?' : 'Already have account?' }}
          </button>
        </div>
        
        <div v-if="error" class="error">
          {{ error }}
        </div>
      </form>
    </div>
    
    <div v-else class="user-info">
      <h2>Welcome, {{ user.sub }}!</h2>
      <p>Logged in since: {{ new Date(user.iat).toLocaleString() }}</p>
      <p>Session expires: {{ new Date(user.exp).toLocaleString() }}</p>
      
      <button @click="logout" class="logout-btn">
        Logout
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useGunAuth } from '../composables/useGunAuth.js'

const { user, loading, error, isAuthenticated, register, login, logout } = useGunAuth()

const isLogin = ref(true)
const form = reactive({
  username: '',
  password: ''
})

const toggleMode = () => {
  isLogin.value = !isLogin.value
  form.username = ''
  form.password = ''
}

const handleSubmit = async () => {
  try {
    if (isLogin.value) {
      await login(form.username, form.password)
    } else {
      await register(form.username, form.password)
      // Auto-login after successful registration
      await login(form.username, form.password)
    }
    
    // Clear form on success
    form.username = ''
    form.password = ''
  } catch (err) {
    console.error('Authentication failed:', err)
  }
}
</script>

<style scoped>
.auth-form {
  max-width: 400px;
  margin: 0 auto;
  padding: 2rem;
  border: 1px solid #ddd;
  border-radius: 8px;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 1rem;
}

.form-actions {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.form-actions button {
  padding: 0.75rem;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
}

.form-actions button[type="submit"] {
  background-color: #007bff;
  color: white;
}

.form-actions button[type="button"] {
  background-color: #f8f9fa;
  color: #6c757d;
}

.form-actions button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.error {
  color: #dc3545;
  text-align: center;
  font-size: 0.875rem;
}

.user-info {
  text-align: center;
}

.logout-btn {
  background-color: #dc3545;
  color: white;
  padding: 0.75rem 1.5rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

.logout-btn:hover {
  background-color: #c82333;
}
</style>
```

#### Vue 3 Router Integration

```javascript
// router/index.js
import { createRouter, createWebHistory } from 'vue-router'
import { useGunAuth } from '../composables/useGunAuth.js'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/Home.vue')
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: { requiresGuest: true }
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue'),
    meta: { requiresAuth: true }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation guard
router.beforeEach(async (to, from, next) => {
  const { isAuthenticated, refreshAuth } = useGunAuth()
  
  // Refresh auth state if needed
  if (!isAuthenticated.value) {
    await refreshAuth()
  }
  
  if (to.meta.requiresAuth && !isAuthenticated.value) {
    next('/login')
  } else if (to.meta.requiresGuest && isAuthenticated.value) {
    next('/dashboard')
  } else {
    next()
  }
})

export default router
```

#### Vue 3 Pinia Store Integration

```javascript
// stores/auth.js
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const GUNAUTH_URL = import.meta.env.VITE_GUNAUTH_URL

export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  const token = ref(null)
  const pub = ref(null)
  const loading = ref(false)
  const error = ref(null)

  const isAuthenticated = computed(() => !!user.value)
  const isTokenExpired = computed(() => {
    if (!user.value?.exp) return true
    return Date.now() > user.value.exp
  })

  const register = async (username, password) => {
    loading.value = true
    error.value = null
    
    try {
      const response = await fetch(`${GUNAUTH_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      
      const result = await response.json()
      
      if (result.success) {
        pub.value = result.pub
        return result
      } else {
        throw new Error(result.error)
      }
    } catch (err) {
      error.value = err.message
      throw err
    } finally {
      loading.value = false
    }
  }

  const login = async (username, password) => {
    loading.value = true
    error.value = null
    
    try {
      const response = await fetch(`${GUNAUTH_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      
      const result = await response.json()
      
      if (result.success) {
        token.value = result.token
        pub.value = result.pub
        localStorage.setItem('gunauth_token', result.token)
        localStorage.setItem('gunauth_pub', result.pub)
        
        // Verify token to get user claims
        await verifyToken(result.token, result.pub)
        
        return result
      } else {
        throw new Error(result.error)
      }
    } catch (err) {
      error.value = err.message
      throw err
    } finally {
      loading.value = false
    }
  }

  const logout = () => {
    token.value = null
    pub.value = null
    user.value = null
    error.value = null
    localStorage.removeItem('gunauth_token')
    localStorage.removeItem('gunauth_pub')
  }

  const verifyToken = async (tokenToVerify, pubKey) => {
    if (!tokenToVerify || !pubKey) return null
    
    try {
      const response = await fetch(`${GUNAUTH_URL}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: tokenToVerify, pub: pubKey })
      })
      
      const result = await response.json()
      
      if (result.success) {
        user.value = result.claims
        return result.claims
      } else {
        logout()
        return null
      }
    } catch (err) {
      console.error('Token verification failed:', err)
      logout()
      return null
    }
  }

  const initAuth = async () => {
    const storedToken = localStorage.getItem('gunauth_token')
    const storedPub = localStorage.getItem('gunauth_pub')
    
    if (storedToken && storedPub) {
      token.value = storedToken
      pub.value = storedPub
      await verifyToken(storedToken, storedPub)
    }
  }

  return {
    // State
    user,
    token,
    pub,
    loading,
    error,
    isAuthenticated,
    isTokenExpired,
    
    // Actions
    register,
    login,
    logout,
    verifyToken,
    initAuth
  }
})
```

### Environment Variables for Cloud Integration

```bash
# Common environment variables for cloud deployments
GUNAUTH_URL=https://your-gunauth-instance.com
NODE_ENV=production
PORT=3000

# GUN relay configuration
GUN_RELAYS=https://your-relay1.com/gun,https://your-relay2.com/gun

# AWS specific
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Google Cloud specific  
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Azure specific
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id
```

## 📡 API Endpoints

### POST /register
Register a new user and generate SEA key pair.

**Request:**
```json
{
  "username": "alice",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "success": true,
  "username": "alice",
  "pub": "user-public-key",
  "createdAt": 1642694400000
}
```

### POST /login
Authenticate user and return signed token.

**Request:**
```json
{
  "username": "alice",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "success": true,
  "token": "signed-jwt-token",
  "pub": "user-public-key",
  "exp": 1642698000000
}
```

### POST /verify
Verify a signed token.

**Request:**
```json
{
  "token": "signed-jwt-token",
  "pub": "user-public-key"
}
```

**Response:**
```json
{
  "success": true,
  "claims": {
    "sub": "alice",
    "iss": "https://your-app-domain.com",
    "iat": 1642694400000,
    "exp": 1642698000000
  },
  "valid": true
}
```

### GET /user/:username/pub
Get user's public key by username.

**Response:**
```json
{
  "username": "alice",
  "pub": "user-public-key",
  "createdAt": 1642694400000
}
```

## 🔗 GUN Relay Configuration

GunAuth uses multiple GUN relay peers for improved reliability and performance.

### Default Relays

The application includes several reliable public GUN relays:
- `https://gun-manhattan.herokuapp.com/gun` - Primary US relay
- `https://gunjs.herokuapp.com/gun` - Secondary US relay  
- `https://gun-us.herokuapp.com/gun` - US East coast relay
- `https://gun-eu.herokuapp.com/gun` - European relay
- `https://peer.wallie.io/gun` - Community relay
- `https://relay.peer.ooo/gun` - Peer.ooo relay
- WebSocket versions for real-time sync

### Custom Relay Configuration

For production deployments, consider using your own GUN relays:

```bash
# Set custom relays via environment variable
export GUN_RELAYS="https://your-relay1.com/gun,https://your-relay2.com/gun,wss://your-relay1.com/gun"
```

### Hosting Your Own GUN Relay

```javascript
// gun-relay-server.js
import Gun from 'gun';
import express from 'express';
import { createServer } from 'http';

const app = express();
const server = createServer(app);

// Serve GUN
app.use(Gun.serve);
server.listen(8765);

// Initialize Gun with persistence
const gun = Gun({ 
  web: server,
  file: 'data.json' // Local file storage
});

console.log('GUN relay server running on port 8765');
```

### Production Relay Best Practices

1. **Multiple Relays**: Use 3-5 relays for redundancy
2. **Geographic Distribution**: Spread relays across regions
3. **HTTPS/WSS**: Always use secure connections in production  
4. **Monitoring**: Monitor relay health and connectivity
5. **Backup**: Regular backups of relay data

3. **HTTPS/WSS**: Always use secure connections in production  
4. **Monitoring**: Monitor relay health and connectivity
5. **Backup**: Regular backups of relay data

## 🛡️ Production Considerations for Cloud Deployment

### Security Best Practices
```

## �️ Production Considerations for Cloud Deployment

### Security Best Practices

1. **HTTPS Only**: Always use HTTPS in production
2. **Rate Limiting**: Implement rate limiting for authentication endpoints
3. **Input Validation**: Validate all inputs server-side
4. **Environment Variables**: Store sensitive config in environment variables
5. **Logging**: Implement comprehensive logging for security monitoring

### Monitoring & Observability

#### AWS CloudWatch Integration
```javascript
// aws-cloudwatch-logger.js
import AWS from 'aws-sdk';

const cloudwatchlogs = new AWS.CloudWatchLogs();

export const logAuthEvent = async (event, username, success) => {
  const params = {
    logGroupName: '/aws/lambda/gunauth',
    logStreamName: new Date().toISOString().split('T')[0],
    logEvents: [{
      timestamp: Date.now(),
      message: JSON.stringify({
        event,
        username,
        success,
        timestamp: new Date().toISOString()
      })
    }]
  };
  
  try {
    await cloudwatchlogs.putLogEvents(params).promise();
  } catch (error) {
    console.error('CloudWatch logging failed:', error);
  }
};
```

#### Google Cloud Logging
```javascript
// gcp-logging.js
import { Logging } from '@google-cloud/logging';

const logging = new Logging();
const log = logging.log('gunauth');

export const logAuthEvent = async (event, username, success) => {
  const metadata = {
    resource: { type: 'global' },
    severity: success ? 'INFO' : 'WARNING'
  };
  
  const entry = log.entry(metadata, {
    event,
    username,
    success,
    timestamp: new Date().toISOString()
  });
  
  await log.write(entry);
};
```

#### Azure Application Insights
```javascript
// azure-insights.js
import appInsights from 'applicationinsights';

appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING);
appInsights.start();

const client = appInsights.defaultClient;

export const logAuthEvent = (event, username, success) => {
  client.trackEvent({
    name: 'AuthenticationEvent',
    properties: {
      event,
      username,
      success: success.toString(),
      timestamp: new Date().toISOString()
    }
  });
  
  if (!success) {
    client.trackException({
      exception: new Error(`Authentication failed for ${username}`)
    });
  }
};
```

### Scaling Considerations

#### Load Balancing
- Use cloud load balancers (ALB, Cloud Load Balancing, Azure Load Balancer)
- Implement health checks on the `/` endpoint
- Consider sticky sessions if needed for GUN synchronization

#### Database Scaling
- GUN automatically handles peer-to-peer synchronization
- Consider deploying multiple GUN relay peers for redundancy
- Monitor GUN peer connectivity and sync status

#### Caching Strategy
```javascript
// redis-cache-middleware.js
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export const cacheMiddleware = (ttl = 300) => {
  return async (req, res, next) => {
    if (req.method !== 'GET') return next();
    
    const key = `cache:${req.originalUrl}`;
    const cached = await redis.get(key);
    
    if (cached) {
      return res.json(JSON.parse(cached));
    }
    
    const originalSend = res.json;
    res.json = function(data) {
      redis.setex(key, ttl, JSON.stringify(data));
      return originalSend.call(this, data);
    };
    
    next();
  };
};
```

### High Availability Setup

#### Multi-Region Deployment
```yaml
# docker-compose.ha.yml
version: '3.8'
services:
  gunauth-primary:
    image: gunauth:latest
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://redis:6379
      - GUN_PEERS=ws://gunauth-secondary:8765,ws://gunauth-tertiary:8765
    ports:
      - "3000:3000"
      
  gunauth-secondary:
    image: gunauth:latest
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://redis:6379
      - GUN_PEERS=ws://gunauth-primary:8765,ws://gunauth-tertiary:8765
    ports:
      - "3001:3000"
      
  gunauth-tertiary:
    image: gunauth:latest
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://redis:6379
      - GUN_PEERS=ws://gunauth-primary:8765,ws://gunauth-secondary:8765
    ports:
      - "3002:3000"
      
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
      
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
```

## 🔐 Security Features

- Passwords are hashed using `SEA.work()` before storage
- Private keys are stored separately from user data
- Tokens expire after 1 hour
- Only public data is stored in GUN
- CORS enabled for browser requests
- Multiple relay peers for distributed resilience
- Dynamic issuer URL prevents token reuse across domains

## 🛠 Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Start production server
npm start
```

## 📦 Tech Stack

- **Node.js** (ESM modules)
- **Express.js** (web server)
- **GUN** (distributed database)
- **SEA** (cryptographic functions)

## 🌐 Environment Variables

- `PORT` - Server port (defaults to 3000)
- `NODE_ENV` - Environment mode
- `ISSUER_URL` - JWT issuer URL (auto-detected from request if not set)
- `GUN_RELAYS` - Comma-separated list of GUN relay URLs (uses default relays if not set)

## ⚡ Usage Example

```javascript
// Register a new user
const registerResponse = await fetch('https://your-app-domain.com/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'alice',
    password: 'secure-password'
  })
});

// Login and get token
const loginResponse = await fetch('https://your-app-domain.com/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'alice',
    password: 'secure-password'
  })
});

const { token, pub } = await loginResponse.json();

// Verify token
const verifyResponse = await fetch('https://your-app-domain.com/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token, pub })
});
```

## 📄 License

MIT

A decentralized Identity Provider built on GUN SEA
```

## 📄 License

MIT
A decentralized Identity Provider built on GUN SEA
