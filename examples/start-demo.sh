#!/bin/bash

# GunAuth Cross-Domain Test Setup Script

echo "🚀 Starting GunAuth Cross-Domain Test Environment..."

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $1 is already in use"
        return 1
    else
        return 0
    fi
}

# Kill any existing processes on our ports
echo "🧹 Cleaning up existing processes..."
pkill -f "python3 -m http.server" 2>/dev/null
pkill -f "node index.js" 2>/dev/null

# Start GunAuth server
echo "🔐 Starting GunAuth server on port 8000..."
cd /Users/danraeder/Documents/GitHub/gunauth
PORT=8000 node index.js &
GUNAUTH_PID=$!

# Wait for server to start
sleep 2

# Start App 1 server
echo "📱 Starting App 1 on port 8001..."
cd /Users/danraeder/Documents/GitHub/gunauth/examples
python3 -m http.server 8001 &
APP1_PID=$!

# Start App 2 server  
echo "📱 Starting App 2 on port 8002..."
python3 -m http.server 8002 &
APP2_PID=$!

# Wait a moment for servers to fully start
sleep 3

echo ""
echo "✅ All servers started successfully!"
echo ""
echo "🌐 Access URLs:"
echo "   • GunAuth Server:  http://localhost:8000"
echo "   • Application 1:   http://localhost:8001/app1.html"
echo "   • Application 2:   http://localhost:8002/app2.html"
echo "   • Session Bridge:  http://localhost:8000/session-bridge.html"
echo ""
echo "🧪 Test Instructions:"
echo "✅ SSO Authentication Flow (OAuth2-like redirect):"
echo "   1. Open App 1: http://localhost:8001/app1.html"
echo "   2. Register a new user (or use existing: testuser/password123)"
echo "   3. Click 'Login via SSO' - redirects to server for authentication"
echo "   4. Enter credentials - redirects back with session"
echo "   5. Open App 2: http://localhost:8002/app2.html"
echo "   6. Session should be shared across domains via Gun P2P"
echo ""
echo "🔐 Direct Authentication Flow (Client-side key storage):"
echo "   1. Use Register/Login forms directly in the apps"
echo "   2. Private keys stored encrypted in browser localStorage"
echo "   3. Most secure - keys never leave your device"
echo ""
echo "🛡️ Security: Private keys now stored securely client-side only!"
echo ""
echo "💡 You can also create test users by running: npm run test:cross-domain"
echo ""
echo "Press Ctrl+C to stop all servers..."

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping all servers..."
    kill $GUNAUTH_PID $APP1_PID $APP2_PID 2>/dev/null
    pkill -f "python3 -m http.server" 2>/dev/null
    pkill -f "node index.js" 2>/dev/null
    echo "✅ All servers stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Keep script running
wait
