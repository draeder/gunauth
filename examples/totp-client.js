/**
 * Pure JavaScript TOTP implementation for browsers
 * No Node.js dependencies - uses Web Crypto API
 */

class TOTPClient {
    constructor() {
        this.algorithm = 'SHA-1';
        this.digits = 6;
        this.period = 30; // 30 second windows
    }

    /**
     * Generate a random TOTP secret
     * @returns {string} - Base32 encoded secret
     */
    generateSecret() {
        const bytes = new Uint8Array(20); // 160 bits
        crypto.getRandomValues(bytes);
        return this.base32Encode(bytes);
    }

    /**
     * Generate a deterministic TOTP secret based on user credentials (improved JWT token handling)
     * @param {string} username - User's username
     * @param {string} keyMaterial - User's private key or other key material (e.g., JWT token)
     * @returns {Promise<string>} - Base32 encoded deterministic secret
     */
    async generateDeterministicSecret(username, keyMaterial) {
        const encoder = new TextEncoder();
        
        // Handle JWT tokens by hashing them first for consistent seed generation
        let cleanKeyMaterial = keyMaterial;
        if (keyMaterial.startsWith('SEA{') || keyMaterial.length > 200) {
            // Hash JWT tokens to get consistent, manageable key material
            const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(keyMaterial));
            cleanKeyMaterial = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
        
        // Create a deterministic seed from username and cleaned key material
        const seedString = `gunauth_totp_${username}_${cleanKeyMaterial}`;
        const seedBytes = encoder.encode(seedString);
        
        // Use PBKDF2 to derive a consistent 160-bit secret
        const baseKey = await crypto.subtle.importKey(
            'raw',
            seedBytes,
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: encoder.encode('gunauth_totp_salt_2025'),
                iterations: 10000,
                hash: 'SHA-256'
            },
            baseKey,
            160 // 160 bits = 20 bytes
        );
        
        const secretBytes = new Uint8Array(derivedBits);
        return this.base32Encode(secretBytes);
    }    /**
     * Generate TOTP code for current time
     * @param {string} secret - Base32 encoded secret
     * @param {number} time - Unix timestamp (optional, defaults to now)
     * @returns {Promise<string>} - 6-digit TOTP code
     */
    async generateTOTP(secret, time = Date.now()) {
        const timeStep = Math.floor(time / 1000 / this.period);
        const secretBytes = this.base32Decode(secret);
        
        // Convert time step to 8-byte big-endian
        const timeBuffer = new ArrayBuffer(8);
        const timeView = new DataView(timeBuffer);
        timeView.setUint32(4, timeStep, false); // Big-endian
        
        // Import secret key
        const key = await crypto.subtle.importKey(
            'raw',
            secretBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );
        
        // Calculate HMAC
        const signature = await crypto.subtle.sign('HMAC', key, timeBuffer);
        const signatureBytes = new Uint8Array(signature);
        
        // Dynamic truncation
        const offset = signatureBytes[signatureBytes.length - 1] & 0xf;
        const code = (
            ((signatureBytes[offset] & 0x7f) << 24) |
            ((signatureBytes[offset + 1] & 0xff) << 16) |
            ((signatureBytes[offset + 2] & 0xff) << 8) |
            (signatureBytes[offset + 3] & 0xff)
        ) % Math.pow(10, this.digits);
        
        return code.toString().padStart(this.digits, '0');
    }

    /**
     * Verify TOTP code with time window tolerance
     * @param {string} token - 6-digit code to verify
     * @param {string} secret - Base32 encoded secret
     * @param {number} window - Number of time periods to check (default 1 = ±30s)
     * @returns {Promise<boolean>} - True if valid
     */
    async verifyTOTP(token, secret, window = 1) {
        const currentTime = Date.now();
        
        for (let i = -window; i <= window; i++) {
            const testTime = currentTime + (i * this.period * 1000);
            const expectedCode = await this.generateTOTP(secret, testTime);
            
            if (token === expectedCode) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Generate QR code URL for authenticator apps
     * @param {string} secret - Base32 encoded secret
     * @param {string} username - User identifier
     * @param {string} issuer - Service name
     * @returns {string} - otpauth:// URL
     */
    generateQRCodeURL(secret, username, issuer = 'GunAuth') {
        const params = new URLSearchParams({
            secret: secret,
            issuer: issuer,
            algorithm: this.algorithm,
            digits: this.digits.toString(),
            period: this.period.toString()
        });
        
        return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?${params}`;
    }

    /**
     * Generate QR code as data URL using a simple QR library
     * @param {string} text - Text to encode
     * @returns {string} - Data URL for QR code image
     */
    async generateQRCodeDataURL(text) {
        // Simple QR code generation for demo - in production use a proper library
        // For now, return a placeholder that shows the URL
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 200;
        const ctx = canvas.getContext('2d');
        
        // Simple placeholder QR code visualization
        ctx.fillStyle = '#000';
        ctx.fillRect(0, 0, 200, 200);
        ctx.fillStyle = '#fff';
        ctx.font = '10px Arial';
        ctx.fillText('QR Code:', 10, 20);
        ctx.fillText(text.substring(0, 30) + '...', 10, 40);
        ctx.fillText('Use URL above', 10, 60);
        ctx.fillText('with authenticator', 10, 80);
        
        return canvas.toDataURL();
    }

    /**
     * Base32 encode bytes
     */
    base32Encode(bytes) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let result = '';
        let bits = 0;
        let value = 0;
        
        for (const byte of bytes) {
            value = (value << 8) | byte;
            bits += 8;
            
            while (bits >= 5) {
                result += alphabet[(value >>> (bits - 5)) & 31];
                bits -= 5;
            }
        }
        
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 31];
        }
        
        return result;
    }

    /**
     * Base32 decode to bytes
     */
    base32Decode(base32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const bytes = [];
        let bits = 0;
        let value = 0;
        
        for (const char of base32.toUpperCase()) {
            const index = alphabet.indexOf(char);
            if (index === -1) continue;
            
            value = (value << 5) | index;
            bits += 5;
            
            if (bits >= 8) {
                bytes.push((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        
        return new Uint8Array(bytes);
    }

    /**
     * Store TOTP secret securely in localStorage
     * @param {string} username - User identifier
     * @param {string} secret - Base32 encoded secret
     * @param {string} password - User password for encryption
     */
    async storeSecret(username, secret, password) {
        try {
            // Encrypt secret with user password
            const key = await this.deriveKey(password, username);
            const encrypted = await this.encrypt(secret, key);
            
            localStorage.setItem(`totp_secret_${username}`, JSON.stringify({
                encrypted: Array.from(encrypted.ciphertext),
                iv: Array.from(encrypted.iv),
                timestamp: Date.now()
            }));
            
            return true;
        } catch (error) {
            console.error('Failed to store TOTP secret:', error);
            return false;
        }
    }

    /**
     * Load TOTP secret from localStorage
     * @param {string} username - User identifier  
     * @param {string} password - User password for decryption
     * @returns {Promise<string|null>} - Base32 encoded secret or null
     */
    async loadSecret(username, password) {
        try {
            const stored = localStorage.getItem(`totp_secret_${username}`);
            if (!stored) return null;
            
            const data = JSON.parse(stored);
            const key = await this.deriveKey(password, username);
            
            const encrypted = {
                ciphertext: new Uint8Array(data.encrypted),
                iv: new Uint8Array(data.iv)
            };
            
            const decrypted = await this.decrypt(encrypted, key);
            return decrypted;
        } catch (error) {
            console.error('Failed to load TOTP secret:', error);
            return null;
        }
    }

    /**
     * Derive encryption key from password (with improved JWT token handling)
     */
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        
        // If the password looks like a JWT token, hash it first to avoid encoding issues
        let keyMaterial = password;
        if (password.startsWith('SEA{') || password.length > 200) {
            // Hash long/complex passwords (like JWT tokens) first
            const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(password));
            keyMaterial = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
        
        const importedKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(keyMaterial),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode(salt),
                iterations: 100000,
                hash: 'SHA-256'
            },
            importedKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data with AES-GCM
     */
    async encrypt(data, key) {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encoder.encode(data)
        );
        
        return {
            ciphertext: new Uint8Array(ciphertext),
            iv: iv
        };
    }

    /**
     * Decrypt data with AES-GCM
     */
    async decrypt(encrypted, key) {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: encrypted.iv },
            key,
            encrypted.ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
}

// Export for use in browser or modules
if (typeof window !== 'undefined') {
    window.TOTPClient = TOTPClient;
} else if (typeof module !== 'undefined' && module.exports) {
    module.exports = TOTPClient;
}
