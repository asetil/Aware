// Advanced Secure API client using CryptoJS for proper cryptographic operations
class CryptoSecureApiClient {
    constructor(baseUrl = 'https://localhost:5001') {
        this.baseUrl = baseUrl;
        this.accessToken = null;
        this.browserFingerprint = null;
        this.clientSecret = null; // Derived from server handshake
        this.sessionKey = null;   // Session-specific encryption key
        this.isRefreshing = false;
        this.failedQueue = [];
        
        // Generate a unique client identifier
        this.clientId = this.generateClientId();
        
        // Initialize client-side entropy
        this.initializeEntropy();
    }

    // Generate a unique client identifier using browser characteristics
    generateClientId() {
        const browserData = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenResolution: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            deviceMemory: navigator.deviceMemory || 0,
            timestamp: Date.now()
        };
        
        const dataString = JSON.stringify(browserData);
        return CryptoJS.SHA256(dataString).toString();
    }

    // Initialize client-side entropy for additional randomness
    initializeEntropy() {
        this.entropy = {
            mouseEvents: [],
            keyEvents: [],
            touchEvents: [],
            timestamps: []
        };

        // Collect mouse movement entropy (if available)
        if (typeof document !== 'undefined') {
            let mouseEventCount = 0;
            document.addEventListener('mousemove', (e) => {
                if (mouseEventCount < 10) { // Limit collection
                    this.entropy.mouseEvents.push({
                        x: e.clientX,
                        y: e.clientY,
                        t: Date.now()
                    });
                    mouseEventCount++;
                }
            });
        }
    }

    // Generate entropy-based random values
    generateEntropyBasedRandom() {
        const entropyData = {
            mouse: this.entropy.mouseEvents,
            timestamp: Date.now(),
            random: Math.random(),
            performance: typeof performance !== 'undefined' ? performance.now() : Date.now()
        };
        
        return CryptoJS.SHA256(JSON.stringify(entropyData)).toString().substring(0, 32);
    }

    // Derive a shared secret through a secure handshake
    async performSecureHandshake() {
        try {
            // Generate client key pair (simplified - in production use proper key exchange)
            const clientPrivateKey = this.generateEntropyBasedRandom();
            const clientPublicKey = CryptoJS.SHA256(clientPrivateKey + this.clientId).toString();
            
            const handshakeData = {
                clientId: this.clientId,
                clientPublicKey: clientPublicKey,
                timestamp: Date.now(),
                challenge: CryptoJS.lib.WordArray.random(32).toString()
            };

            const response = await fetch(`${this.baseUrl}/api/auth/handshake`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(handshakeData)
            });

            if (!response.ok) {
                throw new Error('Handshake failed');
            }

            const serverResponse = await response.json();
            
            // Derive shared secret (simplified ECDH-like)
            this.clientSecret = CryptoJS.SHA256(
                clientPrivateKey + 
                serverResponse.serverPublicKey + 
                handshakeData.challenge +
                serverResponse.serverChallenge
            ).toString();

            // Generate session key
            this.sessionKey = CryptoJS.SHA256(
                this.clientSecret + 
                Date.now() + 
                this.generateEntropyBasedRandom()
            ).toString();

            return serverResponse;
        } catch (error) {
            console.error('Secure handshake failed:', error);
            throw error;
        }
    }

    // Enhanced login with crypto handshake
    async login(username, password) {
        try {
            // First perform secure handshake
            await this.performSecureHandshake();

            // Hash password client-side with salt
            const salt = CryptoJS.lib.WordArray.random(32).toString();
            const hashedPassword = CryptoJS.PBKDF2(password, salt, {
                keySize: 256/32,
                iterations: 10000
            }).toString();

            // Encrypt login payload
            const loginPayload = {
                username: username,
                passwordHash: hashedPassword,
                salt: salt,
                clientId: this.clientId,
                timestamp: Date.now()
            };

            const encryptedPayload = this.encryptPayload(loginPayload);

            const response = await fetch(`${this.baseUrl}/api/auth/cryptologin`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Client-Id': this.clientId,
                    'X-Session-Key-Hash': CryptoJS.SHA256(this.sessionKey).toString()
                },
                credentials: 'include',
                body: JSON.stringify({
                    encryptedData: encryptedPayload.encrypted,
                    iv: encryptedPayload.iv,
                    signature: this.signData(encryptedPayload.encrypted)
                })
            });

            if (!response.ok) {
                throw new Error('Crypto login failed');
            }

            const encryptedResponse = await response.json();
            const decryptedData = this.decryptPayload({
                encrypted: encryptedResponse.encryptedData,
                iv: encryptedResponse.iv
            });

            this.accessToken = decryptedData.accessToken;
            this.browserFingerprint = decryptedData.browserFingerprint;

            // Set up automatic token refresh
            this.setupTokenRefresh(decryptedData.expiresIn);

            return decryptedData;
        } catch (error) {
            console.error('Crypto login error:', error);
            throw error;
        }
    }

    // Encrypt payload using AES with session key
    encryptPayload(data) {
        const dataString = JSON.stringify(data);
        const iv = CryptoJS.lib.WordArray.random(16);
        
        const encrypted = CryptoJS.AES.encrypt(dataString, this.sessionKey, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        return {
            encrypted: encrypted.toString(),
            iv: iv.toString()
        };
    }

    // Decrypt payload using AES with session key
    decryptPayload(encryptedData) {
        const decrypted = CryptoJS.AES.decrypt(encryptedData.encrypted, this.sessionKey, {
            iv: CryptoJS.enc.Hex.parse(encryptedData.iv),
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
    }

    // Sign data using HMAC-SHA256
    signData(data) {
        return CryptoJS.HmacSHA256(data, this.clientSecret).toString();
    }

    // Generate proper HMAC signature for requests
    generateRequestSignature(method, path, body, timestamp, nonce) {
        const stringToSign = [method, path, body, timestamp, nonce, this.clientId].join('|');
        return CryptoJS.HmacSHA256(stringToSign, this.clientSecret).toString();
    }

    // Generate cryptographically secure nonce
    generateSecureNonce() {
        const entropy = this.generateEntropyBasedRandom();
        const timestamp = Date.now();
        const random = CryptoJS.lib.WordArray.random(32).toString();
        
        return CryptoJS.SHA256(entropy + timestamp + random).toString();
    }

    // Make encrypted API request
    async makeEncryptedRequest(endpoint, options = {}) {
        if (!this.sessionKey) {
            throw new Error('No session key available. Please login first.');
        }

        const url = `${this.baseUrl}${endpoint}`;
        const timestamp = Date.now().toString();
        const nonce = this.generateSecureNonce();
        const body = options.body || '';

        // Generate signature
        const signature = this.generateRequestSignature(
            options.method || 'GET',
            endpoint,
            body,
            timestamp,
            nonce
        );

        // Encrypt the body if present
        let encryptedBody = null;
        if (body) {
            const encrypted = this.encryptPayload(JSON.parse(body));
            encryptedBody = JSON.stringify({
                encryptedData: encrypted.encrypted,
                iv: encrypted.iv
            });
        }

        const headers = {
            'Content-Type': 'application/json',
            'X-Client-Id': this.clientId,
            'X-Request-Signature': signature,
            'X-Request-Timestamp': timestamp,
            'X-Request-Nonce': nonce,
            'X-Session-Key-Hash': CryptoJS.SHA256(this.sessionKey).toString(),
            ...options.headers
        };

        if (this.accessToken) {
            headers['Authorization'] = `Bearer ${this.accessToken}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                method: options.method || 'GET',
                headers,
                body: encryptedBody,
                credentials: 'include'
            });

            // Handle 401 (token expired)
            if (response.status === 401 && this.accessToken) {
                try {
                    await this.refreshToken();
                    // Retry the request with new token
                    headers['Authorization'] = `Bearer ${this.accessToken}`;
                    return await fetch(url, {
                        ...options,
                        headers,
                        body: encryptedBody,
                        credentials: 'include'
                    });
                } catch (refreshError) {
                    this.handleAuthenticationError();
                    throw refreshError;
                }
            }

            // Decrypt response if encrypted
            if (response.headers.get('X-Encrypted-Response') === 'true') {
                const encryptedResponse = await response.json();
                const decryptedData = this.decryptPayload({
                    encrypted: encryptedResponse.encryptedData,
                    iv: encryptedResponse.iv
                });
                
                // Create a new Response object with decrypted data
                return new Response(JSON.stringify(decryptedData), {
                    status: response.status,
                    statusText: response.statusText,
                    headers: response.headers
                });
            }

            return response;
        } catch (error) {
            console.error('Encrypted API request failed:', error);
            throw error;
        }
    }

    // Setup automatic token refresh
    setupTokenRefresh(expiresIn) {
        // Refresh token 30 seconds before it expires
        const refreshTime = (expiresIn - 30) * 1000;
        
        setTimeout(async () => {
            try {
                await this.refreshToken();
            } catch (error) {
                console.error('Token refresh failed:', error);
                this.handleAuthenticationError();
            }
        }, refreshTime);
    }

    // Refresh the access token with encryption
    async refreshToken() {
        if (this.isRefreshing) {
            return new Promise((resolve, reject) => {
                this.failedQueue.push({ resolve, reject });
            });
        }

        this.isRefreshing = true;

        try {
            const refreshPayload = {
                clientId: this.clientId,
                timestamp: Date.now(),
                sessionKeyHash: CryptoJS.SHA256(this.sessionKey).toString()
            };

            const encryptedPayload = this.encryptPayload(refreshPayload);

            const response = await fetch(`${this.baseUrl}/api/auth/cryptorefresh`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json',
                    'X-Client-Id': this.clientId,
                    'X-Session-Key-Hash': CryptoJS.SHA256(this.sessionKey).toString()
                },
                credentials: 'include',
                body: JSON.stringify({
                    encryptedData: encryptedPayload.encrypted,
                    iv: encryptedPayload.iv,
                    signature: this.signData(encryptedPayload.encrypted)
                })
            });

            if (!response.ok) {
                throw new Error('Token refresh failed');
            }

            const encryptedResponse = await response.json();
            const decryptedData = this.decryptPayload({
                encrypted: encryptedResponse.encryptedData,
                iv: encryptedResponse.iv
            });

            this.accessToken = decryptedData.accessToken;

            // Process queued requests
            this.processQueue(null, this.accessToken);
            
            // Setup next refresh
            this.setupTokenRefresh(decryptedData.expiresIn);

            return decryptedData;
        } catch (error) {
            this.processQueue(error, null);
            throw error;
        } finally {
            this.isRefreshing = false;
        }
    }

    // Process queued requests after token refresh
    processQueue(error, token) {
        this.failedQueue.forEach(({ resolve, reject }) => {
            if (error) {
                reject(error);
            } else {
                resolve(token);
            }
        });
        
        this.failedQueue = [];
    }

    // Handle authentication errors
    handleAuthenticationError() {
        this.accessToken = null;
        this.browserFingerprint = null;
        this.clientSecret = null;
        this.sessionKey = null;
        
        console.warn('Authentication failed - please log in again');
        
        if (this.onAuthError) {
            this.onAuthError();
        }
    }

    // Convenience methods for encrypted requests
    async getEncrypted(endpoint) {
        const response = await this.makeEncryptedRequest(endpoint, { method: 'GET' });
        return await response.json();
    }

    async postEncrypted(endpoint, data) {
        const response = await this.makeEncryptedRequest(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        return await response.json();
    }

    // Generate client challenge for additional security
    generateClientChallenge() {
        const challenge = {
            timestamp: Date.now(),
            random: CryptoJS.lib.WordArray.random(32).toString(),
            entropy: this.generateEntropyBasedRandom(),
            clientId: this.clientId
        };
        
        return CryptoJS.SHA256(JSON.stringify(challenge)).toString();
    }

    // Validate server challenge response
    validateServerChallenge(serverChallenge, expectedResponse) {
        const computed = CryptoJS.HmacSHA256(serverChallenge, this.clientSecret).toString();
        return computed === expectedResponse;
    }

    // Secure logout with proper cleanup
    async logout() {
        try {
            if (this.sessionKey) {
                const logoutPayload = {
                    clientId: this.clientId,
                    timestamp: Date.now(),
                    reason: 'user_logout'
                };

                const encryptedPayload = this.encryptPayload(logoutPayload);

                await fetch(`${this.baseUrl}/api/auth/cryptologout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.accessToken}`,
                        'Content-Type': 'application/json',
                        'X-Client-Id': this.clientId
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        encryptedData: encryptedPayload.encrypted,
                        iv: encryptedPayload.iv,
                        signature: this.signData(encryptedPayload.encrypted)
                    })
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            // Clear all sensitive data
            this.handleAuthenticationError();
        }
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoSecureApiClient;
} else {
    window.CryptoSecureApiClient = CryptoSecureApiClient;
}