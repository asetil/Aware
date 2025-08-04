// Secure API client for the protected backend
class SecureApiClient {
    constructor(baseUrl = 'https://localhost:5001') {
        this.baseUrl = baseUrl;
        this.accessToken = null;
        this.browserFingerprint = null;
        this.isRefreshing = false;
        this.failedQueue = [];
    }

    // Initialize the client and login
    async login(username, password) {
        try {
            const response = await fetch(`${this.baseUrl}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', // Include cookies
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                throw new Error('Login failed');
            }

            const data = await response.json();
            this.accessToken = data.accessToken;
            this.browserFingerprint = data.browserFingerprint;

            // Set up automatic token refresh
            this.setupTokenRefresh(data.expiresIn);

            return data;
        } catch (error) {
            console.error('Login error:', error);
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
                // Redirect to login or handle re-authentication
                this.handleAuthenticationError();
            }
        }, refreshTime);
    }

    // Refresh the access token
    async refreshToken() {
        if (this.isRefreshing) {
            return new Promise((resolve, reject) => {
                this.failedQueue.push({ resolve, reject });
            });
        }

        this.isRefreshing = true;

        try {
            const response = await fetch(`${this.baseUrl}/api/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Token refresh failed');
            }

            const data = await response.json();
            this.accessToken = data.accessToken;

            // Process queued requests
            this.processQueue(null, this.accessToken);
            
            // Setup next refresh
            this.setupTokenRefresh(data.expiresIn);

            return data;
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

    // Make a secure API request
    async makeRequest(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.accessToken) {
            headers['Authorization'] = `Bearer ${this.accessToken}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers,
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
                        credentials: 'include'
                    });
                } catch (refreshError) {
                    this.handleAuthenticationError();
                    throw refreshError;
                }
            }

            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Make a signed request for sensitive endpoints
    async makeSignedRequest(endpoint, options = {}) {
        try {
            // Get a nonce for the request
            const nonceResponse = await this.makeRequest('/api/auth/nonce');
            const nonceData = await nonceResponse.json();
            const nonce = nonceData.nonce;

            // Generate timestamp
            const timestamp = Math.floor(Date.now() / 1000).toString();

            // Calculate signature
            const body = options.body || '';
            const signature = await this.signRequest(options.method || 'GET', endpoint, body, timestamp);

            // Add signing headers
            const headers = {
                'X-Request-Signature': signature,
                'X-Request-Timestamp': timestamp,
                'X-Request-Nonce': nonce,
                ...options.headers
            };

            return await this.makeRequest(endpoint, {
                ...options,
                headers
            });
        } catch (error) {
            console.error('Signed request failed:', error);
            throw error;
        }
    }

    // Sign a request (simplified - in production, use Web Crypto API)
    async signRequest(method, path, body, timestamp) {
        // This is a simplified signature for demo purposes
        // In production, you should use HMAC with the secret key from server
        const stringToSign = `${method}|${path}|${body}|${timestamp}|demo-user-id`;
        
        // For demo, we'll use a simple hash (replace with proper HMAC in production)
        const encoder = new TextEncoder();
        const data = encoder.encode(stringToSign);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        return btoa(hashHex); // Base64 encode
    }

    // Handle authentication errors
    handleAuthenticationError() {
        this.accessToken = null;
        this.browserFingerprint = null;
        
        // Clear any stored auth data
        // In a real app, redirect to login page
        console.warn('Authentication failed - please log in again');
        
        // You could dispatch an event or call a callback here
        if (this.onAuthError) {
            this.onAuthError();
        }
    }

    // Logout
    async logout() {
        try {
            await this.makeRequest('/api/auth/logout', { method: 'POST' });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.accessToken = null;
            this.browserFingerprint = null;
        }
    }

    // Convenience methods for common HTTP verbs
    async get(endpoint) {
        const response = await this.makeRequest(endpoint, { method: 'GET' });
        return await response.json();
    }

    async post(endpoint, data) {
        const response = await this.makeRequest(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        return await response.json();
    }

    async getSecure(endpoint) {
        const response = await this.makeSignedRequest(endpoint, { method: 'GET' });
        return await response.json();
    }

    async postSecure(endpoint, data) {
        const response = await this.makeSignedRequest(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        return await response.json();
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureApiClient;
} else {
    window.SecureApiClient = SecureApiClient;
}