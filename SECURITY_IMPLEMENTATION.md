# Advanced API Security Implementation

This solution implements multiple layers of security to prevent unauthorized request replay attacks from tools like Postman, curl, or other API clients. While it's impossible to completely prevent all attacks, this implementation makes it significantly harder for attackers to abuse your API.

## Security Layers Implemented

### 1. 🔍 Browser Fingerprinting & Client Detection
- **Purpose**: Detect and block non-browser clients
- **How it works**: Analyzes HTTP headers to identify suspicious patterns
- **Implementation**: `BrowserFingerprintService` and `BrowserFingerprintMiddleware`

**Detected patterns:**
- Missing browser-specific headers (Accept-Language, Accept-Encoding, etc.)
- Suspicious User-Agent strings (curl, postman, python, etc.)
- Missing Sec-Fetch headers (modern browsers include these)
- Inconsistent header combinations

### 2. 🕒 Short-lived Access Tokens with Automatic Refresh
- **Purpose**: Limit the window of opportunity for token abuse
- **How it works**: Access tokens expire in 5 minutes, requiring frequent refresh
- **Implementation**: `JwtService` with automatic refresh mechanism

**Features:**
- Access tokens expire in 5 minutes
- Refresh tokens stored in secure HTTP-only cookies
- Browser-specific tokens for additional validation
- Automatic token refresh before expiration

### 3. 🔐 Request Signing for Critical Endpoints
- **Purpose**: Cryptographically verify request authenticity
- **How it works**: Critical requests must include HMAC signatures
- **Implementation**: `RequestSigningService` and `RequestSigningMiddleware`

**Process:**
1. Client requests a nonce from the server
2. Client signs the request (method + path + body + timestamp + userId)
3. Server validates the signature and nonce
4. Nonces are single-use to prevent replay attacks

### 4. ⚡ Rate Limiting
- **Purpose**: Prevent abuse through excessive requests
- **How it works**: Limits requests per minute per IP/user
- **Implementation**: Built-in ASP.NET Core rate limiting

**Configuration:**
- 10 requests per minute window
- Queue up to 5 additional requests
- Applied to all API endpoints

### 5. 🍪 Secure Cookie Management
- **Purpose**: Protect refresh tokens and browser validation
- **How it works**: Uses secure, HTTP-only cookies
- **Implementation**: Configured in `AuthController`

**Cookie settings:**
- HTTP-only (not accessible via JavaScript)
- Secure (HTTPS only)
- SameSite=Strict (CSRF protection)
- Proper expiration times

## How Each Layer Prevents Attacks

### Against Postman/curl Requests:
1. **Browser fingerprinting** detects non-browser user agents and header patterns
2. **Missing browser tokens** in cookies will cause authentication to fail
3. **Rate limiting** prevents rapid-fire automated requests
4. **Request signing** requires cryptographic knowledge that's hard to replicate

### Against Copied Browser Requests:
1. **Short token lifetime** means copied tokens expire quickly
2. **Browser fingerprint validation** ensures tokens work only from original browser
3. **Nonce system** prevents exact request replay
4. **Automatic refresh** happens in the background, making token copying ineffective

### Against Advanced Attackers:
1. **Multiple validation layers** make it difficult to bypass all protections
2. **Logging and monitoring** help detect attack attempts
3. **Request signing** requires knowledge of server secret
4. **Browser-specific tokens** tie authentication to specific browser sessions

## Usage Instructions

### Running the Backend:

```bash
cd SignalRExample
dotnet restore
dotnet run
```

The API will be available at `https://localhost:5001`

### Testing the Frontend:

1. Install dependencies:
```bash
cd SignalRExampleUI
npm install
```

2. Open `secure-index.html` in a browser (serve via HTTP server, not file://)

3. Use the demo credentials:
   - Username: `demo`
   - Password: `password`

### Testing Security Features:

1. **Login** - Try the login functionality
2. **Test Protected API** - Access user profile (requires authentication)
3. **Test Sensitive API** - Access signed endpoint (requires request signing)
4. **Test Rate Limiting** - Send multiple requests rapidly
5. **Try Postman/curl** - Attempt to copy requests (should be blocked)

## API Endpoints

### Public Endpoints:
- `GET /api/health` - Health check (no authentication required)

### Authentication Endpoints:
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Token refresh (requires valid refresh token)
- `POST /api/auth/logout` - User logout
- `GET /api/auth/nonce` - Get nonce for request signing

### Protected Endpoints:
- `GET /api/user/profile` - Get user profile (requires authentication)
- `POST /api/user/action` - Perform user action (requires authentication)

### Sensitive Endpoints (require request signing):
- `GET /api/user/sensitive` - Access sensitive data (requires signed request)

## Configuration

### JWT Settings (appsettings.json):
```json
{
  "JwtSettings": {
    "SecretKey": "your-super-secret-256-bit-key",
    "Issuer": "SignalRExampleApp",
    "Audience": "SignalRExampleClient"
  }
}
```

**⚠️ Important**: Change the secret key in production!

### Rate Limiting Configuration:
```csharp
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("api", limiterOptions =>
    {
        limiterOptions.PermitLimit = 10;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
    });
});
```

## Security Considerations

### What This Solution Provides:
✅ Significantly harder to copy and replay requests  
✅ Detection and blocking of common API tools  
✅ Short window for token abuse  
✅ Protection against request replay attacks  
✅ Rate limiting to prevent abuse  
✅ Comprehensive logging for monitoring  

### What This Solution Cannot Prevent:
❌ Determined attackers with browser automation tools  
❌ Attacks from compromised legitimate browsers  
❌ Social engineering attacks  
❌ Server-side vulnerabilities  

### Additional Recommendations:

1. **Use HTTPS everywhere** - Never send tokens over HTTP
2. **Implement proper logging** - Monitor for attack patterns
3. **Add IP-based restrictions** - Block suspicious IP ranges
4. **Use CAPTCHA** - For sensitive operations
5. **Implement account lockouts** - After multiple failed attempts
6. **Add device fingerprinting** - More sophisticated client detection
7. **Use Content Security Policy** - Prevent XSS attacks
8. **Regular security audits** - Keep security measures up to date

## Monitoring and Alerts

The implementation includes extensive logging. Monitor for:
- Suspicious client detections
- Failed authentication attempts
- Rate limiting triggers
- Invalid request signatures
- Unusual browser fingerprint patterns

## Customization

### Adding New Signed Endpoints:
Add endpoint paths to `RequestSigningMiddleware._signedEndpoints`

### Adjusting Browser Detection:
Modify patterns in `BrowserFingerprintService`

### Changing Token Lifetime:
Update expiration in `JwtService.GenerateAccessToken`

### Custom Rate Limiting:
Modify rate limiting configuration in `Program.cs`

This multi-layered approach makes it significantly more difficult for unauthorized clients to abuse your API while maintaining a smooth experience for legitimate browser-based users.