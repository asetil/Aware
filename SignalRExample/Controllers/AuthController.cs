using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SignalRExample.Services;
using System.Security.Claims;

namespace SignalRExample.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("api")]
    public class AuthController : ControllerBase
    {
        private readonly IJwtService _jwtService;
        private readonly IBrowserFingerprintService _fingerprintService;
        private readonly IRequestSigningService _signingService;
        private readonly ICryptoService _cryptoService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IJwtService jwtService,
            IBrowserFingerprintService fingerprintService,
            IRequestSigningService signingService,
            ICryptoService cryptoService,
            ILogger<AuthController> logger)
        {
            _jwtService = jwtService;
            _fingerprintService = fingerprintService;
            _signingService = signingService;
            _cryptoService = cryptoService;
            _logger = logger;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Simple demo authentication - replace with your actual authentication logic
            if (request.Username != "demo" || request.Password != "password")
            {
                return Unauthorized(new { error = "Invalid credentials" });
            }

            var userId = "demo-user-id";
            var browserFingerprint = HttpContext.Items["BrowserFingerprint"]?.ToString() ?? "";
            
            // Generate tokens
            var accessToken = _jwtService.GenerateAccessToken(userId, browserFingerprint);
            var refreshToken = _jwtService.GenerateRefreshToken();
            var browserToken = _jwtService.GenerateBrowserToken(browserFingerprint);

            // Set secure cookies
            SetSecureCookie("refreshToken", refreshToken, TimeSpan.FromDays(7));
            SetSecureCookie("browserToken", browserToken, TimeSpan.FromHours(1));

            _logger.LogInformation($"User {userId} logged in successfully");

            return Ok(new
            {
                accessToken = accessToken,
                expiresIn = 300, // 5 minutes
                tokenType = "Bearer",
                browserFingerprint = browserFingerprint
            });
        }

        [HttpPost("refresh")]
        [Authorize]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var browserToken = Request.Cookies["browserToken"];
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var browserFingerprint = HttpContext.Items["BrowserFingerprint"]?.ToString() ?? "";

            if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new { error = "Invalid refresh token" });
            }

            // Validate browser token
            if (string.IsNullOrEmpty(browserToken) || !_jwtService.ValidateBrowserToken(browserToken, browserFingerprint))
            {
                _logger.LogWarning($"Invalid browser token for user {userId}");
                return Unauthorized(new { error = "Browser validation failed" });
            }

            // Validate refresh token
            if (!_jwtService.ValidateRefreshToken(refreshToken, userId))
            {
                _logger.LogWarning($"Invalid refresh token for user {userId}");
                return Unauthorized(new { error = "Invalid refresh token" });
            }

            // Generate new access token
            var newAccessToken = _jwtService.GenerateAccessToken(userId, browserFingerprint);

            return Ok(new
            {
                accessToken = newAccessToken,
                expiresIn = 300, // 5 minutes
                tokenType = "Bearer"
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (!string.IsNullOrEmpty(refreshToken))
            {
                _jwtService.InvalidateRefreshToken(refreshToken);
            }

            // Clear cookies
            Response.Cookies.Delete("refreshToken");
            Response.Cookies.Delete("browserToken");

            return Ok(new { message = "Logged out successfully" });
        }

        [HttpGet("nonce")]
        [Authorize]
        public async Task<IActionResult> GetNonce()
        {
            var nonce = _signingService.GenerateNonce();
            return Ok(new { nonce = nonce });
        }

        [HttpPost("handshake")]
        public async Task<IActionResult> Handshake([FromBody] ClientHandshakeRequest request)
        {
            try
            {
                // Validate handshake request
                if (!_cryptoService.ValidateClientHandshake(request))
                {
                    return BadRequest(new { error = "Invalid handshake data" });
                }

                // Generate server key pair
                var serverPrivateKey = _cryptoService.GenerateServerKeyPair();
                var serverPublicKey = ComputeServerPublicKey(serverPrivateKey);
                var serverChallenge = _cryptoService.GenerateSecureChallenge();

                // Derive shared secret
                var sharedSecret = _cryptoService.DeriveSharedSecret(
                    request.ClientPublicKey, 
                    serverPrivateKey, 
                    request.Challenge, 
                    serverChallenge
                );

                // Generate session key (will be derived by client)
                var sessionKeyMaterial = $"{sharedSecret}{DateTime.UtcNow.Ticks}";
                
                // Store session temporarily (client will derive session key)
                _cryptoService.StoreClientSession(request.ClientId, sharedSecret, sessionKeyMaterial);

                _logger.LogInformation($"Secure handshake completed for client: {request.ClientId}");

                return Ok(new
                {
                    serverPublicKey = serverPublicKey,
                    serverChallenge = serverChallenge,
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Handshake failed");
                return StatusCode(500, new { error = "Handshake failed" });
            }
        }

        [HttpPost("cryptologin")]
        public async Task<IActionResult> CryptoLogin([FromBody] EncryptedLoginRequest request)
        {
            try
            {
                var clientId = Request.Headers["X-Client-Id"].FirstOrDefault();
                if (string.IsNullOrEmpty(clientId))
                {
                    return BadRequest(new { error = "Missing client ID" });
                }

                var session = _cryptoService.GetClientSession(clientId);
                if (session == null)
                {
                    return Unauthorized(new { error = "No active session" });
                }

                // Validate signature
                if (!_cryptoService.ValidateSignature(request.EncryptedData, request.Signature, session.SharedSecret))
                {
                    return Unauthorized(new { error = "Invalid signature" });
                }

                // Decrypt login data
                var decryptedData = _cryptoService.DecryptData(new EncryptedData
                {
                    EncryptedText = request.EncryptedData,
                    IV = request.IV
                }, session.SessionKey);

                var loginData = System.Text.Json.JsonSerializer.Deserialize<CryptoLoginData>(decryptedData);
                if (loginData == null)
                {
                    return BadRequest(new { error = "Invalid login data" });
                }

                // Validate credentials (simplified - replace with your authentication logic)
                if (loginData.Username != "demo" || !ValidatePasswordHash(loginData.PasswordHash, loginData.Salt, "password"))
                {
                    return Unauthorized(new { error = "Invalid credentials" });
                }

                var userId = "demo-user-id";
                var browserFingerprint = HttpContext.Items["BrowserFingerprint"]?.ToString() ?? "";
                
                // Generate tokens
                var accessToken = _jwtService.GenerateAccessToken(userId, browserFingerprint);
                var refreshToken = _jwtService.GenerateRefreshToken();
                var browserToken = _jwtService.GenerateBrowserToken(browserFingerprint);

                // Set secure cookies
                SetSecureCookie("refreshToken", refreshToken, TimeSpan.FromDays(7));
                SetSecureCookie("browserToken", browserToken, TimeSpan.FromHours(1));

                // Prepare encrypted response
                var responseData = new
                {
                    accessToken = accessToken,
                    expiresIn = 300,
                    tokenType = "Bearer",
                    browserFingerprint = browserFingerprint
                };

                var encryptedResponse = _cryptoService.EncryptData(
                    System.Text.Json.JsonSerializer.Serialize(responseData), 
                    session.SessionKey
                );

                _logger.LogInformation($"Crypto login successful for user: {userId}");

                return Ok(new
                {
                    encryptedData = encryptedResponse.EncryptedText,
                    iv = encryptedResponse.IV
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Crypto login failed");
                return StatusCode(500, new { error = "Login failed" });
            }
        }

        [HttpPost("cryptorefresh")]
        [Authorize]
        public async Task<IActionResult> CryptoRefresh([FromBody] EncryptedRefreshRequest request)
        {
            try
            {
                var clientId = Request.Headers["X-Client-Id"].FirstOrDefault();
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(userId))
                {
                    return BadRequest(new { error = "Missing required data" });
                }

                var session = _cryptoService.GetClientSession(clientId);
                if (session == null)
                {
                    return Unauthorized(new { error = "No active session" });
                }

                // Validate signature
                if (!_cryptoService.ValidateSignature(request.EncryptedData, request.Signature, session.SharedSecret))
                {
                    return Unauthorized(new { error = "Invalid signature" });
                }

                var refreshToken = Request.Cookies["refreshToken"];
                var browserToken = Request.Cookies["browserToken"];
                var browserFingerprint = HttpContext.Items["BrowserFingerprint"]?.ToString() ?? "";

                // Validate refresh token and browser token
                if (string.IsNullOrEmpty(refreshToken) || !_jwtService.ValidateRefreshToken(refreshToken, userId))
                {
                    return Unauthorized(new { error = "Invalid refresh token" });
                }

                if (string.IsNullOrEmpty(browserToken) || !_jwtService.ValidateBrowserToken(browserToken, browserFingerprint))
                {
                    return Unauthorized(new { error = "Browser validation failed" });
                }

                // Generate new access token
                var newAccessToken = _jwtService.GenerateAccessToken(userId, browserFingerprint);

                var responseData = new
                {
                    accessToken = newAccessToken,
                    expiresIn = 300,
                    tokenType = "Bearer"
                };

                var encryptedResponse = _cryptoService.EncryptData(
                    System.Text.Json.JsonSerializer.Serialize(responseData), 
                    session.SessionKey
                );

                return Ok(new
                {
                    encryptedData = encryptedResponse.EncryptedText,
                    iv = encryptedResponse.IV
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Crypto refresh failed");
                return StatusCode(500, new { error = "Refresh failed" });
            }
        }

        [HttpPost("cryptologout")]
        [Authorize]
        public async Task<IActionResult> CryptoLogout([FromBody] EncryptedLogoutRequest request)
        {
            try
            {
                var clientId = Request.Headers["X-Client-Id"].FirstOrDefault();
                if (!string.IsNullOrEmpty(clientId))
                {
                    _cryptoService.RemoveClientSession(clientId);
                }

                var refreshToken = Request.Cookies["refreshToken"];
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    _jwtService.InvalidateRefreshToken(refreshToken);
                }

                // Clear cookies
                Response.Cookies.Delete("refreshToken");
                Response.Cookies.Delete("browserToken");

                return Ok(new { message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Crypto logout failed");
                return StatusCode(500, new { error = "Logout failed" });
            }
        }

        private string ComputeServerPublicKey(string serverPrivateKey)
        {
            // Simplified public key derivation (in production, use proper key derivation)
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var publicKeyBytes = sha256.ComputeHash(Convert.FromBase64String(serverPrivateKey));
            return Convert.ToBase64String(publicKeyBytes);
        }

        private bool ValidatePasswordHash(string providedHash, string salt, string expectedPassword)
        {
            // Simplified password validation - in production, use proper password hashing
            // This should match the client-side PBKDF2 implementation
            try
            {
                using var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(
                    expectedPassword, 
                    Convert.FromBase64String(salt), 
                    10000, 
                    System.Security.Cryptography.HashAlgorithmName.SHA256
                );
                var expectedHash = Convert.ToBase64String(pbkdf2.GetBytes(32));
                return expectedHash == providedHash;
            }
            catch
            {
                return false;
            }
        }

        private void SetSecureCookie(string name, string value, TimeSpan expiry)
        {
            Response.Cookies.Append(name, value, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.Add(expiry)
            });
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class EncryptedLoginRequest
    {
        public string EncryptedData { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
    }

    public class EncryptedRefreshRequest
    {
        public string EncryptedData { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
    }

    public class EncryptedLogoutRequest
    {
        public string EncryptedData { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
    }

    public class CryptoLoginData
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public long Timestamp { get; set; }
    }
}