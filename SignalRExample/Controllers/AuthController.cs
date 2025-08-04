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
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IJwtService jwtService,
            IBrowserFingerprintService fingerprintService,
            IRequestSigningService signingService,
            ILogger<AuthController> logger)
        {
            _jwtService = jwtService;
            _fingerprintService = fingerprintService;
            _signingService = signingService;
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
}