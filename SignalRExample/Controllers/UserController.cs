using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;

namespace SignalRExample.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    [EnableRateLimiting("api")]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;

        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }

        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var browserFingerprint = HttpContext.Items["BrowserFingerprint"]?.ToString();

            _logger.LogInformation($"Profile accessed by user {userId}");

            return Ok(new
            {
                userId = userId,
                username = "demo",
                email = "demo@example.com",
                browserFingerprint = browserFingerprint,
                lastAccess = DateTime.UtcNow
            });
        }

        [HttpGet("sensitive")]
        public async Task<IActionResult> GetSensitiveData()
        {
            // This endpoint requires request signing (configured in middleware)
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            _logger.LogInformation($"Sensitive data accessed by user {userId}");

            return Ok(new
            {
                sensitiveData = "This is protected sensitive information",
                accessTime = DateTime.UtcNow,
                userId = userId
            });
        }

        [HttpPost("action")]
        public async Task<IActionResult> PerformAction([FromBody] ActionRequest request)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            _logger.LogInformation($"Action '{request.Action}' performed by user {userId}");

            return Ok(new
            {
                message = $"Action '{request.Action}' completed successfully",
                timestamp = DateTime.UtcNow,
                userId = userId
            });
        }
    }

    public class ActionRequest
    {
        public string Action { get; set; } = string.Empty;
        public string Data { get; set; } = string.Empty;
    }
}