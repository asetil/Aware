using SignalRExample.Services;
using System.Text.Json;
using System.Security.Claims;

namespace SignalRExample.Middleware
{
    public class RequestSigningMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IRequestSigningService _signingService;
        private readonly ILogger<RequestSigningMiddleware> _logger;

        // Endpoints that require request signing
        private readonly string[] _signedEndpoints = {
            "/api/auth/refresh",
            "/api/user/sensitive",
            "/api/admin"
        };

        public RequestSigningMiddleware(
            RequestDelegate next,
            IRequestSigningService signingService,
            ILogger<RequestSigningMiddleware> logger)
        {
            _next = next;
            _signingService = signingService;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check if this endpoint requires signing
            var requiresSigning = _signedEndpoints.Any(endpoint => 
                context.Request.Path.StartsWithSegments(endpoint));

            if (requiresSigning)
            {
                var signature = context.Request.Headers["X-Request-Signature"].FirstOrDefault();
                var timestamp = context.Request.Headers["X-Request-Timestamp"].FirstOrDefault();
                var nonce = context.Request.Headers["X-Request-Nonce"].FirstOrDefault();

                if (string.IsNullOrEmpty(signature) || string.IsNullOrEmpty(timestamp) || string.IsNullOrEmpty(nonce))
                {
                    _logger.LogWarning($"Missing required headers for signed endpoint: {context.Request.Path}");
                    await WriteUnauthorizedResponse(context, "Missing required security headers");
                    return;
                }

                // Validate nonce (prevents replay attacks)
                if (!_signingService.ValidateNonce(nonce))
                {
                    _logger.LogWarning($"Invalid or replayed nonce for endpoint: {context.Request.Path}");
                    await WriteUnauthorizedResponse(context, "Invalid or replayed request");
                    return;
                }

                // Get user ID from JWT token
                var userId = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    await WriteUnauthorizedResponse(context, "Authentication required");
                    return;
                }

                // Validate request signature
                if (!_signingService.ValidateRequestSignature(context.Request, signature, timestamp, userId))
                {
                    _logger.LogWarning($"Invalid request signature for user {userId} on endpoint: {context.Request.Path}");
                    await WriteUnauthorizedResponse(context, "Invalid request signature");
                    return;
                }
            }

            await _next(context);
        }

        private async Task WriteUnauthorizedResponse(HttpContext context, string message)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new 
            { 
                error = "Unauthorized",
                message = message
            }));
        }
    }
}