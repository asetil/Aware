using SignalRExample.Services;
using System.Text.Json;

namespace SignalRExample.Middleware
{
    public class BrowserFingerprintMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IBrowserFingerprintService _fingerprintService;
        private readonly ILogger<BrowserFingerprintMiddleware> _logger;

        public BrowserFingerprintMiddleware(
            RequestDelegate next,
            IBrowserFingerprintService fingerprintService,
            ILogger<BrowserFingerprintMiddleware> logger)
        {
            _next = next;
            _fingerprintService = fingerprintService;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip fingerprinting for non-API requests
            if (!context.Request.Path.StartsWithSegments("/api"))
            {
                await _next(context);
                return;
            }

            // Check if client appears to be a suspicious API client
            if (_fingerprintService.IsSuspiciousClient(context.Request))
            {
                _logger.LogWarning($"Suspicious client detected from {context.Connection.RemoteIpAddress}: {context.Request.Headers["User-Agent"]}");
                
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync(JsonSerializer.Serialize(new 
                { 
                    error = "Access denied",
                    message = "This endpoint requires browser access"
                }));
                return;
            }

            // Generate and store browser fingerprint
            var fingerprint = _fingerprintService.GenerateFingerprint(context.Request);
            context.Items["BrowserFingerprint"] = fingerprint;

            await _next(context);
        }
    }
}