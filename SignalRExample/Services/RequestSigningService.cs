using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

namespace SignalRExample.Services
{
    public class RequestSigningService : IRequestSigningService
    {
        private readonly IConfiguration _configuration;
        private readonly ConcurrentDictionary<string, DateTime> _usedNonces = new();
        private readonly Timer _cleanupTimer;

        public RequestSigningService(IConfiguration configuration)
        {
            _configuration = configuration;
            // Clean up expired nonces every 5 minutes
            _cleanupTimer = new Timer(CleanupExpiredNonces, null, TimeSpan.Zero, TimeSpan.FromMinutes(5));
        }

        public string SignRequest(string method, string path, string body, string timestamp, string userId)
        {
            var secretKey = _configuration["JwtSettings:SecretKey"] ?? "your-super-secret-key-that-should-be-in-config";
            var stringToSign = $"{method}|{path}|{body}|{timestamp}|{userId}";
            
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
            return Convert.ToBase64String(signatureBytes);
        }

        public bool ValidateRequestSignature(HttpRequest request, string signature, string timestamp, string userId)
        {
            try
            {
                // Check timestamp (allow 5 minute window)
                if (!long.TryParse(timestamp, out var timestampLong))
                    return false;

                var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestampLong);
                var now = DateTimeOffset.UtcNow;
                
                if (Math.Abs((now - requestTime).TotalMinutes) > 5)
                    return false;

                // Read request body
                request.EnableBuffering();
                var body = "";
                if (request.ContentLength > 0)
                {
                    using var reader = new StreamReader(request.Body, Encoding.UTF8, true, 1024, true);
                    body = reader.ReadToEndAsync().Result;
                    request.Body.Position = 0;
                }

                var expectedSignature = SignRequest(request.Method, request.Path, body, timestamp, userId);
                return signature == expectedSignature;
            }
            catch
            {
                return false;
            }
        }

        public string GenerateNonce()
        {
            var nonce = Guid.NewGuid().ToString("N");
            _usedNonces[nonce] = DateTime.UtcNow.AddMinutes(10); // Expire after 10 minutes
            return nonce;
        }

        public bool ValidateNonce(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
                return false;

            if (!_usedNonces.TryGetValue(nonce, out var expiry))
                return false;

            if (expiry < DateTime.UtcNow)
            {
                _usedNonces.TryRemove(nonce, out _);
                return false;
            }

            // Remove nonce after use (single use)
            _usedNonces.TryRemove(nonce, out _);
            return true;
        }

        private void CleanupExpiredNonces(object? state)
        {
            var expiredNonces = _usedNonces
                .Where(kvp => kvp.Value < DateTime.UtcNow)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var nonce in expiredNonces)
            {
                _usedNonces.TryRemove(nonce, out _);
            }
        }

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
        }
    }
}