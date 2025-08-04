using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SignalRExample.Services
{
    public class BrowserFingerprintService : IBrowserFingerprintService
    {
        private readonly string[] _suspiciousUserAgents = {
            "postman", "curl", "wget", "httpclient", "python", "java", "go-http", "okhttp", "axios"
        };

        private readonly string[] _requiredBrowserHeaders = {
            "Accept", "Accept-Language", "Accept-Encoding", "DNT", "Connection"
        };

        public string GenerateFingerprint(HttpRequest request)
        {
            var fingerprint = new
            {
                UserAgent = request.Headers["User-Agent"].ToString(),
                AcceptLanguage = request.Headers["Accept-Language"].ToString(),
                AcceptEncoding = request.Headers["Accept-Encoding"].ToString(),
                Accept = request.Headers["Accept"].ToString(),
                Connection = request.Headers["Connection"].ToString(),
                DNT = request.Headers["DNT"].ToString(),
                Upgrade = request.Headers["Upgrade-Insecure-Requests"].ToString(),
                SecFetchSite = request.Headers["Sec-Fetch-Site"].ToString(),
                SecFetchMode = request.Headers["Sec-Fetch-Mode"].ToString(),
                SecFetchUser = request.Headers["Sec-Fetch-User"].ToString(),
                SecFetchDest = request.Headers["Sec-Fetch-Dest"].ToString(),
                HasReferer = !string.IsNullOrEmpty(request.Headers["Referer"]),
                ContentLength = request.ContentLength?.ToString() ?? "0"
            };

            var json = JsonSerializer.Serialize(fingerprint);
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(json));
            return Convert.ToBase64String(hashBytes);
        }

        public bool IsSuspiciousClient(HttpRequest request)
        {
            var userAgent = request.Headers["User-Agent"].ToString().ToLowerInvariant();
            
            // Check for common API client user agents
            if (_suspiciousUserAgents.Any(suspicious => userAgent.Contains(suspicious)))
                return true;

            // Check for missing browser headers
            var missingBrowserHeaders = _requiredBrowserHeaders.Count(header => 
                string.IsNullOrEmpty(request.Headers[header]));
            
            if (missingBrowserHeaders > 2)
                return true;

            // Check for suspicious header combinations
            var hasSecFetchHeaders = request.Headers.ContainsKey("Sec-Fetch-Site");
            var hasModernBrowserUA = userAgent.Contains("chrome") || userAgent.Contains("firefox") || 
                                   userAgent.Contains("safari") || userAgent.Contains("edge");

            // Modern browsers should have Sec-Fetch headers
            if (hasModernBrowserUA && !hasSecFetchHeaders)
                return true;

            // Check for missing referer in non-direct navigation
            var secFetchSite = request.Headers["Sec-Fetch-Site"].ToString();
            var hasReferer = !string.IsNullOrEmpty(request.Headers["Referer"]);
            
            if (secFetchSite == "same-origin" && !hasReferer)
                return true;

            // Check for suspicious Accept headers
            var accept = request.Headers["Accept"].ToString();
            if (string.IsNullOrEmpty(accept) || accept == "*/*")
                return true;

            return false;
        }

        public bool ValidateFingerprint(string fingerprint, HttpRequest request)
        {
            var currentFingerprint = GenerateFingerprint(request);
            return fingerprint == currentFingerprint;
        }
    }
}