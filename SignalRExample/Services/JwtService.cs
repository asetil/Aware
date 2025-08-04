using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

namespace SignalRExample.Services
{
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly SymmetricSecurityKey _key;
        private readonly ConcurrentDictionary<string, RefreshTokenData> _refreshTokens = new();
        private readonly ConcurrentDictionary<string, DateTime> _browserTokens = new();

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
            var secretKey = _configuration["JwtSettings:SecretKey"] ?? "your-super-secret-key-that-should-be-in-config";
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        }

        public string GenerateAccessToken(string userId, string browserFingerprint)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("browser_fingerprint", browserFingerprint),
                new Claim("token_type", "access")
            };

            var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
            
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"] ?? "YourAppIssuer",
                audience: _configuration["JwtSettings:Audience"] ?? "YourAppAudience",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(5), // Very short-lived access token
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        public string GenerateBrowserToken(string browserFingerprint)
        {
            var tokenData = $"{browserFingerprint}:{DateTime.UtcNow:yyyy-MM-dd-HH}"; // Changes every hour
            var hash = ComputeHash(tokenData);
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{tokenData}:{hash}"));
            
            _browserTokens[token] = DateTime.UtcNow.AddHours(1);
            return token;
        }

        public bool ValidateBrowserToken(string token, string browserFingerprint)
        {
            try
            {
                if (!_browserTokens.ContainsKey(token))
                    return false;

                if (_browserTokens[token] < DateTime.UtcNow)
                {
                    _browserTokens.TryRemove(token, out _);
                    return false;
                }

                var tokenBytes = Convert.FromBase64String(token);
                var tokenString = Encoding.UTF8.GetString(tokenBytes);
                var parts = tokenString.Split(':');
                
                if (parts.Length != 3)
                    return false;

                var storedFingerprint = parts[0];
                var timestamp = parts[1];
                var storedHash = parts[2];

                var expectedData = $"{storedFingerprint}:{timestamp}";
                var expectedHash = ComputeHash(expectedData);

                return storedFingerprint == browserFingerprint && 
                       storedHash == expectedHash;
            }
            catch
            {
                return false;
            }
        }

        public ClaimsPrincipal? ValidateAccessToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _key,
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["JwtSettings:Issuer"] ?? "YourAppIssuer",
                    ValidateAudience = true,
                    ValidAudience = _configuration["JwtSettings:Audience"] ?? "YourAppAudience",
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                return principal;
            }
            catch
            {
                return null;
            }
        }

        public bool ValidateRefreshToken(string refreshToken, string userId)
        {
            if (!_refreshTokens.TryGetValue(refreshToken, out var tokenData))
                return false;

            if (tokenData.ExpiryDate < DateTime.UtcNow || tokenData.UserId != userId)
            {
                _refreshTokens.TryRemove(refreshToken, out _);
                return false;
            }

            return true;
        }

        public void InvalidateRefreshToken(string refreshToken)
        {
            _refreshTokens.TryRemove(refreshToken, out _);
        }

        private string ComputeHash(string input)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input + _configuration["JwtSettings:SecretKey"]));
            return Convert.ToBase64String(hashBytes);
        }

        private class RefreshTokenData
        {
            public string UserId { get; set; } = string.Empty;
            public DateTime ExpiryDate { get; set; }
        }
    }
}