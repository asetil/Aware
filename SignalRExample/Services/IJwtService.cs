using System.Security.Claims;

namespace SignalRExample.Services
{
    public interface IJwtService
    {
        string GenerateAccessToken(string userId, string browserFingerprint);
        string GenerateRefreshToken();
        ClaimsPrincipal? ValidateAccessToken(string token);
        bool ValidateRefreshToken(string refreshToken, string userId);
        void InvalidateRefreshToken(string refreshToken);
        string GenerateBrowserToken(string browserFingerprint);
        bool ValidateBrowserToken(string token, string browserFingerprint);
    }
}