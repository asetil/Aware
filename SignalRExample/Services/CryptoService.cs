using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;

namespace SignalRExample.Services
{
    public class CryptoService : ICryptoService
    {
        private readonly IConfiguration _configuration;
        private readonly ConcurrentDictionary<string, ClientSession> _clientSessions = new();
        private readonly Timer _cleanupTimer;

        public CryptoService(IConfiguration configuration)
        {
            _configuration = configuration;
            
            // Clean up expired sessions every 10 minutes
            _cleanupTimer = new Timer(CleanupExpiredSessions, null, TimeSpan.Zero, TimeSpan.FromMinutes(10));
        }

        public string GenerateServerKeyPair()
        {
            // Generate server private key (simplified - in production use proper key generation)
            using var rng = RandomNumberGenerator.Create();
            var serverPrivateKey = new byte[32];
            rng.GetBytes(serverPrivateKey);
            return Convert.ToBase64String(serverPrivateKey);
        }

        public string DeriveSharedSecret(string clientPublicKey, string serverPrivateKey, string clientChallenge, string serverChallenge)
        {
            // Simplified ECDH-like key derivation (in production, use proper ECDH)
            var combinedData = $"{clientPublicKey}{serverPrivateKey}{clientChallenge}{serverChallenge}";
            using var sha256 = SHA256.Create();
            var secretBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combinedData));
            return Convert.ToBase64String(secretBytes);
        }

        public EncryptedData EncryptData(string data, string sessionKey)
        {
            using var aes = Aes.Create();
            aes.Key = DeriveKeyFromString(sessionKey);
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var encryptedBytes = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

            return new EncryptedData
            {
                EncryptedText = Convert.ToBase64String(encryptedBytes),
                IV = Convert.ToBase64String(aes.IV)
            };
        }

        public string DecryptData(EncryptedData encryptedData, string sessionKey)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = DeriveKeyFromString(sessionKey);
                aes.IV = Convert.FromBase64String(encryptedData.IV);

                using var decryptor = aes.CreateDecryptor();
                var encryptedBytes = Convert.FromBase64String(encryptedData.EncryptedText);
                var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Decryption failed", ex);
            }
        }

        public bool ValidateSignature(string data, string signature, string secret)
        {
            try
            {
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                var computedSignature = Convert.ToBase64String(computedHash);
                
                return computedSignature == signature;
            }
            catch
            {
                return false;
            }
        }

        public string GenerateSecureChallenge()
        {
            using var rng = RandomNumberGenerator.Create();
            var challengeBytes = new byte[32];
            rng.GetBytes(challengeBytes);
            return Convert.ToBase64String(challengeBytes);
        }

        public bool ValidateClientHandshake(ClientHandshakeRequest request)
        {
            // Validate timestamp (allow 5 minute window)
            var requestTime = DateTimeOffset.FromUnixTimeMilliseconds(request.Timestamp);
            var now = DateTimeOffset.UtcNow;
            
            if (Math.Abs((now - requestTime).TotalMinutes) > 5)
                return false;

            // Validate client ID format
            if (string.IsNullOrEmpty(request.ClientId) || request.ClientId.Length != 64)
                return false;

            // Validate public key format
            if (string.IsNullOrEmpty(request.ClientPublicKey) || request.ClientPublicKey.Length != 64)
                return false;

            // Validate challenge format
            if (string.IsNullOrEmpty(request.Challenge))
                return false;

            return true;
        }

        public void StoreClientSession(string clientId, string sharedSecret, string sessionKey)
        {
            _clientSessions[clientId] = new ClientSession
            {
                SharedSecret = sharedSecret,
                SessionKey = sessionKey,
                CreatedAt = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow
            };
        }

        public ClientSession? GetClientSession(string clientId)
        {
            if (_clientSessions.TryGetValue(clientId, out var session))
            {
                // Update last activity
                session.LastActivity = DateTime.UtcNow;
                return session;
            }
            return null;
        }

        public void RemoveClientSession(string clientId)
        {
            _clientSessions.TryRemove(clientId, out _);
        }

        public bool ValidateSessionKeyHash(string clientId, string sessionKeyHash)
        {
            var session = GetClientSession(clientId);
            if (session == null) return false;

            using var sha256 = SHA256.Create();
            var computedHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(session.SessionKey));
            var computedHashString = Convert.ToBase64String(computedHash);

            return computedHashString == sessionKeyHash;
        }

        private byte[] DeriveKeyFromString(string keyString)
        {
            using var sha256 = SHA256.Create();
            var keyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
            return keyBytes;
        }

        private void CleanupExpiredSessions(object? state)
        {
            var expiredSessions = _clientSessions
                .Where(kvp => kvp.Value.LastActivity < DateTime.UtcNow.AddHours(-2)) // 2 hour timeout
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var sessionId in expiredSessions)
            {
                _clientSessions.TryRemove(sessionId, out _);
            }
        }

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
        }
    }

    public class ClientSession
    {
        public string SharedSecret { get; set; } = string.Empty;
        public string SessionKey { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
    }
}