namespace SignalRExample.Services
{
    public interface ICryptoService
    {
        string GenerateServerKeyPair();
        string DeriveSharedSecret(string clientPublicKey, string serverPrivateKey, string clientChallenge, string serverChallenge);
        EncryptedData EncryptData(string data, string sessionKey);
        string DecryptData(EncryptedData encryptedData, string sessionKey);
        bool ValidateSignature(string data, string signature, string secret);
        string GenerateSecureChallenge();
        bool ValidateClientHandshake(ClientHandshakeRequest request);
    }

    public class EncryptedData
    {
        public string EncryptedText { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
    }

    public class ClientHandshakeRequest
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientPublicKey { get; set; } = string.Empty;
        public long Timestamp { get; set; }
        public string Challenge { get; set; } = string.Empty;
    }
}