namespace SignalRExample.Services
{
    public interface IRequestSigningService
    {
        string SignRequest(string method, string path, string body, string timestamp, string userId);
        bool ValidateRequestSignature(HttpRequest request, string signature, string timestamp, string userId);
        string GenerateNonce();
        bool ValidateNonce(string nonce);
    }
}