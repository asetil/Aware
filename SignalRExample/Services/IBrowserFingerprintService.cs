namespace SignalRExample.Services
{
    public interface IBrowserFingerprintService
    {
        string GenerateFingerprint(HttpRequest request);
        bool IsSuspiciousClient(HttpRequest request);
        bool ValidateFingerprint(string fingerprint, HttpRequest request);
    }
}