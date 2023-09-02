namespace UnAuth;

internal sealed class UnAuthLoginRequest
{
    // changed from Username to Email after preview 7
    public string? Email { get; init; }
    public string? Password { get; init; }
    public string? TwoFactorCode { get; init; }
    public string? TwoFactorRecoveryCode { get; init; }
}
