
internal sealed class TwoFactorLoginRequest
{
    public required string? TwoFactorCode { get; init; }
    public string? TwoFactorRecoveryCode { get; init; }
}