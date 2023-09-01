

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

public enum UnAuthSchemes
{
    Bearer,
    Cookie,
    Both
}

public sealed class UnAuthOptions : AuthenticationSchemeOptions
{
    public string? ChallengeScheme { get; set; } = IdentityConstants.BearerScheme;
    public UnAuthSchemes AllowedSchemes { get; set; } = UnAuthSchemes.Both;
    
    /// <summary>
    /// Controls how much time the two factor user id token will remain valid from the point it is created.
    /// This is the token that temporarily stores the user info while waiting for a two factor code
    /// The expiration information is stored in the protected token. Because of that, an expired token will be rejected
    /// even if it is passed to the server after the client should have purged it.
    /// </summary>
    /// <remarks>
    /// Defaults to 10 minutes.
    /// </remarks>
    public TimeSpan TwoFactorUserIdTokenExpiration { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Controls how much time the two factor remember token will remain valid from the point it is created.
    /// This is the token that allows two factor to be bypassed and should be stored in a cookie.
    /// The expiration information is stored in the protected token. Because of that, an expired token will be rejected
    /// even if it is passed to the server after the client should have purged it.
    /// </summary>
    /// <remarks>
    /// Defaults to 14 days.
    /// </remarks>
    public TimeSpan TwoFactorRememberTokenExpiration { get; set; } = TimeSpan.FromDays(14);
    
    private ISecureDataFormat<AuthenticationTicket>? _twoFactorUserIdTokenProtector;
    private ISecureDataFormat<AuthenticationTicket>? _twoFactorRememberTokenProtector;
    
    /// <summary>
    /// If set, the <see cref="TwoFactorUserIdTokenProtector"/> is used to protect and unprotect the identity and other properties which are stored in the
    /// two factor user id pre-code token. If not provided, one will be created using <see cref="TicketDataFormat"/> and the <see cref="IDataProtectionProvider"/>
    /// from the application <see cref="IServiceProvider"/>.
    /// </summary>
    public ISecureDataFormat<AuthenticationTicket> TwoFactorUserIdTokenProtector
    {
        get => _twoFactorUserIdTokenProtector ?? throw new InvalidOperationException($"{nameof(TwoFactorUserIdTokenProtector)} was not set.");
        set => _twoFactorUserIdTokenProtector = value;
    }

    /// <summary>
    /// If set, the <see cref="TwoFactorRememberTokenProtector"/> is used to protect and unprotect the identity and other properties which are stored in the
    /// two factor remember me  token. If not provided, one will be created using <see cref="TicketDataFormat"/> and the <see cref="IDataProtectionProvider"/>
    /// from the application <see cref="IServiceProvider"/>.
    /// </summary>
    public ISecureDataFormat<AuthenticationTicket> TwoFactorRememberTokenProtector
    {
        get => _twoFactorRememberTokenProtector ?? throw new InvalidOperationException($"{nameof(TwoFactorRememberTokenProtector)} was not set.");
        set => _twoFactorRememberTokenProtector = value;
    }

}