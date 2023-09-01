using Microsoft.AspNetCore.Identity;

public sealed class UnAuthSignInResult : SignInResult
{
    public string? TwoFactorUserIdToken { get; set; }
    public string? TwoFactorRememberMeToken { get; set; }

    public Dictionary<string, object?>? ToDictionary()
    {
        var dictionary = new Dictionary<string, object?>();
        if (TwoFactorUserIdToken is not null)
        {
            dictionary.Add(IdentityConstants.TwoFactorUserIdScheme, TwoFactorUserIdToken);
        }
        if (TwoFactorRememberMeToken is not null)
        {
            dictionary.Add(IdentityConstants.TwoFactorRememberMeScheme, TwoFactorRememberMeToken);
        }

        return dictionary.Count == 0 ? null : dictionary;
    }

    public UnAuthSignInResult(SignInResult origin)
    {
        this.IsLockedOut = origin.IsLockedOut;
        this.Succeeded = origin.Succeeded;
        this.IsNotAllowed = origin.IsNotAllowed;
        this.RequiresTwoFactor = origin.RequiresTwoFactor;
    }
}

public static class SignInResultExtensions
{
    public static UnAuthSignInResult ToUnAuth(this SignInResult? origin) =>
        new UnAuthSignInResult(origin ?? new());
}