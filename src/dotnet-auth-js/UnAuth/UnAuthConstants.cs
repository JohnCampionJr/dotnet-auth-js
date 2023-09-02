namespace UnAuth;
public static class UnAuthConstants
{
    public static readonly string IdentityScheme = "Identity.UnAuth";
    public static readonly string TwoFactorUserIdCookieScheme = "UnAuth.2FCookie.UserId";
    public static readonly string TwoFactorRememberMeCookieScheme = "UnAuth.2FCookie.RememberMe";
}

internal static class UnAuthContextItems
{
    public static readonly string CookieMode = "UnAuthCookieMode";
    public static readonly string Bearer = "UnAuthBearer";
    public static readonly string TwoFactorUserId = "UnAuthTwoFactorUserId";
    public static readonly string TwoFactorRememberMe = "UnAuthTwoFactorRememberMe";
} 