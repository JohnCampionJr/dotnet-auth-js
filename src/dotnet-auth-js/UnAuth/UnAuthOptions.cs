// these are not implemented yet, just setting up for future work

public static class UnAuthOptions
{
    public static string FrontEndBaseUrl { get; set; } = "https://localhost:5002";
    public static string ExternalLoginFrontEndReturnUrl { get; set; } = "/external-login-return";
    public static string ExternalLoginTokenCookieName { get; set; } = "UnAuth.ExternalLoginToken";
}
