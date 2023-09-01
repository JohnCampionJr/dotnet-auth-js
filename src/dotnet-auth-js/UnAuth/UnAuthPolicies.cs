using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Microsoft.Extensions.DependencyInjection;

public static class UnAuthPolicies
{
    
    public static readonly string BearerOnly = "UnAuth.BearerPolicy";
    public static readonly string CookieOnly = "UnAuth.CookiePolicy";

    public static void AddUnAuthPolicies(this AuthorizationOptions a)
    {
        a.AddPolicy(
            UnAuthPolicies.BearerOnly,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.BearerScheme);
                p.RequireAuthenticatedUser();
            }
        );
        a.AddPolicy(
            UnAuthPolicies.CookieOnly,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
                p.RequireAuthenticatedUser();
            }
        );
    }
}
