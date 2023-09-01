using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Microsoft.Extensions.DependencyInjection;

public static class UnAuthPolicies
{
    public static void AddUnAuthPolicies(this AuthorizationOptions a)
    {
        a.AddPolicy(
            UnAuthConstants.BearerOnlyPolicy,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.BearerScheme);
                p.RequireAuthenticatedUser();
            }
        );
        a.AddPolicy(
            UnAuthConstants.CookieOnlyPolicy,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
                p.RequireAuthenticatedUser();
            }
        );
    }
}
