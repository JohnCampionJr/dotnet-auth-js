using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System;

public sealed class CompositeIdentityHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
     : SignInAuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var bearerResult = await Context.AuthenticateAsync(IdentityConstants.BearerScheme);

        // Only try to authenticate with the application cookie if there is no bearer token.
        if (!bearerResult.None)
        {
            return bearerResult;
        }

        // Cookie auth will return AuthenticateResult.NoResult() like bearer auth just did if there is no cookie.
        return await Context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
    }

    protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        throw new NotImplementedException();
    }

    protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        throw new NotImplementedException();
    }
}