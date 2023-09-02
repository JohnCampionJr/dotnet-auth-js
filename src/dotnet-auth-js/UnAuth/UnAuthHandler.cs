using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace UnAuth;

internal sealed class UnAuthHandler(
    UnAuthTokenService tokenService,
    IOptionsMonitor<UnAuthOptions> optionsMonitor,
    IAuthenticationSchemeProvider schemeProvider,
    IAuthenticationHandlerProvider handlers,
    ILoggerFactory loggerFactory,
    UrlEncoder urlEncoder
) : SignInAuthenticationHandler<UnAuthOptions>(optionsMonitor, loggerFactory, urlEncoder)
{
    private static readonly AuthenticateResult FailedUnprotectingToken = AuthenticateResult.Fail(
        "Unprotected token failed"
    );
    private static readonly AuthenticateResult TokenExpired = AuthenticateResult.Fail(
        "Token expired"
    );

    private bool? CookieMode()
    {
        // the options cannot be overridden by request
        if (Options.AllowedSchemes == UnAuthSchemes.Bearer) return false;
        
        if (Context.Items.TryGetValue(UnAuthContextItems.CookieMode, out var obj) && obj is bool mode)
        {
            return mode;
        }

        return null;
    }

    private bool BearerMode() => Options.AllowedSchemes != UnAuthSchemes.Cookie;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var cookieMode = CookieMode();

        if (Scheme.Name == UnAuthConstants.IdentityScheme)
        {

            if (cookieMode is not true && BearerMode())
            {
                var bearerResult = await Context.AuthenticateAsync(IdentityConstants.BearerScheme);
                if (bearerResult != AuthenticateResult.NoResult())
                {
                    return bearerResult;
                }
            }

            // Cookie auth will return AuthenticateResult.NoResult() like bearer auth just did if there is no cookie.
            if (cookieMode is not false && await schemeProvider.GetSchemeAsync(IdentityConstants.ApplicationScheme) is not null)
                return await Context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            
            return AuthenticateResult.NoResult();
        }

        if (Scheme.Name == IdentityConstants.TwoFactorUserIdScheme)
        {
            if (cookieMode is not false && await schemeProvider.GetSchemeAsync(UnAuthConstants.TwoFactorUserIdCookieScheme) is not null) {                
                var cookieResult = await Context.AuthenticateAsync(UnAuthConstants.TwoFactorUserIdCookieScheme);

                if (cookieMode is true) return cookieResult;

                if (cookieResult.Succeeded)
                {
                    return cookieResult;
                }
            }
            else if (cookieMode is true)
            {
                // if cookie mode is specifically requested and provider not registered, throw exception similar to core code
                throw new InvalidOperationException("The UnAuth.TwoFactorUserCookieScheme has not been registered");
            }

            if (BearerMode())
            {
                var token = GetTokenOrNull("TwoFactorUserIdToken");
                if (token is null)
                {
                    return AuthenticateResult.NoResult();
                }

                var ticket = Options.TwoFactorUserIdTokenProtector.Unprotect(token);

                if (ticket?.Properties?.ExpiresUtc is not { } expiresUtc)
                {
                    return FailedUnprotectingToken;
                }

                if (TimeProvider.GetUtcNow() >= expiresUtc)
                {
                    return TokenExpired;
                }

                return AuthenticateResult.Success(ticket);
            }
        }

        if (Scheme.Name == IdentityConstants.TwoFactorRememberMeScheme)
        {
            if (cookieMode is not false && await schemeProvider.GetSchemeAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme) is not null)
            {
                var cookieResult = await Context.AuthenticateAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme);

                if (cookieMode is true) return cookieResult;

                if (cookieResult.Succeeded)
                {
                    return cookieResult;
                }
            }
            else if (cookieMode is true)
            {
                // if cookie mode is specifically requested and provider not registered, throw exception similar to core code
                throw new InvalidOperationException("The UnAuth.TwoFactorRememberCookie Scheme has not been registered");
            }

            if (BearerMode())
            {

                var token = GetTokenOrNull("TwoFactorRemember");
                if (token is null)
                {
                    return AuthenticateResult.NoResult();
                }

                var ticket = Options.TwoFactorRememberTokenProtector.Unprotect(token);

                if (ticket?.Properties?.ExpiresUtc is not { } expiresUtc)
                {
                    return FailedUnprotectingToken;
                }

                if (TimeProvider.GetUtcNow() >= expiresUtc)
                {
                    return TokenExpired;
                }

                return AuthenticateResult.Success(ticket);
            }
        }

        throw new ArgumentException($"{Scheme.Name} is an unsupported Scheme type for UnAuth");
    }

    protected override async Task HandleSignInAsync(
        ClaimsPrincipal user,
        AuthenticationProperties? properties
    )
    {
        var cookieMode = CookieMode();

        if (Scheme.Name == UnAuthConstants.IdentityScheme)
        {           
            if (cookieMode is not false)
            {
                if (await schemeProvider.GetSchemeAsync(IdentityConstants.ApplicationScheme) is not null)
                {
                    await Context.SignInAsync(IdentityConstants.ApplicationScheme, user, properties);
                }
                else if (cookieMode is true)
                {
                    // if cookie mode is specifically requested and provider not registered, throw exception similar to core code
                    throw new InvalidOperationException();
                }

                // cookies set this, so need to reset so correct expiration picked up for bearer
                if (properties is not null) properties.ExpiresUtc = null;
            }

            if (cookieMode is not true && BearerMode())
            {
                var response = tokenService.GenerateIdentity(user, IdentityConstants.BearerScheme, properties);
                Context.Items.TryAdd(UnAuthContextItems.Bearer, response);
                // don't want handler to write to context
                // await Context.SignInAsync(IdentityConstants.BearerScheme, user, properties);
            }

            return;
        }
        if (Scheme.Name == IdentityConstants.TwoFactorUserIdScheme)
        {
            var response = tokenService.GenerateTwoFactorUserId(user, properties);
            Context.Items.TryAdd(UnAuthContextItems.TwoFactorUserId, response.AccessToken);

            if (await schemeProvider.GetSchemeAsync(UnAuthConstants.TwoFactorUserIdCookieScheme) is not null)
            {
                await Context.SignInAsync(UnAuthConstants.TwoFactorUserIdCookieScheme, user, properties);
            }
            else if (cookieMode is true && BearerMode())
            {
                // if cookie mode is specifically requested and provider not registered, throw exception similar to core code
                throw new InvalidOperationException("The UnAuth.TwoFactorUserCookieScheme has not been registered");
            }

            return;
        }
        if (Scheme.Name == IdentityConstants.TwoFactorRememberMeScheme)
        {
            var response = tokenService.GenerateTwoFactorRemember(user, properties);
            Context.Items.TryAdd(UnAuthContextItems.TwoFactorRememberMe, response.AccessToken);

            if (await schemeProvider.GetSchemeAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme) is not null)
            {
                await Context.SignInAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme, user, properties);
            }
            else if (cookieMode is true && BearerMode())
            {
                // if cookie mode is specifically requested and provider not registered, throw exception similar to core code
                throw new InvalidOperationException("The UnAuth.TwoFactorRememberCookie Scheme has not been registered");
            }

            return;
        }

        throw new ArgumentException($"{Scheme.Name} is an unsupported Scheme type for UnAuth");
    }

    protected override async Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        var cookieMode = CookieMode();

        if (Scheme.Name == UnAuthConstants.IdentityScheme)
        {
            if (cookieMode is not false && await schemeProvider.GetSchemeAsync(IdentityConstants.ApplicationScheme) is not null)
            {
                await Context.SignOutAsync(IdentityConstants.ApplicationScheme, properties);
            }

            return;
        }

        if (Scheme.Name == IdentityConstants.TwoFactorUserIdScheme)
        {
            if (cookieMode is not false && await schemeProvider.GetSchemeAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme) is not null)
            {
                await Context.SignOutAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme);
            }

            return;
        }

        if (Scheme.Name == IdentityConstants.TwoFactorRememberMeScheme)
        {
            if (cookieMode is not false && await schemeProvider.GetSchemeAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme) is not null)
            {
                await Context.SignOutAsync(UnAuthConstants.TwoFactorRememberMeCookieScheme);
            }

            return;
        }

        throw new ArgumentException($"{Scheme.Name} is an unsupported Scheme type for UnAuth");
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        Options.ChallengeScheme is null
            ? base.HandleChallengeAsync(properties)
            : Context.ChallengeAsync(Options.ChallengeScheme);

    private string? GetTokenOrNull(string tokenId)
    {
        var authorization = Request.Headers.Authorization.ToString();

        if (!tokenId.EndsWith(" "))
            tokenId += " ";
        
        var authString = authorization.StartsWith(tokenId, StringComparison.Ordinal)
            ? authorization[tokenId.Length..]
            : null;

        // this allows us to store the two factor headers alongside the authorization header
        if (authString is null)
        {
            var other = Request.Headers[tokenId.Trim()];
            if (other.Count > 0)
            {
                authString = other[0];
            }
        }

        return authString;
    }
}
