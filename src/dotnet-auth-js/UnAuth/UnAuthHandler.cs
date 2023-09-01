using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

public sealed class UnAuthHandler(
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
        if (Context.Items.TryGetValue(UnAuthConstants.CookieMode, out var obj) && obj is bool mode)
        {
            return mode;
        }

        return null;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Scheme.Name == UnAuthConstants.IdentityScheme)
        {
            var authorization = GetTokenOrNull("Bearer");
            if (authorization is not null)
            {
                return await Context.AuthenticateAsync(IdentityConstants.BearerScheme);
            }

            // Cookie auth will return AuthenticateResult.NoResult() like bearer auth just did if there is no cookie.
            if (await schemeProvider.GetSchemeAsync(IdentityConstants.ApplicationScheme) is not null)
                return await Context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            
            return AuthenticateResult.NoResult();
        }

        if (Scheme.Name == IdentityConstants.TwoFactorUserIdScheme)
        {
            var token = GetTokenOrNull("TwoFactorUserId");
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

        if (Scheme.Name == IdentityConstants.TwoFactorRememberMeScheme)
        {
            var token = GetTokenOrNull("TwoFactorRemember");
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

        throw new ArgumentException($"{Scheme.Name} is an unsupported Scheme type for UnAuth");
    }

    protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        return Task.CompletedTask;
    }

    protected override async Task HandleSignInAsync(
        ClaimsPrincipal user,
        AuthenticationProperties? properties
    )
    {
        if (Scheme.Name == UnAuthConstants.IdentityScheme)
        {
            var cookieMode = CookieMode();
            
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

            if (CookieMode() is not true)
            {
                // no reason to not let the original bearer token work here.
                // var response = tokenService.Generate(user, IdentityConstants.BearerScheme, properties);
                // await Context.Response.WriteAsJsonAsync(response);
                await Context.SignInAsync(IdentityConstants.BearerScheme, user, properties);
            }

            return;
        }
        if (Scheme.Name == IdentityConstants.TwoFactorUserIdScheme)
        {
            var response = tokenService.GenerateTwoFactorUserId(user, properties);
            Context.Items.TryAdd(UnAuthConstants.TwoFactorUserIdToken, response.AccessToken);
            
            var scheme = await schemeProvider.GetSchemeAsync(IdentityConstants.ApplicationScheme);
            if (scheme is null) return;
            
            var handler = await handlers.GetHandlerAsync(Context, IdentityConstants.ApplicationScheme);
            if (handler is null) return;
            
            await handler.InitializeAsync(Scheme, Context);
            if (handler is IAuthenticationSignInHandler signInHandler)
            {
                await signInHandler.SignInAsync(user, properties);
            }

            
            // Context.Response.StatusCode = 401;
            // await Context.Response.WriteAsJsonAsync(response);

            //             await Context.SignInAsync(IdentityConstants.ApplicationScheme, user, properties);
            // return tokenService.Generate(user, Scheme.Name)
            // await Context.SignInAsync(IdentityConstants.BearerScheme, user, properties);
            return;
        }
        if (Scheme.Name == IdentityConstants.TwoFactorRememberMeScheme)
        {
            var response = tokenService.GenerateTwoFactorRemember(user, properties);
            Context.Items.TryAdd(UnAuthConstants.TwoFactorRememberToken, response.AccessToken);
            
            var scheme = await schemeProvider.GetSchemeAsync(IdentityConstants.ApplicationScheme);
            if (scheme is null) return;
            
            var handler = await handlers.GetHandlerAsync(Context, IdentityConstants.ApplicationScheme);
            if (handler is null) return;
            
            await handler.InitializeAsync(Scheme, Context);
            if (handler is IAuthenticationSignInHandler signInHandler)
            {
                await signInHandler.SignInAsync(user, properties);
            }


            // Context.Response.StatusCode = 401;
            // await Context.Response.WriteAsJsonAsync(response);
            // await Context.SignInAsync(IdentityConstants.ApplicationScheme, user, properties);
            // await Context.SignInAsync(IdentityConstants.BearerScheme, user, properties);
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

        return authorization.StartsWith(tokenId, StringComparison.Ordinal)
            ? authorization[tokenId.Length..]
            : null;
    }
}
