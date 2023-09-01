// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using jcamp.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using BearerTokenOptions = Microsoft.AspNetCore.Authentication.BearerToken.BearerTokenOptions;

// using jcamp.BearerToken;


// Based off of the BearerTokenHandler
// https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/BearerToken/src/BearerTokenHandler.cs

public sealed class UnAuthTokenService(IOptionsMonitor<UnAuthOptions> unAuthOptionsMonitor, IOptionsMonitor<BearerTokenOptions> bearerOptionsMonitor, TimeProvider timeProvider)
{
    public UnAuthTokenResponse GenerateIdentity(
        ClaimsPrincipal user,
        string authenticationScheme,
        AuthenticationProperties? properties = null
    )
    {
        var utcNow = timeProvider.GetUtcNow();
        var bearerOptions = bearerOptionsMonitor.Get(IdentityConstants.BearerScheme);

        properties ??= new();
        properties.ExpiresUtc = utcNow + bearerOptions.BearerTokenExpiration;

        return new UnAuthTokenResponse
        {
            TokenType = authenticationScheme,
            AccessToken = bearerOptions.BearerTokenProtector.Protect(
                CreateBearerTicket(user, authenticationScheme, properties)
            ),
            ExpiresInSeconds = (long)bearerOptions.BearerTokenExpiration.TotalSeconds,
            RefreshToken = bearerOptions.RefreshTokenProtector.Protect(
                CreateRefreshTicket(user, authenticationScheme, utcNow + bearerOptions.RefreshTokenExpiration)
            ),
        };
    }

    public UnAuthTokenResponse GenerateTwoFactorUserId(
        ClaimsPrincipal user,
        AuthenticationProperties? properties = null
    )
    {
        var utcNow = timeProvider.GetUtcNow();
        var unAuthOptions = unAuthOptionsMonitor.Get(IdentityConstants.TwoFactorUserIdScheme);

        properties ??= new();
        properties.ExpiresUtc = utcNow + unAuthOptions.TwoFactorUserIdTokenExpiration;

        return new UnAuthTokenResponse
        {
            TokenType = IdentityConstants.TwoFactorUserIdScheme,
            AccessToken = unAuthOptions.TwoFactorUserIdTokenProtector.Protect(
                CreateBearerTicket(user, IdentityConstants.TwoFactorUserIdScheme, properties)
            ),
            ExpiresInSeconds = (long)unAuthOptions.TwoFactorUserIdTokenExpiration.TotalSeconds,
        };
    }

    public UnAuthTokenResponse GenerateTwoFactorRemember(
        ClaimsPrincipal user,
        AuthenticationProperties? properties = null
    )
    {
        var utcNow = timeProvider.GetUtcNow();
        var unAuthOptions = unAuthOptionsMonitor.Get(IdentityConstants.TwoFactorRememberMeScheme);

        properties ??= new();
        properties.ExpiresUtc = utcNow + unAuthOptions.TwoFactorRememberTokenExpiration;

        return new UnAuthTokenResponse
        {
            TokenType = IdentityConstants.TwoFactorRememberMeScheme,
            AccessToken = unAuthOptions.TwoFactorRememberTokenProtector.Protect(
                CreateBearerTicket(user, IdentityConstants.TwoFactorRememberMeScheme, properties)
            ),
            ExpiresInSeconds = (long)unAuthOptions.TwoFactorRememberTokenExpiration.TotalSeconds,
        };
    }


    private AuthenticationTicket CreateBearerTicket(
        ClaimsPrincipal user,
        string authenticationScheme,
        AuthenticationProperties properties
    ) => new(user, properties, $"{authenticationScheme}:AccessToken");

    private AuthenticationTicket CreateRefreshTicket(ClaimsPrincipal user, string authenticationScheme, DateTimeOffset expires)
    {
        var refreshProperties = new AuthenticationProperties { ExpiresUtc = expires };
        return new AuthenticationTicket(
            user,
            refreshProperties,
            $"{authenticationScheme}:RefreshToken"
        );
    }
}
