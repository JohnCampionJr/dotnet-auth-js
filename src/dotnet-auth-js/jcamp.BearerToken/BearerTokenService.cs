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

public sealed class BearerTokenService(IOptionsMonitor<BearerTokenOptions> optionsMonitor, TimeProvider timeProvider)
{
    public AccessTokenResponse Generate(
        ClaimsPrincipal user,
        string authenticationScheme,
        AuthenticationProperties? properties = null
    )
    {
        var utcNow = timeProvider.GetUtcNow();
        var options = optionsMonitor.Get(IdentityConstants.BearerScheme);

        properties ??= new();
        properties.ExpiresUtc = utcNow + options.BearerTokenExpiration;

        return new AccessTokenResponse
        {
            TokenType = authenticationScheme,
            AccessToken = options.BearerTokenProtector.Protect(
                CreateBearerTicket(user, authenticationScheme, properties)
            ),
            ExpiresInSeconds = (long)options.BearerTokenExpiration.TotalSeconds,
            RefreshToken = options.RefreshTokenProtector.Protect(
                CreateRefreshTicket(user, authenticationScheme, utcNow + options.RefreshTokenExpiration)
            ),
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