// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;

// Based off of the BearerTokenHandler
// https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/BearerToken/src/BearerTokenHandler.cs

public sealed class BearerTokenService(IOptionsMonitor<BearerTokenOptions> optionsMonitor, TimeProvider timeProvider)
{
    public AccessTokenResponse Generate(ClaimsPrincipal user, AuthenticationProperties? properties = null)
    {
        var utcNow = timeProvider.GetUtcNow();
        var options = optionsMonitor.Get(IdentityConstants.BearerScheme);

        properties ??= new();
        properties.ExpiresUtc = utcNow + options.BearerTokenExpiration;

        return new AccessTokenResponse
        {
            AccessToken = options.BearerTokenProtector.Protect(CreateBearerTicket(user, properties)),
            ExpiresIn = (long)options.BearerTokenExpiration.TotalSeconds,
            RefreshToken = options.RefreshTokenProtector.Protect(CreateRefreshTicket(user, utcNow + options.RefreshTokenExpiration)),
        };

    }

    private AuthenticationTicket CreateBearerTicket(ClaimsPrincipal user, AuthenticationProperties properties)
        => new(user, properties, $"{IdentityConstants.BearerScheme}:AccessToken");

    private AuthenticationTicket CreateRefreshTicket(ClaimsPrincipal user, DateTimeOffset expires)
    {
        var refreshProperties = new AuthenticationProperties
        {
            ExpiresUtc = expires
        };
        return new AuthenticationTicket(user, refreshProperties, $"{IdentityConstants.BearerScheme}:RefreshToken");
    }
}