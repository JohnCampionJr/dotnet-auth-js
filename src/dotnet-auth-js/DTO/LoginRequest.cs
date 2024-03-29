// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity.DTO;

internal sealed class LoginRequest
{
    // removed after preview7
    // public string? Username { get; init; }
    // added after preview7
    public required string Email { get; init; }
    public required string Password { get; init; }
    public string? TwoFactorCode { get; init; }
    public string? TwoFactorRecoveryCode { get; init; }
}
