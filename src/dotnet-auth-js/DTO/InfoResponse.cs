// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity.DTO;

internal sealed class InfoResponse
{
    //removed after preview7
    //public required string Username { get; init; }
    public required string Email { get; init; }
    // added after preview7
    public required bool IsEmailConfirmed { get; init; }
    public required IDictionary<string, string> Claims { get; init; }
}
