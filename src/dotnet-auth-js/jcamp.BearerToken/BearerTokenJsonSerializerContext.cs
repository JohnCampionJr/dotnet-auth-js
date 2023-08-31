// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text.Json.Serialization;

namespace jcamp.BearerToken;

[JsonSerializable(typeof(AccessTokenResponse))]
internal sealed partial class BearerTokenJsonSerializerContext : JsonSerializerContext
{
}
