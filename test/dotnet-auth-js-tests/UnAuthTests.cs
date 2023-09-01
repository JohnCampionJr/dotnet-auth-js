﻿using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using Xunit.Sdk;

namespace Microsoft.AspNetCore.Identity.FunctionalTests;

public partial class UnAuthMapIdentityApiTests
{
    [Fact]
    public async Task LoginFailsGivenNoData()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var result = await client.PostAsJsonAsync("/identity/unauthlogin", new { });
        AssertBadRequestAndEmpty(result);
    }

    [Fact]
    public async Task LoginProceedsWithJustTwoFactorCode()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsJsonAsync("/identity/unauthlogin", new { TwoFactorCode = "123456"});
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task LoginProceedsWithJustRecoveryCode()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsJsonAsync("/identity/unauthlogin", new { TwoFactorRecoveryCode = "123456"});
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task LoginFailsGivenNoUsername(string username)
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var result = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username = username, Password });
        AssertBadRequestAndEmpty(result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task LoginFailsGivenNoPassword(string password)
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var result = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password = password });
        AssertBadRequestAndEmpty(result);
    }
    
    [Theory]
    [MemberData(nameof(AddIdentityModes))]
    public async Task CanEnableAndLoginWithTwoFactorTwoStep(string addIdentityMode)
    {
        await using var app = await CreateAppAsync(AddIdentityActions[addIdentityMode]);
        using var client = app.GetTestClient();

        await RegisterAsync(client);
        var loginResponse = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password });

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = loginContent.GetProperty("access_token").GetString();
        var refreshToken = loginContent.GetProperty("refresh_token").GetString();

        AssertUnauthorizedAndEmpty(await client.GetAsync("/identity/account/2fa"));

        client.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);

        // We cannot enable 2fa without verifying we can produce a valid
        await AssertValidationProblemAsync(await client.PostAsJsonAsync("/identity/account/2fa", new { Enable = true }),
            "RequiresTwoFactor");
        await AssertValidationProblemAsync(
            await client.PostAsJsonAsync("/identity/account/2fa", new { Enable = true, TwoFactorCode = "wrong" }),
            "InvalidTwoFactorCode");

        var twoFactorKeyResponse = await client.GetFromJsonAsync<JsonElement>("/identity/account/2fa");
        Assert.False(twoFactorKeyResponse.GetProperty("isTwoFactorEnabled").GetBoolean());
        Assert.False(twoFactorKeyResponse.GetProperty("isMachineRemembered").GetBoolean());

        var sharedKey = twoFactorKeyResponse.GetProperty("sharedKey").GetString();

        var keyBytes = Base32.FromBase32(sharedKey);
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timestep = Convert.ToInt64(unixTimestamp / 30);
        var twoFactorCode = Rfc6238AuthenticationService.ComputeTotp(keyBytes, (ulong)timestep, modifierBytes: null)
            .ToString();

        var enable2faResponse =
            await client.PostAsJsonAsync("/identity/account/2fa", new { twoFactorCode, Enable = true });
        var enable2faContent = await enable2faResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(enable2faContent.GetProperty("isTwoFactorEnabled").GetBoolean());
        Assert.False(enable2faContent.GetProperty("isMachineRemembered").GetBoolean());

        // We can still access auth'd endpoints with old access token.
        Assert.Equal($"Hello, {Username}!", await client.GetStringAsync("/auth/hello"));

        // But the refresh token is invalidated by the security stamp.
        AssertUnauthorizedAndEmpty(await client.PostAsJsonAsync("/identity/refresh", new { refreshToken }));

        client.DefaultRequestHeaders.Clear();
        
        // changes start here for two step
        var twoFactorStep1 = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password });
        var twoFactorContent = await twoFactorStep1.Content.ReadFromJsonAsync<JsonElement>();
        AssertProblemWithJson(twoFactorStep1, twoFactorContent, "RequiresTwoFactor");
        ApplyCookiesMaybe(client, twoFactorStep1);

        var twoFactorUserIdToken = twoFactorContent.GetProperty("TwoFactorUserIdToken").GetString();
        client.DefaultRequestHeaders.Authorization = new("TwoFactorUserIdToken", twoFactorUserIdToken);

        AssertOk(await client.PostAsJsonAsync("/identity/unauthlogin", new { twoFactorCode }));
    }

    [Theory]
    [MemberData(nameof(AddIdentityModes))]
    public async Task CanLoginWithRecoveryCodeTwoStepAndDisableTwoFactor(string addIdentityMode)
    {
        await using var app = await CreateAppAsync(AddIdentityActions[addIdentityMode]);
        using var client = app.GetTestClient();

        await RegisterAsync(client);
        var loginResponse = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password });

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = loginContent.GetProperty("access_token").GetString();
        client.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);

        var twoFactorKeyResponse = await client.GetFromJsonAsync<JsonElement>("/identity/account/2fa");
        var sharedKey = twoFactorKeyResponse.GetProperty("sharedKey").GetString();

        var keyBytes = Base32.FromBase32(sharedKey);
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timestep = Convert.ToInt64(unixTimestamp / 30);
        var twoFactorCode = Rfc6238AuthenticationService.ComputeTotp(keyBytes, (ulong)timestep, modifierBytes: null).ToString();

        var enable2faResponse = await client.PostAsJsonAsync("/identity/account/2fa", new { twoFactorCode, Enable = true });
        var enable2faContent = await enable2faResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(enable2faContent.GetProperty("isTwoFactorEnabled").GetBoolean());

        var recoveryCodes = enable2faContent.GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Equal(10, recoveryCodes.Length);

        client.DefaultRequestHeaders.Clear();

        // changes start here for two step
        var twoFactorStep1 = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password });
        var twoFactorContent = await twoFactorStep1.Content.ReadFromJsonAsync<JsonElement>();
        AssertProblemWithJson(twoFactorStep1, twoFactorContent, "RequiresTwoFactor");
        ApplyCookiesMaybe(client, twoFactorStep1);

        var twoFactorUserIdToken = twoFactorContent.GetProperty("TwoFactorUserIdToken").GetString();
        client.DefaultRequestHeaders.Authorization = new("TwoFactorUserIdToken", twoFactorUserIdToken);
        
        var recoveryLoginResponse = await client.PostAsJsonAsync("/identity/unauthlogin", new { TwoFactorRecoveryCode = recoveryCodes[0] });
        AssertOk(recoveryLoginResponse);
        
        // same below
        var recoveryLoginContent = await recoveryLoginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var recoveryAccessToken = recoveryLoginContent.GetProperty("access_token").GetString();
        Assert.NotEqual(accessToken, recoveryAccessToken);

        client.DefaultRequestHeaders.Authorization = new("Bearer", recoveryAccessToken);

        var disable2faResponse = await client.PostAsJsonAsync("/identity/account/2fa", new { Enable = false });
        var disable2faContent = await disable2faResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(disable2faContent.GetProperty("isTwoFactorEnabled").GetBoolean());

        client.DefaultRequestHeaders.Clear();

        AssertOk(await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password }));
    }

    
    private static void AssertProblemWithJson(HttpResponseMessage response, JsonElement content, string detail, HttpStatusCode status = HttpStatusCode.Unauthorized)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(ReasonPhrases.GetReasonPhrase((int)HttpStatusCode.Unauthorized), content.GetProperty("title").GetString());
        Assert.Equal(detail, content.GetProperty("detail").GetString());
    }

    private static void ApplyCookiesMaybe(HttpClient client, HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(HeaderNames.SetCookie, out var setCookieHeaders)) return;
        foreach (var setCookieHeader in setCookieHeaders)
        {
            if (setCookieHeader.Split(';', 2) is not [var cookie, _])
            {
                throw new XunitException("Invalid Set-Cookie header!");
            }

            // Cookies starting with "CookieName=;" are being deleted
            if (!cookie.EndsWith("=", StringComparison.Ordinal))
            {
                client.DefaultRequestHeaders.Add(HeaderNames.Cookie, cookie);
            }
        }
    }
}