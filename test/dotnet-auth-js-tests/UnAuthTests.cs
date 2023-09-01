using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using Xunit.Sdk;

namespace Microsoft.AspNetCore.Identity.FunctionalTests;

public partial class UnAuthMapIdentityApiTests 
{
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
        await AssertValidationProblemAsync(await client.PostAsJsonAsync("/identity/account/2fa", new { Enable = true, TwoFactorCode = "wrong" }),
            "InvalidTwoFactorCode");

        var twoFactorKeyResponse = await client.GetFromJsonAsync<JsonElement>("/identity/account/2fa");
        Assert.False(twoFactorKeyResponse.GetProperty("isTwoFactorEnabled").GetBoolean());
        Assert.False(twoFactorKeyResponse.GetProperty("isMachineRemembered").GetBoolean());

        var sharedKey = twoFactorKeyResponse.GetProperty("sharedKey").GetString();

        var keyBytes = Base32.FromBase32(sharedKey);
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timestep = Convert.ToInt64(unixTimestamp / 30);
        var twoFactorCode = Rfc6238AuthenticationService.ComputeTotp(keyBytes, (ulong)timestep, modifierBytes: null).ToString();

        var enable2faResponse = await client.PostAsJsonAsync("/identity/account/2fa", new { twoFactorCode, Enable = true });
        var enable2faContent = await enable2faResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(enable2faContent.GetProperty("isTwoFactorEnabled").GetBoolean());
        Assert.False(enable2faContent.GetProperty("isMachineRemembered").GetBoolean());

        // We can still access auth'd endpoints with old access token.
        Assert.Equal($"Hello, {Username}!", await client.GetStringAsync("/auth/hello"));

        // But the refresh token is invalidated by the security stamp.
        AssertUnauthorizedAndEmpty(await client.PostAsJsonAsync("/identity/refresh", new { refreshToken }));

        client.DefaultRequestHeaders.Clear();
        var twoFactorStep1 = await client.PostAsJsonAsync("/identity/unauthlogin", new { Username, Password });
        var twoFactorContent = await twoFactorStep1.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(HttpStatusCode.Unauthorized, twoFactorStep1.StatusCode);
        Assert.Equal(ReasonPhrases.GetReasonPhrase((int)HttpStatusCode.Unauthorized), twoFactorContent.GetProperty("title").GetString());
        Assert.Equal("RequiresTwoFactor", twoFactorContent.GetProperty("detail").GetString());

        // await AssertProblemAsync(twoFactorStep1, "RequiresTwoFactor");
        ApplyCookiesMaybe(client, twoFactorStep1);

        var twoFactorUserIdToken = twoFactorContent.GetProperty("TwoFactorUserIdToken").GetString();
        client.DefaultRequestHeaders.Authorization = new("TwoFactorUserIdToken", twoFactorUserIdToken);

        AssertOk(await client.PostAsJsonAsync("/identity/unauthlogin", new { twoFactorCode }));
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