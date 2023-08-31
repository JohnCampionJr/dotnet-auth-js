using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.DTO;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Routing;

public static partial class IdentityApiEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder? ComboMapIdentityApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var timeProvider = endpoints.ServiceProvider.GetRequiredService<TimeProvider>();
        var bearerTokenOptions = endpoints.ServiceProvider.GetRequiredService<IOptionsMonitor<BearerTokenOptions>>();
        var emailSender = endpoints.ServiceProvider.GetRequiredService<IEmailSender>();
        var linkGenerator = endpoints.ServiceProvider.GetRequiredService<LinkGenerator>();

        // We'll figure out a unique endpoint name based on the final route pattern during endpoint generation.
        string? confirmEmailEndpointName = null;

        var routeGroup = endpoints.MapGroup("");
        
        routeGroup.MapPost("/logincombo", async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>>
            ([FromBody] LoginRequest login, [FromQuery] bool? cookieMode, [FromQuery] bool? persistCookies, [FromServices] IServiceProvider sp) =>
        {
            cookieMode ??= true;
            var signInManager = sp.GetRequiredService<SignInManager<TUser>>();

            signInManager.PrimaryAuthenticationScheme = cookieMode == true ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;
            var isPersistent = persistCookies ?? true;

            var user = await signInManager.UserManager.FindByNameAsync(login.Username);

            if (user is null)
            {
                return TypedResults.Problem(SignInResult.Failed.ToString(), statusCode: StatusCodes.Status401Unauthorized);
            }

            var result = await signInManager.PasswordSignInAsync(user, login.Password, isPersistent, lockoutOnFailure: true);

            if (result.RequiresTwoFactor)
            {
                if (!string.IsNullOrEmpty(login.TwoFactorCode))
                {
                    result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent, rememberClient: isPersistent);
                }
                else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
                {
                    result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
                }
            }

            if (result.Succeeded)
            {
                var principal = await signInManager.CreateUserPrincipalAsync(user);
                var token = sp.GetRequiredService<BearerTokenService>().Generate(principal);
                return TypedResults.Ok(token);
            }

            return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        });
        return new IdentityEndpointsConventionBuilder(routeGroup);
    }

}