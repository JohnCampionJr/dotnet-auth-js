using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Net.Http.Headers;

/// <summary>
/// Helper functions for configuring identity services.
/// </summary>
public static class IdentityBuilderExtensions
{
    public static IdentityBuilder AddCombinedIdentityServices(this IdentityBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddApiEndpoints();
        builder.Services.AddTransient<BearerTokenService>();

        return builder;
    }
}

public static class AuthenticationBuilderExtensions
{
    public static IServiceCollection AddCombinedAuthorization(this IServiceCollection services) =>
        services.AddAuthorization(a =>
        {
            a.AddCombinedPolicies();
        });

    public static IServiceCollection AddCombinedAuthorization(
        this IServiceCollection services,
        Action<AuthorizationOptions> configureOptions
    ) =>
        services.AddAuthorization(a =>
        {
            a.AddCombinedPolicies();
            configureOptions(a);
        });
    
    public static AuthenticationBuilder AddCombinedAuthentication(
        this IServiceCollection services
    ) =>
        services
            .AddAuthentication(x =>
            {
                x.DefaultScheme = MyIdentityConstants.BearerAndApplicationScheme;
                x.DefaultChallengeScheme = IdentityConstants.BearerScheme;
            })
            .AddCombinedPolciesAndSchemes();

    public static AuthenticationBuilder AddCombinedAuthentication(
        this IServiceCollection services,
        Action<AuthenticationOptions> configureOptions
    ) =>
        services
            .AddAuthentication(x =>
            {
                x.DefaultScheme = MyIdentityConstants.BearerAndApplicationScheme;
                x.DefaultChallengeScheme = IdentityConstants.BearerScheme;
                configureOptions(x);
            })
            .AddCombinedPolciesAndSchemes();

    public static AuthenticationBuilder AddCombinedPolciesAndSchemes(
        this AuthenticationBuilder builder
    ) => builder.AddCombinedPolicy().AddCombinedSchemes();

    public static AuthenticationBuilder AddCombinedPolicy(this AuthenticationBuilder builder)
    {
        builder.AddPolicyScheme(
            MyIdentityConstants.BearerAndApplicationScheme,
            MyIdentityConstants.BearerAndApplicationScheme,
            options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    string? authorization = context.Request.Headers[HeaderNames.Authorization];
                    if (authorization is not null && authorization.StartsWith("Bearer "))
                        return IdentityConstants.BearerScheme;

                    return IdentityConstants.ApplicationScheme;
                };
            }
        );
        return builder;
    }

    public static AuthenticationBuilder AddCombinedSchemes(this AuthenticationBuilder builder)
    {
        builder
            .AddJcampBearerToken(IdentityConstants.BearerScheme)
            .AddIdentityCookies(
                (c) =>
                {
                    // this makes the site return 401s rather than 302 for cookie only paths
                    c.ApplicationCookie?.Configure(
                        o => o.ForwardChallenge = IdentityConstants.BearerScheme
                    );
                }
            );
        return builder;
    }
}

public static class AuthorizationOptionsExtensions
{
    public static void AddCombinedPolicies(this AuthorizationOptions a)
    {
        a.AddPolicy(
            MyPolicyConstants.BearerOnly,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.BearerScheme);
                p.RequireAuthenticatedUser();
            }
        );
        a.AddPolicy(
            MyPolicyConstants.ApplicationOnly,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
                p.RequireAuthenticatedUser();
            }
        );
        a.AddPolicy(
            MyPolicyConstants.BearerOrApplication,
            p =>
            {
                p.AddAuthenticationSchemes(IdentityConstants.BearerScheme);
                p.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
                p.RequireAuthenticatedUser();
            }
        );
    }
}
