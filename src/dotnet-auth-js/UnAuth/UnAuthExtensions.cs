using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using UnAuth;

namespace Microsoft.Extensions.DependencyInjection;

public static class UnAuthExtensions
{
    public static IServiceCollection AddUnAuthorization(this IServiceCollection services)
        => services.AddAuthorization(a => a.AddUnAuthPolicies());
    
    public static IServiceCollection AddUnAuthorization(this IServiceCollection services, Action<AuthorizationOptions> configureOptions) =>
        services.AddAuthorization(a =>
        {
            a.AddUnAuthPolicies();
            configureOptions(a);
        });
    
    public static AuthenticationBuilder AddUnAuthentication(this IServiceCollection services)
        => services.AddAuthentication(UnAuthConstants.AuthScheme).AddUnAuthSchemes();
    
    public static AuthenticationBuilder AddUnAuthentication(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        var builder = services.AddUnAuthentication();
        services.Configure(configureOptions);
        return builder;
    }

    public static IdentityBuilder AddUnAuthentication<TUser>(this IServiceCollection services) where TUser : class, new() =>
        AddUnAuthentication<TUser>(services, _ => { }); 
    
    /// <summary>
    /// Adds a set of common identity services to the application to support <see cref="IdentityApiEndpointRouteBuilderExtensions.MapIdentityApi{TUser}(IEndpointRouteBuilder)"/>
    /// and configures authentication to support identity bearer tokens and cookies.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="configure">Configures the <see cref="IdentityOptions"/>.</param>
    /// <returns>The <see cref="IdentityBuilder"/>.</returns>
    public static IdentityBuilder AddUnAuthentication<TUser>(this IServiceCollection services, Action<IdentityOptions> configure)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services
            .AddAuthentication(UnAuthConstants.AuthScheme)
            .AddUnAuthSchemes()
            .AddBearerToken(IdentityConstants.BearerScheme)
            .AddUnAuthCookies();

        return services.AddIdentityCore<TUser>(configure).AddUnAuthIdentityServices();
    }

    public static IdentityBuilder AddUnAuthIdentityServices(this IdentityBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddApiEndpoints();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<UnAuthSchemeOptions>, UnAuthConfigureSchemeOptions>()
        );
        builder.Services.AddScoped<UnAuthTokenService>();

        return builder;
    }

    public static AuthenticationBuilder AddUnAuthSchemes(this AuthenticationBuilder builder) =>
        builder
            .AddScheme<UnAuthSchemeOptions, UnAuthHandler>(UnAuthConstants.AuthScheme, _ => { })
            .AddScheme<UnAuthSchemeOptions, UnAuthHandler>(IdentityConstants.TwoFactorUserIdScheme, _ => { })
            .AddScheme<UnAuthSchemeOptions, UnAuthHandler>(IdentityConstants.TwoFactorRememberMeScheme, _ => { });
}


/// <summary>
/// Extension methods to configure the bearer token authentication.
/// </summary>
public static class UnAuthCookieExtensions
{
    /// <summary>
    /// Adds cookie authentication.
    /// </summary>
    /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
    /// <returns>The <see cref="IdentityCookiesBuilder"/> which can be used to configure the identity cookies.</returns>
    public static IdentityCookiesBuilder AddUnAuthCookies(this AuthenticationBuilder builder) =>
        builder.AddUnAuthCookies(o => { });

    /// <summary>
    /// Adds the cookie authentication needed for sign in manager.
    /// </summary>
    /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
    /// <param name="configureCookies">Action used to configure the cookies.</param>
    /// <returns>The <see cref="IdentityCookiesBuilder"/> which can be used to configure the identity cookies.</returns>
    public static IdentityCookiesBuilder AddUnAuthCookies(this AuthenticationBuilder builder, Action<IdentityCookiesBuilder> configureCookies)
    {
        var cookieBuilder = new IdentityCookiesBuilder();
        cookieBuilder.ApplicationCookie = builder.AddUnAuthApplicationCookie();
        cookieBuilder.ExternalCookie = builder.AddExternalCookie();
        cookieBuilder.TwoFactorRememberMeCookie = builder.AddUnAuthTwoFactorRememberMeCookie();
        cookieBuilder.TwoFactorUserIdCookie = builder.AddUnAuthTwoFactorUserIdCookie();
        configureCookies?.Invoke(cookieBuilder);
        return cookieBuilder;
    }

    /// <summary>
    /// Adds the identity application cookie.
    /// </summary>
    /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
    /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
    public static OptionsBuilder<CookieAuthenticationOptions> AddUnAuthApplicationCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(IdentityConstants.ApplicationScheme, o =>
        {
            // o.LoginPath = new PathString("/Account/Login");
            o.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync,
                OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = 401;
                    return Task.CompletedTask;
                },
                OnRedirectToAccessDenied = context =>
                {
                    context.Response.StatusCode = 403;
                    return Task.CompletedTask;
                }
            };
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.ApplicationScheme);
    }

    /// <summary>
    /// Adds the identity cookie used for two factor remember me.
    /// </summary>
    /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
    /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
    public static OptionsBuilder<CookieAuthenticationOptions> AddUnAuthTwoFactorRememberMeCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(UnAuthConstants.TwoFactorRememberMeCookieScheme, o =>
        {
            o.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme; 
            o.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = SecurityStampValidator.ValidateAsync<ITwoFactorSecurityStampValidator>
            };
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.TwoFactorRememberMeScheme);
    }
 
    /// <summary>
    /// Adds the identity cookie used for two factor logins.
    /// </summary>
    /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
    /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
    public static OptionsBuilder<CookieAuthenticationOptions> AddUnAuthTwoFactorUserIdCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(UnAuthConstants.TwoFactorUserIdCookieScheme, o =>
        {
            o.Cookie.Name = IdentityConstants.TwoFactorUserIdScheme;
            o.Events = new CookieAuthenticationEvents
            {
                OnRedirectToReturnUrl = _ => Task.CompletedTask
            };
            o.ExpireTimeSpan = TimeSpan.FromMinutes(10);
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.TwoFactorUserIdScheme);
    }

}
