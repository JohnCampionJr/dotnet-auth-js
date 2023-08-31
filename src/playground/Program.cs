using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization();
var dbConnection = new SqliteConnection("DataSource=:memory:");
builder.Services.AddSingleton(_ => dbConnection);
builder.Services
    .AddAuthentication(x =>
    {
        x.DefaultScheme = MyIdentityConstants.BearerAndApplicationScheme;
    })
    .AddPolicyScheme(
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
    )
    .AddBearerToken(IdentityConstants.BearerScheme)
    .AddIdentityCookies(
        (c) =>
        {
            // just so show how to use this
            c.ApplicationCookie?.Configure(o => o.LoginPath = "/account/login");
        }
    );

builder.Services
    .AddDbContext<ApplicationDbContext>(
        (sp, options) => options.UseSqlite(sp.GetRequiredService<SqliteConnection>())
    )
    .AddIdentityCore<ApplicationUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddApiEndpoints();

builder.Services.AddTransient<BearerTokenService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGroup("/identity").MyMapIdentityApi<ApplicationUser>();

var authGroup = app.MapGroup("/auth").RequireAuthorization();
authGroup.MapGet("/hello", (ClaimsPrincipal user) => $"Hello, {user.Identity?.Name}!");

authGroup.MapGet(
    "/testtoken",
    (
        ClaimsPrincipal user,
        BearerTokenService tokenGen,
        TimeProvider timeProvider,
        IOptionsMonitor<BearerTokenOptions> optionsMonitor
    ) =>
    {
        return TypedResults.Ok(tokenGen.Generate(user, null));
    }
);

app.UseHttpsRedirection();

// little messy, but ensures the Sqlite database is ready for use
await dbConnection.OpenAsync();
var options = new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(dbConnection).Options;
var db = new ApplicationDbContext(options);
await db.Database.EnsureCreatedAsync();

var summaries = new[]
{
    "Freezing",
    "Bracing",
    "Chilly",
    "Cool",
    "Mild",
    "Warm",
    "Balmy",
    "Hot",
    "Sweltering",
    "Scorching"
};

app.MapGet(
        "/weatherforecast",
        () =>
        {
            var forecast = Enumerable
                .Range(1, 5)
                .Select(
                    index =>
                        new WeatherForecast(
                            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                            Random.Shared.Next(-20, 55),
                            summaries[Random.Shared.Next(summaries.Length)]
                        )
                )
                .ToArray();
            return forecast;
        }
    )
    .WithName("GetWeatherForecast")
    .WithOpenApi();

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}