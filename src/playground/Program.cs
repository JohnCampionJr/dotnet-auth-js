using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.ResolveConflictingActions(a => a.Last());
});

var dbConnection = new SqliteConnection("DataSource=:memory:");
builder.Services.AddSingleton(_ => dbConnection);

builder.Services.AddUnAuthorization();

builder.Services
    .AddDbContext<ApplicationDbContext>(
        (sp, options) => options.UseSqlite(sp.GetRequiredService<SqliteConnection>())
    )
    .AddUnAuthentication<ApplicationUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGroup("/identity").MapUnAuthApi<ApplicationUser>();

app.MapGet("/cookieonly", (ClaimsPrincipal user) => $"With Cookie: Hello, {user.Identity?.Name}!")
    .RequireAuthorization(UnAuthPolicies.CookieOnly);

app.MapGet("/tokenonly", (ClaimsPrincipal user) => $"With Token: Hello, {user.Identity?.Name}!")
    .RequireAuthorization(UnAuthPolicies.BearerOnly);

var authGroup = app.MapGroup("/auth").RequireAuthorization();
authGroup.MapGet("/hello", (ClaimsPrincipal user) => $"With Either: Hello, {user.Identity?.Name}!");
authGroup.MapGet("/cookieonly", (ClaimsPrincipal user) => $"With Cookie: Hello, {user.Identity?.Name}!")
    .RequireAuthorization(UnAuthPolicies.CookieOnly);

authGroup.MapGet("/tokenonly", (ClaimsPrincipal user) => $"With Token: Hello, {user.Identity?.Name}!")
    .RequireAuthorization(UnAuthPolicies.BearerOnly);

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
