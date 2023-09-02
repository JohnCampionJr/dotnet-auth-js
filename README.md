# UnAuth
Unified Auth / Universal Auth

A project expanding on .NET 8.0's Minimal API Auth.

## Features
- Allows using both cookies or bearer tokens for all identity processes, including two factor operations. This is it's real reason for existing.  I didn't like the Minimal API Auth's all in stance on bearer tokens, yet I liked the configuration.
- UnAuth Logging in at `/identity/unlogin` - this is is to prevent colliding with the default `/identity/login`
- Uses standard ASP.NET Core Identity, with Bearer and Cookie Schemes for proven security.
- Does not require storing and sending password twice for two factor logging in.  
- Allows for a token to prevent requiring two factor codes with every login (another flaw in the .NET minimal API for me)

Similar to the cookie based Identity, UnAuth sends tokens for two factor two step logging in and remembering the machine so a two factor code is not needed with every login  

### Ideas
- [ ] Roles
- [ ] Separate Mappings to separate static methods for use in controllers if desired
- [ ] Database helpers for quick setup (would need separate packages for dependencies though)
- [ ] Email sender configurations
- [ ] Documentation - see unit tests for now
- [ ] Samples


### Post .NET 8.0 Preview 7 changes
-[X] Change to email/password instead of username 
-[ ] AccessTokenResponse JSON Changes (can't do until rc1, due to BearerToken)
-[ ] DTOs will be public from dotnet (rc.2 it appears)
-[ ] Once MapIdentityApi is stable, remove its code and rely on dotnet code (probably rc2 or release)

### Related Issues
[#49957 BearerAndApplicationScheme](https://github.com/dotnet/aspnetcore/issues/49957)


### Credits

[Original Minimal API Identity Endpoints](https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Core/src/IdentityApiEndpointRouteBuilderExtensions.cs)

[Original Identity and Minimal API Endpoints Tests](https://github.com/dotnet/aspnetcore/tree/main/src/Identity/test/Identity.FunctionalTests)

[Microsoft.AspNetCore.Testing (DotNet Internal Project)](https://github.com/dotnet/aspnetcore/tree/main/src/Testing/src)
This may get renamed [#49776](https://github.com/dotnet/aspnetcore/issues/49776)

[Rick Strahl's Work on Combining Cookie and Token](https://weblog.west-wind.com/posts/2022/Mar/29/Combining-Bearer-Token-and-Cookie-Auth-in-ASPNET)


