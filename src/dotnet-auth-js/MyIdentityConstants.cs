using Microsoft.AspNetCore.Identity;

// until this is merged / changed
// https://github.com/dotnet/aspnetcore/issues/49957

public class MyIdentityConstants : IdentityConstants
{
    /// <summary>
    /// The scheme used to identify combination of <see cref="BearerScheme"/> and <see cref="ApplicationScheme"/>.
    /// </summary>
    public static readonly string BearerAndApplicationScheme = "Identity.BearerAndApplication";
}
