using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace UnAuth;

public sealed class UnAuthConfigureSchemeOptions(IDataProtectionProvider dp) : IConfigureNamedOptions<UnAuthSchemeOptions>
{
    
    private const string _primaryPurpose = "UnAuthToken";
    
    public void Configure(string? schemeName, UnAuthSchemeOptions schemeOptions)
    {
        if (schemeName is null)
        {
            return;
        }
        schemeOptions.TwoFactorUserIdTokenProtector = new TicketDataFormat(dp.CreateProtector(_primaryPurpose, IdentityConstants.TwoFactorUserIdScheme, "2FUserToken"));
        schemeOptions.TwoFactorRememberTokenProtector = new TicketDataFormat(dp.CreateProtector(_primaryPurpose, IdentityConstants.TwoFactorRememberMeScheme, "2fRememberToken"));
    }
    
    public void Configure(UnAuthSchemeOptions schemeOptions)
    {
        throw new NotImplementedException();
    }

}