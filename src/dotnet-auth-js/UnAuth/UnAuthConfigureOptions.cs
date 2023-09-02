using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace UnAuth;

public sealed class UnAuthConfigureOptions(IDataProtectionProvider dp) : IConfigureNamedOptions<UnAuthOptions>
{
    
    private const string _primaryPurpose = "UnAuthToken";
    
    public void Configure(string? schemeName, UnAuthOptions options)
    {
        if (schemeName is null)
        {
            return;
        }
        options.TwoFactorUserIdTokenProtector = new TicketDataFormat(dp.CreateProtector(_primaryPurpose, IdentityConstants.TwoFactorUserIdScheme, "2FUserToken"));
        options.TwoFactorRememberTokenProtector = new TicketDataFormat(dp.CreateProtector(_primaryPurpose, IdentityConstants.TwoFactorRememberMeScheme, "2fRememberToken"));
    }
    
    public void Configure(UnAuthOptions options)
    {
        throw new NotImplementedException();
    }

}