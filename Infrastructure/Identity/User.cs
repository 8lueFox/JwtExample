using Microsoft.AspNetCore.Identity;

namespace Infrastructure.Identity;

public sealed class User : IdentityUser
{
    public byte[] PasswordHash { get; set; }

    public byte[] PasswordSalt { get; set; }

    public string RefreshToken { get; set; } = string.Empty;

    public DateTime TokenCreated { get; set; }

    public DateTime TokenExpires { get; set; }
}
