namespace Infrastructure.Identity;

public sealed class User
{
    public string UserName { get; set; } = string.Empty;
    public byte[] PasswordHash { get; set; }
    public byte[] PasswordSalt { get; set; }
}
