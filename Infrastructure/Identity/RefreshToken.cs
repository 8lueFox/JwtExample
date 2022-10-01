namespace Infrastructure.Identity;

public class RefreshToken
{
    public string Token { get; set; } = string.Empty;

    public DateTime Created { get; init; } = DateTime.Now;

    public DateTime Expires { get; set; }
}
