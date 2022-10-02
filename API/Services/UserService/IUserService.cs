using Infrastructure.Identity;

namespace API.Services.UserService;

public interface IUserService
{
    string GetMyName();
    Task<string> CreateUser(User user);
    Task<User?> GetUser(string username);
    Task<string> GetUserId(string name);
}
