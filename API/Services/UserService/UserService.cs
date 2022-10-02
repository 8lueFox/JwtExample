using Infrastructure.Identity;
using Infrastructure.Persistance.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace API.Services.UserService;

public class UserService : IUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly ApplicationDbContext _db;


    public UserService(IHttpContextAccessor httpContextAccessor,
        SignInManager<User> signInManager,
        UserManager<User> userManager,
        ApplicationDbContext db)
    {
        _httpContextAccessor = httpContextAccessor;
        _signInManager = signInManager;
        _userManager = userManager;
        _db = db;
    }

    public async Task<string> CreateUser(User user)
    {
        var result = await _userManager.CreateAsync(user, "password");

        return "";
    }

    public string GetMyName()
    {
        var result = string.Empty;
        if(_httpContextAccessor.HttpContext != null)
        {
            result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
        }
        return result;
    }

    public async Task<User?> GetUser(string username)
    {
        return await _userManager.Users.FirstOrDefaultAsync(u => u.UserName == username);
    }

    public async Task<string> GetUserId(string name)
    {
        var users = await _userManager.Users.ToListAsync();
        return users.FirstOrDefault(u => u.UserName == name).Id;
    }
}
