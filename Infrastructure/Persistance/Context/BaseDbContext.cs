using Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistance.Context;

public class BaseDbContext : IdentityDbContext<User, ApplicationRole, string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, ApplicationRoleClaim, IdentityUserToken<string>>
{
    public BaseDbContext(DbContextOptions options)
        :base(options)
    {
    }
}
