using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistance.Context;

public class ApplicationDbContext : BaseDbContext
{
    public ApplicationDbContext(DbContextOptions options)
        : base(options)
    {
    }
}
