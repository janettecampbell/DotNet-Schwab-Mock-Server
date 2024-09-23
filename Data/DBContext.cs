using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Schwab.Models;
namespace SchwabSite.Data
{
  public class DBContext : IdentityDbContext<Client>
  {
    public DBContext(DbContextOptions<DBContext> options) : base(options)
    {
      
    }
  }
}