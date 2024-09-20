using Microsoft.EntityFrameworkCore;
using System.Reflection.Emit;
using webapi.Controllers;
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Define your DbSets here
        // Example:
        // public DbSet<Product> Products { get; set; }
        // public DbSet<Employee> Employees { get; set; }
        public DbSet<adm_mst_tuser> AdmMstTuser { get; set; } // Adjust the DbSet name as needed
        public DbSet<adm_mst_ttokens> AdmMstTtokens { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Configure your entities here
            modelBuilder.Entity<adm_mst_tuser>()
             .ToTable("adm_mst_tuser")
             .HasKey(u => u.user_gid);

            modelBuilder.Entity<adm_mst_tuser>()
                .Property(u => u.user_code)
                .IsRequired();

            modelBuilder.Entity<adm_mst_tuser>()
                .Property(u => u.user_password)
                .IsRequired();
            //modelBuilder.Entity<adm_mst_tuser>()
            //   .Property(u => u.user_lastname)
            //   .IsRequired();
            modelBuilder.Entity<adm_mst_ttokens>()
             .ToTable("adm_mst_ttokens")
             .HasKey(t => t.token_id);

            modelBuilder.Entity<adm_mst_ttokens>()
                .Property(t => t.TokenType)
                .IsRequired();

            modelBuilder.Entity<adm_mst_ttokens>()
                .Property(t => t.Token)
                .IsRequired();

            modelBuilder.Entity<adm_mst_ttokens>()
                .Property(t => t.ExpiryTime)
                .IsRequired();
        }
    }

