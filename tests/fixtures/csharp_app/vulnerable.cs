// C# fixture -- triggers csharp-001 through csharp-008
// Used by TestCSharpAdapterDepth

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace VulnerableApp
{
    public class Startup
    {
        // csharp-001: hardcoded connection string with Password= literal
        private static readonly string connectionString =
            "Server=prod-db.internal;Database=AppDb;User Id=sa;Password=P@ssw0rd123!;";

        public void ConfigureServices(IServiceCollection services)
        {
            // csharp-002: hardcoded password literal
            string password = "hardcoded_admin_pass";

            // csharp-005: JWT ValidateLifetime disabled
            var tokenParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
            };

            // csharp-006: AllowAnyOrigin -- CORS misconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("OpenPolicy", builder =>
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader());
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            // csharp-007: developer exception page without IsDevelopment guard
            app.UseDeveloperExceptionPage();
            app.UseRouting();
        }
    }

    public class UserController : ControllerBase
    {
        private readonly AppDbContext _db;

        public UserController(AppDbContext db) { _db = db; }

        // csharp-003: ExecuteSqlRaw with string concatenation
        public IActionResult GetUserById(string userId)
        {
            _db.Database.ExecuteSqlRaw("SELECT * FROM Users WHERE Id = " + userId);
            return Ok();
        }

        // csharp-004: SQL string interpolation with SQL keyword
        public IActionResult SearchUsers(string userName)
        {
            var query = $"SELECT * FROM Users WHERE Name = '{userName}'";
            return Ok(query);
        }

        // csharp-008: [HttpPost] with no [ValidateAntiForgeryToken]
        [HttpPost]
        public IActionResult Submit(UserFormModel model)
        {
            return Ok(model);
        }
    }
}
