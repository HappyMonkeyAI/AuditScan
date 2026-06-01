// C# fixture -- clean of all csharp-001..csharp-008 detectors
// Used by TestCSharpAdapterDepth to verify no false positives

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace SafeApp
{
    public class Startup
    {
        // Safe: connection string from environment variable, no embedded credentials
        private static readonly string connectionString =
            Environment.GetEnvironmentVariable("DB_CONNECTION_STRING") ?? string.Empty;

        public void ConfigureServices(IServiceCollection services)
        {
            // Safe: credential from environment, not a literal
            string credential = Environment.GetEnvironmentVariable("APP_CREDENTIAL");

            // Safe: ValidateLifetime is true (default-safe)
            var tokenParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
            };

            // Safe: specific allowed origin, not AllowAnyOrigin
            services.AddCors(options =>
            {
                options.AddPolicy("RestrictedPolicy", builder =>
                    builder.WithOrigins("https://app.example.com")
                           .AllowAnyMethod()
                           .AllowAnyHeader());
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Safe: exception page behind environment guard -- note: no UseDeveloperExceptionPage call here
            if (env.IsDevelopment())
            {
                app.UseExceptionHandler("/dev-error");
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseRouting();
        }
    }

    public class UserController : ControllerBase
    {
        private readonly AppDbContext _db;

        public UserController(AppDbContext db) { _db = db; }

        // Safe: parameterized EF Core query, no raw SQL with user input
        public IActionResult GetUserById(int userId)
        {
            var user = _db.Users.FirstOrDefault(u => u.Id == userId);
            return Ok(user);
        }

        // Safe: parameterized FromSqlRaw with {0} placeholder
        public IActionResult SearchUsers(string term)
        {
            var results = _db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = {0}", term);
            return Ok(results);
        }

        // Safe: [HttpPost] with [ValidateAntiForgeryToken] present
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Submit(UserFormModel model)
        {
            return Ok(model);
        }

        // Safe: GET endpoint (read-only, no antiforgery needed)
        [HttpGet]
        public IActionResult ListUsers()
        {
            return Ok(_db.Users.ToList());
        }
    }
}
