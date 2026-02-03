using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Controllers + Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Db + Identity (SQLite)
builder.Services.AddDbContext<AuthDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services
    .AddIdentityCore<IdentityUser>(opt =>
    {
        opt.Password.RequireNonAlphanumeric = false;
        opt.Password.RequireUppercase = false;
        opt.Password.RequireLowercase = false;
        opt.Password.RequireDigit = false;
        opt.Password.RequiredLength = 6;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddSignInManager();

// JWT Auth
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSection["Key"] ?? throw new InvalidOperationException("Missing Jwt:Key");
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSection["Issuer"],
            ValidAudience = jwtSection["Audience"],
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.FromSeconds(10)
        };
    });

// Authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
    options.AddPolicy("AtLeast18", p => p.RequireClaim("age", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"));
});

// CORS
const string CorsPolicyName = "Frontend";
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];

builder.Services.AddCors(opt =>
{
    opt.AddPolicy(CorsPolicyName, p =>
        p.WithOrigins(allowedOrigins)
         .AllowAnyHeader()
         .AllowAnyMethod());
});

var app = builder.Build();

// Auto-create DB (simple for practice)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.EnsureCreatedAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors(CorsPolicyName);

app.UseAuthentication();
app.UseAuthorization();

// ---- Minimal endpoints (ngắn gọn để thực hành) ----

app.MapPost("/auth/register", async (
    RegisterRequest req,
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager) =>
{
    var user = new IdentityUser { UserName = req.Email, Email = req.Email };
    var result = await userManager.CreateAsync(user, req.Password);
    if (!result.Succeeded) return Results.BadRequest(result.Errors);

    // Optional: assign role Admin if requested (for demo)
    if (!string.IsNullOrWhiteSpace(req.Role))
    {
        if (!await roleManager.RoleExistsAsync(req.Role))
            await roleManager.CreateAsync(new IdentityRole(req.Role));

        await userManager.AddToRoleAsync(user, req.Role);
    }

    if (req.Age is not null)
        await userManager.AddClaimAsync(user, new Claim("age", req.Age.Value.ToString()));

    return Results.Ok(new { message = "Registered" });
});

app.MapPost("/auth/login", async (
    LoginRequest req,
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager) =>
{
    var user = await userManager.FindByEmailAsync(req.Email);
    if (user is null) return Results.Unauthorized();

    var ok = await signInManager.CheckPasswordSignInAsync(user, req.Password, lockoutOnFailure: false);
    if (!ok.Succeeded) return Results.Unauthorized();

    var roles = await userManager.GetRolesAsync(user);
    var claims = await userManager.GetClaimsAsync(user);

    var tokenHandler = new JwtSecurityTokenHandler();

    var tokenClaims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, user.Id),
        new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
        new(ClaimTypes.NameIdentifier, user.Id),
        new(ClaimTypes.Name, user.UserName ?? "")
    };

    tokenClaims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
    tokenClaims.AddRange(claims);

    var expiresMinutes = int.TryParse(jwtSection["ExpiresMinutes"], out var m) ? m : 60;

    var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(tokenClaims),
        Expires = DateTime.UtcNow.AddMinutes(expiresMinutes),
        Issuer = jwtSection["Issuer"],
        Audience = jwtSection["Audience"],
        SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
    });

    return Results.Ok(new { accessToken = tokenHandler.WriteToken(token) });
});

app.MapGet("/me", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        name = user.Identity?.Name,
        claims = user.Claims.Select(c => new { c.Type, c.Value })
    });
}).RequireAuthorization();

app.MapGet("/admin", () => Results.Ok("Only Admin can see this"))
   .RequireAuthorization("AdminOnly");

app.MapGet("/age18", () => Results.Ok("Need age claim >= 18 (demo)"))
   .RequireAuthorization("AtLeast18");

app.MapControllers();

app.Run();

// --- DTOs ---
record RegisterRequest(string Email, string Password, string? Role, int? Age);
record LoginRequest(string Email, string Password);

// --- DbContext for Identity ---
sealed class AuthDbContext(DbContextOptions<AuthDbContext> options)
    : IdentityDbContext<IdentityUser, IdentityRole, string>(options) { }
