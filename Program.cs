using MySqlConnector;
using Microsoft.AspNetCore.Identity;
using Schwab.Models;
using Microsoft.Extensions.DependencyInjection;
using SchwabSite.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);
// MySQL connection
// builder.Services.AddMySqlDataSource(builder.Configuration.GetConnectionString("DefaultConnection")!);
// var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
// builder.Services.AddDbContext<DBContext>(options => 
// {
//   options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
// });
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddTransient<MySqlConnection>(_ => new MySqlConnection(connectionString)); // Register MySqlConnection service

// Register ICorsService
builder.Services.AddCors(options =>
{
  options.AddPolicy("AllowSpecificOrigin",
      policy =>
      {
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyHeader()
              .AllowAnyMethod();
      });
});

// Register authorization services
builder.Services.AddAuthorization();

// Configure JWT authentication
var key = builder.Configuration["JWTSetting:SecurityKey"];
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
        ValidIssuer = builder.Configuration["JWTSetting:Issuer"],
        ValidAudience = builder.Configuration["JWTSetting:Audience"]
    };
});

var app = builder.Build();

// Create the PasswordHasher instance
var passwordHasher = new PasswordHasher<Client>();

// Middleware configuration
app.UseCors("AllowSpecificOrigin");
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/clients", async (Client newClient, MySqlConnection connection) =>
{
  // Hash the password before storing it
  var hashedPassword = passwordHasher.HashPassword(newClient, newClient.password);
  newClient.password = hashedPassword;  // Update the password with its hashed version

  // Insert the new client into the database
  var query = "INSERT INTO clients (first_name, last_name, login_ID, password) VALUES (@first_name, @last_name, @login_ID, @password)";

  using var cmd = new MySqlCommand(query, connection);
  cmd.Parameters.AddWithValue("@first_name", newClient.first_name);
  cmd.Parameters.AddWithValue("@last_name", newClient.last_name);
  cmd.Parameters.AddWithValue("@login_ID", newClient.login_ID);
  cmd.Parameters.AddWithValue("@password", newClient.password);

  await connection.OpenAsync();
  await cmd.ExecuteNonQueryAsync();

  return Results.Ok(newClient);
});

app.MapPost("/login", async (Client loginUser, MySqlConnection connection) =>
{
  var query = "SELECT login_ID, password FROM clients WHERE login_ID = @login_ID";

  using var cmd = new MySqlCommand(query, connection);
  cmd.Parameters.AddWithValue("@login_ID", loginUser.login_ID);

  await connection.OpenAsync();
  using var reader = await cmd.ExecuteReaderAsync();

  if (await reader.ReadAsync())
  {
    var dbClient = new Client
    {
      login_ID = reader.GetString(0),
      password = reader.GetString(1),
    };

    // Verify the password
    var result = passwordHasher.VerifyHashedPassword(dbClient, dbClient.password, loginUser.password);

    if (result == PasswordVerificationResult.Success)
    {
      // Generate JWT token
            var token = GenerateJwtToken(dbClient.login_ID);
            return Results.Ok(new {isSuccess = true, Token = token });
    }
    else
    {
      return Results.Unauthorized();
    }
  }

  return Results.NotFound("User not found");
});

// Method to generate JWT token
string GenerateJwtToken(string loginId)
{
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, loginId)
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWTSetting:SecurityKey"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: builder.Configuration["JWTSetting:Issuer"],
        audience: builder.Configuration["JWTSetting:Audience"],
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: creds);

    return new JwtSecurityTokenHandler().WriteToken(token);
};

app.Run();