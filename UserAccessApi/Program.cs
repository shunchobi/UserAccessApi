using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using UserAccessApi.Models;
using SameSiteMode = Microsoft.AspNetCore.Http.SameSiteMode;


var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers();


builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/login";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.AccessDeniedPath = "/Forbidden/";
}).AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, option =>
{
    option.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"], // string is represent vaild issuer(発行者)
        ValidAudience = builder.Configuration["Jwt:Audience"], // string is represent vaild audience(user)
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true
    };
    option.Events = new JwtBearerEvents()
    {
        OnMessageReceived = context =>
        {
            string cookieContainKey = builder.Configuration["Jwt:CookieContainKey"];
            if (context.Request.Cookies.ContainsKey(cookieContainKey))
            {
                // "X-Access-Tokenのcookieが存在する場合はこの値を認証トークンとして扱う
                context.Token = context.Request.Cookies[cookieContainKey];
            }
            return Task.CompletedTask;
        },
    };
});


builder.Services.AddAuthorization();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// DI definition
builder.Services.Configure<JwtSettingModel>(builder.Configuration.GetSection("Jwt"));


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/security/getMessage",
    [Authorize(Roles = "admin,editor")] // Token生成時のnew Claim(ClaimTypes.Role, user.Name)で指定したuser.Nameの文字列が"adminTest"と同じなら認証されてレスポンスが返る(Roles = "admin,editor")
() => "Hello World!").RequireAuthorization();

app.MapPost("/security/createToken",
[AllowAnonymous] object (User? user, HttpResponse response) =>
{
    if (user is null)
        return Results.Unauthorized();

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("Id", Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, user.Name),
            new Claim(JwtRegisteredClaimNames.Name, user.Name),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        }),
        Expires = DateTime.UtcNow.AddMinutes(5),
        Issuer = builder.Configuration["Jwt:Issuer"],
        Audience = builder.Configuration["Jwt:Audience"],
        SigningCredentials = new SigningCredentials
        (new SymmetricSecurityKey(
            Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"])),
        SecurityAlgorithms.HmacSha512Signature),
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = tokenHandler.WriteToken(token);
    var stringToken = tokenHandler.WriteToken(token);

    var cookieOptions = new CookieOptions()
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Secure = true
    };

    response.Cookies.Append(builder.Configuration["CookieContainKey"], stringToken, cookieOptions);
    return Results.Ok();

});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.UseCookiePolicy();

app.Run();





