using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using UserAccessApi.Models;

namespace UserAccessApi.Controllers
{
    [AllowAnonymous]
    [ApiController]
    [Route("api/[controller]")]
    public class SigninController : Controller
    {
        private readonly IConfiguration _configuration;
        private JwtSettingModel? JwtSettingModel { get; set; }

        public SigninController(IConfiguration configuration)
        {
            _configuration = configuration;
            JwtSettingModel = _configuration.GetSection(JwtSettingModel.Jwt).Get<JwtSettingModel>();
        }


        [HttpPost]
        public async Task<ActionResult<object>> CreateToken(User? user)
        {
            if (user is null)
                return NoContent();

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
                Issuer = JwtSettingModel.Issuer,
                Audience = JwtSettingModel.Audience,
                SigningCredentials = new SigningCredentials
                (new SymmetricSecurityKey(
                    Encoding.ASCII.GetBytes(JwtSettingModel.Key)),
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


            Response.Cookies.Append(JwtSettingModel.CookieContainKey, stringToken, cookieOptions);
            return Ok();
        }
    }
}
