using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserAccessApi.Models;

namespace UserAccessApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [AllowAnonymous]
    public class TokenCreationController : ControllerBase
    {
        private readonly JwtSettingModel _jwtSettingModel;
        private HttpResponse _response;
        public TokenCreationController(JwtSettingModel jwtSettingModel, HttpResponse response)
        {
            _jwtSettingModel = jwtSettingModel;
            _response = response;
        }

        [HttpPost]
        public async Task<ActionResult<object>> CreateToken(User? user)
        {
            var test = _jwtSettingModel.CookieContainKey;

            if (user is null)
                return Unauthorized();

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
                Issuer = _jwtSettingModel.Issuer,
                Audience = _jwtSettingModel.Audience,
                SigningCredentials = new SigningCredentials
                (new SymmetricSecurityKey(
                    Encoding.ASCII.GetBytes(_jwtSettingModel.Key)),
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

            _response.Cookies.Append(_jwtSettingModel.CookieContainKey, stringToken, cookieOptions);
            return Ok();
        }
    }
}
