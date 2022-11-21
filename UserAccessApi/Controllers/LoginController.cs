using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using UserAccessApi.Models;
using UserAccessApi.Utiluties;

namespace UserAccessApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class LoginController : Controller
    {
        private IConfiguration _configuration;
        private JwtSettingModel JwtSettingModel;

        public LoginController (IConfiguration configuration)
        {
            _configuration = configuration;
            JwtSettingModel = _configuration.GetSection(JwtSettingModel.Jwt).Get<JwtSettingModel>();
        }

        [HttpGet]
        public async Task<ActionResult<object>> CheckTokenExist()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            Request.Headers.TryGetValue("cookie", out var cookieValue);
            JwtUtilities jwtUtilities = new(_configuration);
            string jwtString = jwtUtilities.ExtractJwtString(cookieValue);
            var jwtObj = tokenHandler.ReadJwtToken(jwtString);
            string? role = null;
            foreach (var claim in jwtObj.Claims)
            {
                if(claim.Type == "role")
                {
                    role = claim.Value;
                    break;
                }
            }
            return Ok(role);
        }

    }
}
