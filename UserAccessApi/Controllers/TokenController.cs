using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using UserAccessApi.Models;

namespace UserAccessApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [AllowAnonymous]

    public class TokenController : Controller
    {
        [HttpPost]
        public async Task<object> Authenticate([FromBody] User loginUser)
        {
            var user = await accountRepo.AuthenticateAndLoadUser(loginUser.Name, loginUser.Password);
            if (user == null)
                throw new ApiException("Invalid Login Credentials", 401);

            // APP SPECIFIC: create a state object we can serialize as a single claim
            var UserState = new UserState();

            // track user state through our claim
            UserState.UserIdInt = user.Id;
            UserState.Name = user.Fullname;
            UserState.Email = user.Username;

            // create a new token with token helper and add our claim
            var token = JwtHelper.GetJwtToken(
                user.Username,
                Configuration.JwtToken.SigningKey,
                Configuration.JwtToken.Issuer,
                Configuration.JwtToken.Audience,
                TimeSpan.FromMinutes(Configuration.JwtToken.TokenTimeoutMinutes),
                new[]
                {
            new Claim("UserState", UserState.ToString())
                });

            // also add cookie auth for Swagger Access
            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Username));
            identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    AllowRefresh = true,
                    ExpiresUtc = DateTime.UtcNow.AddDays(1)
                });

            // return the token to API client
            return new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expires = token.ValidTo,
                displayName = user.Fullname
            };
        }
    }
}
