using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetAuthTokenProject.Models;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace NetAuthTokenProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppSettings _applicationSettings;
        public AuthController(IOptions<AppSettings> applicationSettings)
        {
            this._applicationSettings = applicationSettings.Value;
            userList.Add(new Models.User() { UserName = "marcetic.mihailo99@gmail.com", Role = "Admin" });
        }

        private static List<User> userList = new List<User>();


        [HttpPost("Login")]
        public IActionResult Login([FromBody] Login model)
        {
            var user = userList.Where(u => u.UserName == model.UserName).FirstOrDefault();

            if (user == null)
            {
                return BadRequest("User name or password was invalid");
            }

            var match = CheckPassword(model.Password, user);

            if (!match)
            {
                return BadRequest("User name or password was invalid");
            }
            JwtGenerator(user);
            return Ok();
        }

        [HttpPost("Register")]
        public IActionResult Register([FromBody] Register model)
        {
            var user = new User() { UserName = model.UserName, Role = model.Role };

            if (model.ConfirmPassword == model.Password)
            {
                using (HMACSHA512? hmac = new HMACSHA512())
                {
                    user.PasswordSalt = hmac.Key;
                    user.PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(model.Password));
                }
            }
            else
            {
                return BadRequest("Passwords don't match");
            }
            userList.Add(user);

            return Ok(user);
        }

        [HttpPost("LoginWithGoogle")]
        public async Task<IActionResult> LoginWithGoogle([FromBody] string credentials)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new List<string> { this._applicationSettings.GoogleClientId }
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(credentials, settings);

            var user = userList.Where(x => x.UserName == payload.Email).FirstOrDefault();

            if (user != null)
            {
                JwtGenerator(user);
                return Ok();
            }
            else
            {
                return BadRequest();
            }
        }

        //this metod will generate new jwt token, when current jwt token expires
        [HttpGet("RefreshToken")]
        public ActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["X-Refresh-Token"];

            var user = userList.Where(x => x.Token == refreshToken).FirstOrDefault();

            if (user == null || user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token has expired");
            }
            JwtGenerator(user);

            return Ok();
        }

        //this metod will be called as the last method to delete current refresh token on that user
        //if refresh token expires or refresh token is invalid, and user will have to login again 
        //to get new refresh token
        [HttpDelete("RevokeToken/{username}")]
        public async Task<IActionResult> RevokeToken(string username)
        {
            userList.Where(x => x.UserName == username).Select(x => x.Token = string.Empty);

            return Ok();
        }

        private dynamic JwtGenerator(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(this._applicationSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                    new Claim("id", user.UserName),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };


            var token = tokenHandler.CreateToken(tokenDescriptor);
            var encripterToken = tokenHandler.WriteToken(token);

            SetJwt(encripterToken);

            var refreshToken = GenerateRefreshToken();

            SetRefreshToken(refreshToken, user);

            return new { token = encripterToken, username = user.UserName };
        }

        private bool CheckPassword(string password, User user)
        {
            bool result;

            using (HMACSHA512? hmac = new HMACSHA512(user.PasswordSalt))
            {
                var compute = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                result = compute.SequenceEqual(user.PasswordHash);
            }
            return result;

        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Created = DateTime.Now,
                Expires = DateTime.Now.AddMinutes(2)
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken refreshToken, User user)
        {
            HttpContext.Response.Cookies.Append("X-Refresh-Token", refreshToken.Token,
                new CookieOptions
                {
                    Expires = refreshToken.Expires,
                    HttpOnly = true,
                    Secure = true,
                    IsEssential = true,
                    SameSite = SameSiteMode.None
                });

            userList.Where(x => x.UserName == user.UserName).First().Token = refreshToken.Token;
            userList.Where(x => x.UserName == user.UserName).First().TokenExpires = refreshToken.Expires;
            userList.Where(x => x.UserName == user.UserName).First().TokenCreated = refreshToken.Created;


        }

        private void SetJwt(string encriptedToken)
        {
            HttpContext.Response.Cookies.Append("X-Access-Token", encriptedToken,
                new CookieOptions
                {
                    Expires = DateTime.Now.AddMinutes(1),
                    HttpOnly = true,
                    Secure = true,
                    IsEssential = true,
                    SameSite = SameSiteMode.None
                });
        }
    }
}
