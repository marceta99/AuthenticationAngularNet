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
            this._applicationSettings= applicationSettings.Value;
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

            HttpContext.Response.Cookies.Append("token", encripterToken,
                new CookieOptions
                { 
                    Expires = DateTime.Now.AddDays(7),
                    HttpOnly = true, 
                    Secure=true, 
                    IsEssential=true,
                    SameSite=SameSiteMode.None
                });

            return new {token = encripterToken, username = user.UserName};
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

        [HttpPost("Register")]
        public IActionResult Register([FromBody] Register model)
        {
            var user = new User() { UserName= model.UserName, Role = model.Role };

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
    }
}
