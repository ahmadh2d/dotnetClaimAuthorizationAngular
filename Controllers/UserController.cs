using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Claim.Data.Entities;
using Claim.Models;
using Claim.ViewModels;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace dotnetClaimAuthorizationAngular.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly ILogger<UserController> _logger;
    private readonly UserManager<AppUser> _userManager;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly JWTConfig _jwtConfig;

    public UserController(ILogger<UserController> logger, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IOptions<JWTConfig> jwtConfig)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtConfig = jwtConfig.Value;
    }

    [HttpPost("RegisterUser")]
    public async Task<object> RegisterUser([FromBody] AddUpdateRegisterUserViewModel model)
    {
        try
        {
            AppUser appUser = new AppUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName,
                CreatedOn = DateTime.UtcNow,
                ModifiedOn = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(appUser, model.Password);
            if (result.Succeeded)
            {
                return await Task.FromResult("User is successfully Registered");
            }
            return await Task.FromResult(string.Join(", ", result.Errors.Select(x => x.Description).ToArray()));
        }
        catch (Exception ex)
        {
            return await Task.FromResult(ex.Message);
        }

    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpGet("GetAllUsers")]
    public async Task<object> GetAllUsers()
    {
        try
        {
            var users = from user in _userManager.Users
                        select new UserViewModel
                        {
                            FullName = user.FullName,
                            Email = user.Email,
                            UserName = user.UserName,
                            CreatedOn = user.CreatedOn,
                            ModifiedOn = user.ModifiedOn
                        };
            return await Task.FromResult(users);
        }
        catch (Exception ex)
        {
            return await Task.FromResult(ex.Message);
        }
    }

    [HttpPost("LoginUser")]
    public async Task<object> LoginUser([FromBody] LoginUserViewModel model)
    {
        try
        {
            if (!ModelState.IsValid)
                return await Task.FromResult(model);

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
            if (result.Succeeded)
            {
                var appUser = await _userManager.FindByEmailAsync(model.Email);
                var token = GenerateToken(appUser);

                UserViewModel user = new UserViewModel
                {
                    FullName = appUser.FullName,
                    Email = appUser.Email,
                    UserName = appUser.UserName,
                    CreatedOn = appUser.CreatedOn,
                    Token = token
                };

                return await Task.FromResult(user);
            }

            return await Task.FromResult("Invalid Username or password");
        }
        catch (Exception ex)
        {
            return await Task.FromResult(ex.Message);
        }

    }

    private string GenerateToken(AppUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtConfig.Key);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[] {
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.NameId, user.Id),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Email, user.Email),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        }),
            Expires = DateTime.UtcNow.AddHours(12),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        return jwtTokenHandler.WriteToken(token);
    }
}
