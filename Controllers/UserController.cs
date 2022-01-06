using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Claim.Data.Entities;
using Claim.Enums;
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
                var user = new UserViewModel()
                {
                    FullName = appUser.FullName,
                    Email = appUser.Email,
                    UserName = appUser.UserName
                };

                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "User is successfully Registered", DataSet = user });
            }
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Failed! Correct the fields", DataSet = result.Errors.Select(x => x.Description).ToArray() });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = ex.Message, DataSet = null });
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
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "Success! All users get", DataSet = users });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = ex.Message, DataSet = null });
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

                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "Success! You are logged in", DataSet = user });
            }

            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Invalid Username or password", DataSet = null });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = ex.Message, DataSet = null });
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
