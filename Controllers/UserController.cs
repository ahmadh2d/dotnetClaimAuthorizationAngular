using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Claim.Data;
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
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly JWTConfig _jwtConfig;
    private readonly AppDBContext _appDBContext;

    public UserController(ILogger<UserController> logger, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IOptions<JWTConfig> jwtConfig, RoleManager<IdentityRole> roleManager, AppDBContext appDBContext)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtConfig = jwtConfig.Value;
        _roleManager = roleManager;
        _appDBContext = appDBContext;
    }

    [HttpPost("RegisterUser")]
    public async Task<object> RegisterUser([FromBody] AddUpdateRegisterUserViewModel model)
    {
        try
        {
            if (model.Roles == null)
            {
                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Failed! Roles are missing", DataSet = null });
            }

            foreach (var role in model.Roles)
            {
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Oops! Role doesn't exist", DataSet = null });
                }
            }


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

                var tempUser = await _userManager.FindByEmailAsync(user.Email);

                user.Roles = new List<string>();
                foreach (var role in model.Roles)
                {
                    user.Roles.Add(role);
                    await _userManager.AddToRoleAsync(tempUser, role);
                }

                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "User is successfully Registered", DataSet = user });
            }
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Failed! Correct the fields", DataSet = result.Errors.Select(x => x.Description).ToArray() });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = ex.Message, DataSet = null });
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
                var roles = (await _userManager.GetRolesAsync(appUser)).ToList();
                var token = GenerateToken(appUser, roles);

                UserViewModel user = new UserViewModel
                {
                    FullName = appUser.FullName,
                    Email = appUser.Email,
                    UserName = appUser.UserName,
                    CreatedOn = appUser.CreatedOn,
                    Token = token,
                    Roles = roles
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


    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
    [HttpGet("GetAllUsers")]
    public async Task<object> GetAllUsers()
    {
        try
        {
            // var users = from user in _appDBContext.Users
            //             join userRole in _appDBContext.UserRoles on user.Id equals userRole.UserId into ps
            //             from p in ps.DefaultIfEmpty()
            //             join role in _appDBContext.Roles on p.RoleId equals role.Id into ks
            //             from k in ks.DefaultIfEmpty()
            //             select new UserViewModel
            //             {
            //                 FullName = user.FullName,
            //                 Email = user.Email,
            //                 UserName = user.UserName,
            //                 CreatedOn = user.CreatedOn,
            //                 ModifiedOn = user.ModifiedOn,
            //                 // Roles = k.Name
            //             };
            var users = (from user in _appDBContext.Users
                         let query = (from userRole in _appDBContext.UserRoles
                                      where (userRole.UserId.Equals(user.Id) || userRole.UserId.Equals(null))
                                      join role in _appDBContext.Roles on userRole.RoleId equals role.Id into ks
                                      from k in ks.DefaultIfEmpty()
                                      select k.Name).ToList()
                         select new UserViewModel
                         {
                             FullName = user.FullName,
                             Email = user.Email,
                             UserName = user.UserName,
                             CreatedOn = user.CreatedOn,
                             ModifiedOn = user.ModifiedOn,
                             Roles = query
                         }).ToList();

            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "Success! All users get", DataSet = users });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = ex.Message, DataSet = null });
        }
    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User,Admin")]
    [HttpGet("GetUsers")]
    public async Task<object> GetUsers()
    {
        try
        {
            var users = from user in _appDBContext.Users
                        join userRole in _appDBContext.UserRoles on user.Id equals userRole.UserId
                        join role in _appDBContext.Roles on userRole.RoleId equals role.Id
                        where role.Name == "User"
                        let query = (from role in _appDBContext.Roles
                                     where role.Id.Equals(userRole.RoleId)
                                     select role.Name).ToList()
                        select new UserViewModel
                        {
                            FullName = user.FullName,
                            Email = user.Email,
                            UserName = user.UserName,
                            CreatedOn = user.CreatedOn,
                            ModifiedOn = user.ModifiedOn,
                            Roles = query
                        };
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "Success! All users get", DataSet = users });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = ex.Message, DataSet = null });
        }
    }


    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
    [HttpPost("AddRole")]
    public async Task<object> AddRole([FromBody] AddRoleViewModel addRoleViewModel)
    {
        try
        {
            if (!ModelState.IsValid)
                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Please fill up all parameters", DataSet = null });

            if (await _roleManager.RoleExistsAsync(addRoleViewModel.Role))
            {
                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "This role already exists", DataSet = null });
            }

            IdentityRole role = new IdentityRole();
            role.Name = addRoleViewModel.Role;

            var result = await _roleManager.CreateAsync(role);

            if (result.Succeeded)
            {
                return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = $"Success! new role '{role.Name}' is created ", DataSet = null });
            }

            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = "Failed! new role not created", DataSet = null });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = ex.Message, DataSet = null });
        }
    }

    [HttpGet("GetRoles")]
    public async Task<object> GetRoles()
    {
        try
        {
            var roles = _appDBContext.Roles.Select(x => new { Id = x.Id, RoleName = x.Name });

            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Success, ResponseMessage = "Success, Here are all roles", DataSet = roles });
        }
        catch (Exception ex)
        {
            return await Task.FromResult(new ResponseAPIViewModel { ResponseStatusCode = ResponseStatus.Failure, ResponseMessage = ex.Message, DataSet = null });
        }
    }

    private string GenerateToken(AppUser user, List<string> roles)
    {
        var claims = new List<System.Security.Claims.Claim>() {
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.NameId, user.Id),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Email, user.Email),
            new System.Security.Claims.Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        foreach (var role in roles)
        {
            claims.Add(new System.Security.Claims.Claim(ClaimTypes.Role, role));
        }

        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtConfig.Key);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(12),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        return jwtTokenHandler.WriteToken(token);
    }
}
