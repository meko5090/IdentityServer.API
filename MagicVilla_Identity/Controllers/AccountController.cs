using IdentityModel;
using MagicVilla_Identity.Models;
using MagicVilla_Identity.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MagicVilla_Identity.Controllers;

[Route("api")]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AccountController(
        UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleInManager
          )
    {
        _roleManager = roleInManager;
        _userManager = userManager;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = new ApplicationUser()
        {
            UserName = model.Email,
            Email = model.Email,
            EmailConfirmed = true,
            Name = model.Name,
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            var isRoleExist = await _roleManager.RoleExistsAsync(model.RoleName);
            // creeate role if not exist
            if (!isRoleExist)
            {
                var userRole = new IdentityRole
                {
                    Name = model.RoleName,
                    NormalizedName = model.RoleName,
                };
                await _roleManager.CreateAsync(userRole);
            }
            await _userManager.AddToRoleAsync(user, model.RoleName);

            await _userManager.AddClaimsAsync(user, new Claim[] {
                    new Claim(JwtClaimTypes.Name,model.Email),
                    new Claim(JwtClaimTypes.Email,model.Email),
                    new Claim(JwtClaimTypes.Role,model.RoleName)
                });

            return Ok("Account created successfully");
        }
        else
        {
            return BadRequest(result.Errors);
        }
    }
}