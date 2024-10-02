using BasicAuthentication.Domain;
using BasicAuthentication.Dto_s;
using BasicAuthentication.Helper;
using BasicAuthentication.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace BasicAuthentication.Controllers;

[Route("api/[Controller]")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly AppDbContext _context;
    private const string PasswordPattern = @"^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$";
    public UserController(AppDbContext context)
    {
        _context = context;
    }
    [Authorize]
    [HttpGet]
    public IActionResult GetUserName()
    {
        var userName = JwtCreator.GetUserName(HttpContext.User);

        var userName2 = HttpContext.User.GetUserName();

        var user = _context.Users.FirstOrDefault(i => i.UserName == userName);

        return Ok(user);
    }


    [HttpPost]
    public IActionResult RegisterUser([FromBody] UserDto dto)
    {
        if (!IsValidPassword(dto.Password))
        {
            return BadRequest("Password is weak, it must be at least 8 characters, include numbers and special characters!");
        }

        if (dto.Password.Length <= 8)
        {
            return BadRequest("you have to input 8 characaters at least!");
        }

        var exist = _context.Users.Any(i => i.UserName == dto.UserName);

        if (exist == true)
        {
            return BadRequest("this username is already taken!");
        }

        var user = new User
        {
            UserName = dto.UserName,
            Password = dto.Password
        };

        _context.Users.Add(user);
        _context.SaveChanges();

        return Ok(user);
    }
    
    private bool IsValidPassword(string password)
    {
        return Regex.IsMatch(password, PasswordPattern);
    }
}


