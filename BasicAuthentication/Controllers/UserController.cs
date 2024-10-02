using BasicAuthentication.Domain;
using BasicAuthentication.Dto_s;
using BasicAuthentication.Helper;
using BasicAuthentication.Infrastructure;
using BasicAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BasicAuthentication.Controllers;

[Route("api/[Controller]")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly PasswordService _service;
    public UserController(AppDbContext context, PasswordService service)
    {
        _context = context;
        _service = service;
    }
    [Authorize]
    [HttpGet]
    public IActionResult GetProfile()
    {
        var userName = JwtCreator.GetUserName(HttpContext.User);

        var userName2 = HttpContext.User.GetUserName();

        var user = _context.Users.FirstOrDefault(i => i.UserName == userName);

        return Ok(user);
    }


    [HttpPost]
    public IActionResult RegisterUser([FromBody] UserDto dto)
    {
        if (!_service.IsValidPassword(dto.Password))
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
}


