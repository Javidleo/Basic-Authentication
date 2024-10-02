using BasicAuthentication.Dto_s;
using BasicAuthentication.Helper;
using BasicAuthentication.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace BasicAuthentication.Controllers;

[Route("api/[Controller]")]
[ApiController]
public class JwtController : ControllerBase
{
    private IConfiguration _config;
    private readonly AppDbContext _context;
    public JwtController(IConfiguration config, AppDbContext context)
    {
        _config = config;
        _context = context;
    }

    [HttpPost("token")]
    public IActionResult Login(UserDto dto)
    {
        var user = _context.Users.FirstOrDefault(u => u.UserName == dto.UserName);
        if (user is null)
            return NotFound("user notfound");

        if(user.Password == dto.Password)
        {
            var token = JwtCreator.CreateToken(user.UserName,
                _config["Jwt:Key"],
                DateTime.Now.AddMinutes(10),
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"]);

            return Ok(token);
        }
        else
        {
            return BadRequest("invalid credentials");
        }
    }
    [HttpPost("refresh-token")]
    public IActionResult GenerateRefreshToken(UserDto dto)
    {
        var user = _context.Users.FirstOrDefault(u => u.UserName == dto.UserName);

        var refreshToken = JwtCreator.CreateRefreshToken(user.UserName);

        return Ok(refreshToken);
    }
}
