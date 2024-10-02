using BasicAuthentication.Dto_s;
using BasicAuthentication.Helper;
using BasicAuthentication.Infrastructure;
using BasicAuthentication.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace BasicAuthentication.Controllers;

[Route("api/[Controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private IConfiguration _config;
    private readonly AppDbContext _context;
    public AuthController(IConfiguration config, AppDbContext context)
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

        if (user.Password == dto.Password)
        {
            var token = JwtCreator.CreateToken(user.UserName,
                _config["Jwt:Key"],
                DateTime.Now.AddMinutes(10),
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"]);

            var refreshtoken = JwtCreator.CreateRefreshToken(user.UserName);

            TokenVm vm = new TokenVm()
            {
                AccessToken = token,
                RefreshToken = refreshtoken
            };
            user.RefreshToken = refreshtoken;
            user.RefreshTokenExpirationTime = DateTime.Now.AddDays(10);
            
            _context.SaveChanges();
            
            return Ok(vm);
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
        if (user is null)
        {
            return NotFound("not found");
        }
        var refreshToken = JwtCreator.CreateRefreshToken(user.UserName);

        return Ok(refreshToken);
    }
}
