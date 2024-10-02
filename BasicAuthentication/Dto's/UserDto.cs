using BasicAuthentication.Domain;
using Microsoft.IdentityModel.Tokens;
using System.Text.RegularExpressions;

namespace BasicAuthentication.Dto_s;

public class UserDto
{
    public string UserName { get; set; }
    public string Password { get; set; }

   
}
