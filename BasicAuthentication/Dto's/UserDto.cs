using BasicAuthentication.Domain;
using Microsoft.IdentityModel.Tokens;
using System.Text.RegularExpressions;

namespace BasicAuthentication.Dto_s;

public class UserDto
{
    public string UserName { get; set; }
    public string Password { get; set; }

    private const string PasswordPattern = @"^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$";
    public bool IsValidPassword(string password)
    {
        return Regex.IsMatch(Password, PasswordPattern);
    }
}
