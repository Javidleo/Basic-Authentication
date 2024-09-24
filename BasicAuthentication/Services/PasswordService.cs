using System.Text.RegularExpressions;

namespace BasicAuthentication.Domain;

public class PasswordService
{
    private const string PasswordPattern = @"^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$";

    public bool IsValidPassword(string password)
    {
        return Regex.IsMatch(password, PasswordPattern);
    }
}
