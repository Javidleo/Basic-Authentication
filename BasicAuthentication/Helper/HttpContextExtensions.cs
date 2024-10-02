using System.Security.Claims;

namespace BasicAuthentication.Helper;

public static class HttpContextExtensions
{
    public static string GetUserName(this ClaimsPrincipal user)
    {
        return user.FindFirstValue(ClaimTypes.NameIdentifier);
    }
}
