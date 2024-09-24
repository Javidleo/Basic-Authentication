using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BasicAuthentication.JwtCreator;

public class JwtCreator
{
    public static ClaimsPrincipal GetDataFromExpiredToken(string token,
        string issuer,
        string audience,
        string signingKey)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateLifetime = false,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidIssuer = issuer,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");

        return principal;

    }

    public static (string Token, DateTime Expiration) GetJwtToken(
        string username,
        string signingKey,
        string issuer,
        string audience,
        TimeSpan expiration,
        Claim[] additionalClaims = null)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub,username),
            new Claim(JwtRegisteredClaimNames.Name,username),
            // this guarantees the token is unique
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        if (additionalClaims is object)
        {
            var claimList = new List<Claim>(claims);
            claimList.AddRange(additionalClaims);
            claims = claimList.ToArray();
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expirationDate = DateTime.UtcNow.Add(expiration);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            expires: expirationDate,
            claims: claims,
            signingCredentials: creds
        );
        return (new JwtSecurityTokenHandler().WriteToken(token), expirationDate);
    }
    public static (string Token, DateTime Expiration) GetRefreshToken(
       string username,
        string signingKey,
        string issuer,
        string audience,
        TimeSpan expiration)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expirationDate = DateTime.UtcNow.Add(expiration);

        var refreshToken = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            expires: expirationDate,
            signingCredentials: creds);

        return (new JwtSecurityTokenHandler().WriteToken(refreshToken), expirationDate);
    }
}
