using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class TokenService
{
    private readonly string _secretKey;

    public TokenService(string secretKey)
    {
        _secretKey = secretKey;
    }
    public (string token, DateTime expiryTime) GenerateToken(string userCode)
    {
        var tokenExpiry = DateTime.Now.AddMinutes(1); // Set expiry time (adjust as needed)

        // Token creation logic (e.g., using JWT)
        var token = CreateJwtToken(userCode, tokenExpiry);
        return (token, tokenExpiry);
    }

    private string CreateJwtToken(string userCode, DateTime expiryTime)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, userCode)

        };

        // Symmetric security key
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Generate JWT token
        var token = new JwtSecurityToken(
            issuer: "my_app",
            audience: "my_service",
            claims: claims,
            expires: expiryTime,
            signingCredentials: creds);

        var Token = new JwtSecurityTokenHandler().WriteToken(token);
        return Token;
    }

}
