using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using static System.Runtime.InteropServices.JavaScript.JSType;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;
    private readonly AppDbContext _dbContext;
    private readonly SymmetricSecurityKey _signingKey;

    public AuthController(TokenService tokenService, AppDbContext dbContext)
    {
        _tokenService = tokenService;
        _dbContext = dbContext;
        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
    }

    private readonly string _secretKey = Guid.NewGuid().ToString("N"); // Generate a random secret key

    // Token generation method

    [HttpPost("Token")]
    public async Task<IActionResult> GetToken([FromBody] LoginRequest request)
    {
        // Authenticate the user
        if (await AuthenticateUser(request.user_code, request.user_password))
        {
            // Fetch user details from the database
            var user = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_code == request.user_code);

            if (user == null)
            {
                return Unauthorized(new
                {
                    message = "User not found.",
                    status = false
                });
            }

            // Generate the token
            var (token, expiryTime) = _tokenService.GenerateToken(request.user_code);

            // Remove any existing token for the user
            var existingToken = await _dbContext.AdmMstTtokens.FirstOrDefaultAsync(t => t.user_gid == user.user_gid);
            if (existingToken != null)
            {
                _dbContext.AdmMstTtokens.Remove(existingToken);
                await _dbContext.SaveChangesAsync();
            }

            // Create a new token entity
            var tokenEntity = new adm_mst_ttokens
            {
                user_code = request.user_code,
                user_gid = user.user_gid,
                TokenType = "Bearer",
                Token = token,
                ExpiryTime = expiryTime
            };

            // Add the token entity to the database
            _dbContext.AdmMstTtokens.Add(tokenEntity);
            await _dbContext.SaveChangesAsync();

            // Set the token in a cookie
            Response.Cookies.Append("Authorization", $"{token}", new CookieOptions
            {
                HttpOnly = true,
                Expires = expiryTime
            });

            // Return the token details
            return Ok(new
            {
                TokenType = "Bearer",
                Token = token,
                ExpiryTime = expiryTime
            });
        }

        // Return Unauthorized if authentication fails
        return Unauthorized(new
        {
            message = "Invalid user credentials.",
            status = false
        });
    }

    private void SetCookie(string key, string value, int expires)
    {
        var cookieOptions = new CookieOptions
        {
            Expires = DateTime.Now.AddMinutes(expires)
        };
        Response.Cookies.Append(key, value, cookieOptions);
    }

    // Authenticate user based on provided credentials
    private async Task<bool> AuthenticateUser(string user_code, string user_password)
    {
        var user = await _dbContext.AdmMstTuser
            .FirstOrDefaultAsync(u => u.user_code == user_code);
        string ascii_password = ConvertToAscii(user_password);
        if (user != null && user.user_password == ascii_password)
        {
            return true;
        }

        return false;
    }
    private string ConvertToAscii(string str)
    {
        int iIndex;
        int lenOfUserString;
        string newUserPass = string.Empty;
        string tmp;
        lenOfUserString = str.Length;
        for (iIndex = 0; iIndex < lenOfUserString; iIndex++)
        {
            tmp = str.Substring(iIndex, 1);
            tmp = (((int)Convert.ToChar(tmp)) - lenOfUserString).ToString();
            newUserPass = newUserPass + (tmp.Length < 3 ? "0" : "") + tmp;
        }
        return newUserPass;
    }
    // Secured endpoint to get user details
    [HttpGet("GetUsers")]
    [Authorize]
    public async Task<IActionResult> GetUserDetails()
    {
        var token = Request.Cookies["Authorization"];
        string? user_gid = await ValidateTokenAsync(token);

        if (string.IsNullOrEmpty(user_gid))
        {
            return Unauthorized(new
            {
                message = "Invalid token.",
                status = false
            });
        }


        var users = await _dbContext.AdmMstTuser.ToListAsync();

        if (users != null)
        {
            return Ok(new
            {
                users
                // Add other details if necessary
            });
        }
        else
        {
            return NotFound(new
            {
                message = "No users found.",
                status = false
            });
        }
    }

    [HttpGet("GetUsersWithCode/{userCode}")]
    public async Task<IActionResult> GetUserDetailsBasedOnCode(string userCode)
    {
        // Retrieve token from the Authorization header
        var token = Request.Cookies["Authorization"];
        string? user_gid = await ValidateTokenAsync(token);

        if (string.IsNullOrEmpty(user_gid))
        {
            return Unauthorized(new
            {
                message = "Invalid token.",
                status = false
            });
        }


        // Fetch user details from the database
        var user = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_code == userCode);

        if (user == null)
        {
            return Unauthorized(new
            {
                message = "User not found.",
                status = false
            });
        }
        else
        {

            // Return sanitized user details
            return Ok(new
            {
                user
                // Add other details if necessary
            });
        }
    }
    [HttpPost("CreateUser")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserDto values)
    {
        var token = Request.Cookies["Authorization"];
        string? user_gid = await ValidateTokenAsync(token);

        if (string.IsNullOrEmpty(user_gid))
        {
            return Unauthorized(new
            {
                message = "Invalid token.",
                status = false
            });
        }

        // Check if all required fields are provided
        if (string.IsNullOrEmpty(values.user_code) || string.IsNullOrEmpty(values.user_password))
        {
            return BadRequest(new
            {
                message = "User code and password are required.",
                status = false
            });
        }

        // Check if a user with the same code already exists
        var existingUser = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_code == values.user_code);
        if (existingUser != null)
        {
            return Conflict(new
            {
                message = "A user with this code already exists.",
                status = false
            });
        }
        string ascipassword = ConvertToAscii(values.user_password);
        // Create a new user entity
        var newUser = new adm_mst_tuser
        {
            user_gid = Guid.NewGuid().ToString(), // Generate a new unique ID
            user_code = values.user_code,
            user_password = ascipassword,
            user_firstname = values.user_firstname,
            user_lastname = values.user_lastname
        };

        // Add the new user to the DbContext
        _dbContext.AdmMstTuser.Add(newUser);
        await _dbContext.SaveChangesAsync();

        // Return the newly created user
        return Ok(new
        {
            message = "User Created Successfully",
            status = true
        });
        //return Ok(new
        //{
        //    user_gid = newUser.user_gid,
        //    user_code = newUser.user_code,
        //    user_firstname = newUser.user_firstname,
        //    user_lastname = newUser.user_lastname
        //});
    }
    [HttpDelete("DeleteUser/{usergid}")]
    public async Task<IActionResult> DeleteUser(string usergid)
    {
        var token = Request.Cookies["Authorization"];
        string? user_gid = await ValidateTokenAsync(token);

        if (string.IsNullOrEmpty(user_gid))
        {
            return Unauthorized(new
            {
                message = "Invalid token.",
                status = false
            });
        }

        // Check if the user code is provided
        if (string.IsNullOrEmpty(usergid))
        {
            return BadRequest(new
            {
                message = "User code is required.",
                status = false
            });
        }

        // Find the user by code
        var user = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_gid == usergid);
        if (user == null)
        {
            return NotFound(new
            {
                message = "User not found.",
                status = false
            });
        }

        // Delete the user
        _dbContext.AdmMstTuser.Remove(user);
        await _dbContext.SaveChangesAsync();

        // Return a success response
        return Ok(new
        {
            message = "User deleted successfully.",
            status = true
        });
    }
    [HttpPut("UpdateUser/{usergid}")]
    public async Task<IActionResult> UpdateUser(string usergid, [FromBody] CreateUserDto values)
    {
        var token = Request.Cookies["Authorization"];
        string? user_gid = await ValidateTokenAsync(token);

        if (string.IsNullOrEmpty(user_gid))
        {
            return Unauthorized(new
            {
                message = "Invalid token.",
                status = false
            });
        }

        // Check if the user ID is provided
        if (string.IsNullOrEmpty(usergid))
        {
            return BadRequest(new { message = "User ID is required.", status = false });
        }

        // Find the user by ID
        var user = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_gid == usergid);
        if (user == null)
        {
            return NotFound(new { message = "User not found.", status = false });
        }
        var users = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_code == values.user_code);
        if (users != null && user.user_gid != users.user_gid)
        {
            return NotFound(new { message = "User Code Already Exist", status = false });
        }
        try
        {
            // Update the user's details
            user.user_code = values.user_code;
            user.user_firstname = values.user_firstname;
            user.user_lastname = values.user_lastname;

            if (!string.IsNullOrEmpty(values.user_password))
            {
                user.user_password = ConvertToAscii(values.user_password);
            }

            // Save the changes
            await _dbContext.SaveChangesAsync();
            return Ok(new
            {
                message = "User Update successfully.",
                status = true
            });
        }
        catch (Exception ex)
        {
            // Log the exception
            // _logger.LogError(ex, "Error updating user.");

            return StatusCode(500, new { message = "An error occurred while updating the user.", status = false });
        }

        // Return a success response
        return Ok(new
        {
            message = "User updated successfully.",
            status = true
        });
    }

    private async Task<string?> ValidateTokenAsync(string token)
    {
        // Check if the token exists and is still valid
        var tokenEntity = await _dbContext.AdmMstTtokens
            .FirstOrDefaultAsync(t => t.Token == token && t.ExpiryTime > DateTime.Now);

        // Return the user_gid if the token is valid, otherwise return null
        return tokenEntity?.user_gid;
    }
    [HttpGet("ReverseAscii/{userCode}")]
    public async Task<IActionResult> ReverseAscii(string userCode)
    {
        // The [Authorize] attribute ensures that a valid token is present
        // You can access the authenticated user's claims here
        var token = Request.Cookies["Authorization"];
        string? user_gid = await ValidateTokenAsync(token);

        if (string.IsNullOrEmpty(user_gid))
        {
            return Unauthorized(new
            {
                message = "Invalid token.",
                status = false
            });
        }
        // Fetch the encoded string and original length based on userCode
        string? encodedStr = await GetEncodedStringFromDatabaseOrService(userCode);
        int originalLength = await GetOriginalLengthFromDatabaseOrService(userCode);

        if (encodedStr == null)
        {
            return NotFound(new
            {
                message = "Encoded string not found.",
                status = false
            });
        }

        // Reverse the encoded string
        string reversedWords = ReverseAscii(encodedStr, originalLength);

        // Fetch user details
        var user = await _dbContext.AdmMstTuser.FirstOrDefaultAsync(u => u.user_code == userCode);
        if (user == null)
        {
            return NotFound(new
            {
                message = "User not found.",
                status = false
            });
        }

        // Return user details along with the reversed password
        return Ok(new
        {
            Actualpassword = reversedWords,
            user_gid = user.user_gid,
            user_firstname = user.user_firstname,
            user_lastname = user.user_lastname
        });
    }
    private string ReverseAscii(string encodedStr, int originalLength)
    {
        string reversedWords = string.Empty;
        int lstemp = encodedStr.Length / 3;
        int j = 0;
        for (int i = 0; i < lstemp; i++) // Process each group of three characters.
        {
            string numberStr = encodedStr.Substring(j, 3);
            int number = int.Parse(numberStr);
            char character = (char)(number + lstemp);
            reversedWords += character;
            j = j + 3;
        }

        return reversedWords;
    }

    // Replace with your implementation to retrieve the encoded string from a database or service
    private async Task<string> GetEncodedStringFromDatabaseOrService(string userCode)
    {
        var user = await _dbContext.AdmMstTuser
            .FirstOrDefaultAsync(u => u.user_code == userCode);

        return user?.user_password;
    }
    // Replace with your implementation to retrieve the original length from a database or service
    private async Task<int> GetOriginalLengthFromDatabaseOrService(string userCode)
    {
        var user = await _dbContext.AdmMstTuser
            .FirstOrDefaultAsync(u => u.user_code == userCode);

        return user?.user_password?.Length ?? 0;
    }
}

    public class LoginRequest
{
    public string user_code { get; set; }
    public string user_password { get; set; }
}
public class adm_mst_tuser
{
    public string user_gid { get; set; }
    public string user_code { get; set; }
    public string user_password { get; set; }
    public string? user_firstname { get; set; }
    public string? user_lastname { get; set; }
    // Other properties as needed
}
public class CreateUserDto
{
    public string user_code { get; set; }
    public string user_password { get; set; }
    public string? user_firstname { get; set; }
    public string? user_lastname { get; set; }
}
public class adm_mst_ttokens
{
    public string TokenType { get; set; }
    public string Token { get; set; }
    public DateTime ExpiryTime { get; set; }
    public string? user_code { get; set; }
    public string? user_gid { get; set; }
    public int token_id { get; set; }
    // Other properties as needed
}


