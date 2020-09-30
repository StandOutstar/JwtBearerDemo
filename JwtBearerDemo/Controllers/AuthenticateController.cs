using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtBearerDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JwtBearerDemo.Controllers
{
    [Authorize]
    [Route("auth")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        public AuthenticateController(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; set; }

        [AllowAnonymous]
        [HttpPost("token", Name = nameof(GenerateToken))]
        public IActionResult GenerateToken(LoginUser loginUser)
        {
            if (loginUser.Name != "demouser" || loginUser.Password != "demopassword")
            {
                return Unauthorized();
            }
            
            // 生成 token
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, loginUser.Name)
            };

            var tokenSection = Configuration.GetSection("Security:Token");
            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenSection["Key"]));  // 长度必须超过 16 位
            var signCredential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            
            var jwtToken = new JwtSecurityToken(
                issuer: tokenSection["Issuer"],
                audience: tokenSection["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(3),
                signingCredentials: signCredential
                );

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                expiration = TimeZoneInfo.ConvertTimeFromUtc(jwtToken.ValidTo, TimeZoneInfo.Local)
            });
        }

        [HttpGet("info")]
        public IActionResult Info()
        {
            return Ok(new
            {
                name = "ok"
            });
        }
    }
}