using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace AuthenticationTest.Controllers
{
    public class AuthController : Controller
    {
        private IConfiguration _config;

        public AuthController(IConfiguration Configuration)
        {
            this._config = Configuration;
        }

        //Auth/Login
        public IActionResult Login()
        {
            ViewData["Message"] = "Login Page.";

            return View();
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginUser(string returnUrl, string username, string password)
        {
            var self = this;
            var Issuer = self._config.GetValue<string>("myUrl");

            if (username == "Jon" && password == "jon")
            {
                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, "jon", ClaimValueTypes.String, Issuer)
                    };
                var userIdentity = new ClaimsIdentity(claims, "SecureLogin");
                var userPrincipal = new ClaimsPrincipal(userIdentity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    userPrincipal,
                    new AuthenticationProperties
                    {
                        ExpiresUtc = DateTime.UtcNow.AddMinutes(1),
                        IsPersistent = false,
                        AllowRefresh = false
                    });

                return GoToReturnUrl(returnUrl);
            }
            return RedirectToAction("Login", "Auth");
        }

        private IActionResult GoToReturnUrl(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction(nameof(Login));
        }
    }
}