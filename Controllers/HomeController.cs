using System.Diagnostics;
using LoginandRegistration.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;

namespace LoginandRegistration.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private MyContext db;

    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;
        db = context;
    }

    [HttpGet("")]
    public IActionResult Index()
    {
        return View("Index");
    }

    [HttpPost("register")]
    public IActionResult Register(User user)
    {
        if (!ModelState.IsValid)
        {
            return Index();
        }

        PasswordHasher<User> hashPw = new PasswordHasher<User>();
        user.Password = hashPw.HashPassword(user, user.Password);

        db.Users.Add(user);
        db.SaveChanges();

        HttpContext.Session.SetInt32("UserId", user.UserId);
        return RedirectToAction("Success");
    }

    [HttpPost("login")]
    public IActionResult Login(LoginUser user)
    {
        if(!ModelState.IsValid)
        {
            return Index();
        }

        User? dbUser = db.Users.FirstOrDefault(u=> u.Email == user.LoginEmail);

        if (dbUser == null)
        {
            ModelState.AddModelError("Email", "not found");
            return Index();
        }

        PasswordHasher<LoginUser> hashPw = new PasswordHasher<LoginUser>();
        PasswordVerificationResult pwCompareResult = hashPw.VerifyHashedPassword(user, dbUser.Password, user.LoginPassword);

        if (pwCompareResult == 0)
        {
            ModelState.AddModelError("LoginPassword", "invalid password");
            return Index();
        }

        HttpContext.Session.SetInt32("UserId", dbUser.UserId);
        return RedirectToAction("Success");
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }

    [SessionCheck]
    [HttpGet("/success")]
    public IActionResult Success()
    {
        return View("Success");
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

// Name this anything you want with the word "Attribute" at the end
public class SessionCheckAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        // Find the session, but remember it may be null so we need int?
        int? userId = context.HttpContext.Session.GetInt32("UserId");
        // Check to see if we got back null
        if(userId == null)
        {
            // Redirect to the Index page if there was nothing in session
            // "Home" here is referring to "HomeController", you can use any controller that is appropriate here
            context.Result = new RedirectToActionResult("Index", "Home", null);
        }
    }
}


