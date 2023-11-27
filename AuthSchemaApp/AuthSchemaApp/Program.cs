using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthSchemaApp;
using AuthSchemaApp.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Web.Providers.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);
var keyManager_ = new KeyManager();
builder.Services.AddSingleton(keyManager_);
builder.Services.AddDbContext<IdentityDbContext>(c =>
{
    c.UseInMemoryDatabase("my_db");
});



builder.Services.AddIdentity<IdentityUser , IdentityRole>(o =>
{
    o.User.RequireUniqueEmail = true;


    o.Password.RequireDigit = false;
    o.Password.RequiredLength = 4;
    o.Password.RequireLowercase = false;
    o.Password.RequireUppercase = false;
    o.Password.RequireNonAlphanumeric = false;
})
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddAuthentication()
    .AddJwtBearer("jwt", o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateAudience = false,
            ValidateIssuer = false,
        };

        o.Configuration = new OpenIdConnectConfiguration()
        {
            SigningKeys ={

                new RsaSecurityKey(keyManager_.RsaKey)

            },
        };

        o.MapInboundClaims = false;
    });

builder.Services.Configure<CRMSettingOptions>(
    builder.Configuration.GetSection(nameof(CRMSettingOptions)));

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>("visitor", o => { })
    .AddCookie("local")
    .AddCookie("patreon-cookie")
    .AddOAuth("external-patreon", o =>
    {

        o.SignInScheme = "patreon-cookie";

        o.ClientId = "id";
        o.ClientSecret = "secret";

        o.AuthorizationEndpoint = "https://oauth.wiremockapi.cloud/oauth/authorize";
        o.TokenEndpoint = "https://oauth.wiremockapi.cloud/oauth/token";
        o.UserInformationEndpoint = "https://oauth.wiremockapi.cloud/userinfo";

        o.CallbackPath = "/cb-patreon";
        o.Scope.Add("profile");
        o.SaveTokens = true;
    });

    builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("customer", p =>
    {
        p.AddAuthenticationSchemes("local", "visitor")
        .RequireAuthenticatedUser();

    });


    b.AddPolicy("user", p =>
    {
        p.AddAuthenticationSchemes("local")
        .RequireAuthenticatedUser();

    });

});







var app =  builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();



app.MapGet("/" , (ClaimsPrincipal User) => User.Claims.Select(x => KeyValuePair.Create(x.Type, x.Value)));
app.MapGet("/secret" , () => "Secret").RequireAuthorization("the_policy");
app.MapGet("/secret-cookie", () => "Secret-cookie").RequireAuthorization("the_policy", "cookie-policiy");
app.MapGet("/secret-token", () => "Secret-token").RequireAuthorization("the_policy", "token-policy");


app.MapGet("/jwt/sign-In", (KeyManager keyManager) =>
{
    var handler = new JsonWebTokenHandler();
    var key = new RsaSecurityKey(keyManager.RsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://localhost:7065",
        Subject = null,
        SigningCredentials = new SigningCredentials(key , SecurityAlgorithms.RsaSha256),
    });

    return token;
});


app.MapGet("/options" , (
    IOptions<CRMSettingOptions> options,
    IOptionsSnapshot<CRMSettingOptions> optionsSnapshot,
    IOptionsMonitor<CRMSettingOptions> optionsMonitor) => 
    {

        var response = new
        {
            OptionsValueT = options.Value.RequestTImeout,
            OptionsValueM = options.Value.MaxRetries,

            SnapshotValueT = optionsSnapshot.Value.RequestTImeout,
            SnapshotValueM = optionsSnapshot.Value.MaxRetries,

            MonitorValueT = optionsMonitor.CurrentValue.RequestTImeout,
            MonitorValueM = optionsMonitor.CurrentValue.MaxRetries


        };

        return Results.Ok(response);
    

});


app.MapGet("/", ctx => Task.FromResult("Hello World")).RequireAuthorization("customer");
app.MapGet("/cookie-login-local", async (ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("user", "anton"));
    var identity = new ClaimsIdentity(claims, "local");
    var user = new ClaimsPrincipal(identity);


    await ctx.SignInAsync("local", user);
});

app.MapGet("/cookie-login-patreon", async (ctx) => 
await ctx.ChallengeAsync("external-patreon", new AuthenticationProperties() 
{

    RedirectUri = "/"

    
})
).RequireAuthorization("user");




app.Run();





public class VisitorAuthHandler : CookieAuthenticationHandler
{
    public VisitorAuthHandler(
        IOptionsMonitor<CookieAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {

    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();
        if (result.Succeeded)
        {
            return result;
        }
        var claims = new List<Claim>();
        claims.Add(new Claim("user", "anton"));
        var identity = new ClaimsIdentity(claims, "visitor");
        var user = new ClaimsPrincipal(identity);
        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));

    }

}