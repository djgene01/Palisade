using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Palisade.Core;
using Palisade.UI.Layout;
using Palisade.UI.Services;
using Palisade.Web.Components;
using Palisade.Web.Components.Layout;
using Palisade.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// systemd hands the service its own state folder; on a development machine use ./data.
var dataDirectory = Environment.GetEnvironmentVariable("STATE_DIRECTORY")
    ?? Path.Combine(builder.Environment.ContentRootPath, "data");
Directory.CreateDirectory(dataDirectory);

var backendKind = builder.Configuration["Palisade:Backend"] ?? (OperatingSystem.IsLinux() ? "agent" : "simulated");

// The firewall rules open the default ports. Other ports are only for running on a development machine.
var ports = new WebPorts(builder.Configuration.GetValue("Palisade:WebPort", PalisadeDefaults.WebPort), builder.Configuration.GetValue("Palisade:CheckPort", PalisadeDefaults.CheckPort));
builder.Services.AddSingleton(ports);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(ports.Web);
    kestrel.ListenAnyIP(ports.Check);
});

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDirectory, "keys")));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(cookie =>
{
    cookie.Cookie.Name = "palisade";
    cookie.Cookie.SameSite = SameSiteMode.Strict;
    cookie.ExpireTimeSpan = TimeSpan.FromHours(12);
    cookie.SlidingExpiration = true;
    cookie.LoginPath = "/login";
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton(new PasswordStore(dataDirectory));
// Asking who made a device goes out to the internet, so the demo on a development machine leaves it off unless told otherwise.
builder.Services.AddSingleton<IMakerSource>(new MakerLookup(dataDirectory, builder.Configuration.GetValue("Palisade:MakerLookup", backendKind != "simulated")));
builder.Services.AddPalisadeUi();
builder.Services.AddScoped<IConnectionProbe, BrowserProbe>();
builder.Services.AddSingleton(new ShellOptions { SignOutButton = typeof(SignOutButton) });

if (backendKind == "simulated")
{
    builder.Services.AddSingleton<IFirewallBackend>(_ =>
        new FirewallEngine(new SimulatedPlatform(), Path.Combine(dataDirectory, "simulated"), TimeSpan.FromSeconds(PalisadeDefaults.ConfirmSeconds)));
    builder.Services.AddSingleton<IUpdates>(new SimulatedUpdates());
    var simulatedWatch = new SimulatedWatch();
    builder.Services.AddSingleton<ITrafficWatch>(simulatedWatch);
    builder.Services.AddSingleton<IDnsControl>(simulatedWatch);
}
else
{
    builder.Services.AddSingleton<IFirewallBackend>(_ =>
        new AgentClient(builder.Configuration["Palisade:Socket"] ?? "/run/palisade/agent.sock"));
    builder.Services.AddSingleton(sp => (IUpdates)sp.GetRequiredService<IFirewallBackend>());
    builder.Services.AddSingleton(sp => (ITrafficWatch)sp.GetRequiredService<IFirewallBackend>());
    builder.Services.AddSingleton(sp => (IDnsControl)sp.GetRequiredService<IFirewallBackend>());
}

var app = builder.Build();

if (app.Services.GetRequiredService<IFirewallBackend>() is FirewallEngine simulated)
    await simulated.InitializeAsync();

if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/Error", createScopeForErrors: true);

// The second port answers one thing only: "a new connection still reaches the firewall".
app.Use(async (context, next) =>
{
    if (context.Connection.LocalPort != ports.Check)
    {
        await next();
        return;
    }
    context.Response.StatusCode = context.Request.Path == "/ping" ? StatusCodes.Status204NoContent : StatusCodes.Status404NotFound;
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.Connection = "close";
});

app.UseAuthentication();

// Nothing but the sign-in pages and their static files is reachable without the admin password.
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? "/";
    var isPublic = path is "/login" or "/setup" or "/Error"
        || path.StartsWith("/_framework/", StringComparison.Ordinal)
        // The shared screens' stylesheet, script and font, served from the Palisade.UI library.
        || path.StartsWith("/_content/", StringComparison.Ordinal)
        || path.EndsWith(".css", StringComparison.Ordinal)
        || path.EndsWith(".js", StringComparison.Ordinal);
    if (isPublic || context.User.Identity?.IsAuthenticated == true)
    {
        await next();
        return;
    }
    if (path.StartsWith("/_blazor", StringComparison.Ordinal) || path.StartsWith("/api/", StringComparison.Ordinal))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }
    var passwords = context.RequestServices.GetRequiredService<PasswordStore>();
    context.Response.Redirect(passwords.HasPassword ? "/login" : "/setup");
});

app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapGet("/api/whoami", (HttpContext context) =>
    Results.Text(context.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? ""));
app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync();
    return Results.Redirect("/login");
}).DisableAntiforgery();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode().AddAdditionalAssemblies(typeof(MainLayout).Assembly);

app.Run();

public sealed record WebPorts(int Web, int Check);

public static class SignIn
{
    public static Task AdminAsync(HttpContext context) =>
        context.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin")], CookieAuthenticationDefaults.AuthenticationScheme)));
}
