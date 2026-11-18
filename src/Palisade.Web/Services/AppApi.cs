using Palisade.Core;
using Palisade.UI.Services;

namespace Palisade.Web.Services;

/// <summary>What the firewall says about itself before pairing: enough for the app to know it found the right thing.</summary>
public sealed record ApiInfo(string Product, int Api, string Version);

public sealed record PairRequest(string? Code, string? Name);

public sealed record PairResponse(string DeviceId, string Token);

/// <summary>A problem in plain words, the same kind the web pages show.</summary>
public sealed record ApiProblem(string Problem);

/// <summary>
/// The companion app's interface. It offers exactly what the web pages can do, through the same backend, so
/// every change is still checked by the agent and still waits for confirmation. It answers only on the
/// encrypted port and only to paired devices, apart from the three calls needed before pairing.
/// </summary>
public static class AppApi
{
    /// <summary>Raised when the app's interface changes in a way older apps cannot follow.</summary>
    public const int Version = 1;
    public const string Prefix = "/api/v1";

    private const string DeviceItem = "palisade.device";

    /// <summary>
    /// Keeps the two front doors apart: the encrypted port serves only this interface, and this interface is
    /// never served over plain HTTP, where a token could be read off the wire.
    /// </summary>
    public static IApplicationBuilder UseAppApiGate(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        var isApi = context.Request.Path.StartsWithSegments(Prefix, StringComparison.Ordinal);
        if (isApi != context.Request.IsHttps)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        await next();
    });

    public static void MapAppApi(this IEndpointRouteBuilder routes, string version)
    {
        var open = routes.MapGroup(Prefix).DisableAntiforgery();
        open.MapGet("/info", () => new ApiInfo("Palisade", Version, version));
        // A fresh connection that gets this answer proves a change has not locked this device out.
        open.MapGet("/ping", (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Connection = "close";
            return Results.NoContent();
        });
        open.MapPost("/pair", (PairRequest request, PairedDevices devices) =>
        {
            var (token, device, problem) = devices.Pair(request.Code, request.Name);
            return token is null
                ? Results.Json(new ApiProblem(problem), statusCode: StatusCodes.Status400BadRequest)
                : Results.Ok(new PairResponse(device!.Id, token));
        });

        var api = routes.MapGroup(Prefix).DisableAntiforgery().AddEndpointFilter(RequireDevice);

        api.MapGet("/status", (IFirewallBackend b, CancellationToken ct) => b.GetStatusAsync(ct));
        api.MapGet("/config", (IFirewallBackend b, CancellationToken ct) => b.GetConfigAsync(ct));
        api.MapGet("/leases", (IFirewallBackend b, CancellationToken ct) => b.GetLeasesAsync(ct));
        api.MapGet("/usage", (IFirewallBackend b, CancellationToken ct) => b.GetUsageAsync(ct));
        api.MapPost("/config/apply", (FirewallConfig config, IFirewallBackend b, CancellationToken ct) => b.ApplyAsync(config, ct));
        api.MapPost("/config/confirm", async (IFirewallBackend b, CancellationToken ct) => { await b.ConfirmAsync(ct); return Results.NoContent(); });
        api.MapPost("/config/revert", async (IFirewallBackend b, CancellationToken ct) => { await b.RevertAsync(ct); return Results.NoContent(); });
        api.MapPost("/access", (List<DeviceAccess> access, IFirewallBackend b, CancellationToken ct) => b.SetAccessAsync(access, ct));
        api.MapPost("/names", (List<DeviceName> names, IFirewallBackend b, CancellationToken ct) => b.SetNamesAsync(names, ct));
        api.MapGet("/wifi", (IFirewallBackend b, CancellationToken ct) => b.GetWifiAsync(ct));
        api.MapPost("/wifi", (WifiRequest request, IFirewallBackend b, CancellationToken ct) => b.SetWifiAsync(request, ct));
        api.MapPost("/dns/flush", (IDnsControl dns, CancellationToken ct) => dns.FlushDnsAsync(ct));
        api.MapPost("/watch", (WatchRequest request, ITrafficWatch watch, CancellationToken ct) => watch.WatchAsync(request, ct));
        api.MapGet("/update", (IUpdates u, CancellationToken ct) => u.GetUpdateAsync(ct));
        api.MapPost("/update/settings", (UpdateSettings settings, IUpdates u, CancellationToken ct) => u.SetUpdateAsync(settings, ct));
        api.MapPost("/update/check", (IUpdates u, CancellationToken ct) => u.CheckUpdateAsync(install: false, ct));
        api.MapPost("/update/install", (IUpdates u, CancellationToken ct) => u.CheckUpdateAsync(install: true, ct));
        // Who made each device. Unknown makers come back as null while the firewall looks them up.
        api.MapGet("/makers", (string[] mac, IMakerSource makers) =>
            mac.Take(256).Distinct().ToDictionary(m => m, m => makers.Find(m)));
        // Lets the app forget the firewall cleanly: its own token stops working.
        api.MapPost("/unpair", (HttpContext context, PairedDevices devices) =>
        {
            devices.Remove(((PairedDevice)context.Items[DeviceItem]!).Id);
            return Results.NoContent();
        });
    }

    private static async ValueTask<object?> RequireDevice(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
    {
        var context = invocation.HttpContext;
        var header = context.Request.Headers.Authorization.ToString();
        var token = header.StartsWith("Bearer ", StringComparison.Ordinal) ? header["Bearer ".Length..].Trim() : null;
        if (context.RequestServices.GetRequiredService<PairedDevices>().Verify(token) is not { } device)
        {
            context.Response.Headers.WWWAuthenticate = "Bearer";
            return Results.Json(new ApiProblem("This device is not linked to the firewall, or its link was removed. Link it again from the firewall's Advanced page."),
                statusCode: StatusCodes.Status401Unauthorized);
        }
        context.Items[DeviceItem] = device;
        try
        {
            return await next(invocation);
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Net.Sockets.SocketException)
        {
            // The same situation the web pages explain: the web interface is up, the part that controls the network is not.
            return Results.Json(new ApiProblem($"The firewall service is not answering, so nothing was changed. ({ex.Message})"),
                statusCode: StatusCodes.Status502BadGateway);
        }
    }
}
