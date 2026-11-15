using System.Diagnostics;
using System.Text.Json.Serialization;
using Palisade.Agent;
using Palisade.Core;

[assembly: System.Runtime.Versioning.UnsupportedOSPlatform("windows")]

// The privileged half of Palisade. It listens only on a Unix socket that the web UI's
// group may open, and it accepts whole configs, never commands.
var builder = WebApplication.CreateBuilder(args);

var socketPath = builder.Configuration["Palisade:Socket"] ?? "/run/palisade/agent.sock";
var dataDirectory = builder.Configuration["Palisade:DataDirectory"] ?? "/var/lib/palisade";
var socketGroup = builder.Configuration["Palisade:SocketGroup"] ?? "palisade";

builder.WebHost.ConfigureKestrel(kestrel =>
{
    if (File.Exists(socketPath)) File.Delete(socketPath);
    kestrel.ListenUnixSocket(socketPath);
});
builder.Services.ConfigureHttpJsonOptions(json =>
{
    json.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});
builder.Services.AddSingleton<ISystemPlatform>(sp => new LinuxPlatform(dataDirectory, sp.GetRequiredService<ILogger<LinuxPlatform>>()));
builder.Services.AddSingleton(sp =>
{
    var logger = sp.GetRequiredService<ILogger<FirewallEngine>>();
    return new FirewallEngine(sp.GetRequiredService<ISystemPlatform>(), dataDirectory,
        TimeSpan.FromSeconds(PalisadeDefaults.ConfirmSeconds), message => logger.LogWarning("{Message}", message));
});

var app = builder.Build();
var engine = app.Services.GetRequiredService<FirewallEngine>();
await engine.InitializeAsync();

app.MapGet("/status", (CancellationToken ct) => engine.GetStatusAsync(ct));
app.MapGet("/config", (CancellationToken ct) => engine.GetConfigAsync(ct));
app.MapGet("/leases", (CancellationToken ct) => engine.GetLeasesAsync(ct));
app.MapPost("/config/apply", (FirewallConfig config, CancellationToken ct) => engine.ApplyAsync(config, ct));
app.MapPost("/config/confirm", async (CancellationToken ct) => { await engine.ConfirmAsync(ct); return Results.NoContent(); });
app.MapPost("/config/revert", async (CancellationToken ct) => { await engine.RevertAsync(ct); return Results.NoContent(); });

app.Lifetime.ApplicationStarted.Register(() =>
{
    // Root owns the socket; members of the web UI's group may connect, nobody else.
    if (OperatingSystem.IsWindows()) return;
    using var chgrp = Process.Start(new ProcessStartInfo("/usr/bin/chgrp") { ArgumentList = { socketGroup, socketPath } });
    chgrp?.WaitForExit();
    File.SetUnixFileMode(socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
});

app.Run();
