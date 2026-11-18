using Microsoft.Extensions.Logging;
using Palisade.App.Services;
using Palisade.Core;
using Palisade.UI.Services;

namespace Palisade.App;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();

        builder.Services.AddMauiBlazorWebView();
#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        // For now the app only talks to a demo firewall that lives inside it. The same engine and
        // pretend network as the web interface's demo mode, so every screen works without a network.
        var demo = new FirewallEngine(new SimulatedPlatform(), Path.Combine(FileSystem.AppDataDirectory, "demo"),
            TimeSpan.FromSeconds(PalisadeDefaults.ConfirmSeconds));
        // Off the UI thread: the engine reads its saved settings from disk, and a UI-thread wait could deadlock.
        Task.Run(() => demo.InitializeAsync()).GetAwaiter().GetResult();
        var watch = new SimulatedWatch();

        builder.Services.AddSingleton<IFirewallBackend>(demo);
        builder.Services.AddSingleton<IUpdates>(new SimulatedUpdates());
        builder.Services.AddSingleton<ITrafficWatch>(watch);
        builder.Services.AddSingleton<IDnsControl>(watch);
        builder.Services.AddSingleton<IConnectionProbe, DemoProbe>();
        builder.Services.AddSingleton<IMakerSource, NoMakers>();
        // Nothing to sign out of yet: there is no account in the app.
        builder.Services.AddSingleton(new ShellOptions());
        builder.Services.AddPalisadeUi();

        return builder.Build();
    }
}
