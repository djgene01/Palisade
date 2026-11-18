using Microsoft.Extensions.Logging;
using Palisade.App.Services;
using Palisade.Core;
using Palisade.UI.Services;
using ZXing.Net.Maui.Controls;

namespace Palisade.App;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>().UseBarcodeReader();

        builder.Services.AddMauiBlazorWebView();
#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        // Off the UI thread: both read from disk and secure storage, and a UI-thread wait could deadlock.
        var demo = new FirewallEngine(new SimulatedPlatform(), Path.Combine(FileSystem.AppDataDirectory, "demo"),
            TimeSpan.FromSeconds(PalisadeDefaults.ConfirmSeconds));
        var store = new FirewallStore();
        Task.Run(async () =>
        {
            await demo.InitializeAsync();
            await store.LoadAsync();
        }).GetAwaiter().GetResult();

        // Opens on the firewall shown last time. With none, the routes send the owner to the start screen.
        var active = new ActiveFirewall(demo);
        if (store.Chosen == FirewallStore.Demo) active.ShowDemo();
        else if (store.Links.FirstOrDefault(l => l.DeviceId == store.Chosen) is { } link) active.Show(link);

        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton(active);
        builder.Services.AddSingleton<IFirewallBackend>(active);
        builder.Services.AddSingleton<IUpdates>(active);
        builder.Services.AddSingleton<ITrafficWatch>(active);
        builder.Services.AddSingleton<IDnsControl>(active);
        builder.Services.AddSingleton<IConnectionProbe>(active);
        builder.Services.AddSingleton<IMakerSource>(active);
        builder.Services.AddSingleton<QrScanner>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<AppLock>();
        builder.Services.AddSingleton<AppLinks>();
        builder.Services.AddScoped<FirewallSwitcher>();
        builder.Services.AddSingleton(new ShellOptions
        {
            OnTheFirewall = false,
            ExtraLinks = [new ShellLink("/firewalls", "Firewalls", "firewalls")],
            Subtitle = () => active.Name,
            ThemeChanged = SystemBars.Apply,
            CanBePaused = true,
        });
        builder.Services.AddPalisadeUi();

        return builder.Build();
    }
}
