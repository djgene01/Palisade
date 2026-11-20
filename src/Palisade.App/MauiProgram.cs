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
        builder.Services.AddSingleton<ISystemHealth>(active);
        builder.Services.AddSingleton<ISpeedTest>(active);
#if ANDROID
        // The VPN built into the app, on Android only; elsewhere the VPN page shows what the firewall offers.
        builder.Services.AddSingleton<IPhoneVpn>(new PhoneVpn(active));
#endif
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
            ShareFile = ShareFileAsync,
#if WINDOWS
            ShareFileLabel = "Save settings file",
            ShareFileHint = "Press Save settings file, then in WireGuard choose Import tunnel(s) from file and pick it in Downloads. Delete the file afterwards: it holds the device's key.",
#else
            ShareFileLabel = "Share settings file",
            ShareFileHint = "Press Share settings file and choose WireGuard. If WireGuard isn't in the list, save the file to Files instead, then in WireGuard press + and Import from file.",
#endif
        });
        builder.Services.AddPalisadeUi();

        return builder.Build();
    }

    /// <summary>
    /// The phone's share sheet, for a VPN device's settings: they go to the WireGuard app from here. The file holds
    /// a private key, so it lives in the app's own cache and is deleted again two minutes later.
    /// </summary>
    private static async Task ShareFileAsync(string fileName, string text)
    {
#if WINDOWS
        // A share sheet can't reach WireGuard on Windows: save it where people look, and show it there.
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        Directory.CreateDirectory(folder);
        var saved = Path.Combine(folder, Path.GetFileName(fileName));
        await File.WriteAllTextAsync(saved, text);
        System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{saved}\"");
#else
        var path = Path.Combine(FileSystem.CacheDirectory, Path.GetFileName(fileName));
        await File.WriteAllTextAsync(path, text);
        await MainThread.InvokeOnMainThreadAsync(() => Share.Default.RequestAsync(new ShareFileRequest { Title = "Add to WireGuard", File = new ShareFile(path) }));
        _ = Task.Delay(TimeSpan.FromMinutes(2)).ContinueWith(_ => File.Delete(path), TaskScheduler.Default);
#endif
    }
}
