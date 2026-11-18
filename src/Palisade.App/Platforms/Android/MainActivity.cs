using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Palisade.App.Services;

namespace Palisade.App;

// A fixed Java name, so the app icon's shortcuts (Resources/xml/shortcuts.xml) can point at this activity.
// One instance in its own task: a share from a browser switches to Palisade instead of starting a second copy inside the browser.
[Activity(Name = "io.github.djgene01.palisade.MainActivity", Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
// "Share" from a browser or another app: block or allow that site.
[IntentFilter([Intent.ActionSend], Categories = [Intent.CategoryDefault], DataMimeType = "text/plain", Label = "Block or allow in Palisade")]
// The firewall's linking code, read by the phone's own camera app.
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault, Intent.CategoryBrowsable], DataScheme = "palisade", DataHost = "pair")]
// The app icon's shortcuts. Not browsable: web pages cannot open these.
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault], DataScheme = "palisade", DataHost = "open")]
[MetaData("android.app.shortcuts", Resource = "@xml/shortcuts")]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        // Opened afresh by a link or a share; a restored activity has already handled its intent.
        if (savedInstanceState is null) HandleIntent(Intent);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        HandleIntent(intent);
    }

    private static void HandleIntent(Intent? intent)
    {
        // Reopened from Recents, Android hands over the intent the app was first opened with: not something new.
        if (intent is null || intent.Flags.HasFlag(ActivityFlags.LaunchedFromHistory)) return;
        if (IPlatformApplication.Current?.Services.GetService<AppLinks>() is not { } links) return;
        if (intent.Action == Intent.ActionSend) links.Shared(intent.GetStringExtra(Intent.ExtraText));
        else if (intent.Action == Intent.ActionView) links.OpenLink(intent.DataString);
    }
}
