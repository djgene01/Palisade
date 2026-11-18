namespace Palisade.App.Services;

/// <summary>
/// Colours what is around the page (behind the status bar and the gesture bar) to match the page's own
/// light or dark colours, and tells Android whether the icons there should be dark or light to stay readable.
/// </summary>
public static class SystemBars
{
    private static readonly Color Light = Color.FromArgb("#f2f5fb");
    private static readonly Color Dark = Color.FromArgb("#0e1a33");

    public static void Apply(bool dark) => MainThread.BeginInvokeOnMainThread(() =>
    {
        if (Application.Current?.Windows.FirstOrDefault()?.Page is { } page) page.BackgroundColor = dark ? Dark : Light;
#if ANDROID
        var window = Platform.CurrentActivity?.Window;
        if (window is null) return;
        if (AndroidX.Core.View.WindowCompat.GetInsetsController(window, window.DecorView) is not { } bars) return;
        // "Light" bars mean dark icons, for a light background.
        bars.AppearanceLightStatusBars = !dark;
        bars.AppearanceLightNavigationBars = !dark;
#endif
    });
}
