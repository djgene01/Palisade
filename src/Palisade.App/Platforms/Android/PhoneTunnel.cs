using Android.App;
using Android.Content;
using Com.Wireguard.Android.Backend;
using Com.Wireguard.Config;
using Com.Wireguard.Crypto;

namespace Palisade.App.Services;

/// <summary>
/// WireGuard's own Android engine (the one in the official app), driven through Android's VPN service. Android asks
/// the owner once whether Palisade may set up a VPN; after that, one tap brings the tunnel up.
/// </summary>
public static class PhoneTunnel
{
    private const int ConsentRequest = 7210;
    private static readonly Lazy<GoBackend> Backend = new(() => new GoBackend(Platform.AppContext));
    private static readonly Tunnel Ours = new();
    private static TaskCompletionSource<bool>? _consent;

    private sealed class Tunnel : Java.Lang.Object, ITunnel
    {
        public string Name => "palisade";
        public void OnStateChange(ITunnel.State? newState) => IsUp = newState == ITunnel.State.Up;
    }

    public static bool IsUp { get; private set; }

    public static (string Private, string Public) NewKeys()
    {
        using var pair = new KeyPair();
        return (pair.PrivateKey!.ToBase64()!, pair.PublicKey!.ToBase64()!);
    }

    public static (long Received, long Sent) Traffic()
    {
        try { return Backend.Value.GetStatistics(Ours) is { } s ? (s.TotalRx(), s.TotalTx()) : (0, 0); }
        catch (Java.Lang.Throwable) { return (0, 0); }
    }

    /// <summary>Called by the activity with Android's answer to "may Palisade set up a VPN?".</summary>
    public static void ConsentAnswered(int requestCode, Result result)
    {
        if (requestCode == ConsentRequest) _consent?.TrySetResult(result == Result.Ok);
    }

    public static async Task<string?> UpAsync(string configText)
    {
        // Android's own question, the first time: may this app create a VPN?
        var ask = MainThread.InvokeOnMainThreadAsync(() =>
        {
            if (Platform.CurrentActivity is not { } activity) return Task.FromResult(false);
            if (Android.Net.VpnService.Prepare(activity) is not { } consent) return Task.FromResult(true);
            _consent = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            activity.StartActivityForResult(consent, ConsentRequest);
            return _consent.Task;
        });
        if (!await ask) return "Android didn't allow Palisade to set up a VPN. Try again and choose OK.";

        // The engine does network work, so never on the main thread.
        return await Task.Run(() =>
        {
            try
            {
                using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(configText));
                var config = Config.Parse(stream);
                Backend.Value.SetState(Ours, ITunnel.State.Up, config);
                IsUp = true;
                return (string?)null;
            }
            catch (Java.Lang.Throwable ex)
            {
                IsUp = false;
                Android.Util.Log.Warn("Palisade", $"VPN start failed: {ex}");
                return $"The VPN could not start ({Describe(ex)}).";
            }
        });
    }

    /// <summary>
    /// WireGuard's errors often carry no message, only a reason code: say which, so a failure can be told apart.
    /// A phone that uses 16 KB memory pages can't load the engine at all, which shows as a link error.
    /// </summary>
    private static string Describe(Java.Lang.Throwable ex) => ex switch
    {
        BackendException b => $"WireGuard: {b.GetReason()?.Name() ?? "unknown reason"}",
        Java.Lang.UnsatisfiedLinkError => "this phone can't load WireGuard's engine; use the WireGuard app with a QR code instead",
        _ => string.IsNullOrWhiteSpace(ex.Message) ? ex.GetType().Name : $"{ex.GetType().Name}: {ex.Message}",
    };

    /// <summary>
    /// True once home has answered through the tunnel. The tunnel exists the moment it starts, but only bytes coming
    /// back prove the firewall is there: until then, "connected" would be a lie with the internet gone.
    /// </summary>
    public static async Task<bool> HomeAnswersAsync(TimeSpan within)
    {
        var until = DateTime.UtcNow + within;
        while (DateTime.UtcNow < until)
        {
            if (IsUp && Traffic().Received > 0) return true;
            await Task.Delay(500);
        }
        return false;
    }

    public static Task DownAsync() => Task.Run(() =>
    {
        try { Backend.Value.SetState(Ours, ITunnel.State.Down, null); }
        catch (Java.Lang.Throwable) { }
        IsUp = false;
    });
}
