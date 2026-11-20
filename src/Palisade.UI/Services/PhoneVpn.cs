using Palisade.Core;

namespace Palisade.UI.Services;

public enum PhoneVpnState
{
    /// <summary>This phone isn't one of the firewall's VPN devices yet.</summary>
    NotSetUp,
    Off,
    Connecting,
    On,
}

/// <summary>Where this phone's own tunnel stands, for the VPN page.</summary>
public sealed record PhoneVpnStatus(PhoneVpnState State, string DeviceId = "", string Name = "", long ReceivedBytes = 0, long SentBytes = 0, string Problem = "");

/// <summary>
/// The VPN built into the app, on a phone that can run it (Android): it makes its own key, joins the firewall's VPN
/// over the paired connection, and connects with one tap. Not registered where there is no such tunnel (the web page,
/// the Windows app), and the VPN page then shows only what the firewall offers.
/// </summary>
public interface IPhoneVpn
{
    event Action? Changed;
    PhoneVpnStatus Status { get; }
    /// <summary>A name to suggest for this phone on the firewall, such as the name the owner gave the phone itself.</summary>
    string DefaultName { get; }
    /// <summary>Makes this phone's key, adds it to the firewall's VPN under the given name, and keeps the settings here.</summary>
    Task<IReadOnlyList<ValidationIssue>> SetUpAsync(string name);
    /// <summary>Asks Android's permission the first time, then brings the tunnel up. Returns a problem in plain words, or null.</summary>
    Task<string?> ConnectAsync();
    Task DisconnectAsync();
    /// <summary>Forgets this phone's settings, for example after it was removed on the firewall.</summary>
    Task ForgetAsync();
    /// <summary>Reads the tunnel's state afresh, and notices a phone the firewall no longer lists.</summary>
    Task RefreshAsync(FirewallConfig? config);
}
