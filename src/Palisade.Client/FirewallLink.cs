using System.Globalization;
using Palisade.Core;

namespace Palisade.Client;

/// <summary>Where a firewall's app interface is, and, when known, the key it must present there.</summary>
public sealed record FirewallAddress(string Host, int Port, string? Pin)
{
    public Uri BaseUri => new UriBuilder(Uri.UriSchemeHttps, Host, Port).Uri;
}

/// <summary>What a pairing QR code holds: the address, the key to expect, and the one-time code.</summary>
public sealed record PairingInvite(FirewallAddress Address, string Code);

/// <summary>
/// A firewall this app is linked to. The app keeps it in the phone's secure storage: the token is the
/// device's key to the firewall, and the pin is how the app knows it is talking to that same firewall.
/// </summary>
public sealed record FirewallLink(string Host, int Port, string Pin, string Token, string DeviceId)
{
    public FirewallAddress Address => new(Host, Port, Pin);

    /// <summary>Leaves the token out, so a link that ends up in a log or an error report gives nothing away.</summary>
    public override string ToString() => $"FirewallLink {{ Host = {Host}, Port = {Port}, DeviceId = {DeviceId} }}";
}

public static class PairingLinks
{
    /// <summary>
    /// Reads the link from a pairing QR code (palisade://pair?h=…&amp;p=…&amp;k=…&amp;c=…). Returns null for
    /// anything else, so a stray QR code from a menu or a poster is simply not recognised.
    /// </summary>
    public static PairingInvite? Parse(string? text)
    {
        if (!Uri.TryCreate(text?.Trim(), UriKind.Absolute, out var uri)
            || !uri.Scheme.Equals(AppContract.LinkScheme, StringComparison.OrdinalIgnoreCase)
            || !uri.Host.Equals("pair", StringComparison.OrdinalIgnoreCase))
            return null;
        var query = Query(uri.Query);
        if (!query.TryGetValue("h", out var host) || !IsHost(host)) return null;
        if (!query.TryGetValue("p", out var portText) || !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535) return null;
        if (!query.TryGetValue("k", out var pin) || !CertificatePin.IsValid(pin)) return null;
        if (!query.TryGetValue("c", out var code) || code.Length is < 4 or > 16) return null;
        return new PairingInvite(new FirewallAddress(host, port, pin), code);
    }

    /// <summary>
    /// What a person typed instead of scanning: the address shown on the firewall's page, with or without a
    /// port. There is no pin yet; the app shows the firewall's fingerprint to compare before going on.
    /// </summary>
    public static FirewallAddress? Typed(string? address)
    {
        var text = (address ?? "").Trim();
        if (text.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) text = text[8..];
        else if (text.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) text = text[7..];
        text = text.TrimEnd('/');
        // Any port a person adds is usually the web page's (8080). The app interface always has its own,
        // so the port is dropped: "[v6]:port" and "host:port" lose it, a bare IPv6 address (many colons) stays whole.
        var host = text.StartsWith('[') && text.IndexOf(']') is var end and > 0 ? text[1..end]
            : text.Count(ch => ch == ':') == 1 ? text[..text.IndexOf(':')]
            : text;
        return IsHost(host) ? new FirewallAddress(host, PalisadeDefaults.ApiPort, null) : null;
    }

    private static bool IsHost(string host) =>
        host.Length is > 0 and <= 253 && Uri.CheckHostName(host) is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6;

    private static Dictionary<string, string> Query(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            result.TryAdd(part[..eq], Uri.UnescapeDataString(part[(eq + 1)..]));
        }
        return result;
    }
}
