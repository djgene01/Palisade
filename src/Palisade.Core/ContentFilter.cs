using System.Text.RegularExpressions;

namespace Palisade.Core;

/// <summary>How much the name lookups (DNS) of a device are filtered. Each level includes the ones before it.</summary>
public enum FilterLevel { Off, Security, Adult, Family }

public sealed class ContentFilter
{
    /// <summary>The level for every device that has no entry in <see cref="Devices"/>.</summary>
    public FilterLevel Level { get; set; } = FilterLevel.Off;
    /// <summary>Sites nobody on the network can open, whatever their level.</summary>
    public List<string> BlockedSites { get; set; } = [];
    /// <summary>Sites that stay reachable even when a level would block them.</summary>
    public List<string> AllowedSites { get; set; } = [];
    public List<DeviceFilter> Devices { get; set; } = [];
    /// <summary>Refuses the services that rent a home connection out to strangers, for every device at every level.</summary>
    public bool BlockRelays { get; set; }
}

/// <summary>A device that uses a different level from the rest of the network. Keyed by hardware address, so it holds without a fixed IP.</summary>
public sealed class DeviceFilter
{
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
    public FilterLevel Level { get; set; }
}

/// <summary>A second name server on its own port, serving the devices whose level differs from the network's.</summary>
public sealed record DnsInstance(FilterLevel Level, string Name, int Port, string Conf);

public static partial class SiteName
{
    [GeneratedRegex(@"^(?=.{4,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")]
    private static partial Regex Domain();

    /// <summary>True for a plain lower-case site name such as "example.com". Nothing else may reach a generated file.</summary>
    public static bool IsValid(string? name) => name is not null && Domain().IsMatch(name);

    /// <summary>Reduces whatever a person pastes ("https://www.Example.com/watch?v=1") to the site name ("example.com").</summary>
    public static bool TryNormalize(string? text, out string name)
    {
        name = (text ?? "").Trim().ToLowerInvariant();
        var scheme = name.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) name = name[(scheme + 3)..];
        var end = name.IndexOfAny(['/', '?', '#', ':']);
        if (end >= 0) name = name[..end];
        if (name.StartsWith("*.", StringComparison.Ordinal)) name = name[2..];
        if (name.StartsWith("www.", StringComparison.Ordinal) && name.Count(ch => ch == '.') >= 2) name = name[4..];
        name = name.TrimEnd('.');
        return IsValid(name);
    }
}

/// <summary>Works out, from a config, which name servers each level uses and which extra instances must run.</summary>
public static class FilterPlan
{
    /// <summary>A name every instance answers by itself, so a health check works even when the internet is down.</summary>
    public const string CheckName = "palisade-check.invalid";

    private static readonly string[] FallbackServers = ["1.1.1.1", "9.9.9.9"];

    // Names browsers and phones use to switch to their own encrypted lookups, which would skip the filter.
    // The first is the signal Firefox checks; the iCloud ones switch off Private Relay; the rest are the
    // common secure-DNS services a browser can be pointed at by name.
    public static readonly string[] BypassNames =
    [
        "use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com",
        "dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
        "dns.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
    ];

    // Services that pay app makers, or the owner, to pass strangers' traffic through a home connection.
    // Cheap TV boxes and "free" apps often carry them without saying so. Each name is the one the
    // relay software must look up to join its network, so refusing it keeps the device out.
    public static readonly string[] RelayNames =
    [
        "bright-sdk.com", "brdtnet.com", "lum-sdk.io", "luminati.io", "luminatinet.com",
        "oxylabs.io", "honeygain.com", "packetstream.io", "pawns.app", "iproyal.com", "earnapp.com",
        "peer2profit.com", "repocket.co", "traffmonetizer.com", "proxyrack.net", "infatica.io", "joinmassive.com",
    ];

    public static string Name(FilterLevel level) => level.ToString().ToLowerInvariant();

    public static int Port(FilterLevel level) => 5380 + (int)level;

    public static IEnumerable<FilterLevel> AllLevels => Enum.GetValues<FilterLevel>();

    /// <summary>Filtering services published by their operators: Cloudflare for Families and CleanBrowsing's free family filter.</summary>
    public static IReadOnlyList<string> Servers(FilterLevel level, FirewallConfig c) => level switch
    {
        FilterLevel.Security => ["1.1.1.2", "1.0.0.2"],
        FilterLevel.Adult => ["1.1.1.3", "1.0.0.3"],
        FilterLevel.Family => ["185.228.168.168", "185.228.169.168"],
        _ => c.Dhcp.UpstreamDns,
    };

    /// <summary>Unfiltered servers for the sites on the allow list.</summary>
    public static IReadOnlyList<string> PlainServers(FirewallConfig c) =>
        c.Dhcp.UpstreamDns.Count > 0 ? c.Dhcp.UpstreamDns : FallbackServers;

    /// <summary>Devices whose own setting really differs from the network's.</summary>
    public static IEnumerable<DeviceFilter> Overrides(FirewallConfig c) =>
        c.Filter.Devices.Where(d => d.Level != c.Filter.Level);

    public static IReadOnlyList<FilterLevel> InstanceLevels(FirewallConfig c) =>
        [.. Overrides(c).Select(d => d.Level).Distinct().Order()];

    /// <summary>When anything is filtered, lookups are forced through the firewall so a device can't pick its own name server.</summary>
    public static bool Enforced(FirewallConfig c) =>
        c.Filter.Level != FilterLevel.Off || c.Filter.BlockedSites.Count > 0 || c.Filter.BlockRelays || c.Limits.Count > 0 || Overrides(c).Any();

    public static FilterLevel LevelFor(FirewallConfig c, string mac) =>
        c.Filter.Devices.FirstOrDefault(d => d.Mac == mac)?.Level ?? c.Filter.Level;
}
