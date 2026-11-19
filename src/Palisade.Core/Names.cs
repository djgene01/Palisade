using System.Globalization;
using System.Text;

namespace Palisade.Core;

/// <summary>The name a device answers to on the home network, such as "grans-tablet" for grans-tablet.home.arpa.</summary>
public sealed record DeviceDnsName(string Mac, string Name);

/// <summary>One name as kept on disk, so a device keeps its name (and its "-2") across restarts.</summary>
public sealed record SavedName(string Mac, string Name, string Base, DateTimeOffset LastSeen)
{
    /// <summary>True when the name comes from the owner, who outranks whatever a device calls itself.</summary>
    public bool Given { get; init; }
}

/// <summary>A device as the namer sees it: who it is, where it is now, and what it could be called.</summary>
public sealed record NameCandidate(string Mac, string Address, string GivenName, string OwnName, string Maker);

/// <summary>Automatic names for every device on the home network, under home.arpa (RFC 8375).</summary>
public static class NamePlan
{
    public const string Domain = "home.arpa";
    /// <summary>The firewall's own name: palisade.home.arpa.</summary>
    public const string Firewall = "palisade";
    /// <summary>Where dnsmasq finds the names. It watches the folder and picks up changes by itself, keeping its cache.</summary>
    public const string Directory = "/etc/palisade/names";
    public const string HostsFile = Directory + "/hosts";
    /// <summary>Run by dnsmasq for each lease. It keeps what each device calls itself, one file per hardware address, in <see cref="SeenDirectory"/>.</summary>
    public const string LeaseScript = "/opt/palisade/palisade-lease-name";
    public const string SeenDirectory = "/var/lib/palisade/hostnames";
    private const int MaxLength = 40;

    /// <summary>
    /// Names nobody may give a device, not even the owner: the firewall's own, and the ones programs look up by
    /// themselves to find a proxy or set themselves up, which a device could otherwise answer for.
    /// </summary>
    public static readonly IReadOnlySet<string> Reserved = new HashSet<string>(StringComparer.Ordinal)
    {
        Firewall, "localhost", "wpad", "isatap",
    };

    /// <summary>
    /// Names a device may not give itself, on top of <see cref="Reserved"/>: ones that sound like part of the network.
    /// The owner may still call a device "router" on the Devices page.
    /// </summary>
    public static readonly IReadOnlySet<string> ReservedForDevices = new HashSet<string>(Reserved, StringComparer.Ordinal)
    {
        "router", "gateway", "dns", "ns", "www", "mail", "home", "local",
    };

    /// <summary>A name made safe for DNS: lower case letters, digits and single dashes, at most 40 long. Empty when nothing usable is left.</summary>
    public static string Slug(string? text)
    {
        var sb = new StringBuilder();
        foreach (var ch in (text ?? "").Normalize(NormalizationForm.FormD).ToLowerInvariant())
        {
            if (CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.NonSpacingMark) continue;   // é becomes e
            if (ch is >= 'a' and <= 'z' or >= '0' and <= '9') sb.Append(ch);
            else if (ch == '\'') continue;                                                         // gran's becomes grans
            else if (sb.Length > 0 && sb[^1] != '-') sb.Append('-');
        }
        var slug = sb.ToString().Trim('-');
        if (slug.Length > MaxLength) slug = slug[..MaxLength].TrimEnd('-');
        // A name of digits alone could be mistaken for an address.
        return slug.All(char.IsAsciiDigit) ? "" : slug;
    }

    /// <summary>What a device should be called, best source first: the owner's name, the device's own, its maker, or "device".</summary>
    public static string Base(NameCandidate d)
    {
        foreach (var wanted in new[] { d.GivenName, d.OwnName })
            if (Slug(wanted) is { Length: > 0 } slug) return slug;
        var tag = d.Mac.Replace(":", "", StringComparison.Ordinal)[^4..];
        var maker = Slug(Maker.IsMadeUp(d.Mac) ? "" : d.Maker.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault());
        return $"{(maker.Length > 0 ? maker : "device")}-{tag}";
    }

    /// <summary>
    /// The devices to name: every device with an address on the home network now, and every device with a fixed
    /// address, here or not. With Zero Trust on, only approved devices: a waiting or blocked one gets no name.
    /// </summary>
    public static List<NameCandidate> Candidates(FirewallConfig c, IEnumerable<DhcpLease> leases, Func<string, string?> maker, DateTimeOffset now)
    {
        var given = c.Names.GroupBy(n => n.Mac).ToDictionary(g => g.Key, g => g.First().Name);
        var approved = c.ZeroTrust.Approved.Select(a => a.Mac).ToHashSet();
        bool Allowed(string mac) => !c.ZeroTrust.Enabled || approved.Contains(mac);
        bool AtHome(string address) => Ip4.TryParse(address, out var ip) && Ip4.TryParse(c.LanAddress, out var lan) && ip.IsIn(lan, c.LanPrefix);

        var result = new Dictionary<string, NameCandidate>(StringComparer.Ordinal);
        foreach (var r in c.Dhcp.Reservations)
            if (ConfigValidator.TryNormalizeMac(r.Mac, out var mac) && Allowed(mac) && AtHome(r.Address))
                result[mac] = new NameCandidate(mac, r.Address, given.GetValueOrDefault(mac, ""), r.Name, maker(mac) ?? "");
        foreach (var l in leases.Where(l => l.Expires > now).OrderBy(l => l.Expires))
            if (ConfigValidator.TryNormalizeMac(l.Mac, out var mac) && Allowed(mac) && AtHome(l.Address) && !result.ContainsKey(mac))
                result[mac] = new NameCandidate(mac, l.Address, given.GetValueOrDefault(mac, ""), l.Hostname ?? "", maker(mac) ?? "");
        return [.. result.Values];
    }

    /// <summary>The file dnsmasq reads: the firewall, then each named device, with its full name and the short one.</summary>
    public static string HostsFileText(string firewallAddress, IEnumerable<(string Address, string Name)> devices)
    {
        var sb = new StringBuilder("# Generated by Palisade. Do not edit: names change as devices come and go.\n");
        sb.Append(Line(firewallAddress, Firewall));
        foreach (var (address, name) in devices.OrderBy(d => d.Name, StringComparer.Ordinal)) sb.Append(Line(address, name));
        return sb.ToString();

        static string Line(string address, string name) =>
            Ip4.TryParse(address, out var ip) && ip.ToString() == address && Slug(name) == name && name.Length > 0
                ? $"{address} {name}.{Domain} {name}\n"
                : throw new InvalidOperationException($"Unsafe name or address for the names file: {name} {address}");
    }
}

/// <summary>
/// Hands out names and remembers them by hardware address, so a device keeps its name while it is away and a
/// newcomer with the same name always gets the "-2", never the other way round.
/// </summary>
public sealed class NameBook
{
    /// <summary>A device unseen for this long gives up its name, so names don't pile up forever.</summary>
    public static readonly TimeSpan Kept = TimeSpan.FromDays(90);
    private readonly Dictionary<string, SavedName> _names = new(StringComparer.Ordinal);

    public NameBook(IEnumerable<SavedName>? saved = null)
    {
        foreach (var s in saved ?? [])
            if (ConfigValidator.TryNormalizeMac(s.Mac, out var mac) && NamePlan.Slug(s.Name) == s.Name && s.Name.Length > 0
                && !(s.Given ? NamePlan.Reserved : NamePlan.ReservedForDevices).Contains(s.Name)
                && !_names.Values.Any(n => n.Name == s.Name))
                _names[mac] = s with { Mac = mac };
    }

    public IReadOnlyList<SavedName> Export() => [.. _names.Values.OrderBy(n => n.Name, StringComparer.Ordinal)];

    /// <summary>The name a device has now, if any.</summary>
    public string? NameOf(string mac) => _names.TryGetValue(mac, out var n) ? n.Name : null;

    /// <summary>
    /// Names the devices present now. A device keeps its name while what it should be called is unchanged; when the
    /// owner renames it, or it starts calling itself something else, it is named afresh. True when anything changed.
    /// </summary>
    public bool Assign(IEnumerable<NameCandidate> present, DateTimeOffset now)
    {
        var changed = false;
        foreach (var stale in _names.Values.Where(n => now - n.LastSeen > Kept).Select(n => n.Mac).ToList())
            changed |= _names.Remove(stale);

        // Names the owner gave go first and may take a name from a device that only called itself that: naming the
        // NAS "nas" must not end as "nas-2" because some phone said "nas" first. Among equals, a device that already
        // holds its name goes first, so a newcomer can never take it.
        var devices = present.GroupBy(d => d.Mac).Select(g => g.First())
            .Select(d => (Device: d, Base: NamePlan.Base(d), Given: NamePlan.Slug(d.GivenName).Length > 0))
            .OrderBy(d => d.Given ? 0 : 1)
            .ThenBy(d => _names.TryGetValue(d.Device.Mac, out var held) && held.Base == d.Base ? 0 : 1)
            .ThenBy(d => d.Device.Mac, StringComparer.Ordinal)
            .ToList();
        var settled = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (device, wanted, given) in devices)
        {
            if (_names.TryGetValue(device.Mac, out var held) && held.Base == wanted && held.Given == given)
            {
                _names[device.Mac] = held with { LastSeen = now };
                settled.Add(device.Mac);
                continue;
            }
            _names.Remove(device.Mac);
            var name = Free(wanted, given, settled);
            _names[device.Mac] = new SavedName(device.Mac, name, wanted, now) { Given = given };
            settled.Add(device.Mac);
            changed = true;
        }
        return changed;
    }

    /// <summary>
    /// The wanted name, or the first free "-2", "-3". The owner's names take precedence: a device holding the wanted
    /// name only because it called itself that gives it up and is named again (here, or when it next comes back).
    /// </summary>
    private string Free(string wanted, bool given, HashSet<string> settled)
    {
        var reserved = given ? NamePlan.Reserved : NamePlan.ReservedForDevices;
        bool Taken(string name)
        {
            if (reserved.Contains(name)) return true;
            var holder = _names.Values.FirstOrDefault(n => n.Name == name);
            if (holder is null) return false;
            // Only the exact name is taken back: a device that is "nas-2" keeps that, rather than names shuffling along.
            if (!given || name != wanted || holder.Given || settled.Contains(holder.Mac)) return true;
            _names.Remove(holder.Mac);
            return false;
        }
        if (!Taken(wanted)) return wanted;
        for (var i = 2; ; i++)
        {
            var suffix = "-" + i.ToString(CultureInfo.InvariantCulture);
            var name = (wanted.Length + suffix.Length > 40 ? wanted[..(40 - suffix.Length)].TrimEnd('-') : wanted) + suffix;
            if (!Taken(name)) return name;
        }
    }
}
