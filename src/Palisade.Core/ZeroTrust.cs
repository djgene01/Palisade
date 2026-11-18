using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Palisade.Core;

/// <summary>
/// Zero Trust Mode: a device may use the network only once someone has approved it. Until then it is given an
/// address in a separate holding zone that reaches nothing, and everything it tries is counted and captured.
/// The lists are kept by the engine itself and changed only through <see cref="IFirewallBackend.ChangeApprovalAsync"/>,
/// so a screen that saves an older copy of the settings can never switch the mode off or undo an approval.
/// </summary>
public sealed class ZeroTrustSettings
{
    public bool Enabled { get; set; }
    /// <summary>The firewall's own address in the holding zone. Waiting devices get an address next to it.</summary>
    public string HoldingAddress { get; set; } = "10.99.0.1";
    public int HoldingPrefix { get; set; } = 24;
    public List<ApprovedDevice> Approved { get; set; } = [];
    /// <summary>Devices turned away for good: they get no address and are not listed as waiting.</summary>
    public List<BlockedDevice> Blocked { get; set; } = [];
}

public sealed class ApprovedDevice
{
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTimeOffset ApprovedAt { get; set; }
}

public sealed class BlockedDevice
{
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTimeOffset BlockedAt { get; set; }
}

/// <summary>Switching the mode on or off, or moving the holding zone. Goes through apply and confirm.</summary>
public sealed class ZeroTrustRequest
{
    public bool Enabled { get; set; }
    public string HoldingAddress { get; set; } = "10.99.0.1";
    public int HoldingPrefix { get; set; } = 24;
}

public enum ApprovalAction { Approve, Block, Remove, Unblock }

/// <summary>One decision about one device.</summary>
public sealed class ApprovalChange
{
    public ApprovalAction Action { get; set; }
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
}

/// <summary>A device that is not approved and has turned up: what it is, and what it tried to reach.</summary>
public sealed class HeldDevice
{
    public string Mac { get; set; } = "";
    /// <summary>Its address in the holding zone, when it got one. Empty for a device with an address set by hand.</summary>
    public string Address { get; set; } = "";
    /// <summary>The name it gave when asking for an address, if any.</summary>
    public string Hostname { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    /// <summary>Packets it sent that were turned away.</summary>
    public long Attempts { get; set; }
    /// <summary>Where it tried to go, busiest first. At most <see cref="ZeroTrustPlan.FlowsKept"/>.</summary>
    public List<HeldFlow> Flows { get; set; } = [];
}

public sealed class HeldFlow
{
    public string Address { get; set; } = "";
    public string Protocol { get; set; } = "";
    public int Port { get; set; }
    public long Packets { get; set; }
    public DateTimeOffset LastSeen { get; set; }
}

/// <summary>The packets waiting devices sent, as captured, for opening in Wireshark. Only on a real firewall.</summary>
public interface IHeldCapture
{
    /// <summary>The capture files zipped together, newest included, or null when nothing has been captured.</summary>
    Task<byte[]?> GetHeldCaptureAsync(CancellationToken ct = default);
}

public static class ZeroTrustPlan
{
    public const string ApprovedSet = "approved";
    public const string FlowsSet = "held_flows";
    /// <summary>The kernel log group the capture listens on. Exactly the packets that were turned away go to it.</summary>
    public const int LogGroup = 7;
    /// <summary>Read by dnsmasq: approved devices are "known" and get a home address, blocked ones are ignored.</summary>
    public const string HostsFile = "/etc/palisade/zt-hosts";
    /// <summary>How long a holding-zone address lasts. Short, so an approved device moves home within minutes.</summary>
    public const string HoldingLease = "2m";
    public const int FlowsKept = 50;
    public const int MaxDevices = 1000;
    public static readonly TimeSpan Kept = TimeSpan.FromDays(7);

    public static string HoldingRange(ZeroTrustSettings z) =>
        Ip4.TryParse(z.HoldingAddress, out var ip) && z.HoldingPrefix is >= 24 and <= 28
            ? $"{ip.Network(z.HoldingPrefix)}/{z.HoldingPrefix.ToString(CultureInfo.InvariantCulture)}"
            : throw new InvalidOperationException($"Unsafe holding zone in config: {z.HoldingAddress}/{z.HoldingPrefix}");

    /// <summary>The addresses handed to waiting devices: .100 to .250 in a /24, the whole zone but the firewall in a smaller one.</summary>
    public static (Ip4 First, Ip4 Last) HoldingPool(ZeroTrustSettings z)
    {
        if (!Ip4.TryParse(z.HoldingAddress, out var ip)) throw new InvalidOperationException("Unsafe holding zone in config.");
        var network = ip.Network(z.HoldingPrefix).Value;
        var last = ip.Broadcast(z.HoldingPrefix).Value - 1;
        var (first, end) = z.HoldingPrefix == 24 ? (network + 100, network + 250) : (network + 1, last);
        if (ip.Value >= first && ip.Value <= end) first = ip.Value + 1;
        return (new Ip4(first), new Ip4(end));
    }

    public static bool InHoldingZone(ZeroTrustSettings z, string address) =>
        z.Enabled && Ip4.TryParse(address, out var a) && Ip4.TryParse(z.HoldingAddress, out var h) && a.IsIn(h, z.HoldingPrefix);

    /// <summary>dnsmasq's hosts file: one line per approved device, "mac,ignore" for a blocked one.</summary>
    public static string HostsFileText(ZeroTrustSettings z)
    {
        var sb = new StringBuilder("# Generated by Palisade. Do not edit: approvals change it.\n");
        foreach (var d in z.Approved) sb.Append(Mac(d.Mac)).Append('\n');
        foreach (var d in z.Blocked) sb.Append(Mac(d.Mac)).Append(",ignore\n");
        return sb.ToString();
    }

    /// <summary>Makes the kernel's approved set equal to the list, in one step that nft applies whole.</summary>
    public static string SetScript(ZeroTrustSettings z)
    {
        var sb = new StringBuilder($"flush set inet palisade {ApprovedSet}\n");
        if (z.Approved.Count > 0) sb.Append($"add element inet palisade {ApprovedSet} {{ {string.Join(", ", z.Approved.Select(d => Mac(d.Mac)))} }}\n");
        return sb.ToString();
    }

    /// <summary>
    /// Everything the firewall already knows about, approved in one go when the mode is switched on, so nobody in
    /// the house loses the internet. A device that has been quiet the whole time is not in it.
    /// </summary>
    public static List<ApprovedDevice> KnownDevices(FirewallConfig c, IEnumerable<DhcpLease> leases, IEnumerable<string> neighbours, DateTimeOffset now)
    {
        var found = new Dictionary<string, string>(StringComparer.Ordinal);
        void Add(string? mac, string? name)
        {
            if (!ConfigValidator.TryNormalizeMac(mac, out var m) || c.ZeroTrust.Blocked.Any(b => b.Mac == m)) return;
            var clean = ConfigValidator.IsSafeName(name) ? name! : "";
            if (!found.TryGetValue(m, out var existing) || existing.Length == 0) found[m] = clean;
        }
        foreach (var d in c.ZeroTrust.Approved) Add(d.Mac, d.Name);
        foreach (var n in c.Names) Add(n.Mac, n.Name);
        foreach (var r in c.Dhcp.Reservations) Add(r.Mac, r.Name);
        foreach (var a in c.Access) Add(a.Mac, a.Name);
        foreach (var f in c.Filter.Devices) Add(f.Mac, f.Name);
        foreach (var l in c.Limits) Add(l.Mac, l.Name);
        foreach (var l in leases.Where(l => !InHoldingZone(c.ZeroTrust, l.Address))) Add(l.Mac, l.Hostname);
        foreach (var n in neighbours) Add(n, null);
        return [.. found.Select(kv => c.ZeroTrust.Approved.FirstOrDefault(d => d.Mac == kv.Key)
            ?? new ApprovedDevice { Mac = kv.Key, Name = kv.Value, ApprovedAt = now }).OrderBy(d => d.Mac, StringComparer.Ordinal)];
    }

    public static List<ValidationIssue> Validate(FirewallConfig c)
    {
        var z = c.ZeroTrust;
        var issues = new List<ValidationIssue>();
        void Add(string field, string message) => issues.Add(new(field, message));
        // The holding zone only matters while the mode is on: switched off, it must never stand in the way of other saves,
        // such as a home network moved onto the range it would use. It is checked again when the mode is switched on.
        if (!z.Enabled) { }
        else if (!Ip4.TryParse(z.HoldingAddress, out var holding) || holding.ToString() != z.HoldingAddress || !holding.IsPrivate)
            Add("ZeroTrust.HoldingAddress", "The holding zone needs a private address, such as 10.99.0.1.");
        else if (z.HoldingPrefix is < 24 or > 28)
            Add("ZeroTrust.HoldingAddress", "The holding zone must hold between 16 and 256 addresses (from /24 to /28).");
        else
        {
            if (holding.Value == holding.Network(z.HoldingPrefix).Value || holding.Value == holding.Broadcast(z.HoldingPrefix).Value)
                Add("ZeroTrust.HoldingAddress", "The firewall's address in the holding zone can't be the first or last of its range.");
            if (Ip4.TryParse(c.LanAddress, out var lan) && holding.IsIn(lan, Math.Min(c.LanPrefix, z.HoldingPrefix)))
                Add("ZeroTrust.HoldingAddress", "The holding zone overlaps your network. Choose another range, such as 10.99.0.1.");
            foreach (var n in c.ExtraNetworks)
                if (Ip4.TryParse(n.Address, out var other) && holding.IsIn(other, Math.Min(n.Prefix, z.HoldingPrefix)))
                    Add("ZeroTrust.HoldingAddress", $"The holding zone overlaps the extra network \"{n.Name}\". Choose another range.");
        }
        if (z.Approved.Count + z.Blocked.Count > MaxDevices) Add("ZeroTrust", $"At most {MaxDevices} devices can be approved or blocked.");
        var seen = new HashSet<string>();
        foreach (var (mac, name, list) in z.Approved.Select(d => (d.Mac, d.Name, "approved")).Concat(z.Blocked.Select(d => (d.Mac, d.Name, "blocked"))))
        {
            if (!ConfigValidator.TryNormalizeMac(mac, out var m) || m != mac) Add("ZeroTrust", $"\"{mac}\" is not a valid hardware (MAC) address.");
            else if (!seen.Add(mac)) Add("ZeroTrust", $"{mac} is on the approved or blocked list twice.");
            if (name.Length > 0 && !ConfigValidator.IsSafeName(name)) Add("ZeroTrust", $"The name of {mac} on the {list} list uses characters that aren't allowed.");
        }
        return issues;
    }

    /// <summary>Reads "nft -j list set" of the flows set: hardware address, destination, protocol, port and packets.</summary>
    public static List<(string Mac, string Address, string Protocol, int Port, long Packets)> ParseFlows(string json)
    {
        var result = new List<(string, string, string, int, long)>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("nftables", out var items)) return result;
            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("set", out var set) || !set.TryGetProperty("elem", out var elems)) continue;
                foreach (var wrapped in elems.EnumerateArray())
                {
                    if (!wrapped.TryGetProperty("elem", out var elem) || !elem.TryGetProperty("val", out var val)) continue;
                    if (!val.TryGetProperty("concat", out var parts) || parts.GetArrayLength() != 4) continue;
                    var p = parts.EnumerateArray().ToArray();
                    if (!ConfigValidator.TryNormalizeMac(p[0].GetString(), out var mac) || !Ip4.TryParse(p[1].GetString(), out var ip)) continue;
                    var proto = p[2].ValueKind == JsonValueKind.String ? p[2].GetString()! : p[2].GetInt32() switch { 6 => "tcp", 17 => "udp", var n => n.ToString(CultureInfo.InvariantCulture) };
                    if (proto is not ("tcp" or "udp")) continue;
                    var port = p[3].ValueKind == JsonValueKind.Number ? p[3].GetInt32() : int.TryParse(p[3].GetString(), out var n2) ? n2 : -1;
                    if (port is < 0 or > 65535) continue;
                    var packets = elem.TryGetProperty("counter", out var counter) && counter.TryGetProperty("packets", out var pk) && pk.TryGetInt64(out var count) ? count : 0;
                    result.Add((mac, ip.ToString(), proto, port, packets));
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException) { }
        return result;
    }

    internal static string Mac(string text) =>
        ConfigValidator.TryNormalizeMac(text, out var mac) && mac == text ? mac : throw new InvalidOperationException($"Unsafe hardware address in config: {text}");
}

/// <summary>
/// Remembers what waiting devices tried, across rule reloads and restarts. The kernel counts per destination
/// and starts again from zero on every reload, so only growth between two readings is added. Approved and
/// blocked devices are dropped from it; anything not seen for a week is forgotten.
/// </summary>
public sealed class HeldTracker(IEnumerable<HeldDevice>? saved = null)
{
    private readonly Dictionary<string, HeldDevice> _held = (saved ?? []).Where(h => ConfigValidator.TryNormalizeMac(h.Mac, out var m) && m == h.Mac).ToDictionary(h => h.Mac);
    private readonly Dictionary<(string, string, string, int), long> _last = [];

    /// <summary>Returns true when something changed, so the caller knows to save.</summary>
    public bool Record(DateTimeOffset now, IEnumerable<(string Mac, string Address, string Protocol, int Port, long Packets)> flows,
        IEnumerable<DhcpLease> holdingLeases, ZeroTrustSettings z)
    {
        var changed = false;
        var current = new HashSet<(string, string, string, int)>();
        foreach (var (mac, address, protocol, port, packets) in flows)
        {
            var key = (mac, address, protocol, port);
            current.Add(key);
            var before = _last.GetValueOrDefault(key);
            var growth = packets >= before ? packets - before : packets;
            _last[key] = packets;
            if (growth == 0) continue;
            var device = Get(mac, now);
            device.Attempts += growth;
            device.LastSeen = now;
            var flow = device.Flows.FirstOrDefault(f => f.Address == address && f.Protocol == protocol && f.Port == port);
            if (flow is null) device.Flows.Add(flow = new HeldFlow { Address = address, Protocol = protocol, Port = port });
            flow.Packets += growth;
            flow.LastSeen = now;
            device.Flows = [.. device.Flows.OrderByDescending(f => f.Packets).ThenByDescending(f => f.LastSeen).Take(ZeroTrustPlan.FlowsKept)];
            changed = true;
        }
        foreach (var key in _last.Keys.Where(k => !current.Contains(k)).ToList()) _last.Remove(key);
        foreach (var lease in holdingLeases)
        {
            var device = Get(lease.Mac, now);
            if (device.Address != lease.Address || device.Hostname != (lease.Hostname ?? ""))
            {
                (device.Address, device.Hostname) = (lease.Address, lease.Hostname ?? "");
                changed = true;
            }
            if (now - device.LastSeen > TimeSpan.FromMinutes(1)) { device.LastSeen = now; changed = true; }
        }
        // Decided devices and long-gone ones leave the list.
        var decided = z.Approved.Select(d => d.Mac).Concat(z.Blocked.Select(d => d.Mac)).ToHashSet();
        foreach (var gone in _held.Values.Where(h => decided.Contains(h.Mac) || now - h.LastSeen > ZeroTrustPlan.Kept).ToList())
        {
            _held.Remove(gone.Mac);
            changed = true;
        }
        return changed;

        HeldDevice Get(string mac, DateTimeOffset at)
        {
            if (!_held.TryGetValue(mac, out var d)) _held[mac] = d = new HeldDevice { Mac = mac, FirstSeen = at, LastSeen = at };
            return d;
        }
    }

    public List<HeldDevice> Report() =>
        [.. _held.Values.OrderByDescending(h => h.LastSeen).Select(h => new HeldDevice
        {
            Mac = h.Mac, Address = h.Address, Hostname = h.Hostname, FirstSeen = h.FirstSeen, LastSeen = h.LastSeen, Attempts = h.Attempts,
            Flows = [.. h.Flows.Select(f => new HeldFlow { Address = f.Address, Protocol = f.Protocol, Port = f.Port, Packets = f.Packets, LastSeen = f.LastSeen })],
        })];
}
