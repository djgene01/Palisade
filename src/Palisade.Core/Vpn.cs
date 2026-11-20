using System.Globalization;
using System.Text;

namespace Palisade.Core;

/// <summary>What a VPN device may reach.</summary>
public enum VpnAccess
{
    /// <summary>Like being at home: home devices, this firewall's pages and SSH, device names, and the internet.</summary>
    HomeAndInternet,
    /// <summary>The internet through the home line and filter, and name lookups. Nothing at home.</summary>
    InternetOnly,
}

/// <summary>The VPN as kept in the config. Owned by the engine: a whole-config save keeps it.</summary>
public sealed class VpnSettings
{
    public bool Enabled { get; set; }
    public int Port { get; set; } = VpnPlan.DefaultPort;
    /// <summary>The firewall's address inside the tunnel network; devices get the addresses after it.</summary>
    public string Address { get; set; } = "10.66.0.1";
    public int Prefix { get; set; } = 24;
    /// <summary>The DuckDNS name without ".duckdns.org", such as "smithhome". Empty: devices connect to the address itself.</summary>
    public string DuckDnsName { get; set; } = "";
    public List<VpnDevice> Devices { get; set; } = [];
}

/// <summary>One phone or computer allowed in. Only its public key is kept: the private key was shown once and forgotten.</summary>
public sealed class VpnDevice
{
    public string Id { get; set; } = NewId.Create();
    public string Name { get; set; } = "";
    public string PublicKey { get; set; } = "";
    /// <summary>Its one address in the tunnel network. The firewall accepts nothing else from it.</summary>
    public string Address { get; set; } = "";
    public VpnAccess Access { get; set; } = VpnAccess.HomeAndInternet;
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Switches the VPN on or off, or changes its port, range or name. Waits for confirmation like any change.</summary>
public sealed class VpnRequest
{
    public bool Enabled { get; set; }
    public int Port { get; set; } = VpnPlan.DefaultPort;
    public string Address { get; set; } = "10.66.0.1";
    public int Prefix { get; set; } = 24;
    public string DuckDnsName { get; set; } = "";
    /// <summary>The DuckDNS token. Null keeps the stored one; empty removes it. It is never sent back.</summary>
    public string? DuckDnsToken { get; set; }
}

public sealed class VpnDeviceRequest
{
    public string Name { get; set; } = "";
    public VpnAccess Access { get; set; } = VpnAccess.HomeAndInternet;
}

/// <summary>A device just added: its settings for the WireGuard app, shown this once. The private key in them is kept nowhere else.</summary>
public sealed class VpnDeviceResult
{
    public bool Ok { get; set; }
    public List<ValidationIssue> Issues { get; set; } = [];
    public VpnDevice? Device { get; set; }
    /// <summary>The whole WireGuard config, for a QR code or a .conf file.</summary>
    public string ClientConfig { get; set; } = "";
    public string FileName { get; set; } = "";
}

public enum Reachability
{
    /// <summary>The firewall holds a public address, and the internet sees that same address.</summary>
    Ready,
    /// <summary>The internet port has a private or shared (carrier-grade NAT) address: something sits in front.</summary>
    NotPublic,
    /// <summary>The address is public, but the internet sees another one: something translates in between.</summary>
    Different,
    /// <summary>The internet port has no address yet.</summary>
    NoAddress,
    /// <summary>The outside service could not be asked, so the line could not be checked.</summary>
    NoAnswer,
}

public sealed class ReachabilityReport
{
    public Reachability Outcome { get; set; }
    /// <summary>The internet port's own address.</summary>
    public string PortAddress { get; set; } = "";
    /// <summary>The address the internet sees, as Cloudflare reported it.</summary>
    public string SeenAddress { get; set; } = "";
    public DateTimeOffset CheckedAt { get; set; }
    public string Advice => VpnPlan.Advice(this);
}

/// <summary>A device's tunnel as WireGuard reports it.</summary>
public sealed class VpnPeerStatus
{
    public string DeviceId { get; set; } = "";
    public DateTimeOffset? LastHandshake { get; set; }
    public long ReceivedBytes { get; set; }
    public long SentBytes { get; set; }
    /// <summary>True when it last connected from inside the home network, which proves nothing about reaching it from outside.</summary>
    public bool FromHome { get; set; }
}

public sealed class VpnStatus
{
    public ReachabilityReport? Reachability { get; set; }
    public List<VpnPeerStatus> Peers { get; set; } = [];
    public bool DuckDnsHasToken { get; set; }
    /// <summary>The last DuckDNS update, in plain words, such as "Updated 14:02 to 102.182.43.147". Empty before the first.</summary>
    public string DuckDnsResult { get; set; } = "";
    /// <summary>Why nothing can be shown, such as a firewall too old for the VPN. Empty when all is well.</summary>
    public string Problem { get; set; } = "";
}

public static class VpnPlan
{
    public const string Interface = "palisade-wg";
    public const int DefaultPort = 51820;
    public const string KeyDirectory = "/etc/palisade/wireguard";
    public const string ServerKeyFile = KeyDirectory + "/server.key";
    public const string DuckDnsSuffix = ".duckdns.org";
    /// <summary>Asked what address the firewall's requests come from. Cloudflare, like the Security filter.</summary>
    public const string TraceUrl = "https://1.1.1.1/cdn-cgi/trace";
    public const int MaxDevices = 250;
    /// <summary>Tunnel sets in the firewall rules: devices allowed only the internet.</summary>
    public const string InternetOnlySet = "vpn_internet_only";

    /// <summary>
    /// True for an address the internet can reach: not private, not carrier-grade NAT (100.64/10), not loopback,
    /// link-local, multicast, reserved or set aside for documentation.
    /// </summary>
    public static bool IsPublic(Ip4 ip)
    {
        (uint Net, int Prefix)[] special =
        [
            (0x00000000, 8), (0x0A000000, 8), (0x64400000, 10), (0x7F000000, 8), (0xA9FE0000, 16), (0xAC100000, 12),
            (0xC0000000, 24), (0xC0000200, 24), (0xC0A80000, 16), (0xC6120000, 15), (0xC6336400, 24), (0xCB007100, 24),
            (0xE0000000, 4), (0xF0000000, 4),
        ];
        return !special.Any(s => ip.IsIn(new Ip4(s.Net), s.Prefix));
    }

    /// <summary>The "ip=" line of Cloudflare's trace, if it is a plain IPv4 address.</summary>
    public static string ParseTrace(string text)
    {
        foreach (var line in text.Split('\n'))
            if (line.StartsWith("ip=", StringComparison.Ordinal) && Ip4.TryParse(line[3..].Trim(), out var ip))
                return ip.ToString();
        return "";
    }

    public static ReachabilityReport Check(string portAddress, string? seenAddress, DateTimeOffset now)
    {
        var report = new ReachabilityReport { PortAddress = portAddress, SeenAddress = seenAddress ?? "", CheckedAt = now };
        report.Outcome = !Ip4.TryParse(portAddress, out var port) ? Reachability.NoAddress
            : !IsPublic(port) ? Reachability.NotPublic
            : seenAddress is null or "" ? Reachability.NoAnswer
            : seenAddress != port.ToString() ? Reachability.Different
            : Reachability.Ready;
        return report;
    }

    public static string Advice(ReachabilityReport r) => r.Outcome switch
    {
        Reachability.Ready => $"Your firewall holds the public address {r.PortAddress} itself, so phones can reach it from anywhere.",
        Reachability.NotPublic => Ip4.TryParse(r.PortAddress, out var ip) && ip.IsIn(new Ip4(0x64400000), 10)
            ? $"Your provider shares one public address between many customers (carrier-grade NAT, {r.PortAddress}), so nothing from the internet can reach your firewall. Ask your provider for a public IPv4 address."
            : $"The internet port has the private address {r.PortAddress}, so another router sits between your firewall and the internet. Put that router in bridge mode, or plug the firewall straight into the fibre box (ONT).",
        Reachability.Different => $"The internet port has {r.PortAddress}, but the internet sees {r.SeenAddress}: something in between translates addresses. Plug the firewall straight into the fibre box (ONT), or ask your provider.",
        Reachability.NoAddress => "The internet port has no address yet. Check the cable to your fibre box (ONT) and try again.",
        _ => "The firewall could not ask the internet which address it sees. Check that the internet works, then try again.",
    };

    /// <summary>The address the next new device gets: the first free one after the firewall's.</summary>
    public static string? NextAddress(VpnSettings v)
    {
        if (!Ip4.TryParse(v.Address, out var server)) return null;
        var used = v.Devices.Select(d => d.Address).ToHashSet();
        var network = server.Network(v.Prefix).Value;
        for (var a = network + 1; a < server.Broadcast(v.Prefix).Value; a++)
        {
            var candidate = new Ip4(a).ToString();
            if (a != server.Value && !used.Contains(candidate)) return candidate;
        }
        return null;
    }

    public static string Range(VpnSettings v) =>
        Ip4.TryParse(v.Address, out var ip) ? $"{ip.Network(v.Prefix)}/{v.Prefix.ToString(CultureInfo.InvariantCulture)}" : "";

    /// <summary>Checks the VPN settings, but only while it is on: switched off, it never stands in the way of other saves.</summary>
    public static List<ValidationIssue> Validate(FirewallConfig c)
    {
        var v = c.Vpn;
        var issues = new List<ValidationIssue>();
        if (!v.Enabled) return issues;
        void Add(string message) => issues.Add(new("Vpn", message));
        if (v.Port is < 1024 or > 65535) Add("Choose a VPN port between 1024 and 65535.");
        if (c.PortForwards.Any(f => f.Enabled && f.Protocol != Protocol.Tcp && PortSpec.TryParseRange(f.ExternalPort, out var r) && v.Port >= r.From && v.Port <= r.To))
            Add($"Port {v.Port} is already forwarded on Open ports. Choose another VPN port.");
        if (!Ip4.TryParse(v.Address, out var ip) || ip.ToString() != v.Address || !ip.IsPrivate)
            Add("The VPN network needs a private address, such as 10.66.0.1.");
        else if (v.Prefix is < 24 or > 28)
            Add("The VPN network must be between /24 and /28.");
        else
        {
            if (ip.Value == ip.Network(v.Prefix).Value || ip.Value == ip.Broadcast(v.Prefix).Value)
                Add("The firewall's VPN address can't be the first or last of its range.");
            (string Address, int Prefix, string Name)[] others =
            [
                (c.LanAddress, c.LanPrefix, "your network"),
                .. c.ExtraNetworks.Select(n => (n.Address, n.Prefix, $"the extra network \"{n.Name}\"")),
                .. c.ZeroTrust.Enabled ? [(c.ZeroTrust.HoldingAddress, c.ZeroTrust.HoldingPrefix, "the Zero Trust holding zone")] : Array.Empty<(string, int, string)>(),
            ];
            foreach (var (address, prefix, name) in others)
                if (Ip4.TryParse(address, out var other) && ip.IsIn(other, Math.Min(prefix, v.Prefix)))
                    Add($"The VPN network overlaps {name}. Choose another range, such as 10.66.0.1.");
            foreach (var d in v.Devices)
                if (!Ip4.TryParse(d.Address, out var da) || !da.IsIn(ip, v.Prefix) || da.Value == ip.Value)
                    Add($"{d.Name}'s VPN address is outside the VPN network. Remove the device and add it again.");
        }
        if (v.DuckDnsName.Length > 0 && !IsDuckDnsName(v.DuckDnsName))
            Add("A DuckDNS name is the part before .duckdns.org: letters, numbers and dashes.");
        if (v.Devices.Count > MaxDevices) Add($"At most {MaxDevices} VPN devices.");
        var keys = new HashSet<string>();
        foreach (var d in v.Devices)
        {
            if (!IsKey(d.PublicKey)) Add($"{d.Name} has a key that isn't a WireGuard key.");
            else if (!keys.Add(d.PublicKey)) Add($"{d.Name} has the same key as another device.");
            if (!ConfigValidator.IsSafeName(d.Name)) Add("Give each VPN device a short name using letters, numbers and spaces.");
        }
        return issues;
    }

    public static bool IsDuckDnsName(string name) =>
        name.Length is > 0 and <= 63 && name.All(ch => char.IsAsciiLetterLower(ch) || char.IsAsciiDigit(ch) || ch == '-') && name[0] != '-' && name[^1] != '-';

    /// <summary>A WireGuard key: 32 bytes in base64, 44 characters ending in "=".</summary>
    public static bool IsKey(string key)
    {
        if (key.Length != 44 || key[^1] != '=') return false;
        try { return Convert.FromBase64String(key).Length == 32; }
        catch (FormatException) { return false; }
    }

    /// <summary>
    /// The server's peer list in wg(8) format, without its private key (the agent adds that in a root-only file).
    /// Each device is allowed exactly its own address, so nothing it sends can claim to be from anywhere else.
    /// </summary>
    public static string PeersText(VpnSettings v)
    {
        var sb = new StringBuilder($"[Interface]\nListenPort = {v.Port.ToString(CultureInfo.InvariantCulture)}\n");
        foreach (var d in v.Devices)
        {
            if (!IsKey(d.PublicKey) || !Ip4.TryParse(d.Address, out var a) || a.ToString() != d.Address)
                throw new InvalidOperationException("Unsafe VPN device in config.");
            sb.Append($"\n[Peer]\n# {(ConfigValidator.IsSafeName(d.Name) ? d.Name : "device")}\nPublicKey = {d.PublicKey}\nAllowedIPs = {d.Address}/32\n");
        }
        return sb.ToString();
    }

    /// <summary>Makes the kernel's list of internet-only devices equal to the config, in one step nft applies whole.</summary>
    public static string InternetOnlyScript(VpnSettings v)
    {
        var only = v.Devices.Where(d => d.Access == VpnAccess.InternetOnly).Select(d =>
            Ip4.TryParse(d.Address, out var a) && a.ToString() == d.Address ? d.Address : throw new InvalidOperationException("Unsafe VPN address.")).ToList();
        var sb = new StringBuilder($"flush set inet palisade {InternetOnlySet}\n");
        if (only.Count > 0) sb.Append($"add element inet palisade {InternetOnlySet} {{ {string.Join(", ", only)} }}\n");
        return sb.ToString();
    }

    /// <summary>Where devices connect to: the DuckDNS name when there is one, else the public address.</summary>
    public static string EndpointHost(VpnSettings v, string publicAddress) =>
        v.DuckDnsName.Length > 0 ? v.DuckDnsName + DuckDnsSuffix : publicAddress;

    /// <summary>
    /// What the WireGuard app needs: the device's key and address, the home name server (with home.arpa, so device
    /// names work), and the firewall as the way to everything. All traffic goes through the tunnel, IPv6 included,
    /// so nothing leaks around it on a café's Wi-Fi.
    /// </summary>
    public static string ClientConfig(VpnSettings v, VpnDevice device, string privateKey, string serverPublicKey, string endpointHost) =>
        string.Join('\n',
            "[Interface]",
            $"# {device.Name}, from Palisade",
            $"PrivateKey = {privateKey}",
            $"Address = {device.Address}/32",
            $"DNS = {v.Address}, {NamePlan.Domain}",
            "",
            "[Peer]",
            $"PublicKey = {serverPublicKey}",
            $"Endpoint = {endpointHost}:{v.Port.ToString(CultureInfo.InvariantCulture)}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            "PersistentKeepalive = 25",
            "");

    /// <summary>A file name for the .conf download: WireGuard names the tunnel after it, so short and plain.</summary>
    public static string FileName(VpnDevice device)
    {
        // WireGuard names the tunnel after the file, and a tunnel name may be 15 characters at most.
        var slug = NamePlan.Slug(device.Name);
        var name = slug.Length > 0 ? slug : "palisade";
        return (name.Length > 15 ? name[..15].TrimEnd('-') : name) + ".conf";
    }

    /// <summary>Reads "wg show &lt;interface&gt; dump": one line per device with its key, where it came from, last handshake and bytes.</summary>
    public static List<VpnPeerStatus> ParseDump(string dump, VpnSettings v, Func<string, bool> isHomeAddress)
    {
        var byKey = v.Devices.ToDictionary(d => d.PublicKey, d => d.Id);
        var result = new List<VpnPeerStatus>();
        foreach (var line in dump.Split('\n').Skip(1))
        {
            var f = line.Split('\t');
            if (f.Length < 8 || !byKey.TryGetValue(f[0], out var id)) continue;
            var handshake = long.TryParse(f[4], CultureInfo.InvariantCulture, out var seconds) && seconds > 0 ? DateTimeOffset.FromUnixTimeSeconds(seconds) : (DateTimeOffset?)null;
            var from = f[2].LastIndexOf(':') is var colon and > 0 ? f[2][..colon] : "";
            result.Add(new VpnPeerStatus
            {
                DeviceId = id, LastHandshake = handshake,
                ReceivedBytes = long.TryParse(f[5], CultureInfo.InvariantCulture, out var rx) ? rx : 0,
                SentBytes = long.TryParse(f[6], CultureInfo.InvariantCulture, out var tx) ? tx : 0,
                FromHome = from.Length > 0 && isHomeAddress(from),
            });
        }
        return result;
    }

    /// <summary>DuckDNS's update address. It carries the token, so it is never logged or shown.</summary>
    public static string DuckDnsUpdateUrl(string name, string token) =>
        $"https://www.duckdns.org/update?domains={Uri.EscapeDataString(name)}&token={Uri.EscapeDataString(token)}&ip=";

    public static bool IsDuckDnsToken(string token) => Guid.TryParse(token, out _);
}
