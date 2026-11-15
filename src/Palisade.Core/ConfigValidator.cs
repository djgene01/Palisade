using System.Text.RegularExpressions;

namespace Palisade.Core;

/// <summary>
/// Everything in a config ends up in files owned by root, so nothing passes through here
/// unless it parses as a typed value or matches a narrow character set.
/// </summary>
public static partial class ConfigValidator
{
    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,15}$")]
    private static partial Regex InterfaceName();

    [GeneratedRegex(@"^[A-Za-z0-9 _.,()\-]{1,60}$")]
    private static partial Regex SafeName();

    [GeneratedRegex(@"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")]
    private static partial Regex HostName();

    [GeneratedRegex(@"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")]
    private static partial Regex MacAddress();

    public static bool IsSafeName(string? name) => name is not null && SafeName().IsMatch(name);
    public static bool IsHostName(string? name) => name is not null && HostName().IsMatch(name);

    public static bool TryNormalizeMac(string? text, out string mac)
    {
        mac = (text ?? "").Trim().ToLowerInvariant().Replace('-', ':');
        return MacAddress().IsMatch(mac);
    }

    public static List<ValidationIssue> Validate(FirewallConfig c)
    {
        var issues = new List<ValidationIssue>();
        void Add(string field, string message) => issues.Add(new(field, message));

        if (!InterfaceName().IsMatch(c.WanInterface)) Add("WanInterface", "Choose which network port faces the internet.");
        if (!InterfaceName().IsMatch(c.LanInterface)) Add("LanInterface", "Choose which network port your devices plug into.");
        if (c.WanInterface == c.LanInterface && c.WanInterface.Length > 0)
            Add("LanInterface", "The internet port and the home network port must be different.");

        var lanOk = Ip4.TryParse(c.LanAddress, out var lan);
        if (!lanOk || !lan.IsPrivate)
            Add("LanAddress", "The firewall's address must be a private address such as 192.168.50.1.");
        if (c.LanPrefix is < 16 or > 30)
            Add("LanPrefix", "Pick a network size between /16 and /30.");
        else if (lanOk && (lan == lan.Network(c.LanPrefix) || lan == lan.Broadcast(c.LanPrefix)))
            Add("LanAddress", "That address is reserved on this network. Try one ending in .1.");

        var subnetKnown = lanOk && c.LanPrefix is >= 16 and <= 30;
        bool Usable(Ip4 ip) => subnetKnown && ip.IsIn(lan, c.LanPrefix)
            && ip != lan.Network(c.LanPrefix) && ip != lan.Broadcast(c.LanPrefix);

        var d = c.Dhcp;
        if (d.Enabled)
        {
            var startOk = Ip4.TryParse(d.RangeStart, out var start);
            var endOk = Ip4.TryParse(d.RangeEnd, out var end);
            if (!startOk || !Usable(start)) Add("Dhcp.RangeStart", "The first address must be inside your network.");
            if (!endOk || !Usable(end)) Add("Dhcp.RangeEnd", "The last address must be inside your network.");
            if (startOk && endOk && end.Value < start.Value) Add("Dhcp.RangeEnd", "The last address must come after the first.");
            if (startOk && endOk && lanOk && lan.Value >= start.Value && lan.Value <= end.Value)
                Add("Dhcp.RangeStart", "The range includes the firewall's own address. Move the range past it.");
            if (d.LeaseHours is < 1 or > 720) Add("Dhcp.LeaseHours", "Addresses can be lent for 1 to 720 hours.");
        }
        foreach (var dns in d.UpstreamDns)
            if (!Ip4.TryParse(dns, out _)) Add("Dhcp.UpstreamDns", $"\"{dns}\" is not a valid DNS server address.");
        if (d.UpstreamDns.Count > 4) Add("Dhcp.UpstreamDns", "Use at most four DNS servers.");

        var macs = new HashSet<string>();
        var addresses = new HashSet<string>();
        foreach (var r in d.Reservations)
        {
            var field = $"Reservation.{r.Id}";
            if (!IsHostName(r.Name)) Add(field, $"Device name \"{r.Name}\" can only use letters, numbers and dashes.");
            if (!MacAddress().IsMatch(r.Mac)) Add(field, $"\"{r.Mac}\" is not a valid hardware (MAC) address.");
            else if (!macs.Add(r.Mac)) Add(field, $"{r.Mac} already has a fixed address.");
            if (!Ip4.TryParse(r.Address, out var ip) || !Usable(ip)) Add(field, $"{r.Name}: the fixed address must be inside your network.");
            else if (ip == lan) Add(field, $"{r.Name}: that address belongs to the firewall itself.");
            else if (!addresses.Add(r.Address)) Add(field, $"{r.Address} is already fixed to another device.");
        }

        var seen = new List<(Protocol Protocol, PortRange Range, string Name)>();
        foreach (var f in c.PortForwards)
        {
            var field = $"PortForward.{f.Id}";
            if (!IsSafeName(f.Name)) Add(field, "Give the open port a short name using letters, numbers and spaces.");
            if (f.Protocol is not (Protocol.Tcp or Protocol.Udp or Protocol.TcpUdp))
                Add(field, $"{f.Name}: choose TCP, UDP or both.");
            if (!Ip4.TryParse(f.InternalAddress, out var target) || !Usable(target) || target == lan)
                Add(field, $"{f.Name}: the device address must be a device inside your network.");
            if (f.InternalPort is < 1 or > 65535) Add(field, $"{f.Name}: the device port must be between 1 and 65535.");
            if (!PortSpec.TryParseRange(f.ExternalPort, out var range))
            {
                Add(field, $"{f.Name}: the port must be a number from 1 to 65535, or a range like 8000-8010.");
                continue;
            }
            if (range.From != range.To && f.InternalPort is not null)
                Add(field, $"{f.Name}: a range of ports keeps the same numbers on the device, so leave the device port empty.");
            if (!f.Enabled) continue;
            if (f.Protocol != Protocol.Udp && c.AllowManagementFromWan
                && new[] { PalisadeDefaults.WebPort, PalisadeDefaults.CheckPort, PalisadeDefaults.SshPort }.Any(p => range.Overlaps(new(p, p))))
                Add(field, $"{f.Name}: ports {PalisadeDefaults.SshPort}, {PalisadeDefaults.WebPort} and {PalisadeDefaults.CheckPort} are used to manage this firewall from the internet side.");
            foreach (var other in seen)
                if (other.Range.Overlaps(range) && SharesProtocol(other.Protocol, f.Protocol))
                    Add(field, $"{f.Name}: port {range} is already opened by \"{other.Name}\".");
            seen.Add((f.Protocol, range, f.Name));
        }

        foreach (var r in c.Rules)
        {
            var field = $"Rule.{r.Id}";
            if (!IsSafeName(r.Name)) Add(field, "Give the rule a short name using letters, numbers and spaces.");
            if (r.Source.Length > 0 && !AddressSpec.TryNormalize(r.Source, out _))
                Add(field, $"{r.Name}: \"{r.Source}\" is not an address or range like 192.168.50.20 or 10.0.0.0/8.");
            if (r.Destination.Length > 0 && !AddressSpec.TryNormalize(r.Destination, out _))
                Add(field, $"{r.Name}: \"{r.Destination}\" is not an address or range like 203.0.113.9 or 203.0.113.0/24.");
            if (r.Ports.Length > 0)
            {
                if (r.Protocol is not (Protocol.Tcp or Protocol.Udp or Protocol.TcpUdp))
                    Add(field, $"{r.Name}: ports only apply to TCP or UDP traffic.");
                if (!PortSpec.TryParseList(r.Ports, out _))
                    Add(field, $"{r.Name}: ports must look like 80, 443 or 8000-8010.");
            }
        }

        return issues;
    }

    private static bool SharesProtocol(Protocol a, Protocol b) =>
        a == b || a == Protocol.TcpUdp || b == Protocol.TcpUdp;
}
